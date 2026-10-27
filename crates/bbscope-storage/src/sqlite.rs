use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use bbscope_core::normalize::normalize_target;
use bbscope_core::{Change, ChangeType, Entry, PROGRAM_CATEGORY};
use chrono::{DateTime, NaiveDateTime, Utc};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};

use crate::{ListOptions, PlatformStats, ProgramType, Result, StorageError, Store, UpsertEntry};

const TS: &str = "%Y-%m-%d %H:%M:%S";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS programs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    platform      TEXT NOT NULL,
    handle        TEXT NOT NULL,
    url           TEXT NOT NULL UNIQUE,
    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    strict        INTEGER NOT NULL DEFAULT 0 CHECK (strict IN (0,1)),
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
    is_ignored    INTEGER NOT NULL DEFAULT 0 CHECK (is_ignored IN (0,1))
);
CREATE INDEX IF NOT EXISTS idx_programs_platform_handle ON programs(platform, handle);
CREATE INDEX IF NOT EXISTS idx_programs_disabled_ignored ON programs(disabled, is_ignored);

CREATE TABLE IF NOT EXISTS targets_raw (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id    INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    target        TEXT NOT NULL,
    category      TEXT NOT NULL,
    description   TEXT,
    in_scope      INTEGER NOT NULL CHECK (in_scope IN (0,1)),
    is_bbp        INTEGER NOT NULL DEFAULT 0 CHECK (is_bbp IN (0,1)),
    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_id, category, target)
);
CREATE INDEX IF NOT EXISTS idx_targets_raw_program_id ON targets_raw(program_id, in_scope);

CREATE TABLE IF NOT EXISTS scope_changes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    program_url       TEXT NOT NULL,
    platform          TEXT NOT NULL,
    handle            TEXT NOT NULL,
    target_normalized TEXT NOT NULL,
    target_raw        TEXT NOT NULL DEFAULT '',
    category          TEXT NOT NULL,
    in_scope          INTEGER NOT NULL CHECK (in_scope IN (0,1)),
    is_bbp            INTEGER NOT NULL DEFAULT 0 CHECK (is_bbp IN (0,1)),
    change_type       TEXT NOT NULL CHECK (change_type IN ('added','updated','removed'))
);
CREATE INDEX IF NOT EXISTS idx_changes_time ON scope_changes(occurred_at);
CREATE INDEX IF NOT EXISTS idx_changes_program ON scope_changes(program_url, occurred_at);
"#;

/// SQLite-backed [`Store`]. One connection behind a mutex: writes are short
/// and polling is network-bound, so this is not a bottleneck.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    path: String,
}

fn ts(t: DateTime<Utc>) -> String {
    t.format(TS).to_string()
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    NaiveDateTime::parse_from_str(s, TS)
        .map(|n| n.and_utc())
        .or_else(|_| DateTime::parse_from_rfc3339(s).map(|d| d.with_timezone(&Utc)))
        .unwrap_or_default()
}

fn identity_key(raw: &str, category: &str) -> String {
    let raw = raw.trim().to_lowercase();
    if raw.is_empty() {
        return String::new();
    }
    format!("{raw}|{}", category.trim().to_lowercase())
}

struct Existing {
    id: i64,
    raw: String,
    category: String,
    description: String,
    in_scope: bool,
    is_bbp: bool,
}

impl SqliteStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = Path::new(path).parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| StorageError::Other(format!("creating {parent:?}: {e}")))?;
            }
            Connection::open(path)?
        };
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn), path: path.to_string() })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn change_from_row(r: &Row) -> rusqlite::Result<Change> {
    let occurred: String = r.get(0)?;
    let kind: String = r.get(10)?;
    Ok(Change {
        occurred_at: parse_ts(&occurred),
        program_url: r.get(1)?,
        platform: r.get(2)?,
        handle: r.get(3)?,
        target_normalized: r.get(4)?,
        target_raw: r.get(5)?,
        category: r.get(6)?,
        in_scope: r.get(7)?,
        is_bbp: r.get(8)?,
        // column 9 is unused padding so both queries share the layout
        change_type: ChangeType::parse(&kind).unwrap_or(ChangeType::Updated),
    })
}

impl Store for SqliteStore {
    fn active_program_count(&self, platform: &str) -> Result<usize> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM programs WHERE platform = ?1 AND disabled = 0 AND is_ignored = 0",
            [platform],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    fn ignored_programs(&self, platform: &str) -> Result<HashSet<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT url FROM programs WHERE platform = ?1 AND is_ignored = 1")?;
        let urls = stmt.query_map([platform], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(urls)
    }

    fn upsert_program(
        &self,
        program_url: &str,
        platform: &str,
        handle: &str,
        entries: &[UpsertEntry],
    ) -> Result<Vec<Change>> {
        let now = Utc::now();
        let now_s = ts(now);
        let mut conn = self.conn();
        let tx = conn.transaction()?;

        let program_id: i64 = tx.query_row(
            "INSERT INTO programs(platform, handle, url, first_seen_at, last_seen_at) VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(url) DO UPDATE SET platform = excluded.platform, handle = excluded.handle,
                 last_seen_at = excluded.last_seen_at, disabled = 0
             RETURNING id",
            params![platform, handle, program_url, now_s],
            |r| r.get(0),
        )?;

        let mut existing: HashMap<String, Existing> = HashMap::new();
        {
            let mut stmt = tx.prepare(
                "SELECT id, target, category, COALESCE(description, ''), in_scope, is_bbp FROM targets_raw WHERE program_id = ?1",
            )?;
            let rows = stmt.query_map([program_id], |r| {
                Ok(Existing {
                    id: r.get(0)?,
                    raw: r.get(1)?,
                    category: r.get(2)?,
                    description: r.get(3)?,
                    in_scope: r.get(4)?,
                    is_bbp: r.get(5)?,
                })
            })?;
            for ex in rows {
                let ex = ex?;
                existing.insert(identity_key(&ex.raw, &ex.category), ex);
            }
        }

        if entries.is_empty() && !existing.is_empty() {
            return Err(StorageError::ScopeWipe);
        }

        let change = |kind, raw: &str, norm: &str, category: &str, in_scope, is_bbp| Change {
            occurred_at: now,
            program_url: program_url.to_string(),
            platform: platform.to_string(),
            handle: handle.to_string(),
            target_raw: raw.to_string(),
            target_normalized: norm.to_string(),
            category: category.to_string(),
            in_scope,
            is_bbp,
            change_type: kind,
        };

        let mut changes = Vec::new();
        let mut seen = HashSet::new();
        {
            let mut insert = tx.prepare(
                "INSERT INTO targets_raw(program_id, target, category, description, in_scope, is_bbp, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(program_id, category, target) DO UPDATE SET description = excluded.description,
                     in_scope = excluded.in_scope, is_bbp = excluded.is_bbp, last_seen_at = excluded.last_seen_at",
            )?;
            let mut update = tx.prepare(
                "UPDATE targets_raw SET description = ?1, in_scope = ?2, is_bbp = ?3, last_seen_at = ?4 WHERE id = ?5",
            )?;
            let mut touch = tx.prepare("UPDATE targets_raw SET last_seen_at = ?1 WHERE id = ?2")?;

            for e in entries {
                let key = identity_key(&e.target_raw, &e.category);
                if key.is_empty() || !seen.insert(key.clone()) {
                    continue;
                }
                let desc = (!e.description.is_empty()).then_some(e.description.as_str());
                match existing.get(&key) {
                    None => {
                        insert.execute(params![program_id, e.target_raw, e.category, desc, e.in_scope, e.is_bbp, now_s])?;
                        changes.push(change(ChangeType::Added, &e.target_raw, &e.target_normalized, &e.category, e.in_scope, e.is_bbp));
                    }
                    Some(ex) if ex.description != e.description || ex.in_scope != e.in_scope || ex.is_bbp != e.is_bbp => {
                        update.execute(params![desc, e.in_scope, e.is_bbp, now_s, ex.id])?;
                        changes.push(change(ChangeType::Updated, &e.target_raw, &e.target_normalized, &e.category, e.in_scope, e.is_bbp));
                    }
                    Some(ex) => {
                        touch.execute(params![now_s, ex.id])?;
                    }
                }
            }

            let mut delete = tx.prepare("DELETE FROM targets_raw WHERE id = ?1")?;
            for (key, ex) in &existing {
                if !seen.contains(key) {
                    delete.execute([ex.id])?;
                    changes.push(change(
                        ChangeType::Removed,
                        &ex.raw,
                        &normalize_target(&ex.raw),
                        &ex.category,
                        ex.in_scope,
                        ex.is_bbp,
                    ));
                }
            }
        }
        tx.commit()?;
        Ok(changes)
    }

    fn sync_platform_programs(&self, platform: &str, polled_urls: &[String]) -> Result<Vec<Change>> {
        let polled: HashSet<&str> = polled_urls.iter().map(String::as_str).collect();
        let now = Utc::now();
        let mut conn = self.conn();
        let gone: Vec<(i64, String, String)> = {
            let mut stmt =
                conn.prepare("SELECT id, url, handle FROM programs WHERE platform = ?1 AND disabled = 0 AND is_ignored = 0")?;
            let rows = stmt.query_map([platform], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.filter(|r| r.as_ref().map_or(true, |(_, url, _): &(i64, String, String)| !polled.contains(url.as_str())))
                .collect::<rusqlite::Result<_>>()?
        };

        let tx = conn.transaction()?;
        let mut changes = Vec::with_capacity(gone.len());
        for (id, url, handle) in gone {
            tx.execute("UPDATE programs SET disabled = 1 WHERE id = ?1", [id])?;
            tx.execute("DELETE FROM targets_raw WHERE program_id = ?1", [id])?;
            changes.push(Change {
                occurred_at: now,
                program_url: url.clone(),
                platform: platform.to_string(),
                handle,
                target_normalized: url.clone(),
                target_raw: url,
                category: PROGRAM_CATEGORY.to_string(),
                in_scope: false,
                is_bbp: false,
                change_type: ChangeType::Removed,
            });
        }
        tx.commit()?;
        Ok(changes)
    }

    fn log_changes(&self, changes: &[Change]) -> Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO scope_changes(occurred_at, program_url, platform, handle, target_normalized, target_raw,
                     category, in_scope, is_bbp, change_type) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for c in changes {
                stmt.execute(params![
                    ts(c.occurred_at),
                    c.program_url,
                    c.platform,
                    c.handle,
                    c.target_normalized,
                    c.target_raw,
                    c.category,
                    c.in_scope,
                    c.is_bbp,
                    c.change_type.as_str()
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn set_program_ignored(&self, pattern: &str, ignored: bool) -> Result<usize> {
        Ok(self
            .conn()
            .execute("UPDATE programs SET is_ignored = ?1 WHERE url LIKE ?2", params![ignored, format!("%{pattern}%")])?)
    }

    fn list_entries(&self, opts: &ListOptions) -> Result<Vec<Entry>> {
        let mut sql = String::from(
            "SELECT p.url, p.platform, p.handle, p.strict, t.target, t.category, COALESCE(t.description, ''),
                    t.in_scope, t.is_bbp
             FROM targets_raw t JOIN programs p ON t.program_id = p.id WHERE p.disabled = 0",
        );
        let mut args: Vec<Value> = Vec::new();

        let platforms: Vec<&str> =
            opts.platforms.split(',').map(str::trim).filter(|p| !p.is_empty() && *p != "all").collect();
        if !platforms.is_empty() {
            sql += &format!(" AND p.platform IN ({})", vec!["?"; platforms.len()].join(","));
            args.extend(platforms.iter().map(|p| Value::Text(p.to_string())));
        }
        if !opts.program_filter.is_empty() {
            sql += " AND p.url LIKE ?";
            args.push(Value::Text(format!("%{}%", opts.program_filter)));
        }
        if !opts.include_oos {
            sql += " AND t.in_scope = 1";
        }
        if !opts.include_ignored {
            sql += " AND p.is_ignored = 0";
        }
        if let Some(since) = opts.since {
            sql += " AND t.last_seen_at >= ?";
            args.push(Value::Text(ts(since)));
        }
        match opts.program_type {
            ProgramType::All => {}
            ProgramType::Bbp => sql += " AND EXISTS (SELECT 1 FROM targets_raw t2 WHERE t2.program_id = p.id AND t2.is_bbp = 1)",
            ProgramType::Vdp => {
                sql += " AND NOT EXISTS (SELECT 1 FROM targets_raw t2 WHERE t2.program_id = p.id AND t2.is_bbp = 1)"
            }
        }
        sql += " ORDER BY p.url, t.target";

        let conn = self.conn();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            let raw: String = r.get(4)?;
            Ok(Entry {
                program_url: r.get(0)?,
                platform: r.get(1)?,
                handle: r.get(2)?,
                strict: r.get(3)?,
                target_normalized: normalize_target(&raw),
                target_raw: raw,
                category: r.get(5)?,
                description: r.get(6)?,
                in_scope: r.get(7)?,
                is_bbp: r.get(8)?,
                is_historical: false,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn add_custom_target(&self, target: &str, category: &str, program_url: &str) -> Result<bool> {
        let now_s = ts(Utc::now());
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let program_id: i64 = tx.query_row(
            "INSERT INTO programs(platform, handle, url, first_seen_at, last_seen_at) VALUES ('custom', ?1, ?2, ?3, ?3)
             ON CONFLICT(url) DO UPDATE SET last_seen_at = excluded.last_seen_at, disabled = 0
             RETURNING id",
            params![target, program_url, now_s],
            |r| r.get(0),
        )?;
        let exists = tx
            .query_row(
                "SELECT 1 FROM targets_raw WHERE program_id = ?1 AND category = ?2 AND target = ?3",
                params![program_id, category, target],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        tx.execute(
            "INSERT INTO targets_raw(program_id, target, category, in_scope, is_bbp, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, 1, 0, ?4, ?4)
             ON CONFLICT(program_id, category, target) DO UPDATE SET last_seen_at = excluded.last_seen_at",
            params![program_id, target, category, now_s],
        )?;
        tx.commit()?;
        Ok(!exists)
    }

    fn recent_changes(
        &self,
        limit: usize,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
    ) -> Result<Vec<Change>> {
        let mut sql = String::from(
            "SELECT occurred_at, program_url, platform, handle, target_normalized, target_raw, category, in_scope, is_bbp,
                    NULL, change_type FROM scope_changes WHERE 1=1",
        );
        let mut args: Vec<Value> = Vec::new();
        if let Some(s) = since {
            sql += " AND occurred_at >= ?";
            args.push(Value::Text(ts(s)));
        }
        if let Some(u) = until {
            sql += " AND occurred_at <= ?";
            args.push(Value::Text(ts(u)));
        }
        sql += " ORDER BY occurred_at DESC, id DESC LIMIT ?";
        args.push(Value::Integer(if limit == 0 { -1 } else { limit as i64 }));

        let conn = self.conn();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), change_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn stats(&self) -> Result<Vec<PlatformStats>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT p.platform, COUNT(DISTINCT p.id),
                    SUM(CASE WHEN t.in_scope = 1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN t.in_scope = 0 THEN 1 ELSE 0 END)
             FROM programs p JOIN targets_raw t ON p.id = t.program_id
             WHERE p.is_ignored = 0 AND p.disabled = 0
             GROUP BY p.platform ORDER BY p.platform",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(PlatformStats {
                platform: r.get(0)?,
                programs: r.get::<_, i64>(1)? as u64,
                in_scope: r.get::<_, i64>(2)? as u64,
                out_of_scope: r.get::<_, i64>(3)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    fn search(&self, term: &str) -> Result<Vec<Entry>> {
        let like = format!("%{term}%");
        let conn = self.conn();
        let mut out = Vec::new();
        let mut current = HashSet::new();

        let mut stmt = conn.prepare(
            "SELECT p.url, p.platform, p.handle, t.target, t.category, COALESCE(t.description, ''), t.in_scope, t.is_bbp
             FROM targets_raw t JOIN programs p ON t.program_id = p.id
             WHERE p.is_ignored = 0 AND (t.target LIKE ?1 OR t.description LIKE ?1 OR p.url LIKE ?1)
             ORDER BY p.url, t.target",
        )?;
        let rows = stmt.query_map([&like], |r| {
            let raw: String = r.get(3)?;
            Ok(Entry {
                program_url: r.get(0)?,
                platform: r.get(1)?,
                handle: r.get(2)?,
                target_normalized: normalize_target(&raw),
                target_raw: raw,
                category: r.get(4)?,
                description: r.get(5)?,
                in_scope: r.get(6)?,
                is_bbp: r.get(7)?,
                ..Default::default()
            })
        })?;
        for e in rows {
            let e = e?;
            current.insert(format!("{}|{}|{}", e.program_url, e.target_normalized, e.category));
            out.push(e);
        }

        // Historical: targets seen in the change log that are no longer current.
        let mut stmt = conn.prepare(
            "SELECT DISTINCT program_url, platform, handle, target_raw, category, in_scope, is_bbp
             FROM scope_changes
             WHERE category != 'program' AND (target_normalized LIKE ?1 OR target_raw LIKE ?1 OR program_url LIKE ?1)
             ORDER BY program_url, target_raw",
        )?;
        let rows = stmt.query_map([&like], |r| {
            let raw: String = r.get(3)?;
            Ok(Entry {
                program_url: r.get(0)?,
                platform: r.get(1)?,
                handle: r.get(2)?,
                target_normalized: normalize_target(&raw),
                target_raw: raw,
                category: r.get(4)?,
                in_scope: r.get(5)?,
                is_bbp: r.get(6)?,
                is_historical: true,
                ..Default::default()
            })
        })?;
        for e in rows {
            let e = e?;
            if current.insert(format!("{}|{}|{}", e.program_url, e.target_normalized, e.category)) {
                out.push(e);
            }
        }
        Ok(out)
    }

    fn shell_command(&self) -> Option<(String, Vec<String>)> {
        (self.path != ":memory:").then(|| ("sqlite3".to_string(), vec![self.path.clone()]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_entries, Store};
    use bbscope_core::{ProgramData, ScopeElement};

    fn pd(targets: &[(&str, &str, bool)]) -> ProgramData {
        let mut pd = ProgramData::new("https://hackerone.com/acme");
        for (t, c, in_scope) in targets {
            let e = ScopeElement::new(*t, "", *c);
            if *in_scope { pd.in_scope.push(e) } else { pd.out_of_scope.push(e) }
        }
        pd
    }

    fn upsert(db: &SqliteStore, p: &ProgramData) -> Result<Vec<Change>> {
        db.upsert_program(&p.url, "h1", "acme", &build_entries(p))
    }

    fn kinds(ch: &[Change]) -> Vec<(ChangeType, String)> {
        let mut v: Vec<_> = ch.iter().map(|c| (c.change_type, c.target_raw.clone())).collect();
        v.sort_by(|a, b| a.1.cmp(&b.1));
        v
    }

    #[test]
    fn change_tracking() {
        let db = SqliteStore::open(":memory:").unwrap();
        let first = upsert(&db, &pd(&[("*.acme.com", "wildcard", true), ("https://app.acme.com", "url", true)])).unwrap();
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|c| c.change_type == ChangeType::Added));

        // Same scope again: nothing changes.
        assert!(upsert(&db, &pd(&[("*.acme.com", "wildcard", true), ("https://app.acme.com", "url", true)]))
            .unwrap()
            .is_empty());

        // One removed, one moved out of scope, one added.
        let ch = upsert(&db, &pd(&[("*.acme.com", "wildcard", false), ("api.acme.com", "url", true)])).unwrap();
        assert_eq!(
            kinds(&ch),
            vec![
                (ChangeType::Updated, "*.acme.com".into()),
                (ChangeType::Added, "api.acme.com".into()),
                (ChangeType::Removed, "https://app.acme.com".into()),
            ]
        );

        // Empty scope never wipes a program.
        assert!(matches!(upsert(&db, &pd(&[])), Err(StorageError::ScopeWipe)));

        let entries = db.list_entries(&ListOptions::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].target_normalized, "api.acme.com");
        assert_eq!(db.list_entries(&ListOptions { include_oos: true, ..Default::default() }).unwrap().len(), 2);
        assert_eq!(db.stats().unwrap()[0], PlatformStats { platform: "h1".into(), programs: 1, in_scope: 1, out_of_scope: 1 });
    }

    #[test]
    fn programs_lifecycle_and_history() {
        let db = SqliteStore::open(":memory:").unwrap();
        let p = pd(&[("old.acme.com", "url", true)]);
        db.log_changes(&upsert(&db, &p).unwrap()).unwrap();
        db.log_changes(&upsert(&db, &pd(&[("new.acme.com", "url", true)])).unwrap()).unwrap();
        assert_eq!(db.active_program_count("h1").unwrap(), 1);

        let hits = db.search("acme.com").unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|e| e.target_raw == "old.acme.com" && e.is_historical));
        assert!(hits.iter().any(|e| e.target_raw == "new.acme.com" && !e.is_historical));

        assert_eq!(db.set_program_ignored("acme", true).unwrap(), 1);
        assert!(db.ignored_programs("h1").unwrap().contains(&p.url));
        assert_eq!(db.active_program_count("h1").unwrap(), 0);
        db.set_program_ignored("acme", false).unwrap();

        let removed = db.sync_platform_programs("h1", &[]).unwrap();
        assert_eq!(removed.len(), 1);
        assert!(removed[0].is_program_removal());
        assert_eq!(db.active_program_count("h1").unwrap(), 0);
        assert!(db.list_entries(&ListOptions::default()).unwrap().is_empty());

        db.log_changes(&removed).unwrap();
        let recent = db.recent_changes(2, None, None).unwrap();
        assert_eq!(recent.len(), 2);
        assert!(recent[0].is_program_removal());
    }

    #[test]
    fn custom_targets() {
        let db = SqliteStore::open(":memory:").unwrap();
        assert!(db.add_custom_target("*.mine.com", "wildcard", "custom").unwrap());
        assert!(!db.add_custom_target("*.mine.com", "wildcard", "custom").unwrap());
        let es = db.list_entries(&ListOptions { platforms: "custom".into(), ..Default::default() }).unwrap();
        assert_eq!(es.len(), 1);
    }
}
