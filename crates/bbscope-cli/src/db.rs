//! `bbscope db ...`

use std::io::Write;

use anyhow::{bail, Context, Result};
use bbscope_core::normalize::aggressive_transform;
use bbscope_core::output::{Field, LineFormat};
use bbscope_core::Entry;
use bbscope_storage::ListOptions;
use bbscope_targets::{Kind, WildcardOptions};
use chrono::{DateTime, Duration, Local, NaiveDate, NaiveTime, TimeZone, Utc};
use clap::{Args, Subcommand, ValueEnum};

use crate::Ctx;

#[derive(Args)]
pub struct DbCmd {
    #[command(subcommand)]
    command: DbCommand,
}

#[derive(Subcommand)]
enum DbCommand {
    /// Programs and targets per platform
    Stats,
    /// Recent scope changes
    #[command(long_about = "Recent scope changes.\n\nTime formats for --since/--until: today, yesterday, 7d, 30d, 90d, 1y, or YYYY-MM-DD")]
    Changes {
        /// Number of changes to show (0 = all)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
    },
    /// Print stored scope
    Print {
        /// Comma-separated platforms (h1,bc,it,ywh,immunefi,custom) or 'all'
        #[arg(long, default_value = "all")]
        platform: String,
        /// Filter by program handle or URL substring
        #[arg(long, default_value = "")]
        program: String,
        /// Include out-of-scope elements
        #[arg(long)]
        oos: bool,
        /// Only targets seen since this RFC3339 timestamp
        #[arg(long)]
        since: Option<String>,
        #[arg(long, value_enum, default_value_t = Format::Txt)]
        format: Format,
        /// Delimiter between fields (txt)
        #[arg(short = 'd', long, default_value = " ")]
        delimiter: String,
        /// Fields (txt): t (target), d (description), c (category), u (program URL)
        #[arg(short = 'o', long, default_value = "tu")]
        output: String,
        /// Include ignored programs
        #[arg(long)]
        include_ignored: bool,
    },
    /// Search current and historical scopes
    Find { query: String },
    /// Add custom targets
    Add {
        /// Target(s), comma-separated
        #[arg(short = 't', long, required = true)]
        target: String,
        #[arg(short = 'c', long, default_value = "wildcard")]
        category: String,
        #[arg(short = 'u', long, default_value = "custom")]
        program_url: String,
    },
    /// Skip programs matching a URL pattern during polling
    Ignore {
        #[arg(short = 'u', long, required = true)]
        program_url: String,
    },
    /// Stop ignoring programs matching a URL pattern
    Unignore {
        #[arg(short = 'u', long, required = true)]
        program_url: String,
    },
    /// Extract specific target types
    Get(GetCmd),
    /// Open a database shell (sqlite3)
    Shell,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Txt,
    Json,
    Csv,
}

#[derive(Args)]
struct GetCmd {
    /// Limit to platforms (comma-separated) or 'all'
    #[arg(long, global = true, default_value = "all")]
    platform: String,
    #[command(subcommand)]
    kind: GetKind,
}

#[derive(Subcommand)]
enum GetKind {
    /// Root domains for subdomain enumeration
    Wildcards {
        /// Also extract root domains from plain domain and URL targets
        #[arg(short = 'a', long)]
        aggressive: bool,
        /// Fields: t (domain), u (program URL)
        #[arg(short = 'o', long, default_value = "t")]
        output: String,
        #[arg(short = 'd', long, default_value = " ")]
        delimiter: String,
    },
    /// Domains (including wildcards)
    Domains {
        /// Turn every domain into a root-domain wildcard
        #[arg(short = 'a', long)]
        aggressive: bool,
    },
    /// http(s) URLs
    Urls,
    /// IP addresses
    Ips,
    /// CIDR and IP ranges
    Cidrs,
}

pub fn run(ctx: &Ctx, cmd: DbCmd) -> Result<()> {
    let store = ctx.store()?;
    let mut out = std::io::stdout().lock();
    match cmd.command {
        DbCommand::Stats => {
            let stats = store.stats()?;
            if stats.is_empty() {
                println!("No data in the database to generate stats.");
                return Ok(());
            }
            let row = |a: &str, b: String, c: String, d: String| format!("{a:>10}   {b:>9}   {c:>9}   {d:>12}");
            writeln!(out, "{}", row("PLATFORM", "PROGRAMS".into(), "IN-SCOPE".into(), "OUT-OF-SCOPE".into()))?;
            let (mut p, mut i, mut o) = (0, 0, 0);
            for s in &stats {
                writeln!(out, "{}", row(&s.platform, s.programs.to_string(), s.in_scope.to_string(), s.out_of_scope.to_string()))?;
                (p, i, o) = (p + s.programs, i + s.in_scope, o + s.out_of_scope);
            }
            writeln!(out)?;
            writeln!(out, "{}", row("TOTAL", p.to_string(), i.to_string(), o.to_string()))?;
        }

        DbCommand::Changes { limit, since, until } => {
            let since = since.as_deref().map(|s| parse_time(s, false)).transpose().context("invalid --since")?;
            let until = until.as_deref().map(|s| parse_time(s, true)).transpose().context("invalid --until")?;
            for c in store.recent_changes(limit, since, until)? {
                let ts = c.occurred_at.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S");
                let kind = c.change_type.as_str();
                if c.is_program_removal() {
                    writeln!(out, "{ts}  {kind:<7}  {}  Program removed: {}", c.platform, c.program_url)?;
                    continue;
                }
                let target = if c.target_raw.is_empty() { &c.target_normalized } else { &c.target_raw };
                let oos = if c.in_scope { "" } else { " [OOS]" };
                writeln!(out, "{ts}  {kind:<7}  {}  {}  {target}{oos}", c.platform, c.program_url)?;
            }
        }

        DbCommand::Print { platform, program, oos, since, format, delimiter, output, include_ignored } => {
            let since = since
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|d| d.with_timezone(&Utc)))
                .transpose()
                .context("invalid --since, need RFC3339 (e.g. 2024-01-31T00:00:00Z)")?;
            let entries = store.list_entries(&ListOptions {
                platforms: platform,
                program_filter: program,
                since,
                include_oos: oos,
                include_ignored,
                ..Default::default()
            })?;
            match format {
                Format::Txt => {
                    let fmt = LineFormat::parse(&output, &delimiter)?;
                    for e in &entries {
                        let line = fmt.line(&e.target_normalized, &e.description, &e.category, &e.program_url);
                        if e.in_scope {
                            writeln!(out, "{line}")?;
                        } else {
                            writeln!(out, "[OOS] {line}")?;
                        }
                    }
                }
                Format::Json => {
                    let rows: Vec<_> = entries.iter().map(entry_json).collect();
                    writeln!(out, "{}", serde_json::to_string(&rows)?)?;
                }
                Format::Csv => {
                    let mut w = csv::Writer::from_writer(out);
                    w.write_record(["program_url", "platform", "handle", "target", "category", "description", "in_scope"])?;
                    for e in &entries {
                        w.write_record([
                            &e.program_url,
                            &e.platform,
                            &e.handle,
                            &e.target_normalized,
                            &e.category,
                            &e.description,
                            &e.in_scope.to_string(),
                        ])?;
                    }
                    w.flush()?;
                }
            }
        }

        DbCommand::Find { query } => {
            let results = store.search(&query)?;
            if results.is_empty() {
                println!("No results found.");
            }
            for e in results {
                let status = if e.in_scope { "in-scope" } else { "out-of-scope" };
                let hist = if e.is_historical { " (historical)" } else { "" };
                writeln!(out, "{} | {} | {} ({status}){hist}", e.platform, e.program_url, e.target_normalized)?;
            }
        }

        DbCommand::Add { target, category, program_url } => {
            for t in target.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                match store.add_custom_target(t, &category, &program_url) {
                    Ok(true) => writeln!(out, "Successfully added target: {t}")?,
                    Ok(false) => writeln!(out, "Target already exists, refreshed timestamp: {t}")?,
                    Err(e) => eprintln!("Error adding target {t}: {e}"),
                }
            }
        }

        DbCommand::Ignore { program_url } => set_ignored(store.as_ref(), &program_url, true)?,
        DbCommand::Unignore { program_url } => set_ignored(store.as_ref(), &program_url, false)?,

        DbCommand::Get(get) => {
            let include_oos = matches!(get.kind, GetKind::Wildcards { .. });
            let mut entries = store.list_entries(&ListOptions { platforms: get.platform, include_oos, ..Default::default() })?;
            match get.kind {
                GetKind::Wildcards { aggressive, output, delimiter } => {
                    let fmt = LineFormat::parse_with(if output.is_empty() { "t" } else { &output }, &delimiter, "tu")?;
                    let per_program = fmt.fields.contains(&Field::ProgramUrl);
                    for r in bbscope_targets::collect_wildcards(&entries, WildcardOptions { aggressive }) {
                        if per_program {
                            for url in &r.program_urls {
                                writeln!(out, "{}", fmt.line(&r.domain, "", "", url))?;
                            }
                        } else {
                            writeln!(out, "{}", fmt.line(&r.domain, "", "", ""))?;
                        }
                    }
                }
                kind => {
                    let kind = match kind {
                        GetKind::Domains { aggressive } => {
                            if aggressive {
                                transform_all(&mut entries);
                            }
                            Kind::Domains
                        }
                        GetKind::Urls => Kind::Urls,
                        GetKind::Ips => Kind::Ips,
                        GetKind::Cidrs => Kind::Cidrs,
                        GetKind::Wildcards { .. } => unreachable!(),
                    };
                    for t in bbscope_targets::collect(&entries, kind, true) {
                        writeln!(out, "{t}")?;
                    }
                }
            }
        }

        DbCommand::Shell => {
            let Some((program, args)) = store.shell_command() else {
                bail!("this database backend has no interactive shell");
            };
            println!("bbscope database schema:");
            println!("  programs      (id, platform, handle, url, strict, disabled, is_ignored, first_seen_at, last_seen_at)");
            println!("  targets_raw   (id, program_id, target, category, description, in_scope, is_bbp, first_seen_at, last_seen_at)");
            println!("  scope_changes (id, occurred_at, program_url, platform, handle, target_normalized, target_raw, category, in_scope, is_bbp, change_type)");
            println!();
            let status = std::process::Command::new(&program)
                .args(&args)
                .status()
                .with_context(|| format!("running {program} (is it installed and on PATH?)"))?;
            if !status.success() {
                bail!("{program} exited with {status}");
            }
        }
    }
    Ok(())
}

fn set_ignored(store: &dyn bbscope_storage::Store, pattern: &str, ignored: bool) -> Result<()> {
    if store.set_program_ignored(pattern, ignored)? == 0 {
        bail!("no program found matching URL pattern: {pattern}");
    }
    println!("✅ Successfully {} programs matching: {pattern}", if ignored { "ignored" } else { "unignored" });
    Ok(())
}

fn transform_all(entries: &mut [Entry]) {
    for e in entries {
        e.target_normalized = aggressive_transform(&e.target_normalized);
    }
}

fn entry_json(e: &Entry) -> serde_json::Value {
    serde_json::json!({
        "program_url": e.program_url,
        "platform": e.platform,
        "handle": e.handle,
        "target": e.target_normalized,
        "category": e.category,
        "description": e.description,
        "in_scope": e.in_scope,
    })
}

/// `today`, `yesterday`, `7d`, `30d`, `90d`, `1y` or `YYYY-MM-DD` (local time).
/// With `end_of_day`, a plain date means the end of that day.
fn parse_time(s: &str, end_of_day: bool) -> Result<DateTime<Utc>> {
    let s = s.trim();
    let now = Local::now();
    let midnight = |d: NaiveDate| -> Result<DateTime<Utc>> {
        Local
            .from_local_datetime(&d.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap_or_default()))
            .earliest()
            .map(|t| t.with_timezone(&Utc))
            .context("invalid local time")
    };
    let t = match s {
        "today" => midnight(now.date_naive())?,
        "yesterday" => midnight(now.date_naive() - Duration::days(1))?,
        "7d" => (now - Duration::days(7)).with_timezone(&Utc),
        "30d" => (now - Duration::days(30)).with_timezone(&Utc),
        "90d" => (now - Duration::days(90)).with_timezone(&Utc),
        "1y" => (now - Duration::days(365)).with_timezone(&Utc),
        _ => {
            let d = NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .context("use today, yesterday, 7d, 30d, 90d, 1y, or YYYY-MM-DD")?;
            let start = midnight(d)?;
            return Ok(if end_of_day { start + Duration::seconds(86_399) } else { start });
        }
    };
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let a = parse_time("2024-03-01", false).unwrap();
        let b = parse_time("2024-03-01", true).unwrap();
        assert_eq!((b - a).num_seconds(), 86_399);
        assert!(parse_time("7d", false).unwrap() < Utc::now());
        assert!(parse_time("nope", false).is_err());
    }
}
