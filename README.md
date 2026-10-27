# bbscope (Rust)

A Rust rewrite of [sw33tLie/bbscope](https://github.com/sw33tLie/bbscope): collect bug bounty
scopes from HackerOne, Bugcrowd, Intigriti, YesWeHack and Immunefi, and track how they change.

## Build

```sh
cargo build --release          # binary: target/release/bbscope
cargo test --workspace
```

Build only some platforms:

```sh
cargo build --release -p bbscope-cli --no-default-features --features hackerone,intigriti
```

## Usage

```sh
# Print scopes (no database). Credentials are passed as flags; there is no config file.
bbscope poll h1 -u USER -t TOKEN
bbscope poll bc --public-only -o tdcu -d ","
bbscope poll bc -E EMAIL -P PASSWORD -O TOTP_SECRET     # or: -t SESSION_COOKIE
bbscope poll it -t TOKEN
bbscope poll ywh                       # public programs, no login needed
bbscope poll ywh -E EMAIL -P PASSWORD -O TOTP_SECRET    # or: -t TOKEN
bbscope poll immunefi --category blockchain

# Track changes in a database (default ~/.bbscope.db, override with --db-url or DB_URL)
bbscope poll h1 -u USER -t TOKEN --db  # first run fills the DB, later runs print changes
bbscope db changes --since 7d
bbscope db print --platform h1,bc --format json
bbscope db find example.com
bbscope db get wildcards -a -o tu
bbscope db get domains | urls | ips | cidrs
bbscope db add -t "*.mine.com,api.other.com" -c wildcard
bbscope db ignore -u hackerone.com/noisy-program
bbscope db stats
bbscope db shell                       # needs sqlite3 on PATH
```

The v1 shortcut `bbscope h1 ...` still works and is rewritten to `bbscope poll h1 ...`.

Global flags: `--proxy http://127.0.0.1:8080`, `-l debug`, `--debug-http`, `--db-url`.

Poll flags (before or after the platform): `--db`, `--category`, `--concurrency`, `--oos`,
`-o tdcu`, `-d DELIM`, `-b` (bounty only), `-p` (private only).

## Layout

```
crates/
  bbscope-core       models, Platform trait, HTTP client, normalization, categories, TOTP, output
  bbscope-platforms  one module per platform, each behind a cargo feature
  bbscope-targets    wildcard / domain / URL / IP / CIDR extraction
  bbscope-storage    Store trait + SQLite backend with change tracking
  bbscope-poll       concurrent polling engine (any Platform x any Store)
  bbscope-cli        the `bbscope` binary (clap)
```

Dependencies only point downward: platforms, targets and storage depend on core; poll depends
on core + storage; the CLI wires everything together.

### Adding a platform

1. Add `crates/bbscope-platforms/src/<name>.rs` with a struct implementing
   `bbscope_core::Platform` (`name`, `list_program_handles`, `fetch_program_scope`).
2. Register the module and a feature in `bbscope-platforms` (`lib.rs`, `Cargo.toml`).
3. Add a subcommand in `crates/bbscope-cli/src/poll.rs`.

The poll engine, storage and `db` commands work with it unchanged.

### Adding a storage backend

Implement `bbscope_storage::Store` and dispatch to it from `bbscope_storage::open` based on the
connection string.

## Differences from the Go version

- No `~/.bbscope.yaml`: credentials are command-line flags, and `bbscope poll` needs a platform
  subcommand (it no longer polls "every configured platform").
- Storage is SQLite (a single local file) instead of PostgreSQL. `postgres://` URLs are rejected
  with a clear error; the `Store` trait is the place to add a Postgres backend.
- Not ported: the web UI (`serve`), `reports`, the `dev` platform and AI-assisted normalization (`--ai`).
- When some programs fail to fetch during `poll --db`, removed-program detection is skipped for that
  run instead of reporting the failed programs as removed.
- `db print --platform` and `db get --platform` accept comma-separated lists.
- `db print --format csv` writes properly quoted CSV.
