//! `bbscope poll [platform]`

use std::io::Write;

use anyhow::{bail, Result};
use bbscope_core::output::LineFormat;
use bbscope_core::{Change, ChangeType, Platform, PollOptions};
use clap::{Args, Subcommand};

use crate::Ctx;

#[derive(Args)]
pub struct PollCmd {
    #[command(flatten)]
    common: CommonArgs,

    /// Platform to poll
    #[command(subcommand)]
    platform: PlatformCmd,
}

#[derive(Args)]
struct CommonArgs {
    /// Categories to include: wildcard, url, cidr, android, ios, mobile, ai, hardware, blockchain, binary, code, other, all
    #[arg(long, global = true, default_value = "all")]
    category: String,

    /// Save results to the database and print changes since the last poll
    #[arg(long, global = true)]
    db: bool,

    /// Concurrent program fetches per platform
    #[arg(long, global = true, default_value_t = bbscope_poll::DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Include out-of-scope elements
    #[arg(long, global = true)]
    oos: bool,

    /// Output fields: t (target), d (description), c (category), u (program URL)
    #[arg(short = 'o', long, global = true, default_value = "tu")]
    output: String,

    /// Delimiter between output fields
    #[arg(short = 'd', long, global = true, default_value = " ")]
    delimiter: String,

    /// Only programs offering monetary rewards
    #[arg(short = 'b', long, global = true)]
    bbp_only: bool,

    /// Only private programs
    #[arg(short = 'p', long, global = true)]
    private_only: bool,
}

#[derive(Subcommand)]
enum PlatformCmd {
    /// Poll HackerOne
    H1 {
        /// HackerOne username
        #[arg(short = 'u', long, required = true)]
        user: String,
        /// HackerOne API token
        #[arg(short = 't', long, required = true)]
        token: String,
    },
    /// Poll Bugcrowd
    Bc {
        /// Fetch only public programs, without authentication
        #[arg(long)]
        public_only: bool,
        /// _bugcrowd_session cookie value (or a full Cookie header)
        #[arg(short = 't', long)]
        token: Option<String>,
        #[command(flatten)]
        login: LoginArgs,
    },
    /// Poll Intigriti
    It {
        /// Intigriti API token
        #[arg(short = 't', long, required = true)]
        token: String,
    },
    /// Poll YesWeHack (public programs work without credentials)
    Ywh {
        /// YesWeHack bearer token
        #[arg(short = 't', long)]
        token: Option<String>,
        #[command(flatten)]
        login: LoginArgs,
    },
    /// Poll Immunefi (no authentication)
    Immunefi,
}

#[derive(Args)]
struct LoginArgs {
    /// Login email
    #[arg(short = 'E', long)]
    email: Option<String>,
    /// Login password
    #[arg(short = 'P', long)]
    password: Option<String>,
    /// TOTP secret (base32 or otpauth:// URI)
    #[arg(short = 'O', long)]
    otp_secret: Option<String>,
}

impl LoginArgs {
    fn credentials(&self) -> bbscope_platforms::Credentials {
        bbscope_platforms::Credentials {
            email: self.email.clone().unwrap_or_default(),
            password: self.password.clone().unwrap_or_default(),
            otp_secret: self.otp_secret.clone().unwrap_or_default(),
        }
    }
}

pub async fn run(ctx: &Ctx, cmd: PollCmd) -> Result<()> {
    let c = &cmd.common;
    let format = LineFormat::parse(&c.output, &c.delimiter)?;
    let opts = PollOptions { bounty_only: c.bbp_only, private_only: c.private_only, categories: c.category.clone() };

    let platforms = vec![build(ctx, &cmd.platform).await?];

    if c.db {
        poll_into_db(ctx, &platforms, &opts, c.concurrency).await
    } else {
        print_scopes(&platforms, &opts, c.concurrency, &format, c.oos).await
    }
}

async fn print_scopes(
    platforms: &[Box<dyn Platform>],
    opts: &PollOptions,
    concurrency: usize,
    format: &LineFormat,
    oos: bool,
) -> Result<()> {
    for p in platforms {
        tracing::info!("Fetching scope from {}...", p.name());
        let stdout = std::io::stdout();
        bbscope_poll::fetch_all(p.as_ref(), opts, concurrency, |handle, res| match res {
            Ok(pd) => {
                let mut out = stdout.lock();
                for line in format.program_lines(&pd, oos) {
                    let _ = writeln!(out, "{line}");
                }
            }
            Err(e) => tracing::warn!("Failed to fetch scope for {handle}: {e}"),
        })
        .await?;
    }
    Ok(())
}

async fn poll_into_db(ctx: &Ctx, platforms: &[Box<dyn Platform>], opts: &PollOptions, concurrency: usize) -> Result<()> {
    let store = ctx.store()?;
    let mut failed = 0;
    for p in platforms {
        tracing::info!("Fetching scope from {}...", p.name());
        let report = bbscope_poll::poll_platform(p.as_ref(), store.as_ref(), opts, concurrency, |_, changes, first_run| {
            if !first_run {
                print_changes(changes);
            }
        })
        .await?;
        if !report.first_run {
            print_changes(&report.removed_programs);
        }
        tracing::info!(
            "{}: {} programs, {} changes{}",
            p.name(),
            report.polled_urls.len(),
            report.changes.len() + report.removed_programs.len(),
            if report.first_run { " (first run, not logged)" } else { "" }
        );
        failed += report.errors.len();
    }
    if failed > 0 {
        bail!("{failed} program(s) failed to fetch or store");
    }
    Ok(())
}

pub fn print_changes(changes: &[Change]) {
    let mut out = std::io::stdout().lock();
    for c in changes {
        if c.is_program_removal() {
            let _ = writeln!(out, "❌ Program removed: {}", c.program_url);
            continue;
        }
        let icon = match c.change_type {
            ChangeType::Added => "🆕",
            ChangeType::Removed => "❌",
            ChangeType::Updated => "🔄",
        };
        let target = if c.target_raw.is_empty() { &c.target_normalized } else { &c.target_raw };
        let oos = if c.in_scope { "" } else { " [OOS]" };
        let _ = writeln!(out, "{icon}  {}  {}  {target}{oos}", c.platform, c.program_url);
    }
}

/// Builds the platform named on the command line.
async fn build(ctx: &Ctx, cmd: &PlatformCmd) -> Result<Box<dyn Platform>> {
    let http = ctx.http()?;
    #[allow(unused_variables)]
    let platform: Box<dyn Platform> = match cmd {
        #[cfg(feature = "hackerone")]
        PlatformCmd::H1 { user, token } => Box::new(bbscope_platforms::hackerone::HackerOne::new(http, user, token)),
        #[cfg(feature = "bugcrowd")]
        PlatformCmd::Bc { public_only, token, login } => {
            use bbscope_platforms::bugcrowd::Bugcrowd;
            let creds = login.credentials();
            if *public_only {
                Box::new(Bugcrowd::public(http))
            } else if let Some(token) = token.as_deref().filter(|t| !t.is_empty()) {
                Box::new(Bugcrowd::with_token(http, token))
            } else if creds.is_complete() {
                Box::new(Bugcrowd::login(http, &creds).await?)
            } else {
                bail!("Bugcrowd requires --token, --email + --password + --otp-secret, or --public-only");
            }
        }
        #[cfg(feature = "intigriti")]
        PlatformCmd::It { token } => Box::new(bbscope_platforms::intigriti::Intigriti::new(http, token.clone())),
        #[cfg(feature = "yeswehack")]
        PlatformCmd::Ywh { token, login } => {
            use bbscope_platforms::yeswehack::YesWeHack;
            let creds = login.credentials();
            if let Some(token) = token.as_deref().filter(|t| !t.is_empty()) {
                Box::new(YesWeHack::with_token(http, token))
            } else if creds.is_empty() {
                tracing::info!("No YesWeHack credentials provided; polling public programs only");
                Box::new(YesWeHack::with_token(http, ""))
            } else if creds.is_complete() {
                Box::new(YesWeHack::login(http, &creds).await?)
            } else {
                bail!("YesWeHack login requires --email + --password + --otp-secret (or use --token)");
            }
        }
        #[cfg(feature = "immunefi")]
        PlatformCmd::Immunefi => Box::new(bbscope_platforms::immunefi::Immunefi::new(http)),
        #[allow(unreachable_patterns)]
        _ => bail!("this platform was not compiled into this build of bbscope"),
    };
    Ok(platform)
}
