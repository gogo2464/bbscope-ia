mod db;
mod poll;

use anyhow::Result;
use clap::{Parser, Subcommand};

const LOGO: &str = r"
	 _     _
	| |__ | |__  ___  ___ ___  _ __   ___
	| '_ \| '_ \/ __|/ __/ _ \| '_ \ / _ \
	| |_) | |_) \__ \ (_| (_) | |_) |  __/
	|_.__/|_.__/|___/\___\___/| .__/ \___|
	                          |_|        rust
";

#[derive(Parser)]
#[command(
    name = "bbscope",
    version,
    about = "A scope aggregator for bug bounty hunters.",
    long_about = format!("{LOGO}\nbbscope collects bug bounty program scopes from HackerOne, Bugcrowd,\nIntigriti, YesWeHack and Immunefi, and tracks how they change over time.")
)]
pub struct Cli {
    /// HTTP proxy, e.g. http://127.0.0.1:8080 (TLS verification is disabled)
    #[arg(long, global = true)]
    proxy: Option<String>,

    /// Log level: debug, info, warn, error
    #[arg(short = 'l', long, global = true, default_value = "info")]
    loglevel: String,

    /// Print every HTTP request and response
    #[arg(long, global = true)]
    debug_http: bool,

    /// Database location (SQLite file path). Default: ~/.bbscope.db
    #[arg(long, global = true, env = "DB_URL")]
    db_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Poll platforms and fetch scopes
    Poll(poll::PollCmd),
    /// Query and manage the scope database
    Db(db::DbCmd),
}

/// Global settings every command gets.
pub struct Ctx {
    pub proxy: Option<String>,
    pub debug_http: bool,
    pub db_url: Option<String>,
}

impl Ctx {
    pub fn http(&self) -> Result<bbscope_core::HttpClient> {
        Ok(bbscope_core::HttpClient::new(bbscope_core::HttpConfig {
            proxy: self.proxy.clone(),
            debug: self.debug_http,
            ..Default::default()
        })?)
    }

    pub fn store(&self) -> Result<Box<dyn bbscope_storage::Store>> {
        let url = match self.db_url.as_deref().filter(|u| !u.is_empty()) {
            Some(u) => u.to_string(),
            None => {
                let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory; pass --db-url"))?;
                home.join(".bbscope.db").to_string_lossy().into_owned()
            }
        };
        tracing::debug!("Using database {url}");
        Ok(bbscope_storage::open(&url)?)
    }
}

/// `bbscope h1 ...` (v1 syntax) -> `bbscope poll h1 ...`.
fn rewrite_legacy_args(mut args: Vec<String>) -> Vec<String> {
    if let Some(first) = args.get(1) {
        if ["h1", "bc", "it", "ywh", "immunefi"].contains(&first.as_str()) {
            eprintln!("warning: 'bbscope {first}' is deprecated, running 'bbscope poll {first}' instead.");
            args.insert(1, "poll".into());
        }
    }
    args
}

fn init_logging(level: &str) -> Result<()> {
    let level = match level.to_lowercase().as_str() {
        "debug" => "debug",
        "info" => "info",
        "warn" | "warning" => "warn",
        "error" | "fatal" => "error",
        other => anyhow::bail!("bad log level '{other}' (use debug, info, warn or error)"),
    };
    let ours = ["bbscope", "bbscope_core", "bbscope_platforms", "bbscope_poll", "bbscope_storage", "bbscope_targets"];
    let directives: Vec<String> = ours.iter().map(|c| format!("{c}={level}")).collect();
    let filter = tracing_subscriber::EnvFilter::new(format!("warn,{}", directives.join(",")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(false)
        .init();
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    init_logging(&cli.loglevel)?;
    let ctx = Ctx {
        proxy: cli.proxy,
        debug_http: cli.debug_http,
        db_url: cli.db_url,
    };
    match cli.command {
        Command::Poll(cmd) => poll::run(&ctx, cmd).await,
        Command::Db(cmd) => db::run(&ctx, cmd),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse_from(rewrite_legacy_args(std::env::args().collect()));
    if let Err(e) = run(cli).await {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn legacy_args() {
        let a = rewrite_legacy_args(["bbscope", "h1", "-u", "me", "-t", "tok", "-b"].map(String::from).to_vec());
        assert_eq!(a[..3], ["bbscope", "poll", "h1"]);
        let cli = Cli::try_parse_from(&a).unwrap();
        assert!(matches!(cli.command, Command::Poll(_)));
    }
}
