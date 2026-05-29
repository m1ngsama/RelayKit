use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use relaykit_server::{plan_server, run_server, ServerConfig};

#[path = "../common.rs"]
mod common;

#[derive(Debug, Parser)]
#[command(name = "relaykitd")]
#[command(about = "Run the self-hosted RelayKit relay daemon")]
#[command(version)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,

    #[arg(long)]
    public_url: Option<String>,

    #[arg(long, env = "RELAYKIT_OPERATOR_TOKEN")]
    operator_token: Option<String>,

    #[arg(
        long,
        help = "Allow unauthenticated operator APIs for loopback-only local development"
    )]
    insecure_no_operator_auth: bool,

    #[arg(long, env = "RELAYKIT_ARTIFACT_DIR")]
    artifact_dir: Option<PathBuf>,

    #[arg(long, env = "RELAYKIT_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    #[arg(long, env = "RELAYKIT_TLS_KEY")]
    tls_key: Option<PathBuf>,

    #[arg(long)]
    json: bool,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    common::init_tracing(cli.verbose)?;

    let config = ServerConfig {
        listen: cli.listen,
        public_url: cli.public_url,
        operator_token: cli.operator_token,
        insecure_no_operator_auth: cli.insecure_no_operator_auth,
        artifact_dir: cli.artifact_dir,
        tls_cert: cli.tls_cert,
        tls_key: cli.tls_key,
    };
    if cli.json {
        common::print_output(cli.json, &plan_server(config.clone()))?;
    }
    run_server(config).await
}
