use anyhow::Result;
use clap::{Parser, Subcommand};
use relaykit_agent::{run_join, ExposeRequest, JoinRequest};
use relaykit_protocol::SessionCode;
use relaykit_tunnel::RelayFingerprint;

#[path = "../common.rs"]
mod common;

#[derive(Debug, Parser)]
#[command(name = "relaykit-agent")]
#[command(about = "Join RelayKit support sessions from assisted machines")]
#[command(version)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,

    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[arg(long, env = "RELAYKIT_RELAY_FINGERPRINT", global = true)]
    relay_fingerprint: Option<RelayFingerprint>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Join a short-lived support session.
    Join {
        #[arg(long = "relay", env = "RELAYKIT_RELAY")]
        server: String,

        #[arg(long)]
        code: SessionCode,

        #[arg(long)]
        device: Option<String>,

        #[arg(long = "tcp")]
        exposes: Vec<ExposeRequest>,

        #[arg(long, default_value_t = true)]
        foreground: bool,

        #[arg(long = "no-preflight")]
        skip_preflight: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    common::init_tracing(cli.verbose)?;

    match cli.command {
        Command::Join {
            server,
            code,
            device,
            exposes,
            foreground,
            skip_preflight,
        } => {
            let request = JoinRequest {
                server,
                session: code,
                relay_fingerprint: cli.relay_fingerprint,
                device,
                exposes,
                foreground,
                preflight: !skip_preflight,
            };
            if cli.json {
                common::print_output(cli.json, &relaykit_agent::plan_join(request.clone()))?;
            }
            run_join(request).await?;
        }
    }

    Ok(())
}
