use std::{
    io::ErrorKind,
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use relaykit_agent::ExposeRequest;
use relaykit_protocol::{Capability, SessionId};
use relaykit_server::{CreateSessionRequest, CreateSessionResponse, SessionSummary};
use relaykit_tunnel::{
    relay_fingerprint_client_config, run_operator_tunnel, OperatorTunnelConfig, RelayFingerprint,
    TunnelSpec,
};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use url::{Host, Url};

#[path = "../common.rs"]
mod common;

#[derive(Debug, Parser)]
#[command(name = "rk")]
#[command(about = "RelayKit operator CLI")]
#[command(version)]
struct Cli {
    #[arg(long, global = true)]
    json: bool,

    #[arg(long, env = "RELAYKIT_OPERATOR_TOKEN", global = true)]
    operator_token: Option<String>,

    #[arg(long, env = "RELAYKIT_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[arg(long, env = "RELAYKIT_RELAY_FINGERPRINT", global = true)]
    relay_fingerprint: Option<RelayFingerprint>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Store or check relay operator configuration.
    Login {
        #[arg(value_name = "RELAY_URL")]
        server: String,
    },
    /// Create and manage short-lived assistance sessions.
    Session(SessionCommand),
    /// Run a guided assistance workflow.
    Assist(AssistCommand),
    /// Prepare a local SSH tunnel to the assisted machine.
    Ssh(ConnectCommand),
    /// Prepare a local RDP tunnel to the assisted Windows machine.
    Rdp(ConnectCommand),
    /// Prepare a generic local TCP tunnel to the assisted machine.
    Tunnel(TunnelCommand),
    /// Publish assisted-machine artifacts to a relay host.
    Artifact(ArtifactCommand),
    /// Deploy or inspect relay server runtime assets.
    Relay(RelayCommand),
}

#[derive(Debug, Args)]
struct SessionCommand {
    #[command(subcommand)]
    command: SessionSubcommand,
}

#[derive(Debug, Args)]
struct AssistCommand {
    #[command(subcommand)]
    command: AssistSubcommand,
}

#[derive(Debug, Subcommand)]
enum AssistSubcommand {
    /// Create an SSH assistance session, wait for the user, then open a local tunnel.
    Ssh {
        #[arg(long, env = "RELAYKIT_RELAY")]
        server: Option<String>,

        #[arg(
            long,
            visible_alias = "label",
            help = "Operator-visible label; use a customer name, public IP, or domain"
        )]
        device: Option<String>,

        #[arg(long, default_value_t = 900)]
        ttl_seconds: u64,

        #[arg(long, default_value = "127.0.0.1:22")]
        target: String,

        #[arg(long, default_value = "127.0.0.1:22022")]
        listen: String,

        #[arg(long, default_value_t = 300)]
        wait_seconds: u64,

        #[arg(long)]
        no_wait: bool,

        #[arg(long)]
        no_tunnel: bool,
    },
    /// Create an RDP assistance session, wait for the user, then open a local tunnel.
    Rdp {
        #[arg(long, env = "RELAYKIT_RELAY")]
        server: Option<String>,

        #[arg(
            long,
            visible_alias = "label",
            help = "Operator-visible label; use a customer name, public IP, or domain"
        )]
        device: Option<String>,

        #[arg(long, default_value_t = 900)]
        ttl_seconds: u64,

        #[arg(long, default_value = "127.0.0.1:3389")]
        target: String,

        #[arg(long, default_value = "127.0.0.1:23389")]
        listen: String,

        #[arg(long, default_value_t = 300)]
        wait_seconds: u64,

        #[arg(long)]
        no_wait: bool,

        #[arg(long)]
        no_tunnel: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SessionSubcommand {
    /// Create a short-lived support session.
    New {
        #[arg(long, env = "RELAYKIT_RELAY")]
        server: Option<String>,

        #[arg(
            long,
            visible_alias = "label",
            help = "Operator-visible label; use a customer name, public IP, or domain"
        )]
        device: Option<String>,

        #[arg(long, default_value_t = 900)]
        ttl_seconds: u64,

        #[arg(long = "capability", value_delimiter = ',')]
        capabilities: Vec<Capability>,

        #[arg(long = "allow")]
        allowed: Vec<ExposeRequest>,
    },
    /// List sessions visible to the operator.
    List {
        #[arg(long, env = "RELAYKIT_RELAY")]
        server: Option<String>,
    },
    /// End a support session.
    End {
        #[arg(long, env = "RELAYKIT_RELAY")]
        server: Option<String>,

        session: SessionId,
    },
}

#[derive(Debug, Args)]
struct ConnectCommand {
    #[arg(long, env = "RELAYKIT_RELAY")]
    server: Option<String>,

    session: SessionId,

    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
}

#[derive(Debug, Args)]
struct TunnelCommand {
    #[arg(long, env = "RELAYKIT_RELAY")]
    server: Option<String>,

    session: SessionId,

    name: String,

    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,
}

#[derive(Debug, Args)]
struct ArtifactCommand {
    #[command(subcommand)]
    command: ArtifactSubcommand,
}

#[derive(Debug, Subcommand)]
enum ArtifactSubcommand {
    /// Publish a relaykit-agent binary into the relay artifact directory.
    PublishAgent {
        #[arg(long)]
        host: String,

        #[arg(long, default_value = "/tmp/relaykit-artifacts")]
        artifact_dir: String,

        #[arg(long)]
        binary: PathBuf,

        #[arg(long, value_enum, default_value_t = AgentArtifactTarget::LinuxX86_64)]
        target: AgentArtifactTarget,

        #[arg(long, default_value = "ssh")]
        ssh: String,

        #[arg(long, default_value = "scp")]
        scp: String,

        #[arg(long)]
        no_sudo: bool,

        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
enum AgentArtifactTarget {
    #[value(name = "linux-x86_64")]
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[value(name = "linux-aarch64")]
    #[serde(rename = "linux-aarch64")]
    LinuxAarch64,
    #[value(name = "windows-x86_64")]
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
    #[value(name = "windows-aarch64")]
    #[serde(rename = "windows-aarch64")]
    WindowsAarch64,
}

#[derive(Debug, Args)]
struct RelayCommand {
    #[command(subcommand)]
    command: RelaySubcommand,
}

#[derive(Debug, Subcommand)]
enum RelaySubcommand {
    /// Deploy relaykitd as a Linux systemd service on a relay host.
    DeploySystemd {
        #[arg(long)]
        host: String,

        #[arg(long)]
        binary: PathBuf,

        #[arg(long)]
        public_url: String,

        #[arg(long, default_value = "0.0.0.0:18080")]
        listen: String,

        #[arg(long)]
        tls_cert: Option<String>,

        #[arg(long)]
        tls_key: Option<String>,

        #[arg(long, default_value = "/opt/relaykit/bin")]
        install_dir: String,

        #[arg(long, default_value = "/var/lib/relaykit/artifacts")]
        artifact_dir: String,

        #[arg(long, default_value = "/etc/relaykit/relaykitd.env")]
        env_file: String,

        #[arg(long, default_value = "relaykitd")]
        service_name: String,

        #[arg(long, default_value = "relaykit")]
        service_user: String,

        #[arg(long, default_value = "ssh")]
        ssh: String,

        #[arg(long, default_value = "scp")]
        scp: String,

        #[arg(long)]
        no_sudo: bool,

        #[arg(long)]
        skip_health_check: bool,

        #[arg(long)]
        dry_run: bool,
    },
    /// Check a deployed relay systemd service and expected artifacts over SSH.
    Status {
        #[arg(long)]
        host: String,

        #[arg(long, default_value = "0.0.0.0:18080")]
        listen: String,

        #[arg(long)]
        tls: bool,

        #[arg(long, default_value = "/var/lib/relaykit/artifacts")]
        artifact_dir: String,

        #[arg(long = "artifact", default_values_t = vec!["relaykit-agent-linux-x86_64".to_owned()])]
        artifacts: Vec<String>,

        #[arg(long, default_value = "relaykitd")]
        service_name: String,

        #[arg(long, default_value = "ssh")]
        ssh: String,

        #[arg(long)]
        no_sudo: bool,

        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    common::init_tracing(cli.verbose)?;
    let config_path = operator_config_path(cli.config.as_deref())?;
    let stored_config = read_operator_config(&config_path)?;
    let operator_token =
        resolve_operator_token(cli.operator_token.as_deref(), stored_config.as_ref());
    let cli_relay_fingerprint = cli.relay_fingerprint.clone();
    let relay_fingerprint =
        resolve_relay_fingerprint(cli.relay_fingerprint.as_ref(), stored_config.as_ref());

    match cli.command {
        Command::Login { server } => {
            validate_operator_server_url(&server)?;
            let config = OperatorConfig {
                server: server.clone(),
                operator_token,
                relay_fingerprint: cli_relay_fingerprint,
            };
            write_operator_config(&config_path, &config)?;
            let result = LoginResult {
                server,
                config_path: config_path.display().to_string(),
                operator_token_stored: config.operator_token.is_some(),
                relay_fingerprint: config.relay_fingerprint.clone(),
                status: "saved",
            };
            if cli.json {
                common::print_output(cli.json, &result)?;
            } else {
                print_login_result(&result);
            }
        }
        Command::Session(command) => match command.command {
            SessionSubcommand::New {
                server,
                device,
                ttl_seconds,
                capabilities,
                allowed,
            } => {
                let server = resolve_server(server, stored_config.as_ref())?;
                let capabilities = if capabilities.is_empty() {
                    vec![Capability::Ssh, Capability::Rdp, Capability::Tcp]
                } else {
                    capabilities
                };
                if allowed.is_empty() {
                    return Err(anyhow!(
                        "at least one --allow target is required, for example --allow ssh=127.0.0.1:22"
                    ));
                }
                let allowed_tunnels = allowed.into_iter().map(Into::into).collect();
                let response = create_operator_session(
                    &server,
                    operator_token.as_deref(),
                    relay_fingerprint.as_ref(),
                    CreateSessionRequest {
                        device,
                        capabilities,
                        allowed_tunnels,
                        ttl_seconds,
                        relay_fingerprint: relay_fingerprint.clone(),
                    },
                )
                .await?;

                if cli.json {
                    common::print_output(cli.json, &response)?;
                } else {
                    print_session_created(&response);
                }
            }
            SessionSubcommand::List { server } => {
                let server = resolve_server(server, stored_config.as_ref())?;
                let response = list_operator_sessions(
                    &server,
                    operator_token.as_deref(),
                    relay_fingerprint.as_ref(),
                )
                .await?;
                if cli.json {
                    common::print_output(cli.json, &response)?;
                } else {
                    print_session_list(&response);
                }
            }
            SessionSubcommand::End { server, session } => {
                let server = resolve_server(server, stored_config.as_ref())?;
                let path = format!("/api/sessions/{session}");
                let client = http_client(relay_fingerprint.as_ref())?;
                apply_operator_auth(
                    client.delete(api_url(&server, &path)?),
                    operator_token.as_deref(),
                )
                .send()
                .await?
                .error_for_status()?;
                if cli.json {
                    common::print_output(
                        cli.json,
                        &SessionEndResult {
                            server,
                            session: session.to_string(),
                            closed: true,
                        },
                    )?;
                } else {
                    println!("closed session {session}");
                }
            }
        },
        Command::Assist(command) => match command.command {
            AssistSubcommand::Ssh {
                server,
                device,
                ttl_seconds,
                target,
                listen,
                wait_seconds,
                no_wait,
                no_tunnel,
            } => {
                let server = resolve_server(server, stored_config.as_ref())?;
                let target = ssh_target_spec(&target)?;
                if !no_tunnel {
                    ensure_listen_available(&listen)?;
                }
                let response = create_operator_session(
                    &server,
                    operator_token.as_deref(),
                    relay_fingerprint.as_ref(),
                    CreateSessionRequest {
                        device,
                        capabilities: vec![Capability::Ssh, Capability::Tcp],
                        allowed_tunnels: vec![target],
                        ttl_seconds,
                        relay_fingerprint: relay_fingerprint.clone(),
                    },
                )
                .await?;
                let result = AssistSshResult {
                    session: response.session.to_string(),
                    join_command: response.join_command.clone(),
                    listen: listen.clone(),
                    ssh_command: ssh_client_hint(&listen),
                    status: "created",
                };

                if cli.json {
                    common::print_output(cli.json, &result)?;
                    return Ok(());
                }

                print_assist_ssh_created(&response, &listen, !no_wait, !no_tunnel);
                if no_tunnel {
                    return Ok(());
                }

                if !no_wait {
                    let summary = wait_for_agent(
                        &server,
                        operator_token.as_deref(),
                        relay_fingerprint.as_ref(),
                        &response.session,
                        &response.join_command,
                        Duration::from_secs(wait_seconds),
                    )
                    .await?;
                    print_assist_ssh_connected(&listen, &summary);
                }

                run_operator_tunnel(OperatorTunnelConfig {
                    server,
                    session: response.session,
                    target: "ssh".to_owned(),
                    listen,
                    operator_token: operator_token.clone(),
                    relay_fingerprint: relay_fingerprint.clone(),
                })
                .await?;
            }
            AssistSubcommand::Rdp {
                server,
                device,
                ttl_seconds,
                target,
                listen,
                wait_seconds,
                no_wait,
                no_tunnel,
            } => {
                let server = resolve_server(server, stored_config.as_ref())?;
                let target = rdp_target_spec(&target)?;
                if !no_tunnel {
                    ensure_listen_available(&listen)?;
                }
                let response = create_operator_session(
                    &server,
                    operator_token.as_deref(),
                    relay_fingerprint.as_ref(),
                    CreateSessionRequest {
                        device,
                        capabilities: vec![Capability::Rdp, Capability::Tcp],
                        allowed_tunnels: vec![target],
                        ttl_seconds,
                        relay_fingerprint: relay_fingerprint.clone(),
                    },
                )
                .await?;
                let result = AssistRdpResult {
                    session: response.session.to_string(),
                    join_command: response.join_command.clone(),
                    listen: listen.clone(),
                    rdp_command: rdp_client_hint(&listen),
                    status: "created",
                };

                if cli.json {
                    common::print_output(cli.json, &result)?;
                    return Ok(());
                }

                print_assist_rdp_created(&response, &listen, !no_wait, !no_tunnel);
                if no_tunnel {
                    return Ok(());
                }

                if !no_wait {
                    let summary = wait_for_agent(
                        &server,
                        operator_token.as_deref(),
                        relay_fingerprint.as_ref(),
                        &response.session,
                        &response.join_command,
                        Duration::from_secs(wait_seconds),
                    )
                    .await?;
                    print_assist_rdp_connected(&listen, &summary);
                }

                run_operator_tunnel(OperatorTunnelConfig {
                    server,
                    session: response.session,
                    target: "rdp".to_owned(),
                    listen,
                    operator_token: operator_token.clone(),
                    relay_fingerprint: relay_fingerprint.clone(),
                })
                .await?;
            }
        },
        Command::Ssh(command) => {
            let server = resolve_server(command.server, stored_config.as_ref())?;
            ensure_listen_available(&command.listen)?;
            run_operator_tunnel(OperatorTunnelConfig {
                server,
                session: command.session,
                target: "ssh".to_owned(),
                listen: command.listen,
                operator_token: operator_token.clone(),
                relay_fingerprint: relay_fingerprint.clone(),
            })
            .await?;
        }
        Command::Rdp(command) => {
            let server = resolve_server(command.server, stored_config.as_ref())?;
            ensure_listen_available(&command.listen)?;
            run_operator_tunnel(OperatorTunnelConfig {
                server,
                session: command.session,
                target: "rdp".to_owned(),
                listen: command.listen,
                operator_token: operator_token.clone(),
                relay_fingerprint: relay_fingerprint.clone(),
            })
            .await?;
        }
        Command::Tunnel(command) => {
            let server = resolve_server(command.server, stored_config.as_ref())?;
            ensure_listen_available(&command.listen)?;
            run_operator_tunnel(OperatorTunnelConfig {
                server,
                session: command.session,
                target: command.name,
                listen: command.listen,
                operator_token: operator_token.clone(),
                relay_fingerprint: relay_fingerprint.clone(),
            })
            .await?;
        }
        Command::Artifact(command) => match command.command {
            ArtifactSubcommand::PublishAgent {
                host,
                artifact_dir,
                binary,
                target,
                ssh,
                scp,
                no_sudo,
                dry_run,
            } => {
                let plan = publish_agent_artifact(AgentArtifactPublishRequest {
                    host,
                    artifact_dir,
                    binary,
                    target,
                    ssh,
                    scp,
                    no_sudo,
                    dry_run,
                })?;
                if cli.json {
                    common::print_output(cli.json, &plan)?;
                } else {
                    print_artifact_publish_plan(&plan);
                }
            }
        },
        Command::Relay(command) => match command.command {
            RelaySubcommand::DeploySystemd {
                host,
                binary,
                public_url,
                listen,
                tls_cert,
                tls_key,
                install_dir,
                artifact_dir,
                env_file,
                service_name,
                service_user,
                ssh,
                scp,
                no_sudo,
                skip_health_check,
                dry_run,
            } => {
                let plan = deploy_relay_systemd(RelaySystemdDeployRequest {
                    host,
                    binary,
                    public_url,
                    listen,
                    tls_cert,
                    tls_key,
                    install_dir,
                    artifact_dir,
                    env_file,
                    service_name,
                    service_user,
                    ssh,
                    scp,
                    no_sudo,
                    skip_health_check,
                    dry_run,
                })?;
                if cli.json {
                    common::print_output(cli.json, &plan)?;
                } else {
                    print_relay_systemd_deploy_plan(&plan);
                }
            }
            RelaySubcommand::Status {
                host,
                listen,
                tls,
                artifact_dir,
                artifacts,
                service_name,
                ssh,
                no_sudo,
                dry_run,
            } => {
                let report = check_relay_status(RelayStatusRequest {
                    host,
                    listen,
                    tls,
                    artifact_dir,
                    artifacts,
                    service_name,
                    ssh,
                    no_sudo,
                    dry_run,
                })?;
                if cli.json {
                    common::print_output(cli.json, &report)?;
                } else {
                    print_relay_status_report(&report);
                }
            }
        },
    }

    Ok(())
}

fn http_client(relay_fingerprint: Option<&RelayFingerprint>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(relay_fingerprint) = relay_fingerprint {
        builder =
            builder.use_preconfigured_tls(relay_fingerprint_client_config(relay_fingerprint)?);
    }
    builder.build().context("failed to build relay HTTP client")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OperatorConfig {
    server: String,
    operator_token: Option<String>,
    #[serde(default)]
    relay_fingerprint: Option<RelayFingerprint>,
}

fn operator_config_path(cli_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = cli_path {
        return Ok(path.to_owned());
    }

    default_operator_config_path()
}

#[cfg(windows)]
fn default_operator_config_path() -> Result<PathBuf> {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return Ok(PathBuf::from(appdata).join("RelayKit").join("config.json"));
    }
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(user_profile)
            .join(".config")
            .join("relaykit")
            .join("config.json"));
    }
    Err(anyhow!(
        "APPDATA and USERPROFILE are not set; pass --config or RELAYKIT_CONFIG"
    ))
}

#[cfg(not(windows))]
fn default_operator_config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set; pass --config or RELAYKIT_CONFIG"))?;
    Ok(home.join(".config").join("relaykit").join("config.json"))
}

fn read_operator_config(path: &Path) -> Result<Option<OperatorConfig>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents)
            .with_context(|| format!("invalid RelayKit config {}", path.display()))
            .map(Some),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn write_operator_config(path: &Path, config: &OperatorConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        let parent_missing = !parent.exists();
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        if parent_missing {
            set_owner_only_dir_permissions(parent)?;
        }
    }

    let mut contents = serde_json::to_vec_pretty(config)?;
    contents.push(b'\n');
    write_owner_only_file(path, &contents)?;
    set_owner_only_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn write_owner_only_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(not(unix))]
fn write_owner_only_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(unix)]
fn set_owner_only_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn resolve_server(cli_server: Option<String>, config: Option<&OperatorConfig>) -> Result<String> {
    if let Some(server) = cli_server {
        return Ok(server);
    }
    if let Some(config) = config {
        return Ok(config.server.clone());
    }
    Err(anyhow!(
        "relay server is required; pass --server, set RELAYKIT_RELAY, or run rk login"
    ))
}

fn resolve_operator_token(
    cli_token: Option<&str>,
    config: Option<&OperatorConfig>,
) -> Option<String> {
    cli_token
        .map(ToOwned::to_owned)
        .or_else(|| config.and_then(|config| config.operator_token.clone()))
}

fn resolve_relay_fingerprint(
    cli_fingerprint: Option<&RelayFingerprint>,
    config: Option<&OperatorConfig>,
) -> Option<RelayFingerprint> {
    cli_fingerprint
        .cloned()
        .or_else(|| config.and_then(|config| config.relay_fingerprint.clone()))
}

async fn create_operator_session(
    server: &str,
    operator_token: Option<&str>,
    relay_fingerprint: Option<&RelayFingerprint>,
    request: CreateSessionRequest,
) -> Result<CreateSessionResponse> {
    let client = http_client(relay_fingerprint)?;
    let response = apply_operator_auth(
        client.post(api_url(server, "/api/sessions")?),
        operator_token,
    )
    .json(&request)
    .send()
    .await?
    .error_for_status()?
    .json::<CreateSessionResponse>()
    .await?;
    Ok(response)
}

async fn list_operator_sessions(
    server: &str,
    operator_token: Option<&str>,
    relay_fingerprint: Option<&RelayFingerprint>,
) -> Result<Vec<SessionSummary>> {
    let client = http_client(relay_fingerprint)?;
    let response = apply_operator_auth(
        client.get(api_url(server, "/api/sessions")?),
        operator_token,
    )
    .send()
    .await?
    .error_for_status()?
    .json::<Vec<SessionSummary>>()
    .await?;
    Ok(response)
}

async fn wait_for_agent(
    server: &str,
    operator_token: Option<&str>,
    relay_fingerprint: Option<&RelayFingerprint>,
    session: &SessionId,
    join_command: &str,
    timeout: Duration,
) -> Result<SessionSummary> {
    let started = Instant::now();
    let deadline = started + timeout;
    let progress_interval = Duration::from_secs(10);
    let mut next_progress = started + progress_interval;

    loop {
        let sessions = list_operator_sessions(server, operator_token, relay_fingerprint).await?;
        if let Some(summary) = sessions
            .iter()
            .find(|summary| summary.session == *session && summary.agent_connected)
        {
            return Ok(summary.clone());
        }

        let now = Instant::now();
        if now >= deadline {
            print_wait_timeout(session, join_command);
            return Err(anyhow!(
                "assisted machine did not connect within {} seconds; ask the user to keep the RelayKit window open and retry",
                timeout.as_secs()
            ));
        }

        if now >= next_progress {
            print_wait_progress(session, started, deadline, now);
            while next_progress <= now {
                next_progress += progress_interval;
            }
        }

        sleep(std::cmp::min(
            Duration::from_secs(2),
            deadline.saturating_duration_since(now),
        ))
        .await;
    }
}

fn ssh_target_spec(target: &str) -> Result<TunnelSpec> {
    let expose: ExposeRequest = format!("ssh={target}")
        .parse()
        .with_context(|| format!("invalid SSH target {target}; expected host:port"))?;
    Ok(expose.into())
}

fn rdp_target_spec(target: &str) -> Result<TunnelSpec> {
    let expose: ExposeRequest = format!("rdp={target}")
        .parse()
        .with_context(|| format!("invalid RDP target {target}; expected host:port"))?;
    Ok(expose.into())
}

fn apply_operator_auth(
    builder: reqwest::RequestBuilder,
    operator_token: Option<&str>,
) -> reqwest::RequestBuilder {
    if let Some(operator_token) = operator_token {
        builder.bearer_auth(operator_token)
    } else {
        builder
    }
}

fn api_url(server: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(server).with_context(|| format!("invalid relay URL {server}"))?;
    validate_relay_transport(&url)?;
    match url.scheme() {
        "http" | "https" => {}
        "ws" => url
            .set_scheme("http")
            .map_err(|_| anyhow!("invalid URL scheme"))?,
        "wss" => url
            .set_scheme("https")
            .map_err(|_| anyhow!("invalid URL scheme"))?,
        other => return Err(anyhow!("unsupported relay URL scheme: {other}")),
    }
    url.set_path(path);
    url.set_query(None);
    Ok(url)
}

fn validate_operator_server_url(server: &str) -> Result<()> {
    api_url(server, "/healthz").map(|_| ())
}

fn print_session_created(response: &CreateSessionResponse) {
    println!("session: {}", response.session);
    println!("code: {}", response.code);
    println!("ttl_seconds: {}", response.ttl_seconds);
    println!("join:");
    println!("{}", response.join_command);
    if response.install_command.is_some() {
        println!("agent:");
        println!("{}", response.agent_command);
    }
}

fn print_assist_ssh_created(
    response: &CreateSessionResponse,
    listen: &str,
    will_wait: bool,
    will_tunnel: bool,
) {
    println!("session: {}", response.session);
    println!("send this command to the assisted user:");
    println!("{}", response.join_command);
    println!();
    if !will_tunnel {
        println!("session created; open a tunnel later with:");
        println!("rk ssh {} --listen {listen}", response.session);
        return;
    }
    if will_wait {
        println!("waiting for the assisted machine to connect...");
    } else {
        println!("starting local tunnel without waiting for the assisted machine");
    }
    println!("keep this terminal open");
    println!("local SSH will listen on {listen}");
}

fn print_assist_ssh_connected(listen: &str, summary: &SessionSummary) {
    println!("assisted machine connected");
    if let Some(device) = &summary.device {
        println!("label: {device}");
    }
    if let Some(remote_addr) = &summary.agent_remote_addr {
        println!("source: {remote_addr}");
    }
    println!("open SSH from another terminal:");
    println!("{}", ssh_client_hint(listen));
    println!("starting local tunnel; keep this terminal open");
}

fn print_assist_rdp_created(
    response: &CreateSessionResponse,
    listen: &str,
    will_wait: bool,
    will_tunnel: bool,
) {
    println!("session: {}", response.session);
    println!("send this command to the assisted user:");
    println!("{}", response.join_command);
    println!();
    if !will_tunnel {
        println!("session created; open a tunnel later with:");
        println!("rk rdp {} --listen {listen}", response.session);
        return;
    }
    if will_wait {
        println!("waiting for the assisted machine to connect...");
    } else {
        println!("starting local tunnel without waiting for the assisted machine");
    }
    println!("keep this terminal open");
    println!("local RDP will listen on {listen}");
}

fn print_assist_rdp_connected(listen: &str, summary: &SessionSummary) {
    println!("assisted machine connected");
    if let Some(device) = &summary.device {
        println!("label: {device}");
    }
    if let Some(remote_addr) = &summary.agent_remote_addr {
        println!("source: {remote_addr}");
    }
    println!("open RDP from another terminal:");
    println!("{}", rdp_client_hint(listen));
    println!("starting local tunnel; keep this terminal open");
}

fn print_wait_progress(session: &SessionId, started: Instant, deadline: Instant, now: Instant) {
    let elapsed = now.saturating_duration_since(started).as_secs();
    let remaining = deadline.saturating_duration_since(now).as_secs();
    println!("waiting: elapsed={elapsed}s remaining={remaining}s session={session}");
}

fn print_wait_timeout(session: &SessionId, join_command: &str) {
    println!("timed out waiting for session {session}");
    println!("ask the assisted user to run this join command again:");
    println!("{join_command}");
}

fn ssh_client_hint(listen: &str) -> String {
    match listen_port(listen) {
        Ok(0) | Err(_) => format!("ssh -p <port> <user>@{}", listen_host(listen)),
        Ok(port) => format!("ssh -p {port} <user>@{}", listen_host(listen)),
    }
}

fn rdp_client_hint(listen: &str) -> String {
    let endpoint = rdp_client_endpoint(listen);
    if cfg!(target_os = "windows") {
        format!("mstsc /v:{endpoint}")
    } else {
        format!("open an RDP client and connect to {endpoint}")
    }
}

fn rdp_client_endpoint(listen: &str) -> String {
    match listen_port(listen) {
        Ok(0) | Err(_) => format!("{}:<port>", listen_host(listen)),
        Ok(port) => format!("{}:{port}", listen_host(listen)),
    }
}

fn listen_host(listen: &str) -> &str {
    listen
        .rsplit_once(':')
        .map(|(host, _)| match host {
            "" | "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
            _ => host,
        })
        .unwrap_or("127.0.0.1")
}

fn print_login_result(result: &LoginResult) {
    println!("server: {}", result.server);
    println!("config: {}", result.config_path);
    println!(
        "operator_token: {}",
        if result.operator_token_stored {
            "stored"
        } else {
            "not stored"
        }
    );
    if let Some(relay_fingerprint) = &result.relay_fingerprint {
        println!("relay_fingerprint: {relay_fingerprint}");
    }
    println!("status: {}", result.status);
}

fn print_session_list(sessions: &[SessionSummary]) {
    if sessions.is_empty() {
        println!("no sessions");
        return;
    }

    for (index, session) in sessions.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("session: {}", session.session);
        if let Some(device) = &session.device {
            println!("device: {device}");
        }
        if let Some(remote_addr) = &session.agent_remote_addr {
            println!("source: {remote_addr}");
        }
        println!(
            "agent: {}",
            if session.agent_connected {
                "connected"
            } else {
                "waiting"
            }
        );
        println!("expires_in_seconds: {}", session.expires_in_seconds);
        println!("active_streams: {}", session.active_streams);
        if !session.allowed_tunnels.is_empty() {
            let tunnels = session
                .allowed_tunnels
                .iter()
                .map(|tunnel| {
                    format!(
                        "{}={}:{}",
                        tunnel.name, tunnel.target.host, tunnel.target.port
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("tunnels: {tunnels}");
        }
    }
}

#[derive(Debug, Clone)]
struct AgentArtifactPublishRequest {
    host: String,
    artifact_dir: String,
    binary: PathBuf,
    target: AgentArtifactTarget,
    ssh: String,
    scp: String,
    no_sudo: bool,
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ArtifactPublishPlan {
    host: String,
    artifact_dir: String,
    binary: String,
    target: AgentArtifactTarget,
    artifact_name: String,
    checksum_name: String,
    remote_path: String,
    checksum_remote_path: String,
    temporary_remote_path: String,
    temporary_checksum_remote_path: String,
    local_checksum_path: String,
    sha256: Option<String>,
    commands: Vec<ExternalCommandPlan>,
    status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ExternalCommandPlan {
    program: String,
    args: Vec<String>,
}

impl AgentArtifactTarget {
    fn artifact_name(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "relaykit-agent-linux-x86_64",
            Self::LinuxAarch64 => "relaykit-agent-linux-aarch64",
            Self::WindowsX86_64 => "relaykit-agent-windows-x86_64.exe",
            Self::WindowsAarch64 => "relaykit-agent-windows-aarch64.exe",
        }
    }
}

fn publish_agent_artifact(request: AgentArtifactPublishRequest) -> Result<ArtifactPublishPlan> {
    let mut plan = plan_agent_artifact_publish(&request)?;

    if request.dry_run {
        plan.status = "dry-run";
        return Ok(plan);
    }

    let metadata = std::fs::metadata(&request.binary)
        .with_context(|| format!("agent binary not found: {}", request.binary.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "agent binary path is not a file: {}",
            request.binary.display()
        ));
    }
    let sha256 = sha256_file(&request.binary)?;
    std::fs::write(
        &plan.local_checksum_path,
        checksum_sidecar_contents(&sha256, &plan.artifact_name),
    )
    .with_context(|| {
        format!(
            "failed to write checksum sidecar {}",
            plan.local_checksum_path
        )
    })?;
    plan.sha256 = Some(sha256);

    let run_result = plan.commands.iter().try_for_each(run_external_command);
    let cleanup_result = std::fs::remove_file(&plan.local_checksum_path);
    if let Err(error) = cleanup_result {
        if error.kind() != ErrorKind::NotFound && run_result.is_ok() {
            return Err(error).with_context(|| {
                format!(
                    "failed to remove local checksum sidecar {}",
                    plan.local_checksum_path
                )
            });
        }
    }
    run_result?;

    plan.status = "published";
    Ok(plan)
}

fn plan_agent_artifact_publish(
    request: &AgentArtifactPublishRequest,
) -> Result<ArtifactPublishPlan> {
    validate_remote_host(&request.host)?;
    validate_remote_dir(&request.artifact_dir)?;
    validate_external_program(&request.ssh, "ssh")?;
    validate_external_program(&request.scp, "scp")?;

    let artifact_name = request.target.artifact_name().to_owned();
    let checksum_name = format!("{artifact_name}.sha256");
    let remote_path = format!("{}/{}", request.artifact_dir, artifact_name);
    let checksum_remote_path = format!("{}/{}", request.artifact_dir, checksum_name);
    let activation_id = std::process::id();
    let temporary_remote_path = if request.no_sudo {
        format!("{}.tmp-{activation_id}", remote_path)
    } else {
        format!("/tmp/{}.tmp-{activation_id}", artifact_name)
    };
    let temporary_checksum_remote_path = if request.no_sudo {
        format!("{}.tmp-{activation_id}", checksum_remote_path)
    } else {
        format!("/tmp/{}.tmp-{activation_id}", checksum_name)
    };
    let local_checksum_path = std::env::temp_dir()
        .join(format!("{checksum_name}.tmp-{activation_id}"))
        .to_string_lossy()
        .to_string();
    let binary = request.binary.to_string_lossy().to_string();
    let sudo = sudo_prefix(request.no_sudo);
    let install_dir_command = format!("{}mkdir -p {}", sudo, request.artifact_dir);
    let activate_command = if request.no_sudo {
        format!(
            "chmod 755 {} && chmod 644 {} && mv -f {} {} && mv -f {} {}",
            temporary_remote_path,
            temporary_checksum_remote_path,
            temporary_remote_path,
            remote_path,
            temporary_checksum_remote_path,
            checksum_remote_path
        )
    } else {
        format!(
            "{}install -m 0755 {} {} && {}install -m 0644 {} {} && rm -f {} {}",
            sudo,
            temporary_remote_path,
            remote_path,
            sudo,
            temporary_checksum_remote_path,
            checksum_remote_path,
            temporary_remote_path,
            temporary_checksum_remote_path
        )
    };

    Ok(ArtifactPublishPlan {
        host: request.host.clone(),
        artifact_dir: request.artifact_dir.clone(),
        binary: binary.clone(),
        target: request.target,
        artifact_name: artifact_name.clone(),
        checksum_name,
        remote_path: remote_path.clone(),
        checksum_remote_path: checksum_remote_path.clone(),
        temporary_remote_path: temporary_remote_path.clone(),
        temporary_checksum_remote_path: temporary_checksum_remote_path.clone(),
        local_checksum_path: local_checksum_path.clone(),
        sha256: None,
        commands: vec![
            ExternalCommandPlan {
                program: request.ssh.clone(),
                args: vec![request.host.clone(), install_dir_command],
            },
            ExternalCommandPlan {
                program: request.scp.clone(),
                args: vec![
                    binary,
                    format!("{}:{}", request.host, temporary_remote_path),
                ],
            },
            ExternalCommandPlan {
                program: request.scp.clone(),
                args: vec![
                    local_checksum_path,
                    format!("{}:{}", request.host, temporary_checksum_remote_path),
                ],
            },
            ExternalCommandPlan {
                program: request.ssh.clone(),
                args: vec![request.host.clone(), activate_command],
            },
        ],
        status: "planned",
    })
}

fn run_external_command(command: &ExternalCommandPlan) -> Result<()> {
    let status = ProcessCommand::new(&command.program)
        .args(&command.args)
        .status()
        .with_context(|| format!("failed to run {}", command.display()))?;
    if !status.success() {
        return Err(anyhow!("command failed: {}", command.display()));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut errors = Vec::new();

    match ProcessCommand::new("sha256sum").arg(path).output() {
        Ok(output) => match parse_sha256_command_output("sha256sum", output) {
            Ok(checksum) => return Ok(checksum),
            Err(error) => errors.push(error.to_string()),
        },
        Err(error) if error.kind() == ErrorKind::NotFound => {
            errors.push("sha256sum not found".to_owned());
        }
        Err(error) => errors.push(format!("sha256sum failed to start: {error}")),
    }

    match ProcessCommand::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
    {
        Ok(output) => match parse_sha256_command_output("shasum", output) {
            Ok(checksum) => return Ok(checksum),
            Err(error) => errors.push(error.to_string()),
        },
        Err(error) if error.kind() == ErrorKind::NotFound => {
            errors.push("shasum not found".to_owned());
        }
        Err(error) => errors.push(format!("shasum failed to start: {error}")),
    }

    Err(anyhow!(
        "unable to compute SHA-256 for {}; install sha256sum or shasum: {}",
        path.display(),
        errors.join("; ")
    ))
}

fn parse_sha256_command_output(program: &str, output: std::process::Output) -> Result<String> {
    if !output.status.success() {
        return Err(anyhow!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_sha256_output(&output.stdout)
}

fn parse_sha256_output(output: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(output).context("sha256 output was not UTF-8")?;
    let checksum = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("sha256 output was empty"))?;
    if checksum.len() == 64 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(checksum.to_ascii_lowercase())
    } else {
        Err(anyhow!(
            "sha256 output did not start with a SHA-256 hex digest"
        ))
    }
}

fn checksum_sidecar_contents(sha256: &str, artifact_name: &str) -> String {
    format!("{sha256}  {artifact_name}\n")
}

impl ExternalCommandPlan {
    fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn print_artifact_publish_plan(plan: &ArtifactPublishPlan) {
    println!("artifact: {}", plan.artifact_name);
    println!("remote: {}:{}", plan.host, plan.remote_path);
    println!("checksum: {}:{}", plan.host, plan.checksum_remote_path);
    if let Some(sha256) = &plan.sha256 {
        println!("sha256: {sha256}");
    } else if plan.status == "dry-run" {
        println!("sha256: unknown (dry-run)");
    }
    println!("status: {}", plan.status);
    if plan.status == "dry-run" {
        println!("commands:");
        for command in &plan.commands {
            println!("{}", command.display());
        }
    }
}

#[derive(Debug, Clone)]
struct RelaySystemdDeployRequest {
    host: String,
    binary: PathBuf,
    public_url: String,
    listen: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    install_dir: String,
    artifact_dir: String,
    env_file: String,
    service_name: String,
    service_user: String,
    ssh: String,
    scp: String,
    no_sudo: bool,
    skip_health_check: bool,
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RelaySystemdDeployPlan {
    host: String,
    service_name: String,
    unit_path: String,
    binary: String,
    remote_binary_path: String,
    temporary_remote_binary_path: String,
    artifact_dir: String,
    env_file: String,
    public_url: String,
    listen: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    health_url: Option<String>,
    unit: String,
    commands: Vec<ExternalCommandPlan>,
    status: &'static str,
}

fn deploy_relay_systemd(request: RelaySystemdDeployRequest) -> Result<RelaySystemdDeployPlan> {
    let mut plan = plan_relay_systemd_deploy(&request)?;

    if request.dry_run {
        plan.status = "dry-run";
        return Ok(plan);
    }

    let metadata = std::fs::metadata(&request.binary)
        .with_context(|| format!("relaykitd binary not found: {}", request.binary.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "relaykitd binary path is not a file: {}",
            request.binary.display()
        ));
    }

    for command in &plan.commands {
        run_external_command(command)?;
    }

    plan.status = "deployed";
    Ok(plan)
}

fn plan_relay_systemd_deploy(
    request: &RelaySystemdDeployRequest,
) -> Result<RelaySystemdDeployPlan> {
    validate_remote_host(&request.host)?;
    validate_remote_dir(&request.install_dir)?;
    validate_remote_dir(&request.artifact_dir)?;
    validate_systemd_artifact_dir(&request.artifact_dir)?;
    validate_remote_file(&request.env_file)?;
    validate_service_name(&request.service_name)?;
    validate_linux_user(&request.service_user)?;
    validate_external_program(&request.ssh, "ssh")?;
    validate_external_program(&request.scp, "scp")?;
    validate_listen(&request.listen)?;
    validate_public_url(&request.public_url)?;
    validate_optional_tls_paths(request.tls_cert.as_deref(), request.tls_key.as_deref())?;

    let service_unit = format!("{}.service", request.service_name);
    let unit_path = format!("/etc/systemd/system/{service_unit}");
    let remote_binary_path = format!("{}/relaykitd", request.install_dir);
    let temporary_remote_binary_path = format!("/tmp/relaykitd.tmp-{}", std::process::id());
    let binary = request.binary.to_string_lossy().to_string();
    let env_dir = parent_dir(&request.env_file)?;
    let sudo = sudo_prefix(request.no_sudo);
    let unit = relaykitd_systemd_unit(request, &remote_binary_path);
    let tls_enabled = request.tls_cert.is_some();
    let health_url = if request.skip_health_check {
        None
    } else {
        Some(format!(
            "{}://127.0.0.1:{}/healthz",
            if tls_enabled { "https" } else { "http" },
            listen_port(&request.listen)?
        ))
    };

    let mut commands = vec![
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!(
                    "if ! id -u {} >/dev/null 2>&1; then {}useradd --system --home-dir {} --shell /usr/sbin/nologin {}; fi",
                    request.service_user, sudo, request.artifact_dir, request.service_user
                ),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("{}install -d -m 0755 {}", sudo, request.install_dir),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!(
                    "{}install -d -m 0750 -o {} -g {} {}",
                    sudo, request.service_user, request.service_user, request.artifact_dir
                ),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("{}install -d -m 0750 {}", sudo, env_dir),
            ],
        },
        ExternalCommandPlan {
            program: request.scp.clone(),
            args: vec![
                binary.clone(),
                format!("{}:{}", request.host, temporary_remote_binary_path),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!(
                    "{}install -m 0755 {} {} && rm -f {}",
                    sudo, temporary_remote_binary_path, remote_binary_path, temporary_remote_binary_path
                ),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!(
                    "printf %s {} | {}tee {} >/dev/null",
                    shell_quote(&unit),
                    sudo,
                    unit_path
                ),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![request.host.clone(), format!("{}systemctl daemon-reload", sudo)],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("{}systemctl enable {}", sudo, service_unit),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("{}systemctl restart {}", sudo, service_unit),
            ],
        },
    ];
    if let Some(health_url) = &health_url {
        let curl_flags = if tls_enabled { "-fsSk" } else { "-fsS" };
        commands.push(ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("curl {curl_flags} {}", shell_quote(health_url)),
            ],
        });
    }

    Ok(RelaySystemdDeployPlan {
        host: request.host.clone(),
        service_name: request.service_name.clone(),
        unit_path,
        binary,
        remote_binary_path,
        temporary_remote_binary_path,
        artifact_dir: request.artifact_dir.clone(),
        env_file: request.env_file.clone(),
        public_url: request.public_url.clone(),
        listen: request.listen.clone(),
        tls_cert: request.tls_cert.clone(),
        tls_key: request.tls_key.clone(),
        health_url,
        unit,
        commands,
        status: "planned",
    })
}

fn relaykitd_systemd_unit(request: &RelaySystemdDeployRequest, binary_path: &str) -> String {
    let tls_args = relaykitd_tls_args(request);
    format!(
        r#"[Unit]
Description=RelayKit relay daemon
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={user}
Group={user}
EnvironmentFile={env_file}
ExecStart={binary_path} --listen {listen} --public-url {public_url} --artifact-dir {artifact_dir}{tls_args}
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths={artifact_dir}

[Install]
WantedBy=multi-user.target
"#,
        user = request.service_user,
        env_file = request.env_file,
        binary_path = binary_path,
        listen = request.listen,
        public_url = request.public_url,
        artifact_dir = request.artifact_dir,
        tls_args = tls_args,
    )
}

fn relaykitd_tls_args(request: &RelaySystemdDeployRequest) -> String {
    match (&request.tls_cert, &request.tls_key) {
        (Some(cert), Some(key)) => format!(" --tls-cert {cert} --tls-key {key}"),
        _ => String::new(),
    }
}

fn print_relay_systemd_deploy_plan(plan: &RelaySystemdDeployPlan) {
    println!("service: {}", plan.service_name);
    println!("remote: {}:{}", plan.host, plan.unit_path);
    println!("binary: {}:{}", plan.host, plan.remote_binary_path);
    println!("env_file: {}:{}", plan.host, plan.env_file);
    println!("status: {}", plan.status);
    if plan.status == "dry-run" {
        println!("unit:");
        print!("{}", plan.unit);
        println!("commands:");
        for command in &plan.commands {
            println!("{}", command.display());
        }
    }
}

#[derive(Debug, Clone)]
struct RelayStatusRequest {
    host: String,
    listen: String,
    tls: bool,
    artifact_dir: String,
    artifacts: Vec<String>,
    service_name: String,
    ssh: String,
    no_sudo: bool,
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RelayStatusReport {
    host: String,
    service_name: String,
    active: Option<bool>,
    healthy: Option<bool>,
    health_url: String,
    artifacts: Vec<RelayArtifactStatus>,
    commands: Vec<ExternalCommandPlan>,
    status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RelayArtifactStatus {
    name: String,
    remote_path: String,
    checksum_remote_path: String,
    executable: Option<bool>,
    checksum_verified: Option<bool>,
}

fn check_relay_status(request: RelayStatusRequest) -> Result<RelayStatusReport> {
    let mut report = plan_relay_status(&request)?;

    if request.dry_run {
        report.status = "dry-run";
        return Ok(report);
    }

    let active = run_external_command_success(&report.commands[0])?;
    let healthy = run_external_command_success(&report.commands[1])?;
    let mut all_artifacts = true;
    let mut all_checksums = true;
    let mut command_index = 2;
    for artifact in report.artifacts.iter_mut() {
        let executable = run_external_command_success(&report.commands[command_index])?;
        command_index += 1;
        let checksum_verified = run_external_command_success(&report.commands[command_index])?;
        command_index += 1;
        artifact.executable = Some(executable);
        artifact.checksum_verified = Some(checksum_verified);
        all_artifacts &= executable;
        all_checksums &= checksum_verified;
    }
    report.active = Some(active);
    report.healthy = Some(healthy);
    report.status = if active && healthy && all_artifacts && all_checksums {
        "ok"
    } else {
        "degraded"
    };
    Ok(report)
}

fn plan_relay_status(request: &RelayStatusRequest) -> Result<RelayStatusReport> {
    validate_remote_host(&request.host)?;
    validate_remote_dir(&request.artifact_dir)?;
    validate_service_name(&request.service_name)?;
    validate_external_program(&request.ssh, "ssh")?;
    validate_listen(&request.listen)?;
    if request.artifacts.is_empty() {
        return Err(anyhow!("at least one artifact name is required"));
    }
    for artifact in &request.artifacts {
        validate_artifact_name(artifact)?;
    }

    let sudo = sudo_prefix(request.no_sudo);
    let service_unit = format!("{}.service", request.service_name);
    let health_url = format!(
        "{}://127.0.0.1:{}/healthz",
        if request.tls { "https" } else { "http" },
        listen_port(&request.listen)?
    );
    let curl_flags = if request.tls { "-fsSk" } else { "-fsS" };
    let mut commands = vec![
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("systemctl is-active --quiet {service_unit}"),
            ],
        },
        ExternalCommandPlan {
            program: request.ssh.clone(),
            args: vec![
                request.host.clone(),
                format!("curl {curl_flags} {}", shell_quote(&health_url)),
            ],
        },
    ];
    let artifacts = request
        .artifacts
        .iter()
        .map(|artifact| {
            let remote_path = format!("{}/{}", request.artifact_dir, artifact);
            let checksum_remote_path = format!("{remote_path}.sha256");
            commands.push(ExternalCommandPlan {
                program: request.ssh.clone(),
                args: vec![
                    request.host.clone(),
                    format!("{}test -x {}", sudo, remote_path),
                ],
            });
            commands.push(ExternalCommandPlan {
                program: request.ssh.clone(),
                args: vec![
                    request.host.clone(),
                    artifact_checksum_command(sudo, &request.artifact_dir, artifact),
                ],
            });
            RelayArtifactStatus {
                name: artifact.clone(),
                remote_path,
                checksum_remote_path,
                executable: None,
                checksum_verified: None,
            }
        })
        .collect::<Vec<_>>();

    Ok(RelayStatusReport {
        host: request.host.clone(),
        service_name: request.service_name.clone(),
        active: None,
        healthy: None,
        health_url,
        artifacts,
        commands,
        status: "planned",
    })
}

fn artifact_checksum_command(sudo: &str, artifact_dir: &str, artifact: &str) -> String {
    let checksum_name = format!("{artifact}.sha256");
    let inner = format!(
        "cd {} && test -s {} && (if command -v sha256sum >/dev/null 2>&1; then sha256sum -c {}; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -c {}; else echo 'sha256 verifier missing' >&2; exit 1; fi)",
        shell_quote(artifact_dir),
        shell_quote(&checksum_name),
        shell_quote(&checksum_name),
        shell_quote(&checksum_name)
    );
    if sudo.is_empty() {
        inner
    } else {
        format!("sudo sh -c {}", shell_quote(&inner))
    }
}

fn run_external_command_success(command: &ExternalCommandPlan) -> Result<bool> {
    let output = ProcessCommand::new(&command.program)
        .args(&command.args)
        .output()
        .with_context(|| format!("failed to run {}", command.display()))?;
    Ok(output.status.success())
}

fn print_relay_status_report(report: &RelayStatusReport) {
    println!("service: {}", report.service_name);
    println!("host: {}", report.host);
    println!("active: {}", bool_label(report.active));
    println!("health: {}", bool_label(report.healthy));
    println!("status: {}", report.status);
    for artifact in &report.artifacts {
        println!(
            "artifact: {} {} executable={} checksum={}",
            artifact.name,
            artifact.remote_path,
            bool_label(artifact.executable),
            bool_label(artifact.checksum_verified)
        );
    }
    if report.status == "dry-run" {
        println!("commands:");
        for command in &report.commands {
            println!("{}", command.display());
        }
    }
}

fn bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn validate_remote_host(host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'));
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe relay host: {host}"))
    }
}

fn validate_remote_dir(path: &str) -> Result<()> {
    let valid = path.starts_with('/')
        && path.len() > 1
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .all(|segment| segment != "." && segment != "..");
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe artifact directory: {path}"))
    }
}

fn validate_remote_file(path: &str) -> Result<()> {
    let valid = path.starts_with('/')
        && path.len() > 1
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .all(|segment| segment != "." && segment != "..");
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe remote file path: {path}"))
    }
}

fn validate_optional_tls_paths(cert: Option<&str>, key: Option<&str>) -> Result<()> {
    match (cert, key) {
        (Some(cert), Some(key)) => {
            validate_remote_file(cert)?;
            validate_remote_file(key)?;
            Ok(())
        }
        (Some(_), None) => Err(anyhow!("--tls-cert requires --tls-key")),
        (None, Some(_)) => Err(anyhow!("--tls-key requires --tls-cert")),
        (None, None) => Ok(()),
    }
}

fn validate_systemd_artifact_dir(path: &str) -> Result<()> {
    if path == "/tmp" || path.starts_with("/tmp/") {
        return Err(anyhow!(
            "systemd artifact directory must not be under /tmp when PrivateTmp is enabled: {path}"
        ));
    }
    Ok(())
}

fn validate_service_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe systemd service name: {name}"))
    }
}

fn validate_linux_user(user: &str) -> Result<()> {
    let valid = !user.is_empty()
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe linux user name: {user}"))
    }
}

fn validate_artifact_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe artifact name: {name}"))
    }
}

fn validate_external_program(program: &str, label: &str) -> Result<()> {
    let valid = !program.is_empty() && !program.starts_with('-') && !program.contains('/');
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe {label} program name: {program}"))
    }
}

fn validate_listen(listen: &str) -> Result<()> {
    listen_port(listen)?;
    let valid = !listen.is_empty() && !listen.bytes().any(|byte| byte.is_ascii_whitespace());
    if valid {
        Ok(())
    } else {
        Err(anyhow!("unsafe listen address: {listen}"))
    }
}

fn ensure_listen_available(listen: &str) -> Result<()> {
    validate_listen(listen)?;
    if listen_port(listen)? == 0 {
        return Ok(());
    }

    let listener = StdTcpListener::bind(listen).with_context(|| {
        format!(
            "local listen address {listen} is unavailable; choose another port with --listen host:port or use --listen 127.0.0.1:0 for a dynamic port"
        )
    })?;
    drop(listener);
    Ok(())
}

fn validate_public_url(public_url: &str) -> Result<()> {
    let url =
        Url::parse(public_url).with_context(|| format!("invalid relay public URL {public_url}"))?;
    validate_relay_transport(&url)?;
    match url.scheme() {
        "http" | "https" => {}
        other => return Err(anyhow!("unsupported relay public URL scheme: {other}")),
    }
    if public_url.bytes().any(|byte| byte.is_ascii_whitespace()) || public_url.contains('%') {
        return Err(anyhow!("unsafe relay public URL: {public_url}"));
    }
    Ok(())
}

fn validate_relay_transport(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" | "wss" => Ok(()),
        "http" | "ws" if url_uses_loopback_host(url) => Ok(()),
        "http" | "ws" => Err(anyhow!(
            "non-local relay URLs must use https or wss; use http/ws only for loopback development"
        )),
        other => Err(anyhow!("unsupported relay URL scheme: {other}")),
    }
}

fn url_uses_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn listen_port(listen: &str) -> Result<u16> {
    let (_, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("listen address must include a port: {listen}"))?;
    port.parse::<u16>()
        .with_context(|| format!("invalid listen port in {listen}"))
}

fn parent_dir(path: &str) -> Result<String> {
    let (parent, _) = path
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("remote file path has no parent directory: {path}"))?;
    if parent.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(parent.to_owned())
    }
}

fn sudo_prefix(no_sudo: bool) -> &'static str {
    if no_sudo {
        ""
    } else {
        "sudo "
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[derive(Debug, Serialize)]
struct SessionEndResult {
    server: String,
    session: String,
    closed: bool,
}

#[derive(Debug, Serialize)]
struct LoginResult {
    server: String,
    config_path: String,
    operator_token_stored: bool,
    relay_fingerprint: Option<RelayFingerprint>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct AssistSshResult {
    session: String,
    join_command: String,
    listen: String,
    ssh_command: String,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct AssistRdpResult {
    session: String,
    join_command: String,
    listen: String,
    rdp_command: String,
    status: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish_request() -> AgentArtifactPublishRequest {
        AgentArtifactPublishRequest {
            host: "relay-host".to_owned(),
            artifact_dir: "/tmp/relaykit-artifacts".to_owned(),
            binary: PathBuf::from("target/release/relaykit-agent"),
            target: AgentArtifactTarget::LinuxX86_64,
            ssh: "ssh".to_owned(),
            scp: "scp".to_owned(),
            no_sudo: false,
            dry_run: true,
        }
    }

    #[test]
    fn agent_artifact_targets_map_to_relay_names() {
        assert_eq!(
            AgentArtifactTarget::LinuxX86_64.artifact_name(),
            "relaykit-agent-linux-x86_64"
        );
        assert_eq!(
            AgentArtifactTarget::LinuxAarch64.artifact_name(),
            "relaykit-agent-linux-aarch64"
        );
        assert_eq!(
            AgentArtifactTarget::WindowsX86_64.artifact_name(),
            "relaykit-agent-windows-x86_64.exe"
        );
        assert_eq!(
            AgentArtifactTarget::WindowsAarch64.artifact_name(),
            "relaykit-agent-windows-aarch64.exe"
        );
    }

    #[test]
    fn publish_plan_uses_atomic_remote_activation() {
        let plan = plan_agent_artifact_publish(&publish_request()).expect("valid plan");

        assert_eq!(plan.host, "relay-host");
        assert_eq!(
            plan.remote_path,
            "/tmp/relaykit-artifacts/relaykit-agent-linux-x86_64"
        );
        assert_eq!(plan.checksum_name, "relaykit-agent-linux-x86_64.sha256");
        assert_eq!(
            plan.checksum_remote_path,
            "/tmp/relaykit-artifacts/relaykit-agent-linux-x86_64.sha256"
        );
        assert!(plan
            .temporary_remote_path
            .starts_with("/tmp/relaykit-agent-linux-x86_64.tmp-"));
        assert!(plan
            .temporary_checksum_remote_path
            .starts_with("/tmp/relaykit-agent-linux-x86_64.sha256.tmp-"));
        assert!(plan
            .local_checksum_path
            .contains("relaykit-agent-linux-x86_64.sha256.tmp-"));
        assert_eq!(plan.commands.len(), 4);
        assert_eq!(plan.commands[0].program, "ssh");
        assert_eq!(
            plan.commands[0].args,
            vec!["relay-host", "sudo mkdir -p /tmp/relaykit-artifacts"]
        );
        assert_eq!(plan.commands[1].program, "scp");
        assert_eq!(plan.commands[1].args[0], "target/release/relaykit-agent");
        assert!(plan.commands[1].args[1]
            .starts_with("relay-host:/tmp/relaykit-agent-linux-x86_64.tmp-"));
        assert_eq!(plan.commands[2].program, "scp");
        assert!(plan.commands[2].args[0].contains("relaykit-agent-linux-x86_64.sha256.tmp-"));
        assert!(plan.commands[2].args[1]
            .starts_with("relay-host:/tmp/relaykit-agent-linux-x86_64.sha256.tmp-"));
        assert_eq!(plan.commands[3].program, "ssh");
        assert!(plan.commands[3].args[1].contains("sudo install -m 0755"));
        assert!(plan.commands[3].args[1].contains("sudo install -m 0644"));
        assert!(plan.commands[3].args[1].contains("rm -f"));
    }

    #[test]
    fn checksum_sidecar_uses_sha256sum_format() {
        let digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        assert_eq!(
            parse_sha256_output(format!("{digest}  relaykit-agent\n").as_bytes()).unwrap(),
            digest.to_ascii_lowercase()
        );
        assert_eq!(
            checksum_sidecar_contents(&digest.to_ascii_lowercase(), "relaykit-agent-linux-x86_64"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  relaykit-agent-linux-x86_64\n"
        );
        assert!(parse_sha256_output(b"not-a-checksum  file\n").is_err());
    }

    #[test]
    fn publish_plan_rejects_unsafe_remote_inputs() {
        let mut request = publish_request();
        request.host = "-oProxyCommand=bad".to_owned();
        assert!(plan_agent_artifact_publish(&request).is_err());

        let mut request = publish_request();
        request.artifact_dir = "/tmp/../etc".to_owned();
        assert!(plan_agent_artifact_publish(&request).is_err());

        let mut request = publish_request();
        request.artifact_dir = "/tmp/relaykit artifacts".to_owned();
        assert!(plan_agent_artifact_publish(&request).is_err());
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(shell_quote("User's host"), "'User'\\''s host'");
    }

    #[test]
    fn assist_ssh_target_builds_ssh_tunnel_spec() {
        let spec = ssh_target_spec("127.0.0.1:22").expect("valid ssh target");

        assert_eq!(spec.name, "ssh");
        assert_eq!(spec.target.host, "127.0.0.1");
        assert_eq!(spec.target.port, 22);
        assert!(ssh_target_spec("127.0.0.1").is_err());
    }

    #[test]
    fn assist_rdp_target_builds_rdp_tunnel_spec() {
        let spec = rdp_target_spec("127.0.0.1:3389").expect("valid rdp target");

        assert_eq!(spec.name, "rdp");
        assert_eq!(spec.target.host, "127.0.0.1");
        assert_eq!(spec.target.port, 3389);
        assert!(rdp_target_spec("127.0.0.1").is_err());
    }

    #[test]
    fn assist_ssh_hint_uses_listen_port() {
        assert_eq!(
            ssh_client_hint("127.0.0.1:22022"),
            "ssh -p 22022 <user>@127.0.0.1"
        );
        assert_eq!(
            ssh_client_hint("0.0.0.0:2222"),
            "ssh -p 2222 <user>@127.0.0.1"
        );
    }

    #[test]
    fn assist_rdp_hint_uses_listen_port() {
        assert_eq!(rdp_client_endpoint("127.0.0.1:23389"), "127.0.0.1:23389");
        assert_eq!(rdp_client_endpoint("0.0.0.0:23389"), "127.0.0.1:23389");
        assert!(rdp_client_hint("127.0.0.1:23389").contains("127.0.0.1:23389"));
    }

    fn test_config_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "relaykit-{name}-{}-config.json",
            std::process::id()
        ))
    }

    #[test]
    fn operator_config_round_trips_without_printing_token() {
        let path = test_config_path("round-trip");
        let _ = std::fs::remove_file(&path);
        let config = OperatorConfig {
            server: "https://relay.example.com".to_owned(),
            operator_token: Some("secret-token".to_owned()),
            relay_fingerprint: None,
        };

        write_operator_config(&path, &config).expect("write config");
        let read = read_operator_config(&path)
            .expect("read config")
            .expect("config exists");
        let _ = std::fs::remove_file(&path);

        assert_eq!(read, config);
    }

    #[test]
    fn resolve_server_prefers_cli_then_config() {
        let config = OperatorConfig {
            server: "https://stored.example.com".to_owned(),
            operator_token: None,
            relay_fingerprint: None,
        };

        assert_eq!(
            resolve_server(Some("https://cli.example.com".to_owned()), Some(&config)).unwrap(),
            "https://cli.example.com"
        );
        assert_eq!(
            resolve_server(None, Some(&config)).unwrap(),
            "https://stored.example.com"
        );
        assert!(resolve_server(None, None).is_err());
    }

    #[test]
    fn resolve_operator_token_prefers_cli_then_config() {
        let config = OperatorConfig {
            server: "https://relay.example.com".to_owned(),
            operator_token: Some("stored-token".to_owned()),
            relay_fingerprint: None,
        };

        assert_eq!(
            resolve_operator_token(Some("cli-token"), Some(&config)).as_deref(),
            Some("cli-token")
        );
        assert_eq!(
            resolve_operator_token(None, Some(&config)).as_deref(),
            Some("stored-token")
        );
        assert_eq!(resolve_operator_token(None, None), None);
    }

    #[test]
    fn resolve_relay_fingerprint_prefers_cli_then_config() {
        let stored: RelayFingerprint =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap();
        let cli: RelayFingerprint =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap();
        let config = OperatorConfig {
            server: "https://relay.example.com".to_owned(),
            operator_token: None,
            relay_fingerprint: Some(stored.clone()),
        };

        assert_eq!(
            resolve_relay_fingerprint(Some(&cli), Some(&config)),
            Some(cli)
        );
        assert_eq!(resolve_relay_fingerprint(None, Some(&config)), Some(stored));
        assert_eq!(resolve_relay_fingerprint(None, None), None);
    }

    #[test]
    fn api_url_requires_tls_for_non_local_relays() {
        let local =
            api_url("http://127.0.0.1:18080", "/api/sessions").expect("loopback http is allowed");
        assert_eq!(local.as_str(), "http://127.0.0.1:18080/api/sessions");

        let remote = api_url("wss://relay.example.com/ws/operator", "/api/sessions")
            .expect("remote wss is normalized to https");
        assert_eq!(remote.as_str(), "https://relay.example.com/api/sessions");

        let err = api_url("http://relay.example.com", "/api/sessions")
            .expect_err("remote plaintext relay URL should fail");
        assert!(
            err.to_string().contains("non-local relay URLs must use"),
            "{err}"
        );
    }

    #[test]
    fn login_url_validation_rejects_non_local_plaintext() {
        validate_operator_server_url("https://relay.example.com")
            .expect("remote https should be accepted");
        validate_operator_server_url("http://127.0.0.1:18080")
            .expect("loopback http should be accepted");

        let err = validate_operator_server_url("http://relay.example.com")
            .expect_err("remote plaintext relay URL should fail before storing config");
        assert!(
            err.to_string().contains("non-local relay URLs must use"),
            "{err}"
        );
    }

    fn systemd_request() -> RelaySystemdDeployRequest {
        RelaySystemdDeployRequest {
            host: "relay-host".to_owned(),
            binary: PathBuf::from("target/release/relaykitd"),
            public_url: "https://relay.example.com".to_owned(),
            listen: "0.0.0.0:18080".to_owned(),
            tls_cert: None,
            tls_key: None,
            install_dir: "/opt/relaykit/bin".to_owned(),
            artifact_dir: "/var/lib/relaykit/artifacts".to_owned(),
            env_file: "/etc/relaykit/relaykitd.env".to_owned(),
            service_name: "relaykitd".to_owned(),
            service_user: "relaykit".to_owned(),
            ssh: "ssh".to_owned(),
            scp: "scp".to_owned(),
            no_sudo: false,
            skip_health_check: false,
            dry_run: true,
        }
    }

    #[test]
    fn relay_systemd_plan_generates_unit_without_secrets() {
        let plan = plan_relay_systemd_deploy(&systemd_request()).expect("valid plan");

        assert_eq!(plan.unit_path, "/etc/systemd/system/relaykitd.service");
        assert_eq!(plan.remote_binary_path, "/opt/relaykit/bin/relaykitd");
        assert_eq!(
            plan.health_url.as_deref(),
            Some("http://127.0.0.1:18080/healthz")
        );
        assert!(plan
            .unit
            .contains("EnvironmentFile=/etc/relaykit/relaykitd.env"));
        assert!(plan.unit.contains(
            "ExecStart=/opt/relaykit/bin/relaykitd --listen 0.0.0.0:18080 --public-url https://relay.example.com --artifact-dir /var/lib/relaykit/artifacts"
        ));
        assert!(plan
            .unit
            .contains("ReadWritePaths=/var/lib/relaykit/artifacts"));
        assert!(!plan.unit.contains("RELAYKIT_OPERATOR_TOKEN"));
    }

    #[test]
    fn relay_systemd_plan_uses_ssh_scp_and_systemctl() {
        let plan = plan_relay_systemd_deploy(&systemd_request()).expect("valid plan");

        assert!(plan.commands.iter().any(
            |command| command.program == "scp" && command.args[0] == "target/release/relaykitd"
        ));
        assert!(plan.commands.iter().any(|command| {
            command.program == "ssh"
                && command
                    .args
                    .get(1)
                    .is_some_and(|arg| arg.contains("systemctl enable relaykitd.service"))
        }));
        assert!(plan.commands.iter().any(|command| {
            command.program == "ssh"
                && command
                    .args
                    .get(1)
                    .is_some_and(|arg| arg.contains("systemctl restart relaykitd.service"))
        }));
        assert!(plan.commands.iter().any(|command| {
            command.program == "ssh"
                && command
                    .args
                    .get(1)
                    .is_some_and(|arg| arg.contains("curl -fsS 'http://127.0.0.1:18080/healthz'"))
        }));
    }

    #[test]
    fn relay_systemd_plan_rejects_unsafe_values() {
        let mut request = systemd_request();
        request.public_url = "ftp://relay.example.com".to_owned();
        assert!(plan_relay_systemd_deploy(&request).is_err());

        let mut request = systemd_request();
        request.public_url = "http://relay.example.com".to_owned();
        assert!(plan_relay_systemd_deploy(&request).is_err());

        let mut request = systemd_request();
        request.service_name = "relaykitd;rm".to_owned();
        assert!(plan_relay_systemd_deploy(&request).is_err());

        let mut request = systemd_request();
        request.env_file = "/etc/relaykit/../token".to_owned();
        assert!(plan_relay_systemd_deploy(&request).is_err());

        let mut request = systemd_request();
        request.listen = "0.0.0.0:not-a-port".to_owned();
        assert!(plan_relay_systemd_deploy(&request).is_err());

        let mut request = systemd_request();
        request.artifact_dir = "/tmp/relaykit-artifacts".to_owned();
        assert!(plan_relay_systemd_deploy(&request).is_err());

        let mut request = systemd_request();
        request.tls_cert = Some("/etc/relaykit/relay.crt".to_owned());
        assert!(plan_relay_systemd_deploy(&request).is_err());
    }

    #[test]
    fn relay_systemd_plan_supports_builtin_tls() {
        let mut request = systemd_request();
        request.public_url = "https://relay.example.com:18443".to_owned();
        request.listen = "0.0.0.0:18443".to_owned();
        request.tls_cert = Some("/etc/relaykit/relay.crt".to_owned());
        request.tls_key = Some("/etc/relaykit/relay.key".to_owned());

        let plan = plan_relay_systemd_deploy(&request).expect("valid TLS plan");

        assert_eq!(
            plan.health_url.as_deref(),
            Some("https://127.0.0.1:18443/healthz")
        );
        assert!(plan
            .unit
            .contains(" --tls-cert /etc/relaykit/relay.crt --tls-key /etc/relaykit/relay.key"));
        assert!(plan.commands.iter().any(|command| {
            command.program == "ssh"
                && command
                    .args
                    .get(1)
                    .is_some_and(|arg| arg.contains("curl -fsSk 'https://127.0.0.1:18443/healthz'"))
        }));
    }

    fn status_request() -> RelayStatusRequest {
        RelayStatusRequest {
            host: "relay-host".to_owned(),
            listen: "0.0.0.0:18080".to_owned(),
            tls: false,
            artifact_dir: "/var/lib/relaykit/artifacts".to_owned(),
            artifacts: vec!["relaykit-agent-linux-x86_64".to_owned()],
            service_name: "relaykitd".to_owned(),
            ssh: "ssh".to_owned(),
            no_sudo: false,
            dry_run: true,
        }
    }

    #[test]
    fn relay_status_plan_checks_service_health_and_artifacts() {
        let report = plan_relay_status(&status_request()).expect("valid status plan");

        assert_eq!(report.health_url, "http://127.0.0.1:18080/healthz");
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(
            report.artifacts[0].remote_path,
            "/var/lib/relaykit/artifacts/relaykit-agent-linux-x86_64"
        );
        assert_eq!(
            report.artifacts[0].checksum_remote_path,
            "/var/lib/relaykit/artifacts/relaykit-agent-linux-x86_64.sha256"
        );
        assert_eq!(report.commands.len(), 4);
        assert!(report.commands[0].args[1].contains("systemctl is-active"));
        assert!(report.commands[1].args[1].contains("curl -fsS"));
        assert!(report.commands[2].args[1]
            .contains("sudo test -x /var/lib/relaykit/artifacts/relaykit-agent-linux-x86_64"));
        assert!(report.commands[3].args[1].contains("sudo sh -c"));
        assert!(report.commands[3].args[1].contains("sha256sum -c"));
        assert!(report.commands[3].args[1].contains("relaykit-agent-linux-x86_64.sha256"));
    }

    #[test]
    fn relay_status_plan_rejects_unsafe_artifact_names() {
        let mut request = status_request();
        request.artifacts = vec!["../relaykit-agent".to_owned()];

        assert!(plan_relay_status(&request).is_err());
    }
}
