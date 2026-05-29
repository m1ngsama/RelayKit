# RelayKit

[![CI](https://github.com/m1ngsama/RelayKit/actions/workflows/ci.yml/badge.svg)](https://github.com/m1ngsama/RelayKit/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

RelayKit is an open-source Rust toolkit for deploying trusted remote assistance capabilities to user machines quickly, using self-owned compute, relay, and tunneling infrastructure.

The initial goal is not to clone a full commercial remote desktop product. It is to create a reliable operator workflow for helping a user on Windows, macOS, or Linux when they explicitly request support.

## Product Direction

RelayKit should provide:

- `relaykitd`: a self-hosted relay daemon that runs on the operator's server.
- `relaykit-agent`: a lightweight assisted-machine helper that joins short-lived sessions.
- `rk`: an operator CLI for creating sessions and opening SSH/RDP/TCP tunnels.
- Short-lived session codes and audit logs for support sessions.
- Packaging paths for Windows, macOS, and Linux.
- A clear separation between transport, authorization, and remote-control features.

## Non-Goals

RelayKit should not include stealth installation, persistence without consent, credential theft, security-control bypass, or hidden remote access. Remote assistance must be explicit, time-bound, auditable, and easy for the user to stop.

## Repository Layout

```text
crates/
  relaykit-agent/    User-side helper runtime.
  relaykit-cli/      Binaries: rk, relaykit-agent, relaykitd.
  relaykit-platform/ Cross-platform OS detection and setup helpers.
  relaykit-protocol/ Shared IDs, capabilities, and protocol model.
  relaykit-server/   Relay/control-plane runtime.
  relaykit-tunnel/   TCP tunnel model and forwarding primitives.
docs/
  abuse-prevention.md
                     Abuse boundaries for a public remote-access project.
  architecture.md    System shape and component boundaries.
  development-topology.md
                     Local and three-machine development test flows.
  product.md         Product shape and staged scope.
  public-release-checklist.md
                     Checklist before changing public visibility or releases.
  release-roadmap.md 0.0.1 to 0.1.0 iteration order and release gates.
  security.md        Safety, consent, and operational requirements.
  technical-decisions.md
                     Key implementation decisions and deferred tradeoffs.
  threat-model.md    Trust boundaries, assets, threats, and mitigations.
CHANGELOG.md         User-readable release history.
CODE_OF_CONDUCT.md   Community behavior expectations.
CONTRIBUTING.md      Contribution and safety-review guidance.
SECURITY.md          Vulnerability reporting and supported versions.
```

## Quick Start

Download release archives from
[GitHub Releases](https://github.com/m1ngsama/RelayKit/releases), or build from
source with `cargo build --release --workspace`. Each release archive contains
`relaykitd`, `relaykit-agent`, `rk`, and `SHA256SUMS`.

Verify the downloaded archive checksum first, then verify the binaries inside
the archive:

```sh
sha256sum -c relaykit-0.1.1-linux-x86_64.tar.gz.sha256
tar -xzf relaykit-0.1.1-linux-x86_64.tar.gz
cd relaykit-0.1.1-linux-x86_64
sha256sum -c SHA256SUMS
```

On macOS, use `shasum -a 256 -c` for the `.sha256` file and `SHA256SUMS`.

Run the relay daemon with an operator token:

```sh
RELAYKIT_OPERATOR_TOKEN=replace-me \
cargo run -p relaykit-cli --bin relaykitd -- \
  --listen 0.0.0.0:18443 \
  --public-url https://203.0.113.10:18443 \
  --tls-cert /etc/relaykit/relay.crt \
  --tls-key /etc/relaykit/relay.key \
  --artifact-dir /var/lib/relaykit/artifacts
```

`relaykitd` can serve HTTPS/WSS directly. A DNS name and a reverse proxy are
not required; a raw IP certificate works when operators and agents pin the
certificate fingerprint.

For a Linux relay host, deploy `relaykitd` as a systemd service with:

```sh
cargo run -p relaykit-cli --bin rk -- relay deploy-systemd \
  --host 203.0.113.10 \
  --binary target/release/relaykitd \
  --listen 0.0.0.0:18443 \
  --public-url https://203.0.113.10:18443 \
  --tls-cert /etc/relaykit/relay.crt \
  --tls-key /etc/relaykit/relay.key
```

The systemd unit requires the operator token in `/etc/relaykit/relaykitd.env`;
create that env file on the relay host out of band and keep it out of git. If
you use a private key under `/etc/relaykit`, make it readable by the
`relaykit` service user or group, for example mode `0640` with group
`relaykit`.

Check a deployed relay host with:

```sh
cargo run -p relaykit-cli --bin rk -- relay status \
  --host 203.0.113.10 \
  --listen 0.0.0.0:18443 \
  --tls
```

For Linux one-line join support, place the assisted-machine binary at:

```text
/var/lib/relaykit/artifacts/relaykit-agent-linux-x86_64
```

For hosted Windows PowerShell join support, place the assisted-machine binary at:

```text
/var/lib/relaykit/artifacts/relaykit-agent-windows-x86_64.exe
/var/lib/relaykit/artifacts/relaykit-agent-windows-aarch64.exe
```

The Windows script is served as visible text at:

```text
https://relay.example.com/join/RK-REPLACE-ME.ps1
```

It downloads `relaykit-agent.exe` from the relay artifact server, runs it in the
current PowerShell window with the session code and allowed tunnels, and prints
that pressing `Ctrl+C` or closing the window stops assistance. The script does
not include the operator token.

You can publish an already-built Linux agent binary to the relay host with:

```sh
cargo run -p relaykit-cli --bin rk -- artifact publish-agent \
  --host relay.example.com \
  --artifact-dir /var/lib/relaykit/artifacts \
  --binary target/release/relaykit-agent \
  --target linux-x86_64
```

`publish-agent` stages through `/tmp` and uses remote `sudo install` by default, so it works with protected artifact directories. Use `--no-sudo` only for directories already writable by your SSH user.

For Windows artifacts, use `--target windows-x86_64` or `--target windows-aarch64`
with the corresponding `relaykit-agent.exe` build. The publish step uploads a
SHA-256 sidecar at `<artifact>.sha256`; `rk relay status` checks that sidecar,
and the hosted join script verifies it before starting the downloaded agent.

Log in once from the operator machine:

```sh
cargo run -p relaykit-cli --bin rk -- \
  --operator-token replace-me \
  login https://relay.example.com
```

Start a guided SSH assistance workflow:

```sh
cargo run -p relaykit-cli --bin rk -- assist ssh \
  --label customer-203.0.113.10
```

`rk login` stores local operator config in `~/.config/relaykit/config.json` by default on Unix systems and `%APPDATA%\RelayKit\config.json` on Windows. On Unix systems RelayKit writes the config file with owner-only permissions. You can also keep using `--server` and `RELAYKIT_OPERATOR_TOKEN` for stateless operation.

`rk assist ssh` creates a session, prints the one-line command to send to the assisted user, waits for the agent to connect, then opens a local SSH tunnel. By default it exposes `127.0.0.1:22` on the assisted machine and listens on `127.0.0.1:22022` on the operator machine.

`--label` is only an operator-visible label; `--device` remains as a compatibility alias. Use a customer name, ticket number, public IP, or domain if that is what you have. RelayKit does not need the assisted machine to have an inbound hostname; after the agent connects, `rk session list` also shows the relay-observed source address.

The assisted-user command looks like:

```sh
sh -c 'u=$1; curl -fsSL --connect-timeout 10 --max-time 120 --noproxy "*" "$u" || curl -fsSL --connect-timeout 10 --max-time 120 "$u"' sh 'https://relay.example.com/join/RK-REPLACE-ME.sh' | sh
```

If a hosted artifact has no checksum sidecar, the join script refuses to run it.
Hosted join is usable for the 0.1.x real-user pilot only when the matching
`.sha256` sidecar is served and verifies successfully.

Non-local relay URLs must use encrypted HTTPS/WSS. A relay does not need a
domain name: `relaykitd` can listen with `--tls-cert` and `--tls-key` on a raw
IP, and operators can pin that relay certificate with
`--relay-fingerprint sha256:<cert-der-sha256>`. Plaintext HTTP/WS is accepted
only for loopback development.

When `--relay-fingerprint` is set, RelayKit uses that certificate fingerprint
as the relay identity, similar in spirit to an SSH host key. Hosted curl-based
join is not the primary bootstrap path for self-signed IP relays; install or
copy the agent binary through a channel you trust, then run the printed
`relaykit-agent join` command.

For lower-level debugging, you can still create sessions manually:

```sh
cargo run -p relaykit-cli --bin rk -- session new \
  --label customer-203.0.113.10 \
  --allow ssh=127.0.0.1:22 \
  --allow rdp=127.0.0.1:3389
```

Without hosted artifacts, run the agent directly on the assisted machine:

```sh
cargo run -p relaykit-cli --bin relaykit-agent -- join \
  --relay https://203.0.113.10:18443 \
  --relay-fingerprint sha256:REPLACE_WITH_RELAY_CERT_SHA256 \
  --code DEMO-1234 \
  --device customer-203.0.113.10 \
  --tcp ssh=127.0.0.1:22
```

The agent checks each exposed local TCP target before joining and prints a warning if, for example, local SSH on `127.0.0.1:22` is not reachable. Use `--no-preflight` only when you deliberately want to skip that local check.

Open a local operator tunnel:

```sh
cargo run -p relaykit-cli --bin rk -- ssh \
  rk-session-id \
  --listen 127.0.0.1:22022
```

Session codes are single-use by default. The operator token stays with the operator and relay server; assisted users only receive short-lived session codes.

## Release Roadmap

The `0.1.x` line is pilot-quality, not general availability. The executable
iteration order, security gates, Windows/RDP readiness criteria, and real user
experience scripts live in
[docs/release-roadmap.md](docs/release-roadmap.md). User-readable release notes
live in [CHANGELOG.md](CHANGELOG.md).

The current 0.1.x pilot path is Linux/SSH only. RDP commands remain available
for lab testing, but RelayKit should not be used for real-user RDP assistance
until a supported Windows host rehearsal is recorded in the release notes.

RDP support for 0.1.x means a localhost-only tunnel to an existing Windows Remote Desktop service. RelayKit should not automatically enable RDP, change firewall rules, add users, collect passwords, disable Windows security controls, or install persistence for assistance.

## Next Decisions

- Transport: WebSocket/TLS first, then QUIC if the protocol and deployment shape justify it.
- Operator surface: CLI first, browser console or native desktop app later.
- Remote capability: SSH 22, RDP 3389, and generic TCP tunnel first; screen control later.
- Distribution: signed binaries, one-line installer, package managers, or MDM-friendly bundles.
- Identity: operator accounts, device enrollment, one-time session codes, and audit retention.

Use the release gates in [docs/security.md](docs/security.md) before treating any of these decisions as ready for real-user assistance.

## Open Source Readiness

RelayKit accepts contributions within a narrow safety scope. Start with
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[docs/threat-model.md](docs/threat-model.md), and
[docs/abuse-prevention.md](docs/abuse-prevention.md) before proposing changes
to remote access, installation, authentication, or artifact handling.

## License

RelayKit is distributed under the terms of both the MIT license and the Apache
License 2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
