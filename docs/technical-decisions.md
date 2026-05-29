# Technical Decisions

## Rust As The Primary Runtime

RelayKit uses Rust because the project needs small binaries, predictable resource use, robust networking, and cross-platform distribution.

## Unix-Style Binaries

RelayKit uses separate binaries instead of one large command:

- `relaykitd`: relay daemon.
- `relaykit-agent`: assisted-machine helper.
- `rk`: operator CLI.

Each binary should do one job, support scriptable output with `--json`, return meaningful exit codes, and stop cleanly on signals.

## WebSocket/TLS Before QUIC

The first real transport should be WebSocket over TLS. `relaykitd` should be
usable as a standalone Unix daemon: it can terminate TLS itself with
`--tls-cert` and `--tls-key`, and operators can still put another TLS
terminator in front of it when their environment requires that.

QUIC remains a later option if performance, multiplexing, or mobile-network behavior makes it worth the deployment cost.

## Session Key, Not Server Secret

Users should receive short-lived session codes, not server secrets. Server secrets and operator credentials belong only on operator-controlled machines.

RelayKit now separates:

- Operator token: required by `relaykitd` with `--operator-token` or `RELAYKIT_OPERATOR_TOKEN`, and passed by `rk` with the same env var or `--operator-token`. Operator HTTP requests and WebSocket handshakes send it as bearer authorization, not in assisted-user commands or WebSocket query strings.
- Session code: generated per support session and given to the assisted user.

Session codes are single-use by default. If a code is reused, the relay rejects the second agent join.

## Bounded Relay Channels

RelayKit uses bounded internal channels on relay and agent stream paths. A stalled peer should apply pressure to the stream instead of growing memory without limit.

## Relay-Hosted Agent Bootstrap

`relaykitd` can serve assisted-machine artifacts from `--artifact-dir`. When enabled, session creation returns a one-line command:

```sh
sh -c 'u=$1; curl -fsSL --connect-timeout 10 --max-time 120 --noproxy "*" "$u" || curl -fsSL --connect-timeout 10 --max-time 120 "$u"' sh 'https://relay.example.com/join/RK-REPLACE-ME.sh' | sh
```

The generated Linux script downloads `relaykit-agent-linux-x86_64` or `relaykit-agent-linux-aarch64` from the relay and runs it with the one-time session code. The generated Windows PowerShell script downloads `relaykit-agent-windows-x86_64.exe` or `relaykit-agent-windows-aarch64.exe` and runs it visibly in the current PowerShell window. These scripts do not include the operator token.

`rk artifact publish-agent` publishes a SHA-256 sidecar next to each artifact. Hosted join scripts verify the sidecar and refuse to run when the sidecar is missing or mismatched.

Non-local relay URLs must use HTTPS/WSS. Loopback HTTP/WS remains available for
local development. Production-like tests should run `relaykitd` with built-in
TLS or an explicitly chosen external terminator and use the HTTPS public URL. A
DNS name is optional: raw-IP relays can use a self-signed or private certificate
when the operator and agent pass
`--relay-fingerprint sha256:<cert-der-sha256>`.

The operator CLI publishes agent artifacts by composing local `ssh` and `scp` binaries instead of embedding an SSH client. This keeps the tool small, inspectable, and compatible with existing operator SSH configuration.

## Relay systemd Deployment

`rk relay deploy-systemd` deploys `relaykitd` to a Linux relay host by composing
local `ssh` and `scp`, then installing a generated systemd unit. The unit
requires an env file for `RELAYKIT_OPERATOR_TOKEN`; the deploy command does not
accept or transmit that secret. When `--tls-cert` and `--tls-key` are provided,
the generated unit starts `relaykitd` as its own HTTPS/WSS listener rather than
requiring a sidecar proxy.

## Agent Local Target Preflight

`relaykit-agent` checks exposed TCP targets before joining the relay. Preflight failures are warnings rather than hard errors, because the operator may still need a live session to help start SSH, enable RDP, or inspect a local firewall issue.

## TCP Tunnels Before GUI Control

v0 focuses on SSH 22, RDP 3389, and generic TCP tunnels. Full screen viewing and keyboard/mouse control are deferred because they require platform-specific permissions, input injection, capture APIs, and a larger safety model.
