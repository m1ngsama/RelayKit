# Security Principles

RelayKit is remote assistance infrastructure. The default design must assume mistakes are costly and make consent, visibility, and auditability first-class requirements.

## Requirements

- Sessions must require explicit user consent.
- Sessions must be short-lived by default.
- The user must have an obvious way to stop an active session.
- Operators must authenticate before creating or joining sessions.
- Session codes must expire and be single-use unless a different policy is explicitly chosen.
- Sensitive actions should be logged with timestamps, operator identity, device identity, and session ID.
- Transport should be encrypted end to end where practical, and always encrypted over the network.
- Secrets must never be stored in the repository.

## Release Gates

These gates are release blockers for any real-user 0.1.0 pilot. Development
can continue locally when a gate is incomplete, but RelayKit should not be
presented as ready for real assistance until each gate passes.

| Gate | Required evidence | Blocks release when |
| --- | --- | --- |
| Consent | The assisted user intentionally starts a named session with a command or visible binary. | A session can start hidden, unattended, or through persistence. |
| User stop control | The agent displays or documents how the assisted user can stop the session. | Only the operator can practically stop access. |
| Session bounds | Codes expire and are single-use by default. | A stale or reused code can attach a new agent without an explicit policy. |
| Operator authentication | Operator APIs and tunnels require the operator token or saved operator config. | The assisted-user command includes an operator token or server secret. |
| Relay identity | Non-local relay connections use HTTPS/WSS with either public trust or an explicit `sha256:` relay certificate fingerprint. | A real-user path relies on public HTTP/WS or asks the user to ignore TLS warnings. |
| Audit trail | Events include timestamp, session ID, device label, operator identity when available, source address, capability, start, and end. | A completed session cannot be reconstructed for review. |
| Localhost defaults | Operator listeners bind to localhost unless the operator explicitly chooses otherwise. | A tunnel is exposed on a public interface by default. |
| Explicit capability | Each exposed assisted-machine target is named and scoped to the session. | The agent exposes undeclared ports or broad local network access. |
| Artifact provenance | User-run binaries have a known source, version/build identity, and development-only warning when unsigned. | A real user is asked to run an untraceable binary or bypass security warnings. |
| Credential safety | RelayKit instructions never ask users to send passwords, private keys, or RDP credentials through RelayKit or chat. | Support depends on credential collection outside the user's normal SSH/RDP client. |

For hosted join paths, `rk artifact publish-agent` publishes `<artifact>.sha256`
next to the agent binary. `rk relay status` verifies that sidecar, and the
generated join scripts refuse checksum mismatches or missing sidecars.

`relaykitd` emits structured audit log events with `audit=true`, a Unix
timestamp, session ID, device label when present, source address when present,
capability/target information, and operator auth mode. For the 0.1.0 pilot, run
`relaykitd` under a log collector such as systemd-journald and preserve those
logs during rollback or incident review.

## Guardrails

RelayKit should not implement:

- Hidden installation or hidden execution.
- Persistence without clear user approval.
- Credential extraction.
- Security-control bypass.
- Undisclosed screen, camera, microphone, or file access.

## Windows And RDP Safety

For the 0.1.0 pilot, RDP support means tunneling to an existing Windows Remote
Desktop service. It does not mean RelayKit configures Windows into accepting
remote desktop connections.

RelayKit must not automatically:

- Enable Remote Desktop.
- Open or weaken Windows Firewall rules.
- Add users to the Remote Desktop Users group.
- Create, reset, collect, or transmit Windows passwords.
- Disable Network Level Authentication or other Windows security controls.
- Install a service, scheduled task, login item, or other persistence mechanism.
- Ask real users to bypass Defender SmartScreen or equivalent platform warnings.

RDP sessions should be treated as ready only when the assisted user already has
RDP enabled by the machine owner/admin, the agent preflight can reach
`127.0.0.1:3389` or reports a clear warning, and the operator tunnel remains
localhost-only by default.

## Operational Notes

Early development should use test-only session codes and local configuration. Production deployments will need signed builds, key rotation, audit retention policy, and a clear incident response path.
