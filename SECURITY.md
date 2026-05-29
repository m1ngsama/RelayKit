# Security Policy

RelayKit is remote assistance infrastructure. Treat vulnerabilities as
high-impact when they could allow hidden access, unauthorized sessions, token
exposure, relay impersonation, artifact substitution, or audit-log loss.

## Supported Versions

| Version | Status | Notes |
| --- | --- | --- |
| `0.1.0` | Supported for private pilot reports | Linux/SSH pilot only. RDP remains lab-only. |
| `main` | Development | Security reports are welcome, but APIs may change. |
| `< 0.1.0` | Unsupported | Upgrade to 0.1.0 before pilot use. |

## Reporting A Vulnerability

Do not open a public issue with exploit details, tokens, relay URLs containing
secrets, private keys, assisted-user identities, or active session codes.

Preferred reporting path:

1. Use
   [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository)
   for this repository when it is available.
2. If private vulnerability reporting is unavailable, open a minimal public
   issue asking for a private security contact path. Do not include technical
   exploit details in that issue.

Include enough private detail for reproduction when possible:

- RelayKit version or commit.
- Platform and architecture.
- Whether the issue affects `rk`, `relaykitd`, `relaykit-agent`, hosted join
  scripts, artifact publishing, or tunnel forwarding.
- Local reproduction steps using placeholder tokens and non-production hosts.
- Expected security boundary and the observed bypass.
- Relevant audit log lines with secrets and user-identifying details removed.

## 0.1.0 Security Boundaries

The 0.1.0 pilot is intended to preserve these boundaries:

- Operators authenticate before creating sessions, listing sessions, uploading
  artifacts, or opening tunnels.
- Assisted users receive only a short-lived session code or join command, never
  an operator token.
- Non-local relays use HTTPS/WSS and either public trust or an explicit
  `sha256:` relay certificate fingerprint.
- Agents expose only per-session, explicitly allowed local TCP targets.
- Operator-side tunnel listeners bind to localhost by default.
- Hosted artifacts include SHA-256 sidecars and join scripts reject checksum
  failures.
- Real-user assistance remains Linux/SSH only until Windows/RDP pilot evidence
  is recorded.

## Out Of Scope For Public Issues

Please use normal issues or discussions for non-sensitive bugs, documentation
problems, feature requests, and lab-only RDP feedback that does not expose an
active vulnerability.

## Operational Safety

If you suspect active misuse:

1. Stop `relaykitd`.
2. Rotate `RELAYKIT_OPERATOR_TOKEN`.
3. Remove served artifacts from the relay artifact directory.
4. Preserve relay logs for review.
5. Redeploy only after checking the relay binary, agent artifact, TLS
   fingerprint, and operator machines.

For a pilot rollback, stop the relay, rotate the operator token, remove served
artifacts, preserve logs, and redeploy only from verified binaries.
