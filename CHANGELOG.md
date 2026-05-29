# Changelog

All notable RelayKit changes are recorded here.

This project follows the spirit of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) for human-readable
release notes. Version numbers follow [SemVer](https://semver.org/) where
practical, but `0.x` releases remain private pilot builds until the support
policy is finalized.

## Unreleased

### Changed

- Changed the internal v0 wire codec from unmaintained `bincode` to JSON via
  `serde_json`. Do not mix agents, relays, and operator binaries built from
  different commits.

## 0.1.0 - 2026-05-28

Release scope: private Linux/SSH pilot. RDP remains lab-only. Public release
artifacts were not migrated into the clean public repository.

### Added

- Added `relaykitd`, a self-hosted relay daemon for session creation, hosted
  join assets, WebSocket tunnel transport, direct TLS, and structured audit
  logs.
- Added `rk`, the operator CLI for login, relay health checks, systemd
  deployment, artifact publishing, session creation, and local tunnel opening.
- Added `relaykit-agent`, the assisted-machine helper that joins short-lived
  sessions and exposes only explicitly allowed local TCP targets.
- Added a guided SSH workflow through `rk assist ssh`, including a user-visible
  join command and a localhost-only operator tunnel by default.
- Added direct HTTPS/WSS serving in `relaykitd` with `--tls-cert` and
  `--tls-key`, so a relay can run on a raw IP address without a reverse proxy
  or DNS name.
- Added relay certificate fingerprint pinning through
  `--relay-fingerprint sha256:<cert-der-sha256>`, using the pinned certificate
  as the relay identity for self-owned deployments.
- Added hosted Linux and Windows join script generation with checksum sidecars
  for hosted agent artifacts.
- Recorded 0.1.0 release evidence, artifact hashes, rollback notes, and pilot
  notes privately before preparing the clean public repository.

### Security

- Operator APIs require explicit operator authentication before creating
  sessions, listing sessions, uploading artifacts, or opening tunnels.
- Assisted-user join commands never contain the operator token.
- Session codes are single-use by default and can expire.
- Agents can expose only the tunnel targets authorized for their session.
- Non-local relay URLs require encrypted HTTPS/WSS unless the operator is using
  loopback development.
- Hosted join scripts refuse missing or mismatched artifact checksum sidecars.
- Relay audit logs include session, source, device label, capability, and
  operator-auth context needed for pilot review.

### Changed

- Clarified that 0.1.0 is a Unix-style standalone relay tool. It does not
  require nginx, a managed domain, or an inbound assisted-machine address.
- Clarified that the 0.1.0 real-user path is Linux/SSH only.
- Kept RDP commands available for lab testing only until a supported Windows
  rehearsal is recorded.

### Known Limitations

- Release artifacts are not signed yet. Verify the GitHub asset digest and the
  archive's `SHA256SUMS` before use.
- There is no package manager, installer, or automatic upgrade path yet.
- Operator token creation and rotation are manual operational tasks.
- Public support, vulnerability response targets, and long-term compatibility
  promises are not established for the private pilot.
