# Contributing To RelayKit

RelayKit is a self-hosted remote assistance relay. Contributions are welcome,
but the project has a narrow safety boundary: assistance must be explicit,
time-bound, authenticated, auditable, and easy for the assisted user to stop.

## Development Setup

Install a stable Rust toolchain with `rustfmt` and `clippy`.

Useful checks:

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --workspace
```

Use loopback HTTP only for local development. Non-local relay testing must use
HTTPS/WSS with either public trust or an explicit `sha256:` relay certificate
fingerprint.

## Pull Request Scope

Good early contributions:

- Linux/SSH pilot reliability.
- Clear user-facing errors.
- Safer defaults.
- Audit logging and replayable test evidence.
- Documentation that improves installation, verification, or threat clarity.
- Tests for authentication, session bounds, tunnel authorization, and artifact
  integrity.

High-risk contributions need prior discussion:

- RDP or Windows setup automation.
- Background services, scheduled tasks, login items, or persistence.
- One-line install scripts for real users.
- Credential handling.
- Broad network exposure beyond explicit localhost tunnel defaults.
- Changes that weaken TLS, fingerprint pinning, operator authentication,
  artifact checksums, or audit logs.

Out of scope:

- Hidden execution.
- Stealth persistence.
- Credential collection.
- Security-control bypass.
- Instructions that ask users to ignore platform security prompts for real
  assistance.

## Security-Sensitive Changes

Every security-sensitive PR should explain:

- Which trust boundary changes.
- Which actor gains or loses capability.
- Whether assisted users can still see and stop the session.
- Whether operator APIs still require authentication.
- Whether tunnel targets remain explicit and per-session.
- What audit evidence proves the behavior.

Use `SECURITY.md` for vulnerability reports. Do not disclose active exploit
details in public issues or pull requests.

## Commit And Review Notes

- Keep changes focused.
- Prefer repository patterns over new abstractions.
- Add tests in the crate that owns the behavior.
- Update docs when the operator or assisted-user workflow changes.
- Do not commit secrets, real relay IPs, internal host aliases, usernames,
  private keys, or pilot transcripts.
