# Public Release Checklist

Use this checklist before switching the repository or a release from private
pilot to public open-source distribution.

## Repository

- [ ] License files are present and `Cargo.toml` uses the matching SPDX
      expression.
- [ ] README describes the narrow public promise and current limitations.
- [ ] `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, and
      `CODE_OF_CONDUCT.md` are present.
- [ ] Issue templates warn users not to post secrets or exploit details.
- [ ] Threat model and abuse prevention docs are current.
- [ ] Current-tree scan contains no real relay IPs, host aliases, usernames,
      tokens, private keys, pilot transcripts, or private paths.
- [ ] Git history has been reviewed before making a formerly private repository
      public. If history contains sensitive pilot data, rewrite history in a
      coordinated maintenance window before public visibility.

## CI And Release

- [ ] `cargo fmt --all --check` passes.
- [ ] `cargo test --workspace` passes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo build --release --workspace` passes.
- [ ] Dependency audit passes or exceptions are documented.
- [ ] Tag-based release workflow creates draft release archives and checksums.
- [ ] Release artifacts contain `relaykitd`, `relaykit-agent`, `rk`, and
      `SHA256SUMS`.
- [ ] Release notes include scope, supported platforms, verification evidence,
      known limitations, and rollback guidance.

## Security

- [ ] GitHub private vulnerability reporting is enabled if available.
- [ ] Maintainers know the private vulnerability triage path.
- [ ] Public issues do not contain active exploit details or private pilot data.
- [ ] Operator token rotation is documented for real pilots.
- [ ] Relay fingerprints and artifact hashes are recorded for pilots without
      exposing private infrastructure details publicly.

## Scope

- [ ] Linux/SSH is the only real-user 0.1.x path.
- [ ] RDP remains lab-only until supported Windows rehearsal evidence exists.
- [ ] No feature implies hidden execution, persistence without consent,
      credential collection, or security-control bypass.
