## Summary

-

## Safety Review

- [ ] Assisted-user consent remains explicit.
- [ ] Assisted-user stop path remains clear.
- [ ] Operator-only APIs still require authentication.
- [ ] Tunnel targets remain explicit and per-session.
- [ ] Non-local transport remains HTTPS/WSS or fingerprint-pinned.
- [ ] Artifacts remain traceable and checksum-verified where hosted.
- [ ] Audit evidence is preserved or improved.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`

## Notes

Mention any intentionally skipped checks and why.
