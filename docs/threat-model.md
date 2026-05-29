# RelayKit Threat Model

Scope: `rk`, `relaykitd`, `relaykit-agent`, hosted join scripts, release
artifacts, and the 0.1.x Linux/SSH pilot workflow.

Out of scope for this model: future GUI remote desktop, unattended device
enrollment, managed SaaS control planes, and real-user RDP support.

## System Model

RelayKit has three runtime roles:

- Operator machine: runs `rk`, authenticates to the relay, creates sessions,
  and opens local tunnels.
- Relay host: runs `relaykitd`, authenticates operators, validates session
  codes, serves hosted join assets, and routes tunnel streams.
- Assisted machine: runs `relaykit-agent` visibly, joins a session with a
  short-lived code, and exposes explicitly allowed local TCP targets.

The 0.1.x public promise is narrow: self-hosted Linux/SSH remote assistance for
explicit, short-lived support sessions. Non-local transport must be HTTPS/WSS
with either public trust or an explicit `sha256:` relay certificate
fingerprint.

## Assets

- Operator token and saved operator config.
- Session codes and session IDs.
- Relay TLS private key and relay certificate fingerprint.
- Agent and relay release binaries.
- Hosted agent artifacts and `.sha256` sidecars.
- Audit logs containing session, source address, device label, capability, and
  operator-auth context.
- Assisted-machine local services exposed through a session, such as
  `127.0.0.1:22`.

## Trust Boundaries

| Boundary | Existing controls | Primary risk |
| --- | --- | --- |
| Operator to relay API | Operator token or saved config; non-local HTTPS/WSS; optional fingerprint pinning | Unauthorized session creation or tunnel opening |
| Assisted machine to relay | Short-lived session code; explicit tunnel offers; TLS/fingerprint support | Session hijack, stale code reuse, or relay impersonation |
| Relay to hosted artifact directory | Controlled artifact path; `.sha256` sidecars; status checks | Agent substitution or stale artifact use |
| Operator local tunnel to local clients | Localhost-only listeners by default | Accidental public exposure of assisted services |
| Assisted agent to local service | Per-session target allowlist and preflight | Exposing unintended local ports |
| Release process to users | Release archives, `SHA256SUMS`, release notes, CI release workflow | Compromised or unverifiable binaries |
| Public issue tracker to maintainers | SECURITY.md and issue templates | Disclosure of active exploit details or private pilot data |

## Realistic Attackers

- Network attacker between operator, relay, and assisted machine.
- Unauthorized person with access to a leaked operator token or session code.
- Malicious or compromised relay host operator.
- Attacker who can modify hosted agent artifacts.
- Contributor or issue reporter who submits unsafe changes or public exploit
  details.
- User who accidentally runs an old or unverified agent binary.

Non-capabilities assumed for 0.1.x: no kernel compromise, no bypass of the
operator's local SSH client, and no protection against a relay host owner who is
fully malicious and controls both binary deployment and logs.

## Priority Threats

### T1: Unauthorized Operator Access

Impact: high. Likelihood: medium.

If an attacker gets the operator token or bypasses operator auth, they can
create sessions, list sessions, upload artifacts, and open tunnels. Existing
controls require operator auth by default and keep the token out of assisted
join commands.

Mitigations:

- Keep `RELAYKIT_OPERATOR_TOKEN` out of git, issues, release notes, and join
  commands.
- Rotate tokens before and after unclear pilot access.
- Add token scoping and rotation tooling before broader beta.
- Preserve audit logs for all operator-authenticated actions.

### T2: Relay Impersonation Or TLS Downgrade

Impact: high. Likelihood: medium.

An attacker who convinces an operator or agent to use a fake relay can observe
or control session setup. Existing controls reject public plaintext for
non-local use and support `sha256:` certificate fingerprint pinning.

Mitigations:

- Keep public examples on HTTPS/WSS.
- Require fingerprint pinning for self-signed raw-IP relays.
- Treat plaintext HTTP/WS as loopback-only development.
- Document relay fingerprint verification in every install path.

### T3: Agent Artifact Substitution

Impact: high. Likelihood: medium.

If hosted artifacts are replaced or served without checksums, assisted users
could run the wrong binary. Existing controls publish `.sha256` sidecars and
join scripts refuse missing or mismatched sidecars.

Mitigations:

- Keep `.sha256` sidecars mandatory for hosted join.
- Add signed release artifacts before public beta.
- Keep CI release packaging reproducible and reviewable.
- Avoid asking users to bypass platform security prompts for real assistance.

### T4: Unauthorized Local Port Exposure

Impact: high. Likelihood: low to medium.

A bug in tunnel authorization could expose a local service that the operator did
not request or the assisted user did not intend to share. Existing controls use
explicit per-session tunnel specs and agent expose validation.

Mitigations:

- Keep localhost-only operator listeners as the default.
- Test unauthorized tunnel names, target mismatches, and duplicate offers.
- Require explicit review for broad network exposure features.
- Keep RDP setup automation out of real-user scope until separately reviewed.

### T5: Stale Or Reused Session Codes

Impact: medium to high. Likelihood: medium.

Reusable or long-lived session codes could allow a later unintended join.
Existing controls make codes single-use by default and support expiration.

Mitigations:

- Keep single-use as the default.
- Audit failed reuse and expiry attempts.
- Make any reusable-code policy explicit, rare, and documented.

### T6: Public Disclosure Of Private Pilot Data

Impact: medium. Likelihood: medium.

Public issues, docs, release evidence, or logs can leak real relay IPs,
fingerprints, usernames, host aliases, user labels, or support transcripts.

Mitigations:

- Use documentation-only IPs such as `203.0.113.10`.
- Keep private pilot notes outside the public repository.
- Redact logs before attaching them to issues.
- Run a current-tree and history secret scan before making the repository
  public.

## Security Roadmap

Before broad public beta:

- Add signed artifacts.
- Add SBOM/provenance for release archives.
- Add token rotation and operational runbooks.
- Add rate limiting or abuse throttling for public relay deployments.
- Add CI dependency audit enforcement.
- Rehearse Windows/RDP only in lab until a separate threat model and supported
  host evidence exist.

## Open Assumptions

- 0.1.x remains self-hosted and single-operator or small-team operated.
- Operators own the relay host or trust the relay host administrator.
- Assisted users intentionally launch the agent and can close it.
- The project will not accept hidden execution or persistence features.
