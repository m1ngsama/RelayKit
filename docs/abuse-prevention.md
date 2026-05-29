# Abuse Prevention

RelayKit can move traffic into an assisted user's machine. That makes abuse
prevention part of the product design, not an afterthought.

## Project Stance

RelayKit is for explicit, time-bound remote assistance. It should not provide
stealth installation, unattended persistence, credential theft, security-control
bypass, or hidden access.

The open-source license does not restrict fields of use. The project instead
uses narrow scope, safe defaults, review policy, documentation, and issue
triage to avoid normalizing abusive workflows.

## Required Product Properties

- Assisted users intentionally start a named session.
- Assisted users can see and stop the running agent.
- Operators authenticate before creating sessions or opening tunnels.
- Assisted-user commands never contain operator tokens.
- Session codes are short-lived and single-use by default.
- Tunnel targets are explicit and per-session.
- Operator listeners bind to localhost by default.
- Hosted artifacts are checksum-verified.
- Non-local relay connections use HTTPS/WSS and either public trust or
  fingerprint pinning.
- Audit logs are sufficient to reconstruct session start, end, source, device
  label, capability, and operator-auth context.

## Contributions That Need Extra Review

- RDP or Windows configuration automation.
- Automatic installers or one-line scripts for real users.
- Background services, login items, scheduled tasks, or persistence.
- Credential storage, collection, forwarding, or reset flows.
- Public-interface tunnel listeners.
- Relay discovery, device enrollment, or unattended reconnect features.
- Any feature that weakens TLS, fingerprint pinning, operator auth, session
  expiry, or audit logging.

## Contributions That Will Be Rejected

- Hidden execution.
- Stealth persistence.
- Credential extraction.
- Security-control bypass.
- Instructions to disable platform protections for real assistance.
- Broad local network access without explicit per-session scope.
- Changes that make it hard for the assisted user to stop a session.

## Public Issue Handling

Use public issues for non-sensitive bugs and feature requests. Do not include:

- Active session codes.
- Operator tokens.
- Private relay URLs or IPs.
- Private keys.
- User-identifying logs.
- Exploit details for active vulnerabilities.
- Support transcripts.

Use `SECURITY.md` for vulnerabilities.

## Maintainer Checklist

Before accepting a feature, answer:

1. Who gains a new capability?
2. Can the assisted user see it?
3. Can the assisted user stop it?
4. Is operator auth still required?
5. Is the tunnel scope explicit?
6. Is non-local transport encrypted and identity-checked?
7. Is artifact provenance preserved?
8. Does the audit trail still explain what happened?
