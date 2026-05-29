# Release Roadmap To 0.1.0

This roadmap turns the current review findings into an executable sequence from
the first usable baseline to a private 0.1.0 pilot. The release target is not
general availability. It is a narrow, auditable remote-assistance workflow that
can help a real consenting user without surprising them.

## Review Themes

- Keep the Linux SSH path as the baseline until it is boringly repeatable.
- Treat safety gates as release blockers, not as follow-up notes.
- Make Windows/RDP readiness explicit before claiming remote-desktop support.
- Validate the real operator/user experience, not only protocol plumbing.
- Do not add stealth, persistence, credential collection, or security-control
  bypass to make a support session easier.

## Milestone Order

| Milestone | Goal | Required work | Exit criteria |
| --- | --- | --- | --- |
| 0.0.1 | Linux SSH lab baseline | Relay deploy, artifact publish, hosted Linux join script, `rk assist ssh`, manual `rk ssh` fallback | Local smoke test and three-machine operator/relay/assisted SSH tunnel pass; session code is single-use; assisted user never receives the operator token |
| 0.0.2 | Consent, stop, and audit hardening | Visible session status, clear stop instructions, session expiry, `rk session end`, audit fields for operator/device/session/source address | A tester can explain how to stop the session; relay logs enough to answer who connected, when, from where, and for which capability |
| 0.0.3 | Distribution and artifact integrity | Stable artifact names, artifact directory permissions, checksum sidecars, publish dry-run, TLS deployment notes | Operator can identify the exact agent artifact served to the user; hosted join refuses checksum-missing or mismatched artifacts |
| 0.0.4 | Windows join readiness | Windows agent artifact path, PowerShell/direct-exe join instructions, visible foreground runtime, Windows config path, outbound relay connectivity checks | A Windows tester can join a TCP session without admin-only installation or background persistence |
| 0.0.5 | RDP readiness | `rk assist rdp`, Windows RDP preflight checklist, unsupported Windows Home note, manual fallback commands | Operator can reach `127.0.0.1:3389` through a localhost RelayKit tunnel; failures distinguish RelayKit tunnel issues from local Windows RDP setup issues |
| 0.1.0 | Private real-user pilot | One SSH or RDP support script rehearsed end to end, security gates passed, rollback and incident notes written | A consenting non-developer can start, observe, and stop a session; the operator can close it and produce the audit trail |

## Security Gates

These gates must pass before tagging 0.1.0. If a gate fails, the next milestone
can still be developed locally, but it should not be used with a real user.

| Gate | Pass condition | Release blocker |
| --- | --- | --- |
| S1 Consent | The assisted user intentionally runs a session command or binary for a named support session | Any hidden start, background install, or unattended join |
| S2 Stop control | The assisted user has an obvious way to terminate the running agent | Closing the operator tunnel is the only practical stop path |
| S3 Session bounds | Session codes expire and are single-use by default | Reusable codes are accepted without an explicit policy decision |
| S4 Operator auth | Operator-only API calls require the operator token or saved operator config | The assisted-user command contains the operator token |
| S5 Auditability | Sensitive events include timestamp, session ID, device label, operator identity when available, source address, and capability | A completed session cannot be reconstructed from relay-side records |
| S6 Local exposure | Operator tunnel listeners bind to localhost by default and exposed assisted-machine targets are explicit | A tunnel listens on a public interface by default or exposes undeclared targets |
| S7 Transport and artifact hygiene | Production-like testing uses TLS with either public trust or an explicit relay certificate fingerprint; artifacts are served from controlled directories; development-only unsigned binaries are labeled | Real-user instructions ask users to bypass security warnings or trust an untraceable binary |
| S8 Credential safety | RelayKit never asks the assisted user to send passwords, private keys, or RDP credentials through chat or the relay | A support script depends on collecting or relaying user credentials |

## Windows/RDP Readiness

RelayKit 0.1.0 should describe RDP as a tunnel to an existing Windows RDP
service, not as a Windows configuration manager.

Current release candidate scope: Linux/SSH is the real-user pilot path. RDP
remains lab-only until a supported Windows host rehearsal is completed and
recorded with the release evidence.

When RDP enters the pilot, supported:

- Windows 10/11 Pro, Enterprise, or Education with Remote Desktop host support.
- Windows Server with Remote Desktop enabled by the owner/admin.
- A visible `relaykit-agent.exe` process launched by the assisted user.
- Outbound relay connectivity from the Windows machine to `relaykitd`.
- Operator-side RDP client connection to a localhost tunnel.

Unsupported or blocked for RDP:

- Windows Home as an assisted RDP host.
- Automatically enabling Remote Desktop.
- Opening or weakening Windows Firewall rules automatically.
- Adding users to the Remote Desktop Users group.
- Creating, resetting, collecting, or transmitting Windows passwords.
- Disabling Network Level Authentication or other Windows security controls.
- Installing a background service, scheduled task, login item, or persistence
  mechanism for assistance.
- Asking users to bypass Defender SmartScreen for a real support session.

Minimum RDP readiness checklist:

1. User confirms they understand that an RDP login may lock or switch their local
   desktop session depending on Windows edition and policy.
2. User confirms Remote Desktop is already enabled by the machine owner/admin.
3. User confirms the intended Windows account is allowed to use RDP.
4. Agent preflight can reach `127.0.0.1:3389` or prints a clear warning.
5. Operator creates a session that exposes only `rdp=127.0.0.1:3389`.
6. Operator opens a localhost-only tunnel, for example `127.0.0.1:13389`.
7. Operator connects their RDP client to the localhost tunnel.
8. Operator ends the RelayKit session when support is complete.
9. Audit records show the RDP capability, session ID, device label, source
   address, start time, and end time.

Current lower-level Windows RDP rehearsal:

```sh
rk session new \
  --server https://relay.example.com \
  --label ticket-1234-windows \
  --capability rdp,tcp \
  --allow rdp=127.0.0.1:3389
```

With the relay artifact server enabled, assisted Windows users can inspect the
hosted PowerShell script for the one-time code printed by `rk session new`:

```text
https://relay.example.com/join/RK-REPLACE-ME.ps1
```

The script downloads `relaykit-agent.exe` from the relay artifact directory and
runs it visibly in the current PowerShell window. It must not contain the
operator token, install persistence, enable RDP, change firewall rules, or ask
the user to bypass Windows security prompts. If script execution is blocked by
local policy, use the direct visible agent command instead of weakening policy:

```powershell
.\relaykit-agent.exe join `
  --relay https://relay.example.com `
  --code RK-REPLACE-ME `
  --device ticket-1234-windows `
  --tcp rdp=127.0.0.1:3389
```

Operator opens the local RDP tunnel:

```sh
rk rdp rk-session-id-replace-me --listen 127.0.0.1:13389
```

Then the operator connects their RDP client to `127.0.0.1:13389`.
After the Windows hosted join path exists, this rehearsal should move to
`rk assist rdp --label ticket-1234-windows --listen 127.0.0.1:13389`.

## Real User Experience Scripts

These scripts are acceptance tests for the product shape. They should be run
with a real consenting tester before calling 0.1.0 ready.

### Script A: Linux SSH Assistance

Operator setup:

1. Log in with `rk login https://relay.example.com`.
2. Start `rk assist ssh --label ticket-1234-linux`.
3. Send only the printed assisted-user command to the user.

Assisted user experience:

1. User sees a short command from the operator and runs it in a terminal.
2. The agent prints the relay URL, session code or session label, exposed target,
   and how to stop the session.
3. User keeps the terminal open during support.
4. User can stop assistance by closing the terminal or using the documented stop
   action.

Operator completion:

1. CLI reports that the assisted machine connected.
2. Operator connects with the printed SSH command.
3. Operator fixes or inspects the issue.
4. Operator ends the session with `rk session end`.
5. Operator confirms the tunnel is closed and audit records exist.

Success criteria:

- The user never receives the operator token.
- The operator listener is localhost-only.
- The session cannot be joined a second time with the same code.
- The user can describe how to stop the agent.

### Script B: Windows RDP Assistance

Operator setup:

1. Confirm the user is on a supported Windows edition with RDP already enabled.
2. Create a session exposing only `rdp=127.0.0.1:3389`.
3. Send the visible Windows agent command and explain that RelayKit does not need
   their Windows password.

Assisted user experience:

1. User launches the visible agent from PowerShell or a terminal.
2. User sees the session label, relay URL, RDP target, and stop instructions.
3. If preflight warns that `127.0.0.1:3389` is unreachable, the session pauses
   and the operator treats it as a Windows RDP setup issue, not a RelayKit
   tunnel success.
4. User stays available while the RDP client connects because Windows may show
   prompts, lock the local display, or require account approval.

Operator completion:

1. Operator starts `rk rdp <session> --listen 127.0.0.1:13389`.
2. Operator opens their RDP client to `127.0.0.1:13389`.
3. Operator enters credentials only into their local RDP client when appropriate;
   credentials are not sent through RelayKit commands or chat.
4. Operator ends the session after support and verifies audit records.

Success criteria:

- The RDP path works without enabling persistence on the assisted machine.
- RDP setup failures are clearly separated from relay/tunnel failures.
- No support instruction asks the user to weaken Windows security controls.

### Script C: Safe Failure

Run this before the real-user pilot:

1. Try to reuse an already-consumed session code.
2. Try to join after session expiry.
3. Start an agent with an unreachable local target.
4. End a session while a tunnel is active.
5. Disconnect the assisted agent network mid-session.

Success criteria:

- Failures produce actionable operator/user messages.
- Tunnels close without leaving public listeners behind.
- Audit records show failed joins, expiry, explicit end, and disconnects.
- The user is not instructed to share secrets to recover from the failure.

## 0.1.0 Release Checklist

- `docs/security.md` gates are reviewed and all 0.1.0 blockers are closed.
- README quick start matches the current safest path.
- Linux SSH script has passed local and three-machine tests.
- Windows/RDP rehearsal has passed on at least one supported Windows host, or
  README clearly marks it as not ready for real-user use.
- Artifact provenance is documented for every binary a user is asked to run.
- Real-user pilot notes include start time, end time, operator, device label,
  capability, outcome, and any user confusion.
- Rollback path is clear: stop `relaykitd`, revoke/rotate the operator token,
  remove served artifacts, and preserve audit logs for review.
