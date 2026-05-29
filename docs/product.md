# Product Shape

RelayKit is a self-hosted remote assistance access layer. It exists because configuring generic tunneling tools, SSH, RDP, firewall rules, and server secrets is too error-prone for non-technical users.

The product should make this workflow simple:

1. The operator runs a relay server on owned infrastructure.
2. The operator creates a short-lived assistance session.
3. The assisted user runs one command with a session code.
4. The agent connects outbound to the relay.
5. The operator opens SSH, RDP, or TCP tunnels through the relay.
6. The session expires or either side closes it.

## v0 Scope

- Rust implementation.
- Three binaries:
  - `relaykitd` for the relay server.
  - `relaykit-agent` for the assisted machine.
  - `rk` for the operator.
- Linux-first real-world testing with a separate assisted machine and
  self-hosted relay server.
- TCP tunneling model for SSH 22, RDP 3389, and arbitrary local ports.
- Short-lived session codes.
- Localhost-only operator listeners by default.

## Non-Scope For v0

- Full GUI remote desktop.
- Hidden background persistence.
- Browser operator console.
- Automatic production installation as a system service.
- Long-lived device enrollment.

## Desired User Experience

Assisted user command:

```sh
sh -c 'u=$1; curl -fsSL --connect-timeout 10 --max-time 120 --noproxy "*" "$u" || curl -fsSL --connect-timeout 10 --max-time 120 "$u"' sh 'https://relay.example.com/join/RK-ABCD-EFGH.sh' | sh
```

Operator commands:

```sh
rk --operator-token <token> login https://relay.example.com
rk assist ssh --device customer-203.0.113.10
ssh -p 22022 user@127.0.0.1
rk session end --server https://relay.example.com rk-session-id
```

`rk assist ssh` is the preferred operator workflow. It creates the session, prints the assisted-user command, waits for the agent to connect, and then opens the local SSH tunnel. Lower-level `rk session new` and `rk ssh` remain available for debugging and automation.

`--device` is a support-side label, not a routable host requirement. It can be a public IP, domain, customer name, or ticket number. When omitted or ambiguous, the relay records and shows the agent's observed source address after connection.
