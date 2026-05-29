# Architecture

RelayKit starts as a small set of separable Rust components. Each component should be replaceable while the product shape is still being decided.

```text
local operator machine         relay server                 assisted machine
        rk       <---------->   relaykitd   <------------>   relaykit-agent
 local SSH/RDP client          session/tunnel routing        local 22/3389/TCP
```

## Components

### Agent

The `relaykit-agent` binary runs on the assisted user's machine. It should be easy to start, easy to inspect, and easy to stop. Early versions should avoid background persistence and focus on session-based assistance.

Responsibilities:

- Accept explicit session configuration from the user or operator.
- Connect outbound to the relay service.
- Expose only the local TCP targets enabled for the current session, such as SSH on 22 or RDP on 3389.
- Show clear local status while a session is active.
- Emit local and server-side audit events.

### Relay Service

The `relaykitd` service is the self-hosted coordination layer. It should authenticate operators, validate session codes, and route traffic between operator and agent.

Responsibilities:

- Issue and validate short-lived assistance sessions.
- Maintain operator and agent connection state.
- Route transport streams without requiring inbound connectivity to the assisted machine.
- Store minimal audit logs.
- Enforce session expiry and revocation.

### Operator Surface

The operator surface starts as the `rk` CLI and may later become a browser or native app.

Responsibilities:

- Create support sessions.
- Show connected devices and active capabilities.
- Open local SSH, RDP, and generic TCP tunnels.
- End sessions cleanly.

## Initial Flow

1. Operator creates a short-lived support session.
2. User starts the agent with the session code.
3. Agent connects outbound to the relay service.
4. Relay authenticates both sides and establishes transport.
5. Operator opens a local tunnel to the allowed assisted-machine service.
6. Either side can terminate the session.

## Open Design Questions

- Should v0 WebSocket/TLS streams be relay-readable, or should operator-agent stream encryption land before real use?
- Which Windows setup steps are safe to automate for RDP without surprising the user?
- What should the one-line installer look like before binaries are signed?
- How much audit data should be stored on the relay server?
