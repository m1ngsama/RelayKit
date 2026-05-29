# Development Topology

RelayKit development uses separate operator, relay, and assisted-machine roles
so trust boundaries are visible during testing.

Use private hostnames in your own shell config if you want short aliases, but
keep public documentation on documentation-only example names and addresses.

## Roles

### Operator Machine

Role: control machine.

- Runs `rk` during development.
- Starts and ends assistance sessions.
- Opens local SSH/RDP/TCP clients to localhost-only tunnels.
- May use SSH to inspect lab hosts when needed.

### Assisted Linux Host

Role: user-side test machine.

- Runs `relaykit-agent` visibly as the assisted user.
- Initiates outbound connections to the relay server.
- Hosts the local test service being exposed, such as `127.0.0.1:22`.
- Should show local session status and allow the assisted user to stop a
  session.

### Relay Host

Role: self-hosted relay server.

- Runs `relaykitd`.
- Authenticates operators and validates session codes.
- Routes operator-agent traffic without requiring inbound connectivity to the
  assisted machine.
- Stores only the minimum test audit data needed for development.

Example documentation values:

```text
relay host:       relay.example.com or 203.0.113.10
assisted host:    assisted-linux
operator host:    local machine
relay listen:     0.0.0.0:18443
operator tunnel:  127.0.0.1:22022
```

## Lab Notes

- Lab sudo credentials are supplied out of band during development.
- Keep lab credentials out of production workflows.
- Do not commit secrets such as API tokens, SSH private keys, relay signing
  keys, real user credentials, or production passwords.
- Store secrets in local environment files ignored by git, host-level
  configuration, or a password manager.
- `relaykitd` requires `RELAYKIT_OPERATOR_TOKEN` by default. Use
  `--insecure-no-operator-auth` only for isolated local development; it is
  rejected unless the listener and public URL are loopback addresses.
- Assisted users do not receive `RELAYKIT_OPERATOR_TOKEN`; they only receive
  one short-lived session code.
- Do not publish real relay IPs, internal host aliases, fingerprints, usernames,
  or pilot transcript output in public docs or issues.

## Local Smoke Test

Build the workspace:

```sh
cargo build --workspace
```

Start the relay:

```sh
RELAYKIT_OPERATOR_TOKEN=local-test-token \
target/debug/relaykitd -v \
  --listen 127.0.0.1:18080 \
  --public-url http://127.0.0.1:18080 \
  --artifact-dir /tmp/relaykit-artifacts
```

For local artifact serving, place a test agent binary in that directory:

```sh
mkdir -p /tmp/relaykit-artifacts
cp target/debug/relaykit-agent /tmp/relaykit-artifacts/relaykit-agent-linux-x86_64
```

Start a local target service in another terminal:

```sh
python3 -m http.server 19090 --bind 127.0.0.1
```

Create a session:

```sh
RELAYKIT_OPERATOR_TOKEN=local-test-token \
target/debug/rk session new \
  --server http://127.0.0.1:18080 \
  --device local-agent \
  --allow web=127.0.0.1:19090
```

Join from the assisted side:

```sh
sh -c 'u=$1; curl -fsSL --connect-timeout 10 --max-time 120 --noproxy "*" "$u" || curl -fsSL --connect-timeout 10 --max-time 120 "$u"' sh http://127.0.0.1:18080/join/RK-REPLACE-ME.sh | sh
```

If hosted artifacts are disabled, run the agent directly:

```sh
target/debug/relaykit-agent -v join \
  --relay http://127.0.0.1:18080 \
  --code RK-REPLACE-ME \
  --device local-agent \
  --tcp web=127.0.0.1:19090
```

Open an operator tunnel:

```sh
RELAYKIT_OPERATOR_TOKEN=local-test-token \
target/debug/rk -v tunnel \
  --server http://127.0.0.1:18080 \
  rk-session-id-replace-me \
  web \
  --listen 127.0.0.1:19091
```

Verify traffic crosses the relay:

```sh
curl -I http://127.0.0.1:19091/
```

Expected result: HTTP headers from the Python server.

## Three-Machine SSH Test

On the relay host, create the operator token env file outside the repository:

```sh
if ! id -u relaykit >/dev/null 2>&1; then sudo useradd --system --home-dir /var/lib/relaykit/artifacts --shell /usr/sbin/nologin relaykit; fi
sudo install -d -m 0750 -o root -g relaykit /etc/relaykit
printf 'RELAYKIT_OPERATOR_TOKEN=replace-me\n' | sudo tee /etc/relaykit/relaykitd.env >/dev/null
sudo chmod 0600 /etc/relaykit/relaykitd.env
```

Install or generate a TLS certificate for the relay IP. For a self-signed raw-IP
certificate:

```sh
sudo openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout /etc/relaykit/relay.key \
  -out /etc/relaykit/relay.crt \
  -subj "/CN=203.0.113.10" \
  -addext "subjectAltName=IP:203.0.113.10"
sudo chgrp relaykit /etc/relaykit/relay.key
sudo chmod 0640 /etc/relaykit/relay.key
openssl x509 -in /etc/relaykit/relay.crt -outform DER | shasum -a 256 | awk '{print "sha256:" $1}'
```

From the operator machine, deploy an already-built `relaykitd` binary as a
systemd service:

```sh
target/debug/rk relay deploy-systemd \
  --host 203.0.113.10 \
  --binary target/release/relaykitd \
  --listen 0.0.0.0:18443 \
  --public-url https://203.0.113.10:18443 \
  --tls-cert /etc/relaykit/relay.crt \
  --tls-key /etc/relaykit/relay.key
```

Use `--dry-run` to inspect the generated unit and remote commands first.
Non-local relay public URLs must use encrypted HTTPS/WSS for pilot testing;
plaintext HTTP is limited to loopback development. A domain name is not
required: run `relaykitd` with `--tls-cert` and `--tls-key` on a raw IP, then
pass `--relay-fingerprint sha256:<cert-der-sha256>` to the operator and agent
commands when that certificate is self-signed or otherwise not publicly trusted.

Check the deployed relay:

```sh
target/debug/rk relay status --host 203.0.113.10 --listen 0.0.0.0:18443 --tls
```

The artifact directory on the relay host should contain:

```text
/var/lib/relaykit/artifacts/relaykit-agent-linux-x86_64
/var/lib/relaykit/artifacts/relaykit-agent-linux-x86_64.sha256
```

From the operator machine, publish an already-built Linux agent binary to the
relay host:

```sh
target/debug/rk artifact publish-agent \
  --host 203.0.113.10 \
  --artifact-dir /var/lib/relaykit/artifacts \
  --binary target/release/relaykit-agent \
  --target linux-x86_64
```

Use `--dry-run` to print the underlying `ssh` and `scp` commands without
writing to the relay host. By default the publish step stages through `/tmp` and
uses remote `sudo install`, which is required for protected service directories
such as `/var/lib/relaykit/artifacts`.

The publish step writes the `.sha256` sidecar used by `rk relay status` and the
hosted join script. A missing checksum sidecar causes hosted join to fail.

On the local operator machine, log in and start the guided SSH workflow:

```sh
target/debug/rk \
  --operator-token replace-me \
  --relay-fingerprint sha256:REPLACE_WITH_RELAY_CERT_SHA256 \
  login https://203.0.113.10:18443

target/debug/rk assist ssh --label ticket-1234-linux
```

`rk assist ssh` prints the command to run on the assisted machine, waits for the
agent to connect, then opens the local SSH tunnel. `--label` is only an
operator-visible label; in real use it can be a ticket number, customer name, or
public IP if that is already part of the support workflow.

On the assisted Linux host, join the session with the printed command or a
direct visible agent command:

```sh
target/debug/relaykit-agent -v join \
  --relay https://203.0.113.10:18443 \
  --relay-fingerprint sha256:REPLACE_WITH_RELAY_CERT_SHA256 \
  --code RK-REPLACE-ME \
  --device ticket-1234-linux \
  --tcp ssh=127.0.0.1:22
```

The agent runs a local TCP preflight by default. A warning such as
`local target preflight failed` means the assisted machine accepted the RelayKit
command, but the requested local service is not reachable yet. Use
`--no-preflight` when testing relay connectivity independently from the local
target service.

For lower-level tunnel debugging, open the SSH tunnel manually:

```sh
target/debug/rk -v ssh \
  rk-session-id-replace-me \
  --listen 127.0.0.1:22022
```

Then connect through RelayKit:

```sh
ssh -p 22022 127.0.0.1
```

Validated public evidence should record only sanitized values: session ID,
artifact SHA-256, relay fingerprint status, capability, start/end timestamps,
and whether the expected test command succeeded. Keep raw usernames, hostnames,
public relay IPs, and transcripts in private pilot notes.
