# About response-runtime project

response-runtime brings a Docker-like model to threat response: the runtime provides a capability-isolated execution container, and JS playbooks are the reusable response images.

A cross-platform, JS-powered threat response runtime for Wazuh, OSSEC, and related forks.

```text
Docker model
+-------------------+      +------------------+
| Docker Engine     | ---> | Container Image  |
| runtime + limits  |      | app + logic      |
+-------------------+      +------------------+

response-runtime model
+---------------------------------+      +----------------------+
| response-runtime                | ---> | JS playbook          |
| capability-isolated runtime     |      | response logic       |
+---------------------------------+      +----------------------+
```

The runtime stays stable; playbooks carry the response logic.

`response-runtime` is a responder built around a capability-sandboxed JS runtime. Instead of dropping loose Python, shell, or platform-specific scripts onto endpoints, it gives playbooks a fixed set of helpers. The public build keeps higher-risk helpers off unless you turn them on at build time.

## What It Is

- A drop-in active responder for Wazuh, OSSEC, and compatible forks.
- A cross-platform runtime for response playbooks and built-in actions.
- A safer default than loose script collections because the helper set is explicit and build-gated.

## Safe Default Model

The default public build:

- Builds `active-response` only.
- Excludes `emergency-response` unless explicitly requested.
- Excludes emergency, update, HTTP-capable, and other high-control features unless explicitly enabled.
- Excludes broad JS file-content reads and active network probes unless explicitly enabled.
- Preserves practical investigation and containment features such as hashing, inspection, process response, and IP blocking.

The runtime is not self-activating. Copying the binary to an endpoint does nothing by itself. It only runs when a Wazuh or OSSEC active-response path is configured to call it. Like any executable on an endpoint, it still needs normal supply-chain and access-control discipline, which is why the public build keeps higher-risk features off by default.

## Build

Show the build matrix and toggles:

```bash
make help
```

Safe default cross-platform build:

```bash
make build
```

Build the optional `emergency-response` binary too:

```bash
make build BUILD_EMERGENCY_RESPONSE=1
```

Enable authenticated JS helpers such as `sshExec`:

```bash
make build ENABLE_JS_UNSAFE_WITH_AUTH=1
```

Run the safe sample playbooks locally:

```bash
make playbook-test-safe
```

Use `.env.example` as a starting point if you want local persistent build defaults.

Updater-enabled builds can also override the sample manifest endpoint through `UPDATE_MANIFEST_URL`.

Generate a fresh update signing keypair locally:

```bash
make update-keygen
```

That writes a private/public PEM pair under `build/update-keys/`. Normal builds do **not** auto-generate updater keys, because the verifier key embedded in the binary needs to stay stable across signed releases. Keep the **private key out of git**. If you run your own updater service, replace the sample public key in `cmd/active-response/internal/updateclient/embedded/response-runtime_update_public.pem` with your generated public key before building updater-enabled releases.

## Quick Install On An Existing Wazuh Or OSSEC Agent

1. Build or extract the platform-specific `active-response` binary.
2. Copy it into the agent active-response bin directory.
3. Configure the manager and/or agent to call that exact filename by name.

Common locations:

- Linux: `/var/ossec/active-response/bin`
- macOS: `/Library/Ossec/active-response/bin`
- Windows: the Wazuh or OSSEC agent `active-response\bin` directory

The filename does not have to match an upstream default, as long as your Wazuh or OSSEC command configuration points to the correct executable.

## Quick Manager Configuration

Example manager-side command registration:

```xml
<command>
  <name>response-runtime</name>
  <executable>active-response</executable>
  <expect>json</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>response-runtime</command>
  <location>local</location>
  <rules_id>100001</rules_id>
</active-response>
```

See the detailed integration guide in [docs/WAZUH_INTEGRATION.md](docs/WAZUH_INTEGRATION.md).

## Optional Feature Tags

- `danger_emergencies`: enable emergency-only `emergency-response` RPC such as remote shell and endpoint file extraction.
- `unsafe_features`: enable non-JS unsafe local control or destructive features.
- `enable_remote_updates`: enable HTTP self-update flows.
- `js_file_read`: enable JS file-content reads such as `readFile` and `readTextFile`.
- `js_sensitive_reads`: enable JS hosts/auth/registry read helpers.
- `js_unsafe_features`: enable JS `exec`, file writes, and local `importModule`.
- `js_enable_http_import`: enable `importModule` over HTTP(S).
- `enable_http_client`: enable JS `httpGet` and `httpPost`.
- `js_network_probes`: enable JS active network probing helpers such as `ping`, `traceroute`, DNS lookups, banner grabs, and fingerprinting.
- `js_walk_dir`: enable JS recursive directory walking via `walkDir`.
- `js_unsafe_with_auth`: enable authenticated JS helpers such as `sshExec`.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/INSTALL.md](docs/INSTALL.md)
- [docs/JS_HELPERS.md](docs/JS_HELPERS.md)
- [docs/WAZUH_INTEGRATION.md](docs/WAZUH_INTEGRATION.md)
- [docs/PRINCIPLES.md](docs/PRINCIPLES.md)
- [SECURITY.md](SECURITY.md)
- [playbooks/README.md](playbooks/README.md)

## Playbooks

The repository includes a `playbooks/` tree with safe sample hunting and containment playbooks.

- `playbooks/hunt/`: investigation-oriented examples
- `playbooks/contain/`: bounded response examples
- `playbooks/eradicate/`: stronger remediation category for future use
- `playbooks/shared/`: shared modules and snippets for future reuse

The goal is simple: keep a useful set of playbooks in-tree and accept pull requests that fit the same safety rules as the rest of the project.

If you build the optional `emergency-response` companion, it will look for the matching `active-response` binary next to itself using the build-time active-response name. Set `RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN` to override that path explicitly.

Author: sunmnp from [MoonSecure™](https://MoonSecure.net)
