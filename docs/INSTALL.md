# Install

## Existing Agent Install

The **simplest deployment path** is:

1. Build the platform artifact.
2. Copy the `active-response` binary into the agent active-response bin directory.
3. Reference that filename in Wazuh or OSSEC configuration.

Typical paths:

- Linux: `/var/ossec/active-response/bin`
- macOS: `/Library/Ossec/active-response/bin`
- Windows: the agent `active-response\bin` directory

## Build Variants

**Safe default**:

```bash
make build
```

Add the **optional** `emergency-response` binary:

```bash
make build BUILD_EMERGENCY_RESPONSE=1
```

Use `.env.example` for **local default toggles** if you do not want to pass flags on every build.

If you deploy `emergency-response`, place its companion `active-response` binary alongside it or set `RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN` to the **exact path** of the runtime binary it should use for `runJS`.

## Packaging Into Internal Agent Images

If you maintain your own Wazuh or OSSEC agent packages, bundle the chosen output artifact and point the corresponding `ossec.conf` command entry to that filename. The **binary name is configurable**; the **config binding** matters more than the exact filename.
