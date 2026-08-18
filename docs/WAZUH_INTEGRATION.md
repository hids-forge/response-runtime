# Wazuh And OSSEC Integration

## Manager Command Registration

Register the responder as a **JSON-consuming command**:

```xml
<command>
  <name>response-runtime</name>
  <executable>active-response</executable>
  <expect>json</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

## Active-Response Binding

Bind that command to a **rule or level**:

```xml
<active-response>
  <command>response-runtime</command>
  <location>local</location>
  <rules_id>100001</rules_id>
</active-response>
```

Adjust `location`, rule selection, and timeout semantics to match your **deployment model**.

## Agent Placement

Copy the built responder binary into the appropriate **agent active-response bin directory**.

## Payload Shape

The responder expects **Wazuh or OSSEC style JSON** on `stdin`, then dispatches based on the first entry in `payload.parameters.extra_args`.

Examples:

- `block-ip`
- `unblock-ip`
- `get-md5`
- `js`

## Binary Naming

The **executable name is configurable**. Wazuh or OSSEC only needs the configured filename to match what you deployed on the endpoint.

If you also deploy `emergency-response`, keep its companion `active-response` binary in the same directory or set `RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN` to the **exact path** you want it to invoke for `runJS`.
