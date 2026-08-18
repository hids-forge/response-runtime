# Architecture

## Overview

`response-runtime` has **two execution surfaces**:

- `active-response`: one-shot responder invoked by Wazuh or OSSEC
- `emergency-response`: optional MQTT control-plane binary for emergency use

The **public default build** only ships the safe `active-response` path.

## End-To-End Wazuh Or OSSEC Flow

```text
Wazuh/OSSEC Manager
        |
        | alert + rule match
        v
Manager policy / ossec.conf
        |
        | command + active-response mapping
        v
Agent active-response executable
        |
        | JSON on stdin
        v
response-runtime active-response
        |
        +--> built-in subcommand handlers
        |
        +--> JS runtime
              |
              +--> safe helpers
              +--> tagged high-risk helpers when explicitly enabled
        |
        +--> optional MQTT result/progress/debug publish
```

## Active-Response Dispatch

The responder reads **one JSON message from `stdin`**, takes the subcommand from `extra_args`, and dispatches to:

- built-in handlers such as blocking an IP or hashing a file
- the JS runtime for playbook execution

That keeps the Wazuh or OSSEC trigger path separate from the actual response logic.

Wazuh or OSSEC does **not** give the responder a native structured return channel for execution output. In this project, the practical return path is **optional MQTT**:

- the manager-side workflow can inject short-lived MQTT credentials and topic names into the alert payload
- `active-response` can connect to that broker during the one-shot execution
- the responder can publish final results, progress events, and debug strings back to the operator

This is how a **security engineer** can see what a JS playbook did even though the active-response trigger itself is **one-shot**.

## JS Runtime Model

The runtime embeds a JS engine and exposes **explicit host helpers**.

```text
JS Playbook
    |
    v
Capability-sandboxed JS runtime
    |
    +--> observe helpers
    +--> respond helpers
    +--> tagged control helpers
```

The safety boundary comes from **helper exposure**, not from giving the script a full local interpreter environment. Playbooks can only access what the host runtime registers.

See [JS_HELPERS.md](JS_HELPERS.md) for the helper inventory, tag matrix, and example entry points.

## Result And Telemetry Return Path

Classic Wazuh and OSSEC active-response execution is good at **triggering a binary**, but weak at **reporting back what that binary actually did**. In practice, the manager can launch a responder on the endpoint, but it does not give the analyst a rich built-in channel for:

- final structured result data
- step-by-step execution progress
- debug output from the responder or playbook
- operator-facing logs from a longer or more complex response action

That is fine for simple actions such as "block this IP" or "kill this process", but it becomes a problem once a responder starts doing **real investigation** or **multi-step containment**. A security engineer needs to know what happened on the endpoint, what the playbook found, whether it partially failed, and what state it left behind.

**That is why `response-runtime` adds an optional MQTT return path.**

The Wazuh or OSSEC trigger still stays **one-shot** and **local**. The responder is still launched in the usual active-response way. What changes is that the payload may also carry **short-lived MQTT connection details** so the endpoint can publish the execution result back to the operator during that one run.

For the `js` subcommand, the payload can include:

- `mqtt-url`
- `mqtt-username`
- `mqtt-password`
- `reply_to`
- `correlation_id`
- `progress_to`
- `debug_to`

When those fields are present, the responder can use them like this:

- `console.log(...)` output becomes the final JS result string
- that result is published to `reply_to`
- `reportProgress(...)` publishes structured progress events to `progress_to`
- `outputDebugString(...)` publishes debug text to `debug_to`

This makes the one-shot responder much more usable in **real incident response**:

- the playbook can return evidence, not just "it ran"
- the analyst can watch progress while a response is still running
- partial failures or branch decisions can be surfaced to the operator
- the endpoint does not need a permanent control channel just to send back execution output

Just as important, this behavior is still **optional**.

**If the manager does not include MQTT instructions in the payload, none of this happens.**

In that case:

- the responder still runs locally
- the JS playbook still executes
- no MQTT connection is created
- no result/progress/debug stream is published back

So the return path is an **added capability** for real-life threat response, not a mandatory **always-on** behavior.

## Build Tags And Capability Gates

**Default build**:

- safe `active-response`
- no `emergency-response`
- no remote shell
- no arbitrary local command execution
- no HTTP client
- no remote updates

**Optional tags**:

- `danger_emergencies`
- `unsafe_features`
- `enable_remote_updates`
- `js_unsafe_features`
- `js_enable_http_import`
- `enable_http_client`
- `js_unsafe_with_auth`

## Emergency-Response MQTT Flow

`emergency-response` is an **optional companion binary** intended for **authorized emergency response**, not general remote administration.

```text
Authorized bootstrap event
        |
        | responder receives MQTT credentials and session metadata
        v
emergency-response child process
        |
        | connects to MQTT
        v
RPC request topic
        |
        +--> runJS
        +--> emergency-only RPC if built with danger_emergencies
```

In the intended model, `runJS` uses the companion `active-response` runtime so helper exposure and build-tag behavior stay aligned. By default it resolves the **build-matched companion name** next to the `emergency-response` executable, and `RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN` can **override that path explicitly**.

## Trust Boundaries

- **Manager policy** controls when the responder is invoked.
- The endpoint binary is **not self-activating**.
- **Build tags** decide which capabilities can ever exist in a given artifact.
- The JS runtime can only do what the host exposes.

## Security Notes

- `observe` and bounded `respond` features belong in the **safe build**.
- `control` features must be **explicitly justified** and usually tagged.
- Emergency features are **operationally sensitive** even when authenticated.
