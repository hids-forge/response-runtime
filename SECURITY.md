# Security Policy

## Reporting

If you find a vulnerability, do not open a public issue with exploit details. Report it privately to the maintainers first.

Until a dedicated reporting mailbox is published, open a minimal private contact request through the maintainer profile or repository security contact when available.

## Security Model

`response-runtime` is built to keep the default public artifact narrow:

- The default public build ships `active-response` only.
- High-control features are excluded unless explicitly enabled at build time.
- JS playbooks operate inside a capability-sandboxed runtime and only receive helpers exposed by the build.
- Emergency `emergency-response` capabilities are not part of the default build.

## Deployment Boundary

The binary is not self-activating. Copying it onto an endpoint does not execute it or connect it to any control plane. It becomes operational only when an operator deploys it into a Wazuh or OSSEC active-response path and configures policy to invoke it.

That does not make it harmless just because it is present. Any executable on an endpoint still carries tampering and supply-chain risk. This project reduces that risk mainly by:

- safe-default builds
- explicit feature gating
- clear trust-boundary documentation
- minimizing default remote-control surface

## Feature Classes

Maintainers should classify new capabilities in one of three classes:

- `observe`: inspection, collection, hashing, metadata, network/process discovery
- `respond`: bounded containment or response actions such as process termination or IP blocking
- `control`: broad local or remote execution, mutation, code loading, or administrative control

`control` features need stronger justification, tests, docs, and usually a build tag.
