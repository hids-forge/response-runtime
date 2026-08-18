# Principles

## Privacy First

- Collect what is needed for investigation or containment, **not more**.
- Do **not** ship broad exfiltration features in the default build.
- Be clear when a helper can **move data off host**.

## User Safety First

- **Safe by default** matters more than shipping every possible feature.
- High-control features should require an **explicit build-time choice**.
- Emergency tooling should stay **obvious, narrow, and documented**.

## Least Privilege In Capability Design

- Prefer **bounded helpers** over arbitrary interpreters or shells.
- Prefer **typed operations** over raw command strings.
- Keep dangerous capability behind **explicit gates**.

## Maintainer Guardrails

- New capabilities must be classified as `observe`, `respond`, or `control`.
- `control` capabilities require **stronger review, tests, and docs**.
- **Public artifacts** should stay safe by default even if private builds are stronger.
