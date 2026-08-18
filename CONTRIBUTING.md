# Contributing

## Ground Rules

- Keep the default public build safe by default.
- Prefer narrow, typed helpers over broad command execution surfaces.
- Do not add high-control capability by default.
- Update documentation when capability boundaries change.

## Capability Classification

If you add a new capability, classify it in the PR as one of:

- `observe`
- `respond`
- `control`

Use these definitions:

- `observe`: inspect or collect information without mutating host state
- `respond`: bounded containment or response action with a narrow blast radius
- `control`: arbitrary execution, mutation, code loading, remote shell, broad file write, or update/install behavior

## When Build Tags Are Required

Use a build tag when the change:

- provide arbitrary command execution
- write or delete arbitrary files
- fetch or execute code remotely
- provide remote shell or similar emergency control
- replace or update binaries

## PR Expectations

For capability changes, include:

- classification: `observe`, `respond`, or `control`
- why it should be default-on or tagged
- tests
- docs updates
- security considerations
