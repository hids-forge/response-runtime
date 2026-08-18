# Playbooks

This folder holds JavaScript response playbooks for `response-runtime`.

Keep playbooks:

- portable across supported platforms where possible
- explicit about required helpers
- safe by default unless clearly marked otherwise
- easy to test locally with `active-response local-run-js`

## Contribution Culture

Treat playbooks like detection rules: keep them small, obvious, and easy to review.

- keep each playbook focused
- document what it inspects or changes
- prefer typed runtime helpers over broad execution primitives
- avoid unsafe tags unless the use case clearly requires them
- include progress output where it helps operators understand what happened

## Develop And Test

Build the host binary once:

```bash
make build-host
```

Run the safe sample set end to end:

```bash
make playbook-test-safe
```

Run a playbook locally:

```bash
./dist/host/active-response local-run-js --playbook playbooks/hunt/hash_and_report_file.js --alert alert.json
```

Write structured output to a file while iterating:

```bash
./dist/host/active-response local-run-js \
  --playbook playbooks/contain/contain_process_and_block_ip.js \
  --alert alert.json \
  --progress-to tmp.progress.json \
  --result-to tmp.result.json
```

Inspect the currently available helper surface in your build:

```bash
./dist/host/active-response helpers
```

See [docs/JS_HELPERS.md](../docs/JS_HELPERS.md) for the helper matrix, tag gates, and API reference.

If you are testing stronger playbooks, use an isolated VM or container instead of your daily host.

## Folder Groups

- `hunt/`: information gathering and investigation playbooks
- `contain/`: bounded response and containment playbooks
- `eradicate/`: stronger remediation logic that may terminate or remove threats
- `shared/`: future common helper modules or reference snippets

## Safety Expectations

- Public playbooks should prefer the safe-default helper surface.
- If a playbook requires tagged capabilities, say so clearly at the top of the file.
- Destructive actions should be obvious from the filename, header comment, and README notes.

## Conduct

This folder follows the same project rules as [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

## Contribute By Pull Request

When contributing a playbook:

1. Put it in the right category folder.
2. Add a short header comment explaining purpose, required helpers, and whether it is safe-default or tag-dependent.
3. Keep the logic focused and reviewable.
4. Include or update example alert input when useful.
5. Explain in the pull request whether the playbook is `observe`, `respond`, or `control`.

Safe sample alert fixtures for local testing live under `playbooks/testdata/`.
