# Contributing to Parley

Thanks for helping. Read [`specs/parley-mvp/`](specs/parley-mvp/) first: the spec says what Parley promises, the plan says how it is built, and the tasks list the phased work.

## Repository layout

| Path | What |
|---|---|
| `cmd/parleyd` | The background daemon (Go) |
| `cmd/parley-cli` | The user-facing CLI (Go); talks to `parleyd` over a local socket |
| `internal/` | Shared Go packages (crypto module, adapters, caller interface) |
| `gateway/` | Gateway Worker and Durable Objects (TypeScript, Cloudflare) |
| `admin/` | Admin page: metadata and approval queue, never content |
| `tests/` | End-to-end, adversarial and layout tests, plus `journeys.md` |
| `specs/` | Specification, plan and tasks |

## Working on a task

- Pick a task from [`tasks.md`](specs/parley-mvp/tasks.md) and do one task per change.
- Add or update tests with the change. Coverage tiers and gates are in the plan; do not lower them.
- Never log or persist task content. Only ids, states, sizes and timestamps may reach a log call.
- Use vetted crypto libraries only; no custom primitives.

## Running tests

```
make test
```

Go tests run with the race detector (`go test -race ./...`).

## Local harness

```
make dev N=3
```

boots a gateway, a mock OIDC server (stands in for Google and Entra) and N `parleyd` processes, and prints their URLs. The gateway is a placeholder until the real Worker lands; set `PARLEY_GATEWAY_CMD` (for example `npx wrangler dev --port $PORT`) to run another command from `gateway/`, which must serve `/healthz` on `$PORT`. Daemons get `PARLEY_HOME`, `PARLEY_GATEWAY_URL` and `PARLEY_OIDC_ISSUER`. Tests can call `start()` from `tests/harness/harness.mjs`.

## License headers

Every source file (`.go`, `.ts`, `.js`, `.sh`, `.yml` and similar) starts with the header below (use `#` instead of `//` for shell, Python and YAML, after any shebang line):

```
// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0
```

`make test` fails if a source file lacks it. By contributing you agree your work is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). Sign off commits (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/).

## Security issues

Do not open a public issue for a vulnerability. Report it privately to the maintainers through the repository's private security advisory feature.
