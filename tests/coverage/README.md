# Coverage and mutation gates

What each gate measures, what it cannot, and what covers the gap. The policy is
the plan's (`specs/parley-mvp/plan.md`, "Coverage policy"); the files here are
what CI reads.

| File | Read by |
|---|---|
| `tiers.json` | `scripts/covergate` (Go statements per package), `scripts/mutation.sh` (tier 1 Go packages) |
| `gateway-tier1.json` | `gateway/vitest.config.ts` (100% per file), `gateway/stryker.config.json`, `scripts/mutation.sh` |
| `mutation-allowlist.json` | `scripts/mutation-gate.mjs`: the only way a Go mutant may survive |

## Go: statements, not branches

`go test -coverprofile` reports statements; Go has no branch coverage. Tier 1
therefore has two checks that together stand in for "100% line and branch":

1. 100% of statements, with no `//cover:ignore` (covergate refuses one in tier 1).
2. Mutation testing with every gremlins mutator on. A condition that is never
   taken one way, or whose boundary no test pins, leaves a mutant alive
   (`CONDITIONALS_NEGATION`, `CONDITIONALS_BOUNDARY`, `INVERT_LOGICAL`); a branch
   body no test reaches shows up as a mutant that is not covered. Every one of
   those fails the gate unless `mutation-allowlist.json` names it with a reason.
   A mutant that makes the tests hang (timeout) counts as detected, as in Stryker:
   the tests did not pass on it, and which mutants time out varies by runner.

The allowlist holds two kinds of entry, each with its reason: constant
   expressions (`const X = 90 * 24 * time.Hour` has no statement to cover; the
   value is pinned by `TestConstantsArePinned` in the package) and equivalent
   mutants (the directory fsync after a rename; the ignored `fd` of an anonymous
   Linux `mmap`). The stale check applies per OS, to the files that OS owns.

Statement coverage is measured on each of the three OSes in CI, so a file
built only for one OS (`internal/prekey/mem_windows.go`, `harden_linux.go`,
`quiesce_linux.go`, `scrub_*.go`) is held to 100% by the runner that builds it.
Mutation runs on each OS too: gremlins parses every `.go` file whatever its build
constraints, so `scripts/mutation-gate.mjs` judges a file only on the first runner
(Linux, then macOS, then Windows) whose `go list` builds it, and there every
not-covered or surviving mutant fails the gate. Nothing OS-specific is
allowlisted. `tests/mutation-gate.test.mjs` fails if a tier 1 file is owned by no
runner, except `prekey/scrub_other.go` (an empty function for other architectures:
no statement to cover or mutate). TypeScript mutation and the malicious-gateway
mutants run on Linux only.

## Assembly (`internal/prekey/scrub_*.s`)

The Go cover profile has no statements for assembly, so 100% cannot mean the
`.s` files. They are covered by tests that execute them and check the result
instead:

- `scrub_amd64_test.go`, `scrub_arm64_test.go`: a probe written in assembly fills
  every vector register with `0xAA`, runs the scrub, and reads the registers
  back. A scrub that misses a register fails; each feature level (SSE, AVX,
  AVX-512 with its mask registers) is checked, and the routine for a feature the
  CPU lacks must not run.
- `scrub_amd64_linux_test.go`: the feature detection (`hasAVX`, `hasAVX512`)
  must agree with `/proc/cpuinfo`.
- The nightly "Memscan (repeat)" workflow (`.github/workflows/memscan.yml`) and
  `TestAddressSpaceHoldsNoErasedKey` check the end result: no erased key in the
  address space after the scrub is on the path of every key operation.

`tests/coverage.test.mjs` fails if an assembly file has no `_test.go` beside it.

## TypeScript

The gateway files in `gateway-tier1.json` have a 100% per-file gate for lines,
statements, branches and functions (istanbul does measure branches), with no
exclusion, and Stryker must kill every mutant. `scripts/stryker-gate.mjs` also
fails on a mutant whose run crashed (`RuntimeError`) or did not compile, which
Stryker's own score leaves out. `tenant.ts` is tier 2 (95% lines, 90% branches),
as in the plan: tier 1 names the task state machine, deadlines and retention,
and ACL evaluation; the Device DO and the sealed-part checks (`parts.ts`) are
held to the tier 1 bar as well.

## When mutation runs

- Pull request: `MUTATION_SCOPE=changed` mutates only the tier 1 packages and
  files the PR touches, plus every gateway tier 1 file that a changed gateway
  test imports (a2a.test.ts kills task.ts mutants, not only task.test.ts). A
  changed test helper in `gateway/test/` means every gateway file. A change to
  the gates themselves (`tests/coverage/`, the mutation and Stryker gate
  scripts, both workflows, Stryker or vitest config, `go.mod`) runs everything.
- The choice is made by `scripts/mutation-scope.mjs` and it fails closed: if the
  merge base with the base branch cannot be computed (a shallow checkout, a
  missing ref) or the diff fails, it prints why and runs everything. It never
  skips. `tests/mutation-scope.test.mjs` runs it in a shallow-clone fixture, and
  the CI job checks out full history (`fetch-depth: 0`).
- Every push to main and nightly (`.github/workflows/mutation.yml`): everything,
  with `--stale`, so an allowlist entry that no longer matches a mutant fails.
- `scripts/malgw-mutations.sh` (the defences the malicious-gateway tests exercise)
  runs in CI on every pull request and in the full run, and fails if one mutant
  survives.

## Plan tier 1 against what is registered

| Plan's tier 1 item | Registered as tier 1 |
|---|---|
| Crypto module, transcript encode/decode, envelope and signature verification | `internal/envelope` |
| Replay table | `internal/replay` |
| Prekey lifecycle | `internal/prekey` (and `internal/receive`, which consumes it) |
| Binding and revocation verification | `internal/binding`, `internal/revocation` |
| ACL evaluation | `gateway/src/acl.ts` |
| Task state machine, deadlines and retention | `gateway/src/task.ts` |
| Log-redaction wrapper | `internal/logx` |
| Also held to tier 1 | `gateway/src/device.ts`, `gateway/src/parts.ts` |

Not tier 1, and why: `internal/root` and `internal/release` carry
`//cover:ignore` branches for `crypto/rand` and AEAD construction failures that
cannot be injected, which tier 1 forbids, so they stay tier 2 (95%) and
`internal/trust` is wiring over the tier 1 binding and revocation packages.
`gateway/src/tenant.ts` is a Tenant DO, named in the plan's tier 2 row. There
is no separate signer package. Moving any of these up is a plan change.
