// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Phase 0 acceptance (T008): the harness boots, a release build is reproducible
// and verifiable with the project key, and the redaction build test fails on a
// leaked payload field. Each check drives the real tool end to end.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { start } from "./harness/harness.mjs";

const root = join(fileURLToPath(import.meta.url), "..", "..");
// Mirrors `make test-go`: skip locally without Go, fail under CI.
const haveGo = spawnSync("go", ["version"], { stdio: "ignore" }).status === 0;
const needsGo = haveGo ? {} : { skip: process.env.CI ? false : "go not installed" };
const env = {
  ...process.env,
  PARLEY_TARGETS: "linux/amd64 darwin/arm64 windows/amd64",
  PARLEY_RELEASE_KEY_PASSWORD: "acceptance-password",
};

const scratch = () => mkdtempSync(join(tmpdir(), "parley-accept-"));
const tool = (...args) =>
  spawnSync("go", ["run", "./cmd/parley-release", ...args], { cwd: root, env, encoding: "utf8" });

test("acceptance: harness boots a gateway, mock OIDC and daemons", needsGo, async () => {
  const h = await start({ daemons: 2, quiet: true });
  try {
    assert.equal((await fetch(`${h.gatewayUrl}/healthz`)).status, 200);
    const cfg = await (await fetch(`${h.oidcIssuer}/.well-known/openid-configuration`)).json();
    assert.equal(cfg.issuer, h.oidcIssuer);
    assert.equal(h.daemons.length, 2);
    for (const d of h.daemons) assert.equal(d.child.exitCode, null, `${d.name} running`);
  } finally {
    await h.stop();
  }
  await assert.rejects(fetch(`${h.gatewayUrl}/healthz`), "everything stopped");
});

test("acceptance: release build is reproducible and verifiable with the project key", needsGo, () => {
  const dir = scratch();
  try {
    const secret = join(dir, "project.key");
    const pub = join(dir, "project.pub");
    assert.equal(tool("keygen", secret, pub).status, 0);

    const [a, b] = [join(dir, "a"), join(dir, "b")];
    for (const out of [a, b]) {
      execFileSync("sh", ["scripts/release.sh", "v0.0.0-accept", out, secret], { cwd: root, env, stdio: "pipe" });
    }
    // Reproducible: two independent builds are byte-identical, binaries included.
    const sumsA = readFileSync(join(a, "SHA256SUMS"), "utf8");
    assert.equal(sumsA, readFileSync(join(b, "SHA256SUMS"), "utf8"));
    assert.match(sumsA, /parleyd_v0\.0\.0-accept_darwin_arm64/);
    assert.match(sumsA, /sbom\.cdx\.json/);
    for (const f of ["parleyd_v0.0.0-accept_linux_amd64", "parley-cli_v0.0.0-accept_windows_amd64.exe", "sbom.cdx.json"]) {
      assert.ok(readFileSync(join(a, f)).equals(readFileSync(join(b, f))), `${f} identical`);
    }

    // Verifiable: signature checks against the project key, then every file against the sums.
    assert.equal(tool("verify", pub, join(a, "SHA256SUMS")).status, 0);
    assert.equal(tool("verify-checksums", join(a, "SHA256SUMS")).status, 0);

    // A key other than the one that signed is rejected, including the key committed
    // in release/release.pub (this build was not signed with it).
    assert.notEqual(tool("verify", join(root, "release", "release.pub"), join(a, "SHA256SUMS")).status, 0);

    // Tampering with a binary or with the checksum list is caught.
    writeFileSync(join(a, "parleyd_v0.0.0-accept_linux_amd64"), "evil");
    assert.notEqual(tool("verify-checksums", join(a, "SHA256SUMS")).status, 0);
    writeFileSync(join(b, "SHA256SUMS"), sumsA.replace(/^./, (c) => (c === "0" ? "1" : "0")));
    assert.notEqual(tool("verify", pub, join(b, "SHA256SUMS")).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("acceptance: the redaction build test fails on a leaked payload field", needsGo, () => {
  const dir = scratch();
  try {
    // A throwaway copy of the module, so the real tree is never touched.
    const copy = join(dir, "repo");
    const skip = new Set([".git", "node_modules", "dist", ".wrangler"]);
    cpSync(root, copy, { recursive: true, filter: (p) => !skip.has(p.split(/[\\/]/).pop()) });
    const run = () =>
      spawnSync("go", ["test", "-count=1", "-run", "^TestNoPayloadFieldReachesALog$", "./internal/logx"], {
        cwd: copy,
        env,
        encoding: "utf8",
      });

    const clean = run();
    assert.equal(clean.status, 0, clean.stdout + clean.stderr);

    mkdirSync(join(copy, "internal", "leak"));
    writeFileSync(
      join(copy, "internal", "leak", "leak.go"),
      `// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package leak

import "github.com/kalahroudi/parley/internal/logx"

type result struct{ Text string }

func Report(l *logx.Logger, task string, res result) {
	l.Info("done", logx.ID("task", res.Text))
}
`,
    );
    const leaked = run();
    assert.notEqual(leaked.status, 0, "build test must fail");
    assert.match(leaked.stdout + leaked.stderr, /leak\.go:\d+:.*payload field/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Phase 1 acceptance (T107, spike 2): enroll, approve and revoke; binding
// rollback rejected; recovery code restores the root; stale revocation list
// behavior. The checks live in internal/acceptance and cross the root, binding
// and revocation packages together.
test("acceptance: JA-01 root, approval, binding rollback, revocation and recovery code", needsGo, () => {
  const r = spawnSync("go", ["test", "-race", "-count=1", "./internal/acceptance"], { cwd: root, encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

// Phase 2 acceptance (T207, spike 3): published test vectors pass, fuzzing finds
// no crashes, and every malicious-gateway attack is rejected or detected. Each
// check runs the real Go tests and requires the named tests to have actually run,
// so a renamed or skipped test cannot let the acceptance pass empty.
const go = (args) => spawnSync("go", args, { cwd: root, encoding: "utf8" });
const ran = (out, names) => {
  for (const n of names) assert.match(out, new RegExp(`^--- PASS: ${n} `, "m"), `${n} did not run and pass`);
};

test("acceptance: T207 published transcript and binding test vectors pass", needsGo, () => {
  const r = go(["test", "-count=1", "-v", "-run", "^TestPublishedVectors$", "./internal/envelope", "./internal/binding"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^ok\s+\S+\/internal\/envelope/m);
  assert.match(r.stdout, /^ok\s+\S+\/internal\/binding/m);
  // One vector test per package: envelope transcripts and root-signed bindings.
  assert.equal(r.stdout.match(/^--- PASS: TestPublishedVectors /gm)?.length, 2, "both vector tests must run and pass");
});

// A fuzz target that panics or breaks an invariant exits nonzero and writes the
// failing input under testdata/fuzz; a clean run over the committed corpus plus a
// short random run exits zero. Go allows one -fuzz target per invocation.
for (const [name, fuzzTime] of [
  ["FuzzMessage", "15s"],
  ["FuzzUnpad", "8s"],
  ["FuzzDecryptFile", "8s"],
]) {
  test(`acceptance: T207 ${name} finds no crashes`, needsGo, () => {
    const r = go(["test", "./internal/envelope", "-run", "^$", "-fuzz", `^${name}$`, "-fuzztime", fuzzTime]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /fuzz: elapsed/, "fuzzing did not run");
  });
}

test("acceptance: T207 every malicious-gateway attack is rejected or detected", needsGo, () => {
  const attacks = [
    "TestHonestGateway",
    "TestKeySubstitution",
    "TestReplay",
    "TestReorder",
    "TestDrop",
    "TestSwappedReplies",
    "TestWithheldPrekeys",
    "TestReusedPrekeys",
    "TestJunkFramesBurnNothing",
    "TestSignedButUnopenableBurnsNothing",
    "TestClocks",
    "TestWrongDirection",
    "TestSenderPolicy",
    "TestReconnectAndRestart",
    "TestQuota",
  ];
  const r = go(["test", "-race", "-count=1", "-v", "./internal/acceptance"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  ran(r.stdout, attacks);
});
