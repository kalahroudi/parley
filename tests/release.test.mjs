// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const hasGo = spawnSync("go", ["version"]).status === 0;
const opts = { skip: !hasGo && "go not installed" };
const env = { ...process.env, PARLEY_TARGETS: "linux/amd64 windows/amd64" };

function tmp() {
  return mkdtempSync(join(tmpdir(), "parley-release-"));
}
function release(out, key) {
  const args = ["scripts/release.sh", "v0.0.0-test", out];
  if (key) args.push(key);
  execFileSync("sh", args, { cwd: root, env, stdio: "pipe" });
}
function tool(...args) {
  return spawnSync("go", ["run", "./cmd/parley-release", ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

test("release build is reproducible, signed and verifiable", opts, () => {
  const dir = tmp();
  const [a, b] = [join(dir, "a"), join(dir, "b")];
  const secret = join(dir, "release.key");
  const pub = join(dir, "release.pub");
  assert.equal(tool("keygen", secret, pub).status, 0);

  release(a, secret);
  release(b, secret);
  const sums = readFileSync(join(a, "SHA256SUMS"), "utf8");
  assert.equal(sums, readFileSync(join(b, "SHA256SUMS"), "utf8"));
  assert.match(sums, /parleyd_v0\.0\.0-test_windows_amd64\.exe/);
  assert.match(sums, /sbom\.cdx\.json/);
  assert.equal(
    readFileSync(join(a, "sbom.cdx.json"), "utf8"),
    readFileSync(join(b, "sbom.cdx.json"), "utf8"),
  );

  const sums1 = join(a, "SHA256SUMS");
  assert.equal(tool("verify", pub, sums1).status, 0);
  assert.equal(tool("verify-checksums", sums1).status, 0);

  // A tampered binary fails the checksum check.
  writeFileSync(join(a, "parleyd_v0.0.0-test_linux_amd64"), "evil");
  assert.notEqual(tool("verify-checksums", sums1).status, 0);

  // A tampered checksum file fails signature verification.
  writeFileSync(sums1, sums + "\n");
  assert.notEqual(tool("verify", pub, sums1).status, 0);

  // A different project key is rejected.
  const other = join(dir, "other.pub");
  assert.equal(tool("keygen", join(dir, "other.key"), other).status, 0);
  assert.notEqual(tool("verify", other, join(b, "SHA256SUMS")).status, 0);
  assert.ok(existsSync(join(b, "SHA256SUMS.minisig")));
});
