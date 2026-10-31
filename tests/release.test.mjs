// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const hasGo = spawnSync("go", ["version"]).status === 0;
const opts = { skip: !hasGo && "go not installed" };
const env = {
  ...process.env,
  PARLEY_TARGETS: "linux/amd64 windows/amd64",
  PARLEY_RELEASE_KEY_PASSWORD: "test-password",
};

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
    env,
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

  // The secret key file is encrypted and needs the right password.
  assert.ok(!readFileSync(secret, "utf8").includes("untrusted"));
  const wrong = spawnSync("sh", ["scripts/release.sh", "v0", join(dir, "w"), secret], {
    cwd: root,
    env: { ...env, PARLEY_RELEASE_KEY_PASSWORD: "wrong" },
  });
  assert.notEqual(wrong.status, 0);

  // keygen never overwrites an existing key.
  assert.notEqual(tool("keygen", secret, join(dir, "again.pub")).status, 0);
  assert.ok(!existsSync(join(dir, "again.pub")));
});

test("release.sh handles spaces, refuses a non-empty outdir, unsigned has no .minisig", opts, () => {
  const dir = tmp();
  const out = join(dir, "out dir");
  release(out);
  assert.ok(existsSync(join(out, "SHA256SUMS")));
  assert.ok(!existsSync(join(out, "SHA256SUMS.minisig")));
  assert.throws(() => release(out));
});

test("release.sh enforces PARLEY_GO_VERSION", opts, () => {
  const bad = spawnSync("sh", ["scripts/release.sh", "v0", join(tmp(), "o")], {
    cwd: root,
    env: { ...env, PARLEY_GO_VERSION: "go0.0.0" },
    encoding: "utf8",
  });
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /want go0\.0\.0/);
});

test("release-setup.sh sets both secrets via gh and keeps secrets out of the repo", opts, () => {
  const dir = tmp();
  const bin = join(dir, "bin");
  mkdirSync(bin);
  // Fake gh: records "secret set NAME" and its stdin; "secret list" is empty.
  writeFileSync(
    join(bin, "gh"),
    `#!/bin/sh
if [ "$2" = set ]; then cat > "${dir}/$3.value"; echo "$3" >> "${dir}/set.log"; fi
`,
    { mode: 0o755 },
  );
  const keydir = join(dir, "keys");
  const pub = join(dir, "out", "release.pub");
  const e = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    PARLEY_KEY_DIR: keydir,
    PARLEY_PUB_OUT: pub,
  };
  delete e.PARLEY_RELEASE_KEY_PASSWORD;
  const r = spawnSync("sh", ["scripts/release-setup.sh", "--no-commit"], { cwd: root, env: e, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(readFileSync(join(dir, "set.log"), "utf8").trim().split("\n"), [
    "PARLEY_RELEASE_KEY",
    "PARLEY_RELEASE_KEY_PASSWORD",
  ]);
  const password = readFileSync(join(dir, "PARLEY_RELEASE_KEY_PASSWORD.value"), "utf8");
  assert.equal(password.length, 48);
  assert.ok(!r.stdout.includes(password) && !r.stderr.includes(password));
  assert.equal(
    readFileSync(join(dir, "PARLEY_RELEASE_KEY.value"), "utf8"),
    readFileSync(join(keydir, "release.key"), "utf8"),
  );
  // The generated key really signs with that password, and the public key matches.
  const f = join(dir, "msg");
  writeFileSync(f, "x");
  const s = spawnSync("go", ["run", "./cmd/parley-release", "sign", join(keydir, "release.key"), f, "c"], {
    cwd: root,
    env: { ...process.env, PARLEY_RELEASE_KEY_PASSWORD: password },
  });
  assert.equal(s.status, 0, String(s.stderr));
  assert.equal(spawnSync("go", ["run", "./cmd/parley-release", "verify", pub, f], { cwd: root }).status, 0);
  // A second run refuses to overwrite the key.
  assert.notEqual(spawnSync("sh", ["scripts/release-setup.sh", "--no-commit"], { cwd: root, env: e }).status, 0);
});
