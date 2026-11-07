// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
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

test("release.sh signs a manifest header with the version and a validity window", opts, () => {
  const dir = tmp();
  const secret = join(dir, "release.key");
  const pub = join(dir, "release.pub");
  assert.equal(tool("keygen", secret, pub).status, 0);
  const out = join(dir, "o");
  const e = { ...env, PARLEY_ISSUED: "1800000000", PARLEY_VALID_DAYS: "30" };
  execFileSync("sh", ["scripts/release.sh", "v1.2.3", out, secret], { cwd: root, env: e, stdio: "pipe" });
  const v = tool("verify", pub, join(out, "SHA256SUMS"));
  assert.equal(v.status, 0);
  // 1800000000 + 30 days. The text is what internal/update.FormatComment writes (a Go test pins that format).
  assert.equal(v.stdout.trim(), "signature ok: parley release v1.2.3 issued=1800000000 expires=1802592000");
});

test("release.sh refuses a validity window outside 1 to 400 days", opts, () => {
  for (const days of ["0", "401", "abc", "-5", "1.5", "010"]) {
    const r = spawnSync("sh", ["scripts/release.sh", "v1.2.3", join(tmp(), "o")], {
      cwd: root,
      env: { ...env, PARLEY_VALID_DAYS: days },
      encoding: "utf8",
    });
    assert.notEqual(r.status, 0, `days=${days}`);
    assert.match(r.stderr, /PARLEY_VALID_DAYS/, `days=${days}`);
  }
});

// A signed plain-tag release with every default target, built once and shared by the channel tests below.
let shared;
function signedRelease() {
  if (shared) return shared;
  const dir = tmp();
  const secret = join(dir, "release.key");
  const pub = join(dir, "release.pub");
  assert.equal(tool("keygen", secret, pub).status, 0);
  const out = join(dir, "dist");
  const e = { ...process.env, PARLEY_RELEASE_KEY_PASSWORD: "test-password" };
  delete e.PARLEY_TARGETS;
  execFileSync("sh", ["scripts/release.sh", "v1.2.3", out, secret], { cwd: root, env: e, stdio: "pipe" });
  return (shared = { dir, out, pub, secret });
}

test("a plain release tag also builds the Homebrew formula and Debian packages, all covered by SHA256SUMS", opts, () => {
  const { out } = signedRelease();
  const sums = readFileSync(join(out, "SHA256SUMS"), "utf8");
  for (const f of ["parley.rb", "parley_1.2.3_amd64.deb", "parley_1.2.3_arm64.deb", "parleyd_v1.2.3_darwin_arm64"]) {
    assert.ok(existsSync(join(out, f)), f);
    assert.ok(sums.includes("  " + f + "\n"), `${f} is not in SHA256SUMS`);
  }
  const formula = readFileSync(join(out, "parley.rb"), "utf8");
  const sha = (f) => sums.split("\n").find((l) => l.endsWith("  " + f)).split("  ")[0];
  assert.ok(formula.includes(`sha256 "${sha("parleyd_v1.2.3_darwin_arm64")}"`), "formula hash differs from the signed one");
  assert.ok(formula.includes(`sha256 "${sha("parley-cli_v1.2.3_linux_amd64")}"`));
  assert.equal(tool("verify-checksums", join(out, "SHA256SUMS")).status, 0);
});

// ---- scripts/publish-tap.sh -------------------------------------------------------------------------------------

function git(cwd, ...args) {
  return execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.test", ...args], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}
// A tap checkout whose "origin" is a local bare repository, so a real push can be observed without a network.
function tapCheckout() {
  const d = tmp();
  const bare = join(d, "origin.git");
  git(d, "init", "-q", "--bare", "-b", "main", bare);
  const work = join(d, "tap");
  git(d, "clone", "-q", bare, work);
  writeFileSync(join(work, "README.md"), "tap\n");
  git(work, "add", "README.md");
  git(work, "commit", "-q", "-m", "init");
  git(work, "push", "-q", "origin", "HEAD:main");
  return { bare, work };
}
function publishTap(dist, tap, pub, ...extra) {
  return spawnSync("sh", ["scripts/publish-tap.sh", dist, tap, ...extra], {
    cwd: root,
    env: { ...process.env, PARLEY_RELEASE_PUB: pub },
    encoding: "utf8",
  });
}

test("publish-tap.sh --dry-run verifies the release and changes nothing", opts, () => {
  const { out, pub } = signedRelease();
  const { work, bare } = tapCheckout();
  const before = git(bare, "rev-parse", "main");
  const r = publishTap(out, work, pub, "--dry-run");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /dry run: would publish parley v1\.2\.3/);
  assert.equal(git(work, "status", "--porcelain"), "");
  assert.ok(!existsSync(join(work, "Formula")));
  assert.equal(git(bare, "rev-parse", "main"), before);
});

test("publish-tap.sh commits and pushes the verified formula once", opts, () => {
  const { out, pub } = signedRelease();
  const { work, bare } = tapCheckout();
  const r = publishTap(out, work, pub);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /published parley v1\.2\.3/);
  assert.equal(git(bare, "log", "-1", "--format=%s", "main").trim(), "parley v1.2.3");
  assert.equal(git(bare, "show", "main:Formula/parley.rb"), readFileSync(join(out, "parley.rb"), "utf8"));
  const again = publishTap(out, work, pub);
  assert.equal(again.status, 0);
  assert.match(again.stdout, /already in the tap/);
  assert.equal(git(bare, "rev-list", "--count", "main").trim(), "2");
});

test("publish-tap.sh refuses what does not verify", opts, () => {
  const { out, pub, dir } = signedRelease();
  const { work, bare } = tapCheckout();
  const before = git(bare, "rev-parse", "main");
  // Another project key.
  const other = join(dir, "other.pub");
  assert.equal(tool("keygen", join(dir, "other.key"), other).status, 0);
  let r = publishTap(out, work, other);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not signed by the project key/);
  // A formula changed after signing, and one that is not covered by the checksums.
  const copy = join(tmp(), "dist");
  execFileSync("cp", ["-R", out, copy]);
  writeFileSync(join(copy, "parley.rb"), readFileSync(join(copy, "parley.rb"), "utf8") + "# tampered\n");
  r = publishTap(copy, work, pub);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /does not match SHA256SUMS/);
  // Not a release directory, not a git checkout, and bad arguments.
  assert.notEqual(publishTap(tmp(), work, pub).status, 0);
  r = publishTap(out, tmp(), pub);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not a git checkout/);
  assert.equal(publishTap(out, work, pub, "--force").status, 2);
  assert.equal(spawnSync("sh", ["scripts/publish-tap.sh", out], { cwd: root }).status, 2);
  assert.equal(git(bare, "rev-parse", "main"), before);
  assert.equal(git(work, "status", "--porcelain"), "");
});

test("publish-tap.sh refuses a formula the signature does not cover or that is for another version", opts, () => {
  const { out, pub, secret } = signedRelease();
  const { work } = tapCheckout();
  // Signed, but built for a target list that makes no formula: the formula is not covered.
  const partial = join(tmp(), "dist");
  execFileSync("sh", ["scripts/release.sh", "v1.2.3", partial, secret], { cwd: root, env, stdio: "pipe" });
  let r = publishTap(partial, work, pub);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /parley\.rb is not covered/);
  // A correctly signed release whose formula is the formula of another version.
  const copy = join(tmp(), "dist");
  execFileSync("cp", ["-R", out, copy]);
  writeFileSync(join(copy, "parley.rb"), readFileSync(join(copy, "parley.rb"), "utf8").replace('version "1.2.3"', 'version "9.9.9"'));
  const files = readdirSync(copy).filter((f) => !f.startsWith("SHA256SUMS"));
  assert.equal(tool("checksums", copy, join(copy, "SHA256SUMS"), ...files).status, 0);
  assert.equal(tool("sign", secret, join(copy, "SHA256SUMS"), "parley release v1.2.3 issued=1800000000 expires=1810000000").status, 0);
  r = publishTap(copy, work, pub);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not the formula of v1\.2\.3/);
});

// ---- scripts/publish-apt.sh -------------------------------------------------------------------------------------

const hasGpg = spawnSync("gpg", ["--version"]).status === 0;
function publishApt(dist, repo, pub, extraEnv, ...args) {
  return spawnSync("sh", ["scripts/publish-apt.sh", dist, repo, ...args], {
    cwd: root,
    env: { ...process.env, PARLEY_RELEASE_PUB: pub, ...extraEnv },
    encoding: "utf8",
  });
}
function signingEnv() {
  const { secret } = signedRelease();
  return { PARLEY_RELEASE_KEY: secret, PARLEY_RELEASE_KEY_PASSWORD: "test-password" };
}

test("publish-apt.sh --dry-run verifies and prepares everything and changes nothing", opts, () => {
  const { out, pub } = signedRelease();
  const { work, bare } = tapCheckout();
  const before = git(bare, "rev-parse", "main");
  let r = publishApt(out, work, pub, signingEnv(), "--dry-run");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /dry run: would publish parley v1\.2\.3 .*\(\d+ files, signed with the project key\)/);
  // Without the key it still verifies, and says the repository would not be signed.
  r = publishApt(out, work, pub, { PARLEY_RELEASE_KEY: "", PARLEY_RELEASE_KEY_PASSWORD: "" }, "--dry-run");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /not signed/);
  assert.equal(git(work, "status", "--porcelain"), "");
  assert.ok(!existsSync(join(work, "apt")));
  assert.equal(git(bare, "rev-parse", "main"), before);
});

test("publish-apt.sh publishes a repository signed by the project key, once", opts, () => {
  const { out, pub } = signedRelease();
  const { work, bare } = tapCheckout();
  const r = publishApt(out, work, pub, signingEnv());
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /published parley v1\.2\.3 to the apt repository/);
  const files = git(bare, "ls-tree", "--name-only", "main:apt").trim().split("\n");
  for (const f of ["InRelease", "Packages", "Release", "Release.gpg", "parley.asc", "parley_1.2.3_amd64.deb", "parley_1.2.3_arm64.deb"]) {
    assert.ok(files.includes(f), `${f} missing from ${files}`);
  }
  assert.equal(git(bare, "log", "-1", "--format=%s", "main").trim(), "apt: parley v1.2.3");
  const show = (f) => git(bare, "show", `main:apt/${f}`);
  assert.match(show("Release"), /Date: .* UTC\n/);
  assert.match(show("InRelease"), /^-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Parley\n/);
  assert.match(show("Release.gpg"), /^-----BEGIN PGP SIGNATURE-----/);
  assert.match(show("parley.asc"), /^-----BEGIN PGP PUBLIC KEY BLOCK-----/);
  assert.match(show("Packages"), /Filename: \.\/parley_1\.2\.3_arm64\.deb\n/);
  if (hasGpg) {
    // What a client does: import the published key, verify the published signatures.
    const home = mkdtempSync(join("/tmp", "pg"));
    const g = (...a) => spawnSync("gpg", ["--homedir", home, "--batch", "--no-tty", ...a], { encoding: "utf8" });
    const dir = tmp();
    for (const f of ["InRelease", "Release", "Release.gpg", "parley.asc"]) writeFileSync(join(dir, f), show(f));
    assert.equal(g("--import", join(dir, "parley.asc")).status, 0);
    assert.equal(g("--verify", join(dir, "InRelease")).status, 0);
    assert.equal(g("--verify", join(dir, "Release.gpg"), join(dir, "Release")).status, 0);
  } else if (process.env.CI && process.platform === "linux") {
    assert.fail("gpg is required on Linux CI to check the published apt signatures");
  }
  const again = publishApt(out, work, pub, signingEnv());
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, /already in the apt repository/);
  assert.equal(git(bare, "rev-list", "--count", "main").trim(), "2");
});

test("publish-apt.sh refuses what does not verify or cannot be signed", opts, () => {
  const { out, pub, dir } = signedRelease();
  const { work, bare } = tapCheckout();
  const before = git(bare, "rev-parse", "main");
  const key = signingEnv();
  const other = join(dir, "other2.pub");
  assert.equal(tool("keygen", join(dir, "other2.key"), other).status, 0);
  let r = publishApt(out, work, other, key);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /not signed by the project key/);
  const copy = join(tmp(), "dist");
  execFileSync("cp", ["-R", out, copy]);
  writeFileSync(join(copy, "parley_1.2.3_amd64.deb"), "tampered");
  r = publishApt(copy, work, pub, key);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /does not match SHA256SUMS/);
  r = publishApt(out, work, pub, { ...key, PARLEY_RELEASE_KEY_PASSWORD: "" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /PARLEY_RELEASE_KEY_PASSWORD/);
  r = publishApt(out, work, pub, { ...key, PARLEY_RELEASE_KEY_PASSWORD: "wrong" });
  assert.notEqual(r.status, 0);
  r = publishApt(out, work, pub, { PARLEY_RELEASE_KEY: "", PARLEY_RELEASE_KEY_PASSWORD: "" });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /set PARLEY_RELEASE_KEY/);
  r = publishApt(out, work, pub, { ...key, PARLEY_RELEASE_KEY: join(dir, "missing.key") });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /names no file/);
  r = publishApt(out, tmp(), pub, key);
  assert.match(r.stderr, /not a git checkout/);
  assert.notEqual(publishApt(tmp(), work, pub, key).status, 0);
  // A release without the packages (built for a short target list) is refused too.
  const { secret } = signedRelease();
  const partial = join(tmp(), "dist");
  execFileSync("sh", ["scripts/release.sh", "v1.2.3", partial, secret], { cwd: root, env, stdio: "pipe" });
  r = publishApt(partial, work, pub, key);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /is missing from/);
  assert.equal(publishApt(out, work, pub, key, "--force").status, 2);
  assert.equal(spawnSync("sh", ["scripts/publish-apt.sh", out], { cwd: root }).status, 2);
  assert.equal(git(bare, "rev-parse", "main"), before);
  assert.equal(git(work, "status", "--porcelain"), "");
});

test("publish-apt.sh refuses a package the signature does not cover", opts, () => {
  const { out, pub, secret } = signedRelease();
  const { work } = tapCheckout();
  const copy = join(tmp(), "dist");
  execFileSync("cp", ["-R", out, copy]);
  // Re-signed by the project key, but the arm64 package is no longer listed.
  const files = readdirSync(copy).filter((f) => !f.startsWith("SHA256SUMS") && f !== "parley_1.2.3_arm64.deb");
  assert.equal(tool("checksums", copy, join(copy, "SHA256SUMS"), ...files).status, 0);
  assert.equal(tool("sign", secret, join(copy, "SHA256SUMS"), "parley release v1.2.3 issued=1800000000 expires=1810000000").status, 0);
  const r = publishApt(copy, work, pub, signingEnv());
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /parley_1\.2\.3_arm64\.deb is not covered/);
});
