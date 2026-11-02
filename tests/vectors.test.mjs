// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { SETS, check, root, update, versusBase } from "../scripts/vectorlock.mjs";

test("every published vector file matches its lock", () => {
  for (const dir of Object.keys(SETS)) assert.deepEqual(check(dir), []);
});

test("a vector file edited without updating the lock fails", () => {
  const dir = "internal/binding/testdata";
  const tmp = mkdtempSync(join(tmpdir(), "vec-"));
  cpSync(join(root, dir), join(tmp, dir), { recursive: true });
  writeFileSync(join(tmp, dir, "vectors.json"), readFileSync(join(tmp, dir, "vectors.json"), "utf8").replace("basic", "basik"));
  assert.match(check(dir, tmp).join("\n"), /vectors changed without a lock update/);
  // CRLF checkouts hash the same.
  writeFileSync(join(tmp, dir, "vectors.json"), readFileSync(join(root, dir, "vectors.json"), "utf8").replaceAll("\n", "\r\n"));
  assert.deepEqual(check(dir, tmp), []);
});

test("update bumps the version only when a vector changed", () => {
  const dir = "internal/binding/testdata";
  const tmp = mkdtempSync(join(tmpdir(), "vec-"));
  cpSync(join(root, dir), join(tmp, dir), { recursive: true });
  const v = JSON.parse(readFileSync(join(tmp, dir, "vectors.lock.json"), "utf8")).version;
  assert.equal(update(dir, tmp).version, v);
  writeFileSync(join(tmp, dir, "vectors.json"), readFileSync(join(tmp, dir, "vectors.json"), "utf8").replace("basic", "basik"));
  assert.equal(update(dir, tmp).version, v + 1);
});

test("a changed vector with an unchanged version fails against the base", () => {
  const tmp = mkdtempSync(join(tmpdir(), "vec-"));
  const dir = "internal/binding/testdata";
  const git = (...a) => assert.equal(spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@t", ...a], { cwd: tmp }).status, 0, a.join(" "));
  git("init", "-q");
  cpSync(join(root, dir), join(tmp, dir), { recursive: true });
  git("add", "."); git("commit", "-qm", "base");
  assert.deepEqual(versusBase(dir, "HEAD", tmp), []);
  // Edit the vector and rewrite the lock's digest but not its version.
  writeFileSync(join(tmp, dir, "vectors.json"), readFileSync(join(tmp, dir, "vectors.json"), "utf8").replace("basic", "basik"));
  const lock = JSON.parse(readFileSync(join(tmp, dir, "vectors.lock.json"), "utf8"));
  const bumped = update(dir, tmp);
  writeFileSync(join(tmp, dir, "vectors.lock.json"), JSON.stringify({ version: lock.version, files: bumped.files }));
  assert.match(versusBase(dir, "HEAD", tmp).join("\n"), /still 1/);
  writeFileSync(join(tmp, dir, "vectors.lock.json"), JSON.stringify(bumped));
  assert.deepEqual(versusBase(dir, "HEAD", tmp), []);
});
