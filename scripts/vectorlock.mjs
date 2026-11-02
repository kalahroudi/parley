// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// The published test vectors are a wire-format promise. Each vector directory
// has a vectors.lock.json holding a format version and the SHA-256 of every
// vector file (line endings normalized so a Windows checkout hashes the same).
//
//   node scripts/vectorlock.mjs check          digests match the files
//   node scripts/vectorlock.mjs update         re-hash; bump the version if any file changed
//   node scripts/vectorlock.mjs base <git-ref> versus <ref>: changed vectors need a higher version
//
// So editing a vector by hand fails `check`, regenerating it bumps the version,
// and rewriting the lock to hide a change fails `base` in the pull request.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export const root = join(fileURLToPath(import.meta.url), "..", "..");

// Vector directory to the vector files it locks.
export const SETS = {
  "internal/envelope/testdata": ["vectors.json", "vectors_padfile.json"],
  "internal/binding/testdata": ["vectors.json"],
};
const lockPath = (dir) => join(dir, "vectors.lock.json");

const digest = (path) =>
  createHash("sha256").update(readFileSync(path, "utf8").replaceAll("\r\n", "\n")).digest("hex");

export function digests(dir, files = SETS[dir], base = root) {
  return Object.fromEntries(files.map((f) => [f, digest(join(base, dir, f))]));
}

export function readLock(dir, base = root) {
  return JSON.parse(readFileSync(join(base, lockPath(dir)), "utf8"));
}

/** Problems with the lock of one vector directory; empty when it holds. */
export function check(dir, base = root) {
  const lock = readLock(dir, base);
  const now = digests(dir, SETS[dir], base);
  const bad = [];
  if (!Number.isInteger(lock.version) || lock.version < 1) bad.push(`${dir}: lock version must be a positive integer`);
  for (const f of new Set([...Object.keys(now), ...Object.keys(lock.files ?? {})])) {
    if (now[f] !== lock.files?.[f]) bad.push(`${dir}/${f}: vectors changed without a lock update; run: node scripts/vectorlock.mjs update`);
  }
  return bad;
}

export function update(dir, base = root) {
  const now = digests(dir, SETS[dir], base);
  let prev = { version: 0, files: {} };
  try { prev = readLock(dir, base); } catch {}
  const changed = JSON.stringify(now) !== JSON.stringify(prev.files);
  const lock = { version: changed ? prev.version + 1 : prev.version, files: now };
  writeFileSync(join(base, lockPath(dir)), JSON.stringify(lock, null, 2) + "\n");
  return lock;
}

/** Problems versus a git ref: a changed vector file needs a strictly higher version. */
export function versusBase(dir, ref, base = root) {
  const git = (...a) => spawnSync("git", a, { cwd: base, encoding: "utf8" });
  const shown = git("show", `${ref}:${lockPath(dir).replaceAll("\\", "/")}`);
  if (shown.status !== 0) return []; // the lock is new: nothing to compare
  const old = JSON.parse(shown.stdout);
  const lock = readLock(dir, base);
  const now = digests(dir, SETS[dir], base);
  const bad = [];
  for (const f of Object.keys(now)) {
    const was = git("show", `${ref}:${dir}/${f}`);
    if (was.status === 0 && createHash("sha256").update(was.stdout.replaceAll("\r\n", "\n")).digest("hex") !== now[f] && lock.version <= old.version) {
      bad.push(`${dir}/${f} changed but the vector version is still ${lock.version} (base ${old.version}): bump it with the update command`);
    }
  }
  if (lock.version < old.version) bad.push(`${dir}: vector version went down from ${old.version} to ${lock.version}`);
  return bad;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, ref] = process.argv.slice(2);
  let bad = [];
  for (const dir of Object.keys(SETS)) {
    if (cmd === "update") console.log(dir, update(dir));
    else if (cmd === "check") bad.push(...check(dir));
    else if (cmd === "base" && ref) bad.push(...check(dir), ...versusBase(dir, ref));
    else { console.error("usage: vectorlock.mjs check | update | base <git-ref>"); process.exit(2); }
  }
  for (const b of bad) console.error(b);
  process.exit(bad.length ? 1 : 0);
}
