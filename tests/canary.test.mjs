// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FIELDS, Scan, mintCanaries } from "./canary/canary.mjs";

test("canaries are unique per run and per field", () => {
  const a = mintCanaries();
  const b = mintCanaries();
  assert.deepEqual(Object.keys(a), FIELDS);
  assert.equal(new Set([...Object.values(a), ...Object.values(b)]).size, FIELDS.length * 2);
});

test("clean sinks produce zero hits", () => {
  const scan = new Scan(mintCanaries());
  scan.text("log", "state=WORKING size=4096 id=abc");
  scan.bytes("storage", Buffer.from(Array.from({ length: 4096 }, (_, i) => i % 251)));
  scan.assertClean();
  assert.deepEqual(scan.sinks, ["log", "storage"]);
});

// Positive controls: a scanner that cannot see a planted canary proves nothing.
const encodings = {
  plain: (c) => `x ${c} y`,
  utf16le: (c) => Buffer.from(`x${c}y`, "utf16le"),
  hex: (c) => Buffer.from(c).toString("hex"),
  utf16be: (c) => Buffer.from(`x${c}y`, "utf16le").swap16(),
  hexUpper: (c) => Buffer.from(c).toString("hex").toUpperCase(),
  url: (c) => `/tasks?q=${encodeURIComponent(c)}`,
  urlDouble: (c) => encodeURIComponent(encodeURIComponent(`a=b&${c}/x`)),
  json: (c) => JSON.stringify({ msg: c }),
  jsonEscaped: (c) => JSON.stringify(`é"${c}"\n`),
  uint8array: (c) => new Uint8Array(Buffer.from(`..${c}..`)),
  subarray: (c) => Buffer.from(`..${c}..`).subarray(2),
  arraybuffer: (c) => new Uint8Array(Buffer.from(`..${c}..`)).buffer,
  base64: (c) => Buffer.from(`k=${c}`).toString("base64"),
  base64url: (c) => Buffer.from(`kk=${c}`).toString("base64url"),
};

for (const [enc, wrap] of Object.entries(encodings)) {
  for (const field of FIELDS) {
    test(`detects ${field} canary leaked as ${enc}`, () => {
      const canaries = mintCanaries();
      const scan = new Scan(canaries);
      scan.bytes("sink", wrap(canaries[field]));
      assert.ok(
        scan.hits.some((h) => h.field === field),
        `${field}/${enc} not detected`,
      );
      assert.throws(() => scan.assertClean(), /canary leak/);
    });
  }
}

test("detects base64 at every alignment inside a larger stream", () => {
  const canaries = mintCanaries();
  const c = canaries.input;
  for (let pad = 0; pad < 6; pad++) {
    for (let after = 0; after < 3; after++) {
      const scan = new Scan(canaries);
      const data = Buffer.concat([Buffer.alloc(pad, 0xff), Buffer.from(c), Buffer.alloc(after, 0xfe)]);
      scan.bytes("s", data.toString("base64"));
      assert.ok(scan.hits.length, `pad ${pad} after ${after}`);
    }
  }
});

test("path scan covers file contents and file names", () => {
  const canaries = mintCanaries();
  const dir = mkdtempSync(join(tmpdir(), "parley-canary-"));
  try {
    mkdirSync(join(dir, "do", "sub"), { recursive: true });
    writeFileSync(join(dir, "do", "clean.sqlite"), "nothing here");
    const clean = new Scan(canaries);
    clean.path(dir);
    clean.assertClean();

    writeFileSync(join(dir, "do", "sub", "blob"), Buffer.from(`..${canaries.result}..`));
    writeFileSync(join(dir, "r2-" + canaries.filename), "x");
    const scan = new Scan(canaries);
    scan.path(dir);
    assert.deepEqual(
      [...new Set(scan.hits.map((h) => h.field))].sort(),
      ["filename", "result"],
    );
    assert.match(scan.report().join("\n"), /result found in .*blob \(plain\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unsupported data types throw instead of scanning clean", () => {
  const scan = new Scan(mintCanaries());
  assert.throws(() => scan.bytes("s", { a: 1 }), TypeError);
  assert.throws(() => scan.bytes("s", null), TypeError);
});

test("mintCanaries honours a custom field list", () => {
  assert.deepEqual(Object.keys(mintCanaries(["a", "b"])), ["a", "b"]);
});

test("path scan handles a single file, an empty dir and skips symlinks", () => {
  const canaries = mintCanaries();
  const dir = mkdtempSync(join(tmpdir(), "parley-canary-"));
  try {
    const empty = new Scan(canaries);
    empty.path(dir);
    empty.assertClean();

    const file = join(dir, "one");
    writeFileSync(file, canaries.input);
    const single = new Scan(canaries);
    single.path(file);
    assert.deepEqual(single.hits.map((h) => h.field), ["input"]);

    const target = join(dir, "target");
    mkdirSync(target);
    writeFileSync(join(target, "f"), canaries.error);
    const linkRoot = mkdtempSync(join(tmpdir(), "parley-canary-link-"));
    try {
      symlinkSync(target, join(linkRoot, "link"));
      const scan = new Scan(canaries);
      scan.path(linkRoot);
      scan.assertClean();
      assert.deepEqual(scan.skipped, [join(linkRoot, "link")]);
    } finally {
      rmSync(linkRoot, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("documented blind spots: gzip and a canary split across calls are not detected", () => {
  const canaries = mintCanaries();
  const c = canaries.input;
  const scan = new Scan(canaries);
  scan.bytes("gz", gzipSync(Buffer.from(c)));
  scan.bytes("a", c.slice(0, 10));
  scan.bytes("b", c.slice(10));
  assert.equal(scan.hits.length, 0);
});

test("another run's canaries never match", () => {
  const scan = new Scan(mintCanaries());
  scan.text("log", Object.values(mintCanaries()).join(" "));
  scan.assertClean();
});
