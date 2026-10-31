// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
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
  url: (c) => `/tasks?q=${encodeURIComponent(c)}`,
  json: (c) => JSON.stringify({ msg: c }),
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

test("a canary scanned against itself never matches a different run's canary", () => {
  const scan = new Scan(mintCanaries());
  scan.text("log", Object.values(mintCanaries()).join(" "));
  scan.assertClean();
});
