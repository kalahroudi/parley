// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const read = (p) => readFileSync(join(root, p), "utf8").replace(/\r\n/g, "\n");

const STATUSES = new Set(["planned", "passing"]);

function cells(line) {
  return line.slice(1, -1).split("|").map((c) => c.trim());
}

// Rows of the first table in `text` that has a `Journey` header, as objects.
function table(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => /^\|\s*Journey\s*\|/.test(l));
  assert.ok(start >= 0, "no Journey table found");
  const head = cells(lines[start]);
  const rows = [];
  for (let i = start + 2; i < lines.length && lines[i].startsWith("|"); i++) {
    const c = cells(lines[i]);
    assert.equal(c.length, head.length, `bad column count: ${lines[i]}`);
    rows.push(Object.fromEntries(head.map((h, j) => [h, c[j]])));
  }
  return rows;
}

// Journey letter -> set of phases, from tasks.md ("A Admin onboarding, B ..." | "1, 5").
function expectedPhases() {
  const map = new Map();
  for (const r of table(read("specs/parley-mvp/tasks.md"))) {
    const phases = r.Phase.split(",").map((p) => p.trim());
    for (const m of r.Journey.matchAll(/(?:^|,\s*)([A-L])\s/g)) map.set(m[1], new Set(phases));
  }
  return map;
}

const rows = table(read("tests/journeys.md"));
const letterOf = (r) => r.Journey[0];

test("every journey A to L has at least one test", () => {
  const seen = new Set(rows.map(letterOf));
  for (const l of "ABCDEFGHIJKL") assert.ok(seen.has(l), `journey ${l} has no test`);
  assert.deepEqual([...seen].sort().join(""), "ABCDEFGHIJKL");
});

test("test ids are unique and match their journey", () => {
  const ids = new Set();
  for (const r of rows) {
    assert.match(r["Test id"], /^J[A-L]-\d{2}$/, `bad id ${r["Test id"]}`);
    assert.equal(r["Test id"][1], letterOf(r), `${r["Test id"]} filed under journey ${letterOf(r)}`);
    assert.ok(!ids.has(r["Test id"]), `duplicate id ${r["Test id"]}`);
    ids.add(r["Test id"]);
  }
});

test("phases agree with the journey to phase matrix in tasks.md", () => {
  const expected = expectedPhases();
  assert.equal(expected.size, 12, "tasks.md matrix must cover A to L");
  for (const r of rows) {
    assert.match(r.Phase, /^[0-6]$/, `bad phase for ${r["Test id"]}`);
    const l = letterOf(r);
    assert.ok(expected.get(l).has(r.Phase), `${r["Test id"]}: phase ${r.Phase} not allowed for ${l}`);
  }
});

test("status is planned or passing, with a scenario", () => {
  for (const r of rows) {
    assert.ok(STATUSES.has(r.Status), `${r["Test id"]}: bad status ${r.Status}`);
    assert.ok(r.Scenario.length > 0, `${r["Test id"]}: empty scenario`);
  }
});
