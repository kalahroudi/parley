// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(import.meta.url), "..", "..");
const read = (p) => readFileSync(join(root, p), "utf8").replace(/\r\n/g, "\n");

const STATUSES = new Set(["planned", "passing"]);

function cells(line) {
  return line.trim().slice(1, -1).split("|").map((c) => c.trim());
}

// Rows of the first table in `text` that has a `Journey` header, as objects.
function table(text) {
  const lines = text.split("\n");
  const start = lines.findIndex((l) => /^\|\s*Journey\s*\|/.test(l));
  assert.ok(start >= 0, "no Journey table found");
  const head = cells(lines[start]);
  const rows = [];
  let i = start + 2;
  for (; i < lines.length && lines[i].startsWith("|"); i++) {
    const c = cells(lines[i]);
    assert.equal(c.length, head.length, `bad column count (a literal | in a cell?): ${lines[i]}`);
    rows.push(Object.fromEntries(head.map((h, j) => [h, c[j]])));
  }
  const stray = lines.slice(i).find((l) => l.startsWith("|"));
  assert.equal(stray, undefined, `table rows after a break are ignored: ${stray}`);
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

// Journey letters defined in spec.md ("**A. Admin onboarding ...**").
const LETTERS = [...read("specs/parley-mvp/spec.md").matchAll(/^\*\*([A-Z])\. /gm)].map((m) => m[1]).sort().join("");

// All test sources except the matrix and its own checker.
function testSources(dir = join(root, "tests")) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return testSources(p);
    return /journeys\.(md|test\.mjs)$/.test(p) ? [] : [readFileSync(p, "utf8")];
  });
}

test("every journey A to L has at least one test", () => {
  const seen = new Set(rows.map(letterOf));
  assert.ok(LETTERS.length > 0, "no journeys found in spec.md");
  for (const l of LETTERS) assert.ok(seen.has(l), `journey ${l} has no test`);
  assert.equal([...seen].sort().join(""), LETTERS);
});

test("test ids are unique and match their journey", () => {
  const ids = new Set();
  for (const r of rows) {
    assert.match(r["Test id"], /^J[A-Z]-\d{2}$/, `bad id ${r["Test id"]}`);
    assert.equal(r["Test id"][1], letterOf(r), `${r["Test id"]} filed under journey ${letterOf(r)}`);
    assert.ok(!ids.has(r["Test id"]), `duplicate id ${r["Test id"]}`);
    ids.add(r["Test id"]);
  }
});

test("phases agree with the journey to phase matrix in tasks.md", () => {
  const expected = expectedPhases();
  assert.equal([...expected.keys()].sort().join(""), LETTERS, "tasks.md matrix must cover every journey in spec.md");
  for (const r of rows) {
    assert.match(r.Phase, /^[0-6]$/, `bad phase for ${r["Test id"]}`);
    const l = letterOf(r);
    assert.ok(expected.get(l).has(r.Phase), `${r["Test id"]}: phase ${r.Phase} not allowed for ${l}`);
  }
  // Each phase listed for a group of journeys must be covered by some journey in that group.
  for (const g of table(read("specs/parley-mvp/tasks.md"))) {
    const letters = [...g.Journey.matchAll(/(?:^|,\s*)([A-Z])\s/g)].map((m) => m[1]);
    const have = new Set(rows.filter((r) => letters.includes(letterOf(r))).map((r) => r.Phase));
    for (const p of g.Phase.split(",").map((x) => x.trim())) {
      assert.ok(have.has(p), `journeys ${letters.join(", ")} have no test in phase ${p}`);
    }
  }
});

test("status is planned or passing, with a scenario", () => {
  for (const r of rows) {
    assert.ok(STATUSES.has(r.Status), `${r["Test id"]}: bad status ${r.Status}`);
    assert.ok(r.Scenario.length > 0, `${r["Test id"]}: empty scenario`);
  }
});

test("a passing row has a test that names its id; a planned row has none", () => {
  const sources = testSources().join("\n");
  for (const r of rows) {
    const id = r["Test id"];
    const found = new RegExp(`\\b${id}\\b`).test(sources);
    if (r.Status === "passing") assert.ok(found, `${id} is passing but no test under tests/ names it`);
    else assert.ok(!found, `${id} has a test under tests/; mark it passing`);
  }
});
