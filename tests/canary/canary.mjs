// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Canary scaffold (spike 4). A run mints one unique canary per task content
// field, the test drives a task carrying them through the system, and then
// scans every place a canary must never appear. Pass = zero hits.
//
// Later phases plug real sinks in with scan.path() / scan.text() / scan.bytes():
// Durable Object storage, R2, D1, daemon and gateway logs, URLs, headers and
// error messages. A canary is searched for in the encodings a leak could take.
import { randomBytes } from "node:crypto";
import { readdirSync, readFileSync, lstatSync } from "node:fs";
import { join } from "node:path";

// Task content fields from the spec (G1): inputs, results, status text,
// questions, errors, files (the file name is the canary).
export const FIELDS = ["input", "result", "status", "question", "error", "filename"];

export function mintCanaries(fields = FIELDS) {
  const out = {};
  for (const f of fields) out[f] = `CANARY-${f}-${randomBytes(12).toString("hex")}`;
  return out;
}

// Base64 of `s` as it appears inside a larger base64 stream at any of the three
// byte alignments, keeping only the characters that do not depend on neighbours.
function base64Variants(s) {
  const raw = Buffer.from(s);
  const skip = [0, 2, 3];
  const out = [];
  for (let pad = 0; pad < 3; pad++) {
    const enc = Buffer.concat([Buffer.alloc(pad), raw]).toString("base64").replace(/=+$/, "");
    const tail = (pad + raw.length) % 3 === 0 ? 0 : 1;
    out.push(enc.slice(skip[pad], enc.length - tail));
  }
  return out;
}

// Every form a leaked canary could take, as [encoding, needle] pairs.
export function needles(canary) {
  const b64 = base64Variants(canary);
  const forms = [
    ["plain", canary],
    ["utf16le", Buffer.from(canary, "utf16le")],
    ["hex", Buffer.from(canary).toString("hex")],
    ["url", encodeURIComponent(canary)],
    ["json", JSON.stringify(canary).slice(1, -1)],
    ...b64.map((v) => ["base64", v]),
    ...b64.map((v) => ["base64url", v.replaceAll("+", "-").replaceAll("/", "_")]),
  ];
  return forms.map(([enc, n]) => [enc, Buffer.from(n)]);
}

export class Scan {
  constructor(canaries) {
    this.canaries = canaries;
    this.table = Object.entries(canaries).flatMap(([field, c]) =>
      needles(c).map(([encoding, needle]) => ({ field, encoding, needle })),
    );
    this.hits = [];
    this.sinks = [];
  }

  // Scans a buffer or string; `sink` names where it came from in the report.
  bytes(sink, data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
    if (!this.sinks.includes(sink)) this.sinks.push(sink);
    for (const { field, encoding, needle } of this.table) {
      if (!buf.includes(needle)) continue;
      if (!this.hits.some((h) => h.sink === sink && h.field === field && h.encoding === encoding)) {
        this.hits.push({ sink, field, encoding });
      }
    }
  }

  text(sink, str) {
    this.bytes(sink, str);
  }

  // Scans a file, or a directory tree: file contents and every path name
  // (an uploaded file name is itself a canary field).
  path(root) {
    const walk = (p) => {
      this.bytes(`${root} (names)`, p.slice(root.length));
      const st = lstatSync(p);
      if (st.isDirectory()) {
        for (const name of readdirSync(p)) walk(join(p, name));
      } else if (st.isFile()) {
        this.bytes(p, readFileSync(p));
      }
    };
    walk(root);
  }

  report() {
    return this.hits.map((h) => `${h.field} found in ${h.sink} (${h.encoding})`);
  }

  assertClean() {
    const r = this.report();
    if (r.length) throw new Error(`canary leak, ${r.length} hit(s):\n${r.join("\n")}`);
  }
}
