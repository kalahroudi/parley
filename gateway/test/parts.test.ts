// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Tier 1: src/parts.ts is held to 100% coverage (vitest.config.ts) and to
// mutation testing (stryker.config.json). It decides what the gateway will relay.

import { describe, expect, it } from "vitest";
import { MAX_BUCKET, MAX_RAW_CHARS, MIN_BUCKET, parseSealedPart, parseWire, SEALED_MEDIA_TYPE, SIGNED_TYPE, type SignedKind } from "../src/parts";
import { b64, encodeHeader, encodeWire, header, taskBytes, taskHex, type Header, type Wire } from "./wire";

const KINDS = Object.keys(SIGNED_TYPE) as SignedKind[];
const ok = (kind: SignedKind = "TASK", h: Header = {}, w: Partial<Wire> = {}) => encodeWire({ header: header(kind, h), ...w });
const part = (wire: Uint8Array) => ({ raw: b64(wire), mediaType: SEALED_MEDIA_TYPE });

it("the constants are the ones the daemons and the frame limit fix", () => {
  expect(SEALED_MEDIA_TYPE).toBe("application/vnd.parley.sealed");
  // 4 length prefixes + the largest header + enc + the largest ciphertext + signature, as base64.
  expect(MAX_RAW_CHARS).toBe(Math.ceil((16 + 16384 + 32 + (1 << 19) + 16 + 64) / 3) * 4);
  expect(MAX_RAW_CHARS).toBe(721_068);
});

describe("a valid message", () => {
  it("is read field for field for every kind", () => {
    for (const kind of KINDS) {
      const h = header(kind, { tenant: "acme", sender: "caller", target: "target", context: "ctx9", task: taskBytes("abc"), seq: kind === "TASK" ? 0 : 7 });
      expect(parseWire(encodeWire({ header: h, bucket: 8192 })), kind).toEqual({
        kind, tenant: "acme", sender: "caller", target: "target", context: "ctx9", taskId: taskHex("abc"), seq: kind === "TASK" ? 0 : 7, bucket: 8192,
      });
    }
  });

  it("takes the task id as lowercase hex of its 16 bytes", () => {
    const task = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
    expect(parseWire(ok("TASK", { task }))?.taskId).toBe("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
  });

  it("accepts every power-of-two bucket from 4 KiB to the largest, and nothing else", () => {
    expect(MIN_BUCKET).toBe(4096);
    expect(MAX_BUCKET).toBe(1 << 19);
    for (let b = MIN_BUCKET; b <= MAX_BUCKET; b *= 2) expect(parseWire(ok("TASK", {}, { bucket: b }))?.bucket, String(b)).toBe(b);
    for (const b of [0, 1, 16, 2048, 4095, 4097, 6144, 8191, MAX_BUCKET * 2, MAX_BUCKET * 4]) expect(parseWire(ok("TASK", {}, { bucket: b })), String(b)).toBeNull();
    // A ciphertext without the tag, or with extra bytes, is not a bucket plus the tag.
    for (const ctLen of [4096, 4096 + 15, 4096 + 17, 8192]) expect(parseWire(ok("TASK", {}, { ctLen })), String(ctLen)).toBeNull();
  });

  it("accepts a seq up to the largest safe integer and no further", () => {
    expect(parseWire(ok("STATUS", { seq: Number.MAX_SAFE_INTEGER }))?.seq).toBe(Number.MAX_SAFE_INTEGER);
    expect(parseWire(ok("STATUS", { seq: BigInt(Number.MAX_SAFE_INTEGER) + 1n }))).toBeNull();
    expect(parseWire(ok("STATUS", { seq: 1n << 63n }))).toBeNull();
  });
});

describe("a message the daemon's parser would refuse", () => {
  const bad: [string, Wire][] = [
    ["wrong label", { header: header("TASK", { label: "parley/msg/v2" }) }],
    ["label of another length", { header: header("TASK", { label: "parley/msg/v1x" }) }],
    ["short label", { header: header("TASK", { label: "parley/msg/v" }) }],
    ["wrong KEM", { header: header("TASK", { suite: [0x0021, 0x0001, 0x0003] }) }],
    ["wrong KDF", { header: header("TASK", { suite: [0x0020, 0x0002, 0x0003] }) }],
    ["wrong AEAD", { header: header("TASK", { suite: [0x0020, 0x0001, 0x0002] }) }],
    ["empty tenant", { header: header("TASK", { tenant: "" }) }],
    ["empty sender", { header: header("TASK", { sender: "" }) }],
    ["empty key id", { header: header("TASK", { keyId: "" }) }],
    ["binding version 0", { header: header("TASK", { version: 0 }) }],
    ["empty target", { header: header("TASK", { target: "" }) }],
    ["empty prekey id", { header: header("TASK", { prekeyId: "" }) }],
    ["empty context", { header: header("TASK", { context: "" }) }],
    ["tenant not UTF-8", { header: header("TASK", { tenant: Uint8Array.of(0xff, 0xfe) }) }],
    ["task id 15 bytes", { header: header("TASK", { task: new Uint8Array(15) }) }],
    ["task id 17 bytes", { header: header("TASK", { task: new Uint8Array(17) }) }],
    ["type 0", { header: header("TASK", { type: 0 }) }],
    ["type 8", { header: header("TASK", { type: 8 }) }],
    ["expiry equals issued", { header: header("TASK", { issued: 5, expiry: 5 }) }],
    ["expiry before issued", { header: header("TASK", { issued: 5, expiry: 4 }) }],
    ["issued past a safe integer", { header: header("TASK", { issued: 1n << 60n }) }],
    ["expiry past a safe integer", { header: header("TASK", { expiry: 1n << 60n }) }],
    ["version past a safe integer", { header: header("TASK", { version: 1n << 60n }) }],
    ["rpk of 31 bytes", { header: header("TASK", { rpk: new Uint8Array(31) }) }],
    ["rpk of 33 bytes", { header: header("TASK", { rpk: new Uint8Array(33) }) }],
    ["TASK without rpk", { header: header("TASK", { rpk: new Uint8Array(0) }) }],
    ["TASK with seq", { header: header("TASK", { seq: 1 }) }],
    ["TASK with a previous hash", { header: header("TASK", { prev: new Uint8Array(32) }) }],
    ["TASK without a prekey", { header: header("TASK", { prekey: new Uint8Array(0) }) }],
    ["reply with seq 0", { header: header("STATUS", { seq: 0 }) }],
    ["reply without a previous hash", { header: header("STATUS", { prev: new Uint8Array(0) }) }],
    ["reply with a short previous hash", { header: header("STATUS", { prev: new Uint8Array(31) }) }],
    ["reply with a long previous hash", { header: header("STATUS", { prev: new Uint8Array(33) }) }],
    ["reply with a prekey", { header: header("STATUS", { prekey: new Uint8Array(1) }) }],
    ["reply with rpk of 31 bytes", { header: header("STATUS", { rpk: new Uint8Array(31) }) }],
    ["trailing bytes in the header", { header: header("TASK", { trailing: Uint8Array.of(0) }) }],
    ["trailing bytes after the signature", { header: header("TASK"), trailing: Uint8Array.of(0) }],
    ["enc of 31 bytes", { header: header("TASK"), enc: new Uint8Array(31) }],
    ["enc of 33 bytes", { header: header("TASK"), enc: new Uint8Array(33) }],
    ["no enc", { header: header("TASK"), enc: new Uint8Array(0) }],
    ["signature of 63 bytes", { header: header("TASK"), sig: new Uint8Array(63) }],
    ["signature of 65 bytes", { header: header("TASK"), sig: new Uint8Array(65) }],
    ["header over the cap", { header: header("TASK", { prekey: new Uint8Array(1 << 14) }) }],
  ];
  it.each(bad)("%s", (_, w) => expect(parseWire(encodeWire(w))).toBeNull());

  it("a header at the cap is still read", () => {
    // The cap counts the whole encoded header, so find the largest prekey that fits.
    let n = 1 << 13;
    const size = (k: number) => encodeHeader(header("TASK", { prekey: new Uint8Array(k) })).length;
    while (size(n + 1) <= 1 << 14) n++;
    expect(size(n)).toBeLessThanOrEqual(1 << 14);
    expect(parseWire(ok("TASK", { prekey: new Uint8Array(n) }))).not.toBeNull();
    expect(parseWire(ok("TASK", { prekey: new Uint8Array(n + 1) }))).toBeNull();
  });

  it("a single field over its cap", () => {
    expect(parseWire(ok("TASK", { tenant: "a".repeat(1 << 16) }))).toBeNull();
    expect(parseWire(ok("TASK", { tenant: "a".repeat(1000) }))?.tenant).toHaveLength(1000);
  });

  it("keeps a leading byte-order mark in a name, as the daemon does", () => {
    expect(parseWire(ok("TASK", { tenant: "\uFEFFt" }))?.tenant).toBe("\uFEFFt");
  });

  it("refuses a type number no daemon knows even when everything else fits another kind", () => {
    for (const type of [0, 8, 255]) {
      expect(parseWire(ok("STATUS", { type })), String(type)).toBeNull();
      expect(parseWire(ok("TASK", { type })), String(type)).toBeNull();
    }
  });

  it("refuses a header that ends inside any field, even when the outer lengths are right", () => {
    for (const kind of ["TASK", "STATUS"] as const) {
      const full = encodeHeader(header(kind));
      expect(parseWire(encodeWire({ header: {}, hdrBytes: full })), kind).not.toBeNull();
      for (let n = 0; n < full.length; n++) expect(parseWire(encodeWire({ header: {}, hdrBytes: full.subarray(0, n) })), `${kind} ${n}`).toBeNull();
    }
  });

  it("is refused at every truncation, and with any length prefix that runs past the data", () => {
    const wire = ok("TASK");
    for (let n = 0; n < wire.length; n++) expect(parseWire(wire.subarray(0, n)), String(n)).toBeNull();
    expect(parseWire(wire)).not.toBeNull();
    const lie = wire.slice();
    lie[0] = 0x7f; // header length far beyond the message
    expect(parseWire(lie)).toBeNull();
    const huge = wire.slice();
    huge.set([0xff, 0xff, 0xff, 0xff], 0); // 4 GiB header
    expect(parseWire(huge)).toBeNull();
  });
});

describe("the part around it", () => {
  const good = () => part(ok("TASK"));
  it("returns the raw text and the shape of a sealed part", () => {
    const p = good();
    expect(parseSealedPart(p)).toEqual({ raw: p.raw, shape: parseWire(ok("TASK")) });
  });

  it("allows exactly raw and mediaType", () => {
    expect(parseSealedPart({ ...good(), text: "x" })).toBeNull();
    expect(parseSealedPart({ ...good(), filename: "x" })).toBeNull();
    expect(parseSealedPart({ ...good(), metadata: {} })).toBeNull();
    expect(parseSealedPart({ ...good(), url: "x" })).toBeNull();
    expect(parseSealedPart({ ...good(), data: 1 })).toBeNull();
    expect(parseSealedPart({ raw: good().raw })).toBeNull();
    expect(parseSealedPart({ mediaType: SEALED_MEDIA_TYPE })).toBeNull();
    expect(parseSealedPart({ ...good(), mediaType: "text/plain" })).toBeNull();
    expect(parseSealedPart({ ...good(), mediaType: SEALED_MEDIA_TYPE + "x" })).toBeNull();
    for (const v of [null, undefined, "x", 5, [], [good()]]) expect(parseSealedPart(v)).toBeNull();
  });

  it("allows only canonical base64 of a valid message", () => {
    const raw = good().raw;
    for (const bad of ["", "not base64!", raw + "=", raw.slice(1), raw.slice(0, -1), raw.replace(/.$/, "*"), raw.replace(/^./, "-"), raw.replace(/^./, "_"), raw.replace(/^./, " ")]) {
      expect(parseSealedPart({ raw: bad, mediaType: SEALED_MEDIA_TYPE }), bad.slice(0, 8)).toBeNull();
    }
    expect(parseSealedPart({ raw: 5, mediaType: SEALED_MEDIA_TYPE })).toBeNull();
    // Valid base64 that is not an envelope.
    expect(parseSealedPart({ raw: "c2VhbGVk", mediaType: SEALED_MEDIA_TYPE })).toBeNull();
    expect(parseSealedPart({ raw: "YQ==", mediaType: SEALED_MEDIA_TYPE })).toBeNull();
    // One wire form has one text form: whitespace and stray padding bits decode, but are refused.
    for (const len of [3, 4, 5, 6]) {
      const p = part(ok("TASK", { context: "c".repeat(len) }));
      expect(parseSealedPart(p), String(len)).not.toBeNull();
      expect(parseSealedPart({ ...p, raw: p.raw.slice(0, 8) + "\n" + p.raw.slice(8) }), `newline ${len}`).toBeNull();
      expect(parseSealedPart({ ...p, raw: " " + p.raw.slice(1) }), `space ${len}`).toBeNull();
    }
    const padded = [3, 4, 5, 6].map((len) => part(ok("TASK", { context: "c".repeat(len) }))).filter((p) => p.raw.endsWith("="));
    expect(padded.length).toBeGreaterThan(0);
    for (const p of padded) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      const body = p.raw.replace(/=+$/, "");
      const last = alphabet.indexOf(body.at(-1)!);
      const twin = alphabet[last ^ 1]!; // same data bits, different unused bits
      expect(parseSealedPart({ ...p, raw: body.slice(0, -1) + twin + p.raw.slice(body.length) })).toBeNull();
    }
  });

  it("measures the text before decoding it", () => {
    const biggest = ok("TASK", {}, { bucket: MAX_BUCKET });
    expect(b64(biggest).length).toBeLessThanOrEqual(MAX_RAW_CHARS);
    expect(parseSealedPart(part(biggest))).not.toBeNull();
    // Longer than the largest legal message can be, even though every character is valid base64:
    // refused on length alone, so nothing that large is decoded.
    const huge = "A".repeat(MAX_RAW_CHARS + 4);
    expect(parseSealedPart({ raw: huge, mediaType: SEALED_MEDIA_TYPE })).toBeNull();
    const atCap = "A".repeat(MAX_RAW_CHARS);
    expect(atCap.length % 4).toBe(0);
    expect(parseSealedPart({ raw: atCap, mediaType: SEALED_MEDIA_TYPE })).toBeNull(); // within the cap: decoded, then not an envelope
    // The text length limit is the only thing between a hostile string and the decoder: one
    // character under it, over it and exactly on it must differ in the work done, not the answer.
    const decoded: string[] = [];
    const real = globalThis.atob;
    globalThis.atob = ((s: string) => (decoded.push(s), real(s))) as typeof atob;
    try {
      parseSealedPart({ raw: atCap, mediaType: SEALED_MEDIA_TYPE });
      parseSealedPart({ raw: "A".repeat(MAX_RAW_CHARS + 4), mediaType: SEALED_MEDIA_TYPE });
    } finally {
      globalThis.atob = real;
    }
    expect(decoded.map((d) => d.length)).toEqual([MAX_RAW_CHARS]);
  });
});

it("the signed type numbers are the daemon's (internal/envelope Type)", () => {
  expect(SIGNED_TYPE).toEqual({ TASK: 1, STATUS: 2, INPUT_REQUIRED: 3, RESULT: 4, ERROR: 5, CANCEL: 6, REPLY: 7 });
});
