// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { byteLength, MAX_RELAY_BYTES, parseClientMessage, parseRelayFrame, PROTOCOL_VERSION } from "../src/protocol";

const parse = (m: unknown) => parseClientMessage(typeof m === "string" ? m : JSON.stringify(m));

describe("parseClientMessage", () => {
  it("accepts well-formed hello, frame and ack messages", () => {
    expect(parse({ t: "hello", v: PROTOCOL_VERSION, last_rx: 0 })).toEqual({ t: "hello", v: PROTOCOL_VERSION, session: undefined, last_rx: 0 });
    expect(parse({ t: "hello", v: PROTOCOL_VERSION, session: "s".repeat(64), last_rx: 7 })).toMatchObject({ session: "s".repeat(64), last_rx: 7 });
    expect(parse({ t: "frame", seq: 1, body: "" })).toEqual({ t: "frame", seq: 1, body: "" });
    expect(parse({ t: "ack", seq: 0 })).toEqual({ t: "ack", seq: 0 });
  });

  it("rejects anything else", () => {
    for (const bad of [
      "not json",
      "null",
      "42",
      '"hello"',
      {},
      { t: "other" },
      { t: "hello", v: PROTOCOL_VERSION + 1, last_rx: 0 },
      { t: "hello", v: PROTOCOL_VERSION },
      { t: "hello", v: PROTOCOL_VERSION, last_rx: -1 },
      { t: "hello", v: PROTOCOL_VERSION, last_rx: 1.5 },
      { t: "hello", v: PROTOCOL_VERSION, last_rx: 0, session: 5 },
      { t: "hello", v: PROTOCOL_VERSION, last_rx: 0, session: "s".repeat(65) },
      { t: "frame", seq: 0, body: "x" },
      { t: "frame", seq: 1 },
      { t: "frame", seq: 1, body: 5 },
      { t: "ack", seq: -1 },
      { t: "ack" },
    ]) {
      expect(parse(bad), JSON.stringify(bad)).toBeNull();
    }
  });
});

describe("byteLength", () => {
  it("counts UTF-8 bytes, not UTF-16 units", () => {
    expect(byteLength("abc")).toBe(3);
    expect(byteLength("é")).toBe(2);
    expect(byteLength("€")).toBe(3);
    expect(byteLength("😀")).toBe(4);
  });
});

describe("parseRelayFrame", () => {
  const nonce = btoa("0123456789abcdef");
  const req = { t: "prekey_request", id: "r-1_A", to: "dev1", nonce, expires_at: 1_800_000_900_000 };
  const parseR = (m: unknown) => parseRelayFrame(typeof m === "string" ? m : JSON.stringify(m));

  // The same strings internal/frames (Go) builds, checked there too.
  it("accepts exactly the frames a daemon builds", () => {
    expect(parseR('{"t":"prekey_request","id":"req1","to":"dev-b","nonce":"AQID","expires_at":1800000900000}')).toEqual({ t: "prekey_request", id: "req1", to: "dev-b", nonce: "AQID", expires_at: 1800000900000 });
    expect(parseR('{"t":"prekey_reply","id":"req1","to":"dev-a","prekey":"CQg="}')).toEqual({ t: "prekey_reply", id: "req1", to: "dev-a", prekey: "CQg=" });
    expect(parseR('{"t":"prekey_refused","id":"req1","to":"dev-a"}')).toEqual({ t: "prekey_refused", id: "req1", to: "dev-a" });
  });

  it("allows a nonce of 32 bytes and a prekey of 1024, and not one byte more", () => {
    const big = (n: number) => btoa("a".repeat(n));
    expect(parseR({ ...req, nonce: big(32) })).not.toBeNull();
    expect(parseR({ ...req, nonce: big(33) })).toBeNull();
    expect(parseR({ t: "prekey_reply", id: "r", to: "d", prekey: big(1024) })).not.toBeNull();
    expect(parseR({ t: "prekey_reply", id: "r", to: "d", prekey: big(1025) })).toBeNull();
  });

  it("refuses everything else", () => {
    const bad: unknown[] = [
      "", "nope", "null", "[]", "7", '"x"', "{}",
      { ...req, t: "prekey_other" },
      { ...req, extra: 1 },
      { ...req, id: "" },
      { ...req, id: "a b" },
      { ...req, id: "x".repeat(65) },
      { ...req, to: "" },
      { ...req, to: 5 },
      { ...req, nonce: null },
      { ...req, expires_at: undefined, other: 1 }, // as many keys, one of them not the right one
      { t: "prekey_reply", id: "r", to: "d", prekey: null },
      { t: "prekey_reply", id: "r", to: "d", other: "CQg=" },
      { t: "prekey_refused", id: "r", other: "d" },
      [req],
      { ...req, to: "a/b" },
      { ...req, id: 5 },
      { ...req, nonce: "" },
      { ...req, nonce: "!!" },
      { ...req, nonce: "AQI" }, // not what btoa writes
      { ...req, nonce: btoa("x".repeat(33)) },
      { ...req, nonce: 5 },
      { ...req, expires_at: 0 },
      { ...req, expires_at: -1 },
      { ...req, expires_at: 1.5 },
      { ...req, expires_at: "1" },
      { t: "prekey_request", id: "r", to: "d", nonce },
      { t: "prekey_reply", id: "r", to: "d" },
      { t: "prekey_reply", id: "r", to: "d", prekey: "" },
      { t: "prekey_reply", id: "r", to: "d", prekey: btoa("x".repeat(1025)) },
      { t: "prekey_reply", id: "r", to: "d", prekey: "CQg=", nonce },
      { t: "prekey_refused", id: "r", to: "d", reason: "x" },
      { t: "prekey_refused", id: "r" },
    ];
    for (const b of bad) expect(parseR(b), JSON.stringify(b)).toBeNull();
    expect(parseRelayFrame("x".repeat(MAX_RELAY_BYTES + 1))).toBeNull();
    // The body limit is on the whole text, whitespace included, and the limit itself is allowed.
    const text = JSON.stringify(req);
    expect(parseRelayFrame(text + " ".repeat(MAX_RELAY_BYTES - text.length + 1))).toBeNull();
    expect(parseRelayFrame(text + " ".repeat(MAX_RELAY_BYTES - text.length))).toMatchObject({ id: "r-1_A" });
    expect(parseRelayFrame(JSON.stringify({ ...req, id: "x".repeat(MAX_RELAY_BYTES) }))).toBeNull();
  });
});
