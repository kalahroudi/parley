// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { byteLength, parseClientMessage, PROTOCOL_VERSION } from "../src/protocol";

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
