// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  MAX_CARD_GROUPS,
  MAX_EXAMPLES,
  MAX_MEMBERS,
  MAX_MEMBER_CHARS,
  MAX_TAGS,
  PAGE_DEFAULT,
  PAGE_MAX,
  canSee,
  cardKey,
  isCardId,
  isDeviceId,
  paginate,
  validatePage,
  lintSecrets,
  matches,
  memberships,
  validateCard,
  validateGroup,
  validateQuery,
  type Card,
} from "../src/acl";

const base = { name: "Reviewer", description: "Reviews diffs", tags: ["review"], examples: ["review this"], visibility: "tenant", groups: [] };
const ok = (over: object = {}) => validateCard({ ...base, ...over });
const card = (over: Partial<Card> = {}): Card => ({ ...base, visibility: "tenant", ...over });

describe("validateCard", () => {
  it("accepts a card and normalizes tags and groups to lowercase, without duplicates", () => {
    expect(ok({ tags: ["Review", "review", " Go "], visibility: "groups", groups: ["Eng", "eng"] })).toEqual({
      card: { ...base, tags: ["review", "go"], visibility: "groups", groups: ["eng"] },
    });
  });

  it("defaults to tenant visibility and optional lists", () => {
    expect(validateCard({ name: "a", description: "b" })).toEqual({ card: { name: "a", description: "b", tags: [], examples: [], visibility: "tenant", groups: [] } });
  });

  it("rejects non-objects and missing or malformed text", () => {
    for (const v of [null, undefined, "x", 3, [], { description: "d" }, { name: "n" }, { name: 1, description: "d" }, { name: "n", description: 1 }]) {
      expect(validateCard(v)).toEqual({ error: "bad_card" });
    }
  });

  it("enforces text limits and clean text", () => {
    expect(ok({ name: "n".repeat(65) })).toEqual({ error: "bad_card" });
    expect(ok({ name: "x ".repeat(31) + "xx" })).toHaveProperty("card");
    expect(ok({ description: "d".repeat(501) })).toEqual({ error: "bad_card" });
    expect(ok({ description: "x ".repeat(249) + "xx" })).toHaveProperty("card");
    expect(ok({ name: "a‮b" })).toEqual({ error: "bad_card" });
    expect(ok({ description: "a\nb" })).toEqual({ error: "bad_card" });
    expect(ok({ examples: ["e".repeat(201)] })).toEqual({ error: "bad_card" });
    expect(ok({ tags: ["t".repeat(33)] })).toEqual({ error: "bad_card" });
  });

  it("keeps the case of examples", () => {
    expect(ok({ examples: ["Review THIS"] })).toMatchObject({ card: { examples: ["Review THIS"] } });
  });

  it("enforces list shapes and counts", () => {
    expect(ok({ tags: "x" })).toEqual({ error: "bad_card" });
    expect(ok({ tags: [1] })).toEqual({ error: "bad_card" });
    expect(ok({ tags: Array.from({ length: MAX_TAGS + 1 }, (_, i) => `t${i}`) })).toEqual({ error: "bad_card" });
    expect(ok({ tags: Array.from({ length: MAX_TAGS }, (_, i) => `t${i}`) })).toHaveProperty("card");
    expect(ok({ examples: Array.from({ length: MAX_EXAMPLES + 1 }, (_, i) => `e${i}`) })).toEqual({ error: "bad_card" });
    expect(ok({ examples: Array.from({ length: MAX_EXAMPLES }, (_, i) => `e${i}`) })).toHaveProperty("card");
    const gs = (n: number) => Array.from({ length: n }, (_, i) => `g${i}`);
    expect(ok({ visibility: "groups", groups: gs(MAX_CARD_GROUPS + 1) })).toEqual({ error: "bad_card" });
    expect(ok({ visibility: "groups", groups: gs(MAX_CARD_GROUPS) })).toHaveProperty("card");
  });

  it("validates visibility and ties groups to it", () => {
    expect(ok({ visibility: "public" })).toEqual({ error: "bad_card" });
    expect(ok({ visibility: 3 })).toEqual({ error: "bad_card" });
    expect(ok({ visibility: "groups" })).toEqual({ error: "bad_card" }); // no group named
    expect(ok({ visibility: "tenant", groups: ["eng"] })).toEqual({ error: "bad_card" });
    expect(ok({ visibility: "private", groups: ["eng"] })).toEqual({ error: "bad_card" });
    expect(ok({ visibility: "private" })).toHaveProperty("card");
  });

  it("rejects a card with a secret, naming the field", () => {
    expect(ok({ description: "use key AKIAABCDEFGHIJKLMNOP" })).toEqual({ error: "secret_detected", field: "description" });
    expect(ok({ examples: ["password: hunter2hunter2"] })).toEqual({ error: "secret_detected", field: "examples" });
  });
});

describe("lintSecrets", () => {
  const secrets: Record<string, string> = {
    pem: "-----BEGIN RSA PRIVATE KEY-----",
    aws: "AKIAABCDEFGHIJKLMNOP",
    github: "ghp_" + "a".repeat(30),
    githubPat: "github_pat_" + "A1_".repeat(10),
    openai: "sk-" + "a1".repeat(12),
    slack: "xoxb-1234567890-abcdef",
    pod: "pet_" + "0123456789abcdef".repeat(3),
    ghMin: "ghs_" + "a".repeat(20),
    skMin: "sk-" + "a".repeat(20),
    xoxMin: "xoxp-1234567890",
    jwtMin: "eyJabcdefgh.abcdefgh.abcdefgh",
    apikey: "apikey: abcdefgh1",
    tight: "secret=abcdefgh",
    blobMin: "a".repeat(40),
    jwt: "eyJhbGciOiJI.eyJzdWIiOiIx.c2lnbmF0dXJl",
    assign: "api_key = abcdefgh1",
    colon: "Token: abcdefghij",
    blob: "Zm9vYmFyYmF6cXV4" + "Zm9vYmFyYmF6cXV4" + "Zm9vYmFy",
  };
  for (const [kind, text] of Object.entries(secrets)) {
    it(`flags ${kind} in every field`, () => {
      expect(lintSecrets(card({ name: text }))).toBe("name");
      expect(lintSecrets(card({ description: text }))).toBe("description");
      expect(lintSecrets(card({ tags: ["ok", text] }))).toBe("tags");
      expect(lintSecrets(card({ examples: [text] }))).toBe("examples");
      expect(lintSecrets(card({ visibility: "groups", groups: [text] }))).toBe("groups");
    });
  }

  it("passes ordinary text, including short values after the word token", () => {
    const text = "Reviews pull requests for Go services. Token: short. See https://example.test/docs/reviewing-pull-requests-in-go.";
    expect(lintSecrets(card({ description: text }))).toBeNull();
    expect(lintSecrets(card())).toBeNull();
  });

  it("does not flag values just under each threshold", () => {
    for (const t of ["ghp_" + "a".repeat(19), "sk-" + "a".repeat(19), "xoxb-123456789", "eyJabcdefgh.abcdefgh.abcdefg", "secret: abcdefg", "a".repeat(39) + " b"]) {
      expect(lintSecrets(card({ description: t })), t).toBeNull();
    }
  });

  it("flags a 40-character run that is followed by other text", () => {
    expect(lintSecrets(card({ description: "a".repeat(40) + " rest" }))).toBe("description");
  });

  it("does not join separate list entries into one secret", () => {
    const half = "a1b2c3d4e5f6g7h8i9j0";
    expect(lintSecrets(card({ examples: [half, half] }))).toBeNull();
    expect(lintSecrets(card({ visibility: "groups", groups: [half, half] }))).toBeNull();
  });

  it("reports the first matching field in order", () => {
    expect(lintSecrets(card({ name: secrets.aws!, description: secrets.aws! }))).toBe("name");
  });
});

describe("validateGroup", () => {
  it("normalizes the name and members", () => {
    expect(validateGroup(" Eng ", ["Alice@Example.test", "alice@example.test", "bob@example.test"])).toEqual({ name: "eng", members: ["alice@example.test", "bob@example.test"] });
    expect(validateGroup("g", undefined)).toEqual({ name: "g", members: [] });
  });

  it("rejects bad names and member lists", () => {
    for (const n of [undefined, 5, "", "  ", "a\nb", "x".repeat(65)]) expect(validateGroup(n, [])).toEqual({ error: "bad_group" });
    expect(validateGroup("x".repeat(64), [])).toHaveProperty("name");
    for (const m of ["a", [1], ["a\u202E"], [""], ["x".repeat(255)]]) expect(validateGroup("g", m)).toEqual({ error: "bad_members" });
    expect(validateGroup("g", Array.from({ length: MAX_MEMBERS + 1 }, (_, i) => `u${i}`))).toEqual({ error: "bad_members" });
    expect(validateGroup("g", Array.from({ length: MAX_MEMBERS }, (_, i) => `u${i}`))).toHaveProperty("members");
  });

  it("bounds the total size of the member list", () => {
    expect(MAX_MEMBER_CHARS).toBe(60_000);
    expect(validateGroup("g", Array.from({ length: 300 }, (_, i) => `${i}`.padStart(200, "u")))).toHaveProperty("members"); // exactly 60,000
    expect(validateGroup("g", [...Array.from({ length: 300 }, (_, i) => `${i}`.padStart(200, "u")).slice(0, 299), "y".repeat(201)])).toEqual({ error: "bad_members" });
  });
});

describe("memberships", () => {
  it("returns the groups that list the viewer", () => {
    const groups: [string, string[]][] = [["eng", ["a", "b"]], ["ops", ["b"]], ["empty", []]];
    expect([...memberships(groups, "a")]).toEqual(["eng"]);
    expect([...memberships(groups, "b")].sort()).toEqual(["eng", "ops"]);
    expect(memberships(groups, "z").size).toBe(0);
  });
  it("matches identities case-insensitively, and never matches an empty viewer", () => {
    expect([...memberships([["eng", ["a@x.test"]]], "A@X.test")]).toEqual(["eng"]);
    expect(memberships([["eng", [""]]], "").size).toBe(0);
  });
});

describe("canSee", () => {
  const eng = new Set(["eng"]);
  const none = new Set<string>();
  it("lets the owner see every mode", () => {
    for (const visibility of ["tenant", "groups", "private"] as const) expect(canSee({ visibility, groups: ["x"] }, "o", "o", none)).toBe(true);
  });
  it("tenant: everyone", () => expect(canSee({ visibility: "tenant", groups: [] }, "o", "v", none)).toBe(true));
  it("groups: only members of a listed group", () => {
    expect(canSee({ visibility: "groups", groups: ["ops", "eng"] }, "o", "v", eng)).toBe(true);
    expect(canSee({ visibility: "groups", groups: ["ops"] }, "o", "v", eng)).toBe(false);
    expect(canSee({ visibility: "groups", groups: ["eng"] }, "o", "v", none)).toBe(false);
    expect(canSee({ visibility: "groups", groups: [] }, "o", "v", eng)).toBe(false);
  });
  it("private: only the owner", () => expect(canSee({ visibility: "private", groups: ["eng"] }, "o", "v", eng)).toBe(false));
});

// Table-driven matrix: caller x group membership x rule (mode + listed groups) x target
// (owner). Groups as they exist now: eng has bob, ops has carol, empty has nobody;
// "gone" (deleted or renamed away) and "typo" do not exist at all. There are no
// deny rules, so there is no allow/deny precedence to test: default deny, owner first.
describe("canSee matrix (default deny)", () => {
  const groups: [string, string[]][] = [["eng", ["bob@x.test"]], ["ops", ["carol@x.test"]], ["empty", []]];
  const owner = "alice@x.test";
  type Row = [string, "tenant" | "groups" | "private", string[], string, boolean];
  const rows: Row[] = [
    // tenant: everyone with an identity
    ["tenant, stranger", "tenant", [], "zed@x.test", true],
    ["tenant, owner", "tenant", [], owner, true],
    ["tenant, no identity", "tenant", [], "", false],
    // private: owner only
    ["private, owner", "private", [], owner, true],
    ["private, owner in other case", "private", [], "ALICE@x.test", true],
    ["private, member of some group", "private", [], "bob@x.test", false],
    ["private, stranger", "private", [], "zed@x.test", false],
    ["private, no identity", "private", [], "", false],
    // groups: viewer must be in a listed group that exists
    ["groups, member of listed", "groups", ["eng"], "bob@x.test", true],
    ["groups, member in other case", "groups", ["eng"], "BOB@x.test", true],
    ["groups, member of one of several", "groups", ["gone", "eng"], "bob@x.test", true],
    ["groups, member of a different group", "groups", ["eng"], "carol@x.test", false],
    ["groups, stranger", "groups", ["eng"], "zed@x.test", false],
    ["groups, owner not in the group", "groups", ["eng"], owner, true],
    ["groups, empty group", "groups", ["empty"], "bob@x.test", false],
    ["groups, deleted or renamed group", "groups", ["gone"], "bob@x.test", false],
    ["groups, unknown group", "groups", ["typo"], "bob@x.test", false],
    ["groups, only missing groups", "groups", ["gone", "typo"], "carol@x.test", false],
    ["groups, no groups listed (malformed)", "groups", [], "bob@x.test", false],
    ["groups, no identity", "groups", ["empty"], "", false],
    // a malformed mode is refused, never read as visible
    ["unknown mode", "public" as never, ["eng"], "bob@x.test", false],
    ["missing mode", undefined as never, [], "bob@x.test", false],
  ];
  for (const [name, visibility, listed, viewer, want] of rows) {
    it(`${name}: ${want ? "visible" : "hidden"}`, () => {
      expect(canSee({ visibility, groups: listed }, owner, viewer, memberships(groups, viewer))).toBe(want);
    });
  }
  it("an empty owner and an empty viewer are not the same person", () => {
    expect(canSee({ visibility: "private", groups: [] }, "", "", new Set())).toBe(false);
  });
});

describe("ids", () => {
  it("accept exactly the shapes the gateway generates", () => {
    const dev = "0123456789abcdef".repeat(2);
    expect(isDeviceId(dev)).toBe(true);
    expect(isCardId(`${dev}:0123456789abcdef`)).toBe(true);
    for (const v of [undefined, 5, [dev], "", dev.slice(1), dev + "0", dev.toUpperCase(), `${dev}\n`, "../" + dev, `${dev}:`]) expect(isDeviceId(v), String(v)).toBe(false);
    for (const v of [undefined, [`${dev}:0123456789abcdef`], dev, `${dev}:0123456789abcde`, `${dev}:0123456789abcdef0`, `${dev}:0123456789ABCDEF`, `x${dev}:0123456789abcdef`, `${dev}:0123456789abcdef\n`]) expect(isCardId(v), String(v)).toBe(false);
  });
});

describe("pagination", () => {
  const items = Array.from({ length: 7 }, (_, i) => `k${i}`);
  const key = (s: string) => s;
  it("defaults to 25 and caps at 100", () => {
    expect(validatePage({})).toEqual({ limit: PAGE_DEFAULT, after: null });
    expect(PAGE_DEFAULT).toBe(25);
    expect(validatePage({ limit: PAGE_MAX })).toEqual({ limit: 100, after: null });
    expect(validatePage({ limit: 1 })).toEqual({ limit: 1, after: null });
    for (const limit of [0, -1, 101, 1.5, "5", null, NaN]) expect(validatePage({ limit }), String(limit)).toBeNull();
  });
  it("walks a list page by page with stable cursors and no overlap", () => {
    const seen: string[] = [];
    let after: string | null = null;
    let pages = 0;
    for (;;) {
      const r: { items: string[]; next_cursor?: string } = paginate(items, key, { limit: 3, after });
      seen.push(...r.items);
      pages++;
      if (!r.next_cursor) break;
      after = validatePage({ cursor: r.next_cursor })!.after;
    }
    expect(seen).toEqual(items);
    expect(pages).toBe(3);
    expect(paginate(items, key, { limit: 7, after: null })).toEqual({ items }); // exactly full: no cursor
    expect(paginate(items, key, { limit: 6, after: null }).next_cursor).toBeDefined();
    expect(paginate([], key, { limit: 3, after: null })).toEqual({ items: [] });
  });
  it("a cursor survives inserts and deletes around it", () => {
    const first = paginate(items, key, { limit: 3, after: null });
    const after = validatePage({ cursor: first.next_cursor })!.after;
    const changed = ["k0", "k2", "k15", "k3", "k4", "k5", "k6"].sort(); // k1 deleted, k15 inserted before the cursor key
    expect(paginate(changed, key, { limit: 3, after }).items).toEqual(["k3", "k4", "k5"]);
  });
  it("cursors are hex of the sort key and are checked strictly", () => {
    expect(validatePage({ cursor: "6b31" })).toEqual({ limit: 25, after: "k1" });
    expect(validatePage({ cursor: "e282ac" })).toEqual({ limit: 25, after: "€" });
    expect(validatePage({ cursor: "efbbbf6b31" })).toEqual({ limit: 25, after: "k1" }); // a leading BOM is dropped, never part of a key
    const nl = paginate(["a\nb", "a\nc"], key, { limit: 1, after: null }); // bytes below 0x10 keep their leading zero
    expect(nl.next_cursor).toBe("610a62");
    expect(validatePage({ cursor: nl.next_cursor })!.after).toBe("a\nb");
    for (const cursor of ["", "6B31", "6b3", "zz", 5, null, ["6b31"], { match: 1 }, "ff", "c0af", "6b31".repeat(401)]) expect(validatePage({ cursor }), String(cursor)).toBeNull();
    expect(validatePage({ cursor: "61".repeat(800) })).not.toBeNull();
  });
  it("cardKey orders by lowercase name then id, with a separator no name can hold", () => {
    expect(cardKey({ name: "Ab", id: "x" })).toBe("ab\nx");
  });
});

describe("matches and validateQuery", () => {
  const c = { name: "Code Reviewer", description: "Checks Go diffs", tags: ["review", "go"] };
  it("an empty or blank query matches everything", () => {
    expect(matches(c, {})).toBe(true);
    expect(matches(c, { text: "  ", tag: " " })).toBe(true);
  });
  it("text matches name or description, case-insensitively", () => {
    expect(matches(c, { text: "CODE rev" })).toBe(true);
    expect(matches(c, { text: "go diffs" })).toBe(true);
    expect(matches(c, { text: "reviewer checks" })).toBe(false); // name and description are not joined into one phrase
    expect(matches(c, { text: "python" })).toBe(false);
  });
  it("a tag must match exactly", () => {
    expect(matches(c, { tag: "GO" })).toBe(true);
    expect(matches(c, { tag: "rev" })).toBe(false);
  });
  it("text and tag both apply", () => {
    expect(matches(c, { text: "reviewer", tag: "go" })).toBe(true);
    expect(matches(c, { text: "reviewer", tag: "py" })).toBe(false);
    expect(matches(c, { text: "python", tag: "go" })).toBe(false);
  });
  it("validates the query shape", () => {
    expect(validateQuery(undefined)).toEqual({});
    expect(validateQuery({ text: "a", tag: "b" })).toEqual({ text: "a", tag: "b" });
    expect(validateQuery({})).toEqual({ text: undefined, tag: undefined });
    for (const q of [null, "x", [], { text: 1 }, { tag: 1 }, { text: "x".repeat(201) }, { tag: "x".repeat(65) }]) expect(validateQuery(q)).toBeNull();
    expect(validateQuery({ text: "x".repeat(200), tag: "x".repeat(64) })).not.toBeNull();
  });
});
