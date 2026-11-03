// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  MAX_CARD_GROUPS,
  MAX_EXAMPLES,
  MAX_MEMBERS,
  MAX_TAGS,
  canSee,
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
});

describe("memberships", () => {
  it("returns the groups that list the viewer", () => {
    const groups: [string, string[]][] = [["eng", ["a", "b"]], ["ops", ["b"]], ["empty", []]];
    expect([...memberships(groups, "a")]).toEqual(["eng"]);
    expect([...memberships(groups, "b")].sort()).toEqual(["eng", "ops"]);
    expect(memberships(groups, "z").size).toBe(0);
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
