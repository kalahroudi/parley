// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { MAX_CARDS_PER_DEVICE, MAX_CARDS_PER_TENANT, MAX_GROUPS, MAX_MEMBER_CHARS } from "../src/acl";
import { MAX_AUDIT } from "../src/tenant";

const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const post = (path: string, body: unknown, auth?: string) =>
  SELF.fetch(`https://gw${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(auth ? { Authorization: auth } : {}) },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
const json = async (r: Response) => (await r.json()) as any;

let n = 0;
// A tenant with an admin and a way to bring a user's device to "approved and bound".
function tenant() {
  const t = `dir${++n}`;
  const admin = `Bearer dev-admin:${t}`;
  const stub = env.TENANT.get(env.TENANT.idFromName(t));
  const enroll = async (email: string, bind = true) => {
    const sk = key();
    const { id } = await json(await post("/v1/enroll/request", { name: "laptop", signing_key: sk }, `Bearer dev-user:${t}:${email}`));
    await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, admin);
    if (bind) await post("/v1/admin/bindings", { id, binding: { device_id: id, signing_key: sk, version: 1 } }, admin);
    return { id, auth: `Bearer dev:${t}:${id}` };
  };
  return { t, admin, stub, enroll };
}
const card = (over: object = {}) => ({ name: "Reviewer", description: "Reviews diffs", tags: ["review"], examples: ["review this"], ...over });
const publish = async (d: { auth: string }, c: object) => json(await post("/v1/cards/publish", { card: c }, d.auth));
// A direct call on the Tenant DO (for methods with no HTTP route).
const call = (x: ReturnType<typeof tenant>, method: string, ...args: unknown[]): Promise<any> => runInDurableObject(x.stub, async (i) => (i as any)[method](...args));
const find = async (d: { auth: string }, query?: object) => ((await json(await post("/v1/directory/find", { query }, d.auth))).agents as any[]).map((a) => a.name);

describe("publishing cards", () => {
  it("publishes with the owner taken from the enrollment, and lists it", async () => {
    const x = tenant();
    const alice = await x.enroll("Alice@Example.test");
    const r = await post("/v1/cards/publish", { card: card(), owner: "mallory@example.test", device_id: "other" }, alice.auth);
    expect(r.status).toBe(200);
    const { id } = await json(r);
    expect(id).toMatch(new RegExp(`^${alice.id}:[0-9a-f]{16}$`));
    const found = (await json(await post("/v1/directory/find", {}, alice.auth))).agents;
    expect(found).toEqual([expect.objectContaining({ id, name: "Reviewer", device_id: alice.id, owner: "alice@example.test", visibility: "tenant", tags: ["review"] })]);
  });

  it("republishing the same name (any case) replaces the card; another name adds one", async () => {
    const x = tenant();
    const a = await enrollAndPublish(x);
    expect((await publish(a.d, card({ name: "REVIEWER", description: "v2" }))).id).toBe(a.id);
    await publish(a.d, card({ name: "Other" }));
    const all = (await json(await post("/v1/directory/find", {}, a.d.auth))).agents;
    expect(all.map((c: any) => [c.name, c.description])).toEqual([["Other", "Reviews diffs"], ["REVIEWER", "v2"]]);
  });

  it("refuses devices that are not enrolled: unknown, pending, rejected, unbound", async () => {
    const x = tenant();
    const unbound = await x.enroll("a@example.test", false);
    const { id: pending } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, `Bearer dev-user:${x.t}:b@example.test`));
    const { id: rejected } = await json(await post("/v1/enroll/request", { name: "d", signing_key: key() }, `Bearer dev-user:${x.t}:c@example.test`));
    await post("/v1/admin/enrollments/decide", { id: rejected, decision: "rejected" }, x.admin);
    for (const auth of [unbound.auth, `Bearer dev:${x.t}:${pending}`, `Bearer dev:${x.t}:${rejected}`, `Bearer dev:${x.t}:${"0".repeat(32)}`]) {
      expect((await post("/v1/cards/publish", { card: card() }, auth)).status).toBe(403);
      expect((await post("/v1/directory/find", {}, auth)).status).toBe(403);
    }
  });

  it("rejects bad cards and secrets with the field", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    expect((await post("/v1/cards/publish", { card: { name: "x" } }, d.auth)).status).toBe(400);
    expect((await post("/v1/cards/publish", {}, d.auth)).status).toBe(400);
    const r = await post("/v1/cards/publish", { card: card({ examples: ["use AKIAABCDEFGHIJKLMNOP"] }) }, d.auth);
    expect(r.status).toBe(422);
    expect(await json(r)).toEqual({ error: "secret_detected", field: "examples" });
    expect(await find(d)).toEqual([]);
  });

  it("caps cards per device but still allows replacing one", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    for (let i = 0; i < MAX_CARDS_PER_DEVICE; i++) expect((await publish(d, card({ name: `bot${i}` }))).id).toBeDefined();
    expect((await post("/v1/cards/publish", { card: card({ name: "one-too-many" }) }, d.auth)).status).toBe(429);
    expect((await publish(d, card({ name: "BOT0", description: "new" }))).id).toBeDefined();
    const other = await x.enroll("b@example.test");
    expect((await publish(other, card({ name: "fine" }))).id).toBeDefined(); // the cap is per device
  });

  it("removes only the publishing device's own card", async () => {
    const x = tenant();
    const a = await enrollAndPublish(x);
    const b = await x.enroll("b@example.test");
    expect((await post("/v1/cards/remove", { id: a.id }, b.auth)).status).toBe(404);
    expect(await find(b)).toEqual(["Reviewer"]);
    expect((await post("/v1/cards/remove", { id: a.id }, a.d.auth)).status).toBe(200);
    expect((await post("/v1/cards/remove", { id: a.id }, a.d.auth)).status).toBe(404);
    expect((await post("/v1/cards/remove", {}, a.d.auth)).status).toBe(404);
    expect(await find(b)).toEqual([]);
  });
});

async function enrollAndPublish(x: ReturnType<typeof tenant>, email = "alice@example.test", c: object = card()) {
  const d = await x.enroll(email);
  return { d, id: (await publish(d, c)).id as string };
}

describe("visibility and groups", () => {
  it("tenant cards are visible to everyone in the tenant; private only to the owner", async () => {
    const x = tenant();
    const alice = await x.enroll("alice@example.test");
    const alice2 = await x.enroll("ALICE@example.test"); // a second device of the same owner
    const bob = await x.enroll("bob@example.test");
    await publish(alice, card({ name: "Open" }));
    await publish(alice, card({ name: "Secretive", visibility: "private" }));
    expect(await find(alice)).toEqual(["Open", "Secretive"]);
    expect(await find(alice2)).toEqual(["Open", "Secretive"]);
    expect(await find(bob)).toEqual(["Open"]);
  });

  it("group cards are visible to the owner and members of a listed group, and follow membership changes", async () => {
    const x = tenant();
    const alice = await x.enroll("alice@example.test");
    const bob = await x.enroll("bob@example.test");
    const carol = await x.enroll("carol@example.test");
    await publish(alice, card({ name: "Eng only", visibility: "groups", groups: ["Eng"] }));
    expect(await find(bob)).toEqual([]);
    expect(await find(alice)).toEqual(["Eng only"]);

    expect((await post("/v1/admin/groups/put", { name: "ENG", members: ["Bob@example.test"] }, x.admin)).status).toBe(200);
    expect(await find(bob)).toEqual(["Eng only"]);
    expect(await find(carol)).toEqual([]);

    await post("/v1/admin/groups/put", { name: "eng", members: ["carol@example.test"] }, x.admin); // replaces the member list
    expect(await find(bob)).toEqual([]);
    expect(await find(carol)).toEqual(["Eng only"]);

    await post("/v1/admin/groups/delete", { name: "Eng" }, x.admin);
    expect(await find(carol)).toEqual([]);
  });

  it("a hidden card cannot be resolved for a call, and looks like one that does not exist", async () => {
    const x = tenant();
    const alice = await x.enroll("alice@example.test");
    const bob = await x.enroll("bob@example.test");
    const priv = await publish(alice, card({ name: "Priv", visibility: "private" }));
    const open = await publish(alice, card({ name: "Open" }));
    const bobFor = (id: string) => x.stub.resolve(bob.id, id);
    expect(await bobFor(priv.id)).toBeNull();
    expect(await bobFor(`${alice.id}:0000000000000000`)).toBeNull();
    expect(await bobFor(open.id)).toMatchObject({ name: "Open", owner: "alice@example.test", device_id: alice.id });
    expect(await x.stub.resolve(alice.id, priv.id)).toMatchObject({ name: "Priv" });
    const unbound = await x.enroll("c@example.test", false);
    expect(await x.stub.resolve(unbound.id, open.id)).toBeNull();
  });

  it("pods are identified by their named service owner", async () => {
    const x = tenant();
    const { token } = await json(await post("/v1/admin/enrollment-tokens", { owner: "svc-ci" }, x.admin));
    const sk = key();
    const { id } = await json(await post("/v1/enroll/request", { tenant: x.t, token, name: "ci-1", signing_key: sk }));
    await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, x.admin);
    await post("/v1/admin/bindings", { id, binding: { device_id: id, signing_key: sk, version: 1 } }, x.admin);
    const pod = { auth: `Bearer dev:${x.t}:${id}` };
    const alice = await x.enroll("alice@example.test");
    await publish(alice, card({ name: "For CI", visibility: "groups", groups: ["ci"] }));
    expect(await find(pod)).toEqual([]);
    await post("/v1/admin/groups/put", { name: "ci", members: ["svc-ci"] }, x.admin);
    expect(await find(pod)).toEqual(["For CI"]);
  });

  it("tenants are isolated", async () => {
    const a = tenant();
    const b = tenant();
    const alice = await a.enroll("alice@example.test");
    const bob = await b.enroll("alice@example.test");
    await publish(alice, card());
    expect(await find(bob)).toEqual([]);
    await post("/v1/admin/groups/put", { name: "eng", members: ["x@example.test"] }, a.admin);
    expect((await json(await post("/v1/admin/groups", {}, b.admin))).groups).toEqual([]);
    expect((await post("/v1/admin/groups/delete", { name: "eng" }, b.admin)).status).toBe(404);
  });
});

describe("purged enrollments", () => {
  it("a card whose device enrollment is gone is no longer listed or resolvable, and the alarm purges it", async () => {
    const x = tenant();
    const a = await x.enroll("a@example.test");
    const b = await x.enroll("b@example.test");
    const { id } = await publish(a, card());
    expect(await find(b)).toEqual(["Reviewer"]);
    await runInDurableObject(x.stub, async (_i, s) => {
      await s.storage.delete(`enr:${a.id}`);
    });
    expect(await find(b)).toEqual([]);
    expect(await runInDurableObject(x.stub, (i) => (i as any).resolve(b.id, id))).toBeNull();
    await runInDurableObject(x.stub, async (i, s) => {
      await (i as any).alarm();
      expect([...(await s.storage.list({ prefix: "card:" })).keys()]).toEqual([]);
    });
  });
});

describe("find", () => {
  it("filters by name, description and tag, sorted by name", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    await publish(d, card({ name: "Zed", description: "Translates", tags: ["i18n"] }));
    await publish(d, card({ name: "Alpha", description: "Reviews Go diffs", tags: ["review", "go"] }));
    await publish(d, card({ name: "Mid", description: "Summarizes", tags: ["go"] }));
    expect(await find(d)).toEqual(["Alpha", "Mid", "Zed"]);
    expect(await find(d, { text: "go diffs" })).toEqual(["Alpha"]);
    expect(await find(d, { tag: "GO" })).toEqual(["Alpha", "Mid"]);
    expect(await find(d, { text: "z", tag: "i18n" })).toEqual(["Zed"]);
    expect(await find(d, { text: "nothing" })).toEqual([]);
  });

  it("rejects a malformed query", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    expect((await post("/v1/directory/find", { query: "x" }, d.auth)).status).toBe(400);
  });

  it("pages with a default of 25, a maximum of 100, and stable cursors", async () => {
    const x = tenant();
    const devs = await Promise.all(Array.from({ length: 3 }, (_, i) => x.enroll(`u${i}@example.test`)));
    for (const d of devs) for (let i = 0; i < 20; i++) await publish(d, card({ name: `bot-${String(i).padStart(2, "0")}` }));
    const ask = async (body: object) => json(await post("/v1/directory/find", body, devs[0]!.auth));
    const first = await ask({});
    expect(first.agents).toHaveLength(25);
    expect(first.agents.slice(0, 3).map((a: any) => a.name)).toEqual(["bot-00", "bot-00", "bot-00"]); // equal names ordered by id
    const all = [...first.agents];
    for (let r = first; r.next_cursor; ) {
      r = await ask({ limit: 25, cursor: r.next_cursor });
      all.push(...r.agents);
    }
    expect(all).toHaveLength(60);
    expect(new Set(all.map((a: any) => a.id)).size).toBe(60);
    expect((await ask({ limit: 100 })).next_cursor).toBeUndefined();
    // deleting the card a cursor points at does not skip or repeat anything
    const p1 = await ask({ limit: 10 });
    await post("/v1/cards/remove", { id: p1.agents[9].id }, devs[[0, 1, 2].find((i) => p1.agents[9].device_id === devs[i]!.id)!]!.auth);
    const p2 = await ask({ limit: 10, cursor: p1.next_cursor });
    expect(p2.agents[0].id).toBe(all[10].id);
    for (const bad of [{ limit: 0 }, { limit: 101 }, { limit: "5" }, { cursor: "zz" }, { cursor: 5 }, { cursor: ["6b31"] }]) {
      expect((await post("/v1/directory/find", bad, devs[0]!.auth)).status, JSON.stringify(bad)).toBe(400);
    }
  }, 60_000);

  it("reads at most MAX_CARDS_PER_TENANT cards and refuses to publish past it", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    await runInDurableObject(x.stub, async (_i, s) => {
      const all: Record<string, unknown> = {};
      for (let i = 0; i < MAX_CARDS_PER_TENANT; i++) all[`card:${"1".repeat(31)}${(i % 10).toString(16)}:${String(i).padStart(16, "0")}`] = { name: `n${i}`, description: "d", tags: [], examples: [], visibility: "tenant", groups: [], id: `x${i}`, device_id: "f".repeat(32), owner: "z", published: 0 };
      for (let i = 0; i < MAX_CARDS_PER_TENANT; i += 100) await s.storage.put(Object.fromEntries(Object.entries(all).slice(i, i + 100)));
    });
    expect((await post("/v1/cards/publish", { card: card() }, d.auth)).status).toBe(429);
    expect((await json(await post("/v1/directory/find", { limit: 100 }, d.auth))).agents).toHaveLength(0); // the seeded cards belong to no live device
  }, 60_000);
});

describe("groups admin", () => {
  it("lists, replaces and deletes groups; admin only", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    expect((await post("/v1/admin/groups", {})).status).toBe(401);
    expect((await post("/v1/admin/groups", {}, d.auth)).status).toBe(401);
    expect((await post("/v1/admin/groups/put", { name: "g", members: [] }, d.auth)).status).toBe(401);
    expect(await json(await post("/v1/admin/groups/put", { name: " Eng ", members: ["B@example.test", "a@example.test", "b@example.test"] }, x.admin))).toEqual({
      name: "eng",
      members: ["b@example.test", "a@example.test"],
    });
    await post("/v1/admin/groups/put", { name: "ops" }, x.admin);
    expect((await json(await post("/v1/admin/groups", {}, x.admin))).groups.map((g: any) => g.name)).toEqual(["eng", "ops"]);
    expect((await post("/v1/admin/groups/delete", { name: " ENG " }, x.admin)).status).toBe(200);
    expect((await post("/v1/admin/groups/delete", { name: "eng" }, x.admin)).status).toBe(404);
    expect((await post("/v1/admin/groups/delete", {}, x.admin)).status).toBe(404);
    expect((await post("/v1/admin/groups/nope", {}, x.admin)).status).toBe(404);
  });

  it("rejects bad names and members, and caps the number of groups", async () => {
    const x = tenant();
    expect((await post("/v1/admin/groups/put", { name: "", members: [] }, x.admin)).status).toBe(400);
    expect((await post("/v1/admin/groups/put", { name: "g", members: "a" }, x.admin)).status).toBe(400);
    for (let i = 0; i < MAX_GROUPS; i++) await x.stub.putGroup(`g${i}`, []);
    expect((await post("/v1/admin/groups/put", { name: "extra", members: [] }, x.admin)).status).toBe(429);
    expect((await post("/v1/admin/groups/put", { name: "G0", members: ["a@example.test"] }, x.admin)).status).toBe(200); // replacing is fine
  }, 60_000);
});

describe("request handling", () => {
  it("needs a identity, a POST and a JSON object body", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    for (const p of ["/v1/cards/publish", "/v1/cards/remove", "/v1/directory/find", "/v1/admin/groups"]) expect((await post(p, {})).status).toBe(401);
    expect((await post("/v1/cards/publish", { card: card() }, "Bearer nonsense")).status).toBe(401);
    expect((await post("/v1/cards/publish", { card: card() }, x.admin)).status).toBe(401); // an admin is not a device
    expect((await post("/v1/directory/find", {}, "Bearer dev:bad/tenant:d")).status).toBe(401);
    expect((await SELF.fetch("https://gw/v1/directory/find", { headers: { Authorization: d.auth } })).status).toBe(405);
    for (const bad of ["not json", "[]", "null", "x".repeat(20000)]) expect((await post("/v1/directory/find", bad, d.auth)).status, bad.slice(0, 10)).toBe(400);
    expect((await post("/v1/directory/find", "{}", d.auth)).status).toBe(200);
    expect((await post("/v1/directory/nope", {}, d.auth)).status).toBe(404);
    expect((await post("/v1/cards/nope", {}, d.auth)).status).toBe(404);
    const big = await SELF.fetch("https://gw/v1/directory/find", { method: "POST", headers: { Authorization: d.auth, "content-length": "99999" }, body: "{}" });
    expect(big.status).toBe(400);
  });

  it("fails closed without DEV_AUTH", async () => {
    const { handleDirectory } = await import("../src/directory");
    const r = await handleDirectory(new Request("https://gw/v1/directory/find", { method: "POST", headers: { Authorization: "Bearer dev:t:d" }, body: "{}" }), { ...env, DEV_AUTH: undefined });
    expect(r.status).toBe(401);
  });
});

describe("storage", () => {
  it("keeps cards and groups under their own prefixes, with no poll or content fields", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    await publish(d, card());
    await x.stub.putGroup("eng", ["a@example.test"]);
    const keys = await runInDurableObject(x.stub, async (_i, s) => [...(await s.storage.list()).keys()].map((k) => k.split(":")[0]));
    expect([...new Set(keys)].sort()).toEqual(["aud", "auds", "card", "enr", "grp"]);
  });
});

describe("default deny and group lifecycle", () => {
  it("an empty, deleted, renamed or never-created group shows a groups card to nobody but its owner", async () => {
    const x = tenant();
    const alice = await x.enroll("alice@example.test");
    const bob = await x.enroll("bob@example.test");
    for (const g of ["empty", "gone", "renamed", "typo"]) await publish(alice, card({ name: g, visibility: "groups", groups: [g] }));
    await post("/v1/admin/groups/put", { name: "empty", members: [] }, x.admin);
    await post("/v1/admin/groups/put", { name: "gone", members: ["bob@example.test"] }, x.admin);
    await post("/v1/admin/groups/put", { name: "renamed", members: ["bob@example.test"] }, x.admin);
    expect(await find(bob)).toEqual(["gone", "renamed"]);
    await post("/v1/admin/groups/delete", { name: "gone" }, x.admin);
    await post("/v1/admin/groups/delete", { name: "renamed" }, x.admin); // a rename is delete + put under a new name
    await post("/v1/admin/groups/put", { name: "renamed2", members: ["bob@example.test"] }, x.admin);
    expect(await find(bob)).toEqual([]);
    expect(await find(alice)).toEqual(["empty", "gone", "renamed", "typo"]);
    const id = (await publish(alice, card({ name: "gone", visibility: "groups", groups: ["gone"] }))).id;
    expect(await call(x, "resolve", bob.id, id)).toBeNull();
  });

  it("a caller with no rule that matches sees nothing: stranger, other group, non-member", async () => {
    const x = tenant();
    const alice = await x.enroll("alice@example.test");
    const outsiders = [await x.enroll("zed@example.test"), await x.enroll("carol@example.test")];
    await publish(alice, card({ name: "Eng", visibility: "groups", groups: ["eng"] }));
    await post("/v1/admin/groups/put", { name: "eng", members: ["bob@example.test"] }, x.admin);
    await post("/v1/admin/groups/put", { name: "ops", members: ["carol@example.test"] }, x.admin);
    for (const o of outsiders) expect(await find(o)).toEqual([]);
  });

  it("group names that differ only in case or padding are one group, and members are case-insensitive", async () => {
    const x = tenant();
    const alice = await x.enroll("alice@example.test");
    const bob = await x.enroll("BOB@example.test");
    await publish(alice, card({ name: "E", visibility: "groups", groups: [" ENG"] }));
    await post("/v1/admin/groups/put", { name: "eng ", members: ["Bob@Example.TEST"] }, x.admin);
    expect(await find(bob)).toEqual(["E"]);
  });

  it("the gateway only shows cards: resolve is visibility, and a signed-binding allowlist is not stored or consulted here", async () => {
    const x = tenant();
    const a = await enrollAndPublish(x);
    const keys = await runInDurableObject(x.stub, async (_i, s) => JSON.stringify([...(await s.storage.list()).values()]));
    expect(keys).not.toMatch(/allow/i); // no allowlist, no grant: the target daemon decides from the binding
    expect(a.id).toBeDefined();
  });
});

describe("tenant isolation", () => {
  it("cards, groups, ids and the audit log never cross tenants", async () => {
    const x = tenant();
    const y = tenant();
    const a = await x.enroll("alice@example.test");
    const b = await y.enroll("alice@example.test"); // the same email in another tenant
    const ca = (await publish(a, card({ name: "Mine" }))).id as string;
    await publish(b, card({ name: "Theirs", visibility: "groups", groups: ["eng"] }));
    await post("/v1/admin/groups/put", { name: "eng", members: ["alice@example.test"] }, y.admin);
    expect(await find(a)).toEqual(["Mine"]);
    expect(await find(b)).toEqual(["Theirs"]);
    // x's device id presented with y's tenant is not enrolled there, and x's card id is nothing in y
    expect((await post("/v1/directory/find", {}, `Bearer dev:${y.t}:${a.id}`)).status).toBe(403);
    expect((await post("/v1/cards/publish", { card: card() }, `Bearer dev:${y.t}:${a.id}`)).status).toBe(403);
    expect((await post("/v1/cards/remove", { id: ca }, b.auth)).status).toBe(404);
    expect(await call(y, "resolve", b.id, ca)).toBeNull();
    expect((await post("/v1/admin/groups/get", { name: "eng" }, x.admin)).status).toBe(404);
    expect((await json(await post("/v1/admin/groups", {}, x.admin))).groups).toEqual([]);
    expect((await json(await post("/v1/admin/audit", {}, x.admin))).events.map((e: any) => e.subject)).toEqual([ca]);
  });

  it("crafted tenant, device and card ids are refused before storage", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    const other = tenant();
    for (const bad of [`Bearer dev:${x.t}:${d.id.toUpperCase()}`, `Bearer dev:${x.t}:${d.id}:x`, `Bearer dev:${x.t}/../${other.t}:${d.id}`, `Bearer dev:${x.t}:../${d.id}`, `Bearer dev:${x.t}:${"a".repeat(31)}`, `Bearer dev:${x.t}:${d.id}0`, `Bearer dev:${"x".repeat(65)}:${d.id}`, `Bearer dev-admin:${x.t}:${other.t}`]) {
      expect((await post("/v1/directory/find", {}, bad)).status, bad).toBe(401);
    }
    const id = (await publish(d, card())).id as string;
    for (const bad of [id.toUpperCase(), `${id}x`, `card:${id}`, `${d.id}:${"0".repeat(15)}`, `${"0".repeat(32)}:${id.split(":")[1]}`, `${d.id}:../${id.split(":")[1]}`, 5, null, ["x"]]) {
      expect((await post("/v1/cards/remove", { id: bad }, d.auth)).status, String(bad)).toBe(404);
    }
    expect(await find(d)).toEqual(["Reviewer"]);
    expect(await call(x, "resolve", d.id, `${id}x`)).toBeNull();
    expect(await call(x, "publishCard", "not-a-device", card())).toEqual({ error: "not_enrolled" });
  });
});

describe("revocation", () => {
  it("a revoked device leaves the directory at once, with its cards, and cannot use it", async () => {
    const x = tenant();
    const a = await enrollAndPublish(x, "alice@example.test", card({ name: "Gone" }));
    const bob = await x.enroll("bob@example.test");
    await publish(bob, card({ name: "Stays" }));
    expect(await find(bob)).toEqual(["Gone", "Stays"]);
    const list = (version: number, revoked: unknown) => ({ tenant: x.t, version, issued_at: "2026-01-01T00:00:00Z", revoked, signature: "AA" });
    expect((await post("/v1/admin/revocations", { list: list(1, [a.d.id, 7, null]) }, x.admin)).status).toBe(200);
    expect(await find(bob)).toEqual(["Stays"]);
    expect((await post("/v1/directory/find", {}, a.d.auth)).status).toBe(403);
    expect((await post("/v1/cards/publish", { card: card() }, a.d.auth)).status).toBe(403);
    expect((await post("/v1/cards/remove", { id: a.id }, a.d.auth)).status).toBe(404);
    expect(await call(x, "resolve", bob.id, a.id)).toBeNull();
    const kept = await runInDurableObject(x.stub, async (_i, s) => [...(await s.storage.list({ prefix: "card:" })).keys()]);
    expect(kept).toHaveLength(1);
    const events = (await json(await post("/v1/admin/audit", {}, x.admin))).events;
    expect(events.at(-1)).toMatchObject({ action: "revocations.put", subject: "1", detail: { revoked: 1, cards_removed: 1 } });
  });

  it("an identical list changes nothing; a list without revoked ids, or a malformed one, hides nobody", async () => {
    const x = tenant();
    const a = await enrollAndPublish(x);
    const base = { tenant: x.t, version: 1 };
    expect((await post("/v1/admin/revocations", { list: base }, x.admin)).status).toBe(200);
    expect((await post("/v1/admin/revocations", { list: { ...base, revoked: "nope" } }, x.admin)).status).toBe(409); // same version, different list
    expect((await post("/v1/admin/revocations", { list: { ...base, version: 2, revoked: "nope" } }, x.admin)).status).toBe(200);
    const n = (await json(await post("/v1/admin/audit", {}, x.admin))).events.length;
    expect((await post("/v1/admin/revocations", { list: { ...base, version: 2, revoked: "nope" } }, x.admin)).status).toBe(200);
    expect((await json(await post("/v1/admin/audit", {}, x.admin))).events).toHaveLength(n); // idempotent: no new event
    expect(await find(a.d)).toEqual(["Reviewer"]);
  });
});

describe("limits", () => {
  it("bounds the size of a group", async () => {
    const x = tenant();
    const members = (n: number, len: number) => Array.from({ length: n }, (_, i) => `${i}`.padStart(len, "u"));
    expect((await post("/v1/admin/groups/put", { name: "big", members: members(300, 200) }, x.admin)).status).toBe(200); // exactly MAX_MEMBER_CHARS
    expect(300 * 200).toBe(MAX_MEMBER_CHARS);
    expect((await post("/v1/admin/groups/put", { name: "bigger", members: members(300, 201) }, x.admin)).status).toBe(400);
    const stored = await runInDurableObject(x.stub, async (_i, s) => JSON.stringify(await s.storage.get("grp:big")).length);
    expect(stored).toBeLessThan(131072);
  });

  it("only group puts may carry a large body", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    const huge = { name: "g", members: Array.from({ length: 150 }, (_, i) => `${i}`.padStart(150, "u")) }; // > 16 KiB, < 64 KiB
    expect((await post("/v1/admin/groups/put", huge, x.admin)).status).toBe(200);
    expect((await post("/v1/admin/groups/get", { name: "other", pad: "x".repeat(20000) }, x.admin)).status).toBe(400);
    expect((await post("/v1/admin/groups/put", { ...huge, pad: "x".repeat(70000) }, x.admin)).status).toBe(400);
    expect((await post("/v1/directory/find", { pad: "x".repeat(20000) }, d.auth)).status).toBe(400);
  });
});

describe("groups pages and the audit log", () => {
  it("lists groups and members a page at a time, admin only", async () => {
    const x = tenant();
    const d = await x.enroll("a@example.test");
    for (let i = 0; i < 30; i++) await x.stub.putGroup(`g${String(i).padStart(2, "0")}`, i === 0 ? ["z@example.test", "a@example.test", "m@example.test"] : []);
    const p1 = await json(await post("/v1/admin/groups", {}, x.admin));
    expect(p1.groups).toHaveLength(25);
    expect(p1.groups[0]).toEqual({ name: "g00", member_count: 3 });
    const p2 = await json(await post("/v1/admin/groups", { cursor: p1.next_cursor }, x.admin));
    expect(p2.groups.map((g: any) => g.name)).toEqual(["g25", "g26", "g27", "g28", "g29"]);
    expect(p2.next_cursor).toBeUndefined();
    const m1 = await json(await post("/v1/admin/groups/get", { name: " G00", limit: 2 }, x.admin));
    expect(m1.members).toEqual(["a@example.test", "m@example.test"]);
    expect((await json(await post("/v1/admin/groups/get", { name: "g00", limit: 2, cursor: m1.next_cursor }, x.admin))).members).toEqual(["z@example.test"]);
    expect((await post("/v1/admin/groups/get", { name: "nope" }, x.admin)).status).toBe(404);
    expect((await post("/v1/admin/groups/get", { name: "g00", limit: 0 }, x.admin)).status).toBe(400);
    expect((await post("/v1/admin/groups", { limit: 101 }, x.admin)).status).toBe(400);
    for (const path of ["/v1/admin/groups/get", "/v1/admin/audit"]) {
      expect((await post(path, {}, d.auth)).status).toBe(401);
      expect((await post(path, {})).status).toBe(401);
    }
    expect((await post("/v1/admin/audit", { limit: 0 }, x.admin)).status).toBe(400);
  }, 60_000);

  it("records group, card and list changes as metadata, never member identities or card text", async () => {
    const x = tenant();
    const a = await enrollAndPublish(x, "alice@example.test", card({ name: "Private name", visibility: "groups", groups: ["eng"] }));
    await post("/v1/admin/groups/put", { name: "eng", members: ["secret.person@example.test", "b@example.test"] }, x.admin);
    await post("/v1/admin/groups/delete", { name: "eng" }, x.admin);
    await post("/v1/admin/groups/delete", { name: "eng" }, x.admin); // nothing to delete: no event
    await post("/v1/cards/remove", { id: a.id }, a.d.auth);
    const events = (await json(await post("/v1/admin/audit", {}, x.admin))).events;
    expect(events.map((e: any) => [e.action, e.actor === a.d.id ? "device" : e.actor, e.subject === a.id ? "card" : e.subject])).toEqual([
      ["card.publish", "device", "card"],
      ["group.put", "admin", "eng"],
      ["group.delete", "admin", "eng"],
      ["card.remove", "device", "card"],
    ]);
    expect(events[0].detail).toEqual({ visibility: "groups", groups: 1 });
    expect(events[1].detail).toEqual({ members: 2 });
    expect(JSON.stringify(events)).not.toMatch(/secret\.person|Private name|example\.test/);
    const p = await json(await post("/v1/admin/audit", { limit: 3 }, x.admin));
    expect(p.events).toHaveLength(3);
    expect((await json(await post("/v1/admin/audit", { limit: 3, cursor: p.next_cursor }, x.admin))).events).toHaveLength(1);
  });

  it("keeps only the newest MAX_AUDIT events", async () => {
    const x = tenant();
    await runInDurableObject(x.stub, async (_i, s) => {
      const seed = Array.from({ length: MAX_AUDIT }, (_, i) => [`aud:${String(i + 1).padStart(12, "0")}`, { at: i, action: "group.put", actor: "admin", subject: `s${i + 1}` }] as const);
      for (let i = 0; i < MAX_AUDIT; i += 100) await s.storage.put(Object.fromEntries(seed.slice(i, i + 100)));
      await s.storage.put("auds", MAX_AUDIT);
    });
    await x.stub.putGroup("new", []);
    const first = (await json(await post("/v1/admin/audit", { limit: 100 }, x.admin))).events;
    expect(first[0].subject).toBe("s2"); // s1, the oldest, was dropped in the same commit
    const count = await runInDurableObject(x.stub, async (_i, s) => [(await s.storage.list({ prefix: "aud:" })).size, await s.storage.get("auds")]);
    expect(count).toEqual([MAX_AUDIT, MAX_AUDIT + 1]);
  }, 60_000);

  it("a change and its event commit together", async () => {
    const x = tenant();
    await x.stub.putGroup("a", ["x@example.test"]);
    const r = await runInDurableObject(x.stub, async (_i, s) => [(await s.storage.list({ prefix: "grp:" })).size, (await s.storage.list({ prefix: "aud:" })).size, await s.storage.get("auds")]);
    expect(r).toEqual([1, 1, 1]);
  });

  it("events keep their order within one millisecond", async () => {
    const x = tenant();
    for (const n of ["a", "b", "c", "d", "e"]) await x.stub.putGroup(n, []);
    expect((await json(await post("/v1/admin/audit", {}, x.admin))).events.map((e: any) => e.subject)).toEqual(["a", "b", "c", "d", "e"]);
  });
});

// Needs the daemon side (the allowlist in the signed binding), which has no gateway test harness yet.
describe("T307 acceptance", () => {
  it.todo("T307: ACL matrix end to end: gateway visibility x the target daemon's allowlist from the signed binding; the daemon refuses a visible card whose binding does not name the caller");
});
