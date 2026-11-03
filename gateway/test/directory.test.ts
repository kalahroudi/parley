// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { MAX_CARDS_PER_DEVICE, MAX_GROUPS } from "../src/acl";

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
    for (const auth of [unbound.auth, `Bearer dev:${x.t}:${pending}`, `Bearer dev:${x.t}:${rejected}`, `Bearer dev:${x.t}:nosuch`]) {
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

  it("returns at most 50 results", async () => {
    const x = tenant();
    const devs = await Promise.all(Array.from({ length: 3 }, (_, i) => x.enroll(`u${i}@example.test`)));
    for (const d of devs) for (let i = 0; i < 20; i++) await publish(d, card({ name: `bot-${String(i).padStart(2, "0")}` }));
    const names = await find(devs[0]!);
    expect(names).toHaveLength(50);
    expect(names.slice(0, 3)).toEqual(["bot-00", "bot-00", "bot-00"]); // equal names ordered by id
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
    expect(keys.sort()).toEqual(["card", "enr", "grp"]);
  });
});
