// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T307 acceptance, the gateway half of the ACL matrix (the end-to-end half, with real daemons applying their own
// allowlist, is tests/acl-matrix.test.mjs). Every combination of viewer x card x group state is asked three ways
// through the real Tenant DO and compared with an oracle written here, apart from src/acl.ts:
//   find (what the viewer is shown), resolve (what it may address) and mayRelay (whether its prekey request is
//   carried). The three must agree, a hidden card must be indistinguishable from a card that does not exist, and
//   nothing the gateway stores or answers is a grant.

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { MAX_MEMBERS } from "../src/acl";
import { isAdmin, isUser } from "../src/session";
import { handleDirectory, type DeviceAuth } from "../src/directory";
import directorySource from "../src/directory.ts?raw";
import tenantSource from "../src/tenant.ts?raw";

const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const testDevice: DeviceAuth = async (req) => {
  const m = /^Bearer dev:([^:]+):([^:]+)$/.exec(req.headers.get("Authorization") ?? "");
  return m ? { tenant: m[1]!, device: m[2]! } : null;
};
const post = async (path: string, body: unknown, auth = "") => {
  const init = { method: "POST", headers: { "content-type": "application/json", Authorization: auth }, body: JSON.stringify(body) };
  return auth.startsWith("Bearer dev:") ? handleDirectory(new Request(`https://gw${path}`, init), env, testDevice) : SELF.fetch(`https://gw${path}`, init);
};
const json = async (r: Response) => (await r.json()) as any;

const session = async (t: string, role: "admin" | "user", email: string) => `Bearer ps_${t}.${(await env.TENANT.get(env.TENANT.idFromName(t)).createSession(email, role)).secret}`;

let n = 0;
function tenant() {
  const t = `acl${++n}`;
  const stub = env.TENANT.get(env.TENANT.idFromName(t));
  const session = async (role: "admin" | "user", email: string) => `Bearer ps_${t}.${(await stub.createSession(email, role)).secret}`;
  const adminSession = session("admin", "admin@example.test"); // one admin session per tenant, as a person has
  const enroll = async (email: string, bind = true) => {
    const sk = key();
    // A user session lasts only while the tenant still lists the user (src/session.ts), and these addresses are test data (look-alikes
    // among them), so each is listed as it is used.
    (env as { USERS?: string }).USERS = `${env.USERS ?? ""},${t}:${email}`;
    // A named service owner (no address) is a pod: it enrolls with an admin-minted token, as in production.
    const { id } = email.includes("@")
      ? await json(await post("/v1/enroll/request", { name: "laptop", signing_key: sk }, await session("user", email)))
      : await json(await post("/v1/enroll/request", { name: "laptop", signing_key: sk, tenant: t, token: (await stub.mintToken(email))!.token }, ""));
    const admin = await adminSession;
    expect((await post("/v1/admin/enrollments/decide", { id, decision: "approved" }, admin)).status).toBe(200);
    if (bind) expect((await post("/v1/admin/bindings", { id, binding: { device_id: id, signing_key: sk, version: 1 } }, admin)).status).toBe(200);
    return { id, auth: `Bearer dev:${t}:${id}` };
  };
  return { t, stub, enroll, admin: () => adminSession };
}

type Card = { visibility: "tenant" | "groups" | "private"; groups?: string[] };
type Groups = Record<string, string[]>;

// The rule, restated: the owner sees everything; "tenant" is everyone; "groups" is a listed group that exists and
// lists the viewer; anything else is nobody. Case does not matter in identities or group names.
const lc = (s: string) => s.trim().toLowerCase();
function oracle(card: Card, owner: string, viewer: string, groups: Groups): boolean {
  if (lc(viewer) === lc(owner)) return true;
  if (card.visibility === "tenant") return true;
  if (card.visibility !== "groups") return false;
  return (card.groups ?? []).some((g) => Object.entries(groups).some(([name, members]) => lc(name) === lc(g) && members.some((m) => lc(m) === lc(viewer))));
}

const OWNER = "owner@example.test";
const VIEWERS = {
  owner: "owner@example.test",
  ownerAgain: "OWNER@Example.test", // a second device of the owner, written differently
  member: "Member@example.test",
  other: "other@example.test",
  pod: "svc-ci", // a named service owner
};
const CARDS: [string, Card][] = [
  ["tenant", { visibility: "tenant" }],
  ["private", { visibility: "private" }],
  ["groups [eng]", { visibility: "groups", groups: ["eng"] }],
  ["groups [ENG, ops]", { visibility: "groups", groups: ["ENG", "ops"] }],
  ["groups [missing]", { visibility: "groups", groups: ["missing"] }],
];
const GROUP_STATES: [string, Groups][] = [
  ["no groups", {}],
  ["eng is empty", { eng: [] }],
  ["eng has the member", { eng: ["member@EXAMPLE.test"] }],
  ["eng has someone else", { eng: ["other@example.test"] }],
  ["ops has the pod", { eng: ["other@example.test"], ops: ["svc-ci"] }],
  ["every group lists everyone", { eng: Object.values(VIEWERS), ops: Object.values(VIEWERS) }],
];

describe("gateway ACL matrix: viewer x card x group state", () => {
  it("find, resolve and the prekey relay agree with the rule for every combination, and a hidden card looks absent", async () => {
    const x = tenant();
    const devices: Record<string, { id: string; auth: string }> = {};
    for (const [who, email] of Object.entries(VIEWERS)) devices[who] = await x.enroll(email);
    const admin = await x.admin();
    const publisher = await x.enroll(OWNER); // the target device, owned by OWNER
    let combos = 0;
    for (const [cardName, card] of CARDS) {
      const pub = await json(await post("/v1/cards/publish", { card: { name: "Bot", description: "d", tags: [], examples: [], ...card } }, publisher.auth));
      expect(typeof pub.id, cardName).toBe("string");
      for (const [stateName, groups] of GROUP_STATES) {
        // Make the groups exactly this state.
        const have = (await json(await post("/v1/admin/groups", {}, admin))).groups as { name: string }[];
        for (const g of have) expect((await post("/v1/admin/groups/delete", { name: g.name }, admin)).status).toBe(200);
        for (const [name, members] of Object.entries(groups)) expect((await post("/v1/admin/groups/put", { name, members }, admin)).status).toBe(200);
        for (const [who, d] of Object.entries(devices)) {
          const at = `${cardName} / ${stateName} / ${who}`;
          const want = oracle(card, OWNER, VIEWERS[who as keyof typeof VIEWERS], groups);
          const found = (await json(await post("/v1/directory/find", {}, d.auth))).agents.some((a: any) => a.id === pub.id);
          const resolved = await x.stub.resolve(d.id, pub.id);
          // The relay carries the request only when the viewer sees one of the target's cards (it has one here).
          const relayed = await x.stub.mayRelay(d.id, publisher.id, true);
          expect(found, `find: ${at}`).toBe(want);
          expect(resolved !== null, `resolve: ${at}`).toBe(want);
          expect(relayed, `relay: ${at}`).toBe(want);
          // A card that is hidden is the same answer as one that was never published, and a shown one is not a grant.
          if (!want) expect(resolved).toEqual(await x.stub.resolve(d.id, `${publisher.id}:0000000000000000`));
          else expect(Object.keys(resolved!).join(",")).not.toMatch(/allow|grant|permit/i);
          // Frames that are not requests (a reply, a prekey the target sends) are not hidden by visibility.
          expect(await x.stub.mayRelay(d.id, publisher.id, false), `non-request: ${at}`).toBe(true);
          combos++;
        }
      }
    }
    expect(combos).toBe(CARDS.length * GROUP_STATES.length * Object.keys(VIEWERS).length);
  }, 300_000);

  it("a device that is not enrolled, not bound or from another tenant sees nothing and is carried nowhere, in every mode", async () => {
    const x = tenant();
    const y = tenant();
    const owner = await x.enroll(OWNER);
    const unbound = await x.enroll("u@example.test", false);
    const foreign = await y.enroll(OWNER); // same address, another tenant
    const admin = await x.admin();
    await post("/v1/admin/groups/put", { name: "eng", members: ["u@example.test", OWNER] }, admin);
    for (const [name, card] of CARDS) {
      const { id } = await json(await post("/v1/cards/publish", { card: { name: "Bot", description: "d", tags: [], examples: [], ...card } }, owner.auth));
      for (const d of [unbound, foreign]) {
        expect(await x.stub.resolve(d.id, id), name).toBeNull();
        expect(await x.stub.mayRelay(d.id, owner.id, true), name).toBe(false);
        expect(await x.stub.mayRelay(d.id, owner.id, false), name).toBe(false);
      }
      expect((await post("/v1/directory/find", {}, unbound.auth)).status, name).toBe(403);
      expect((await json(await post("/v1/directory/find", {}, foreign.auth))).agents, name).toEqual([]);
    }
  });

  it("a target that published nothing says nothing a directory could hide: enrolled callers are carried, strangers are not", async () => {
    const x = tenant();
    const quiet = await x.enroll(OWNER);
    const caller = await x.enroll("c@example.test");
    const unbound = await x.enroll("u@example.test", false);
    expect(await x.stub.mayRelay(caller.id, quiet.id, true)).toBe(true);
    expect(await x.stub.mayRelay(unbound.id, quiet.id, true)).toBe(false);
    expect(await x.stub.mayRelay(caller.id, "f".repeat(32), true)).toBe(false); // an unknown target
  });

  it("the edits that change who sees a card take effect on the next question: membership, deletion, republishing", async () => {
    const x = tenant();
    const owner = await x.enroll(OWNER);
    const bob = await x.enroll("bob@example.test");
    const admin = await x.admin();
    const publish = async (card: object) => (await json(await post("/v1/cards/publish", { card: { name: "Bot", description: "d", tags: [], examples: [], ...card } }, owner.auth))).id as string;
    const sees = async () => (await x.stub.resolve(bob.id, id)) !== null && (await x.stub.mayRelay(bob.id, owner.id, true));
    let id = await publish({ visibility: "groups", groups: ["eng"] });
    expect(await sees()).toBe(false);
    await post("/v1/admin/groups/put", { name: "eng", members: ["bob@example.test"] }, admin);
    expect(await sees()).toBe(true);
    await post("/v1/admin/groups/put", { name: "eng", members: [] }, admin);
    expect(await sees()).toBe(false);
    await post("/v1/admin/groups/put", { name: "eng", members: ["bob@example.test"] }, admin);
    expect(await sees()).toBe(true);
    await post("/v1/admin/groups/delete", { name: "eng" }, admin);
    expect(await sees()).toBe(false);
    await post("/v1/admin/groups/put", { name: "eng", members: ["bob@example.test"] }, admin);
    id = await publish({ visibility: "private" }); // the same card, republished
    expect(await sees()).toBe(false);
    id = await publish({ visibility: "tenant" });
    expect(await sees()).toBe(true);
  });

  it("the gateway keeps no allowlist and no grant, whatever the cards and groups say", async () => {
    const x = tenant();
    const owner = await x.enroll(OWNER);
    await x.enroll("bob@example.test");
    const admin = await x.admin();
    await post("/v1/admin/groups/put", { name: "eng", members: ["bob@example.test"] }, admin);
    for (const [, card] of CARDS) await post("/v1/cards/publish", { card: { name: `Bot ${Math.random()}`, description: "d", tags: [], examples: [], ...card } }, owner.auth);
    const stored = await runInDurableObject(x.stub, async (_i, s) => [...(await s.storage.list()).keys()].map((k) => k.split(":")[0]));
    expect([...new Set(stored)].sort()).toEqual(["aud", "auds", "card", "enr", "grp", "ses"]);
    const values = await runInDurableObject(x.stub, async (_i, s) => JSON.stringify([...(await s.storage.list({ prefix: "card:" })).values()]));
    expect(values).not.toMatch(/allow|grant|permit|acl/i);
  });
});

// Who may call which route: caller kind x route, each cell an explicit allow or deny. "allow" means the request got past
// authorization (any status but 401/403: a bad body or a missing card is still an answer to an authorized caller).
const ADMIN_ROUTES = ["/v1/admin/groups", "/v1/admin/groups/get", "/v1/admin/groups/put", "/v1/admin/groups/delete", "/v1/admin/retention", "/v1/admin/retention/put", "/v1/admin/audit"];
const DEVICE_ROUTES = ["/v1/cards/publish", "/v1/cards/remove", "/v1/directory/find", "/v1/directory/binding"];
const CALLERS = ["anonymous", "user session", "admin session", "device", "unbound device", "device of another tenant", "admin of another tenant"] as const;
// admin routes: only the tenant's admin session; device routes: only an enrolled, bound device of the tenant.
const ALLOW: Record<(typeof CALLERS)[number], "admin" | "device" | "none"> = {
  anonymous: "none",
  "user session": "none",
  "admin session": "admin",
  device: "device",
  "unbound device": "none",
  "device of another tenant": "none",
  "admin of another tenant": "admin", // authorized in its own tenant; it must reach nothing in this one (checked below)
};

describe("route authority matrix: caller kind x route", () => {
  it("every route admits exactly the callers it should, and every route of the handler is in the matrix", async () => {
    const x = tenant();
    const y = tenant();
    const device = await x.enroll("d@example.test");
    const unbound = await x.enroll("u@example.test", false);
    const foreign = await y.enroll("d@example.test");
    const auth: Record<(typeof CALLERS)[number], string | null> = {
      anonymous: null,
      "user session": await session(x.t, "user", "d@example.test"),
      "admin session": await x.admin(),
      device: device.auth,
      "unbound device": unbound.auth,
      "device of another tenant": `Bearer dev:${x.t}:${foreign.id}`, // another tenant's device id presented here
      "admin of another tenant": await y.admin(), // resolves to tenant y, never x: checked by what it can see below
    };
    const body = (path: string) => (path === "/v1/admin/groups/put" ? { name: "g", members: [] } : path === "/v1/admin/groups/get" || path === "/v1/admin/groups/delete" ? { name: "g" } : path === "/v1/admin/retention/put" ? { mode: "strict" } : path === "/v1/cards/publish" ? { card: { name: "B", description: "d", tags: [], examples: [], visibility: "tenant" } } : path === "/v1/directory/binding" ? { device: device.id } : {});
    let cells = 0;
    for (const caller of CALLERS) {
      for (const path of [...ADMIN_ROUTES, ...DEVICE_ROUTES]) {
        const want = ALLOW[caller] === (ADMIN_ROUTES.includes(path) ? "admin" : "device");
        if (path === "/v1/cards/remove") {
          // Removing answers 404 both for "no such card" and for "not yours", so the deny cells assert the card survives.
          const { id } = await json(await post("/v1/cards/publish", { card: { name: `R${cells}`, description: "d", tags: [], examples: [], visibility: "tenant" } }, device.auth));
          await post(path, { id }, auth[caller] ?? "");
          const left = await runInDurableObject(x.stub, async (_i, s) => (await s.storage.get(`card:${id}`)) !== undefined);
          expect(!left, `${caller} -> ${path} removed the card`).toBe(want);
          cells++;
          continue;
        }
        const r = await post(path, body(path), auth[caller] ?? "");
        const got = r.status !== 401 && r.status !== 403;
        expect(got, `${caller} -> ${path} (${r.status})`).toBe(want);
        cells++;
      }
    }
    expect(cells).toBe(CALLERS.length * (ADMIN_ROUTES.length + DEVICE_ROUTES.length));
    // y's admin works on y's data only: the group it wrote is in y, not in x.
    await post("/v1/admin/groups/put", { name: "only-y", members: [] }, auth["admin of another tenant"]!);
    const names = async (t: ReturnType<typeof tenant>) => ((await json(await post("/v1/admin/groups", {}, await t.admin()))).groups as { name: string }[]).map((g) => g.name);
    expect(await names(y)).toContain("only-y");
    expect(await names(x)).not.toContain("only-y");

    // Drift guard: a route added to the handler, or a role added to sessions, without a row here fails this test.
    const routes = new Set([...directorySource.matchAll(/"(\/v1\/(?:admin|cards|directory)\/[a-z/]+|\/v1\/admin\/(?:groups|audit|retention))"/g)].map((m) => m[1]!));
    expect([...routes].sort()).toEqual([...ADMIN_ROUTES, ...DEVICE_ROUTES].sort());
    const roles = /export type Role = ([^;]+);/.exec(tenantSource)?.[1]?.split("|").map((r) => r.trim().replace(/"/g, "")).sort();
    expect(roles, "the roles this matrix knows: admin (all admin routes) and user (none of them)").toEqual(["admin", "user"]);
  }, 60_000);
});

describe("identity edge cases: lookalikes, maximal groups, revocation", () => {
  const sees = async (x: ReturnType<typeof tenant>, viewer: { id: string; auth: string }, cardId: string, owner: { id: string }) => {
    const found = (await json(await post("/v1/directory/find", {}, viewer.auth))).agents?.some((a: any) => a.id === cardId) ?? false;
    const resolved = (await x.stub.resolve(viewer.id, cardId)) !== null;
    const relayed = await x.stub.mayRelay(viewer.id, owner.id, true);
    expect({ found, resolved, relayed }).toEqual({ found, resolved: found, relayed: found });
    return found;
  };

  it("an identity that only looks like a member is not one (other script, full width, zero width, padding), and a group name is not a prefix match", async () => {
    const x = tenant();
    const owner = await x.enroll(OWNER);
    const admin = await x.admin();
    const { id } = await json(await post("/v1/cards/publish", { card: { name: "Bot", description: "d", tags: [], examples: [], visibility: "groups", groups: ["eng"] } }, owner.auth));
    await post("/v1/admin/groups/put", { name: "eng", members: ["alice@example.test"] }, admin);
    await post("/v1/admin/groups/put", { name: "eng2", members: ["mallory@example.test"] }, admin);
    const real = await x.enroll("Alice@Example.TEST");
    expect(await sees(x, real, id, owner)).toBe(true); // control: case alone does not matter
    const tried: [string, boolean][] = [];
    for (const lookalike of ["alice@exampl\u0435.test", "\uff41lice@example.test", "alice@example.test\u200b", "ali\u0441e@example.test", "alice@example.test.", "alice+x@example.test", "alic\u0435@example.test"]) {
      const d = await x.enroll(lookalike).catch(() => null);
      tried.push([lookalike, !!d]);
      if (d) expect(await sees(x, d, id, owner), JSON.stringify(lookalike)).toBe(false);
    }
    expect(tried.filter(([, enrolled]) => enrolled)).toHaveLength(6); // not vacuous: these did enroll and were still refused
    expect(tried.filter(([, enrolled]) => !enrolled).map(([l]) => l)).toEqual(["alice@example.test\u200b"]); // a zero-width character never enrolls
    // Characters that fold or normalize to ASCII (Kelvin sign: NFC gives "K"; dotted capital I: lower case gives "i" + a dot) are
    // other characters, not case variants: the first is refused at enrollment, the second enrolls and sees nothing.
    await post("/v1/admin/groups/put", { name: "eng", members: ["alice@example.test", "kim@example.test", "ian@example.test"] }, admin);
    const kelvin = await post("/v1/enroll/request", { name: "laptop", signing_key: key() }, await session(x.t, "user", "\u212aim@example.test"));
    expect(kelvin.status).toBe(400);
    expect(await sees(x, await x.enroll("\u0130an@example.test"), id, owner)).toBe(false);
    const prefix = await x.enroll("mallory@example.test"); // in eng2 only
    expect(await sees(x, prefix, id, owner)).toBe(false);
    // Group names differ only by case or surrounding space: the same group. A lookalike name is another.
    const { id: id2 } = await json(await post("/v1/cards/publish", { card: { name: "Bot2", description: "d", tags: [], examples: [], visibility: "groups", groups: ["  ENG "] } }, owner.auth));
    expect(await sees(x, real, id2, owner)).toBe(true);
    const owner3 = await x.enroll("owner3@example.test"); // its only card names a lookalike group
    const { id: id3 } = await json(await post("/v1/cards/publish", { card: { name: "Bot3", description: "d", tags: [], examples: [], visibility: "groups", groups: ["\u0435ng"] } }, owner3.auth));
    expect(await sees(x, real, id3, owner3)).toBe(false);
  });

  it("a maximal group admits its last member and nobody else; an empty member list admits nobody", async () => {
    const x = tenant();
    const owner = await x.enroll(OWNER);
    const admin = await x.admin();
    const { id } = await json(await post("/v1/cards/publish", { card: { name: "Bot", description: "d", tags: [], examples: [], visibility: "groups", groups: ["big"] } }, owner.auth));
    const last = "last@example.test";
    const members = [...Array.from({ length: MAX_MEMBERS - 1 }, (_, i) => `m${i}@e.test`), last];
    expect((await post("/v1/admin/groups/put", { name: "big", members }, admin)).status).toBe(200);
    expect((await post("/v1/admin/groups/put", { name: "toobig", members: [...members, "one-more@e.test"] }, admin)).status).toBe(400);
    expect(await sees(x, await x.enroll(last), id, owner)).toBe(true);
    expect(await sees(x, await x.enroll("m0@E.test"), id, owner)).toBe(true);
    expect(await sees(x, await x.enroll("one-more@e.test"), id, owner)).toBe(false);
    await post("/v1/admin/groups/put", { name: "big", members: [] }, admin);
    expect(await sees(x, await x.enroll(last), id, owner)).toBe(false);
  });

  it("a revoked device sees nothing and is carried nowhere, and a revoked target is unreachable, whatever the card says", async () => {
    const x = tenant();
    const owner = await x.enroll(OWNER);
    const viewer = await x.enroll("v@example.test");
    const admin = await x.admin();
    const { id } = await json(await post("/v1/cards/publish", { card: { name: "Bot", description: "d", tags: [], examples: [], visibility: "tenant" } }, owner.auth));
    expect(await sees(x, viewer, id, owner)).toBe(true);
    const list = { tenant: x.t, version: 1, issued_at: "2026-01-01T00:00:00Z", revoked: [viewer.id], signature: "AA" };
    expect((await post("/v1/admin/revocations", { list }, admin)).status).toBe(200);
    expect(await x.stub.resolve(viewer.id, id)).toBeNull();
    expect(await x.stub.mayRelay(viewer.id, owner.id, true)).toBe(false);
    expect(await x.stub.mayRelay(viewer.id, owner.id, false)).toBe(false);
    expect(await x.stub.mayRelay(owner.id, viewer.id, false)).toBe(false); // nor can anyone relay to it
    const bystander = await x.enroll("b@example.test");
    expect(await x.stub.mayRelay(bystander.id, viewer.id, true)).toBe(false);
  });

  it("the owner reaches their own card in every mode, including a groups card naming no group they are in (self-target)", async () => {
    const x = tenant();
    const owner = await x.enroll(OWNER);
    const second = await x.enroll(OWNER.toUpperCase());
    for (const card of [{ visibility: "private" }, { visibility: "groups", groups: ["nobody"] }, { visibility: "tenant" }]) {
      const { id } = await json(await post("/v1/cards/publish", { card: { name: `B${Math.random()}`, description: "d", tags: [], examples: [], ...card } }, owner.auth));
      expect(await sees(x, owner, id, owner)).toBe(true);
      expect(await sees(x, second, id, owner)).toBe(true);
    }
  });
});

describe("identity lists compare ASCII case only", () => {
  it("the Kelvin sign and the dotted capital I are not the ASCII letters in ADMINS, USERS or USER_DOMAINS", () => {
    const e = { ADMINS: "t1:kim@example.test", USERS: "t1:ian@example.test", USER_DOMAINS: "t1:corp.test" } as any;
    expect([isAdmin(e, "t1", "KIM@Example.test"), isUser(e, "t1", "IAN@example.TEST"), isUser(e, "t1", "Q@CORP.test")]).toEqual([true, true, true]);
    expect([isAdmin(e, "t1", "\u212aim@example.test"), isUser(e, "t1", "\u0130an@example.test"), isUser(e, "t1", "q@corp.test\u212a")]).toEqual([false, false, false]);
  });
});
