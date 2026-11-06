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
import { handleDirectory, type DeviceAuth } from "../src/directory";

const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const testDevice: DeviceAuth = async (req) => {
  const m = /^Bearer dev:([^:]+):([^:]+)$/.exec(req.headers.get("Authorization") ?? "");
  return m ? { tenant: m[1]!, device: m[2]! } : null;
};
const post = async (path: string, body: unknown, auth: string) => {
  const init = { method: "POST", headers: { "content-type": "application/json", Authorization: auth }, body: JSON.stringify(body) };
  return auth.startsWith("Bearer dev:") ? handleDirectory(new Request(`https://gw${path}`, init), env, testDevice) : SELF.fetch(`https://gw${path}`, init);
};
const json = async (r: Response) => (await r.json()) as any;

let n = 0;
function tenant() {
  const t = `acl${++n}`;
  const stub = env.TENANT.get(env.TENANT.idFromName(t));
  const session = async (role: "admin" | "user", email: string) => `Bearer ps_${t}.${(await stub.createSession(email, role)).secret}`;
  const adminSession = session("admin", "admin@example.test"); // one admin session per tenant, as a person has
  const enroll = async (email: string, bind = true) => {
    const sk = key();
    const { id } = await json(await post("/v1/enroll/request", { name: "laptop", signing_key: sk }, await session("user", email)));
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
