// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T109: unit tests for the reality-check probes against an in-memory gateway that
// follows gateway/src/device.ts (hello/welcome, frame/ack, 1 MiB cap, ping/pong).
// The real check itself needs a Cloudflare account; see specs/parley-mvp/reality-check-1.md.

import { test } from "node:test";
import assert from "node:assert/strict";
import { checkLoginRedirect, estimateCost, MAX_FRAME_BYTES, openTunnel, perDeviceMonth, probeDeploy, probeFrameLimits, probeHibernation, renderReport } from "./lib.mjs";
import pricing from "./pricing.json" with { type: "json" };

function fakeGateway({ dropAfterFrames = Infinity, dropOnce = true } = {}) {
  const g = { sessions: new Map(), sockets: [], frames: 0, dropped: false, nextId: 1 };
  class FakeWebSocket extends EventTarget {
    constructor() {
      super();
      this.rx = 0;
      g.sockets.push(this);
      queueMicrotask(() => this.dispatchEvent(new Event("open")));
    }
    reply(m) {
      queueMicrotask(() => {
        const e = new Event("message");
        e.data = typeof m === "string" ? m : JSON.stringify(m);
        this.dispatchEvent(e);
      });
    }
    kill(code) {
      this.dead = true;
      queueMicrotask(() => {
        const e = new Event("close");
        e.code = code;
        this.dispatchEvent(e);
      });
    }
    close(code) {
      this.kill(code);
    }
    send(data) {
      if (this.dead) throw new Error("closed");
      if (data === "ping") return this.reply("pong");
      if (data.length > MAX_FRAME_BYTES) return this.kill(1009);
      const m = JSON.parse(data);
      if (m.t === "hello") {
        const stored = g.sessions.get(m.session);
        this.session = stored ?? { id: `s${g.nextId++}`, rx: 0 };
        g.sessions.set(this.session.id, this.session);
        return this.reply({ t: "welcome", v: 1, session: this.session.id, resumed: !!stored, rx_seq: this.session.rx, heartbeat_ms: 20000 });
      }
      if (m.t === "frame") {
        g.frames++;
        if (g.frames > dropAfterFrames && (!g.dropped || !dropOnce)) {
          g.dropped = true;
          return this.kill(1006); // a deploy: the frame in flight is lost
        }
        this.session.rx = Math.max(this.session.rx, m.seq);
        return this.reply({ t: "ack", seq: m.seq });
      }
    }
  }
  return { g, WebSocket: FakeWebSocket };
}

const opts = (WebSocket) => ({ WebSocket, url: "wss://gw.example/v1/connect", token: "dev:t:d" });
const instant = () => Promise.resolve();

test("limits: finds the 1 MiB cap and records the refusal close code", async () => {
  const { WebSocket } = fakeGateway();
  const r = await probeFrameLimits(opts(WebSocket));
  assert.equal(r.largestAccepted, MAX_FRAME_BYTES - 64);
  assert.equal(r.smallestRefused, MAX_FRAME_BYTES);
  const refused = r.results.filter((x) => !x.accepted);
  assert.ok(refused.length >= 1);
  assert.ok(refused.every((x) => x.closeCode === 1009));
});

test("limits: a gateway that accepts nothing reports no largest", async () => {
  const { WebSocket } = fakeGateway();
  const r = await probeFrameLimits(opts(WebSocket), [MAX_FRAME_BYTES + 1]);
  assert.equal(r.largestAccepted, null);
});

test("hibernation: reports cold and warm round trips and that the session resumes", async () => {
  const { WebSocket } = fakeGateway();
  const slept = [];
  const h = await probeHibernation(opts(WebSocket), [10, 60], { sleep: (ms) => (slept.push(ms), instant()) });
  assert.deepEqual(slept, [10_000, 60_000]);
  assert.equal(h.results.length, 2);
  for (const x of h.results) assert.ok(x.survived && x.coldMs >= 0 && x.warmMs >= 0);
  assert.equal(h.resume.resumed, true);
  assert.equal(h.resume.rxSeq, h.resume.expectedRxSeq);
});

test("hibernation: heartbeat mode pings every 20 s and expects pong", async () => {
  const { WebSocket, g } = fakeGateway();
  const slept = [];
  const h = await probeHibernation(opts(WebSocket), [50], { heartbeat: true, sleep: (ms) => (slept.push(ms), instant()) });
  assert.deepEqual(slept, [20_000, 20_000, 10_000]);
  assert.equal(h.heartbeat, true);
  assert.ok(g.sockets.length >= 2);
});

test("hibernation: a socket the platform closed is reported as not surviving", async () => {
  const { WebSocket, g } = fakeGateway();
  const h = await probeHibernation(opts(WebSocket), [30, 60], {
    sleep: async () => {
      g.sockets[0].kill(1001);
      await new Promise((r) => setTimeout(r, 1));
    },
  });
  assert.deepEqual(h.results, [{ idle: 30, survived: false, closeCode: 1001 }]);
});

test("hibernation: a lost session is reported as not resumed", async () => {
  const { WebSocket, g } = fakeGateway();
  const h = await probeHibernation(opts(WebSocket), [1], {
    sleep: async () => {
      g.sessions.clear();
    },
  });
  // The first connection kept its in-memory session; resuming by id finds nothing.
  assert.equal(h.resume.resumed, false);
});

test("deploy: a disconnect mid-run is retransmitted, nothing is lost or duplicated", async () => {
  const { WebSocket } = fakeGateway({ dropAfterFrames: 3 });
  let t = 0;
  const events = [];
  const d = await probeDeploy(opts(WebSocket), {
    durationMs: 10_000,
    intervalMs: 1000,
    clock: () => t,
    sleep: async (ms) => {
      t += ms;
      await new Promise((r) => setTimeout(r, 1));
    },
    onEvent: (e) => events.push(e),
  });
  assert.equal(d.disconnects.length, 1);
  assert.equal(d.disconnects[0].closeCode, 1006);
  assert.equal(d.disconnects[0].resumed, true);
  assert.ok(d.disconnects[0].retransmitted >= 1);
  assert.deepEqual(d.lost, []);
  assert.deepEqual(d.duplicateAcks, []);
  assert.equal(d.acknowledged, d.sent);
  assert.ok(events.some((e) => e.reconnected));
});

test("deploy: a frame the gateway never acknowledges is reported lost", async () => {
  const { WebSocket } = fakeGateway();
  const orig = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) {
    if (typeof data === "string" && data.includes('"seq":2')) return; // swallowed
    return orig.call(this, data);
  };
  let t = 0;
  const d = await probeDeploy(opts(WebSocket), {
    durationMs: 3000,
    intervalMs: 1000,
    clock: () => t,
    sleep: async (ms) => {
      t += ms;
      await new Promise((r) => setTimeout(r, 1));
    },
  });
  assert.deepEqual(d.lost, [2]);
});

test("openTunnel: a close before welcome rejects", async () => {
  class Dead extends EventTarget {
    constructor() {
      super();
      queueMicrotask(() => this.dispatchEvent(new Event("open")));
    }
    send() {
      queueMicrotask(() => {
        const e = new Event("close");
        e.code = 4400;
        this.dispatchEvent(e);
      });
    }
  }
  await assert.rejects(openTunnel({ WebSocket: Dead, url: "wss://x", token: "t" }), /closed 4400/);
});

test("cost: prices requests, WebSocket messages at 20:1, duration, rows and storage", () => {
  const p = { wsMessageRatio: 20, prices: { planPerMonth: 5, includedRequests: 0, perMillionRequests: 1, includedGbSeconds: 0, perMillionGbSeconds: 2, includedRowsRead: 0, perMillionRowsRead: 3, includedRowsWritten: 0, perMillionRowsWritten: 4, includedStorageGb: 0, perGbMonthStorage: 5 } };
  const e = estimateCost({ requests: 1e6, wsMessages: 20e6, durationSeconds: 1024e6, memoryMb: 128, rowsRead: 1e6, rowsWritten: 1e6, storageGb: 2 }, p);
  assert.equal(e.billedRequests, 2e6);
  assert.equal(e.gbSeconds, 128e6);
  assert.deepEqual(e.parts, { requests: 2, duration: 256, rowsRead: 3, rowsWritten: 4, storage: 10 });
  assert.equal(e.total, 280);
});

test("cost: included allowances are subtracted and never go negative", () => {
  const e = estimateCost({ requests: 10, wsMessages: 0, durationSeconds: 1, memoryMb: 128, rowsRead: 1, rowsWritten: 1, storageGb: 0 }, pricing);
  assert.equal(e.usageCost, 0);
  assert.equal(e.total, pricing.prices.planPerMonth);
});

test("cost: one hibernating device costs less than one awake all month", () => {
  const sleepy = perDeviceMonth({ messagesPerDay: 200, awakeSecondsPerDay: 60 }, pricing);
  const awake = perDeviceMonth({ messagesPerDay: 200, awakeSecondsPerDay: 86_400 }, pricing);
  assert.ok(awake.total > sleepy.total * 10);
  assert.equal(sleepy.planCost, 0);
});

test("pricing.json is marked unverified until someone fills in the source", () => {
  assert.match(pricing.pricingSource, /UNVERIFIED|developers\.cloudflare\.com/);
  assert.ok(pricing.pricingAsOf);
});

const GW = "https://gw.example.workers.dev";
const google = new URL("https://accounts.google.com/o/oauth2/v2/auth");
const entraUrl = (tid) => new URL(`https://login.microsoftonline.com/${tid}/oauth2/v2.0/authorize`);
const fill = (u, provider, over = {}) => {
  const q = { response_type: "code", client_id: "cid", redirect_uri: `${GW}/auth/${provider}/callback`, scope: "openid email", state: "s", nonce: "n", code_challenge: "c", code_challenge_method: "S256", ...over };
  for (const [k, v] of Object.entries(q)) if (v !== null) u.searchParams.set(k, v);
  return u.toString();
};
const cfg = { clientId: "cid", tenantId: "tid", gatewayOrigin: GW };

test("login redirect: accepts the real Google and Entra shapes", () => {
  assert.deepEqual(checkLoginRedirect("google", fill(new URL(google), "google"), cfg), { ok: true, problems: [] });
  assert.deepEqual(checkLoginRedirect("entra", fill(entraUrl("tid"), "entra"), cfg), { ok: true, problems: [] });
});

test("login redirect: names each thing that is wrong", () => {
  const bad = (provider, url, re) => {
    const r = checkLoginRedirect(provider, url, cfg);
    assert.equal(r.ok, false);
    assert.match(r.problems.join(";"), re);
  };
  bad("google", "not a url", /not a URL/);
  bad("google", fill(new URL(google), "google").replace("https:", "http:"), /not https/);
  bad("google", fill(new URL("https://evil.example/auth"), "google"), /host evil\.example/);
  bad("entra", fill(entraUrl("other"), "entra"), /configured tenant/);
  bad("google", fill(new URL(google), "google", { code_challenge_method: "plain" }), /code_challenge_method is wrong/);
  bad("google", fill(new URL(google), "google", { redirect_uri: "https://x/cb" }), /redirect_uri is wrong/);
  bad("google", fill(new URL(google), "google", { client_id: null }), /client_id is missing/);
  bad("google", fill(new URL(google), "google", { state: null, nonce: null, code_challenge: null }), /state missing;nonce missing;code_challenge missing/);
  bad("google", fill(new URL(google), "google", { scope: "email" }), /openid/);
});

test("report: a section with no data reads NOT RUN, never a pass", () => {
  const md = renderReport({});
  for (const h of ["Limits", "Hibernation timing", "Deploy-driven disconnects", "Costs", "Real logins"]) {
    assert.match(md, new RegExp(`### ${h}\\n\\nNOT RUN`));
  }
});

test("report: renders every section from results", async () => {
  const { WebSocket } = fakeGateway({ dropAfterFrames: 2 });
  let t = 0;
  const r = {
    when: "2026-11-02",
    gateway: "gw.example",
    limits: await probeFrameLimits(opts(WebSocket), [1024, MAX_FRAME_BYTES + 1]),
    hibernation: [await probeHibernation(opts(fakeGateway().WebSocket), [10], { sleep: instant })],
    deploy: await probeDeploy(opts(WebSocket), { durationMs: 4000, intervalMs: 1000, clock: () => t, sleep: async (ms) => ((t += ms), new Promise((x) => setTimeout(x, 1))) }),
    cost: { pricingSource: "src", pricingAsOf: "2026-11-02", estimate: estimateCost({ requests: 1, wsMessages: 0, durationSeconds: 0, memoryMb: 128, rowsRead: 0, rowsWritten: 0, storageGb: 0 }, pricing), perDevice: perDeviceMonth({ messagesPerDay: 1, awakeSecondsPerDay: 1 }, pricing) },
    logins: [{ provider: "google", redirect: "ok" }],
  };
  const md = renderReport(r);
  assert.match(md, /Largest accepted 1024 B \(1\.0 KiB\), smallest refused 1048577 B/);
  assert.match(md, /Resume after idle: yes/);
  assert.match(md, /lost 0, duplicate acks 0/);
  assert.match(md, /Prices from src \(2026-11-02\)/);
  assert.match(md, /\| google \| ok \| NOT RUN \| NOT RUN \|/);
});
