// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Queued retention with real daemons (T405): the caller's connection drops while a task runs, the bot's result is
// held at the gateway (sealed) for the tenant's TTL, and
//  - control: a caller that is back inside the TTL receives the result;
//  - the TTL passes before the caller is back: the caller reconnects and receives nothing, and the task is not
//    completed from what the gateway knows (the gateway's state code is a hint; only a signed message completes it).
// The shortest TTL a tenant can set is 15 minutes, so this takes about 17 minutes of real time. It is not part of
// `node --test tests/**/*.test.mjs`; `make queued-ttl` runs it, on macOS and Linux.
// The caller's gateway_url points at a TCP proxy (tests/harness/e2e.mjs, cuttableProxy) so the test can cut its
// connection and restore it while the daemon keeps running; every other process talks to the gateway directly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGateway } from "../harness/gateway.mjs";
import { build, capture, cuttableProxy, mcpClient, newTenant, post, repo, sleep, testOptions, waitFor } from "../harness/e2e.mjs";

const TTL_MS = 15 * 60_000; // the shortest Queued TTL the gateway accepts
const opts = process.platform === "win32" ? { ...testOptions(30 * 60_000), skip: "macOS and Linux only" } : testOptions(30 * 60_000);

test("T405: Queued TTL deletion with a real daemon whose connection drops", opts, async () => {
  const { bin, exe } = build({ "parley-cli": "./cmd/parley-cli", parleyd: "./cmd/parleyd", botd: "./tests/harness/botd" });
  const gw = await startGateway({ admins: "acme:admin@acme.test" });
  const scratch = mkdtempSync(join(tmpdir(), "parley-queued-ttl-"));
  const runs = join(scratch, "runs");
  mkdirSync(runs);
  const children = [];
  let tenant, proxy;
  try {
    tenant = await newTenant(gw, exe);
    const { admin, cli, enroll } = tenant;
    const set = await post(gw.url, "/v1/admin/retention/put", admin, { mode: "queued", queue_ttl_ms: TTL_MS });
    assert.equal(set.status, 200, JSON.stringify(set.body));
    const caller = await enroll("svc-ci");
    const botHome = await enroll("svc-ci");

    proxy = await cuttableProxy(Number(new URL(gw.url).port));
    const cfgPath = join(caller.home, "config.json");
    writeFileSync(cfgPath, JSON.stringify({ ...JSON.parse(readFileSync(cfgPath, "utf8")), gateway_url: proxy.url }));

    const run = (cmd, args, home) => {
      const p = capture(spawn(exe(cmd), args, { env: { ...process.env, PARLEY_HOME: home }, stdio: ["ignore", "pipe", "pipe"] }));
      children.push(p);
      return p;
    };
    const callerD = run("parleyd", [], caller.home);
    const botD = run("botd", ["-owner", "svc-ci", "-command", process.execPath, "--", join(repo, "tests", "harness", "skeleton-bot.mjs"), runs], botHome.home);
    await waitFor("the caller daemon to answer on its socket", async () => {
      for (const d of [callerD, botD]) assert.equal(d.child.exitCode, null, `a daemon exited early:\n${d.output()}`);
      return (await cli(caller.home, ["list"]).done).code === 0;
    }, 450);
    const mcpProc = capture(spawn(exe("parley-cli"), ["mcp"], { env: { ...process.env, PARLEY_HOME: caller.home }, stdio: ["pipe", "pipe", "pipe"] }));
    children.push(mcpProc);
    const mcp = mcpClient(mcpProc.child);
    await mcp.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "queued-ttl", version: "1" } });
    const agent = (await waitFor("the bot's card", async () => {
      const f = await mcp.tool("find_agents", { text: "skeleton" });
      return f.json.agents?.length ? f : null;
    })).json.agents[0].id;

    const view = async (id, wait = 0) => (await mcp.tool("get_task", { task_id: id, wait_seconds: wait })).json;
    const send = async (text, expiry_seconds) => {
      const s = await mcp.tool("send_task", { agent, text, expiry_seconds });
      assert.equal(s.isError, false, s.text);
      return s.json.task_id;
    };
    const release = (name) => writeFileSync(join(runs, `release-${name}`), "");
    // The bot has the task and is working on it (its process exists), and the caller is cut off.
    const running = async (id, name) => {
      await waitFor(`the bot to start ${name}`, async () => (await view(id)).state === "TASK_STATE_WORKING");
      proxy.cut();
      await sleep(2000);
    };

    // Control: the result is held while the caller is away, and delivered when it is back inside the TTL.
    const near = await send("slow near", 3600);
    await running(near, "near");
    release("near");
    await sleep(5000); // the bot answers; the gateway holds the sealed result
    proxy.restore();
    const got = await waitFor("the held result to arrive", async () => {
      const v = await view(near, 5);
      return v.state === "TASK_STATE_COMPLETED" ? v : null;
    }, 400);
    assert.equal(got.content, "bot heard: near");

    // The TTL case: the caller stays away past the TTL.
    const far = await send("slow far", 3600);
    await running(far, "far");
    release("far");
    await sleep(5000);
    await sleep(TTL_MS + 60_000); // the TTL, and a minute for the gateway's alarm to delete the sealed result
    proxy.restore();
    await sleep(30_000); // the daemon reconnects (backoff) and would be handed anything still held
    const reconnected = await mcp.tool("list_tasks", {});
    assert.equal(reconnected.isError, false);
    const after = await view(far, 5);
    assert.notEqual(after.state, "TASK_STATE_COMPLETED", "the task was completed from stale data");
    // The only thing it has is the status the bot sent while the caller was still connected; the result never came.
    assert.notEqual(after.content_kind, "result", "the caller received the result after the TTL");
    assert.ok(!(after.content ?? "").includes("bot heard"), "the caller received the result after the TTL");
    assert.ok(!callerD.output().includes("bot heard"), "the caller's log carries no answer");
    // What the caller can still do with it is not asserted here; it stays in WORKING until its expiry.
    console.log("cancel_task after the TTL:", (await mcp.tool("cancel_task", { task_id: far })).text);
  } finally {
    for (const c of children) {
      c.child.kill("SIGTERM");
      await Promise.race([c.done, sleep(15000)]);
      c.child.kill("SIGKILL");
    }
    await proxy?.close();
    await gw.close();
    for (const dir of [bin, scratch, gw.state, gw.log, ...(tenant ? tenant.homes : [])]) rmSync(dir, { recursive: true, force: true });
  }
});
