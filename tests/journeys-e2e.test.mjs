// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T509: journeys that run end to end on macOS, Linux and Windows, with real `parleyd`-based daemons and the real
// gateway (`wrangler dev`). Nothing here needs a pseudo-terminal, so the same file runs on all three systems.
//  JH-01  Pods: an admin-minted single-use token enrolls a headless device under a named service owner; the binding is
//         signed by the root and posted by the admin; the token cannot be used a second time; the pod then publishes a
//         bot that another pod of the same owner calls; the canary scan of the gateway and daemon output is clean.
// Journeys that depend on tasks not built yet (admin page, billing, auto-update, install channels, the owner's call
// log and the admin kill-switch) are named pending tests in tests/pending-t509.test.mjs.
// (The admin's daemon does not sign bindings yet; as in the other end-to-end tests, the test holds the root key and
// plays the admin.)

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Scan } from "./canary/canary.mjs";
import { signBinding, startGateway } from "./harness/gateway.mjs";
import { build, capture, newTenant, post, repo, sleep, testOptions, waitFor } from "./harness/e2e.mjs";

test("JH-01, pods (T509): single-use token, named service owner, root-signed binding, token reuse fails", testOptions(300000), async () => {
  const { bin, exe } = build({ "parley-cli": "./cmd/parley-cli", parleyd: "./cmd/parleyd", botd: "./tests/harness/botd" });
  const gw = await startGateway({ admins: "acme:admin@acme.test" });
  const scratch = mkdtempSync(join(tmpdir(), "parley-pods-"));
  const botRuns = join(scratch, "runs");
  mkdirSync(botRuns);
  const children = [];
  let tenant;
  const canary = `CANARY-pod-${randomBytes(8).toString("hex")}`;
  try {
    tenant = await newTenant(gw, exe);
    const { admin, rootKey, fp, cli, enroll } = tenant;
    const OWNER = "svc-ci";

    // Enrolling by hand, to keep one token for a second try. The token names the owner; the request carries it.
    const token = (await post(gw.url, "/v1/admin/enrollment-tokens", admin, { owner: OWNER })).body.token;
    assert.ok(token, "the admin minted a token");
    const enrollArgs = ["enroll", "-token", "-gateway", gw.url, "-tenant", "acme", "-root", fp, "-key-store", "file"];
    const home = mkdtempSync(join(tmpdir(), "parley-home-"));
    tenant.homes.push(home);
    const first = cli(home, [...enrollArgs, "-name", "pod-first"], { PARLEY_ENROLL_TOKEN: token });
    const req = await waitFor("the pod's enrollment request", async () => (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending?.find((p) => p.name === "pod-first"));
    assert.equal(req.kind, "pod");
    assert.equal(req.owner, OWNER, "the pod enrolls under the named service owner, not under a person");
    assert.equal((await post(gw.url, "/v1/admin/enrollments/decide", admin, { id: req.id, decision: "approved" })).status, 200);
    const binding = signBinding(rootKey, { tenant: "acme", owner: OWNER, id: req.id, publicKey: Buffer.from(req.signing_key, "base64") });
    assert.equal((await post(gw.url, "/v1/admin/bindings", admin, { id: req.id, binding })).status, 200);
    const done = await first.done;
    assert.equal(done.code, 0, done.out);
    assert.ok(!done.out.includes(token), "the token is never printed");
    assert.equal(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).device_id, req.id);
    assert.ok(existsSync(join(home, "bindings.json")), "the signed binding is stored on the pod");

    // Token reuse fails, and leaves no request for the admin to approve and no identity on disk.
    const home2 = mkdtempSync(join(tmpdir(), "parley-home-"));
    tenant.homes.push(home2);
    const reused = await cli(home2, [...enrollArgs, "-name", "pod-reuse"], { PARLEY_ENROLL_TOKEN: token }).done;
    assert.notEqual(reused.code, 0, `a used token enrolled a second device:\n${reused.out}`);
    assert.equal(existsSync(join(home2, "config.json")), false);
    const left = (await post(gw.url, "/v1/admin/enrollments", admin, {})).body.pending ?? [];
    assert.deepEqual(left.filter((p) => p.name === "pod-reuse" && !p.decided), [], "a used token left a pending request");

    // The enrolled pods work: a bot on the first pod, called from a second pod of the same service owner.
    const botHome = { home, id: req.id };
    const caller = await enroll(OWNER);
    const run = (cmd, args, h) => {
      const p = capture(spawn(exe(cmd), args, { env: { ...process.env, PARLEY_HOME: h }, stdio: ["ignore", "pipe", "pipe"] }));
      children.push(p);
      return p;
    };
    const botD = run("botd", ["-owner", OWNER, "-command", process.execPath, "--", join(repo, "tests", "harness", "skeleton-bot.mjs"), botRuns], botHome.home);
    const callerD = run("parleyd", [], caller.home);
    await waitFor("the caller pod's daemon", async () => {
      for (const d of [callerD, botD]) assert.equal(d.child.exitCode, null, `a daemon exited early:\n${d.output()}`);
      return (await cli(caller.home, ["list"]).done).code === 0;
    }, 450);
    const found = await waitFor("the bot's card", async () => {
      const f = await cli(caller.home, ["find", "skeleton"]).done;
      assert.equal(f.code, 0, f.out);
      return JSON.parse(f.out.slice(f.out.indexOf("{"))).agents?.[0];
    }, 450);
    assert.equal(found.device_id, botHome.id);
    const sent = await cli(caller.home, ["send", "-to", found.id, `echo ${canary}`]).done;
    assert.equal(sent.code, 0, sent.out);
    const taskId = JSON.parse(sent.out.slice(sent.out.indexOf("{"))).task_id;
    const result = await waitFor("the pod's result", async () => {
      const g = await cli(caller.home, ["get", taskId, "-wait", "5s"]).done;
      assert.equal(g.code, 0, g.out);
      const v = JSON.parse(g.out.slice(g.out.indexOf("{")));
      return v.state === "TASK_STATE_COMPLETED" ? v : null;
    }, 400);
    assert.equal(result.content, `bot heard: ${canary}`);
    assert.equal(result.untrusted, true);

    const scan = new Scan({ task: canary, heard: "bot heard: " });
    scan.path(gw.state);
    scan.path(gw.log);
    for (const [i, d] of [callerD, botD].entries()) scan.bytes(`daemon ${i} output`, d.output());
    scan.assertClean();
    assert.ok(scan.sinks.length > 2, "the scan looked at the gateway's real state and log");
    const control = new Scan({ task: canary });
    control.bytes("planted", `x ${canary} y`);
    assert.equal(control.report().length, 1, "the scan can see the text it looks for");
  } finally {
    const codes = [];
    for (const c of children) {
      c.child.kill("SIGTERM");
      codes.push(await Promise.race([c.done.then((r) => r.code), sleep(15000).then(() => "hung")]));
      c.child.kill("SIGKILL");
    }
    await gw.close();
    for (const dir of [bin, scratch, gw.state, gw.log, ...(tenant ? tenant.homes : [])]) rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    assert.deepEqual(codes.filter((c) => c !== 0 && c !== null), [], "a process did not shut down cleanly");
  }
});
