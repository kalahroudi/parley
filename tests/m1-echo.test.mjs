// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Milestone M1 (T414) end to end against the real gateway (`wrangler dev`, real Durable Objects, a mock IdP): real
// `parleyd` processes and the real `parley-cli`. The test plays the admin: it registers the root, posts the signed
// revocation list, and approves each device and posts its root-signed binding. Nothing in the daemons is injected:
// they connect with connect tokens, find each other's bindings through the gateway, exchange prekeys over the live
// relay, and `parley-cli test` sends a sealed task to the other daemon's test bot and checks the sealed echo.
//  1. Two devices of one owner: the test passes.
//  2. A device of another owner: the test bot refuses it (the target's own allowlist), the test fails, and the
//     bot of the owner's other device never sees it.
//  3. A device id the gateway does not know: the test fails at once.
//  4. A daemon that is not running: the test says so.
//  5. A device the root has revoked cannot be echoed to.
//  6. The gateway's storage and log hold none of the plaintext (the canary scan), and both daemons shut down cleanly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { Scan } from "./canary/canary.mjs";
import { signRevocations, startGateway } from "./harness/gateway.mjs";
import { build, capture, isWindows, newTenant, post, sleep, testOptions, waitFor } from "./harness/e2e.mjs";

const opts = testOptions(240000);

test("M1/T414: parley-cli test between two real daemons through the real gateway", opts, async (t) => {
  const { bin, exe } = build({ "parley-cli": "./cmd/parley-cli", parleyd: "./cmd/parleyd" });
  const gw = await startGateway({ admins: "acme:admin@acme.test" });
  const daemons = [];
  let homes = [];
  try {
    const { admin, rootKey, cli, enroll, homes: h } = await newTenant(gw, exe);
    homes = h;
    const startDaemon = (d) => {
      const p = capture(spawn(exe("parleyd"), [], { env: { ...process.env, PARLEY_HOME: d.home }, stdio: ["ignore", "pipe", "pipe"] }));
      daemons.push(p);
      return p;
    };

    const a = await enroll("svc-ci");
    const b = await enroll("svc-ci");
    const c = await enroll("svc-other");
    const r = await enroll("svc-ci");
    // The root revokes r before any daemon starts: every daemon's first revocation list names it.
    const revoked = signRevocations(rootKey, { tenant: "acme", version: 2, revoked: [r.id] });
    assert.equal((await post(gw.url, "/v1/admin/revocations", admin, { list: revoked })).status, 200);

    // 4. No daemon is running yet: the test says so, and does not hang.
    const down = await cli(a.home, ["test", "-to", b.id]).done;
    assert.equal(down.code, 1, down.out);
    assert.match(down.out, /not running or not reachable/);

    const [da, db, dc] = [startDaemon(a), startDaemon(b), startDaemon(c)];
    // Ready when each daemon answers its local socket. The socket file is not looked for: on Windows it is an AF_UNIX
    // socket that Node's file checks cannot see. A daemon that died says why instead of the wait timing out.
    await waitFor("the daemons to answer on their sockets", async () => {
      for (const d of daemons) assert.equal(d.child.exitCode, null, `a daemon exited early (${d.child.exitCode}):\n${d.output()}`);
      return (await Promise.all([a, b, c].map((d) => cli(d.home, ["list"]).done))).every((r) => r.code === 0);
    }, 450);

    // 1. Two devices of one owner.
    const pass = await cli(a.home, ["test", "-to", b.id, "-timeout", "90s"]).done;
    assert.equal(pass.code, 0, `${pass.out}\n--- a\n${da.output()}\n--- b\n${db.output()}`);
    assert.match(pass.out, /PASS: the other device answered, end to end encrypted/);
    // And back the other way, from the second device.
    const back = await cli(b.home, ["test", "-to", a.id, "-timeout", "90s"]).done;
    assert.equal(back.code, 0, back.out);

    // 2. Another owner's device is refused by the target's own allowlist.
    const refused = await cli(c.home, ["test", "-to", b.id, "-timeout", "30s"]).done;
    assert.equal(refused.code, 1, refused.out);
    assert.match(refused.out, /FAIL/);
    assert.match(refused.out, /owner/);
    assert.doesNotMatch(refused.out, /PASS/);

    // 3. A device the gateway does not know.
    const unknown = await cli(a.home, ["test", "-to", "f".repeat(32), "-timeout", "30s"]).done;
    assert.equal(unknown.code, 1, unknown.out);
    assert.match(unknown.out, /FAIL/);

    // 5. A revoked device of the same owner is refused, and never echoes.
    const gone = await cli(a.home, ["test", "-to", r.id, "-timeout", "30s"]).done;
    assert.equal(gone.code, 1, gone.out);
    assert.match(gone.out, /FAIL/);
    assert.match(gone.out, /does not know that device/);
    assert.doesNotMatch(gone.out, /PASS/);

    // Nothing the daemons log carries a task text or a key.
    for (const d of [da, db, dc]) assert.doesNotMatch(d.output(), /parley-test [0-9a-f]{32}|parley echo/);

    // 6. Every task text starts "parley-test " and every answer "parley echo: ": neither may be anywhere the gateway
    // keeps or says anything, in any encoding (a sealed message is random bytes; a plaintext leak is a hit).
    const scan = new Scan({ task: "parley-test ", answer: "parley echo: " });
    scan.path(gw.state);
    scan.path(gw.log);
    scan.bytes("the CLI output", pass.out); // control: the CLI itself does not print the text either
    scan.assertClean();
    assert.ok(scan.sinks.length > 5 && readFileSync(gw.log).length > 0, "the scan looked at the gateway's real state and log, not at nothing");
    const control = new Scan({ task: "parley-test " });
    control.bytes("planted", "x parley-test y");
    assert.equal(control.report().length, 1, "the scan can see the text it looks for");
  } finally {
    // Clean shutdown: a daemon stops on SIGTERM within its own timeout (Windows has no such signal: it is killed).
    const codes = [];
    for (const d of daemons) {
      d.child.kill("SIGTERM");
      codes.push(await Promise.race([d.done.then((r) => r.code), sleep(15000).then(() => "hung")]));
      d.child.kill("SIGKILL");
    }
    await gw.close();
    for (const dir of [bin, ...homes, gw.state, gw.log]) rmSync(dir, { recursive: true, force: true });
    if (!isWindows) assert.deepEqual(codes.filter((c) => c !== 0 && c !== null), [], "a daemon did not shut down cleanly");
  }
});
