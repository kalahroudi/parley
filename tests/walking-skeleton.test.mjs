// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// The walking-skeleton journey (T405, spike 9) on macOS and Linux: a real MCP client (`parley-cli mcp`, speaking
// JSON-RPC over stdio) on one device finds a bot published by another device and calls it end to end through the
// real gateway (`wrangler dev`). Each device is its own process with its own home, keys and socket. The bot is a real
// program behind the CLI adapter and the bot host (tests/harness/botd), because parleyd has no bot configuration yet.
//  JD-02  find_agents, send_task, get_task: the result comes back, marked untrusted.
//  JE-02  the bot asks a question (INPUT_REQUIRED) and the answer goes on the same task.
//  cancel      a task the bot is working on is canceled; the bot's process is gone.
//  offline     a task sent to a stopped daemon waits (nothing at the gateway), and runs when the daemon returns.
//  expiry      a task whose recipient never returns fails (recipient offline) once its expiry passes, and the bot never runs it.
//  approval    a second bot holds each task for its owner, who answers `parley-cli approve` on a real pseudo-terminal
//              (tests/harness/ptyrun): shown the task, "no" keeps it waiting, deny rejects it, "yes" runs it; a process
//              without a terminal and a bot of the daemon's own cannot approve or deny (the bot never sees a task before approval).
//  refused     a device of another owner is refused by the bot daemon's own allowlist; the bot never runs it.
//  canary      none of the task, answer or question texts is in the gateway's storage or log, or in any daemon's log.
// Windows is not part of this test (tool-using skills and the walking skeleton are macOS and Linux for the MVP).

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Scan } from "./canary/canary.mjs";
import { signRevocations, startGateway } from "./harness/gateway.mjs";
import { build, capture, mcpClient, newTenant, post, repo, sleep, testOptions, waitFor } from "./harness/e2e.mjs";

const opts = process.platform === "win32" ? { ...testOptions(420000), skip: "macOS and Linux only" } : testOptions(420000);

test("JD-02 and JE-02, walking skeleton (T405): a real MCP client calls a bot on another device", opts, async () => {
  const { bin, exe } = build({ "parley-cli": "./cmd/parley-cli", parleyd: "./cmd/parleyd", botd: "./tests/harness/botd", ptyrun: "./tests/harness/ptyrun" });
  const gw = await startGateway({ admins: "acme:admin@acme.test" });
  const scratch = mkdtempSync(join(tmpdir(), "parley-skeleton-"));
  const botRuns = join(scratch, "runs"); // one pid file per bot process, written by the bot (harness/skeleton-bot.mjs)
  mkdirSync(botRuns);
  const botRuns2 = join(scratch, "runs-approval"); // the same for the bot that holds every task for its owner's approval
  mkdirSync(botRuns2);
  const children = [];
  let tenant;
  const random = () => randomBytes(8).toString("hex");
  const canary = { echo: `CANARY-echo-${random()}`, answer: `CANARY-answer-${random()}`, late: `CANARY-late-${random()}`, stranger: `CANARY-stranger-${random()}`, offline: `CANARY-offline-${random()}`, resent: `CANARY-resent-${random()}`, revoked: `CANARY-revoked-${random()}`, gated: `CANARY-gated-${random()}`, held: `CANARY-held-${random()}` };
  try {
    tenant = await newTenant(gw, exe);
    const { cli, enroll } = tenant;
    const caller = await enroll("svc-ci");
    const botHome = await enroll("svc-ci");
    const stranger = await enroll("svc-other");
    const botHome2 = await enroll("svc-ci");

    const run = (cmd, args, home) => {
      const p = capture(spawn(exe(cmd), args, { env: { ...process.env, PARLEY_HOME: home }, stdio: ["ignore", "pipe", "pipe"] }));
      children.push(p);
      return p;
    };
    const startBot = (home = botHome.home, runsDir = botRuns, extra = []) =>
      run("botd", ["-owner", "svc-ci", ...extra, "-command", process.execPath, "--", join(repo, "tests", "harness", "skeleton-bot.mjs"), runsDir], home);
    const stopBot = async (p) => {
      p.child.kill("SIGTERM");
      const r = await p.done;
      assert.equal(r.code, 0, `the bot daemon did not stop cleanly:\n${r.out}`);
    };
    const callerD = run("parleyd", [], caller.home);
    const strangerD = run("parleyd", [], stranger.home);
    let botD = startBot();
    await waitFor("the caller and stranger daemons to answer on their sockets", async () => {
      for (const d of [callerD, strangerD, botD]) assert.equal(d.child.exitCode, null, `a daemon exited early:\n${d.output()}`);
      return (await Promise.all([caller, stranger].map((d) => cli(d.home, ["list"]).done))).every((r) => r.code === 0);
    }, 450);

    // The MCP client: what an agent such as Claude Code starts.
    const startMcp = (home) => {
      const p = capture(spawn(exe("parley-cli"), ["mcp"], { env: { ...process.env, PARLEY_HOME: home }, stdio: ["pipe", "pipe", "pipe"] }));
      children.push(p);
      return mcpClient(p.child);
    };
    let mcp = startMcp(caller.home);
    const init = await mcp.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "walking-skeleton", version: "1" } });
    assert.equal(init.result.protocolVersion, "2025-06-18");
    mcp.notify("notifications/initialized");
    const listed = (await mcp.rpc("tools/list", {})).result.tools.map((t) => t.name).sort();
    assert.deepEqual(listed, ["cancel_task", "find_agents", "get_task", "list_tasks", "send_task"]);

    const finalStates = new Set(["TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"]);
    // Follows a task until `until(view)` holds, up to `seconds` (get_task waits at most 20 s a time).
    const follow = async (id, until, seconds = 90) => {
      const stop = Date.now() + seconds * 1000;
      for (;;) {
        const v = await mcp.tool("get_task", { task_id: id, wait_seconds: 5 });
        assert.equal(v.isError, false, v.text);
        if (until(v.json)) return v;
        assert.ok(Date.now() < stop, `the task did not get there; last view ${JSON.stringify({ ...v.json, content: undefined })}\n--- caller daemon\n${callerD.output()}\n--- bot daemon\n${botD.output()}`);
      }
    };
    const send = async (args) => {
      const s = await mcp.tool("send_task", args);
      assert.equal(s.isError, false, s.text);
      return s.json.task_id;
    };
    const runs = (verb) => readdirSync(botRuns).filter((f) => f.startsWith(`${verb}-`));
    const alive = (pid) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    const pidOf = (file) => Number(readFileSync(join(botRuns, file)));

    // Discover. The card was written by another device, so the client is told to treat it as data.
    const found = await waitFor("the bot's card in find_agents", async () => {
      const f = await mcp.tool("find_agents", { text: "skeleton" });
      return f.json.agents?.length ? f : null;
    });
    assert.ok(found.text.startsWith("UNTRUSTED CONTENT"), found.text);
    assert.equal(found.json.untrusted, true);
    assert.equal(found.json.agents[0].device_id, botHome.id);
    const agent = found.json.agents[0].id;

    // JD-02: call it, and read the result.
    const echoed = await follow(await send({ agent, text: `echo ${canary.echo}` }), (v) => finalStates.has(v.state));
    assert.equal(echoed.json.state, "TASK_STATE_COMPLETED");
    assert.equal(echoed.json.content, `bot heard: ${canary.echo}`);
    assert.equal(echoed.json.untrusted, true);
    assert.ok(echoed.text.startsWith("UNTRUSTED CONTENT"), "the result is marked untrusted for the model");

    // JE-02: the bot asks, the caller answers on the same task.
    const asked = await send({ agent, text: "ask" });
    const question = await follow(asked, (v) => v.state === "TASK_STATE_INPUT_REQUIRED");
    assert.equal(question.json.content_kind, "question");
    assert.equal(question.json.content, "which colour?");
    const answered = await mcp.tool("send_task", { task_id: asked, text: canary.answer });
    assert.equal(answered.isError, false, answered.text);
    const colour = await follow(asked, (v) => finalStates.has(v.state));
    assert.equal(colour.json.state, "TASK_STATE_COMPLETED");
    assert.equal(colour.json.content, `colour: ${canary.answer}`);

    // Cancel: the bot is working, the caller cancels, and the bot's process goes away.
    const hung = await send({ agent, text: "hang" });
    await follow(hung, (v) => v.state === "TASK_STATE_WORKING");
    await waitFor("the bot to start working", async () => runs("hang").length === 1);
    const [hangPid] = runs("hang").map(pidOf);
    assert.ok(alive(hangPid), "the bot is running");
    assert.equal((await mcp.tool("cancel_task", { task_id: hung })).isError, false);
    assert.equal((await follow(hung, (v) => finalStates.has(v.state))).json.state, "TASK_STATE_CANCELED");
    await waitFor("the canceled bot's process to end", async () => !alive(hangPid), 100);

    // Refused: a device of another owner is turned away by the bot daemon's own allowlist, and the bot never runs.
    const before = readdirSync(botRuns).length;
    const strangerMcp = startMcp(stranger.home);
    const sent = await strangerMcp.tool("send_task", { agent, text: `echo ${canary.stranger}` });
    assert.equal(sent.isError, false, sent.text);
    const refused = await waitFor("the stranger's task to end", async () => {
      const v = (await strangerMcp.tool("get_task", { task_id: sent.json.task_id, wait_seconds: 5 })).json;
      return finalStates.has(v.state) ? v : null;
    }, 200);
    assert.notEqual(refused.state, "TASK_STATE_COMPLETED");
    assert.equal(refused.content ?? "", "");
    assert.equal(readdirSync(botRuns).length, before, "the bot never ran the stranger's task");

    // Offline: the daemon is gone. The task waits at the caller, and runs when the daemon comes back.
    await stopBot(botD);
    const waiting = await send({ agent, text: `echo ${canary.offline}` });
    const w = await follow(waiting, (v) => v.waiting_for_recipient === true, 30);
    assert.equal(w.json.state, "TASK_STATE_SUBMITTED");
    botD = startBot();
    const back = await follow(waiting, (v) => finalStates.has(v.state), 120);
    assert.equal(back.json.state, "TASK_STATE_COMPLETED");
    assert.equal(back.json.content, `bot heard: ${canary.offline}`);

    // Expiry: the daemon is gone and stays away past the task's expiry; the task fails as expired and never runs.
    await stopBot(botD);
    const runsBefore = readdirSync(botRuns).length;
    const late = await send({ agent, text: `echo ${canary.late}`, expiry_seconds: 5 });
    const expired = await follow(late, (v) => finalStates.has(v.state), 60);
    assert.equal(expired.json.state, "TASK_STATE_FAILED");
    assert.equal(expired.json.reason, "recipient_offline"); // it waited for the recipient up to the task's expiry
    assert.ok(expired.json.updated_at >= expired.json.expires_at - 1, "it did not give up before the expiry");
    botD = startBot();
    await sleep(3000); // the daemon is back: the expired task must not be delivered now
    assert.equal(readdirSync(botRuns).length, runsBefore, "the expired task was not run");
    assert.equal((await mcp.tool("get_task", { task_id: late })).json.state, "TASK_STATE_FAILED");

    // Restart mid-conversation: the bot daemon restarts while a task is running. The task is lost with the daemon's
    // memory (by design: the bot's process ends and nothing re-runs it), the caller can cancel it, and a resend works
    // because the restarted daemon's fresh prekeys are used. The lost task is never run a second time.
    const mid = await send({ agent, text: "slow mid" });
    await follow(mid, (v) => v.state === "TASK_STATE_WORKING");
    await waitFor("the bot to start the slow task", async () => runs("slow").length === 1);
    const [slowPid] = runs("slow").map(pidOf);
    await stopBot(botD);
    await waitFor("the slow bot's process to end with its daemon", async () => !alive(slowPid), 100);
    botD = startBot();
    const resent = await follow(await send({ agent, text: `echo ${canary.resent}` }), (v) => finalStates.has(v.state), 120);
    assert.equal(resent.json.state, "TASK_STATE_COMPLETED");
    assert.equal(resent.json.content, `bot heard: ${canary.resent}`);
    assert.equal(runs("slow").length, 1, "the task lost in the restart was not run again");
    assert.equal(runs("echo").length, 3, "the first echo, the offline echo and the resend each ran exactly once (the expired one and the stranger's never)");
    assert.equal((await mcp.tool("cancel_task", { task_id: mid })).isError, false);
    assert.equal((await follow(mid, (v) => finalStates.has(v.state))).json.state, "TASK_STATE_CANCELED");

    // The caller's own list shows every task, with no content.
    const all = await mcp.tool("list_tasks", {});
    assert.equal(all.json.tasks.length, 7);
    assert.ok(all.json.tasks.every((t) => !("content" in t)));

    // Approval (T403 and T406): a second bot holds every task for its owner, who answers with `parley-cli approve`
    // on the bot's machine. That command asks on the controlling terminal and nowhere else, so the test types the answer
    // on a real pseudo-terminal (tests/harness/ptyrun); a process without a terminal cannot answer, and the daemon
    // refuses a bot of its own. A pending task never reaches its bot until it is approved.
    const botD2 = startBot(botHome2.home, botRuns2, ["-approval", "owner"]);
    const agent2 = (await waitFor("the approval bot's card in find_agents", async () => {
      assert.equal(botD2.child.exitCode, null, `the approval bot's daemon exited early:\n${botD2.output()}`);
      return (await mcp.tool("find_agents", { text: "skeleton" })).json.agents?.find((a) => a.device_id === botHome2.id);
    })).id;
    const ownerEnv = { ...process.env, PARLEY_HOME: botHome2.home };
    const pendingList = () =>
      new Promise((resolve, reject) =>
        execFile(exe("parley-cli"), ["approve"], { env: ownerEnv }, (err, stdout) => {
          try {
            resolve(JSON.parse(stdout).pending);
          } catch {
            reject(err ?? new Error(`approve printed no JSON: ${stdout}`));
          }
        }),
      );
    const pendingTask = (id) => waitFor(`task ${id} to wait for approval`, async () => (await pendingList()).find((p) => p.task_id === id), 300);
    // The owner at the terminal: ptyrun gives parley-cli a controlling terminal and types `answer` at the prompt.
    const atTerminal = (id, answer) => capture(spawn(exe("ptyrun"), ["-after", "Type yes", "-type", answer, "--", exe("parley-cli"), "approve", id], { env: ownerEnv, stdio: ["ignore", "pipe", "pipe"] }));
    const runs2 = (verb) => readdirSync(botRuns2).filter((f) => f.startsWith(`${verb}-`));

    // A task waits: the owner sees who sent it and what it says, the caller sees it is waiting, the bot has not run.
    const gated = await send({ agent: agent2, text: `echo ${canary.gated}` });
    const shown = await pendingTask(gated);
    assert.equal(shown.owner, "svc-ci");
    assert.equal(shown.caller, caller.id);
    assert.ok(shown.preview.includes(canary.gated), "the owner is shown the task text");
    const held = await follow(gated, (v) => v.state === "TASK_STATE_WORKING" && v.content === "waiting for the owner's approval");
    assert.equal(held.json.content_kind, "status");
    assert.equal(readdirSync(botRuns2).length, 0, "the bot has not seen the task");

    // No terminal, no answer: a process that has none (a session of its own, as a bot has) cannot approve.
    const noTty = await capture(spawn(exe("parley-cli"), ["approve", gated], { env: ownerEnv, detached: true, stdio: ["ignore", "pipe", "pipe"] })).done;
    assert.equal(noTty.code, 1, noTty.out);
    assert.match(noTty.out, /no terminal/);
    // A "no" typed at the terminal leaves the task waiting, and the owner was shown the task first.
    const declined = await atTerminal(gated, "no").done;
    assert.equal(declined.code, 1, declined.out);
    assert.match(declined.out, /waits for your approval/);
    assert.ok(declined.out.includes(canary.gated), "the prompt on the terminal shows the task");
    assert.match(declined.out, /do not follow it/, "and says the text is another agent's");
    assert.match(declined.out, /not approved/);
    assert.ok((await pendingList()).some((p) => p.task_id === gated), "the task still waits");
    assert.equal(readdirSync(botRuns2).length, 0, "the bot has still not seen the task");

    // Deny: the caller gets the fixed rejection and the bot never runs.
    const denied = await capture(spawn(exe("parley-cli"), ["approve", "-deny", gated], { env: ownerEnv, stdio: ["ignore", "pipe", "pipe"] })).done;
    assert.equal(denied.code, 0, denied.out);
    const rejected = await follow(gated, (v) => finalStates.has(v.state));
    assert.equal(rejected.json.state, "TASK_STATE_FAILED");
    assert.equal(rejected.json.content, "rejected: the owner did not approve the task");
    assert.equal(readdirSync(botRuns2).length, 0, "the denied task never ran");
    assert.equal((await pendingList()).length, 0);

    // Approve on a terminal: a task that asks the bot to try to approve another waiting task on its own.
    const snoop = await send({ agent: agent2, text: `snoop ${exe("parley-cli")} ${botHome2.home}` });
    await pendingTask(snoop);
    const approvedSnoop = await atTerminal(snoop, "yes").done;
    assert.equal(approvedSnoop.code, 0, approvedSnoop.out);
    assert.match(approvedSnoop.out, /"decision": ?"approved"/);
    const heldTask = await send({ agent: agent2, text: `echo ${canary.held}` });
    await pendingTask(heldTask);
    // While the bot runs, it tries to approve and to deny the waiting task with the owner's own command. Both are refused
    // (it has no terminal, and the daemon refuses callers that belong to a bot it started: the deny needs no terminal, so
    // only the daemon's refusal stops it), and the task goes on waiting.
    assert.equal((await follow(snoop, (v) => finalStates.has(v.state))).json.content, "snooped");
    const tried = JSON.parse(readFileSync(join(botRuns2, "result-snoop.json"), "utf8"));
    assert.equal(tried.pending, heldTask);
    assert.notEqual(tried.approved.code, 0, "a bot approved a task");
    assert.match(tried.approved.stderr, /no terminal/);
    assert.notEqual(tried.denied.code, 0, "a bot denied a task");
    assert.match(tried.denied.stderr, /not_permitted/);
    assert.ok((await pendingList()).some((p) => p.task_id === heldTask), "the task the bot tried to decide still waits");
    assert.equal(runs2("echo").length, 0, "the held task has not run");
    // The owner approves it at the terminal, and only then does it run, once.
    assert.equal((await atTerminal(heldTask, "yes").done).code, 0);
    const done2 = await follow(heldTask, (v) => finalStates.has(v.state));
    assert.equal(done2.json.state, "TASK_STATE_COMPLETED");
    assert.equal(done2.json.content, `bot heard: ${canary.held}`);
    assert.equal(runs2("echo").length, 1);
    assert.equal(runs2("snoop").length, 1);
    // The same task cannot be approved again.
    assert.equal((await atTerminal(heldTask, "yes").done).code, 1);

    // Revocation: the root revokes the bot's device. A daemon reads the list when it starts, so the caller's daemon
    // restarts and must now refuse to send to it; nothing reaches the bot.
    const revokedList = signRevocations(tenant.rootKey, { tenant: "acme", version: 2, revoked: [botHome.id] });
    assert.equal((await post(gw.url, "/v1/admin/revocations", tenant.admin, { list: revokedList })).status, 200);
    callerD.child.kill("SIGTERM");
    assert.equal((await callerD.done).code, 0, "the caller daemon stops cleanly");
    const callerD2 = run("parleyd", [], caller.home);
    await waitFor("the restarted caller daemon", async () => {
      assert.equal(callerD2.child.exitCode, null, `the caller daemon exited early:\n${callerD2.output()}`);
      return (await cli(caller.home, ["list"]).done).code === 0;
    }, 450);
    const echoesBefore = runs("echo").length;
    mcp = startMcp(caller.home);
    await mcp.rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "walking-skeleton", version: "1" } });
    mcp.notify("notifications/initialized");
    const sentRevoked = await mcp.tool("send_task", { agent, text: `echo ${canary.revoked}`, expiry_seconds: 5 });
    assert.equal(sentRevoked.isError, false, sentRevoked.text);
    const refusedRevoked = await follow(sentRevoked.json.task_id, (v) => finalStates.has(v.state), 60);
    assert.equal(refusedRevoked.json.state, "TASK_STATE_FAILED");
    assert.equal(refusedRevoked.json.reason, "recipient_not_found"); // not recipient_offline: the revoked device is not a recipient at all
    assert.equal(runs("echo").length, echoesBefore, "nothing reached the revoked device's bot");

    // Canary: no task, question or answer text is anywhere the gateway keeps or says anything, or in a daemon's log.
    const scan = new Scan({ ...canary, heard: "bot heard: ", colour: "colour: ", question: "which colour?" });
    scan.path(gw.state);
    scan.path(gw.log);
    for (const [i, d] of [callerD, callerD2, strangerD, botD, botD2].entries()) scan.bytes(`daemon ${i} output`, d.output());
    scan.assertClean();
    assert.ok(scan.sinks.length > 5, "the scan looked at the gateway's real state and log, not at nothing");
    const control = new Scan({ task: canary.echo });
    control.bytes("planted", `x ${canary.echo} y`);
    assert.equal(control.report().length, 1, "the scan can see the text it looks for");
  } finally {
    const codes = [];
    for (const c of children) {
      c.child.kill("SIGTERM");
      codes.push(await Promise.race([c.done.then((r) => r.code), sleep(15000).then(() => "hung")]));
      c.child.kill("SIGKILL");
    }
    await gw.close();
    const dirs = [bin, scratch, gw.state, gw.log, ...(tenant ? tenant.homes : [])];
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 }); // workerd may still hold a file for a moment after the gateway is killed (EBUSY on Windows)
    assert.deepEqual(codes.filter((c) => c !== 0 && c !== null), [], "a process did not shut down cleanly");
  }
});
