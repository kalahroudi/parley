// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// T308: what Cloudflare retains after we delete, and how R2 deletion behaves. `observe` drives the measurement
// Worker (worker: retention/entry.ts) through `call(path, body)` and returns booleans, sizes and timings only
// (the data it writes is random and is never returned). `judge` turns the observations into findings, each one
// confirmed, refuted or "not measured", so a run that could not measure something says so instead of passing.
//
// The Durable Object part needs real Cloudflare: the local runtime (`wrangler dev`, the vitest pool) returns an
// all-zero placeholder bookmark and restores nothing, so `observe` marks that case `placeholderBookmarks` and
// `judge` reports the Durable Object findings as not measured. The R2 part runs locally as a stand-in, but only a run
// against Cloudflare (`retention-run.mjs`, reality check 2) counts as verification: `judge` records `real`.
import { randomBytes } from "node:crypto";

const hex = (n = 12) => randomBytes(n).toString("hex");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const PLACEHOLDER_BOOKMARK = /^0{8}-0{8}-0{8}-0+$/;
const DAY = 24 * 3600 * 1000;

// `call(path, body)` resolves to the Worker's `result` or throws.
export async function observe(call, { real, ttlMs = 300, settleMs = 1500 } = {}) {
  const obs = { real: real === true, startedAt: new Date().toISOString(), do: {}, r2: {} };
  const vault = (name, op, ...args) => call("/__vault", { name, op, args });
  const holds = (state, key, value) => state.kv[key] === value || Object.values(state.sql).includes(value);

  // ---- Durable Object: delete, then restore from a bookmark taken before the delete.
  const name = `t308-${hex(6)}`;
  const kv = { key: "held:a", value: hex() };
  const sql = { key: "sql-a", value: hex() };
  await vault(name, "put", kv.key, kv.value);
  await vault(name, "putSql", sql.key, sql.value);
  const before = await vault(name, "bookmark");
  obs.do.placeholderBookmarks = PLACEHOLDER_BOOKMARK.test(before);
  await vault(name, "del", kv.key);
  await vault(name, "del", sql.key);
  const gone = await vault(name, "read");
  obs.do.deletedFromObject = !holds(gone, kv.key, kv.value) && !holds(gone, sql.key, sql.value);
  await vault(name, "restore", before);
  const back = await vault(name, "read");
  obs.do.restoredKv = back.kv[kv.key] === kv.value;
  obs.do.restoredSql = back.sql[sql.key] === sql.value;

  // The product's TTL path (an alarm deletes the held row), then deleteAll (the 90-day purge), then restore.
  const ttl = { key: "held:ttl", value: hex() };
  await vault(name, "holdWithTtl", ttl.key, ttl.value, ttlMs);
  const heldMark = await vault(name, "bookmark");
  await sleep(settleMs);
  obs.do.alarmDeleted = (await vault(name, "read")).kv[ttl.key] === undefined;
  await vault(name, "restore", heldMark);
  obs.do.restoredAfterAlarm = (await vault(name, "read")).kv[ttl.key] === ttl.value;
  await vault(name, "wipe");
  const wiped = await vault(name, "read");
  obs.do.wipedEmpty = Object.keys(wiped.kv).length === 0 && Object.keys(wiped.sql).length === 0;
  await vault(name, "restore", before);
  const afterWipe = await vault(name, "read");
  obs.do.restoredAfterWipe = holds(afterWipe, kv.key, kv.value) || holds(afterWipe, sql.key, sql.value);

  // Where the window ends: a time inside it works, one older than 30 days is refused.
  const probeAt = async (ms) => {
    try {
      return { ok: typeof (await vault(name, "bookmarkAt", ms)) === "string" };
    } catch (err) {
      return { ok: false, error: String(err.message).slice(0, 200) };
    }
  };
  obs.do.bookmarkRecent = await probeAt(Date.now() - 1000);
  obs.do.bookmark31Days = await probeAt(Date.now() - 31 * DAY);
  await vault(name, "wipe");

  // ---- R2: absence after delete through the API, and how long it takes.
  const prefix = `t308/${hex(6)}/`;
  const r2 = (op, body = {}) => call("/__r2", { op, ...body });
  const present = async (key) => ({
    head: (await r2("head", { key })) !== null,
    get: (await r2("get", { key })) !== null,
    listed: (await r2("list", { prefix })).keys.includes(key),
  });
  const absent = (p) => !p.head && !p.get && !p.listed;

  const k1 = `${prefix}one`;
  await r2("put", { key: k1, body: hex() });
  const seen = await present(k1);
  obs.r2.putVisible = seen.head && seen.get && seen.listed;
  await r2("delete", { key: k1 });
  obs.r2.deletedImmediately = absent(await present(k1));
  await sleep(settleMs);
  obs.r2.deletedAfterSettle = absent(await present(k1));
  try {
    await r2("delete", { key: k1 });
    await r2("delete", { key: `${prefix}never-existed` });
    obs.r2.deleteMissingIsNoop = true;
  } catch {
    obs.r2.deleteMissingIsNoop = false;
  }

  const k2 = `${prefix}over`;
  await r2("put", { key: k2, body: hex() });
  await r2("put", { key: k2, body: hex() });
  await r2("delete", { key: k2 });
  obs.r2.overwrittenThenDeleted = absent(await present(k2));

  const k3 = `${prefix}mpu`;
  const done = await r2("multipart", { key: k3 });
  obs.r2.multipartSize = done.size;
  await r2("delete", { key: k3 });
  obs.r2.multipartDeleted = absent(await present(k3));
  const k4 = `${prefix}mpu-abort`;
  await r2("multipart-abort", { key: k4 });
  obs.r2.abortedMultipartAbsent = absent(await present(k4));

  const batch = [0, 1, 2].map((i) => `${prefix}batch${i}`);
  for (const key of batch) await r2("put", { key, body: hex() });
  await r2("delete", { keys: batch });
  obs.r2.batchDeleted = (await r2("list", { prefix })).keys.length === 0;

  obs.finishedAt = new Date().toISOString();
  return obs;
}

const need = (o, group, keys) => keys.filter((k) => o[group]?.[k] === undefined);

// Findings in a fixed order. status: "confirmed" | "refuted" | "not measured" | "incomplete".
export function judge(obs) {
  const f = [];
  const add = (id, claim, status, detail) => f.push({ id, claim, status, detail });
  const doKeys = ["placeholderBookmarks", "deletedFromObject", "restoredKv", "restoredSql", "alarmDeleted", "restoredAfterAlarm", "wipedEmpty", "restoredAfterWipe", "bookmarkRecent", "bookmark31Days"];
  const r2Keys = ["putVisible", "deletedImmediately", "deletedAfterSettle", "deleteMissingIsNoop", "overwrittenThenDeleted", "multipartSize", "multipartDeleted", "abortedMultipartAbsent", "batchDeleted"];
  const missing = [...need(obs, "do", doKeys).map((k) => `do.${k}`), ...need(obs, "r2", r2Keys).map((k) => `r2.${k}`)];
  if (missing.length) {
    add("complete", "the run recorded every observation", "incomplete", `missing: ${missing.join(", ")}`);
    return { real: obs.real === true, findings: f };
  }
  const d = obs.do;
  const where = obs.real ? "on Cloudflare" : "in the local runtime only";

  if (d.placeholderBookmarks) {
    for (const [id, claim] of [
      ["do-restore-delete", "a row we deleted can be restored from a bookmark taken before the delete"],
      ["do-restore-alarm", "a row deleted by the TTL alarm can be restored from a bookmark"],
      ["do-restore-wipe", "data removed by deleteAll can be restored from a bookmark"],
      ["do-window", "the recovery window ends 30 days back"],
    ]) add(id, claim, "not measured", `the runtime returned a placeholder bookmark (${where}); only Cloudflare keeps history`);
  } else {
    const rec = (id, claim, deleted, restored) =>
      add(id, claim, !deleted ? "incomplete" : restored ? "confirmed" : "refuted", deleted ? (restored ? "deleted from the object, then readable again after the restore" : "deleted and not readable after the restore") : "the delete did not take effect, so the restore proves nothing");
    rec("do-restore-delete", "a row we deleted can be restored from a bookmark taken before the delete", d.deletedFromObject, d.restoredKv && d.restoredSql);
    rec("do-restore-alarm", "a row deleted by the TTL alarm can be restored from a bookmark", d.alarmDeleted, d.restoredAfterAlarm);
    rec("do-restore-wipe", "data removed by deleteAll can be restored from a bookmark", d.wipedEmpty, d.restoredAfterWipe);
    add(
      "do-window",
      "the recovery window ends 30 days back",
      d.bookmarkRecent.ok && !d.bookmark31Days.ok ? "confirmed" : "refuted",
      `a bookmark for one second ago ${d.bookmarkRecent.ok ? "was" : "was not"} issued; one for 31 days ago ${d.bookmark31Days.ok ? "was" : "was not"} issued${d.bookmark31Days.error ? ` (${d.bookmark31Days.error})` : ""}. The refusal shows where the window ends for new bookmarks; it does not show when stored history is physically erased`,
    );
  }

  const r = obs.r2;
  const gone = r.deletedImmediately && r.deletedAfterSettle && r.overwrittenThenDeleted && r.multipartDeleted && r.batchDeleted;
  add("r2-delete", "a deleted object is absent from head, get and list at once and stays absent", r.putVisible && gone ? "confirmed" : "refuted", `${where}; single, overwritten, multipart and batch deletes checked`);
  add("r2-delete-idempotent", "deleting an object that is not there is not an error", r.deleteMissingIsNoop ? "confirmed" : "refuted", where);
  add("r2-multipart", "an aborted multipart upload leaves no object", r.abortedMultipartAbsent && r.multipartSize >= 5 * 1024 * 1024 ? "confirmed" : "refuted", where);
  add("r2-physical", "R2 erases the bytes physically at delete time", "not measured", "not observable from the API; our claim stays \"deleted from our bucket\"");
  return { real: obs.real === true, findings: f };
}
