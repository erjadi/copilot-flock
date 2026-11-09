import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { readPrivateJson, writePrivateJson } from "./zero-broker-roster.mjs";

export const LEGACY_MUTATION_PROTOCOL = "copilot-flock/legacy-mutation-admission/v1";
export const LEGACY_ADMISSION_CAPACITY = 100000;
export const LEGACY_REPLAY_CLOCK_ALLOWANCE_MS = 300000;

function requireState(condition, code, message) {
  if (!condition) throw Object.assign(new Error(message), { code });
}

function locations(home, receiverKey) {
  requireState(typeof home === "string" && path.isAbsolute(home) && /^[0-9a-f]{64}$/.test(receiverKey),
    "RPC_ADMISSION_INPUT_INVALID", "Invalid local admission identity or directory");
  return {
    anchors: path.join(home, "legacy-rpc-admission-anchors"),
    directory: path.join(home, "legacy-rpc-admissions", receiverKey),
    anchorName: `${receiverKey}.json`,
  };
}

function openAdmissionStore({ home, receiverKey, nowMs, initialize = false, allowFirstInitialization = false }) {
  const where = locations(home, receiverKey);
  const anchorPath = path.join(where.anchors, where.anchorName);
  const file = path.join(where.directory, "state.sqlite");
  const hasAnchor = fs.existsSync(anchorPath);
  const hasFile = fs.existsSync(file);
  if (!hasAnchor || !hasFile) {
    requireState(initialize && allowFirstInitialization && !hasAnchor && !hasFile &&
      !fs.existsSync(path.join(where.directory, "binding.json")),
    "RPC_ADMISSION_STATE_REQUIRED", "Legacy admission state is missing or incomplete; restore it or perform an explicitly approved coherent upgrade, never reset it under an existing key");
    const binding = { protocol: LEGACY_MUTATION_PROTOCOL, receiverKey, ledgerId: crypto.randomUUID() };
    writePrivateJson(where.directory, "binding.json", binding, { exclusive: true });
    fs.closeSync(fs.openSync(file, "wx", 0o600));
    const created = new DatabaseSync(file);
    try {
      created.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE; CREATE TABLE binding (protocol TEXT NOT NULL,receiver TEXT NOT NULL,ledger TEXT NOT NULL,last_clock INTEGER NOT NULL); CREATE TABLE admissions (flock TEXT NOT NULL,receiver TEXT NOT NULL,sender TEXT NOT NULL,request TEXT NOT NULL,action TEXT NOT NULL,digest TEXT NOT NULL,deadline INTEGER NOT NULL,retain_until INTEGER NOT NULL,outcome TEXT NOT NULL,PRIMARY KEY(flock,receiver,sender,request));");
      created.prepare("INSERT INTO binding VALUES (?,?,?,?)").run(binding.protocol, receiverKey, binding.ledgerId, nowMs);
      created.exec("COMMIT");
    } finally { created.close(); }
    writePrivateJson(where.anchors, where.anchorName, binding, { exclusive: true });
  }
  requireState(!fs.lstatSync(file).isSymbolicLink() && !fs.lstatSync(where.directory).isSymbolicLink(),
    "RPC_ADMISSION_STATE_INVALID", "Legacy admission storage cannot be a symbolic link");
  const anchor = readPrivateJson(where.anchors, where.anchorName);
  const binding = readPrivateJson(where.directory, "binding.json");
  requireState(anchor.protocol === LEGACY_MUTATION_PROTOCOL && anchor.receiverKey === receiverKey &&
    anchor.ledgerId === binding.ledgerId && binding.protocol === anchor.protocol && binding.receiverKey === receiverKey,
  "RPC_ADMISSION_STATE_INVALID", "Legacy admission anchor or identity binding changed; no state reset was performed");
  const db = new DatabaseSync(file);
  try {
    db.exec("PRAGMA busy_timeout=1000; PRAGMA synchronous=FULL");
    requireState(db.prepare("PRAGMA journal_mode").get().journal_mode === "wal",
      "RPC_ADMISSION_STATE_INVALID", "Legacy admission database lost its durable journal mode");
    const saved = db.prepare("SELECT * FROM binding").all();
    requireState(saved.length === 1 && saved[0].protocol === anchor.protocol &&
      saved[0].receiver === receiverKey && saved[0].ledger === anchor.ledgerId && Number.isSafeInteger(saved[0].last_clock),
    "RPC_ADMISSION_STATE_INVALID", "Legacy admission database does not match its durable anchor");
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

function validateClaim(value, nowMs) {
  for (const key of ["flock", "receiver", "sender", "request", "action"]) {
    requireState(typeof value[key] === "string" && value[key].length > 0 && value[key].length <= 256,
      "RPC_ADMISSION_INPUT_INVALID", "Invalid trusted admission coordinates");
  }
  requireState(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.ledgerId) &&
    /^[0-9a-f]{64}$/.test(value.digest) && Number.isSafeInteger(value.deadline) &&
    value.deadline > nowMs && value.deadline <= nowMs + 2 * 86400000 + LEGACY_REPLAY_CLOCK_ALLOWANCE_MS,
  "RPC_ADMISSION_INPUT_INVALID", "Invalid signed admission digest or deadline");
}

export function legacyAdmissionOperation(input) {
  requireState(["initialize", "inspect", "claim", "complete"].includes(input.operation),
    "RPC_ADMISSION_INPUT_INVALID", "Unknown local admission operation");
  const nowMs = input.nowMs ?? Date.now();
  requireState(Number.isSafeInteger(nowMs), "RPC_ADMISSION_INPUT_INVALID", "Invalid admission clock");
  if (["claim", "complete"].includes(input.operation)) validateClaim(input, input.operation === "claim" ? nowMs : Math.min(nowMs, input.deadline - 1));
  const db = openAdmissionStore({
    home: input.home, receiverKey: input.receiverKey, nowMs,
    initialize: input.operation === "initialize", allowFirstInitialization: input.allowFirstInitialization === true,
  });
  try {
    const { ledger } = db.prepare("SELECT ledger FROM binding").get();
    if (["initialize", "inspect"].includes(input.operation)) {
      return { initialized: true, protocol: LEGACY_MUTATION_PROTOCOL, ledgerId: ledger };
    }
    requireState(input.ledgerId === ledger, "RPC_ADMISSION_LEDGER_CHANGED",
      "Receiver admission incarnation changed; captured requests cannot be rebound or automatically retried");
    db.exec("BEGIN IMMEDIATE");
    try {
      const { last_clock: lastClock } = db.prepare("SELECT last_clock FROM binding").get();
      requireState(nowMs + LEGACY_REPLAY_CLOCK_ALLOWANCE_MS >= lastClock, "RPC_ADMISSION_CLOCK_ROLLBACK",
        "Admission clock moved behind its durable bound; no mutation or replay-state reset occurred");
      db.prepare("UPDATE binding SET last_clock=?").run(Math.max(nowMs, lastClock));
      if (input.operation === "claim") {
        db.prepare("DELETE FROM admissions WHERE retain_until<?").run(nowMs);
        const row = db.prepare("SELECT * FROM admissions WHERE flock=? AND receiver=? AND sender=? AND request=?")
          .get(input.flock, input.receiver, input.sender, input.request);
        if (row) {
          requireState(row.action === input.action && row.digest === input.digest && row.deadline === input.deadline,
            "RPC_ADMISSION_ID_REUSED", "Signed request ID was reused with different action, payload or deadline");
          throw Object.assign(new Error(`Signed request already has a durable ${row.outcome} admission; no redispatch occurred`),
            { code: "RPC_REQUEST_REPLAY" });
        }
        requireState(db.prepare("SELECT COUNT(*) AS count FROM admissions").get().count < LEGACY_ADMISSION_CAPACITY,
          "RPC_ADMISSION_CAPACITY", "Legacy admission capacity exhausted; no unexpired claim was evicted");
        db.prepare("INSERT INTO admissions VALUES (?,?,?,?,?,?,?,?,'UNKNOWN')").run(input.flock, input.receiver,
          input.sender, input.request, input.action, input.digest, input.deadline,
          input.deadline + LEGACY_REPLAY_CLOCK_ALLOWANCE_MS);
      } else {
        requireState(["COMPLETED", "UNKNOWN"].includes(input.outcome),
          "RPC_ADMISSION_INPUT_INVALID", "Invalid durable admission outcome");
        const changed = db.prepare("UPDATE admissions SET outcome=? WHERE flock=? AND receiver=? AND sender=? AND request=? AND action=? AND digest=? AND deadline=? AND outcome='UNKNOWN'")
          .run(input.outcome, input.flock, input.receiver, input.sender, input.request, input.action, input.digest, input.deadline);
        requireState(changed.changes === 1, "RPC_ADMISSION_STATE_INVALID", "Cannot complete an absent, replaced or terminal admission");
      }
      db.exec("COMMIT");
      return { admitted: true, outcome: input.operation === "claim" ? "UNKNOWN" : input.outcome };
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  } finally { db.close(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const raw = fs.readFileSync(0, "utf8");
    requireState(Buffer.byteLength(raw) <= 16384, "RPC_ADMISSION_INPUT_INVALID", "Oversized local admission command");
    console.log(JSON.stringify({ ok: true, ...legacyAdmissionOperation(JSON.parse(raw)) }));
  } catch (error) {
    console.log(JSON.stringify({ ok: false, code: error.code?.startsWith("RPC_") ? error.code : "RPC_ADMISSION_STORAGE_ERROR",
      error: error.code?.startsWith("RPC_") ? error.message : "Legacy admission storage is unavailable or invalid; no state reset or redispatch occurred" }));
  }
}
