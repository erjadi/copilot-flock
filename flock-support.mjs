import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { atomicJson, assertNoLinks } from "./flock-lifecycle.mjs";

const TYPE = "copilot-flock-support-mailbox-v1";
const TICKET_TYPE = "SupportCapabilityV1";
const MAX_TEXT_BYTES = 4096;
const MAX_REPORT_BYTES = 16 * 1024;
const DEFAULT_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;
const ALLOWED_DIAGNOSTICS = new Set([
  "artifact", "protocol", "platform", "stage", "error", "correlation",
  "clock", "fingerprint", "rosterEpoch",
]);
const SECRET_PATTERN =
  /-----BEGIN [^-]+ PRIVATE KEY-----|SharedAccessSignature|SharedAccessKey|github_pat_|gh[pousr]_|Bearer\s+[A-Za-z0-9._~+/-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i;
const ABSOLUTE_PATH_PATTERN = /(?:^|[\s"'(])(?:[A-Za-z]:\\|\\\\[^\\\s]+\\|\/(?:home|Users|var|etc|root|tmp)\/)/i;

const canonical = (value) => JSON.stringify(value);
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fingerprint = (publicKey) => digest(String(publicKey)).slice(0, 32);
const iso = (ms) => new Date(ms).toISOString();

export function ensureSupportDeviceKey(root) {
  const resolvedRoot = assertNoLinks(path.resolve(root));
  const filename = path.join(resolvedRoot, "support-device.json");
  fs.mkdirSync(resolvedRoot, { recursive: true });
  if (fs.existsSync(filename)) {
    const stored = JSON.parse(fs.readFileSync(assertNoLinks(filename), "utf8"));
    if (stored?.type !== "copilot-flock-support-device-v1" || !stored.publicKey || !stored.privateKey) {
      throw new Error("Invalid support-only device key");
    }
    return stored;
  }
  const pair = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const stored = {
    type: "copilot-flock-support-device-v1",
    deviceId: crypto.randomUUID(),
    fingerprint: fingerprint(pair.publicKey),
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    createdAt: iso(Date.now()),
  };
  atomicJson(filename, stored);
  return stored;
}

function boundedText(value, field, maxBytes = MAX_TEXT_BYTES) {
  const text = String(value ?? "").trim();
  if (!text) throw new Error(`${field} is required`);
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error(`${field} exceeds ${maxBytes} bytes`);
  if (SECRET_PATTERN.test(text)) throw new Error(`${field} contains credential-like content`);
  if (ABSOLUTE_PATH_PATTERN.test(text)) throw new Error(`${field} contains an absolute or network path`);
  return text;
}

function validateDiagnostics(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("diagnostics must be an object");
  }
  const output = {};
  for (const [key, value] of Object.entries(input)) {
    if (!ALLOWED_DIAGNOSTICS.has(key)) throw new Error(`Unsupported diagnostic field "${key}"`);
    if (key === "rosterEpoch") {
      if (!Number.isSafeInteger(value) || value < 0) throw new Error("rosterEpoch must be a non-negative integer");
      output[key] = value;
      continue;
    }
    output[key] = boundedText(value, `diagnostics.${key}`, 1024);
  }
  return output;
}

function verifySignature(publicKey, payload, signature) {
  if (!crypto.verify(null, Buffer.from(canonical(payload)), publicKey, Buffer.from(String(signature), "base64"))) {
    throw new Error("Invalid support signature");
  }
}

function safeAttempt(attempt) {
  return { untrustedData: {
    attemptId: attempt.attemptId,
    ticketId: attempt.ticketId,
    identity: "ticket_holder",
    state: attempt.state,
    createdAt: attempt.createdAt,
    updatedAt: attempt.updatedAt,
    expiresAt: attempt.expiresAt,
    report: attempt.report,
    replies: attempt.replies,
  } };
}

export class SupportMailbox {
  constructor(root, { clock = Date.now, retentionMs = DEFAULT_RETENTION_MS } = {}) {
    this.root = assertNoLinks(path.resolve(root));
    this.filename = path.join(this.root, "support-mailbox.json");
    this.clock = clock;
    this.retentionMs = Math.max(60_000, Number(retentionMs) || DEFAULT_RETENTION_MS);
  }

  read() {
    if (!fs.existsSync(this.filename)) {
      return { type: TYPE, tickets: {}, attempts: {}, audit: [] };
    }
    const data = JSON.parse(fs.readFileSync(assertNoLinks(this.filename), "utf8"));
    if (data?.type !== TYPE || !data.tickets || !data.attempts || !Array.isArray(data.audit)) {
      throw new Error("Invalid support mailbox state");
    }
    return data;
  }

  save(data) {
    fs.mkdirSync(this.root, { recursive: true });
    data.updatedAt = iso(this.clock());
    atomicJson(this.filename, data);
  }

  audit(data, event, details = {}) {
    const previousHash = data.audit.at(-1)?.hash || "0".repeat(64);
    const entry = {
      eventId: crypto.randomUUID(),
      event,
      at: iso(this.clock()),
      previousHash,
      ...details,
    };
    entry.hash = digest(canonical(entry));
    data.audit.push(entry);
    data.audit = data.audit.slice(-500);
  }

  cleanup(data = this.read()) {
    const cutoff = this.clock() - this.retentionMs;
    for (const [attemptId, attempt] of Object.entries(data.attempts)) {
      if (["closed", "revoked", "expired"].includes(attempt.state) &&
          Date.parse(attempt.updatedAt || attempt.createdAt) < cutoff) {
        delete data.attempts[attemptId];
      }
    }
    for (const [ticketId, ticket] of Object.entries(data.tickets)) {
      if (ticket.status !== "issued" && Date.parse(ticket.updatedAt || ticket.createdAt) < cutoff) {
        delete data.tickets[ticketId];
      }
    }
    data.audit = data.audit.filter((entry) => Date.parse(entry.at) >= cutoff);
    return data;
  }

  issue({ maintainerIdentity, flockId, supportPublicKey, ttlSeconds = 900 }) {
    if (!maintainerIdentity?.privateKey || !maintainerIdentity?.publicKey || !maintainerIdentity?.deviceId) {
      throw new Error("Maintainer device identity is required");
    }
    const ttl = Math.min(3600, Math.max(60, Number(ttlSeconds) || 900));
    const now = this.clock();
    const body = {
      type: TICKET_TYPE,
      ticketId: crypto.randomUUID(),
      flockId: boundedText(flockId, "flockId", 256),
      issuerDeviceId: maintainerIdentity.deviceId,
      issuerFingerprint: fingerprint(maintainerIdentity.publicKey),
      supportKeyFingerprint: fingerprint(supportPublicKey),
      nonce: crypto.randomBytes(24).toString("base64url"),
      issuedAt: iso(now),
      expiresAt: iso(now + ttl * 1000),
      permissions: ["submit_text_report"],
      deniedAuthorities: [
        "flock", "signalr", "service_bus", "roster", "presence", "session", "thread",
        "file", "repository", "config", "mutation", "command", "queue", "autopilot",
        "enrollment", "key_rotation",
      ],
    };
    const ticket = {
      body,
      issuerPublicKey: maintainerIdentity.publicKey,
      signature: crypto.sign(null, Buffer.from(canonical(body)), maintainerIdentity.privateKey).toString("base64"),
    };
    const data = this.cleanup();
    const recentIssues = data.audit.filter(
      (entry) =>
        entry.event === "ticket_issued" &&
        entry.issuerDeviceId === body.issuerDeviceId &&
        Date.parse(entry.at) > now - 60_000
    );
    if (recentIssues.length >= 10) throw new Error("Support ticket issue rate limit exceeded");
    data.tickets[body.ticketId] = {
      ticketDigest: digest(canonical(ticket)),
      issuerDeviceId: body.issuerDeviceId,
      supportKeyFingerprint: body.supportKeyFingerprint,
      status: "issued",
      createdAt: body.issuedAt,
      updatedAt: body.issuedAt,
      expiresAt: body.expiresAt,
    };
    this.audit(data, "ticket_issued", { ticketId: body.ticketId, issuerDeviceId: body.issuerDeviceId });
    this.save(data);
    return ticket;
  }

  revoke({ ticketId, maintainerDeviceId }) {
    const data = this.cleanup();
    const ticket = data.tickets[ticketId];
    if (!ticket) throw new Error("Unknown support ticket");
    if (ticket.issuerDeviceId !== maintainerDeviceId) throw new Error("Support ticket maintainer mismatch");
    ticket.status = "revoked";
    ticket.updatedAt = iso(this.clock());
    this.audit(data, "ticket_revoked", { ticketId, issuerDeviceId: maintainerDeviceId });
    this.save(data);
    return { ticketId, state: "revoked" };
  }

  submit({ ticket, supportPublicKey, report, signature }) {
    if (ticket?.body?.type !== TICKET_TYPE) throw new Error("Invalid support ticket");
    const ticketKeys = Object.keys(ticket || {}).sort();
    const bodyKeys = Object.keys(ticket?.body || {}).sort();
    const expectedTicketKeys = ["body", "issuerPublicKey", "signature"];
    const expectedBodyKeys = [
      "deniedAuthorities", "expiresAt", "flockId", "issuedAt", "issuerDeviceId",
      "issuerFingerprint", "nonce", "permissions", "supportKeyFingerprint", "ticketId", "type",
    ].sort();
    if (canonical(ticketKeys) !== canonical(expectedTicketKeys.sort()) ||
        canonical(bodyKeys) !== canonical(expectedBodyKeys)) {
      throw new Error("Support ticket contains unsupported fields");
    }
    verifySignature(ticket.issuerPublicKey, ticket.body, ticket.signature);
    if (fingerprint(ticket.issuerPublicKey) !== ticket.body.issuerFingerprint) {
      throw new Error("Support ticket issuer fingerprint mismatch");
    }
    if (fingerprint(supportPublicKey) !== ticket.body.supportKeyFingerprint) {
      throw new Error("Support ticket is bound to another support device key");
    }
    if (Date.parse(ticket.body.expiresAt) <= this.clock()) throw new Error("Support ticket expired");
    const reportKeys = Object.keys(report || {}).sort();
    if (reportKeys.some((key) => !["diagnostics", "submittedAt", "text"].includes(key))) {
      throw new Error("Support report contains unsupported fields");
    }
    const normalizedReport = {
      text: boundedText(report?.text, "report.text", MAX_TEXT_BYTES),
      diagnostics: validateDiagnostics(report?.diagnostics || {}),
      submittedAt: report?.submittedAt || iso(this.clock()),
    };
    if (Buffer.byteLength(canonical(normalizedReport), "utf8") > MAX_REPORT_BYTES) {
      throw new Error(`Support report exceeds ${MAX_REPORT_BYTES} bytes`);
    }
    verifySignature(supportPublicKey, {
      ticketId: ticket.body.ticketId,
      nonce: ticket.body.nonce,
      report: normalizedReport,
    }, signature);
    const data = this.cleanup();
    const stored = data.tickets[ticket.body.ticketId];
    if (!stored || stored.ticketDigest !== digest(canonical(ticket))) throw new Error("Support ticket is not trusted by this mailbox");
    if (stored.status !== "issued") throw new Error(`Support ticket is ${stored.status}; replay rejected`);
    const attemptId = crypto.randomUUID();
    const now = iso(this.clock());
    stored.status = "redeemed";
    stored.updatedAt = now;
    data.attempts[attemptId] = {
      attemptId,
      ticketId: ticket.body.ticketId,
      issuerDeviceId: ticket.body.issuerDeviceId,
      supportKeyFingerprint: ticket.body.supportKeyFingerprint,
      state: "report_submitted",
      createdAt: now,
      updatedAt: now,
      expiresAt: iso(this.clock() + this.retentionMs),
      report: normalizedReport,
      replies: [],
    };
    this.audit(data, "report_submitted", { attemptId, ticketId: ticket.body.ticketId });
    this.save(data);
    return safeAttempt(data.attempts[attemptId]);
  }

  assertMaintainer(attempt, maintainerDeviceId) {
    if (!attempt || attempt.issuerDeviceId !== maintainerDeviceId) {
      throw new Error("Support attempt maintainer mismatch");
    }
  }

  list({ maintainerDeviceId, cursor = 0, limit = 25, includeClosed = false }) {
    const data = this.cleanup();
    this.save(data);
    const offset = Math.max(0, Number(cursor) || 0);
    const size = Math.min(50, Math.max(1, Number(limit) || 25));
    const all = Object.values(data.attempts)
      .filter((attempt) => attempt.issuerDeviceId === maintainerDeviceId)
      .filter((attempt) => includeClosed || !["closed", "revoked", "expired"].includes(attempt.state))
      .sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
    const items = all.slice(offset, offset + size).map(safeAttempt);
    return { items, nextCursor: offset + items.length < all.length ? offset + items.length : null, total: all.length };
  }

  get({ attemptId, maintainerDeviceId }) {
    const attempt = this.read().attempts[attemptId];
    this.assertMaintainer(attempt, maintainerDeviceId);
    return safeAttempt(attempt);
  }

  reply({ attemptId, maintainerDeviceId, text }) {
    const data = this.cleanup();
    const attempt = data.attempts[attemptId];
    this.assertMaintainer(attempt, maintainerDeviceId);
    if (["closed", "revoked", "expired"].includes(attempt.state)) throw new Error(`Support attempt is ${attempt.state}`);
    if (attempt.replies.length >= 10) throw new Error("Support reply quota exceeded");
    attempt.replies.push({
      replyId: crypto.randomUUID(),
      from: "maintainer",
      text: boundedText(text, "reply.text"),
      createdAt: iso(this.clock()),
    });
    attempt.state = "maintainer_replied";
    attempt.updatedAt = iso(this.clock());
    this.audit(data, "maintainer_replied", { attemptId });
    this.save(data);
    return safeAttempt(attempt);
  }

  close({ attemptId, maintainerDeviceId }) {
    const data = this.cleanup();
    const attempt = data.attempts[attemptId];
    this.assertMaintainer(attempt, maintainerDeviceId);
    attempt.state = "closed";
    attempt.updatedAt = iso(this.clock());
    this.audit(data, "attempt_closed", { attemptId });
    this.save(data);
    return safeAttempt(attempt);
  }
}

