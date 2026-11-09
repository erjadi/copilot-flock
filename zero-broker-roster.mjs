import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";

export const ROSTER_SCHEMA = "copilot-flock/roster/v3-zero-broker";
export const ENVELOPE_VERSION = "v3-zb-1";
export const MAX_LEASE_MS = 3600000;
const MAX_DOCUMENT_BYTES = 1048576;
const MAX_ENVELOPE_BYTES = 700 * 1024;
const PEER = /^peer_[0-9a-f]{24}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${Array.from(value, canonicalJson).join(",")}]`;
  requireValue(value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype, "Expected plain JSON data");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function admissionAuthorization(value, rosterEpoch) {
  if (value === undefined || value === null) return null;
  requireValue(value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(",") === "grantRevision,mode,rosterEpoch" &&
    ["PRESENCE", "ROOT", "SNAPSHOT"].includes(value.mode) &&
    typeof value.grantRevision === "string" && value.grantRevision.length > 0 && value.grantRevision.length <= 128 &&
    Number.isSafeInteger(value.rosterEpoch) && value.rosterEpoch > 0 &&
    (rosterEpoch === undefined || value.rosterEpoch === rosterEpoch), "Invalid admission authorization binding");
  return canonicalJson(value);
}

function admissionReceipt(row, authorization) {
  return { status: row.status, authorization: row.authorization === null ? null : JSON.parse(row.authorization),
    result: row.authorization === authorization && row.result !== null ? JSON.parse(row.result) : null };
}

function withoutSignature(value) {
  const { signature, ...unsigned } = value;
  return unsigned;
}

function publicKey(pem, type) {
  requireValue(typeof pem === "string" && pem.startsWith("-----BEGIN PUBLIC KEY-----\n"), "Public metadata requires SPKI public keys, never private key material");
  const key = crypto.createPublicKey(pem);
  requireValue(key.asymmetricKeyType === type, `Expected ${type} public key`);
  requireValue(key.export({ type: "spki", format: "pem" }) === pem, "Public keys must use canonical SPKI encoding without appended material");
  return key;
}

export function keyFingerprint(pem) {
  return digest(crypto.createPublicKey(pem).export({ type: "spki", format: "der" }));
}

function coordinates({ flockUuid, rosterEpoch, recipientOpaquePeerId, bundleType }) {
  requireValue(UUID.test(flockUuid), "Invalid flock UUID");
  requireValue(Number.isSafeInteger(rosterEpoch) && rosterEpoch > 0, "Invalid roster epoch");
  requireValue(PEER.test(recipientOpaquePeerId), "Invalid recipient peer ID");
  requireValue(/^[a-z][a-z0-9-]{0,63}$/.test(bundleType), "Invalid bundle type");
  return `${flockUuid}|${rosterEpoch}|${recipientOpaquePeerId}|${bundleType}`;
}

function encodeGcm(plaintext, material, aad) {
  const cipher = crypto.createCipheriv("aes-256-gcm", material.subarray(0, 32), material.subarray(32, 44));
  cipher.setAAD(Buffer.from(aad, "utf8"));
  return {
    ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

function decodeGcm(bundle, material, aad) {
  requireValue(typeof bundle.ciphertext === "string" && bundle.ciphertext.length <= 4 * Math.ceil(MAX_DOCUMENT_BYTES / 3) && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(bundle.ciphertext), "Invalid ciphertext size or encoding");
  requireValue(typeof bundle.tag === "string" && /^[A-Za-z0-9+/]{22}==$/.test(bundle.tag), "Invalid GCM tag");
  const decipher = crypto.createDecipheriv("aes-256-gcm", material.subarray(0, 32), material.subarray(32, 44));
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(bundle.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(bundle.ciphertext, "base64")), decipher.final()]);
}

function derive(secret, salt, info) {
  return Buffer.from(crypto.hkdfSync("sha256", secret, Buffer.from(salt, "utf8"), Buffer.from(info, "utf8"), 44));
}

export function sealBundle({ payload, recipientEncPubPem, ...context }) {
  const aad = coordinates(context);
  const ephemeral = crypto.generateKeyPairSync("x25519");
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKey(recipientEncPubPem, "x25519") });
  requireValue(shared.some((byte) => byte !== 0), "Invalid low-order encryption key");
  const material = derive(shared, context.flockUuid, `copilot-flock-v3-bundle|${aad}`);
  try {
    const plaintext = Buffer.from(canonicalJson(payload), "utf8");
    requireValue(plaintext.length <= MAX_DOCUMENT_BYTES, "Bundle exceeds size limit");
    return {
      ...context,
      ephemeralPub: ephemeral.publicKey.export({ type: "spki", format: "pem" }),
      ...encodeGcm(plaintext, material, aad),
    };
  } finally {
    shared.fill(0);
    material.fill(0);
  }
}

export function openSealedBundle({ bundle, recipientEncPrivPem, ...expected }) {
  const aad = coordinates(expected);
  requireValue(coordinates(bundle) === aad, "Sealed bundle context mismatch");
  const privateKey = crypto.createPrivateKey(recipientEncPrivPem);
  requireValue(privateKey.asymmetricKeyType === "x25519", "Expected X25519 private key");
  const shared = crypto.diffieHellman({ privateKey, publicKey: publicKey(bundle.ephemeralPub, "x25519") });
  requireValue(shared.some((byte) => byte !== 0), "Invalid low-order encryption key");
  const material = derive(shared, expected.flockUuid, `copilot-flock-v3-bundle|${aad}`);
  try {
    return JSON.parse(decodeGcm(bundle, material, aad).toString("utf8"));
  } finally {
    shared.fill(0);
    material.fill(0);
  }
}

function privateDirectory(base, suffix) {
  const directory = path.resolve(base, suffix);
  for (let current = directory; ; current = path.dirname(current)) {
    if (fs.existsSync(current)) requireValue(!fs.lstatSync(current).isSymbolicLink(), "Private state ancestry cannot contain symbolic links or junctions");
    if (path.dirname(current) === current) break;
  }
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  requireValue(!fs.lstatSync(directory).isSymbolicLink(), "Private state directory cannot be a symbolic link");
  if (process.platform === "win32") {
    execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
      "$ErrorActionPreference='Stop'; $p=$env:FLOCK_PRIVATE_DIRECTORY; $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; $acl=New-Object System.Security.AccessControl.DirectorySecurity; $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false); $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule); (New-Object System.IO.DirectoryInfo($p)).SetAccessControl($acl)"],
    { env: { ...process.env, FLOCK_PRIVATE_DIRECTORY: directory }, stdio: ["ignore", "pipe", "pipe"], timeout: 10000, windowsHide: true });
  } else {
    fs.chmodSync(directory, 0o700);
  }
  return directory;
}

export function writePrivateJson(directory, name, value, { exclusive = false } = {}) {
  requireValue(/^[a-zA-Z0-9_.-]+\.json$/.test(name), "Invalid private JSON filename");
  const targetDirectory = privateDirectory(directory, ".");
  const temporary = path.join(targetDirectory, `${name}.${crypto.randomUUID()}.tmp`);
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(fd, canonicalJson(value) + "\n");
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  try {
    if (exclusive) fs.linkSync(temporary, path.join(targetDirectory, name));
    else fs.renameSync(temporary, path.join(targetDirectory, name));
  }
  finally { if (fs.existsSync(temporary)) fs.unlinkSync(temporary); }
}

export function readPrivateJson(directory, name) {
  requireValue(/^[a-zA-Z0-9_.-]+\.json$/.test(name), "Invalid private JSON filename");
  const filename = path.join(directory, name);
  requireValue(fs.existsSync(filename) && !fs.lstatSync(filename).isSymbolicLink() && fs.statSync(filename).size <= MAX_DOCUMENT_BYTES, "Missing or invalid private JSON state");
  return JSON.parse(fs.readFileSync(filename, "utf8"));
}

export function createDeviceKeys({ directory, flockUuid }) {
  requireValue(UUID.test(flockUuid), "Invalid flock UUID");
  const privatePath = privateDirectory(directory, `flock-${flockUuid}`);
  const file = path.join(privatePath, "device.json");
  if (fs.existsSync(file)) {
    requireValue(!fs.lstatSync(file).isSymbolicLink(), "Device key file cannot be a symbolic link");
    const keys = JSON.parse(fs.readFileSync(file, "utf8"));
    requireValue(keys.flockUuid === flockUuid && PEER.test(keys.opaquePeerId), "Invalid persisted device identity");
    for (const [pub, priv, type] of [["signingPub", "signingPriv", "ed25519"], ["encPub", "encPriv", "x25519"]]) {
      publicKey(keys[pub], type);
      requireValue(keyFingerprint(keys[pub]) === keyFingerprint(crypto.createPrivateKey(keys[priv])), "Device keypair mismatch");
    }
    return keys;
  }
  const signing = crypto.generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const encryption = crypto.generateKeyPairSync("x25519", { publicKeyEncoding: { type: "spki", format: "pem" }, privateKeyEncoding: { type: "pkcs8", format: "pem" } });
  const keys = { flockUuid, opaquePeerId: `peer_${crypto.randomBytes(12).toString("hex")}`, signingPub: signing.publicKey, signingPriv: signing.privateKey, encPub: encryption.publicKey, encPriv: encryption.privateKey };
  const fd = fs.openSync(file, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(keys)); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  return keys;
}

export function createRosterState({ directory, capacity = 100000 }) {
  requireValue(Number.isSafeInteger(capacity) && capacity > 0, "Invalid replay capacity");
  const privatePath = privateDirectory(directory, "roster-state");
  const file = path.join(privatePath, "state.sqlite");
  if (!fs.existsSync(file)) fs.closeSync(fs.openSync(file, "wx", 0o600));
  requireValue(!fs.lstatSync(file).isSymbolicLink(), "State database cannot be a symbolic link");
  const db = new DatabaseSync(file);
  db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000; CREATE TABLE IF NOT EXISTS rosters (flock TEXT PRIMARY KEY, epoch INTEGER NOT NULL, hash TEXT NOT NULL, document TEXT NOT NULL); CREATE TABLE IF NOT EXISTS claims (direction TEXT NOT NULL, flock TEXT NOT NULL, epoch INTEGER NOT NULL, sender TEXT NOT NULL, message TEXT NOT NULL, expiry INTEGER NOT NULL, PRIMARY KEY(direction,flock,epoch,sender,message)); CREATE TABLE IF NOT EXISTS admissions (flock TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL, request TEXT NOT NULL, digest TEXT NOT NULL, expiry INTEGER NOT NULL, status TEXT NOT NULL, result TEXT, PRIMARY KEY(flock,sender,recipient,request)); CREATE TABLE IF NOT EXISTS outbox (flock TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL, request TEXT NOT NULL, digest TEXT NOT NULL, expiry INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(flock,sender,recipient,request));");
  if (!db.prepare("PRAGMA table_info(outbox)").all().some((column) => column.name === "attempted")) db.exec("ALTER TABLE outbox ADD COLUMN attempted INTEGER NOT NULL DEFAULT 0");
  if (!db.prepare("PRAGMA table_info(admissions)").all().some((column) => column.name === "authorization")) db.exec("ALTER TABLE admissions ADD COLUMN authorization TEXT");
  db.exec("CREATE TABLE IF NOT EXISTS receipts (flock TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,request TEXT NOT NULL,digest TEXT NOT NULL,status TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(flock,sender,recipient,request))");
  function transaction(fn) {
    db.exec("BEGIN IMMEDIATE");
    try { const result = fn(); db.exec("COMMIT"); return result; }
    catch (err) { db.exec("ROLLBACK"); throw err; }
  }
  return {
    close: () => db.close(),
    get: (flockUuid) => {
      const row = db.prepare("SELECT document FROM rosters WHERE flock=?").get(flockUuid);
      return row ? JSON.parse(row.document) : null;
    },
    acceptVerifiedRoster: (roster) => transaction(() => {
      const hash = hashRoster(roster);
      const row = db.prepare("SELECT epoch,hash FROM rosters WHERE flock=?").get(roster.flockUuid);
      requireValue(!row || roster.rosterEpoch > row.epoch || (roster.rosterEpoch === row.epoch && hash === row.hash), "Roster rollback or equal-epoch fork");
      db.prepare("INSERT INTO rosters VALUES (?,?,?,?) ON CONFLICT(flock) DO UPDATE SET epoch=excluded.epoch,hash=excluded.hash,document=excluded.document").run(roster.flockUuid, roster.rosterEpoch, hash, canonicalJson(roster));
      db.prepare("DELETE FROM claims WHERE flock=? AND epoch<?").run(roster.flockUuid, roster.rosterEpoch);
    }),
    assertRoster: (roster) => {
      const row = db.prepare("SELECT epoch,hash FROM rosters WHERE flock=?").get(roster.flockUuid);
      requireValue(row && row.epoch === roster.rosterEpoch && row.hash === hashRoster(roster), "Roster has not been durably verified");
    },
    queue: ({ flockUuid, sender, recipient, requestId, payload, expiresAt, nowMs = Date.now() }) => transaction(() => {
      requireValue(UUID.test(flockUuid) && PEER.test(sender) && PEER.test(recipient) && /^[A-Za-z0-9_-]{16,128}$/.test(requestId), "Invalid outbox coordinates");
      requireValue(Number.isSafeInteger(expiresAt) && expiresAt > nowMs, "Invalid outbox expiry");
      const document = canonicalJson(payload);
      requireValue(Buffer.byteLength(document) <= MAX_DOCUMENT_BYTES, "Outbox payload exceeds size limit");
      const hash = digest(canonicalJson({ payload, expiresAt }));
      requireValue(!db.prepare("SELECT 1 FROM receipts WHERE flock=? AND sender=? AND recipient=? AND request=?").get(flockUuid, sender, recipient, requestId), "Request already has a terminal receipt; inspect it instead of redispatching");
      const row = db.prepare("SELECT digest FROM outbox WHERE flock=? AND sender=? AND recipient=? AND request=?").get(flockUuid, sender, recipient, requestId);
      requireValue(!row || row.digest === hash, "Outbox request ID reused with different payload");
      if (!row) {
        requireValue(db.prepare("SELECT COUNT(*) AS count FROM outbox").get().count < capacity, "Outbox storage capacity exhausted");
        db.prepare("INSERT INTO outbox(flock,sender,recipient,request,digest,expiry,document) VALUES (?,?,?,?,?,?,?)").run(flockUuid, sender, recipient, requestId, hash, expiresAt, document);
      }
    }),
    pendingOutbox: (flockUuid, limit = Math.min(100, capacity)) => {
      requireValue(Number.isInteger(limit) && limit > 0 && limit <= capacity, "Invalid outbox query limit");
      return db.prepare("SELECT * FROM outbox WHERE flock=? ORDER BY rowid LIMIT ?").all(flockUuid, limit).map((row) => ({ ...row, payload: JSON.parse(row.document) }));
    },
    getOutboxEntry: ({ flockUuid, sender, recipient, requestId }) => {
      const row = db.prepare("SELECT * FROM outbox WHERE flock=? AND sender=? AND recipient=? AND request=?").get(flockUuid, sender, recipient, requestId);
      return row ? { ...row, payload: JSON.parse(row.document) } : null;
    },
    getOutboxAttemptState: ({ flockUuid, sender, recipient, requestId, payload, expiresAt }) => {
      const expected = digest(canonicalJson({ payload, expiresAt }));
      const queued = db.prepare("SELECT digest,attempted FROM outbox WHERE flock=? AND sender=? AND recipient=? AND request=?")
        .get(flockUuid, sender, recipient, requestId);
      const receipt = db.prepare("SELECT digest,status FROM receipts WHERE flock=? AND sender=? AND recipient=? AND request=?")
        .get(flockUuid, sender, recipient, requestId);
      requireValue((!queued || queued.digest === expected) && (!receipt || receipt.digest === expected),
        "Outgoing request ID reused with different payload or expiry");
      return { attempted: queued?.attempted === 1 || Boolean(receipt && receipt.status !== "DENIED"),
        status: receipt?.status || null };
    },
    getOutboxReceipt: ({ flockUuid, sender, recipient, requestId, payload, expiresAt }) => {
      const row = db.prepare("SELECT * FROM receipts WHERE flock=? AND sender=? AND recipient=? AND request=?").get(flockUuid, sender, recipient, requestId);
      if (!row) return null;
      requireValue(row.digest === digest(canonicalJson({ payload, expiresAt })), "Receipt request ID reused with different payload");
      return { requestId, status: row.status, result: JSON.parse(row.result) };
    },
    storeOutboxReceipt: ({ flockUuid, sender, recipient, requestId, status, result }) => transaction(() => {
      requireValue(["DELIVERED", "DENIED", "UNKNOWN", "OFFLINE", "BUSY"].includes(status), "Invalid outbox receipt status");
      const row = db.prepare("SELECT digest FROM outbox WHERE flock=? AND sender=? AND recipient=? AND request=?").get(flockUuid, sender, recipient, requestId);
      requireValue(row, "Receipt has no corresponding durable outbox");
      const document = canonicalJson(result);
      const previous = db.prepare("SELECT status FROM receipts WHERE flock=? AND sender=? AND recipient=? AND request=?").get(flockUuid, sender, recipient, requestId);
      requireValue(Buffer.byteLength(document) <= MAX_ENVELOPE_BYTES && (previous || db.prepare("SELECT COUNT(*) AS count FROM receipts").get().count < capacity), "Receipt storage limit exhausted");
      requireValue(!previous || previous.status === "UNKNOWN", "Cannot overwrite a terminal receipt");
      db.prepare("INSERT INTO receipts VALUES(?,?,?,?,?,?,?) ON CONFLICT(flock,sender,recipient,request) DO UPDATE SET status=excluded.status,result=excluded.result WHERE receipts.status='UNKNOWN'").run(flockUuid, sender, recipient, requestId, row.digest, status, document);
      if (status !== "UNKNOWN") db.prepare("DELETE FROM outbox WHERE flock=? AND sender=? AND recipient=? AND request=?").run(flockUuid, sender, recipient, requestId);
    }),
    markOutboxAttempt: ({ flockUuid, sender, recipient, requestId }) => db.prepare("UPDATE outbox SET attempted=1 WHERE flock=? AND sender=? AND recipient=? AND request=? AND attempted=0").run(flockUuid, sender, recipient, requestId).changes === 1,
    acknowledgeOutbox: ({ flockUuid, sender, recipient, requestId }) => db.prepare("DELETE FROM outbox WHERE flock=? AND sender=? AND recipient=? AND request=?").run(flockUuid, sender, recipient, requestId),
    readRequestReceipt: ({ roster, sender, recipient, requestId, payload, expiresAt, authorization, nowMs = Date.now() }) => {
      const trusted = db.prepare("SELECT epoch,hash FROM rosters WHERE flock=?").get(roster.flockUuid);
      requireValue(trusted && trusted.epoch === roster.rosterEpoch && trusted.hash === hashRoster(roster), "Stale roster at receipt disclosure");
      checkLease(roster, nowMs);
      activeMember(roster, sender, nowMs);
      activeMember(roster, recipient, nowMs);
      requireValue(/^[A-Za-z0-9_-]{16,128}$/.test(requestId) && Number.isSafeInteger(expiresAt), "Invalid receipt coordinates");
      const row = db.prepare("SELECT * FROM admissions WHERE flock=? AND sender=? AND recipient=? AND request=?").get(roster.flockUuid, sender, recipient, requestId);
      if (!row) return { status: "NOT_ADMITTED", result: null, authorization: null };
      requireValue(row.digest === digest(canonicalJson({ payload, expiresAt })), "Receipt request ID reused with different payload");
      return admissionReceipt(row, admissionAuthorization(authorization, roster.rosterEpoch));
    },
    admitRequest: ({ roster, sender, recipient, requestId, payload, expiresAt, authorization, nowMs = Date.now() }) => transaction(() => {
      const trusted = db.prepare("SELECT epoch,hash FROM rosters WHERE flock=?").get(roster.flockUuid);
      requireValue(trusted && trusted.epoch === roster.rosterEpoch && trusted.hash === hashRoster(roster), "Stale roster before application admission");
      checkLease(roster, nowMs);
      activeMember(roster, sender, nowMs);
      activeMember(roster, recipient, nowMs);
      requireValue(Number.isSafeInteger(expiresAt) && expiresAt > nowMs && /^[A-Za-z0-9_-]{16,128}$/.test(requestId), "Request expired or invalid");
      const hash = digest(canonicalJson({ payload, expiresAt }));
      const binding = admissionAuthorization(authorization, roster.rosterEpoch);
      const row = db.prepare("SELECT * FROM admissions WHERE flock=? AND sender=? AND recipient=? AND request=?").get(roster.flockUuid, sender, recipient, requestId);
      if (row) {
        requireValue(row.digest === hash, "Admission request ID reused with different payload");
        return { dispatch: false, ...admissionReceipt(row, binding) };
      }
      requireValue(db.prepare("SELECT COUNT(*) AS count FROM admissions").get().count < capacity, "Admission storage capacity exhausted");
      db.prepare("INSERT INTO admissions(flock,sender,recipient,request,digest,expiry,status,result,authorization) VALUES (?,?,?,?,?,?,'UNKNOWN',NULL,?)").run(roster.flockUuid, sender, recipient, requestId, hash, expiresAt, binding);
      return { dispatch: true, status: "UNKNOWN", result: null, authorization: authorization || null };
    }),
    finishRequest: ({ flockUuid, sender, recipient, requestId, status, result, authorization }) => {
      requireValue(["DELIVERED", "DENIED", "UNKNOWN", "OFFLINE", "BUSY"].includes(status), "Invalid admission result status");
      const document = canonicalJson(result);
      requireValue(Buffer.byteLength(document) <= MAX_ENVELOPE_BYTES, "Admission result exceeds size limit");
      const changed = db.prepare("UPDATE admissions SET status=?,result=? WHERE flock=? AND sender=? AND recipient=? AND request=? AND status='UNKNOWN' AND authorization IS ?").run(status, document, flockUuid, sender, recipient, requestId, admissionAuthorization(authorization));
      requireValue(changed.changes === 1, "Cannot complete an unclaimed request");
    },
    claim: (direction, roster, sender, message, expiresAt, nowMs) => transaction(() => {
      db.prepare("DELETE FROM claims WHERE direction='receive' AND expiry<=?").run(nowMs);
      const row = db.prepare("SELECT epoch,hash FROM rosters WHERE flock=?").get(roster.flockUuid);
      requireValue(row && row.epoch === roster.rosterEpoch && row.hash === hashRoster(roster), "Stale roster at message admission");
      if (db.prepare("SELECT 1 FROM claims WHERE direction=? AND flock=? AND epoch=? AND sender=? AND message=?").get(direction, roster.flockUuid, roster.rosterEpoch, sender, message)) {
        throw Object.assign(new Error("Replay or reused sender/message nonce"), { code: direction === "receive" ? "REPLAY" : "NONCE_REUSE" });
      }
      requireValue(db.prepare("SELECT COUNT(*) AS count FROM claims").get().count < capacity, "Replay storage capacity exhausted");
      db.prepare("INSERT INTO claims VALUES (?,?,?,?,?,?)").run(direction, roster.flockUuid, roster.rosterEpoch, sender, message, expiresAt);
    }),
  };
}

export function hashRoster(roster) {
  return digest(canonicalJson(roster));
}

function validateRosterShape(roster, nowMs, requireFresh = true) {
  requireValue(Buffer.byteLength(canonicalJson(roster)) <= MAX_DOCUMENT_BYTES, "Public roster exceeds size limit");
  requireValue(Object.keys(roster).every((key) => ["schema", "flockUuid", "rosterEpoch", "prevRosterHash", "issuedAt", "leaseExpiresAt", "rootFingerprint", "ownerSigners", "members", "pendingVouchers", "consumedVouchers", "sealedOwnerVault", "signature", "recoveryCheckpoint"].includes(key)), "Unknown or plaintext public roster metadata is forbidden");
  requireValue(roster.schema === ROSTER_SCHEMA && UUID.test(roster.flockUuid), "Invalid roster schema or flock UUID");
  requireValue(Number.isSafeInteger(roster.rosterEpoch) && roster.rosterEpoch > 0, "Invalid roster epoch");
  requireValue(roster.prevRosterHash === "GENESIS" || /^[0-9a-f]{64}$/.test(roster.prevRosterHash), "Invalid previous roster hash");
  const issued = Date.parse(roster.issuedAt);
  const lease = Date.parse(roster.leaseExpiresAt);
  requireValue(Number.isFinite(issued) && issued <= nowMs + 30000 && lease > issued && lease - issued <= MAX_LEASE_MS && (!requireFresh || lease > nowMs), "Invalid or expired signed freshness lease");
  requireValue(Array.isArray(roster.members) && Array.isArray(roster.ownerSigners), "Invalid roster membership");
  const ids = new Set();
  const signingKeys = new Set();
  const encryptionKeys = new Set();
  for (const member of roster.members) {
    requireValue(PEER.test(member.opaquePeerId) && !ids.has(member.opaquePeerId), "Duplicate or invalid member peer ID");
    ids.add(member.opaquePeerId);
    publicKey(member.signingPub, "ed25519");
    publicKey(member.encPub, "x25519");
    const signing = keyFingerprint(member.signingPub);
    const encryption = keyFingerprint(member.encPub);
    requireValue(!signingKeys.has(signing) && !encryptionKeys.has(encryption), "Per-flock device keys cannot be shared between peers");
    signingKeys.add(signing);
    encryptionKeys.add(encryption);
    requireValue(["owner", "collaborator", "guest"].includes(member.role), "Invalid member role");
    requireValue(!member.membershipExpiresAt || Number.isFinite(Date.parse(member.membershipExpiresAt)), "Invalid membership expiry");
    requireValue(Object.keys(member).every((key) => ["opaquePeerId", "signingPub", "encPub", "role", "membershipExpiresAt", "sealedMemberBundle"].includes(key)), "Plaintext identity or unknown member metadata is forbidden");
    requireValue(coordinates(member.sealedMemberBundle) === coordinates({ flockUuid: roster.flockUuid, rosterEpoch: roster.rosterEpoch, recipientOpaquePeerId: member.opaquePeerId, bundleType: "member" }), "Member bundle is not bound to this epoch");
    validatePublicBundle(member.sealedMemberBundle);
  }
  const ownerIds = new Set();
  let root;
  for (const signer of roster.ownerSigners) {
    requireValue(PEER.test(signer.opaquePeerId) && !ownerIds.has(signer.opaquePeerId), "Duplicate or invalid owner signer");
    ownerIds.add(signer.opaquePeerId);
    const member = roster.members.find((entry) => entry.opaquePeerId === signer.opaquePeerId);
    requireValue(member?.role === "owner" && !member.membershipExpiresAt && signer.signingPub === member.signingPub, "Owner signer must retain its non-expiring owner member identity");
    requireValue(["genesis-root", "owner-delegate"].includes(signer.role), "Invalid owner governance role");
    requireValue(Object.keys(signer).every((key) => ["opaquePeerId", "signingPub", "role", "permissions"].includes(key)), "Invalid owner signer metadata");
    requireValue(signer.permissions && ["canKick", "canModifyOwners", "canMintTokens"].every((key) => typeof signer.permissions[key] === "boolean") && Object.keys(signer.permissions).length === 3, "Invalid owner permissions");
    if (signer.role === "genesis-root") {
      requireValue(!root && signer.permissions.canModifyOwners && signer.permissions.canMintTokens, "Exactly one authorized genesis root is required");
      root = signer;
    } else {
      requireValue(!signer.permissions.canModifyOwners, "Delegates cannot modify owner governance");
    }
  }
  requireValue(root && roster.rootFingerprint === keyFingerprint(root.signingPub), "Root fingerprint mismatch");
  requireValue(roster.signature && Object.keys(roster.signature).length === 2 && PEER.test(roster.signature.signedByOpaquePeerId) && /^[A-Za-z0-9+/]{86}==$/.test(roster.signature.ed25519Signature), "Invalid public roster signature");
  if (roster.recoveryCheckpoint) {
    const checkpoint = roster.recoveryCheckpoint;
    requireValue(Object.keys(checkpoint).length === 4 && Number.isSafeInteger(checkpoint.baseEpoch) && checkpoint.baseEpoch > 0 && /^[0-9a-f]{64}$/.test(checkpoint.baseRosterHash) && /^[0-9a-f]{64}$/.test(checkpoint.nextRosterHash) && /^[A-Za-z0-9+/]{86}==$/.test(checkpoint.signature), "Invalid public recovery checkpoint");
  }
  requireValue(roster.members.every((member) => member.role !== "owner" || ownerIds.has(member.opaquePeerId)), "Owner members require explicit owner signer authority");
  requireValue(roster.sealedOwnerVault && Object.getPrototypeOf(roster.sealedOwnerVault) === Object.prototype, "Invalid owner vault");
  for (const [id, bundle] of Object.entries(roster.sealedOwnerVault)) {
    const signer = roster.ownerSigners.find((entry) => entry.opaquePeerId === id);
    requireValue(signer && (signer.role === "genesis-root" || signer.permissions.canMintTokens), "Azure keys cannot be sealed to non-minting delegates or guests");
    requireValue(coordinates(bundle) === coordinates({ flockUuid: roster.flockUuid, rosterEpoch: roster.rosterEpoch, recipientOpaquePeerId: id, bundleType: "owner-vault" }), "Owner vault epoch mismatch");
    validatePublicBundle(bundle);
  }
  for (const signer of roster.ownerSigners) {
    if (signer.role === "genesis-root" || signer.permissions.canMintTokens) requireValue(roster.sealedOwnerVault[signer.opaquePeerId], "Authorized token issuer is missing its sealed vault");
  }
  for (const table of ["pendingVouchers", "consumedVouchers"]) requireValue(roster[table] && Object.getPrototypeOf(roster[table]) === Object.prototype, "Invalid voucher table");
  for (const [id, pending] of Object.entries(roster.pendingVouchers)) {
    requireValue(Object.keys(pending).every((key) => ["voucherId", "voucherHash", "issuedByOpaquePeerId", "role", "expiresAt", "recipientBinding"].includes(key)), "Pending public vouchers cannot contain bearer tokens or plaintext identities");
    requireValue(roster.ownerSigners.some((signer) => signer.opaquePeerId === pending.issuedByOpaquePeerId), "Pending voucher issuer is not authorized");
    requireValue(UUID.test(id) && pending.voucherId === id && /^[0-9a-f]{64}$/.test(pending.voucherHash) && ["collaborator", "guest"].includes(pending.role) && Number.isFinite(Date.parse(pending.expiresAt)), "Invalid pending voucher metadata");
    if (pending.recipientBinding) requireValue(Object.keys(pending.recipientBinding).length === 2 && /^[0-9a-f]{64}$/.test(pending.recipientBinding.signingFingerprint) && /^[0-9a-f]{64}$/.test(pending.recipientBinding.encFingerprint), "Invalid pre-bound recipient fingerprints");
  }
  for (const [id, consumed] of Object.entries(roster.consumedVouchers)) {
    requireValue(UUID.test(id) && Object.keys(consumed).length === 2 && PEER.test(consumed.opaquePeerId) && /^[0-9a-f]{64}$/.test(consumed.claimHash), "Invalid consumed voucher metadata");
  }
  requireValue(roster.signature && PEER.test(roster.signature.signedByOpaquePeerId), "Missing roster signature");
  requireValue(Buffer.byteLength(canonicalJson(roster)) <= MAX_DOCUMENT_BYTES, "Roster exceeds size limit");
  return root;
}

function validatePublicBundle(bundle) {
  requireValue(Object.keys(bundle).length === 7 && Object.keys(bundle).every((key) => ["flockUuid", "rosterEpoch", "recipientOpaquePeerId", "bundleType", "ephemeralPub", "ciphertext", "tag"].includes(key)), "Public bundles cannot include plaintext identity or secret fields");
  publicKey(bundle.ephemeralPub, "x25519");
  requireValue(typeof bundle.ciphertext === "string" && bundle.ciphertext.length <= 4 * Math.ceil(MAX_DOCUMENT_BYTES / 3) && /^[A-Za-z0-9+/]*={0,2}$/.test(bundle.ciphertext) && typeof bundle.tag === "string" && /^[A-Za-z0-9+/]{22}==$/.test(bundle.tag), "Invalid public ciphertext encoding");
}

export function validateRosterDocument(roster, nowMs = Date.now()) {
  validateRosterShape(roster, nowMs, false);
  return roster;
}

function verifyRosterSignature(roster, signer) {
  requireValue(signer && roster.signature.signedByOpaquePeerId === signer.opaquePeerId, "Unauthorized roster signer");
  requireValue(crypto.verify(null, Buffer.from(canonicalJson(withoutSignature(roster))), publicKey(signer.signingPub, "ed25519"), Buffer.from(roster.signature.ed25519Signature, "base64")), "Invalid roster signature");
}

export function signRoster(roster, actor) {
  const unsigned = withoutSignature(roster);
  return { ...unsigned, signature: { signedByOpaquePeerId: actor.opaquePeerId, ed25519Signature: crypto.sign(null, Buffer.from(canonicalJson(unsigned)), actor.signingPriv).toString("base64") } };
}

export function validateRosterTransition(prevRoster, nextRoster, nowMs = Date.now(), { requireFresh = true } = {}) {
  validateRosterShape(prevRoster, nowMs, false);
  validateRosterShape(nextRoster, nowMs, requireFresh);
  requireValue(nextRoster.flockUuid === prevRoster.flockUuid && nextRoster.rosterEpoch === prevRoster.rosterEpoch + 1 && nextRoster.prevRosterHash === hashRoster(prevRoster), "Broken roster epoch/hash chain");
  const signer = prevRoster.ownerSigners.find((entry) => entry.opaquePeerId === nextRoster.signature.signedByOpaquePeerId);
  verifyRosterSignature(nextRoster, signer);
  if (signer.role !== "genesis-root") {
    requireValue(nextRoster.rootFingerprint === prevRoster.rootFingerprint && canonicalJson(nextRoster.ownerSigners) === canonicalJson(prevRoster.ownerSigners), "Only genesis root can modify owners, root fingerprint or token-minting permissions");
    for (const owner of prevRoster.ownerSigners) {
      const before = prevRoster.members.find((member) => member.opaquePeerId === owner.opaquePeerId);
      const after = nextRoster.members.find((member) => member.opaquePeerId === owner.opaquePeerId);
      requireValue(after && canonicalJson(withoutMemberBundle(before)) === canonicalJson(withoutMemberBundle(after)), "Delegate cannot remove or downgrade an owner signer member");
    }
    const removed = prevRoster.members.some((member) => !nextRoster.members.some((next) => next.opaquePeerId === member.opaquePeerId));
    requireValue(!removed || signer.permissions.canKick, "Delegate lacks kick permission");
  }
  preserveConsumedVouchers(prevRoster, nextRoster);
  return nextRoster;
}

function preserveConsumedVouchers(previous, next) {
  for (const voucherId of Object.keys(previous.consumedVouchers)) {
    requireValue(next.consumedVouchers[voucherId] && canonicalJson(next.consumedVouchers[voucherId]) === canonicalJson(previous.consumedVouchers[voucherId]), "Consumed vouchers cannot be restored or altered");
    requireValue(!next.pendingVouchers[voucherId], "Consumed voucher cannot become pending");
  }
}

function withoutMemberBundle(member) {
  const { sealedMemberBundle, ...identity } = member;
  return identity;
}

function checkpointTarget(roster) {
  const { signature, recoveryCheckpoint, ...body } = roster;
  return digest(canonicalJson(body));
}

export function verifyRosterChain(trustedRoster, transitionRosters, nowMs = Date.now(), { state, pinnedRootFingerprint, requireFresh = true } = {}) {
  if (state) {
    const stored = state.get(trustedRoster.flockUuid);
    if (stored) requireValue(hashRoster(stored) === hashRoster(trustedRoster), "Trusted snapshot differs from persisted trust anchor");
  }
  if (!state?.get(trustedRoster.flockUuid)) {
    const root = validateRosterShape(trustedRoster, nowMs, false);
    requireValue(trustedRoster.rosterEpoch === 1 && trustedRoster.prevRosterHash === "GENESIS" && pinnedRootFingerprint === trustedRoster.rootFingerprint, "Bootstrap requires an independently pinned signed genesis roster");
    verifyRosterSignature(trustedRoster, root);
  }
  let current = trustedRoster;
  for (const next of transitionRosters) {
    if (next.rosterEpoch === current.rosterEpoch + 1) {
      current = validateRosterTransition(current, next, nowMs, { requireFresh: false });
      continue;
    }
    const root = current.ownerSigners.find((entry) => entry.role === "genesis-root");
    validateRosterShape(next, nowMs, false);
    const checkpoint = next.recoveryCheckpoint;
    requireValue(next.flockUuid === current.flockUuid && next.rosterEpoch > current.rosterEpoch && checkpoint?.baseEpoch === current.rosterEpoch && checkpoint.baseRosterHash === hashRoster(current) && checkpoint.nextRosterHash === checkpointTarget(next), "Missing valid genesis-root recovery checkpoint");
    requireValue(crypto.verify(null, Buffer.from(canonicalJson(withoutSignature(checkpoint))), publicKey(root.signingPub, "ed25519"), Buffer.from(checkpoint.signature, "base64")), "Invalid recovery checkpoint signature");
    verifyRosterSignature(next, root);
    preserveConsumedVouchers(current, next);
    current = next;
  }
  if (requireFresh) checkLease(current, nowMs);
  if (state) state.acceptVerifiedRoster(current);
  return current;
}

function actorAuthority(roster, actor) {
  const signer = roster.ownerSigners.find((entry) => entry.opaquePeerId === actor.opaquePeerId);
  requireValue(signer && keyFingerprint(signer.signingPub) === keyFingerprint(crypto.createPrivateKey(actor.signingPriv)), "Unauthorized owner signing key");
  return signer;
}

function buildMemberTransport(roster, member, ownerCredentials, nowMs) {
  validateOwnerCredentials(ownerCredentials);
  const { signalr, serviceBus } = ownerCredentials;
  requireValue(signalr?.endpoint && signalr.accessKey && serviceBus?.namespaceHost && serviceBus.topicName && serviceBus.sendRuleKey && serviceBus.listenRuleKey, "Epoch rotation requires complete issuer credentials");
  requireValue(new RegExp(`-f${roster.flockUuid.replaceAll("-", "")}-e${roster.rosterEpoch}-[0-9a-f]{12}$`).test(serviceBus.topicName), "Epoch topic must be flock-isolated and uniquely staged");
  const hubName = epochHubName(roster.flockUuid, roster.rosterEpoch);
  const subscriptionName = `sub-${member.opaquePeerId}-e${roster.rosterEpoch}`;
  const expiresAtSeconds = Math.floor(Math.min(Date.parse(roster.leaseExpiresAt), member.membershipExpiresAt ? Date.parse(member.membershipExpiresAt) : Infinity) / 1000);
  requireValue(expiresAtSeconds > Math.floor(nowMs / 1000), "Transport lease has expired");
  const signalrParameters = { endpoint: signalr.endpoint, accessKey: signalr.accessKey, hubName, opaquePeerId: member.opaquePeerId, expiresAtSeconds };
  const serviceBusParameters = { namespaceHost: serviceBus.namespaceHost, topicName: serviceBus.topicName, expiresAtSeconds };
  return {
    endpoint: endpointUrl(signalr.endpoint), hubName, namespaceHost: serviceBus.namespaceHost, topicName: serviceBus.topicName, subscriptionName, expiresAtSeconds,
    wsClientJwt: mintSignalRToken({ ...signalrParameters, isRestPublish: false }),
    hubPublishJwt: mintSignalRToken({ ...signalrParameters, isRestPublish: true }),
    sbSendSas: mintServiceBusSas({ ...serviceBusParameters, ruleName: "FlockSendRule", ruleKey: serviceBus.sendRuleKey }),
    sbListenSas: mintServiceBusSas({ ...serviceBusParameters, ruleName: "FlockListenRule", ruleKey: serviceBus.listenRuleKey, subscriptionName }),
  };
}

function validateOwnerCredentials(credentials) {
  requireValue(credentials && Object.keys(credentials).length === 2 && credentials.signalr && credentials.serviceBus, "Owner vault accepts only Azure transport credentials");
  const { signalr, serviceBus } = credentials;
  requireValue(Object.keys(signalr).length === 2 && typeof signalr.endpoint === "string" && typeof signalr.accessKey === "string" && signalr.accessKey.length > 0, "Invalid SignalR issuer credentials");
  endpointUrl(signalr.endpoint);
  requireValue(Object.keys(serviceBus).length === 4 && ["namespaceHost", "topicName", "sendRuleKey", "listenRuleKey"].every((key) => typeof serviceBus[key] === "string" && serviceBus[key].length > 0), "Invalid Service Bus issuer credentials");
}

function resealEpoch(roster, { actor, ownerCredentials, nowMs = Date.now() }) {
  const key = crypto.randomBytes(32);
  try {
    const next = structuredClone(roster);
    for (const member of next.members) {
      member.sealedMemberBundle = sealBundle({
        payload: { flockKey: key.toString("base64"), transport: buildMemberTransport(next, member, ownerCredentials, nowMs) },
        recipientEncPubPem: member.encPub, flockUuid: next.flockUuid, rosterEpoch: next.rosterEpoch,
        recipientOpaquePeerId: member.opaquePeerId, bundleType: "member",
      });
    }
    next.sealedOwnerVault = {};
    for (const signer of next.ownerSigners) {
      if (signer.role !== "genesis-root" && !signer.permissions.canMintTokens) continue;
      const member = next.members.find((entry) => entry.opaquePeerId === signer.opaquePeerId);
      next.sealedOwnerVault[signer.opaquePeerId] = sealBundle({
        payload: ownerCredentials, recipientEncPubPem: member.encPub, flockUuid: next.flockUuid,
        rosterEpoch: next.rosterEpoch, recipientOpaquePeerId: member.opaquePeerId, bundleType: "owner-vault",
      });
    }
    const signed = signRoster(next, actor);
    validateRosterShape(signed, nowMs);
    return signed;
  } finally { key.fill(0); }
}

export function createGenesisRoster({ owner, ownerCredentials, nowMs = Date.now() }) {
  const member = { opaquePeerId: owner.opaquePeerId, signingPub: owner.signingPub, encPub: owner.encPub, role: "owner", membershipExpiresAt: null };
  return resealEpoch({
    schema: ROSTER_SCHEMA, flockUuid: owner.flockUuid, rosterEpoch: 1, prevRosterHash: "GENESIS",
    issuedAt: new Date(nowMs).toISOString(), leaseExpiresAt: new Date(nowMs + MAX_LEASE_MS).toISOString(),
    rootFingerprint: keyFingerprint(owner.signingPub),
    ownerSigners: [{ opaquePeerId: owner.opaquePeerId, signingPub: owner.signingPub, role: "genesis-root", permissions: { canKick: true, canModifyOwners: true, canMintTokens: true } }],
    members: [member], pendingVouchers: {}, consumedVouchers: {}, sealedOwnerVault: {},
  }, { actor: owner, ownerCredentials, nowMs });
}

export function createPreBoundInvite({ roster, actor, recipient, role = "guest", membershipExpiresAt = null, ownerPermissions = null, ...epochOptions }) {
  requireValue(PEER.test(recipient.opaquePeerId) && !roster.members.some((member) => member.opaquePeerId === recipient.opaquePeerId), "Invalid or existing pre-bound recipient");
  publicKey(recipient.signingPub, "ed25519");
  publicKey(recipient.encPub, "x25519");
  if (role === "owner") {
    requireValue(actorAuthority(roster, actor).role === "genesis-root" && ownerPermissions, "Owner delegation requires explicit genesis-root permissions");
  }
  return rotateRosterEpoch({ roster, actor, ...epochOptions, mutate: (next) => {
    next.members.push({ opaquePeerId: recipient.opaquePeerId, signingPub: recipient.signingPub, encPub: recipient.encPub, role, membershipExpiresAt });
    if (role === "owner") next.ownerSigners.push({ opaquePeerId: recipient.opaquePeerId, signingPub: recipient.signingPub, role: "owner-delegate", permissions: ownerPermissions });
  } });
}

export function rotateRosterEpoch({ roster, actor, mutate = () => {}, ownerCredentials, nowMs = Date.now() }) {
  const authority = actorAuthority(roster, actor);
  requireValue(authority.permissions.canMintTokens, "Epoch rotation requires an online authorized token issuer");
  const next = structuredClone(withoutSignature(roster));
  next.rosterEpoch++;
  next.prevRosterHash = hashRoster(roster);
  next.issuedAt = new Date(nowMs).toISOString();
  next.leaseExpiresAt = new Date(nowMs + MAX_LEASE_MS).toISOString();
  delete next.recoveryCheckpoint;
  mutate(next);
  const signed = resealEpoch(next, { actor, ownerCredentials, nowMs });
  validateRosterTransition(roster, signed, nowMs);
  return signed;
}

export function renewRosterLease(options) {
  return rotateRosterEpoch(options);
}

export function kickMemberFromRoster({ roster, actor, opaquePeerId, ...epochOptions }) {
  const authority = actorAuthority(roster, actor);
  requireValue(authority.permissions.canKick, "Owner lacks kick permission");
  requireValue(roster.members.some((entry) => entry.opaquePeerId === opaquePeerId), "Unknown kick target");
  requireValue(!roster.ownerSigners.some((entry) => entry.opaquePeerId === opaquePeerId), "Use genesis-root recovery to remove an owner delegate");
  return rotateRosterEpoch({ roster, actor, ...epochOptions, mutate: (next) => { next.members = next.members.filter((entry) => entry.opaquePeerId !== opaquePeerId); } });
}

export function pruneExpiredMembersAndRotate({ roster, actor, nowMs = Date.now(), ...epochOptions }) {
  const expired = roster.members.filter((entry) => entry.membershipExpiresAt && Date.parse(entry.membershipExpiresAt) <= nowMs);
  if (!expired.length) return roster;
  return rotateRosterEpoch({ roster, actor, nowMs, ...epochOptions, mutate: (next) => { next.members = next.members.filter((entry) => !expired.some((old) => old.opaquePeerId === entry.opaquePeerId)); } });
}

export function recoverFromCompromisedDelegate({ roster, actor, delegateOpaquePeerId, rotatedOwnerCredentials, ...epochOptions }) {
  requireValue(actorAuthority(roster, actor).role === "genesis-root", "Recovery requires genesis-root signature");
  requireValue(roster.ownerSigners.some((entry) => entry.opaquePeerId === delegateOpaquePeerId && entry.role === "owner-delegate"), "Recovery target must be an owner delegate");
  validateOwnerCredentials(rotatedOwnerCredentials);
  const previous = openSealedBundle({
    bundle: roster.sealedOwnerVault[actor.opaquePeerId], recipientEncPrivPem: actor.encPriv,
    flockUuid: roster.flockUuid, rosterEpoch: roster.rosterEpoch,
    recipientOpaquePeerId: actor.opaquePeerId, bundleType: "owner-vault",
  });
  requireValue(previous.signalr.accessKey !== rotatedOwnerCredentials.signalr.accessKey && previous.serviceBus.sendRuleKey !== rotatedOwnerCredentials.serviceBus.sendRuleKey && previous.serviceBus.listenRuleKey !== rotatedOwnerCredentials.serviceBus.listenRuleKey, "Recovery requires changed SignalR, Send and Listen signing keys");
  return rotateRosterEpoch({ roster, actor, ownerCredentials: rotatedOwnerCredentials, ...epochOptions, mutate: (next) => {
    next.ownerSigners = next.ownerSigners.filter((entry) => entry.opaquePeerId !== delegateOpaquePeerId);
    next.members = next.members.filter((entry) => entry.opaquePeerId !== delegateOpaquePeerId);
    for (const [id, voucher] of Object.entries(next.pendingVouchers)) if (voucher.issuedByOpaquePeerId === delegateOpaquePeerId) delete next.pendingVouchers[id];
  } });
}

export function createRecoveryCheckpoint({ trustedRoster, nextRoster, actor, nowMs = Date.now() }) {
  requireValue(actorAuthority(trustedRoster, actor).role === "genesis-root", "Checkpoint requires the trusted genesis root");
  validateRosterShape(nextRoster, nowMs);
  requireValue(nextRoster.flockUuid === trustedRoster.flockUuid && nextRoster.rosterEpoch > trustedRoster.rosterEpoch, "Recovery checkpoint must advance the same flock");
  preserveConsumedVouchers(trustedRoster, nextRoster);
  const body = { baseEpoch: trustedRoster.rosterEpoch, baseRosterHash: hashRoster(trustedRoster), nextRosterHash: checkpointTarget(nextRoster) };
  const recoveryCheckpoint = { ...body, signature: crypto.sign(null, Buffer.from(canonicalJson(body)), actor.signingPriv).toString("base64") };
  return signRoster({ ...withoutSignature(nextRoster), recoveryCheckpoint }, actor);
}

function voucherBody(voucher) {
  const { ownerSignature, ...body } = voucher;
  return body;
}

export function createInviteVoucher({ roster, actor, rosterUrl, enrollmentSbSendSas, role = "guest", expiresAt, recipientBinding = null, nowMs = Date.now() }) {
  checkLease(roster, nowMs);
  actorAuthority(roster, actor);
  requireValue(["collaborator", "guest"].includes(role), "Owner delegation requires a separate genesis-root governance transition");
  requireValue(new URL(rosterUrl).protocol === "https:" && typeof enrollmentSbSendSas === "string" && enrollmentSbSendSas.startsWith("SharedAccessSignature "), "Invite requires HTTPS roster and provisional send token");
  requireValue(Date.parse(expiresAt) > nowMs, "Voucher already expired");
  const body = { voucherId: crypto.randomUUID(), flockUuid: roster.flockUuid, rosterUrl, rootFingerprint: roster.rootFingerprint, enrollmentSbSendSas, role, maxDevices: 1, expiresAt, recipientBinding };
  const voucher = { ...body, ownerSignature: { signedByOpaquePeerId: actor.opaquePeerId, ed25519Signature: crypto.sign(null, Buffer.from(canonicalJson(body)), actor.signingPriv).toString("base64") } };
  return { voucher, pendingRecord: { voucherId: voucher.voucherId, voucherHash: digest(canonicalJson(voucher)), issuedByOpaquePeerId: actor.opaquePeerId, role, expiresAt, recipientBinding } };
}

function claimCanonical(claim) {
  requireValue(UUID.test(claim.flockUuid) && UUID.test(claim.voucherId) && PEER.test(claim.opaquePeerId) && /^[a-z0-9][a-z0-9-]{0,38}$/i.test(claim.githubUser), "Invalid enrollment claim coordinates");
  publicKey(claim.signingPub, "ed25519");
  publicKey(claim.encPub, "x25519");
  return `copilot-flock-v3-enroll|${claim.flockUuid}|${claim.voucherId}|${claim.opaquePeerId}|${claim.signingPub}|${claim.encPub}|${claim.githubUser}`;
}

export function verifyEnrollmentClaimProof({ roster, voucher, claim, nowMs = Date.now() }) {
  const pending = roster.pendingVouchers[voucher.voucherId];
  const issuer = roster.ownerSigners.find((entry) => entry.opaquePeerId === voucher.ownerSignature?.signedByOpaquePeerId);
  requireValue(pending && !roster.consumedVouchers[voucher.voucherId] && pending.voucherHash === digest(canonicalJson(voucher)), "Unknown or consumed enrollment voucher");
  requireValue(voucher.flockUuid === roster.flockUuid && voucher.rootFingerprint === roster.rootFingerprint && claim.flockUuid === roster.flockUuid && claim.voucherId === voucher.voucherId && Date.parse(voucher.expiresAt) > nowMs, "Invalid enrollment claim coordinates or expiry");
  requireValue(issuer && crypto.verify(null, Buffer.from(canonicalJson(voucherBody(voucher))), publicKey(issuer.signingPub, "ed25519"), Buffer.from(voucher.ownerSignature.ed25519Signature, "base64")), "Invalid voucher signature");
  requireValue(claim.action === "ENROLL_CLAIM" && crypto.verify(null, Buffer.from(claimCanonical(claim)), publicKey(claim.signingPub, "ed25519"), Buffer.from(claim.signature, "base64")), "Invalid enrollment proof of possession");
  return { signingFingerprint: keyFingerprint(claim.signingPub), encFingerprint: keyFingerprint(claim.encPub) };
}

export function createEnrollmentClaim({ voucher, device, githubUser }) {
  requireValue(device.flockUuid === voucher.flockUuid, "Cross-flock enrollment device");
  const claim = { action: "ENROLL_CLAIM", flockUuid: voucher.flockUuid, voucherId: voucher.voucherId, opaquePeerId: device.opaquePeerId, signingPub: device.signingPub, encPub: device.encPub, githubUser };
  return { ...claim, signature: crypto.sign(null, Buffer.from(claimCanonical(claim)), device.signingPriv).toString("base64") };
}

export function approveEnrollmentClaim({ claim, actor, verifiedSigningFingerprint, verifiedEncFingerprint }) {
  requireValue(verifiedSigningFingerprint === keyFingerprint(claim.signingPub) && verifiedEncFingerprint === keyFingerprint(claim.encPub), "Independent fingerprint verification does not match claim");
  const body = { claimHash: digest(canonicalJson(claim)), verifiedSigningFingerprint, verifiedEncFingerprint, approvedByOpaquePeerId: actor.opaquePeerId };
  return { ...body, signature: crypto.sign(null, Buffer.from(canonicalJson(body)), actor.signingPriv).toString("base64") };
}

export function redeemEnrollmentClaim({ roster, voucher, claim, actor, approval = null, membershipExpiresAt = null, ...epochOptions }) {
  const nowMs = epochOptions.nowMs ?? Date.now();
  checkLease(roster, nowMs);
  const pending = roster.pendingVouchers[voucher.voucherId];
  requireValue(pending && !roster.consumedVouchers[voucher.voucherId] && pending.voucherHash === digest(canonicalJson(voucher)), "Unknown, modified or already consumed voucher");
  requireValue(voucher.flockUuid === roster.flockUuid && claim.flockUuid === roster.flockUuid && claim.voucherId === voucher.voucherId && voucher.maxDevices === 1 && voucher.rootFingerprint === roster.rootFingerprint && Date.parse(voucher.expiresAt) > nowMs, "Invalid or expired voucher");
  const issuer = roster.ownerSigners.find((entry) => entry.opaquePeerId === voucher.ownerSignature.signedByOpaquePeerId);
  requireValue(issuer && pending.issuedByOpaquePeerId === issuer.opaquePeerId && crypto.verify(null, Buffer.from(canonicalJson(voucherBody(voucher))), publicKey(issuer.signingPub, "ed25519"), Buffer.from(voucher.ownerSignature.ed25519Signature, "base64")), "Invalid voucher owner signature");
  requireValue(claim.action === "ENROLL_CLAIM" && crypto.verify(null, Buffer.from(claimCanonical(claim)), publicKey(claim.signingPub, "ed25519"), Buffer.from(claim.signature, "base64")), "Invalid enrollment proof of possession");
  const signingFingerprint = keyFingerprint(claim.signingPub);
  const encFingerprint = keyFingerprint(claim.encPub);
  if (pending.recipientBinding) {
    requireValue(pending.recipientBinding.signingFingerprint === signingFingerprint && pending.recipientBinding.encFingerprint === encFingerprint, "Pre-bound recipient key mismatch");
  } else {
    const approver = roster.ownerSigners.find((entry) => entry.opaquePeerId === approval?.approvedByOpaquePeerId);
    requireValue(approver && approval.claimHash === digest(canonicalJson(claim)) && approval.verifiedSigningFingerprint === signingFingerprint && approval.verifiedEncFingerprint === encFingerprint && crypto.verify(null, Buffer.from(canonicalJson(withoutSignature(approval))), publicKey(approver.signingPub, "ed25519"), Buffer.from(approval.signature, "base64")), "Unbound claim requires independently verified owner approval");
  }
  requireValue(!membershipExpiresAt || Date.parse(membershipExpiresAt) > nowMs, "Membership already expired");
  return rotateRosterEpoch({ roster, actor, ...epochOptions, nowMs, mutate: (next) => {
    delete next.pendingVouchers[voucher.voucherId];
    next.consumedVouchers[voucher.voucherId] = { opaquePeerId: claim.opaquePeerId, claimHash: digest(canonicalJson(claim)) };
    next.members.push({ opaquePeerId: claim.opaquePeerId, signingPub: claim.signingPub, encPub: claim.encPub, role: voucher.role, membershipExpiresAt });
  } });
}

export async function publishRosterWithCas({ readLatest, prepare, put, discard, trustedRoster, state, attempts = 3, nowMs = () => Date.now() }) {
  requireValue(Number.isSafeInteger(attempts) && attempts > 0 && attempts <= 10, "Invalid CAS retry bound");
  let current = trustedRoster;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const latest = await readLatest(current);
    current = verifyRosterChain(current, latest.transitions, nowMs(), { state, requireFresh: false });
    const candidate = await prepare(current);
    let publicationConfirmed = false;
    let cleanupStarted = false;
    const discardOnce = async () => {
      if (cleanupStarted) return;
      cleanupStarted = true;
      await discard(candidate);
    };
    try {
      validateRosterTransition(current, candidate.roster, nowMs());
      const result = await put({ roster: candidate.roster, sha: latest.sha });
      if (result.status === 409) {
        await discardOnce();
        continue;
      }
      requireValue(result.status === 200 || result.status === 201, `GitHub roster CAS failed with HTTP ${result.status}`);
      publicationConfirmed = true;
      if (state) state.acceptVerifiedRoster(candidate.roster);
      return candidate.roster;
    } catch (err) {
      if (err.ambiguous) throw new Error("Roster publication outcome UNKNOWN; reconcile GitHub before deleting staging resources", { cause: err });
      if (publicationConfirmed) throw new Error("Roster was published but local persistence failed; reconcile without deleting committed resources", { cause: err });
      await discardOnce();
      throw err;
    }
  }
  throw new Error("Roster CAS conflict retry limit reached");
}

function activeMember(roster, id, nowMs) {
  requireValue(PEER.test(id), "Invalid peer ID");
  const member = roster.members.find((entry) => entry.opaquePeerId === id);
  requireValue(member && member.role !== "provisional", "Peer is not an active roster member");
  requireValue(!member.membershipExpiresAt || Date.parse(member.membershipExpiresAt) > nowMs, "Membership expired");
  return member;
}

function checkLease(roster, nowMs) {
  requireValue(Date.parse(roster.leaseExpiresAt) > nowMs, "Signed roster freshness lease expired");
}

const INFORMATIONAL_ACTIONS = new Set(["ping", "list_shared_threads", "get_transcript", "list_sessions"]);

function actionAllowed(member, action) {
  if (member.role === "owner") return true;
  return INFORMATIONAL_ACTIONS.has(action);
}

function envelopeCanonical(inner) {
  return [inner.version, inner.flockUuid, inner.rosterEpoch, inner.prevRosterHash, inner.action, inner.fromOpaquePeerId, inner.toOpaquePeerId, inner.messageId, inner.timestamp, inner.expiresAt, inner.bodySha256].join("|");
}

function messageContext(header) {
  coordinates({ ...header, recipientOpaquePeerId: header.toOpaquePeerId, bundleType: "message" });
  requireValue(PEER.test(header.fromOpaquePeerId), "Invalid sender peer ID");
  requireValue(/^[A-Za-z0-9_-]{16,128}$/.test(header.messageId), "Invalid message ID");
  return `${header.flockUuid}|${header.rosterEpoch}|${header.fromOpaquePeerId}|${header.toOpaquePeerId}|${header.messageId}`;
}

function messageMaterial(flockKey, header) {
  requireValue(Buffer.isBuffer(flockKey) && flockKey.length === 32, "Expected a 256-bit flock key");
  return derive(flockKey, `${header.fromOpaquePeerId}:${header.messageId}`, `copilot-flock-v3-msg|${header.flockUuid}|${header.rosterEpoch}`);
}

export function encryptFlockEnvelope({ roster, state, flockKey, signingPriv, action, fromOpaquePeerId, toOpaquePeerId, body, messageId = crypto.randomUUID(), nowMs = Date.now(), expiresAt }) {
  state.assertRoster(roster);
  checkLease(roster, nowMs);
  const member = activeMember(roster, fromOpaquePeerId, nowMs);
  const recipient = activeMember(roster, toOpaquePeerId, nowMs);
  expiresAt ??= new Date(Math.min(nowMs + 60000, Date.parse(roster.leaseExpiresAt), member.membershipExpiresAt ? Date.parse(member.membershipExpiresAt) : Infinity, recipient.membershipExpiresAt ? Date.parse(recipient.membershipExpiresAt) : Infinity)).toISOString();
  requireValue(/^[a-z][a-z0-9_]{0,63}$/.test(action) && actionAllowed(member, action), "Action denied for sender role");
  requireValue(keyFingerprint(member.signingPub) === keyFingerprint(crypto.createPrivateKey(signingPriv)), "Sender signing key mismatch");
  const expiry = Date.parse(expiresAt);
  requireValue(expiry > nowMs && expiry <= Date.parse(roster.leaseExpiresAt) && (!member.membershipExpiresAt || expiry <= Date.parse(member.membershipExpiresAt)), "Invalid envelope expiry");
  const inner = { version: ENVELOPE_VERSION, flockUuid: roster.flockUuid, rosterEpoch: roster.rosterEpoch, prevRosterHash: roster.prevRosterHash, action, fromOpaquePeerId, toOpaquePeerId, messageId, timestamp: new Date(nowMs).toISOString(), expiresAt, bodySha256: digest(canonicalJson(body)), body };
  const header = { flockUuid: inner.flockUuid, rosterEpoch: inner.rosterEpoch, fromOpaquePeerId, toOpaquePeerId, messageId };
  const aad = messageContext(header);
  inner.signature = crypto.sign(null, Buffer.from(envelopeCanonical(inner), "utf8"), signingPriv).toString("base64");
  const plaintext = Buffer.from(canonicalJson(inner));
  requireValue(plaintext.length <= MAX_ENVELOPE_BYTES, "Envelope exceeds size limit");
  state.claim("send", roster, fromOpaquePeerId, messageId, expiry, nowMs);
  const material = messageMaterial(flockKey, header);
  try { return { ...header, ...encodeGcm(plaintext, material, aad) }; }
  finally { material.fill(0); }
}

export function decryptFlockEnvelope({ envelope, roster, state, flockKey, recipientOpaquePeerId, nowMs = Date.now() }) {
  state.assertRoster(roster);
  checkLease(roster, nowMs);
  requireValue(envelope.flockUuid === roster.flockUuid && envelope.rosterEpoch === roster.rosterEpoch && envelope.toOpaquePeerId === recipientOpaquePeerId, "Cross-flock, stale-epoch or wrong-recipient envelope");
  activeMember(roster, recipientOpaquePeerId, nowMs);
  const member = activeMember(roster, envelope.fromOpaquePeerId, nowMs);
  const aad = messageContext(envelope);
  const material = messageMaterial(flockKey, envelope);
  let inner;
  try {
    const plaintext = decodeGcm(envelope, material, aad);
    requireValue(plaintext.length <= MAX_ENVELOPE_BYTES, "Envelope exceeds size limit");
    inner = JSON.parse(plaintext.toString("utf8"));
  }
  finally { material.fill(0); }
  requireValue(inner.version === ENVELOPE_VERSION && inner.flockUuid === roster.flockUuid && inner.rosterEpoch === roster.rosterEpoch && inner.prevRosterHash === roster.prevRosterHash && inner.fromOpaquePeerId === envelope.fromOpaquePeerId && inner.toOpaquePeerId === recipientOpaquePeerId && inner.messageId === envelope.messageId, "Envelope binding mismatch");
  requireValue(/^[a-z][a-z0-9_]{0,63}$/.test(inner.action) && actionAllowed(member, inner.action), "Action denied for sender role");
  const expiry = Date.parse(inner.expiresAt);
  const timestamp = Date.parse(inner.timestamp);
  requireValue(Number.isFinite(timestamp) && timestamp <= nowMs + 30000 && expiry > nowMs && expiry > timestamp && expiry <= Date.parse(roster.leaseExpiresAt) && (!member.membershipExpiresAt || expiry <= Date.parse(member.membershipExpiresAt)), "Expired or invalid envelope timestamps");
  requireValue(inner.bodySha256 === digest(canonicalJson(inner.body)), "Envelope body digest mismatch");
  requireValue(crypto.verify(null, Buffer.from(envelopeCanonical(inner), "utf8"), publicKey(member.signingPub, "ed25519"), Buffer.from(inner.signature, "base64")), "Invalid envelope signature");
  state.claim("receive", roster, member.opaquePeerId, inner.messageId, expiry, nowMs);
  return inner;
}

function endpointUrl(endpoint) {
  const url = new URL(endpoint);
  requireValue(url.protocol === "https:" && !url.username && !url.password && url.pathname === "/" && !url.search && !url.hash, "Expected HTTPS service origin");
  return url.origin;
}

function jwt(audience, accessKey, opaquePeerId, expiresAtSeconds) {
  requireValue(PEER.test(opaquePeerId) && Number.isSafeInteger(expiresAtSeconds), "Invalid token identity or expiry");
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ aud: audience, nameid: opaquePeerId, "asrs.s.uid": opaquePeerId, exp: expiresAtSeconds })).toString("base64url");
  requireValue(typeof accessKey === "string" && accessKey.length > 0, "Missing SignalR signing key");
  return `${header}.${payload}.${crypto.createHmac("sha256", Buffer.from(accessKey, "utf8")).update(`${header}.${payload}`).digest("base64url")}`;
}

export function epochHubName(flockUuid, rosterEpoch) {
  coordinates({ flockUuid, rosterEpoch, recipientOpaquePeerId: `peer_${"0".repeat(24)}`, bundleType: "hub" });
  return `v3_flock_${flockUuid.replaceAll("-", "")}_e${rosterEpoch}`;
}

export function mintSignalRToken({ endpoint, accessKey, hubName, opaquePeerId, expiresAtSeconds, isRestPublish }) {
  requireValue(/^v3_flock_[0-9a-f]{32}_e[1-9][0-9]*$/.test(hubName), "Expected epoch-isolated hub");
  const origin = endpointUrl(endpoint);
  return jwt(isRestPublish ? `${origin}/api/v1/hubs/${hubName}` : `${origin}/client/?hub=${hubName}`, accessKey, opaquePeerId, expiresAtSeconds);
}

export function mintServiceBusSas({ namespaceHost, topicName, ruleName, ruleKey, subscriptionName, expiresAtSeconds }) {
  requireValue(/^[a-z0-9-]+\.servicebus\.windows\.net$/i.test(namespaceHost) && /^[a-z0-9._-]+$/i.test(topicName), "Invalid Service Bus entity");
  requireValue(Number.isSafeInteger(expiresAtSeconds) && typeof ruleKey === "string" && ruleKey.length > 0, "Invalid Service Bus key or expiry");
  requireValue(ruleName === (subscriptionName ? "FlockListenRule" : "FlockSendRule"), "Incorrect least-privilege Service Bus rule");
  if (subscriptionName) requireValue(/^sub-peer_[0-9a-f]{24}-e[1-9][0-9]*$/.test(subscriptionName), "Expected epoch-bound subscription");
  const uri = `https://${namespaceHost}/${topicName}${subscriptionName ? `/subscriptions/${subscriptionName}` : ""}`.toLowerCase();
  const sr = encodeURIComponent(uri);
  const sig = encodeURIComponent(crypto.createHmac("sha256", Buffer.from(ruleKey, "utf8")).update(`${sr}\n${expiresAtSeconds}`).digest("base64"));
  return `SharedAccessSignature sr=${sr}&sig=${sig}&se=${expiresAtSeconds}&skn=${encodeURIComponent(ruleName)}`;
}

export function buildSignalRCloseUserConnectionsRequest({ endpoint, accessKey, hubName, opaquePeerId, nowMs = Date.now() }) {
  requireValue(/^v3_flock_[0-9a-f]{32}_e[1-9][0-9]*$/.test(hubName) && PEER.test(opaquePeerId), "Invalid close-connections target");
  const audience = `${endpointUrl(endpoint)}/api/hubs/${hubName}/users/${encodeURIComponent(opaquePeerId)}/:closeConnections`;
  return { method: "POST", url: `${audience}?api-version=2024-12-01`, headers: { Authorization: `Bearer ${jwt(audience, accessKey, opaquePeerId, Math.floor(nowMs / 1000) + 60)}` } };
}
