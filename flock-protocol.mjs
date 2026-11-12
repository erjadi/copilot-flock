import crypto from "node:crypto";
import fs from "node:fs";
import { atomicJson, assertNoLinks } from "./flock-lifecycle.mjs";

const DAY = 86400000;
const MAX_BYTES = 128 * 1024;
const domain = "copilot-flock/3.4/";
const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
const encode = (value) => Buffer.from(value).toString("base64url");
export function peerSubscription(peerId) {
  if (typeof peerId !== "string" || !/^[a-f0-9]{64}$/.test(peerId)) throw new Error("Invalid subscription peer identity");
  return `sub-${digest(domain + "subscription\n" + peerId).slice(0, 46)}`;
}
function bytes(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Noncanonical binary encoding");
  const result = Buffer.from(value, "base64url");
  if (encode(result) !== value || (length !== undefined && result.length !== length)) throw new Error("Invalid binary length");
  return result;
}
export function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new Error("Noncanonical protocol value");
}
function sign(label, value, privateKey) {
  return encode(crypto.sign(null, Buffer.from(domain + label + "\n" + canonical(value)), privateKey));
}
function verify(label, value, signature, publicKey) {
  const key = crypto.createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ed25519" ||
      !crypto.verify(null, Buffer.from(domain + label + "\n" + canonical(value)), key, bytes(signature, 64))) {
    throw new Error(`Invalid ${label} signature`);
  }
}
function keypair(type) {
  return crypto.generateKeyPairSync(type, { publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" } });
}
export function createDeviceIdentity() {
  return { ed25519: keypair("ed25519"), x25519: keypair("x25519") };
}
export function ownerFingerprint(publicKey) {
  const key = crypto.createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Owner must use Ed25519");
  return digest(key.export({ type: "spki", format: "der" }));
}
function publicDevice(join) {
  if (!["personal", "work"].includes(join.scope) || typeof join.machineId !== "string" ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(join.machineId)) throw new Error("Invalid device machine/scope");
  if (crypto.createPublicKey(join.deviceEd25519Pub).asymmetricKeyType !== "ed25519" ||
      crypto.createPublicKey(join.deviceX25519Pub).asymmetricKeyType !== "x25519") throw new Error("Wrong device key algorithm");
  if (join.peerId !== ownerFingerprint(join.deviceEd25519Pub)) throw new Error("Peer ID is not device-key bound");
}
export function createJoinCode(identity, { machineId, scope, flockId }, now = Date.now()) {
  if (!["personal", "work"].includes(scope) || typeof machineId !== "string" ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(machineId)) throw new Error("Invalid machine or scope");
  const body = { type: "copilot-flock-join-v1", peerId: ownerFingerprint(identity.ed25519.publicKey),
    deviceEd25519Pub: identity.ed25519.publicKey, deviceX25519Pub: identity.x25519.publicKey,
    machineId, scope, ...(flockId ? { flockId } : {}), issuedAt: now, expiresAt: now + 600000, nonce: encode(crypto.randomBytes(32)) };
  return { body, signature: sign("join", body, identity.ed25519.privateKey) };
}
export function verifyJoinCode(code, now = Date.now()) {
  if (Buffer.byteLength(canonical(code)) > 16384) throw new Error("Join Code size limit exceeded");
  const join = code.body;
  if (join.type !== "copilot-flock-join-v1" || !Number.isSafeInteger(join.issuedAt) ||
      !Number.isSafeInteger(join.expiresAt) || join.expiresAt <= join.issuedAt || join.issuedAt > now + 30000 ||
      join.expiresAt <= now || join.expiresAt - join.issuedAt > 600000) throw new Error("Expired Join Code");
  publicDevice(join);
  if (join.flockId !== undefined && (typeof join.flockId !== "string" ||
      !/^[a-z0-9-]+\/[a-z0-9-]+$/.test(join.flockId) || join.flockId.length > 128)) throw new Error("Invalid intended flock");
  bytes(join.nonce, 32);
  verify("join", join, code.signature, join.deviceEd25519Pub);
  return join;
}
export function validateCert(cert, ownerPublicKey, now = Date.now()) {
  verify("member-cert", cert.body, cert.signature, ownerPublicKey);
  const body = cert.body;
  publicDevice(body);
  if (body.type !== "copilot-flock-member-v1" ||
      !["owner", "collaborator", "guest"].includes(body.role) ||
      !["personal", "work"].includes(body.scope) ||
      !Number.isSafeInteger(body.issuedAt) || !Number.isSafeInteger(body.expiresAt) ||
      body.issuedAt > now + 30000 || body.expiresAt <= now ||
      body.expiresAt - body.issuedAt > DAY || body.expiresAt <= body.issuedAt ||
      typeof body.flockId !== "string" || !/^[a-z0-9-]+\/[a-z0-9-]+$/.test(body.flockId) || body.flockId.length > 128 ||
      !Array.isArray(body.sessionIds) || body.sessionIds.some((id) => typeof id !== "string" || !id || id.length > 128) ||
      body.sessionIds.length > 100) throw new Error("Invalid or expired MemberCert");
  return body;
}
export function verifyRosterMemberCert(cert, ownerPublicKey, expectedFlockId = null, now = Date.now()) {
  if (!cert || typeof cert !== "object" || !cert.body) throw new Error("Missing MemberCert");
  verify("member-cert", cert.body, cert.signature, ownerPublicKey);
  const body = cert.body;
  publicDevice(body);
  if (body.type !== "copilot-flock-member-v1" ||
      !["owner", "collaborator", "guest"].includes(body.role) ||
      !["personal", "work"].includes(body.scope) ||
      !Number.isSafeInteger(body.issuedAt) || !Number.isSafeInteger(body.expiresAt) ||
      body.issuedAt > now + 30000 ||
      body.expiresAt - body.issuedAt > DAY || body.expiresAt <= body.issuedAt ||
      typeof body.flockId !== "string" || !/^[a-z0-9-]+\/[a-z0-9-]+$/.test(body.flockId) || body.flockId.length > 128 ||
      (expectedFlockId && body.flockId !== expectedFlockId) ||
      !Array.isArray(body.sessionIds) || body.sessionIds.some((id) => typeof id !== "string" || !id || id.length > 128) ||
      body.sessionIds.length > 100) throw new Error("Invalid MemberCert");
  return { ...body, credentialExpired: body.expiresAt <= now };
}
function sharedKey(privateKey, publicKey, salt, info) {
  if (crypto.createPublicKey(publicKey).asymmetricKeyType !== "x25519") throw new Error("Expected X25519 recipient");
  const secret = crypto.diffieHellman({ privateKey: crypto.createPrivateKey(privateKey), publicKey: crypto.createPublicKey(publicKey) });
  return Buffer.from(crypto.hkdfSync("sha256", secret, salt, Buffer.from(domain + info), 32));
}
export function seal(value, recipientPublicKey) {
  const ephemeral = keypair("x25519");
  const salt = crypto.randomBytes(32);
  const aad = Buffer.from(canonical({ publicKey: ephemeral.publicKey, salt: encode(salt) }));
  const cipher = crypto.createCipheriv("aes-256-gcm", sharedKey(ephemeral.privateKey, recipientPublicKey, salt, "welcome"), Buffer.alloc(12));
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(canonical(value)), cipher.final()]);
  return { publicKey: ephemeral.publicKey, salt: encode(salt), ciphertext: encode(ciphertext), tag: encode(cipher.getAuthTag()) };
}
export function unseal(box, privateKey) {
  const salt = bytes(box.salt, 32);
  const aad = Buffer.from(canonical({ publicKey: box.publicKey, salt: box.salt }));
  const decipher = crypto.createDecipheriv("aes-256-gcm", sharedKey(privateKey, box.publicKey, salt, "welcome"), Buffer.alloc(12));
  decipher.setAAD(aad);
  decipher.setAuthTag(bytes(box.tag, 16));
  return JSON.parse(Buffer.concat([decipher.update(bytes(box.ciphertext)), decipher.final()]).toString("utf8"));
}

export async function approveJoin({ code, ownerIdentity, ownerPublicKey, rotationOwnerPeerId, flockId, role,
  sessionIds = [], membershipExpiresAt, epoch, keyId, groupKey, verifyIdentityPolicy,
  provisionTransport, authorizeOwner, metadata = {}, now = Date.now() }) {
  const join = verifyJoinCode(code, now);
  if (role === "owner") throw new Error("Join approval cannot delegate rotation-owner authority");
  if (!Number.isSafeInteger(membershipExpiresAt) || membershipExpiresAt <= now) throw new Error("Membership expiry required");
  const expiresAt = Math.min(now + DAY, membershipExpiresAt);
  // Neither a GitHub display name nor a self-box grants approval authority.
  await authorizeOwner();
  await verifyIdentityPolicy(join);
  await authorizeOwner();
  const body = { type: "copilot-flock-member-v1", flockId, peerId: join.peerId, role,
    scope: join.scope, machineId: join.machineId, deviceEd25519Pub: join.deviceEd25519Pub,
    deviceX25519Pub: join.deviceX25519Pub, issuedAt: now, expiresAt, sessionIds };
  const cert = { body, signature: sign("member-cert", body, ownerIdentity.ed25519.privateKey) };
  validateCert(cert, ownerPublicKey, now);
  const transport = await provisionTransport({ peerId: join.peerId, subscription: peerSubscription(join.peerId), expiresAt, cert });
  await authorizeOwner();
  const allowedTransportFields = ["expiresAt", "subscription", "signalrClientToken", "signalrRestToken",
    "serviceBusSendSas", "serviceBusListenSas"];
  if (Object.keys(transport).some((field) => !allowedTransportFields.includes(field))) throw new Error("Unexpected transport material");
  if (transport.expiresAt > expiresAt || transport.expiresAt <= now ||
      transport.subscription !== peerSubscription(join.peerId)) throw new Error("Transport scope or expiry mismatch");
  for (const token of [transport.signalrClientToken, transport.signalrRestToken, transport.serviceBusSendSas, transport.serviceBusListenSas]) {
    if (typeof token !== "string" || !token || /(?:AccessKey|SharedAccessKey)=/.test(token)) throw new Error("Scoped transport tokens required; never export transport master keys");
  }
  const payload = { cert, ownerPublicKey, rotationOwnerPeerId, epoch, keyId, groupKey: encode(groupKey), transport, metadata };
  const bodyTicket = { type: "copilot-flock-welcome-v1", peerId: join.peerId, flockId,
    joinHash: digest(canonical(code)), expiresAt, box: seal(payload, join.deviceX25519Pub) };
  return { body: bodyTicket, ownerPublicKey, signature: sign("welcome", bodyTicket, ownerIdentity.ed25519.privateKey) };
}
export function acceptWelcome(ticket, { identity, code, pinnedOwnerFingerprint, now = Date.now() }) {
  if (ownerFingerprint(ticket.ownerPublicKey) !== pinnedOwnerFingerprint) throw new Error("Owner fingerprint pin mismatch");
  verify("welcome", ticket.body, ticket.signature, ticket.ownerPublicKey);
  if (ticket.body.type !== "copilot-flock-welcome-v1" || ticket.body.expiresAt <= now ||
      ticket.body.joinHash !== digest(canonical(code)) ||
      ticket.body.peerId !== ownerFingerprint(identity.ed25519.publicKey)) throw new Error("Welcome Ticket not bound to this Join Code");
  const result = unseal(ticket.body.box, identity.x25519.privateKey);
  const member = validateCert(result.cert, ticket.ownerPublicKey, now);
  if (member.peerId !== ticket.body.peerId || member.flockId !== ticket.body.flockId ||
      member.machineId !== code.body.machineId || member.scope !== code.body.scope ||
      member.deviceX25519Pub !== identity.x25519.publicKey || result.ownerPublicKey !== ticket.ownerPublicKey ||
      member.expiresAt !== ticket.body.expiresAt || result.transport.expiresAt > member.expiresAt) throw new Error("Welcome key/certificate binding mismatch");
  if (!Number.isSafeInteger(result.epoch) || result.epoch < 1 ||
      typeof result.keyId !== "string" || !result.keyId ||
      result.rotationOwnerPeerId !== ownerFingerprint(ticket.ownerPublicKey)) throw new Error("Welcome epoch/owner binding mismatch");
  bytes(result.groupKey, 32);
  return result;
}

function messageKey(groupKey, header) {
  return Buffer.from(crypto.hkdfSync("sha256", groupKey, bytes(header.salt, 32),
    Buffer.from(domain + "message-key\n" + canonical(header)), 32));
}
function authorize(header, cert, state, now) {
  const member = validateCert(cert, state.ownerPublicKey, now);
  if (member.flockId !== state.flockId || header.flockId !== state.flockId ||
      header.peerId !== member.peerId || header.scope !== member.scope ||
      header.epoch !== state.epoch || header.epoch < state.minAcceptedEpoch ||
      header.keyId !== state.keyId || header.sentAt > now + 30000 ||
      header.expiresAt <= now || header.expiresAt > member.expiresAt ||
      header.expiresAt - header.sentAt > 300000 || header.sentAt > header.expiresAt ||
      !Number.isSafeInteger(header.sentAt) || !Number.isSafeInteger(header.expiresAt) ||
      (member.role === "owner" && member.peerId !== state.rotationOwnerPeerId) ||
      typeof header.messageId !== "string" || header.messageId.length > 128 ||
      typeof header.targetPeerId !== "string" ||
      (header.targetPeerId !== "*" && header.targetPeerId !== state.localPeerId && header.peerId !== state.localPeerId)) {
    throw new Error("Envelope scope, epoch, recipient or lifetime rejected");
  }
  return member;
}
export function authorizeAction(member, action, payload) {
  if (typeof action !== "string" || action.length > 64) throw new Error("Invalid action");
  if (member.role === "owner") return;
  if (action === "list_roster" && member.role === "collaborator") return;
  if (["ping", "list_shared_threads", "list_sessions", "rpc_response", "leave", "renew"].includes(action)) return;
  if ((action === "send_message" || action === "get_transcript") &&
      member.sessionIds.includes(payload?.params?.targetSession || payload?.params?.session) &&
      !payload.params.delegate && !payload.params.newSession) return;
  throw new Error("Member role/session scope forbids this action");
}
export function encryptEnvelope({ state, identity, cert, action, payload, targetPeerId, now = Date.now(), messageId = crypto.randomUUID() }) {
  const header = { v: 34, flockId: state.flockId, peerId: ownerFingerprint(identity.ed25519.publicKey),
    scope: cert.body.scope, epoch: state.epoch, keyId: state.keyId, salt: encode(crypto.randomBytes(32)),
    messageId, sentAt: now, expiresAt: Math.min(now + 300000, cert.body.expiresAt),
    targetPeerId, action };
  authorize(header, cert, state, now);
  authorizeAction(cert.body, action, payload);
  const aad = Buffer.from(domain + "aad\n" + canonical({ header, cert }));
  const cipher = crypto.createCipheriv("aes-256-gcm", messageKey(bytes(state.groupKey, 32), header), Buffer.alloc(12));
  cipher.setAAD(aad);
  const plaintext = Buffer.from(canonical(payload));
  if (plaintext.length > MAX_BYTES) throw new Error("Message size limit exceeded");
  const signed = { header, cert, ciphertext: encode(Buffer.concat([cipher.update(plaintext), cipher.final()])),
    tag: encode(cipher.getAuthTag()) };
  return { ...signed, signature: sign("envelope", signed, identity.ed25519.privateKey) };
}

export function decryptEnvelope(envelope, state, now = Date.now()) {
  if (Buffer.byteLength(canonical(envelope)) > MAX_BYTES * 2 || envelope.header.v !== 34) throw new Error("Invalid envelope version or size");
  const member = authorize(envelope.header, envelope.cert, state, now);
  const { signature, ...signed } = envelope;
  verify("envelope", signed, signature, member.deviceEd25519Pub);
  const aad = Buffer.from(domain + "aad\n" + canonical({ header: envelope.header, cert: envelope.cert }));
  const decipher = crypto.createDecipheriv("aes-256-gcm", messageKey(bytes(state.groupKey, 32), envelope.header), Buffer.alloc(12));
  decipher.setAAD(aad);
  decipher.setAuthTag(bytes(envelope.tag, 16));
  const plaintext = Buffer.concat([decipher.update(bytes(envelope.ciphertext)), decipher.final()]);
  if (plaintext.length > MAX_BYTES) throw new Error("Message size limit exceeded");
  const payload = JSON.parse(plaintext.toString("utf8"));
  authorizeAction(member, envelope.header.action, payload);
  return { member, payload };
}

export function createOwnerState({ identity, flockId, scope, machineId, now = Date.now() }) {
  const peerId = ownerFingerprint(identity.ed25519.publicKey);
  const body = { type: "copilot-flock-member-v1", flockId, peerId, role: "owner", scope, machineId,
    deviceEd25519Pub: identity.ed25519.publicKey, deviceX25519Pub: identity.x25519.publicKey,
    issuedAt: now, expiresAt: now + DAY, sessionIds: [] };
  const cert = { body, signature: sign("member-cert", body, identity.ed25519.privateKey) };
  validateCert(cert, identity.ed25519.publicKey, now);
  return { flockId, localPeerId: peerId, rotationOwnerPeerId: peerId, ownerPublicKey: identity.ed25519.publicKey,
    epoch: 1, minAcceptedEpoch: 1, keyId: crypto.randomUUID(), groupKey: encode(crypto.randomBytes(32)), cert };
}

export function signedControl(type, body, identity) {
  return { type, body, signature: sign(`control/${type}`, body, identity.ed25519.privateKey) };
}
export function verifyControl(control, ownerPublicKey, type) {
  if (control.type !== type) throw new Error("Unexpected control type");
  verify(`control/${type}`, control.body, control.signature, ownerPublicKey);
  return control.body;
}
export function renewOwnerCert(state, identity, now = Date.now()) {
  if (ownerFingerprint(identity.ed25519.publicKey) !== state.rotationOwnerPeerId) throw new Error("Not the rotation owner");
  const body = { ...state.cert.body, issuedAt: now, expiresAt: now + DAY };
  const cert = { body, signature: sign("member-cert", body, identity.ed25519.privateKey) };
  validateCert(cert, state.ownerPublicKey, now);
  return cert;
}

export class DurableReceiver {
  constructor(filename, loadState, clock = Date.now) {
    this.filename = filename;
    this.loadState = loadState;
    this.clock = clock;
  }
  async dispatch(envelope, handler, authorizeCompletion = null) {
    assertNoLinks(this.filename);
    const lock = `${this.filename}.lock`;
    const fd = fs.openSync(lock, "wx", 0o600);
    try {
      const { member, payload } = decryptEnvelope(envelope, this.loadState(), this.clock());
      const key = `${envelope.header.flockId}:${envelope.header.peerId}:${envelope.header.messageId}`;
      const ledger = fs.existsSync(this.filename) ? JSON.parse(fs.readFileSync(this.filename, "utf8")) : {};
      if (ledger[key]) throw new Error(`Replay/ambiguous dispatch quarantined: ${ledger[key].status}`);
      const assertAuthorized = () => authorize(envelope.header, envelope.cert, this.loadState(), this.clock());
      // An interrupted admitted operation is never automatically re-dispatched.
      ledger[key] = { hash: digest(canonical(envelope)), status: "quarantined", expiresAt: envelope.header.expiresAt };
      for (const [id, record] of Object.entries(ledger)) {
        if (record.status === "complete" && record.expiresAt < this.clock() - 300000) delete ledger[id];
      }
      if (Object.keys(ledger).length > 100000) throw new Error("Replay ledger full; operator reconciliation required");
      atomicJson(this.filename, ledger);
      assertAuthorized();
      const result = await handler({ member, payload, header: envelope.header, assertAuthorized });
      if (authorizeCompletion) authorizeCompletion();
      else assertAuthorized();
      ledger[key].status = "complete";
      atomicJson(this.filename, ledger);
      return result;
    } finally { fs.closeSync(fd); fs.unlinkSync(lock); }
  }
}

export function createRotation(state, identity, retainedCerts, now = Date.now()) {
  if (ownerFingerprint(identity.ed25519.publicKey) !== state.rotationOwnerPeerId ||
      identity.ed25519.publicKey !== state.ownerPublicKey) throw new Error("Only designated rotation owner may rotate");
  const epoch = state.epoch + 1;
  const keyId = crypto.randomUUID();
  const groupKey = encode(crypto.randomBytes(32));
  const recipients = {};
  for (const cert of retainedCerts) {
    const member = validateCert(cert, state.ownerPublicKey, now);
    if (member.flockId !== state.flockId || recipients[member.peerId]) throw new Error("Duplicate or foreign rotation recipient");
    recipients[member.peerId] = seal({ groupKey, epoch, keyId, flockId: state.flockId }, member.deviceX25519Pub);
  }
  const body = { flockId: state.flockId, epoch, minAcceptedEpoch: epoch, keyId, previousHash: state.rotationHash || null, recipients };
  return { body, signature: sign("rotation", body, identity.ed25519.privateKey) };
}
export function applyRotation(filename, rotation, identity, state) {
  verify("rotation", rotation.body, rotation.signature, state.ownerPublicKey);
  const hash = digest(canonical(rotation));
  const stored = fs.existsSync(filename) ? JSON.parse(fs.readFileSync(filename, "utf8")) : state;
  if (rotation.body.epoch === stored.epoch && stored.rotationHash === hash) return stored;
  if (rotation.body.flockId !== stored.flockId || rotation.body.epoch !== stored.epoch + 1 ||
      rotation.body.minAcceptedEpoch !== rotation.body.epoch ||
      rotation.body.previousHash !== (stored.rotationHash || null)) throw new Error("Old epoch, rollback or conflicting rotation hash");
  const box = rotation.body.recipients[ownerFingerprint(identity.ed25519.publicKey)];
  if (!box) throw new Error("Device not retained by rotation owner");
  const key = unseal(box, identity.x25519.privateKey);
  bytes(key.groupKey, 32);
  if (key.epoch !== rotation.body.epoch || key.keyId !== rotation.body.keyId || key.flockId !== stored.flockId) throw new Error("Rotation box mismatch");
  const next = { ...stored, ...key, minAcceptedEpoch: key.epoch, rotationHash: hash };
  atomicJson(filename, next);
  return next;
}
