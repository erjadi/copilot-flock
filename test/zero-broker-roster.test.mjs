import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { DatabaseSync } from "node:sqlite";
import * as zb from "../zero-broker-roster.mjs";
import { AUTOMATIC_RECONCILE_LIMIT, createZeroBrokerRuntime, isVerifiedZeroBrokerContext, RPC_BODY_LIMIT_BYTES } from "../zero-broker-runtime.mjs";
import { cloudRequest, createGitHubRosterRepository, ENCRYPTED_PACKET_HEADER_RESERVE_BYTES, peekLockEncryptedPacket,
  prepareEncryptedPacket, sendEncryptedPacket, SERVICE_BUS_STANDARD_MESSAGE_BYTES, stageEpochResources } from "../zero-broker-transport.mjs";
import { getZeroBrokerApi as flockApi } from "../flock.mjs";
import { getZeroBrokerApi as bridgeApi } from "../bridge.mjs";

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-zb-test-"));
  let state;
  let receiverState;
  const cleanups = [];
  t.after(() => { for (const cleanup of cleanups.reverse()) cleanup(); state?.close(); receiverState?.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const flockUuid = crypto.randomUUID();
  const owner = zb.createDeviceKeys({ directory: path.join(directory, "owner"), flockUuid });
  const peer = zb.createDeviceKeys({ directory: path.join(directory, "peer"), flockUuid });
  state = zb.createRosterState({ directory: path.join(directory, "owner") });
  receiverState = zb.createRosterState({ directory: path.join(directory, "peer") });
  const nowMs = Date.now();
  function credentials(epoch) {
    return {
      signalr: { endpoint: "https://demo.service.signalr.net", accessKey: `synthetic-signalr-key-${epoch}` },
      serviceBus: { namespaceHost: "demo.servicebus.windows.net", topicName: `offline-f${flockUuid.replaceAll("-", "")}-e${epoch}-${crypto.randomBytes(6).toString("hex")}`, sendRuleKey: `synthetic-send-key-${epoch}`, listenRuleKey: `synthetic-listen-key-${epoch}` },
    };
  }

  const genesis = zb.createGenesisRoster({ owner, ownerCredentials: credentials(1), nowMs });
  const trust = (store, initial = genesis, transitions = []) => zb.verifyRosterChain(initial, transitions, nowMs, { state: store, pinnedRootFingerprint: genesis.rootFingerprint });
  trust(state);
  trust(receiverState);
  function memberBundle(roster, device) {
    return zb.openSealedBundle({
      bundle: roster.members.find((member) => member.opaquePeerId === device.opaquePeerId).sealedMemberBundle,
      recipientEncPrivPem: device.encPriv, flockUuid, rosterEpoch: roster.rosterEpoch,
      recipientOpaquePeerId: device.opaquePeerId, bundleType: "member",
    });
  }
  return { directory, flockUuid, owner, peer, state, receiverState, genesis, nowMs, credentials, trust, memberBundle, trackCleanup: (cleanup) => cleanups.push(cleanup) };
}

test("both full entry points expose the same lazy Zero-Broker API without installing or provisioning", async () => {
  const [flock, bridge] = await Promise.all([flockApi(), bridgeApi()]);
  for (const name of ["createDeviceKeys", "sealBundle", "verifyRosterChain", "createZeroBrokerRuntime", "stageEpochResources"]) {
    assert.equal(flock[name], bridge[name]);
    assert.equal(typeof flock[name], "function");
  }
});

test("per-flock pseudonymous keys persist privately; sealed bundles bind every context field and reject bad keys", (t) => {
  const f = fixture(t);
  assert.deepEqual(zb.createDeviceKeys({ directory: path.join(f.directory, "owner"), flockUuid: f.flockUuid }), f.owner);
  assert.notEqual(f.owner.opaquePeerId, f.peer.opaquePeerId);
  const context = { flockUuid: f.flockUuid, rosterEpoch: 1, recipientOpaquePeerId: f.peer.opaquePeerId, bundleType: "member" };
  const bundle = zb.sealBundle({ payload: { message: "Private synthetic payload" }, recipientEncPubPem: f.peer.encPub, ...context });
  assert.deepEqual(zb.openSealedBundle({ bundle, recipientEncPrivPem: f.peer.encPriv, ...context }), { message: "Private synthetic payload" });
  assert.throws(() => zb.openSealedBundle({ bundle, recipientEncPrivPem: f.owner.encPriv, ...context }));
  for (const changed of [{ flockUuid: crypto.randomUUID() }, { rosterEpoch: 2 }, { recipientOpaquePeerId: f.owner.opaquePeerId }, { bundleType: "owner-vault" }]) {
    assert.throws(() => zb.openSealedBundle({ bundle, recipientEncPrivPem: f.peer.encPriv, ...context, ...changed }), /context mismatch/);
  }
  assert.throws(() => zb.openSealedBundle({ bundle: { ...bundle, tag: Buffer.alloc(16).toString("base64") }, recipientEncPrivPem: f.peer.encPriv, ...context }));
  assert.throws(() => zb.sealBundle({ payload: {}, recipientEncPubPem: f.peer.signingPub, ...context }), /x25519/);
  const lowOrder = crypto.createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.alloc(32).toString("base64url") }, format: "jwk" }).export({ type: "spki", format: "pem" });
  assert.throws(() => zb.sealBundle({ payload: {}, recipientEncPubPem: lowOrder, ...context }));
  if (process.platform !== "win32") {
    const file = path.join(f.directory, "owner", `flock-${f.flockUuid}`, "device.json");
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});

test("group messages are signed inside authenticated encryption; durable nonce and replay claims reject reuse", (t) => {
  const f = fixture(t);
  const roster = zb.createPreBoundInvite({ roster: f.genesis, actor: f.owner, recipient: f.peer, role: "guest", ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  f.trust(f.state, f.genesis, [roster]);
  f.trust(f.receiverState, f.genesis, [roster]);
  const key = Buffer.from(f.memberBundle(roster, f.owner).flockKey, "base64");
  const options = { roster, state: f.state, flockKey: key, signingPriv: f.owner.signingPriv, action: "ping", fromOpaquePeerId: f.owner.opaquePeerId, toOpaquePeerId: f.peer.opaquePeerId, body: { text: "Synthetic message" }, nowMs: f.nowMs };
  const encrypted = zb.encryptFlockEnvelope(options);
  const decrypted = zb.decryptFlockEnvelope({ envelope: encrypted, roster, state: f.receiverState, flockKey: key, recipientOpaquePeerId: f.peer.opaquePeerId, nowMs: f.nowMs });
  assert.deepEqual(decrypted.body, options.body);
  assert.throws(() => zb.decryptFlockEnvelope({ envelope: encrypted, roster, state: f.receiverState, flockKey: key, recipientOpaquePeerId: f.peer.opaquePeerId, nowMs: f.nowMs }), /Replay/);
  assert.throws(() => zb.encryptFlockEnvelope({ ...options, messageId: encrypted.messageId, body: { text: "Different" } }), /reused/);
  assert.throws(() => zb.encryptFlockEnvelope({ ...options, fromOpaquePeerId: f.peer.opaquePeerId, signingPriv: f.peer.signingPriv, toOpaquePeerId: f.owner.opaquePeerId, action: "send_message" }), /denied/);
  assert.throws(() => zb.encryptFlockEnvelope({ ...options, signingPriv: f.peer.signingPriv }), /key mismatch/);
  const second = zb.encryptFlockEnvelope(options);
  assert.notEqual(second.ciphertext, encrypted.ciphertext);
  assert.throws(() => zb.decryptFlockEnvelope({ envelope: { ...second, toOpaquePeerId: f.owner.opaquePeerId }, roster, state: f.receiverState, flockKey: key, recipientOpaquePeerId: f.peer.opaquePeerId, nowMs: f.nowMs }), /wrong-recipient/);
  assert.throws(() => zb.decryptFlockEnvelope({ envelope: second, roster, state: f.receiverState, flockKey: key, recipientOpaquePeerId: f.peer.opaquePeerId, nowMs: f.nowMs + zb.MAX_LEASE_MS }), /lease expired/);
  assert.throws(() => zb.encryptFlockEnvelope({ ...options, roster: f.genesis }), /durably verified/);
});

test("SignalR JWTs and Service Bus SAS have exact audiences, UTF-8 signing keys and epoch-scoped subscriptions", (t) => {
  const f = fixture(t);
  const member = f.memberBundle(f.genesis, f.owner);
  const transport = member.transport;
  const jwtPayload = (token) => JSON.parse(Buffer.from(token.split(".")[1], "base64url"));
  assert.equal(jwtPayload(transport.wsClientJwt).aud, `${transport.endpoint}/client/?hub=${transport.hubName}`);
  assert.equal(jwtPayload(transport.wsClientJwt).nameid, f.owner.opaquePeerId);
  assert.equal(jwtPayload(transport.hubPublishJwt).aud, `${transport.endpoint}/api/v1/hubs/${transport.hubName}`);
  const send = new URLSearchParams(transport.sbSendSas.slice("SharedAccessSignature ".length));
  const listen = new URLSearchParams(transport.sbListenSas.slice("SharedAccessSignature ".length));
  assert.equal(send.get("sr"), `https://demo.servicebus.windows.net/${transport.topicName}`);
  assert.ok(!send.get("sr").endsWith("/messages"));
  assert.equal(listen.get("sr"), `${send.get("sr")}/subscriptions/sub-${f.owner.opaquePeerId}-e1`);
  const expected = crypto.createHmac("sha256", "synthetic-send-key-1").update(`${encodeURIComponent(send.get("sr"))}\n${send.get("se")}`).digest("base64");
  assert.equal(send.get("sig"), expected);
  const close = zb.buildSignalRCloseUserConnectionsRequest({ endpoint: transport.endpoint, accessKey: "synthetic-signalr-key", hubName: transport.hubName, opaquePeerId: f.owner.opaquePeerId, nowMs: f.nowMs });
  assert.equal(close.method, "POST");
  assert.ok(close.url.endsWith(`/${f.owner.opaquePeerId}/:closeConnections?api-version=2024-12-01`));
  assert.equal(jwtPayload(close.headers.Authorization.slice(7)).aud, close.url.split("?")[0]);
});

test("genesis-root protects governance; non-minting delegates receive no Azure vault and cannot rotate or downgrade owners", (t) => {
  const f = fixture(t);
  const delegated = zb.createPreBoundInvite({
    roster: f.genesis, actor: f.owner, recipient: f.peer, role: "owner",
    ownerPermissions: { canKick: true, canModifyOwners: false, canMintTokens: false },
    ownerCredentials: f.credentials(2), nowMs: f.nowMs,
  });
  assert.equal(delegated.sealedOwnerVault[f.peer.opaquePeerId], undefined);
  assert.throws(() => zb.rotateRosterEpoch({ roster: delegated, actor: f.peer, ownerCredentials: f.credentials(3), nowMs: f.nowMs }), /authorized token issuer/);
  const mutable = zb.createPreBoundInvite({
    roster: f.genesis, actor: f.owner, recipient: f.peer, role: "owner",
    ownerPermissions: { canKick: true, canModifyOwners: false, canMintTokens: true },
    ownerCredentials: f.credentials(2), nowMs: f.nowMs,
  });
  const next = zb.rotateRosterEpoch({ roster: mutable, actor: f.peer, ownerCredentials: f.credentials(3), nowMs: f.nowMs });
  assert.equal(zb.validateRosterTransition(mutable, next, f.nowMs), next);
  const modified = structuredClone(next);
  modified.ownerSigners.find((signer) => signer.opaquePeerId === f.peer.opaquePeerId).permissions.canKick = false;
  assert.throws(() => zb.validateRosterTransition(mutable, zb.signRoster(modified, f.peer), f.nowMs), /Only genesis root/);
  const missingRoot = structuredClone(next);
  missingRoot.members = missingRoot.members.filter((member) => member.opaquePeerId !== f.owner.opaquePeerId);
  assert.throws(() => zb.validateRosterTransition(mutable, zb.signRoster(missingRoot, f.peer), f.nowMs), /owner member identity/);
  const recovered = zb.recoverFromCompromisedDelegate({ roster: mutable, actor: f.owner, delegateOpaquePeerId: f.peer.opaquePeerId, rotatedOwnerCredentials: f.credentials(3), nowMs: f.nowMs });
  assert.ok(!recovered.members.some((member) => member.opaquePeerId === f.peer.opaquePeerId));
  assert.equal(recovered.sealedOwnerVault[f.peer.opaquePeerId], undefined);
});

test("vouchers require pinned keys or signed independent owner approval, and CAS-published consumption is one time", (t) => {
  const f = fixture(t);
  const invite = zb.createInviteVoucher({ roster: f.genesis, actor: f.owner, rosterUrl: "https://demo.github.io/flock/flock-roster.json", enrollmentSbSendSas: "SharedAccessSignature synthetic-provisional-token", expiresAt: new Date(f.nowMs + 60000).toISOString(), nowMs: f.nowMs });
  assert.equal(invite.voucher.invitePriv, undefined);
  assert.equal(invite.voucher.flockKey, undefined);
  const pending = zb.rotateRosterEpoch({ roster: f.genesis, actor: f.owner, ownerCredentials: f.credentials(2), nowMs: f.nowMs, mutate: (next) => { next.pendingVouchers[invite.voucher.voucherId] = invite.pendingRecord; } });
  const claim = zb.createEnrollmentClaim({ voucher: invite.voucher, device: f.peer, githubUser: "demo-user" });
  const options = { roster: pending, voucher: invite.voucher, claim, actor: f.owner, ownerCredentials: f.credentials(3), nowMs: f.nowMs };
  assert.throws(() => zb.redeemEnrollmentClaim(options), /independently verified owner approval/);
  const approval = zb.approveEnrollmentClaim({ claim, actor: f.owner, verifiedSigningFingerprint: zb.keyFingerprint(f.peer.signingPub), verifiedEncFingerprint: zb.keyFingerprint(f.peer.encPub) });
  const redeemed = zb.redeemEnrollmentClaim({ ...options, approval });
  assert.ok(redeemed.members.some((member) => member.opaquePeerId === f.peer.opaquePeerId));
  assert.ok(redeemed.consumedVouchers[claim.voucherId]);
  assert.throws(() => zb.redeemEnrollmentClaim({ ...options, roster: redeemed, approval, ownerCredentials: f.credentials(4) }), /consumed/);
  assert.ok(!JSON.stringify(redeemed).includes("demo-user"));
  assert.ok(!JSON.stringify(redeemed).includes("synthetic-provisional-token"));
});

test("explicit kick and scheduled expiry rotate keys, hubs, tokens and epoch topics", (t) => {
  const f = fixture(t);
  const joined = zb.createPreBoundInvite({ roster: f.genesis, actor: f.owner, recipient: f.peer, membershipExpiresAt: new Date(f.nowMs + 1000).toISOString(), ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  const prior = f.memberBundle(joined, f.owner);
  const kicked = zb.kickMemberFromRoster({ roster: joined, actor: f.owner, opaquePeerId: f.peer.opaquePeerId, ownerCredentials: f.credentials(3), nowMs: f.nowMs });
  const renewed = f.memberBundle(kicked, f.owner);
  assert.notEqual(prior.flockKey, renewed.flockKey);
  assert.notEqual(prior.transport.hubName, renewed.transport.hubName);
  assert.notEqual(prior.transport.topicName, renewed.transport.topicName);
  assert.notEqual(prior.transport.subscriptionName, renewed.transport.subscriptionName);
  const expired = zb.pruneExpiredMembersAndRotate({ roster: joined, actor: f.owner, ownerCredentials: f.credentials(3), nowMs: f.nowMs + 2000 });
  assert.equal(expired.rosterEpoch, 3);
  assert.equal(expired.members.length, 1);
  assert.equal(zb.pruneExpiredMembersAndRotate({ roster: joined, actor: f.owner, nowMs: f.nowMs }), joined);
});

test("persistent anchors reject rollback/forks and durable application claims survive an epoch cutover without redispatch", (t) => {
  const f = fixture(t);
  const joined = zb.createPreBoundInvite({ roster: f.genesis, actor: f.owner, recipient: f.peer, ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  f.trust(f.state, f.genesis, [joined]);
  const request = { roster: joined, sender: f.owner.opaquePeerId, recipient: f.peer.opaquePeerId, requestId: crypto.randomUUID(), payload: { action: "ping" }, expiresAt: f.nowMs + 3600000, nowMs: f.nowMs };
  assert.equal(f.state.admitRequest(request).dispatch, true);
  const renewed = zb.rotateRosterEpoch({ roster: joined, actor: f.owner, ownerCredentials: f.credentials(3), nowMs: f.nowMs });
  zb.verifyRosterChain(joined, [renewed], f.nowMs, { state: f.state });
  assert.deepEqual(f.state.admitRequest({ ...request, roster: renewed }), { dispatch: false, status: "UNKNOWN", result: null, authorization: null });
  assert.throws(() => f.state.admitRequest({ ...request, roster: renewed, payload: { action: "different" } }), /different payload/);
  assert.throws(() => f.state.acceptVerifiedRoster(f.genesis), /rollback/);
  assert.throws(() => f.state.acceptVerifiedRoster({ ...renewed, issuedAt: new Date(f.nowMs - 1).toISOString() }), /fork/);
  const queue = { flockUuid: f.flockUuid, sender: f.owner.opaquePeerId, recipient: f.peer.opaquePeerId, requestId: crypto.randomUUID(), payload: { message: "Synthetic offline work" }, expiresAt: f.nowMs + 3600000, nowMs: f.nowMs };
  f.state.queue(queue);
  const reopened = zb.createRosterState({ directory: path.join(f.directory, "owner") });
  try {
    assert.equal(reopened.get(f.flockUuid).rosterEpoch, 3);
    assert.deepEqual(reopened.pendingOutbox(f.flockUuid)[0].payload, queue.payload);
    assert.equal(reopened.admitRequest({ ...request, roster: renewed }).dispatch, false);
  } finally { reopened.close(); }
});

test("a CAS conflict discards only that staged candidate and retries against newly verified history", async (t) => {
  const f = fixture(t);
  const competing = zb.rotateRosterEpoch({ roster: f.genesis, actor: f.owner, ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  let puts = 0;
  let discarded = 0;
  const result = await zb.publishRosterWithCas({
    trustedRoster: f.genesis, state: f.state, nowMs: () => f.nowMs,
    readLatest: async (current) => ({ sha: `blob-${puts}`, transitions: puts === 0 ? [] : current.rosterEpoch === 1 ? [competing] : [] }),
    prepare: async (current) => ({ roster: zb.rotateRosterEpoch({ roster: current, actor: f.owner, ownerCredentials: f.credentials(current.rosterEpoch + 1), nowMs: f.nowMs }) }),
    put: async ({ sha }) => { assert.equal(sha, `blob-${puts}`); puts++; return { status: puts === 1 ? 409 : 200 }; },
    discard: async () => { discarded++; },
  });
  assert.equal(discarded, 1);
  assert.equal(result.rosterEpoch, 3);
  assert.equal(result.prevRosterHash, zb.hashRoster(competing));
});

test("offline peers verify expired intermediate history, but execution still requires a fresh final lease", async (t) => {
  const f = fixture(t);
  const second = zb.rotateRosterEpoch({ roster: f.genesis, actor: f.owner, ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  const later = f.nowMs + zb.MAX_LEASE_MS + 1000;
  const third = zb.rotateRosterEpoch({ roster: second, actor: f.owner, ownerCredentials: f.credentials(3), nowMs: later });
  assert.equal(zb.verifyRosterChain(f.genesis, [second, third], later, { state: f.receiverState }).rosterEpoch, 3);
  assert.throws(() => zb.verifyRosterChain(f.genesis, [], later, { state: f.state }), /lease expired/);
  const renewed = await zb.publishRosterWithCas({
    trustedRoster: f.genesis, state: f.state, nowMs: () => later,
    readLatest: async () => ({ sha: "synthetic-blob", transitions: [] }),
    prepare: async (current) => ({ roster: zb.rotateRosterEpoch({ roster: current, actor: f.owner, ownerCredentials: f.credentials(2), nowMs: later }) }),
    put: async () => ({ status: 200 }),
    discard: async () => assert.fail("Confirmed renewal must not be discarded"),
  });
  assert.equal(renewed.rosterEpoch, 2);
});

test("root recovery checkpoints are signed and cannot resurrect consumed vouchers; vaults reject extra secrets", (t) => {
  const f = fixture(t);
  const second = zb.rotateRosterEpoch({ roster: f.genesis, actor: f.owner, ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  const third = zb.rotateRosterEpoch({ roster: second, actor: f.owner, ownerCredentials: f.credentials(3), nowMs: f.nowMs });
  const checkpoint = zb.createRecoveryCheckpoint({ trustedRoster: f.genesis, nextRoster: third, actor: f.owner, nowMs: f.nowMs });
  assert.equal(zb.verifyRosterChain(f.genesis, [checkpoint], f.nowMs, { state: f.state }).rosterEpoch, 3);
  const changed = structuredClone(checkpoint);
  changed.recoveryCheckpoint.baseRosterHash = "0".repeat(64);
  assert.throws(() => zb.verifyRosterChain(f.genesis, [zb.signRoster(changed, f.owner)], f.nowMs, { state: f.receiverState }), /checkpoint/);
  assert.throws(() => zb.createGenesisRoster({ owner: f.owner, ownerCredentials: { ...f.credentials(1), rootSigningPriv: f.owner.signingPriv }, nowMs: f.nowMs }), /only Azure/);
  assert.throws(() => zb.validateRosterDocument({ ...f.genesis, githubUser: "synthetic-private-identity" }), /public roster metadata/);
  const privatePem = structuredClone(f.genesis);
  privatePem.members[0].signingPub = f.owner.signingPriv;
  assert.throws(() => zb.validateRosterDocument(privatePem), /never private key/);
  const voucherId = crypto.randomUUID();
  const consumedGenesis = zb.signRoster({ ...f.genesis, consumedVouchers: { [voucherId]: { opaquePeerId: f.peer.opaquePeerId, claimHash: "a".repeat(64) } } }, f.owner);
  assert.throws(() => zb.createRecoveryCheckpoint({ trustedRoster: consumedGenesis, nextRoster: third, actor: f.owner, nowMs: f.nowMs }), /Consumed vouchers/);
  const { signature, ...unsignedThird } = third;
  const checkpointBody = { baseEpoch: 1, baseRosterHash: zb.hashRoster(consumedGenesis), nextRosterHash: crypto.createHash("sha256").update(zb.canonicalJson(unsignedThird)).digest("hex") };
  const malicious = zb.signRoster({ ...third, recoveryCheckpoint: { ...checkpointBody, signature: crypto.sign(null, Buffer.from(zb.canonicalJson(checkpointBody)), f.owner.signingPriv).toString("base64") } }, f.owner);
  assert.throws(() => zb.verifyRosterChain(consumedGenesis, [malicious], f.nowMs, { pinnedRootFingerprint: f.genesis.rootFingerprint }), /Consumed vouchers/);
});

test("a group-key holder cannot forge the signed plaintext or poison the original message replay claim", (t) => {
  const f = fixture(t);
  const key = Buffer.from(f.memberBundle(f.genesis, f.owner).flockKey, "base64");
  const envelope = zb.encryptFlockEnvelope({ roster: f.genesis, state: f.state, flockKey: key, signingPriv: f.owner.signingPriv, action: "ping", fromOpaquePeerId: f.owner.opaquePeerId, toOpaquePeerId: f.owner.opaquePeerId, body: { value: "original" }, nowMs: f.nowMs });
  const material = Buffer.from(crypto.hkdfSync("sha256", key, Buffer.from(`${envelope.fromOpaquePeerId}:${envelope.messageId}`), Buffer.from(`copilot-flock-v3-msg|${f.flockUuid}|1`), 44));
  const aad = Buffer.from(`${f.flockUuid}|1|${envelope.fromOpaquePeerId}|${envelope.toOpaquePeerId}|${envelope.messageId}`);
  const decipher = crypto.createDecipheriv("aes-256-gcm", material.subarray(0, 32), material.subarray(32));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const inner = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8"));
  inner.body = { value: "forged" };
  inner.bodySha256 = crypto.createHash("sha256").update(zb.canonicalJson(inner.body)).digest("hex");
  const cipher = crypto.createCipheriv("aes-256-gcm", material.subarray(0, 32), material.subarray(32));
  cipher.setAAD(aad);
  const forged = { ...envelope, ciphertext: Buffer.concat([cipher.update(zb.canonicalJson(inner)), cipher.final()]).toString("base64"), tag: cipher.getAuthTag().toString("base64") };
  const options = { roster: f.genesis, state: f.receiverState, flockKey: key, recipientOpaquePeerId: f.owner.opaquePeerId, nowMs: f.nowMs };
  assert.throws(() => zb.decryptFlockEnvelope({ ...options, envelope: forged }), /Invalid envelope signature/);
  assert.equal(zb.decryptFlockEnvelope({ ...options, envelope }).body.value, "original");
  key.fill(0);
  material.fill(0);
});

test("application claims fail closed at capacity, preserve deadlines and cannot overwrite a terminal admission", (t) => {
  const f = fixture(t);
  const limited = zb.createRosterState({ directory: path.join(f.directory, "limited"), capacity: 1 });
  f.trackCleanup(() => limited.close());
  f.trust(limited);
  const coordinates = { roster: f.genesis, sender: f.owner.opaquePeerId, recipient: f.owner.opaquePeerId, requestId: crypto.randomUUID(), payload: { action: "ping" }, expiresAt: f.nowMs + 1000, nowMs: f.nowMs };
  limited.admitRequest(coordinates);
  assert.throws(() => limited.admitRequest({ ...coordinates, requestId: crypto.randomUUID() }), /capacity/);
  limited.finishRequest({ flockUuid: f.flockUuid, sender: coordinates.sender, recipient: coordinates.recipient, requestId: coordinates.requestId, status: "DELIVERED", result: { admitted: true } });
  assert.throws(() => limited.finishRequest({ flockUuid: f.flockUuid, sender: coordinates.sender, recipient: coordinates.recipient, requestId: coordinates.requestId, status: "UNKNOWN", result: null }), /unclaimed/);
  const queue = { flockUuid: f.flockUuid, sender: f.owner.opaquePeerId, recipient: f.owner.opaquePeerId, requestId: crypto.randomUUID(), payload: {}, expiresAt: f.nowMs + 1000, nowMs: f.nowMs };
  limited.queue(queue);
  assert.throws(() => limited.queue({ ...queue, expiresAt: f.nowMs + 2000 }), /different payload/);
  assert.throws(() => limited.queue({ ...queue, requestId: crypto.randomUUID() }), /capacity/);
});

test("admission and reconciliation schema upgrades preserve existing claims, attempted proof, schedules and identity", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-zb-ledger-upgrade-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const stateDirectory = path.join(directory, "roster-state");
  fs.mkdirSync(stateDirectory);
  const file = path.join(stateDirectory, "state.sqlite");
  fs.closeSync(fs.openSync(file, "wx", 0o600));
  const identity = path.join(directory, "synthetic-existing-identity.json");
  fs.writeFileSync(identity, "Synthetic existing identity must remain unchanged");
  const original = new DatabaseSync(file);
  try {
    original.exec("CREATE TABLE admissions (flock TEXT NOT NULL,sender TEXT NOT NULL,recipient TEXT NOT NULL,request TEXT NOT NULL,digest TEXT NOT NULL,expiry INTEGER NOT NULL,status TEXT NOT NULL,result TEXT,PRIMARY KEY(flock,sender,recipient,request))");
    original.prepare("INSERT INTO admissions VALUES (?,?,?,?,?,?,?,?)").run(
      "synthetic-flock", "synthetic-sender", "synthetic-recipient", "synthetic-request",
      "synthetic-digest", 123456789, "DELIVERED", '{"transcript":"Synthetic retained private receipt"}');
    original.exec("CREATE TABLE outbox (flock TEXT,sender TEXT,recipient TEXT,request TEXT,digest TEXT,expiry INTEGER,document TEXT,attempted INTEGER,PRIMARY KEY(flock,sender,recipient,request)); CREATE TABLE claims (direction TEXT,flock TEXT,epoch INTEGER,sender TEXT,message TEXT,expiry INTEGER,PRIMARY KEY(direction,flock,epoch,sender,message))");
    original.prepare("INSERT INTO outbox VALUES (?,?,?,?,?,?,?,?)").run("synthetic-flock", "synthetic-sender", "synthetic-recipient",
      "synthetic-request", "synthetic-digest", 123456789, '{"retained":true}', 1);
    original.prepare("INSERT INTO claims VALUES (?,?,?,?,?,?)").run("send", "synthetic-flock", 1, "synthetic-sender", "synthetic-message", 123456789);
  } finally { original.close(); }
  for (let attempt = 0; attempt < 2; attempt++) {
    const upgraded = zb.createRosterState({ directory });
    if (attempt === 0) assert.equal(upgraded.claimOutboxReconciliation({
      flockUuid: "synthetic-flock", sender: "synthetic-sender", nowMs: 1000, limit: 1 }).length, 1);
    else assert.equal(upgraded.claimOutboxReconciliation({
      flockUuid: "synthetic-flock", sender: "synthetic-sender", nowMs: 1000, limit: 1 }).length, 0);
    upgraded.close();
  }
  const inspected = new DatabaseSync(file);
  try {
    assert.ok(inspected.prepare("PRAGMA table_info(admissions)").all().some((column) => column.name === "authorization"));
    const rows = inspected.prepare("SELECT * FROM admissions").all();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].digest, "synthetic-digest");
    assert.equal(rows[0].expiry, 123456789);
    assert.equal(rows[0].status, "DELIVERED");
    assert.equal(rows[0].result, '{"transcript":"Synthetic retained private receipt"}');
    assert.equal(rows[0].authorization, null);
    const queued = inspected.prepare("SELECT * FROM outbox").get();
    assert.equal(queued.digest, "synthetic-digest");
    assert.equal(queued.document, '{"retained":true}');
    assert.equal(queued.expiry, 123456789);
    assert.equal(queued.attempted, 1);
    assert.equal(queued.reconcile_attempts, 1);
    assert.equal(queued.next_reconcile_at, 1000 + zb.OUTBOX_RECONCILE_BASE_DELAY_MS);
    assert.equal(inspected.prepare("SELECT COUNT(*) AS count FROM claims").get().count, 1);
    assert.equal(fs.readFileSync(identity, "utf8"), "Synthetic existing identity must remain unchanged");
  } finally { inspected.close(); }
});

function runtimeFixture(t, { dispatch, readSnapshot, role = "owner", canMintTokens = false, captureResponses = false, cloudTransport = false, fakeClock = false } = {}) {
  const f = fixture(t);
  const roster = zb.createPreBoundInvite({
    roster: f.genesis, actor: f.owner, recipient: f.peer, role,
    ...(role === "owner" ? { ownerPermissions: { canKick: false, canModifyOwners: false, canMintTokens } } : {}),
    ownerCredentials: f.credentials(2), nowMs: f.nowMs,
  });
  f.trust(f.state, f.genesis, [roster]);
  f.trust(f.receiverState, f.genesis, [roster]);
  const peers = new Map();
  const packets = [];
  const errors = [];
  const cloudAttempts = [];
  let offline = false;
  let grants = false;
  let rootGrants = true;
  let grantRevision = 0;
  let summary = "Synthetic approved summary";
  let calls = 0;
  let clock = f.nowMs;
  let publicationGate = null;
  let publicationGateOnce = false;
  const sendPacket = async ({ transport, envelope }) => {
    packets.push(envelope);
    if (publicationGate) {
      const gate = publicationGate;
      if (publicationGateOnce) publicationGate = null;
      await gate;
    }
    if (offline) throw Object.assign(new Error("Synthetic offline transport"), { ambiguous: true });
    if (captureResponses && envelope.fromOpaquePeerId === f.peer.opaquePeerId) return { admittedToTransport: true };
    if (cloudTransport) return await sendEncryptedPacket({ transport, envelope, request: async (url, options) => {
      cloudAttempts.push({ url, options });
      if (url.includes(".servicebus.windows.net/")) await peers.get(envelope.toOpaquePeerId).receive(envelope);
      return { status: 201 };
    } });
    await peers.get(envelope.toOpaquePeerId).receive(envelope);
    return { admittedToTransport: true };
  };
  const options = {
    sendPacket,
    now: fakeClock ? () => clock : Date.now,
    reportError: (error) => errors.push(error),
    authorizeRoot: async () => rootGrants,
    authorizeSnapshot: async () => grants,
    getAuthorizationRevision: () => String(grantRevision),
    readSnapshot: readSnapshot || (async () => ({ status: "DELIVERED", result: { approvedSnapshot: true, summary } })),
    dispatch: async (request, context) => {
      assert.ok(isVerifiedZeroBrokerContext(context));
      assert.ok(isVerifiedZeroBrokerContext(context, request));
      assert.equal(isVerifiedZeroBrokerContext(context, { ...request, action: "create_session" }), false);
      assert.equal(context.mode, "ROOT");
      calls++;
      return dispatch ? await dispatch(request, context) : { status: "DELIVERED", result: { admitted: true } };
    },
  };
  const ownerRuntime = createZeroBrokerRuntime({ ...options, device: f.owner, state: f.state });
  const peerRuntime = createZeroBrokerRuntime({ ...options, device: f.peer, state: f.receiverState });
  peers.set(f.owner.opaquePeerId, ownerRuntime);
  peers.set(f.peer.opaquePeerId, peerRuntime);
  f.trackCleanup(() => { ownerRuntime.close(); peerRuntime.close(); });
  return { ...f, ownerRuntime, peerRuntime, packets, errors, cloudAttempts, calls: () => calls,
    advance: (milliseconds) => { clock += milliseconds; },
    setPublicationGate: (gate, once = false) => { publicationGate = gate; publicationGateOnce = once; },
    setOffline: (value) => { offline = value; },
    setGrants: (value) => { grants = value; grantRevision++; },
    setRootGrants: (value) => { rootGrants = value; grantRevision++; },
    setSummary: (value) => { summary = value; grantRevision++; },
    summary: () => summary,
  };
}

async function deliverRootApplication(f, request, kind = "request") {
  const roster = f.state.get(f.flockUuid);
  const key = Buffer.from(f.memberBundle(roster, f.owner).flockKey, "base64");
  try {
    const sealedRpcBody = zb.sealBundle({
      payload: { kind, request }, recipientEncPubPem: f.peer.encPub,
      flockUuid: f.flockUuid, rosterEpoch: roster.rosterEpoch,
      recipientOpaquePeerId: f.peer.opaquePeerId, bundleType: "rpc-body",
    });
    const envelope = zb.encryptFlockEnvelope({
      roster, state: f.state, flockKey: key, signingPriv: f.owner.signingPriv,
      fromOpaquePeerId: f.owner.opaquePeerId, toOpaquePeerId: f.peer.opaquePeerId,
      action: kind === "reconcile" ? "ping" : request.action,
      body: { sealedRpcBody }, nowMs: f.nowMs,
    });
    await f.peerRuntime.receive(envelope);
    const authenticated = zb.decryptFlockEnvelope({
      envelope: f.packets.at(-1), roster, state: f.state, flockKey: key,
      recipientOpaquePeerId: f.owner.opaquePeerId, nowMs: f.nowMs,
    });
    return zb.openSealedBundle({
      bundle: authenticated.body.sealedRpcBody, recipientEncPrivPem: f.owner.encPriv,
      flockUuid: f.flockUuid, rosterEpoch: roster.rosterEpoch,
      recipientOpaquePeerId: f.owner.opaquePeerId, bundleType: "rpc-body",
    });
  } finally { key.fill(0); }
}

test("ROOT transcript downgrade discloses only the retained current snapshot on normal and reconciled duplicates", async (t) => {
  const secret = "Synthetic ROOT transcript not authorized by the retained summary";
  const f = runtimeFixture(t, {
    captureResponses: true,
    dispatch: async () => ({ status: "DELIVERED", result: { transcript: secret } }),
  });
  const request = { requestId: crypto.randomUUID(), action: "get_transcript",
    params: { sessionId: crypto.randomUUID() }, expiresAt: f.nowMs + 60000 };
  assert.deepEqual((await deliverRootApplication(f, request)).result, { transcript: secret });
  assert.equal(f.calls(), 1);
  f.setRootGrants(false);
  f.setGrants(true);
  f.setSummary("Current approved summary, not the ROOT transcript");
  for (const kind of ["request", "reconcile", "request"]) {
    const response = await deliverRootApplication(f, request, kind);
    assert.equal(response.status, "DELIVERED");
    assert.deepEqual(response.result, { approvedSnapshot: true, summary: f.summary() });
    assert.equal(JSON.stringify(response).includes(secret), false);
    assert.equal(f.calls(), 1, "Privacy projection must never redispatch the original ROOT action");
  }
  const before = f.state.get(f.flockUuid);
  const next = zb.rotateRosterEpoch({ roster: before, actor: f.owner,
    ownerCredentials: f.credentials(before.rosterEpoch + 1), nowMs: f.nowMs });
  f.trust(f.state, before, [next]);
  f.trust(f.receiverState, before, [next]);
  assert.deepEqual((await deliverRootApplication(f, request)).result,
    { approvedSnapshot: true, summary: f.summary() });
  assert.equal(f.calls(), 1);
});

test("ROOT read downgraded during await never discloses its newly computed privileged result", async (t) => {
  let started;
  let release;
  const ready = new Promise((resolve) => { started = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const f = runtimeFixture(t, { dispatch: async () => {
    started();
    await gate;
    return { status: "DELIVERED", result: { transcript: "Synthetic never-disclosed ROOT content" } };
  } });
  const pending = f.ownerRuntime.request({ toOpaquePeerId: f.peer.opaquePeerId,
    action: "get_transcript", params: { sessionId: crypto.randomUUID() } });
  await ready;
  f.setRootGrants(false);
  f.setGrants(true);
  release();
  const response = await pending;
  assert.equal(response.status, "DELIVERED");
  assert.deepEqual(response.result, { approvedSnapshot: true, summary: f.summary() });
  assert.equal(f.calls(), 1);
});

test("nonempty snapshot replacement during await rejects the earlier authorization revision", async (t) => {
  let started;
  let release;
  const ready = new Promise((resolve) => { started = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const f = runtimeFixture(t, {
    role: "guest",
    readSnapshot: async () => {
      const summary = f.summary();
      started();
      await gate;
      return { status: "DELIVERED", result: { approvedSnapshot: true, summary } };
    },
  });
  f.setGrants(true);
  const pending = f.peerRuntime.request({ toOpaquePeerId: f.owner.opaquePeerId,
    action: "get_transcript", params: { sessionId: crypto.randomUUID() } });
  await ready;
  f.setSummary("Replacement summary remains nonempty and approved");
  release();
  const response = await pending;
  assert.equal(response.status, "DENIED");
  assert.equal(response.result, null);
  assert.equal(f.calls(), 0);
});

test("ROOT cached admissions bind grant revisions and roster epochs without redispatching reads or side effects", async (t) => {
  for (const action of ["get_transcript", "send_message"]) {
    const f = runtimeFixture(t, {
      captureResponses: true,
      dispatch: async () => ({ status: "DELIVERED", result: { privateResult: "Synthetic ROOT-only result" } }),
    });
    const request = { requestId: crypto.randomUUID(), action, params: {}, expiresAt: f.nowMs + 60000 };
    assert.equal((await deliverRootApplication(f, request)).status, "DELIVERED");
    f.setRootGrants(false);
    f.setRootGrants(true);
    for (const kind of ["request", "reconcile"]) {
      const response = await deliverRootApplication(f, request, kind);
      assert.equal(response.status, action === "send_message" ? "UNKNOWN" : "DENIED");
      assert.equal(response.result, null);
      assert.equal(f.calls(), 1);
    }
    const before = f.state.get(f.flockUuid);
    const next = zb.rotateRosterEpoch({ roster: before, actor: f.owner,
      ownerCredentials: f.credentials(before.rosterEpoch + 1), nowMs: f.nowMs });
    f.trust(f.state, before, [next]);
    f.trust(f.receiverState, before, [next]);
    const response = await deliverRootApplication(f, request);
    assert.equal(response.status, action === "send_message" ? "UNKNOWN" : "DENIED");
    assert.equal(response.result, null);
    assert.equal(f.calls(), 1, "An incompatible receipt must not reset its durable application claim");
  }
});

test("unbound pre-upgrade admission receipts remain claimed but cannot disclose ROOT data", async (t) => {
  const f = runtimeFixture(t, { captureResponses: true });
  const roster = f.receiverState.get(f.flockUuid);
  const request = { requestId: crypto.randomUUID(), action: "get_transcript", params: {}, expiresAt: f.nowMs + 60000 };
  const claim = { roster, sender: f.owner.opaquePeerId, recipient: f.peer.opaquePeerId,
    requestId: request.requestId, payload: request, expiresAt: request.expiresAt, nowMs: f.nowMs };
  f.receiverState.admitRequest(claim);
  f.receiverState.finishRequest({ flockUuid: f.flockUuid, sender: claim.sender, recipient: claim.recipient,
    requestId: request.requestId, status: "DELIVERED", result: { transcript: "Synthetic pre-upgrade private content" } });
  for (const kind of ["request", "reconcile"]) {
    const response = await deliverRootApplication(f, request, kind);
    assert.equal(response.status, "DENIED");
    assert.equal(response.result, null);
    assert.equal(f.calls(), 0);
  }
  f.setRootGrants(false);
  f.setGrants(true);
  const projected = await deliverRootApplication(f, request);
  assert.deepEqual(projected.result, { approvedSnapshot: true, summary: f.summary() });
  assert.equal(f.calls(), 0);
});

test("grant changes after possible dispatch preserve UNKNOWN through reconciliation without redispatch", async (t) => {
  const f = runtimeFixture(t, { dispatch: async () => {
    f.setRootGrants(false);
    return { status: "DELIVERED", result: { admitted: true } };
  } });
  const request = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: {},
    requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000 };
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal(f.calls(), 1);
  await f.ownerRuntime.reconcilePending();
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
  assert.equal(f.calls(), 1);
});

function addSharedMember(f) {
  const guest = zb.createDeviceKeys({ directory: path.join(f.directory, "new-guest"), flockUuid: f.flockUuid });
  const before = f.state.get(f.flockUuid);
  const next = zb.createPreBoundInvite({ roster: before, actor: f.owner, recipient: guest, role: "guest",
    ownerCredentials: f.credentials(before.rosterEpoch + 1), nowMs: f.nowMs });
  f.trust(f.state, before, [next]);
  f.trust(f.receiverState, before, [next]);
}

test("outgoing authority loss after possible admission preserves UNKNOWN and the original outbox", async (t) => {
  const f = runtimeFixture(t, { captureResponses: true });
  const request = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: {},
    requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000, timeoutMs: 100 };
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal(f.calls(), 1);
  addSharedMember(f);
  const beforePackets = f.packets.length;
  const readReceipt = f.state.getOutboxReceipt;
  f.state.getOutboxReceipt = () => assert.fail("Local authority denial must not read cached result data");
  let response;
  try { response = await f.ownerRuntime.request(request); }
  finally { f.state.getOutboxReceipt = readReceipt; }
  assert.equal(response.status, "UNKNOWN");
  assert.equal(response.result, null);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
  assert.equal(f.state.pendingOutbox(f.flockUuid)[0].request, request.requestId);
  assert.equal(f.packets.length, beforePackets);
  assert.equal(f.calls(), 1);
  await assert.rejects(f.ownerRuntime.request({ ...request, params: { changed: true } }), /different payload or expiry/);
  const fresh = await f.ownerRuntime.request({ ...request, requestId: crypto.randomUUID() });
  assert.equal(fresh.status, "DENIED", "Definitely never-attempted work can still be denied");
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
});

test("outgoing authority loss between retry gates cannot terminally deny an earlier possible admission", async (t) => {
  const f = runtimeFixture(t, { captureResponses: true });
  const request = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: {},
    requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000, timeoutMs: 100 };
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  const mark = f.state.markOutboxAttempt;
  f.state.markOutboxAttempt = (coordinates) => {
    const first = mark(coordinates);
    addSharedMember(f);
    return first;
  };
  const response = await f.ownerRuntime.request(request);
  assert.equal(response.status, "UNKNOWN");
  assert.equal(response.result, null);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
  assert.equal(f.calls(), 1);
});

test("mock-adapter RPC confirms admission once, seals recipients and rejects delegate execution before transport", async (t) => {
  const f = runtimeFixture(t);
  assert.equal(isVerifiedZeroBrokerContext({ mode: "ROOT" }), false);
  const options = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: { targetSession: "synthetic-session", message: "Synthetic task" }, requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000 };
  assert.equal((await f.ownerRuntime.request(options)).status, "DELIVERED");
  assert.equal((await f.ownerRuntime.request(options)).status, "DELIVERED");
  assert.equal(f.calls(), 1);
  f.setRootGrants(false);
  assert.equal((await f.ownerRuntime.request({ toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: { message: "No local execution grant" } })).status, "DENIED");
  assert.equal(f.calls(), 1);
  f.setRootGrants(true);
  const before = f.packets.length;
  assert.equal((await f.peerRuntime.request({ toOpaquePeerId: f.owner.opaquePeerId, action: "send_message", params: { message: "Denied task" } })).status, "DENIED");
  assert.equal(f.packets.length, before);
  const inspectionState = zb.createRosterState({ directory: path.join(f.directory, "inspection") });
  f.trackCleanup(() => inspectionState.close());
  f.trust(inspectionState, f.genesis, [f.state.get(f.flockUuid)]);
  const roster = f.state.get(f.flockUuid);
  const key = Buffer.from(f.memberBundle(roster, f.owner).flockKey, "base64");
  const decrypted = zb.decryptFlockEnvelope({ envelope: f.packets[0], roster, state: inspectionState, flockKey: key, recipientOpaquePeerId: f.peer.opaquePeerId });
  assert.throws(() => zb.openSealedBundle({ bundle: decrypted.body.sealedRpcBody, recipientEncPrivPem: f.owner.encPriv, flockUuid: f.flockUuid, rosterEpoch: roster.rosterEpoch, recipientOpaquePeerId: f.peer.opaquePeerId, bundleType: "rpc-body" }));
  key.fill(0);
});

test("incoming mint-enabled delegates cannot replace receiver authority or turn snapshots into root dispatch", async (t) => {
  const f = runtimeFixture(t, { canMintTokens: true });
  const roster = f.state.get(f.flockUuid);
  assert.ok(roster.sealedOwnerVault[f.owner.opaquePeerId]);
  assert.ok(roster.sealedOwnerVault[f.peer.opaquePeerId]);
  const key = Buffer.from(f.memberBundle(roster, f.peer).flockKey, "base64");
  const maliciousParameters = {
    targetSession: "synthetic-root-session", message: "Synthetic attempted privileged task",
    registryMembers: [{ opaquePeerId: f.owner.opaquePeerId, signingPub: f.peer.signingPub }],
    flockPolicy: { trustTier: "owner_root", canMintTokens: true, allowedActions: ["*"] },
    verifiedContext: { mode: "ROOT" }, allowAll: true,
  };
  async function incoming(action) {
    const request = { requestId: crypto.randomUUID(), action, params: maliciousParameters, expiresAt: f.nowMs + 60000 };
    f.receiverState.queue({
      flockUuid: f.flockUuid, sender: f.peer.opaquePeerId, recipient: f.owner.opaquePeerId,
      requestId: request.requestId, payload: request, expiresAt: request.expiresAt, nowMs: f.nowMs,
    });
    const sealedRpcBody = zb.sealBundle({
      payload: { kind: "request", request }, recipientEncPubPem: f.owner.encPub,
      flockUuid: f.flockUuid, rosterEpoch: roster.rosterEpoch,
      recipientOpaquePeerId: f.owner.opaquePeerId, bundleType: "rpc-body",
    });
    const envelope = zb.encryptFlockEnvelope({
      roster, state: f.receiverState, flockKey: key, signingPriv: f.peer.signingPriv,
      fromOpaquePeerId: f.peer.opaquePeerId, toOpaquePeerId: f.owner.opaquePeerId,
      action, body: { sealedRpcBody }, nowMs: f.nowMs,
    });
    const received = await f.ownerRuntime.receive(envelope);
    const receipt = f.receiverState.getOutboxReceipt({
      flockUuid: f.flockUuid, sender: f.peer.opaquePeerId, recipient: f.owner.opaquePeerId,
      requestId: request.requestId, payload: request, expiresAt: request.expiresAt,
    });
    assert.equal(receipt.status, received.status);
    return receipt;
  }
  try {
    assert.equal((await incoming("send_message")).status, "DENIED");
    assert.equal((await incoming("get_transcript")).status, "DENIED");
    assert.equal(f.calls(), 0);
    f.setGrants(true);
    const shared = await incoming("get_transcript");
    assert.equal(shared.status, "DELIVERED");
    assert.deepEqual(shared.result, { approvedSnapshot: true, summary: "Synthetic approved summary" });
    assert.equal(f.calls(), 0);
    assert.equal(f.packets.length, 3);
  } finally { key.fill(0); }
});

test("authenticated missing-receipt reconciliation preserves offline work without blind redispatch of UNKNOWN", async (t) => {
  const f = runtimeFixture(t);
  const request = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: { message: "Synthetic queued task" }, requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000 };
  f.setOffline(true);
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal(f.state.pendingOutbox(f.flockUuid)[0].attempted, 1);
  assert.equal(f.calls(), 0);
  f.setOffline(false);
  await f.ownerRuntime.reconcilePending();
  assert.equal(f.calls(), 1);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 0);
  assert.equal((await f.ownerRuntime.request(request)).status, "DELIVERED");
  assert.equal(f.calls(), 1);
});

test("ambiguous adapter admissions remain durably UNKNOWN; shared groups only expose current approved snapshots", async (t) => {
  const f = runtimeFixture(t, { dispatch: async () => { throw new Error("Synthetic crash after admission"); } });
  const request = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params: {}, requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000 };
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal(f.calls(), 1);
  await f.ownerRuntime.reconcilePending();
  assert.equal(f.calls(), 1);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
  const shared = runtimeFixture(t, { role: "guest" });
  assert.equal((await shared.ownerRuntime.request({ toOpaquePeerId: shared.peer.opaquePeerId, action: "send_message", params: { message: "Do not leak this denied task" } })).status, "DENIED");
  assert.equal(shared.packets.length, 0);
  const query = { toOpaquePeerId: shared.owner.opaquePeerId, action: "get_transcript", params: { session: "synthetic-session" } };
  assert.equal((await shared.peerRuntime.request(query)).status, "DENIED");
  shared.setGrants(true);
  const result = await shared.peerRuntime.request(query);
  assert.equal(result.status, "DELIVERED");
  assert.equal(result.result.approvedSnapshot, true);
  assert.equal(shared.calls(), 0);
});

test("snapshot revocation during an awaited read denies disclosure and never invokes privileged dispatch", async (t) => {
  let started;
  let release;
  const ready = new Promise((resolve) => { started = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const f = runtimeFixture(t, {
    role: "guest",
    readSnapshot: async () => {
      started();
      await gate;
      return { status: "DELIVERED", result: { summary: "Synthetic revoked content" } };
    },
  });
  f.setGrants(true);
  const request = f.peerRuntime.request({ toOpaquePeerId: f.owner.opaquePeerId, action: "get_transcript", params: { session: "synthetic-session" } });
  await ready;
  f.setGrants(false);
  release();
  const result = await request;
  assert.equal(result.status, "DENIED");
  assert.equal(result.result, null);
  assert.equal(f.calls(), 0);
});

function encryptedRpcPacket(f, body) {
  const roster = f.state.get(f.flockUuid);
  const bundle = f.memberBundle(roster, f.owner);
  const key = Buffer.from(bundle.flockKey, "base64");
  try {
    const sealedRpcBody = zb.sealBundle({ payload: body, recipientEncPubPem: f.peer.encPub,
      flockUuid: f.flockUuid, rosterEpoch: roster.rosterEpoch,
      recipientOpaquePeerId: f.peer.opaquePeerId, bundleType: "rpc-body" });
    const envelope = zb.encryptFlockEnvelope({ roster, state: f.state, flockKey: key,
      signingPriv: f.owner.signingPriv, fromOpaquePeerId: f.owner.opaquePeerId,
      toOpaquePeerId: f.peer.opaquePeerId, action: body.kind === "response" ? "ping" : body.request.action,
      body: { sealedRpcBody }, nowMs: f.nowMs });
    return { envelope, transport: bundle.transport };
  } finally { key.fill(0); }
}

test("Standard wire preflight rejects real double-sealed 180KiB RPC before either cloud attempt", async (t) => {
  const f = runtimeFixture(t);
  const packet = encryptedRpcPacket(f, { kind: "request",
    request: { requestId: crypto.randomUUID(), action: "send_message", expiresAt: f.nowMs + 60000,
      params: { message: "x".repeat(180 * 1024) } } });
  assert.ok(Buffer.byteLength(JSON.stringify(packet.envelope), "utf8") > 256 * 1024);
  t.diagnostic(`180 KiB application text produces ${Buffer.byteLength(JSON.stringify(packet.envelope), "utf8")} encrypted packet bytes before broker properties/reserve`);
  const attempts = [];
  await assert.rejects(sendEncryptedPacket({ ...packet, request: async (url, options) => {
    attempts.push({ url, options });
    return { status: url.includes("servicebus") ? 413 : 200 };
  } }), { code: "PACKET_TOO_LARGE" });
  assert.equal(attempts.length, 0);
});

function standardMessageBytes(envelope) {
  const properties = { "Content-Type": "application/json", toOpaquePeerId: JSON.stringify(envelope.toOpaquePeerId),
    BrokerProperties: JSON.stringify({ MessageId: envelope.messageId, TimeToLive: 3600 }) };
  return Buffer.byteLength(JSON.stringify(envelope), "utf8") + Buffer.byteLength(JSON.stringify(properties), "utf8") + ENCRYPTED_PACKET_HEADER_RESERVE_BYTES;
}

test("Standard wire boundary measures actual encrypted request/receipt UTF-8 bytes and broker properties", async (t) => {
  const f = runtimeFixture(t);
  for (const kind of ["request", "response"]) {
    const body = (count) => {
      const nested = { escaped: "\u0000\"\\\n😀".repeat(64), pad: "x".repeat(count) };
      return kind === "request" ? { kind, request: { requestId: "r".repeat(128), action: "send_message",
        expiresAt: f.nowMs + 60000, params: nested } } :
        { kind, requestId: "r".repeat(128), status: "DELIVERED", result: nested };
    };
    let low = 0, high = 180 * 1024;
    while (low < high) {
      const middle = Math.ceil((low + high) / 2);
      const packet = encryptedRpcPacket(f, body(middle));
      if (standardMessageBytes(packet.envelope) <= SERVICE_BUS_STANDARD_MESSAGE_BYTES) low = middle;
      else high = middle - 1;
    }
    const accepted = encryptedRpcPacket(f, body(low));
    const rejected = encryptedRpcPacket(f, body(low + 1));
    const prepared = prepareEncryptedPacket(accepted.envelope);
    assert.equal(prepared.messageBytes, standardMessageBytes(accepted.envelope));
    assert.ok(prepared.messageBytes <= 256 * 1024);
    assert.ok(prepared.messageBytes > 256 * 1024 - 16);
    assert.ok(standardMessageBytes(rejected.envelope) > 256 * 1024);
    t.diagnostic(`${kind}: accepted total ${prepared.messageBytes} bytes, next application byte totals ${standardMessageBytes(rejected.envelope)} bytes; 262144-byte budget includes 16384-byte reserve`);
    const attempts = [];
    assert.deepEqual(await sendEncryptedPacket({ ...accepted, request: async (url, options) => {
      attempts.push({ url, options }); return { status: 201 };
    } }), { admittedToTransport: true });
    assert.equal(attempts.length, 2);
    const signalr = attempts.find(({ url }) => url.includes(".service.signalr.net/")).options;
    const serviceBus = attempts.find(({ url }) => url.includes(".servicebus.windows.net/")).options;
    assert.deepEqual(JSON.parse(signalr.body).arguments, [JSON.parse(serviceBus.body)]);
    const { Authorization: _token, ...properties } = serviceBus.headers;
    assert.equal(Buffer.byteLength(serviceBus.body, "utf8") + Buffer.byteLength(JSON.stringify(properties), "utf8") +
      ENCRYPTED_PACKET_HEADER_RESERVE_BYTES, prepared.messageBytes);
    await assert.rejects(sendEncryptedPacket({ ...rejected, request: async () => assert.fail("Oversize must not reach either transport") }), { code: "PACKET_TOO_LARGE" });
  }
});

test("Standard wire provider size rejection is explicit even after the other channel accepts", async (t) => {
  const f = runtimeFixture(t);
  const packet = encryptedRpcPacket(f, { kind: "response", requestId: crypto.randomUUID(), status: "UNKNOWN", result: null });
  for (const rejectedChannel of ["servicebus", "signalr"]) {
    const attempts = [];
    await assert.rejects(sendEncryptedPacket({ ...packet, request: async (url) => {
      attempts.push(url); return { status: url.includes(rejectedChannel) ? 413 : 201 };
    } }), { code: "PACKET_SIZE_REJECTED", ambiguous: true });
    assert.equal(attempts.length, 2);
  }
});

function padCanonical(value, targetBytes, measure = (entry) => zb.canonicalJson(entry)) {
  const remaining = targetBytes - Buffer.byteLength(measure(value), "utf8");
  assert.ok(remaining >= 0);
  value.pad = "x".repeat(remaining);
  assert.equal(Buffer.byteLength(measure(value), "utf8"), targetBytes);
  return value;
}

test("Standard runtime accepts exact typed UTF-8 boundaries on both cloud paths and rejects before new outbox admission", async (t) => {
  const outcome = { status: "DELIVERED", result: { nested: "\u0000\"\\\n😀".repeat(1024), pad: "" } };
  padCanonical(outcome.result, RPC_BODY_LIMIT_BYTES - 1024, (result) => zb.canonicalJson({ ...outcome, result }));
  const f = runtimeFixture(t, { cloudTransport: true, dispatch: async () => outcome });
  const request = { requestId: "r".repeat(128), action: "s".repeat(64),
    params: { nested: { escaped: "\u0000\"\\\n😀".repeat(1024) }, pad: "" }, expiresAt: f.nowMs + 60000 };
  padCanonical(request.params, RPC_BODY_LIMIT_BYTES, (params) => zb.canonicalJson({ kind: "reconcile", request: { ...request, params } }));
  const result = await f.ownerRuntime.request({ ...request, toOpaquePeerId: f.peer.opaquePeerId });
  assert.equal(result.status, "DELIVERED");
  assert.deepEqual(result.result, outcome.result);
  assert.equal(f.calls(), 1);
  assert.equal(f.cloudAttempts.length, 4);
  for (const { url, options } of f.cloudAttempts) {
    const envelope = url.includes(".servicebus.windows.net/") ? JSON.parse(options.body) : JSON.parse(options.body).arguments[0];
    assert.ok(standardMessageBytes(envelope) <= SERVICE_BUS_STANDARD_MESSAGE_BYTES);
  }
  const before = f.cloudAttempts.length;
  await assert.rejects(f.ownerRuntime.request({ ...request, requestId: "n".repeat(128),
    params: { ...request.params, pad: request.params.pad + "x" }, toOpaquePeerId: f.peer.opaquePeerId }), { code: "RPC_PAYLOAD_TOO_LARGE" });
  assert.equal(f.cloudAttempts.length, before);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 0);
  const params = {};
  const changed = f.ownerRuntime.request({ toOpaquePeerId: f.peer.opaquePeerId, action: "send_message", params });
  params.message = "x".repeat(180 * 1024);
  await assert.rejects(changed, { code: "PACKET_TOO_LARGE" });
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 0);
  assert.equal(f.cloudAttempts.length, before);
});

test("Standard runtime retains durable UNKNOWN without redispatch when a post-action result exceeds its boundary", async (t) => {
  const outcome = { status: "DELIVERED", result: { nested: "\u0000\"\\\n😀", pad: "" } };
  padCanonical(outcome.result, RPC_BODY_LIMIT_BYTES - 1024 + 1, (result) => zb.canonicalJson({ ...outcome, result }));
  const f = runtimeFixture(t, { cloudTransport: true, dispatch: async () => outcome });
  const request = { toOpaquePeerId: f.peer.opaquePeerId, requestId: crypto.randomUUID(),
    action: "send_message", params: {}, expiresAt: f.nowMs + 60000 };
  const result = await f.ownerRuntime.request(request);
  assert.equal(result.status, "UNKNOWN");
  assert.equal(result.result, null);
  assert.equal(f.calls(), 1);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
  const receipt = f.receiverState.readRequestReceipt({ roster: f.receiverState.get(f.flockUuid),
    sender: f.owner.opaquePeerId, recipient: f.peer.opaquePeerId, requestId: request.requestId,
    payload: { requestId: request.requestId, action: request.action, params: {}, expiresAt: request.expiresAt },
    expiresAt: request.expiresAt, authorization: { mode: "ROOT", grantRevision: "0", rosterEpoch: 2 } });
  assert.equal(receipt.status, "UNKNOWN");
  assert.equal(receipt.result, null);
  assert.ok(f.errors.some((entry) => entry.status === "UNKNOWN" && /result exceeds/.test(entry.message)));
  await f.ownerRuntime.reconcilePending();
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  assert.equal(f.calls(), 1);
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 1);
});

test("automatic reconciliation stops expired queries but retains uncertainty and accepts a late authenticated receipt", async (t) => {
  const f = runtimeFixture(t, { captureResponses: true, fakeClock: true });
  const request = { toOpaquePeerId: f.peer.opaquePeerId, requestId: crypto.randomUUID(),
    action: "send_message", params: {}, expiresAt: f.nowMs + 1000, timeoutMs: 20 };
  assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
  const lateReceipt = f.packets.at(-1);
  const before = f.packets.length;
  f.advance(1001);
  for (let cycle = 0; cycle < 3; cycle++) await f.ownerRuntime.reconcilePending();
  assert.equal(f.packets.length, before, "Expired uncertainty is retained, not polled indefinitely");
  const [retained] = f.state.pendingOutbox(f.flockUuid);
  assert.equal(retained.request, request.requestId);
  assert.equal(retained.attempted, 1);
  assert.equal(f.calls(), 1);
  assert.equal((await f.ownerRuntime.receive(lateReceipt)).status, "RECEIPT_ACCEPTED");
  assert.equal(f.state.pendingOutbox(f.flockUuid).length, 0);
  assert.equal(f.calls(), 1);
});

test("actual daemon still polls receipts/enrollment when an outgoing reconciliation is denied or its publication stalls", async (t) => {
  for (const blocked of [false, true]) {
    const f = runtimeFixture(t, { captureResponses: true });
    const request = { toOpaquePeerId: f.peer.opaquePeerId, action: "send_message",
      params: {}, requestId: crypto.randomUUID(), expiresAt: f.nowMs + 60000, timeoutMs: 20 };
    assert.equal((await f.ownerRuntime.request(request)).status, "UNKNOWN");
    let release, watchdogFired = false;
    const gate = new Promise((resolve) => { release = resolve; });
    if (blocked) f.setPublicationGate(gate);
    else addSharedMember(f);
    let polls = 0, enrollmentPolls = 0;
    const controller = new AbortController();
    const group = { device: f.owner, state: f.state, runtime: f.ownerRuntime,
      transport: () => f.memberBundle(f.state.get(f.flockUuid), f.owner).transport,
      configuration: () => ({ issuer: false }), renewAndPrune: async () => {},
      poll: async () => { polls++; }, pollEnrollment: async () => { enrollmentPolls++; },
      suspend: () => f.ownerRuntime.close(), close: () => {} };
    const config = { architecture: "zero-broker", groups: [{ flockUuid: f.flockUuid, rootFingerprint: f.genesis.rootFingerprint }] };
    const source = fs.readFileSync(new URL("../zero-broker-lifecycle.mjs", import.meta.url), "utf8");
    const start = source.indexOf("export async function runZeroBrokerService(");
    assert.ok(start > 0);
    const service = vm.runInNewContext(`${source.slice(start).replace("export async function", "async function")}\nrunZeroBrokerService`, {
      openZeroBrokerGroup: () => group, rosterApi: { readPrivateJson: () => config },
      check: (condition, message) => { if (!condition) throw new Error(message); },
      WebSocket: class { close() { this.onclose?.(); } }, URL, Buffer, setTimeout, clearTimeout, setInterval, clearInterval,
    });
    const watchdog = setTimeout(() => { watchdogFired = true; release(); controller.abort(); }, 1000);
    try {
      await service({ home: "synthetic-only", config, host: { reportError: () => {} },
        signal: controller.signal, onStatus: () => controller.abort() });
      assert.equal(watchdogFired, false, "Blocked publication must not hold up the polling cycle");
      assert.equal(polls, 1);
      assert.equal(enrollmentPolls, 1);
    } finally { clearTimeout(watchdog); release(); controller.abort(); }
  }
});

test("automatic reconciliation is bounded, fair across failures and exponentially backed off without changing attempted proof", async (t) => {
  const f = runtimeFixture(t, { fakeClock: true });
  f.setOffline(true);
  const count = AUTOMATIC_RECONCILE_LIMIT + 2;
  for (let index = 0; index < count; index++) {
    assert.equal((await f.ownerRuntime.request({ toOpaquePeerId: f.peer.opaquePeerId, action: "send_message",
      params: { index }, expiresAt: f.nowMs + zb.MAX_LEASE_MS - 1000, timeoutMs: 20 })).status, "UNKNOWN");
  }
  const initial = f.packets.length;
  assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, AUTOMATIC_RECONCILE_LIMIT);
  assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, 2, "Later rows progress despite earlier transport failures");
  assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, 0);
  assert.equal(f.packets.length, initial + count);
  let clock = f.nowMs;
  for (const delay of [30000, 60000, 120000, 240000, 300000, 300000]) {
    f.advance(delay - 1);
    assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, 0);
    f.advance(1); clock += delay;
    assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, AUTOMATIC_RECONCILE_LIMIT);
    assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, 2);
    assert.equal((await f.ownerRuntime.reconcilePending()).scheduled, 0);
    const retained = f.state.pendingOutbox(f.flockUuid);
    assert.equal(retained.length, count);
    for (const row of retained) {
      assert.equal(row.attempted, 1, "Admission-attempt proof is a boolean, never a retry counter");
      assert.ok(row.reconcile_attempts >= 1 && row.reconcile_attempts <= 5);
      assert.equal(row.next_reconcile_at, clock + Math.min(zb.OUTBOX_RECONCILE_MAX_DELAY_MS,
        zb.OUTBOX_RECONCILE_BASE_DELAY_MS * 2 ** (row.reconcile_attempts - 1)));
    }
  }
  assert.equal(f.calls(), 0);
  assert.ok(f.errors.some((entry) => /reconciliation failed/.test(entry.message) && entry.status === "UNKNOWN"));
});

test("one blocked automatic publication cannot monopolize reconciliation slots or prevent later rows progressing", async (t) => {
  const f = runtimeFixture(t, { fakeClock: true, captureResponses: true });
  f.setOffline(true);
  const count = AUTOMATIC_RECONCILE_LIMIT + 2;
  for (let index = 0; index < count; index++) await f.ownerRuntime.request({ toOpaquePeerId: f.peer.opaquePeerId,
    action: "send_message", params: { index }, expiresAt: f.nowMs + 60000, timeoutMs: 20 });
  f.setOffline(false);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  f.setPublicationGate(gate, true);
  try {
    assert.equal((await f.ownerRuntime.reconcilePending({ waitForCompletion: false })).scheduled, AUTOMATIC_RECONCILE_LIMIT);
    await new Promise(setImmediate);
    assert.equal((await f.ownerRuntime.reconcilePending({ waitForCompletion: false })).scheduled, 2);
    await new Promise(setImmediate);
    assert.equal((await f.ownerRuntime.reconcilePending({ waitForCompletion: false })).scheduled, 0);
    assert.ok(f.state.pendingOutbox(f.flockUuid).every((row) => row.reconcile_attempts === 1 && row.attempted === 1));
    assert.equal(f.calls(), 0);
  } finally { release(); await new Promise(setImmediate); }
});

test("cloud HTTP is bounded, HTTPS-only and does not follow credential-bearing redirects", async () => {
  await assert.rejects(cloudRequest("http://synthetic.invalid"), /HTTPS/);
  let calls = 0;
  const fetchImpl = async (url, options) => {
    calls++;
    assert.equal(options.redirect, "error");
    assert.ok(options.signal);
    return new Response("synthetic", { status: 200 });
  };
  assert.equal((await cloudRequest("https://synthetic.invalid", { fetchImpl })).text, "synthetic");
  await assert.rejects(cloudRequest("https://synthetic.invalid", { fetchImpl, body: "x".repeat(1048577) }), /request exceeds/);
  assert.equal(calls, 1);
  await assert.rejects(cloudRequest("https://synthetic.invalid", { fetchImpl: async () => new Response("x".repeat(1048577)) }), /response exceeds/);
});

test("mock Azure staging uses exactly Send/Listen rules and unique recipient-filtered epoch resources", async () => {
  const calls = [];
  const options = { flockUuid: crypto.randomUUID(), rosterEpoch: 2, opaquePeerIds: [`peer_${"a".repeat(24)}`], resourceGroup: "synthetic-rg", namespaceName: "synthetic-namespace", signalr: { endpoint: "https://demo.service.signalr.net", accessKey: "synthetic-key" } };
  const staged = await stageEpochResources({ ...options, runAz: (args) => {
    calls.push(args);
    return args.includes("keys") ? { primaryKey: "synthetic-rule-key" } : null;
  } });
  assert.equal(calls.filter((args) => args.includes("authorization-rule") && args.includes("create")).length, 2);
  assert.ok(calls.some((args) => args.includes("RecipientOnly") && args.includes(`toOpaquePeerId = '${options.opaquePeerIds[0]}'`)));
  assert.ok(calls.some((args) => args.includes("$Default")));
  await staged.discard();
  const count = calls.length;
  await staged.discard();
  assert.equal(calls.length, count);
  assert.ok(calls.at(-1).includes(staged.topicName));
  assert.equal(staged.ownerCredentials.serviceBus.namespaceHost, "synthetic-namespace.servicebus.windows.net");
});

test("GitHub genesis history is immutable and archived before the latest roster SHA-precondition write", async (t) => {
  const f = fixture(t);
  const calls = [];
  const repository = createGitHubRosterRepository({
    repository: "synthetic-owner/synthetic-roster", token: "synthetic-token",
    request: async (url, options) => {
      calls.push({ url, body: JSON.parse(options.body) });
      return { status: 201 };
    },
  });
  await repository.publishGenesis(f.genesis);
  assert.ok(calls[0].url.endsWith("/history/genesis.json"));
  assert.ok(calls[1].url.endsWith(`/history/${zb.hashRoster(f.genesis)}.json`));
  assert.ok(calls[2].url.endsWith("/flock-roster.json"));
  assert.ok(calls.every((call) => !Object.hasOwn(call.body, "sha")));
  const second = zb.rotateRosterEpoch({ roster: f.genesis, actor: f.owner, ownerCredentials: f.credentials(2), nowMs: f.nowMs });
  await repository.put({ roster: second, sha: "a".repeat(40) });
  assert.equal(calls.at(-1).body.sha, "a".repeat(40));
  const decoded = Buffer.from(calls.at(-1).body.content, "base64").toString("utf8");
  assert.ok(!decoded.includes("synthetic-signalr-key"));
});

test("Service Bus acknowledgements reject lock URLs outside the exact subscription and occur only explicitly", async () => {
  const transport = { namespaceHost: "synthetic.servicebus.windows.net", topicName: "synthetic-topic", subscriptionName: `sub-peer_${"a".repeat(24)}-e1`, sbListenSas: "synthetic-listen-token" };
  const base = `https://${transport.namespaceHost}/${transport.topicName}/subscriptions/${transport.subscriptionName}/messages/`;
  for (const location of ["https://synthetic.invalid/stolen", `${base}lock#fragment`, `${base}../outside`]) {
    await assert.rejects(peekLockEncryptedPacket({ transport, request: async () => ({ status: 201, text: "{}", headers: new Headers({ location }) }) }), /out-of-scope/);
  }
  const calls = [];
  const received = await peekLockEncryptedPacket({ transport, request: async (url, options) => {
    calls.push(options.method);
    return options.method === "POST" ? { status: 201, text: "{}", headers: new Headers({ location: `${base}synthetic-message/synthetic-lock` }) } : { status: 204 };
  } });
  assert.deepEqual(calls, ["POST"]);
  await received.acknowledge();
  assert.deepEqual(calls, ["POST", "DELETE"]);
});
