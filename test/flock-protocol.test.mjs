import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createDeviceIdentity, createJoinCode, verifyJoinCode, createOwnerState,
  ownerFingerprint, approveJoin, acceptWelcome, encryptEnvelope, decryptEnvelope,
  DurableReceiver, createRotation, applyRotation } from "../flock-protocol.mjs";

async function group(role = "collaborator") {
  const owner = createDeviceIdentity();
  const peer = createDeviceIdentity();
  const state = createOwnerState({ identity: owner, flockId: "demo/team", scope: "personal", machineId: "OWNER-PC" });
  const code = createJoinCode(peer, { machineId: "PEER-PC", scope: "personal" });
  const options = { code, ownerIdentity: owner, ownerPublicKey: state.ownerPublicKey,
    rotationOwnerPeerId: state.rotationOwnerPeerId, flockId: state.flockId, role,
    sessionIds: ["shared-session"], membershipExpiresAt: Date.now() + 86400000,
    epoch: state.epoch, keyId: state.keyId, groupKey: Buffer.from(state.groupKey, "base64url"),
    verifyIdentityPolicy: async () => {}, authorizeOwner: async () => {},
    provisionTransport: async ({ subscription, expiresAt }) => ({ subscription, expiresAt,
      signalrClientToken: "synthetic-client", signalrRestToken: "synthetic-rest",
      serviceBusSendSas: "synthetic-send", serviceBusListenSas: "synthetic-listen" }),
  };
  const ticket = await approveJoin(options);
  const welcome = acceptWelcome(ticket, { identity: peer, code, pinnedOwnerFingerprint: ownerFingerprint(state.ownerPublicKey) });
  const peerState = { ...welcome, flockId: state.flockId, localPeerId: welcome.cert.body.peerId,
    minAcceptedEpoch: welcome.epoch };
  return { owner, peer, state, code, ticket, peerState, options };
}
test("two-device signed join and sealed Welcome bind both keys and independent owner pin", async () => {
  const f = await group();
  assert.equal(verifyJoinCode(f.code).peerId, f.peerState.localPeerId);
  assert.throws(() => acceptWelcome(f.ticket, { identity: f.peer, code: f.code, pinnedOwnerFingerprint: "wrong" }), /pin/);
  assert.throws(() => acceptWelcome(f.ticket, { identity: createDeviceIdentity(), code: f.code,
    pinnedOwnerFingerprint: ownerFingerprint(f.state.ownerPublicKey) }), /bound/);
  const substituted = structuredClone(f.code);
  substituted.body.deviceX25519Pub = createDeviceIdentity().x25519.publicKey;
  assert.throws(() => verifyJoinCode(substituted), /signature/);
  await assert.rejects(approveJoin({ ...f.options, role: "owner" }), /delegate/);
  await assert.rejects(approveJoin({ ...f.options, authorizeOwner: async () => { throw Error("not owner"); } }), /not owner/);
  await assert.rejects(approveJoin({ ...f.options, verifyIdentityPolicy: async () => { throw Error("identity denied"); } }), /identity denied/);
});
test("HKDF per-message random salt, canonical AAD and mandatory signature reject all tampering", async () => {
  const f = await group();
  const send = () => encryptEnvelope({ state: f.state, identity: f.owner, cert: f.state.cert,
    action: "ping", payload: { greeting: "hello" }, targetPeerId: f.peerState.localPeerId });
  const first = send();
  const second = send();
  assert.notEqual(first.header.salt, second.header.salt);
  assert.equal(Buffer.from(first.header.salt, "base64url").length, 32);
  assert.deepEqual(decryptEnvelope(first, f.peerState).payload, { greeting: "hello" });
  for (const field of ["scope", "epoch", "keyId", "salt", "targetPeerId", "action", "messageId"]) {
    const changed = structuredClone(first);
    changed.header[field] = field === "epoch" ? 9 : "changed";
    assert.throws(() => decryptEnvelope(changed, f.peerState));
  }
  for (const field of ["ciphertext", "tag", "signature"]) assert.throws(() => decryptEnvelope({ ...first, [field]: "AAAA" }, f.peerState));
  const missing = structuredClone(first);
  delete missing.signature;
  assert.throws(() => decryptEnvelope(missing, f.peerState));
  assert.throws(() => decryptEnvelope(first, f.peerState, first.cert.body.expiresAt + 1), /expired/);
});
test("guest and collaborator cannot derive owner privileges or access unshared sessions", async () => {
  const f = await group("guest");
  for (const action of ["self_update", "create_session", "list_sessions", "reprovision"]) {
    assert.throws(() => encryptEnvelope({ state: f.peerState, identity: f.peer, cert: f.peerState.cert,
      action, payload: { params: { fromGitHubUser: "demo" } }, targetPeerId: f.state.localPeerId }), /forbids/);
  }
  assert.throws(() => encryptEnvelope({ state: f.peerState, identity: f.peer, cert: f.peerState.cert,
    action: "send_message", payload: { params: { targetSession: "private" } }, targetPeerId: f.state.localPeerId }), /forbids/);
  const valid = encryptEnvelope({ state: f.peerState, identity: f.peer, cert: f.peerState.cert,
    action: "send_message", payload: { params: { targetSession: "shared-session" } }, targetPeerId: f.state.localPeerId });
  assert.equal(decryptEnvelope(valid, f.state).member.role, "guest");
});
test("durable replay admission quarantines ambiguous dispatch and rechecks authorization after awaits", async () => {
  const f = await group();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-replay-test-"));
  try {
    let active = f.peerState;
    const filename = path.join(directory, "replay.json");
    const receiver = new DurableReceiver(filename, () => active);
    const message = () => encryptEnvelope({ state: f.state, identity: f.owner, cert: f.state.cert,
      action: "ping", payload: {}, targetPeerId: f.peerState.localPeerId });
    const first = message();
    assert.equal(await receiver.dispatch(first, async () => "ok"), "ok");
    await assert.rejects(new DurableReceiver(filename, () => active).dispatch(first, async () => "duplicate"), /Replay/);
    const crash = message();
    await assert.rejects(receiver.dispatch(crash, async () => { throw Error("crash"); }), /crash/);
    await assert.rejects(receiver.dispatch(crash, async () => "duplicate"), /quarantined/);
    await assert.rejects(receiver.dispatch(message(), async ({ assertAuthorized }) => {
      await Promise.resolve();
      active = { ...active, minAcceptedEpoch: 2 };
      assertAuthorized();
    }), /epoch/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
test("designated owner rotation is sealed to retained devices and persists epoch/hash anti-rollback", async () => {
  const f = await group();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-rotation-test-"));
  try {
    const rotation = createRotation(f.state, f.owner, [f.state.cert, f.peerState.cert]);
    assert.throws(() => createRotation(f.peerState, f.peer, [f.peerState.cert]), /designated/);
    const file = path.join(directory, "epoch.json");
    const next = applyRotation(file, rotation, f.peer, f.peerState);
    assert.equal(next.epoch, 2);
    assert.equal(next.minAcceptedEpoch, 2);
    assert.deepEqual(applyRotation(file, rotation, f.peer, f.peerState), next);
    const conflict = createRotation(f.state, f.owner, [f.peerState.cert]);
    assert.throws(() => applyRotation(file, conflict, f.peer, f.peerState), /conflicting/);
    const old = encryptEnvelope({ state: f.state, identity: f.owner, cert: f.state.cert,
      action: "ping", payload: {}, targetPeerId: next.localPeerId });
    assert.throws(() => decryptEnvelope(old, next), /epoch/);
    const kicked = createRotation(f.state, f.owner, [f.state.cert]);
    assert.throws(() => applyRotation(path.join(directory, "kicked.json"), kicked, f.peer, f.peerState), /not retained/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
