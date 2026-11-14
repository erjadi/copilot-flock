import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createBootstrapServer,
  createV3FlockInvite,
  enrollV3Device,
} from "../bootstrap-server.mjs";
import {
  applyV3EnrollmentResult,
  handleRpcAction,
  openFlockMembershipRegistry,
  signV3EnrollmentRequest,
  signRpcRequest,
  syncFlockMemberships,
  verifyEnrollmentReadiness,
} from "../flock.mjs";

function identity() {
  const pair = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    ...pair,
    fingerprint: crypto.createHash("sha256").update(pair.publicKey).digest("hex").slice(0, 32),
  };
}

function signedRequest({ key, machineId, action, params = {}, toMachine = "LOCAL" }) {
  const requestId = crypto.randomUUID();
  const sentAt = new Date().toISOString();
  const auth = signRpcRequest({
    requestId,
    sentAt,
    fromMachine: machineId,
    toMachine,
    action,
    params,
    identity: key,
  });
  return { requestId, sentAt, action, params, toMachine, auth };
}

test("3.6 authoritative registry closes split-brain and pins peer keys by exact flock", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-roster-"));
  const flocksPath = path.join(root, "flocks.json");
  const alice = identity();
  const collision = identity();
  try {
    fs.writeFileSync(flocksPath, JSON.stringify({
      flocks: {
        "owner/team": {
          flockId: "owner/team",
          ownerGitHubUser: "owner",
          trustTier: "collaborator",
          rosterEpoch: 3,
          sessionVisibility: "explicit_opt_in_only",
          members: [],
        },
        "other/team": {
          flockId: "other/team",
          ownerGitHubUser: "other",
          trustTier: "collaborator",
          rosterEpoch: 9,
          sessionVisibility: "explicit_opt_in_only",
          members: [],
        },
      },
    }));
    const registry = openFlockMembershipRegistry(flocksPath);
    registry.reconcileV3BrokerFlock({
      flockId: "owner/team",
      ownerGitHubUser: "owner",
      rosterEpoch: 4,
      members: [{
        peerId: "2002:alice-device",
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: "alice-device",
        keyFingerprint: "alice-device",
        machineId: "JAPAN-STU",
        scope: "work",
        trustTier: "collaborator",
        publicKey: alice.publicKey,
      }],
    });
    registry.reconcileV3BrokerFlock({
      flockId: "other/team",
      ownerGitHubUser: "other",
      rosterEpoch: 9,
      members: [{
        peerId: "3003:collision-device",
        githubUser: "mallory",
        githubUserId: 3003,
        deviceId: "collision-device",
        keyFingerprint: "collision-device",
        machineId: "JAPAN-STU",
        scope: "work",
        trustTier: "collaborator",
        publicKey: collision.publicKey,
      }],
    });

    const params = { flock: "owner/team" };
    const request = signedRequest({
      key: alice,
      machineId: "JAPAN-STU",
      action: "list_locks",
      params,
    });
    const result = await handleRpcAction(
      { machineId: "LOCAL", githubUser: "owner", scope: "work", flocksConfigPath: flocksPath },
      { ...request, flocksConfigPath: flocksPath }
    );
    assert.equal(result.machineId, "LOCAL");
    assert.equal(registry.findActiveMember("owner/team", { machineId: "JAPAN-STU" }).githubUser, "alice");
    assert.equal(registry.findActiveMember("other/team", { machineId: "JAPAN-STU" }).githubUser, "mallory");

    const forged = signedRequest({
      key: collision,
      machineId: "JAPAN-STU",
      action: "list_locks",
      params,
    });
    await assert.rejects(
      () => handleRpcAction(
        { machineId: "LOCAL", githubUser: "owner", scope: "work", flocksConfigPath: flocksPath },
        { ...forged, flocksConfigPath: flocksPath }
      ),
      /public key mismatch|signature verification failed/i
    );

    registry.reconcileV3BrokerFlock({
      flockId: "owner/team",
      ownerGitHubUser: "owner",
      rosterEpoch: 5,
      members: [],
    });
    assert.equal(registry.findActiveMember("owner/team", { machineId: "JAPAN-STU" }), null);
    assert.throws(
      () => registry.reconcileV3BrokerFlock({
        flockId: "owner/team",
        ownerGitHubUser: "owner",
        rosterEpoch: 4,
        members: [],
      }),
      (error) => error.code === "ROSTER_ROLLBACK_REJECTED"
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 membership sync capability preflight is bounded and single-flight", async () => {
  const key = identity();
  const cfg = { machineId: "LOCAL", bootstrapUrl: "https://broker.invalid/api/bootstrap" };
  await assert.rejects(
    () => syncFlockMemberships(cfg, {
      identityKeypair: key,
      callEndpoint: async (_cfg, subPath) => subPath === "/capabilities"
        ? { ok: true, capabilities: { rosterSync: false, tokenLocalDeviceAuth: true, deviceSignedOperations: true } }
        : { ok: true },
    }),
    (error) => error.code === "BROKER_CAPABILITY_UNSUPPORTED" && error.stage === "broker_capability"
  );

  let capabilityCalls = 0;
  let syncCalls = 0;
  const callEndpoint = async (_cfg, subPath) => {
    if (subPath === "/capabilities") {
      capabilityCalls++;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return {
        ok: true,
        capabilities: { rosterSync: true, tokenLocalDeviceAuth: true, deviceSignedOperations: true },
      };
    }
    syncCalls++;
    return { ok: false, code: "SYNTHETIC_SYNC_FAILURE", error: "synthetic sync failure" };
  };
  const attempts = await Promise.allSettled([
    syncFlockMemberships(cfg, { identityKeypair: key, callEndpoint }),
    syncFlockMemberships(cfg, { identityKeypair: key, callEndpoint }),
  ]);
  assert.equal(capabilityCalls, 1);
  assert.equal(syncCalls, 1);
  assert.ok(attempts.every((attempt) => attempt.status === "rejected"));
  assert.ok(attempts.every((attempt) => attempt.reason.code === "SYNTHETIC_SYNC_FAILURE"));
});

test("3.6 first contact auto-syncs once on an unpinned explicit-flock peer and retries", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-first-contact-"));
  const flocksPath = path.join(root, "flocks.json");
  const newcomer = identity();
  try {
    fs.writeFileSync(flocksPath, JSON.stringify({
      flocks: {
        "owner/japan-team": {
          flockId: "owner/japan-team",
          ownerGitHubUser: "owner",
          trustTier: "collaborator",
          rosterEpoch: 3,
          sessionVisibility: "explicit_opt_in_only",
          members: [],
        },
      },
    }));
    let syncCalls = 0;
    const cfg = {
      machineId: "LOCAL",
      githubUser: "owner",
      scope: "work",
      flocksConfigPath: flocksPath,
      syncFlockMembershipsFn: async () => {
        syncCalls++;
        openFlockMembershipRegistry(flocksPath).reconcileV3BrokerFlock({
          flockId: "owner/japan-team",
          ownerGitHubUser: "owner",
          rosterEpoch: 4,
          members: [{
            peerId: "4004:japan-device",
            githubUser: "newcomer",
            githubUserId: 4004,
            deviceId: "japan-device",
            keyFingerprint: "japan-device",
            machineId: "JAPAN-STU",
            scope: "work",
            trustTier: "collaborator",
            publicKey: newcomer.publicKey,
          }],
        });
        return { ok: true, reconciledFlockIds: ["owner/japan-team"] };
      },
    };
    const request = signedRequest({
      key: newcomer,
      machineId: "JAPAN-STU",
      action: "list_locks",
      params: { flock: "owner/japan-team" },
    });
    const result = await handleRpcAction(cfg, { ...request, flocksConfigPath: flocksPath });
    assert.equal(result.machineId, "LOCAL");
    assert.equal(syncCalls, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 voucher reissue separates redemption lifetime, membership duration, replay, and expiry", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-voucher-"));
  const storePath = path.join(root, "broker.json");
  const invited = identity();
  try {
    const first = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
      durationMinutes: 60,
      trustTier: "guest",
    }, { storePath });
    assert.equal(first.enrollmentJson.remainingRedemptionLifetimeSeconds, 86400);
    assert.equal(first.enrollmentJson.membershipDurationMinutes, 60);

    const replacement = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
      trustTier: "collaborator",
      reissue: true,
    }, { storePath });
    assert.deepEqual(replacement.supersededVoucherIds, [first.voucherId]);
    assert.equal(replacement.enrollmentJson.remainingRedemptionLifetimeSeconds, 259200);
    const missingSecret = structuredClone(replacement.enrollmentJson);
    delete missingSecret.flocks[0].voucherSecret;
    await assert.rejects(
      () => enrollV3Device({
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: invited.fingerprint,
        machineId: "ALICE-PC",
        scope: "work",
        publicKey: invited.publicKey,
        keyFingerprint: invited.fingerprint,
        enrollmentJson: missingSecret,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_SECRET_REQUIRED"
    );

    await assert.rejects(
      () => enrollV3Device({
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: invited.fingerprint,
        machineId: "ALICE-PC",
        scope: "work",
        publicKey: invited.publicKey,
        keyFingerprint: invited.fingerprint,
        enrollmentJson: first.enrollmentJson,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_SUPERSEDED"
    );

    const enrolled = await enrollV3Device({
      githubUser: "alice",
      githubUserId: 2002,
      deviceId: invited.fingerprint,
      machineId: "ALICE-PC",
      scope: "work",
      publicKey: invited.publicKey,
      keyFingerprint: invited.fingerprint,
      enrollmentJson: replacement.enrollmentJson,
    }, { storePath, connectionString: "" });
    assert.ok(enrolled.enrolledFlocks.some((flock) => flock.flockId === "owner/team"));

    const replayKey = identity();
    await assert.rejects(
      () => enrollV3Device({
        githubUser: "alice",
        githubUserId: 2002,
        deviceId: invited.fingerprint,
        machineId: "ALICE-PC",
        scope: "work",
        publicKey: replayKey.publicKey,
        keyFingerprint: invited.fingerprint,
        enrollmentJson: replacement.enrollmentJson,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_REPLAY"
    );

    const expired = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "bob",
      invitedGitHubUserId: 3003,
      voucherTtlSeconds: 60,
    }, { storePath });
    const state = JSON.parse(fs.readFileSync(storePath, "utf8"));
    state.flocks["owner/team"].vouchers[expired.voucherId].voucherExpiresAtMs = Date.now() - 1;
    fs.writeFileSync(storePath, JSON.stringify(state));
    const bob = identity();
    await assert.rejects(
      () => enrollV3Device({
        githubUser: "bob",
        githubUserId: 3003,
        deviceId: bob.fingerprint,
        machineId: "BOB-PC",
        scope: "work",
        publicKey: bob.publicKey,
        keyFingerprint: bob.fingerprint,
        enrollmentJson: expired.enrollmentJson,
      }, { storePath, connectionString: "" }),
      (error) => error.code === "VOUCHER_EXPIRED"
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 token-local enrollment rejects master SignalR AccessKey persistence", () => {
  assert.throws(
    () => applyV3EnrollmentResult(
      { tokenLocalAuth: true },
      {
        ok: true,
        connectionString: "Endpoint=https://example.invalid;AccessKey=secret;Version=1.0;",
        enrolledFlocks: [],
      }
    ),
    (error) => error.code === "MASTER_CREDENTIAL_EXPOSURE_REJECTED"
  );
});

test("3.6 broker advertises capabilities and never returns a master AccessKey to voucher enrollment", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flock-36-http-enroll-"));
  const storePath = path.join(root, "broker.json");
  const membersPath = path.join(root, "members.json");
  const invited = identity();
  const previousConnection = process.env.SIGNALR_CONNECTION_STRING;
  process.env.SIGNALR_CONNECTION_STRING =
    "Endpoint=https://example.service.signalr.net;AccessKey=master-secret;Version=1.0;";
  const server = createBootstrapServer({
    v3StorePath: storePath,
    v3PreviewStorePath: path.join(root, "preview.json"),
    membersPath,
  });
  try {
    const invite = await createV3FlockInvite({
      callerGitHubUser: "owner",
      callerGitHubUserId: 1001,
      targetAddress: "owner/team",
      invitedUser: "alice",
      invitedGitHubUserId: 2002,
      allowedScopes: ["work"],
    }, { storePath });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    const capabilities = await fetch(`http://127.0.0.1:${port}/api/v3/capabilities`).then((res) => res.json());
    assert.equal(capabilities.capabilities.rosterSync, true);
    assert.equal(capabilities.capabilities.tokenLocalDeviceAuth, true);

    const body = signV3EnrollmentRequest({
      deviceId: invited.fingerprint,
      machineId: "ALICE-PC",
      scope: "work",
      publicKey: invited.publicKey,
      keyFingerprint: invited.fingerprint,
      enrollmentJson: invite.enrollmentJson,
      maintainerVisibilityAck: true,
    }, 2002, invited);
    const response = await fetch(`http://127.0.0.1:${port}/api/v3/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    assert.equal(response.status, 200);
    assert.equal(result.ok, true);
    assert.equal(result.connectionString, undefined);
    assert.doesNotMatch(JSON.stringify(result), /AccessKey=|master-secret/);
    const flocksPath = path.join(root, "flocks.json");
    const applied = applyV3EnrollmentResult(
      {
        tokenLocalAuth: true,
        githubUser: "alice",
        machineId: "ALICE-PC",
        scope: "work",
      },
      result,
      flocksPath
    );
    assert.ok(applied.enrolledFlocks.every((flock) => !flock.hubToken && !flock.serverNonce));
    const persistedPolicy = fs.readFileSync(flocksPath, "utf8");
    assert.doesNotMatch(persistedPolicy, /master-secret|hubToken|serverNonce/);
    const vault = JSON.parse(fs.readFileSync(path.join(root, "flock-credentials.json"), "utf8"));
    assert.ok(Object.values(vault.credentials).some((entry) => entry.bearerToken));
    assert.doesNotMatch(JSON.stringify(vault), /AccessKey=|master-secret/);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    if (previousConnection === undefined) delete process.env.SIGNALR_CONNECTION_STRING;
    else process.env.SIGNALR_CONNECTION_STRING = previousConnection;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("3.6 cross-user unscoped project and lock reads fail closed", async () => {
  const alice = identity();
  const cfg = { machineId: "LOCAL", githubUser: "owner", scope: "work" };
  for (const action of ["list_projects", "list_locks"]) {
    const request = signedRequest({ key: alice, machineId: "ALICE-PC", action });
    await assert.rejects(
      () => handleRpcAction(cfg, {
        ...request,
        registryMembers: [{
          machineId: "ALICE-PC",
          githubUser: "alice",
          scope: "work",
          publicKey: alice.publicKey,
        }],
      }),
      (error) => error.code === "UNAUTHORIZED_FLOCK" && error.statusCode === 403
    );
  }
});

test("3.6 enrollment readiness requires correlated bidirectional epoch agreement", async () => {
  const awaitingPeer = await verifyEnrollmentReadiness(
    { machineId: "LOCAL" },
    [{ flockId: "owner/team", rosterEpoch: 7, members: [{ machineId: "LOCAL" }] }],
    { correlationId: "corr-awaiting" }
  );
  assert.equal(awaitingPeer.status, "enrolled_awaiting_peer_online");
  assert.equal(awaitingPeer.ready, false);

  const enrolledFlocks = [{
    flockId: "owner/team",
    rosterEpoch: 7,
    members: [
      { machineId: "LOCAL", peerId: "1001:local" },
      { machineId: "REMOTE", peerId: "2002:remote" },
    ],
  }];
  const success = await verifyEnrollmentReadiness(
    { machineId: "LOCAL" },
    enrolledFlocks,
    {
      correlationId: "corr-success",
      invokeRpc: async () => ({
        result: {
          enrollmentReadinessAck: {
            correlationId: "corr-success",
            flockId: "owner/team",
            rosterEpoch: 7,
          },
        },
      }),
    }
  );
  assert.equal(success.ready, true);
  assert.equal(success.status, "verified_bidirectional");
  assert.equal(success.stages.at(-1).stage, "first_contact");
  assert.equal(success.stages.at(-1).ok, true);

  const mismatch = await verifyEnrollmentReadiness(
    { machineId: "LOCAL" },
    enrolledFlocks,
    {
      correlationId: "corr-fail",
      invokeRpc: async () => ({
        result: {
          enrollmentReadinessAck: {
            correlationId: "corr-fail",
            flockId: "owner/team",
            rosterEpoch: 6,
          },
        },
      }),
    }
  );
  assert.equal(mismatch.ready, false);
  assert.equal(mismatch.stages.at(-1).ok, false);
  assert.match(mismatch.error, /roster epoch/i);
});
