import assert from "node:assert/strict";
import crypto from "node:crypto";
import { azureEndpoints } from "../flock-azure.mjs";
import { signV3EnrollmentRequest, buildTokenLocalDeviceAuthHeaders } from "../flock.mjs";
import { signLeave } from "../flock-membership.mjs";
import { withAzureGateCleanup } from "./azure-negative-probes.mjs";

export function validateHostedGate(config, pins) {
  assert.equal(config.disposable, true, "Hosted gate requires an explicitly disposable deployment");
  assert.equal(config.serviceBusAuth, "entra-rbac");
  assert.equal(config.serviceBusDisableLocalAuth, true, "Effective Service Bus disableLocalAuth must be true");
  azureEndpoints(config.signalrEndpoint, config.serviceBusEndpoint);
  assert.match(config.bootstrapUrl, /^https:\/\/[a-z0-9-]+\.azurewebsites\.net$/);
  for (const [field, pin] of [["signalrEndpoint", pins.signalr], ["serviceBusEndpoint", pins.serviceBus],
    ["bootstrapUrl", pins.bootstrap]]) {
    assert.ok(pin, `Explicit ${field} pin required`);
    assert.equal(config[field], pin, `${field} differs from approved disposable deployment`);
  }
  assert.match(config.githubUser, /^[a-z0-9][a-z0-9-]{0,38}$/i);
  assert.ok(Number.isSafeInteger(config.githubUserId) && config.githubUserId > 0);
}

export async function pollHostedRbac(attempt, { clock = Date.now, delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs = 180000 } = {}) {
  assert.ok(timeoutMs > 0 && timeoutMs <= 180000);
  const deadline = clock() + timeoutMs;
  for (let count = 0; count < 37; count++) {
    const result = await attempt(Math.max(1, deadline - clock()));
    if (result.serviceBusPublished === true) return result;
    if (!["servicebus_authz_denied", "servicebus_transient_error", "msi_transient_error"].includes(result.serviceBusCategory)) {
      throw new Error(`Hosted gate terminal authentication failure (${result.serviceBusCategory || "unknown"}); response withheld`);
    }
    if (clock() >= deadline) break;
    await delay(Math.min(5000, deadline - clock()));
  }
  throw new Error("Hosted gate Entra/RBAC publication did not become ready within 180 seconds");
}

export async function runHostedEntraGate(t, config, {
  pins = { signalr: process.env.COPILOT_FLOCK_LIVE_SIGNALR_ENDPOINT,
    serviceBus: process.env.COPILOT_FLOCK_LIVE_SERVICEBUS_ENDPOINT,
    bootstrap: process.env.COPILOT_FLOCK_LIVE_BOOTSTRAP_ENDPOINT },
  maintainerToken = process.env.COPILOT_FLOCK_LIVE_GITHUB_TOKEN,
  fetchImpl = fetch,
} = {}) {
  validateHostedGate(config, pins);
  assert.ok(maintainerToken, "Existing authorized maintainer authentication is required in the isolated runner environment");
  const peers = ["OWNER", "GUEST"].map((kind) => {
    const pair = crypto.generateKeyPairSync("ed25519", { publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" } });
    const fingerprint = crypto.createHash("sha256").update(pair.publicKey.trim()).digest("hex").slice(0, 32);
    return { ...pair, fingerprint, machineId: `GATE-${kind}-${crypto.randomUUID().slice(0, 8)}`, flocks: new Set() };
  });
  const [owner, guest] = peers;
  const request = async (endpoint, body, { peer, token, invalidSignature = false, timeoutMs = 15000 } = {}) => {
    const raw = JSON.stringify(body);
    const signed = peer ? buildTokenLocalDeviceAuthHeaders({ method: "POST", pathnameWithSearch: endpoint, body: raw }, peer) : null;
    const response = await fetchImpl(`${config.bootstrapUrl}${endpoint}`, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(timeoutMs),
      headers: { "Content-Type": "application/json", "X-Flock-Protocol-Version": "36",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(signed ? { "X-Flock-Device-Id": signed.deviceId, "X-Flock-Timestamp": signed.timestamp,
          "X-Flock-Signature": invalidSignature ? "AAAA" : signed.signature } : {}) },
      body: raw,
    });
    let data;
    try { data = await response.json(); }
    catch { throw new Error(`Hosted gate returned non-JSON (HTTP ${response.status}); response withheld`); }
    return { status: response.status, data };
  };
  const positive = (operation, evidence = {}) => t.diagnostic(JSON.stringify({ kind: "live-gate-positive-probe",
    operation, outcome: "passed", serviceBusAuth: "entra-rbac", ...evidence }));
  const requireOk = (response, operation) => {
    assert.equal(response.status, 200, `${operation} failed (HTTP ${response.status}); response withheld`);
    assert.equal(response.data.ok, true, `${operation} did not confirm success; response withheld`);
    return response.data;
  };
  const negatives = async (operation, endpoint, body, options) => {
    const result = await request(endpoint, body, options);
    assert.ok([401, 403].includes(result.status), `${operation} must be denied, not globally unavailable (HTTP ${result.status})`);
    t.diagnostic(JSON.stringify({ kind: "live-gate-negative-probe", operation, status: result.status, outcome: "denied" }));
  };
  const enrolled = async (peer, userId, enrollmentJson, token) => {
    const body = signV3EnrollmentRequest({ deviceId: peer.fingerprint, machineId: peer.machineId,
      scope: "work", publicKey: peer.publicKey, keyFingerprint: peer.fingerprint,
      ...(enrollmentJson ? { enrollmentJson, maintainerVisibilityAck: true } : {}) }, userId, peer);
    const result = requireOk(await request("/api/v3/enroll", body, { token }), "device enrollment");
    for (const flock of result.enrolledFlocks || []) peer.flocks.add(flock.flockId);
    assert.ok(peer.flocks.size);
  };
  const pendingIds = [];
  await withAzureGateCleanup(async () => {
    const health = await fetchImpl(`${config.bootstrapUrl}/health`, { redirect: "error", signal: AbortSignal.timeout(15000) });
    assert.equal(health.status, 200);
    const status = await health.json();
    assert.equal(status.serviceBusResource, "https://servicebus.azure.net", "Hosted MSI must use the approved Service Bus audience");
    assert.equal(status.serviceBusNamespace, new URL(config.serviceBusEndpoint).hostname);
    assert.equal(status.msiConfigured, true);
    await enrolled(owner, config.githubUserId, null, maintainerToken);
    const flockId = `${config.githubUser.toLowerCase()}/gate-${crypto.randomUUID().slice(0, 8)}`;
    const guestId = 1000000000 + crypto.randomInt(1000000000);
    const invite = requireOk(await request("/api/v3/flocks/invite", {
      targetAddress: flockId, invitedUser: `gate-${crypto.randomUUID().slice(0, 8)}`,
      invitedGitHubUserId: guestId, durationMinutes: 10, maxDevices: 1,
      allowedScopes: ["work"], tokenLocalVoucherAuth: true, bootstrapUrl: config.bootstrapUrl,
    }, { token: maintainerToken }), "guest invite");
    owner.flocks.add(flockId);
    await enrolled(guest, guestId, invite.enrollmentJson);
    positive("two-device-ed25519-enrollment");
    const queued = await pollHostedRbac(async (remainingMs) => {
      const requestId = crypto.randomUUID();
      pendingIds.push(requestId);
      return requireOk(await request("/api/queue/enqueue", {
        toMachine: guest.machineId, machineId: owner.machineId, ttlSeconds: 60,
        rpcPayload: { requestId, fromMachine: owner.machineId, action: "ping", params: { fixture: true } },
      }, { peer: owner, timeoutMs: Math.min(15000, remainingMs) }), "owner enqueue");
    });
    assert.equal(queued.serviceBusPublished, true);
    assert.equal(queued.serviceBusStage, "topic_post");
    assert.equal(queued.serviceBusCategory, "servicebus_ok");
    positive("broker-msi-subscription-put-and-topic-publish", { resource: status.serviceBusResource,
      stages: ["subscription_put", "topic_post"], statusCode: queued.serviceBusStatusCode });
    const canonicalGuest = `${flockId}/${guest.machineId}`;
    const secondId = crypto.randomUUID();
    pendingIds.push(secondId);
    const repeated = requireOk(await request("/api/queue/enqueue", {
      toMachine: canonicalGuest, machineId: owner.machineId, ttlSeconds: 60,
      rpcPayload: { requestId: secondId, fromMachine: owner.machineId, action: "ping", params: { fixture: true } },
    }, { peer: owner }), "canonical second-message enqueue");
    assert.equal(repeated.serviceBusPublished, true, "Existing subscription must not prevent repeat publication");
    assert.equal(repeated.toMachine, guest.machineId);
    positive("broker-msi-existing-subscription-repeat-publish-and-canonical-target");
    const drained = requireOk(await request("/api/queue/drain", { machineId: canonicalGuest, peekOnly: true },
      { peer: guest }), "own queue drain");
    assert.ok(drained.messages.some((item) => item.requestId === queued.requestId && item.serviceBusPublished === true));
    assert.ok(drained.messages.some((item) => item.requestId === secondId && item.toMachine === guest.machineId && item.serviceBusPublished === true));
    await negatives("cross-peer-drain", "/api/queue/drain", { machineId: owner.machineId, peekOnly: true }, { peer: guest });
    await negatives("cross-peer-ack", "/api/queue/ack", { machineId: guest.machineId, requestIds: pendingIds }, { peer: owner });
    for (const [operation, selector] of [
      ["device-maintainer-foreign-ack-without-selector", {}],
      ["device-maintainer-foreign-ack-own-selector", { machineId: owner.machineId }],
    ]) {
      const foreignAck = requireOk(await request("/api/queue/ack", { ...selector, requestIds: pendingIds },
        { peer: owner }), "device ACK foreign item");
      assert.equal(foreignAck.ackedCount, 0, "A device-authenticated maintainer cannot acknowledge another device's items");
      assert.equal(foreignAck.remainingCount, 0, "Scoped ACK cannot disclose foreign queue depth");
      const preserved = requireOk(await request("/api/queue/drain", { machineId: guest.machineId, peekOnly: true },
        { peer: guest }), "foreign queue preservation");
      assert.deepEqual(preserved.messages, drained.messages, "Foreign queue items must remain unchanged after the denied ACK");
      t.diagnostic(JSON.stringify({ kind: "live-gate-authorization-probe", operation, outcome: "denied_no_mutation",
        status: 200, ackedCount: foreignAck.ackedCount, remainingCount: foreignAck.remainingCount, foreignItemsPreserved: true }));
    }
    await negatives("guest-enqueue", "/api/queue/enqueue", { toMachine: owner.machineId,
      rpcPayload: { requestId: crypto.randomUUID() } }, { peer: guest });
    await negatives("invalid-device-signature", "/api/queue/drain", { machineId: guest.machineId },
      { peer: guest, invalidSignature: true });
    await negatives("unauthenticated-drain", "/api/queue/drain", { machineId: guest.machineId });
    const ownRequestId = crypto.randomUUID();
    const ownQueued = requireOk(await request("/api/queue/enqueue", {
      toMachine: owner.machineId, machineId: owner.machineId, ttlSeconds: 60,
      rpcPayload: { requestId: ownRequestId, fromMachine: owner.machineId, action: "ping", params: { fixture: true } },
    }, { peer: owner }), "maintainer own enqueue");
    assert.equal(ownQueued.serviceBusPublished, true);
    const ownAck = requireOk(await request("/api/queue/ack", { machineId: owner.machineId, requestIds: [ownRequestId] },
      { peer: owner }), "maintainer own ACK");
    assert.equal(ownAck.ackedCount, 1);
    assert.equal(ownAck.remainingCount, 0, "A successful own ACK must not disclose the still-pending foreign queue");
    positive("device-maintainer-own-ack", { ackedCount: ownAck.ackedCount, remainingCount: ownAck.remainingCount });
    const ack = requireOk(await request("/api/queue/ack", { machineId: canonicalGuest, requestIds: pendingIds },
      { peer: guest }), "own queue acknowledgement");
    assert.equal(ack.ackedCount, pendingIds.length);
    const afterAck = requireOk(await request("/api/queue/drain", { machineId: guest.machineId, peekOnly: true },
      { peer: guest }), "post-ack drain");
    assert.equal(afterAck.messages.some((item) => pendingIds.includes(item.requestId)), false);
    positive("broker-durable-json-own-queue-drain-and-ack");
    for (const id of [...guest.flocks]) {
      const left = requireOk(await request("/api/v3/flocks/leave",
        signLeave({ flockId: id, deviceId: guest.fingerprint, machineId: guest.machineId }, guest.privateKey)), "guest signed leave");
      assert.equal(left.confirmed, true);
      assert.equal(left.subscription.stage, "subscription_delete");
      assert.equal(left.subscription.category, "servicebus_ok");
      guest.flocks.delete(id);
    }
    positive("broker-msi-subscription-delete-on-leave", { resource: status.serviceBusResource, stage: "subscription_delete" });
    await negatives("departed-device-drain", "/api/queue/drain", { machineId: guest.machineId }, { peer: guest });
  }, async () => {
    const errors = [];
    for (const peer of [...peers].reverse()) for (const flockId of peer.flocks) {
      try {
        const result = await request("/api/v3/flocks/leave",
          signLeave({ flockId, deviceId: peer.fingerprint, machineId: peer.machineId }, peer.privateKey));
        if (result.status !== 200 || result.data.confirmed !== true) throw new Error("Unconfirmed disposable device leave");
      } catch {
        errors.push(new Error("Hosted disposable fixture device cleanup incomplete; response withheld"));
      }
    }
    if (errors.length) throw new AggregateError(errors, "Hosted fixture cleanup incomplete; disposable resource-group teardown still required");
  });
}
