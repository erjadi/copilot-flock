import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { AzureTransport, azureEndpoints, parseAzureConnection, HUB, TOPIC, jwt, sas } from "../flock-azure.mjs";
import { createDeviceIdentity, createOwnerState, createJoinCode, approveJoin, acceptWelcome, ownerFingerprint, peerSubscription } from "../flock-protocol.mjs";
import { connectSignalRClient } from "../flock.mjs";
import { OTHER_HUB, createOtherHubClientControl, runAzureNegativeProbes, classifySignalRClientDenial } from "./azure-negative-probes.mjs";

// Deliberately excluded from npm test. Never point this gate at an enrolled/production namespace.
test("LIVE RELEASE GATE: scoped Azure clients, REST JWTs and subscription-only SAS isolation", {
  skip: process.env.COPILOT_FLOCK_LIVE_AZURE_APPROVED !== "1" ? "UNRUN: explicit approval and a disposable Azure namespace are required" : false,
  timeout: 240000,
}, async (t) => {
  const files = ["flock.mjs", "bridge.mjs", "flock-azure.mjs", "flock-protocol.mjs", "flock-broker-free.mjs",
    "flock-lifecycle.mjs", "test/flock-azure.live.test.mjs", "test/azure-negative-probes.mjs"];
  t.diagnostic(JSON.stringify({ kind: "live-gate-source-hashes", sha256: Object.fromEntries(files.map((file) =>
    [file, crypto.createHash("sha256").update(fs.readFileSync(new URL(`../${file}`, import.meta.url))).digest("hex")])) }));
  const config = JSON.parse(fs.readFileSync(process.env.COPILOT_FLOCK_LIVE_AZURE_CONFIG, "utf8"));
  assert.equal(config.disposable, true, "Only an explicitly disposable deployment is eligible");
  const signalr = parseAzureConnection(config.connectionString, "signalr");
  const manage = parseAzureConnection(config.manageConnectionString, "servicebus");
  const send = parseAzureConnection(config.sendConnectionString, "servicebus");
  const listen = parseAzureConnection(config.listenConnectionString, "servicebus");
  const endpoints = azureEndpoints(signalr.endpoint, manage.endpoint);
  assert.equal(endpoints.signalrEndpoint, process.env.COPILOT_FLOCK_LIVE_SIGNALR_ENDPOINT, "Explicit SignalR endpoint pin required");
  assert.equal(endpoints.serviceBusEndpoint, process.env.COPILOT_FLOCK_LIVE_SERVICEBUS_ENDPOINT, "Explicit Service Bus endpoint pin required");
  assert.equal(send.endpoint, manage.endpoint);
  assert.equal(listen.endpoint, manage.endpoint);
  assert.equal(manage.rule, "RootManageSharedAccessKey");
  assert.equal(send.rule, "FlockSendRule");
  assert.equal(listen.rule, "FlockListenRule");
  const azure = new AzureTransport(endpoints, { secrets: { signalrKey: signalr.key,
    manageKey: manage.key, manageRule: manage.rule, sendKey: send.key, listenKey: listen.key } });
  const owner = createDeviceIdentity();
  const peer = createDeviceIdentity();
  const state = createOwnerState({ identity: owner, flockId: "fixture/live", machineId: "FIXTURE-OWNER", scope: "personal" });
  const code = createJoinCode(peer, { machineId: "FIXTURE-PEER", scope: "personal", flockId: state.flockId });
  const peerIds = [state.localPeerId, code.body.peerId];
  const clients = [];
  const request = (url, token, method = "POST", body) => fetch(url, { method, redirect: "error",
    signal: AbortSignal.timeout(10000), headers: {
      Authorization: new URL(url).origin === signalr.endpoint ? `Bearer ${token}` : token,
      "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  try {
    const ownerTransport = await azure.issue(state.cert, state.ownerPublicKey);
    const ticket = await approveJoin({ code, ownerIdentity: owner, ownerPublicKey: state.ownerPublicKey,
      rotationOwnerPeerId: state.rotationOwnerPeerId, flockId: state.flockId, role: "guest",
      epoch: state.epoch, keyId: state.keyId, groupKey: Buffer.from(state.groupKey, "base64url"),
      membershipExpiresAt: Date.now() + 3600000, verifyIdentityPolicy: async () => {},
      authorizeOwner: async () => {}, provisionTransport: ({ cert }) => azure.issue(cert, state.ownerPublicKey) });
    const welcome = acceptWelcome(ticket, { identity: peer, code, pinnedOwnerFingerprint: ownerFingerprint(state.ownerPublicKey) });
    const ownSub = `${manage.endpoint}/${TOPIC}/subscriptions/${peerSubscription(code.body.peerId)}`;
    const results = await runAzureNegativeProbes({ request, signalrEndpoint: signalr.endpoint,
      serviceBusEndpoint: manage.endpoint, ownerPeerId: state.localPeerId, peerId: code.body.peerId,
      transport: welcome.transport,
      expiredRestToken: jwt(`${signalr.endpoint}/api/v1/hubs/${HUB}`, signalr.key,
        Date.now() - 300000, { now: Date.now() - 600000 }),
      expiredListenSas: sas(ownSub, "FlockListenRule", listen.key, Date.now() - 300000, Date.now() - 600000) });
    for (const result of results) t.diagnostic(JSON.stringify({ kind: "live-gate-negative-probe", ...result }));
    const probe = crypto.randomUUID();
    const received = new Set();
    let clientIsolation;
    for (const [peerId, transport] of [[state.localPeerId, ownerTransport], [code.body.peerId, welcome.transport]]) {
      const cfg = { protocol: "broker-free-v34", endpoint: signalr.endpoint,
        host: new URL(signalr.endpoint).hostname, hub: HUB, clientToken: transport.signalrClientToken,
        credentialExpiresAt: transport.expiresAt };
      clients.push(await connectSignalRClient(cfg, { userId: peerId, onInvocation: (target, args) => {
        if (target === "flock34" && args[0]?.probe === probe) received.add(peerId);
      } }));
      t.diagnostic(JSON.stringify({ kind: "live-gate-positive-probe",
        operation: peerId === state.localPeerId ? "owner-client-connect" : "peer-client-connect", outcome: "passed" }));
      if (peerId === code.body.peerId) {
        let controlReceived = false;
        const controlCfg = createOtherHubClientControl(cfg, { key: signalr.key, peerId });
        clients.push(await connectSignalRClient(controlCfg, { userId: peerId, onInvocation: (target, args) => {
          if (target === "flock34Control" && args[0]?.probe === probe) controlReceived = true;
        } }));
        t.diagnostic(JSON.stringify({ kind: "live-gate-positive-probe",
          operation: "other-hub-valid-client-connect", outcome: "passed" }));
        const controlUrl = `${signalr.endpoint}/api/v1/hubs/${OTHER_HUB}`;
        const controlToken = jwt(controlUrl, signalr.key, transport.expiresAt);
        const controlResponse = await request(controlUrl, controlToken, "POST", {
          target: "flock34Control", arguments: [{ probe }],
        });
        await controlResponse.body?.cancel();
        assert.equal(controlResponse.status, 202, "The distinct valid hub must accept its correctly scoped REST token");
        const controlDeadline = Date.now() + 10000;
        while (!controlReceived && Date.now() < controlDeadline) await new Promise((resolve) => setTimeout(resolve, 50));
        assert.ok(controlReceived, "The distinct valid hub must deliver to its correctly scoped client");
        t.diagnostic(JSON.stringify({ kind: "live-gate-positive-probe",
          operation: "other-hub-valid-rest-send-and-client-receive", outcome: "passed" }));
        try {
          const invalid = await connectSignalRClient({ ...cfg, hub: OTHER_HUB }, { userId: peerId, onInvocation() {} });
          invalid.close();
          clientIsolation = classifySignalRClientDenial({ statusCode: 101 });
        } catch (error) { clientIsolation = classifySignalRClientDenial(error); }
        t.diagnostic(JSON.stringify({ kind: "live-gate-websocket-negative-probe", ...clientIsolation }));
      }
    }
    await azure.publish(welcome.transport, { type: "fixture-probe", probe });
    const deadline = Date.now() + 10000;
    while (received.size !== 2 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(received.size, 2, "Scoped REST send and both fixed-peer client JWTs must work");
    t.diagnostic(JSON.stringify({ kind: "live-gate-positive-probe", operation: "rest-send-and-both-client-receive", outcome: "passed" }));
    let queued = false;
    await azure.drain(welcome.transport, async (message) => { if (message.probe === probe) queued = true; return true; });
    assert.ok(queued, "Own-subscription Listen SAS must receive the Send-only topic message");
    t.diagnostic(JSON.stringify({ kind: "live-gate-positive-probe", operation: "topic-send-and-own-subscription-listen", outcome: "passed" }));
    assert.deepEqual(results.filter((result) => result.outcome !== "denied"), [],
      "All original isolation probes require HTTP 401/403; acceptance, missing entities and request failures fail the gate");
    assert.equal(clientIsolation?.outcome, "denied",
      "Client JWT must be denied on another hub with typed HTTP 401/403; HTTP400/close/network/timeouts do not pass this gate");
  } finally {
    clients.forEach((client) => client.close());
    // Exactly the two freshly generated fixture peers, never a namespace/topic or preexisting subscription.
    const cleanup = await Promise.allSettled(peerIds.map((peerId) => azure.subscription(peerId, "DELETE")));
    const failures = cleanup.filter((result) => result.status === "rejected").map((result) => result.reason);
    if (failures.length) throw new AggregateError(failures, "Disposable fixture subscription cleanup incomplete");
  }
});
