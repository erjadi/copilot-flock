import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import { AzureTransport, azureEndpoints, parseAzureConnection, HUB, TOPIC, jwt, sas } from "../flock-azure.mjs";
import { createDeviceIdentity, createOwnerState, createJoinCode, approveJoin, acceptWelcome, ownerFingerprint } from "../flock-protocol.mjs";
import { connectSignalRClient } from "../flock.mjs";

// Deliberately excluded from npm test. Never point this gate at an enrolled/production namespace.
test("LIVE RELEASE GATE: scoped Azure clients, REST JWTs and subscription-only SAS isolation", {
  skip: process.env.COPILOT_FLOCK_LIVE_AZURE_APPROVED !== "1" ? "UNRUN: explicit approval and a disposable Azure namespace are required" : false,
  timeout: 120000,
}, async () => {
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
    signal: AbortSignal.timeout(10000), headers: { Authorization: token, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const denied = async (url, token, method = "POST", body) => {
    const response = await request(url, token, method, body);
    assert.ok([401, 403].includes(response.status), `Isolation gate required HTTP 401/403; observed ${response.status}`);
    await response.body?.cancel();
  };
  try {
    const ownerTransport = await azure.issue(state.cert, state.ownerPublicKey);
    const ticket = await approveJoin({ code, ownerIdentity: owner, ownerPublicKey: state.ownerPublicKey,
      rotationOwnerPeerId: state.rotationOwnerPeerId, flockId: state.flockId, role: "guest",
      epoch: state.epoch, keyId: state.keyId, groupKey: Buffer.from(state.groupKey, "base64url"),
      membershipExpiresAt: Date.now() + 3600000, verifyIdentityPolicy: async () => {},
      authorizeOwner: async () => {}, provisionTransport: ({ cert }) => azure.issue(cert, state.ownerPublicKey) });
    const welcome = acceptWelcome(ticket, { identity: peer, code, pinnedOwnerFingerprint: ownerFingerprint(state.ownerPublicKey) });
    const probe = crypto.randomUUID();
    const received = new Set();
    for (const [peerId, transport] of [[state.localPeerId, ownerTransport], [code.body.peerId, welcome.transport]]) {
      const cfg = { protocol: "broker-free-v34", endpoint: signalr.endpoint,
        host: new URL(signalr.endpoint).hostname, hub: HUB, clientToken: transport.signalrClientToken,
        credentialExpiresAt: transport.expiresAt };
      clients.push(await connectSignalRClient(cfg, { userId: peerId, onInvocation: (target, args) => {
        if (target === "flock34" && args[0]?.probe === probe) received.add(peerId);
      } }));
      if (peerId === code.body.peerId) {
        let rejected = false;
        try {
          const invalid = await connectSignalRClient({ ...cfg, hub: "fixture-forbidden" }, { userId: peerId, onInvocation() {} });
          invalid.close();
        } catch (error) { rejected = /\b(?:401|403)\b/.test(error.message); }
        assert.ok(rejected, "Client JWT must be denied on another hub; network/timeouts do not pass this gate");
      }
    }
    await azure.publish(welcome.transport, { type: "fixture-probe", probe });
    const deadline = Date.now() + 10000;
    while (received.size !== 2 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(received.size, 2, "Scoped REST send and both fixed-peer client JWTs must work");
    let queued = false;
    await azure.drain(welcome.transport, async (message) => { if (message.probe === probe) queued = true; return true; });
    assert.ok(queued, "Own-subscription Listen SAS must receive the Send-only topic message");
    const hubUrl = `${signalr.endpoint}/api/v1/hubs/${HUB}`;
    const probeBody = { target: "fixture-negative", arguments: [] };
    await denied(hubUrl, welcome.transport.signalrClientToken, "POST", probeBody);
    await denied(`${signalr.endpoint}/api/v1/hubs/fixture-forbidden`, welcome.transport.signalrRestToken, "POST", probeBody);
    await denied(`${hubUrl}/users/${state.localPeerId}`, welcome.transport.signalrRestToken, "POST", probeBody);
    await denied(hubUrl, jwt(hubUrl, signalr.key, Date.now() - 300000, { now: Date.now() - 600000 }), "POST", probeBody);
    const ownSub = `${manage.endpoint}/${TOPIC}/Subscriptions/sub-${code.body.peerId}`;
    const otherSub = `${manage.endpoint}/${TOPIC}/Subscriptions/sub-${state.localPeerId}`;
    await denied(`${otherSub}/messages/head?timeout=0`, welcome.transport.serviceBusListenSas);
    await denied(`${ownSub}/messages/head?timeout=0`, welcome.transport.serviceBusSendSas);
    await denied(`${manage.endpoint}/${TOPIC}/messages`, welcome.transport.serviceBusListenSas, "POST", { probe });
    await denied(`${ownSub}?api-version=2017-04`, welcome.transport.serviceBusListenSas, "DELETE");
    await denied(`${ownSub}?api-version=2017-04`, welcome.transport.serviceBusSendSas, "DELETE");
    await denied(`${ownSub}/messages/head?timeout=0`, sas(ownSub, "FlockListenRule", listen.key,
      Date.now() - 300000, Date.now() - 600000));
  } finally {
    clients.forEach((client) => client.close());
    // Exactly the two freshly generated fixture peers, never a namespace/topic or preexisting subscription.
    const cleanup = await Promise.allSettled(peerIds.map((peerId) => azure.subscription(peerId, "DELETE")));
    const failures = cleanup.filter((result) => result.status === "rejected").map((result) => result.reason);
    if (failures.length) throw new AggregateError(failures, "Disposable fixture subscription cleanup incomplete");
  }
});
