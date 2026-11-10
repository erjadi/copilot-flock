import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { OTHER_HUB, createOtherHubClientControl, runAzureNegativeProbes, classifySignalRClientDenial } from "./azure-negative-probes.mjs";
import { HUB } from "../flock-azure.mjs";
import { peerSubscription } from "../flock-protocol.mjs";

const fixture = {
  signalrEndpoint: "https://fixture.service.signalr.net",
  serviceBusEndpoint: "https://fixture.servicebus.windows.net",
  ownerPeerId: "a".repeat(64), peerId: "b".repeat(64),
  transport: { signalrClientToken: "fixture-client", signalrRestToken: "fixture-rest",
    serviceBusSendSas: "fixture-send", serviceBusListenSas: "fixture-listen" },
  expiredRestToken: "fixture-expired-rest", expiredListenSas: "fixture-expired-listen",
};

test("Azure wrong-hub fixture is syntactically valid and its positive control has matching scoped credentials", () => {
  assert.match(OTHER_HUB, /^[A-Za-z][A-Za-z0-9_]*$/);
  assert.notEqual(OTHER_HUB.toLowerCase(), HUB.toLowerCase());
  const now = 1800000000000;
  const cfg = { protocol: "broker-free-v34", endpoint: fixture.signalrEndpoint, hub: HUB,
    clientToken: fixture.transport.signalrClientToken, credentialExpiresAt: now + 60000 };
  const control = createOtherHubClientControl(cfg, { key: "fixture-key", peerId: fixture.peerId, now });
  assert.equal(cfg.hub, HUB);
  assert.equal(cfg.clientToken, fixture.transport.signalrClientToken);
  assert.equal(control.hub, OTHER_HUB);
  assert.equal(control.credentialExpiresAt, cfg.credentialExpiresAt);
  const [header, body, signature] = control.clientToken.split(".");
  const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  assert.equal(claims.aud, `${fixture.signalrEndpoint}/client/?hub=${OTHER_HUB}`);
  assert.equal(claims.nameid, fixture.peerId);
  assert.equal(claims.exp, cfg.credentialExpiresAt / 1000);
  assert.equal(signature, crypto.createHmac("sha256", "fixture-key").update(`${header}.${body}`).digest("base64url"));
});

test("Azure gate probes all original isolation operations with exact tokens, targets and methods", async () => {
  const calls = [];
  const results = await runAzureNegativeProbes({ ...fixture, request: async (...args) => {
    calls.push(args);
    return new Response(null, { status: 403 });
  } });
  assert.equal(results.length, 11);
  assert.equal(new Set(results.map((result) => result.operation)).size, 11);
  assert.ok(results.every((result) => result.outcome === "denied" && result.status === 403));
  assert.deepEqual(calls.map(([url, token, method]) => [url, token, method]), [
    [`${fixture.signalrEndpoint}/api/v1/hubs/copilotbridge`, "fixture-client", "POST"],
    [`${fixture.signalrEndpoint}/api/v1/hubs/${OTHER_HUB}`, "fixture-rest", "POST"],
    [`${fixture.signalrEndpoint}/api/v1/hubs/copilotbridge/users/${fixture.ownerPeerId}`, "fixture-rest", "POST"],
    [`${fixture.signalrEndpoint}/api/v1/hubs/copilotbridge`, "fixture-send", "POST"],
    [`${fixture.signalrEndpoint}/api/v1/hubs/copilotbridge`, "fixture-expired-rest", "POST"],
    [`${fixture.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peerSubscription(fixture.ownerPeerId)}/messages/head?timeout=0`, "fixture-listen", "POST"],
    [`${fixture.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peerSubscription(fixture.peerId)}/messages/head?timeout=0`, "fixture-send", "POST"],
    [`${fixture.serviceBusEndpoint}/copilot-bridge-offline/messages`, "fixture-listen", "POST"],
    [`${fixture.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peerSubscription(fixture.peerId)}?api-version=2017-04`, "fixture-listen", "DELETE"],
    [`${fixture.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peerSubscription(fixture.peerId)}?api-version=2017-04`, "fixture-send", "DELETE"],
    [`${fixture.serviceBusEndpoint}/copilot-bridge-offline/subscriptions/${peerSubscription(fixture.peerId)}/messages/head?timeout=0`, "fixture-expired-listen", "POST"],
  ]);
  assert.deepEqual(calls[1][3], { target: "fixture-negative", arguments: [] });
  assert.deepEqual(calls[2][3], calls[1][3]);
});

test("Azure gate retains wrong-hub and other-user acceptance failures while completing remaining probes", async () => {
  let count = 0;
  const results = await runAzureNegativeProbes({ ...fixture, request: async () => {
    const index = count++;
    return new Response(null, { status: index === 1 || index === 2 ? 202 : 401 });
  } });
  assert.equal(count, 11);
  assert.deepEqual(results.filter((result) => result.outcome !== "denied").map((result) => result.operation),
    ["rest-jwt-cannot-send-other-hub", "rest-jwt-cannot-send-other-user"]);
});

test("Azure gate never treats network errors, server failures or missing entities as denials and redacts errors", async () => {
  let count = 0;
  const results = await runAzureNegativeProbes({ ...fixture, request: async () => {
    const index = count++;
    if (index === 0) throw new Error("sensitive-token-in-request-url");
    return new Response(null, { status: index === 1 ? 500 : index === 2 ? 404 : 403 });
  } });
  assert.equal(count, 11);
  assert.deepEqual(results.slice(0, 3).map(({ status, outcome }) => ({ status, outcome })), [
    { status: null, outcome: "request-failed" }, { status: 500, outcome: "failed" }, { status: 404, outcome: "failed" },
  ]);
  assert.doesNotMatch(JSON.stringify(results), /sensitive-token|https:|fixture-rest|fixture-send|fixture-listen/);
  for (const status of [401, 403]) {
    assert.equal(classifySignalRClientDenial({ statusCode: status }).outcome, "denied");
  }
  for (const status of [400, 404, 500, 101]) {
    assert.equal(classifySignalRClientDenial({ statusCode: status }).outcome, "failed");
  }
  for (const error of [new Error("HTTP 401 with sensitive-token"), { statusCode: "401" }, {}, null]) {
    const result = classifySignalRClientDenial(error);
    assert.equal(result.outcome, "request-failed");
    assert.equal(result.status, null);
    assert.doesNotMatch(JSON.stringify(result), /sensitive-token|HTTP 401/);
  }
});
