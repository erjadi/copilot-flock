import test from "node:test";
import assert from "node:assert/strict";
import { runAzureNegativeProbes } from "./azure-negative-probes.mjs";
import { peerSubscription } from "../flock-protocol.mjs";

const fixture = {
  signalrEndpoint: "https://fixture.service.signalr.net",
  serviceBusEndpoint: "https://fixture.servicebus.windows.net",
  ownerPeerId: "a".repeat(64), peerId: "b".repeat(64),
  transport: { signalrClientToken: "fixture-client", signalrRestToken: "fixture-rest",
    serviceBusSendSas: "fixture-send", serviceBusListenSas: "fixture-listen" },
  expiredRestToken: "fixture-expired-rest", expiredListenSas: "fixture-expired-listen",
};

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
    [`${fixture.signalrEndpoint}/api/v1/hubs/fixture-forbidden`, "fixture-rest", "POST"],
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
});
