import { HUB, TOPIC } from "../flock-azure.mjs";
import { peerSubscription } from "../flock-protocol.mjs";

export function classifySignalRClientDenial(error) {
  const status = Number.isInteger(error?.statusCode) && error.statusCode >= 100 && error.statusCode <= 599 ? error.statusCode : null;
  return { operation: "client-jwt-cannot-connect-other-hub", method: "GET", status,
    outcome: [401, 403].includes(status) ? "denied" : status === null ? "request-failed" : "failed" };
}

export async function runAzureNegativeProbes({ request, signalrEndpoint, serviceBusEndpoint,
  ownerPeerId, peerId, transport, expiredRestToken, expiredListenSas }) {
  const hub = `${signalrEndpoint}/api/v1/hubs/${HUB}`;
  const topic = `${serviceBusEndpoint}/${TOPIC}`;
  const own = `${topic}/subscriptions/${peerSubscription(peerId)}`;
  const other = `${topic}/subscriptions/${peerSubscription(ownerPeerId)}`;
  const body = { target: "fixture-negative", arguments: [] };
  const probes = [
    ["client-jwt-cannot-rest-send", hub, transport.signalrClientToken, "POST", body],
    ["rest-jwt-cannot-send-other-hub", `${signalrEndpoint}/api/v1/hubs/fixture-forbidden`, transport.signalrRestToken, "POST", body],
    ["rest-jwt-cannot-send-other-user", `${hub}/users/${ownerPeerId}`, transport.signalrRestToken, "POST", body],
    ["servicebus-sas-cannot-rest-send", hub, transport.serviceBusSendSas, "POST", body],
    ["expired-rest-jwt", hub, expiredRestToken, "POST", body],
    ["listen-cannot-read-other-subscription", `${other}/messages/head?timeout=0`, transport.serviceBusListenSas, "POST"],
    ["send-cannot-read-own-subscription", `${own}/messages/head?timeout=0`, transport.serviceBusSendSas, "POST"],
    ["listen-cannot-send-topic", `${topic}/messages`, transport.serviceBusListenSas, "POST", { probe: "fixture-negative" }],
    ["listen-cannot-delete-subscription", `${own}?api-version=2017-04`, transport.serviceBusListenSas, "DELETE"],
    ["send-cannot-delete-subscription", `${own}?api-version=2017-04`, transport.serviceBusSendSas, "DELETE"],
    ["expired-listen-sas", `${own}/messages/head?timeout=0`, expiredListenSas, "POST"],
  ];
  const results = [];
  for (const [operation, url, token, method, body] of probes) {
    let status = null;
    try {
      const response = await request(url, token, method, body);
      status = response.status;
      await response.body?.cancel();
      results.push({ operation, method, status, outcome: [401, 403].includes(status) ? "denied" : "failed" });
    } catch {
      // Fetch errors can include credentials or URLs. A transport error never proves denial.
      results.push({ operation, method, status, outcome: "request-failed" });
    }
  }
  return results;
}
