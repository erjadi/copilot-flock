import { HUB, TOPIC, jwt } from "../flock-azure.mjs";
import { peerSubscription } from "../flock-protocol.mjs";

export const OTHER_HUB = "fixture_forbidden";

export async function withAzureGateCleanup(run, cleanup) {
  const errors = [];
  let result;
  try { result = await run(); } catch (error) { errors.push(error); }
  try { await cleanup(); } catch (error) { errors.push(error); }
  if (errors.length === 1) throw errors[0];
  if (errors.length) throw new AggregateError(errors, "Azure gate failed and fixture cleanup was incomplete");
  return result;
}

export function createOtherHubClientControl(cfg, { key, peerId, now = Date.now() }) {
  return { ...cfg, hub: OTHER_HUB,
    clientToken: jwt(`${cfg.endpoint}/client/?hub=${OTHER_HUB}`, key, cfg.credentialExpiresAt, { peerId, now }) };
}

export function classifySignalRClientDenial(error) {
  const status = Number.isInteger(error?.statusCode) && error.statusCode >= 100 && error.statusCode <= 599 ? error.statusCode : null;
  return { operation: "client-jwt-cannot-connect-other-hub", method: "GET", status,
    outcome: [401, 403].includes(status) ? "denied" : status === null ? "request-failed" : "failed" };
}

export async function classifyAzureProbeResponse(response) {
  let text = "";
  const reader = response.body?.getReader();
  if (reader) {
    let remaining = 4096;
    try {
      while (remaining > 0) {
        const { done, value } = await reader.read();
        if (done) break;
        text += Buffer.from(value.subarray(0, remaining)).toString("utf8");
        remaining -= value.length;
      }
    } finally { await reader.cancel(); }
  }
  const denied = [401, 403].includes(response.status);
  if (denied && /LocalAuth(?:entication)?(?:Is)?Disabled|local authentication.{0,80}disabled|SAS authentication.{0,80}disabled/i.test(text)) {
    return { outcome: "auth-mode-blocked", code: "LOCAL_AUTH_DISABLED" };
  }
  return { outcome: denied ? "denied" : "failed" };
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
    ["rest-jwt-cannot-send-other-hub", `${signalrEndpoint}/api/v1/hubs/${OTHER_HUB}`, transport.signalrRestToken, "POST", body],
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
      results.push({ operation, method, status, ...await classifyAzureProbeResponse(response) });
    } catch {
      // Fetch errors can include credentials or URLs. A transport error never proves denial.
      results.push({ operation, method, status, outcome: "request-failed" });
    }
  }
  return results;
}
