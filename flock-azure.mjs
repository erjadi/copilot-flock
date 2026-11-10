import crypto from "node:crypto";
import { validateCert } from "./flock-protocol.mjs";

export const HUB = "copilotbridge";
export const TOPIC = "copilot-bridge-offline";
const DAY = 86400000;
export function azureEndpoints(signalrEndpoint, serviceBusEndpoint) {
  if (!/^https:\/\/[a-z0-9-]+\.service\.signalr\.net$/.test(signalrEndpoint) ||
      !/^https:\/\/[a-z0-9-]+\.servicebus\.windows\.net$/.test(serviceBusEndpoint)) throw new Error("Invalid Azure transport endpoints");
  return { signalrEndpoint, serviceBusEndpoint, hub: HUB, topic: TOPIC };
}
export function parseAzureConnection(value, service) {
  if (typeof value !== "string" || value.length > 16384) throw new Error("Missing Azure owner credentials");
  const parts = Object.fromEntries(value.split(";").filter(Boolean).map((part) => {
    const index = part.indexOf("=");
    if (index <= 0) throw new Error("Malformed Azure connection string");
    return [part.slice(0, index), part.slice(index + 1)];
  }));
  const endpoint = parts.Endpoint?.replace(/^sb:/, "https:").replace(/\/$/, "");
  if (service === "signalr") {
    azureEndpoints(endpoint, "https://placeholder.servicebus.windows.net");
    if (!parts.AccessKey) throw new Error("Missing SignalR signing key");
    return { endpoint, key: parts.AccessKey };
  }
  azureEndpoints("https://placeholder.service.signalr.net", endpoint);
  if (!parts.SharedAccessKey || !parts.SharedAccessKeyName) throw new Error("Missing Service Bus signing policy");
  return { endpoint, key: parts.SharedAccessKey, rule: parts.SharedAccessKeyName };
}
export function jwt(audience, key, expiresAt, { peerId, now = Date.now() } = {}) {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt - now > DAY) throw new Error("Invalid transport lifetime");
  const head = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = { aud: audience, iat: Math.floor(now / 1000), exp: Math.floor(expiresAt / 1000) };
  if (peerId) Object.assign(body, { nameid: peerId, "asrs.s.uid": peerId, "asrs.s.coae": "true",
    "asrs.s.aeo": String(Math.floor(expiresAt / 1000)) });
  const encoded = Buffer.from(JSON.stringify(body)).toString("base64url");
  const input = `${head}.${encoded}`;
  return `${input}.${crypto.createHmac("sha256", key).update(input).digest("base64url")}`;
}
export function sas(resource, rule, key, expiresAt, now = Date.now()) {
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt - now > DAY) throw new Error("Invalid SAS lifetime");
  const sr = encodeURIComponent(resource);
  const expiry = Math.floor(expiresAt / 1000);
  const signature = crypto.createHmac("sha256", key).update(`${sr}\n${expiry}`).digest("base64");
  return `SharedAccessSignature sr=${sr}&sig=${encodeURIComponent(signature)}&se=${expiry}&skn=${encodeURIComponent(rule)}`;
}
export function validateTransport(transport, endpoints, peerId, certificateExpiresAt, now = Date.now()) {
  azureEndpoints(endpoints.signalrEndpoint, endpoints.serviceBusEndpoint);
  if (!Number.isSafeInteger(transport.expiresAt) || transport.subscription !== `sub-${peerId}` || transport.expiresAt > certificateExpiresAt ||
      transport.expiresAt <= now || transport.expiresAt - now > DAY) throw new Error("Transport lifetime or subscription mismatch");
  for (const [field, audience] of [
    ["signalrClientToken", `${endpoints.signalrEndpoint}/client/?hub=${HUB}`],
    ["signalrRestToken", `${endpoints.signalrEndpoint}/api/v1/hubs/${HUB}`],
  ]) {
    const token = transport[field];
    if (typeof token !== "string" || token.length > 16384 || token.split(".").length !== 3) throw new Error("Invalid scoped SignalR JWT");
    const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    const body = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
    if (header.alg !== "HS256" || !Number.isSafeInteger(body.exp) ||
        body.aud !== audience || body.exp * 1000 > transport.expiresAt || body.exp * 1000 <= now ||
        (field === "signalrClientToken" && body.nameid !== peerId)) throw new Error("SignalR audience, principal or expiry mismatch");
  }
  for (const [field, resource, rule] of [
    ["serviceBusSendSas", `${endpoints.serviceBusEndpoint}/${TOPIC}`, "FlockSendRule"],
    ["serviceBusListenSas", `${endpoints.serviceBusEndpoint}/${TOPIC}/Subscriptions/sub-${peerId}`, "FlockListenRule"],
  ]) {
    if (!transport[field]?.startsWith("SharedAccessSignature ")) throw new Error("Expected scoped SAS, not a connection string");
    const token = new URLSearchParams(transport[field].slice(22));
    if (!/^\d+$/.test(token.get("se") || "") || token.get("sr") !== resource || token.get("skn") !== rule || !token.get("sig") ||
        Number(token.get("se")) * 1000 > transport.expiresAt || Number(token.get("se")) * 1000 <= now) throw new Error("Service Bus audience/policy/expiry mismatch");
  }
}

export class AzureTransport {
  constructor(endpoints, { secrets = null, fetchImpl = fetch, clock = Date.now } = {}) {
    this.endpoints = azureEndpoints(endpoints.signalrEndpoint, endpoints.serviceBusEndpoint);
    this.secrets = secrets;
    this.fetch = fetchImpl;
    this.clock = clock;
  }
  async request(url, options, allowed = []) {
    const response = await this.fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(10000) });
    if (!response.ok && !allowed.includes(response.status)) throw new Error(`Azure ${options.method} failed (HTTP ${response.status}); credential-bearing response withheld`);
    return response;
  }
  async subscription(peerId, method) {
    if (!/^[a-f0-9]{64}$/.test(peerId) || !["PUT", "DELETE"].includes(method)) throw new Error("Invalid targeted subscription operation");
    if (!this.secrets?.manageKey || this.secrets.manageRule !== "RootManageSharedAccessKey") throw new Error("Explicit owner Manage credentials required for subscription changes");
    const resource = `${this.endpoints.serviceBusEndpoint}/${TOPIC}/Subscriptions/sub-${peerId}`;
    const token = sas(this.endpoints.serviceBusEndpoint, this.secrets.manageRule, this.secrets.manageKey, this.clock() + 300000, this.clock());
    const body = method === "PUT" ? '<entry xmlns="http://www.w3.org/2005/Atom"><content type="application/xml"><SubscriptionDescription xmlns="http://schemas.microsoft.com/netservices/2010/10/servicebus/connect"><DefaultMessageTimeToLive>P1D</DefaultMessageTimeToLive><LockDuration>PT1M</LockDuration><MaxDeliveryCount>10</MaxDeliveryCount></SubscriptionDescription></content></entry>' : undefined;
    await this.request(`${resource}?api-version=2017-04`, { method, headers: {
      Authorization: token, "Content-Type": "application/atom+xml;type=entry;charset=utf-8",
    }, ...(body ? { body } : {}) }, method === "DELETE" ? [404] : []);
    return { confirmed: true, subscription: `sub-${peerId}` };
  }
  async issue(cert, ownerPublicKey) {
    const member = validateCert(cert, ownerPublicKey, this.clock());
    await this.subscription(member.peerId, "PUT");
    return this.credentials(cert, ownerPublicKey);
  }
  credentials(cert, ownerPublicKey) {
    const member = validateCert(cert, ownerPublicKey, this.clock());
    if (!this.secrets?.signalrKey || !this.secrets.sendKey || !this.secrets.listenKey) throw new Error("Owner signing credentials unavailable");
    const expiresAt = Math.min(member.expiresAt, this.clock() + DAY);
    const result = { subscription: `sub-${member.peerId}`, expiresAt,
      signalrClientToken: jwt(`${this.endpoints.signalrEndpoint}/client/?hub=${HUB}`, this.secrets.signalrKey, expiresAt, { peerId: member.peerId, now: this.clock() }),
      signalrRestToken: jwt(`${this.endpoints.signalrEndpoint}/api/v1/hubs/${HUB}`, this.secrets.signalrKey, expiresAt, { now: this.clock() }),
      serviceBusSendSas: sas(`${this.endpoints.serviceBusEndpoint}/${TOPIC}`, "FlockSendRule", this.secrets.sendKey, expiresAt, this.clock()),
      serviceBusListenSas: sas(`${this.endpoints.serviceBusEndpoint}/${TOPIC}/Subscriptions/sub-${member.peerId}`, "FlockListenRule", this.secrets.listenKey, expiresAt, this.clock()),
    };
    validateTransport(result, this.endpoints, member.peerId, member.expiresAt, this.clock());
    return result;
  }
  async publish(transport, message) {
    const body = JSON.stringify(message);
    if (Buffer.byteLength(body) > 240 * 1024) throw new Error("Wire message exceeds Standard Service Bus size budget");
    const expiresAt = Math.min(message.envelope?.header.expiresAt || message.request?.body.expiresAt ||
      this.clock() + 86400000, transport.expiresAt);
    if (expiresAt <= this.clock()) throw new Error("Transport expired");
    // Queue first. A failed realtime send is explicit; the durable copy is not re-signed on retry.
    await this.request(`${this.endpoints.serviceBusEndpoint}/${TOPIC}/messages`, { method: "POST",
      headers: { Authorization: transport.serviceBusSendSas, "Content-Type": "application/json",
        BrokerProperties: JSON.stringify({ TimeToLive: Math.max(1, Math.floor((expiresAt - this.clock()) / 1000)) }) }, body });
    await this.request(`${this.endpoints.signalrEndpoint}/api/v1/hubs/${HUB}`, { method: "POST",
      headers: { Authorization: transport.signalrRestToken, "Content-Type": "application/json" },
      body: JSON.stringify({ target: "flock34", arguments: [message] }) });
  }
  async drain(transport, consume, limit = 20) {
    const resource = `${this.endpoints.serviceBusEndpoint}/${TOPIC}/Subscriptions/${transport.subscription}`;
    for (let index = 0; index < limit; index++) {
      const response = await this.request(`${resource}/messages/head?timeout=0`, {
        method: "POST", headers: { Authorization: transport.serviceBusListenSas },
      }, [204]);
      if (response.status === 204) return;
      const location = response.headers.get("location");
      const lockUrl = new URL(location || "", resource);
      if (lockUrl.origin !== new URL(resource).origin || !lockUrl.pathname.startsWith(new URL(resource).pathname + "/messages/") ||
          lockUrl.username || lockUrl.password || lockUrl.hash) throw new Error("Queue lock URL escaped peer subscription");
      let accepted = false;
      try {
        const text = await response.text();
        if (Buffer.byteLength(text) > 240 * 1024) throw new Error("Queue wire message exceeds size limit");
        accepted = await consume(JSON.parse(text));
      }
      finally {
        await this.request(lockUrl.href, { method: accepted ? "DELETE" : "PUT",
          headers: { Authorization: transport.serviceBusListenSas } });
      }
      if (!accepted) return;
    }
  }
}
