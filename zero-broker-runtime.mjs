import crypto from "node:crypto";
import {
  canonicalJson, decryptFlockEnvelope, encryptFlockEnvelope,
  openSealedBundle, sealBundle, verifyRosterChain,
} from "./zero-broker-roster.mjs";
import { sendEncryptedPacket } from "./zero-broker-transport.mjs";

const VERIFIED_CONTEXTS = new WeakSet();
const SNAPSHOT_ACTIONS = new Set(["list_sessions", "list_shared_threads", "get_transcript"]);
const TERMINAL_STATUSES = new Set(["DELIVERED", "DENIED", "OFFLINE", "BUSY", "UNKNOWN"]);
const REQUEST_LIMIT = 430 * 1024;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function deny(message) {
  throw Object.assign(new Error(message), { code: "DENIED" });
}

export function isVerifiedZeroBrokerContext(context, request) {
  return VERIFIED_CONTEXTS.has(context) && (!request || context.requestDigest === crypto.createHash("sha256").update(canonicalJson(request)).digest("hex"));
}

export function createZeroBrokerRuntime({
  device, state, dispatch, authorizeRoot, authorizeSnapshot, readSnapshot, getAuthorizationRevision,
  refreshRoster = async () => [],
  sendPacket = sendEncryptedPacket,
  now = Date.now,
  reportError,
  capacity = 32,
}) {
  requireValue(typeof dispatch === "function" && typeof authorizeRoot === "function" && typeof authorizeSnapshot === "function" &&
    typeof getAuthorizationRevision === "function" && typeof reportError === "function",
    "Runtime requires dispatch, local root/snapshot authorization, receiver-owned grant revisions and explicit error reporting");
  requireValue(Number.isSafeInteger(capacity) && capacity > 0 && capacity <= 256, "Invalid runtime capacity");
  const waiters = new Map();
  const responsesInFlight = new Set();
  let incoming = 0;
  let closed = false;
  let refreshing = null;

  function snapshot() {
    const roster = state.get(device.flockUuid);
    requireValue(roster && Date.parse(roster.leaseExpiresAt) > now(), "Signed roster freshness lease expired or missing");
    const member = roster.members.find((entry) => entry.opaquePeerId === device.opaquePeerId);
    requireValue(member && (!member.membershipExpiresAt || Date.parse(member.membershipExpiresAt) > now()), "Local membership expired or revoked");
    const bundle = openSealedBundle({
      bundle: member.sealedMemberBundle, recipientEncPrivPem: device.encPriv,
      flockUuid: roster.flockUuid, rosterEpoch: roster.rosterEpoch,
      recipientOpaquePeerId: device.opaquePeerId, bundleType: "member",
    });
    const flockKey = Buffer.from(bundle.flockKey, "base64");
    requireValue(flockKey.length === 32 && bundle.transport.expiresAtSeconds * 1000 > now(), "Invalid or expired member transport bundle");
    return { roster, member, flockKey, transport: bundle.transport };
  }

  async function refresh() {
    requireValue(!closed, "Runtime is closed");
    if (!refreshing) {
      refreshing = (async () => {
        const trusted = state.get(device.flockUuid);
        requireValue(trusted, "Runtime requires a persisted, pinned roster anchor");
        const transitions = await refreshRoster(trusted);
        verifyRosterChain(trusted, transitions, now(), { state });
      })().finally(() => { refreshing = null; });
    }
    await refreshing;
  }

  function validateRequest(request) {
    requireValue(request && Object.keys(request).length === 4 && /^[A-Za-z0-9_-]{16,128}$/.test(request.requestId) && /^[a-z][a-z0-9_]{0,63}$/.test(request.action) && Number.isSafeInteger(request.expiresAt), "Invalid typed RPC request");
    requireValue(request.params && Object.getPrototypeOf(request.params) === Object.prototype && Buffer.byteLength(canonicalJson(request)) <= REQUEST_LIMIT, "Invalid or oversized RPC parameters");
  }

  async function authorize(request, senderId, envelopeExpiresAt = request.expiresAt) {
    const { roster, flockKey } = snapshot();
    flockKey.fill(0);
    const sender = roster.members.find((member) => member.opaquePeerId === senderId);
    if (!sender || (sender.membershipExpiresAt && Date.parse(sender.membershipExpiresAt) <= now())) deny("Sender membership expired or revoked");
    const grantRevision = getAuthorizationRevision();
    requireValue(typeof grantRevision === "string" && grantRevision.length > 0 && grantRevision.length <= 128, "Invalid receiver-owned grant revision");
    const rootSender = roster.ownerSigners.some((signer) => signer.opaquePeerId === senderId && signer.role === "genesis-root");
    const privateOwnerGroup = roster.members.every((member) => member.role === "owner");
    let mode;
    if (request.action === "ping") {
      mode = "PRESENCE";
    } else if ((rootSender && privateOwnerGroup || request.action === "list_sessions" && sender.role === "owner" && privateOwnerGroup) && await authorizeRoot({ request, sender, roster })) {
      mode = "ROOT";
    } else {
      if (!SNAPSHOT_ACTIONS.has(request.action)) deny("Delegates and shared flocks cannot initiate arbitrary execution or privileged RPC");
      if (typeof readSnapshot !== "function" || !await authorizeSnapshot({ request, sender, roster })) deny("No current local approved-snapshot adapter or grant");
      mode = "SNAPSHOT";
    }
    if (getAuthorizationRevision() !== grantRevision) deny("Local authorization changed during grant evaluation");
    state.assertRoster(roster);
    const context = Object.freeze({
      roster, sender, recipientOpaquePeerId: device.opaquePeerId, mode,
      authorization: Object.freeze({ mode, grantRevision, rosterEpoch: roster.rosterEpoch }),
      requestDigest: crypto.createHash("sha256").update(canonicalJson(request)).digest("hex"),
      dispatchExpiresAt: Math.min(request.expiresAt, envelopeExpiresAt),
    });
    VERIFIED_CONTEXTS.add(context);
    return context;
  }

  function sameAuthorization(first, second) {
    return first && second && canonicalJson(first) === canonicalJson(second);
  }

  function assertSameAuthorization(before, after) {
    if (!sameAuthorization(before.authorization, after.authorization)) deny("Local authorization changed before disclosure");
    state.assertRoster(after.roster);
  }

  function validateOutcome(outcome) {
    requireValue(outcome && TERMINAL_STATUSES.has(outcome.status) && Object.hasOwn(outcome, "result"), "Adapter must return an explicit admission status, not execution success");
    requireValue(Buffer.byteLength(canonicalJson(outcome)) <= REQUEST_LIMIT - 1024, "RPC result exceeds recipient-sealed transport limit");
  }

  function deniedRequestStatus(request, sender, receipt) {
    if (request.action === "ping" || SNAPSHOT_ACTIONS.has(request.action)) return "DENIED";
    if (!receipt) {
      const current = snapshot();
      current.flockKey.fill(0);
      receipt = state.readRequestReceipt({ roster: current.roster, sender, recipient: device.opaquePeerId,
        requestId: request.requestId, payload: request, expiresAt: request.expiresAt, nowMs: now() });
    }
    return ["NOT_ADMITTED", "DENIED"].includes(receipt.status) ? "DENIED" : "UNKNOWN";
  }

  async function emit(toOpaquePeerId, body, action = "ping") {
    const current = snapshot();
    try {
      requireValue(Buffer.byteLength(canonicalJson(body)) <= REQUEST_LIMIT, "RPC body exceeds recipient-sealed transport limit");
      const recipient = current.roster.members.find((member) => member.opaquePeerId === toOpaquePeerId);
      requireValue(recipient, "Unknown encrypted RPC recipient");
      const sealedRpcBody = sealBundle({
        payload: body, recipientEncPubPem: recipient.encPub,
        flockUuid: current.roster.flockUuid, rosterEpoch: current.roster.rosterEpoch,
        recipientOpaquePeerId: toOpaquePeerId, bundleType: "rpc-body",
      });
      const envelope = encryptFlockEnvelope({
        roster: current.roster, state, flockKey: current.flockKey,
        signingPriv: device.signingPriv, fromOpaquePeerId: device.opaquePeerId,
        toOpaquePeerId, action, body: { sealedRpcBody }, nowMs: now(),
      });
      return await sendPacket({ transport: current.transport, envelope });
    } finally {
      current.flockKey.fill(0);
    }
  }

  function authorizeOutgoing(payload) {
      const { roster, flockKey } = snapshot();
      flockKey.fill(0);
      const rootSender = roster.ownerSigners.some((signer) => signer.opaquePeerId === device.opaquePeerId && signer.role === "genesis-root");
      if (payload.action === "ping") {
        if (Object.keys(payload.params).length) deny("Presence requests cannot carry arbitrary parameters");
      } else if (!(rootSender && roster.members.every((member) => member.role === "owner")) && !SNAPSHOT_ACTIONS.has(payload.action)) {
        deny("Delegates and shared flocks cannot send arbitrary execution payloads");
      }
  }

  async function transmit(entry, reconcile = false) {
    if (entry.expiry <= now() && !reconcile) return;
    authorizeOutgoing(entry.payload);
    await emit(entry.recipient, { kind: reconcile ? "reconcile" : "request", request: entry.payload }, reconcile ? "ping" : entry.payload.action);
  }

  function error(status, message, requestId) {
    reportError({ status, message, ...(requestId ? { requestId } : {}) });
  }

  async function receive(envelope) {
    requireValue(!closed, "Runtime is closed");
    if (envelope?.toOpaquePeerId !== device.opaquePeerId) return { status: "NOT_RECIPIENT" };
    if (incoming >= capacity) {
      error("BUSY", "Incoming runtime capacity exhausted");
      return { status: "BUSY" };
    }
    incoming++;
    try {
      await refresh();
      const current = snapshot();
      let authenticated;
      try {
        authenticated = decryptFlockEnvelope({
          envelope, roster: current.roster, state, flockKey: current.flockKey,
          recipientOpaquePeerId: device.opaquePeerId, nowMs: now(),
        });
      } finally {
        current.flockKey.fill(0);
      }
      requireValue(authenticated.body && Object.keys(authenticated.body).length === 1 && authenticated.body.sealedRpcBody, "RPC requires a recipient-sealed body");
      const body = openSealedBundle({
        bundle: authenticated.body.sealedRpcBody, recipientEncPrivPem: device.encPriv,
        flockUuid: authenticated.flockUuid, rosterEpoch: authenticated.rosterEpoch,
        recipientOpaquePeerId: device.opaquePeerId, bundleType: "rpc-body",
      });
      requireValue(body && ["request", "reconcile", "response"].includes(body.kind), "Unknown encrypted RPC kind");
      if (body.kind === "response") {
        requireValue(authenticated.action === "ping" && Object.keys(body).length === 4 && typeof body.requestId === "string" && (TERMINAL_STATUSES.has(body.status) || body.status === "NOT_ADMITTED"), "Invalid typed RPC response");
        const entry = state.getOutboxEntry({ flockUuid: device.flockUuid, sender: device.opaquePeerId, recipient: authenticated.fromOpaquePeerId, requestId: body.requestId });
        requireValue(entry, "Response does not match an outstanding recipient-bound request");
        if (body.status === "NOT_ADMITTED") {
          const priorReceipt = state.getOutboxReceipt({ flockUuid: device.flockUuid, sender: device.opaquePeerId, recipient: entry.recipient, requestId: entry.request, payload: entry.payload, expiresAt: entry.expiry });
          if (!priorReceipt && entry.expiry > now() && !responsesInFlight.has(entry.request)) {
            responsesInFlight.add(entry.request);
            try { await transmit(entry); }
            finally { responsesInFlight.delete(entry.request); }
          }
          return { status: "RECONCILED" };
        }
        state.storeOutboxReceipt({ flockUuid: device.flockUuid, sender: device.opaquePeerId, recipient: entry.recipient, requestId: entry.request, status: body.status, result: body.result });
        waiters.get(entry.request)?.resolve({ requestId: entry.request, status: body.status, result: body.result });
        return { status: "RECEIPT_ACCEPTED" };
      }
      requireValue(Object.keys(body).length === 2, "Invalid typed RPC body");
      validateRequest(body.request);
      requireValue(authenticated.action === (body.kind === "reconcile" ? "ping" : body.request.action), "RPC action does not match signed envelope");
      const request = body.request;
      const sender = authenticated.fromOpaquePeerId;
      const sideEffecting = request.action !== "ping" && !SNAPSHOT_ACTIONS.has(request.action);
      let context;
      try { context = await authorize(request, sender, Date.parse(authenticated.expiresAt)); }
      catch (err) {
        if (err.code !== "DENIED") throw err;
        const status = deniedRequestStatus(request, sender);
        await emit(sender, { kind: "response", requestId: request.requestId, status, result: null });
        return { status };
      }
      let receipt;
      const claim = { roster: context.roster, sender, recipient: device.opaquePeerId, requestId: request.requestId,
        payload: request, expiresAt: request.expiresAt, authorization: context.authorization, nowMs: now() };
      if (body.kind === "reconcile") {
        receipt = state.readRequestReceipt(claim);
      } else {
        const admission = state.admitRequest(claim);
        receipt = admission;
        if (admission.dispatch) {
          let dispatchStarted = false;
          try {
            const beforeDispatch = await authorize(request, sender, Date.parse(authenticated.expiresAt));
            assertSameAuthorization(context, beforeDispatch);
            context = beforeDispatch;
            requireValue(request.expiresAt > now() && Date.parse(authenticated.expiresAt) > now(), "Request authority expired before dispatch");
            let outcome;
            if (context.mode === "PRESENCE") {
              outcome = { status: "DELIVERED", result: { opaquePeerId: device.opaquePeerId, rosterEpoch: context.roster.rosterEpoch, status: "online" } };
            } else if (context.mode === "SNAPSHOT") {
              outcome = { status: "DELIVERED", result: null };
            } else {
              dispatchStarted = true;
              outcome = await dispatch(request, context);
            }
            requireValue(!closed, "Runtime closed before admission confirmation");
            validateOutcome(outcome);
            await refresh();
            const afterDispatch = await authorize(request, sender, Date.parse(authenticated.expiresAt));
            assertSameAuthorization(context, afterDispatch);
            state.finishRequest({ flockUuid: device.flockUuid, sender, recipient: device.opaquePeerId,
              requestId: request.requestId, authorization: claim.authorization, status: outcome.status, result: outcome.result });
            receipt = { status: outcome.status, result: outcome.result, authorization: claim.authorization };
          } catch (err) {
            if (closed) return { status: "UNKNOWN" };
            const status = err.code === "DENIED" && !(dispatchStarted && sideEffecting) ? "DENIED" : "UNKNOWN";
            error(status, status === "DENIED" ? "Authorization changed before disclosure" : "Dispatch outcome unconfirmed; no automatic redispatch", request.requestId);
            state.finishRequest({ flockUuid: device.flockUuid, sender, recipient: device.opaquePeerId,
              requestId: request.requestId, authorization: claim.authorization, status, result: null });
            receipt = { status, result: null, authorization: claim.authorization };
          }
        }
      }
      await refresh();
      try {
        context = await authorize(request, sender, Date.parse(authenticated.expiresAt));
        if (context.mode === "SNAPSHOT" && receipt.status !== "NOT_ADMITTED") {
          const beforeRead = context;
          receipt = await readSnapshot(request, context);
          validateOutcome(receipt);
          await refresh();
          context = await authorize(request, sender, Date.parse(authenticated.expiresAt));
          assertSameAuthorization(beforeRead, context);
        } else if (receipt.status !== "NOT_ADMITTED" && !sameAuthorization(receipt.authorization, context.authorization)) {
          receipt = { status: deniedRequestStatus(request, sender, receipt), result: null };
        }
      }
      catch (err) {
        if (err.code !== "DENIED") throw err;
        const status = deniedRequestStatus(request, sender, receipt);
        await emit(sender, { kind: "response", requestId: request.requestId, status, result: null });
        return { status };
      }
      await emit(sender, { kind: "response", requestId: request.requestId, status: receipt.status, result: receipt.result });
      return { status: receipt.status };
    } catch (err) {
      if (err.code === "REPLAY") return { status: "REPLAY" };
      error(err.code === "DENIED" ? "DENIED" : "UNKNOWN", "Encrypted RPC rejected or outcome unconfirmed; no unauthenticated result disclosure");
      throw err;
    } finally {
      incoming--;
    }
  }

  async function request({ toOpaquePeerId, action, params = {}, requestId = crypto.randomUUID(), expiresAt = now() + 3600000, timeoutMs = 8000 }) {
    requireValue(!closed && waiters.size < capacity && !waiters.has(requestId), "Outgoing runtime is closed, busy or request is already in flight");
    requireValue(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 300000, "Invalid request wait timeout");
    const payload = { requestId, action, params, expiresAt };
    validateRequest(payload);
    await refresh();
    try { authorizeOutgoing(payload); }
    catch (err) {
      if (err.code !== "DENIED") throw err;
      return { requestId, status: "DENIED", result: null };
    }
    const coordinates = { flockUuid: device.flockUuid, sender: device.opaquePeerId, recipient: toOpaquePeerId, requestId };
    const previous = state.getOutboxReceipt({ ...coordinates, payload, expiresAt });
    if (previous) return previous;
    state.queue({ ...coordinates, payload, expiresAt, nowMs: now() });
    let timer;
    let resolve;
    const response = new Promise((res) => { resolve = res; });
    timer = setTimeout(() => resolve({ requestId, status: "UNKNOWN", result: null }), timeoutMs);
    const receiptTimer = setInterval(() => {
      try {
        const receipt = state.getOutboxReceipt({ ...coordinates, payload, expiresAt });
        if (receipt) resolve(receipt);
      } catch {
        error("UNKNOWN", "Persisted receipt could not be read; no automatic redispatch", requestId);
        resolve({ requestId, status: "UNKNOWN", result: null });
      }
    }, 50);
    waiters.set(requestId, { resolve, timer });
    try {
      const entry = state.getOutboxEntry(coordinates);
      const firstAttempt = state.markOutboxAttempt(coordinates);
      void transmit(entry, !firstAttempt).catch((err) => {
        if (closed) return;
        const status = err.code === "DENIED" ? "DENIED" : "UNKNOWN";
        if (status === "DENIED") {
          try { state.storeOutboxReceipt({ ...coordinates, status, result: null }); }
          catch {
            error("UNKNOWN", "Denied receipt could not be persisted; no automatic redispatch", requestId);
            resolve({ requestId, status: "UNKNOWN", result: null });
            return;
          }
        }
        error(status, status === "DENIED" ? "Outgoing request denied before transport" : "Encrypted transport admission unconfirmed; durable outbox retained", requestId);
        resolve({ requestId, status, result: null });
      });
      return await response;
    } finally {
      clearTimeout(timer);
      clearInterval(receiptTimer);
      waiters.delete(requestId);
    }
  }

  async function reconcilePending() {
    await refresh();
    for (const entry of state.pendingOutbox(device.flockUuid, capacity)) {
      const coordinates = { flockUuid: device.flockUuid, sender: entry.sender, recipient: entry.recipient, requestId: entry.request };
      if (entry.sender !== device.opaquePeerId) continue;
      if (!entry.attempted && entry.expiry > now()) {
        state.markOutboxAttempt(coordinates);
        await transmit(entry);
      } else {
        await transmit(entry, true);
      }
    }
  }

  return {
    request, receive, refresh, reconcilePending,
    close: () => {
      closed = true;
      for (const [requestId, waiter] of waiters) {
        clearTimeout(waiter.timer);
        waiter.resolve({ requestId, status: "UNKNOWN", result: null });
      }
      waiters.clear();
    },
  };
}
