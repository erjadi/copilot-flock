import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as rosterApi from "./zero-broker-roster.mjs";
import {
  cloudRequest, createGitHubRosterRepository, fetchPublicRosterChain,
  peekLockEncryptedPacket, prepareGitHubPagesRepository, stageEpochResources, runAzureCli,
} from "./zero-broker-transport.mjs";
import { createZeroBrokerRuntime, isVerifiedZeroBrokerContext } from "./zero-broker-runtime.mjs";
export { claimZeroBrokerVoucher } from "./zero-broker-enrollment.mjs";

const executeFile = promisify(execFile);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

export async function getOwnerGitHubToken() {
  try {
    const result = await executeFile("gh", ["auth", "token"], { encoding: "utf8", windowsHide: true, timeout: 10000 });
    check(result.stdout.trim(), "Missing GitHub token");
    return result.stdout.trim();
  } catch { throw new Error("Owner publication requires the configured gh account; captured authentication output was not logged"); }
}

export async function getLocalGitHubUser() {
  try {
    const result = await executeFile("gh", ["api", "--hostname", "github.com", "user", "--jq", ".login"], { encoding: "utf8", windowsHide: true, timeout: 10000 });
    const login = result.stdout.trim().toLowerCase();
    check(/^[a-z0-9][a-z0-9-]{0,38}$/.test(login), "Invalid local GitHub identity");
    return login;
  } catch { throw new Error("Local GitHub identity unavailable; automatic owner-scope discovery was not granted"); }
}

function groupDirectory(home, uuid) {
  check(UUID.test(uuid), "Invalid local flock UUID");
  return path.join(home, "zero-broker", uuid);
}

function privateBundle(roster, device, type) {
  const bundle = type === "member"
    ? roster.members.find((member) => member.opaquePeerId === device.opaquePeerId)?.sealedMemberBundle
    : roster.sealedOwnerVault[device.opaquePeerId];
  check(bundle, `No authorized ${type} bundle for this device`);
  return rosterApi.openSealedBundle({
    bundle, recipientEncPrivPem: device.encPriv, flockUuid: roster.flockUuid,
    rosterEpoch: roster.rosterEpoch, recipientOpaquePeerId: device.opaquePeerId, bundleType: type,
  });
}

export function openZeroBrokerGroup({ home, group, host, request = cloudRequest, runAz, getToken = getOwnerGitHubToken, now = Date.now }) {
  const directory = groupDirectory(home, group.flockUuid);
  const identityFile = path.join(directory, `flock-${group.flockUuid}`, "device.json");
  const stateFile = path.join(directory, "roster-state", "state.sqlite");
  check(fs.existsSync(identityFile) && fs.existsSync(stateFile), "Zero-Broker identity or admission ledger is missing; re-enroll with new keys, never reconstruct a ledger under old keys");
  const device = rosterApi.createDeviceKeys({ directory, flockUuid: group.flockUuid });
  const state = rosterApi.createRosterState({ directory });
  const initial = state.get(group.flockUuid);
  if (!initial || initial.rootFingerprint !== group.rootFingerprint) {
    state.close();
    throw new Error("Missing or mismatched durable roster trust anchor");
  }
  const configuration = () => rosterApi.readPrivateJson(directory, "configuration.json");
  const grants = () => fs.existsSync(path.join(directory, "grants.json")) ? rosterApi.readPrivateJson(directory, "grants.json") : { discovery: false, rootSessions: [], snapshots: {} };
  let closed = false;
  let disposed = false;
  let lastFetch = 0;
  let changing = null;

  async function repository() {
    const config = configuration();
    check(config.issuer, "This device has no local owner-issuer configuration");
    return createGitHubRosterRepository({ repository: config.repository, rosterPath: config.rosterPath, token: await getToken(), request, now });
  }

  async function refreshRoster(trusted, force = false) {
    if (!force && now() - lastFetch < 5000 && Date.parse(trusted.leaseExpiresAt) > now()) return [];
    const config = configuration();
    const latest = config.issuer
      ? await (await repository()).readLatest(trusted)
      : await fetchPublicRosterChain({ rosterUrl: config.rosterUrl, trustedRoster: trusted, request });
    lastFetch = now();
    return latest.transitions;
  }

  function rootGrant({ request: rpc, roster }) {
    if (closed) return false;
    const configured = grants();
    const session = rpc.params.sessionId || rpc.params.targetSession;
    return configuration().shared !== true && configuration().sameOwner === true && roster.rootFingerprint === group.rootFingerprint &&
      ["send_message", "get_transcript", "list_sessions"].includes(rpc.action) &&
      (rpc.action === "list_sessions" ? configured.discovery === true || configured.rootSessions.length > 0 : UUID.test(session || "") && configured.rootSessions.includes(session));
  }

  function snapshotGrant({ request: rpc }) {
    if (closed) return false;
    const snapshots = grants().snapshots;
    const session = rpc.params.sessionId || rpc.params.targetSession;
    return rpc.action === "list_sessions" || rpc.action === "list_shared_threads"
      ? Object.keys(snapshots).length > 0
      : Boolean(snapshots[session]);
  }

  const reportError = host.reportError;
  check(typeof reportError === "function", "Native host requires explicit error reporting");
  const runtime = createZeroBrokerRuntime({
    device, state, now, refreshRoster, reportError,
    sendPacket: (packet) => import("./zero-broker-transport.mjs").then(({ sendEncryptedPacket }) => sendEncryptedPacket({ ...packet, request })),
    authorizeRoot: rootGrant, authorizeSnapshot: snapshotGrant,
    readSnapshot: async (rpc) => {
      const snapshots = grants().snapshots;
      const result = rpc.action === "get_transcript"
        ? snapshots[rpc.params.sessionId || rpc.params.targetSession] || null
        : Object.values(snapshots).slice(0, 100).map(({ sessionId, title }) => ({ sessionId, title, visibility: "approved-snapshot" }));
      return { status: "DELIVERED", result };
    },
    dispatch: async (rpc, context) => {
      check(isVerifiedZeroBrokerContext(context, rpc) && context.mode === "ROOT", "Native dispatch requires a request-bound verified root capability");
      const allowed = () => !closed && rootGrant({ request: rpc, roster: state.get(group.flockUuid) }) &&
        state.get(group.flockUuid).rosterEpoch === context.roster.rosterEpoch &&
        now() < Math.min(context.dispatchExpiresAt, Date.parse(state.get(group.flockUuid).leaseExpiresAt));
      check(allowed(), "Local root grant changed before native dispatch");
      if (rpc.action === "list_sessions") {
        const configured = grants();
        const ids = new Set(configured.rootSessions);
        const bindings = fs.existsSync(path.join(home, "session-bindings.json")) ? rosterApi.readPrivateJson(home, "session-bindings.json") : {};
        return { status: "DELIVERED", result: host.listSessions().filter((session) => (configured.discovery === true || ids.has(session.session_id)) && (!bindings[session.session_id] || bindings[session.session_id] === group.flockUuid)).slice(0, 100) };
      }
      if (rpc.action === "get_transcript") return { status: "DELIVERED", result: await host.readTranscript(rpc.params.sessionId || rpc.params.targetSession, Math.min(30, Number(rpc.params.limit) || 10)) };
      return await host.sendMessage({ ...rpc.params, expiresAt: context.dispatchExpiresAt, allowed, fromOpaquePeerId: context.sender.opaquePeerId });
    },
  });

  async function transition(prepare) {
    check(!changing, "An owner transition is already in progress in this process");
    changing = (async () => {
      const repo = await repository();
      const config = configuration();
      await retryPendingCloses();
      let committedBase;
      const next = await rosterApi.publishRosterWithCas({
        trustedRoster: state.get(group.flockUuid), state, nowMs: now,
        readLatest: repo.readLatest,
        put: async (input) => {
          rosterApi.writePrivateJson(directory, "pending-cutover.json", { previous: committedBase, next: input.roster }, { exclusive: true });
          return await repo.put(input);
        },
        discard: async (candidate) => {
          await candidate.discard();
          const file = path.join(directory, "pending-cutover.json");
          if (fs.existsSync(file) && rosterApi.hashRoster(rosterApi.readPrivateJson(directory, "pending-cutover.json").next) === rosterApi.hashRoster(candidate.roster)) fs.unlinkSync(file);
        },
        prepare: async (trusted) => {
          committedBase = trusted;
          const previousCredentials = privateBundle(trusted, device, "owner-vault");
          const plan = prepare(trusted);
          const staged = await stageEpochResources({
            flockUuid: trusted.flockUuid, rosterEpoch: trusted.rosterEpoch + 1,
            opaquePeerIds: plan.memberIds, resourceGroup: config.resourceGroup,
            namespaceName: config.namespaceName, signalr: previousCredentials.signalr, runAz,
            subscriptionId: config.subscriptionId,
          });
          try {
            let roster = plan.build(staged.ownerCredentials);
            if (trusted.ownerSigners.some((signer) => signer.opaquePeerId === device.opaquePeerId && signer.role === "genesis-root")) {
              roster = rosterApi.createRecoveryCheckpoint({ trustedRoster: rosterApi.readPrivateJson(directory, "genesis.json"), nextRoster: roster, actor: device, nowMs: now() });
            }
            return { roster, discard: staged.discard };
          } catch (error) {
            await staged.discard();
            throw error;
          }
        },
      });
      await retryPendingCloses();
      return next;
    })().finally(() => { changing = null; });
    return await changing;
  }

  async function renewAndPrune() {
    const config = configuration();
    if (!config.issuer) return false;
    const trusted = state.get(group.flockUuid);
    const latest = await refreshRoster(trusted, true);
    const current = rosterApi.verifyRosterChain(trusted, latest, now(), { state, requireFresh: false });
    const expired = current.members.filter((member) => member.membershipExpiresAt && Date.parse(member.membershipExpiresAt) <= now());
    if (!expired.length && Date.parse(current.leaseExpiresAt) - now() > rosterApi.MAX_LEASE_MS / 3) return false;
    await transition((roster) => ({
      memberIds: roster.members.filter((member) => !member.membershipExpiresAt || Date.parse(member.membershipExpiresAt) > now()).map((member) => member.opaquePeerId),
      build: (ownerCredentials) => roster.members.some((member) => member.membershipExpiresAt && Date.parse(member.membershipExpiresAt) <= now())
        ? rosterApi.pruneExpiredMembersAndRotate({ roster, actor: device, ownerCredentials, nowMs: now() })
        : rosterApi.renewRosterLease({ roster, actor: device, ownerCredentials, nowMs: now() }),
    }));
    return true;
  }

  async function retryPendingCloses() {
    const file = path.join(directory, "pending-cutover.json");
    if (!fs.existsSync(file)) return;
    const pending = rosterApi.readPrivateJson(directory, "pending-cutover.json");
    const latest = await (await repository()).readLatest(pending.previous);
    check(pending.previous.rootFingerprint === group.rootFingerprint, "Pending cutover root pin mismatch");
    let verified = pending.previous;
    for (const next of latest.transitions) verified = rosterApi.validateRosterTransition(verified, next, now(), { requireFresh: false });
    check([pending.previous, ...latest.transitions].some((roster) => rosterApi.hashRoster(roster) === rosterApi.hashRoster(pending.next)), "Cutover publication remains unconfirmed; retained exact proposal, no new transition or blind cleanup");
    const credentials = privateBundle(verified, device, "owner-vault");
    for (const member of pending.previous.members.filter((entry) => !pending.next.members.some((active) => active.opaquePeerId === entry.opaquePeerId))) {
      const close = rosterApi.buildSignalRCloseUserConnectionsRequest({
        ...credentials.signalr, hubName: rosterApi.epochHubName(group.flockUuid, pending.previous.rosterEpoch), opaquePeerId: member.opaquePeerId,
      });
      const result = await request(close.url, { method: close.method, headers: close.headers });
      check(result.status === 200 || result.status === 202 || result.status === 204, `Roster cutover committed, but closing old SignalR connections failed with HTTP ${result.status}`);
    }
    fs.unlinkSync(file);
  }

  async function invite({ recipient, role = "guest", membershipExpiresAt = null, canMintTokens = false, canKick = false, verifiedSigningFingerprint, verifiedEncFingerprint }) {
    check(recipient?.flockUuid === group.flockUuid, "Recipient must generate a distinct key card for this flock UUID");
    check(verifiedSigningFingerprint === rosterApi.keyFingerprint(recipient.signingPub) && verifiedEncFingerprint === rosterApi.keyFingerprint(recipient.encPub), "Invite requires independently verified recipient fingerprints");
    check(role === "owner" || configuration().shared === true, "External guests require a separate shared flock, never an owner personal/work roster");
    await renewAndPrune();
    await runtime.refresh();
    const current = state.get(group.flockUuid);
    const existing = current.members.find((member) => member.opaquePeerId === recipient.opaquePeerId);
    check(existing || role !== "owner" || current.ownerSigners.some((signer) => signer.opaquePeerId === device.opaquePeerId && signer.role === "genesis-root"), "Only genesis-root can add an owner signer");
    check(!existing || existing.signingPub === recipient.signingPub && existing.encPub === recipient.encPub && existing.role === role, "Existing member key or role mismatch; do not replace an identity while reissuing enrollment");
    const next = existing ? current : await transition((roster) => ({
      memberIds: [...roster.members.map((member) => member.opaquePeerId), recipient.opaquePeerId],
      build: (ownerCredentials) => rosterApi.createPreBoundInvite({
        roster, actor: device, recipient, role, membershipExpiresAt, ownerCredentials, nowMs: now(),
        ...(role === "owner" ? { ownerPermissions: { canKick, canModifyOwners: false, canMintTokens } } : {}),
      }),
    }));
    const minting = next.ownerSigners.find((signer) => signer.opaquePeerId === recipient.opaquePeerId)?.permissions.canMintTokens;
    const ownerControl = role === "owner" && minting ? rosterApi.sealBundle({ payload: configuration(), recipientEncPubPem: recipient.encPub, flockUuid: group.flockUuid, rosterEpoch: next.rosterEpoch, recipientOpaquePeerId: recipient.opaquePeerId, bundleType: "owner-control" }) : null;
    const body = { type: "copilot-flock-zero-broker-invite-v1", flockUuid: group.flockUuid, rootFingerprint: group.rootFingerprint, rosterUrl: configuration().rosterUrl, genesis: rosterApi.readPrivateJson(directory, "genesis.json"), recipientOpaquePeerId: recipient.opaquePeerId, rosterEpoch: next.rosterEpoch, ownerControl, ownerGitHubUser: configuration().ownerGitHubUser, shared: configuration().shared, label: group.label };
    return { ...body, ownerSignature: { signedByOpaquePeerId: device.opaquePeerId, signature: crypto.sign(null, Buffer.from(rosterApi.canonicalJson(body)), device.signingPriv).toString("base64") } };
  }

  async function kick(opaquePeerId) {
    const next = await transition((roster) => {
        check(roster.members.some((member) => member.opaquePeerId === opaquePeerId) && !roster.ownerSigners.some((signer) => signer.opaquePeerId === opaquePeerId), "Kick requires a non-owner member; owner removal requires root recovery");
        check(roster.ownerSigners.find((signer) => signer.opaquePeerId === device.opaquePeerId)?.permissions.canKick, "Owner lacks kick permission");
      return {
      memberIds: roster.members.filter((member) => member.opaquePeerId !== opaquePeerId).map((member) => member.opaquePeerId),
      build: (ownerCredentials) => rosterApi.kickMemberFromRoster({ roster, actor: device, opaquePeerId, ownerCredentials, nowMs: now() }),
      };
    });
    return { rosterEpoch: next.rosterEpoch, kickedOpaquePeerId: opaquePeerId };
  }

  function enrollmentCredentials() {
    return rosterApi.openSealedBundle({
      bundle: rosterApi.readPrivateJson(directory, "enrollment-vault.json"), recipientEncPrivPem: device.encPriv,
      flockUuid: group.flockUuid, rosterEpoch: 1, recipientOpaquePeerId: device.opaquePeerId, bundleType: "enrollment-vault",
    });
  }

  async function createVoucher({ role = "guest", durationMinutes = 60 }) {
    check(configuration().shared === true, "External vouchers require a separate shared flock");
    check(Number.isInteger(durationMinutes) && durationMinutes >= 1 && durationMinutes <= 1440, "Choose a bounded invitation duration between 1 and 1440 minutes");
    await renewAndPrune();
    const keys = enrollmentCredentials();
    let voucher;
    await transition((roster) => ({
      memberIds: roster.members.map((member) => member.opaquePeerId),
      build: (ownerCredentials) => {
        const created = rosterApi.createInviteVoucher({
          roster, actor: device, role, rosterUrl: configuration().rosterUrl,
          enrollmentSbSendSas: rosterApi.mintServiceBusSas({ ...keys, ruleName: "FlockSendRule", ruleKey: keys.sendRuleKey, expiresAtSeconds: Math.floor((now() + Math.min(durationMinutes * 60000, 3600000)) / 1000) }),
          expiresAt: new Date(now() + Math.min(durationMinutes * 60000, 3600000)).toISOString(), nowMs: now(),
        });
        voucher = created.voucher;
        return rosterApi.rotateRosterEpoch({ roster, actor: device, ownerCredentials, nowMs: now(), mutate: (next) => { next.pendingVouchers[voucher.voucherId] = created.pendingRecord; } });
      },
    }));
    return { type: "copilot-flock-zero-broker-voucher-v1", voucher, genesis: rosterApi.readPrivateJson(directory, "genesis.json"), issuerOpaquePeerId: device.opaquePeerId, enrollmentEndpoint: { namespaceHost: keys.namespaceHost, topicName: keys.topicName }, membershipDurationMinutes: durationMinutes, rootFingerprint: group.rootFingerprint };
  }

  async function receiveEnrollment(packet) {
    check(configuration().issuer && packet?.kind === "enrollment-claim" && Buffer.byteLength(JSON.stringify(packet)) <= 16384, "Invalid provisional claim packet");
    const body = rosterApi.openSealedBundle({
      bundle: packet.bundle, recipientEncPrivPem: device.encPriv, flockUuid: group.flockUuid,
      rosterEpoch: packet.bundle.rosterEpoch, recipientOpaquePeerId: device.opaquePeerId, bundleType: "enrollment-claim",
    });
    const proof = rosterApi.verifyEnrollmentClaimProof({ roster: state.get(group.flockUuid), ...body, nowMs: now() });
    const claims = fs.existsSync(path.join(directory, "enrollment-claims.json")) ? rosterApi.readPrivateJson(directory, "enrollment-claims.json") : {};
    const id = crypto.createHash("sha256").update(rosterApi.canonicalJson(body.claim)).digest("hex");
    check(Object.hasOwn(claims, id) || Object.keys(claims).length < 32, "Provisional claim capacity exhausted; no automatic admission");
    claims[id] = { ...body, ...proof };
    rosterApi.writePrivateJson(directory, "enrollment-claims.json", claims);
  }

  function pendingClaims() {
    return fs.existsSync(path.join(directory, "enrollment-claims.json")) ? rosterApi.readPrivateJson(directory, "enrollment-claims.json") : {};
  }

  async function approveClaim({ claimId, signingFingerprint, encFingerprint, durationMinutes = 60 }) {
    await renewAndPrune();
    const entry = pendingClaims()[claimId];
    check(entry && Number.isInteger(durationMinutes) && durationMinutes >= 1 && durationMinutes <= 1440, "Select a pending claim and bounded membership duration");
    const approval = rosterApi.approveEnrollmentClaim({ claim: entry.claim, actor: device, verifiedSigningFingerprint: signingFingerprint, verifiedEncFingerprint: encFingerprint });
    const next = await transition((roster) => {
      rosterApi.verifyEnrollmentClaimProof({ roster, voucher: entry.voucher, claim: entry.claim, nowMs: now() });
      return {
        memberIds: [...roster.members.map((member) => member.opaquePeerId), entry.claim.opaquePeerId],
        build: (ownerCredentials) => rosterApi.redeemEnrollmentClaim({ roster, voucher: entry.voucher, claim: entry.claim, actor: device, approval, ownerCredentials, membershipExpiresAt: new Date(now() + durationMinutes * 60000).toISOString(), nowMs: now() }),
      };
    });
    return { admitted: true, opaquePeerId: entry.claim.opaquePeerId, rosterEpoch: next.rosterEpoch };
  }

  async function pollEnrollment() {
    if (!configuration().issuer || !fs.existsSync(path.join(directory, "enrollment-vault.json"))) return;
    const keys = enrollmentCredentials();
    const subscriptionName = `sub-${device.opaquePeerId}-e1`;
    const sbListenSas = rosterApi.mintServiceBusSas({ ...keys, ruleName: "FlockListenRule", ruleKey: keys.listenRuleKey, subscriptionName, expiresAtSeconds: Math.floor(now() / 1000) + 3600 });
    const locked = await peekLockEncryptedPacket({ transport: { ...keys, subscriptionName, sbListenSas }, request });
    if (locked) {
      try { await receiveEnrollment(locked.envelope); }
      catch { reportError({ status: "DENIED", message: "Provisional enrollment claim rejected; no admission or execution" }); }
      await locked.acknowledge();
    }
  }

  async function poll() {
    if (closed) return;
    await runtime.refresh();
    const current = state.get(group.flockUuid);
    const transport = privateBundle(current, device, "member").transport;
    const locked = await peekLockEncryptedPacket({ transport, request });
    if (locked) {
      await runtime.receive(locked.envelope);
      await locked.acknowledge();
    }
  }

  function setGrants(value) {
    check(value && (typeof value.discovery === "undefined" || typeof value.discovery === "boolean"), "Invalid discovery grant");
    check(!value.rootSessions?.length || configuration().sameOwner === true && configuration().shared !== true, "Live root grants require a verified private owner scope");
    const existing = new Set(host.listSessions().map((session) => session.session_id));
    check(Array.isArray(value.rootSessions) && value.rootSessions.length <= 100 && value.rootSessions.every((id) => UUID.test(id) && existing.has(id)), "Root grants require selected existing session UUIDs");
    check(value.snapshots && Object.getPrototypeOf(value.snapshots) === Object.prototype && Object.keys(value.snapshots).length <= 100, "Invalid snapshot grants");
    const bindings = fs.existsSync(path.join(home, "session-bindings.json")) ? rosterApi.readPrivateJson(home, "session-bindings.json") : {};
    for (const id of value.rootSessions) {
      check(!bindings[id] || bindings[id] === group.flockUuid, "Session is already bound to another flock; use a new session or an approved snapshot");
      bindings[id] = group.flockUuid;
    }
    for (const [id, snapshot] of Object.entries(value.snapshots)) {
      check(UUID.test(id) && snapshot.sessionId === id && typeof snapshot.title === "string" && snapshot.title.length <= 512 && typeof snapshot.summary === "string" && Buffer.byteLength(snapshot.summary) <= 32768, "Snapshots require explicit bounded summary text, never automatic live transcripts");
      const text = `${snapshot.title}\n${snapshot.summary}`;
      check(!/-----BEGIN .*PRIVATE KEY-----|SharedAccessSignature\s|AccessKey=|SharedAccessKey=|\bgh[pousr]_[a-zA-Z0-9]+|\bgithub_pat_|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i.test(text), "Snapshot contains recognizable credential material; remove it before sharing");
      if (state.get(group.flockUuid).sealedOwnerVault[device.opaquePeerId]) {
        const credentials = privateBundle(state.get(group.flockUuid), device, "owner-vault");
        const secrets = [credentials.signalr.accessKey, credentials.serviceBus.sendRuleKey, credentials.serviceBus.listenRuleKey];
        if (fs.existsSync(path.join(directory, "enrollment-vault.json"))) {
          const keys = enrollmentCredentials();
          secrets.push(keys.sendRuleKey, keys.listenRuleKey);
        }
        check(!secrets.some((secret) => text.includes(secret)), "Snapshot contains a known local issuer credential");
      }
    }
    rosterApi.writePrivateJson(home, "session-bindings.json", bindings);
    rosterApi.writePrivateJson(directory, "grants.json", value);
  }

  return {
    device, state, runtime, poll, pollEnrollment, renewAndPrune, retryPendingCloses, invite, createVoucher, pendingClaims, approveClaim, kick, setGrants, grants, configuration,
    transport: () => privateBundle(state.get(group.flockUuid), device, "member").transport,
    suspend: () => { closed = true; runtime.close(); },
    close: () => { if (!disposed) { disposed = true; closed = true; runtime.close(); state.close(); } },
  };
}

export async function initializeZeroBrokerOwner({ home, repository, resourceGroup, namespaceName, signalr, subscriptionId, enrollmentKeys, scope = "personal", shared = false, flockName = scope, publishConsent, request = cloudRequest, runAz = runAzureCli, getToken = getOwnerGitHubToken, now = Date.now }) {
  const existing = fs.existsSync(path.join(home, "config.json")) ? rosterApi.readPrivateJson(home, "config.json") : null;
  check(!fs.existsSync(path.join(home, "initialization-pending.json")), "An initialization outcome is pending; reconcile that exact candidate with resume-init before creating another identity");
  check(!existing || (existing.architecture === "zero-broker" && shared), "Existing installation remains unchanged; only explicit additional shared flocks can be created in place");
  check(["personal", "work"].includes(scope) && /^[a-z0-9][a-z0-9-]{0,63}$/.test(flockName), "Invalid initial flock scope or name");
  check(UUID.test(subscriptionId || ""), "Explicitly pin the approved Azure subscription before owner initialization");
  check(typeof namespaceName === "string" && /^[a-z0-9-]{6,50}$/i.test(namespaceName) && typeof signalr?.endpoint === "string" && typeof signalr.accessKey === "string", "Approved Azure issuer configuration is incomplete");
  const token = await getToken();
  const pages = await prepareGitHubPagesRepository({ repository, token, publishConsent, request });
  check(!existing?.groups.some((entry) => entry.label === `${pages.githubUser}/${flockName}`), "Flock label is already enrolled");
  const flockUuid = crypto.randomUUID();
  const directory = groupDirectory(home, flockUuid);
  const device = rosterApi.createDeviceKeys({ directory, flockUuid });
  const state = rosterApi.createRosterState({ directory });
  const rosterPath = `flocks/${flockUuid}/flock-roster.json`;
  const config = { issuer: true, shared, sameOwner: true, ownerGitHubUser: pages.githubUser, repository, resourceGroup, namespaceName, subscriptionId, rosterPath, rosterUrl: new URL(rosterPath, pages.pagesBaseUrl).href };
  try {
    rosterApi.writePrivateJson(directory, "configuration.json", config);
    rosterApi.writePrivateJson(home, "initialization-pending.json", { flockUuid, group: { flockUuid, rootFingerprint: rosterApi.keyFingerprint(device.signingPub), label: `${pages.githubUser}/${flockName}` }, githubUser: pages.githubUser, scope, shared }, { exclusive: true });
  } catch (error) { state.close(); throw error; }
  let staged;
  try {
    staged = await stageEpochResources({ flockUuid, rosterEpoch: 1, opaquePeerIds: [device.opaquePeerId], resourceGroup, namespaceName, subscriptionId, signalr, runAz });
    if (enrollmentKeys) {
      check(enrollmentKeys.namespaceHost === `${namespaceName.toLowerCase()}.servicebus.windows.net` && /^[A-Za-z0-9_-]+$/.test(enrollmentKeys.topicName) && typeof enrollmentKeys.sendRuleKey === "string" && typeof enrollmentKeys.listenRuleKey === "string", "Invalid dedicated enrollment issuer keys");
      const common = ["--subscription", subscriptionId, "--resource-group", resourceGroup, "--namespace-name", namespaceName, "--topic-name", enrollmentKeys.topicName];
      const subscriptionName = `sub-${device.opaquePeerId}-e1`;
      await runAz(["servicebus", "topic", "subscription", "create", ...common, "--name", subscriptionName, "--output", "none"]);
      await runAz(["servicebus", "topic", "subscription", "rule", "create", ...common, "--subscription-name", subscriptionName, "--name", "RecipientOnly", "--filter-sql-expression", `flockUuid = '${flockUuid}' AND toOpaquePeerId = '${device.opaquePeerId}'`, "--output", "none"]);
      await runAz(["servicebus", "topic", "subscription", "rule", "delete", ...common, "--subscription-name", subscriptionName, "--name", "$Default", "--output", "none"]);
      rosterApi.writePrivateJson(directory, "enrollment-vault.json", rosterApi.sealBundle({ payload: enrollmentKeys, recipientEncPubPem: device.encPub, flockUuid, rosterEpoch: 1, recipientOpaquePeerId: device.opaquePeerId, bundleType: "enrollment-vault" }));
    }
    const genesis = rosterApi.createGenesisRoster({ owner: device, ownerCredentials: staged.ownerCredentials, nowMs: now() });
    rosterApi.writePrivateJson(directory, "genesis.json", genesis);
    rosterApi.writePrivateJson(directory, "grants.json", { discovery: !shared, rootSessions: [], snapshots: {} });
    const repo = createGitHubRosterRepository({ repository, rosterPath, token, request, now });
    const publication = await repo.publishGenesis(genesis);
    check(publication.status === 200 || publication.status === 201, `Genesis publication failed with HTTP ${publication.status}; reconcile publication before retrying`);
    rosterApi.verifyRosterChain(genesis, [], now(), { state, pinnedRootFingerprint: genesis.rootFingerprint });
    const group = { flockUuid, rootFingerprint: genesis.rootFingerprint, label: `${pages.githubUser}/${flockName}` };
    check(!existing?.groups.some((entry) => entry.label === group.label), "Flock label is already enrolled");
    const installed = existing ? { ...existing, groups: [...existing.groups, group] } : { architecture: "zero-broker", machineId: device.opaquePeerId, githubUser: pages.githubUser, scope, groups: [group] };
    rosterApi.writePrivateJson(home, "config.json", installed);
    fs.unlinkSync(path.join(home, "initialization-pending.json"));
    return installed;
  } catch (error) {
    throw new Error(`Zero-Broker initialization did not complete; retained private recovery state for flock ${flockUuid}. Reconcile GitHub publication and staged topic ${staged?.topicName || "not confirmed"} before retrying`, { cause: error });
  } finally { state.close(); }
}

export async function resumeZeroBrokerInitialization({ home, host, request = cloudRequest, runAz, getToken = getOwnerGitHubToken, now = Date.now }) {
  const pending = rosterApi.readPrivateJson(home, "initialization-pending.json");
  const directory = groupDirectory(home, pending.flockUuid);
  check(fs.existsSync(path.join(directory, "roster-state", "state.sqlite")), "Pending admission ledger is missing; do not reconstruct it under old keys");
  check(fs.existsSync(path.join(directory, "genesis.json")), "Epoch staging never produced a signed candidate; reconcile the exact reported Azure topic before abandoning this pending initialization");
  const device = rosterApi.createDeviceKeys({ directory, flockUuid: pending.flockUuid });
  const genesis = rosterApi.readPrivateJson(directory, "genesis.json");
  check(rosterApi.keyFingerprint(device.signingPub) === pending.group.rootFingerprint && genesis.rootFingerprint === pending.group.rootFingerprint, "Pending identity or root pin mismatch");
  const config = rosterApi.readPrivateJson(directory, "configuration.json");
  const repo = createGitHubRosterRepository({ repository: config.repository, rosterPath: config.rosterPath, token: await getToken(), request, now });
  const latest = await repo.readRoster({ optional: true });
  if (!latest) {
    const result = await repo.publishGenesis(genesis);
    check(result.status === 200 || result.status === 201, "Genesis publication remains unconfirmed; pending candidate was retained");
  }
  const state = rosterApi.createRosterState({ directory });
  try {
    const trusted = state.get(pending.flockUuid) || genesis;
    const fetched = await repo.readLatest(trusted);
    rosterApi.verifyRosterChain(trusted, fetched.transitions, now(), { state, pinnedRootFingerprint: pending.group.rootFingerprint, requireFresh: false });
  } finally { state.close(); }
  const installed = fs.existsSync(path.join(home, "config.json")) ? rosterApi.readPrivateJson(home, "config.json") : { architecture: "zero-broker", machineId: device.opaquePeerId, githubUser: pending.githubUser, scope: pending.scope, groups: [] };
  check(installed.architecture === "zero-broker", "Cannot replace a legacy installation during recovery");
  if (!installed.groups.some((group) => group.flockUuid === pending.flockUuid)) installed.groups.push(pending.group);
  rosterApi.writePrivateJson(home, "config.json", installed);
  const service = openZeroBrokerGroup({ home, group: pending.group, host, request, runAz, getToken, now });
  try { await service.renewAndPrune(); }
  finally { service.close(); }
  fs.unlinkSync(path.join(home, "initialization-pending.json"));
  return installed;
}

export function prepareZeroBrokerEnrollment({ home, flockUuid }) {
  const directory = groupDirectory(home, flockUuid);
  const { opaquePeerId, signingPub, encPub } = rosterApi.createDeviceKeys({ directory, flockUuid });
  return { flockUuid, opaquePeerId, signingPub, encPub, signingFingerprint: rosterApi.keyFingerprint(signingPub), encFingerprint: rosterApi.keyFingerprint(encPub) };
}

export async function enrollZeroBrokerDevice({ home, invite, verifiedRootFingerprint, scope = "personal", request = cloudRequest, resolveGitHubUser = getLocalGitHubUser, now = Date.now }) {
  check(["personal", "work"].includes(scope), "Invalid local enrollment scope");
  check(invite.type === "copilot-flock-zero-broker-invite-v1" && invite.rootFingerprint === verifiedRootFingerprint, "Enrollment requires a separately verified root fingerprint");
  const directory = groupDirectory(home, invite.flockUuid);
  check(fs.existsSync(path.join(directory, `flock-${invite.flockUuid}`, "device.json")), "Generate and independently verify the device key card before owner enrollment");
  const device = rosterApi.createDeviceKeys({ directory, flockUuid: invite.flockUuid });
  check(device.opaquePeerId === invite.recipientOpaquePeerId, "Invite is bound to a different device");
  const configPath = path.join(home, "config.json");
  const installed = fs.existsSync(configPath) ? rosterApi.readPrivateJson(home, "config.json") : { architecture: "zero-broker", machineId: device.opaquePeerId, scope, groups: [] };
  check(installed.architecture === "zero-broker", "Existing legacy installation remains unchanged; do not silently migrate it");
  check(!installed.groups.some((group) => group.flockUuid === invite.flockUuid), "Flock already enrolled; never reset its admission ledger");
  const state = rosterApi.createRosterState({ directory });
  try {
    const trusted = state.get(invite.flockUuid) || invite.genesis;
    rosterApi.verifyRosterChain(trusted, [], now(), { state, pinnedRootFingerprint: verifiedRootFingerprint, requireFresh: false });
    const fetched = await fetchPublicRosterChain({ rosterUrl: invite.rosterUrl, trustedRoster: trusted, request });
    const current = rosterApi.verifyRosterChain(trusted, fetched.transitions, now(), { state });
    const member = current.members.find((entry) => entry.opaquePeerId === device.opaquePeerId);
    check(current.rosterEpoch >= invite.rosterEpoch && member && (!member.membershipExpiresAt || Date.parse(member.membershipExpiresAt) > now()), "Enrollment is not yet active in a fresh signed Pages roster");
    privateBundle(current, device, "member");
    const { ownerSignature, ...body } = invite;
    const issuer = current.ownerSigners.find((entry) => entry.opaquePeerId === ownerSignature?.signedByOpaquePeerId);
    check(issuer && crypto.verify(null, Buffer.from(rosterApi.canonicalJson(body)), issuer.signingPub, Buffer.from(ownerSignature.signature, "base64")), "Invalid owner-signed enrollment descriptor");
    let localUser = null;
    let discoveryReason = "external flock";
    if (!invite.shared && current.members.every((member) => member.role === "owner")) {
      try { localUser = await resolveGitHubUser(); }
      catch { discoveryReason = "local GitHub identity unavailable; automatic discovery disabled"; }
    }
    const sameOwner = Boolean(localUser && localUser === invite.ownerGitHubUser);
    const signer = current.ownerSigners.find((entry) => entry.opaquePeerId === device.opaquePeerId);
    const ownerControl = invite.ownerControl && signer?.permissions.canMintTokens ? rosterApi.openSealedBundle({ bundle: invite.ownerControl, recipientEncPrivPem: device.encPriv, flockUuid: current.flockUuid, rosterEpoch: invite.rosterEpoch, recipientOpaquePeerId: device.opaquePeerId, bundleType: "owner-control" }) : null;
    rosterApi.writePrivateJson(directory, "configuration.json", { ...(ownerControl || { issuer: false, rosterUrl: invite.rosterUrl }), shared: invite.shared, sameOwner, ownerGitHubUser: invite.ownerGitHubUser });
    rosterApi.writePrivateJson(directory, "grants.json", { discovery: sameOwner, rootSessions: [], snapshots: {} });
    rosterApi.writePrivateJson(directory, "genesis.json", invite.genesis);
    installed.groups.push({ flockUuid: invite.flockUuid, rootFingerprint: verifiedRootFingerprint, label: invite.label });
    rosterApi.writePrivateJson(home, "config.json", installed);
    return { enrolled: true, flockUuid: invite.flockUuid, opaquePeerId: device.opaquePeerId, rosterEpoch: current.rosterEpoch, metadataDiscovery: sameOwner ? "same-owner scope" : discoveryReason };
  } finally { state.close(); }
}

export async function runZeroBrokerService({ home, config, host, signal, request, runAz, getToken, intervalMs = 1000, onStatus = () => {} }) {
  check(Number.isInteger(intervalMs) && intervalMs >= 100, "Invalid daemon polling interval");
  const groups = [];
  try { for (const group of config.groups) groups.push(openZeroBrokerGroup({ home, group, host, request, runAz, getToken })); }
  catch (error) { for (const group of groups) group.close(); throw error; }
  const inFlight = new Set();
  let stopping = false;
  const sockets = new Map();
  const signalrReceivers = new Map();
  const stop = () => { stopping = true; for (const group of groups) group.suspend(); for (const socket of sockets.values()) socket.close(); };
  signal?.addEventListener("abort", stop, { once: true });
  if (signal?.aborted) stop();
  async function connect(group) {
    const transport = group.transport();
    if (signalrReceivers.get(group.device.opaquePeerId) === transport.hubName) return;
    sockets.get(group.device.opaquePeerId)?.close();
    const endpoint = new URL(transport.endpoint);
    endpoint.protocol = "wss:";
    endpoint.pathname = "/client/";
    endpoint.search = new URLSearchParams({ hub: transport.hubName, access_token: transport.wsClientJwt }).toString();
    const socket = new WebSocket(endpoint);
    socket.binaryType = "arraybuffer";
    sockets.set(group.device.opaquePeerId, socket);
    signalrReceivers.set(group.device.opaquePeerId, transport.hubName);
    let buffer = "";
    let keepalive = null;
    socket.onopen = () => {
      socket.send('{"protocol":"json","version":1}\u001e');
      keepalive = setInterval(() => { if (socket.readyState === WebSocket.OPEN) socket.send('{"type":6}\u001e'); }, 15000);
    };
    socket.onmessage = (event) => {
      buffer += typeof event.data === "string" ? event.data : Buffer.from(event.data).toString("utf8");
      if (Buffer.byteLength(buffer) > 1048576) { socket.close(); host.reportError({ status: "DENIED", message: "SignalR frame exceeds bound" }); return; }
      const frames = buffer.split("\u001e");
      buffer = frames.pop();
      for (const frame of frames) {
        if (!frame) continue;
        try {
          const message = JSON.parse(frame);
          if (message.error || message.type === 7) { socket.close(); host.reportError({ status: "OFFLINE", message: "SignalR handshake or connection closed" }); continue; }
          const envelope = message.target === "zeroBrokerEnvelope" && message.arguments?.length === 1 ? message.arguments[0] : null;
          if (!stopping && envelope?.toOpaquePeerId === group.device.opaquePeerId) {
            if (inFlight.size >= 32) { socket.close(); host.reportError({ status: "DENIED", message: "SignalR receive capacity reached; no unbounded admission" }); continue; }
            const work = group.runtime.receive(envelope).catch(() => host.reportError({ status: "UNKNOWN", message: "SignalR packet processing failed; durable claims retained" })).finally(() => inFlight.delete(work));
            inFlight.add(work);
          }
        } catch { socket.close(); host.reportError({ status: "DENIED", message: "Malformed SignalR frame" }); }
      }
    };
    socket.onerror = () => { socket.close(); host.reportError({ status: "OFFLINE", message: "SignalR connection failed; credential-bearing URLs were not logged" }); };
    socket.onclose = () => { clearInterval(keepalive); if (sockets.get(group.device.opaquePeerId) === socket) signalrReceivers.delete(group.device.opaquePeerId); };
  }
  try {
    while (!stopping) {
      const saved = rosterApi.readPrivateJson(home, "config.json");
      check(saved.architecture === "zero-broker", "Daemon configuration architecture changed; stop rather than migrate");
      for (let index = groups.length - 1; index >= 0; index--) {
        const group = groups[index];
        const entry = saved.groups.find((entry) => entry.flockUuid === group.device.flockUuid);
        if (!entry) {
          group.suspend();
          sockets.get(group.device.opaquePeerId)?.close();
          await Promise.allSettled([...inFlight]);
          group.close();
          groups.splice(index, 1);
        } else check(entry.rootFingerprint === group.state.get(group.device.flockUuid).rootFingerprint, "Configuration cannot silently replace a pinned root");
      }
      for (const entry of saved.groups) {
        if (!groups.some((group) => group.device.flockUuid === entry.flockUuid)) groups.push(openZeroBrokerGroup({ home, group: entry, host, request, runAz, getToken }));
      }
      for (const group of groups) {
        if (stopping) break;
        try {
          await group.renewAndPrune();
          if (group.configuration().issuer) await group.retryPendingCloses();
          await group.runtime.refresh();
          await connect(group);
          await group.runtime.reconcilePending();
          await group.poll();
          await group.pollEnrollment();
          onStatus({ status: "ready", group: group.device.flockUuid });
        } catch { onStatus({ status: "degraded", group: group.device.flockUuid }); host.reportError({ status: "UNKNOWN", message: "Zero-Broker synchronization failed closed; queued work and recovery state retained" }); }
      }
      if (!stopping) await new Promise((resolve) => {
        const timer = setTimeout(done, intervalMs);
        function done() { clearTimeout(timer); signal?.removeEventListener("abort", done); resolve(); }
        signal?.addEventListener("abort", done, { once: true });
      });
    }
  } finally {
    stop();
    signal?.removeEventListener("abort", stop);
    await Promise.allSettled([...inFlight]);
    for (const group of groups) group.close();
  }
}
