import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { atomicJson, assertNoLinks, inspectProcess } from "./flock-lifecycle.mjs";
import { AzureTransport, azureEndpoints, parseAzureConnection, validateTransport, HUB } from "./flock-azure.mjs";
import { createDeviceIdentity, createOwnerState, createJoinCode, approveJoin, acceptWelcome,
  ownerFingerprint, canonical, encryptEnvelope, decryptEnvelope, DurableReceiver,
  createRotation, applyRotation, signedControl, verifyControl, renewOwnerCert, validateCert,
  verifyRosterMemberCert, verifyJoinCode, peerSubscription } from "./flock-protocol.mjs";
import { FlockMembershipRegistry, createSignedRosterSnapshot, createSignedRosterDelta } from "./flock-registry.mjs";

const hash = (value) => crypto.createHash("sha256").update(typeof value === "string" ? value : canonical(value)).digest("hex");
let processIdentity;
export class BrokerFreeRuntime {
  constructor(root, { transportFactory = (endpoints, options) => new AzureTransport(endpoints, options),
    clock = Date.now, connect, dispatch, log = (message) => process.stderr.write(`${message}\n`) } = {}) {
    this.root = assertNoLinks(root);
    this.filename = path.join(root, "broker-free.json");
    this.transportFactory = transportFactory;
    this.clock = clock;
    this.connect = connect;
    this.dispatch = dispatch;
    this.log = log;
    this.registry = new FlockMembershipRegistry(this.root, { clock: this.clock });
    this.serial = Promise.resolve();
  }
  read() {
    assertNoLinks(this.filename);
    const data = fs.existsSync(this.filename) ? JSON.parse(fs.readFileSync(this.filename, "utf8"))
      : { schema: 34, flocks: {}, pendingJoins: {} };
    if (data.schema !== 34 || !data.flocks || !data.pendingJoins) throw new Error("Invalid broker-free state; no legacy fallback");
    return data;
  }
  save(data) { atomicJson(this.filename, data); }
  async mutate(handler) {
    fs.mkdirSync(this.root, { recursive: true });
    const lock = path.join(this.root, "broker-free-mutation.lock");
    assertNoLinks(lock);
    if (fs.existsSync(lock)) {
      const before = fs.readFileSync(lock, "utf8");
      const previous = JSON.parse(before);
      if (previous.type !== "copilot-flock-mutation-lock-v1" || !previous.identity?.start) throw new Error("Unverifiable mutation lock requires reconciliation");
      const live = inspectProcess(previous.identity.pid);
      if (live && live.start === previous.identity.start) throw new Error("Broker-free mutation already in progress");
      if (JSON.stringify(inspectProcess(previous.identity.pid)) !== JSON.stringify(live) ||
          fs.readFileSync(assertNoLinks(lock), "utf8") !== before) throw new Error("Mutation lock changed during recovery");
      fs.unlinkSync(lock);
    }
    const fd = fs.openSync(lock, "wx", 0o600);
    let lockText;
    try {
      processIdentity ||= inspectProcess(process.pid);
      if (!processIdentity?.start) throw new Error("Cannot prove mutation process creation identity");
      lockText = JSON.stringify({ type: "copilot-flock-mutation-lock-v1", identity: processIdentity });
      fs.writeFileSync(fd, lockText);
      fs.fsyncSync(fd);
    } catch (error) { fs.closeSync(fd); fs.unlinkSync(lock); throw error; }
    try { return await handler(this.read()); }
    finally {
      fs.closeSync(fd);
      if (fs.readFileSync(assertNoLinks(lock), "utf8") !== lockText) throw new Error("Mutation lock ownership changed; retained");
      fs.unlinkSync(lock);
    }
  }
  record(flockId) {
    const record = this.read().flocks[flockId];
    if (!record || record.departed) throw new Error("Not an active broker-free flock");
    const anchorPath = this.anchorPath(flockId);
    if (fs.existsSync(anchorPath)) {
      const anchor = JSON.parse(fs.readFileSync(assertNoLinks(anchorPath), "utf8"));
      if (record.epoch < anchor.epoch || (record.epoch === anchor.epoch && record.rotationHash !== anchor.rotationHash)) {
        const transition = Object.values(record.transitions || {}).find((entry) => !entry.confirmed &&
          entry.rotation.body.epoch === anchor.epoch && hash(entry.rotation) === anchor.rotationHash);
        if (!transition || anchor.epoch !== record.epoch + 1) throw new Error("Persisted epoch/hash rollback rejected");
        const recovered = applyRotation(anchorPath, transition.rotation, record.identity, record);
        Object.assign(record, { epoch: recovered.epoch, keyId: recovered.keyId, groupKey: recovered.groupKey,
          minAcceptedEpoch: recovered.minAcceptedEpoch, rotationHash: recovered.rotationHash });
      }
    }
    return record;
  }
  anchorPath(flockId) { return path.join(this.root, `epoch-${hash(flockId)}.json`); }
  select(flockId) {
    if (flockId) return this.record(flockId);
    const records = Object.values(this.read().flocks).filter((record) => !record.departed);
    if (records.length !== 1) throw new Error("Select an explicit --flock; broker-free dispatch is ambiguous");
    return this.record(records[0].flockId);
  }
  transport(record) {
    return this.transportFactory(record.endpoints, { secrets: record.ownerSecrets || null, clock: this.clock });
  }
  assertOwner(record) {
    const latest = this.record(record.flockId);
    if (!latest.ownerSecrets || latest.localPeerId !== latest.rotationOwnerPeerId ||
        ownerFingerprint(latest.identity.ed25519.publicKey) !== latest.rotationOwnerPeerId ||
        latest.ownerPublicKey !== latest.identity.ed25519.publicKey) throw new Error("Designated owner's local cryptographic authority required");
    return latest;
  }
  refreshOwnerCredentials(record) {
    this._ensureOwnerRosterInitialized(record);
    if (record.cert.body.expiresAt < this.clock() + 300000) {
      record.cert = renewOwnerCert(record, record.identity, this.clock());
      record.transport = this.transport(record).credentials(record.cert, record.ownerPublicKey);
      const nextRev = (record.rosterRevision || 1) + 1;
      record.members[record.localPeerId] = {
        ...record.members[record.localPeerId],
        cert: record.cert,
        updatedAtRevision: nextRev,
      };
      const built = this._buildOwnerRosterArtifacts(record, { revision: nextRev });
      this._commitOwnerRoster(record, built.snapshot);
    }
    return record;
  }
  _compileOwnerMembersAndTombstones(record, { defaultEpoch = record.epoch, defaultRevision = record.rosterRevision || 1 } = {}) {
    const members = [];
    const tombstones = [];
    for (const [peerId, entry] of Object.entries(record.members || {})) {
      if (entry.removed) {
        tombstones.push({
          peerId,
          keyFingerprint: peerId,
          machineId: entry.cert.body.machineId,
          githubUser: null,
          removedAtMs: entry.removedAtMs ?? this.clock(),
          removedAtEpoch: entry.removedAtEpoch ?? defaultEpoch,
          removedAtRevision: entry.removedAtRevision ?? defaultRevision,
          reason: entry.removalReason || "removed",
          operationId: entry.removalOperationId || null,
        });
      } else {
        members.push({
          peerId,
          keyFingerprint: peerId,
          deviceEd25519Pub: entry.cert.body.deviceEd25519Pub,
          deviceX25519Pub: entry.cert.body.deviceX25519Pub,
          machineId: entry.cert.body.machineId,
          githubUser: null,
          role: entry.cert.body.role,
          scope: entry.cert.body.scope,
          membershipExpiresAtMs: entry.membershipExpiresAt ?? null,
          certIssuedAtMs: entry.cert.body.issuedAt,
          certExpiresAtMs: entry.cert.body.expiresAt,
          addedAtEpoch: entry.addedAtEpoch ?? 1,
          addedAtRevision: entry.addedAtRevision ?? 1,
          updatedAtRevision: entry.updatedAtRevision ?? 1,
        });
      }
    }
    return { members, tombstones };
  }
  _buildOwnerRosterArtifacts(record, {
    epoch = record.epoch,
    minAcceptedEpoch = record.minAcceptedEpoch || epoch,
    rotationHash = record.rotationHash || null,
    revision,
    membersOverride = null,
    tombstonesOverride = null,
  }) {
    const prevSnapshot = record.lastRosterSnapshot || null;
    const compiled = membersOverride && tombstonesOverride
      ? { members: membersOverride, tombstones: tombstonesOverride }
      : this._compileOwnerMembersAndTombstones(record, { defaultEpoch: epoch, defaultRevision: revision });
    const issuedAt = this.clock();
    const snapshot = createSignedRosterSnapshot({
      flockId: record.flockId,
      ownerIdentity: record.identity,
      epoch,
      minAcceptedEpoch,
      rotationHash,
      revision,
      previousRosterHash: prevSnapshot?.body.rosterHash || null,
      members: compiled.members,
      tombstones: compiled.tombstones,
      issuedAt,
    });
    let delta = null;
    if (prevSnapshot && (epoch > prevSnapshot.body.epoch || (epoch === prevSnapshot.body.epoch && revision > prevSnapshot.body.revision))) {
      const prevMembersByKey = new Map(prevSnapshot.body.members.map((m) => [m.identityKey, canonical(m)]));
      const prevTombsByKey = new Map(prevSnapshot.body.tombstones.map((t) => [t.identityKey, canonical(t)]));
      const upserts = snapshot.body.members.filter((m) => prevMembersByKey.get(m.identityKey) !== canonical(m));
      const removals = snapshot.body.tombstones.filter((t) => prevTombsByKey.get(t.identityKey) !== canonical(t));
      delta = createSignedRosterDelta({
        flockId: record.flockId,
        ownerIdentity: record.identity,
        baseEpoch: prevSnapshot.body.epoch,
        baseRevision: prevSnapshot.body.revision,
        baseRosterHash: prevSnapshot.body.rosterHash,
        epoch,
        minAcceptedEpoch,
        rotationHash,
        revision,
        upserts,
        removals,
        resultingMembers: snapshot.body.members,
        resultingTombstones: snapshot.body.tombstones,
        issuedAt,
      });
    }
    return { snapshot, delta };
  }
  _commitOwnerRoster(record, snapshot) {
    record.rosterRevision = snapshot.body.revision;
    record.rosterHash = snapshot.body.rosterHash;
    record.lastRosterSnapshot = snapshot;
    this.registry.applySignedSnapshot(snapshot, {
      ownerPublicKey: record.ownerPublicKey,
      expectedFlockId: record.flockId,
      minAcceptedEpoch: record.minAcceptedEpoch || 1,
      now: this.clock(),
    });
  }
  _ensureOwnerRosterInitialized(record) {
    if (!record?.ownerSecrets || record.localPeerId !== record.rotationOwnerPeerId) return;
    if (!record.lastRosterSnapshot) {
      const rev = record.rosterRevision || 1;
      const built = this._buildOwnerRosterArtifacts(record, { revision: rev });
      this._commitOwnerRoster(record, built.snapshot);
    } else if (!this.registry.hasFlock(record.flockId)) {
      this.registry.applySignedSnapshot(record.lastRosterSnapshot, {
        ownerPublicKey: record.ownerPublicKey,
        expectedFlockId: record.flockId,
        minAcceptedEpoch: record.minAcceptedEpoch || 1,
        now: this.clock(),
      });
    }
  }
  ensureRegistrySeeded(flockId) {
    const record = this.record(flockId);
    if (this.registry.hasFlock(record.flockId)) return;
    if (record.lastRosterSnapshot) {
      this.registry.applySignedSnapshot(record.lastRosterSnapshot, {
        ownerPublicKey: record.ownerPublicKey,
        expectedFlockId: record.flockId,
        minAcceptedEpoch: record.minAcceptedEpoch || 1,
        now: this.clock(),
      });
      return;
    }
    if (record.ownerSecrets && record.localPeerId === record.rotationOwnerPeerId) {
      this._ensureOwnerRosterInitialized(record);
    }
  }
  exportSignedRosterSnapshot(flockId) {
    const record = this.assertOwner(this.select(flockId));
    this._ensureOwnerRosterInitialized(record);
    return record.lastRosterSnapshot;
  }
  getFlockRegistryView(flockId, options = {}) {
    const record = this.select(flockId);
    this.ensureRegistrySeeded(record.flockId);
    return this.registry.getFlockView(record.flockId, options);
  }
  listRegisteredMembers(flockId, options = {}) {
    return this.getFlockRegistryView(flockId, options).members;
  }
  async syncRoster(flockId) {
    const record = this.select(flockId);
    if (record.localPeerId === record.rotationOwnerPeerId) {
      this._ensureOwnerRosterInitialized(record);
      return this.getFlockRegistryView(record.flockId);
    }
    const ownerMachine = record.members[record.rotationOwnerPeerId]?.cert.body.machineId;
    if (!ownerMachine) throw new Error("Pinned rotation owner route unavailable for roster sync");
    const response = await this.invoke({
      flockId: record.flockId,
      toMachine: ownerMachine,
      action: "roster_sync",
      params: {},
      timeoutMs: 10000,
    });
    return this.mutate(async (data) => {
      const latest = this.record(record.flockId);
      this.registry.applySignedSnapshot(response.result, {
        ownerPublicKey: latest.ownerPublicKey,
        expectedFlockId: latest.flockId,
        expectedOwnerFingerprint: ownerFingerprint(latest.ownerPublicKey),
        minAcceptedEpoch: latest.minAcceptedEpoch || 1,
        now: this.clock(),
      });
      latest.lastRosterSnapshot = response.result;
      latest.rosterRevision = response.result.body.revision;
      latest.rosterHash = response.result.body.rosterHash;
      data.flocks[latest.flockId] = latest;
      this.save(data);
      return this.registry.getFlockView(latest.flockId);
    });
  }
  assertActive(record) {
    const latest = this.record(record.flockId);
    validateCert(latest.cert, latest.ownerPublicKey, this.clock());
    validateTransport(latest.transport, latest.endpoints, latest.localPeerId, latest.cert.body.expiresAt, this.clock());
    return latest;
  }
  async initializeOwner({ flockId, machineId, scope, connectionString, manageConnectionString,
    sendConnectionString, listenConnectionString }) {
    return this.mutate(async (data) => {
      if (data.flocks[flockId]) throw new Error("Existing enrollment is not replaced by owner initialization");
      const signalr = parseAzureConnection(connectionString, "signalr");
      const manage = parseAzureConnection(manageConnectionString, "servicebus");
      const send = parseAzureConnection(sendConnectionString, "servicebus");
      const listen = parseAzureConnection(listenConnectionString, "servicebus");
      if (manage.rule !== "RootManageSharedAccessKey" || send.rule !== "FlockSendRule" ||
          listen.rule !== "FlockListenRule" || manage.endpoint !== send.endpoint || manage.endpoint !== listen.endpoint) {
        throw new Error("Owner Manage and separate Send-only/Listen-only policy credentials required");
      }
      const identity = createDeviceIdentity();
      const state = createOwnerState({ identity, flockId, machineId, scope, now: this.clock() });
      const record = { ...state, identity, endpoints: azureEndpoints(signalr.endpoint, manage.endpoint),
        ownerSecrets: { signalrKey: signalr.key, manageKey: manage.key, manageRule: manage.rule,
          sendKey: send.key, listenKey: listen.key }, members: {}, transitions: {}, departed: false,
        rosterSeq: 1, rosterUpdatedAt: this.clock() };
      data.flocks[flockId] = record;
      record.transport = this.transport(record).credentials(record.cert, record.ownerPublicKey);
      record.members[record.localPeerId] = { cert: record.cert, membershipExpiresAt: null, addedAtEpoch: 1, addedAtRevision: 1, updatedAtRevision: 1 };
      this.save(data); // Keep recovery for an interrupted subscription operation.
      record.transport = await this.transport(record).issue(record.cert, record.ownerPublicKey);
      record.members[record.localPeerId] = { cert: record.cert, membershipExpiresAt: null, addedAtEpoch: 1, addedAtRevision: 1, updatedAtRevision: 1 };
      const initialRoster = this._buildOwnerRosterArtifacts(record, { epoch: 1, minAcceptedEpoch: 1, revision: 1 });
      this._commitOwnerRoster(record, initialRoster.snapshot);
      this.save(data);
      return { flockId, peerId: record.localPeerId, ownerFingerprint: ownerFingerprint(record.ownerPublicKey), enrolled: true };
    });
  }
  async joinRequest({ machineId, scope, renewFlock = null, flockId = renewFlock }) {
    return this.mutate(async (data) => {
      if (typeof flockId !== "string" || !/^[a-z0-9-]+\/[a-z0-9-]+$/.test(flockId) ||
          flockId.length > 128 || (renewFlock && renewFlock !== flockId)) throw new Error("Join Code requires its explicit intended flock");
      const identity = renewFlock ? this.record(renewFlock).identity : createDeviceIdentity();
      const code = createJoinCode(identity, { machineId, scope, flockId }, this.clock());
      for (const [id, pending] of Object.entries(data.pendingJoins)) {
        if (pending.code.body.expiresAt <= this.clock()) delete data.pendingJoins[id];
      }
      if (Object.keys(data.pendingJoins).length >= 100) throw new Error("Too many pending Join Codes");
      data.pendingJoins[hash(code)] = { code, identity, renewFlock };
      this.save(data);
      return code;
    });
  }
  async approve({ flockId, code, role = "collaborator", sessionIds = [], membershipExpiresAt,
    expectedEd25519Fingerprint, renew = false }) {
    return this.mutate(async (data) => {
      let record = this.assertOwner(data.flocks[flockId] || {});
      record = this.refreshOwnerCredentials(record);
      data.flocks[flockId] = record;
      this.save(data);
      const join = verifyJoinCode(code, this.clock());
      if (join.flockId !== flockId) throw new Error("Join Code is bound to another flock");
      if (join.peerId !== expectedEd25519Fingerprint) throw new Error("Join identity policy requires the independently supplied Ed25519 fingerprint");
      const previous = record.members[join.peerId];
      for (const other of Object.values(data.flocks)) {
        if (other.endpoints.serviceBusEndpoint !== record.endpoints.serviceBusEndpoint) continue;
        const ids = new Set([other.localPeerId, ...Object.keys(other.members || {}), ...Object.keys(other.pendingApprovals || {})]);
        if ([...ids].some((id) => peerSubscription(id) === peerSubscription(join.peerId) &&
            (other.flockId !== flockId || id !== join.peerId))) throw new Error("Peer subscription collides with an existing membership");
      }
      if (Object.entries(record.members).some(([id, entry]) => id !== join.peerId && !entry.removed &&
          entry.cert.body.machineId.toLowerCase() === join.machineId.toLowerCase())) throw new Error("Duplicate machine name would make RPC dispatch ambiguous");
      if (!previous && Object.keys(record.members).length >= 100) throw new Error("Flock member limit exceeded");
      if (previous?.removed) throw new Error("Revoked membership cannot be renewed through a stale Join Code");
      if (renew) {
        if (!previous || previous.cert.body.deviceX25519Pub !== join.deviceX25519Pub ||
            previous.cert.body.scope !== join.scope) throw new Error("Renewal keys/scope not bound to retained member");
        role = previous.cert.body.role;
        sessionIds = previous.cert.body.sessionIds;
        membershipExpiresAt = previous.membershipExpiresAt;
      } else if (previous) throw new Error("Member already exists; use explicit renewal");
      if (role === "owner") throw new Error("Owner delegation is not a join operation");
      if (!Number.isSafeInteger(membershipExpiresAt) || membershipExpiresAt <= this.clock()) throw new Error("Explicit finite membership expiry required");
      let issuedCert;
      let nextRoster = null;
      const nextRevision = (record.rosterRevision || 1) + 1;
      const ticketMetadata = { endpoints: record.endpoints, rotationHash: record.rotationHash || null,
        ownerCert: record.cert, membershipExpiresAt };
      const otherRetainedPeers = Object.entries(record.members).filter(([id, entry]) =>
        id !== record.localPeerId && id !== join.peerId && !entry.removed);
      const ticket = await approveJoin({ code, ownerIdentity: record.identity, ownerPublicKey: record.ownerPublicKey,
        rotationOwnerPeerId: record.rotationOwnerPeerId, flockId, role, sessionIds, membershipExpiresAt,
        epoch: record.epoch, keyId: record.keyId, groupKey: Buffer.from(record.groupKey, "base64url"),
        metadata: ticketMetadata,
        authorizeOwner: async () => { record = this.assertOwner(record); },
        verifyIdentityPolicy: async () => {
          if (join.peerId !== expectedEd25519Fingerprint) throw new Error("Identity policy changed");
        },
        provisionTransport: async ({ cert }) => {
          issuedCert = cert;
          record.pendingApprovals ||= {};
          record.pendingApprovals[join.peerId] = { cert, membershipExpiresAt };
          data.flocks[flockId] = record;
          this.save(data);
          const issuedTransport = await this.transport(record).issue(cert, record.ownerPublicKey);
          const candidateRecord = {
            ...record,
            members: {
              ...record.members,
              [join.peerId]: {
                cert,
                membershipExpiresAt,
                addedAtEpoch: previous?.addedAtEpoch ?? record.epoch,
                addedAtRevision: previous?.addedAtRevision ?? nextRevision,
                updatedAtRevision: nextRevision,
              },
            },
          };
          nextRoster = this._buildOwnerRosterArtifacts(candidateRecord, { revision: nextRevision });
          ticketMetadata.rosterSnapshot = nextRoster.snapshot;
          return issuedTransport;
        }, now: this.clock() });
      record.members[join.peerId] = {
        cert: issuedCert,
        membershipExpiresAt,
        addedAtEpoch: previous?.addedAtEpoch ?? record.epoch,
        addedAtRevision: previous?.addedAtRevision ?? nextRevision,
        updatedAtRevision: nextRevision,
      };
      record.rosterSeq = (Number.isSafeInteger(record.rosterSeq) ? record.rosterSeq : 1) + 1;
      record.rosterUpdatedAt = this.clock();
      delete record.pendingApprovals[join.peerId];
      if (nextRoster) this._commitOwnerRoster(record, nextRoster.snapshot);
      data.flocks[flockId] = record;
      this.save(data);
      if (otherRetainedPeers.length > 0 && nextRoster?.delta) {
        try {
          await this.publish(record, { type: "roster-update", delta: nextRoster.delta });
        } catch (err) {
          this.log(`Broker-free roster delta broadcast deferred: ${err.message}`);
        }
      }
      return ticket;
    });
  }
  async accept(ticket, pinnedOwnerFingerprint) {
    return this.mutate(async (data) => {
    const pending = data.pendingJoins[ticket.body?.joinHash];
    if (!pending) throw new Error("No matching locally generated Join Code");
    if (pending.code.body.flockId !== ticket.body.flockId) throw new Error("Welcome Ticket changed the intended flock");
    const welcome = acceptWelcome(ticket, { identity: pending.identity, code: pending.code,
      pinnedOwnerFingerprint, now: this.clock() });
    const previous = data.flocks[ticket.body.flockId];
    if (previous && (previous.ownerPublicKey !== welcome.ownerPublicKey ||
        previous.localPeerId !== welcome.cert.body.peerId || previous.epoch > welcome.epoch ||
        (previous.epoch === welcome.epoch && (previous.rotationHash || null) !== welcome.metadata.rotationHash))) {
      throw new Error("Renewal owner/key/epoch/hash rollback rejected");
    }
    validateTransport(welcome.transport, welcome.metadata.endpoints, welcome.cert.body.peerId, welcome.cert.body.expiresAt, this.clock());
    const owner = validateCert(welcome.metadata.ownerCert, welcome.ownerPublicKey, this.clock());
    if (owner.peerId !== welcome.rotationOwnerPeerId || owner.role !== "owner" || owner.flockId !== welcome.cert.body.flockId) throw new Error("Unbound owner route");
    const record = { ...welcome, identity: pending.identity, endpoints: welcome.metadata.endpoints,
      flockId: welcome.cert.body.flockId, localPeerId: welcome.cert.body.peerId,
      minAcceptedEpoch: welcome.epoch, rotationHash: welcome.metadata.rotationHash,
      members: { [welcome.rotationOwnerPeerId]: { cert: welcome.metadata.ownerCert } }, transitions: {}, departed: false };
    if (welcome.metadata.rosterSnapshot) {
      this.registry.applySignedSnapshot(welcome.metadata.rosterSnapshot, {
        ownerPublicKey: welcome.ownerPublicKey,
        expectedFlockId: record.flockId,
        expectedOwnerFingerprint: pinnedOwnerFingerprint,
        minAcceptedEpoch: record.minAcceptedEpoch,
        now: this.clock(),
      });
      record.lastRosterSnapshot = welcome.metadata.rosterSnapshot;
      record.rosterRevision = welcome.metadata.rosterSnapshot.body.revision;
      record.rosterHash = welcome.metadata.rosterSnapshot.body.rosterHash;
    }
    data.flocks[record.flockId] = record;
    delete data.pendingJoins[ticket.body.joinHash];
    this.save(data);
    atomicJson(this.anchorPath(record.flockId), record);
    return { enrolled: true, flockId: record.flockId, peerId: record.localPeerId, role: record.cert.body.role };
    });
  }
  async renewMembership(flockId) {
    const record = this.record(flockId);
    if (record.localPeerId === record.rotationOwnerPeerId) return this.renewOwn(flockId);
    const code = await this.joinRequest({ machineId: record.cert.body.machineId, scope: record.cert.body.scope, renewFlock: flockId });
    const response = await this.invoke({ flockId, toMachine: record.members[record.rotationOwnerPeerId].cert.body.machineId,
      action: "renew", params: { code }, timeoutMs: 15000 });
    return this.accept(response.result, ownerFingerprint(record.ownerPublicKey));
  }
  async renewOwn(flockId) {
    return this.mutate(async (data) => {
      const record = this.assertOwner(data.flocks[flockId] || {});
      this._ensureOwnerRosterInitialized(record);
      record.cert = renewOwnerCert(record, record.identity, this.clock());
      record.transport = await this.transport(record).issue(record.cert, record.ownerPublicKey);
      const nextRev = (record.rosterRevision || 1) + 1;
      record.members[record.localPeerId] = {
        ...record.members[record.localPeerId],
        cert: record.cert,
        membershipExpiresAt: null,
        updatedAtRevision: nextRev,
      };
      const built = this._buildOwnerRosterArtifacts(record, { revision: nextRev });
      this._commitOwnerRoster(record, built.snapshot);
      data.flocks[flockId] = record;
      this.save(data);
    });
  }
  async publish(record, message) {
    this.assertActive(record);
    await this.transport(record).publish(record.transport, { ...message, flockId: record.flockId });
    this.assertActive(record);
  }
  async removePeer({ flockId, peerId, operationId = crypto.randomUUID(), selfLeave = false }) {
    return this.mutate(async (data) => {
      let record = this.assertOwner(data.flocks[flockId] || {});
      record = this.refreshOwnerCredentials(record);
      data.flocks[flockId] = record;
      this.save(data);
      const prior = record.transitions[operationId];
      if (prior?.peerId && prior.peerId !== peerId) throw new Error("Leave operation target changed");
      if (prior?.confirmed) return prior.receipt;
      const member = record.members[peerId];
      if (!member || (member.removed && !prior)) throw new Error("Unknown or already removed peer; explicit receipt required for retry");
      if (peerId === record.rotationOwnerPeerId && !selfLeave) throw new Error("Rotation owner removal requires its explicit self-leave");
      if (!prior) {
        const retained = Object.entries(record.members).filter(([id, entry]) => id !== peerId &&
          !entry.removed && entry.cert.body.expiresAt > this.clock()).map(([, entry]) => entry.cert);
        const rotation = createRotation(record, record.identity, retained, this.clock());
        const nextRev = (record.rosterRevision || 1) + 1;
        const removedAtMs = this.clock();
        record.members[peerId] = {
          ...record.members[peerId],
          removed: true,
          removedAtMs,
          removedAtEpoch: rotation.body.epoch,
          removedAtRevision: nextRev,
          removalReason: selfLeave ? "self_leave" : "removed",
          removalOperationId: operationId,
        };
        record.rosterSeq = (Number.isSafeInteger(record.rosterSeq) ? record.rosterSeq : 1) + 1;
        record.rosterUpdatedAt = removedAtMs;
        const rosterArtifacts = this._buildOwnerRosterArtifacts(record, {
          epoch: rotation.body.epoch,
          minAcceptedEpoch: rotation.body.epoch,
          rotationHash: hash(rotation),
          revision: nextRev,
        });
        record.transitions[operationId] = {
          peerId,
          rotation,
          rosterDelta: rosterArtifacts.delta,
          rosterSnapshot: rosterArtifacts.snapshot,
          confirmed: false,
        };
        // Advance the receiving owner's floor before any remote await.
        record.minAcceptedEpoch = rotation.body.epoch;
        data.flocks[flockId] = record;
        this.save(data);
      }
      const transition = record.transitions[operationId];
      if (selfLeave) {
        for (const id of Object.keys(record.pendingApprovals || {})) {
          await this.transport(record).subscription(id, "DELETE");
          this.assertOwner(record);
          delete record.pendingApprovals[id];
          data.flocks[flockId] = record;
          this.save(data);
        }
      }
      await this.transport(record).subscription(peerId, "DELETE");
      this.assertOwner(record);
      // The rotation is owner-signed and recipient-sealed; it is not encrypted under a revoked epoch.
      await this.transport(record).publish(record.transport, {
        type: "rotation",
        flockId,
        rotation: transition.rotation,
        ...(transition.rosterDelta ? { rosterDelta: transition.rosterDelta } : {}),
        ...(transition.rosterSnapshot ? { rosterSnapshot: transition.rosterSnapshot } : {}),
      });
      this.assertOwner(record);
      if (!selfLeave) {
        const next = applyRotation(this.anchorPath(flockId), transition.rotation, record.identity, {
          ...record, minAcceptedEpoch: record.epoch,
        });
        record = { ...record, epoch: next.epoch, keyId: next.keyId, groupKey: next.groupKey,
          minAcceptedEpoch: next.minAcceptedEpoch, rotationHash: next.rotationHash };
        if (transition.rosterSnapshot) this._commitOwnerRoster(record, transition.rosterSnapshot);
      }
      const receipt = signedControl("leave-receipt", { flockId, peerId, operationId,
        epoch: transition.rotation.body.epoch, confirmed: true, subscriptionDeleted: peerSubscription(peerId) }, record.identity);
      record.transitions[operationId] = { ...transition, confirmed: true, receipt };
      if (selfLeave) record.departed = true;
      data.flocks[flockId] = record;
      this.save(data);
      return receipt;
    });
  }
  async consume(record, message) {
    if (!message || Buffer.byteLength(JSON.stringify(message)) > 240 * 1024) throw new Error("Invalid or oversized broker-free wire message");
    if (message.flockId !== record.flockId) return true;
    if (message.type === "leave-receipt") {
      const body = verifyControl(message.receipt, record.ownerPublicKey, "leave-receipt");
      if (body.flockId !== record.flockId || !body.confirmed || body.subscriptionDeleted !== peerSubscription(body.peerId)) {
        throw new Error("Invalid leave receipt");
      }
      return true;
    }
    if (message.type === "roster-update") {
      return this.mutate(async (data) => {
        const latest = this.record(record.flockId);
        this.ensureRegistrySeeded(latest.flockId);
        const expectedOwnerFp = ownerFingerprint(latest.ownerPublicKey);
        if (message.delta) {
          try {
            const applied = this.registry.applySignedDelta(message.delta, {
              ownerPublicKey: latest.ownerPublicKey,
              expectedFlockId: latest.flockId,
              expectedOwnerFingerprint: expectedOwnerFp,
              minAcceptedEpoch: latest.minAcceptedEpoch || 1,
              now: this.clock(),
            });
            latest.rosterRevision = applied.rosterRevision;
            latest.rosterHash = applied.rosterHash;
            data.flocks[latest.flockId] = latest;
            this.save(data);
            return true;
          } catch (err) {
            if (err.code === "ROSTER_ROLLBACK_REJECTED") {
              this.log(`Broker-free stale roster delta ignored for ${latest.flockId}: ${err.message}`);
              return true;
            }
            if (err.code !== "ROSTER_DELTA_GAP" || !message.snapshot) {
              if (err.code === "ROSTER_DELTA_GAP") {
                this.log(`Broker-free roster delta gap for ${latest.flockId}; full snapshot sync required`);
                return true;
              }
              throw err;
            }
          }
        }
        if (message.snapshot) {
          try {
            const applied = this.registry.applySignedSnapshot(message.snapshot, {
              ownerPublicKey: latest.ownerPublicKey,
              expectedFlockId: latest.flockId,
              expectedOwnerFingerprint: expectedOwnerFp,
              minAcceptedEpoch: latest.minAcceptedEpoch || 1,
              now: this.clock(),
            });
            latest.lastRosterSnapshot = message.snapshot;
            latest.rosterRevision = applied.rosterRevision;
            latest.rosterHash = applied.rosterHash;
            data.flocks[latest.flockId] = latest;
            this.save(data);
          } catch (err) {
            if (err.code === "ROSTER_ROLLBACK_REJECTED") {
              this.log(`Broker-free stale roster snapshot ignored for ${latest.flockId}: ${err.message}`);
              return true;
            }
            throw err;
          }
        }
        return true;
      });
    }
    if (message.type === "leave-request") {
      if (record.localPeerId !== record.rotationOwnerPeerId) return true;
      const latest = this.assertOwner(record);
      const claimed = message.request?.body;
      const member = latest.members[claimed?.peerId];
      if (!member) throw new Error("Leave signer is not an enrolled device");
      const body = verifyControl(message.request, member.cert.body.deviceEd25519Pub, "device-leave");
      if (body.flockId !== latest.flockId || body.fromMachine !== member.cert.body.machineId ||
          !Number.isSafeInteger(body.issuedAt) || !Number.isSafeInteger(body.expiresAt) ||
          body.expiresAt <= this.clock() || body.issuedAt > this.clock() + 30000 ||
          body.expiresAt - body.issuedAt > 300000 || typeof body.operationId !== "string" ||
          !/^[a-zA-Z0-9-]{1,128}$/.test(body.operationId) || typeof body.requestId !== "string") {
        throw new Error("Signed leave proof target/lifetime mismatch");
      }
      const receipt = await this.removePeer({ flockId: latest.flockId, peerId: body.peerId, operationId: body.operationId });
      const current = this.assertOwner(latest);
      await this.transport(current).publish(current.transport, {
        type: "leave-receipt", flockId: latest.flockId, requestId: body.requestId, receipt });
      return true;
    }
    if (message.type === "rotation") {
      return this.mutate(async (data) => {
        const latest = this.record(record.flockId);
        const next = applyRotation(this.anchorPath(record.flockId), message.rotation, latest.identity, latest);
        const updated = { ...latest, epoch: next.epoch, keyId: next.keyId,
          groupKey: next.groupKey, rotationHash: next.rotationHash, minAcceptedEpoch: next.minAcceptedEpoch };
        const expectedOwnerFp = ownerFingerprint(updated.ownerPublicKey);
        if (message.rosterDelta || message.rosterSnapshot) {
          let rosterApplied = false;
          if (message.rosterDelta && this.registry.hasFlock(updated.flockId)) {
            try {
              const res = this.registry.applySignedDelta(message.rosterDelta, {
                ownerPublicKey: updated.ownerPublicKey,
                expectedFlockId: updated.flockId,
                expectedOwnerFingerprint: expectedOwnerFp,
                minAcceptedEpoch: updated.minAcceptedEpoch,
                now: this.clock(),
              });
              updated.rosterRevision = res.rosterRevision;
              updated.rosterHash = res.rosterHash;
              rosterApplied = true;
            } catch (err) {
              if (err.code !== "ROSTER_DELTA_GAP") throw err;
            }
          }
          if (!rosterApplied && message.rosterSnapshot) {
            const res = this.registry.applySignedSnapshot(message.rosterSnapshot, {
              ownerPublicKey: updated.ownerPublicKey,
              expectedFlockId: updated.flockId,
              expectedOwnerFingerprint: expectedOwnerFp,
              minAcceptedEpoch: updated.minAcceptedEpoch,
              now: this.clock(),
            });
            updated.lastRosterSnapshot = message.rosterSnapshot;
            updated.rosterRevision = res.rosterRevision;
            updated.rosterHash = res.rosterHash;
          }
        }
        data.flocks[record.flockId] = updated;
        this.save(data);
        return true;
      });
    }
    if (message.type !== "envelope" || !message.envelope) throw new Error("Unknown broker-free wire message");
    const envelope = message.envelope;
    const fresh = this.record(record.flockId);
    const decoded = decryptEnvelope(envelope, fresh, this.clock());
    if (decoded.payload.toMachine && decoded.payload.toMachine !== "*" &&
        decoded.payload.toMachine.toLowerCase() !== fresh.cert.body.machineId.toLowerCase()) return true;
    if (envelope.header.action === "rpc_response") return true; // Responses are admitted by the correlated caller.
    const receiver = new DurableReceiver(path.join(this.root, `replay-${hash(record.flockId)}.json`),
      () => this.record(record.flockId), this.clock);
    try {
      await receiver.dispatch(envelope, async ({ member, payload, header, assertAuthorized }) => {
        this.assertActive(this.record(record.flockId));
        if (typeof payload.requestId !== "string" || payload.requestId !== header.messageId ||
            payload.fromMachine !== member.machineId) throw new Error("RPC request identity binding mismatch");
        if (this.registry.hasFlock(fresh.flockId)) {
          try {
            this.registry.recordPresence(fresh.flockId, [{
              peerId: member.peerId,
              machineId: member.machineId,
              observedAtMs: this.clock(),
              liveVerified: true,
            }], { now: this.clock() });
          } catch {}
        }
        let result;
        let error;
        try {
          assertAuthorized();
          if (header.action === "leave") {
            if (fresh.localPeerId !== fresh.rotationOwnerPeerId || payload.params.peerId !== member.peerId) throw new Error("Leave must target this signed device at the designated owner");
            result = await this.removePeer({ flockId: fresh.flockId, peerId: member.peerId,
              operationId: payload.params.operationId });
          } else if (header.action === "renew") {
            if (fresh.localPeerId !== fresh.rotationOwnerPeerId) throw new Error("Renewal requires designated owner");
            const join = verifyJoinCode(payload.params.code, this.clock());
            if (join.peerId !== member.peerId) throw new Error("Renewal cannot change device identity");
            result = await this.approve({ flockId: fresh.flockId, code: payload.params.code, renew: true,
              expectedEd25519Fingerprint: member.peerId });
          } else if (header.action === "list_roster") {
            if (fresh.localPeerId !== fresh.rotationOwnerPeerId) throw new Error("Roster snapshot requires designated owner");
            if (member.role !== "owner" && member.role !== "collaborator") throw new Error("Member role/session scope forbids this action");
            result = this.buildRosterSnapshot(fresh, this.clock());
          } else if (header.action === "roster_sync") {
            if (fresh.localPeerId !== fresh.rotationOwnerPeerId) throw new Error("Roster sync requires designated owner");
            result = this.exportSignedRosterSnapshot(fresh.flockId);
          } else {
            if (!this.dispatch) throw new Error("Local broker-free RPC dispatcher unavailable");
            result = await this.dispatch({ member, payload, action: header.action, assertAuthorized, flockId: fresh.flockId });
          }
          if (header.action !== "leave") assertAuthorized();
        } catch (failure) { error = failure.message; }
        // Leave may have rotated away the departing peer: its receipt is separately owner-signed.
        if (header.action === "leave" && result) {
          await this.transport(this.record(fresh.flockId)).publish(this.record(fresh.flockId).transport,
            { type: "leave-receipt", flockId: fresh.flockId, requestId: payload.requestId, receipt: result });
        } else {
          const current = this.assertActive(this.record(fresh.flockId));
          const response = encryptEnvelope({ state: current, identity: current.identity, cert: current.cert,
            action: "rpc_response", payload: { requestId: payload.requestId, fromMachine: current.cert.body.machineId,
              ...(error ? { error } : { result: result ?? null }) }, targetPeerId: member.peerId, now: this.clock() });
          await this.publish(current, { type: "envelope", envelope: response });
          assertAuthorized();
        }
      }, envelope.header.action === "leave" ? () => {
        const latest = this.record(fresh.flockId);
        const receipt = latest.transitions[decoded.payload.params.operationId]?.receipt;
        const confirmed = verifyControl(receipt, latest.ownerPublicKey, "leave-receipt");
        if (!confirmed.confirmed || confirmed.peerId !== decoded.member.peerId ||
            confirmed.epoch !== latest.epoch) throw new Error("Leave transition completion not committed");
      } : null);
      return true;
    } catch (failure) {
      // Duplicate complete/quarantined admission is acknowledged, never dispatched twice.
      const ledgerPath = path.join(this.root, `replay-${hash(record.flockId)}.json`);
      const ledger = fs.existsSync(ledgerPath) ? JSON.parse(fs.readFileSync(ledgerPath, "utf8")) : {};
      const id = `${envelope.header.flockId}:${envelope.header.peerId}:${envelope.header.messageId}`;
      if (!ledger[id]) throw failure;
      this.log(`Broker-free admission retained (${ledger[id].status}): ${failure.message}`);
      return true;
    }
  }
  async invoke({ flockId, toMachine = "*", action, params = {}, timeoutMs = 8000, collectAll = false }) {
    const record = this.assertActive(this.select(flockId));
    if (!this.connect) throw new Error("Broker-free WebSocket adapter unavailable");
    const requestId = crypto.randomUUID();
    const responses = [];
    let settle;
    let reject;
    const responsePromise = new Promise((resolve, fail) => { settle = resolve; reject = fail; });
    responsePromise.catch(() => {}); // The socket can reject while the queue-first send is still awaited.
    const expectedPeer = Object.entries(record.members).find(([, entry]) =>
      !entry.removed && entry.cert.body.machineId.toLowerCase() === toMachine.toLowerCase())?.[0] ||
      (this.registry.hasFlock(record.flockId)
        ? this.registry.listMembers(record.flockId).find((m) => !m.removed && m.machineId.toLowerCase() === toMachine.toLowerCase())?.peerId
        : undefined);
    const client = await this.connect(this.clientConfig(record), { userId: record.localPeerId,
      onInvocation: (target, args) => {
        if (target !== "flock34" || args[0]?.flockId !== record.flockId) return;
        try {
          const message = args[0];
          if (action === "leave" && message.type === "leave-receipt" && message.requestId === requestId) {
            const receipt = verifyControl(message.receipt, record.ownerPublicKey, "leave-receipt");
            if (receipt.flockId !== record.flockId || receipt.peerId !== record.localPeerId ||
                receipt.operationId !== params.operationId || !receipt.confirmed ||
                receipt.subscriptionDeleted !== peerSubscription(record.localPeerId)) throw new Error("Leave receipt target mismatch");
            settle({ result: message.receipt, fromMachine: toMachine, requestId });
            return;
          }
          if (message.type !== "envelope" || message.envelope.header.action !== "rpc_response") return;
          const { payload, member } = decryptEnvelope(message.envelope, this.record(record.flockId), this.clock());
          if (payload.requestId !== requestId || payload.fromMachine !== member.machineId ||
              (expectedPeer && member.peerId !== expectedPeer) ||
              (toMachine !== "*" && toMachine.toLowerCase() !== member.machineId.toLowerCase())) return;
          if ((action === "renew" || action === "leave" || action === "roster_sync") && member.peerId !== record.rotationOwnerPeerId) throw new Error("Control response not from designated owner");
          const receiver = new DurableReceiver(path.join(this.root, `responses-${hash(record.flockId)}.json`),
            () => this.record(record.flockId), this.clock);
          this.serial = this.serial.then(() => receiver.dispatch(message.envelope, async () => payload)).then(() => {
            if (this.registry.hasFlock(record.flockId)) {
              try {
                this.registry.recordPresence(record.flockId, [{
                  peerId: member.peerId,
                  machineId: member.machineId,
                  observedAtMs: this.clock(),
                  version: payload.result?.version ?? null,
                  activeSessionCount: payload.result?.activeSessionCount ?? null,
                  liveVerified: true,
                }], { now: this.clock() });
              } catch {}
            }
            if (!responses.some((response) => response.fromMachine === payload.fromMachine)) responses.push(payload);
            if (!collectAll) settle(payload);
          }).catch((error) => { this.log(`Broker-free response admission rejected: ${error.message}`); reject(error); });
        } catch (error) { reject(error); }
      },
    });
    let timer;
    try {
      if (action === "leave") {
        if (params.peerId !== record.localPeerId) throw new Error("Signed leave can target only this local device");
        const request = signedControl("device-leave", { requestId, flockId: record.flockId,
          peerId: record.localPeerId, operationId: params.operationId, fromMachine: record.cert.body.machineId,
          issuedAt: this.clock(), expiresAt: this.clock() + 300000 }, record.identity);
        await this.publish(record, { type: "leave-request", request });
      } else {
        const payload = { requestId, fromMachine: record.cert.body.machineId, toMachine, params };
        const envelope = encryptEnvelope({ state: record, identity: record.identity, cert: record.cert,
          action, payload, targetPeerId: expectedPeer || "*", now: this.clock(), messageId: requestId });
        await this.publish(record, { type: "envelope", envelope });
      }
      const timeout = new Promise((resolve, fail) => {
        timer = setTimeout(() => collectAll ? resolve(responses) : fail(new Error("Broker-free RPC timed out; queued dispatch may be pending or quarantined")), Math.min(120000, Math.max(100, timeoutMs)));
      });
      const result = await Promise.race([collectAll ? timeout : responsePromise, timeout]);
      if (!collectAll && result.error) throw new Error(result.error);
      return result;
    } finally { clearTimeout(timer); client.close(); }
  }
  clientConfig(record) {
    this.assertActive(record);
    return { protocol: "broker-free-v34", endpoint: record.endpoints.signalrEndpoint,
      host: new URL(record.endpoints.signalrEndpoint).hostname, hub: HUB,
      clientToken: record.transport.signalrClientToken, credentialExpiresAt: record.transport.expiresAt };
  }
  async start() {
    if (!this.connect) throw new Error("Broker-free WebSocket adapter unavailable");
    const clients = [];
    const timers = [];
    let stopped = false;
    const enqueue = (flockId, message) => {
      const pending = this.serial.then(() => this.consume(this.record(flockId), message));
      this.serial = pending.catch((error) => { this.log(`Broker-free receive rejected: ${error.message}`); });
      return pending;
    };
    try {
    for (const initial of Object.values(this.read().flocks).filter((record) => !record.departed)) {
      let record = initial;
      if (record.localPeerId === record.rotationOwnerPeerId && record.cert.body.expiresAt < this.clock() + 300000) {
        await this.renewOwn(record.flockId);
        record = this.record(record.flockId);
      }
      const open = async () => {
        const current = this.assertActive(this.record(record.flockId));
        return this.connect(this.clientConfig(current), { userId: current.localPeerId,
          onInvocation: (target, args) => { if (target === "flock34") enqueue(current.flockId, args[0]).catch(() => {}); },
          onClose: () => { if (!stopped) this.log(`Broker-free connection closed for ${current.flockId}; reconnecting on next poll`); },
        });
      };
      let client = await open();
      clients.push(() => client.close());
      let polling = false;
      const poll = async () => {
        if (polling || stopped) return;
        polling = true;
        try {
        let current = this.record(record.flockId);
        if (current.transport.expiresAt < this.clock() + 300000) {
          await this.renewMembership(current.flockId);
          current = this.record(current.flockId);
          client.close();
          client = await open();
        }
        this.assertActive(current);
        if (client.ws?.closed) client = await open();
        await this.transport(current).drain(current.transport, (message) => enqueue(current.flockId, message));
        } finally { polling = false; }
      };
      await poll();
      const timer = setInterval(() => { poll().catch((error) => this.log(`Broker-free queue/renewal pending: ${error.message}`)); }, 15000);
      timers.push(timer);
    }
    } catch (error) {
      stopped = true;
      timers.forEach(clearInterval);
      clients.forEach((close) => close());
      await this.serial;
      throw error;
    }
    return { close: async () => { stopped = true; timers.forEach(clearInterval); clients.forEach((close) => close()); await this.serial; } };
  }
  async leaveAll() {
    const results = [];
    for (const record of Object.values(this.read().flocks).filter((entry) => !entry.departed)) {
      const operationId = record.leaveOperationId || crypto.randomUUID();
      await this.mutate(async (data) => { data.flocks[record.flockId].leaveOperationId = operationId; this.save(data); });
      try {
        let receipt;
        if (record.localPeerId === record.rotationOwnerPeerId) {
          receipt = await this.removePeer({ flockId: record.flockId, peerId: record.localPeerId, operationId, selfLeave: true });
        } else {
          const owner = record.members[record.rotationOwnerPeerId]?.cert.body.machineId;
          if (!owner) throw new Error("Pinned rotation owner route unavailable");
          const response = await this.invoke({ flockId: record.flockId, toMachine: owner, action: "leave",
            params: { peerId: record.localPeerId, operationId }, timeoutMs: 15000 });
          receipt = response.result;
          verifyControl(receipt, record.ownerPublicKey, "leave-receipt");
          await this.mutate(async (data) => { data.flocks[record.flockId].departed = true;
            data.flocks[record.flockId].leaveReceipt = receipt;
            for (const [id, pending] of Object.entries(data.pendingJoins)) {
              if (pending.code.body.flockId === record.flockId && pending.code.body.peerId === record.localPeerId) delete data.pendingJoins[id];
            }
            this.save(data); });
        }
        results.push({ flockId: record.flockId, confirmed: true, receipt });
      } catch (error) { results.push({ flockId: record.flockId, confirmed: false, error: error.message }); }
    }
    return results;
  }
  buildRosterSnapshot(record, now = this.clock()) {
    const latest = this.assertOwner(record);
    const members = [];
    for (const [peerId, entry] of Object.entries(latest.members || {})) {
      if (!entry || entry.removed) continue;
      if (entry.membershipExpiresAt !== null && entry.membershipExpiresAt !== undefined &&
          entry.membershipExpiresAt <= now) continue;
      const verified = verifyRosterMemberCert(entry.cert, latest.ownerPublicKey, latest.flockId, now);
      if (verified.peerId !== peerId) continue;
      members.push({
        peerId: verified.peerId,
        machineId: verified.machineId,
        role: verified.role,
        scope: verified.scope,
        issuedAt: verified.issuedAt,
        certExpiresAt: verified.expiresAt,
        membershipExpiresAt: Number.isSafeInteger(entry.membershipExpiresAt) ? entry.membershipExpiresAt : null,
      });
    }
    members.sort((a, b) => (a.peerId < b.peerId ? -1 : a.peerId > b.peerId ? 1 : 0));
    return signedControl("roster-snapshot", {
      flockId: latest.flockId,
      epoch: latest.epoch,
      rosterSeq: Number.isSafeInteger(latest.rosterSeq) ? latest.rosterSeq : 1,
      rotationHash: latest.rotationHash || null,
      issuedAt: now,
      members,
    }, latest.identity);
  }
  localVerifiedCertMembers(record, now = this.clock()) {
    const out = new Map();
    const ownerCert = record.members?.[record.rotationOwnerPeerId]?.cert;
    if (ownerCert) {
      const owner = verifyRosterMemberCert(ownerCert, record.ownerPublicKey, record.flockId, now);
      out.set(owner.peerId, {
        peerId: owner.peerId,
        machineId: owner.machineId,
        role: owner.role,
        scope: owner.scope,
        issuedAt: owner.issuedAt,
        certExpiresAt: owner.expiresAt,
        credentialExpired: owner.credentialExpired,
        membershipExpiresAt: null,
      });
    }
    const selfExp = record.metadata?.membershipExpiresAt ?? null;
    if (selfExp === null || selfExp > now) {
      const self = verifyRosterMemberCert(record.cert, record.ownerPublicKey, record.flockId, now);
      out.set(self.peerId, {
        peerId: self.peerId,
        machineId: self.machineId,
        role: self.role,
        scope: self.scope,
        issuedAt: self.issuedAt,
        certExpiresAt: self.expiresAt,
        credentialExpired: self.credentialExpired,
        membershipExpiresAt: Number.isSafeInteger(selfExp) ? selfExp : null,
      });
    }
    return [...out.values()];
  }
  async inspectRoster(flockId, { refresh = true, timeoutMs = 2000 } = {}) {
    let record = this.select(flockId);
    const now = this.clock();
    const evaluatedAt = new Date(now).toISOString();
    if (record.localPeerId === record.rotationOwnerPeerId) {
      const latest = this.assertOwner(record);
      const members = [];
      for (const [peerId, entry] of Object.entries(latest.members || {})) {
        if (!entry || entry.removed) continue;
        if (entry.membershipExpiresAt !== null && entry.membershipExpiresAt !== undefined &&
            entry.membershipExpiresAt <= now) continue;
        const verified = verifyRosterMemberCert(entry.cert, latest.ownerPublicKey, latest.flockId, now);
        if (verified.peerId !== peerId) continue;
        members.push({
          peerId: verified.peerId,
          machineId: verified.machineId,
          role: verified.role,
          scope: verified.scope,
          issuedAt: verified.issuedAt,
          certExpiresAt: verified.expiresAt,
          credentialExpired: verified.credentialExpired,
          membershipExpiresAt: Number.isSafeInteger(entry.membershipExpiresAt) ? entry.membershipExpiresAt : null,
        });
      }
      members.sort((a, b) => (a.peerId < b.peerId ? -1 : a.peerId > b.peerId ? 1 : 0));
      const warnings = [];
      const pendingTransitionCount = Object.values(latest.transitions || {}).filter((t) => !t.confirmed).length;
      const pendingApprovalCount = Object.keys(latest.pendingApprovals || {}).length;
      if (pendingTransitionCount > 0) warnings.push(`${pendingTransitionCount} removal transition(s) pending completion`);
      if (pendingApprovalCount > 0) warnings.push(`${pendingApprovalCount} join approval(s) interrupted before completion`);
      const incomplete = pendingTransitionCount > 0 || pendingApprovalCount > 0;
      const fetchedMs = latest.rosterUpdatedAt || latest.cert.body.issuedAt || now;
      return {
        flockId: latest.flockId,
        localPeerId: latest.localPeerId,
        role: latest.cert.body.role,
        ownerFingerprint: ownerFingerprint(latest.ownerPublicKey),
        source: "broker_free_owner_authority",
        sources: {
          ownerAuthority: {
            attempted: true,
            ok: true,
            status: incomplete ? "incomplete" : "ok",
            fetchedAt: new Date(fetchedMs).toISOString(),
            error: null,
          },
        },
        freshness: {
          fetchedAt: new Date(fetchedMs).toISOString(),
          evaluatedAt,
          stale: false,
          rosterEpoch: latest.epoch,
          rosterSeq: Number.isSafeInteger(latest.rosterSeq) ? latest.rosterSeq : 1,
        },
        refresh: {
          status: incomplete ? "incomplete" : "ok",
          complete: !incomplete,
          incomplete,
          failed: false,
          errors: [],
          warnings,
        },
        members,
      };
    }

    const selfExp = record.metadata?.membershipExpiresAt ?? null;
    if (selfExp !== null && selfExp <= now) {
      throw new Error(`Membership in flock "${record.flockId}" has expired`);
    }
    const localRole = verifyRosterMemberCert(record.cert, record.ownerPublicKey, record.flockId, now).role;
    if (localRole === "guest") {
      const members = this.localVerifiedCertMembers(record, now);
      return {
        flockId: record.flockId,
        localPeerId: record.localPeerId,
        role: localRole,
        ownerFingerprint: ownerFingerprint(record.ownerPublicKey),
        source: "broker_free_local_certs",
        sources: {
          localBrokerFreeState: {
            attempted: true,
            ok: true,
            status: "local_only",
            fetchedAt: new Date(record.cert.body.issuedAt).toISOString(),
            error: null,
          },
        },
        freshness: {
          fetchedAt: new Date(record.cert.body.issuedAt).toISOString(),
          evaluatedAt,
          stale: false,
          rosterEpoch: record.epoch,
          rosterSeq: null,
        },
        refresh: {
          status: "local_only",
          complete: true,
          incomplete: false,
          failed: false,
          errors: [],
          warnings: ["Guest membership is scoped to owner route only; sibling roster enumeration is forbidden"],
        },
        members,
      };
    }

    const errors = [];
    const warnings = [];
    let rpcAttempted = false;
    if (refresh !== false && this.connect) {
      rpcAttempted = true;
      const ownerMachine = record.members?.[record.rotationOwnerPeerId]?.cert?.body?.machineId;
      try {
        if (!ownerMachine) throw new Error("Pinned rotation owner route unavailable");
        const response = await this.invoke({
          flockId: record.flockId,
          toMachine: ownerMachine,
          action: "list_roster",
          timeoutMs,
        });
        const latest = this.record(record.flockId);
        const snapshotBody = verifyControl(response.result, latest.ownerPublicKey, "roster-snapshot");
        if (snapshotBody.flockId !== latest.flockId ||
            !Number.isSafeInteger(snapshotBody.epoch) ||
            snapshotBody.epoch < latest.epoch ||
            !Array.isArray(snapshotBody.members)) {
          throw new Error("Owner roster snapshot failed flock/epoch verification");
        }
        if (latest.rosterSnapshot) {
          const prevBody = verifyControl(latest.rosterSnapshot, latest.ownerPublicKey, "roster-snapshot");
          if (snapshotBody.epoch < prevBody.epoch ||
              (snapshotBody.epoch === prevBody.epoch &&
                (snapshotBody.rosterSeq || 0) < (prevBody.rosterSeq || 0))) {
            throw new Error("Owner roster snapshot rollback rejected");
          }
        }
        await this.mutate(async (data) => {
          if (data.flocks[latest.flockId] && !data.flocks[latest.flockId].departed) {
            data.flocks[latest.flockId].rosterSnapshot = response.result;
            data.flocks[latest.flockId].rosterFetchedAt = now;
            this.save(data);
          }
        });
        record = this.record(record.flockId);
        const members = snapshotBody.members
          .filter((m) => m.membershipExpiresAt === null || m.membershipExpiresAt > now)
          .map((m) => ({
            ...m,
            credentialExpired: m.certExpiresAt <= now,
          }));
        const fetchedIso = new Date(now).toISOString();
        return {
          flockId: record.flockId,
          localPeerId: record.localPeerId,
          role: localRole,
          ownerFingerprint: ownerFingerprint(record.ownerPublicKey),
          source: "broker_free_owner_synced",
          sources: {
            ownerRosterRpc: {
              attempted: true,
              ok: true,
              status: "ok",
              fetchedAt: fetchedIso,
              error: null,
            },
          },
          freshness: {
            fetchedAt: fetchedIso,
            evaluatedAt,
            stale: false,
            rosterEpoch: snapshotBody.epoch,
            rosterSeq: snapshotBody.rosterSeq,
          },
          refresh: {
            status: "ok",
            complete: true,
            incomplete: false,
            failed: false,
            errors: [],
            warnings: [],
          },
          members,
        };
      } catch (err) {
        errors.push(err.message);
        record = this.record(record.flockId);
      }
    } else if (refresh !== false && !this.connect) {
      warnings.push("Broker-free WebSocket adapter unavailable; live owner roster sync skipped");
    }

    if (record.rosterSnapshot) {
      try {
        const snapshotBody = verifyControl(record.rosterSnapshot, record.ownerPublicKey, "roster-snapshot");
        if (snapshotBody.flockId !== record.flockId) {
          throw new Error("Cached roster snapshot flock mismatch");
        }
        if (snapshotBody.epoch < record.epoch) {
          warnings.push(`Cached roster snapshot at epoch ${snapshotBody.epoch} predates current epoch ${record.epoch}; stale members withheld`);
        } else {
          const members = snapshotBody.members
            .filter((m) => m.membershipExpiresAt === null || m.membershipExpiresAt > now)
            .map((m) => ({
              ...m,
              credentialExpired: m.certExpiresAt <= now,
            }));
          const fetchedMs = record.rosterFetchedAt || snapshotBody.issuedAt;
          return {
            flockId: record.flockId,
            localPeerId: record.localPeerId,
            role: localRole,
            ownerFingerprint: ownerFingerprint(record.ownerPublicKey),
            source: "broker_free_cached_snapshot",
            sources: {
              ...(rpcAttempted ? {
                ownerRosterRpc: {
                  attempted: true,
                  ok: false,
                  status: "failed",
                  fetchedAt: null,
                  error: errors[0] || "Owner roster sync failed",
                },
              } : {}),
              localBrokerFreeState: {
                attempted: true,
                ok: true,
                status: "cached",
                fetchedAt: fetchedMs ? new Date(fetchedMs).toISOString() : null,
                error: null,
              },
            },
            freshness: {
              fetchedAt: fetchedMs ? new Date(fetchedMs).toISOString() : null,
              evaluatedAt,
              stale: true,
              rosterEpoch: record.epoch,
              rosterSeq: snapshotBody.rosterSeq,
            },
            refresh: {
              status: errors.length ? "failed" : "incomplete",
              complete: false,
              incomplete: true,
              failed: errors.length > 0,
              errors,
              warnings,
            },
            members,
          };
        }
      } catch (snapErr) {
        warnings.push(`Cached roster snapshot invalid: ${snapErr.message}`);
      }
    }

    const members = this.localVerifiedCertMembers(record, now);
    return {
      flockId: record.flockId,
      localPeerId: record.localPeerId,
      role: localRole,
      ownerFingerprint: ownerFingerprint(record.ownerPublicKey),
      source: "broker_free_local_certs",
      sources: {
        ...(rpcAttempted ? {
          ownerRosterRpc: {
            attempted: true,
            ok: false,
            status: "failed",
            fetchedAt: null,
            error: errors[0] || "Owner roster sync failed",
          },
        } : {}),
        localBrokerFreeState: {
          attempted: true,
          ok: true,
          status: "local_certs_only",
          fetchedAt: null,
          error: null,
        },
      },
      freshness: {
        fetchedAt: null,
        evaluatedAt,
        stale: true,
        rosterEpoch: record.epoch,
        rosterSeq: null,
      },
      refresh: {
        status: errors.length ? "failed" : "incomplete",
        complete: false,
        incomplete: true,
        failed: errors.length > 0,
        errors,
        warnings,
      },
      members,
    };
  }
}
