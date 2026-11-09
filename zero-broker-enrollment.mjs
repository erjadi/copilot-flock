import fs from "node:fs";
import path from "node:path";
import * as api from "./zero-broker-roster.mjs";
import { cloudRequest, fetchPublicRosterChain } from "./zero-broker-transport.mjs";

function check(condition, message) {
  if (!condition) throw new Error(message);
}

export async function claimZeroBrokerVoucher({ home, invitation, verifiedRootFingerprint, githubUser, request = cloudRequest, now = Date.now }) {
  check(invitation.type === "copilot-flock-zero-broker-voucher-v1" && invitation.rootFingerprint === verifiedRootFingerprint, "Voucher bootstrap requires an independently verified root fingerprint");
  const voucher = invitation.voucher;
  check(/^[0-9a-f-]{36}$/.test(voucher.flockUuid), "Invalid provisional flock UUID");
  const directory = path.join(home, "zero-broker", voucher.flockUuid);
  const device = api.createDeviceKeys({ directory, flockUuid: voucher.flockUuid });
  const configPath = path.join(home, "config.json");
  const config = fs.existsSync(configPath) ? api.readPrivateJson(home, "config.json") : { architecture: "zero-broker", machineId: device.opaquePeerId, scope: "personal", groups: [] };
  check(config.architecture === "zero-broker", "Existing legacy installation cannot be silently migrated");
  const state = api.createRosterState({ directory });
  try {
    const pinned = state.get(voucher.flockUuid) || invitation.genesis;
    api.verifyRosterChain(pinned, [], now(), { pinnedRootFingerprint: verifiedRootFingerprint, state, requireFresh: false });
    const fetched = await fetchPublicRosterChain({ rosterUrl: voucher.rosterUrl, trustedRoster: pinned, request });
    const current = api.verifyRosterChain(pinned, fetched.transitions, now(), { state });
    const existing = current.members.find((member) => member.opaquePeerId === device.opaquePeerId);
    if (existing) {
      check(!existing.membershipExpiresAt || Date.parse(existing.membershipExpiresAt) > now(), "Admitted membership has expired; a new approved invitation is required");
      api.openSealedBundle({ bundle: existing.sealedMemberBundle, recipientEncPrivPem: device.encPriv, flockUuid: current.flockUuid, rosterEpoch: current.rosterEpoch, recipientOpaquePeerId: device.opaquePeerId, bundleType: "member" });
      api.writePrivateJson(directory, "configuration.json", { issuer: false, shared: true, sameOwner: false, rosterUrl: voucher.rosterUrl, provisional: false });
      return { enrolled: true, provisional: false, opaquePeerId: device.opaquePeerId, rosterEpoch: current.rosterEpoch };
    }
    const claim = api.createEnrollmentClaim({ voucher, device, githubUser });
    const proof = api.verifyEnrollmentClaimProof({ roster: current, voucher, claim, nowMs: now() });
    const issuer = current.members.find((member) => member.opaquePeerId === voucher.ownerSignature.signedByOpaquePeerId);
    check(issuer && issuer.opaquePeerId === invitation.issuerOpaquePeerId, "Provisional enrollment issuer mismatch");
    const packet = { kind: "enrollment-claim", bundle: api.sealBundle({ payload: { voucher, claim }, recipientEncPubPem: issuer.encPub, flockUuid: current.flockUuid, rosterEpoch: current.rosterEpoch, recipientOpaquePeerId: issuer.opaquePeerId, bundleType: "enrollment-claim" }) };
    const endpoint = invitation.enrollmentEndpoint;
    const sas = new URLSearchParams(voucher.enrollmentSbSendSas.replace(/^SharedAccessSignature /, ""));
    check(sas.get("sr") === `https://${endpoint.namespaceHost}/${endpoint.topicName}`.toLowerCase(), "Provisional endpoint differs from its signed scoped token");
    api.writePrivateJson(directory, "configuration.json", { issuer: false, rosterUrl: voucher.rosterUrl, provisional: true });
    api.writePrivateJson(directory, "genesis.json", invitation.genesis);
    api.writePrivateJson(directory, "provisional-claim.json", { voucher, claim });
    if (!config.groups.some((group) => group.flockUuid === voucher.flockUuid)) {
      config.groups.push({ flockUuid: voucher.flockUuid, rootFingerprint: verifiedRootFingerprint, label: voucher.flockUuid });
      api.writePrivateJson(home, "config.json", config);
    }
    const result = await request(`https://${endpoint.namespaceHost}/${endpoint.topicName}/messages`, {
      method: "POST", headers: { Authorization: voucher.enrollmentSbSendSas, "Content-Type": "application/json", toOpaquePeerId: JSON.stringify(issuer.opaquePeerId), flockUuid: JSON.stringify(current.flockUuid), BrokerProperties: JSON.stringify({ TimeToLive: 3600 }) }, body: JSON.stringify(packet),
    });
    check(result.status === 200 || result.status === 201 || result.status === 202, `Provisional claim transport failed with HTTP ${result.status}; no membership or execution was granted`);
    return { provisional: true, admittedToTransport: true, claim, ...proof, reason: "Independent owner approval and a fresh signed roster are still required" };
  } finally { state.close(); }
}
