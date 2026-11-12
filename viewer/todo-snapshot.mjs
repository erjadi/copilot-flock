const statuses = new Set(["pending", "in_progress", "blocked", "done"]);

export const VERIFICATION_TIERS = ["unverified", "source_reviewed", "unit_synthetic", "live_multi_pc"];
export const DELIVERY_STAGES = ["proposed", "approved", "implemented", "deployed", "verified"];
export const EVIDENCE_CONFIDENCES = ["reported", "reproduced", "independently_verified"];
export const EVIDENCE_DISPOSITIONS = ["accepted", "rejected", "superseded"];

const verificationTierSet = new Set(VERIFICATION_TIERS);
const deliveryStageSet = new Set(DELIVERY_STAGES);
const confidenceSet = new Set(EVIDENCE_CONFIDENCES);
const dispositionSet = new Set(EVIDENCE_DISPOSITIONS);
const tierRank = Object.fromEntries(VERIFICATION_TIERS.map((tier, index) => [tier, index]));

const ISO_TIMESTAMP_RE = /^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/;
const CANDIDATE_SHA_RE = /^[0-9a-f]{7,64}$/i;
const EVIDENCE_DIGEST_RE = /^(?:sha(?:256|384|512):)?[0-9a-f]{16,128}$/i;
const CONTROL_CHAR_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

export const TODO_DIMENSIONS = [
  { key: "riskReduction", label: "Risk reduction", meaning: "Security, data-loss, upgrade or session risk prevented" },
  { key: "userImpact", label: "User impact", meaning: "Severity of the affected workflow" },
  { key: "reach", label: "Reach", meaning: "Machines, users or workflows benefited" },
  { key: "urgency", label: "Urgency", meaning: "Active failures, deadlines or worsening conditions" },
  { key: "unblockingValue", label: "Unblocking value", meaning: "Important dependencies or repeated blockers removed" },
  { key: "effortAndChangeRisk", label: "Effort and change risk", meaning: "Implementation, rollout and regression exposure; 5 means harder or riskier" },
];

function isIsoTimestamp(input) {
  return typeof input === "string" && ISO_TIMESTAMP_RE.test(input) && Number.isFinite(Date.parse(input));
}

function normalizeSha(input) {
  if (typeof input !== "string" || !CANDIDATE_SHA_RE.test(input)) return null;
  return input.toLowerCase();
}

function normalizeHostKey(hostId) {
  return String(hostId).trim().toLowerCase();
}

function validateReadinessEvidenceEntry(entry, invalid) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) invalid();
  const text = (input, max = 20000) => {
    if (typeof input !== "string" || !input.trim() || input.length > max || CONTROL_CHAR_RE.test(input)) invalid();
    return input;
  };
  const nonNegative = (input) => {
    if (!Number.isSafeInteger(input) || input < 0) invalid();
    return input;
  };
  const candidateSha = normalizeSha(entry.candidateSha);
  if (!candidateSha) invalid();
  if (!isIsoTimestamp(entry.capturedAt)) invalid();
  if (typeof entry.evidenceDigest !== "string" || !EVIDENCE_DIGEST_RE.test(entry.evidenceDigest)) invalid();
  if (!confidenceSet.has(entry.confidence)) invalid();
  if (!verificationTierSet.has(entry.verificationTier)) invalid();
  if (!Array.isArray(entry.prerequisites) || entry.prerequisites.length > 100) invalid();

  const normalized = {
    candidateSha,
    hostId: text(entry.hostId, 256),
    os: text(entry.os, 256),
    command: text(entry.command, 4000),
    capturedAt: entry.capturedAt,
    passCount: nonNegative(entry.passCount),
    failCount: nonNegative(entry.failCount),
    skipCount: nonNegative(entry.skipCount),
    prerequisites: entry.prerequisites.map((item) => text(item, 2000)),
    evidenceDigest: entry.evidenceDigest.toLowerCase(),
    confidence: entry.confidence,
    verificationTier: entry.verificationTier,
  };

  if (Object.hasOwn(entry, "deliveryStage")) {
    if (!deliveryStageSet.has(entry.deliveryStage)) invalid();
    normalized.deliveryStage = entry.deliveryStage;
  }
  if (Object.hasOwn(entry, "verificationPrompt")) {
    normalized.verificationPrompt = text(entry.verificationPrompt, 20000);
  }
  if (Object.hasOwn(entry, "disposition")) {
    if (!dispositionSet.has(entry.disposition)) invalid();
    normalized.disposition = entry.disposition;
  }

  if (normalized.failCount > 0 && normalized.disposition === "accepted") invalid();
  if (normalized.verificationTier === "unverified" && normalized.confidence === "independently_verified") invalid();
  if (
    (normalized.verificationTier === "unit_synthetic" || normalized.verificationTier === "live_multi_pc") &&
    normalized.passCount === 0 &&
    normalized.failCount === 0 &&
    normalized.disposition === "accepted"
  ) {
    invalid();
  }

  return normalized;
}

function receiptIdentityKey(entry) {
  return `${entry.candidateSha}\0${normalizeHostKey(entry.hostId)}\0${entry.capturedAt}\0${entry.evidenceDigest}`;
}

function sameReceiptPayload(a, b) {
  return (
    a.candidateSha === b.candidateSha &&
    a.hostId === b.hostId &&
    a.os === b.os &&
    a.command === b.command &&
    a.capturedAt === b.capturedAt &&
    a.passCount === b.passCount &&
    a.failCount === b.failCount &&
    a.skipCount === b.skipCount &&
    a.evidenceDigest === b.evidenceDigest &&
    a.confidence === b.confidence &&
    a.verificationTier === b.verificationTier &&
    a.prerequisites.length === b.prerequisites.length &&
    a.prerequisites.every((value, index) => value === b.prerequisites[index])
  );
}

export function sortTodoIssues(issues, key = "editorial", direction = "asc") {
  if (key !== "editorial" && !TODO_DIMENSIONS.some(dimension => dimension.key === key)) throw new Error("Invalid TODO sort dimension");
  if (!["asc", "desc"].includes(direction)) throw new Error("Invalid TODO sort direction");
  return [...issues].sort((a, b) => {
    const first = key === "editorial" ? a.rank : a.scores?.[key];
    const second = key === "editorial" ? b.rank : b.scores?.[key];
    if (first === undefined && second !== undefined) return 1;
    if (second === undefined && first !== undefined) return -1;
    const difference = first === undefined ? 0 : first - second;
    return (direction === "asc" ? difference : -difference) ||
      a.rank - b.rank || (a.todoId < b.todoId ? -1 : a.todoId > b.todoId ? 1 : 0);
  });
}

export function validateTodoSnapshot(value) {
  const invalid = () => { throw new Error("Invalid TODO snapshot"); };
  const text = (input) => {
    if (typeof input !== "string" || !input.trim() || input.length > 20000) invalid();
    return input;
  };
  const positive = (input) => {
    if (!Number.isSafeInteger(input) || input < 1) invalid();
    return input;
  };
  if (!value || value.schemaVersion !== 1 || !Array.isArray(value.issues) || value.issues.length > 1000) invalid();
  if (!isIsoTimestamp(value.updatedAt)) invalid();
  const ids = new Set(), numbers = new Set(), ranks = new Set();
  const issues = value.issues.map((item) => {
    if (!item || !["bug", "architecture"].includes(item.type) || !statuses.has(item.status)) invalid();
    if (!Array.isArray(item.details) || !Array.isArray(item.relatedIssues)) invalid();
    const issue = {
      todoId: text(item.todoId), number: positive(item.number), rank: positive(item.rank),
      title: text(item.title), type: item.type, status: item.status,
      rankingBasis: text(item.rankingBasis), rankingExplanation: text(item.rankingExplanation),
      evidence: text(item.evidence), implementationStatus: text(item.implementationStatus),
      nextStep: text(item.nextStep), details: item.details.map(text),
      relatedIssues: item.relatedIssues.map(positive),
    };
    if (Object.hasOwn(item, "scores")) {
      if (!item.scores || typeof item.scores !== "object" || Array.isArray(item.scores)) invalid();
      issue.scores = Object.fromEntries(TODO_DIMENSIONS.map(({ key }) => {
        const score = item.scores[key];
        if (!Number.isInteger(score) || score < 1 || score > 5) invalid();
        return [key, score];
      }));
    }
    if (Object.hasOwn(item, "evidenceConfidence")) {
      if (!confidenceSet.has(item.evidenceConfidence)) invalid();
      issue.evidenceConfidence = item.evidenceConfidence;
    }
    if (Object.hasOwn(item, "acceptanceCriteria")) {
      if (!Array.isArray(item.acceptanceCriteria)) invalid();
      issue.acceptanceCriteria = item.acceptanceCriteria.map(text);
    }
    if (Object.hasOwn(item, "implementationDetails")) {
      const progress = item.implementationDetails;
      if (!progress || typeof progress !== "object" || Array.isArray(progress) ||
          !Array.isArray(progress.changedFiles) || typeof progress.mergedIn35Candidate !== "boolean") invalid();
      issue.implementationDetails = {
        stage: text(progress.stage), workerSessionId: text(progress.workerSessionId),
        model: text(progress.model), branch: text(progress.branch),
        commitSha: progress.commitSha === null ? null : text(progress.commitSha),
        changedFiles: progress.changedFiles.map(text),
        testSummary: progress.testSummary === null ? null : text(progress.testSummary),
        mergedIn35Candidate: progress.mergedIn35Candidate,
        flockReviewStatus: text(progress.flockReviewStatus),
      };
    }
    if (Object.hasOwn(item, "candidateSha")) {
      const candidateSha = normalizeSha(item.candidateSha);
      if (!candidateSha) invalid();
      issue.candidateSha = candidateSha;
    }
    if (Object.hasOwn(item, "verificationTier")) {
      if (!verificationTierSet.has(item.verificationTier)) invalid();
      issue.verificationTier = item.verificationTier;
    }
    if (Object.hasOwn(item, "deliveryStage")) {
      if (!deliveryStageSet.has(item.deliveryStage)) invalid();
      issue.deliveryStage = item.deliveryStage;
    }
    if (Object.hasOwn(item, "verificationPrompt")) {
      if (CONTROL_CHAR_RE.test(String(item.verificationPrompt ?? ""))) invalid();
      issue.verificationPrompt = text(item.verificationPrompt);
    }
    if (Object.hasOwn(item, "readinessEvidence")) {
      if (!Array.isArray(item.readinessEvidence) || item.readinessEvidence.length > 200) invalid();
      const seenReceipts = new Set();
      issue.readinessEvidence = item.readinessEvidence.map((entry) => {
        const normalizedEntry = validateReadinessEvidenceEntry(entry, invalid);
        const receiptKey = receiptIdentityKey(normalizedEntry);
        if (seenReceipts.has(receiptKey)) invalid();
        seenReceipts.add(receiptKey);
        return normalizedEntry;
      });
    }
    if (ids.has(issue.todoId) || numbers.has(issue.number) || ranks.has(issue.rank)) invalid();
    ids.add(issue.todoId); numbers.add(issue.number); ranks.add(issue.rank);
    return issue;
  });
  if (issues.some((item) => item.relatedIssues.some((number) => !numbers.has(number) || number === item.number))) invalid();
  return {
    schemaVersion: 1, revision: positive(value.revision), updatedAt: value.updatedAt,
    source: text(value.source), issues: issues.sort((a, b) => a.rank - b.rank),
  };
}

export function appendTodoReadinessEvidence(issue, entry, { promoteCandidate = false } = {}) {
  if (!issue || typeof issue !== "object") throw new Error("Invalid TODO issue");
  const normalizedEntry = validateReadinessEvidenceEntry(entry, () => {
    throw new Error("Invalid TODO readiness evidence entry");
  });
  const existing = Array.isArray(issue.readinessEvidence)
    ? issue.readinessEvidence.map((item) => validateReadinessEvidenceEntry(item, () => {
        throw new Error("Invalid existing TODO readiness evidence entry");
      }))
    : [];

  const entryKey = receiptIdentityKey(normalizedEntry);
  for (const prior of existing) {
    if (receiptIdentityKey(prior) === entryKey) {
      if (!sameReceiptPayload(prior, normalizedEntry)) {
        throw new Error("Conflicting TODO readiness evidence receipt");
      }
      const priorRejected = prior.failCount > 0 || prior.disposition === "rejected";
      if (priorRejected && normalizedEntry.disposition === "accepted") {
        throw new Error("Cannot overwrite rejected readiness evidence");
      }
      return { ...issue, readinessEvidence: existing.map((item) => ({ ...item, prerequisites: [...item.prerequisites] })) };
    }
  }

  const existingCandidateSha = issue.candidateSha ? normalizeSha(issue.candidateSha) : null;
  const nextCandidateSha = promoteCandidate
    ? normalizedEntry.candidateSha
    : (existingCandidateSha ?? normalizedEntry.candidateSha);

  const nextEntryHostKey = normalizeHostKey(normalizedEntry.hostId);
  const nextEntryTime = Date.parse(normalizedEntry.capturedAt);
  const hasNewerSameHostReceipt = existing.some(
    (prior) =>
      prior.disposition !== "superseded" &&
      prior.candidateSha === nextCandidateSha &&
      normalizeHostKey(prior.hostId) === nextEntryHostKey &&
      Date.parse(prior.capturedAt) > nextEntryTime,
  );

  const entryRejected = normalizedEntry.failCount > 0 || normalizedEntry.disposition === "rejected";
  const entryMatchesActiveSha = normalizedEntry.candidateSha === nextCandidateSha;
  const finalDisposition = entryRejected
    ? "rejected"
    : normalizedEntry.disposition === "superseded" || !entryMatchesActiveSha || hasNewerSameHostReceipt
      ? "superseded"
      : "accepted";

  const preservedHistory = existing.map((prior) => {
    const copy = { ...prior, prerequisites: [...prior.prerequisites] };
    const priorRejected = copy.failCount > 0 || copy.disposition === "rejected";
    if (priorRejected) {
      copy.disposition = "rejected";
      return copy;
    }
    if (copy.disposition === "superseded") {
      return copy;
    }
    if (copy.candidateSha !== nextCandidateSha) {
      if (promoteCandidate || existingCandidateSha) {
        copy.disposition = "superseded";
      }
      return copy;
    }
    if (
      normalizeHostKey(copy.hostId) === nextEntryHostKey &&
      finalDisposition !== "superseded" &&
      Date.parse(copy.capturedAt) <= nextEntryTime
    ) {
      copy.disposition = "superseded";
      return copy;
    }
    return copy;
  });

  const updatedIssue = {
    ...issue,
    candidateSha: nextCandidateSha,
    readinessEvidence: [
      ...preservedHistory,
      { ...normalizedEntry, prerequisites: [...normalizedEntry.prerequisites], disposition: finalDisposition },
    ],
  };
  return updatedIssue;
}

export function assertEvidenceHistoryPreserved(previousSnapshot, nextSnapshot) {
  const previous = validateTodoSnapshot(previousSnapshot);
  const next = validateTodoSnapshot(nextSnapshot);
  const nextById = new Map(next.issues.map((issue) => [issue.todoId, issue]));
  const nextByNumber = new Map(next.issues.map((issue) => [issue.number, issue]));

  for (const prevIssue of previous.issues) {
    const prevEvidence = prevIssue.readinessEvidence ?? [];
    if (!prevEvidence.length) continue;
    const nextIssue = nextById.get(prevIssue.todoId) ?? nextByNumber.get(prevIssue.number);
    if (!nextIssue) {
      throw new Error(`Refusing to drop TODO ${prevIssue.todoId} with recorded readiness evidence history`);
    }
    const nextEvidence = nextIssue.readinessEvidence ?? [];
    const nextReceipts = new Map(nextEvidence.map((entry) => [receiptIdentityKey(entry), entry]));

    for (const prevEntry of prevEvidence) {
      const match = nextReceipts.get(receiptIdentityKey(prevEntry));
      if (!match || !sameReceiptPayload(prevEntry, match)) {
        throw new Error(`Refusing to overwrite or drop readiness evidence history for ${prevIssue.todoId}`);
      }
      const wasRejected = prevEntry.failCount > 0 || prevEntry.disposition === "rejected";
      const isNowRejected = match.failCount > 0 || match.disposition === "rejected";
      if (wasRejected && !isNowRejected) {
        throw new Error(`Refusing to clear rejected readiness evidence disposition for ${prevIssue.todoId}`);
      }
      if (prevEntry.disposition === "superseded" && match.disposition !== "superseded") {
        throw new Error(`Refusing to resurrect superseded readiness evidence for ${prevIssue.todoId}`);
      }
    }
  }
}

export function resolveTodoReadiness(issue) {
  const rawEntries = Array.isArray(issue?.readinessEvidence) ? issue.readinessEvidence : [];
  const explicitCandidateSha = issue?.candidateSha ? normalizeSha(issue.candidateSha) : null;

  let targetCandidateSha = explicitCandidateSha;
  let ambiguousCandidate = false;
  if (!targetCandidateSha && rawEntries.length > 0) {
    const activeShas = new Set(
      rawEntries
        .filter((entry) => entry.disposition !== "superseded")
        .map((entry) => normalizeSha(entry.candidateSha))
        .filter(Boolean),
    );
    if (activeShas.size === 1) {
      [targetCandidateSha] = activeShas;
    } else if (activeShas.size > 1) {
      ambiguousCandidate = true;
    }
  }

  const latestIndexByHost = new Map();
  if (targetCandidateSha) {
    rawEntries.forEach((entry, index) => {
      const sha = normalizeSha(entry.candidateSha);
      const isRejected = entry.failCount > 0 || entry.disposition === "rejected";
      if (sha !== targetCandidateSha || entry.disposition === "superseded" || isRejected) return;
      const hostKey = normalizeHostKey(entry.hostId);
      const current = latestIndexByHost.get(hostKey);
      const time = Date.parse(entry.capturedAt);
      if (!current || time >= current.time) {
        latestIndexByHost.set(hostKey, { index, time });
      }
    });
  }

  const latestStateByHost = new Map();
  if (targetCandidateSha) {
    rawEntries.forEach((entry, index) => {
      const sha = normalizeSha(entry.candidateSha);
      if (sha !== targetCandidateSha || entry.disposition === "superseded") return;
      const hostKey = normalizeHostKey(entry.hostId);
      const time = Date.parse(entry.capturedAt);
      const existing = latestStateByHost.get(hostKey);
      if (!existing || time > existing.time || (time === existing.time && index > existing.index)) {
        latestStateByHost.set(hostKey, { entry, index, time });
      }
    });
  }

  const entries = rawEntries.map((entry, index) => {
    const sha = normalizeSha(entry.candidateSha) ?? entry.candidateSha;
    const hostKey = normalizeHostKey(entry.hostId);
    let effectiveDisposition;
    if (entry.failCount > 0 || entry.disposition === "rejected") {
      effectiveDisposition = "rejected";
    } else if (entry.disposition === "superseded") {
      effectiveDisposition = "superseded";
    } else if (!targetCandidateSha || sha !== targetCandidateSha) {
      effectiveDisposition = "superseded";
    } else {
      const latestHostState = latestStateByHost.get(hostKey);
      const latestAccepted = latestIndexByHost.get(hostKey);
      if (
        latestHostState &&
        (latestHostState.entry.failCount > 0 || latestHostState.entry.disposition === "rejected") &&
        latestHostState.index !== index
      ) {
        effectiveDisposition = "superseded";
      } else if (latestAccepted && latestAccepted.index === index) {
        effectiveDisposition = "accepted";
      } else {
        effectiveDisposition = "superseded";
      }
    }
    return { ...entry, candidateSha: sha, effectiveDisposition };
  });

  const acceptedEntries = entries.filter((entry) => entry.effectiveDisposition === "accepted");
  const rejectedEntries = entries.filter((entry) => entry.effectiveDisposition === "rejected");
  const supersededEntries = entries.filter((entry) => entry.effectiveDisposition === "superseded");

  const failingHosts = [];
  const passingHosts = [];
  const liveMultiPcHosts = [];
  const unitSyntheticHosts = [];
  const sourceReviewedHosts = [];
  const independentlyVerifiedHosts = [];
  const reproducedHosts = [];

  for (const [, { entry }] of latestStateByHost) {
    if (entry.failCount > 0 || entry.disposition === "rejected") {
      failingHosts.push(entry.hostId);
      continue;
    }
    const hasPassingChecks = entry.failCount === 0 && entry.passCount >= 1;
    if (hasPassingChecks || entry.verificationTier === "source_reviewed") {
      passingHosts.push(entry.hostId);
    }
    if (hasPassingChecks && entry.verificationTier === "live_multi_pc") {
      liveMultiPcHosts.push(entry.hostId);
    }
    if (hasPassingChecks && (entry.verificationTier === "unit_synthetic" || entry.verificationTier === "live_multi_pc")) {
      unitSyntheticHosts.push(entry.hostId);
    }
    if (
      entry.failCount === 0 &&
      (entry.verificationTier === "source_reviewed" ||
        (entry.passCount >= 1 && (entry.verificationTier === "unit_synthetic" || entry.verificationTier === "live_multi_pc")))
    ) {
      sourceReviewedHosts.push(entry.hostId);
    }
    if (
      hasPassingChecks &&
      entry.confidence === "independently_verified" &&
      entry.verificationTier !== "unverified"
    ) {
      independentlyVerifiedHosts.push(entry.hostId);
    }
    if (
      entry.failCount === 0 &&
      (entry.confidence === "reproduced" || entry.confidence === "independently_verified") &&
      entry.verificationTier !== "unverified"
    ) {
      reproducedHosts.push(entry.hostId);
    }
  }

  const hasActiveHostFailure = failingHosts.length > 0;
  let maxProvenTier = "unverified";
  if (!hasActiveHostFailure && liveMultiPcHosts.length >= 2) {
    maxProvenTier = "live_multi_pc";
  } else if (!hasActiveHostFailure && unitSyntheticHosts.length >= 1) {
    maxProvenTier = "unit_synthetic";
  } else if (!hasActiveHostFailure && sourceReviewedHosts.length >= 1) {
    maxProvenTier = "source_reviewed";
  }

  const downgradeReasons = [];
  if (ambiguousCandidate) {
    downgradeReasons.push("Multiple non-superseded candidate SHAs exist without an explicit issue candidateSha binding.");
  }
  if (hasActiveHostFailure) {
    downgradeReasons.push(`Active failing/rejected receipt on host(s): ${failingHosts.join(", ")}.`);
  }

  const claimedTier = verificationTierSet.has(issue?.verificationTier) ? issue.verificationTier : null;
  const desiredTier = claimedTier ?? maxProvenTier;
  const effectiveVerificationTier = tierRank[desiredTier] <= tierRank[maxProvenTier] ? desiredTier : maxProvenTier;
  if (claimedTier && tierRank[claimedTier] > tierRank[effectiveVerificationTier]) {
    downgradeReasons.push(
      claimedTier === "live_multi_pc"
        ? `Claimed live_multi_pc downgraded to ${effectiveVerificationTier}: requires passing receipts from at least 2 distinct hosts on the same candidate SHA.`
        : `Claimed ${claimedTier} downgraded to ${effectiveVerificationTier}: missing matching passing receipt evidence for candidate ${targetCandidateSha ?? "unbound"}.`,
    );
  }

  const claimedConfidence = confidenceSet.has(issue?.evidenceConfidence) ? issue.evidenceConfidence : null;
  let effectiveConfidence = claimedConfidence;
  if (claimedConfidence === "independently_verified") {
    if (hasActiveHostFailure || independentlyVerifiedHosts.length === 0) {
      effectiveConfidence = !hasActiveHostFailure && reproducedHosts.length > 0 ? "reproduced" : "reported";
      downgradeReasons.push(
        `Claimed independently_verified downgraded to ${effectiveConfidence}: requires matching passing receipt evidence for candidate ${targetCandidateSha ?? "unbound"}.`,
      );
    }
  } else if (!claimedConfidence) {
    if (!hasActiveHostFailure && independentlyVerifiedHosts.length > 0) {
      effectiveConfidence = "independently_verified";
    } else if (!hasActiveHostFailure && reproducedHosts.length > 0) {
      effectiveConfidence = "reproduced";
    } else if (entries.length > 0) {
      effectiveConfidence = "reported";
    } else {
      effectiveConfidence = null;
    }
  }

  const latestAcceptedStage = [...acceptedEntries]
    .reverse()
    .find((entry) => deliveryStageSet.has(entry.deliveryStage))?.deliveryStage ?? null;
  const claimedDeliveryStage = deliveryStageSet.has(issue?.deliveryStage)
    ? issue.deliveryStage
    : latestAcceptedStage;
  let effectiveDeliveryStage = claimedDeliveryStage;
  if (claimedDeliveryStage === "verified") {
    if (
      hasActiveHostFailure ||
      effectiveVerificationTier === "unverified" ||
      effectiveConfidence !== "independently_verified"
    ) {
      effectiveDeliveryStage = "implemented";
      downgradeReasons.push(
        "Claimed verified delivery stage downgraded to implemented: requires matching independently_verified receipt evidence.",
      );
    }
  }

  let unverifiedCompletionNote = null;
  if (
    (issue?.status === "done" || effectiveDeliveryStage === "implemented" || effectiveDeliveryStage === "deployed") &&
    effectiveVerificationTier === "unverified"
  ) {
    unverifiedCompletionNote = "Completion/implementation status alone does not establish verification without matching candidate receipt evidence.";
  }

  let latestCapturedAt = null;
  for (const entry of entries) {
    if (!latestCapturedAt || Date.parse(entry.capturedAt) > Date.parse(latestCapturedAt)) {
      latestCapturedAt = entry.capturedAt;
    }
  }

  return {
    targetCandidateSha,
    effectiveVerificationTier,
    claimedVerificationTier: claimedTier,
    effectiveConfidence,
    claimedConfidence,
    effectiveDeliveryStage,
    claimedDeliveryStage,
    downgradeReasons,
    unverifiedCompletionNote,
    entries,
    acceptedEntries,
    rejectedEntries,
    supersededEntries,
    passingHosts,
    failingHosts,
    latestCapturedAt,
  };
}

export function getTodoVerificationPrompt(issue) {
  if (typeof issue?.verificationPrompt === "string" && issue.verificationPrompt.trim()) {
    return issue.verificationPrompt;
  }
  const readiness = resolveTodoReadiness(issue);
  for (let index = readiness.acceptedEntries.length - 1; index >= 0; index -= 1) {
    const prompt = readiness.acceptedEntries[index].verificationPrompt;
    if (typeof prompt === "string" && prompt.trim()) return prompt;
  }
  return null;
}

export function sanitizeTodoText(text) {
  return String(text ?? "")
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, "[redacted private key]")
    .replace(/\b(?:Bearer|SharedAccessSignature)\s+[^\s"'<>]+/gi, "[redacted token]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "[redacted JWT]")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)\b/g, "[redacted GitHub token]")
    .replace(/([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)[^@\s/]+@/gi, "$1[redacted]@")
    .replace(
      /((?:SharedAccessKey|AccessKey|AccountKey|api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*["']?\s*[:=]\s*["']?)[^\s;"',}&]+/gi,
      "$1[redacted]",
    )
    .replace(/[A-Za-z]:\\Users\\[^\s"'<>|]+/g, "[redacted local path]")
    .replace(/\/(?:home|Users)\/[^\s"'<>|]+/g, "[redacted local path]")
    .replace(/~\/\.copilot\/[^\s"'<>|]+/g, "[redacted local path]");
}

export function summarizeTodosForFlock(snapshot, {
  format = "both",
  status = "all",
  type = "all",
  verificationTier = "all",
  sortKey = "editorial",
  direction = "asc",
  includeVerificationPrompt = false,
} = {}) {
  if (!["both", "json", "text"].includes(format)) throw new Error("Invalid TODO summary format");
  if (status !== "all" && !statuses.has(status)) throw new Error("Invalid TODO status filter");
  if (type !== "all" && !["bug", "architecture"].includes(type)) throw new Error("Invalid TODO type filter");
  if (verificationTier !== "all" && !verificationTierSet.has(verificationTier)) {
    throw new Error("Invalid TODO verification tier filter");
  }

  const validated = validateTodoSnapshot(snapshot);
  const enriched = validated.issues.map((issue) => ({ issue, readiness: resolveTodoReadiness(issue) }));

  const byStatus = { pending: 0, in_progress: 0, blocked: 0, done: 0 };
  const byVerificationTier = { unverified: 0, source_reviewed: 0, unit_synthetic: 0, live_multi_pc: 0 };
  for (const { issue, readiness } of enriched) {
    byStatus[issue.status] += 1;
    byVerificationTier[readiness.effectiveVerificationTier] += 1;
  }

  const readinessById = new Map(enriched.map(({ issue, readiness }) => [issue.todoId, readiness]));
  const filteredIssues = sortTodoIssues(
    validated.issues.filter((issue) => {
      const readiness = readinessById.get(issue.todoId);
      return (
        (status === "all" || issue.status === status) &&
        (type === "all" || issue.type === type) &&
        (verificationTier === "all" || readiness.effectiveVerificationTier === verificationTier)
      );
    }),
    sortKey,
    direction,
  );

  const summaryIssues = filteredIssues.map((issue) => {
    const readiness = readinessById.get(issue.todoId);
    const prompt = includeVerificationPrompt ? getTodoVerificationPrompt(issue) : null;
    const item = {
      todoId: sanitizeTodoText(issue.todoId),
      number: issue.number,
      rank: issue.rank,
      title: sanitizeTodoText(issue.title),
      type: issue.type,
      status: issue.status,
      candidateSha: readiness.targetCandidateSha,
      verificationTier: readiness.effectiveVerificationTier,
      claimedVerificationTier: readiness.claimedVerificationTier,
      deliveryStage: readiness.effectiveDeliveryStage,
      claimedDeliveryStage: readiness.claimedDeliveryStage,
      evidenceConfidence: readiness.effectiveConfidence,
      claimedEvidenceConfidence: readiness.claimedConfidence,
      scores: issue.scores ? { ...issue.scores } : null,
      nextStep: sanitizeTodoText(issue.nextStep),
      downgradeReasons: readiness.downgradeReasons.map(sanitizeTodoText),
      unverifiedCompletionNote: readiness.unverifiedCompletionNote
        ? sanitizeTodoText(readiness.unverifiedCompletionNote)
        : null,
      receiptSummary: {
        totalReceipts: readiness.entries.length,
        acceptedCount: readiness.acceptedEntries.length,
        rejectedCount: readiness.rejectedEntries.length,
        supersededCount: readiness.supersededEntries.length,
        verifiedHosts: readiness.passingHosts.map(sanitizeTodoText),
        failingHosts: readiness.failingHosts.map(sanitizeTodoText),
        latestCapturedAt: readiness.latestCapturedAt,
      },
    };
    if (includeVerificationPrompt && prompt) {
      item.verificationPrompt = sanitizeTodoText(prompt);
    }
    return item;
  });

  const json = {
    schemaVersion: 1,
    summaryKind: "copilot-flock-todo-summary",
    readOnly: true,
    executable: false,
    revision: validated.revision,
    updatedAt: validated.updatedAt,
    source: sanitizeTodoText(validated.source),
    counts: {
      total: validated.issues.length,
      shown: summaryIssues.length,
      byStatus,
      byVerificationTier,
    },
    issues: summaryIssues,
  };

  const lines = [
    `Copilot Flock TODO Summary (rev ${json.revision} · updated ${json.updatedAt} · read-only, non-executable)`,
    `Source: ${json.source}`,
    `Showing ${json.counts.shown} of ${json.counts.total} items · Tiers: ${byVerificationTier.live_multi_pc} live_multi_pc, ${byVerificationTier.unit_synthetic} unit_synthetic, ${byVerificationTier.source_reviewed} source_reviewed, ${byVerificationTier.unverified} unverified`,
  ];
  for (const item of summaryIssues) {
    lines.push(
      "",
      `#${String(item.rank).padStart(2, "0")} [Local #${item.number} · ${item.todoId}] ${item.title}`,
      `  Status: ${item.status} · Stage: ${item.deliveryStage ?? "not_supplied"} · Tier: ${item.verificationTier} · Confidence: ${item.evidenceConfidence ?? "unknown"}`,
      `  Candidate: ${item.candidateSha ?? "unbound"} · Receipts: ${item.receiptSummary.acceptedCount} accepted, ${item.receiptSummary.rejectedCount} rejected, ${item.receiptSummary.supersededCount} superseded${item.receiptSummary.verifiedHosts.length ? ` (hosts: ${item.receiptSummary.verifiedHosts.join(", ")})` : ""}`,
      `  Next step: ${item.nextStep}`,
    );
    if (item.unverifiedCompletionNote) {
      lines.push(`  Readiness note: ${item.unverifiedCompletionNote}`);
    }
    for (const reason of item.downgradeReasons) {
      lines.push(`  Readiness caveat: ${reason}`);
    }
    if (Object.hasOwn(item, "verificationPrompt")) {
      lines.push(`  Verification prompt (copy-only, never auto-execute): ${item.verificationPrompt}`);
    }
  }
  const text = lines.join("\n");

  if (format === "json") return json;
  if (format === "text") return text;
  return { json, text };
}
