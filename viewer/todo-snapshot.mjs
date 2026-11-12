const statuses = new Set(["pending", "in_progress", "blocked", "done"]);
const ISO_TIMESTAMP_RE = /^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/;

export const MAX_TODO_STALE_AFTER_MINUTES = 525600;

export const TODO_DIMENSIONS = [
  { key: "riskReduction", label: "Risk reduction", meaning: "Security, data-loss, upgrade or session risk prevented" },
  { key: "userImpact", label: "User impact", meaning: "Severity of the affected workflow" },
  { key: "reach", label: "Reach", meaning: "Machines, users or workflows benefited" },
  { key: "urgency", label: "Urgency", meaning: "Active failures, deadlines or worsening conditions" },
  { key: "unblockingValue", label: "Unblocking value", meaning: "Important dependencies or repeated blockers removed" },
  { key: "effortAndChangeRisk", label: "Effort and change risk", meaning: "Implementation, rollout and regression exposure; 5 means harder or riskier" },
];

function parseIsoTimestampMs(value) {
  if (typeof value !== "string" || !ISO_TIMESTAMP_RE.test(value)) throw new Error("Invalid TODO timestamp");
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new Error("Invalid TODO timestamp");
  return ms;
}

function resolveClockMs(now = Date.now) {
  const ms = typeof now === "function" ? now() : now;
  if (typeof ms !== "number" || !Number.isFinite(ms)) throw new Error("Invalid TODO clock value");
  return ms;
}

export function parseTodoStaleAfterMinutes(value) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 1 || value > MAX_TODO_STALE_AFTER_MINUTES) {
      throw new Error("Invalid TODO freshness threshold");
    }
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (!/^[1-9]\d*$/.test(trimmed)) throw new Error("Invalid TODO freshness threshold");
    const parsed = Number(trimmed);
    if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_TODO_STALE_AFTER_MINUTES) {
      throw new Error("Invalid TODO freshness threshold");
    }
    return parsed;
  }
  throw new Error("Invalid TODO freshness threshold");
}

export function formatTodoElapsedAge(isoTimestamp, now = Date.now) {
  const targetMs = parseIsoTimestampMs(isoTimestamp);
  const nowMs = resolveClockMs(now);
  const deltaMs = nowMs - targetMs;
  if (deltaMs < 0) return "0s ago (ahead of local clock)";
  const totalSeconds = Math.floor(deltaMs / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s ago`;
  if (totalSeconds < 3600) {
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    return seconds > 0 ? `${minutes}m ${seconds}s ago` : `${minutes}m ago`;
  }
  if (totalSeconds < 86400) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    return minutes > 0 ? `${hours}h ${minutes}m ago` : `${hours}h ago`;
  }
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (hours > 0) return `${days}d ${hours}h ago`;
  if (minutes > 0) return `${days}d ${minutes}m ago`;
  return `${days}d ago`;
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
  if (typeof value.updatedAt !== "string" || !ISO_TIMESTAMP_RE.test(value.updatedAt) || !Number.isFinite(Date.parse(value.updatedAt))) invalid();
  let staleAfterMinutes;
  if (Object.hasOwn(value, "staleAfterMinutes")) {
    if (typeof value.staleAfterMinutes !== "number" || !Number.isSafeInteger(value.staleAfterMinutes) || value.staleAfterMinutes < 1 || value.staleAfterMinutes > MAX_TODO_STALE_AFTER_MINUTES) {
      invalid();
    }
    staleAfterMinutes = value.staleAfterMinutes;
  }
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
      if (!["reported", "reproduced", "independently_verified"].includes(item.evidenceConfidence)) invalid();
      issue.evidenceConfidence = item.evidenceConfidence;
    }
    if (Object.hasOwn(item, "acceptanceCriteria")) {
      if (!Array.isArray(item.acceptanceCriteria)) invalid();
      issue.acceptanceCriteria = item.acceptanceCriteria.map(text);
    }
    if (ids.has(issue.todoId) || numbers.has(issue.number) || ranks.has(issue.rank)) invalid();
    ids.add(issue.todoId); numbers.add(issue.number); ranks.add(issue.rank);
    return issue;
  });
  if (issues.some((item) => item.relatedIssues.some((number) => !numbers.has(number) || number === item.number))) invalid();
  const result = {
    schemaVersion: 1, revision: positive(value.revision), updatedAt: value.updatedAt,
    source: text(value.source), issues: issues.sort((a, b) => a.rank - b.rank),
  };
  if (staleAfterMinutes !== undefined) result.staleAfterMinutes = staleAfterMinutes;
  return result;
}

export function createTodoRefreshState() {
  return {
    snapshot: null,
    lastSuccessfulFetchAt: null,
    lastSuccessfulRevision: null,
    lastSuccessfulUpdatedAt: null,
    unchangedRevision: false,
    error: null,
  };
}

export function beginTodoRefresh(prevState = createTodoRefreshState()) {
  return {
    snapshot: null,
    lastSuccessfulFetchAt: prevState?.lastSuccessfulFetchAt ?? null,
    lastSuccessfulRevision: prevState?.lastSuccessfulRevision ?? null,
    lastSuccessfulUpdatedAt: prevState?.lastSuccessfulUpdatedAt ?? null,
    unchangedRevision: false,
    error: null,
  };
}

export function formatTodoRefreshError(cause) {
  return cause instanceof Error && cause.message === "403"
    ? "Access is restricted to the configured home LAN or an authenticated SSH connection. Other networks are not permitted."
    : `Could not load the tracker snapshot (${cause instanceof Error ? cause.message : "request failed"}). Check viewer configuration and retry.`;
}

export function applyTodoRefreshSuccess(prevState = createTodoRefreshState(), rawSnapshot, { now = Date.now } = {}) {
  const nowMs = resolveClockMs(now);
  const snapshot = validateTodoSnapshot(rawSnapshot);
  const lastSuccessfulFetchAt = new Date(nowMs).toISOString();
  const unchangedRevision = prevState?.lastSuccessfulRevision === snapshot.revision &&
    prevState?.lastSuccessfulUpdatedAt === snapshot.updatedAt;
  return {
    snapshot,
    lastSuccessfulFetchAt,
    lastSuccessfulRevision: snapshot.revision,
    lastSuccessfulUpdatedAt: snapshot.updatedAt,
    unchangedRevision,
    error: null,
  };
}

export function applyTodoRefreshFailure(prevState = createTodoRefreshState(), cause) {
  return {
    snapshot: null,
    lastSuccessfulFetchAt: prevState?.lastSuccessfulFetchAt ?? null,
    lastSuccessfulRevision: prevState?.lastSuccessfulRevision ?? null,
    lastSuccessfulUpdatedAt: prevState?.lastSuccessfulUpdatedAt ?? null,
    unchangedRevision: false,
    error: formatTodoRefreshError(cause),
  };
}

export async function refreshTodoState(prevState = createTodoRefreshState(), loadSnapshot, { now = Date.now } = {}) {
  const pending = beginTodoRefresh(prevState);
  try {
    const raw = await loadSnapshot();
    return applyTodoRefreshSuccess(pending, raw, { now });
  } catch (cause) {
    return applyTodoRefreshFailure(pending, cause);
  }
}

export function describeTodoTimings(state, { now = Date.now, staleAfterMinutes } = {}) {
  const nowMs = resolveClockMs(now);
  const snapshot = state?.snapshot ?? null;
  const lastSuccessfulFetchAt = state?.lastSuccessfulFetchAt ?? null;
  const thresholdMinutes = staleAfterMinutes !== undefined
    ? parseTodoStaleAfterMinutes(staleAfterMinutes)
    : parseTodoStaleAfterMinutes(snapshot?.staleAfterMinutes);

  let sourceUpdatedAt = null;
  let sourceElapsedMs = null;
  let sourceAgeLabel = null;
  let sourceAheadOfClock = false;
  if (snapshot) {
    sourceUpdatedAt = snapshot.updatedAt;
    const rawSourceDelta = nowMs - parseIsoTimestampMs(snapshot.updatedAt);
    sourceAheadOfClock = rawSourceDelta < 0;
    sourceElapsedMs = Math.max(0, rawSourceDelta);
    sourceAgeLabel = formatTodoElapsedAge(snapshot.updatedAt, nowMs);
  }

  let fetchElapsedMs = null;
  let fetchAgeLabel = null;
  let fetchAheadOfClock = false;
  if (lastSuccessfulFetchAt !== null) {
    const rawFetchDelta = nowMs - parseIsoTimestampMs(lastSuccessfulFetchAt);
    fetchAheadOfClock = rawFetchDelta < 0;
    fetchElapsedMs = Math.max(0, rawFetchDelta);
    fetchAgeLabel = formatTodoElapsedAge(lastSuccessfulFetchAt, nowMs);
  }

  let freshnessState = "age_only";
  let isStale = null;
  let freshnessSummary = "Age only (no staleness threshold configured)";
  if (thresholdMinutes !== null) {
    if (snapshot && sourceElapsedMs !== null) {
      const thresholdMs = thresholdMinutes * 60_000;
      isStale = !sourceAheadOfClock && sourceElapsedMs > thresholdMs;
      freshnessState = isStale ? "stale" : "fresh";
      freshnessSummary = isStale
        ? `Stale snapshot (exceeds ${thresholdMinutes}m source age threshold)`
        : `Within ${thresholdMinutes}m source freshness threshold`;
    } else {
      freshnessState = "unavailable";
      freshnessSummary = `${thresholdMinutes}m source freshness threshold configured (no active snapshot)`;
    }
  }

  return {
    revision: snapshot?.revision ?? null,
    source: snapshot?.source ?? null,
    sourceUpdatedAt,
    sourceElapsedMs,
    sourceAgeLabel,
    sourceAheadOfClock,
    lastSuccessfulFetchAt,
    fetchElapsedMs,
    fetchAgeLabel,
    fetchAheadOfClock,
    unchangedRevision: Boolean(state?.unchangedRevision),
    staleAfterMinutes: thresholdMinutes,
    freshnessState,
    isStale,
    freshnessSummary,
    machinePresenceInferred: false,
  };
}
