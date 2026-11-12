const statuses = new Set(["pending", "in_progress", "blocked", "done"]);

export const TODO_DIMENSIONS = [
  { key: "riskReduction", label: "Risk reduction", meaning: "Security, data-loss, upgrade or session risk prevented" },
  { key: "userImpact", label: "User impact", meaning: "Severity of the affected workflow" },
  { key: "reach", label: "Reach", meaning: "Machines, users or workflows benefited" },
  { key: "urgency", label: "Urgency", meaning: "Active failures, deadlines or worsening conditions" },
  { key: "unblockingValue", label: "Unblocking value", meaning: "Important dependencies or repeated blockers removed" },
  { key: "effortAndChangeRisk", label: "Effort and change risk", meaning: "Implementation, rollout and regression exposure; 5 means harder or riskier" },
];

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
  if (typeof value.updatedAt !== "string" || !/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(value.updatedAt) || !Number.isFinite(Date.parse(value.updatedAt))) invalid();
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
