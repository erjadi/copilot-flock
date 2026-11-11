const statuses = new Set(["pending", "in_progress", "blocked", "done"]);

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
