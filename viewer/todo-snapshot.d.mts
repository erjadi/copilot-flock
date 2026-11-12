export type TodoDimension = "riskReduction" | "userImpact" | "reach" | "urgency" | "unblockingValue" | "effortAndChangeRisk";
export type TodoSortKey = "editorial" | TodoDimension;
export type TodoStatus = "pending" | "in_progress" | "blocked" | "done";
export type TodoVerificationTier = "unverified" | "source_reviewed" | "unit_synthetic" | "live_multi_pc";
export type TodoDeliveryStage = "proposed" | "approved" | "implemented" | "deployed" | "verified";
export type TodoEvidenceConfidence = "reported" | "reproduced" | "independently_verified";
export type TodoEvidenceDisposition = "accepted" | "rejected" | "superseded";

export const VERIFICATION_TIERS: readonly TodoVerificationTier[];
export const DELIVERY_STAGES: readonly TodoDeliveryStage[];
export const EVIDENCE_CONFIDENCES: readonly TodoEvidenceConfidence[];
export const EVIDENCE_DISPOSITIONS: readonly TodoEvidenceDisposition[];
export const TODO_DIMENSIONS: ReadonlyArray<{ key: TodoDimension; label: string; meaning: string }>;

export interface TodoImplementationDetails {
  stage: string;
  workerSessionId: string;
  model: string;
  branch: string;
  commitSha: string | null;
  changedFiles: string[];
  testSummary: string | null;
  mergedIn35Candidate: boolean;
  flockReviewStatus: string;
}

export interface TodoReadinessEvidence {
  candidateSha: string;
  hostId: string;
  os: string;
  command: string;
  capturedAt: string;
  passCount: number;
  failCount: number;
  skipCount: number;
  prerequisites: string[];
  evidenceDigest: string;
  confidence: TodoEvidenceConfidence;
  verificationTier: TodoVerificationTier;
  deliveryStage?: TodoDeliveryStage;
  verificationPrompt?: string;
  disposition?: TodoEvidenceDisposition;
}

export interface ResolvedTodoReadinessEvidence extends TodoReadinessEvidence {
  effectiveDisposition: TodoEvidenceDisposition;
}

export interface TodoIssue {
  todoId: string;
  number: number;
  rank: number;
  title: string;
  type: "bug" | "architecture";
  status: TodoStatus;
  rankingBasis: string;
  rankingExplanation: string;
  evidence: string;
  implementationStatus: string;
  nextStep: string;
  details: string[];
  relatedIssues: number[];
  scores?: Record<TodoDimension, number>;
  evidenceConfidence?: TodoEvidenceConfidence;
  acceptanceCriteria?: string[];
  implementationDetails?: TodoImplementationDetails;
  candidateSha?: string;
  verificationTier?: TodoVerificationTier;
  deliveryStage?: TodoDeliveryStage;
  verificationPrompt?: string;
  readinessEvidence?: TodoReadinessEvidence[];
}

export interface TodoSnapshot {
  schemaVersion: 1;
  revision: number;
  updatedAt: string;
  source: string;
  issues: TodoIssue[];
}

export interface TodoResolvedReadiness {
  targetCandidateSha: string | null;
  effectiveVerificationTier: TodoVerificationTier;
  claimedVerificationTier: TodoVerificationTier | null;
  effectiveConfidence: TodoEvidenceConfidence | null;
  claimedConfidence: TodoEvidenceConfidence | null;
  effectiveDeliveryStage: TodoDeliveryStage | null;
  claimedDeliveryStage: TodoDeliveryStage | null;
  downgradeReasons: string[];
  unverifiedCompletionNote: string | null;
  entries: ResolvedTodoReadinessEvidence[];
  acceptedEntries: ResolvedTodoReadinessEvidence[];
  rejectedEntries: ResolvedTodoReadinessEvidence[];
  supersededEntries: ResolvedTodoReadinessEvidence[];
  passingHosts: string[];
  failingHosts: string[];
  latestCapturedAt: string | null;
}

export interface TodoFlockSummaryIssue {
  todoId: string;
  number: number;
  rank: number;
  title: string;
  type: "bug" | "architecture";
  status: TodoStatus;
  candidateSha: string | null;
  verificationTier: TodoVerificationTier;
  claimedVerificationTier: TodoVerificationTier | null;
  deliveryStage: TodoDeliveryStage | null;
  claimedDeliveryStage: TodoDeliveryStage | null;
  evidenceConfidence: TodoEvidenceConfidence | null;
  claimedEvidenceConfidence: TodoEvidenceConfidence | null;
  scores: Record<TodoDimension, number> | null;
  nextStep: string;
  downgradeReasons: string[];
  unverifiedCompletionNote: string | null;
  receiptSummary: {
    totalReceipts: number;
    acceptedCount: number;
    rejectedCount: number;
    supersededCount: number;
    verifiedHosts: string[];
    failingHosts: string[];
    latestCapturedAt: string | null;
  };
  verificationPrompt?: string;
}

export interface TodoFlockSummaryJson {
  schemaVersion: 1;
  summaryKind: "copilot-flock-todo-summary";
  readOnly: true;
  executable: false;
  revision: number;
  updatedAt: string;
  source: string;
  counts: {
    total: number;
    shown: number;
    byStatus: Record<TodoStatus, number>;
    byVerificationTier: Record<TodoVerificationTier, number>;
  };
  issues: TodoFlockSummaryIssue[];
}

export interface TodoFlockSummaryOptions {
  format?: "both" | "json" | "text";
  status?: "all" | TodoStatus;
  type?: "all" | "bug" | "architecture";
  verificationTier?: "all" | TodoVerificationTier;
  sortKey?: TodoSortKey;
  direction?: "asc" | "desc";
  includeVerificationPrompt?: boolean;
}

export function validateTodoSnapshot(value: unknown): TodoSnapshot;
export function sortTodoIssues(issues: readonly TodoIssue[], key?: TodoSortKey, direction?: "asc" | "desc"): TodoIssue[];
export function appendTodoReadinessEvidence(
  issue: TodoIssue,
  entry: TodoReadinessEvidence,
  options?: { promoteCandidate?: boolean },
): TodoIssue;
export function assertEvidenceHistoryPreserved(previousSnapshot: unknown, nextSnapshot: unknown): void;
export function resolveTodoReadiness(issue: TodoIssue): TodoResolvedReadiness;
export function getTodoVerificationPrompt(issue: TodoIssue): string | null;
export function sanitizeTodoText(text: unknown): string;
export function summarizeTodosForFlock(
  snapshot: unknown,
  options: TodoFlockSummaryOptions & { format: "json" },
): TodoFlockSummaryJson;
export function summarizeTodosForFlock(
  snapshot: unknown,
  options: TodoFlockSummaryOptions & { format: "text" },
): string;
export function summarizeTodosForFlock(
  snapshot: unknown,
  options?: TodoFlockSummaryOptions,
): { json: TodoFlockSummaryJson; text: string };
