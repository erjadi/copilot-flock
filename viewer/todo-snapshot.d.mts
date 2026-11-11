export type TodoDimension = "riskReduction" | "userImpact" | "reach" | "urgency" | "unblockingValue" | "effortAndChangeRisk";
export type TodoSortKey = "editorial" | TodoDimension;
export const TODO_DIMENSIONS: ReadonlyArray<{ key: TodoDimension; label: string; meaning: string }>;
export interface TodoIssue {
  todoId: string;
  number: number;
  rank: number;
  title: string;
  type: "bug" | "architecture";
  status: "pending" | "in_progress" | "blocked" | "done";
  rankingBasis: string;
  rankingExplanation: string;
  evidence: string;
  implementationStatus: string;
  nextStep: string;
  details: string[];
  relatedIssues: number[];
  scores?: Record<TodoDimension, number>;
  evidenceConfidence?: "reported" | "reproduced" | "independently_verified";
  acceptanceCriteria?: string[];
}
export interface TodoSnapshot {
  schemaVersion: 1;
  revision: number;
  updatedAt: string;
  source: string;
  issues: TodoIssue[];
}
export function validateTodoSnapshot(value: unknown): TodoSnapshot;
export function sortTodoIssues(issues: readonly TodoIssue[], key?: TodoSortKey, direction?: "asc" | "desc"): TodoIssue[];
