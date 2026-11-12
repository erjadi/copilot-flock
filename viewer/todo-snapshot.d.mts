export type TodoDimension = "riskReduction" | "userImpact" | "reach" | "urgency" | "unblockingValue" | "effortAndChangeRisk";
export type TodoSortKey = "editorial" | TodoDimension;
export type TodoClock = number | (() => number);
export type TodoFreshnessState = "age_only" | "fresh" | "stale" | "unavailable";
export const MAX_TODO_STALE_AFTER_MINUTES: number;
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
  staleAfterMinutes?: number;
}
export interface TodoRefreshState {
  snapshot: TodoSnapshot | null;
  lastSuccessfulFetchAt: string | null;
  lastSuccessfulRevision: number | null;
  lastSuccessfulUpdatedAt: string | null;
  unchangedRevision: boolean;
  error: string | null;
}
export interface TodoTimings {
  revision: number | null;
  source: string | null;
  sourceUpdatedAt: string | null;
  sourceElapsedMs: number | null;
  sourceAgeLabel: string | null;
  sourceAheadOfClock: boolean;
  lastSuccessfulFetchAt: string | null;
  fetchElapsedMs: number | null;
  fetchAgeLabel: string | null;
  fetchAheadOfClock: boolean;
  unchangedRevision: boolean;
  staleAfterMinutes: number | null;
  freshnessState: TodoFreshnessState;
  isStale: boolean | null;
  freshnessSummary: string;
  machinePresenceInferred: false;
}
export function parseTodoStaleAfterMinutes(value: unknown): number | null;
export function formatTodoElapsedAge(isoTimestamp: string, now?: TodoClock): string;
export function validateTodoSnapshot(value: unknown): TodoSnapshot;
export function sortTodoIssues(issues: readonly TodoIssue[], key?: TodoSortKey, direction?: "asc" | "desc"): TodoIssue[];
export function createTodoRefreshState(): TodoRefreshState;
export function beginTodoRefresh(prevState?: TodoRefreshState): TodoRefreshState;
export function formatTodoRefreshError(cause: unknown): string;
export function applyTodoRefreshSuccess(prevState: TodoRefreshState | undefined, rawSnapshot: unknown, options?: { now?: TodoClock }): TodoRefreshState;
export function applyTodoRefreshFailure(prevState: TodoRefreshState | undefined, cause: unknown): TodoRefreshState;
export function refreshTodoState(prevState: TodoRefreshState | undefined, loadSnapshot: () => Promise<unknown>, options?: { now?: TodoClock }): Promise<TodoRefreshState>;
export function describeTodoTimings(state: { snapshot?: TodoSnapshot | null; lastSuccessfulFetchAt?: string | null; unchangedRevision?: boolean } | null | undefined, options?: { now?: TodoClock; staleAfterMinutes?: number | string | null }): TodoTimings;
