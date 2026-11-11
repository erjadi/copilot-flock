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
}
export interface TodoSnapshot {
  schemaVersion: 1;
  revision: number;
  updatedAt: string;
  source: string;
  issues: TodoIssue[];
}
export function validateTodoSnapshot(value: unknown): TodoSnapshot;
