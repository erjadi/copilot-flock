import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, RefreshCw, Search } from "lucide-react";
import { req } from "@/lib/fleet/api";
import {
  TODO_DIMENSIONS,
  applyTodoRefreshFailure,
  applyTodoRefreshSuccess,
  beginTodoRefresh,
  createTodoRefreshState,
  describeTodoTimings,
  sortTodoIssues,
  validateTodoSnapshot,
  type TodoRefreshState,
  type TodoSortKey,
} from "../../../todo-snapshot.mjs";
import { Btn, Input, Panel, Pill, Select } from "./ui";

const statusLabels = { pending: "Pending", in_progress: "In progress", blocked: "Blocked", done: "Done" };
const confidenceLabels = { reported: "Reported", reproduced: "Reproduced", independently_verified: "Independently verified" };

export interface TodosViewProps {
  now?: () => number;
  staleAfterMinutes?: number | null;
  initialState?: TodoRefreshState;
}

export function TodosView({ now, staleAfterMinutes, initialState }: TodosViewProps = {}) {
  const [state, setState] = useState<TodoRefreshState>(() => initialState ?? createTodoRefreshState());
  const [loading, setLoading] = useState(() => !initialState);
  const [refresh, setRefresh] = useState(0);
  const [, setAgeTick] = useState(0);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const [sortKey, setSortKey] = useState<TodoSortKey>("editorial");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const nowRef = useRef(now);
  nowRef.current = now;
  const skipInitialFetchRef = useRef(Boolean(initialState));

  useEffect(() => {
    if (skipInitialFetchRef.current && refresh === 0) return;
    let active = true;
    setLoading(true);
    setState((prev) => beginTodoRefresh(prev));
    // Private tracker data always comes from this viewer, never a connection override.
    req<unknown>("", "/api/todos")
      .then(validateTodoSnapshot)
      .then((value) => {
        const fetchedAtMs = (nowRef.current ?? Date.now)();
        if (!Number.isFinite(fetchedAtMs)) throw new Error("Invalid TODO clock value");
        if (active) setState((prev) => applyTodoRefreshSuccess(prev, value, { now: fetchedAtMs }));
      })
      .catch((cause: unknown) => {
        if (active) setState((prev) => applyTodoRefreshFailure(prev, cause));
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refresh]);

  useEffect(() => {
    if (now || (!state.snapshot && !state.lastSuccessfulFetchAt)) return;
    // Advance displayed elapsed ages locally without polling /api/todos.
    const timer = setInterval(() => setAgeTick((value) => value + 1), 15000);
    return () => clearInterval(timer);
  }, [now, state.snapshot, state.lastSuccessfulFetchAt]);

  const snapshot = state.snapshot;
  const error = state.error;
  const timings = describeTodoTimings(state, {
    now: now ?? Date.now,
    ...(staleAfterMinutes !== undefined ? { staleAfterMinutes } : {}),
  });
  const items = snapshot?.issues ?? [];
  const filtered = useMemo(() => sortTodoIssues(items.filter((item) =>
    (status === "all" || item.status === status) &&
    (kind === "all" || item.type === kind) &&
    [item.title, item.todoId, `Local #${item.number}`, item.rankingExplanation, item.evidence, item.nextStep, ...item.details, ...(item.acceptanceCriteria ?? [])]
      .join(" ").toLowerCase().includes(query.trim().toLowerCase())
  ), sortKey, direction), [items, status, kind, query, sortKey, direction]);
  const clearFilters = () => { setQuery(""); setStatus("all"); setKind("all"); };

  return <section className="mx-auto max-w-4xl" aria-labelledby="todos-title" aria-busy={loading}>
    <div className="flex flex-wrap items-center gap-3">
      <h1 id="todos-title" className="text-2xl font-semibold tracking-tight sm:text-3xl">Flock priorities</h1>
      <Pill tone="gpu">Provisional editorial ranking</Pill>
    </div>
    <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">What to look at next, and why. This is not a user-approved severity assessment or approval to implement a proposed fix.</p>
    <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground">
      <span>Viewer-wide tracker; not filtered by the active flock.</span>
      <Btn variant="outline" onClick={() => setRefresh((value) => value + 1)} disabled={loading}><RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />Refresh TODOs</Btn>
    </div>
    {snapshot && state.lastSuccessfulFetchAt && <Panel className="mt-4 p-3.5 sm:p-4" aria-label="Snapshot and refresh timestamps">
      <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] leading-5 text-muted-foreground">
        <span>Source: <span className="text-foreground">{snapshot.source}</span></span>
        <span>·</span>
        <span>revision <span className="text-foreground">{snapshot.revision}</span></span>
        {timings.unchangedRevision && <Pill tone="muted">Unchanged revision on last refresh</Pill>}
        <Pill tone={timings.freshnessState === "stale" ? "busy" : timings.freshnessState === "fresh" ? "info" : "muted"}>{timings.freshnessSummary}</Pill>
      </div>
      <dl className="mt-3 grid gap-3 border-t border-border/50 pt-3 font-mono text-[11px] leading-5 sm:grid-cols-2">
        <div>
          <dt className="text-[10px] uppercase tracking-widest text-muted-foreground">Source snapshot updated</dt>
          <dd className="mt-1 text-foreground">
            <time dateTime={snapshot.updatedAt}>{new Date(snapshot.updatedAt).toLocaleString()}</time>
            <span className="ml-1.5 text-muted-foreground">({timings.sourceAgeLabel})</span>
          </dd>
          <p className="mt-0.5 font-sans text-[11px] text-muted-foreground">Tracker authoring timestamp (<code className="font-mono text-[10px]">updatedAt</code>) for revision {snapshot.revision}.</p>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-widest text-muted-foreground">Last successful refresh</dt>
          <dd className="mt-1 text-foreground">
            <time dateTime={state.lastSuccessfulFetchAt}>{new Date(state.lastSuccessfulFetchAt).toLocaleString()}</time>
            <span className="ml-1.5 text-muted-foreground">({timings.fetchAgeLabel})</span>
          </dd>
          <p className="mt-0.5 font-sans text-[11px] text-muted-foreground">Last validated viewer fetch (<code className="font-mono text-[10px]">lastSuccessfulFetchAt</code>){timings.unchangedRevision ? "; content was not re-authored." : "."}</p>
        </div>
      </dl>
      <p className="mt-3 border-t border-border/50 pt-2.5 text-[11px] leading-5 text-muted-foreground">Not a live feed; refresh to check for a newer export. Snapshot age reflects tracker export authoring time only and never indicates machine online or offline state.</p>
    </Panel>}

    {error && <div role="alert" className="mt-6 rounded-xl border border-destructive/50 bg-destructive/10 p-4">
      <h2 className="font-medium text-destructive">Refresh failed - no ranking shown</h2>
      <p className="mt-2 text-sm">{error}</p>
      <p className="mt-1 text-xs text-muted-foreground">No cached ranking or synthetic examples are substituted.</p>
      <p className="mt-2 font-mono text-[11px] text-muted-foreground">
        {state.lastSuccessfulFetchAt
          ? <>Last successful refresh (<code className="text-[10px]">lastSuccessfulFetchAt</code>): <time dateTime={state.lastSuccessfulFetchAt}>{new Date(state.lastSuccessfulFetchAt).toLocaleString()}</time> ({timings.fetchAgeLabel}) · Failed refresh did not advance this timestamp.</>
          : <>Last successful refresh (<code className="text-[10px]">lastSuccessfulFetchAt</code>): none in this view.</>}
      </p>
    </div>}
    {loading && <p role="status" className="mt-6 text-sm text-muted-foreground">Loading tracker snapshot...</p>}

    <dl className="my-6 grid grid-cols-3 gap-3">
      {[["Total", items.length], ["Pending", items.filter((item) => item.status === "pending").length], ["Shown", filtered.length]].map(([label, count]) =>
        <Panel key={label} className="p-3 sm:p-4"><dt className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</dt><dd className="mt-2 font-mono text-2xl">{snapshot ? count : "-"}</dd></Panel>
      )}
    </dl>
    <div className="flex flex-col gap-2 sm:flex-row">
      <div className="relative min-w-0 flex-1"><Search className="pointer-events-none absolute left-3 top-3 h-3.5 w-3.5 text-muted-foreground" /><Input aria-label="Search TODOs" placeholder="Search title, ID, evidence..." className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
      <Select aria-label="TODO status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">All statuses</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</Select>
      <Select aria-label="TODO kind" value={kind} onChange={(event) => setKind(event.target.value)}><option value="all">All kinds</option><option value="bug">Bug</option><option value="architecture">Architecture</option></Select>
    </div>
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <label htmlFor="todo-sort" className="text-xs text-muted-foreground">Sort by</label>
      <Select id="todo-sort" aria-label="TODO sort dimension" value={sortKey} onChange={(event) => {
        const key = TODO_DIMENSIONS.find(dimension => dimension.key === event.target.value)?.key;
        if (key || event.target.value === "editorial") setSortKey(key ?? "editorial");
      }}><option value="editorial">Editorial rank (default)</option>{TODO_DIMENSIONS.map(({ key, label }) => <option key={key} value={key}>{label}</option>)}</Select>
      <Select aria-label="TODO sort direction" value={direction} onChange={(event) => { if (event.target.value === "asc" || event.target.value === "desc") setDirection(event.target.value); }}>
        <option value="asc">{sortKey === "editorial" ? "Ascending rank" : "Ascending score (1 to 5)"}</option>
        <option value="desc">{sortKey === "editorial" ? "Descending rank" : "Descending score (5 to 1)"}</option>
      </Select>
    </div>
    <p className="mt-3 text-xs leading-5 text-muted-foreground">Scores: 1 = low, 5 = high. Effort and change risk: 5 = harder or riskier, not better. Unscored items sort last in either direction; ties use editorial rank, then stable ID. Rank labels stay editorial.</p>
    <details className="mt-3 rounded-lg border border-border/60 p-3 text-xs text-muted-foreground">
      <summary className="cursor-pointer">How priority and scores work</summary>
      <p className="mt-2 leading-5">The tracker owns editorial order: risk reduction and user impact lead, then urgency and unblocking value; reach and effort break ties. No aggregate score is calculated. Evidence confidence is separate, not a rank penalty. Priority is not readiness or authorization.</p>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">{TODO_DIMENSIONS.map(({ key, label, meaning }) => <div key={key}><dt className="font-medium text-foreground">{label}</dt><dd className="mt-1 leading-5">{meaning}</dd></div>)}</dl>
    </details>
    <ol className="mt-4 space-y-3">
      {filtered.map((item) => <li key={item.todoId} value={item.rank}>
        <Panel>
          <details className="group/todo">
            <summary className="flex cursor-pointer list-none items-start gap-3 rounded-xl p-4 focus-visible:outline-2 focus-visible:outline-busy sm:gap-4 sm:p-5 [&::-webkit-details-marker]:hidden">
              <span className="font-mono text-2xl text-online" aria-label={`Rank ${item.rank}`}>{String(item.rank).padStart(2, "0")}</span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[10px] text-muted-foreground">Local #{item.number} · {item.todoId}</span><Pill>{item.type}</Pill><Pill tone={item.status === "done" ? "online" : item.status === "blocked" ? "destructive" : "gpu"}>{statusLabels[item.status]}</Pill></div>
                <h2 className="mt-2 break-words text-base font-medium sm:text-lg">{item.title}</h2>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">{item.rankingExplanation}</p>
                <dl className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3">
                  {TODO_DIMENSIONS.map(({ key, label, meaning }) => <div key={key} title={meaning}><dt className="text-[10px] text-muted-foreground">{label}</dt><dd className="mt-1 font-mono text-xs">{item.scores ? `${item.scores[key]}/5` : "Unscored"}</dd></div>)}
                </dl>
                <p className="mt-3 text-xs text-muted-foreground">Evidence confidence: <span className="text-foreground">{item.evidenceConfidence ? confidenceLabels[item.evidenceConfidence] : "Unknown"}</span></p>
              </div>
              <ChevronDown aria-hidden="true" className="mt-1 h-4 w-4 shrink-0 text-muted-foreground transition-transform group-open/todo:rotate-180" />
            </summary>
            <div className="border-t border-border/70 p-4 sm:p-5">
              <dl className="grid gap-5 text-sm sm:grid-cols-2">
                {[["Ranking basis", item.rankingBasis], ["Evidence", item.evidence], ["Implementation", item.implementationStatus], ["Proposed next step", item.nextStep]].map(([label, text]) => <div key={label}><dt className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</dt><dd className="mt-2 whitespace-pre-wrap break-words leading-6">{text}</dd></div>)}
              </dl>
              <div className="mt-5 border-t border-border/50 pt-4">
                <h3 className="text-[10px] uppercase tracking-widest text-muted-foreground">Acceptance criteria</h3>
                {item.acceptanceCriteria?.length
                  ? <ul className="mt-2 list-disc space-y-2 pl-4 text-sm leading-6">{item.acceptanceCriteria.map((criterion, index) => <li key={index} className="whitespace-pre-wrap break-words">{criterion}</li>)}</ul>
                  : <p className="mt-2 text-sm text-muted-foreground">Not supplied. Readiness or completion is not inferred.</p>}
              </div>
              {item.details.length > 0 && <ul className="mt-5 list-disc space-y-2 border-t border-border/50 pt-4 pl-4 text-sm leading-6 text-muted-foreground">{item.details.map((detail, index) => <li key={index} className="whitespace-pre-wrap break-words">{detail}</li>)}</ul>}
              <p className="mt-4 text-xs text-muted-foreground">Related local items: {item.relatedIssues.length ? item.relatedIssues.map((number) => `#${number}`).join(", ") : "None"}. Related does not mean prerequisite.</p>
            </div>
          </details>
        </Panel>
      </li>)}
    </ol>
    {snapshot && filtered.length === 0 && <div role="status" className="mt-4 rounded-xl border border-dashed border-border p-8 text-center">
      <p className="text-sm">{items.length ? "No items match these filters." : "This tracker snapshot has no TODOs."}</p>
      {items.length > 0 && <Btn onClick={clearFilters} className="mt-2">Clear filters</Btn>}
    </div>}
    <p className="mt-8 font-mono text-[10px] leading-5 text-muted-foreground">IDs and numbers belong to the local tracker, not GitHub issues. Proposals remain proposals until selected and implemented.</p>
  </section>;
}
