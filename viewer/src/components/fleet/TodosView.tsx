import { useEffect, useMemo, useState } from "react";
import { ChevronDown, RefreshCw, Search } from "lucide-react";
import { req } from "@/lib/fleet/api";
import { validateTodoSnapshot, type TodoSnapshot } from "../../../todo-snapshot.mjs";
import { Btn, Input, Panel, Pill, Select } from "./ui";

const statusLabels = { pending: "Pending", in_progress: "In progress", blocked: "Blocked", done: "Done" };

export function TodosView() {
  const [snapshot, setSnapshot] = useState<TodoSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    setSnapshot(null);
    // Private tracker data always comes from this viewer, never a connection override.
    req<unknown>("", "/api/todos")
      .then(validateTodoSnapshot)
      .then((value) => { if (active) setSnapshot(value); })
      .catch((cause: unknown) => { if (active) setError(`Could not load the tracker snapshot (${cause instanceof Error ? cause.message : "request failed"}). Check viewer configuration and retry.`); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refresh]);

  const items = snapshot?.issues ?? [];
  const filtered = useMemo(() => items.filter((item) =>
    (status === "all" || item.status === status) &&
    (kind === "all" || item.type === kind) &&
    [item.title, item.todoId, `Local #${item.number}`, item.rankingExplanation, item.evidence, item.nextStep, ...item.details]
      .join(" ").toLowerCase().includes(query.trim().toLowerCase())
  ), [items, status, kind, query]);
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
    {snapshot && <p className="mt-3 break-words font-mono text-[11px] leading-5 text-muted-foreground">Source: {snapshot.source} · revision {snapshot.revision}<br />Snapshot updated: <time dateTime={snapshot.updatedAt}>{new Date(snapshot.updatedAt).toLocaleString()}</time> · Not a live feed; refresh to load a newer export.</p>}

    {error && <div role="alert" className="mt-6 rounded-xl border border-destructive/50 bg-destructive/10 p-4">
      <h2 className="font-medium text-destructive">Refresh failed - no ranking shown</h2>
      <p className="mt-2 text-sm">{error}</p>
      <p className="mt-1 text-xs text-muted-foreground">No cached ranking or synthetic examples are substituted.</p>
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
              </div>
              <ChevronDown aria-hidden="true" className="mt-1 h-4 w-4 shrink-0 text-muted-foreground transition-transform group-open/todo:rotate-180" />
            </summary>
            <div className="border-t border-border/70 p-4 sm:p-5">
              <dl className="grid gap-5 text-sm sm:grid-cols-2">
                {[["Ranking basis", item.rankingBasis], ["Evidence", item.evidence], ["Implementation", item.implementationStatus], ["Proposed next step", item.nextStep]].map(([label, text]) => <div key={label}><dt className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</dt><dd className="mt-2 whitespace-pre-wrap break-words leading-6">{text}</dd></div>)}
              </dl>
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
