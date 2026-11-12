import { useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, Copy, RefreshCw, Search } from "lucide-react";
import { req } from "@/lib/fleet/api";
import {
  TODO_DIMENSIONS,
  VERIFICATION_TIERS,
  getTodoVerificationPrompt,
  resolveTodoReadiness,
  sortTodoIssues,
  validateTodoSnapshot,
  type TodoDeliveryStage,
  type TodoEvidenceConfidence,
  type TodoEvidenceDisposition,
  type TodoSnapshot,
  type TodoSortKey,
  type TodoVerificationTier,
} from "../../../todo-snapshot.mjs";
import { Btn, Input, Panel, Pill, Select } from "./ui";

const statusLabels = { pending: "Pending", in_progress: "In progress", blocked: "Blocked", done: "Done" };
const confidenceLabels: Record<TodoEvidenceConfidence, string> = {
  reported: "Reported",
  reproduced: "Reproduced",
  independently_verified: "Independently verified",
};
const verificationTierLabels: Record<TodoVerificationTier, string> = {
  unverified: "Unverified",
  source_reviewed: "Source reviewed",
  unit_synthetic: "Unit / synthetic",
  live_multi_pc: "Live multi-PC",
};
const deliveryStageLabels: Record<TodoDeliveryStage, string> = {
  proposed: "Proposed",
  approved: "Approved",
  implemented: "Implemented",
  deployed: "Deployed",
  verified: "Verified",
};
const dispositionLabels: Record<TodoEvidenceDisposition, string> = {
  accepted: "Accepted",
  rejected: "Rejected",
  superseded: "Superseded",
};

function tierTone(tier: TodoVerificationTier): "online" | "info" | "busy" | "muted" {
  if (tier === "live_multi_pc") return "online";
  if (tier === "unit_synthetic") return "info";
  if (tier === "source_reviewed") return "busy";
  return "muted";
}

export function TodosView() {
  const [snapshot, setSnapshot] = useState<TodoSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const [verificationTier, setVerificationTier] = useState<"all" | TodoVerificationTier>("all");
  const [sortKey, setSortKey] = useState<TodoSortKey>("editorial");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const [copiedTodoId, setCopiedTodoId] = useState<string | null>(null);
  const [copyNotice, setCopyNotice] = useState<{ todoId: string; message: string } | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    setSnapshot(null);
    // Private tracker data always comes from this viewer, never a connection override.
    req<unknown>("", "/api/todos")
      .then(validateTodoSnapshot)
      .then((value) => { if (active) setSnapshot(value); })
      .catch((cause: unknown) => {
        if (active) setError(cause instanceof Error && cause.message === "403"
          ? "Access is restricted to the configured home LAN or an authenticated SSH connection. Other networks are not permitted."
          : `Could not load the tracker snapshot (${cause instanceof Error ? cause.message : "request failed"}). Check viewer configuration and retry.`);
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refresh]);

  const items = snapshot?.issues ?? [];
  const readinessById = useMemo(
    () => new Map(items.map((item) => [item.todoId, resolveTodoReadiness(item)])),
    [items],
  );

  const filtered = useMemo(() => sortTodoIssues(items.filter((item) => {
    const readiness = readinessById.get(item.todoId) ?? resolveTodoReadiness(item);
    const receiptTerms = readiness.entries.flatMap((entry) => [
      entry.candidateSha,
      entry.hostId,
      entry.os,
      entry.command,
      entry.evidenceDigest,
      ...entry.prerequisites,
    ]);
    return (
      (status === "all" || item.status === status) &&
      (kind === "all" || item.type === kind) &&
      (verificationTier === "all" || readiness.effectiveVerificationTier === verificationTier) &&
      [
        item.title,
        item.todoId,
        `Local #${item.number}`,
        item.rankingExplanation,
        item.evidence,
        item.nextStep,
        readiness.targetCandidateSha ?? "",
        verificationTierLabels[readiness.effectiveVerificationTier],
        readiness.effectiveDeliveryStage ? deliveryStageLabels[readiness.effectiveDeliveryStage] : "",
        ...item.details,
        ...(item.acceptanceCriteria ?? []),
        ...receiptTerms,
      ]
        .join(" ")
        .toLowerCase()
        .includes(query.trim().toLowerCase())
    );
  }), sortKey, direction), [items, readinessById, status, kind, verificationTier, query, sortKey, direction]);

  const clearFilters = () => {
    setQuery("");
    setStatus("all");
    setKind("all");
    setVerificationTier("all");
  };

  const handleCopyPrompt = async (todoId: string, prompt: string | null) => {
    if (!prompt) return;
    // Copy-only helper: writes text to the clipboard and never executes commands or sessions.
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(prompt);
      setCopiedTodoId(todoId);
      setCopyNotice({ todoId, message: "Verification prompt copied to clipboard (not executed)." });
    } catch {
      setCopiedTodoId(null);
      setCopyNotice({ todoId, message: "Clipboard unavailable here; select and copy the prompt text directly." });
    }
    copyTimerRef.current = setTimeout(() => {
      setCopiedTodoId(null);
      setCopyNotice((current) => (current?.todoId === todoId ? null : current));
    }, 2500);
  };

  const verifiedMultiPcCount = useMemo(
    () => items.filter((item) => (readinessById.get(item.todoId) ?? resolveTodoReadiness(item)).effectiveVerificationTier === "live_multi_pc").length,
    [items, readinessById],
  );

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

    <dl className="my-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
      {[
        ["Total", items.length],
        ["Pending", items.filter((item) => item.status === "pending").length],
        ["Live multi-PC", verifiedMultiPcCount],
        ["Shown", filtered.length],
      ].map(([label, count]) =>
        <Panel key={label} className="p-3 sm:p-4"><dt className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</dt><dd className="mt-2 font-mono text-2xl">{snapshot ? count : "-"}</dd></Panel>
      )}
    </dl>
    <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
      <div className="relative min-w-0 flex-1 basis-56"><Search className="pointer-events-none absolute left-3 top-3 h-3.5 w-3.5 text-muted-foreground" /><Input aria-label="Search TODOs" placeholder="Search title, ID, SHA, host, evidence..." className="pl-9" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
      <Select aria-label="TODO status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="all">All statuses</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</Select>
      <Select aria-label="TODO kind" value={kind} onChange={(event) => setKind(event.target.value)}><option value="all">All kinds</option><option value="bug">Bug</option><option value="architecture">Architecture</option></Select>
      <Select aria-label="TODO verification tier" value={verificationTier} onChange={(event) => {
        const next = VERIFICATION_TIERS.find((tier) => tier === event.target.value);
        setVerificationTier(next ?? "all");
      }}>
        <option value="all">All verification tiers</option>
        {VERIFICATION_TIERS.map((tier) => <option key={tier} value={tier}>{verificationTierLabels[tier]}</option>)}
      </Select>
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
      <p className="mt-2 leading-5">The tracker owns editorial order: risk reduction and user impact lead, then urgency and unblocking value; reach and effort break ties. No aggregate score is calculated. Evidence confidence is separate, not a rank penalty. Priority is not readiness or authorization. Marking an item Done or Implemented never promotes verification tier or confidence without matching candidate-and-host receipts.</p>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">{TODO_DIMENSIONS.map(({ key, label, meaning }) => <div key={key}><dt className="font-medium text-foreground">{label}</dt><dd className="mt-1 leading-5">{meaning}</dd></div>)}</dl>
    </details>
    <ol className="mt-4 space-y-3">
      {filtered.map((item) => {
        const readiness = readinessById.get(item.todoId) ?? resolveTodoReadiness(item);
        const verificationPrompt = getTodoVerificationPrompt(item);
        const isCopied = copiedTodoId === item.todoId;
        const itemCopyNotice = copyNotice?.todoId === item.todoId ? copyNotice.message : null;
        return <li key={item.todoId} value={item.rank}>
          <Panel>
            <details className="group/todo">
              <summary className="flex cursor-pointer list-none items-start gap-3 rounded-xl p-4 focus-visible:outline-2 focus-visible:outline-busy sm:gap-4 sm:p-5 [&::-webkit-details-marker]:hidden">
                <span className="font-mono text-2xl text-online" aria-label={`Rank ${item.rank}`}>{String(item.rank).padStart(2, "0")}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">Local #{item.number} · {item.todoId}</span>
                    <Pill>{item.type}</Pill>
                    <Pill tone={item.status === "done" ? "online" : item.status === "blocked" ? "destructive" : "gpu"}>{statusLabels[item.status]}</Pill>
                    <Pill tone={tierTone(readiness.effectiveVerificationTier)}>{verificationTierLabels[readiness.effectiveVerificationTier]}</Pill>
                    {readiness.effectiveDeliveryStage && <Pill tone={readiness.effectiveDeliveryStage === "verified" ? "online" : "info"}>Stage: {deliveryStageLabels[readiness.effectiveDeliveryStage]}</Pill>}
                    {readiness.targetCandidateSha && <span className="font-mono text-[10px] text-muted-foreground" title={`Candidate SHA ${readiness.targetCandidateSha}`}>@{readiness.targetCandidateSha.slice(0, 12)}</span>}
                  </div>
                  <h2 className="mt-2 break-words text-base font-medium sm:text-lg">{item.title}</h2>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">{item.rankingExplanation}</p>
                  <dl className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3">
                    {TODO_DIMENSIONS.map(({ key, label, meaning }) => <div key={key} title={meaning}><dt className="text-[10px] text-muted-foreground">{label}</dt><dd className="mt-1 font-mono text-xs">{item.scores ? `${item.scores[key]}/5` : "Unscored"}</dd></div>)}
                  </dl>
                  <p className="mt-3 text-xs text-muted-foreground">
                    Evidence confidence: <span className="text-foreground">{readiness.effectiveConfidence ? confidenceLabels[readiness.effectiveConfidence] : "Unknown"}</span>
                    {" · "}Verification: <span className="text-foreground">{verificationTierLabels[readiness.effectiveVerificationTier]}</span>
                    {readiness.entries.length > 0 && <span> · Receipts: <span className="font-mono text-foreground">{readiness.acceptedEntries.length}</span> accepted / <span className="font-mono text-foreground">{readiness.entries.length}</span> total</span>}
                  </p>
                  {(readiness.downgradeReasons.length > 0 || readiness.unverifiedCompletionNote) && (
                    <p className="mt-1.5 text-xs text-busy">
                      {readiness.downgradeReasons[0] ?? readiness.unverifiedCompletionNote}
                    </p>
                  )}
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

                <div className="mt-5 border-t border-border/50 pt-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-[10px] uppercase tracking-widest text-muted-foreground">Readiness &amp; verification evidence</h3>
                    <Btn
                      type="button"
                      variant="outline"
                      disabled={!verificationPrompt}
                      onClick={() => { void handleCopyPrompt(item.todoId, verificationPrompt); }}
                    >
                      {isCopied ? <Check className="h-3.5 w-3.5 text-online" /> : <Copy className="h-3.5 w-3.5" />}
                      {isCopied ? "Copied verification prompt" : "Copy verification prompt"}
                    </Btn>
                  </div>
                  <p className="mt-1 text-[11px] text-muted-foreground">Copying places text on your clipboard only and never executes commands or opens sessions.</p>
                  {itemCopyNotice && <p role="status" className="mt-1.5 text-xs text-online">{itemCopyNotice}</p>}

                  <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-4">
                    <div><dt className="text-[10px] text-muted-foreground">Candidate SHA</dt><dd className="mt-1 break-all font-mono">{readiness.targetCandidateSha ?? "Not bound"}</dd></div>
                    <div><dt className="text-[10px] text-muted-foreground">Effective tier</dt><dd className="mt-1 font-mono">{verificationTierLabels[readiness.effectiveVerificationTier]}</dd></div>
                    <div><dt className="text-[10px] text-muted-foreground">Delivery stage</dt><dd className="mt-1 font-mono">{readiness.effectiveDeliveryStage ? deliveryStageLabels[readiness.effectiveDeliveryStage] : "Not supplied"}</dd></div>
                    <div><dt className="text-[10px] text-muted-foreground">Receipt history</dt><dd className="mt-1 font-mono">{readiness.acceptedEntries.length} accepted · {readiness.rejectedEntries.length} rejected · {readiness.supersededEntries.length} superseded</dd></div>
                  </dl>

                  {(readiness.unverifiedCompletionNote || readiness.downgradeReasons.length > 0) && (
                    <ul className="mt-3 list-disc space-y-1 rounded-lg border border-busy/25 bg-busy/8 p-3 pl-7 text-xs text-busy">
                      {readiness.unverifiedCompletionNote && <li>{readiness.unverifiedCompletionNote}</li>}
                      {readiness.downgradeReasons.map((reason, index) => <li key={index}>{reason}</li>)}
                    </ul>
                  )}

                  {verificationPrompt ? (
                    <div className="mt-3">
                      <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Verification prompt (read-only)</div>
                      <pre className="mt-1.5 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border/60 bg-background/70 p-3 font-mono text-[11px] leading-5">{verificationPrompt}</pre>
                    </div>
                  ) : (
                    <p className="mt-3 text-xs text-muted-foreground">Verification prompt: Not supplied.</p>
                  )}

                  <div className="mt-4">
                    <div className="text-[10px] uppercase tracking-widest text-muted-foreground">Host &amp; candidate receipt log</div>
                    {readiness.entries.length === 0 ? (
                      <p className="mt-1.5 text-xs text-muted-foreground">No structured verification receipts recorded yet.</p>
                    ) : (
                      <ol className="mt-2 space-y-2">
                        {readiness.entries.map((entry, index) => (
                          <li key={`${entry.candidateSha}-${entry.hostId}-${entry.capturedAt}-${index}`} className="rounded-lg border border-border/60 bg-background/50 p-3 text-xs">
                            <div className="flex flex-wrap items-center gap-2">
                              <Pill tone={entry.effectiveDisposition === "accepted" ? "online" : entry.effectiveDisposition === "rejected" ? "destructive" : "muted"}>
                                {dispositionLabels[entry.effectiveDisposition]}
                              </Pill>
                              <span className="font-mono font-medium text-foreground">{entry.hostId}</span>
                              <span className="font-mono text-muted-foreground">{entry.os}</span>
                              <span className="font-mono text-muted-foreground" title={`Candidate SHA ${entry.candidateSha}`}>@{entry.candidateSha.slice(0, 12)}</span>
                              <time className="font-mono text-[11px] text-muted-foreground" dateTime={entry.capturedAt}>{new Date(entry.capturedAt).toLocaleString()}</time>
                            </div>
                            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-muted-foreground">
                              <span>Tier: <span className="text-foreground">{verificationTierLabels[entry.verificationTier]}</span></span>
                              <span>Confidence: <span className="text-foreground">{confidenceLabels[entry.confidence]}</span></span>
                              <span>Counts: <span className="text-online">{entry.passCount} pass</span> · <span className={entry.failCount > 0 ? "text-destructive" : "text-foreground"}>{entry.failCount} fail</span> · <span>{entry.skipCount} skip</span></span>
                            </div>
                            <div className="mt-1.5 break-words font-mono text-[11px] text-muted-foreground">Command: <span className="text-foreground">{entry.command}</span></div>
                            <div className="mt-1 break-all font-mono text-[10px] text-muted-foreground">Digest: {entry.evidenceDigest}</div>
                            <div className="mt-1 break-words text-[11px] text-muted-foreground">Prerequisites: {entry.prerequisites.length ? entry.prerequisites.join("; ") : "None"}</div>
                          </li>
                        ))}
                      </ol>
                    )}
                  </div>
                </div>

                {item.details.length > 0 && <ul className="mt-5 list-disc space-y-2 border-t border-border/50 pt-4 pl-4 text-sm leading-6 text-muted-foreground">{item.details.map((detail, index) => <li key={index} className="whitespace-pre-wrap break-words">{detail}</li>)}</ul>}
                <p className="mt-4 text-xs text-muted-foreground">Related local items: {item.relatedIssues.length ? item.relatedIssues.map((number) => `#${number}`).join(", ") : "None"}. Related does not mean prerequisite.</p>
              </div>
            </details>
          </Panel>
        </li>;
      })}
    </ol>
    {snapshot && filtered.length === 0 && <div role="status" className="mt-4 rounded-xl border border-dashed border-border p-8 text-center">
      <p className="text-sm">{items.length ? "No items match these filters." : "This tracker snapshot has no TODOs."}</p>
      {items.length > 0 && <Btn onClick={clearFilters} className="mt-2">Clear filters</Btn>}
    </div>}
    <p className="mt-8 font-mono text-[10px] leading-5 text-muted-foreground">IDs and numbers belong to the local tracker, not GitHub issues. Proposals remain proposals until selected and implemented.</p>
  </section>;
}
