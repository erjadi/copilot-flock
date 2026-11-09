import { useMemo, useState } from "react";
import { Check, ChevronDown, CircleAlert, GitMerge, KeyRound, LoaderCircle, Play, ShieldCheck, Stethoscope } from "lucide-react";
import type { Ctx } from "./Console";
import { post } from "@/lib/fleet/api";
import { GOVERNANCE_ROUNDS, PIPELINE_STAGES, RELEASE, ROLLOUT_HEALTH, getRoundStats, type Ballot, type GovernanceRound } from "@/lib/fleet/governance";
import { Btn, Dot, PageHeading, Panel, Pill, SmartMessage } from "./ui";
import { cn } from "@/lib/utils";

interface ActionResult { kind: "vote" | "diagnose"; title: string; body: string; simulated: boolean; error?: boolean }

export function GovernanceView({ ctx }: { ctx: Ctx }) {
  const [roundNumber, setRoundNumber] = useState(4);
  const [busy, setBusy] = useState<"vote" | "diagnose" | null>(null);
  const [result, setResult] = useState<ActionResult | null>(null);
  const round = GOVERNANCE_ROUNDS[roundNumber - 1];
  const stats = getRoundStats(round);
  const finalStats = useMemo(() => getRoundStats(GOVERNANCE_ROUNDS[3]), []);

  const run = async (kind: "vote" | "diagnose") => {
    setBusy(kind);
    setResult(null);
    const machines = round.ballots.filter((ballot) => ballot.vote !== "QUEUED OFFLINE").map((ballot) => ballot.machineId);
    const path = kind === "vote" ? "/api/vote-release" : "/api/diagnose";
    const body = kind === "vote"
      ? { branch: "main", sha: GOVERNANCE_ROUNDS[3].sha, machines, rpc: "review_release" }
      : { version: RELEASE.version, fix: false, machines };
    try {
      const response = await post<{ approvedForMerge?: boolean; accepted?: number; total?: number; healthy?: number; results?: { machineId: string; ok: boolean; detail?: string }[] }>(
        ctx.base, ctx.mode, path, body,
        () => kind === "vote"
          ? { approvedForMerge: true, accepted: 6, total: 6, round: 4, sha: GOVERNANCE_ROUNDS[3].sha }
          : { healthy: 6, results: machines.map((machineId) => ({ machineId, ok: true, detail: "Single daemon · v2.1.0 · key registered · boot persistent · Coordinator + Tracker healthy" })) },
      );
      const healthy = response.results?.filter((item) => item.ok).length;
      const title = kind === "vote"
        ? `${response.accepted ?? finalStats.accepted}/${response.total ?? finalStats.online} ACCEPT · ${response.approvedForMerge === false ? "merge blocked" : "quorum reached"}`
        : `${healthy ?? response.healthy ?? finalStats.online}/${finalStats.online} online nodes verified`;
      const details = kind === "vote"
        ? `Signed \`vote-release\` ballots validated for \`${GOVERNANCE_ROUNDS[3].sha}\`. ${response.approvedForMerge === false ? "At least one online voter still blocks merge." : "`approvedForMerge: true` · fast-forward and fleet rollout are permitted."}`
        : response.results?.map((item) => `- **${item.machineId}:** ${item.ok ? "Healthy" : "Attention required"}${item.detail ? ` — ${item.detail}` : ""}`).join("\n") ?? "Single daemon, version, Ed25519 registration, boot persistence, and both required threads verified.";
      setResult({ kind, title, body: details, simulated: Boolean(response.simulated) });
      ctx.pushEvents([{ id: `evt-${Date.now()}`, timestamp: new Date().toISOString(), type: "outbox", target: "governance", fromMachine: "LINUX-CONSOLE", toMachine: machines.join(","), action: kind === "vote" ? "vote-release" : "diagnose", summary: title, payload: body }]);
    } catch (error) {
      setResult({ kind, title: `${kind === "vote" ? "Vote" : "Diagnose"} failed`, body: String(error), simulated: ctx.mode === "seed", error: true });
    } finally { setBusy(null); }
  };

  return <div>
    <PageHeading title="Release governance" description="Synthetic preview rounds, not signed release evidence. Live voting requires unanimous exact-candidate consent.">
      <div className="flex flex-wrap gap-2">
        <Btn variant="outline" disabled={Boolean(busy)} onClick={() => run("vote")}>{busy === "vote" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}Run live vote</Btn>
        <Btn variant="primary" disabled={Boolean(busy)} onClick={() => run("diagnose")}>{busy === "diagnose" ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Stethoscope className="h-3.5 w-3.5" />}Run fleet diagnose</Btn>
      </div>
    </PageHeading>
    <p className="mb-4 text-xs text-muted-foreground">The sample ballots, fingerprints and rollout states below are fictional. No real signatures or captured fleet history are bundled.</p>

    <Panel className="overflow-hidden">
      <ol className="grid grid-cols-5 divide-x divide-border/45">
        {PIPELINE_STAGES.map((stage, index) => <li key={stage.title} className="relative min-w-0 px-1 py-4 text-center sm:px-3 sm:py-5">
          <div className="mx-auto grid h-5 w-5 place-items-center rounded-full border border-online/25 bg-online/8 text-online"><Check className="h-3 w-3" /></div>
          <div className="mt-2 truncate text-[9px] font-medium leading-4 sm:text-[11px]"><span className="sm:hidden">{stage.short}</span><span className="hidden sm:inline">{stage.title}</span></div>
          <div className="mt-1 hidden font-mono text-[9px] text-muted-foreground lg:block">{stage.detail}</div>
          <span className="absolute right-0.5 top-2.5 font-mono text-[8px] text-muted-foreground/45 sm:right-3 sm:top-3">0{index + 1}</span>
        </li>)}
      </ol>
      <div className="border-t border-border/55 px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2 text-xs"><ShieldCheck className="h-4 w-4 text-online" /><span className="font-medium">Unanimous quorum</span></div><span className="font-mono text-[9px] text-muted-foreground sm:text-[10px]">{finalStats.accepted}/{finalStats.online} online ACCEPT · {finalStats.offlineQueued} offline queued</span></div>
        <div className="mt-3 h-0.5 overflow-hidden rounded-full bg-muted" role="progressbar" aria-label="Online release quorum" aria-valuemin={0} aria-valuemax={finalStats.online} aria-valuenow={finalStats.accepted}><div className="h-full rounded-full bg-online transition-all" style={{ width: `${finalStats.accepted / finalStats.online * 100}%` }} /></div>
        <div className="mt-2 truncate font-mono text-[9px] text-muted-foreground">Service Bus · {RELEASE.serviceBus} / {RELEASE.queue}</div>
      </div>
    </Panel>

    {result && <Panel className={cn("enter-up mt-4 p-4 sm:p-5", result.error && "border-destructive/30")}>
      <div className="flex flex-wrap items-center gap-2"><Dot tone={result.error ? "muted" : "online"} /><h3 className={cn("text-xs font-medium", result.error && "text-destructive")}>{result.title}</h3><Pill tone={result.error ? "destructive" : result.simulated ? "muted" : "online"} className="ml-auto">{result.error ? "Error" : result.simulated ? "Preview simulation" : "Live result"}</Pill></div>
      <div className="mt-3 max-h-64 overflow-y-auto"><SmartMessage text={result.body} compact /></div>
    </Panel>}

    <section className="mt-8" aria-labelledby="rounds-heading">
      <div className="mb-4 flex items-end justify-between gap-4"><div><h3 id="rounds-heading" className="text-sm font-medium">Voting rounds</h3><p className="mt-1 text-xs text-muted-foreground">Every rejection resets the gate; every fix earns a new signed ballot.</p></div><span className="hidden font-mono text-[9px] text-muted-foreground sm:block">origin/{RELEASE.branch}</span></div>
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4" role="tablist" aria-label="Release voting rounds">
        {GOVERNANCE_ROUNDS.map((item) => {
          const itemStats = getRoundStats(item);
          const selected = item.number === roundNumber;
          return <button key={item.sha} role="tab" aria-selected={selected} onClick={() => setRoundNumber(item.number)} className={cn("min-w-0 rounded-xl border p-3 text-left transition sm:p-4", selected ? "border-border bg-panel" : "border-border/50 bg-panel/25 hover:bg-panel/50")}>
            <div className="flex items-center gap-2"><span className={cn("font-mono text-[9px]", selected ? "text-foreground" : "text-muted-foreground")}>ROUND {item.number}</span><span className="ml-auto font-mono text-[9px] text-muted-foreground">{item.sha}</span></div>
            <div className="mt-3 flex items-center gap-2"><Dot tone={itemStats.approvedForMerge ? "online" : "muted"} /><span className={cn("text-xs font-medium", itemStats.rejected > 0 && "text-destructive", itemStats.approvedForMerge && "text-online")}>{itemStats.accepted} ACCEPT <span className="text-muted-foreground">/ {itemStats.rejected} REJECT</span></span></div>
            <div className="mt-1 truncate text-[10px] text-muted-foreground">{item.summary}</div>
          </button>;
        })}
      </div>

      <RoundDetail round={round} />
    </section>

    <section className="mt-8" aria-labelledby="ballots-heading">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-2"><div><h3 id="ballots-heading" className="text-sm font-medium">Ballot & rollout matrix</h3><p className="mt-1 text-xs text-muted-foreground">Native checks, Ed25519 proof, review notes, and post-merge health.</p></div><Pill tone={stats.approvedForMerge ? "online" : "destructive"}>{stats.approvedForMerge ? "approvedForMerge: true" : "merge blocked"}</Pill></div>
      <div className="space-y-2">{round.ballots.map((ballot) => <BallotRow key={ballot.machineId} ballot={ballot} released={roundNumber === 4} />)}</div>
    </section>
  </div>;
}

function RoundDetail({ round }: { round: GovernanceRound }) {
  const stats = getRoundStats(round);
  return <Panel className="enter-up mt-3 p-4 sm:p-5 lg:p-6" key={round.sha}>
    <div className="flex flex-wrap items-start justify-between gap-3"><div><div className="flex items-center gap-2 font-mono text-[10px] text-muted-foreground"><GitMerge className="h-3.5 w-3.5" />{round.sha}<span>·</span><span>{round.branch}</span></div><h4 className="mt-2 text-sm font-medium">{round.summary}</h4></div><Pill tone={stats.approvedForMerge ? "online" : "destructive"}>{stats.approvedForMerge ? "Merged to main" : `${stats.rejected} blocking ${stats.rejected === 1 ? "vote" : "votes"}`}</Pill></div>
    <div className="mt-4"><SmartMessage text={round.change} compact /></div>
    {round.blockers.length > 0 ? <div className="mt-5 space-y-2">{round.blockers.map((blocker, index) => <details key={blocker.id} className="group rounded-lg border border-destructive/15 bg-destructive/[0.025] px-3 py-3 sm:px-4" open={index === 0}>
      <summary className="flex cursor-pointer list-none items-start gap-2 [&::-webkit-details-marker]:hidden"><CircleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /><span className="min-w-0 flex-1 text-xs font-medium">{blocker.title}</span><span className="hidden font-mono text-[9px] text-muted-foreground sm:inline">fixed in {blocker.resolvedIn}</span><ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" /></summary>
      <div className="ml-5 mt-3 border-l border-border/60 pl-4"><SmartMessage text={blocker.detail} compact /><div className="mt-3 rounded-md bg-online/[0.035] p-3"><div className="mb-1 font-mono text-[9px] uppercase tracking-wider text-online">Resolution · {blocker.resolvedIn}</div><SmartMessage text={blocker.resolution} compact /></div><div className="mt-2 font-mono text-[9px] text-muted-foreground">Raised by {blocker.raisedBy.join(" + ")}</div></div>
    </details>)}</div> : <div className="mt-5 flex items-start gap-3 rounded-lg border border-online/15 bg-online/[0.025] p-4"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-online" /><div className="text-xs leading-5"><span className="font-medium text-online">No example blockers remain.</span><span className="text-muted-foreground"> The seven fictional nodes accept this synthetic round. No real merge, deployment or signed quorum is asserted.</span></div></div>}
  </Panel>;
}

function BallotRow({ ballot, released }: { ballot: Ballot; released: boolean }) {
  const rollout = ROLLOUT_HEALTH.find((item) => item.machineId === ballot.machineId)!;
  const offline = ballot.vote === "QUEUED OFFLINE";
  return <Panel className="overflow-hidden">
    <div className="grid min-w-0 gap-4 p-4 sm:p-5 lg:grid-cols-[minmax(180px,1.15fr)_minmax(180px,1fr)_minmax(210px,1.2fr)] lg:items-center">
      <div className="min-w-0"><div className="flex min-w-0 items-center gap-2"><Dot tone={offline ? "muted" : ballot.vote === "ACCEPT" ? "online" : "busy"} pulse={!offline && released} /><span className="truncate font-mono text-[11px] font-medium">{ballot.machineId}</span></div><div className="mt-2 flex flex-wrap items-center gap-2 pl-4"><Pill tone={offline ? "muted" : ballot.vote === "ACCEPT" ? "online" : "destructive"}>{ballot.vote}</Pill><span className="font-mono text-[9px] text-muted-foreground">{ballot.platform}</span></div></div>
      <div className="flex flex-wrap gap-x-4 gap-y-2 lg:pl-2">{offline ? <span className="text-[11px] text-muted-foreground">Checks deferred until reconnect</span> : ([["flock.mjs", ballot.checks?.bridge], ["bootstrap", ballot.checks?.bootstrap], ["npm test", ballot.checks?.tests]] as const).map(([label, passed]) => <span key={label} className="flex items-center gap-1.5 font-mono text-[9px] text-muted-foreground">{passed ? <Check className="h-3 w-3 text-online" /> : <CircleAlert className="h-3 w-3 text-destructive" />}{label}</span>)}</div>
      <div className="min-w-0 border-t border-border/45 pt-3 text-[10px] lg:border-l lg:border-t-0 lg:pl-5 lg:pt-0"><div className="flex items-center justify-between gap-3"><span className="text-muted-foreground">Rollout</span><span className={cn("truncate font-mono text-[9px]", released && !offline ? "text-online" : "text-muted-foreground")}>{released ? rollout.version : offline ? "Awaiting merge" : `${RELEASE.previousVersion} retained`}</span></div><div className="mt-1.5 truncate text-muted-foreground">{released ? offline ? rollout.queueReceipt : `PID ${rollout.daemonPid} · Coordinator + Tracker ${rollout.coordinator}` : statsText(offline)}</div></div>
    </div>
    <details className="group border-t border-border/45">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-2.5 text-[10px] text-muted-foreground hover:text-foreground sm:px-5 [&::-webkit-details-marker]:hidden"><KeyRound className="h-3 w-3" />{offline ? "Delivery & upgrade note" : "Review & Ed25519 proof"}<ChevronDown className="ml-auto h-3.5 w-3.5 transition-transform group-open:rotate-180" /></summary>
      <div className="grid gap-4 border-t border-border/40 bg-background/20 px-4 py-4 sm:px-5 lg:grid-cols-2"><SmartMessage text={ballot.review} compact />{offline ? <div className="min-w-0 font-mono text-[9px] leading-5 text-muted-foreground"><div className="mb-1 uppercase tracking-wider">Store-and-forward receipt</div><div className="break-all text-info">{released ? rollout.queueReceipt : `Queued after unanimous merge · ${RELEASE.queue}`}</div></div> : <div className="min-w-0 font-mono text-[9px] leading-5 text-muted-foreground"><div><span className="text-foreground/70">keyFingerprint</span><div className="break-all">{ballot.keyFingerprint}</div></div><div className="mt-2"><span className="text-foreground/70">signed payload</span><div className="break-all">{ballot.votePayload}</div></div><div className="mt-2"><span className="text-foreground/70">voteSignature</span><div className="break-all">{ballot.voteSignature}</div></div></div>}</div>
    </details>
  </Panel>;
}

const statsText = (offline: boolean) => offline ? "No Service Bus receipt before merge" : "Rollout locked by the active peer vote";
