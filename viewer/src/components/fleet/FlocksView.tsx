import { useEffect, useState } from "react";
import { Check, Copy, KeyRound, LoaderCircle, ShieldCheck, UserMinus, X } from "lucide-react";
import type { Ctx } from "./Console";
import { post } from "@/lib/fleet/api";
import { generateInvite, HARD_WALLS, revokeMember, type FlockState, type InviteResult } from "@/lib/fleet/flocks";
import { Btn, Input, PageHeading, Pill, Select } from "./ui";
import { FlockOverlapMatrix } from "./FlockOverlap";

export function FlocksView({ ctx, state, setState, refresh, error }: { ctx: Ctx; state: FlockState; setState: (state: FlockState) => void; refresh: () => Promise<void>; error: string | null }) {
  const [path, setPath] = useState("example/studio-team");
  const [handle, setHandle] = useState("");
  const [duration, setDuration] = useState(0);
  const [devices, setDevices] = useState(3);
  const [busy, setBusy] = useState<string | null>(null);
  const [invite, setInvite] = useState<InviteResult | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 30000); return () => clearInterval(timer); }, []);
  const run = async (key: string, action: () => Promise<void>) => { setBusy(key); setNotice(null); try { await action(); } catch (e) { setNotice(e instanceof Error ? e.message : "Request failed"); } finally { setBusy(null); } };

  return <div className="min-w-0">
    <PageHeading title="Flocks" description="v3.1.0 · Copilot Flock Multi-Flock P2P Platform · <owner>/<flock>[/<machineId>]"><Pill tone={ctx.mode === "live" ? "online" : "muted"}>{ctx.mode === "live" ? "Live flock" : "Preview simulation"}</Pill></PageHeading>
    {(notice || error) && <div role="status" className="mb-5 break-words text-xs text-busy">{notice || error}</div>}
    <FlockOverlapMatrix flocks={state.flocks} error={error} />
    <section aria-labelledby="flocks-heading">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3"><h3 id="flocks-heading" className="text-sm font-medium">Active flocks & maintainer</h3><span className="font-mono text-[10px] text-muted-foreground">{state.flocks.length} flocks · {state.sharedThreads.length} shared threads</span></div>
      <details className="mb-4 border-b border-border/50 pb-3"><summary className="cursor-pointer text-xs text-muted-foreground">Maintainer overview</summary><pre className="mt-3 overflow-auto whitespace-pre-wrap break-all text-[10px] text-muted-foreground">{JSON.stringify(state.maintainer, null, 2)}</pre></details>
      <div className="grid min-w-0 gap-3 xl:grid-cols-2">{state.flocks.map((f) => <article key={f.flockId} className="min-w-0 rounded-lg border border-border/60 bg-panel/40 p-4">
        <div className="flex flex-wrap items-center gap-2"><h4 className="min-w-0 break-all font-mono text-xs font-medium">{f.flockId}</h4><Pill tone={f.trustTier === "owner" ? "online" : f.trustTier === "guest" ? "gpu" : "info"}>{f.trustTier}</Pill></div>
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[9px] text-muted-foreground"><span>{f.kind}</span><span>epoch {f.rosterEpoch}</span><span>{f.sessionVisibility}</span></div>
        <details className="mt-3"><summary className="cursor-pointer text-[10px] text-muted-foreground">Namespace & transport</summary><dl className="mt-2 space-y-2 break-all font-mono text-[10px] text-muted-foreground"><div><dt>flockId</dt><dd className="text-foreground">{f.flockId}</dd></div><div><dt>flockUuid</dt><dd>{f.flockUuid}</dd></div><div><dt>hubName</dt><dd>{f.hubName}</dd></div></dl></details>
        <div className="mt-4 divide-y divide-border/40">{f.members.map((m) => { const remaining = m.membershipExpiresAt ? Math.max(0, Math.ceil((new Date(m.membershipExpiresAt).getTime() - now) / 60000)) : null; return <div key={m.peerId} className="flex min-w-0 items-center gap-2 py-3"><div className="min-w-0 flex-1"><div className="break-words font-mono text-[11px]">{m.machineId}</div><div className="mt-1 break-all font-mono text-[9px] text-muted-foreground">{m.peerId}</div>{remaining !== null && <div className="mt-1"><Pill tone={remaining ? "gpu" : "destructive"}>{remaining ? `${remaining}m remaining` : "Expired"}</Pill></div>}</div><Btn variant="ghost" title={`Revoke ${m.machineId}`} aria-label={`Revoke ${m.machineId} from ${f.flockId}`} disabled={Boolean(busy) || Boolean(error)} onClick={() => run(m.peerId, async () => { await post(ctx.base, ctx.mode, "/api/v3/flocks/kick", { flockId: f.flockId, peerId: m.peerId, machineId: m.machineId }, () => ({ ok: true })); if (ctx.mode === "seed") { setState(revokeMember(state, f.flockId, m.peerId)); setNotice("Preview revocation · roster epoch incremented; no live sockets affected."); } else { await refresh(); setNotice("Revocation accepted by the bridge; roster refreshed."); } })}><UserMinus className="h-4 w-4" /></Btn></div>; })}{!f.members.length && <p className="py-3 text-xs text-muted-foreground">No active members</p>}</div>
      </article>)}</div>
    </section>
    <section className="mt-9 border-t border-border/60 pt-6" aria-labelledby="invite-heading">
      <h3 id="invite-heading" className="mb-4 flex items-center gap-2 text-sm font-medium"><KeyRound className="h-4 w-4 text-info" />Copilot invite</h3>
      <form onSubmit={(e) => { e.preventDefault(); setInvite(null); setCopied(false); void run("invite", async () => setInvite(await generateInvite(ctx.base, ctx.mode, { targetPath: path.trim(), githubHandle: handle.trim(), durationMinutes: duration || null, maxDevices: devices }))); }} className="grid min-w-0 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <label className="space-y-2 text-[11px] text-muted-foreground">Target path<Input aria-label="Target path" value={path} onChange={(e) => setPath(e.target.value)} required /></label>
        <label className="space-y-2 text-[11px] text-muted-foreground">Invitee GitHub handle<Input aria-label="Invitee GitHub handle" placeholder="@alice" value={handle} onChange={(e) => setHandle(e.target.value)} required /></label>
        <label className="space-y-2 text-[11px] text-muted-foreground">Guest pass<Select className="w-full" aria-label="Guest pass" value={duration} onChange={(e) => setDuration(Number(e.target.value))}><option value={0}>None / Permanent</option><option value={120}>120m (2h)</option><option value={480}>480m (8h)</option><option value={1440}>1440m (24h)</option></Select></label>
        <label className="space-y-2 text-[11px] text-muted-foreground">Max devices<Input aria-label="Max devices" type="number" min={1} step={1} value={devices} onChange={(e) => setDevices(Number(e.target.value))} required /></label>
        <div className="sm:col-span-2 lg:col-span-4"><Btn variant="primary" type="submit" disabled={Boolean(busy) || Boolean(error)}>{busy === "invite" ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}Generate invite</Btn></div>
      </form>
      {invite && <div className="mt-5 min-w-0 border-t border-border/40 pt-4"><div className="flex flex-wrap items-center justify-between gap-2"><h4 className="text-xs font-medium">Copilot prompt & {invite.simulated ? "preview enrollment" : "signed v3 enrollment"}</h4><Btn variant="outline" onClick={() => run("copy", async () => { await navigator.clipboard.writeText(invite.copilotPrompt); setCopied(true); })}>{copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}{copied ? "Copied" : "Copy prompt"}</Btn></div><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted/30 p-4 font-mono text-[11px] leading-5">{invite.copilotPrompt}</pre><details className="mt-3"><summary className="cursor-pointer text-xs text-muted-foreground">Enrollment JSON</summary><pre className="mt-3 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px]">{JSON.stringify(invite.enrollment, null, 2)}</pre></details></div>}
    </section>
    <section className="mt-9 border-t border-border/60 pt-6" aria-labelledby="sharing-heading"><h3 id="sharing-heading" className="text-sm font-medium">What am I sharing?</h3>
      {!state.sharedThreads.length ? <p className="my-5 text-xs text-muted-foreground">{error ? "Sharing audit unavailable." : "0 shared threads · no external sessions opted in"}</p> : <div className="mt-4 divide-y divide-border/50">{state.sharedThreads.map((t) => <div key={`${t.boundFlockId}:${t.sessionId}`} className="flex min-w-0 items-start gap-3 py-4"><div className="min-w-0 flex-1"><div className="break-words text-xs">{t.title}</div><div className="mt-2 break-all font-mono text-[10px] text-muted-foreground">{t.machineId} · {t.sharingMode}</div><div className="mt-1 break-all font-mono text-[10px] text-info">boundFlockId · {t.boundFlockId}</div></div><Btn variant="outline" disabled={Boolean(busy)} onClick={() => run(t.sessionId, async () => { await post(ctx.base, ctx.mode, "/api/v3/unshare-thread", { sessionId: t.sessionId, boundFlockId: t.boundFlockId }, () => ({ ok: true })); if (ctx.mode === "seed") setState({ ...state, sharedThreads: state.sharedThreads.filter((s) => s !== t) }); else await refresh(); })}><X className="h-3 w-3" />Unshare</Btn></div>)}</div>}
      <div className="grid gap-3 border-t border-border/40 pt-5 sm:grid-cols-2">{HARD_WALLS.map((wall, i) => <div key={wall} className="flex items-center gap-3 text-[11px] text-muted-foreground"><ShieldCheck className="h-4 w-4 shrink-0 text-online" /><span><span className="mr-2 font-mono text-[9px]">0{i + 1}</span>{wall}</span></div>)}</div>
    </section>
  </div>;
}
