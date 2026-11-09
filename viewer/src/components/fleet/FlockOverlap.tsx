import { useState } from "react";
import { Layers, ShieldCheck, X } from "lucide-react";
import { flockMemberships, type Flock } from "@/lib/fleet/flocks";
import { Btn, IconBtn } from "./ui";

const tones = { owner_root: "flock-root", owner_scope: "flock-personal", collaborator: "flock-team", guest: "flock-guest" };
function tone(f: Flock) { return f.kind === "owner_scope" && f.flockId.endsWith("/work") ? "flock-work" : tones[f.kind]; }
const dotClasses: Record<string, string> = { "flock-root": "bg-flock-root", "flock-personal": "bg-flock-personal", "flock-work": "bg-flock-work", "flock-team": "bg-flock-team", "flock-guest": "bg-flock-guest" };
const graphColors: Record<string, string> = { "flock-root": "var(--flock-root)", "flock-personal": "var(--personal)", "flock-work": "var(--work)", "flock-team": "var(--busy)", "flock-guest": "var(--gpu)" };
const color = (f: Flock) => graphColors[tone(f)];
const shortName = (f: Flock) => f.kind === "owner_root" ? f.flockId : f.flockId.split("/").slice(1).join("/");

export function FlockOverlapMatrix({ flocks, error }: { flocks: Flock[]; error?: string | null }) {
  const [selected, setSelected] = useState<string | null>(null);
  const rows = flockMemberships(flocks);
  const active = rows.find((r) => r.machineId === selected);
  return <section className="mb-8 min-w-0 border-b border-border/60 pb-6" aria-labelledby="overlap-heading">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2"><h3 id="overlap-heading" className="flex items-center gap-2 text-sm font-medium"><Layers className="h-4 w-4 text-busy" />Flock overlap</h3><span className="font-mono text-[10px] text-muted-foreground">{rows.filter((r) => r.overlap).length} overlap machines · {flocks.length} flocks</span></div>
    {error || !rows.length ? <p role="status" className="text-xs text-muted-foreground">{error ? "Flock membership unavailable." : "No active memberships"}</p> : <>
      <div className="max-w-full overflow-x-auto overscroll-contain"><table className="w-full min-w-[540px] border-collapse text-left text-[11px]" aria-label="Flock membership matrix">
        <thead><tr><th className="sticky left-0 z-10 bg-background py-3 pr-4 font-normal text-muted-foreground">Machine</th>{flocks.map((f) => <th key={f.flockId} className="max-w-28 px-2 py-3 text-center font-normal"><span title={f.flockId} className="inline-flex items-center gap-1.5"><span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dotClasses[tone(f)]}`} /><span className="break-words">{f.kind === "guest" ? "Guest pass" : shortName(f)}</span></span></th>)}</tr></thead>
        <tbody>{rows.map((r) => <tr key={r.machineId} className={`border-t border-border/40 ${selected === r.machineId ? "bg-accent/60" : ""}`}><th className="sticky left-0 z-10 bg-background py-1 pr-4 font-normal"><Btn className="justify-start px-0 font-mono text-[10px]" aria-pressed={selected === r.machineId} onClick={() => setSelected(selected === r.machineId ? null : r.machineId)}>{r.machineId}{r.overlap && <Layers className="h-3 w-3 shrink-0 text-busy" />}</Btn></th>{flocks.map((f) => <td key={f.flockId} className="text-center"><Btn className="w-full px-0" aria-label={`${r.machineId} ${r.memberships.includes(f) ? "belongs to" : "not in"} ${f.flockId}`} onClick={() => setSelected(r.machineId)}>{r.memberships.includes(f) ? <span className={`h-2 w-2 rounded-full ${dotClasses[tone(f)]}`} /> : <span className="text-muted-foreground/35">—</span>}</Btn></td>)}</tr>)}</tbody>
      </table></div>
      {active && <div role="status" className="mt-4 flex flex-wrap items-center gap-2 text-xs"><span className="font-mono">{active.machineId}</span><span className="text-muted-foreground">{active.memberships.map((f) => f.flockId).join(" · ")}</span></div>}
      <div className="mt-4 flex items-start gap-2 text-[11px] leading-5 text-muted-foreground"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-online" /><span>Shared machines, isolated threads. External flocks require explicit opt-in; daemon enforcement and boundFlockId partitioning remain authoritative.</span></div>
    </>}
  </section>;
}

export function FlockMembershipGraph({ flocks, W, H, portrait, error }: { flocks: Flock[]; W: number; H: number; portrait: boolean; error?: string | null }) {
  const [selected, setSelected] = useState<string | null>(null);
  const rows = flockMemberships(flocks);
  const scopes = flocks.filter((f) => f.kind !== "owner_root");
  const roots = flocks.filter((f) => f.kind === "owner_root");
  const left = portrait ? 30 : 110, right = portrait ? W - 185 : W - 320;
  const top = portrait ? 205 : 180, bottom = H - (portrait ? 240 : 145);
  const y = (i: number, n: number) => top + i * (bottom - top) / Math.max(1, n - 1);
  const machine = rows.find((r) => r.machineId === selected);
  const flock = flocks.find((f) => f.flockId === selected);
  if (error || !rows.length) return <div className="grid h-full place-items-center px-6 text-center text-xs text-muted-foreground" role="status">{error ? "Flock membership unavailable." : "No active memberships"}</div>;
  return <>
    <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="img" aria-label="All flocks and overlapping machine memberships">
      <g transform={`translate(${portrait ? 24 : 90},105)`}><text className="fill-muted-foreground font-mono text-[11px]">ALL FLOCKS / MEMBERSHIP</text>{roots.map((f, i) => <g key={f.flockId} role="button" tabIndex={0} aria-label={`Highlight flock ${f.flockId}`} onClick={() => setSelected(f.flockId)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelected(f.flockId); }} className="cursor-pointer"><rect y={17 + i * 32} width={W - (portrait ? 48 : 180)} height={30} rx={6} fill="var(--panel)" stroke="var(--border)" /><text x={12} y={37 + i * 32} className="fill-foreground font-mono text-[12px]">{f.flockId} · owner root · {rows.filter((r) => r.memberships.includes(f)).length} machines</text></g>)}</g>
      {scopes.flatMap((f, i) => rows.flatMap((r, j) => {
        if (!r.memberships.includes(f)) return [];
        const focused = !selected || selected === f.flockId || selected === r.machineId || (flock?.kind === "owner_root" && r.memberships.includes(flock));
        return <path key={`${f.flockId}:${r.machineId}`} d={`M ${left + 12} ${y(i, scopes.length)} C ${W * 0.43} ${y(i, scopes.length)}, ${W * 0.43} ${y(j, rows.length)}, ${right} ${y(j, rows.length)}`} fill="none" stroke={color(f)} strokeWidth={selected && focused ? 2.5 : 1.3} strokeOpacity={focused ? 0.5 : 0.07} />;
      }))}
      {scopes.map((f, i) => <g key={f.flockId} transform={`translate(${left},${y(i, scopes.length)})`} role="button" tabIndex={0} aria-label={`Highlight flock ${f.flockId}`} onClick={() => setSelected(selected === f.flockId ? null : f.flockId)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelected(f.flockId); }} className="cursor-pointer outline-none"><title>{f.flockId}</title><rect x={-12} y={-22} width={portrait ? 125 : 200} height={64} rx={6} fill="var(--panel)" stroke={color(f)} strokeOpacity={selected === f.flockId ? 1 : 0.25} /><circle r={4} fill={color(f)} /><text x={12} y={4} className={`fill-foreground font-mono ${portrait ? "text-[14px]" : "text-[14px]"}`}>{f.kind === "guest" ? "Guest pass" : shortName(f)}</text><text x={12} y={23} className="fill-muted-foreground font-mono text-[10px]">{f.kind === "guest" ? "work/CLOUD-DEV-VM" : portrait ? f.trustTier : `${rows.filter((r) => r.memberships.includes(f)).length} machines · ${f.trustTier}`}</text></g>)}
      {rows.map((r, i) => {
        const groups = r.memberships.filter((f) => f.kind !== "owner_root");
        const focused = !selected || selected === r.machineId || r.memberships.some((f) => f.flockId === selected);
        return <g key={r.machineId} transform={`translate(${right},${y(i, rows.length)})`} opacity={focused ? 1 : 0.25} role="button" tabIndex={0} aria-label={`Highlight memberships for ${r.machineId}`} onClick={() => setSelected(selected === r.machineId ? null : r.machineId)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelected(r.machineId); }} className="cursor-pointer outline-none"><title>{r.memberships.map((f) => f.flockId).join(" · ")}</title><circle r={portrait ? 13 : 12} fill="var(--panel)" stroke="var(--border)" />{groups.map((f, k) => <circle key={f.flockId} r={portrait ? 16 : 15} fill="none" stroke={color(f)} strokeWidth={3} strokeDasharray={`${2 * Math.PI * (portrait ? 16 : 15) / groups.length - 3} ${2 * Math.PI * (portrait ? 16 : 15)}`} transform={`rotate(${k * 360 / groups.length - 90})`} />)}<circle r={3} fill={r.overlap ? "var(--busy)" : "var(--muted-foreground)"} /><text x={24} y={2} className={`fill-foreground font-mono ${portrait ? "text-[14px]" : "text-[13px]"}`}>{r.machineId}</text><text x={24} y={18} className="fill-muted-foreground font-mono text-[9px]">{groups.length} {groups.length === 1 ? "scope" : "scopes"}{r.overlap ? " · overlap" : ""}</text></g>;
      })}
    </svg>
    <div className="absolute inset-x-4 bottom-4 flex min-w-0 items-start gap-3 rounded-lg border border-border/60 bg-glass p-3 text-[11px] leading-5 md:inset-x-8 md:bottom-6" role="status"><ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-online" /><div className="min-w-0 flex-1">{selected ? <><div className="break-all font-mono font-medium">{selected}</div><div className="break-words text-muted-foreground">{machine ? machine.memberships.map((f) => f.flockId).join(" · ") : rows.filter((r) => r.memberships.includes(flock as Flock)).map((r) => r.machineId).join(" · ")}</div></> : <div><span className="font-medium">{rows.filter((r) => r.overlap).length} overlap machines</span><span className="text-muted-foreground"> · {flocks.length} flocks · {rows.length} machines</span></div>}<div className="text-muted-foreground">Membership ≠ thread sharing · explicit opt-in for external flocks</div></div>{selected && <IconBtn aria-label="Clear membership selection" onClick={() => setSelected(null)}><X className="h-3.5 w-3.5" /></IconBtn>}</div>
  </>;
}
