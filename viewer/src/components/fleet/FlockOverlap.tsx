import { useEffect, useRef, useState } from "react";
import { Layers, ShieldCheck, X } from "lucide-react";
import { flockMemberships, type Flock } from "@/lib/fleet/flocks";
import { membershipField } from "@/lib/fleet/membership-layout";
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

export function FlockMembershipGraph({ flocks, error }: { flocks: Flock[]; error?: string | null }) {
  const [selected, setSelected] = useState<{ kind: "machine" | "flock"; id: string } | null>(null);
  const fieldRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900);
  useEffect(() => {
    const el = fieldRef.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => { if (entry?.contentRect.width) setWidth(entry.contentRect.width); });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);
  const rows = flockMemberships(flocks);
  const machine = selected?.kind === "machine" ? rows.find((r) => r.machineId === selected.id) : undefined;
  const flock = selected?.kind === "flock" ? flocks.find((f) => f.flockId === selected.id) : undefined;
  const active = machine || flock ? selected : null;
  const field = membershipField(rows, flocks.map((f) => f.flockId), width);
  const toggle = (kind: "machine" | "flock", id: string) => setSelected(active?.kind === kind && active.id === id ? null : { kind, id });
  const focusedFlock = (id: string) => !active || flock?.flockId === id || !!machine?.memberships.some((f) => f.flockId === id);
  return <div className="absolute inset-x-3 bottom-3 top-[76px] flex min-h-0 flex-col gap-3 md:inset-x-6 md:bottom-5" aria-label="Spatial flock memberships">
    <div ref={fieldRef} className="min-h-0 flex-1 overflow-auto overscroll-contain rounded-lg focus-visible:outline-2 focus-visible:outline-ring" role="region" aria-label="Flock membership field and legend" tabIndex={0}>
      {error || !rows.length ? <p role="status" className="p-6 text-center text-xs text-muted-foreground">{error ? "Flock membership unavailable." : "No active memberships"}</p> : <>
        <div className="flex flex-wrap gap-2 p-1" aria-label="Flock legend">
          {flocks.map((f, i) => <button key={f.flockId} type="button" aria-pressed={flock === f} aria-label={`Highlight flock ${f.flockId}`} onClick={() => toggle("flock", f.flockId)} className="min-w-0 max-w-full rounded-lg border bg-panel px-3 py-2 text-left text-[11px] focus-visible:outline-2 focus-visible:outline-ring" style={{ borderColor: color(f), opacity: focusedFlock(f.flockId) ? 1 : 0.45 }}>
            <span className="flex items-start gap-2"><span className="font-mono font-semibold" style={{ color: color(f) }}>{i + 1}</span><span className="min-w-0"><span className="block break-all font-mono">{f.flockId}</span><span className="text-muted-foreground">{rows.filter((r) => r.memberships.includes(f)).length} machines · {f.kind === "owner_root" ? "owner root" : f.trustTier}</span></span></span>
          </button>)}
        </div>
        <p className="px-1 pt-2 text-[10px] leading-4 text-muted-foreground">Contours and numbered badges show membership. Separate outlines keep nonmembers outside a flock.</p>
        <div className="relative" style={{ width: field.width, height: field.height }}>
          <svg width={field.width} height={field.height} className="pointer-events-none absolute inset-0" aria-hidden="true">
            {field.contours.map((contour, i) => <g key={contour.flockId} opacity={focusedFlock(contour.flockId) ? 1 : 0.12}>{contour.paths.map((d, j) => <path key={j} d={d} fill={color(flocks[i])} fillOpacity={0.035} stroke={color(flocks[i])} strokeWidth={active && focusedFlock(contour.flockId) ? 2.5 : 1.4} strokeOpacity={0.65} strokeLinejoin="round" strokeDasharray={flocks[i].kind === "owner_root" ? "5 5" : undefined} />)}</g>)}
          </svg>
          {field.nodes.map((n) => {
            const row = rows.find((r) => r.machineId === n.machineId)!;
            const focused = !active || machine?.machineId === n.machineId || !!flock && row.memberships.includes(flock);
            return <button key={n.machineId} type="button" aria-pressed={machine?.machineId === n.machineId} aria-label={`Highlight memberships for ${n.machineId}: ${row.memberships.map((f) => f.flockId).join(", ")}`} onClick={() => toggle("machine", n.machineId)} className="absolute flex flex-col items-center justify-center gap-1 rounded-2xl border border-border bg-panel px-2 text-center focus-visible:outline-2 focus-visible:outline-ring" style={{ left: n.x, top: n.y, width: n.width, height: n.height, opacity: focused ? 1 : 0.35 }}>
              <span className="w-full break-all font-mono text-[11px] leading-4">{n.machineId}</span>
              <span className="flex max-w-full flex-wrap justify-center gap-1" aria-hidden="true">{row.memberships.map((f) => <span key={f.flockId} className="rounded border px-1 font-mono text-[9px]" style={{ color: color(f), borderColor: color(f) }}>{flocks.indexOf(f) + 1}</span>)}</span>
              {row.overlap && <span className="text-[9px] text-muted-foreground">Overlapping memberships</span>}
            </button>;
          })}
        </div>
      </>}
    </div>
    {!error && rows.length > 0 && <div className="flex max-h-[35%] shrink-0 items-start gap-3 overflow-auto rounded-lg border border-border/60 bg-glass p-3 text-[11px] leading-5" role="status"><ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-online" /><div className="min-w-0 flex-1">{active ? <><div className="break-all font-mono font-medium">{active.id}</div><div className="break-words text-muted-foreground">{machine ? machine.memberships.map((f) => f.flockId).join(" · ") : rows.filter((r) => flock && r.memberships.includes(flock)).map((r) => r.machineId).join(" · ") || "No active memberships"}</div></> : <div><span className="font-medium">{rows.filter((r) => r.overlap).length} overlap machines</span><span className="text-muted-foreground"> · {flocks.length} flocks · {rows.length} machines</span></div>}<div className="text-muted-foreground">Membership ≠ thread sharing · explicit opt-in for external flocks</div></div>{active && <IconBtn aria-label="Clear membership selection" onClick={() => setSelected(null)}><X className="h-3.5 w-3.5" /></IconBtn>}</div>}
  </div>;
}
