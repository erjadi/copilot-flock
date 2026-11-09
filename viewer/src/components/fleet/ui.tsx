import { useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { ChevronDown } from "lucide-react";
import { isLongCode, parseMessage, splitMessageSections } from "@/lib/fleet/messages";
import type { Gpu, Member } from "@/lib/fleet/types";
import { cn } from "@/lib/utils";

export const Panel = ({ className, children }: { className?: string; children: ReactNode }) => (
  <div className={cn("min-w-0 rounded-xl border border-border/80 bg-panel/55", className)}>{children}</div>
);

export const GlassPanel = ({ className, children }: { className?: string; children: ReactNode }) => (
  <div className={cn("glass rounded-xl", className)}>{children}</div>
);

export const Pill = ({ tone = "muted", children, className }: { tone?: "online" | "busy" | "info" | "personal" | "work" | "gpu" | "muted" | "destructive"; children: ReactNode; className?: string }) => {
  const tones: Record<string, string> = {
    online: "border-online/20 bg-online/8 text-online",
    busy: "border-busy/20 bg-busy/8 text-busy",
    info: "border-info/20 bg-info/8 text-info",
    personal: "border-personal/20 bg-personal/8 text-personal",
    work: "border-work/20 bg-work/8 text-work",
    gpu: "border-gpu/20 bg-gpu/8 text-gpu",
    muted: "border-border/70 bg-muted/35 text-muted-foreground",
    destructive: "border-destructive/25 bg-destructive/8 text-destructive",
  };
  return <span className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider", tones[tone], className)}>{children}</span>;
};

export const ScopePill = ({ scope }: { scope: "personal" | "work" }) => <Pill tone={scope}>{scope}</Pill>;

export const Dot = ({ tone = "online", pulse, className }: { tone?: "online" | "busy" | "muted" | "work" | "info"; pulse?: boolean; className?: string }) => (
  <span className={cn("inline-block h-1.5 w-1.5 shrink-0 rounded-full", tone === "online" ? "bg-online" : tone === "busy" ? "bg-busy" : tone === "work" ? "bg-work" : tone === "info" ? "bg-info" : "bg-muted-foreground/60", pulse && "pulse-dot", className)} />
);

export const Meter = ({ value, tone = "busy" }: { value: number; tone?: "busy" | "online" | "gpu" | "work" | "destructive" }) => {
  const bg = { busy: "bg-busy", online: "bg-online", gpu: "bg-gpu", work: "bg-work", destructive: "bg-destructive" }[value > 0.9 ? "destructive" : tone];
  return <div className="h-0.5 w-full overflow-hidden rounded-full bg-muted"><div className={cn("h-full rounded-full transition-all", bg)} style={{ width: `${Math.min(100, value * 100)}%` }} /></div>;
};

export const Btn = ({ variant = "ghost", className, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" | "outline" | "online" }) => (
  <button
    {...p}
    className={cn(
      "inline-flex h-10 shrink-0 items-center justify-center gap-1.5 rounded-lg px-3 text-xs font-medium transition-all disabled:pointer-events-none disabled:opacity-40 md:h-8",
      variant === "primary" && "bg-primary text-primary-foreground shadow-sm hover:bg-primary/90",
      variant === "online" && "bg-online text-primary-foreground hover:bg-online/90",
      variant === "outline" && "border border-border/80 bg-panel/40 text-foreground hover:border-border hover:bg-accent/60",
      variant === "ghost" && "text-muted-foreground hover:bg-accent/55 hover:text-foreground",
      className,
    )}
  />
);

export const IconBtn = ({ className, ...p }: React.ButtonHTMLAttributes<HTMLButtonElement>) => (
  <Btn variant="ghost" className={cn("h-10 w-10 px-0 md:h-8 md:w-8", className)} {...p} />
);

export const Input = (p: React.InputHTMLAttributes<HTMLInputElement>) => (
  <input {...p} className={cn("h-10 min-w-0 w-full rounded-lg border border-transparent bg-muted/35 px-3 text-base text-foreground outline-none transition placeholder:text-muted-foreground/65 focus:border-border focus:bg-panel md:h-9 md:text-xs", p.className)} />
);

export const Select = (p: React.SelectHTMLAttributes<HTMLSelectElement>) => (
  <select {...p} className={cn("h-10 min-w-0 max-w-full rounded-lg border border-transparent bg-muted/35 px-2.5 text-base text-foreground outline-none focus:border-border md:h-9 md:text-xs", p.className)} />
);

export const Label = ({ children, className }: { children: ReactNode; className?: string }) => <div className={cn("mb-1.5 text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground", className)}>{children}</div>;

export const Toggle = ({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) => (
  <button type="button" role="switch" aria-checked={on} onClick={() => onChange(!on)} className="inline-flex items-center gap-2 text-xs text-muted-foreground transition-colors hover:text-foreground">
    <span className={cn("relative h-4 w-7 rounded-full transition-colors", on ? "bg-foreground/85" : "bg-muted")}>
      <span className={cn("absolute top-0.5 h-3 w-3 rounded-full transition-all", on ? "left-3.5 bg-background" : "left-0.5 bg-muted-foreground")} />
    </span>
    {label}
  </button>
);

export function PageHeading({ title, description, children }: { title: string; description: string; children?: ReactNode }) {
  return <div className="mb-5 grid min-w-0 gap-4 lg:mb-7 lg:flex lg:items-end lg:justify-between"><div className="min-w-0"><h2 className="text-xl font-medium">{title}</h2><p className="mt-1 text-xs text-muted-foreground">{description}</p></div>{children}</div>;
}

export function rel(iso: string) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

interface TextTree { type: string; value?: string; children?: TextTree[]; data?: Record<string, unknown> }
function remarkUuids() {
  return (tree: TextTree) => {
    const walk = (parent: TextTree) => {
      if (!parent.children || ["code", "inlineCode", "link"].includes(parent.type)) return;
      parent.children = parent.children.flatMap((child) => {
        if (child.type !== "text" || !child.value) { walk(child); return [child]; }
        const parts = child.value.split(/(\b[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}\b)/gi);
        return parts.map((value, i): TextTree => i % 2 ? { type: "uuid", data: { hName: "span", hProperties: { title: value }, hChildren: [{ type: "text", value: `${value.slice(0, 8)}…` }] } } : { type: "text", value }).filter((part) => part.type !== "text" || Boolean(part.value));
      });
    };
    walk(tree);
  };
}

function MessageDetails({ title, children }: { title: ReactNode; children: ReactNode }) {
  return <details className="group/message min-w-0 border-t border-border/50 py-2"><summary className="flex cursor-pointer list-none items-start gap-2 text-xs font-medium text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden"><span className="min-w-0 flex-1 break-words">{title}</span><ChevronDown className="mt-0.5 h-3.5 w-3.5 shrink-0 transition-transform group-open/message:rotate-180" /></summary><div className="mt-3 min-w-0">{children}</div></details>;
}

function MarkdownBody({ text }: { text: string }) {
  return <ReactMarkdown remarkPlugins={[remarkGfm, remarkUuids]} components={{
    h1: ({ children }) => <h4 className="mb-3 text-base font-medium leading-6">{children}</h4>,
    h2: ({ children }) => <h5 className="my-3 text-sm font-medium">{children}</h5>,
    h3: ({ children }) => <h6 className="my-2 font-medium">{children}</h6>,
    p: ({ children }) => <p className="my-2 leading-6 text-foreground/85">{children}</p>,
    ul: ({ children }) => <ul className="my-3 list-disc space-y-2 pl-4 marker:text-muted-foreground">{children}</ul>,
    ol: ({ children }) => <ol className="my-3 list-decimal space-y-2 pl-5 marker:text-muted-foreground">{children}</ol>,
    li: ({ children }) => <li className="pl-1 leading-6 [&>strong:first-child]:font-medium [&>strong:first-child]:text-muted-foreground">{children}</li>,
    strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
    span: ({ children, title }) => <span title={title} className="inline-block max-w-full rounded border border-border/60 bg-muted/40 px-1.5 align-baseline font-mono text-[10px] text-info">{children}</span>,
    a: ({ children, href }) => <a href={href} className="break-all text-info underline underline-offset-4" target="_blank" rel="noopener noreferrer">{children}</a>,
    table: ({ children }) => <div className="my-3 max-w-full overflow-x-auto overscroll-contain rounded-md border border-border/60"><table className="w-full border-collapse text-left text-[11px]">{children}</table></div>,
    th: ({ children }) => <th className="whitespace-nowrap border-b border-border/60 bg-muted/30 px-3 py-2 font-medium">{children}</th>,
    td: ({ children }) => <td className="border-b border-border/30 px-3 py-2">{children}</td>,
    blockquote: ({ children }) => <blockquote className="my-3 border-l-2 border-info/40 pl-3 text-muted-foreground">{children}</blockquote>,
    pre: ({ children }) => <div className="min-w-0">{children}</div>,
    code: ({ children, className, node }) => {
      const value = String(children);
      const block = Boolean(className) || value.endsWith("\n") || node?.position?.start.line !== node?.position?.end.line;
      if (!block) return <code className="rounded bg-muted/60 px-1 py-0.5 font-mono text-[11px] text-busy [overflow-wrap:anywhere]">{children}</code>;
      const language = className?.replace("language-", "") ?? "code";
      const content = <pre className="my-2 max-w-full overflow-x-auto rounded-md border border-border/60 bg-background/70 p-3 font-mono text-[11px] leading-5"><code>{children}</code></pre>;
      return isLongCode(value) ? <MessageDetails title={`${language} · ${value.trimEnd().split("\n").length} lines`}>{content}</MessageDetails> : content;
    },
  }}>{text}</ReactMarkdown>;
}

export function SmartMessage({ text, compact = false }: { text: string; compact?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const parsed = parseMessage(text);
  const { lead, sections } = splitMessageSections(parsed.body);
  const paragraphs = lead.split(/\n\s*\n/);
  const lines = lead.split("\n");
  const longLead = compact && (lead.length > 260 || paragraphs.length > 2 || lines.length > 4);
  const preview = lines.length > 4 && paragraphs.length <= 2
    ? lines.slice(0, 3).join("\n")
    : paragraphs.slice(0, paragraphs[0]?.startsWith("# ") ? 2 : 1).join("\n\n");
  const visibleLead = longLead && !expanded ? preview : lead;
  return <div className={cn("min-w-0 max-w-full [overflow-wrap:anywhere]", compact ? "text-xs" : "text-sm")}>
    {parsed.origin.machine && <div className="mb-3 flex max-w-full flex-wrap items-center gap-x-1.5 gap-y-1 rounded-md border border-border/50 bg-muted/25 px-2 py-1.5 font-mono text-[9px] leading-4 text-muted-foreground"><span className="text-info">@{parsed.origin.machine}</span>{parsed.origin.scope && <span>· {parsed.origin.scope}</span>}{parsed.origin.thread && <span className="min-w-0">· {parsed.origin.thread}</span>}{parsed.origin.verified && <span className="text-online">· ✓ ed25519</span>}{parsed.origin.trustLevel === "cross_user_informational_only" && <span className="text-gpu">· info-only</span>}{parsed.clarification && <span className="text-busy">· clarification</span>}</div>}
    {visibleLead && <div className={cn(longLead && !expanded && "line-clamp-4")}><MarkdownBody text={visibleLead} /></div>}
    {longLead && <Btn className="my-1 h-8 px-0 text-[10px]" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{expanded ? "Collapse" : "Expand"}<ChevronDown className={cn("h-3 w-3", expanded && "rotate-180")} /></Btn>}
    {sections.map((section, i) => <MessageDetails key={i} title={section.title}><MarkdownBody text={section.body} /></MessageDetails>)}
    {parsed.metadata.length > 0 && <MessageDetails title={<span className="text-[10px] font-normal">Envelope meta</span>}><pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-[9px] leading-5 text-muted-foreground">{parsed.metadata.join("\n")}</pre></MessageDetails>}
  </div>;
}

export function Md(props: { text: string; compact?: boolean }) { return <SmartMessage {...props} />; }

export function gpuLabel(gpu: Gpu) {
  const telemetry = [gpu.vramFreeGb != null ? `${gpu.vramFreeGb}GB free` : null, gpu.utilizationPct != null ? `${gpu.utilizationPct}% util` : null].filter(Boolean);
  return `${gpu.name}${gpu.vramGb ? ` ${gpu.vramGb}GB` : ""}${telemetry.length ? ` (${telemetry.join(" · ")})` : ""}`;
}
export function ReplayHealth({ member }: { member: Member }) {
  const replay = member.offlineReplay;
  if (!replay) return null;
  return <div className={cn("mt-3 break-words font-mono text-[10px] leading-5", replay.ambiguousCount || replay.pendingAckCount ? "text-busy" : "text-online")} title={`${replay.processedCount} processed · ${replay.inFlightCount} in flight`}>Offline replay · {replay.ambiguousCount} ambiguous · {replay.pendingAckCount} pending ACK<span className="block text-muted-foreground">{replay.processedCount} processed · {replay.inFlightCount} in flight</span></div>;
}
