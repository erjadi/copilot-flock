export interface RemoteOrigin { machine?: string | undefined; scope?: string | undefined; thread?: string | undefined; user?: string | undefined; verified?: boolean | undefined; trustLevel?: string | undefined }
export interface ParsedMessage { body: string; origin: RemoteOrigin; metadata: string[]; clarification: boolean }
export interface MessageSection { title: string; body: string }

/** Presentation only: the original wire payload remains untouched. */
export function parseMessage(raw: string): ParsedMessage {
  let body = String(raw || "").trim();
  const origin: RemoteOrigin = {};
  const metadata: string[] = [];
  const remote = body.match(/^\[Remote Copilot @\s*([^\s\]]+)([^\]]*)\]:\s*/i);
  if (remote) {
    origin.machine = remote[1];
    origin.user = remote[2].match(/\(@([^)]*)\)/)?.[1];
    const scope = remote[2].match(/\((personal|private|work)\)/i)?.[1]?.toLowerCase();
    origin.scope = scope === "private" ? "personal" : scope;
    origin.thread = remote[2].match(/\/\s*(.+)$/)?.[1]?.trim();
    metadata.push(remote[0].trim());
    body = body.slice(remote[0].length);
  }
  const envelope = body.match(/<cross_session_message\b([^>]*)>([\s\S]*?)<\/cross_session_message>/i);
  if (envelope) {
    metadata.push(`<cross_session_message${envelope[1]}>`);
    const attrs = [...envelope[1].matchAll(/([\w-]+)\s*=\s*["']([^"']*)["']/g)];
    for (const [, key, value] of attrs) setOrigin(origin, key, value);
    body = body.replace(envelope[0], envelope[2]).trim();
  }
  const clarification = body.match(/^\[CLARIFICATION REQUEST from\s+@?([^\s\]]+)(?:\s*\(session:\s*([^)]*)\))?\]:?\s*/i);
  if (clarification) {
    origin.machine ??= clarification[1];
    origin.thread ??= clarification[2];
    metadata.push(clarification[0].trim());
    body = body.slice(clarification[0].length);
  }
  let fenced = false;
  const lines = body.split("\n").filter((line) => {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (fenced) return true;
    const field = line.match(/^\s*(message_type|from_machine|from_scope|from_github_user|sender_verified|trust_level|from_session_id|from_display_name|from_session|to_machine|to_session|bridge_transport|REPLY_INSTRUCTION|CLARIFICATION_INSTRUCTION|SECURITY_POLICY|CRITICAL SECURITY MANDATE)\s*:\s*(.*)$/i);
    if (!field) return true;
    metadata.push(line.trim());
    setOrigin(origin, field[1], field[2].replace(/^['"]|['"],?$/g, ""));
    return false;
  });
  body = lines.join("\n").replace(/^\s*(?:message_body|body|message)\s*:\s*/i, "").trim();
  return { body, origin, metadata, clarification: Boolean(clarification) };
}

function setOrigin(origin: RemoteOrigin, key: string, value: string) {
  const k = key.toLowerCase();
  if (k === "sender_verified") { origin.verified = value === "true"; return; }
  if (k === "trust_level") { origin.trustLevel = value; return; }
  const fields: Record<string, "machine" | "scope" | "user" | "thread"> = { from_machine: "machine", from_scope: "scope", from_github_user: "user", from_display_name: "thread", from_session_id: "thread", from_session: "thread" };
  const field = fields[k];
  if (field && (!origin[field] || k === "from_display_name")) origin[field] = field === "scope" && value.toLowerCase() === "private" ? "personal" : value;
}

/** Ignore heading-like text inside code fences; only reports with multiple numbered sections fold. */
export function splitMessageSections(body: string): { lead: string; sections: MessageSection[] } {
  const lines = body.split("\n");
  let fence: string | null = null;
  const candidates: { index: number; title: string; numbered: boolean }[] = [];
  lines.forEach((line, index) => {
    const marker = line.match(/^\s*(`{3,}|~{3,})/);
    if (marker) { if (!fence) fence = marker[1][0]; else if (fence === marker[1][0]) fence = null; return; }
    if (fence) return;
    const heading = line.match(/^#{2,3}\s+(.+?)\s*#*$/);
    const numbered = line.match(/^\d+\.\s+\*\*(.+?)\*\*\s*:?\s*(.*)$/);
    if (heading) candidates.push({ index, title: heading[1], numbered: false });
    else if (numbered) candidates.push({ index, title: numbered[1].replace(/:$/, ""), numbered: true });
  });
  const numberedCount = candidates.filter((c) => c.numbered).length;
  const starts = candidates.filter((c) => !c.numbered || numberedCount >= 2);
  if (!starts.length) return { lead: body, sections: [] };
  return {
    lead: lines.slice(0, starts[0].index).join("\n").trim(),
    sections: starts.map((s, i) => {
      const intro = s.numbered ? lines[s.index].replace(/^\d+\.\s+\*\*.+?\*\*\s*:?\s*/, "") : "";
      return { title: s.title, body: [intro, ...lines.slice(s.index + 1, starts[i + 1]?.index ?? lines.length)].join("\n").trim() };
    }),
  };
}

export const isLongCode = (value: string) => value.replace(/\n$/, "").split("\n").length > 6;
