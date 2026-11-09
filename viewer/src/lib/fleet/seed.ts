import type { Member, Overview, Project, Scope, Session, Transcript, WireEvent } from "./types";

const ago = (min: number) => new Date(Date.now() - min * 60000).toISOString();
let sid = 0;
const id = (p: string) => `${p}-${(++sid).toString(16).padStart(4, "0")}${Math.random().toString(16).slice(2, 8)}`;

interface Def {
  machineId: string; scope: Scope; wsPort: number | null; desktop: boolean; specs: Member["specs"]; titles: [string, string, string][];
}

// Fictional hardware, projects and sessions; no captured fleet inventory.
const defs: Def[] = [
  {
    machineId: "MAIN-WORKSTATION", scope: "personal", wsPort: 51010, desktop: true,
    specs: { model: "Demo desktop", os: "Windows 11", cpu: { model: "Example x64 CPU", logicalCores: 16, physicalCores: 8, arch: "x64" }, memory: { totalGb: 32, freeGb: 20 },
      gpus: [{ name: "Example integrated GPU", vramGb: 2 }],
      disks: [{ mount: "C:", label: "System", type: "fixed", totalGb: 512, freeGb: 256 }, { mount: "D:", label: "Projects", type: "fixed", totalGb: 1024, freeGb: 640 }, { mount: "R:", label: "Demo Shared Storage (NAS)", type: "network", totalGb: 8192, freeGb: 4096 }] },
    titles: [["Copilot Flock Console", "example/fleet-console", "feat/viewer"], ["Robotics stage coordination", "example/robot-stage", "main"], ["Stage event routing", "example/stage-events", "design"], ["Rendering pipeline", "example/render-stage", "main"], ["Presence heartbeat", "example/fleet-console", "main"], ["NAS backup audit", "example/storage-tools", "main"]],
  },
  {
    machineId: "3D-STUDIO-PC", scope: "personal", wsPort: 51011, desktop: true,
    specs: { model: "Demo rendering workstation", os: "Windows 11", cpu: { model: "Example x64 CPU", logicalCores: 24, physicalCores: 12, arch: "x64" }, memory: { totalGb: 64, freeGb: 40 },
      gpus: [{ name: "Example discrete GPU", vramGb: 16, vramFreeGb: 12, utilizationPct: 25 }],
      disks: [{ mount: "C:", label: "System", type: "fixed", totalGb: 1024, freeGb: 512 }, { mount: "D:", label: "Renders", type: "fixed", totalGb: 4096, freeGb: 2048 }] },
    titles: [["Copilot Flock Coordinator", "example/render-stage", "main"], ["Lumen shader consultation", "example/material-lab", "main"], ["Robotics simulation status", "example/robot-stage", "main"], ["Nanite asset import", "example/render-stage", "nanite"]],
  },
  {
    machineId: "LINUX-GPU-HOST", scope: "personal", wsPort: null, desktop: false,
    specs: { model: "Demo GPU server", os: "Ubuntu LTS", cpu: { model: "Example x64 CPU", logicalCores: 32, physicalCores: 16, arch: "x64" }, memory: { totalGb: 128, freeGb: 96 },
      gpus: [{ name: "Example compute GPU", vramGb: 24, vramFreeGb: 20, utilizationPct: 15 }],
      disks: [{ mount: "/", label: "NVMe", type: "fixed", totalGb: 2048, freeGb: 1536 }] },
    titles: [["Robotics simulation", "example/robot-stage", "main"], ["Render worker status", "example/render-worker", "main"]],
  },
  {
    machineId: "MINI-SERVER-PC", scope: "personal", wsPort: 51012, desktop: true,
    specs: { model: "Demo compact server", os: "Windows 11", cpu: { model: "Example x64 CPU", logicalCores: 8, physicalCores: 4, arch: "x64" }, memory: { totalGb: 16, freeGb: 10 },
      gpus: [],
      disks: [{ mount: "C:", label: "System", type: "fixed", totalGb: 512, freeGb: 320 }, { mount: "D:", label: "Data", type: "fixed", totalGb: 2048, freeGb: 1280 }] },
    titles: [["Storage compatibility", "example/storage-tools", "main"]],
  },
  {
    machineId: "ARM64-LAPTOP", scope: "work", wsPort: 51016, desktop: true,
    specs: { model: "Demo ARM64 laptop", os: "Windows 11", cpu: { model: "Example ARM64 CPU", logicalCores: 12, physicalCores: 12, arch: "arm64" }, memory: { totalGb: 32, freeGb: 24 },
      gpus: [{ name: "Example integrated GPU", vramGb: 4 }],
      disks: [{ mount: "C:", label: "NVMe", type: "fixed", totalGb: 1024, freeGb: 768 }] },
    titles: [["ARM64 build matrix", "example/build-infra", "arm64"], ["Shared design review", "example/material-lab", "design"], ["Cross-channel messaging gateway", "example/messaging-gateway", "feat/cross-channel"]],
  },
  {
    machineId: "CLOUD-DEV-VM", scope: "work", wsPort: 51015, desktop: true,
    specs: { model: "Demo cloud VM", os: "Windows Server", cpu: { model: "Example virtual CPU", logicalCores: 8, physicalCores: 4, arch: "x64" }, memory: { totalGb: 32, freeGb: 16 },
      gpus: [],
      disks: [{ mount: "C:", label: "OS", type: "fixed", totalGb: 512, freeGb: 384 }, { mount: "D:", label: "Temp", type: "fixed", totalGb: 128, freeGb: 96 }] },
    titles: [["Cross-OS release review", "example/build-infra", "release"], ["Service API and Azure analysis", "example/service-api", "analysis"], ["Product identifier service", "example/catalog", "main"]],
  },
  {
    machineId: "LINUX-CONSOLE", scope: "personal", wsPort: null, desktop: false,
    specs: { model: "Demo headless server", os: "Debian", cpu: { model: "Example x64 CPU", logicalCores: 4, physicalCores: 4, arch: "x64" }, memory: { totalGb: 16, freeGb: 12 }, gpus: [], disks: [{ mount: "/", label: "NVMe", type: "fixed", totalGb: 512, freeGb: 256 }] },
    titles: [["Headless compatibility", "example/build-infra", "main"]],
  },
];

export function buildSeed(): Overview {
  const sessions: Session[] = [];
  const members: Member[] = defs.map((d, mi) => {
    const ms = d.titles.map(([title, repo, branch], i): Session => ({
      machineId: d.machineId, scope: d.scope, githubUser: "erjadi", session_id: id("ses"), workspace_id: id("ws"),
      title, session_type: d.desktop ? "desktop" : "cli", is_running: i < 2 || (i === 0 && !d.desktop), mode: i % 3 === 0 ? "agent" : "ask",
      model: i % 2 ? "claude-sonnet-4.5" : "gpt-5", repo, branch, path: d.machineId === "LINUX-GPU-HOST" ? `/home/example/src/${repo.split("/")[1]}` : `D:\\src\\${repo.split("/")[1]}`,
      updated_at: ago(i * 17 + mi * 3 + 1),
    }));
    sessions.push(...ms);
    return {
      machineId: d.machineId, online: d.machineId !== "MINI-SERVER-PC", githubUser: "erjadi", githubName: "Demo Developer", scope: d.scope, version: "3.1.0",
      copilotDesktopRunning: d.desktop, wsPort: d.wsPort, activeSessionCount: ms.length, registeredAt: ago(60 * 24 * (30 - mi * 4)),
      lastSeenAt: ago(0.2 + mi * 0.1), recentSessions: ms.slice(0, 4).map((s) => ({ session_id: s.session_id, title: s.title })), specs: d.specs, offlineReplay: { processedCount: 24 + mi, pendingAckCount: 0, inFlightCount: 0, ambiguousCount: 0 },
    };
  });
  const events: WireEvent[] = [];
  for (let i = 0; i < 24; i++) events.push(...fakeEvent(members, sessions, 60 - i * 2));
  return {
    hub: { endpoint: "https://your-signalr.service.signalr.net", hub: "v3_flock_00000000000040008000000000000001", version: "3.1.0", viewerHost: "LINUX-CONSOLE (10.0.0.14)", connected: true, lastUpdatedAt: new Date().toISOString() },
    members, sessions, events: events.reverse(),
  };
}

const actions = ["ping", "list_sessions", "get_transcript", "send_message", "create_session"];
export function fakeEvent(members: Member[], sessions: Session[], minAgo = 0): WireEvent[] {
  const now = Date.now() - minAgo * 60000;
  const m = members[Math.floor(Math.random() * members.length)];
  if (!m) return [];
  if (Math.random() < 0.3) {
    return [{ id: id("evt"), timestamp: new Date(now).toISOString(), type: "bridgePresence", target: "all", fromMachine: m.machineId, toMachine: "*", action: "presence",
      summary: `${m.machineId} heartbeat · ${m.activeSessionCount} sessions`, payload: { machineId: m.machineId, online: true, version: m.version, scope: m.scope, activeSessionCount: m.activeSessionCount } }];
  }
  const to = members[Math.floor(Math.random() * members.length)] ?? m;
  const action = actions[Math.floor(Math.random() * actions.length)];
  const requestId = id("req");
  const s = sessions.find((x) => x.machineId === to.machineId);
  const lat = 40 + Math.floor(Math.random() * 400);
  const peers = members.filter((x) => x.machineId !== to.machineId);
  const from = Math.random() < 0.65 && peers.length ? (Math.random() < 0.5 ? (peers.find((x) => x.machineId === "MAIN-WORKSTATION") ?? peers[0]) : peers[Math.floor(Math.random() * peers.length)]).machineId : "LINUX-CONSOLE";
  return [
    { id: id("evt"), timestamp: new Date(now).toISOString(), type: "bridgeRpcRequest", target: to.machineId, fromMachine: from, toMachine: to.machineId, action, requestId,
      summary: `${action} → ${to.machineId}`, payload: { requestId, action, args: action.includes("transcript") || action === "send_message" ? { session_id: s?.session_id } : {} } },
    { id: id("evt"), timestamp: new Date(now + lat).toISOString(), type: "bridgeRpcResponse", target: from, fromMachine: to.machineId, toMachine: from, action, requestId,
      summary: `${action} ok · ${lat}ms`, payload: { requestId, ok: true, latencyMs: lat } },
  ];
}

export function seedTranscript(s: Session): Transcript {
  const t = (m: number) => new Date(new Date(s.updated_at).getTime() - m * 60000).toISOString();
  return {
    machineId: s.machineId,
    session: { session_id: s.session_id, title: s.title, repo: s.repo, branch: s.branch, session_type: s.session_type, is_running: s.is_running },
    messages: [
      { role: "user", messageId: id("msg"), turnId: "t1", timestamp: t(14), content: `Let's pick up "${s.title}". What's the current state of \`${s.branch || "main"}\` in ${s.repo || "workspace"}?` },
      { role: "assistant", messageId: id("msg"), turnId: "t1", timestamp: t(13), toolCalls: ["git_status", "read_file"],
        content: `I checked the working tree on **${s.machineId}**.\n\n- Branch \`${s.branch || "main"}\` is 3 commits ahead of origin\n- 2 modified files, no conflicts\n\n\`\`\`bash\ngit log --oneline -3\na1f9c2e bridge: tail transcript with cursor\n7be0d41 presence: include wsPort\n3c22aa9 chore: bump 1.7.0\n\`\`\`` },
      { role: "user", messageId: id("msg"), turnId: "t2", timestamp: t(6), content: "Good. Run the tests and summarize failures." },
      { role: "assistant", messageId: id("msg"), turnId: "t2", timestamp: t(5), toolCalls: ["run_terminal", "grep_search"],
        content: "All **42** tests pass. One flaky timeout in `presence.spec.ts` was retried once.\n\n```ts\nexpect(await hub.ping('MINI-SERVER-PC')).toBeLessThan(500);\n```\n\nNext I'd suggest pushing and opening a PR." },
    ],
  };
}

export function seedProjects(machineId: string, sessions: Session[], scope: Scope) {
  const repos = Array.from(new Set(sessions.filter((s) => s.machineId === machineId && s.repo).map((s) => s.repo!)));
  const projects: Project[] = repos.map((r, i) => ({ project_id: `prj-${i + 1}`, name: r.split("/")[1] || r, repo: r, container_kind: i % 2 ? "worktree" : "repo",
    path: machineId === "LINUX-GPU-HOST" ? `/home/example/src/${r.split("/")[1] || r}` : `D:\\src\\${r.split("/")[1] || r}`, default_branch: "main" }));
  return { machineId, scope, count: projects.length, projects };
}
