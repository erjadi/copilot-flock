export type Vote = "ACCEPT" | "REJECT" | "QUEUED OFFLINE";
export type Platform = "win32-x64" | "win32-arm64" | "linux-x64";

export interface GovernanceBlocker {
  id: string;
  title: string;
  detail: string;
  raisedBy: string[];
  resolution: string;
  resolvedIn: string;
}

export interface Ballot {
  machineId: string;
  platform: Platform;
  vote: Vote;
  checks: { bridge: boolean; bootstrap: boolean; tests: boolean } | null;
  keyFingerprint: string | null;
  voteSignature: string | null;
  votePayload: string | null;
  review: string;
}

export interface GovernanceRound {
  number: number;
  sha: string;
  branch: string;
  summary: string;
  change: string;
  blockers: GovernanceBlocker[];
  ballots: Ballot[];
}

export interface RolloutHealth {
  machineId: string;
  version: string;
  daemonPid: number | null;
  coordinator: string;
  tracker: string;
  queueReceipt: string | null;
}

export const RELEASE = {
  candidate: "v3.3.0-rc",
  version: "v3.3.0",
  previousVersion: "v3.2.0",
  branch: "v3.3.0-rc",
  serviceBus: "your-servicebus.servicebus.windows.net",
  queue: "copilot-bridge-offline",
};

export const PIPELINE_STAGES = [
  { title: "Candidate Branch", short: "Candidate", detail: "origin/v3.3.0-rc · main untouched" },
  { title: "Ed25519 Daemon Check", short: "Daemon", detail: "flock.mjs + bootstrap syntax + signed vote" },
  { title: "Flock Peer Vote", short: "Peer vote", detail: "Adversarial review · 100% online ACCEPT" },
  { title: "Self-Update Rollout", short: "Rollout", detail: "Fast-forward main + update --all" },
  { title: "Diagnose Verified", short: "Diagnose", detail: "copilot-flock · Coordinator + Tracker" },
] as const;

const MACHINES: { machineId: string; platform: Platform; online: boolean }[] = [
  { machineId: "MAIN-WORKSTATION", platform: "win32-x64", online: true },
  { machineId: "3D-STUDIO-PC", platform: "win32-x64", online: true },
  { machineId: "MINI-SERVER-PC", platform: "win32-x64", online: true },
  { machineId: "LINUX-GPU-HOST", platform: "linux-x64", online: true },
  { machineId: "LINUX-CONSOLE", platform: "linux-x64", online: true },
  { machineId: "CLOUD-DEV-VM", platform: "win32-x64", online: true },
  { machineId: "ARM64-LAPTOP", platform: "win32-arm64", online: true },
];

// Synthetic preview only: these are not registered keys or signed release evidence.
const fingerprint = (machineId: string) =>
  `demo-fingerprint-${MACHINES.findIndex((machine) => machine.machineId === machineId) + 1}`;

const REVIEW_NOTES: Record<string, string> = {
  "1:LINUX-GPU-HOST": "**REJECT.** Collaborator flocks need explicit unshare audit and voucher-authenticated installer bundle so temporary guests do not require permanent GitHub repo collaborator privileges.",
  "2:3D-STUDIO-PC": "**REJECT.** Multi-Flock test plan requires role-bound collaborator wall assertions, a second-principal fixture, and a lost-response nonce grace window on `/api/v3/token/refresh`.",
  "3:LINUX-CONSOLE": "**REJECT.** GitHub repo rename (`example/copilot-signalr-bridge` → `erjadi/copilot-flock`) returns HTTP 301 on legacy API URLs; `githubApiGet` must follow redirects and state must migrate cleanly to `~/.copilot/flock`.",
};

function makeBallots(sha: string, votes: Record<string, Exclude<Vote, "QUEUED OFFLINE">>, round: number): Ballot[] {
  return MACHINES.map(({ machineId, platform, online }) => {
    if (!online) return {
      machineId, platform, vote: "QUEUED OFFLINE", checks: null, keyFingerprint: null, voteSignature: null, votePayload: null,
      review: "Offline during this round. Upgrade is queued in Azure Service Bus (`copilot-bridge-offline`) for store-and-forward delivery upon wake.",
    };
    const vote = votes[machineId];
    const checks = { bridge: true, bootstrap: true, tests: vote === "ACCEPT" };
    return {
      machineId, platform, vote, checks,
      keyFingerprint: fingerprint(machineId),
      voteSignature: null,
      votePayload: `demo-only|${machineId}|${RELEASE.branch}|${sha}|${vote}`,
      review: REVIEW_NOTES[`${round}:${machineId}`] ?? (round === 4
        ? "**Synthetic ACCEPT.** Illustrative syntax, unit and coordinator checks passed. No real signature or release authorization is included in this preview."
        : "**ACCEPT.** `flock.mjs` and `bootstrap-server.mjs` passed native syntax checks. Tests and adversarial review found no merge-blocking regression."),
    };
  });
}

const BLOCKERS: Record<number, GovernanceBlocker[]> = {
  1: [
    {
      id: "unshare-voucher", title: "Thread unshare audit & voucher-authenticated installer bundle", raisedBy: ["LINUX-GPU-HOST", "CLOUD-DEV-VM"],
      detail: "Temporary 2-hour guests and non-admin inviters need a voucher-authenticated installer bundle (`/api/v3/install-bundle`) plus a 1-click thread unshare audit.",
      resolution: "Added `list_shared_threads`, `unshare_thread_from_flock`, 10-minute guest expiry warning, and `/api/v3/install-bundle`.", resolvedIn: "demo-02",
    },
  ],
  2: [
    {
      id: "collaborator-walls", title: "Role-bound collaborator walls & refresh nonce grace window", raisedBy: ["3D-STUDIO-PC", "ARM64-LAPTOP"],
      detail: "Token refresh needed a lost-response nonce grace window on sleep/wake, and adversarial tests needed a second-principal collaborator fixture.",
      resolution: "Added role-bound collaborator wall tests, second-principal sandbox override, and nonce grace window.", resolvedIn: "demo-03",
    },
  ],
  3: [
    {
      id: "repo-rename-301", title: "GitHub repo rename (`erjadi/copilot-flock`) HTTP 301 redirect & state migration", raisedBy: ["LINUX-CONSOLE", "MAIN-WORKSTATION"],
      detail: "Renaming the repository to `erjadi/copilot-flock` required HTTP 301 redirect following in `bootstrap-server.mjs` and seamless `~/.copilot/signalr-bridge` → `~/.copilot/flock` migration.",
      resolution: "Updated `flock.mjs`, `bootstrap-server.mjs`, `copilot-flock.vbs` / `copilot-flock.service`, and `Copilot Flock Coordinator` + `Copilot Flock Thread Tracker` titles.", resolvedIn: "demo-04",
    },
  ],
  4: [],
};

const ROUND_INPUT = [
  { sha: "demo-01", summary: "Synthetic baseline review", change: "Illustrative namespace and security-boundary review.", rejects: ["LINUX-GPU-HOST"] },
  { sha: "demo-02", summary: "Synthetic collaborator review", change: "Illustrative invite and thread-sharing checks.", rejects: ["3D-STUDIO-PC"] },
  { sha: "demo-03", summary: "Synthetic compatibility review", change: "Illustrative cross-OS and state-migration checks.", rejects: ["LINUX-CONSOLE"] },
  { sha: "demo-04", summary: "Synthetic unanimous review", change: "Seven fictional nodes accept the example candidate. This is not a real signed release vote or deployment record.", rejects: [] },
] as const;

export const GOVERNANCE_ROUNDS: GovernanceRound[] = ROUND_INPUT.map((input, index) => {
  const number = index + 1;
  const votes: Record<string, "ACCEPT" | "REJECT"> = Object.fromEntries(MACHINES.filter((m) => m.online).map((m) => [m.machineId, (input.rejects as readonly string[]).includes(m.machineId) ? "REJECT" as const : "ACCEPT" as const]));
  return { number, sha: input.sha, branch: RELEASE.branch, summary: input.summary, change: input.change, blockers: BLOCKERS[number], ballots: makeBallots(input.sha, votes, number) };
});

export const ROLLOUT_HEALTH: RolloutHealth[] = MACHINES.map(({ machineId, online, platform }, index) => ({
  machineId,
  version: online ? `${RELEASE.previousVersion} → ${RELEASE.version}` : `${RELEASE.previousVersion} · upgrade queued`,
  daemonPid: online ? 26400 + index * 173 : null,
  coordinator: online ? `Copilot Flock Coordinator · ${platform.startsWith("linux") ? "copilot-flock.service" : "copilot-flock.vbs"}` : "Pending first reconnect",
  tracker: online ? "Copilot Flock Thread Tracker · allow-all" : "Pending first reconnect",
  queueReceipt: online ? null : `sb://${RELEASE.serviceBus}/${RELEASE.queue} · v3.1.0`,
}));

export function getRoundStats(round: GovernanceRound) {
  const online = round.ballots.filter((ballot) => ballot.vote !== "QUEUED OFFLINE");
  const accepted = online.filter((ballot) => ballot.vote === "ACCEPT").length;
  const rejected = online.filter((ballot) => ballot.vote === "REJECT").length;
  const offlineQueued = round.ballots.length - online.length;
  return { accepted, rejected, online: online.length, offlineQueued, approvedForMerge: online.length > 0 && accepted === online.length };
}
