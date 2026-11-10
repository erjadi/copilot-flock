# Copilot SignalR Bridge `v3.0` — Multi-Flock P2P Platform Architecture & RFC

**Legacy reference:** this document describes broker-backed compatibility,
not the broker-free 3.4.0 default. Its hub, maintainer visibility and revocation
model must not be used to infer 3.4 behavior.
See [the current protocol](./BROKER_FREE_V34.md).

- **Status**: Draft RFC for Flock Peer Review (`branch: v3-multi-flock-design`)
- **Baseline**: `v2.2.0` (`5fc4b3e`)
- **Platform Maintainer**: `@erjadi` (`your-signalr.service.signalr.net` / `your-flock-bootstrap.azurewebsites.net`)
- **Designated `v3` Preview Test Ring**: `MAIN-WORKSTATION`, `ARM64-LAPTOP`, `CLOUD-DEV-VM` *(leaving `3D-STUDIO-PC`, `MINI-SERVER-PC`, `LINUX-GPU-HOST`, and `LINUX-CONSOLE` untouched on `v2.2.0` during preview)*

---

## 1. Executive Summary & Core Goals

In `v1.0`–`v2.2.0`, installing `copilot-signalr-bridge` automatically enrolled every machine into a **single global flock** (`hub=copilotbridge`). While ideal for a single owner's fleet of 7 machines, it prevents using the bridge as a **multi-tenant, peer-to-peer (P2P) platform** where:

1. **Built-In User Flocks (`<githubUser>`, `<githubUser>/personal`, `<githubUser>/work` — Zero Setup Choice Needed)**:
   - Every user automatically has three built-in views of their own machines with **no "default namespace" choice required**:
     - **`erjadi`** *(all of your PCs)*: All 7 of your `@erjadi` machines (`personal` + `work`).
     - **`erjadi/personal`** *(your personal flock)*: Automatically contains all `@erjadi` machines tagged `personal` (`MAIN-WORKSTATION`, `3D-STUDIO-PC`, `MINI-SERVER-PC`, `LINUX-GPU-HOST`, `LINUX-CONSOLE`).
     - **`erjadi/work`** *(your work flock)*: Automatically contains all `@erjadi` machines tagged `work` (`CLOUD-DEV-VM`, `ARM64-LAPTOP`).
   - Note on Terminology: In `v3.0`, machine scope is strictly **`personal` or `work`** (`"private"` is retired completely and not kept as an alias).
   - A colleague (`@alice`) automatically gets **`alice`**, **`alice/personal`**, and **`alice/work`** across her own machines—completely invisible to other colleagues.
2. **Custom / Shared Flocks (`<ownerGitHubUser>/<slug>`)**:
   - You only create a named flock when you want a custom or shared group (e.g. `erjadi/studio-team` with colleagues).
   - A single machine (e.g. `CLOUD-DEV-VM`) automatically belongs to its built-in owner flocks (`erjadi` and `erjadi/work`) **and** can join any number of shared flocks (`erjadi/studio-team`) with strict per-flock sharing rules and zero cross-flock leakage.
3. **P2P Data Plane with Brokered Membership Plane**:
   - **`copilot-flock-bootstrap`** acts as the central **Token Broker & Roster Registry** (enforcing SignalR hub token issuance, roster epochs, and immediate connection revocation), while inside each flock, RPC communication, vouching (`flock vouch`), and release voting operate **peer-to-peer** without a per-flock admin hierarchy.
4. **Platform Maintainer Observability (`@erjadi`) & Explicit Consent**:
   - Flocks are isolated from *each other* via brokered per-flock SignalR hub tokens and Ed25519 signatures rather than opaque client-side E2EE, allowing `@erjadi` (as platform maintainer of `copilot-flock`) to monitor all flocks, health, and traffic in the Fleet Console.
   - **Explicit Disclosure & Consent**: Both `flock create` and `flock join` display a mandatory disclosure banner stating that the flock is hosted on `copilot-flock` where platform maintainer `@erjadi` has plaintext observability for diagnostics and governance, and record `maintainerVisibilityAck: true` in the enrollment request.

---

## 2. System Architecture, Namespace Grammar & Cryptographic Model

### 2.0 Universal Hierarchical Namespace Grammar (`<owner>/<flock>[/<machineId>]`)

Every target on the bridge—whether an entire flock or one specific PC inside that flock—follows **one single path hierarchy**:

```text
<owner>/<flock>[/<machineId>]
```

| Path Level | Format | Examples | Meaning |
| :--- | :--- | :--- | :--- |
| **1. Owner (`<owner>`)** | `<githubUser>` | `erjadi` *(all of the owner's PCs)*<br>`alice` *(all of another owner's PCs)* | Segment 1 is **always** the GitHub handle of the flock's owner. |
| **2. Flock (`<owner>/<flock>`)** | `<owner>/personal`<br>`<owner>/work`<br>`<owner>/<customFlock>` | `erjadi/personal` *(owner's personal PCs)*<br>`erjadi/work` *(owner's work PCs)*<br>`erjadi/studio-team` *(shared team flock)*<br>`alice/project-x` *(another owner's team flock)* | Segment 2 is the **flock name**: either one of the two automatic built-in scopes (`personal` or `work`) or any custom/shared flock name (`studio-team`). |
| **3. Optional PC (`<owner>/<flock>/<machineId>`)** | `<owner>/<flock>/<machineId>` | `erjadi/personal/MAIN-WORKSTATION`<br>`erjadi/personal/LINUX-GPU-HOST`<br>`erjadi/work/ARM64-LAPTOP`<br>`erjadi/studio-team/CLOUD-DEV-VM` | Segment 3 (optional) narrows the target to **one specific machine** inside that flock (including for 2-hour single-PC guest passes!). *(Under the hood, each flock and device is also backed by immutable `flockUuid` and `githubUserId:deviceId` so renames never break security.)* |

### 2.1 Separating Platform Installation from Flock Membership (Collision-Proof Immutable IDs)

| Concept | `v2.2.0` (Single Flock) | `v3.0` (Multi-Flock Platform) |
| :--- | :--- | :--- |
| **`node bridge.mjs install`** | Joins global `copilotbridge` hub immediately | Provisions local daemon, MCP server, and machine Ed25519 key (`identity.json`); auto-joins `<githubUser>` + `<githubUser>/<scope>` (`personal` or `work`). |
| **Canonical Flock Identity** | Single hub `copilotbridge` | Immutable **`flockUuid`** (`hub = v3_flock_<flockUuid_no_dashes>`), mapped from human-friendly handle `<namespace>/<slug>` (preventing `_` vs `-`/`/` slug collisions). |
| **Canonical Peer Identity** | `machineId` (e.g. `ARM64-LAPTOP`) | Immutable **`githubUserId:deviceId`** (numeric GitHub account ID + UUID derived from `keyFingerprint`), with **`<githubUser>@<machineId>`** as display/CLI address alias (immune to GitHub handle renames and same-user hostname collisions). |
| **Wire Credential** | Raw Azure SignalR `AccessKey` distributed by `/api/bootstrap` | **Short-lived (1h) per-flock SignalR Hub JWTs** minted by `/api/v3/token` for `hub = v3_flock_<flockUuid>`. Raw `AccessKey` is **never** sent to `v3` clients, and legacy `v2` SignalR `AccessKey` is rotated/retired before admitting external colleagues. |
| **Offline Queue** | Single topic `copilot-bridge-offline` keyed by `machineId` | Flock-qualified subscription/filter (`flockUuid + deviceId`), re-verifying active `rosterEpoch` and membership at drain time. |

### 2.2 Token Broker, Legacy `AccessKey` Retirement, and Challenge-Bound Refresh

In `v2.2.0`, `/api/bootstrap` returns the master Azure SignalR `AccessKey`. Because any holder of the `v2` master `AccessKey` could mint JWTs for `v3_flock_*` hubs on the same SignalR resource:
- **During the 3-PC internal preview (`MAIN-WORKSTATION`, `ARM64-LAPTOP`, `CLOUD-DEV-VM`)**: Only `@erjadi`'s own machines participate.
- **Before admitting any external colleague in `v3.0` production**: Either (a) all `@erjadi` machines cut over to `v3` brokered tokens and the Azure SignalR primary/secondary `AccessKey` on `copilot-flock` is rotated (invalidating all legacy `v2` static `connectionString` files), OR (b) `v3` uses a dedicated SignalR resource whose `AccessKey` has never been distributed to any client.

**Two-Phase Token Issuance (`Initial Enroll` vs. `Challenge-Bound Refresh`)**:
1. **Initial Enrollment (`POST /api/v3/enroll`) — Requires Both GitHub OAuth Token & Ed25519 Device Signature**:
   - Caller sends `Authorization: Bearer <githubToken>`, `flockId`, `deviceId`, `machineId`, `publicKey`, `maintainerVisibilityAck: true`, and an Ed25519 signature.
   - `copilot-flock-bootstrap` verifies the GitHub token against `https://api.github.com/user` (recording immutable numeric `githubUserId` + current `githubUser` login), verifies the enrollment policy (same-owner or valid P2P voucher), pins `deviceId + publicKey` in the flock roster (`rosterEpoch++`), and returns the initial 1-hour SignalR Hub JWT + signed roster snapshot.
2. **Reconnect / Periodic Token Refresh (`POST /api/v3/token/refresh`) — Challenge-Bound Ed25519 Signature (No `gh` CLI Spawn Required)**:
   - To avoid spawning `gh auth token` on sleep/wake reconnects while preventing replay attacks:
   - Daemon fetches a short-lived `serverNonce` (or uses the rolling nonce from its last token response) and signs:
     `refresh|v3|<flockUuid>|<githubUserId>|<deviceId>|<rosterEpoch>|<serverNonce>|<timestamp>`
   - `copilot-flock-bootstrap` verifies `deviceId` is still an active, unrevoked member of `flockUuid` at the current `rosterEpoch`, verifies the Ed25519 signature and fresh `serverNonce`, and issues a new 1-hour SignalR Hub JWT (`aud = v3_flock_<flockUuid>`, `sub = <githubUserId>:<deviceId>`).
   - GitHub account status is re-verified once every 24 hours (or whenever `rosterEpoch` changes).

### 2.3 Canonical `v3` Request & Response Signing Envelopes

Both RPC **requests** and **responses** over a flock hub are signed with the sender's Ed25519 private key and include `rosterEpoch`:

```text
# Request signing string:
v3|req|<flockUuid>|<rosterEpoch>|<requestId>|<sentAt>|<expiresAt>|<fromPeerId>|<toPeerId>|<action>|<sha256(canonicalJson(params))>

# Response signing string:
v3|res|<flockUuid>|<rosterEpoch>|<requestId>|<respondedAt>|<fromPeerId>|<toPeerId>|<status>|<sha256(canonicalJson(resultOrError))>
```

- Where `fromPeerId` / `toPeerId` are canonical `<githubUserId>:<deviceId>` (or `*` for broadcast requests).
- **Cross-Flock & Stale-Roster Replay Prevention**: Binding `<flockUuid>` and `<rosterEpoch>` inside both request and response signatures prevents cross-flock replay and forces immediate roster refresh if a peer's `rosterEpoch` is behind.

### 2.4 Time-Bound Guest Access (`membershipExpiresAt` for Flocks & Single-PC Guest Passes)

To let a colleague collaborate with **either an entire flock or a single PC/session for a bounded duration** (e.g. 2 hours or 24 hours) without manual cleanup afterward:

1. **Time-Bound Flock Membership (`membershipExpiresAt`)**:
   - An Enrollment JSON voucher can specify `"membershipExpiresAt": "<ISO-8601>"` (distinct from `voucherExpiresAt`).
   - `copilot-flock-bootstrap` records `membershipExpiresAt` on the member's roster entry and caps every minted SignalR Hub JWT `exp` to `min(now + 1h, membershipExpiresAt)`.
   - At `membershipExpiresAt`, `copilot-flock-bootstrap` automatically:
     1. Rejects any further token refreshes,
     2. Calls Azure SignalR REST `DELETE /api/v1/hubs/v3_flock_<flockUuid>/users/<peerId>` to drop any open WebSocket at the exact expiration timestamp, and
     3. Prunes the expired guest entry (`rosterEpoch++`).
2. **Time-Bound Single-PC / Single-Session Guest Pass (`<owner>/guest-<shortId>`)**:
   - When you tell Copilot *"Let `@alice` talk to `CLOUD-DEV-VM` (or my `'service-api debugging'` thread) for 2 hours"*, Copilot creates an **ephemeral 2-peer guest flock** (`erjadi/guest-alice-<shortId>`, containing only `erjadi@CLOUD-DEV-VM` and `@alice`, scoped strictly to that single shared session, with `flockExpiresAt: +2h`).
   - When `flockExpiresAt` is reached, both `copilot-flock-bootstrap` and `CLOUD-DEV-VM` automatically sever the connection and delete the ephemeral guest flock—zero leftover memberships or manual `kick` required.

---

## 3. Local Sharing Policy & The 4 Anti-Leakage Hard Walls

When a machine (such as `CLOUD-DEV-VM` or `ARM64-LAPTOP`) belongs to both `erjadi/personal` and `work/studio-team`, local configuration is stored in `~/.copilot/signalr-bridge/flocks.json`:

```json
{
  "defaultFlock": "erjadi/personal",
  "flocks": {
    "erjadi/personal": {
      "flockId": "erjadi/personal",
      "trustTier": "owner",
      "allowedScopes": ["personal", "work"],
      "allowedRepos": ["*"],
      "sessionVisibility": "all",
      "sharedSessionIds": [],
      "shareSpecs": "full",
      "autoUpgrade": "owner_push"
    },
    "erjadi/studio-team": {
      "flockId": "erjadi/studio-team",
      "flockUuid": "00000000-0000-4000-8000-000000000004",
      "trustTier": "collaborator",
      "allowedScopes": ["work"],
      "allowedRepos": ["microsoft/*", "contoso/*", "erjadi/service-api"],
      "sessionVisibility": "explicit_opt_in_only",
      "sharedSessionIds": ["00000000-0000-4000-8000-000000000014"],
      "shareSpecs": "summary",
      "autoUpgrade": "prompt"
    }
  }
}
```

### Wall 1: Pre-LLM Daemon Enforcement & Strict Collaborator Isolation (Outside the Model)
Before any RPC touches an LLM or returns local state, `handleRpcAction(cfg, flockPolicy, req)` enforces:
1. **Mutating RPC Block**: If `flockPolicy.trustTier !== "owner"` (or `fromGitHubUserId !== localGitHubUserId`), the daemon hard-rejects `self_update`, `reprovision`, `send_file_chunk`, `pull_file_chunk`, `apply_git_bundle`, `acquire_lock`, `release_lock`, `diagnose --fix`, and `create_session`.
2. **Scope & Explicit Session Opt-In Filtering (No Automatic Exposure of Pre-Existing Chat History)**:
   - First, if this machine's `cfg.scope` (strictly `"personal"` or `"work"`) is not in `flockPolicy.allowedScopes` (e.g. `["work"]`), the daemon rejects all session/transcript RPCs on that flock, and a `"personal"` machine is blocked from joining shared `work/*` flocks by default.
   - Second, because an existing coding session in `microsoft/*` may contain pre-existing private history in `events.jsonl` and holds interactive shell/filesystem tools, **`collaborator` flocks default to `sessionVisibility: "explicit_opt_in_only"`** (existing sessions are **never** auto-exposed merely by repo glob).
   - When a user runs `node bridge.mjs flock share-session --flock work/studio-team --session <id> [--mode read-only-projection | dedicated-collaborator-session]`:
     - **`approved-snapshot` (default)**: Publishes only a user-reviewed and explicitly approved summary snapshot (served deterministically by the daemon) and does not allow remote peers to inject prompts into an existing session that holds prior unshared context in its LLM memory.
     - **`dedicated-collaborator-session`**: Spawns a clean, dedicated collaborator session bound to `boundFlockId = "erjadi/studio-team"` in an isolated workspace directory (seeded only with the approved summary) with restricted tool permissions (never `allow-all`).
3. **Hardware Spec Redaction**:
   - `shareSpecs: "summary"` strips disk volume labels/mounts and network share paths (`\\Demo-NAS\...`, `P:`, `R:`, `W:`), returning only OS, CPU core count, total RAM, and GPU model.

### Wall 2: Per-Flock Isolated Context (Owner-Only Auto-Trackers)
- `allow-all` LLM `Thread Tracker` sessions (`session_store_sql`, `list_sessions_and_chats`, `powershell`) are **strictly restricted to `owner` (`<owner>`, `<owner>/personal`, `<owner>/work`) flocks**.
- For `collaborator` flocks, discovery (`list_sessions`, `get_transcript`) is served **deterministically by the daemon** over `sharedSnapshots` and `dedicatedCollaboratorSessions` without invoking an unrestricted LLM tracker that could query unshared local state.

### Wall 3: Runtime-Authenticated Session Taint-Tagging (`boundFlockId`) & Child Inheritance
- Any local session created for or bound to a flock `X` is recorded in `~/.copilot/signalr-bridge/session-flock-bindings.json` with `boundFlockId = X`, and the daemon passes `COPILOT_BRIDGE_BOUND_FLOCK_ID=X` + a per-session HMAC token to its MCP server process (so caller identity is runtime-authenticated, not trusted from CLI arguments).
- **Transitive Child-Session Taint Inheritance**: If a session with `boundFlockId = X` spawns any child session, the child automatically inherits `boundFlockId = X`.
- Any outbound MCP/CLI bridge operation (`machines`, `sessions`, `transcript`, `send`, `broadcast`, `send-file`) from a bound session is hard-locked to `boundFlockId = X` and rejects conflicting `--flock` arguments.

### Wall 4: Flock-Partitioned Storage, Immediate Live Revocation & Redacted Hardware Locks
- All local logs, inboxes, outboxes, and offline replay states are partitioned by immutable `flockUuid` under `~/.copilot/signalr-bridge/flocks/<flockUuid>/`.
- **Immediate Live WebSocket Eviction on Revocation**: When a user or device is revoked (`flock revoke`), `copilot-flock-bootstrap`:
  1. Increments `rosterEpoch`, records `revokedUserIds` / `revokedDeviceIds` (so a revoked user cannot auto-rejoin via another device or unredeemed voucher),
  2. Broadcasts a broker-signed `roster_revoked` frame on `v3_flock_<flockUuid>`, and
  3. Invokes the Azure SignalR REST API `DELETE /api/v1/hubs/v3_flock_<flockUuid>/users/<peerId>` to drop any open WebSocket connection immediately (without waiting up to 1 hour for JWT expiry).
- **Offline Queue Drain Re-Verification**: When draining Service Bus after sleep, the daemon fetches the latest signed roster (`rosterEpoch`) and drops any queued message from a sender no longer in the active roster.
- **Machine-Global Hardware Locks with Redacted Holder Metadata**: Physical locks (`RTX-GPU`) remain machine-global, returning `holder: { ownerFlock: "redacted", reason: "busy (another local flock)" }` across different flocks.

---

## 4. End-to-End User Journeys (Copilot Is the Interface)

**Core UX Principle**: Neither you nor your colleagues ever type CLI commands in a terminal. **GitHub Copilot itself is the user interface.** Every action—from initial installation to creating flocks, inviting colleagues, sharing a chat thread, and asking questions across machines—is done by simply talking to Copilot in natural language (backed by the bridge's MCP tools).

### Journey 1: First-Time Setup, `Work` vs. `Personal` Detection, & Your Personal Flock (`erjadi/personal`)
1. **What you tell Copilot on a new PC**:
   > *"Clone `https://github.com/erjadi/copilot-signalr-bridge` and set up the SignalR bridge on this machine."*
2. **How Copilot knows if the PC is `work` or `personal`**:
   - Copilot inspects local OS/domain signals (whether the PC is corporate Entra ID / AD domain-joined like `ARM64-LAPTOP` and `CLOUD-DEV-VM` $\rightarrow$ **`work`**, or a standalone home machine like `MAIN-WORKSTATION`, `MINI-SERVER-PC`, `LINUX-GPU-HOST` $\rightarrow$ **`personal`**) and asks a 1-click confirmation (`ask_user`): **Work** vs. **Personal** *(unless you already specified it in your prompt)*.
   - Automatically joins your **`erjadi/personal`** flock so all 7 of your `@erjadi` machines (both `personal` and `work`) see each other immediately with full owner trust—no invite codes needed.

### Journey 2: A Colleague Sets Up Her Own PCs (`alice/personal`)
1. **What Alice tells Copilot on her work laptop and home PC**:
   > *"Clone `https://github.com/erjadi/copilot-signalr-bridge` and set up the SignalR bridge."*
2. **What happens**:
   - Because both of Alice's computers are signed into her `@alice` GitHub account, Copilot automatically links them into her own **`alice/personal`** flock.
   - Alice can talk between her work laptop and home PC just like you do, while her computers remain completely invisible to your personal flock.

### Journey 3: Streamlined One-Step Invite to One or More Flocks (GitHub Access + Enrollment JSON + Pasteable Teams/Email Prompt)
1. **Creating a shared flock**: On your work VM or work laptop, you tell Copilot:
   > *"Create a new shared work flock called `erjadi/studio-team` and add my work laptop to it."*
2. **Inviting a colleague to one or more flocks**: You tell Copilot:
   > *"Invite `@alice` to `erjadi/studio-team` (and `erjadi/studio-team`)."*
3. **What your Copilot does automatically**:
   - **Grants GitHub Repo Access (or Uses Voucher-Authenticated Installer)**: If the inviter is repo maintainer `@erjadi`, checks if `@alice` has read/pull access to `erjadi/copilot-signalr-bridge` on GitHub and invites her if needed; additionally, `copilot-flock-bootstrap` serves a voucher-authenticated installer bundle (`/api/v3/install-bundle`) so peers without GitHub repo admin rights (or temporary 2-hour guests) can enroll without needing permanent GitHub collaborator privileges.
   - **Creates the Signed Enrollment JSON**: Mints a 24-hour signed Enrollment JSON bundle bound to `@alice`'s immutable `githubUserId` (allowing up to `maxDevices: 3` of her `work` machines to redeem it idempotently).
   - **Prints a Single Copy-Pasteable Block in Chat (ready for Teams or Email)**:
     ```markdown
     Paste this message into your GitHub Copilot chat to set up the SignalR bridge and join our flock(s):

     Accept my pending GitHub repo invite to `erjadi/copilot-signalr-bridge` (if any), clone `https://github.com/erjadi/copilot-signalr-bridge`, install and set up the SignalR bridge on this machine, and enroll me using this enrollment JSON:
     ```json
     {
       "v": 3,
       "invitedUser": "alice",
       "invitedGitHubUserId": 12345678,
       "invitedBy": "erjadi",
       "bootstrapUrl": "https://your-flock-bootstrap.azurewebsites.net",
       "voucherExpiresAt": "2026-11-09T06:00:00Z",
       "maxDevices": 3,
       "flocks": [
         {
           "flockId": "erjadi/studio-team",
           "flockUuid": "00000000-0000-4000-8000-000000000004",
           "recommendedScope": "work",
           "voucherSignature": "<ed25519-signature>"
         }
       ]
     }
     ```
     ```
4. **What happens when Alice pastes that block into her Copilot**:
   - **Whether Alice is a brand-new user or already has the bridge installed**, pasting that single message into her Copilot handles the entire flow end-to-end:
     1. Verifies `bootstrapUrl` against the pinned allowlist (`https://your-flock-bootstrap.azurewebsites.net`) before touching any token,
     2. Accepts the GitHub repo invitation (if any) and clones/installs the bridge (confirming `Work` vs `Personal` for her PC),
     3. Creates her own built-in `alice` and `alice/work` flocks (if new),
     4. Displays a native `ask_user` confirmation for `erjadi/studio-team` (peers in the flock, `@erjadi` platform maintainer notice, and confirmation that none of her existing chats are shared by default) and enrolls her machine into every flock in the JSON!

### Journey 4: Sharing a Work Thread, Auditing Shared Threads & Talking Across Flocks
- **All chats are private by default**: Even though your work laptop is in both `erjadi/work` and `erjadi/studio-team`, colleagues in `erjadi/studio-team` cannot see or query any of your local Copilot threads unless you explicitly ask Copilot to share one.
- **Sharing a specific thread (Reviewed Summary Snapshot or Dedicated Clean Thread)**:
  - Because an existing thread's LLM still holds pre-share messages in its context window (and could accidentally quote earlier private details even if raw transcript lines were filtered), when you say:
    > *"Share this thread with the `erjadi/studio-team` flock"*
  - Copilot either (a) drafts a **clean summary snapshot** for your 1-click approval and publishes only that approved snapshot to `erjadi/studio-team`, or (b) opens a **fresh, clean `[erjadi/studio-team]` collaborator thread** seeded only with that approved summary so earlier private history is never in the shared LLM's memory.
- **"What am I sharing?" Audit & One-Sentence Unshare**:
  - At any time you can ask Copilot:
    > *"What threads on this PC are currently shared with colleagues?"* or *"Stop sharing this thread with `erjadi/studio-team`."*
  - Unsharing immediately removes the thread from `sharedSessionIds` and severs any guest pass attached to it.
- **Asking a specific flock**: When your PC belongs to multiple flocks, you just tell Copilot which flock you're talking to:
  > *"Ask the `erjadi/studio-team` flock if anyone has the ACS callback test bench running."*
  > *"Ask my personal machines what `LINUX-GPU-HOST` is working on."*

### Journey 5: Time-Bound Guest Access (To a Flock or a Single PC / Thread)
- **Temporary access to a single PC or thread**: Say you want `@alice` to collaborate with your `"service-api debugging"` thread on `CLOUD-DEV-VM` for the afternoon without adding her to a permanent flock. You tell Copilot:
  > *"Give `@alice` access to my `'service-api debugging'` thread on `CLOUD-DEV-VM` for the next 2 hours."*
  - Copilot creates a self-expiring 2-hour guest pass (`erjadi/guest-alice-...` scoped strictly to that one PC and thread, where the 2-hour duration starts upon acceptance, bounded by `voucherExpiresAt`) and outputs the pasteable Copilot invite block for Alice.
- **10-Minute Expiry Warning**: 10 minutes before a guest pass expires during an active session, your Copilot notifies you so you can say *"Extend `@alice`'s pass by 1 hour"* before mid-turn disconnect.
- **Automatic expiration (zero cleanup needed)**:
  - The exact minute the timer expires, `copilot-flock-bootstrap` AND the local daemon enforce the deadline: live SignalR WebSockets are dropped, any in-flight guest query is cancelled, and any queued outbound replies to the expired guest are dropped.

### Journey 6: Leaving a Flock, Kicking a Member, Re-Imaged PCs, and Upgrading
- **Leaving or kicking someone**: You or a colleague simply tell Copilot:
  > *"Leave the `erjadi/studio-team` flock"* or *"Kick `@alice` from `erjadi/studio-team`."*
- **Re-imaged or replaced laptop**: If you re-install Windows on `ARM64-LAPTOP`, Copilot detects that `@erjadi` already has an offline `ARM64-LAPTOP` entry in your flocks and asks: *"Replace your old `ARM64-LAPTOP` device key across your flocks, or keep both?"*
- **Voting & Upgrading**:
  - You tell Copilot: *"Ask the flock to review and vote on the new bridge release"* $\rightarrow$ every online peer tests the candidate in a sandbox and casts a signed vote.
  - You tell Copilot: *"Upgrade all my machines"* $\rightarrow$ all 7 of your `@erjadi` PCs upgrade automatically (and during the `v2` $\rightarrow$ `v3` upgrade, any machine with `scope: "private"` is deterministically migrated to `scope: "personal"` while `scope: "work"` stays `"work"`). For colleagues in `erjadi/studio-team`, their Copilot receives an upgrade notice and lets them update from GitHub without anyone ever force-running code on their machine.

---

## 5. Side-by-Side `v3` Preview Sandbox & Manifest-Driven Teardown Plan

To build and test `v3.0` without risking or polluting the live `v2.2.0` flock:

1. **Strictly Scoped 3-PC Preview Test Ring**:
   - **Included**: `MAIN-WORKSTATION` (`personal`), `ARM64-LAPTOP` (`work`), `CLOUD-DEV-VM` (`work`).
   - **Excluded (100% Untouched on `v2.2.0`)**: `3D-STUDIO-PC`, `MINI-SERVER-PC`, `LINUX-GPU-HOST`, `LINUX-CONSOLE`.
2. **Complete Resource & Wire Isolation (`--sandbox v3`)**:
   - **Local directory**: `~/.copilot/signalr-bridge-v3/` (separate `config.json`, `flocks.json`, `daemon.pid`, `daemon.log`, and **`sandbox-manifest.json`**).
   - **No sidebar chat pollution**: Installing the `v3` sandbox daemon does **not** auto-create GUI Coordinator/Tracker chat tabs in Copilot Desktop.
   - **SignalR Hubs**: `v3_preview_flock_<flockUuid>` (completely invisible to `v2.2.0`'s `copilotbridge` hub).
   - **Bootstrap Endpoints**: `/api/v3/preview/*` backed by `/home/site/data/v3-preview-flocks.json` and `/home/site/data/v3-preview-queue.json`.
   - **Service Bus Topic**: `copilot-bridge-v3-preview`.
3. **Manifest-Driven, Verified Full Teardown (`node bridge.mjs teardown-sandbox`)**:
   - Never uses wildcard file deletion or blind PID killing. Instead, every resource created by `--sandbox v3` is recorded in `~/.copilot/signalr-bridge-v3/sandbox-manifest.json`:
     - `daemonPid` + `daemonStartTime` + `commandLineSubstring: "--sandbox v3"` (verified before sending `SIGTERM` so a recycled OS PID is never killed).
     - Exact `createdSessionIds[]` (verified to carry `[v3-sandbox]` title prefix before calling `delete_session`).
     - Exact file paths under `~/.copilot/signalr-bridge-v3/` and `/home/site/data/v3-preview-flocks.json` + `/home/site/data/v3-preview-queue.json`.
     - Exact Service Bus topic name `copilot-bridge-v3-preview`.

---

## 6. Resolved Design Decisions from Flock Peer Review (Section 6 Doubts)

All 5 open design doubts were reviewed across the flock (`3D-STUDIO-PC`, `CLOUD-DEV-VM`, `LINUX-GPU-HOST`, `LINUX-CONSOLE`, `ARM64-LAPTOP`) and resolved as follows:

### Resolution 1: Owner-Only `allow-all` Trackers & Approved-Snapshot / Clean-Thread Sharing for Collaborator Flocks
- **Decision**: `allow-all` LLM `Thread Tracker` sessions are **strictly restricted to `owner` (`<owner>`, `<owner>/personal`, `<owner>/work`) flocks**.
- **Enforcement**: `collaborator` flocks use `sessionVisibility: "explicit_opt_in_only"` by default (never auto-exposing existing sessions by repo glob, since existing sessions may contain private chat history and unrestricted shell tools). Sharing a session with a collaborator flock either publishes a user-approved `approved-snapshot` (served deterministically by the daemon) or spawns a dedicated clean collaborator session (seeded only with the approved summary) with restricted tool permissions and transitive `boundFlockId` inheritance.

### Resolution 2: Immutable `<githubUserId>:<deviceId>` Canonical Identity + `<githubUser>@<machineId>` Alias
- **Decision**: Internally and cryptographically, every peer is identified by immutable **`<githubUserId>:<deviceId>`** (numeric GitHub user ID + UUID derived from the device's Ed25519 key fingerprint), while **`<githubUser>@<machineId>`** (and unambiguous short `<machineId>`) is supported in CLI flags and UI display.
- **Enforcement**: Handles GitHub username renames, prevents hostname collisions across both different users and the same user's multiple machines, and pins device keys across `rosterEpoch` increments.

### Resolution 3: Distinct-Principal Quorums, Inviter Authority & Immediate Revocation
- **Decision**: Flock creation configures `enrollmentPolicy` (`voucher_1ofN` or `voucher_quorum`, where `K` counts **distinct `githubUserId` principals**, never multiple devices of one user and never shrinking denominator to currently online peers).
- **Revocation & Recovery**: Self-leave (`flock leave`), founder/maintainer revocation, or `2-principal` quorum revocation increments `rosterEpoch`, invalidates all unredeemed vouchers for that principal, blocks re-enrollment via secondary devices, and immediately evicts live connections via SignalR REST `DELETE /api/v1/hubs/<hub>/users/<peerId>`. Founder/maintainer `@erjadi` retains dead-quorum recovery authority.

### Resolution 4: Fail-Closed Explicit `--flock` on All Multi-Flock Operations
- **Decision**: Whenever a machine is enrolled in $>1$ flock, **all** remote operations (both reads like `machines`, `sessions`, `transcript` and writes like `send`, `broadcast`, `create-session`, `send-file`, `update`) require an explicit `--flock <flockId>` unless invoked from a session with a runtime-authenticated `boundFlockId` HMAC token (which also rejects any conflicting `--flock` argument).

### Resolution 5: Two-Phase Enrollment & Challenge-Bound Ed25519 Token Refresh
- **Decision**: Reconciled Section 2 and Section 6:
  1. **Initial enrollment (`/api/v3/enroll`)** requires both a live GitHub token (`Authorization: Bearer <ghToken>`) and Ed25519 device signature.
  2. **Reconnect / 45-minute refresh (`/api/v3/token/refresh`)** uses a challenge-bound Ed25519 signature over `refresh|v3|<flockUuid>|<githubUserId>|<deviceId>|<rosterEpoch>|<serverNonce>|<timestamp>` (requiring no `gh` CLI spawn on sleep/wake, while enforcing nonce replay protection, active membership checks, and 24-hour GitHub account re-validation).
