# Copilot SignalR Bridge `v3.0` — Implementation & Test Plan (DevDoc)

- **Branch**: `origin/v3-multi-flock-design`
- **Companion Spec**: [`docs/V3_MULTI_FLOCK_ARCHITECTURE.md`](./V3_MULTI_FLOCK_ARCHITECTURE.md)
- **Live Production Baseline (Untouched During Preview)**: `v2.2.0` (`5fc4b3e`)
- **Designated 3-PC `v3` Preview Test Ring**: `MAIN-WORKSTATION` (`personal`), `ARM64-LAPTOP` (`work`), `CLOUD-DEV-VM` (`work`)
- **Untouched Production Machines**: `3D-STUDIO-PC`, `MINI-SERVER-PC`, `LINUX-GPU-HOST`, `LINUX-CONSOLE`

---

## 1. Implementation Architecture & Module Breakdown

### 1.1 `bootstrap-server.mjs` (`copilot-flock-bootstrap` Azure App Service)
All existing `v2.2.0` endpoints (`/api/bootstrap`, `/api/register`, `/api/members`, `/api/queue/*`) remain **100% untouched** so the live 7-machine `v2.2.0` flock experiences zero disruption.

We add additive `/api/v3/*` (and `/api/v3/preview/*` when `sandbox=v3`) endpoints backed by `/home/site/data/v3-flocks.json` (or `/home/site/data/v3-preview-flocks.json` in sandbox mode) with `withFlockStoreLock` atomic write-rename serialization:

1. **`POST /api/v3/enroll` (Initial Setup & Voucher Redemption)**:
   - Authenticates caller via `Authorization: Bearer <githubToken>` against `https://api.github.com/user` (resolving immutable numeric `githubUserId` + `githubUser`) **and** verifies the caller's Ed25519 signature over the complete enrollment payload:
     `enroll|v3|<githubUserId>|<deviceId>|<machineId>|<scope>|<publicKeyFingerprint>|<sha256(canonicalEnrollmentJsonOrEmpty)>|<maintainerVisibilityAck>|<timestamp>`
   - Enforces `scope` as strictly `"personal"` or `"work"` (migrating any legacy `"private"` value to `"personal"`).
   - Automatically provisions and enrolls the device into its built-in owner flocks:
     - `<githubUser>` (all machines owned by `<githubUserId>`, `trustTier: "owner"`)
     - `<githubUser>/<scope>` (`<githubUser>/personal` or `<githubUser>/work`, `trustTier: "owner"`)
   - If an `enrollmentJson` bundle is provided:
     - Verifies each voucher's Ed25519 signature, `voucherExpiresAt`, `invitedGitHubUserId == githubUserId`, `maxDevices` limit (default `3`, serialized under `withFlockStoreLock` so concurrent redemptions cannot exceed `maxDevices`, while remaining idempotent on the same `deviceId`), and `maintainerVisibilityAck === true`.
     - For a single-PC guest pass (`<owner>/<flock>/<machineId>`), provisions an isolated guest hub (`v3_guest_<guestPassUuid>`) containing **only** the host machine (`<owner>/<flock>/<machineId>`) and the guest device so the guest never receives broadcast presence or metadata from sibling machines in `<owner>/<flock>`.
     - Pins `githubUserId:deviceId` + `publicKey` + `trustTier` (`"collaborator"` or `"guest"`) + optional `membershipExpiresAt` into the roster and increments `rosterEpoch`.
   - Mints and returns 1-hour SignalR Hub JWTs (`aud = v3_flock_<flockUuid>`, `sub = <githubUserId>:<deviceId>`, `exp = min(now + 1h, membershipExpiresAt)`) for each enrolled flock, plus a `serverNonce` for subsequent refreshes.

2. **`POST /api/v3/token/refresh` & `GET /api/v3/token/challenge` (Sleep/Wake & Lost-Response Resilient Refresh)**:
   - Verifies a challenge-bound Ed25519 signature over:
     `refresh|v3|<flockUuid>|<githubUserId>|<deviceId>|<rosterEpoch>|<serverNonce>|<timestamp>`
   - **Lost-Response / Reconnect Resilience**: Retains the previous `serverNonce` as idempotently valid for a 30-second grace window for the same `(deviceId, rosterEpoch)` if a prior HTTP response was dropped in transit, and exposes `GET /api/v3/token/challenge` to mint a fresh short-lived `serverNonce` after broker restart or long sleep.
   - Confirms `githubUserId:deviceId` is still an active, unrevoked member of `flockUuid` and `now < membershipExpiresAt`.
   - Returns a fresh 1-hour SignalR Hub JWT (capped at `membershipExpiresAt`), the latest signed roster if `rosterEpoch` advanced, and the next `serverNonce`.

3. **`GET /api/v3/my-flocks` (Live Owner & Membership Discovery)**:
   - Authenticated via Ed25519 device signature (or GitHub token).
   - Returns:
     - `ownedFlocks`: **Every** flock owned by `githubUserId` (`<owner>/*`), including flocks created on other PCs *after* this PC was bootstrapped (so your work PC is immediately aware of your `erjadi/personal` or `erjadi/home-lab` flocks and can mint guest passes for them without being a member of them).
     - `joinedFlocks`: Every flock in which this specific `deviceId` is an active participant.

4. **`POST /api/v3/flocks/create` & `POST /api/v3/flocks/invite` (Flock Creation & Streamlined Pasteable Invites)**:
   - Creates `<owner>/<flockName>` (or an ephemeral guest pass targeting `<owner>/<flock>[/<machineId>]` with `durationMinutes`, where `membershipExpiresAt = acceptedAt + durationMinutes` bounded by `voucherExpiresAt`).
   - Returns the signed **Enrollment JSON** and the ready-to-paste **Copilot Invite Prompt** for Teams/email.
   - Exposes `GET /api/v3/install-bundle` (authenticated by a valid Enrollment JSON voucher) so invited colleagues or 2-hour guests can bootstrap `bridge.mjs` without needing permanent GitHub collaborator privileges on `erjadi/copilot-signalr-bridge`.

5. **`POST /api/v3/flocks/kick`, `POST /api/v3/flocks/extend` & Automatic Expiry Sweep (`evictFlockMemberImmediate`)**:
   - Authorization: Verified against flock owner (`ownerGitHubUserId`), platform maintainer (`@erjadi`), self-leave, or `2-principal` quorum. `extend` requires owner/inviter authority and fails closed if the member was already kicked/revoked.
   - Triggered when `kick` / `leave` is called **or** when `membershipExpiresAt` is reached:
     1. Removes the target `githubUserId` (or specific `deviceId`) from the flock roster, records the revocation in `revokedPrincipals`, invalidates any unredeemed vouchers, and increments `rosterEpoch`.
     2. Broadcasts a broker-signed `roster_revoked` event on `v3_flock_<flockUuid>`.
     3. Calls Azure SignalR REST API `DELETE /api/v1/hubs/v3_flock_<flockUuid>/users/<githubUserId>:<deviceId>` to drop open WebSockets immediately (while local daemons also enforce `membershipExpiresAt` and `rosterEpoch` fail-closed on every packet even if the REST eviction call fails or the broker is unreachable).

6. **`GET /api/v3/maintainer/overview` (Platform Maintainer Visibility for `@erjadi`)**:
   - Exclusively for `@erjadi` (`githubUserId` pinned): returns all registered flocks, rosters, active expirations, and observer hub tokens so the Fleet Console can monitor all flocks on `copilot-flock`.

---

### 1.2 `bridge.mjs` (Multi-Flock Daemon, Address Parser, Conversational MCP Tools & Sandbox)

1. **Universal Hierarchical Address Parser (`parseFlockAddress(target)`)**:
   - Parses `<owner>`, `<owner>/<flock>`, and `<owner>/<flock>/<machineId>`:
     - `erjadi/personal` $\rightarrow$ `{ owner: "erjadi", flock: "personal", flockId: "erjadi/personal", machineId: null }`
     - `erjadi/work/ARM64-LAPTOP` $\rightarrow$ `{ owner: "erjadi", flock: "work", flockId: "erjadi/work", machineId: "ARM64-LAPTOP" }`
     - `erjadi/studio-team/CLOUD-DEV-VM` $\rightarrow$ `{ owner: "erjadi", flock: "studio-team", flockId: "erjadi/studio-team", machineId: "CLOUD-DEV-VM" }`

2. **Multi-Hub SignalR Connection Pool (`FlockConnectionPool` in `runDaemon`)**:
   - Maintains an independent `RawWebSocketClient` per joined `flockUuid` (`hub = v3_flock_<flockUuid>`).
   - Runs a 45-minute background token refresh loop + post-sleep reconnect via `/api/v3/token/refresh`.
   - Enforces the **4 Anti-Leakage Hard Walls** on every incoming RPC:
     - Verifies `v3|req|<flockUuid>|<rosterEpoch>|...` Ed25519 signature and checks `membershipExpiresAt` locally (failing closed if expired, cancelling any in-flight guest query, and dropping queued replies).
     - **Role-Bound `trustTier` Enforcement (No Same-Owner Bypass on Collaborator/Guest Flocks)**: Evaluates `trustTier` from the flock's policy and roster entry (`"owner"` only on built-in `<owner>`, `<owner>/personal`, `<owner>/work`; `"collaborator"` on shared flocks like `erjadi/studio-team`; `"guest"` on guest passes)—never bypassing `collaborator`/`guest` restrictions merely because `fromGitHubUserId === localGitHubUserId`.
     - For `collaborator` / `guest` requests, blocks all mutating RPCs (`self_update`, `reprovision`, `send_file_chunk`, `pull_file_chunk`, `create_session`, locks, `allow-all` Thread Trackers) and restricts discovery/messaging strictly to approved snapshots (`sharedSnapshots`) or clean collaborator-bound threads (`boundFlockId`).

3. **OS Auto-Detection of `work` vs. `personal` (`detectMachineScopeRecommendation()`)**:
   - Inspects corporate domain/Entra join (`dsregcmd /status`, `Win32_ComputerSystem.PartOfDomain`, Windows `Enterprise` SKU, and `git config user.email`) to pre-select **`work`** or **`personal`** for 1-click confirmation in Copilot (`ask_user`).

4. **Copilot-First Conversational MCP Tools**:
   - Since **Copilot is the interface**, all multi-flock workflows are exposed as first-class MCP tools so the user simply talks to Copilot:
     - `list_flocks`: Lists all joined flocks on this PC **and** queries `/api/v3/my-flocks` live so you see all flocks you own across all your PCs (including flocks created after this PC was bootstrapped).
     - `create_flock`: Creates `<owner>/<flockName>`.
     - `invite_to_flock`: Accepts `target` (`<owner>/<flock>` or `<owner>/<flock>/<machineId>`), `github_user` (`@alice`), and optional `duration_minutes` (for time-bound guest passes); returns the **pasteable Copilot prompt + signed Enrollment JSON**.
     - `enroll_from_invite_json`: Validates pinned `bootstrapUrl === "https://your-flock-bootstrap.azurewebsites.net"`, verifies Ed25519 voucher signatures, and joins the flock(s).
     - `share_thread` / `unshare_thread` / `list_shared_threads`: Publishes a reviewed summary snapshot (or opens a clean flock-bound thread), lists currently shared threads on this PC, or unshares a thread in one sentence.
     - `kick_flock_member` / `extend_guest_access` / `leave_flock`.

5. **Side-by-Side `--sandbox v3` Mode & Manifest-Driven `teardown-sandbox`**:
   - When `--sandbox v3` (or `COPILOT_BRIDGE_SANDBOX=v3`) is passed:
     - State directory is isolated at `~/.copilot/signalr-bridge-v3/`.
     - Hub names are prefixed `v3_preview_flock_<flockUuid>` and bootstrap calls use `/api/v3/preview/*`.
     - Zero GUI Coordinator/Tracker chat tabs are auto-created on install (no sidebar clutter).
     - Every created resource is logged in `~/.copilot/signalr-bridge-v3/sandbox-manifest.json` (`daemonPid`, `daemonStartTime`, `commandLineSubstring: "--sandbox v3"`, `createdSessionIds[]`).
   - `teardown-sandbox` reads `sandbox-manifest.json`, verifies `daemonPid` start-time and command line before terminating, deletes only manifest-recorded `[v3-sandbox]` sessions, removes `~/.copilot/signalr-bridge-v3/`, and calls `POST /api/v3/preview/teardown`.

---

## 2. Step-by-Step Testing & Verification Plan

### Phase 1: Automated Unit & Adversarial Security Suite (`test/v3-multi-flock.test.mjs`)
Before touching any remote machine, all tests must pass locally via `node --test`:
1. **Namespace Grammar Tests**: Verify `parseFlockAddress` across `erjadi`, `erjadi/personal`, `erjadi/work/ARM64-LAPTOP`, `erjadi/studio-team/CLOUD-DEV-VM`, and reject malformed paths.
2. **Cryptographic & Replay Tests**:
   - Verify `v3|req|...` and `v3|res|...` Ed25519 signatures.
   - Prove that a valid signed RPC from `erjadi/studio-team` is rejected if replayed on `erjadi/personal` (`Cross-flock signature mismatch`).
   - Prove that a message signed with an outdated `rosterEpoch` after a `kick` is rejected.
3. **Collaborator & Anti-Leakage Wall Tests**:
   - Prove that a peer in `erjadi/studio-team` (`collaborator`) receives `403` when requesting `get_transcript` or `send_message` on an unshared local session.
   - Prove that a single-PC guest pass (`erjadi/work/CLOUD-DEV-VM`) is rejected by `ARM64-LAPTOP` even though both are in `erjadi/work`.
   - Prove that mutating RPCs (`self_update`, `reprovision`, `send_file_chunk`, `pull_file_chunk`, `create_session`) from a collaborator or guest are hard-blocked.
   - Prove that `unshare_thread` immediately revokes access and severs any attached single-thread guest pass.
4. **Time-Bound Expiry & Kick Tests**:
   - Prove that when `membershipExpiresAt` passes, token refresh fails (`403 Expired`), open WebSockets are dropped, in-flight guest turns are cancelled, and queued offline replies are dropped.
   - Prove that multi-device invite redemption allows up to `maxDevices: 3` for the invited `githubUserId`, is idempotent on repeat paste from the same `deviceId`, and rejects a different `githubUserId`.
5. **Untrusted Paste & Migration Tests**:
   - Prove that `enroll_from_invite_json` rejects any JSON whose `bootstrapUrl` does not match `https://your-flock-bootstrap.azurewebsites.net`.
   - Prove that `v2` `config.json` with `scope: "private"` migrates deterministically to `scope: "personal"` (and `scope: "work"` stays `"work"`).

### Phase 2: Live 3-PC Preview Sandbox Test (`MAIN-WORKSTATION`, `ARM64-LAPTOP`, `CLOUD-DEV-VM`)
 Using the live `v2.2.0` bridge as our control plane, we deploy `--sandbox v3` **strictly to the 3 designated test PCs** (`3D-STUDIO-PC`, `MINI-SERVER-PC`, `LINUX-GPU-HOST`, and `LINUX-CONSOLE` are never touched):

| Test # | Scenario | Machines Involved | Pass Criteria |
| :--- | :--- | :--- | :--- |
| **L1** | **Built-in `personal` & `work` Auto-Enrollment** | `MAIN-WORKSTATION` (`personal`), `ARM64-LAPTOP` (`work`), `CLOUD-DEV-VM` (`work`) | `MAIN-WORKSTATION` joins `erjadi` + `erjadi/personal`; `ARM64-LAPTOP` & `CLOUD-DEV-VM` join `erjadi` + `erjadi/work`; zero sidebar chats created; `v2.2.0` unaffected. |
| **L2** | **Cross-Scope Owner Awareness After Bootstrap** | `MAIN-WORKSTATION` $\rightarrow$ `ARM64-LAPTOP` | Create `erjadi/home-test` on `MAIN-WORKSTATION` *after* `ARM64-LAPTOP` is already running; verify `ARM64-LAPTOP` sees `erjadi/home-test` via `list_flocks` and can mint a guest invite for it without being a member of `erjadi/home-test`. |
| **L3** | **Streamlined Pasteable Invite, Second-Principal Collaborator Fixture & Multi-Flock Isolation** | `CLOUD-DEV-VM` + `ARM64-LAPTOP` (in `erjadi/studio-team`), `MAIN-WORKSTATION` (outside) | Enroll via Enrollment JSON (including both role-bound `trustTier: "collaborator"` and a distinct sandbox principal fixture `invitedGitHubUserId: 99999999`); verify `erjadi/studio-team` messages never reach `MAIN-WORKSTATION`, cannot read unshared sessions or invoke mutating RPCs on `CLOUD-DEV-VM`, and refreshing/kicking `erjadi/studio-team` never drops `erjadi/work`. |
| **L4** | **Time-Bound Single-PC Guest Pass (`erjadi/work/CLOUD-DEV-VM`), Sibling Isolation & Instant Kick** | `ARM64-LAPTOP` $\rightarrow$ `CLOUD-DEV-VM` | Issue a 30-second guest pass to `erjadi/work/CLOUD-DEV-VM` (`v3_guest_<uuid>`) on an approved snapshot; verify guest never receives broadcast metadata from `ARM64-LAPTOP`, query succeeds before `t=30s`, and automatically disconnects + returns `403` (with in-flight cancellation and local fail-closed deadline enforcement even during simulated broker outage) at `t=31s`. |
| **L5** | **100% Clean, Idempotent Manifest-Driven Teardown** | `MAIN-WORKSTATION`, `ARM64-LAPTOP` (ARM64), `CLOUD-DEV-VM`, `copilot-flock-bootstrap` | Run `teardown-sandbox` twice (verifying idempotency and tampered-PID rejection); confirm `~/.copilot/signalr-bridge-v3/` and `/home/site/data/v3-preview-*` are completely removed, `~/.copilot/mcp-config.json` production entry is untouched, zero `v3` processes remain, and `node bridge.mjs diagnose` on `v2.2.0` reports `7/7` healthy. |

### Phase 3: Full Flock Pre-Merge Vote & Staged Production Cutover (`v3.0.0`)
1. Present the Phase 1 + Phase 2 test report and candidate branch `v3.0.0-rc` to all 7 machines in the flock (`vote-release` + peer review).
2. Only after **unanimous `7/7 ACCEPT`**:
   - **Step 1 (Backup & Rollout)**: Merge `v3.0.0` to `main`, deploy `bootstrap-server.mjs` to `copilot-flock-bootstrap`, and run `update --all` (which snapshots `config.v2.bak.json` for instant rollback and migrates each machine's `v2.2.0` config into `erjadi` + `erjadi/personal` or `erjadi/work`, queuing offline upgrades in Service Bus for any sleeping machine).
   - **Step 2 (Disable Legacy Key Endpoint First)**: Once all `@erjadi` machines are verified on `v3.0.0` brokered JWTs, disable raw `AccessKey` distribution on `/api/bootstrap` (`410 Gone — Use /api/v3/token`) so the new key can never be redistributed.
   - **Step 3 (Rotate Master `AccessKey` Before Admitting Colleagues)**: Rotate the Azure SignalR primary/secondary `AccessKey` on `copilot-flock` (`az signalr key renew`), invalidating all historical `v2` static `connectionString` values before any external colleague is invited.
