---
name: copilot-flock
description: Cross-machine ONLY: discover and message GitHub Copilot threads, manage flocks (<owner>/<flock>[/<machineId>]), generate pasteable invites, and share threads across "the flock" via the copilot-flock Azure SignalR + Service Bus platform. Keep using native list_sessions_and_chats and send_session_message for threads on the same computer.
---

# Copilot Flock Cross-Machine Platform (`copilot-flock`)

Use this skill whenever the user wants to discover, message, coordinate with, invite, or share threads across **the flock** (`<owner>/<flock>[/<machineId>]`).

## Removing Flock from This PC

When the user says "Remove Copilot Flock from this PC", execute the local
`uninstall` entrypoint or `unenroll_flock` with `traceless: true` on their behalf.
The canonical agent command is `node ~/.copilot/flock/flock.mjs uninstall`;
`unenroll --traceless` and the legacy entrypoint are also supported.

Report remote leave failures, pending cleanup and retained artifacts, not
"fully removed". Never silently fall back to local-only deletion. Only after
explicit approval, `--local-only --approve-local-only` removes local owned
artifacts while reporting unconfirmed remote memberships. Preserve local
conversations, chats, session-state, data.db, repositories, worktrees and backups.
Traceless cannot erase transcripts, OS audit logs or external backups.
See [removal behavior](../../docs/REMOVING_FLOCK.md) for limitations.

## Core Rules

**Select the installed protocol first.** `broker-free-v34` uses the two-service
default and never silently falls back to a broker. Use `join_request`,
`approve_join`, `accept_welcome` with independent device/owner fingerprint
verification, finite expiry and explicit session IDs. Use `renew_membership`
before short certificates expire; missed-rotation/expired recovery needs a
fresh Join Code and explicit owner renewal approval. Always preserve incoming
flock scope when replying; multiple memberships require an explicit selector.

Broker-free discovery/transcripts expose only approved shared snapshots.
Messaging is limited to shared certificate-permitted sessions; remote session
creation, file/admin RPC and delegation are unsupported rather than legacy
fallbacks. A self-box is not proof of remote X25519 possession. Partitioned
receivers may accept pre-kick traffic until certificate expiry; renewal and
removal completion require the designated owner. Full recovery is retained for
pending leaves/approvals, not reported as traceless success.

The one-step `invite_to_flock` / `enroll_from_invite_json` path and broader
administrative tools below are explicit legacy compatibility, not this new
protocol. This 3.4.0 source candidate has not passed live Azure isolation,
immutable review or the release vote; do not infer production authorization.

1. **Copilot is the Interface**:
   - Never ask the human user to type CLI commands manually. Run the `copilot-flock` MCP tools (`flock_status`, `list_flocks`, `invite_to_flock`, `enroll_from_invite_json`, `share_thread`, `unshare_thread`, `list_shared_threads`, `kick_flock_member`, `flock_topology`, `send_remote_session_message`, `broadcast_remote_session_message`) or `node ~/.copilot/flock/flock.mjs ...` on their behalf.
2. **Same-Machine vs. Cross-Machine**:
   - **Same-Machine**: Always use native `list_sessions_and_chats`, `get_session`, and `send_session_message` for threads on **this computer**.
   - **Cross-Machine**: Use `copilot-flock` MCP tools or `node ~/.copilot/flock/flock.mjs ...` when communicating with another computer in the flock or replying to a `<cross_session_message>` with `from_machine` set to a remote machine.
3. **Universal Hierarchical Addressing (`<owner>/<flock>[/<machineId>]`)**:
   - `<owner>` — All machines owned by `<owner>` (e.g. `erjadi`).
   - `<owner>/personal` — Personal machines (`personal` scope; note: `private` is retired).
   - `<owner>/work` — Work machines (`work` scope).
   - `<owner>/<custom-flock>` — Shared collaborator flock (e.g. `erjadi/studio-team`).
   - `<owner>/<flock>/<machineId>` — Specific machine or single-PC time-bound guest pass (e.g. `erjadi/work/CLOUD-DEV-VM`).
4. **4 Anti-Leakage Hard Walls (`Shared machines ≠ shared threads`)**:
   - Joining an external/collaborator flock or issuing a guest pass never exposes existing local threads. External callers can only access threads explicitly opted in via `share_thread` (with `approved-snapshot` transcript redaction) or new threads created for that `boundFlockId`.
