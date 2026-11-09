---
name: copilot-flock
description: Cross-machine ONLY: discover and message GitHub Copilot threads, manage flocks (<owner>/<flock>[/<machineId>]), generate pasteable invites, and share threads across "the flock" via the copilot-flock Azure SignalR + Service Bus platform. Keep using native list_sessions_and_chats and send_session_message for threads on the same computer.
---

# Copilot Flock Cross-Machine Platform (`copilot-flock`)

Use this skill whenever the user wants to discover, message, coordinate with, invite, or share threads across **the flock** (`<owner>/<flock>[/<machineId>]`).

## Core Rules

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
