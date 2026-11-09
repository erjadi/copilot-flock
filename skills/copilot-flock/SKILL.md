---
name: copilot-flock
description: Cross-machine ONLY: discover and message GitHub Copilot threads, manage flocks (<owner>/<flock>[/<machineId>]), generate pasteable invites, and share threads across "the flock" via the copilot-flock Azure SignalR + Service Bus platform. Keep using native list_sessions_and_chats and send_session_message for threads on the same computer.
---

# Copilot Flock Cross-Machine Platform (`copilot-flock`)

Use this skill whenever the user wants to discover, message, coordinate with, invite, or share threads across **the flock** (`<owner>/<flock>[/<machineId>]`).

## Core Rules

**Architecture boundary:** first inspect local configuration. Fresh Zero-Broker
setup uses a signed Pages roster and opaque peer IDs; existing legacy
configurations and broker invites are not migrated. The remaining broad tools
and bootstrap examples below describe the **legacy profile only**.
For Zero-Broker use its restricted installed MCP definitions: selected existing
Desktop sessions, explicit root-session grants and approved summary snapshots.
Verified same-owner enrollment permits metadata discovery, not arbitrary
delegate tasks or unrestricted live transcripts. Never use legacy spawning,
headless permission overrides, topology, transfers, locks or fleet updates as a
fallback. Vouchers remain provisional until owner approval; verify fingerprints
independently. Preserve UNKNOWN outcomes without blind retransmission.
The separate LAN trial has its own entry point/state and is not an Azure fallback.

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
   - Trusted owner-root and owner-scope (`personal` / `work`) views intentionally discover the owner's session metadata without `share_thread`. `sharedCount: 0` means no external thread grants, not that same-owner discovery is denied. Discovery alone is not an execution or unrestricted transcript grant. Never apply this owner exception to collaborator or guest flocks.
