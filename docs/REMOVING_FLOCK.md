# Removing Copilot Flock

Tell Copilot: **"Remove Copilot Flock from this PC and leave all its flocks.
Preserve my conversations and repositories."** Copilot executes the operation;
the user does not need to type commands.

## Agent entrypoints

The agent can run `node flock.mjs uninstall`, `node flock.mjs unenroll --traceless`
or `node flock.mjs flock unenroll --traceless`. The legacy `bridge.mjs` entrypoint
supports the same forms. The MCP tool is `unenroll_flock` with `traceless: true`.
It returns the result before its own MCP process exits on successful cleanup.

The current authenticated leave transport is the explicitly configured legacy
broker, using the new signed `/api/v3/flocks/leave-plan` and `/flocks/leave`
routes. An older deployed broker without those routes will return an explicit
pending/failure result. This source change does not deploy or restart brokers.
No automatic Azure management privilege acquisition is attempted.

## Membership acknowledgment and recovery

The device signs its flock, device and machine selectors, request ID and
timestamp with its enrolled Ed25519 key. The broker discovers remote
memberships, removes only the matching member, durably records the pending
leave, and acknowledges only after targeted subscription deletion and
SignalR eviction succeed. Supplying several selectors means **all** must match.
Device-specific removal does not invalidate another device's vouchers.

A reused legacy machine subscription belonging to another device is not
deleted. Missing management permission, offline transport or failed eviction
is pending, not full removal. Send/Listen SAS are not treated as Manage
credentials. The broker removes the matching legacy registry entry only after
the device has no remaining active flock memberships. Leave receipts remain
on the broker as recovery/audit evidence.

Before removing runtime credentials, the local uninstaller persists leave
request IDs and acknowledgments. Retry skips confirmed leaves and signs a fresh
timestamp for unconfirmed requests. If remote cleanup cannot be confirmed, the
installation, credentials and recovery journal are retained. The current
implementation retains the runtime rather than minimizing recovery material.

Only explicit user approval permits local-only removal. The agent then adds
`--local-only --approve-local-only`; this does **not** acknowledge remote leave
and never reports `fullyRemoved: true` for unconfirmed memberships.

## Owned artifacts only

The uninstaller examines the exact dedicated `flock` and `signalr-bridge`
runtime directories under the selected Copilot home. It rejects symlinks,
junctions, filesystem escapes, shared home roots and source checkouts.
It unlinks enumerated runtime files individually, never recursively deletes a
runtime root, and retains unknown files.

MCP entries are removed only when their exact canonical/legacy server name,
Node command and two arguments point to an installed runtime script in `mcp`
mode. Other servers and settings are preserved. Locations checked are
Copilot's `mcp-config.json`, the Desktop app data directory's `mcp-config.json`,
VS Code's user `mcp.json`, and the user's `.vscode/mcp.json`. These are strict
JSON edits with validation, concurrent-change checks and atomic replacement.
JSON-with-comments or otherwise malformed configuration is retained with an
explicit error, not rewritten or guessed.

New skill and startup artifact installations record content hashes.
Cleanup removes matching known artifacts, not arbitrary `flock*` paths.
Modified or unproven artifacts are retained and reported. Legacy skills without
a recorded content hash are retained rather than guessed from their titles.
Exact legacy launcher recognition is available; unrecognized variants remain.
This installer does not install custom-agent files.

Windows Startup VBS, Linux systemd-user units and macOS LaunchAgents require
ownership evidence before removal. Known Windows Scheduled Task names are
inspected, their single Node daemon action must match an exact runtime script,
and their actions are re-read before unregistering the exact task.
Service-stop/disable failures retain the installation. OS cleanup behavior is
covered using synthetic paths and injected process/service fixtures; this is
not a claim of live uninstall validation on every OS.

New daemons persist PID, executable/command and process creation identity.
Cleanup rechecks the live identity before signalling the specific PID. A stale
PID never authorizes terminating an unrelated process. Legacy running daemons
without a creation-identity pin require coordination and are retained.
Other runtime-referencing Node processes are discovered but not terminated
without a creation-identity proof. They retain the installation and require
their host to close them before retrying cleanup.

## Meaning of traceless

The intended scope is owned installation artifacts and active memberships.
Local Copilot conversations, chats, `session-state`, `data.db`, repositories,
worktrees, source evidence and backups are preserved. OS audit logs, transcripts
and external backups cannot be erased by runtime uninstall. Returned `removed`,
`retained`, `pending`, `ok` and `fullyRemoved` fields must be interpreted together;
the current cleanup does not establish that every historical or live MCP
process trace is gone.

## 3.4 protocol preparation, not a release claim

`flock-protocol.mjs` exercises device-bound signed Join Codes, X25519 sealed
Welcome Tickets, independently pinned owner fingerprints, short MemberCerts,
HKDF-SHA256 per-message keys with fresh 32-byte OS randomness, zero-IV AES-GCM
under those derived keys, canonical AAD and mandatory Ed25519 signatures.
The self-box is not proof of remote possession of an X25519 private key.
The randomness assumption excludes undetected live-memory VM RNG cloning.

Durable receive admission quarantines interrupted dispatch rather than
automatically repeating effects. A leftover lock after a process crash requires
operator reconciliation. Epoch rotation is restricted to the designated owner,
sealed to retained recipients, and persists epoch/hash anti-rollback state.
Partitioned receivers unaware of a kick may accept until certificate expiry;
there is no distributed sequencer or immediate-global-revocation guarantee.
Renewal remains owner-mediated.

These are isolated library fixtures, **not wired active runtime behavior**.
Azure token issuance/audience scoping, subscription-only SAS isolation,
broker-free owner-mediated leave/kick, default two-service deployment and
owner-mediated renewal still need integration. Positive and negative live
Azure tests, immutable candidate review and the required release vote remain
unrun gates. Existing installations are untouched and version metadata remains
3.3.1 until a complete release candidate is prepared.
