# Copilot Flock 3.6.1 candidate

This is a local build candidate, not a published release or deployed update.
Its source lineage is the complete 3.6 Milestone 4 commit
`f50df0e4b2c26dd8915c92088c856d3b0039946c`, followed by the presence fix
`e240ec990b5dc86c5f9115d905e287a918592a9b`. It does not derive from the obsolete
3.5.1 candidate or include unrelated in-progress viewer work.

## Sign-in popups and automatic startup

Background GitHub credential discovery retains environment-token, GitHub CLI,
then stored Git-credential precedence. Git disables terminal, GCM GUI/interactive,
and askpass prompting; GitHub CLI prompting is disabled. Authentication remains
local. Token-local configurations bypass credential discovery entirely, including
registration and v3 callers. Missing credentials produce a fixed diagnostic and
defer helper retries for 60 seconds per configuration; supplying an environment
token takes effect immediately. No token or helper error output is logged.
Intentional enrollment/sign-in is not replaced with an automatic interactive login.

Windows credential helpers execute under a kill-on-close Job Object. A fixed
Node worker waits for assignment before receiving its helper command, so no Git
or GCM child runs outside containment. Job closure terminates remaining
descendants on success, failure, timeout, or wrapper termination. Failure to
establish containment refuses helper execution. POSIX helpers use a dedicated
process group that is cleaned after each invocation. No process-name scanning,
unverified PID-tree termination, or App/MCP termination is used. Each helper has
an 8-second inner execution timeout (`timeoutMs = 8000`) plus a 12-second
Windows PowerShell/Job-Object startup allowance (`20s` per helper on Windows;
`9s` on POSIX). Because `resolveLocalGitHubToken` is synchronous and tries
`gh auth token` then `git credential fill`, a cold missing-auth lookup on a
legacy non-token-local daemon is bounded at up to ~16 seconds of helper wait
(and up to 40 seconds worst-case outer wrapper ceiling on Windows, or 18 seconds
on POSIX), which still blocks the event loop and exceeds a single 2.2s-2.5s
discovery wait or 8s RPC window on that initial cold miss before the 60-second
missing-auth cooldown and 15-second `/api/members` negative cache suppress
repeat probes.

Ask Copilot to **stop the Flock daemon** to persist an autostart opt-out, even
when no daemon is running. Automatic MCP startup, later communication calls, and
OS persistence launches respect it. Ask Copilot to **start the daemon explicitly**
to clear that opt-out. `stopLocalDaemon` / `stop-daemon` writes
`daemon-control.json` (`autostart: false`) first and returns a structured
outcome (`{ stopped, status, pid, reason, autostart }`): `stopped: true` is
reported only when a creation-pinned daemon is verified terminated by an
independent postcondition check, while absent/stale PIDs report
`status: "not_running"`, reused/unrelated PIDs report `status: "unowned_pid"`
without signalling them, and unverified guard outcomes report
`status: "unknown"`, all with `stopped: false`. Unproven running daemons fail
closed while retaining the opt-out marker. For contributor automation these
operations are `stop-daemon` and `start-daemon`; the existing `start` alias still
means remote session creation, not daemon startup.

## False-offline presence

Unscoped sender verification uses active local pinned keys before bootstrap
lookups; failed/empty bootstrap lookups have a bounded negative cache. Explicit
flock selectors reach discovery, status and presence probes. Missing broadcast
responses receive at most six targeted confirmations, using only admissible
key-consistent peers observed within 90 seconds. Passive pings do not perform OS
process scans or bypass the 15-second dead-WebSocket-port cache.

Authorized recent peer evidence can update last-seen/version independently of
stale roster timestamps. Cached evidence is not a new successful ping, expired
peers remain offline, and reconnect grace remains bounded. Cross-flock, revoked,
expired, tombstoned, mismatched-key, wrong-scope and excessive-future evidence is
not promoted. Empty collaborator rosters never authorize arbitrary responders;
unreadable presence authority fails explicitly rather than admitting a responder.
These changes do not share sessions or broaden enrollment.

## Qualification and publication

Regenerate entrypoint parity, the embedded entrypoint SHA, and the external
manifest using `hashRuntimeModule` and `computeRuntimeManifest` from
`flock-lifecycle.mjs`. Build/package only verified source and the viewer production
output; never include installed homes, identities, credentials, queues or logs.
Runtime versions and package metadata are 3.6.1; older-version test fixtures
remain intentionally available for compatibility/rollback coverage.

Publication requires the complete repository suite (including the mandatory
`test/flock.test.mjs` run), dependency/import closure and entrypoint parity,
viewer qualification, independent exact-candidate platform/live Azure isolation
and canary evidence, and the mandatory all-online cryptographic ACCEPT vote.
Historical 3.6 approvals or earlier candidate receipts do not qualify this tree.
No live probe, vote, install, daemon restart, cloud/website deployment, merge,
tag or publication is authorized by building this candidate.
