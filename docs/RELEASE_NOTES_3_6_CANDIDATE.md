# Copilot Flock 3.6 candidate

This repository state is a **candidate**, not a published release or deployed
fleet update. Milestone 4 hardens the reviewed Milestones 1-3 baseline without
performing cloud mutation, remote-machine update, deployment, or a release vote.

## Release-hardening changes

- Runtime updates persist an update/correlation ID and explicit
  `staged -> installed -> activated -> verified` phases, or terminal
  `failed` / `rolled_back` state with bounded credential-redacted errors.
  Activation launcher failure restores the previous installed runtime when its
  verified artifact closure is available.
- Unattended Git update preflight disables terminal prompts, credential-manager
  interaction, askpass and editor IPC helpers. Authentication failure is typed
  and does not fall back to interactive or embedded credentials. Signed
  release/bundle distribution remains the preferred product direction.
- Windows daemon recognition parses quoted command lines deterministically and
  still requires the exact executable, runtime realpath, daemon subcommand,
  PID, creation time, and installation ownership proof.
- `SupportCapabilityV1` is a short-lived, signed, single-use, support-device
  bound capability. Its isolated `.data/support-quarantine` mailbox accepts
  only bounded text and the documented inert diagnostic fields. It has replay,
  expiry, revocation, rate, quota, audit-chain, retention, and maintainer
  authorization controls. A ticket holder is not a GitHub-verified member and
  cannot promote itself; enrollment remains the normal independently verified
  flow.
- Broker-free operation query/cancel routing is available with exact
  flock/peer/session authorization and JWT/token redaction.
- Schema 36 pings advertise typed capabilities. Incompatible peers receive
  explicit upgrade remediation; there is no security downgrade.
- Legacy authoritative tombstones suppress live-presence reconnect
  classification before a fresh roster fetch.
- Public status/roster projections default to bounded pages and expose explicit
  full detail. Viewer shims reject obsolete `private` scope input instead of
  translating it.
- Zero-dependency release review requires the root repository test suite,
  entrypoint byte parity, dependency closure, and runtime manifest verification.
  Viewer build/UI tests remain a separate qualification gate with viewer
  dependencies installed.

## Milestone 4 conformance corrections

- The existing bootstrap service exposes an isolated `/api/v3/support/`
  mailbox: `tickets/issue`, `tickets/revoke`, `reports`, `attempts`,
  `attempts/read`, `attempts/reply`, and `attempts/close` (POST JSON).
  Maintainer requests use the enrolled owner's signed device HTTP identity;
  the broker registers an owner-signed capability without receiving its
  private key. Newcomer reports use only the ticket and support-only device
  signature. These routes never enter GitHub credential, membership, SignalR,
  Service Bus, ordinary inbox, or autopilot handlers.
- Ask Copilot on the newcomer PC to create its support-only key. Send that
  public key to the independently verified maintainer, who can ask Copilot to
  issue a support ticket. On the newcomer PC, ask Copilot to submit the report
  using that ticket and the explicitly trusted maintainer bootstrap URL.
  The maintainer can ask Copilot to list, read, reply to, or close the attempt.
  No step enrolls or promotes the newcomer.
- Support HTTP bodies are limited to 16 KiB, report redemption is single-use,
  request quotas apply by hashed source IP and ticket, and signed maintainer
  requests are replay-protected. Both client and server reject credential-like
  text and absolute paths. Traceless removal deletes only recognized owned
  support state/key artifacts, retaining unrelated files.
- MCP status, flock, member, and diagnostic calls honor `detail`, `cursor`,
  and `limit`. Summary mode omits duplicate raw roster sources; `detail=full`
  intentionally restores full projected data. Pagination metadata identifies
  the next cursor.
- Broker-free message admission persists the exact peer, flock, origin session,
  target session, operation/correlation IDs, and timeout-cancellation policy
  before dispatch. Query/cancel checks the same requester identity.
- The update launcher runs a dedicated activator rather than a general
  installer. Successful process creation alone is not verification. The
  activator checks daemon identity/digest, runtime imports/closure, and self-test,
  persists verification evidence, and rolls back a failed activation when safe.
  If the caller's bounded wait expires, activation remains explicitly pending
  under the same update ID rather than racing an in-flight activator.
- Windows ownership checks accept bare `node`/`node.exe` launch syntax against
  the observed executable, without relaxing script or daemon argument checks.
  All recovery shims restore the operations and support modules in dependency
  order. Authoritative registry tombstones also suppress collaborator presence
  before broker refresh.

### Resident updates and pre-enrollment MCP

Resident `self_update` now returns an `activating` acknowledgment containing
the update/correlation ID, previous PID, and target manifest digest before
launching its activator. The detached, session-safe activator is launched only
after the SignalR response POST completes; it must not block the response while
stopping that response's own daemon. An unflushed response or failed launch is
persisted explicitly, and existing activation intent blocks conflicting updates.
Fleet polling requires the exact requested update ID, terminal verified phase,
replacement PID, target digest and verified imports/closure before success.
Failed or rolled-back activation is not a successful fleet update. Local fleet
updates use the same noninteractive update implementation, not a second Git path.

MCP stdio starts passively without GitHub/Azure CLI discovery, SignalR keys,
or a token-local credential vault. Unconfigured sessions can initialize, list
tools, inspect self-info, create a support-only key, submit a support report,
attempt explicit enrollment/removal or safe Join Code generation, and request
explicitly passive status/diagnostics. Other tools return
`UNCONFIGURED_TRANSPORT` or `TOKEN_LOCAL_CREDENTIALS_UNAVAILABLE` from the tool
call rather than terminating stdio startup. Successful enrollment reloads the
same MCP process's runtime configuration; caller code/module digest snapshots
still describe the actually loaded generation.

Qualification includes actual subprocess tests: empty-home and missing-vault
stdio clients submit support to a local TLS bootstrap service, reject ordinary
remote tools, and continue after real enrollment without restarting stdio.
A child resident daemon uses real WebSocket/HTTPS RPC, a disposable Git origin,
and the real activator to check reply ordering, PID replacement, and terminal
verification/failure. Test TLS certificates use `openssl` (available with Git
on the Windows qualification host); no live Azure service or fleet is used.

### Final release-boundary hardening

Release candidate execution is a protected owner-only RPC, including on shared
collaborator/guest flocks. It requires verified same-user owner authorization;
file-transfer or unrestricted-collaborator settings cannot grant it. Review
accepts validated branch names only (never `refs/*`), fetches explicitly from
`refs/heads/`, and disables interactive Git credential helpers. Release voting
uses an authorized owner flock selector and a minimum 1,620-second RPC deadline,
with headroom beyond the configurable 1,500-second candidate test budget.
An omitted selector means the owner root across personal/work; targets must
be active same-owner machines, never collaborators or guests. Explicit scoped
selectors honor that flock's allowed scopes.

Cross-user presence pings omit host usernames/WebSocket ports; unscoped pings
contain no sessions. Host-wide project, lock and diagnostic inventories are
denied to cross-user or restricted-flock callers. The legacy master-credential
bootstrap endpoint is now platform-maintainer-only: repository write access or
general allowlisting does not authorize master transport keys. GitHub-token
queue access requires authoritative active machine ownership (or maintainer
authority), and non-maintainer member lists contain shared peers only.

MCP still loads configuration passively, but configured non-passive MCP hosts
and successful same-process enrollment start the daemon. Explicit passive mode
never starts it. Desktop session creation with `allowAll=false` no longer
requests auto-approval or autopilot. Installation stops only the creation-pinned
owned daemon, never unverified PIDs from network replies. Failed update reply
flush/launcher startup restores the available rollback closure and clears
unlaunched activation intent; ambiguous/failed recovery remains explicit.
Support audit retention removes only contiguous prefixes, preserving hash-chain
integrity across backward clock changes. Caller runtime drift detection covers
the support module as part of the installed companion closure.

### Final qualification and interop corrections

The zero-dependency candidate runner discovers only `test/*.test.mjs`, excluding
`*.live.test.mjs`. It does not select dependency-bearing `viewer/test/` files;
root viewer roster/TODO tests remain included. Multiple candidate files use
Node's normal per-file process isolation with concurrency capped at two on
Windows or four elsewhere and
the host's available parallelism. Only a single-file compatibility fixture can
use `--test-isolation=none`. Qualification tests copy the real root test module
closure into a fixture without `node_modules` and smoke-test its imports.

Trusted local administrative creation paths explicitly request allow-all and
autopilot for coordinator/tracker sessions. The default remains false for
remote/non-owner creation. Queue acknowledgments include the local machine ID;
GitHub-token enqueue requires a shared authorized peer and cannot target
arbitrary or private machines. Isolated HTTP roundtrip tests cover enqueue,
peek-drain, target-scoped acknowledgment and forbidden targets.

## Credential-safe diagnostics and 3.5 recovery

WebSocket connection failures retain only origin/path and typed status/code,
never URL query, fragment, userinfo, or untrusted upgrade response bodies.
The shared diagnostic redactor covers `access_token`, `token`, `sig` and
`signature` query values, including opaque local WebSocket tokens. Error
formatting, daemon logs/state, operation errors, offline replay and RPC replies
use that redactor. Existing historical logs are not silently erased.

3.6 bootstrap requests advertise `X-Flock-Protocol-Version: 36` outside signed
payloads. Enrollment/sync responses to absent/older protocol headers omit
non-built-in owner-tier shared/guest entries that 3.5 rejects; the broker retains
their owner devices/keys internally. 3.6 responses retain complete records.

For an explicitly requested legacy downgrade, ask Copilot to plan recovery with
a separately supplied, verified 3.5 runtime directory and pinned manifest digest.
The `downgrade-3-5` CLI defaults to a plan; application requires explicit
`--apply`, `--source`, `--manifest-digest`, and `--recovery-digest`.
`downgrade-artifacts.json` in that source binds `runtimeManifestDigest` and an
`artifacts` array. Each entry supplies `kind` (`startup` or `mcp`), a basename
`source`, its SHA-256, and (for startup) a platform persistence-path `index`.
The MCP source contains only the reviewed server entry, pointing at the
installed runtime; unrelated current MCP entries are preserved. Independently
verify both supplied digests before applying, including startup executable intent.

Only a stopped, owned legacy installation is eligible. Vault-only token-local
credentials, active operations/leases, and pending execution/activation are
explicit aborts. Shared/guest owner labels, including their cached owner-member
role labels, are normalized to collaborator with explicit opt-in; membership epochs, revocations, expiry, snapshots and
bindings survive. Identity, registry epoch/revision/tombstone floors, offline
dedup and inbox/outbox bytes are never rewound. Replaced artifacts, 3.6-only
state and support data are retained in a timestamped owner-only downgrade
archive, which can contain sensitive local recovery material.

Recovery verifies the supplied 3.5 import/artifact closure and restores the
supplied startup/MCP closure, but does not activate or deploy it. Broker-free
downgrade is intentionally unsupported. Compatibility tests exercise 3.5-style
authority/epoch checks; actual legacy fleet activation and the provenance of a
user-supplied recovery bundle remain independent qualification responsibilities.

## Qualification still required

The configured Copilot root is canonicalized once as an explicit trust boundary,
including the default root-level `.copilot` junction. Its live physical binding
is rechecked and cannot retarget during a process. Physical ancestors and all
descendants still use strict no-link checks; unsafe root/home/temp/repository
targets, chained links and world/shared-group-writable or non-owned POSIX roots are rejected. Logical
and physical runtime aliases remain recognizable for legacy ownership/MCP
cleanup, while new paths and artifact keys use the canonical physical root.
POSIX UPG roots such as owned `0775` directories are accepted only when
`gid == uid`; world-write and foreign-owned root symlinks are refused.
Voter-isolated homes explicitly request `0700`, independent of a `0002` umask.
Default-home reads re-resolve the logical `.copilot` alias each time, and
the mutation selector `all` has the same wildcard semantics as `*`.
An explicit empty `COPILOT_CLI_PATH` disables all automatic CLI discovery,
including cached results and absolute POSIX fallbacks. Candidate review sets
that disable value; CLI-resolution fixtures can still supply explicit binaries.
Failed-update tests clean only rollback directories tied to their own generated
update IDs, without removing product recovery evidence.
On POSIX qualification hosts without `pwsh`, only the two PowerShell setup
entrypoint tests are skipped. Windows PowerShell remains mandatory, as does
POSIX bash coverage; permission/timeouts or a broken installed shell are failures.
TLS WebSocket connections omit SNI for IP literals (required by Node 26) while
retaining DNS SNI. Windows TLS qualification resolves OpenSSL from PATH, the
discovered Git installation (including `usr`, `clangarm64` and `mingw64` binaries),
then standard Program Files/LocalAppData Git locations, with an explicit
failure if unavailable. An unsafe legacy checkout is never deleted to make
compatibility synchronization succeed: its failure is returned and retained as
an update-journal warning, and primary verification does not imply legacy
caller convergence.
Both local self-update and installation return a nonfatal `legacySync`
status/code/reason rather than swallowing compatibility-sync failures.

Windows process inspection returns early only for an ESRCH liveness probe,
retries a CIM ETIMEDOUT once within the existing per-attempt bound, and never
treats permission/tool failures as proof of exit. Windows candidate concurrency
is capped at two. A shared same-owner owner-role target guard protects fleet
updates, reprovision (including offline enqueue), active diagnostics and
new-session broadcasts. Passive collaborator diagnostics use public presence
only; ordinary informational broadcasts retain their existing policy.

1. Run the complete repository suite on the exact candidate commit.
2. Verify disposable Azure positive/negative JWT, SAS, audience, and scope
   isolation gates.
3. Canary the exact artifacts while checking resident daemon and caller MCP
   digests independently.
4. Run the required flock-wide cryptographic release vote.

No signed release artifact distribution redesign was added in this milestone.
The safe noninteractive preflight fails clearly when an authorized artifact or
repository source is unavailable.
