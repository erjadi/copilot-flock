# Broker-free 3.4.0

This source does not by itself establish a released or production-validated
deployment. Existing installations are not migrated. Exact-commit live Azure
isolation tests, immutable implementation review and the all-online-member
ACCEPT release vote are required gates. Confirm the published tag and its
evidence; preparing or reviewing source does not authorize deployment.

## Copilot-led setup and joining

Tell Copilot: **"Set up a new broker-free Flock. Confirm my subscription,
region, resource group, personal/work scope and costs before provisioning."**
The [managed setup guide](./BOOTSTRAP_NEW_FLOCK_BYO_AZURE.md) describes the
two-service default. Each flock has one designated local rotation owner.
The owner's GitHub label is informational, not cryptographic authority.

Tell the invitee's Copilot: **"Create a Join Code for owner/team on this PC."**
The invitee generates per-flock Ed25519 and X25519 identities locally and
signs a ten-minute Join Code binding both public keys, machine, scope and
intended flock. Private keys remain local. The owner independently verifies
the device fingerprint and intended identity/access policy before approval.
The owner approves explicit session IDs, role and finite membership expiry,
creates only the intended peer's subscription, and returns an owner-signed, X25519-sealed Welcome
Ticket. The recipient independently obtains and pins the owner fingerprint
before accepting. A self-box is not remote proof of X25519 private-key possession.
There is no transferable bearer invitation or first-redemption race ledger.

Agent entrypoints (Copilot executes them, not the human):

| Action | CLI | MCP |
| --- | --- | --- |
| Generate Join Code | `join-request --flock owner/team --scope personal` | `join_request` |
| Approve | `approve-join --join-code-file <file> --flock owner/team --device-fingerprint <verified-pin> --membership-expires-at <epoch-ms> --role guest --session-ids <comma-separated-ids>` | `approve_join` |
| Accept | `accept-welcome --welcome-file <file> --owner-fingerprint <independent-pin>` | `accept_welcome` |
| Renew | `renew-membership --flock owner/team` | `renew_membership` |
| List durable roster (no live pings) | `registry --flock owner/team` | `list_flock_members` |
| Remove local installation | `uninstall` or `unenroll --traceless` | `unenroll_flock` |

See [`docs/FLOCK_MEMBERSHIP_REGISTRY.md`](./FLOCK_MEMBERSHIP_REGISTRY.md) for the
durable per-flock membership registry architecture (owner-signed roster
snapshots and deltas, epoch/hash anti-rollback, removal tombstones, and strict
separation from live presence, 24h MemberCert validity, and shared-thread
visibility).

When multiple memberships exist, preserve incoming `from_flock` explicitly on
replies and pass an explicit `flock` selector (`--flock` or MCP `flock`) for
discovery, wildcard, and broadcast operations. An explicit `flock` selector is
always validated first against local active enrollment, non-expired certificate
and transport authority, action/session scope, and target membership; an
invalid, departed, expired, or unauthorized explicit `flock` is rejected
immediately without replacing it via inference. When `flock` is omitted and an
explicit single target (`to_machine`, or single-machine `list_remote_sessions`
`machine`) is provided, the runtime resolves the route automatically **only**
if **exactly one** active, non-expired, authorized enrolled flock contains that
target machine with fresh, cryptographically valid, non-revoked `MemberCert`
membership evidence. If two or more enrolled flocks can reach the target
machine, dispatch fails closed with an actionable ambiguity error listing the
eligible `owner/flock` choices without sending any message. If zero authorized
routes reach the target, or membership/transport evidence is stale, expired, or
revoked, dispatch fails closed clearly without broadcasting or falling back. A
legacy installation requires a separately configured Copilot home for
broker-free enrollment; no silent replacement or hosted-broker fallback occurs.
Canonical and legacy script entrypoints use the same protocol selection.

## Active transport and authorization

The shared Serverless SignalR hub is `copilotbridge`; the Standard Service Bus
topic is `copilot-bridge-offline`. Group traffic is encrypted, not isolated by
separate v3 broker hubs. Every envelope derives its AES-256-GCM key using
HKDF-SHA256 from the epoch key, fresh 32-byte OS randomness and a
domain-separated canonical header. The IV is zero only under this derived
per-message key. Canonical AAD and mandatory sender Ed25519 signatures bind
the certificate, flock, scope, epoch, key ID, salt and message identity.
Independent randomness is assumed; undetected live-memory VM RNG cloning
is outside that guarantee.

Owner-signed MemberCerts and scoped credentials last at most 24 hours and
never outlive membership. SignalR client and REST-send JWT audiences are
distinct. Send-only topic SAS and Listen-only own-subscription SAS do not
grant Manage. Guests receive no transport master keys, owner signing keys
or management credentials. The owner retains management authority locally.
Provider enforcement of these exact scopes is an **unestablished live gate**,
not established by token parsing or mocks. A diagnostic run with required
negative probes removed does not satisfy this gate. In particular, denial of
REST sends to another hub and another user remains required until an explicit
architecture/contract decision changes that boundary; a wrong-credential-type
probe is additional coverage, not a substitute. The disposable live harness
records every negative operation's method, HTTP status and outcome, along with
raw source-file SHA-256 hashes, without logging credentials or response bodies.
Non-401/403 statuses, including 404, and network failures never prove denial.
SignalR REST uses an explicit `Bearer` authorization scheme; Service Bus
retains its separate SAS scheme with a lowercase signed resource URI.
Subscription creation uses the provider-default description; each published
message independently bounds its queue TTL by the message and transport expiry.
The full peer fingerprint remains in the signed certificate/envelope, not
truncated to the transport subscription name. Subscription names are `sub-`
plus 46 hex characters of a domain-separated SHA-256 over the **entire**
canonical peer fingerprint (50 characters, Azure's subscription-name limit).
This uses a 184-bit hash output rather than aliasing peers by
a shared fingerprint prefix. Known mapped-name collisions
with local retained or pending memberships are rejected before provisioning.

The active broker-free RPC surface supports ping, owner-signed collaborator
roster snapshots (`list_roster`; forbidden to guests and omitting session IDs),
certificate-filtered session listings, approved-snapshot transcript access,
guarded messaging to explicitly shared sessions, renewal and leave. `flock_status`
and `list_flocks` keep observed live presence (`onlineMachines`) distinct from
authenticated roster membership (`knownMembers`, `offlineMembers`, `roster`
`source`, `freshness`, and explicit refresh status) without presenting missing
heartbeats as member removal. Local sharing and signed session IDs both apply;
even owner certificates do not expose all local threads by default. Cross-flock
thread bindings are enforced. Snapshots and returned replies use credential
redaction; the user must still approve a secret-free snapshot rather than
relying on redaction alone.

Legacy remote session creation, delegation, file operations and broader
administrative RPC are not enabled in this mode. Unsupported calls fail
explicitly; they never fall through to the broker or legacy dispatcher.
The broker-free installer configures the runtime, MCP, its removal/messaging
skill and boot persistence; it does not automatically create privileged
coordinator sessions or install the legacy topology skill. Strict Linux
installation requires previously approved user lingering.

Queue persistence precedes SignalR delivery. Durable replay admission records
quarantine before effects, checks authorization before and after awaits,
and does not automatically repeat ambiguous dispatch. A crashed receive lock
needs reconciliation. Credential/certificate expiry and epoch rotation can
make old queued work inadmissible; offline delivery is not unconditional.
Payload plaintext is capped at 128 KiB and encoded transport at 240 KiB.

Atomic JSON persistence fsyncs a same-directory staging file before replacing
the destination. Replacement sharing violations (`EPERM`, `EACCES`, `EBUSY`)
receive at most eight retries with less than one second of total backoff.
Each attempt rechecks path safety and the original destination bytes; the
destination is never unlinked to bypass a lock. Persistent denial and other
filesystem errors fail explicitly. Cleanup also rejects junction/path swaps,
retaining staged evidence rather than deleting through an unsafe path.

## Renewal, removal and availability

Renewal is owner-mediated and preserves device keys, role, allowed sessions
and original membership expiry. The daemon attempts renewal before short
credentials expire. After expiry or a missed rotation, ask Copilot to generate
a fresh Join Code with `--renew-flock owner/team` and obtain explicit owner
approval with `--renew`; accepting that Welcome requires the independent pin.

Only the designated owner rotates epoch keys. Durable epoch/hash anchors
reject rollback and conflicting rotations. Kick/leave persists a targeted
transition, removes only the intended subscription, advances the accepted
epoch and seals the new group key to retained recipients. Completion receipts
are owner-signed. An offline/denied/partially completed owner operation remains
pending and retries with the stable operation ID; Send/Listen is never treated
as Manage. Supplying multiple member selectors means all must match.

Receivers partitioned from a kick may accept old traffic until short
certificate expiry. There is no distributed sequencer and no
immediate-global-revocation promise. Owner availability is required for
renewal and administrative completion. Removing the owner ends that renewal
service without delegating its authority or removing unrelated peers.

Uninstall leaves every enrolled flock before removing owned local artifacts.
Pending leaves retain the runtime/credentials/journal for recovery, not a
minimal recovery bundle. Unaccepted Join Codes can correspond to unconfirmed
owner approvals and prevent a full-removal claim until reconciled.
Modified/unmanifested runtime scripts also retain the installation: each
entrypoint/module requires its individual recorded ownership hash. A
same-user process that cannot be inspected is retained, not silently excluded
from the runtime-client census.
See [removal scope and retained-artifact rules](./REMOVING_FLOCK.md).

## Required live Azure gate

`npm test` covers isolated synthetic homes, injected transports/processes and
the actual dispatcher. It does not execute `test/flock-azure.live.test.mjs`.
Syntax checks and synthetic positive/negative cases do not prove Azure
accepts or rejects the issued credentials.

Only after explicit permission for a disposable deployment may Copilot run
`npm run test:azure-live`. It requires:

- `COPILOT_FLOCK_LIVE_AZURE_APPROVED=1`.
- `COPILOT_FLOCK_LIVE_AZURE_CONFIG`: a private JSON file with `disposable: true`,
  `connectionString`, `manageConnectionString`, `sendConnectionString` and
  `listenConnectionString`; never publish this file or its contents.
- Explicit `COPILOT_FLOCK_LIVE_SIGNALR_ENDPOINT` and
  `COPILOT_FLOCK_LIVE_SERVICEBUS_ENDPOINT` pins matching that disposable setup.

The harness creates two fresh peer subscriptions and checks positive
WebSocket/REST/Send/own-subscription Listen, and negative other-hub, wrong REST
audience, expired tokens, other-subscription Listen and unauthorized
Send/Listen/Manage operations. Only HTTP 401/403 satisfies denial cases;
network failures do not count as isolation. Cleanup attempts deletion of
both exact fixture subscriptions and reports failures. Never point it at
enrolled/production resources, infer permission from environment flags, or
mark an unexecuted gate passed.

The distinct wrong-hub fixture is `fixture_forbidden`, shared by the REST and
WebSocket probes. [Azure's documented hub-name syntax](https://learn.microsoft.com/en-us/azure/azure-signalr/swagger/signalr-data-plane-rest-v1)
requires an alphabetic first character and only alphanumeric characters or
underscores; a hyphenated fixture can fail input validation instead of proving
authorization isolation. The harness additionally connects to the distinct
hub using a token minted for that exact hub and confirms REST delivery using
its matching REST token. Both positive controls must pass; they do not replace
any original positive or negative probe, or permit HTTP 400 as a denial.

SignalR startup observes both the HTTP upgrade and JSON handshake from the
start. Rejected upgrades, early closes and handshake timeouts reject the
caller explicitly, close the socket and clear the handshake timer; they do not
become an unhandled background rejection or successful connection. A wrong-hub
HTTP 400 is reported as a request failure, not silently counted as an
authorization denial. Negative probe results alone are insufficient when the
positive delivery checks or the overall test still fail.
Pre-upgrade EOF and timeout reject the upgrade promise; a close event cannot
replace a parsed HTTP rejection with an unrelated JSON-handshake error.
Credential-redacted connection errors preserve a structured HTTP status.
The raw client sends its masked WebSocket Close frame before marking itself
closed. Repeated close calls are idempotent; bounded TCP end/destroy timers
still clean up an unresponsive peer.
The live harness records that status and each positive delivery milestone,
continues independent delivery checks after a failed wrong-hub probe, and
still requires the original HTTP 401/403 boundary for an aggregate pass.

## Release and existing-client upgrades

The full offline suite requires Node.js 22.5 or newer, Bash, and PowerShell:
Windows uses `powershell.exe`; Linux and macOS use PowerShell 7 (`pwsh`).
Both actual setup entrypoints execute with synthetic cloud adapters on every
platform. Missing shell tools fail validation instead of silently skipping
tests; no Azure resources or real enrollment are needed for this suite.

Live provider experiments on an edited checkout are diagnostic evidence, not
approval of its original commit. A source or harness fix creates a new full
commit/tree and new review target. Release requires pinned exact-source test
receipts, positive and negative provider results, disposable-resource teardown,
renewed implementation review and fresh registered-identity ballots from the
complete online flock. Historical votes, self-advertised keys, a mutable
`FETCH_HEAD`, an exit code without executed-test counts, or an approval Boolean
cannot substitute for those gates.

An existing legacy client's software upgrade is **not** a broker-free
infrastructure or credential migration. Preserve its machine ID, existing
Ed25519 identity, flock memberships, credential configuration and conversations.
Roll out a verified published source candidate canary-first with an independent
recovery path, and verify the resident daemon separately from the caller's
already-running MCP process. Do not silently run clean/re-enroll, replace keys,
restart the entire Copilot app, deploy a broker or delete production hosting.
Changing an existing flock's protocol/authority requires a separate explicit
migration decision. A source release alone does not demonstrate that every
host has upgraded or that an old loaded MCP process has reloaded.
