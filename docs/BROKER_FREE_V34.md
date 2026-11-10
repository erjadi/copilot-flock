# Broker-free 3.4.0 source candidate

This is prepared source, not a released or production-validated deployment.
Existing installations are not migrated. Live Azure isolation tests, immutable
implementation review and the all-online-member ACCEPT release vote remain
merge/release gates. Preparing this candidate does not authorize deployment.

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
creates only `sub-<peerId>`, and returns an owner-signed, X25519-sealed Welcome
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
| Remove local installation | `uninstall` or `unenroll --traceless` | `unenroll_flock` |

Use an explicit flock selector when multiple memberships exist, including
replies. Ambiguous dispatch fails. A legacy installation requires a separately
configured Copilot home for broker-free enrollment; no silent replacement or
hosted-broker fallback occurs. Canonical and legacy script entrypoints use
the same protocol selection.

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
Provider enforcement of these exact scopes is an **unrun live gate**, not
established by token parsing or mocks.

The active broker-free RPC surface supports ping, certificate-filtered
session listings, approved-snapshot transcript access, guarded messaging to
explicitly shared sessions, renewal and leave. Local sharing and signed
session IDs both apply; even owner certificates do not expose all local
threads by default. Cross-flock thread bindings are enforced. Snapshots and
returned replies use credential redaction; the user must still approve a
secret-free snapshot rather than relying on redaction alone.

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
