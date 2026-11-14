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
- Release review now requires all repository and viewer tests, entrypoint byte
  parity, dependency closure, and runtime manifest verification.

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

## Qualification still required

1. Run the complete repository suite on the exact candidate commit.
2. Verify disposable Azure positive/negative JWT, SAS, audience, and scope
   isolation gates.
3. Canary the exact artifacts while checking resident daemon and caller MCP
   digests independently.
4. Run the required flock-wide cryptographic release vote.

No signed release artifact distribution redesign was added in this milestone.
The safe noninteractive preflight fails clearly when an authorized artifact or
repository source is unavailable.
