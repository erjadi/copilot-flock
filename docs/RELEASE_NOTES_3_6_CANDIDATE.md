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
