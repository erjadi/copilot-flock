# Ranked TODO companion page

The existing console includes **TODOs**, directly addressable at `/#todos`.
Its ranked cards adapt the synthetic-only
[Lovable design](https://lovable.dev/projects/c6735153-c6d3-42f2-8cf4-ad2aa9fac617).
It uses the console's dark/light tokens and mobile navigation, not a separate
hosted application. Lovable never receives runtime tracker records.

## Private runtime data

`GET /api/todos` reads the file named by `VIEWER_TODOS_PATH` on every request.
Unset, missing, unreadable or invalid snapshots return HTTP 503; no checked-in
data, old snapshot or synthetic fallback is returned. The page loads on entry
and on **Refresh TODOs**; it has no polling automation. A refresh error hides
the ranking rather than presenting it as current.

**Private TODO data defaults to loopback-only**, even when the legacy viewer
listens on all interfaces. Loopback sockets `127.0.0.1`, `::1` and
`::ffff:127.0.0.1` retain access, including existing authenticated SSH tunnels.
After explicit owner approval, `VIEWER_TODOS_LAN_CIDR` can additionally allow
one IPv4 LAN subnet (for example `192.168.42.0/24`). Copilot must validate the
actual home LAN interface/subnet before configuring it; do not infer approval
for Meshnet, VPN, Docker, WAN, or all private networks. An unset value does
not allow LAN access. Malformed/noncanonical CIDRs fail closed with HTTP 503
and a server log; `/0` is rejected.

The route matches the actual socket address, including dotted IPv4-mapped
IPv6 addresses, against that exact subnet. Other IPv6 addresses remain denied
except `::1`. All other clients receive HTTP 403. Forwarded-IP headers cannot
bypass this check, and browser cross-origin checks remain active for LAN
clients. The UI explains 403 as an access restriction rather than a missing
snapshot. LAN access grants the configured audience read-only tracker access;
it does not permit modification or automatically grant any flock/thread access.

The legacy viewer has no built-in HTTP authentication. Do not put an
unauthenticated reverse proxy in front of `/api/todos`: a permitted proxy
would satisfy the socket guard. Any proxy must authenticate the authorized
tracker audience itself. Same-origin checks and absence of wildcard CORS
are browser protections, not authentication.
The tracker is viewer-wide, not scoped by the active flock selector, and
membership in a flock does not grant tracker access.
Keep the file outside the source checkout/static assets in an owner-only
directory, with owner-only file permissions/Windows ACLs. Never embed it in
the bundle, commit it, or send it to a design service.

## Tracker-to-companion handoff

The tracker owns the full normalized export. On content changes it increments
`revision`, updates `updatedAt`, saves the export in its private session
artifacts, and messages the companion with the exact path and revision.
The companion reads only that explicitly handed-off file, validates it and
publishes it to the deployment owner's configured private runtime file.
No scheduled automation or unapproved underlying fixes are implied.

For agents, the publication helper is:

```text
node viewer/publish-todos.mjs <handed-off-export> <private-runtime-file>
```

Copilot executes this, not the human user. The destination directory must
already exist outside the checkout with appropriate access restrictions.
The helper validates and projects the contract, atomically replaces the
snapshot with a mode-0600 file on POSIX, rejects decreasing revisions/timestamps
and conflicting content at the same revision, and permits identical retries.
Windows directory ACLs must be verified separately. A broken existing runtime
file is an explicit failure, not silently overwritten.
Data-only updates need no service restart once the endpoint is configured.

## Snapshot contract (version 1)

Top-level fields: `schemaVersion: 1`, positive integer `revision`, ISO
timestamp `updatedAt`, nonempty `source`, and `issues: []`.
Every issue has:

| Field | Contract |
| --- | --- |
| `todoId`, `number` | Stable nonempty local ID and positive local number; not GitHub IDs |
| `rank` | Unique positive integer; ascending editorial display order |
| `title` | Nonempty title |
| `type` | `bug` or `architecture` |
| `status` | `pending`, `in_progress`, `blocked`, or `done` |
| `rankingBasis`, `rankingExplanation` | Explicit provisional basis and rationale |
| `evidence` | Source confidence, including reproduction caveats |
| `implementationStatus`, `nextStep` | Actual implementation state and proposed action |
| `details` | Array of nonempty explanation strings |
| `relatedIssues` | Array of other local numbers present in this snapshot; not dependencies |

Unknown fields are not exposed by the API. IDs, local numbers and ranks must
be unique. Empty issue lists are valid; invalid data fails as a whole.
Files are limited to 1 MiB and snapshots to 1,000 issues.
The page does not modify items or claim proposals were selected/implemented.

### Scoring and sorting (backward-compatible version 1 extension)

New tracker exports should supply every item with `scores`,
`evidenceConfidence` and `acceptanceCriteria`. They remain optional so existing
version-1 snapshots can be loaded safely; missing data is explicitly displayed
as **Unscored**, **Unknown**, or **Not supplied**, never invented or inferred.
Supplied fields must be valid; a partial `scores` object rejects the snapshot.
The publisher and API preserve these fields through their validated projection.

`scores` has all six integer values from 1 to 5:

| Key | Meaning |
| --- | --- |
| `riskReduction` | Security, data-loss, upgrade or session risk prevented |
| `userImpact` | Workflow severity |
| `reach` | Machines, users or workflows benefited |
| `urgency` | Active failure, deadline or worsening conditions |
| `unblockingValue` | Important dependencies or repeated blockers removed |
| `effortAndChangeRisk` | Implementation, rollout and regression exposure; **5 means harder or riskier**, not better |

`evidenceConfidence` is `reported`, `reproduced`, or
`independently_verified`. It is displayed separately, not used as a priority
penalty. `acceptanceCriteria` is an array of nonempty strings describing
verifiable completion conditions; an absent or empty array is not readiness.

The tracker owns editorial rank and its explanation. Risk reduction and user
impact lead, then urgency and unblocking value; reach and effort are
tiebreakers. No aggregate score is calculated. Priority never implies
implementation readiness or authorization.

The default view sorts editorial rank ascending. A **Sort by** selector
supports each of the six dimensions, with explicit ascending/descending score
direction. Unscored items always appear last in either direction. Ties use
editorial rank ascending, then stable ID in code-point order. Sorting does
not change the visible editorial rank labels or the source data. Search,
status and kind filters continue to work; acceptance criteria are searchable.

## Verification and release

Focused checks: `node --test test/viewer-todos.test.mjs`, then viewer
TypeScript checking and production build. Before merge/release, also run
`node --test test/flock.test.mjs` and obtain unanimous online-member release
votes for the exact candidate, following `AGENTS.md`. Coordinate the specific
viewer service rollout with its maintainer; never reset another checkout,
restart unrelated services, or bypass votes to publish the page.
