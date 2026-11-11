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

**Enabling this endpoint is a publication decision.** The legacy viewer has no
built-in HTTP authentication. Configure the path only after the deployment
owner verifies that the viewer's binding, firewall or authenticated reverse
proxy restricts access to the authorized tracker audience. Same-origin checks
and absence of wildcard CORS are browser protections, not authentication.
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

## Verification and release

Focused checks: `node --test test/viewer-todos.test.mjs`, then viewer
TypeScript checking and production build. Before merge/release, also run
`node --test test/flock.test.mjs` and obtain unanimous online-member release
votes for the exact candidate, following `AGENTS.md`. Coordinate the specific
viewer service rollout with its maintainer; never reset another checkout,
restart unrelated services, or bypass votes to publish the page.
