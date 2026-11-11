import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { authoritativeFlocks } from "../viewer/flock-roster.mjs";

const member = (machineId, membershipExpiresAt = null) => ({ machineId, peerId: `peer-${machineId}`, membershipExpiresAt });
const flock = (flockId, members, extra = {}) => ({ flockId, flockUuid: flockId, hubName: "test-hub", flockType: "shared", ownerGitHubUser: "owner", rosterEpoch: 3, members, ...extra });

test("viewer preserves only authoritative flocks and their exact memberships, including empty and overlapping groups", () => {
  const root = flock("owner", [member("work-pc")], { flockType: "owner_root" });
  const raw = { ownedFlocks: [
    root,
    flock("owner/personal", [], { flockType: "owner_scope" }),
    flock("owner/work-team", []),
    flock("owner/japan-stu", [member("work-pc"), member("personal-pc")]),
    flock("owner/work/work-pc", [member("work-pc", "2030-01-01T00:00:00Z")], { targetMachineId: "work-pc" }),
  ], joinedFlocks: [root] };
  const result = authoritativeFlocks(raw, "OWNER");
  assert.deepEqual(result.map((f) => f.flockId), raw.ownedFlocks.map((f) => f.flockId));
  assert.deepEqual(result.map((f) => f.members), raw.ownedFlocks.map((f) => f.members));
  assert.equal(result[0].trustTier, "owner");
  assert.equal(result[2].trustTier, "collaborator");
  assert.equal(result[2].sessionVisibility, "explicit_opt_in_only");
  assert.equal(result[4].kind, "guest");
  assert.equal(result[4].members[0].membershipExpiresAt, "2030-01-01T00:00:00Z");
  assert.equal(result.some((f) => f.flockId === "owner/studio-team"), false);
  assert.deepEqual(authoritativeFlocks({ ownedFlocks: [], joinedFlocks: [] }, "owner"), []);
});

test("authority failures and malformed rosters are unavailable, never success-shaped demo or cache fallbacks", () => {
  for (const raw of [null, undefined, {}, [], { ok: false, ownedFlocks: [] }, { ownedFlocks: {} }, { ownedFlocks: [], joinedFlocks: null },
    { ownedFlocks: [flock("owner/personal", undefined)] },
    { ownedFlocks: [flock("owner/personal", [{ peerId: "missing-machine" }])] }]) {
    assert.throws(() => authoritativeFlocks(raw, "owner"), /Authoritative flock roster/);
  }
});

test("live membership route uses authority projection without fleet discovery or roster fabrication", () => {
  const source = fs.readFileSync(new URL("../viewer/viewer-server.mjs", import.meta.url), "utf8");
  const route = source.slice(source.indexOf('if (url.pathname === "/api/v3/my-flocks"'), source.indexOf("// 8e.", source.indexOf('if (url.pathname === "/api/v3/my-flocks"')));
  assert.match(route, /callBootstrapV3Endpoint\(cfg, "\/my-flocks", \{ method: "GET" \}\)/);
  assert.match(route, /authoritativeFlocks\(raw, cfg.githubUser\)/);
  assert.match(route, /sendJson\(res, 502/);
  assert.doesNotMatch(route, /fleetCache|refreshFleetState|builtIns|studio-team|Date\.now/);
});
