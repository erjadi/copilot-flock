import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

export function assertExpectedReleaseCommit(commit) {
  if (typeof commit !== "string" || !/^[0-9a-f]{40}$/.test(commit)) {
    throw Object.assign(new Error("Supply the independently expected full release commit SHA."), { code: "RELEASE_COMMIT_REQUIRED" });
  }
  return commit;
}

export function resolveExpectedReleaseCommit({ repoDir, branch, expectedCommit, exec = execFileSync }) {
  assertExpectedReleaseCommit(expectedCommit);
  if (typeof branch !== "string" || !/^[A-Za-z0-9._/-]+$/.test(branch) || branch.startsWith("-") || branch.includes("..")) {
    throw new Error("Invalid release branch");
  }
  const reference = `refs/copilot-flock/reviews/${expectedCommit}`;
  const options = { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 20000, windowsHide: true };
  exec("git", ["-C", repoDir, "fetch", "--no-tags", "--no-write-fetch-head",
    "https://github.com/erjadi/copilot-flock.git", `+refs/heads/${branch}:${reference}`], options);
  const resolved = exec("git", ["-C", repoDir, "rev-parse", "--verify", `${reference}^{commit}`], options).trim();
  if (resolved !== expectedCommit) {
    throw Object.assign(new Error(`Release branch resolved to ${resolved}, not the independently expected ${expectedCommit}.`), { code: "RELEASE_COMMIT_MISMATCH" });
  }
  return resolved;
}

export function releaseTreeFiles(entries) {
  return entries.toString("utf8").split("\0").filter(Boolean).map((entry) => {
    const match = /^100(?:644|755) blob [0-9a-f]{40}\t(.+)$/.exec(entry);
    if (!match) throw new Error("Release tree contains an unsupported entry or symbolic link");
    const filename = match[1];
    if (filename.split("/").some((part) => !part || part === "." || part === "..") || filename.includes("\\") || filename.includes(":")) {
      throw new Error("Unsafe release tree path");
    }
    return filename;
  });
}

export function readExpectedReleaseCoverage({ repoDir, expectedCommit, exec = execFileSync }) {
  assertExpectedReleaseCommit(expectedCommit);
  const files = releaseTreeFiles(exec("git", ["-C", repoDir, "ls-tree", "-r", "-z", expectedCommit],
    { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, timeout: 15000, maxBuffer: 8 * 1024 * 1024 }));
  const inventory = createReleaseCoverage(files);
  if (!verifyReleaseCoverage({ ...inventory, moduleCount: inventory.coverage.modules.length, testFileCount: inventory.coverage.testFiles.length })) {
    throw new Error("Independently expected source lacks required release validation coverage");
  }
  return inventory;
}
export const RELEASE_VALIDATION_POLICY = Object.freeze({
  version: 1,
  gitEntries: "regular_100644_100755_only_no_unsafe_paths",
  syntax: "every_tracked_mjs",
  tests: "every_top_level_test_dot_test_mjs_serial",
  canonicalEntryPoints: Object.freeze(["bridge.mjs", "flock.mjs"]),
  requiredModules: Object.freeze(["bridge.mjs", "flock.mjs", "bootstrap-server.mjs", "release-policy.mjs",
    "zero-broker-roster.mjs", "zero-broker-transport.mjs", "zero-broker-runtime.mjs",
    "zero-broker-lifecycle.mjs", "zero-broker-enrollment.mjs", "zero-broker-release.mjs"].sort()),
  requiredTests: Object.freeze(["bridge", "flock", "setup", "contracts", "rpc-security",
    "zero-broker-roster", "zero-broker-lifecycle"].map((name) => `test/${name}.test.mjs`).sort()),
  environment: "clear_NODE_TEST_selectors_NODE_OPTIONS_coverage_fast_flags_and_cloud_overrides_isolate_COPILOT_HOME",
  testTimeoutMs: 300000,
  workerTimeoutMs: 360000,
  localExecutionConsent: "exact_sha_existing_device_signature_30_minutes_before_tests_and_ballot",
});

export const RELEASE_VALIDATION_POLICY_HASH = crypto.createHash("sha256")
  .update(JSON.stringify(RELEASE_VALIDATION_POLICY)).digest("hex");

export function releaseCoveragePayload(coverage) {
  return JSON.stringify([coverage?.version, coverage?.policyHash, coverage?.modules, coverage?.testFiles]);
}

export function createReleaseCoverage(files) {
  const coverage = { version: RELEASE_VALIDATION_POLICY.version, policyHash: RELEASE_VALIDATION_POLICY_HASH,
    modules: files.filter((name) => name.endsWith(".mjs")).sort(),
    testFiles: files.filter((name) => /^test\/[^/]+\.test\.mjs$/.test(name)).sort() };
  return { coverage, coverageHash: crypto.createHash("sha256").update(releaseCoveragePayload(coverage)).digest("hex") };
}

function validInventory(names, required, predicate) {
  return Array.isArray(names) && names.every((name) => typeof name === "string" && predicate(name) &&
    !name.includes("\\") && !name.includes(":") && name.split("/").every((part) => part && part !== "." && part !== "..")) &&
    new Set(names).size === names.length &&
    names.every((name, index) => index === 0 || names[index - 1] < name) &&
    required.every((name) => names.includes(name));
}

export function verifyReleaseCoverage(checks) {
  const coverage = checks?.coverage;
  return coverage?.version === RELEASE_VALIDATION_POLICY.version &&
    coverage.policyHash === RELEASE_VALIDATION_POLICY_HASH &&
    validInventory(coverage.modules, RELEASE_VALIDATION_POLICY.requiredModules, (name) => name.endsWith(".mjs")) &&
    validInventory(coverage.testFiles, RELEASE_VALIDATION_POLICY.requiredTests, (name) => /^test\/[^/]+\.test\.mjs$/.test(name)) &&
    checks.moduleCount === coverage.modules.length && checks.testFileCount === coverage.testFiles.length &&
    checks.coverageHash === crypto.createHash("sha256").update(releaseCoveragePayload(coverage)).digest("hex");
}
