import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

export const RELEASE_REVIEW_TIMEOUT_MS = 450000;
const execFileAsync = promisify(execFile);

function sqliteFlags() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  return major === 22 && minor < 13 || major === 23 && minor < 4 ? ["--experimental-sqlite"] : [];
}

function releaseEnvironment(home) {
  const env = {
    ...process.env, NODE_OPTIONS: "", NODE_V8_COVERAGE: "", BRIDGE_FAST_VOTE_TEST: "",
    SIGNALR_CONNECTION_STRING: "", SERVICEBUS_CONNECTION_STRING: "",
    COPILOT_FLOCK_INVITE_FILE: "", COPILOT_FLOCK_BOOTSTRAP_URL: "",
    COPILOT_BRIDGE_BOOTSTRAP_URL: "",
  };
  for (const key of Object.keys(env)) if (key.startsWith("NODE_TEST_")) delete env[key];
  if (home) env.COPILOT_HOME = home;
  return env;
}

export async function validateReleaseCandidateInWorker({ repoDir, commit }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("Release validation requires an immutable commit SHA");
  const { stdout } = await execFileAsync(process.execPath, [
    ...sqliteFlags(), fileURLToPath(import.meta.url), "--validate-candidate", repoDir, commit,
  ], { encoding: "utf8", windowsHide: true, timeout: 360000, maxBuffer: 8 * 1024 * 1024, env: releaseEnvironment() });
  const result = JSON.parse(stdout);
  if (result.candidateCommit !== commit || result.modulesSyntaxOk !== true || result.unitTestsOk !== true) {
    throw new Error("Release worker returned incomplete or mismatched candidate validation");
  }
  return result;
}

export function validateReleaseCandidate({ repoDir, commit, exec = execFileSync }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("Release validation requires an immutable commit SHA");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-release-"));
  const options = { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, maxBuffer: 8 * 1024 * 1024, timeout: 15000 };
  const nodeFlags = sqliteFlags();
  try {
    const entries = exec("git", ["-C", repoDir, "ls-tree", "-r", "-z", commit], options).toString("utf8").split("\0").filter(Boolean);
    const files = [];
    for (const entry of entries) {
      const match = /^100(?:644|755) blob [0-9a-f]{40}\t(.+)$/.exec(entry);
      if (!match) throw new Error("Release tree contains an unsupported entry or symbolic link");
      const filename = match[1];
      if (filename.split("/").some((part) => !part || part === "." || part === "..") || filename.includes("\\") || filename.includes(":")) throw new Error("Unsafe release tree path");
      const target = path.join(directory, ...filename.split("/"));
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, exec("git", ["-C", repoDir, "show", `${commit}:${filename}`], options));
      files.push(target);
    }
    const modules = files.filter((filename) => filename.endsWith(".mjs"));
    for (const filename of modules) exec(process.execPath, ["--check", filename], options);
    const tests = files.filter((filename) => path.dirname(filename) === path.join(directory, "test") && filename.endsWith(".test.mjs"));
    const requiredModules = ["flock.mjs", "bridge.mjs", "bootstrap-server.mjs",
      "zero-broker-roster.mjs", "zero-broker-transport.mjs", "zero-broker-runtime.mjs",
      "zero-broker-lifecycle.mjs", "zero-broker-enrollment.mjs", "zero-broker-release.mjs"];
    const requiredTests = ["flock", "bridge", "setup", "contracts", "rpc-security", "zero-broker-roster", "zero-broker-lifecycle"];
    if (requiredModules.some((name) => !files.includes(path.join(directory, name))) ||
        requiredTests.some((name) => !tests.includes(path.join(directory, "test", `${name}.test.mjs`)))) {
      throw new Error("Release candidate lacks required canonical, legacy or Zero-Broker validation surfaces");
    }
    if (!fs.readFileSync(path.join(directory, "flock.mjs")).equals(fs.readFileSync(path.join(directory, "bridge.mjs")))) {
      throw new Error("Release candidate canonical and compatibility entry points differ");
    }
    exec(process.execPath, [...nodeFlags, "--test", "--test-concurrency=1", ...tests], { ...options, cwd: directory, timeout: 300000, env: releaseEnvironment(path.join(directory, "isolated-home")) });
    return { modulesSyntaxOk: true, unitTestsOk: true, moduleCount: modules.length, testFileCount: tests.length, candidateCommit: commit, verificationLevel: "complete_candidate_syntax_and_root_tests" };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv[2] === "--validate-candidate") {
  try {
    console.log(JSON.stringify(validateReleaseCandidate({ repoDir: process.argv[3], commit: process.argv[4] })));
  } catch (error) {
    console.error(error.message);
    if (error.stdout) process.stderr.write(error.stdout);
    if (error.stderr) process.stderr.write(error.stderr);
    process.exitCode = 1;
  }
}
