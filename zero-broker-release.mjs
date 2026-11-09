import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

export function validateReleaseCandidate({ repoDir, commit, exec = execFileSync }) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("Release validation requires an immutable commit SHA");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-release-"));
  const options = { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, maxBuffer: 8 * 1024 * 1024, timeout: 15000 };
  const [major, minor] = process.versions.node.split(".").map(Number);
  const nodeFlags = major === 22 && minor < 13 || major === 23 && minor < 4 ? ["--experimental-sqlite"] : [];
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
    if (!tests.length || !files.includes(path.join(directory, "zero-broker-roster.mjs")) || !files.includes(path.join(directory, "test", "zero-broker-roster.test.mjs"))) throw new Error("Release candidate lacks required Zero-Broker validation surfaces");
    exec(process.execPath, [...nodeFlags, "--test", "--test-concurrency=1", ...tests], { ...options, cwd: directory, timeout: 300000, env: { ...process.env, BRIDGE_FAST_VOTE_TEST: "", COPILOT_HOME: path.join(directory, "isolated-home"), SIGNALR_CONNECTION_STRING: "", SERVICEBUS_CONNECTION_STRING: "", COPILOT_FLOCK_INVITE_FILE: "", COPILOT_FLOCK_BOOTSTRAP_URL: "" } });
    return { modulesSyntaxOk: true, unitTestsOk: true, moduleCount: modules.length, testFileCount: tests.length, candidateCommit: commit, verificationLevel: "complete_candidate_syntax_and_root_tests" };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
