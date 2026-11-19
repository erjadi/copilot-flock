import { after, afterEach } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

export function recordReleaseReviewFailures(testUrl) {
  const testPath = fileURLToPath(testUrl);
  const testDir = path.dirname(testPath);
  const fixture = path.dirname(testDir);
  const root = path.dirname(fixture);
  if (process.platform !== "win32" || path.basename(fixture) !== "fixture" ||
      !path.basename(root).startsWith("flock-vote-")) return;

  const selected = fs.readdirSync(testDir)
    .filter((name) => name.endsWith(".test.mjs") && !name.endsWith(".live.test.mjs"))
    .sort();
  const file = path.basename(testPath);
  const summaries = path.join(root, "failure-summaries");
  fs.mkdirSync(summaries, { recursive: true });
  const failures = [];

  afterEach((t) => {
    if (!t.error) return;
    const cause = t.error.cause || t.error;
    const line = String(cause.stack || "").split("\n")
      .find((frame) => frame.trimStart().startsWith("at ") && frame.includes(`${file}:`))
      ?.match(/:(\d+):(\d+)\)?$/);
    failures.push({
      file,
      line: line ? Number(line[1]) : null,
      test: (t.fullName || t.name).slice(0, 180),
      code: /^[A-Z0-9_]{1,60}$/.test(cause.code || "") ? cause.code : t.error.failureType,
    });
  });

  after(async () => {
    const receipt = (name) => path.join(summaries, `${name}.json`);
    fs.writeFileSync(receipt(file), JSON.stringify(failures), { flag: "wx" });
    if (file !== selected.at(-1)) return;

    // The penultimate worker may still be active when the final file finishes.
    const deadline = performance.now() + 120_000;
    while (selected.some((name) => !fs.existsSync(receipt(name))) &&
           performance.now() < deadline) {
      await delay(50);
    }
    const missing = selected.filter((name) => !fs.existsSync(receipt(name)));
    const failed = selected.filter((name) => !missing.includes(name))
      .flatMap((name) => JSON.parse(fs.readFileSync(receipt(name), "utf8")));
    console.log("RELEASE_REVIEW_DIAGNOSTICS " + JSON.stringify({
      failures: failed.slice(0, 8),
      failureCount: failed.length,
      missing,
    }));
  });
}
