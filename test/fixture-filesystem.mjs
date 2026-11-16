import fs from "node:fs";

const realRename = fs.renameSync;
const realWait = Atomics.wait;

export function renameFixtureDirectory(from, to, rename = realRename, wait = realWait) {
  for (let attempt = 0; ; attempt++) {
    try { rename(from, to); return; }
    catch (cause) {
      if (!["EPERM", "EACCES", "EBUSY"].includes(cause.code) || attempt >= 8) {
        throw Object.assign(new Error("Fixture directory swap failed", { cause }),
          { code: "FLOCK_TEST_SWAP_SETUP_FAILED" });
      }
      wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(10 * 2 ** attempt, 200));
    }
  }
}
