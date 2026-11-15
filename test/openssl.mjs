import fs from "node:fs";
import path from "node:path";

export function resolveOpenSsl({
  platform = process.platform, env = process.env,
  isFile = (filename) => fs.existsSync(filename) && fs.statSync(filename).isFile(),
} = {}) {
  const windows = platform === "win32";
  const paths = windows ? path.win32 : path.posix;
  const directories = String(env.PATH || "").split(windows ? ";" : ":")
    .map((entry) => entry.trim().replace(/^"(.*)"$/, "$1")).filter(Boolean);
  const executable = windows ? "openssl.exe" : "openssl";
  const fromPath = directories.map((directory) => paths.join(directory, executable)).find(isFile);
  if (fromPath) return fromPath;
  if (windows) {
    const git = directories.map((directory) => paths.join(directory, "git.exe")).find(isFile);
    const roots = [
      ...(git ? [paths.resolve(paths.dirname(git), ".."), paths.resolve(paths.dirname(git), "..", "..")] : []),
      paths.join(env.ProgramFiles || "C:\\Program Files", "Git"),
      paths.join(env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Git"),
      ...(env.LOCALAPPDATA ? [paths.join(env.LOCALAPPDATA, "Programs", "Git")] : []),
    ];
    for (const root of roots) {
      for (const suffix of [["usr", "bin"], ["mingw64", "bin"], ["bin"]]) {
        const candidate = paths.join(root, ...suffix, executable);
        if (isFile(candidate)) return candidate;
      }
    }
  }
  throw new Error("OpenSSL is required for isolated TLS qualification; checked PATH and Git for Windows installations");
}
