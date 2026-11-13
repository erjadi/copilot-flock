import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { signLeave } from "./flock-membership.mjs";

const __lifecycleDir = path.dirname(fileURLToPath(import.meta.url));
const hash = (data) => crypto.createHash("sha256").update(data).digest("hex");
const names = ["copilot-flock", "copilot-signalr-bridge"];
export const RUNTIME_MANIFEST_FILENAME = "runtime-manifest.json";
export const RUNTIME_STATE_FILENAME = "runtime-state.json";
export const RUNTIME_CUTOVER_JOURNAL_FILENAME = ".runtime-cutover-journal.json";
export const REQUIRED_RUNTIME_ENTRYPOINTS = Object.freeze(["flock.mjs", "bridge.mjs"]);
export const REQUIRED_COMPANION_MODULES = Object.freeze([
  "flock-lifecycle.mjs",
  "flock-membership.mjs",
  "flock-protocol.mjs",
  "flock-azure.mjs",
  "flock-broker-free.mjs",
]);
export const REQUIRED_RUNTIME_MODULES = Object.freeze([
  ...REQUIRED_RUNTIME_ENTRYPOINTS,
  ...REQUIRED_COMPANION_MODULES,
]);
const runtimeFiles = [
  "flock.mjs", "bridge.mjs", "flock-lifecycle.mjs", "flock-membership.mjs", "flock-registry.mjs",
  "config.json", "identity.json", "flocks.json", "flock-registry.json", "state.json", "daemon.pid",
  "daemon-identity.json", "daemon.log", "inbox.jsonl", "outbox.jsonl", "locks.json",
  "cli-sessions.json", "processed-offline-ids.json", "last-vote-report.json",
  "installation.json", "uninstall-progress.json",
  "flock-protocol.mjs", "flock-azure.mjs", "flock-broker-free.mjs", "broker-free.json",
  RUNTIME_MANIFEST_FILENAME, RUNTIME_STATE_FILENAME,
];

export function lifecyclePaths({ home = os.homedir(), copilotHome = process.env.COPILOT_HOME || path.join(home, ".copilot"),
  appData = process.env.APPDATA, platform = process.platform } = {}) {
  home = path.resolve(home);
  copilotHome = path.resolve(copilotHome);
  if ([home, path.parse(home).root].includes(copilotHome)) throw new Error("Copilot home must be a dedicated directory");
  const app = platform === "win32" ? path.join(appData || path.join(home, "AppData", "Roaming"), "com.github.githubapp")
    : platform === "darwin" ? path.join(home, "Library", "Application Support", "com.github.githubapp")
    : path.join(home, ".config", "com.github.githubapp");
  const roots = ["flock", "signalr-bridge"].map((name) => path.join(copilotHome, name));
  const scripts = roots.flatMap((root) => ["flock.mjs", "bridge.mjs"].map((name) => path.join(root, name)));
  const configs = [
    { path: path.join(copilotHome, "mcp-config.json"), key: "mcpServers" },
    { path: path.join(app, "mcp-config.json"), key: "mcpServers" },
    { path: path.join(home, ".vscode", "mcp.json"), key: "servers" },
    { path: platform === "win32" ? path.join(appData || path.join(home, "AppData", "Roaming"), "Code", "User", "mcp.json")
      : platform === "darwin" ? path.join(home, "Library", "Application Support", "Code", "User", "mcp.json")
      : path.join(home, ".config", "Code", "User", "mcp.json"), key: "servers" },
  ];
  const skills = ["copilot-flock", "flock-topology", "signalr-bridge"].flatMap((name) => [
    path.join(copilotHome, "skills", name, "SKILL.md"),
    path.join(app, "app-skills", name, "SKILL.md"),
    ...roots.map((root) => path.join(root, "skill", name, "SKILL.md")),
  ]);
  const persistence = names.map((name) => platform === "win32"
    ? path.join(appData || path.join(home, "AppData", "Roaming"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", `${name}.vbs`)
    : platform === "darwin" ? path.join(home, "Library", "LaunchAgents", `com.erjadi.${name}.plist`)
    : path.join(home, ".config", "systemd", "user", `${name}.service`));
  return { home, copilotHome, platform, roots, scripts, configs, skills, persistence };
}

export function assertNoLinks(target) {
  const absolute = path.resolve(target);
  let current = path.parse(absolute).root;
  for (const component of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    if (!fs.existsSync(current)) {
      // lstat also catches dangling symlinks.
      try { if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`Unsafe link: ${current}`); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
      continue;
    }
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error(`Unsafe link or junction: ${current}`);
    if (fs.realpathSync.native(current).toLowerCase() !== path.resolve(current).toLowerCase()) {
      throw new Error(`Filesystem path escape: ${current}`);
    }
  }
  return absolute;
}

export function atomicJson(filename, value, expected) {
  assertNoLinks(filename);
  const before = fs.existsSync(filename) ? fs.readFileSync(filename) : null;
  if (expected !== undefined && (expected === null ? before !== null : !before?.equals(expected))) {
    throw new Error(`Concurrent config change: ${filename}`);
  }
  const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
  try {
    const text = JSON.stringify(value, null, 2) + "\n";
    const fd = fs.openSync(temporary, "wx", 0o600);
    try { fs.writeFileSync(fd, text); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    JSON.parse(fs.readFileSync(assertNoLinks(temporary), "utf8"));
    for (let attempt = 0; ; attempt++) {
      assertNoLinks(filename);
      assertNoLinks(temporary);
      const current = fs.existsSync(filename) ? fs.readFileSync(filename) : null;
      if (before === null ? current !== null : !current?.equals(before)) {
        throw new Error(`Concurrent config change: ${filename}`);
      }
      try {
        fs.renameSync(temporary, filename);
        break;
      } catch (error) {
        // Sharing violations can outlive close(); never unlink the destination to bypass them.
        if (!["EPERM", "EACCES", "EBUSY"].includes(error.code) || attempt >= 8) throw error;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(10 * 2 ** attempt, 200));
      }
    }
    if (process.platform !== "win32") {
      const directory = fs.openSync(path.dirname(filename), "r");
      try { fs.fsyncSync(directory); }
      finally { fs.closeSync(directory); }
    }
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(assertNoLinks(temporary));
  }
}

export function recordInstalledArtifact(root, filename, paths = lifecyclePaths()) {
  if (!paths.roots.includes(root) ||
      ![...paths.skills, ...paths.persistence,
        ...runtimeFiles.filter((name) => name.endsWith(".mjs")).map((name) => path.join(root, name))].includes(filename)) {
    throw new Error("Artifact is outside the installation allowlist");
  }
  assertNoLinks(root);
  assertNoLinks(filename);
  const manifestPath = path.join(root, "installation.json");
  const manifest = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, "utf8"))
    : { type: "copilot-flock-installation-v1", artifacts: {} };
  if (manifest.type !== "copilot-flock-installation-v1") throw new Error("Invalid installation ownership manifest");
  manifest.artifacts[filename] = hash(fs.readFileSync(filename));
  atomicJson(manifestPath, manifest);
}

export function inspectProcess(pid, platform = process.platform) {
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("Invalid daemon PID");
  try {
    if (platform === "linux") {
      const base = `/proc/${pid}`;
      const fields = fs.readFileSync(`${base}/stat`, "utf8").split(") ").slice(1).join(") ").split(" ");
      return { pid, executable: fs.readlinkSync(`${base}/exe`),
        start: fields[19], argv: fs.readFileSync(`${base}/cmdline`, "utf8").split("\0").filter(Boolean) };
    }
    if (platform === "win32") {
      const text = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
        `$p=Get-CimInstance Win32_Process -Filter 'ProcessId = ${pid}'; if($p){[pscustomobject]@{pid=$p.ProcessId;executable=$p.ExecutablePath;start=$p.CreationDate.ToUniversalTime().ToString('o');command=$p.CommandLine}|ConvertTo-Json -Compress}`],
      { encoding: "utf8", windowsHide: true, timeout: 15000, stdio: ["ignore", "pipe", "pipe"] }).trim();
      return text ? JSON.parse(text) : null;
    }
    const text = execFileSync("ps", ["-p", String(pid), "-o", "lstart=", "-o", "command="],
      { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"], windowsHide: true }).trim();
    return text ? { pid, start: text.slice(0, 24), executable: process.execPath,
      command: text.slice(25).trim() } : null;
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ESRCH" || error.status === 1) return null;
    throw error;
  }
}

export function pinDaemonIdentity(root, script, inspect = inspectProcess) {
  const identity = inspect(process.pid);
  if (!identity?.start) throw new Error("Cannot pin daemon process creation identity");
  atomicJson(path.join(root, "daemon-identity.json"), { ...identity, script: path.resolve(script) });
}

function commandIsDaemon(identity, scripts) {
  if (identity.argv) return identity.argv.length === 3 &&
    scripts.includes(path.resolve(identity.argv[1])) && identity.argv[2] === "daemon";
  return scripts.some((script) => [
    `"${identity.executable}" "${script}" daemon`,
    `"${identity.executable}" ${script} daemon`,
    `${identity.executable} "${script}" daemon`,
    `${identity.executable} ${script} daemon`,
  ].includes(identity.command));
}

export function inspectLinuxUnifiedCgroup(pid, {
  read = (filename) => fs.readFileSync(filename, "utf8"), uid = process.getuid?.(),
} = {}) {
  const rows = read(`/proc/${pid}/cgroup`).trim().split("\n").filter((line) => line.startsWith("0::"));
  const group = rows.length === 1 ? rows[0].slice(3) : "";
  const parts = group.split("/").slice(1);
  const validPath = pid !== 1 && Number.isSafeInteger(uid) && uid >= 0 &&
    group.startsWith("/") && !group.includes("\0") &&
    (group === "/" || parts.every((part) => Boolean(part) && part !== "." && part !== ".."));
  if (!validPath) return { ok: false, group, parts: [], serviceUnits: [], underUserManager: false };
  const userUnit = `user@${uid}.service`;
  const serviceUnits = parts.filter((part) => part.endsWith(".service") && part !== userUnit);
  return {
    ok: true,
    group,
    parts,
    serviceUnits,
    underUserManager: parts.includes(userUnit),
  };
}

export function assertLinuxDaemonCgroupSafe(pid, {
  read = (filename) => fs.readFileSync(filename, "utf8"), uid = process.getuid?.(),
  allowedServices = [],
} = {}) {
  const info = inspectLinuxUnifiedCgroup(pid, { read, uid });
  const allowed = Array.isArray(allowedServices) ? allowedServices : [];
  const serviceSafe = info.serviceUnits.length === 0 ||
    (allowed.length > 0 && info.underUserManager && info.serviceUnits.length === 1 &&
      allowed.includes(info.serviceUnits[0]));
  if (!info.ok || !serviceSafe) {
    throw new Error("Linux daemon service-cgroup child preservation is unproven; installation retained");
  }
  return info;
}

export function buildLinuxSystemdUnit({ home, targetScript, execPath = process.execPath }) {
  if (!home || !targetScript || !execPath) {
    throw new Error("Linux systemd unit requires home, targetScript and execPath");
  }
  return [
    "[Unit]",
    "Description=GitHub Copilot Flock Daemon (copilot-flock)",
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    `WorkingDirectory=${home}`,
    `Environment=PATH=${path.join(home, ".local", "bin")}:/usr/local/bin:/usr/bin:/bin`,
    `ExecStart=${JSON.stringify(execPath).replace(/%/g, "%%")} ${JSON.stringify(targetScript).replace(/%/g, "%%")} daemon`,
    "KillMode=process",
    "Restart=always",
    "RestartSec=3",
    "",
    "[Install]",
    "WantedBy=default.target",
    "",
  ].join("\n");
}

let cachedTransientScopeSupport = null;

export function probeLinuxTransientScopeSupport({ exec = execFileSync } = {}) {
  try {
    exec("systemd-run", ["--user", "--version"], { stdio: "ignore", timeout: 3000, windowsHide: true });
    exec("systemctl", ["--user", "show-environment"], { stdio: "ignore", timeout: 3000, windowsHide: true });
    return true;
  } catch {
    return false;
  }
}

export function prepareOutsideLinuxServiceCgroupSpawn(command, args = [], {
  platform = process.platform,
  pid = process.pid,
  uid = process.getuid?.(),
  read = (filename) => fs.readFileSync(filename, "utf8"),
  probeScope = () => {
    if (cachedTransientScopeSupport === null) cachedTransientScopeSupport = probeLinuxTransientScopeSupport();
    return cachedTransientScopeSupport;
  },
  unitPrefix = "copilot-flock-session",
  unitId = crypto.randomUUID(),
  requireOutsideCgroup = false,
} = {}) {
  if (platform !== "linux") {
    return { command, args: [...args], supervisedOutsideCgroup: false, mode: "non-linux" };
  }
  let cgroupInfo = null;
  try {
    cgroupInfo = inspectLinuxUnifiedCgroup(pid, { read, uid });
  } catch {
    cgroupInfo = { ok: false, group: "", serviceUnits: [] };
  }
  if (cgroupInfo.ok && cgroupInfo.serviceUnits.length === 0) {
    return {
      command,
      args: [...args],
      supervisedOutsideCgroup: true,
      mode: "already-outside-service-cgroup",
      cgroup: cgroupInfo.group,
    };
  }
  const safePrefix = String(unitPrefix || "copilot-flock-session").replace(/[^A-Za-z0-9_-]/g, "-") || "copilot-flock-session";
  const safeId = String(unitId || "").replace(/[^A-Za-z0-9_-]/g, "");
  if (!safeId) throw new Error("Invalid transient scope unit identifier");
  if (probeScope()) {
    const scopeUnit = `${safePrefix}-${safeId}`;
    return {
      command: "systemd-run",
      args: ["--user", "--scope", "--collect", "--quiet", `--unit=${scopeUnit}`, "--", command, ...args],
      supervisedOutsideCgroup: true,
      mode: "systemd-transient-scope",
      scopeUnit: `${scopeUnit}.scope`,
    };
  }
  if (requireOutsideCgroup) {
    throw new Error("Linux outside-cgroup transient scope supervision is unavailable; refusing unguarded spawn");
  }
  return {
    command,
    args: [...args],
    supervisedOutsideCgroup: false,
    mode: "service-cgroup-fallback",
    cgroup: cgroupInfo.group || null,
  };
}

export function spawnSessionSafeProcess(command, args = [], spawnOptions = {}, supervisionOptions = {}) {
  const spec = prepareOutsideLinuxServiceCgroupSpawn(command, args, supervisionOptions);
  const spawnFn = supervisionOptions.spawnImpl || spawn;
  const child = spawnFn(spec.command, spec.args, { ...spawnOptions, windowsHide: true });
  if (child && typeof child === "object") child.outsideCgroupSupervision = spec;
  return child;
}

export async function stopPinnedDaemon(root, paths, {
  inspect = inspectProcess, kill = (pid) => process.kill(pid),
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  checkLinuxCgroup = assertLinuxDaemonCgroupSafe,
} = {}) {
  const pidPath = path.join(root, "daemon.pid");
  if (!fs.existsSync(pidPath)) return;
  const pid = Number(fs.readFileSync(pidPath, "utf8").trim());
  if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("Malformed daemon PID; inspect installation before retrying");
  const live = inspect(pid);
  if (!live) return;
  const pinPath = path.join(root, "daemon-identity.json");
  if (!fs.existsSync(pinPath)) {
    if (commandIsDaemon(live, paths.scripts)) throw new Error("Legacy daemon is running without a creation-identity pin; retained for safe manual coordination");
    return; // A reused PID is not evidence that the unrelated process belongs to Flock.
  }
  const pin = JSON.parse(fs.readFileSync(pinPath, "utf8"));
  if (pin.pid !== pid || pin.start !== live.start || pin.executable !== live.executable ||
      pin.command !== live.command || JSON.stringify(pin.argv) !== JSON.stringify(live.argv) ||
      !paths.scripts.includes(pin.script) || !commandIsDaemon(live, [pin.script])) {
    if (commandIsDaemon(live, paths.scripts)) throw new Error("Running daemon does not match its stored creation identity");
    return;
  }
  if (pid === process.pid) throw new Error("Uninstaller cannot terminate its own process");
  if (paths.platform === "linux") checkLinuxCgroup(pid);
  // Re-inspect immediately before signalling to reject stale/reused PIDs.
  if (JSON.stringify(inspect(pid)) !== JSON.stringify(live)) throw new Error("Daemon process identity changed");
  kill(pid);
  for (let attempt = 0; attempt < 30; attempt++) {
    const after = inspect(pid);
    if (!after || after.start !== live.start) return;
    await delay(100);
  }
  throw new Error("Daemon did not stop; installation retained");
}

function isOwnedMcp(entry, scripts) {
  return entry && typeof entry.command === "string" && Array.isArray(entry.args) &&
    entry.args.length === 2 && typeof entry.args[0] === "string" &&
    scripts.includes(path.resolve(entry.args[0])) && entry.args[1] === "mcp" &&
    /^(node(?:\.exe)?|.*[\\/]node(?:\.exe)?)$/i.test(entry.command);
}

function removeMcp(config, scripts, removed) {
  assertNoLinks(config.path);
  if (!fs.existsSync(config.path)) return;
  const original = fs.readFileSync(config.path);
  const value = JSON.parse(original.toString("utf8"));
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error(`Invalid MCP config: ${config.path}`);
  const servers = value[config.key];
  if (!servers) return;
  let changed = false;
  for (const name of names) {
    if (isOwnedMcp(servers[name], scripts)) {
      delete servers[name];
      changed = true;
      removed.push(`${config.path}#${config.key}.${name}`);
    }
  }
  if (changed) atomicJson(config.path, value, original);
}

function legacyArtifactOwned(filename, text, paths) {
  if (paths.skills.includes(filename)) {
    return false;
  }
  // Legacy persistence is recognized by the exact installed launch command, not the filename.
  return paths.persistence.includes(filename) && paths.scripts.some((script) =>
    text === `Set WshShell = CreateObject("WScript.Shell")\r\nWshShell.Run """${process.execPath}"" ""${script}"" daemon", 0, False\r\n` ||
    (paths.platform === "linux" && text === `[Unit]
Description=GitHub Copilot Flock Daemon (copilot-flock)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${paths.home}
Environment=PATH=${path.join(paths.home, ".local", "bin")}:/usr/local/bin:/usr/bin:/bin
ExecStart=${process.execPath} ${script} daemon
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`) || (paths.platform === "darwin" && text === `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.erjadi.copilot-flock</string>
  <key>ProgramArguments</key>
  <array>
    <string>${process.execPath}</string>
    <string>${script}</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`));
}

function removeEmptyParents(filename, stop) {
  let current = path.dirname(filename);
  while (current !== stop && current.startsWith(stop + path.sep)) {
    assertNoLinks(current);
    if (!fs.existsSync(current) || fs.readdirSync(current).length) return;
    fs.rmdirSync(current);
    current = path.dirname(current);
  }
}

function queryUserSystemd(args) {
  return execFileSync("systemctl", ["--user", ...args], {
    encoding: "utf8", timeout: 6000, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
}

function parseSystemdProperties(raw, requiredKeys, errorMessage = "Invalid Linux unit properties") {
  const properties = new Map();
  const lines = String(raw ?? "").trim().split("\n").filter(Boolean);
  if (!lines.length) throw new Error(errorMessage);
  for (const line of lines) {
    const separator = line.indexOf("=");
    const key = line.slice(0, separator);
    if (separator < 1 || properties.has(key)) throw new Error(errorMessage);
    properties.set(key, line.slice(separator + 1));
  }
  for (const key of requiredKeys) {
    if (!properties.has(key)) throw new Error(errorMessage);
  }
  return properties;
}

export function readLinuxCgroupPids(controlGroup, {
  cgroupRoot = "/sys/fs/cgroup",
  read,
  readdir,
} = {}) {
  if (!controlGroup) return [];
  const parts = String(controlGroup).split("/").slice(1);
  if (!String(controlGroup).startsWith("/") || String(controlGroup).includes("\0") ||
      (controlGroup !== "/" && parts.some((part) => !part || part === "." || part === ".."))) {
    throw new Error("Invalid Linux ControlGroup path");
  }
  const readFn = read || ((filename) => fs.readFileSync(filename, "utf8"));
  const readdirFn = readdir || (read ? () => [] : (dir) => fs.readdirSync(dir, { withFileTypes: true }));
  const rootPrefix = String(cgroupRoot).replace(/\/+$/, "");
  const startDir = controlGroup === "/" ? (rootPrefix || "/") : `${rootPrefix}${controlGroup}`;
  const pids = new Set();
  const walk = (dir) => {
    const raw = readFn(`${dir}/cgroup.procs`);
    for (const line of String(raw).split("\n").map((item) => item.trim()).filter(Boolean)) {
      if (!/^\d+$/.test(line)) throw new Error("Malformed Linux cgroup.procs entry");
      const pid = Number(line);
      if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("Invalid PID in Linux cgroup.procs");
      pids.add(pid);
    }
    let entries = [];
    try {
      entries = readdirFn(dir) || [];
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    for (const entry of entries) {
      if (!entry || typeof entry.isDirectory !== "function" || !entry.isDirectory()) continue;
      const name = String(entry.name || "");
      if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\0")) continue;
      walk(`${dir}/${name}`);
    }
  };
  walk(startDir);
  return [...pids];
}

export function configureLinuxSystemdPersistence(targetScript, paths = lifecyclePaths(), {
  strict = false,
  execPath = process.execPath,
  query = queryUserSystemd,
  checkLinger = (user) => execFileSync("loginctl", ["show-user", user, "-p", "Linger", "--value"], { encoding: "utf8", timeout: 4000, windowsHide: true }),
  enableLinger = (user) => execFileSync("sudo", ["-n", "loginctl", "enable-linger", user], { stdio: "ignore", timeout: 4000, windowsHide: true }),
  username = () => os.userInfo().username,
} = {}) {
  if (paths.platform !== "linux") return null;
  const unitPath = paths.persistence[0];
  const legacyUnitPath = paths.persistence[1];
  const systemdDir = path.dirname(unitPath);
  assertNoLinks(systemdDir);
  assertNoLinks(unitPath);
  assertNoLinks(legacyUnitPath);
  fs.mkdirSync(systemdDir, { recursive: true });
  const unitContent = buildLinuxSystemdUnit({ home: paths.home, targetScript, execPath });
  fs.writeFileSync(unitPath, unitContent, "utf8");
  if (fs.existsSync(legacyUnitPath)) {
    try {
      const props = parseSystemdProperties(
        query(["show", "copilot-signalr-bridge.service",
          "--property=Id,LoadState,FragmentPath,ActiveState,MainPID,ControlGroup"]),
        ["Id", "LoadState", "FragmentPath", "ActiveState", "MainPID", "ControlGroup"]
      );
      query(["disable", "copilot-signalr-bridge.service"]);
      if (props.get("ActiveState") === "inactive" && props.get("MainPID") === "0" &&
          props.get("ControlGroup") === "") {
        assertNoLinks(legacyUnitPath);
        fs.unlinkSync(legacyUnitPath);
      }
    } catch (error) {
      if (strict) throw error;
    }
  }
  let systemdReady = false;
  try {
    query(["daemon-reload"]);
    query(["enable", "copilot-flock.service"]);
    systemdReady = true;
  } catch (error) {
    if (strict) throw error;
  }
  try {
    const user = username();
    if (strict) {
      const linger = String(checkLinger(user) ?? "").trim();
      if (linger !== "yes") throw new Error("User lingering is not enabled; obtain explicit approval before enabling it");
    } else {
      enableLinger(user);
    }
  } catch (error) {
    if (strict) throw error;
  }
  return { platform: "linux", type: "systemd-user", path: unitPath, killMode: "process", systemdReady };
}

const ACTIVATION_PROPERTIES = [
  "Id", "LoadState", "FragmentPath", "ActiveState", "MainPID", "ControlGroup", "KillMode", "Restart",
];

export async function activateLinuxSystemdDaemon({
  root,
  paths = lifecyclePaths(),
  targetUnit = "copilot-flock.service",
  maintenanceConsent = false,
  allowDisruptiveRestart = false,
  uid = process.getuid?.(),
  query = queryUserSystemd,
  inspect = inspectProcess,
  readCgroup = (filename) => fs.readFileSync(filename, "utf8"),
  readCgroupProcs = (controlGroup) => readLinuxCgroupPids(controlGroup),
  kill = (pid) => process.kill(pid, "SIGTERM"),
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  beforeStart = null,
  waitForReady = null,
} = {}) {
  if (paths.platform !== "linux") throw new Error("Linux systemd activation requires a Linux target");
  const consent = Boolean(maintenanceConsent || allowDisruptiveRestart);
  if (!root || !paths.roots.includes(path.resolve(root))) {
    throw new Error("Activation root must be a managed Flock installation root");
  }
  root = assertNoLinks(root);
  for (const filename of paths.persistence) {
    assertNoLinks(filename);
    assertNoLinks(`${filename}.d`);
  }
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error("Cannot establish Linux UID for session-preserving daemon activation");
  }
  const expected = new Map(paths.persistence.map((filename) => [path.basename(filename), filename]));
  if (!expected.has(targetUnit)) throw new Error(`Unsupported Linux target unit: ${targetUnit}`);

  const readUnit = (unit) => parseSystemdProperties(
    query(["show", unit, `--property=${ACTIVATION_PROPERTIES.join(",")}`]),
    ACTIVATION_PROPERTIES,
    `Invalid Linux unit properties for ${unit}`
  );

  let listedUnits;
  try {
    listedUnits = JSON.parse(query([
      "list-units", "--all", "--output=json", "--no-pager", "--type=service", ...expected.keys(),
    ]));
  } catch (error) {
    throw new Error(`Linux unit inventory unavailable (${error.message}); refusing disruptive restart`);
  }
  if (!Array.isArray(listedUnits)) {
    throw new Error("Linux unit inventory unavailable; refusing disruptive restart");
  }
  const unitNames = new Set();
  for (const entry of listedUnits) {
    if (!expected.has(entry?.unit) || unitNames.has(entry.unit)) {
      throw new Error("Unexpected Linux unit inventory; refusing disruptive restart");
    }
    unitNames.add(entry.unit);
  }
  if (!beforeStart || fs.existsSync(expected.get(targetUnit))) {
    unitNames.add(targetUnit);
  }

  const unitPropsMap = new Map();
  for (const unit of unitNames) {
    const props = readUnit(unit);
    if (props.get("Id") !== unit) {
      throw new Error(`Linux unit identity mismatch for ${unit}; refusing disruptive restart`);
    }
    if (props.get("LoadState") === "loaded" && props.get("FragmentPath") !== expected.get(unit)) {
      throw new Error(`Linux unit ${unit} points to unowned fragment ${props.get("FragmentPath")}; refusing restart`);
    }
    unitPropsMap.set(unit, props);
  }

  const unsafeReasons = [];
  if (!beforeStart) {
    const targetProps = unitPropsMap.get(targetUnit);
    if (!targetProps || targetProps.get("LoadState") !== "loaded" ||
        targetProps.get("FragmentPath") !== expected.get(targetUnit)) {
      unsafeReasons.push(`Target unit ${targetUnit} is not loaded from its managed fragment`);
    } else if (targetProps.get("KillMode") !== "process") {
      unsafeReasons.push(`Target unit ${targetUnit} has KillMode=${targetProps.get("KillMode")}, expected process`);
    }
  }

  const candidateRoots = [root, ...paths.roots.filter((candidate) => candidate !== root)];
  const runningDaemons = [];
  for (const candidateRoot of candidateRoots) {
    const pidPath = assertNoLinks(path.join(candidateRoot, "daemon.pid"));
    if (!fs.existsSync(pidPath)) continue;
    const pid = Number(fs.readFileSync(pidPath, "utf8").trim());
    if (!Number.isSafeInteger(pid) || pid <= 0) {
      unsafeReasons.push("Malformed daemon PID; child preservation is unproven");
      continue;
    }
    let live;
    try {
      live = inspect(pid, "linux");
    } catch (error) {
      unsafeReasons.push(`Cannot inspect recorded daemon PID ${pid}: ${error.message}`);
      continue;
    }
    if (!live) continue;
    const pinPath = assertNoLinks(path.join(candidateRoot, "daemon-identity.json"));
    const pin = fs.existsSync(pinPath) ? JSON.parse(fs.readFileSync(pinPath, "utf8")) : null;
    const matchesPin = Boolean(
      pin && pin.pid === pid && pin.start === live.start && pin.executable === live.executable &&
      pin.command === live.command && JSON.stringify(pin.argv) === JSON.stringify(live.argv) &&
      paths.scripts.includes(pin.script) && commandIsDaemon(live, [pin.script])
    );
    if (matchesPin) {
      if (!runningDaemons.some((entry) => entry.pid === pid)) {
        runningDaemons.push({ root: candidateRoot, pid, live, pin });
      }
    } else if (commandIsDaemon(live, paths.scripts)) {
      unsafeReasons.push("Running Linux daemon lacks a matching creation-identity pin");
    }
  }
  if (runningDaemons.length > 1) {
    unsafeReasons.push("Multiple pinned Flock daemons are running; child preservation is unproven");
  }
  const pinnedDaemon = runningDaemons.length === 1 ? runningDaemons[0] : null;
  if (pinnedDaemon && pinnedDaemon.pid === process.pid) {
    throw new Error("Activator cannot terminate its own process");
  }

  let activeServiceUnit = null;
  const activeChildren = new Map();
  for (const [unit, props] of unitPropsMap.entries()) {
    const activeState = props.get("ActiveState");
    const mainPidRaw = props.get("MainPID");
    const controlGroup = props.get("ControlGroup");
    const isRunningOrTransitioning = activeState !== "inactive" || mainPidRaw !== "0";
    if (isRunningOrTransitioning) {
      if (props.get("LoadState") !== "loaded" || props.get("FragmentPath") !== expected.get(unit)) {
        throw new Error(`Active Linux unit ${unit} is not backed by its managed fragment; refusing restart`);
      }
      if (activeServiceUnit && activeServiceUnit !== unit) {
        unsafeReasons.push("Multiple Linux Flock units are active simultaneously; child preservation is unproven");
      } else {
        activeServiceUnit = unit;
      }
      const mainPid = Number(mainPidRaw);
      if (!Number.isSafeInteger(mainPid) || mainPid <= 0) {
        unsafeReasons.push(`Linux unit ${unit} is ${activeState} without a stable MainPID`);
      } else if (!pinnedDaemon || pinnedDaemon.pid !== mainPid) {
        unsafeReasons.push(`Active Linux unit ${unit} MainPID ${mainPid} does not match pinned daemon identity`);
      }
    }
    if (controlGroup !== "") {
      try {
        const cgroupPids = readCgroupProcs(controlGroup);
        for (const cgroupPid of cgroupPids) {
          if (pinnedDaemon && cgroupPid === pinnedDaemon.pid) continue;
          const childLive = inspect(cgroupPid, "linux");
          if (childLive) activeChildren.set(cgroupPid, childLive);
        }
      } catch (error) {
        unsafeReasons.push(`Cannot inspect cgroup processes for ${unit}: ${error.message}`);
      }
    }
  }

  let daemonCgroupInfo = null;
  if (pinnedDaemon) {
    try {
      daemonCgroupInfo = inspectLinuxUnifiedCgroup(pinnedDaemon.pid, { read: readCgroup, uid });
    } catch (error) {
      unsafeReasons.push(`Cannot inspect daemon cgroup: ${error.message}`);
    }
    if (daemonCgroupInfo) {
      if (!daemonCgroupInfo.ok) {
        unsafeReasons.push("Linux daemon unified cgroup v2 path is unavailable or malformed");
      } else if (daemonCgroupInfo.serviceUnits.some((svc) => !expected.has(svc)) ||
          (daemonCgroupInfo.serviceUnits.length > 0 && !daemonCgroupInfo.underUserManager) ||
          daemonCgroupInfo.serviceUnits.length > 1) {
        // Never disrupt a third-party or system service unit even if maintenanceConsent is supplied.
        throw new Error("Linux daemon resides in an unowned service cgroup; refusing restart");
      } else if (daemonCgroupInfo.serviceUnits.length === 1 &&
          daemonCgroupInfo.serviceUnits[0] !== activeServiceUnit) {
        unsafeReasons.push(`Daemon cgroup service ${daemonCgroupInfo.serviceUnits[0]} disagrees with systemd active unit state`);
      }
    }
  }

  const signaledPids = [];

  if (unsafeReasons.length > 0) {
    if (!consent) {
      throw new Error(`${unsafeReasons[0]}; refusing disruptive Linux daemon restart without explicit maintenance consent`);
    }
    if (pinnedDaemon && !activeServiceUnit) {
      if (JSON.stringify(inspect(pinnedDaemon.pid, "linux")) !== JSON.stringify(pinnedDaemon.live)) {
        throw new Error("Daemon process identity changed");
      }
      signaledPids.push(pinnedDaemon.pid);
      kill(pinnedDaemon.pid);
    }
    if (activeServiceUnit === "copilot-signalr-bridge.service" && targetUnit !== "copilot-signalr-bridge.service") {
      query(["stop", "copilot-signalr-bridge.service"]);
      query(["disable", "copilot-signalr-bridge.service"]);
    }
    if (beforeStart) await beforeStart();
    const refreshedTarget = readUnit(targetUnit);
    if (refreshedTarget.get("LoadState") !== "loaded" ||
        refreshedTarget.get("FragmentPath") !== expected.get(targetUnit)) {
      throw new Error(`Target unit ${targetUnit} is not loaded from its managed fragment`);
    }
    query(["restart", targetUnit]);
    let startedPid = 0;
    for (let attempt = 0; attempt < 30; attempt++) {
      const current = readUnit(targetUnit);
      const pid = Number(current.get("MainPID"));
      if (current.get("ActiveState") === "active" && Number.isSafeInteger(pid) && pid > 0) {
        startedPid = pid;
        break;
      }
      await delay(100);
    }
    if (!startedPid) throw new Error(`Linux unit ${targetUnit} did not report an active MainPID after restart`);
    if (waitForReady) await waitForReady({ pid: startedPid, unit: targetUnit });
    return {
      activated: true,
      mode: "maintenance-restart",
      unit: targetUnit,
      pid: startedPid,
      maintenanceConsentUsed: true,
      signaledPids,
      policyRestored: true,
      preservedChildren: [...activeChildren.values()].filter((child) => {
        try {
          const after = inspect(child.pid, "linux");
          return Boolean(after && after.start === child.start);
        } catch {
          return false;
        }
      }).map((child) => ({ pid: child.pid, start: child.start })),
    };
  }

  let policyRestored = true;
  if (pinnedDaemon && activeServiceUnit) {
    const activeUnitPath = expected.get(activeServiceUnit);
    const activeProps = unitPropsMap.get(activeServiceUnit);
    const originalPolicy = {
      KillMode: activeProps.get("KillMode"),
      Restart: activeProps.get("Restart"),
    };
    const dropInDir = `${activeUnitPath}.d`;
    const dropInPath = path.join(dropInDir, "90-flock-session-handoff.conf");
    assertNoLinks(dropInDir);
    assertNoLinks(dropInPath);
    const hadDropInDir = fs.existsSync(dropInDir);
    const previousDropIn = fs.existsSync(dropInPath) ? fs.readFileSync(dropInPath) : null;
    policyRestored = false;

    const restoreOriginalPolicy = () => {
      if (policyRestored) return;
      assertNoLinks(dropInDir);
      assertNoLinks(dropInPath);
      if (previousDropIn === null) {
        if (fs.existsSync(dropInPath)) fs.unlinkSync(dropInPath);
        if (!hadDropInDir && fs.existsSync(dropInDir) && fs.readdirSync(dropInDir).length === 0) {
          fs.rmdirSync(dropInDir);
        }
      } else {
        fs.mkdirSync(dropInDir, { recursive: true });
        fs.writeFileSync(dropInPath, previousDropIn);
      }
      query(["daemon-reload"]);
      if (fs.existsSync(activeUnitPath)) {
        const restoredProps = readUnit(activeServiceUnit);
        if (restoredProps.get("KillMode") !== originalPolicy.KillMode ||
            restoredProps.get("Restart") !== originalPolicy.Restart) {
          throw new Error(
            `Failed to restore original policy on ${activeServiceUnit} (got KillMode=${restoredProps.get("KillMode")}, Restart=${restoredProps.get("Restart")})`
          );
        }
      }
      policyRestored = true;
    };

    let primaryError = null;
    try {
      fs.mkdirSync(dropInDir, { recursive: true });
      fs.writeFileSync(dropInPath, "[Service]\nKillMode=process\nRestart=no\n", { encoding: "utf8", mode: 0o600 });
      query(["daemon-reload"]);
      const handoffProps = readUnit(activeServiceUnit);
      if (handoffProps.get("KillMode") !== "process" || handoffProps.get("Restart") !== "no") {
        throw new Error(
          `Linux unit ${activeServiceUnit} did not adopt session-preserving handoff policy (KillMode=${handoffProps.get("KillMode")}, Restart=${handoffProps.get("Restart")}); refusing disruptive Linux daemon restart without explicit maintenance consent`
        );
      }
      if (handoffProps.get("MainPID") !== String(pinnedDaemon.pid)) {
        throw new Error("Daemon MainPID changed before signalling; refusing restart");
      }
      assertLinuxDaemonCgroupSafe(pinnedDaemon.pid, {
        read: readCgroup,
        uid,
        allowedServices: [activeServiceUnit],
      });
      if (JSON.stringify(inspect(pinnedDaemon.pid, "linux")) !== JSON.stringify(pinnedDaemon.live)) {
        throw new Error("Daemon process identity changed");
      }
      signaledPids.push(pinnedDaemon.pid);
      kill(pinnedDaemon.pid);
      let stoppedUnitProps = null;
      for (let attempt = 0; attempt < 30; attempt++) {
        const afterProc = inspect(pinnedDaemon.pid, "linux");
        const procExited = !afterProc || afterProc.start !== pinnedDaemon.live.start;
        if (procExited) {
          const currentUnit = readUnit(activeServiceUnit);
          if (currentUnit.get("MainPID") === "0" &&
              ["inactive", "failed"].includes(currentUnit.get("ActiveState"))) {
            stoppedUnitProps = currentUnit;
            break;
          }
        }
        await delay(100);
      }
      if (!stoppedUnitProps) {
        throw new Error("Pinned Linux daemon did not stop cleanly; aborting activation");
      }
      restoreOriginalPolicy();
      if (stoppedUnitProps.get("ActiveState") === "failed") {
        try { query(["reset-failed", activeServiceUnit]); } catch {}
      }
      if (activeServiceUnit === "copilot-signalr-bridge.service" &&
          targetUnit !== "copilot-signalr-bridge.service") {
        query(["disable", "copilot-signalr-bridge.service"]);
        if (stoppedUnitProps.get("ControlGroup") === "" && fs.existsSync(activeUnitPath)) {
          assertNoLinks(activeUnitPath);
          fs.unlinkSync(activeUnitPath);
          query(["daemon-reload"]);
        }
      }
    } catch (error) {
      primaryError = error;
      throw error;
    } finally {
      if (!policyRestored) {
        try {
          restoreOriginalPolicy();
        } catch (restoreError) {
          if (!primaryError) throw restoreError;
          primaryError.restoreError = restoreError;
          primaryError.message = `${primaryError.message} (policy restore also failed: ${restoreError.message})`;
        }
      }
    }
  } else if (pinnedDaemon) {
    await stopPinnedDaemon(pinnedDaemon.root, paths, {
      inspect: (pid) => inspect(pid, "linux"),
      kill: (pid) => { signaledPids.push(pid); kill(pid); },
      delay,
      checkLinuxCgroup: (pid) => assertLinuxDaemonCgroupSafe(pid, { read: readCgroup, uid }),
    });
  }

  if (beforeStart) await beforeStart();

  const finalTargetProps = readUnit(targetUnit);
  if (finalTargetProps.get("LoadState") !== "loaded" ||
      finalTargetProps.get("FragmentPath") !== expected.get(targetUnit)) {
    throw new Error(`Target unit ${targetUnit} is not loaded from its managed fragment`);
  }
  if (finalTargetProps.get("KillMode") !== "process") {
    throw new Error(
      `Target unit ${targetUnit} has KillMode=${finalTargetProps.get("KillMode")}, expected process; refusing activation`
    );
  }

  query(["start", targetUnit]);
  let newMainPid = 0;
  for (let attempt = 0; attempt < 30; attempt++) {
    const current = readUnit(targetUnit);
    const pid = Number(current.get("MainPID"));
    if (current.get("ActiveState") === "active" && Number.isSafeInteger(pid) && pid > 0 &&
        (!pinnedDaemon || pid !== pinnedDaemon.pid ||
          inspect(pid, "linux")?.start !== pinnedDaemon.live.start)) {
      newMainPid = pid;
      break;
    }
    await delay(100);
  }
  if (!newMainPid) {
    throw new Error(`Linux unit ${targetUnit} did not report an active new MainPID`);
  }
  if (waitForReady) {
    await waitForReady({ pid: newMainPid, unit: targetUnit });
  }

  const preservedChildren = [];
  for (const [childPid, beforeChild] of activeChildren.entries()) {
    const afterChild = inspect(childPid, "linux");
    if (afterChild && afterChild.pid === beforeChild.pid && afterChild.start === beforeChild.start) {
      preservedChildren.push({ pid: childPid, start: afterChild.start });
    }
  }

  return {
    activated: true,
    mode: pinnedDaemon ? "restarted-session-preserving" : "started",
    unit: targetUnit,
    pid: newMainPid,
    maintenanceConsentUsed: false,
    signaledPids,
    policyRestored,
    preservedChildren,
  };
}

export function assertLinuxUnitsQuiescent(paths, {
  query = queryUserSystemd, inspect = inspectProcess, checkCgroup = assertLinuxDaemonCgroupSafe,
} = {}) {
  if (paths.platform !== "linux") return;
  const expected = new Map(paths.persistence.map((filename) => [path.basename(filename), filename]));
  const units = JSON.parse(query(["list-units", "--all", "--output=json", "--no-pager",
    "--type=service", ...expected.keys()]));
  if (!Array.isArray(units)) throw new Error("Linux unit inventory unavailable; installation retained");
  const seen = new Set();
  for (const unit of units) {
    if (!expected.has(unit?.unit) || seen.has(unit.unit)) {
      throw new Error("Unexpected Linux unit inventory; installation retained");
    }
    seen.add(unit.unit);
    const properties = new Map();
    for (const line of query(["show", unit.unit,
      "--property=Id,LoadState,FragmentPath,ActiveState,MainPID,ControlGroup"]).trim().split("\n")) {
      const separator = line.indexOf("=");
      const key = line.slice(0, separator);
      if (separator < 1 || properties.has(key)) throw new Error("Invalid Linux unit properties; installation retained");
      properties.set(key, line.slice(separator + 1));
    }
    if (properties.get("Id") !== unit.unit || properties.get("LoadState") !== "loaded" ||
        properties.get("FragmentPath") !== expected.get(unit.unit) ||
        properties.get("ActiveState") !== "inactive" || properties.get("MainPID") !== "0" ||
        properties.get("ControlGroup") !== "") {
      throw new Error(`Linux unit ${unit.unit} is active or child preservation is unproven; installation retained`);
    }
  }
  for (const root of paths.roots) {
    const filename = assertNoLinks(path.join(root, "daemon.pid"));
    if (!fs.existsSync(filename)) continue;
    const pid = Number(fs.readFileSync(filename, "utf8").trim());
    if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error("Malformed daemon PID; installation retained");
    const live = inspect(pid, "linux");
    if (live && commandIsDaemon(live, paths.scripts)) checkCgroup(pid);
  }
}

export async function disablePersistence(filename, paths, { query = queryUserSystemd } = {}) {
  if (paths.platform === "linux") {
    assertLinuxUnitsQuiescent(paths, { query });
    query(["disable", path.basename(filename)]);
  } else if (paths.platform === "darwin") {
    execFileSync("launchctl", ["bootout", `gui/${process.getuid()}`, filename],
      { timeout: 6000, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  }
}

export async function removeOwnedScheduledTasks(paths) {
  if (paths.platform !== "win32") return [];
  const taskNames = ["CopilotFlock", "Copilot Flock", "CopilotSignalRBridge", "Copilot SignalR Bridge"];
  const script = `$ErrorActionPreference='Stop'
$names=ConvertFrom-Json $env:FLOCK_TASK_NAMES
$scripts=ConvertFrom-Json $env:FLOCK_TASK_SCRIPTS
$results=@()
$tasks=@(Get-ScheduledTask | Where-Object { $_.TaskName -in $names })
foreach($task in $tasks) {
  $actions=@($task.Actions)
  $owned=$false
  if($actions.Count -eq 1 -and $actions[0].Execute -eq $env:FLOCK_NODE) {
    foreach($s in $scripts) {
      if($actions[0].Arguments -ceq ('"'+$s+'" daemon') -or $actions[0].Arguments -ceq ($s+' daemon')) { $owned=$true }
    }
  }
  if($owned) {
    # Re-read the action before unregistering the exact task.
    $fresh=Get-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName
    if(($fresh.Actions|ConvertTo-Json -Compress) -cne ($task.Actions|ConvertTo-Json -Compress)) { throw 'Scheduled task action changed' }
    Unregister-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -Confirm:$false
    $results+=@{path=('ScheduledTask:'+ $task.TaskPath + $task.TaskName);removed=$true}
  } else { $results+=@{path=('ScheduledTask:'+ $task.TaskPath + $task.TaskName);removed=$false;reason='Task ownership unproven; preserved'} }
}
ConvertTo-Json -InputObject @($results) -Compress`;
  const output = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    env: { ...process.env, FLOCK_TASK_NAMES: JSON.stringify(taskNames), FLOCK_TASK_SCRIPTS: JSON.stringify(paths.scripts),
      FLOCK_NODE: process.execPath },
    encoding: "utf8", windowsHide: true, timeout: 15000, stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(output);
}

export function findRuntimeClients(paths, {
  inspect = inspectProcess, readdir = fs.readdirSync, stat = fs.statSync, uid = process.getuid?.(),
} = {}) {
  const scripts = paths.scripts;
  if (paths.platform === "win32") {
    const output = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `
$ErrorActionPreference='Stop'
$scripts=ConvertFrom-Json $env:FLOCK_RUNTIME_SCRIPTS
$found=@()
foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='node.exe'")) {
  if($p.ProcessId -eq $env:FLOCK_SELF_PID) { continue }
  foreach($s in $scripts) {
    if($p.CommandLine -and $p.CommandLine.Contains($s)) {
      $found+=@{pid=$p.ProcessId;reason='Runtime-referencing Node process has no uninstaller creation-identity proof'}
      break
    }
  }
}
ConvertTo-Json -InputObject @($found) -Compress`], {
      env: { ...process.env, FLOCK_RUNTIME_SCRIPTS: JSON.stringify(scripts), FLOCK_SELF_PID: String(process.pid) },
      encoding: "utf8", windowsHide: true, timeout: 15000, stdio: ["ignore", "pipe", "pipe"],
    });
    return JSON.parse(output);
  }
  if (!Number.isSafeInteger(uid) || uid < 0) throw new Error("Cannot establish process ownership for runtime cleanup");
  const pids = paths.platform === "linux" ? readdir("/proc").filter((id) => /^\d+$/.test(id)).map(Number)
    : execFileSync("ps", ["-axo", "uid=,pid="], { encoding: "utf8", timeout: 5000, windowsHide: true }).split("\n")
      .map((line) => /^\s*(\d+)\s+(\d+)\s*$/.exec(line)).filter((match) => match && Number(match[1]) === uid)
      .map((match) => Number(match[2]));
  const results = [];
  for (const pid of pids) {
    if (pid === process.pid) continue;
    let identity;
    try {
      if (paths.platform === "linux") {
        const owner = stat(`/proc/${pid}`).uid;
        if (!Number.isSafeInteger(owner) || owner < 0) throw new Error("Process ownership unavailable; runtime retained");
        if (owner !== uid) continue;
      }
      identity = inspect(pid, paths.platform);
    } catch (error) {
      if (error.code === "ESRCH" || error.code === "ENOENT") continue;
      if (error.code === "EACCES" || error.code === "EPERM") {
        results.push({ pid, reason: "Process ownership or identity is uninspectable; runtime retained" });
        continue;
      }
      throw error;
    }
    if (identity && (identity.argv?.some((arg) => scripts.includes(arg)) ||
        scripts.some((script) => identity.command?.includes(script)))) {
      results.push({ pid, reason: "Runtime-referencing process requires creation-identity proof before termination" });
    }
  }
  return results;
}

export async function uninstallFlock({
  paths = lifecyclePaths(), leave, inventory, brokerFreeLeave, localOnly = false, approveLocalOnly = false,
  stopDaemon = stopPinnedDaemon, disable = disablePersistence, removeTasks = removeOwnedScheduledTasks,
  findProcesses = findRuntimeClients, checkPersistence = assertLinuxUnitsQuiescent,
} = {}) {
  if (localOnly && !approveLocalOnly) throw new Error("Local-only removal requires explicit approval; remote membership will remain");
  const report = { ok: false, fullyRemoved: false, localOnly, removed: [], retained: [], pending: [], preserved:
    ["Copilot conversations, session-state, chats and data.db", "source checkouts, backups and OS audit logs"] };
  const installations = [];
  for (const root of paths.roots) {
    assertNoLinks(root);
    if (!fs.existsSync(root)) continue;
    if (fs.existsSync(path.join(root, ".git"))) throw new Error(`Refusing source checkout cleanup: ${root}`);
    const owned = ["flock.mjs", "bridge.mjs"].some((name) => {
      const script = path.join(root, name);
      assertNoLinks(script);
      return fs.existsSync(script) && /export const BRIDGE_VERSION =/.test(fs.readFileSync(script, "utf8")) &&
        /export async function runDaemon/.test(fs.readFileSync(script, "utf8"));
    });
    if (!owned) { report.retained.push({ path: root, reason: "Installation ownership unproven" }); continue; }
    const read = (name, fallback) => {
      const filename = path.join(root, name);
      assertNoLinks(filename);
      return fs.existsSync(filename) ? JSON.parse(fs.readFileSync(filename, "utf8")) : fallback;
    };
    const config = read("config.json", {});
    const identity = read("identity.json", null);
    const flocks = read("flocks.json", { flocks: {} }).flocks;
    const brokerFree = read("broker-free.json", null);
    const ownedRuntimeFiles = [...runtimeFiles];
    if (brokerFree) {
      if (brokerFree.schema !== 34 || !brokerFree.flocks || config.protocol !== "broker-free-v34") {
        report.pending.push({ path: root, reason: "Broker-free state/config must be reconciled before removal" });
      } else {
        for (const id of Object.keys(brokerFree.flocks)) {
          for (const prefix of ["epoch", "replay", "responses"]) ownedRuntimeFiles.push(`${prefix}-${hash(id)}.json`);
        }
        try {
          if (localOnly) {
            for (const record of Object.values(brokerFree.flocks).filter((record) => !record.departed)) {
              report.pending.push({ flockId: record.flockId, reason: "Explicit local-only removal; remote leave unconfirmed" });
            }
          } else {
            if (!brokerFreeLeave) throw new Error("Authorized owner-mediated leave unavailable");
            const results = await brokerFreeLeave({ root, config });
            if (!Array.isArray(results)) throw new Error("Broker-free leave results unconfirmed");
            for (const record of Object.values(brokerFree.flocks).filter((record) => !record.departed)) {
              if (!results.some((result) => result.flockId === record.flockId && result.confirmed === true)) {
                report.pending.push({ flockId: record.flockId,
                  reason: results.find((result) => result.flockId === record.flockId)?.error || "Owner acknowledgment pending" });
              }
            }
            const latest = read("broker-free.json", null);
            if (Object.keys(latest?.pendingJoins || {}).length) {
              report.pending.push({ path: root, reason: "Unaccepted Join Codes may have owner-side approvals/subscriptions; retain identities until owner cleanup is confirmed" });
            }
          }
        } catch (error) { report.pending.push({ path: root, reason: error.message }); }
      }
    } else if (config.protocol === "broker-free-v34") {
      report.pending.push({ path: root, reason: "Missing broker-free membership state; cannot prove all flocks left" });
    }
    if (config.protocol !== "broker-free-v34" && inventory && !localOnly && identity?.privateKey && config.machineId) {
      try {
        const request = signLeave({ flockId: "*", deviceId: identity.fingerprint,
          machineId: config.machineId }, identity.privateKey);
        const remote = await inventory({ config, request, root });
        if (remote?.ok !== true || !Array.isArray(remote.flockIds) ||
            remote.flockIds.some((id) => typeof id !== "string" || !id || id.length > 512)) throw new Error("Remote membership inventory unconfirmed");
        for (const id of remote.flockIds) flocks[id] ||= {};
        atomicJson(path.join(root, "flocks.json"), { flocks });
      } catch (error) {
        report.pending.push({ path: root, reason: error.message });
      }
    }
    const journal = read("uninstall-progress.json", { type: "copilot-flock-uninstall-v1", leaves: {} });
    if (journal.type !== "copilot-flock-uninstall-v1") throw new Error("Invalid uninstall journal");
    for (const [flockId, flock] of Object.entries(config.protocol === "broker-free-v34" ? {} : flocks)) {
      if (localOnly) { report.pending.push({ flockId, reason: "Explicit local-only removal; remote leave unconfirmed" }); continue; }
      const previous = journal.leaves[flockId];
      if (previous?.confirmed) continue;
      if (!identity?.privateKey || !config.machineId) {
        report.pending.push({ flockId, reason: "Device identity unavailable" }); continue;
      }
      const request = signLeave({
        flockId, deviceId: identity.fingerprint, machineId: config.machineId,
        ...(previous?.request ? { requestId: previous.request.requestId } : {}),
      }, identity.privateKey);
      journal.leaves[flockId] = { request, confirmed: false };
      atomicJson(path.join(root, "uninstall-progress.json"), journal);
      try {
        if (!leave) throw new Error("Authenticated leave transport unavailable");
        const response = await leave({ config, flock, request, root });
        if (response?.confirmed !== true || response.flockId !== flockId) throw new Error("Owner/broker has not acknowledged roster removal and targeted subscription deletion");
        journal.leaves[flockId].confirmed = true;
      } catch (error) {
        report.pending.push({ flockId, reason: error.message });
      }
      atomicJson(path.join(root, "uninstall-progress.json"), journal);
    }
    if (config.protocol !== "broker-free-v34" && !Object.keys(flocks).length && (config.bootstrapUrl || config.connectionString) && !localOnly) {
      report.pending.push({ path: root, reason: "Legacy membership inventory is unavailable; cannot prove all flocks left" });
    }
    installations.push({ root, ownedRuntimeFiles, manifest: read("installation.json", { artifacts: {} }) });
  }
  if (report.pending.length && !localOnly) {
    report.retained.push(...installations.map(({ root }) => ({ path: root, reason: "Retained credentials and leave journal for retry" })));
    return report;
  }
  // Preflight links before stopping processes or changing any shared configuration.
  for (const filename of [...paths.skills, ...paths.persistence, ...paths.configs.map((config) => config.path)]) assertNoLinks(filename);
  for (const { root, ownedRuntimeFiles, manifest } of installations) {
    for (const filename of ownedRuntimeFiles) {
      const target = assertNoLinks(path.join(root, filename));
      if (filename.endsWith(".mjs") && fs.existsSync(target)) {
        if (!fs.lstatSync(target).isFile() || manifest.type !== "copilot-flock-installation-v1" ||
            manifest.artifacts?.[target] !== hash(fs.readFileSync(target))) {
          report.retained.push({ path: target, reason: "Runtime script ownership hash missing or changed; installation retained" });
        }
      }
    }
  }
  if (report.retained.some(({ path: filename }) => paths.roots.some((root) => filename === root || filename.startsWith(root + path.sep)))) return report;
  if (installations.length) {
    try { await checkPersistence(paths); }
    catch (error) {
      report.retained.push(...installations.map(({ root }) => ({ path: root, reason: error.message })));
      return report;
    }
  }
  if (installations.length) {
    try {
      for (const result of await removeTasks(paths)) {
        if (result.removed) report.removed.push(result.path);
        else report.retained.push({ path: result.path, reason: result.reason });
      }
    } catch (error) {
      report.retained.push({ path: "ScheduledTasks", reason: error.message });
      return report;
    }
  }
  for (const filename of [...paths.persistence, ...paths.skills]) {
    if (!fs.existsSync(filename)) continue;
    const text = fs.readFileSync(filename, "utf8");
    const owned = installations.some(({ manifest }) => manifest.artifacts?.[filename] === hash(Buffer.from(text))) ||
      legacyArtifactOwned(filename, text, paths);
    if (!owned) { report.retained.push({ path: filename, reason: "Unknown or modified artifact; preserved" }); continue; }
    try {
      if (paths.persistence.includes(filename)) await disable(filename, paths);
      assertNoLinks(filename);
      if (fs.readFileSync(filename, "utf8") !== text) throw new Error("Artifact changed during removal");
      fs.unlinkSync(filename);
      report.removed.push(filename);
      if (paths.skills.includes(filename)) {
        const stop = paths.roots.find((root) => filename.startsWith(root + path.sep)) ||
          path.dirname(path.dirname(filename));
        removeEmptyParents(filename, stop);
      }
    } catch (error) {
      report.retained.push({ path: filename, reason: error.message });
      if (paths.persistence.includes(filename)) return report;
    }
  }
  if (report.retained.some(({ path: filename }) => paths.persistence.includes(filename))) return report;
  for (const { root } of installations) {
    try {
      await checkPersistence(paths);
      await stopDaemon(root, paths);
    }
    catch (error) { report.retained.push({ path: root, reason: error.message }); return report; }
  }
  if (installations.length) {
    try {
      const clients = await findProcesses(paths);
      if (clients.length) {
        report.retained.push(...clients.map((client) => ({ path: `Process:${client.pid}`, reason: client.reason })));
        return report;
      }
    } catch (error) {
      report.retained.push({ path: "RuntimeProcesses", reason: error.message });
      return report;
    }
  }
  for (const config of paths.configs) {
    try { removeMcp(config, paths.scripts, report.removed); }
    catch (error) { report.retained.push({ path: config.path, reason: error.message }); }
  }
  if (report.retained.some(({ path: filename }) => paths.configs.some((config) => config.path === filename))) return report;
  for (const { root, ownedRuntimeFiles, manifest } of installations) {
    // Unknown files are never erased, even inside a dedicated runtime directory.
    for (const filename of ownedRuntimeFiles.filter((name) => name !== "flock.mjs" && name !== "bridge.mjs" && name !== "installation.json")
      .concat(["bridge.mjs", "flock.mjs", "installation.json"])) {
      const target = path.join(root, filename);
      assertNoLinks(target);
      if (!fs.existsSync(target)) continue;
      if (!fs.lstatSync(target).isFile()) { report.retained.push({ path: target, reason: "Unexpected non-file" }); continue; }
      if (filename.endsWith(".mjs") && manifest.artifacts?.[target] !== hash(fs.readFileSync(target))) {
        report.retained.push({ path: target, reason: "Runtime script changed during cleanup; preserved" });
        continue;
      }
      if (filename === "installation.json" && report.retained.some(({ path: retained }) => retained.startsWith(root + path.sep))) continue;
      fs.unlinkSync(target);
      report.removed.push(target);
    }
    if (!fs.readdirSync(root).length) fs.rmdirSync(root);
    else report.retained.push({ path: root, reason: "Unrecognized files preserved" });
  }
  report.fullyRemoved = !report.pending.length && !report.retained.length;
  report.ok = report.fullyRemoved || (localOnly && !report.retained.length);
  return report;
}

function runtimeError(code, message, extra = {}) {
  const err = new Error(message);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

export function hashRuntimeModule(data) {
  const text = Buffer.isBuffer(data) ? data.toString("utf8") : String(data);
  return hash(Buffer.from(text.replace(/\r\n/g, "\n"), "utf8"));
}

const REGEX_PREFIX_KEYWORDS = new Set([
  "return", "throw", "case", "delete", "void", "typeof", "instanceof",
  "in", "of", "new", "yield", "await", "else", "do",
]);

function canStartRegexLiteral(prevToken) {
  if (!prevToken) return true;
  if (prevToken.type === "ident") return REGEX_PREFIX_KEYWORDS.has(prevToken.value);
  if (prevToken.type === "punct") {
    return prevToken.value !== ")" && prevToken.value !== "]" &&
      prevToken.value !== "++" && prevToken.value !== "--";
  }
  return false;
}

function tokenizeJsForImports(source) {
  const tokens = [];
  const len = source.length;
  let i = 0;
  const templateBraceStack = [];

  const lastToken = () => (tokens.length > 0 ? tokens[tokens.length - 1] : null);

  const readString = (quote) => {
    i++;
    let out = "";
    while (i < len) {
      const ch = source[i++];
      if (ch === "\\") {
        if (i < len) out += source[i++];
        continue;
      }
      if (ch === quote) return out;
      out += ch;
    }
    return out;
  };

  const skipTemplateChunk = () => {
    while (i < len) {
      const ch = source[i++];
      if (ch === "\\") {
        if (i < len) i++;
        continue;
      }
      if (ch === "`") {
        tokens.push({ type: "template", value: "`" });
        return;
      }
      if (ch === "$" && source[i] === "{") {
        i++;
        templateBraceStack.push(0);
        tokens.push({ type: "punct", value: "${" });
        return;
      }
    }
    tokens.push({ type: "template", value: "`" });
  };

  while (i < len) {
    const ch = source[i];
    if (ch <= " ") {
      i++;
      continue;
    }
    if (ch === "/" && source[i + 1] === "/") {
      i += 2;
      while (i < len && source[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && source[i + 1] === "*") {
      i += 2;
      while (i < len && !(source[i] === "*" && source[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"') {
      const val = readString(ch);
      tokens.push({ type: "string", value: val });
      continue;
    }
    if (ch === "`") {
      i++;
      skipTemplateChunk();
      continue;
    }
    if (ch === "}" && templateBraceStack.length > 0 && templateBraceStack[templateBraceStack.length - 1] === 0) {
      templateBraceStack.pop();
      i++;
      skipTemplateChunk();
      continue;
    }
    if (ch === "/" && canStartRegexLiteral(lastToken())) {
      i++;
      let inClass = false;
      while (i < len) {
        const rc = source[i++];
        if (rc === "\\") {
          if (i < len) i++;
          continue;
        }
        if (rc === "[") inClass = true;
        else if (rc === "]") inClass = false;
        else if (rc === "/" && !inClass) break;
        else if (rc === "\n" && !inClass) break;
      }
      while (i < len && /[a-z]/i.test(source[i])) i++;
      tokens.push({ type: "regex", value: "//" });
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let start = i++;
      while (i < len && /[A-Za-z0-9_$]/.test(source[i])) i++;
      tokens.push({ type: "ident", value: source.slice(start, i) });
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let start = i++;
      while (i < len && /[A-Za-z0-9_.]/.test(source[i])) i++;
      tokens.push({ type: "number", value: source.slice(start, i) });
      continue;
    }
    if (ch === "{") {
      if (templateBraceStack.length > 0) templateBraceStack[templateBraceStack.length - 1]++;
      tokens.push({ type: "punct", value: "{" });
      i++;
      continue;
    }
    if (ch === "}") {
      if (templateBraceStack.length > 0) templateBraceStack[templateBraceStack.length - 1]--;
      tokens.push({ type: "punct", value: "}" });
      i++;
      continue;
    }
    if ((ch === "+" && source[i + 1] === "+") || (ch === "-" && source[i + 1] === "-")) {
      tokens.push({ type: "punct", value: source.slice(i, i + 2) });
      i += 2;
      continue;
    }
    tokens.push({ type: "punct", value: ch });
    i++;
  }
  return tokens;
}

export function extractRelativeModuleImports(sourceText) {
  const tokens = tokenizeJsForImports(String(sourceText));
  const found = new Set();
  const recordSpec = (spec) => {
    if (typeof spec === "string" && (spec.startsWith("./") || spec.startsWith("../"))) {
      found.add(spec);
    }
  };

  let braceDepth = 0;
  let parenDepth = 0;
  for (let idx = 0; idx < tokens.length; idx++) {
    const tok = tokens[idx];
    if (tok.type === "punct") {
      if (tok.value === "{" || tok.value === "${") braceDepth++;
      else if (tok.value === "}") braceDepth = Math.max(0, braceDepth - 1);
      else if (tok.value === "(") parenDepth++;
      else if (tok.value === ")") parenDepth = Math.max(0, parenDepth - 1);
      continue;
    }

    if (tok.type === "ident" && tok.value === "import") {
      const next = tokens[idx + 1];
      if (next?.type === "punct" && next.value === "(") {
        const arg = tokens[idx + 2];
        if (arg?.type === "string") recordSpec(arg.value);
        continue;
      }
      if (braceDepth === 0 && parenDepth === 0) {
        if (next?.type === "string") {
          recordSpec(next.value);
          continue;
        }
        let localBraces = 0;
        for (let j = idx + 1; j < tokens.length; j++) {
          const t = tokens[j];
          if (t.type === "punct" && t.value === "{") localBraces++;
          else if (t.type === "punct" && t.value === "}") localBraces = Math.max(0, localBraces - 1);
          else if (localBraces === 0 && t.type === "punct" && t.value === ";") break;
          else if (localBraces === 0 && t.type === "ident" && t.value === "from" && tokens[j + 1]?.type === "string") {
            recordSpec(tokens[j + 1].value);
            break;
          }
        }
      }
      continue;
    }

    if (tok.type === "ident" && tok.value === "export" && braceDepth === 0 && parenDepth === 0) {
      const next = tokens[idx + 1];
      if (next?.type === "punct" && (next.value === "{" || next.value === "*")) {
        let localBraces = 0;
        for (let j = idx + 1; j < tokens.length; j++) {
          const t = tokens[j];
          if (t.type === "punct" && t.value === "{") localBraces++;
          else if (t.type === "punct" && t.value === "}") localBraces = Math.max(0, localBraces - 1);
          else if (localBraces === 0 && t.type === "punct" && t.value === ";") break;
          else if (localBraces === 0 && t.type === "ident" && t.value === "from" && tokens[j + 1]?.type === "string") {
            recordSpec(tokens[j + 1].value);
            break;
          }
          if (localBraces === 0 && t.type === "ident" && ["function", "class", "const", "let", "var", "async", "default"].includes(t.value)) {
            break;
          }
        }
      }
    }
  }
  return Array.from(found).sort();
}

export function extractEntrypointVersion(sourceText) {
  const m = String(sourceText).match(/export\s+const\s+BRIDGE_VERSION\s*=\s*(["'])([^"']+)\1/);
  return m ? m[2] : null;
}

export function computeManifestDigest(manifest) {
  const sortedEntrypoints = [...(manifest.entrypoints || [])].sort();
  const sortedFiles = Object.keys(manifest.files || {}).sort().map((name) => {
    const entry = manifest.files[name];
    return [
      name,
      entry.role || "companion",
      entry.sha256,
      [...(entry.imports || [])].sort(),
    ];
  });
  return hash(JSON.stringify([
    "copilot-flock-runtime-manifest-v1",
    manifest.version,
    sortedEntrypoints,
    sortedFiles,
  ]));
}

export function computeActualFilesDigest(fileHashes) {
  const entries = Object.keys(fileHashes || {}).sort().map((name) => [name, fileHashes[name]]);
  return entries.length > 0 ? hash(JSON.stringify(["copilot-flock-runtime-files-v1", entries])) : null;
}

function freezeManifest(manifest) {
  if (!manifest || typeof manifest !== "object") return manifest;
  const cloneFiles = {};
  for (const name of Object.keys(manifest.files || {}).sort()) {
    const entry = manifest.files[name];
    cloneFiles[name] = Object.freeze({
      role: entry.role,
      sha256: entry.sha256,
      imports: Object.freeze([...(entry.imports || [])]),
    });
  }
  return Object.freeze({
    type: manifest.type,
    schema: manifest.schema ?? 1,
    version: manifest.version,
    entrypoints: Object.freeze([...(manifest.entrypoints || [])]),
    files: Object.freeze(cloneFiles),
    manifestDigest: manifest.manifestDigest,
  });
}

export function computeRuntimeManifest(sourceDir, {
  version = null,
  entrypoints = REQUIRED_RUNTIME_ENTRYPOINTS,
  requiredModules = REQUIRED_RUNTIME_MODULES,
} = {}) {
  const resolvedSource = assertNoLinks(sourceDir);
  const queue = [...new Set([...entrypoints, ...requiredModules])];
  const seen = new Set();
  const files = {};
  const entrypointSet = new Set(entrypoints);
  const detectedVersions = new Set();

  while (queue.length > 0) {
    const filename = queue.shift();
    if (seen.has(filename)) continue;
    seen.add(filename);
    if (!/^[A-Za-z0-9._-]+\.mjs$/.test(filename)) {
      throw runtimeError("RUNTIME_MANIFEST_INVALID", `Unsafe runtime module filename: ${filename}`);
    }
    const fullPath = assertNoLinks(path.join(resolvedSource, filename));
    if (!fs.existsSync(fullPath) || !fs.lstatSync(fullPath).isFile()) {
      throw runtimeError("RUNTIME_MODULE_MISSING", `Missing required runtime module: ${filename}`, { module: filename });
    }
    const bytes = fs.readFileSync(fullPath);
    const text = bytes.toString("utf8");
    if (entrypointSet.has(filename)) {
      const epVer = extractEntrypointVersion(text);
      if (epVer) detectedVersions.add(epVer);
    }
    const imports = extractRelativeModuleImports(text);
    for (const spec of imports) {
      const targetFull = path.resolve(resolvedSource, spec);
      if (path.dirname(targetFull) !== resolvedSource) {
        throw runtimeError("RUNTIME_PATH_ESCAPE", `Relative import '${spec}' in ${filename} escapes runtime root`);
      }
      const depName = path.basename(targetFull);
      if (!seen.has(depName)) queue.push(depName);
    }
    files[filename] = {
      role: entrypointSet.has(filename) ? "entrypoint" : "companion",
      sha256: hashRuntimeModule(bytes),
      imports,
    };
  }

  if (detectedVersions.size > 1) {
    throw runtimeError(
      "RUNTIME_VERSION_MISMATCH",
      `Entrypoint version mismatch across entrypoints: ${Array.from(detectedVersions).join(", ")}`
    );
  }
  const resolvedVersion = version || (detectedVersions.size === 1 ? Array.from(detectedVersions)[0] : null);
  if (!resolvedVersion || typeof resolvedVersion !== "string") {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", "Could not determine runtime version for manifest");
  }

  const sortedFiles = {};
  for (const key of Object.keys(files).sort()) sortedFiles[key] = files[key];

  const manifest = {
    type: "copilot-flock-runtime-manifest-v1",
    schema: 1,
    version: resolvedVersion,
    entrypoints: [...entrypoints],
    files: sortedFiles,
  };
  manifest.manifestDigest = computeManifestDigest(manifest);
  return freezeManifest(manifest);
}

export function validateRuntimeManifest(manifest, {
  expectedVersion = null,
  entrypoints = REQUIRED_RUNTIME_ENTRYPOINTS,
  requiredModules = REQUIRED_RUNTIME_MODULES,
} = {}) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", "Runtime manifest must be a JSON object");
  }
  if (manifest.type !== "copilot-flock-runtime-manifest-v1") {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", `Invalid runtime manifest type: ${manifest.type}`);
  }
  if (typeof manifest.version !== "string" || !manifest.version.trim()) {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", "Runtime manifest is missing a valid version string");
  }
  if (expectedVersion !== null && manifest.version !== expectedVersion) {
    throw runtimeError(
      "RUNTIME_MANIFEST_VERSION_MISMATCH",
      `Runtime manifest version '${manifest.version}' does not match expected '${expectedVersion}'`
    );
  }
  if (!Array.isArray(manifest.entrypoints) || manifest.entrypoints.length === 0) {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", "Runtime manifest must list entrypoints");
  }
  for (const ep of entrypoints) {
    if (!manifest.entrypoints.includes(ep)) {
      throw runtimeError("RUNTIME_MODULE_MISSING", `Runtime manifest is missing required entrypoint '${ep}'`, { module: ep });
    }
  }
  if (!manifest.files || typeof manifest.files !== "object" || Array.isArray(manifest.files)) {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", "Runtime manifest is missing files map");
  }
  for (const [name, entry] of Object.entries(manifest.files)) {
    if (!/^[A-Za-z0-9._-]+\.mjs$/.test(name)) {
      throw runtimeError("RUNTIME_MANIFEST_INVALID", `Unsafe filename in runtime manifest: ${name}`);
    }
    if (!entry || typeof entry !== "object" || typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
      throw runtimeError("RUNTIME_MANIFEST_INVALID", `Invalid SHA-256 digest for '${name}' in runtime manifest`);
    }
    if (entry.imports !== undefined && (!Array.isArray(entry.imports) || entry.imports.some((s) => typeof s !== "string"))) {
      throw runtimeError("RUNTIME_MANIFEST_INVALID", `Invalid imports list for '${name}' in runtime manifest`);
    }
  }
  for (const reqModule of [...new Set([...entrypoints, ...requiredModules])]) {
    if (!Object.prototype.hasOwnProperty.call(manifest.files, reqModule)) {
      throw runtimeError(
        "RUNTIME_MODULE_MISSING",
        `Runtime manifest omits required module '${reqModule}'`,
        { module: reqModule }
      );
    }
  }
  if (typeof manifest.manifestDigest !== "string" || !/^[a-f0-9]{64}$/.test(manifest.manifestDigest)) {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", "Runtime manifest is missing a valid manifestDigest");
  }
  const recomputed = computeManifestDigest(manifest);
  if (manifest.manifestDigest !== recomputed) {
    throw runtimeError(
      "RUNTIME_HASH_MISMATCH",
      `Runtime manifestDigest mismatch: expected ${recomputed}, got ${manifest.manifestDigest}`
    );
  }
  return freezeManifest(manifest);
}

export function loadRuntimeManifest(dir, options = {}) {
  const resolvedDir = assertNoLinks(dir);
  const manifestPath = assertNoLinks(path.join(resolvedDir, RUNTIME_MANIFEST_FILENAME));
  if (!fs.existsSync(manifestPath) || !fs.lstatSync(manifestPath).isFile()) {
    throw runtimeError("RUNTIME_MANIFEST_MISSING", `Missing ${RUNTIME_MANIFEST_FILENAME} in ${resolvedDir}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch (err) {
    throw runtimeError("RUNTIME_MANIFEST_INVALID", `Invalid JSON in ${manifestPath}: ${err.message}`);
  }
  return validateRuntimeManifest(parsed, options);
}

const EMBEDDED_RUNTIME_MANIFEST_FALLBACK = (() => {
  let selfSha = "0".repeat(64);
  try {
    selfSha = hashRuntimeModule(fs.readFileSync(fileURLToPath(import.meta.url)));
  } catch {}
  const entrypointSha = "6e75ab4bfbc6ee5bcac178a5fd337bc39a4ae22875b756ad6cf2b13844b121bf";
  const fallback = {
    type: "copilot-flock-runtime-manifest-v1",
    schema: 1,
    version: "3.5.0",
    entrypoints: ["flock.mjs", "bridge.mjs"],
    files: {
      "bridge.mjs": {
        role: "entrypoint",
        sha256: entrypointSha,
        imports: [
          "./flock-broker-free.mjs",
          "./flock-lifecycle.mjs",
          "./flock-membership.mjs",
          "./flock-protocol.mjs",
        ],
      },
      "flock-azure.mjs": {
        role: "companion",
        sha256: "6dd60ee4f5f10a7e6d6438d650d71063514a5b8c3675ddb6c15eced6165effab",
        imports: ["./flock-protocol.mjs"],
      },
      "flock-broker-free.mjs": {
        role: "companion",
        sha256: "32d48ea6a437ea5944d8cfbe77e47550398d0c3411385a462c0d165378261972",
        imports: [
          "./flock-azure.mjs",
          "./flock-lifecycle.mjs",
          "./flock-membership.mjs",
          "./flock-protocol.mjs",
        ],
      },
      "flock-lifecycle.mjs": {
        role: "companion",
        sha256: selfSha,
        imports: ["./flock-membership.mjs"],
      },
      "flock-membership.mjs": {
        role: "companion",
        sha256: "5ccd409530a2dcbbd1c8025e6f6f2af7da9ae0a4a79b70d1384f1c46fbd4c77c",
        imports: [
          "./flock-lifecycle.mjs",
          "./flock-protocol.mjs",
        ],
      },
      "flock-protocol.mjs": {
        role: "companion",
        sha256: "4292997940c5b36d6873a00b9ad6aa248ae58e897df98cffd937aeb34a44c8f3",
        imports: ["./flock-lifecycle.mjs"],
      },
      "flock.mjs": {
        role: "entrypoint",
        sha256: entrypointSha,
        imports: [
          "./flock-broker-free.mjs",
          "./flock-lifecycle.mjs",
          "./flock-membership.mjs",
          "./flock-protocol.mjs",
        ],
      },
    },
  };
  fallback.manifestDigest = computeManifestDigest(fallback);
  return freezeManifest(fallback);
})();

function loadInitialRuntimeManifest(dir) {
  if (fs.existsSync(path.join(dir, RUNTIME_CUTOVER_JOURNAL_FILENAME))) {
    const rec = recoverInterruptedRuntimeCutover(dir);
    if (rec?.recoveryFailed) {
      throw runtimeError("RUNTIME_CUTOVER_RECOVERY_FAILED", rec.error || "Interrupted runtime cutover rollback incomplete", {
        errors: rec.errors || [],
      });
    }
  }
  try {
    const manifestPath = path.join(dir, RUNTIME_MANIFEST_FILENAME);
    if (fs.existsSync(manifestPath)) {
      return loadRuntimeManifest(dir);
    }
    if (REQUIRED_RUNTIME_MODULES.every((m) => fs.existsSync(path.join(dir, m)))) {
      return computeRuntimeManifest(dir);
    }
    const presentEp = REQUIRED_RUNTIME_ENTRYPOINTS.find((ep) => fs.existsSync(path.join(dir, ep)));
    if (presentEp && REQUIRED_COMPANION_MODULES.every((m) => fs.existsSync(path.join(dir, m)))) {
      const partial = computeRuntimeManifest(dir, {
        entrypoints: [presentEp],
        requiredModules: [presentEp, ...REQUIRED_COMPANION_MODULES],
      });
      const files = { ...partial.files };
      for (const ep of REQUIRED_RUNTIME_ENTRYPOINTS) {
        if (!files[ep]) files[ep] = { ...files[presentEp] };
      }
      const sortedFiles = {};
      for (const key of Object.keys(files).sort()) sortedFiles[key] = files[key];
      const full = {
        type: "copilot-flock-runtime-manifest-v1",
        schema: 1,
        version: partial.version,
        entrypoints: [...REQUIRED_RUNTIME_ENTRYPOINTS],
        files: sortedFiles,
      };
      full.manifestDigest = computeManifestDigest(full);
      return freezeManifest(full);
    }
  } catch {}
  return EMBEDDED_RUNTIME_MANIFEST_FALLBACK;
}

export const RUNTIME_MODULE_MANIFEST = loadInitialRuntimeManifest(__lifecycleDir);

function defaultRunImportCheck(stageDir, manifest) {
  const verifyScript = `
import fs from "node:fs";
import path from "node:path";
import mod from "node:module";
import { pathToFileURL } from "node:url";

const stageDir = path.resolve(process.env.FLOCK_VERIFY_STAGE_DIR);
const stagePrefix = pathToFileURL(stageDir + path.sep).href.toLowerCase();
const manifest = JSON.parse(process.env.FLOCK_VERIFY_MANIFEST);
const allowedUrls = new Set(
  Object.keys(manifest.files).map((name) => pathToFileURL(path.join(stageDir, name)).href.toLowerCase())
);

if (typeof mod.registerHooks === "function") {
  mod.registerHooks({
    resolve(specifier, context, nextResolve) {
      const resolved = nextResolve(specifier, context);
      if (resolved.url.startsWith("file:")) {
        const normalized = resolved.url.split("?")[0].toLowerCase();
        if (!normalized.startsWith(stagePrefix) || !allowedUrls.has(normalized)) {
          throw new Error("Staged import escaped stageDir or resolved unpinned module: " + resolved.url);
        }
      }
      return resolved;
    },
  });
}

const companionNames = Object.keys(manifest.files).filter((n) => !manifest.entrypoints.includes(n));
for (const name of [...companionNames, ...manifest.entrypoints]) {
  const targetUrl = pathToFileURL(path.join(stageDir, name)).href;
  const loaded = await import(targetUrl);
  if (manifest.entrypoints.includes(name)) {
    if (loaded.BRIDGE_VERSION !== manifest.version) {
      throw new Error(\`Entrypoint \${name} exported BRIDGE_VERSION=\${loaded.BRIDGE_VERSION}, expected \${manifest.version}\`);
    }
    if (typeof loaded.runDaemon !== "function" || typeof loaded.runMcpServer !== "function") {
      throw new Error(\`Entrypoint \${name} is missing runDaemon or runMcpServer export\`);
    }
  }
}
process.stdout.write(JSON.stringify({ ok: true, verifiedCount: Object.keys(manifest.files).length }));
`;

  const cleanEnv = { ...process.env };
  for (const key of Object.keys(cleanEnv)) {
    if (key.startsWith("NODE_TEST_") || key === "NODE_OPTIONS") delete cleanEnv[key];
  }
  cleanEnv.FLOCK_VERIFY_STAGE_DIR = stageDir;
  cleanEnv.FLOCK_VERIFY_MANIFEST = JSON.stringify(manifest);
  cleanEnv.COPILOT_FLOCK_VERIFY_ONLY = "1";

  let out;
  try {
    out = execFileSync(process.execPath, ["--input-type=module", "-e", verifyScript], {
      cwd: stageDir,
      env: cleanEnv,
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (err) {
    const stderr = err.stderr ? String(err.stderr).trim() : "";
    throw runtimeError(
      "RUNTIME_IMPORT_VERIFICATION_FAILED",
      `Staged syntax/import verification failed: ${stderr || err.message}`
    );
  }

  let parsed = null;
  try {
    parsed = JSON.parse(out);
  } catch {}
  if (!parsed || parsed.ok !== true) {
    throw runtimeError("RUNTIME_IMPORT_VERIFICATION_FAILED", "Staged syntax/import verifier did not confirm completion");
  }
  return parsed;
}

export function verifyStagedRuntimeClosure(stageDir, manifest, {
  verifyImports = true,
  runImportCheck = defaultRunImportCheck,
} = {}) {
  const resolvedStage = assertNoLinks(stageDir);
  const validated = validateRuntimeManifest(manifest);

  const actualHashes = {};
  const missingFiles = [];
  const mismatchedFiles = [];

  for (const name of Object.keys(validated.files).sort()) {
    const filePath = assertNoLinks(path.join(resolvedStage, name));
    if (!fs.existsSync(filePath) || !fs.lstatSync(filePath).isFile()) {
      missingFiles.push(name);
      continue;
    }
    const content = fs.readFileSync(filePath);
    if (content.length === 0) {
      mismatchedFiles.push({ file: name, expected: validated.files[name].sha256, actual: hashRuntimeModule(content), reason: "empty_file" });
      continue;
    }
    const actualSha = hashRuntimeModule(content);
    actualHashes[name] = actualSha;
    if (actualSha !== validated.files[name].sha256) {
      mismatchedFiles.push({ file: name, expected: validated.files[name].sha256, actual: actualSha });
    }
  }

  if (missingFiles.length > 0) {
    throw runtimeError(
      "RUNTIME_MODULE_MISSING",
      `Missing staged runtime module(s): ${missingFiles.join(", ")}`,
      { missingFiles }
    );
  }
  if (mismatchedFiles.length > 0) {
    const summary = mismatchedFiles.map((m) => `${m.file} (expected ${m.expected.slice(0, 12)}..., got ${m.actual.slice(0, 12)}...)`).join(", ");
    throw runtimeError(
      "RUNTIME_HASH_MISMATCH",
      `Runtime module SHA-256 mismatch in staged closure: ${summary}`,
      { mismatchedFiles }
    );
  }

  // Walk transitive dependency closure starting from every entrypoint
  const visited = new Set();
  const queue = [...validated.entrypoints];
  while (queue.length > 0) {
    const current = queue.shift();
    if (visited.has(current)) continue;
    visited.add(current);
    const sourceText = fs.readFileSync(path.join(resolvedStage, current), "utf8");
    const actualImports = extractRelativeModuleImports(sourceText);
    const pinnedImports = validated.files[current]?.imports;
    if (Array.isArray(pinnedImports) && JSON.stringify([...pinnedImports].sort()) !== JSON.stringify(actualImports)) {
      throw runtimeError(
        "RUNTIME_MANIFEST_MISMATCH",
        `Relative imports of '${current}' (${actualImports.join(", ")}) do not match pinned manifest (${pinnedImports.join(", ")})`
      );
    }
    for (const spec of actualImports) {
      const targetPath = path.resolve(resolvedStage, spec);
      if (path.dirname(targetPath) !== resolvedStage) {
        throw runtimeError("RUNTIME_PATH_ESCAPE", `Relative import '${spec}' in '${current}' escapes staging directory`);
      }
      const depName = path.basename(targetPath);
      if (!Object.prototype.hasOwnProperty.call(validated.files, depName)) {
        throw runtimeError(
          "RUNTIME_UNPINNED_IMPORT",
          `Module '${current}' imports '${depName}' which is not pinned in ${RUNTIME_MANIFEST_FILENAME}`,
          { module: depName }
        );
      }
      if (!fs.existsSync(targetPath) || !fs.lstatSync(targetPath).isFile()) {
        throw runtimeError("RUNTIME_MODULE_MISSING", `Module '${current}' imports missing companion '${depName}'`, { module: depName });
      }
      if (!visited.has(depName)) queue.push(depName);
    }
  }

  let importVerification = null;
  if (verifyImports) {
    importVerification = runImportCheck(resolvedStage, validated);
  }

  return {
    ok: true,
    version: validated.version,
    manifestDigest: validated.manifestDigest,
    files: actualHashes,
    closureCount: visited.size,
    closureVerified: true,
    importVerified: Boolean(verifyImports),
    importVerification,
  };
}

function atomicReplaceFile(sourcePath, destinationPath) {
  assertNoLinks(sourcePath);
  assertNoLinks(destinationPath);
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(sourcePath, destinationPath);
      break;
    } catch (error) {
      if (!["EPERM", "EACCES", "EBUSY"].includes(error.code) || attempt >= 8) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(10 * 2 ** attempt, 200));
    }
  }
}

function writeBinarySecure(filePath, buffer) {
  assertNoLinks(filePath);
  const fd = fs.openSync(filePath, "wx", 0o600);
  try {
    fs.writeFileSync(fd, buffer);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function cleanupDirectorySafe(dirPath) {
  if (!dirPath) return;
  try {
    assertNoLinks(dirPath);
    if (fs.existsSync(dirPath)) {
      for (const entry of fs.readdirSync(dirPath)) {
        const child = assertNoLinks(path.join(dirPath, entry));
        if (fs.lstatSync(child).isDirectory()) cleanupDirectorySafe(child);
        else fs.unlinkSync(child);
      }
      fs.rmdirSync(dirPath);
    }
  } catch {}
}

function cleanOrphanedStagingDirs(targetDir, { maxAgeMs = 3600000, now = Date.now() } = {}) {
  const cleaned = [];
  if (!fs.existsSync(targetDir)) return cleaned;
  let activeRecordedStageDir = null;
  try {
    activeRecordedStageDir = readRuntimeState(targetDir).staged?.stageDir || null;
  } catch {}
  for (const name of fs.readdirSync(targetDir)) {
    if (!name.startsWith(".runtime-stage-")) continue;
    const full = path.join(targetDir, name);
    if (activeRecordedStageDir && path.resolve(full) === path.resolve(activeRecordedStageDir)) {
      continue;
    }
    try {
      const st = fs.lstatSync(full);
      if (st.isDirectory()) {
        const hasCompletedManifest = fs.existsSync(path.join(full, RUNTIME_MANIFEST_FILENAME));
        const ageMs = now - st.mtimeMs;
        if (hasCompletedManifest || ageMs < maxAgeMs) {
          continue;
        }
      }
    } catch {}
    cleanupDirectorySafe(full);
    cleaned.push(name);
  }
  return cleaned;
}

export function readRuntimeState(targetDir) {
  const resolvedTarget = assertNoLinks(targetDir);
  const statePath = path.join(resolvedTarget, RUNTIME_STATE_FILENAME);
  assertNoLinks(statePath);
  if (!fs.existsSync(statePath)) {
    return { type: "copilot-flock-runtime-state-v1", staged: null, installed: null, verified: null };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath, "utf8"));
    if (parsed && parsed.type === "copilot-flock-runtime-state-v1") return parsed;
  } catch {}
  return { type: "copilot-flock-runtime-state-v1", staged: null, installed: null, verified: null };
}

function updateRuntimeState(targetDir, patch) {
  const resolvedTarget = assertNoLinks(targetDir);
  if (!fs.existsSync(resolvedTarget)) return null;
  const current = readRuntimeState(resolvedTarget);
  const next = {
    type: "copilot-flock-runtime-state-v1",
    staged: patch.staged !== undefined ? patch.staged : current.staged,
    installed: patch.installed !== undefined ? patch.installed : current.installed,
    verified: patch.verified !== undefined ? patch.verified : current.verified,
    updatedAt: new Date().toISOString(),
  };
  atomicJson(path.join(resolvedTarget, RUNTIME_STATE_FILENAME), next);
  return next;
}

const activeCutoverTargets = new Set();

function isCutoverJournalWriterAlive(journal, resolvedTarget) {
  if (!journal || typeof journal.pid !== "number" || !Number.isInteger(journal.pid) || journal.pid <= 0) {
    return false;
  }
  const targetKey = path.resolve(resolvedTarget).toLowerCase();
  if (journal.pid === process.pid) {
    return activeCutoverTargets.has(targetKey);
  }
  try {
    process.kill(journal.pid, 0);
    return true;
  } catch (err) {
    return Boolean(err && err.code === "EPERM");
  }
}

export function recoverInterruptedRuntimeCutover(targetDir, { force = false } = {}) {
  let resolvedTarget;
  try {
    resolvedTarget = assertNoLinks(targetDir);
  } catch {
    return { recovered: false };
  }
  if (!fs.existsSync(resolvedTarget)) return { recovered: false };
  const journalPath = path.join(resolvedTarget, RUNTIME_CUTOVER_JOURNAL_FILENAME);
  try {
    assertNoLinks(journalPath);
  } catch {
    return { recovered: false };
  }
  if (!fs.existsSync(journalPath)) return { recovered: false };
  let journal;
  try {
    if (!fs.lstatSync(journalPath).isFile()) return { recovered: false };
    journal = JSON.parse(fs.readFileSync(journalPath, "utf8"));
  } catch {
    return { recovered: false };
  }
  if (!journal || journal.type !== "copilot-flock-cutover-journal-v1") {
    return { recovered: false };
  }
  if (!force && isCutoverJournalWriterAlive(journal, resolvedTarget)) {
    return {
      recovered: false,
      inProgress: true,
      pid: journal.pid,
    };
  }
  let backupDir = null;
  let stageDir = null;
  try {
    if (journal.backupDir) backupDir = assertNoLinks(path.resolve(journal.backupDir));
  } catch {}
  try {
    if (journal.stageDir) stageDir = assertNoLinks(path.resolve(journal.stageDir));
  } catch {}

  const managedNames = Array.isArray(journal.managedNames)
    ? journal.managedNames
    : [...REQUIRED_RUNTIME_MODULES, RUNTIME_MANIFEST_FILENAME, "installation.json"];
  const existedBefore = new Set(Array.isArray(journal.existedBefore) ? journal.existedBefore : []);
  const backedUpFiles = new Set(Array.isArray(journal.backedUpFiles) ? journal.backedUpFiles : []);
  const previousFileHashes =
    journal.previousFileHashes && typeof journal.previousFileHashes === "object"
      ? journal.previousFileHashes
      : {};
  const rollbackPriority = [
    "flock.mjs",
    "bridge.mjs",
    "installation.json",
    "runtime-manifest.json",
    "flock-registry.mjs",
    "flock-broker-free.mjs",
    "flock-protocol.mjs",
    "flock-lifecycle.mjs",
    "flock-membership.mjs",
    "flock-azure.mjs",
  ];
  const orderedNames = [...managedNames].sort((a, b) => {
    const ia = rollbackPriority.indexOf(a);
    const ib = rollbackPriority.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  });
  const restoreErrors = [];

  for (const name of orderedNames) {
    const activeFile = path.join(resolvedTarget, name);
    const backupFile = backupDir ? path.join(backupDir, name) : null;
    const expectedPrevHash =
      typeof previousFileHashes[name] === "string" ? previousFileHashes[name] : null;
    try {
      assertNoLinks(activeFile);
      if (existedBefore.has(name)) {
        if (
          expectedPrevHash &&
          fs.existsSync(activeFile) &&
          hashRuntimeModule(fs.readFileSync(activeFile)) === expectedPrevHash
        ) {
          continue;
        }
        if (!backedUpFiles.has(name) || !backupFile || !fs.existsSync(backupFile)) {
          restoreErrors.push(`${name}: missing rollback backup file`);
          break;
        }
        atomicReplaceFile(backupFile, activeFile);
        if (!fs.existsSync(activeFile)) {
          restoreErrors.push(`${name}: restored file missing after rename`);
          break;
        } else if (
          expectedPrevHash &&
          hashRuntimeModule(fs.readFileSync(activeFile)) !== expectedPrevHash
        ) {
          restoreErrors.push(`${name}: restored file digest mismatch`);
          break;
        }
      } else if (fs.existsSync(activeFile)) {
        fs.unlinkSync(activeFile);
        if (fs.existsSync(activeFile)) {
          restoreErrors.push(`${name}: failed to remove newly added file`);
          break;
        }
      }
    } catch (err) {
      restoreErrors.push(`${name}: ${err?.code || err?.message || String(err)}`);
      break;
    }
  }

  if (restoreErrors.length > 0) {
    const errMsg = `Interrupted runtime cutover rollback incomplete: ${restoreErrors.join("; ")}`;
    try {
      updateRuntimeState(resolvedTarget, {
        staged: {
          status: "failed",
          version: journal.targetVersion || null,
          manifestDigest: journal.targetManifestDigest || null,
          stageDir: null,
          closureVerified: false,
          importVerified: false,
          error: errMsg,
          code: "RUNTIME_CUTOVER_RECOVERY_FAILED",
          updatedAt: new Date().toISOString(),
        },
      });
    } catch {}
    return {
      recovered: false,
      recoveryFailed: true,
      code: "RUNTIME_CUTOVER_RECOVERY_FAILED",
      error: errMsg,
      errors: restoreErrors,
    };
  }

  try {
    updateRuntimeState(resolvedTarget, {
      staged: {
        status: "failed",
        version: journal.targetVersion || null,
        manifestDigest: journal.targetManifestDigest || null,
        stageDir: null,
        closureVerified: false,
        importVerified: false,
        error: "Recovered interrupted runtime cutover by rolling back to previous generation",
        code: "RUNTIME_CUTOVER_INTERRUPTED_RECOVERED",
        updatedAt: new Date().toISOString(),
      },
    });
  } catch {}

  if (stageDir) cleanupDirectorySafe(stageDir);
  if (backupDir) cleanupDirectorySafe(backupDir);
  try {
    if (fs.existsSync(journalPath)) fs.unlinkSync(assertNoLinks(journalPath));
  } catch {}

  return {
    recovered: true,
    rolledBackToDigest: journal.previousManifestDigest || null,
    abortedTargetDigest: journal.targetManifestDigest || null,
  };
}

export function inspectRuntimeGenerations(targetDir, { resident = null } = {}) {
  const resRunning = Boolean(resident?.running);
  const resDigest = resident?.manifestDigest || resident?.digest || null;
  const normalizedResident = {
    status: resRunning ? (resident?.status || "running") : "stopped",
    running: resRunning,
    pid: resRunning ? (resident?.pid ?? null) : null,
    version: resRunning ? (resident?.version ?? null) : null,
    digest: resRunning ? resDigest : null,
    manifestDigest: resRunning ? resDigest : null,
    startedAt: resRunning ? (resident?.startedAt ?? null) : null,
  };

  let resolvedTarget;
  try {
    resolvedTarget = assertNoLinks(targetDir);
  } catch (linkErr) {
    return {
      staged: {
        status: "none",
        version: null,
        digest: null,
        manifestDigest: null,
        stageDir: null,
        closureVerified: false,
        importVerified: false,
        error: null,
        code: null,
        updatedAt: null,
      },
      installed: {
        status: "unverified_path",
        complete: false,
        version: null,
        digest: null,
        manifestDigest: null,
        actualDigest: null,
        files: {},
        missingFiles: [...REQUIRED_RUNTIME_MODULES].sort(),
        mismatchedFiles: [],
        manifestError: linkErr.message,
        activatedAt: null,
      },
      resident: normalizedResident,
      verified: {
        status: "unverified",
        closureVerified: false,
        importVerified: false,
        residentMatchesInstalled: false,
        fullyActive: false,
        version: null,
        digest: null,
        manifestDigest: null,
        verifiedAt: null,
      },
    };
  }

  const targetExists = fs.existsSync(resolvedTarget);
  if (targetExists) {
    try {
      recoverInterruptedRuntimeCutover(resolvedTarget);
    } catch {}
  }
  const assertDirectChildSafe = (childPath) => {
    const st = fs.lstatSync(childPath);
    if (st.isSymbolicLink()) throw new Error(`Unsafe link or junction: ${childPath}`);
    if (fs.realpathSync.native(childPath).toLowerCase() !== path.resolve(childPath).toLowerCase()) {
      throw new Error(`Filesystem path escape: ${childPath}`);
    }
    return st;
  };

  let persisted = { staged: null, installed: null, verified: null };
  if (targetExists) {
    const statePath = path.join(resolvedTarget, RUNTIME_STATE_FILENAME);
    if (fs.existsSync(statePath)) {
      try {
        if (assertDirectChildSafe(statePath).isFile()) {
          const parsed = JSON.parse(fs.readFileSync(statePath, "utf8"));
          if (parsed && parsed.type === "copilot-flock-runtime-state-v1") persisted = parsed;
        }
      } catch {}
    }
  }

  // 1. Live inspection of installed files on disk
  let diskManifest = null;
  let diskManifestError = null;
  const manifestFile = path.join(resolvedTarget, RUNTIME_MANIFEST_FILENAME);
  if (targetExists && fs.existsSync(manifestFile)) {
    try {
      if (!assertDirectChildSafe(manifestFile).isFile()) {
        throw new Error(`${RUNTIME_MANIFEST_FILENAME} is not a regular file`);
      }
      diskManifest = validateRuntimeManifest(JSON.parse(fs.readFileSync(manifestFile, "utf8")));
    } catch (err) {
      diskManifestError = err.message;
    }
  }

  const expectedModuleNames = diskManifest
    ? Object.keys(diskManifest.files).sort()
    : [...REQUIRED_RUNTIME_MODULES].sort();
  const presentHashes = {};
  const missingFiles = [];
  const mismatchedFiles = [];
  let detectedDiskVersion = diskManifest?.version || null;

  if (targetExists) {
    for (const name of expectedModuleNames) {
      const p = path.join(resolvedTarget, name);
      if (!fs.existsSync(p)) {
        missingFiles.push(name);
        continue;
      }
      let st;
      try {
        st = assertDirectChildSafe(p);
      } catch {
        mismatchedFiles.push(name);
        continue;
      }
      if (!st.isFile()) {
        missingFiles.push(name);
        continue;
      }
      const buf = fs.readFileSync(p);
      const digest = hashRuntimeModule(buf);
      presentHashes[name] = digest;
      if (!detectedDiskVersion && (name === "flock.mjs" || name === "bridge.mjs")) {
        detectedDiskVersion = extractEntrypointVersion(buf.toString("utf8"));
      }
      if (diskManifest && diskManifest.files[name]?.sha256 !== digest) {
        mismatchedFiles.push(name);
      }
    }
  } else {
    missingFiles.push(...expectedModuleNames);
  }

  const anyRuntimePresent = Object.keys(presentHashes).length > 0 || fs.existsSync(manifestFile);
  const actualDigest = computeActualFilesDigest(presentHashes);
  const installedComplete =
    Boolean(diskManifest) &&
    !diskManifestError &&
    missingFiles.length === 0 &&
    mismatchedFiles.length === 0;

  const installedStatus = !anyRuntimePresent
    ? "not_installed"
    : installedComplete
    ? "installed"
    : missingFiles.length > 0
    ? "incomplete"
    : "mismatch";

  const installedDigest = installedComplete ? diskManifest.manifestDigest : null;
  const installed = {
    status: installedStatus,
    complete: installedComplete,
    version: installedComplete ? diskManifest.version : detectedDiskVersion,
    digest: installedDigest,
    manifestDigest: installedDigest,
    actualDigest,
    files: presentHashes,
    missingFiles,
    mismatchedFiles,
    manifestError: diskManifestError,
    activatedAt: persisted.installed?.activatedAt || null,
  };

  // 2. Staged state (independent of installed)
  let activeStageDirs = [];
  if (fs.existsSync(resolvedTarget)) {
    try {
      activeStageDirs = fs.readdirSync(resolvedTarget).filter((n) => n.startsWith(".runtime-stage-"));
    } catch {}
  }
  const rawStaged = persisted.staged;
  const stagedDigest = rawStaged?.manifestDigest || null;
  const staged = rawStaged
    ? {
        status:
          activeStageDirs.length > 0 && rawStaged.status === "staging"
            ? "staging"
            : activeStageDirs.length > 0 && rawStaged.status !== "staged"
            ? "interrupted"
            : rawStaged.status || "none",
        version: rawStaged.version || null,
        digest: stagedDigest,
        manifestDigest: stagedDigest,
        stageDir: rawStaged.stageDir && fs.existsSync(rawStaged.stageDir) ? rawStaged.stageDir : null,
        closureVerified: Boolean(rawStaged.closureVerified),
        importVerified: Boolean(rawStaged.importVerified),
        error: rawStaged.error || null,
        code: rawStaged.code || null,
        updatedAt: rawStaged.updatedAt || null,
      }
    : {
        status: activeStageDirs.length > 0 ? "interrupted" : "none",
        version: null,
        digest: null,
        manifestDigest: null,
        stageDir: null,
        closureVerified: false,
        importVerified: false,
        error: activeStageDirs.length > 0 ? "Orphaned staging directory detected" : null,
        code: activeStageDirs.length > 0 ? "RUNTIME_STAGE_INTERRUPTED" : null,
        updatedAt: null,
      };

  // 3. Verified state (requires live installed closure integrity + recorded verification for exact digest)
  const persistedVerified = persisted.verified;
  const closureVerified =
    installedComplete &&
    Boolean(persistedVerified?.closureVerified) &&
    persistedVerified?.manifestDigest === installedDigest;
  const importVerified =
    closureVerified && Boolean(persistedVerified?.importVerified);
  const residentMatchesInstalled =
    normalizedResident.running &&
    Boolean(installedDigest) &&
    normalizedResident.manifestDigest === installedDigest &&
    normalizedResident.version === installed.version;

  let verifiedStatus = "unverified";
  if (closureVerified && importVerified) {
    verifiedStatus =
      normalizedResident.running && !residentMatchesInstalled
        ? "pending_daemon_restart"
        : "verified";
  }

  const verifiedDigest = closureVerified && importVerified ? installedDigest : null;
  const verified = {
    status: verifiedStatus,
    closureVerified,
    importVerified,
    residentMatchesInstalled,
    fullyActive: Boolean(closureVerified && importVerified && normalizedResident.running && residentMatchesInstalled),
    version: closureVerified && importVerified ? installed.version : null,
    digest: verifiedDigest,
    manifestDigest: verifiedDigest,
    verifiedAt: closureVerified && importVerified ? (persistedVerified?.verifiedAt || null) : null,
  };

  return { staged, installed, resident: normalizedResident, verified };
}

export async function inspectRuntimeGenerationsAsync(targetDir, { resident = null } = {}) {
  const resRunning = Boolean(resident?.running);
  const resDigest = resident?.manifestDigest || resident?.digest || null;
  const normalizedResident = {
    status: resRunning ? (resident?.status || "running") : "stopped",
    running: resRunning,
    pid: resRunning ? (resident?.pid ?? null) : null,
    version: resRunning ? (resident?.version ?? null) : null,
    digest: resRunning ? resDigest : null,
    manifestDigest: resRunning ? resDigest : null,
    startedAt: resRunning ? (resident?.startedAt ?? null) : null,
  };

  const resolvedTarget = path.resolve(targetDir);
  try {
    let current = path.parse(resolvedTarget).root;
    for (const component of resolvedTarget.slice(current.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, component);
      let st;
      try {
        st = await fs.promises.lstat(current);
      } catch (err) {
        if (err.code === "ENOENT") continue;
        throw err;
      }
      if (st.isSymbolicLink()) throw new Error(`Unsafe link or junction: ${current}`);
      const rp = await fs.promises.realpath(current);
      if (rp.toLowerCase() !== path.resolve(current).toLowerCase()) {
        throw new Error(`Filesystem path escape: ${current}`);
      }
    }
  } catch (linkErr) {
    return {
      staged: {
        status: "none",
        version: null,
        digest: null,
        manifestDigest: null,
        stageDir: null,
        closureVerified: false,
        importVerified: false,
        error: null,
        code: null,
        updatedAt: null,
      },
      installed: {
        status: "unverified_path",
        complete: false,
        version: null,
        digest: null,
        manifestDigest: null,
        actualDigest: null,
        files: {},
        missingFiles: [...REQUIRED_RUNTIME_MODULES].sort(),
        mismatchedFiles: [],
        manifestError: linkErr.message,
        activatedAt: null,
      },
      resident: normalizedResident,
      verified: {
        status: "unverified",
        closureVerified: false,
        importVerified: false,
        residentMatchesInstalled: false,
        fullyActive: false,
        version: null,
        digest: null,
        manifestDigest: null,
        verifiedAt: null,
      },
    };
  }

  let targetExists = false;
  try {
    const dirSt = await fs.promises.lstat(resolvedTarget);
    targetExists = dirSt.isDirectory();
  } catch {}
  if (targetExists) {
    try {
      recoverInterruptedRuntimeCutover(resolvedTarget);
    } catch {}
  }

  const assertChildSafeAsync = async (childPath) => {
    const st = await fs.promises.lstat(childPath);
    if (st.isSymbolicLink()) throw new Error(`Unsafe link or junction: ${childPath}`);
    const rp = await fs.promises.realpath(childPath);
    if (rp.toLowerCase() !== path.resolve(childPath).toLowerCase()) {
      throw new Error(`Filesystem path escape: ${childPath}`);
    }
    return st;
  };

  let persisted = { staged: null, installed: null, verified: null };
  if (targetExists) {
    try {
      const statePath = path.join(resolvedTarget, RUNTIME_STATE_FILENAME);
      if ((await assertChildSafeAsync(statePath)).isFile()) {
        const parsed = JSON.parse(await fs.promises.readFile(statePath, "utf8"));
        if (parsed && parsed.type === "copilot-flock-runtime-state-v1") persisted = parsed;
      }
    } catch {}
  }

  let diskManifest = null;
  let diskManifestError = null;
  let manifestExists = false;
  const manifestFile = path.join(resolvedTarget, RUNTIME_MANIFEST_FILENAME);
  if (targetExists) {
    try {
      const mst = await assertChildSafeAsync(manifestFile);
      manifestExists = true;
      if (!mst.isFile()) throw new Error(`${RUNTIME_MANIFEST_FILENAME} is not a regular file`);
      diskManifest = validateRuntimeManifest(JSON.parse(await fs.promises.readFile(manifestFile, "utf8")));
    } catch (err) {
      if (err.code !== "ENOENT") diskManifestError = err.message;
    }
  }

  const expectedModuleNames = diskManifest
    ? Object.keys(diskManifest.files).sort()
    : [...REQUIRED_RUNTIME_MODULES].sort();
  const presentHashes = {};
  const missingFiles = [];
  const mismatchedFiles = [];
  let detectedDiskVersion = diskManifest?.version || null;

  if (targetExists) {
    for (const name of expectedModuleNames) {
      const p = path.join(resolvedTarget, name);
      let st;
      try {
        st = await assertChildSafeAsync(p);
      } catch (err) {
        if (err.code === "ENOENT") missingFiles.push(name);
        else mismatchedFiles.push(name);
        continue;
      }
      if (!st.isFile()) {
        missingFiles.push(name);
        continue;
      }
      const buf = await fs.promises.readFile(p);
      const digest = hashRuntimeModule(buf);
      presentHashes[name] = digest;
      if (!detectedDiskVersion && (name === "flock.mjs" || name === "bridge.mjs")) {
        detectedDiskVersion = extractEntrypointVersion(buf.toString("utf8"));
      }
      if (diskManifest && diskManifest.files[name]?.sha256 !== digest) {
        mismatchedFiles.push(name);
      }
    }
  } else {
    missingFiles.push(...expectedModuleNames);
  }

  const anyRuntimePresent = Object.keys(presentHashes).length > 0 || manifestExists;
  const actualDigest = computeActualFilesDigest(presentHashes);
  const installedComplete =
    Boolean(diskManifest) &&
    !diskManifestError &&
    missingFiles.length === 0 &&
    mismatchedFiles.length === 0;

  const installedStatus = !anyRuntimePresent
    ? "not_installed"
    : installedComplete
    ? "installed"
    : missingFiles.length > 0
    ? "incomplete"
    : "mismatch";

  const installedDigest = installedComplete ? diskManifest.manifestDigest : null;
  const installed = {
    status: installedStatus,
    complete: installedComplete,
    version: installedComplete ? diskManifest.version : detectedDiskVersion,
    digest: installedDigest,
    manifestDigest: installedDigest,
    actualDigest,
    files: presentHashes,
    missingFiles,
    mismatchedFiles,
    manifestError: diskManifestError,
    activatedAt: persisted.installed?.activatedAt || null,
  };

  let activeStageDirs = [];
  if (targetExists) {
    try {
      activeStageDirs = (await fs.promises.readdir(resolvedTarget)).filter((n) => n.startsWith(".runtime-stage-"));
    } catch {}
  }
  const rawStaged = persisted.staged;
  const stagedDigest = rawStaged?.manifestDigest || null;
  let stageDirExists = false;
  if (rawStaged?.stageDir) {
    try {
      await fs.promises.access(rawStaged.stageDir);
      stageDirExists = true;
    } catch {}
  }
  const staged = rawStaged
    ? {
        status:
          activeStageDirs.length > 0 && rawStaged.status === "staging"
            ? "staging"
            : activeStageDirs.length > 0 && rawStaged.status !== "staged"
            ? "interrupted"
            : rawStaged.status || "none",
        version: rawStaged.version || null,
        digest: stagedDigest,
        manifestDigest: stagedDigest,
        stageDir: stageDirExists ? rawStaged.stageDir : null,
        closureVerified: Boolean(rawStaged.closureVerified),
        importVerified: Boolean(rawStaged.importVerified),
        error: rawStaged.error || null,
        code: rawStaged.code || null,
        updatedAt: rawStaged.updatedAt || null,
      }
    : {
        status: activeStageDirs.length > 0 ? "interrupted" : "none",
        version: null,
        digest: null,
        manifestDigest: null,
        stageDir: null,
        closureVerified: false,
        importVerified: false,
        error: activeStageDirs.length > 0 ? "Orphaned staging directory detected" : null,
        code: activeStageDirs.length > 0 ? "RUNTIME_STAGE_INTERRUPTED" : null,
        updatedAt: null,
      };

  const persistedVerified = persisted.verified;
  const closureVerified =
    installedComplete &&
    Boolean(persistedVerified?.closureVerified) &&
    persistedVerified?.manifestDigest === installedDigest;
  const importVerified =
    closureVerified && Boolean(persistedVerified?.importVerified);
  const residentMatchesInstalled =
    normalizedResident.running &&
    Boolean(installedDigest) &&
    normalizedResident.manifestDigest === installedDigest &&
    normalizedResident.version === installed.version;

  let verifiedStatus = "unverified";
  if (closureVerified && importVerified) {
    verifiedStatus =
      normalizedResident.running && !residentMatchesInstalled
        ? "pending_daemon_restart"
        : "verified";
  }

  const verifiedDigest = closureVerified && importVerified ? installedDigest : null;
  const verified = {
    status: verifiedStatus,
    closureVerified,
    importVerified,
    residentMatchesInstalled,
    fullyActive: Boolean(closureVerified && importVerified && normalizedResident.running && residentMatchesInstalled),
    version: closureVerified && importVerified ? installed.version : null,
    digest: verifiedDigest,
    manifestDigest: verifiedDigest,
    verifiedAt: closureVerified && importVerified ? (persistedVerified?.verifiedAt || null) : null,
  };

  return { staged, installed, resident: normalizedResident, verified };
}

export function stageRuntimeRelease({
  sourceDir,
  targetDir,
  manifest = null,
  expectedVersion = null,
  verifyImports = true,
  runImportCheck = defaultRunImportCheck,
  onBeforeStageFile = null,
  onAfterStageFile = null,
  keepStageOnFailure = false,
} = {}) {
  const resolvedSource = assertNoLinks(sourceDir);
  const resolvedTarget = assertNoLinks(targetDir);
  if (fs.existsSync(path.join(resolvedTarget, ".git"))) {
    throw runtimeError("RUNTIME_UNSAFE_TARGET", `Refusing to stage runtime into source checkout: ${resolvedTarget}`);
  }
  const targetExistedBefore = fs.existsSync(resolvedTarget);
  if (targetExistedBefore) {
    const rec = recoverInterruptedRuntimeCutover(resolvedTarget);
    if (rec?.recoveryFailed) {
      throw runtimeError("RUNTIME_CUTOVER_RECOVERY_FAILED", rec.error, { errors: rec.errors || [] });
    }
  }
  fs.mkdirSync(resolvedTarget, { recursive: true });

  const recordStageFailure = (err, candidateManifest) => {
    if (!targetExistedBefore && fs.readdirSync(resolvedTarget).length === 0) return;
    try {
      updateRuntimeState(resolvedTarget, {
        staged: {
          status: "failed",
          version: candidateManifest?.version || null,
          manifestDigest: candidateManifest?.manifestDigest || null,
          closureVerified: false,
          importVerified: false,
          error: err.message,
          code: err.code || "RUNTIME_STAGE_FAILED",
          updatedAt: new Date().toISOString(),
        },
      });
    } catch {}
  };

  let resolvedManifest = null;
  try {
    resolvedManifest = manifest
      ? validateRuntimeManifest(manifest, { expectedVersion })
      : loadRuntimeManifest(resolvedSource, { expectedVersion });
  } catch (err) {
    recordStageFailure(err, manifest);
    throw err;
  }

  cleanOrphanedStagingDirs(resolvedTarget);
  const stageDir = path.join(resolvedTarget, `.runtime-stage-${process.pid}-${crypto.randomUUID()}`);
  assertNoLinks(stageDir);
  fs.mkdirSync(stageDir, { mode: 0o700 });

  try {
    if (targetExistedBefore) {
      updateRuntimeState(resolvedTarget, {
        staged: {
          status: "staging",
          version: resolvedManifest.version,
          manifestDigest: resolvedManifest.manifestDigest,
          stageDir,
          closureVerified: false,
          importVerified: false,
          error: null,
          code: null,
          updatedAt: new Date().toISOString(),
        },
      });
    }

    for (const filename of Object.keys(resolvedManifest.files).sort()) {
      if (typeof onBeforeStageFile === "function") {
        onBeforeStageFile({ filename, sourceDir: resolvedSource, stageDir, manifest: resolvedManifest });
      }
      const srcFile = assertNoLinks(path.join(resolvedSource, filename));
      if (!fs.existsSync(srcFile) || !fs.lstatSync(srcFile).isFile()) {
        throw runtimeError(
          "RUNTIME_MODULE_MISSING",
          `Missing required runtime module '${filename}' in ${resolvedSource}`,
          { module: filename }
        );
      }
      const bytes = fs.readFileSync(srcFile);
      const dstFile = path.join(stageDir, filename);
      writeBinarySecure(dstFile, bytes);
      if (typeof onAfterStageFile === "function") {
        onAfterStageFile({ filename, stagedPath: dstFile, stageDir, manifest: resolvedManifest });
      }
    }

    atomicJson(path.join(stageDir, RUNTIME_MANIFEST_FILENAME), resolvedManifest);

    const verification = verifyStagedRuntimeClosure(stageDir, resolvedManifest, {
      verifyImports,
      runImportCheck,
    });

    const stagedState = {
      status: "staged",
      version: resolvedManifest.version,
      manifestDigest: resolvedManifest.manifestDigest,
      stageDir,
      closureVerified: verification.closureVerified,
      importVerified: verification.importVerified,
      error: null,
      code: null,
      updatedAt: new Date().toISOString(),
    };
    updateRuntimeState(resolvedTarget, { staged: stagedState });

    return {
      ok: true,
      stageDir,
      manifest: resolvedManifest,
      verification,
      staged: stagedState,
      cleanup: () => cleanupDirectorySafe(stageDir),
    };
  } catch (err) {
    if (!keepStageOnFailure) {
      cleanupDirectorySafe(stageDir);
    }
    recordStageFailure(err, resolvedManifest);
    throw err;
  }
}

export function activateStagedRuntime({
  stageDir,
  targetDir,
  manifest = null,
  verifyBeforeCutover = true,
  onDuringBackup = null,
  onDuringCutover = null,
  resident = null,
} = {}) {
  const resolvedStage = assertNoLinks(stageDir);
  const resolvedTarget = assertNoLinks(targetDir);
  if (fs.existsSync(path.join(resolvedTarget, ".git"))) {
    throw runtimeError("RUNTIME_UNSAFE_TARGET", `Refusing to activate runtime into source checkout: ${resolvedTarget}`);
  }
  if (fs.existsSync(resolvedTarget)) {
    const rec = recoverInterruptedRuntimeCutover(resolvedTarget);
    if (rec?.recoveryFailed) {
      throw runtimeError("RUNTIME_CUTOVER_RECOVERY_FAILED", rec.error, { errors: rec.errors || [] });
    }
  }

  const resolvedManifest = manifest ? validateRuntimeManifest(manifest) : loadRuntimeManifest(resolvedStage);

  if (verifyBeforeCutover) {
    // Re-verify exact SHA-256 digests and manifest integrity in stageDir immediately before cutover
    verifyStagedRuntimeClosure(resolvedStage, resolvedManifest, { verifyImports: false });
  }

  const managedNames = [
    ...new Set([
      ...REQUIRED_RUNTIME_MODULES,
      ...Object.keys(resolvedManifest.files),
      "flock-registry.mjs",
      RUNTIME_MANIFEST_FILENAME,
      "installation.json",
    ]),
  ];

  const existedBefore = new Set();
  for (const name of managedNames) {
    const currentPath = assertNoLinks(path.join(resolvedTarget, name));
    if (fs.existsSync(currentPath) && fs.lstatSync(currentPath).isFile()) {
      existedBefore.add(name);
    }
  }

  let previousManifestDigest = null;
  try {
    const existingManifestPath = path.join(resolvedTarget, RUNTIME_MANIFEST_FILENAME);
    if (fs.existsSync(existingManifestPath)) {
      const parsedPrev = JSON.parse(fs.readFileSync(existingManifestPath, "utf8"));
      previousManifestDigest = parsedPrev?.manifestDigest || null;
    }
  } catch {}

  const backupDir = path.join(resolvedTarget, `.runtime-backup-${process.pid}-${crypto.randomUUID()}`);
  const journalPath = path.join(resolvedTarget, RUNTIME_CUTOVER_JOURNAL_FILENAME);
  assertNoLinks(backupDir);
  assertNoLinks(journalPath);
  fs.mkdirSync(backupDir, { mode: 0o700 });
  const backedUpFiles = new Set();
  const previousFileHashes = {};
  const touchedDuringCutover = new Set();
  let cutoverStarted = false;
  let rollbackIncomplete = false;
  const targetKey = path.resolve(resolvedTarget).toLowerCase();

  const companionPriority = [
    "flock-azure.mjs",
    "flock-membership.mjs",
    "flock-lifecycle.mjs",
    "flock-protocol.mjs",
    "flock-registry.mjs",
    "flock-broker-free.mjs",
  ];
  const companionsOrder = Object.keys(resolvedManifest.files)
    .filter((name) => !resolvedManifest.entrypoints.includes(name))
    .sort((a, b) => {
      const ia = companionPriority.indexOf(a);
      const ib = companionPriority.indexOf(b);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.localeCompare(b);
    });
  const entrypointsOrder = [...resolvedManifest.entrypoints];
  const cutoverFilesOrder = [...companionsOrder, RUNTIME_MANIFEST_FILENAME, ...entrypointsOrder];

  activeCutoverTargets.add(targetKey);
  try {
    let backupIndex = 0;
    for (const name of managedNames) {
      if (!existedBefore.has(name)) continue;
      const currentPath = assertNoLinks(path.join(resolvedTarget, name));
      backupIndex++;
      if (typeof onDuringBackup === "function") {
        onDuringBackup({ filename: name, index: backupIndex, targetDir: resolvedTarget, backupDir });
      }
      const prevBytes = fs.readFileSync(currentPath);
      writeBinarySecure(path.join(backupDir, name), prevBytes);
      previousFileHashes[name] = hashRuntimeModule(prevBytes);
      backedUpFiles.add(name);
    }

    atomicJson(journalPath, {
      type: "copilot-flock-cutover-journal-v1",
      pid: process.pid,
      startedAtMs: Date.now(),
      backupDir,
      stageDir: resolvedStage,
      targetVersion: resolvedManifest.version,
      targetManifestDigest: resolvedManifest.manifestDigest,
      previousManifestDigest,
      managedNames,
      existedBefore: [...existedBefore],
      backedUpFiles: [...backedUpFiles],
      previousFileHashes,
      startedAt: new Date().toISOString(),
    });

    cutoverStarted = true;
    let stepIndex = 0;
    for (const name of cutoverFilesOrder) {
      const stagedFile = assertNoLinks(path.join(resolvedStage, name));
      const activeFile = assertNoLinks(path.join(resolvedTarget, name));
      touchedDuringCutover.add(name);
      atomicReplaceFile(stagedFile, activeFile);
      stepIndex++;
      if (typeof onDuringCutover === "function") {
        onDuringCutover({ filename: name, index: stepIndex, targetDir: resolvedTarget, backupDir });
      }
    }

    // Verify active targetDir digests immediately after atomic swap
    for (const [name, entry] of Object.entries(resolvedManifest.files)) {
      const activeFile = assertNoLinks(path.join(resolvedTarget, name));
      if (!fs.existsSync(activeFile) || hashRuntimeModule(fs.readFileSync(activeFile)) !== entry.sha256) {
        throw runtimeError("RUNTIME_HASH_MISMATCH", `Post-cutover digest verification failed for '${name}'`);
      }
    }

    if (!resolvedManifest.files["flock-registry.mjs"]) {
      const obsoleteRegistry = path.join(resolvedTarget, "flock-registry.mjs");
      try {
        if (fs.existsSync(obsoleteRegistry)) {
          touchedDuringCutover.add("flock-registry.mjs");
          fs.unlinkSync(assertNoLinks(obsoleteRegistry));
        }
      } catch {}
    }

    // Record ownership hashes in installation.json while preserving non-script owned artifacts (skills, persistence)
    const installationPath = assertNoLinks(path.join(resolvedTarget, "installation.json"));
    const installationManifest = fs.existsSync(installationPath)
      ? JSON.parse(fs.readFileSync(installationPath, "utf8"))
      : { type: "copilot-flock-installation-v1", artifacts: {} };
    if (installationManifest.type !== "copilot-flock-installation-v1") {
      throw runtimeError("RUNTIME_INSTALLATION_MANIFEST_INVALID", "Invalid installation ownership manifest");
    }
    installationManifest.artifacts ||= {};
    for (const name of Object.keys(resolvedManifest.files)) {
      const activeFile = path.join(resolvedTarget, name);
      installationManifest.artifacts[activeFile] = hash(fs.readFileSync(activeFile));
    }
    touchedDuringCutover.add("installation.json");
    atomicJson(installationPath, installationManifest);

    const nowIso = new Date().toISOString();
    const previousState = readRuntimeState(resolvedTarget);
    const importWasVerified =
      previousState.staged?.manifestDigest === resolvedManifest.manifestDigest
        ? Boolean(previousState.staged?.importVerified)
        : true;

    updateRuntimeState(resolvedTarget, {
      staged: {
        status: "promoted",
        version: resolvedManifest.version,
        manifestDigest: resolvedManifest.manifestDigest,
        stageDir: null,
        closureVerified: true,
        importVerified: importWasVerified,
        error: null,
        code: null,
        updatedAt: nowIso,
      },
      installed: {
        status: "installed",
        version: resolvedManifest.version,
        manifestDigest: resolvedManifest.manifestDigest,
        activatedAt: nowIso,
      },
      verified: {
        status: "verified",
        version: resolvedManifest.version,
        manifestDigest: resolvedManifest.manifestDigest,
        closureVerified: true,
        importVerified: importWasVerified,
        verifiedAt: nowIso,
      },
    });
    if (fs.existsSync(journalPath)) {
      fs.unlinkSync(assertNoLinks(journalPath));
    }
  } catch (err) {
    // Only roll back target files if cutover actually started; backup failures must never delete or mutate preexisting files
    const rollbackErrors = [];
    if (cutoverStarted) {
      for (const name of [...touchedDuringCutover].reverse()) {
        const activeFile = path.join(resolvedTarget, name);
        const backupFile = path.join(backupDir, name);
        const expectedPrevHash = previousFileHashes[name] || null;
        try {
          assertNoLinks(activeFile);
          if (existedBefore.has(name)) {
            if (
              expectedPrevHash &&
              fs.existsSync(activeFile) &&
              hashRuntimeModule(fs.readFileSync(activeFile)) === expectedPrevHash
            ) {
              continue;
            }
            if (!backedUpFiles.has(name) || !fs.existsSync(backupFile)) {
              rollbackErrors.push(`${name}: missing rollback backup file`);
              break;
            }
            atomicReplaceFile(backupFile, activeFile);
            if (
              !fs.existsSync(activeFile) ||
              (expectedPrevHash && hashRuntimeModule(fs.readFileSync(activeFile)) !== expectedPrevHash)
            ) {
              rollbackErrors.push(`${name}: post-rollback digest mismatch`);
              break;
            }
          } else if (fs.existsSync(activeFile)) {
            fs.unlinkSync(activeFile);
          }
        } catch (rbErr) {
          rollbackErrors.push(`${name}: ${rbErr?.code || rbErr?.message || String(rbErr)}`);
          break;
        }
      }
    }
    rollbackIncomplete = rollbackErrors.length > 0;
    if (!rollbackIncomplete) {
      try {
        if (fs.existsSync(journalPath)) fs.unlinkSync(assertNoLinks(journalPath));
      } catch {}
    }
    try {
      updateRuntimeState(resolvedTarget, {
        staged: {
          status: "failed",
          version: resolvedManifest.version,
          manifestDigest: resolvedManifest.manifestDigest,
          stageDir: null,
          closureVerified: false,
          importVerified: false,
          error: rollbackIncomplete
            ? `${err.message} (rollback incomplete: ${rollbackErrors.join("; ")})`
            : err.message,
          code: rollbackIncomplete
            ? "RUNTIME_CUTOVER_RECOVERY_FAILED"
            : err.code || "RUNTIME_CUTOVER_FAILED",
          updatedAt: new Date().toISOString(),
        },
      });
    } catch {}
    throw err;
  } finally {
    activeCutoverTargets.delete(targetKey);
    cleanupDirectorySafe(resolvedStage);
    if (!rollbackIncomplete) {
      cleanupDirectorySafe(backupDir);
      try {
        if (fs.existsSync(journalPath)) fs.unlinkSync(assertNoLinks(journalPath));
      } catch {}
    }
  }

  const states = inspectRuntimeGenerations(resolvedTarget, { resident });
  return {
    ok: true,
    activated: true,
    manifest: resolvedManifest,
    runtimeStates: states,
    ...states,
  };
}

export function stageAndActivateRuntime({
  sourceDir,
  targetDir,
  manifest = null,
  expectedVersion = null,
  activate = true,
  verifyImports = true,
  runImportCheck = defaultRunImportCheck,
  onBeforeStageFile = null,
  onAfterStageFile = null,
  onDuringBackup = null,
  onDuringCutover = null,
  resident = null,
} = {}) {
  const stagedResult = stageRuntimeRelease({
    sourceDir,
    targetDir,
    manifest,
    expectedVersion,
    verifyImports,
    runImportCheck,
    onBeforeStageFile,
    onAfterStageFile,
  });

  if (!activate) {
    const states = inspectRuntimeGenerations(targetDir, { resident });
    return {
      ok: true,
      activated: false,
      stageDir: stagedResult.stageDir,
      manifest: stagedResult.manifest,
      cleanup: stagedResult.cleanup,
      runtimeStates: states,
      ...states,
    };
  }

  return activateStagedRuntime({
    stageDir: stagedResult.stageDir,
    targetDir,
    manifest: stagedResult.manifest,
    onDuringBackup,
    onDuringCutover,
    resident,
  });
}

