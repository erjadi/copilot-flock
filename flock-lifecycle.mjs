import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { signLeave } from "./flock-membership.mjs";

const hash = (data) => crypto.createHash("sha256").update(data).digest("hex");
const names = ["copilot-flock", "copilot-signalr-bridge"];
const runtimeFiles = [
  "flock.mjs", "bridge.mjs", "flock-lifecycle.mjs", "flock-membership.mjs",
  "config.json", "identity.json", "flocks.json", "state.json", "daemon.pid",
  "daemon-identity.json", "daemon.log", "inbox.jsonl", "outbox.jsonl", "locks.json",
  "cli-sessions.json", "processed-offline-ids.json", "last-vote-report.json",
  "installation.json", "uninstall-progress.json",
  "flock-protocol.mjs", "flock-azure.mjs", "flock-broker-free.mjs", "broker-free.json",
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
      { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "pipe"] }).trim();
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
    exec("systemd-run", ["--user", "--version"], { stdio: "ignore", timeout: 3000 });
    exec("systemctl", ["--user", "show-environment"], { stdio: "ignore", timeout: 3000 });
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
  const child = spawnFn(spec.command, spec.args, spawnOptions);
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
    encoding: "utf8", timeout: 6000, stdio: ["ignore", "pipe", "pipe"],
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
  checkLinger = (user) => execFileSync("loginctl", ["show-user", user, "-p", "Linger", "--value"], { encoding: "utf8", timeout: 4000 }),
  enableLinger = (user) => execFileSync("sudo", ["-n", "loginctl", "enable-linger", user], { stdio: "ignore", timeout: 4000 }),
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
      { timeout: 6000, stdio: ["ignore", "pipe", "pipe"] });
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
    : execFileSync("ps", ["-axo", "uid=,pid="], { encoding: "utf8", timeout: 5000 }).split("\n")
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
