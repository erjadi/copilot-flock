import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
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
    JSON.parse(fs.readFileSync(temporary, "utf8"));
    assertNoLinks(filename);
    const current = fs.existsSync(filename) ? fs.readFileSync(filename) : null;
    if (before === null ? current !== null : !current?.equals(before)) {
      throw new Error(`Concurrent config change: ${filename}`);
    }
    fs.renameSync(temporary, filename);
    if (process.platform !== "win32") {
      const directory = fs.openSync(path.dirname(filename), "r");
      try { fs.fsyncSync(directory); }
      finally { fs.closeSync(directory); }
    }
  } finally {
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
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
  return scripts.some((script) => identity.command === `"${identity.executable}" "${script}" daemon` ||
    identity.command === `${identity.executable} ${script} daemon`);
}

export async function stopPinnedDaemon(root, paths, {
  inspect = inspectProcess, kill = (pid) => process.kill(pid),
  delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
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

async function disablePersistence(filename, paths) {
  if (paths.platform === "linux") {
    execFileSync("systemctl", ["--user", "disable", "--now", path.basename(filename)],
      { timeout: 6000, stdio: ["ignore", "pipe", "pipe"] });
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
  findProcesses = findRuntimeClients,
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
    } catch (error) { report.retained.push({ path: filename, reason: error.message }); }
  }
  if (report.retained.some(({ path: filename }) => paths.persistence.includes(filename))) return report;
  for (const { root } of installations) {
    try { await stopDaemon(root, paths); }
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
