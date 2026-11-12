import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const powerShell = process.platform === "win32" ? "powershell.exe" : "pwsh";
const subscription = "11111111-2222-3333-4444-555555555555";
const metadata = Object.fromEntries(Object.entries({
  subscriptionId: subscription, signalrName: "demo-signalr",
  signalrHostName: "demo-signalr.service.signalr.net",
  serviceBusNamespaceName: "demo-sb", serviceBusEndpoint: "sb://demo-sb.servicebus.windows.net/",
  serviceBusTopicName: "copilot-bridge-offline",
  webAppName: "demo-broker", bootstrapUrl: "https://demo-broker.azurewebsites.net",
}).map(([key, value]) => [key, { type: "string", value }]));
const env = { ...process.env, SIGNALR_CONNECTION_STRING: "", SERVICEBUS_CONNECTION_STRING: "",
  COPILOT_FLOCK_INVITE_FILE: "", COPILOT_FLOCK_BOOTSTRAP_URL: "",
  COPILOT_FLOCK_SCOPE: "", COPILOT_BRIDGE_SCOPE: "", GITHUB_USER: "demo-owner",
  COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN: "", COPILOT_BRIDGE_ALLOWED_BOOTSTRAP_ORIGIN: "" };

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-setup-entry-"));
  const journal = path.join(directory, "journal.jsonl");
  fs.writeFileSync(path.join(directory, "driver.mjs"), `
import fs from "node:fs";
import { runManagedCli } from ${JSON.stringify(pathToFileURL(path.join(root, "managed-azure-setup.mjs")).href)};
const args = process.argv.slice(2);
const log = (kind, args) => fs.appendFileSync(process.env.JOURNAL, JSON.stringify({kind, args}) + "\\n");
if (args[0].endsWith("flock.mjs")) { log("legacy", args); process.exit(0); }
try {
  await runManagedCli(args.slice(1), fs.readFileSync(0, "utf8"), {
    runAz: async (args) => {
      log("managed-az", args);
      if (process.env.MOCK_FAIL === "keys") throw Error("synthetic-key-do-not-print");
      if (args[0] === "webapp") return "";
      return JSON.stringify({primaryConnectionString: args[0] === "signalr"
        ? "Endpoint=https://demo-signalr.service.signalr.net;AccessKey=synthetic-key-do-not-print;"
        : "Endpoint=sb://demo-sb.servicebus.windows.net/;SharedAccessKeyName=" + args[args.indexOf("--name")+1] + ";SharedAccessKey=synthetic-key-do-not-print;"});
    },
    waitForBroker: async (url) => { log("health", [url]); },
    install: async (options) => {
      log("install", [options.bootstrapUrlArg, options.scopeArg, options.machineIdArg, options.githubUserArg]);
      return {memberRegistered:true, enrolledFlockCount:2};
    },
  });
} catch (error) { console.error(error.message); process.exitCode = 1; }
`);
  const outputs = (skip) => JSON.stringify(skip ? {
    ...metadata, bootstrapUrl: { value: "" }, webAppName: { value: "" },
  } : metadata);
  return {
    directory, journal, outputs,
    result(result) {
      const events = fs.existsSync(journal) ? fs.readFileSync(journal, "utf8")
        .split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line.replace(/^\uFEFF/, ""))) : [];
      return { ...result, events };
    },
    close() { fs.rmSync(directory, { recursive: true, force: true }); },
  };
}

function runPowerShell({ fail = "", skip = false, legacy = false, githubUser = "demo-owner" } = {}) {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.directory, "wrapper.ps1"), `
$global:Available = $false
function Get-Command {
  if ($args[0] -eq "az") { if ($global:Available) { return @{Name="az"} }; return $null }
  Microsoft.PowerShell.Core\\Get-Command @args
}
function Log($kind, $values) { @{kind=$kind; args=@($values)} | ConvertTo-Json -Compress | Add-Content -Encoding UTF8 $env:JOURNAL }
function winget { Log "winget" $args; $global:Available=$true; $global:LASTEXITCODE=0; if ($env:MOCK_FAIL -eq "cli") {$global:LASTEXITCODE=9} }
function gh { Log "gh" $args; $global:LASTEXITCODE=0; return "demo-owner" }
function az {
  Log "az" $args; $global:LASTEXITCODE=0
  if ($args[0] -eq "account" -and $args[1] -eq "show") {
    if ($args -contains "--query") { return $env:SUBSCRIPTION }
    $global:LASTEXITCODE=1
  }
  if ($args[0] -eq $env:MOCK_FAIL) {
    if ($args[0] -eq "deployment") { Write-Error "synthetic-key-do-not-print" }
    $global:LASTEXITCODE=9; return
  }
  if ($args[0] -eq "deployment") { return $env:OUTPUTS }
}
function node {
  $body = $input | Out-String
  $body | & $env:REAL_NODE (Join-Path $env:FIXTURE "driver.mjs") @args
  $global:LASTEXITCODE = $LASTEXITCODE
}
$a = @{Scope="personal"; MachineId="DEMO-PC"}
if ($env:LEGACY -eq "1") {$a.ConnectionString="synthetic-direct"}
else {
  $a.ProvisionAzure=$true; $a.SubscriptionId=$env:SUBSCRIPTION
  $a.ResourceGroup="rg-demo"; $a.Location="westus2"; $a.NamePrefix="example"
  if ($env:SKIP -ne "1") {$a.LegacyBroker=$true}
}
& $env:SETUP @a
`);
    const result = spawnSync(powerShell,
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path.join(f.directory, "wrapper.ps1")],
      { cwd: root, encoding: "utf8", timeout: 30000, env: {
        ...env, FIXTURE: f.directory, JOURNAL: f.journal, REAL_NODE: process.execPath,
        SETUP: path.join(root, "setup.ps1"), SUBSCRIPTION: subscription,
        OUTPUTS: fail === "malformed" ? "{invalid" : fail === "metadata" ? "{}" : f.outputs(skip),
        MOCK_FAIL: fail, SKIP: skip ? "1" : "", LEGACY: legacy ? "1" : "", GITHUB_USER: githubUser,
      } });
    assert.ifError(result.error);
    return f.result(result);
  } finally { f.close(); }
}

function checkManaged(result, skip = false, githubUser = "demo-owner") {
  assert.equal(result.status, 0, result.stderr);
  const deployment = result.events.find((event) => event.kind === "az" && event.args[0] === "deployment");
  assert.ok(deployment.args.includes("namePrefix=example"));
  assert.ok(deployment.args.includes("location=westus2"));
  assert.ok(deployment.args.includes(`deployTokenBroker=${!skip}`));
  assert.ok(deployment.args.includes("--subscription"));
  assert.ok(result.events.some((event) => event.kind === "az" && event.args[1] === "set"));
  const install = result.events.find((event) => event.kind === "install");
  assert.deepEqual(install.args, [skip ? null : "https://demo-broker.azurewebsites.net", "personal", "DEMO-PC", githubUser]);
  const deploy = result.events.find((event) => event.kind === "managed-az" && event.args[0] === "webapp");
  assert.equal(Boolean(deploy), !skip);
  if (deploy) {
    assert.ok(deploy.args.includes("--type") && deploy.args.includes("zip"));
    assert.ok(!fs.existsSync(deploy.args[deploy.args.indexOf("--src-path") + 1]));
  }
  assert.doesNotMatch(result.stdout + result.stderr + JSON.stringify(result.events), /synthetic-key-do-not-print/);
}

test("PowerShell actual entrypoint installs CLI, authenticates, selects subscription and deploys default/omitted broker", () => {
  for (const skip of [false, true]) {
    const result = runPowerShell({ skip });
    checkManaged(result, skip);
    assert.ok(result.events.some((event) => event.kind === "winget"));
    assert.ok(result.events.some((event) => event.kind === "az" && event.args[0] === "login"));
  }
  const github = runPowerShell({ githubUser: "" });
  checkManaged(github);
  assert.ok(github.events.some((event) => event.kind === "gh" && event.args.includes(".login")));
});

test("PowerShell actual entrypoint fails before local install and preserves direct setup", () => {
  for (const fail of ["cli", "login", "group", "deployment", "malformed", "metadata", "keys"]) {
    const result = runPowerShell({ fail });
    assert.notEqual(result.status, 0, `${fail}: ${result.stdout}\n${result.stderr}`);
    assert.ok(!result.events.some((event) => event.kind === "install"), fail);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-key-do-not-print/);
  }
  const legacy = runPowerShell({ legacy: true });
  assert.equal(legacy.status, 0, legacy.stderr);
  assert.deepEqual(legacy.events.map((event) => event.kind), ["legacy"]);
});

function ensureBashAvailable() {
  if (spawnSync("bash", ["-c", "true"], { encoding: "utf8", timeout: 5000 }).status === 0) {
    return true;
  }
  if (process.platform === "win32") {
    const candidates = [
      "C:\\Program Files\\Git\\bin",
      "C:\\Program Files\\Git\\usr\\bin",
      process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "Programs", "Git", "bin") : null,
      process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "Programs", "Git", "usr", "bin") : null,
    ].filter(Boolean);
    for (const dir of candidates) {
      const bashExe = path.join(dir, "bash.exe");
      if (fs.existsSync(bashExe)) {
        const nextPath = `${dir}${path.delimiter}${process.env.PATH || ""}`;
        if (
          spawnSync(bashExe, ["-c", "true"], {
            encoding: "utf8",
            timeout: 5000,
            env: { ...process.env, PATH: nextPath },
          }).status === 0
        ) {
          process.env.PATH = nextPath;
          return true;
        }
      }
    }
  }
  return false;
}

const bashAvailable = ensureBashAvailable();
test("Bash syntax and actual managed/direct entrypoint flow with synthetic cloud adapters", (t) => {
  if (!bashAvailable && process.platform === "win32") {
    t.skip("Bash is not available on this Windows host");
    return;
  }
  assert.ok(bashAvailable, "Bash is required to exercise the actual setup entrypoint; missing tools must not skip release coverage");
  assert.equal(spawnSync("bash", ["-n", "setup.sh"], { cwd: root }).status, 0);
  const f = fixture();
  try {
    fs.mkdirSync(path.join(f.directory, "bin"));
    fs.mkdirSync(path.join(f.directory, "infra"));
    fs.copyFileSync(path.join(root, "setup.sh"), path.join(f.directory, "setup.sh"));
    fs.copyFileSync(path.join(root, "infra", "azuredeploy.json"), path.join(f.directory, "infra", "azuredeploy.json"));
    fs.writeFileSync(path.join(f.directory, "wrapper.sh"), `
export DEMO_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export PATH="$DEMO_DIR/bin:$PATH"
if command -v cygpath >/dev/null 2>&1; then export REAL_NODE="$(cygpath -u "$REAL_NODE")"; fi
exec bash "$DEMO_DIR/setup.sh" "$@"
`);
    fs.writeFileSync(path.join(f.directory, "bin", "node"), `#!/usr/bin/env bash
exec "$REAL_NODE" "$DEMO_DIR/driver.mjs" "$@"
`, { mode: 0o755 });
    fs.writeFileSync(path.join(f.directory, "bin", "uname"), "#!/usr/bin/env bash\nprintf 'Linux\\n'\n", { mode: 0o755 });
    fs.writeFileSync(path.join(f.directory, "bin", "az"), `#!/usr/bin/env bash
exec "$REAL_NODE" "$DEMO_DIR/az.mjs" "$@"
`, { mode: 0o755 });
    fs.writeFileSync(path.join(f.directory, "bin", "gh"), `#!/usr/bin/env bash
exec "$REAL_NODE" "$DEMO_DIR/gh.mjs" "$@"
`, { mode: 0o755 });
    fs.writeFileSync(path.join(f.directory, "gh.mjs"), `
import fs from "node:fs";
fs.appendFileSync(process.env.JOURNAL, JSON.stringify({kind:"gh", args:process.argv.slice(2)}) + "\\n");
process.stdout.write("demo-owner");
`);
    fs.writeFileSync(path.join(f.directory, "az.mjs"), `
import fs from "node:fs";
const args = process.argv.slice(2);
fs.appendFileSync(process.env.JOURNAL, JSON.stringify({kind:"az", args}) + "\\n");
if (args[0] === process.env.MOCK_FAIL) {
  if (args[0] === "deployment") console.error("synthetic-key-do-not-print");
  process.exit(9);
}
if (args[0] === "account" && args[1] === "show") {
  if (!args.includes("--query")) process.exit(1);
  process.stdout.write(process.env.SUBSCRIPTION);
}
if (args[0] === "deployment") process.stdout.write(process.env.OUTPUTS);
`);
    const run = (args, fail = "", skip = false) => {
      if (fs.existsSync(f.journal)) fs.unlinkSync(f.journal);
      return f.result(spawnSync("bash", ["--noprofile", "--norc", "wrapper.sh", ...args], {
        cwd: f.directory, encoding: "utf8", timeout: 30000, env: {
          ...env, GITHUB_USER: "", DISPLAY: "", REAL_NODE: process.execPath, JOURNAL: f.journal,
          SUBSCRIPTION: subscription, MOCK_FAIL: fail,
          OUTPUTS: fail === "malformed" ? "{invalid" : fail === "metadata" ? "{}" : f.outputs(skip),
        },
      }));
    };
    const args = ["--provision-azure", "--subscription", subscription, "--resource-group", "rg-demo",
      "--location", "westus2", "--name-prefix", "example", "--scope", "personal", "--machine-id", "DEMO-PC"];
    for (const skip of [false, true]) {
      const result = run([...args, ...(skip ? [] : ["--legacy-broker"])], "", skip);
      checkManaged(result, skip, "demo-owner");
      assert.ok(result.events.some((event) => event.kind === "az" && event.args.includes("--use-device-code")));
      if (!skip) assert.ok(result.events.some((event) => event.kind === "gh"));
    }
    for (const fail of ["login", "group", "deployment", "malformed", "metadata", "keys"]) {
      const result = run([...args, "--legacy-broker"], fail);
      assert.notEqual(result.status, 0, fail);
      assert.ok(!result.events.some((event) => event.kind === "install"), fail);
      assert.doesNotMatch(result.stdout + result.stderr, /synthetic-key-do-not-print/);
    }
    const conflict = run(["--provision-azure", "--invite-file", "demo.json"]);
    assert.notEqual(conflict.status, 0);
    assert.equal(conflict.events.length, 0);
    const direct = run(["--scope", "personal", "--connection-string", "synthetic-direct"]);
    assert.equal(direct.status, 0, direct.stderr);
    assert.deepEqual(direct.events.map((event) => event.kind), ["legacy"]);
  } finally { f.close(); }
});
