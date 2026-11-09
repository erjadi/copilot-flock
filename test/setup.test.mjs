import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const fakeSignalr = "Endpoint=https://example.service.signalr.net;AccessKey=synthetic;";
const fakeServiceBus = "Endpoint=sb://example.servicebus.windows.net/;SharedAccessKey=synthetic;";
const cleanEnv = {
  ...process.env,
  SIGNALR_CONNECTION_STRING: "",
  SERVICEBUS_CONNECTION_STRING: "",
  COPILOT_FLOCK_INVITE_FILE: "",
  COPILOT_FLOCK_BOOTSTRAP_URL: "",
  COPILOT_FLOCK_SCOPE: "",
  COPILOT_BRIDGE_SCOPE: "",
};
const readJournal = (file) => fs.existsSync(file)
  ? fs.readFileSync(file, "utf8").trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line.replace(/^\uFEFF/, "")))
  : [];

function runPowerShell(options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-setup-ps-"));
  const journal = path.join(directory, "journal.jsonl");
  try {
    const wrapper = path.join(directory, "wrapper.ps1");
    fs.writeFileSync(wrapper, `
$global:FakeAzAvailable = $env:MOCK_AZ_AVAILABLE -eq "1"
function Get-Command {
    if ($args[0] -eq "az") {
        if ($global:FakeAzAvailable) { return [PSCustomObject]@{ Name = "az" } }
        return $null
    }
    Microsoft.PowerShell.Core\\Get-Command @args
}
function Write-Journal($Kind, $Values) {
    @{ kind = $Kind; args = @($Values) } | ConvertTo-Json -Compress | Add-Content -Encoding UTF8 $env:SETUP_JOURNAL
}
function winget {
    Write-Journal "winget" $args
    if ($env:MOCK_FAIL -eq "install") { $global:LASTEXITCODE = 9; return }
    $global:FakeAzAvailable = $true
    $global:LASTEXITCODE = 0
}
function az {
    Write-Journal "az" $args
    $global:LASTEXITCODE = 0
    if ($args[0] -eq "account") {
        if ($env:MOCK_NATIVE_ACCOUNT_ERROR -eq "1") {
            & $env:ComSpec /c "echo demo-auth-required 1>&2 & exit /b 1"
        }
        if ($env:MOCK_AUTH -ne "1") { $global:LASTEXITCODE = 1 }
    } elseif ($args[0] -eq "login" -and $env:MOCK_FAIL -eq "login") {
        $global:LASTEXITCODE = 9
    } elseif ($args[0] -eq "group" -and $env:MOCK_FAIL -eq "group") {
        $global:LASTEXITCODE = 9
    } elseif ($args[0] -eq "deployment") {
        if ($env:MOCK_FAIL -eq "deployment") { $global:LASTEXITCODE = 9; return }
        if ($env:MOCK_FAIL -eq "malformed") { return '{invalid-json' }
        if ($env:MOCK_FAIL -eq "output") { return '{"signalrConnectionString":{"value":42}}' }
        return $env:MOCK_OUTPUT
    }
}
function node {
    if ($args[0] -eq "--version") {
        $global:LASTEXITCODE = 0
        if ($env:MOCK_NODE_VERSION) { return $env:MOCK_NODE_VERSION }
        return "v24.0.0"
    }
    Write-Journal "node" $args
    $global:LASTEXITCODE = 0
}
if ($env:MOCK_LEGACY -eq "1") {
    & $env:MANAGED_SETUP_SCRIPT -Legacy -Scope personal -MachineId DEMO-PC -ConnectionString $env:MOCK_SIGNALR -ServiceBusConnectionString $env:MOCK_SERVICEBUS
} elseif ($env:MOCK_ZERO -eq "1") {
    & $env:MANAGED_SETUP_SCRIPT -ProvisionAzure -ResourceGroup rg-demo -Location eastus -Scope personal -RosterRepository demo-owner/rosters -PublishRoster
} else {
    & $env:MANAGED_SETUP_SCRIPT -Legacy -ProvisionAzure -ResourceGroup rg-demo -Location eastus -Scope personal -MachineId DEMO-PC
}
`);
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper], {
      cwd: root,
      encoding: "utf8",
      timeout: 30000,
      env: {
        ...cleanEnv,
        COPILOT_HOME: path.join(directory, "copilot-home"),
        MANAGED_SETUP_SCRIPT: path.join(root, "setup.ps1"),
        SETUP_JOURNAL: journal,
        MOCK_AZ_AVAILABLE: options.available ? "1" : "0",
        MOCK_AUTH: options.authenticated ? "1" : "0",
        MOCK_FAIL: options.fail || "",
        MOCK_LEGACY: options.legacy ? "1" : "0",
        MOCK_ZERO: options.zero ? "1" : "0",
        MOCK_NATIVE_ACCOUNT_ERROR: options.nativeAccountError ? "1" : "0",
        MOCK_NODE_VERSION: options.nodeVersion || "",
        MOCK_SIGNALR: fakeSignalr,
        MOCK_SERVICEBUS: fakeServiceBus,
        MOCK_OUTPUT: JSON.stringify({
          signalrConnectionString: { value: fakeSignalr },
          serviceBusConnectionString: { value: fakeServiceBus },
        }),
      },
    });
    return { ...result, events: readJournal(journal) };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("managed PowerShell setup installs missing CLI, authenticates, deploys and passes keys without printing them", { skip: process.platform !== "win32" }, () => {
  const result = runPowerShell();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.events.filter((event) => event.kind === "winget").length, 1);
  assert.ok(result.events.some((event) => event.kind === "az" && event.args[0] === "login"));
  const deployment = result.events.find((event) => event.kind === "az" && event.args[0] === "deployment");
  assert.ok(deployment.args.includes("properties.outputs"));
  assert.ok(deployment.args.some((arg) => String(arg).endsWith("azuredeploy.json")));
  const installed = result.events.find((event) => event.kind === "node");
  assert.ok(installed.args.includes(fakeSignalr) && installed.args.includes(fakeServiceBus));
  assert.ok(!result.stdout.includes(fakeSignalr) && !result.stdout.includes(fakeServiceBus));
  const older = runPowerShell({ zero: true, nodeVersion: "v22.5.0" });
  assert.equal(older.status, 0, older.stderr);
  assert.ok(older.events.find((event) => event.kind === "node").args.includes("--experimental-sqlite"));
});

test("managed Zero-Broker PowerShell setup forwards secret deployment outputs over stdin, not credential arguments", { skip: process.platform !== "win32" }, () => {
  const result = runPowerShell({ zero: true });
  assert.equal(result.status, 0, result.stderr);
  const installed = result.events.find((event) => event.kind === "node");
  assert.ok(installed.args.includes("--azure-output-stdin") && installed.args.includes("--publish-roster"));
  assert.ok(!installed.args.includes(fakeSignalr) && !installed.args.includes(fakeServiceBus));
  assert.ok(!result.stdout.includes(fakeSignalr) && !result.stdout.includes(fakeServiceBus));
});

test("PowerShell setup preserves legacy installation and stops before installation on provisioning failures", { skip: process.platform !== "win32" }, () => {
  const ready = runPowerShell({ available: true, authenticated: true });
  assert.equal(ready.status, 0, ready.stderr);
  assert.ok(!ready.events.some((event) => event.kind === "winget" || (event.kind === "az" && event.args[0] === "login")));
  const nativeFailure = runPowerShell({ available: true, nativeAccountError: true });
  assert.equal(nativeFailure.status, 0, nativeFailure.stderr);
  assert.ok(nativeFailure.events.some((event) => event.kind === "az" && event.args[0] === "login"));
  for (const fail of ["install", "login", "group", "deployment", "output", "malformed"]) {
    const result = runPowerShell({ available: fail !== "install", fail });
    assert.notEqual(result.status, 0);
    assert.ok(!result.events.some((event) => event.kind === "node"));
  }
  const legacy = runPowerShell({ legacy: true });
  assert.equal(legacy.status, 0, legacy.stderr);
  for (const nodeVersion of ["v18.20.0", "v22.4.0", "invalid"]) {
    const tooOld = runPowerShell({ nodeVersion });
    assert.notEqual(tooOld.status, 0);
    assert.equal(tooOld.events.length, 0);
  }
  assert.equal(runPowerShell({ available: true, authenticated: true, nodeVersion: "v22.5.0" }).status, 0);
  assert.deepEqual(legacy.events.map((event) => event.kind), ["node"]);
});

const bashAvailable = spawnSync("bash", ["--version"], { encoding: "utf8", timeout: 5000 }).status === 0;
test("Bash setup syntax is valid", { skip: !bashAvailable }, () => {
  const result = spawnSync("bash", ["--noprofile", "--norc", "-n", "setup.sh"], { cwd: root, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
});

test("Bash setup uses headless authentication, validates outputs, and preserves the non-provisioning path with local stubs", { skip: !bashAvailable }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-setup-bash-"));
  try {
    const bin = path.join(directory, "bin");
    const journal = path.join(directory, "journal.jsonl");
    fs.mkdirSync(bin);
    fs.copyFileSync(path.join(root, "setup.sh"), path.join(directory, "setup.sh"));
    fs.mkdirSync(path.join(directory, "infra"));
    fs.copyFileSync(path.join(root, "infra", "azuredeploy.json"), path.join(directory, "infra", "azuredeploy.json"));
    fs.writeFileSync(path.join(directory, "wrapper.sh"), `#!/usr/bin/env bash
set -euo pipefail
export DEMO_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export COPILOT_HOME="$DEMO_DIR/copilot-home"
export PATH="$DEMO_DIR/bin:$PATH"
if command -v cygpath >/dev/null 2>&1; then export REAL_NODE="$(cygpath -u "$REAL_NODE")"; fi
exec bash "$DEMO_DIR/setup.sh" "$@"
`);
    fs.writeFileSync(path.join(bin, "uname"), "#!/usr/bin/env bash\nprintf 'Linux\\n'\n", { mode: 0o755 });
    fs.writeFileSync(path.join(bin, "az"), '#!/usr/bin/env bash\nexec "$REAL_NODE" "$DEMO_DIR/mock-az.mjs" "$@"\n', { mode: 0o755 });
    fs.writeFileSync(path.join(bin, "node"), `#!/usr/bin/env bash
if [[ "$*" == *flock.mjs* ]]; then exec "$REAL_NODE" "$DEMO_DIR/mock-node.mjs" "$@"; fi
if [[ "\${1:-}" == --version && -n "\${MOCK_NODE_VERSION:-}" ]]; then printf '%s\\n' "$MOCK_NODE_VERSION"; exit 0; fi
exec "$REAL_NODE" "$@"
`, { mode: 0o755 });
    fs.writeFileSync(path.join(directory, "mock-az.mjs"), `
import fs from "node:fs";
const args = process.argv.slice(2);
fs.appendFileSync(process.env.SETUP_JOURNAL, JSON.stringify({ kind: "az", args }) + "\\n");
if (args[0] === "account") process.exit(process.env.MOCK_AUTH === "1" ? 0 : 1);
if (args[0] === "login" && process.env.MOCK_FAIL === "login") process.exit(9);
if (args[0] === "group" && process.env.MOCK_FAIL === "group") process.exit(9);
if (args[0] === "deployment" && process.env.MOCK_FAIL === "deployment") process.exit(9);
if (args[0] === "deployment" && process.env.MOCK_FAIL === "malformed") { process.stdout.write("{invalid-json"); process.exit(0); }
if (args[0] === "deployment") process.stdout.write(process.env.MOCK_FAIL === "output" ? "{}" : process.env.MOCK_OUTPUT);
`);
    fs.writeFileSync(path.join(directory, "mock-node.mjs"), `
import fs from "node:fs";
fs.appendFileSync(process.env.SETUP_JOURNAL, JSON.stringify({ kind: "node", args: process.argv.slice(2) }) + "\\n");
`);
    const run = (args, settings = {}) => {
      if (fs.existsSync(journal)) fs.unlinkSync(journal);
      const result = spawnSync("bash", ["--noprofile", "--norc", "wrapper.sh", ...args, ...(settings.zero ? [] : ["--legacy"])], {
        cwd: directory, encoding: "utf8", timeout: 30000,
        env: {
          ...cleanEnv, DISPLAY: "", REAL_NODE: process.execPath, SETUP_JOURNAL: journal,
          MOCK_FAIL: settings.fail || "", MOCK_AUTH: settings.authenticated ? "1" : "0",
          MOCK_NODE_VERSION: settings.nodeVersion || "",
          MOCK_OUTPUT: JSON.stringify({
            signalrConnectionString: { value: fakeSignalr },
            serviceBusConnectionString: { value: fakeServiceBus },
          }),
        },
      });
      return { ...result, events: readJournal(journal) };
    };
    const managed = run(["--provision-azure", "--scope", "personal", "--resource-group", "rg-demo", "--location", "eastus"]);
    assert.equal(managed.status, 0, managed.stderr);
    assert.ok(managed.events.some((event) => event.kind === "az" && event.args[0] === "login" && event.args.includes("--use-device-code")));
    const installed = managed.events.find((event) => event.kind === "node");
    assert.ok(installed.args.includes(fakeSignalr) && installed.args.includes(fakeServiceBus));
    assert.ok(!managed.stdout.includes(fakeSignalr) && !managed.stdout.includes(fakeServiceBus));
    const zero = run(["--provision-azure", "--roster-repository", "demo-owner/rosters", "--publish-roster"], { zero: true });
    assert.equal(zero.status, 0, zero.stderr);
    assert.ok(zero.events.find((event) => event.kind === "node").args.includes("--azure-output-stdin"));
    assert.ok(!zero.events.find((event) => event.kind === "node").args.includes(fakeSignalr));
    const olderZero = run(["--provision-azure", "--roster-repository", "demo-owner/rosters", "--publish-roster"], { zero: true, nodeVersion: "v22.5.0" });
    assert.equal(olderZero.status, 0, olderZero.stderr);
    assert.ok(olderZero.events.find((event) => event.kind === "node").args.includes("--experimental-sqlite"));
    for (const fail of ["login", "group", "deployment", "output", "malformed"]) {
      const failed = run(["--provision-azure"], { fail });
      assert.notEqual(failed.status, 0);
      assert.ok(!failed.events.some((event) => event.kind === "node"));
    }
    const legacy = run(["--scope", "personal", "--connection-string", fakeSignalr, "--servicebus-connection-string", fakeServiceBus]);
    assert.equal(legacy.status, 0, legacy.stderr);
    assert.deepEqual(legacy.events.map((event) => event.kind), ["node"]);
    const conflict = run(["--provision-azure", "--invite-file", "demo-invite.json"]);
    assert.notEqual(conflict.status, 0);
    assert.equal(conflict.events.length, 0);
    for (const nodeVersion of ["v18.20.0", "v22.4.0", "invalid"]) {
      const tooOld = run(["--provision-azure"], { nodeVersion });
      assert.notEqual(tooOld.status, 0);
      assert.equal(tooOld.events.length, 0);
    }
    assert.equal(run(["--provision-azure"], { authenticated: true, nodeVersion: "v22.5.0" }).status, 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
