import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validateDeployment, runManagedSetup, createBrokerZip, waitForBroker } from "../managed-azure-setup.mjs";
import { createBootstrapServer } from "../bootstrap-server.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const subscription = "11111111-2222-3333-4444-555555555555";
const options = { subscription, resourceGroup: "rg-demo", githubUser: "demo-owner", scope: "personal" };
const values = {
  subscriptionId: subscription, signalrName: "demo-signalr", signalrHostName: "demo-signalr.service.signalr.net",
  serviceBusNamespaceName: "demo-sb", serviceBusEndpoint: "sb://demo-sb.servicebus.windows.net/",
  serviceBusTopicName: "copilot-bridge-offline", webAppName: "demo-broker",
  bootstrapUrl: "https://demo-broker.azurewebsites.net",
};
const outputs = (changes = {}) => Object.fromEntries(Object.entries({ ...values, ...changes })
  .map(([key, value]) => [key, { type: "string", value }]));
const signalr = "Endpoint=https://demo-signalr.service.signalr.net;AccessKey=synthetic-secret;";
const serviceBus = "Endpoint=sb://demo-sb.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=synthetic-secret;";

function adapters(overrides = {}) {
  const events = [];
  return { events,
    runAz: async (args) => {
      events.push(["az", args]);
      return JSON.stringify({ primaryConnectionString: args[0] === "signalr" ? signalr : serviceBus });
    },
    createBrokerZip: (zip) => { createBrokerZip(zip); events.push(["zip", zip]); },
    waitForBroker: async (url) => { events.push(["health", url]); },
    install: async (args) => {
      events.push(["install", args, process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN]);
      return { memberRegistered: true, enrolledFlockCount: 2 };
    }, ...overrides,
  };
}

test("complete conditional ARM stack wires runtime, credentials, persistent storage, identity and namespace role", () => {
  const template = JSON.parse(fs.readFileSync(path.join(root, "infra", "azuredeploy.json"), "utf8"));
  assert.equal(template.parameters.deployTokenBroker.defaultValue, true);
  assert.equal(template.parameters.appServiceSku.defaultValue, "B1");
  assert.equal(template.parameters.allowedGithubRepo.defaultValue, "erjadi/copilot-flock");
  for (const name of ["signalrName", "serviceBusNamespaceName", "webAppName", "appServicePlanName"]) {
    assert.match(template.variables[name], /toLower\(parameters\('namePrefix'\)\)/);
  }
  assert.ok(template.parameters.platformMaintainerUser);
  const plan = template.resources.find((r) => r.type === "Microsoft.Web/serverfarms");
  const site = template.resources.find((r) => r.type === "Microsoft.Web/sites");
  const role = template.resources.find((r) => r.type.endsWith("/roleAssignments"));
  for (const resource of [plan, site, role]) assert.equal(resource.condition, "[parameters('deployTokenBroker')]");
  assert.equal(plan.kind, "linux");
  assert.equal(plan.properties.reserved, true);
  assert.equal(site.properties.httpsOnly, true);
  assert.equal(site.properties.siteConfig.linuxFxVersion, "NODE|22-lts");
  assert.equal(site.properties.siteConfig.appCommandLine, "node bootstrap-server.mjs");
  assert.equal(site.identity.type, "SystemAssigned");
  assert.equal(role.properties.principalType, "ServicePrincipal");
  assert.match(role.properties.principalId, /Microsoft.Web\/sites/);
  assert.match(role.properties.principalId, /^\[if\(parameters\('deployTokenBroker'\)/);
  assert.match(template.variables.serviceBusDataOwnerRole, /090c5cfd-751d-490a-894a-3ce6f1109419/);
  const settings = Object.fromEntries(site.properties.siteConfig.appSettings.map((s) => [s.name, s.value]));
  assert.match(settings.SIGNALR_CONNECTION_STRING, /listKeys/);
  assert.match(settings.SERVICEBUS_CONNECTION_STRING, /RootManageSharedAccessKey/);
  assert.match(settings.SERVICEBUS_NAMESPACE, /servicebus\.windows\.net/);
  assert.equal(settings.SERVICEBUS_TOPIC, "[parameters('serviceBusTopicName')]");
  assert.equal(settings.PLATFORM_MAINTAINER_USER, "[parameters('platformMaintainerUser')]");
  assert.equal(settings.ALLOWED_GITHUB_REPO, "[parameters('allowedGithubRepo')]");
  assert.equal(settings.COPILOT_FLOCK_HUB, "copilotbridge");
  assert.equal(settings.SCM_DO_BUILD_DURING_DEPLOYMENT, "false");
  assert.equal(settings.WEBSITES_ENABLE_APP_SERVICE_STORAGE, "true");
  assert.deepEqual(Object.keys(template.outputs).sort(), Object.keys(values).sort());
  assert.doesNotMatch(JSON.stringify(template.outputs), /listKeys|AccessKey|ConnectionString/i);
});

test("managed installation pins key reads and broker origin, deploys temporary ZIP before install, and restores pin", async () => {
  const a = adapters();
  const old = process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
  await runManagedSetup(outputs(), options, a);
  assert.deepEqual(a.events.map((e) => e[0]), ["az", "az", "zip", "az", "health", "install"]);
  for (const [, args] of a.events.filter((e) => e[0] === "az")) {
    assert.equal(args[args.indexOf("--subscription") + 1], subscription);
    assert.equal(args[args.indexOf("--resource-group") + 1], "rg-demo");
    assert.ok(!args.some((arg) => arg.includes("synthetic-secret")));
  }
  assert.ok(a.events[0][1].includes("demo-signalr"));
  assert.ok(a.events[1][1].includes("demo-sb"));
  assert.ok(a.events[1][1].includes("RootManageSharedAccessKey"));
  const installed = a.events.at(-1);
  assert.equal(installed[1].connectionStringArg, signalr);
  assert.equal(installed[1].serviceBusConnectionStringArg, serviceBus);
  assert.equal(installed[1].bootstrapUrlArg, values.bootstrapUrl);
  assert.equal(installed[2], values.bootstrapUrl);
  assert.equal(process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN, old);
  assert.ok(!fs.existsSync(a.events.find((e) => e[0] === "zip")[1]));
});

test("skip broker has no ZIP, webapp deployment, health or bootstrap origin", async () => {
  const a = adapters();
  await runManagedSetup(outputs({ webAppName: "", bootstrapUrl: "" }), { ...options, skipBroker: true }, a);
  assert.deepEqual(a.events.map((e) => e[0]), ["az", "az", "install"]);
  assert.equal(a.events.at(-1)[1].bootstrapUrlArg, null);
});

test("invalid metadata and legacy secret outputs reject before key reads or initialization", async () => {
  for (const change of [{ subscriptionId: "other" }, { signalrHostName: "attacker.invalid" },
    { serviceBusEndpoint: "sb://other/" }, { bootstrapUrl: "http://demo-broker.azurewebsites.net" },
    { signalrConnectionString: signalr }, { webAppName: "../evil" }, { serviceBusTopicName: "other" }]) {
    const a = adapters();
    await assert.rejects(runManagedSetup(outputs(change), options, a));
    assert.equal(a.events.length, 0);
  }
  assert.throws(() => validateDeployment({}, options), /Missing/);
});

test("denied/malformed/wrong-resource keys, broker deployment and readiness failures never initialize locally or expose captured secrets", async () => {
  for (const stage of ["denied", "malformed", "empty-key", "wrong-resource", "deploy", "health", "archive"]) {
    let zip;
    let installs = 0;
    const a = adapters({
      runAz: async (args) => {
        if (stage === "denied" || (stage === "deploy" && args[0] === "webapp")) throw Error("synthetic-secret");
        if (stage === "malformed") return "synthetic-secret";
        if (stage === "empty-key") return JSON.stringify({ primaryConnectionString: "Endpoint=https://demo-signalr.service.signalr.net;AccessKey=;" });
        if (stage === "wrong-resource") return JSON.stringify({ primaryConnectionString: "Endpoint=https://wrong;AccessKey=synthetic-secret;" });
        return JSON.stringify({ primaryConnectionString: args[0] === "signalr" ? signalr : serviceBus });
      },
      createBrokerZip: (destination) => { zip = destination; if (stage === "archive") throw Error("archive failed"); createBrokerZip(destination); },
      waitForBroker: async () => { if (stage === "health") throw Error("readiness failed"); },
      install: async () => { installs++; },
    });
    await assert.rejects(runManagedSetup(outputs(), options, a), (error) => !error.message.includes("synthetic-secret"));
    assert.equal(installs, 0);
    if (zip) assert.ok(!fs.existsSync(path.dirname(zip)));
  }
});

test("actual mirrored registration blocks report enrollment only after successful local persistence", async () => {
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  for (const filename of ["flock.mjs", "bridge.mjs"]) {
    const source = fs.readFileSync(path.join(root, filename), "utf8");
    const start = source.indexOf("  let memberRegistration = null;", source.indexOf("export async function installBridge"));
    const end = source.indexOf("  // 1. Copy flock.mjs", start);
    assert.ok(start > 0 && end > start);
    const registration = new AsyncFunction("registerWithBootstrapServer", "ensureMachineIdentityKeypair",
      "callBootstrapV3Endpoint", "applyV3EnrollmentResult", "formatErrorDetail",
      `const cfg = {machineId:"DEMO-PC", scope:"personal"}; const sandboxMode=false; const parsedEnrollmentJson=null;
      ${source.slice(start, end)}
      return {memberRegistration, enrolledFlockCount, enrollmentError};`);
    const resultBlock = source.slice(source.indexOf("  return {", end),
      source.indexOf("function generateTopologySkillMarkdown", end));
    assert.match(resultBlock, /\benrollmentError,/);
    for (const failure of ["none", "enroll", "save", "rejected", "validation"]) {
      let saves = 0;
      const result = await registration(async () => ({ ok: true }), () => ({ fingerprint: "synthetic", publicKey: "synthetic" }),
        async () => {
          if (failure === "enroll") throw Error("synthetic enrollment failure");
          if (failure === "rejected") return { ok: false, error: "synthetic broker rejection" };
          return { ok: true, enrolledFlocks: [{ flockId: "demo-flock" }] };
        }, (_cfg, enrollment) => {
          saves++;
          if (failure === "save") throw Error("synthetic storage failure");
          if (failure === "validation") throw Error("unverified owner authority");
          return enrollment;
        }, (error) => error.message);
      assert.equal(result.memberRegistration.ok, true);
      assert.equal(result.enrolledFlockCount, failure === "none" ? 1 : 0);
      assert.equal(saves, failure === "enroll" || failure === "rejected" ? 0 : 1);
      if (failure === "none") assert.equal(result.enrollmentError, null);
      else assert.match(result.enrollmentError, /synthetic|unverified owner authority/);
    }
  }
});

test("conflicting explicit origin pin cannot be silently replaced", async () => {
  const previous = process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
  process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN = "https://different.azurewebsites.net";
  try {
    const a = adapters();
    await assert.rejects(runManagedSetup(outputs(), options, a), /pin differs/);
    assert.ok(!a.events.some((event) => ["install", "zip"].includes(event[0])));
  } finally {
    if (previous === undefined) delete process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
    else process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN = previous;
  }
});

test("local installer failures are explicit, keys withheld, and incomplete broker enrollment is not success", async () => {
  for (const install of [
    async () => { throw Error(signalr); },
    async () => ({ memberRegistered: false, enrolledFlockCount: 0 }),
    async () => ({ memberRegistered: true, enrolledFlockCount: 0 }),
  ]) {
    await assert.rejects(runManagedSetup(outputs(), options, adapters({ install })),
      (error) => /installation failed|invites are not ready/.test(error.message) && !error.message.includes("synthetic-secret"));
  }
});

test("readiness checks actual status fields, retries cold starts and rejects unconfigured or unavailable brokers", async () => {
  let calls = 0;
  let waits = 0;
  await waitForBroker(values.bootstrapUrl, {
    attempts: 3, delay: async () => { waits++; },
    fetchImpl: async (url, opts) => {
      assert.equal(url, `${values.bootstrapUrl}/health`);
      assert.equal(opts.redirect, "error");
      calls++;
      if (calls === 1) throw Error("cold start");
      return { ok: true, json: async () => calls === 2 ? {} :
        { ok: true, service: "copilot-flock-bootstrap", configured: true, msiConfigured: true } };
    },
  });
  assert.equal(calls, 3);
  assert.equal(waits, 2);
  for (const status of [{}, { ok: true, configured: true, msiConfigured: false }]) {
    await assert.rejects(waitForBroker(values.bootstrapUrl, { attempts: 2, delay: async () => {},
      fetchImpl: async () => ({ ok: true, json: async () => status }) }), /timed out/);
  }
});

test("broker /health is an actual HTTP alias without credential disclosure", async () => {
  const server = createBootstrapServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    for (const endpoint of ["/health", "/healthz"]) {
      const response = await fetch(`http://127.0.0.1:${server.address().port}${endpoint}`);
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.service, "copilot-flock-bootstrap");
      assert.equal(typeof body.configured, "boolean");
      assert.doesNotMatch(JSON.stringify(body), /AccessKey|ConnectionString/);
    }
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test("ZIP contains exactly the current two broker source files and opens with the Windows archive reader", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-zip-test-"));
  try {
    const zip = path.join(directory, "broker.zip");
    createBrokerZip(zip);
    const bytes = fs.readFileSync(zip);
    const names = [];
    let offset = 0;
    while (bytes.readUInt32LE(offset) === 0x04034b50) {
      const length = bytes.readUInt32LE(offset + 18);
      const nameLength = bytes.readUInt16LE(offset + 26);
      const name = bytes.subarray(offset + 30, offset + 30 + nameLength).toString();
      const data = bytes.subarray(offset + 30 + nameLength, offset + 30 + nameLength + length);
      assert.deepEqual(data, fs.readFileSync(path.join(root, name)));
      names.push(name);
      offset += 30 + nameLength + length;
    }
    assert.deepEqual(names, ["bootstrap-server.mjs", "package.json"]);
    if (process.platform === "win32") {
      const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
        "Expand-Archive -LiteralPath $env:TEST_ZIP -DestinationPath $env:TEST_DEST -ErrorAction Stop"],
      { encoding: "utf8", timeout: 30000, env: { ...process.env, TEST_ZIP: zip, TEST_DEST: path.join(directory, "expanded") } });
      assert.equal(result.status, 0, result.stderr);
      for (const name of names) assert.deepEqual(fs.readFileSync(path.join(directory, "expanded", name)), fs.readFileSync(path.join(root, name)));
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("actual managed CLI and Azure subprocess withhold key-command stdout/stderr and stop on denial", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flock-key-denial-"));
  const journal = path.join(directory, "args.json");
  try {
    const stub = path.join(directory, "azure-denial.mjs");
    fs.writeFileSync(stub, `
import fs from "node:fs";
fs.writeFileSync(process.env.AZ_DENIAL_JOURNAL, JSON.stringify(process.argv.slice(2)));
console.log("synthetic-secret-command-stdout");
console.error("synthetic-secret-command-stderr");
process.exitCode = 9;
`);
    fs.writeFileSync(path.join(directory, process.platform === "win32" ? "az.cmd" : "az"),
      process.platform === "win32"
        ? `@echo off\r\n"${process.execPath}" "${stub}" %*\r\n`
        : `#!/bin/sh\nexec "${process.execPath}" "${stub}" "$@"\n`, { mode: 0o755 });
    const result = spawnSync(process.execPath, [path.join(root, "managed-azure-setup.mjs"),
      "--subscription", subscription, "--resource-group", "rg-demo", "--github-user", "demo-owner"], {
      input: JSON.stringify(outputs()), encoding: "utf8", timeout: 30000,
      env: { ...process.env, PATH: `${directory}${path.delimiter}${process.env.PATH}`,
        AZ_DENIAL_JOURNAL: journal },
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Authorized Azure key retrieval failed/);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-secret-command/);
    const args = JSON.parse(fs.readFileSync(journal, "utf8"));
    assert.deepEqual(args.slice(0, 3), ["signalr", "key", "list"]);
    assert.ok(args.includes(subscription) && args.includes("rg-demo") && args.includes("demo-signalr"));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
