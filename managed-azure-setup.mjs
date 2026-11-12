import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";

const root = fileURLToPath(new URL(".", import.meta.url));

export function validateDeployment(outputs, options) {
  options = { ...options, skipBroker: options.legacyBroker !== true };
  const names = ["subscriptionId", "signalrName", "signalrHostName", "serviceBusNamespaceName",
    "serviceBusEndpoint", "serviceBusTopicName", "bootstrapUrl", "webAppName"];
  if (!outputs || typeof outputs !== "object" || Object.keys(outputs).some((name) => !names.includes(name))) {
    throw new Error("Unexpected Azure deployment outputs; refusing local installation.");
  }
  const result = {};
  for (const name of names) {
    if (typeof outputs[name]?.value !== "string") throw new Error(`Missing Azure metadata: ${name}.`);
    result[name] = outputs[name].value;
  }
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(options.subscription || "") ||
      result.subscriptionId !== options.subscription ||
      !/^[\w().-]{1,90}$/.test(options.resourceGroup || "") ||
      !/^[a-z0-9-]{1,63}$/i.test(result.signalrName) ||
      !/^[a-z0-9-]{1,50}$/i.test(result.serviceBusNamespaceName) ||
      result.signalrHostName !== `${result.signalrName}.service.signalr.net` ||
      result.serviceBusEndpoint !== `sb://${result.serviceBusNamespaceName}.servicebus.windows.net/` ||
      result.serviceBusTopicName !== "copilot-bridge-offline" ||
      (options.scope && !["personal", "work"].includes(options.scope))) {
    throw new Error("Azure metadata does not match the selected subscription/resources.");
  }
  if (options.skipBroker) {
    if (result.webAppName || result.bootstrapUrl) throw new Error("Unexpected broker in broker-free deployment.");
    if (!/^[a-z0-9][a-z0-9-]{0,38}$/i.test(options.githubUser || "") ||
        !["personal", "work"].includes(options.scope)) throw new Error("Explicit owner label and scope required for new broker-free enrollment");
  } else if (!/^[a-z0-9-]{2,60}$/i.test(result.webAppName) ||
      result.bootstrapUrl !== `https://${result.webAppName}.azurewebsites.net` ||
      !/^[a-z0-9][a-z0-9-]{0,38}$/i.test(options.githubUser || "")) {
    throw new Error("Invalid broker origin or GitHub maintainer.");
  }
  return result;
}

function runAz(args) {
  try {
    const command = process.platform === "win32" ? "powershell.exe" : "az";
    const argv = process.platform === "win32"
      ? ["-NoProfile", "-NonInteractive", "-Command",
        "$a = ConvertFrom-Json $env:COPILOT_FLOCK_AZ_ARGS; & az @a; exit $LASTEXITCODE"]
      : args;
    return execFileSync(command, argv, {
      encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 600000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
      env: { ...process.env, COPILOT_FLOCK_AZ_ARGS: JSON.stringify(args) },
    });
  } catch {
    throw new Error(`Azure ${args.slice(0, 3).join(" ")} failed; captured output withheld.`);
  }
}

// Two stored ZIP entries avoid a platform-specific archiver or npm dependency.
export function createBrokerZip(destination) {
  const local = [];
  const central = [];
  let offset = 0;
  const files = ["bootstrap-server.mjs", "flock-membership.mjs", "package.json"];
  for (const name of files) {
    const data = fs.readFileSync(path.join(root, name));
    const filename = Buffer.from(name);
    let crc = 0xffffffff;
    for (const byte of data) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(33, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(data.length, 18);
    header.writeUInt32LE(data.length, 22);
    header.writeUInt16LE(filename.length, 26);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(33, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(filename.length, 28);
    entry.writeUInt32LE(offset, 42);
    local.push(header, filename, data);
    central.push(entry, filename);
    offset += header.length + filename.length + data.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  fs.writeFileSync(destination, Buffer.concat([...local, directory, end]), { mode: 0o600 });
}

export async function waitForBroker(origin, { fetchImpl = fetch, delay = sleep, attempts = 60 } = {}) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const response = await fetchImpl(`${origin}/health`, {
        redirect: "error", signal: AbortSignal.timeout(5000),
      });
      if (response.ok) {
        const status = await response.json();
        if (status.ok === true && status.service === "copilot-flock-bootstrap" &&
            status.configured === true && status.msiConfigured === true) return;
      }
    } catch {
      // Cold starts and transient deployment responses are retried within this bound.
    }
    if (attempt + 1 < attempts) await delay(5000);
  }
  throw new Error("Broker readiness timed out; Azure resources remain deployed, local installation was not started.");
}

export async function runManagedSetup(outputs, options, adapters = {}) {
  options = { ...options, skipBroker: options.legacyBroker !== true };
  const metadata = validateDeployment(outputs, options);
  const azure = adapters.runAz || runAz;
  const coordinates = ["--subscription", options.subscription, "--resource-group", options.resourceGroup];
  const getKey = async (args, endpoint, policy = "RootManageSharedAccessKey") => {
    let value;
    try {
      value = JSON.parse(await azure([...args, ...coordinates, "--output", "json"])).primaryConnectionString;
    } catch {
      throw new Error("Authorized Azure key retrieval failed; captured output withheld, local installation was not started.");
    }
    if (typeof value !== "string" || value.length > 16384 ||
        !value.startsWith(`Endpoint=${endpoint};`) ||
        !(endpoint.startsWith("https:")
          ? /;AccessKey=[^;]+(?:;|$)/.test(value)
          : /;SharedAccessKey=[^;]+(?:;|$)/.test(value) &&
            value.includes(`;SharedAccessKeyName=${policy};`))) {
      throw new Error("Azure returned invalid credentials; local installation was not started.");
    }
    return value;
  };
  const signalr = await getKey(["signalr", "key", "list", "--name", metadata.signalrName],
    `https://${metadata.signalrHostName}`);
  const serviceBus = await getKey(["servicebus", "namespace", "authorization-rule", "keys", "list",
    "--namespace-name", metadata.serviceBusNamespaceName, "--name", "RootManageSharedAccessKey"],
  metadata.serviceBusEndpoint);
  let send;
  let listen;
  if (options.skipBroker) {
    for (const rule of ["FlockSendRule", "FlockListenRule"]) {
      const credential = await getKey(["servicebus", "namespace", "authorization-rule", "keys", "list",
        "--namespace-name", metadata.serviceBusNamespaceName, "--name", rule], metadata.serviceBusEndpoint, rule);
      if (rule === "FlockSendRule") send = credential;
      else listen = credential;
    }
  }

  if (!options.skipBroker) {
    const pinned = process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN ||
      process.env.COPILOT_BRIDGE_ALLOWED_BOOTSTRAP_ORIGIN;
    if (pinned && new URL(pinned).origin !== metadata.bootstrapUrl) {
      throw new Error("Existing bootstrap origin pin differs from the managed deployment.");
    }
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "copilot-flock-broker-"));
    try {
      const zip = path.join(directory, "broker.zip");
      (adapters.createBrokerZip || createBrokerZip)(zip);
      try {
        await azure(["webapp", "deploy", ...coordinates, "--name", metadata.webAppName,
          "--src-path", zip, "--type", "zip", "--output", "none"]);
      } catch {
        throw new Error("Broker ZIP deployment failed; captured output withheld, local installation was not started.");
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
    await (adapters.waitForBroker || waitForBroker)(metadata.bootstrapUrl);
  }
  const install = adapters.install || (await import("./flock.mjs")).installBridge;
  const previousPin = process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
  try {
    if (!options.skipBroker) process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN = metadata.bootstrapUrl;
    let result;
    try {
      result = await install({
        connectionStringArg: signalr, serviceBusConnectionStringArg: serviceBus,
        bootstrapUrlArg: options.skipBroker ? null : metadata.bootstrapUrl,
        subscriptionArg: options.subscription, resourceGroupArg: options.resourceGroup,
        signalrNameArg: metadata.signalrName, githubUserArg: options.githubUser,
        scopeArg: options.scope || null, machineIdArg: options.machineId || null,
        ...(options.skipBroker ? { protocolArg: "broker-free-v34",
          flockIdArg: `${options.githubUser}/${options.scope}`,
          serviceBusSendConnectionStringArg: send, serviceBusListenConnectionStringArg: listen } : {}),
      });
    } catch {
      throw new Error("Local Flock installation failed; credentials and captured details withheld. Azure resources remain deployed.");
    }
    if (!options.skipBroker && (result?.memberRegistered !== true || !(result?.enrolledFlockCount > 0))) {
      throw new Error("Local installation completed without confirmed broker registration; signed invites are not ready. Check GitHub authentication and broker access before retrying enrollment.");
    }
    return result;
  } finally {
    if (previousPin === undefined) delete process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN;
    else process.env.COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN = previousPin;
  }
}

export async function runManagedCli(args, input, adapters) {
  const { values } = parseArgs({ args, options: {
    subscription: { type: "string" }, "resource-group": { type: "string" },
    "github-user": { type: "string" }, scope: { type: "string" },
    "machine-id": { type: "string" }, "skip-broker": { type: "boolean" }, "legacy-broker": { type: "boolean" },
  } });
  if (values["legacy-broker"] && values["skip-broker"]) throw new Error("Legacy broker and skip broker are mutually exclusive");
  let outputs;
  try { outputs = JSON.parse(input); }
  catch { throw new Error("Azure deployment returned malformed JSON metadata."); }
  return runManagedSetup(outputs, {
    subscription: values.subscription, resourceGroup: values["resource-group"],
    githubUser: values["github-user"], scope: values.scope,
    machineId: values["machine-id"], legacyBroker: values["legacy-broker"],
  }, adapters);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runManagedCli(process.argv.slice(2), fs.readFileSync(0, "utf8")).then(() => {
    console.log("Managed Azure setup and local Flock installation completed.");
  }).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
