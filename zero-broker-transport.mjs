import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { canonicalJson, hashRoster, validateRosterDocument } from "./zero-broker-roster.mjs";

const LIMIT = 1048576;
const executeFile = promisify(execFile);
const PAGES_WORKFLOW = `name: Publish signed Flock rosters
on:
  push:
    branches: [gh-pages]
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
concurrency:
  group: flock-roster-pages
  cancel-in-progress: false
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: \${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: .
      - uses: actions/deploy-pages@v4
        id: deployment
`;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

async function limitedResponse(response) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.length;
      check(size <= LIMIT, "Cloud response exceeds size limit");
      chunks.push(Buffer.from(item.value));
    }
  } finally {
    await reader.cancel();
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function cloudRequest(url, { method = "GET", headers = {}, body, fetchImpl = fetch, timeoutMs = 15000 } = {}) {
  const parsed = new URL(url);
  check(parsed.protocol === "https:" && !parsed.username && !parsed.password && !parsed.hash, "Cloud transport requires an HTTPS URL without credentials");
  if (body !== undefined) check(Buffer.byteLength(body) <= LIMIT, "Cloud request exceeds size limit");
  const response = await fetchImpl(parsed, { method, headers, body, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  return { status: response.status, headers: response.headers, text: await limitedResponse(response) };
}

async function azureArgs(args) {
  if (process.platform !== "win32") {
    return (await executeFile("az", args, { encoding: "utf8", timeout: 120000, maxBuffer: LIMIT })).stdout.trim();
  }
  return (await executeFile("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
    "$ErrorActionPreference='Stop'; $a=ConvertFrom-Json $env:FLOCK_AZ_ARGUMENTS; & az @a; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}"],
  { encoding: "utf8", timeout: 120000, maxBuffer: LIMIT, windowsHide: true,
    env: { ...process.env, FLOCK_AZ_ARGUMENTS: JSON.stringify(args), PSModulePath: `${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\Modules` } })).stdout.trim();
}

export async function runAzureCli(args) {
  let result;
  try { result = await azureArgs(args); }
  catch (err) { throw Object.assign(new Error(`Azure CLI ${args.slice(0, 3).join(" ")} failed (exit ${Number.isInteger(err.code) ? err.code : "unknown"}); no captured credential output was logged`), { ambiguous: true }); }
  if (args[args.indexOf("--output") + 1] === "none") return null;
  try { return JSON.parse(result); }
  catch { throw new Error(`Azure CLI ${args.slice(0, 3).join(" ")} returned invalid JSON; captured output was not logged`); }
}

export async function stageEpochResources({ flockUuid, rosterEpoch, opaquePeerIds, resourceGroup, namespaceName, signalr, subscriptionId, runAz = runAzureCli }) {
  check(/^[0-9a-f-]{36}$/.test(flockUuid) && Number.isSafeInteger(rosterEpoch) && rosterEpoch > 0, "Invalid staged epoch coordinates");
  check(/^[A-Za-z0-9._-]{1,90}$/.test(resourceGroup) && /^[a-z0-9-]{6,50}$/i.test(namespaceName), "Invalid Azure resource identifiers");
  check(Array.isArray(opaquePeerIds) && new Set(opaquePeerIds).size === opaquePeerIds.length && opaquePeerIds.every((id) => /^peer_[0-9a-f]{24}$/.test(id)), "Invalid epoch subscriber set");
  const topicName = `offline-f${flockUuid.replaceAll("-", "")}-e${rosterEpoch}-${crypto.randomBytes(6).toString("hex")}`;
  check(!subscriptionId || /^[0-9a-f-]{36}$/i.test(subscriptionId), "Invalid pinned Azure subscription");
  const topicArgs = [...(subscriptionId ? ["--subscription", subscriptionId] : []), "--resource-group", resourceGroup, "--namespace-name", namespaceName];
  let created = false;
  const discard = async () => {
    if (!created) return;
    await runAz(["servicebus", "topic", "delete", ...topicArgs, "--name", topicName, "--output", "none"]);
    created = false;
  };
  try {
    await runAz(["servicebus", "topic", "create", ...topicArgs, "--name", topicName, "--default-message-time-to-live", "PT1H", "--auto-delete-on-idle", "P1D", "--output", "none"]);
    created = true;
    const ruleKeys = {};
    for (const [name, right] of [["FlockSendRule", "Send"], ["FlockListenRule", "Listen"]]) {
      await runAz(["servicebus", "topic", "authorization-rule", "create", ...topicArgs, "--topic-name", topicName, "--name", name, "--rights", right, "--output", "none"]);
      const keys = await runAz(["servicebus", "topic", "authorization-rule", "keys", "list", ...topicArgs, "--topic-name", topicName, "--name", name, "--output", "json"]);
      check(typeof keys?.primaryKey === "string" && keys.primaryKey.length > 0, "Azure omitted an epoch authorization key");
      ruleKeys[name] = keys.primaryKey;
    }
    for (const opaquePeerId of opaquePeerIds) {
      const subscriptionName = `sub-${opaquePeerId}-e${rosterEpoch}`;
      await runAz(["servicebus", "topic", "subscription", "create", ...topicArgs, "--topic-name", topicName, "--name", subscriptionName, "--default-message-time-to-live", "PT1H", "--output", "none"]);
      const subscriptionArgs = [...topicArgs, "--topic-name", topicName, "--subscription-name", subscriptionName];
      await runAz(["servicebus", "topic", "subscription", "rule", "create", ...subscriptionArgs, "--name", "RecipientOnly", "--filter-sql-expression", `toOpaquePeerId = '${opaquePeerId}'`, "--output", "none"]);
      await runAz(["servicebus", "topic", "subscription", "rule", "delete", ...subscriptionArgs, "--name", "$Default", "--output", "none"]);
    }
    return {
      topicName, discard,
      ownerCredentials: {
        signalr,
        serviceBus: { namespaceHost: `${namespaceName.toLowerCase()}.servicebus.windows.net`, topicName, sendRuleKey: ruleKeys.FlockSendRule, listenRuleKey: ruleKeys.FlockListenRule },
      },
    };
  } catch (err) {
    if (created) {
      try { await discard(); }
      catch (cleanupError) { throw new AggregateError([err, cleanupError], `Epoch staging failed and cleanup failed for ${topicName}`); }
    }
    if (err.ambiguous && !created) throw Object.assign(new Error(`Epoch topic creation outcome is unknown; reconcile only the staged resource ${topicName}`, { cause: err }), { ambiguous: true, topicName });
    throw err;
  }
}

export function createGitHubRosterRepository({ repository, branch = "gh-pages", rosterPath = "flock-roster.json", token, request = cloudRequest, now = Date.now }) {
  check(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository), "Invalid roster repository");
  check(!repository.split("/")[1].toLowerCase().endsWith(".github.io"), "Use a dedicated project-site roster repository, not a GitHub user-site repository");
  check(/^[A-Za-z0-9_.-]+$/.test(branch), "Invalid roster branch");
  check(rosterPath.split("/").every((part) => /^[A-Za-z0-9_.-]+$/.test(part) && part !== "." && part !== ".."), "Invalid roster path");
  check(typeof token === "string" && token.length > 0, "Owner GitHub publication requires a local token");
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" };
  const prefix = `https://api.github.com/repos/${repository}/contents/`;
  const url = (file) => `${prefix}${file.split("/").map(encodeURIComponent).join("/")}`;
  async function read(file, optional = false) {
    const result = await request(`${url(file)}?ref=${encodeURIComponent(branch)}`, { headers });
    if (optional && result.status === 404) return null;
    check(result.status === 200, `GitHub roster read failed with HTTP ${result.status}`);
    const content = JSON.parse(result.text);
    check(content.encoding === "base64" && /^[0-9a-f]{40}$/.test(content.sha) && typeof content.content === "string" && content.content.length <= LIMIT * 2, "Invalid GitHub contents response");
    return { sha: content.sha, roster: JSON.parse(Buffer.from(content.content, "base64").toString("utf8")) };
  }
  async function putFile(file, roster, sha) {
    validateRosterDocument(roster, now());
    const body = { message: "Publish signed pseudonymous Flock roster", branch, content: Buffer.from(canonicalJson(roster)).toString("base64"), ...(sha ? { sha } : {}) };
    try { return await request(url(file), { method: "PUT", headers, body: JSON.stringify(body) }); }
    catch (err) {
      throw Object.assign(new Error("GitHub roster write has an ambiguous outcome", { cause: err }), { ambiguous: true });
    }
  }
  async function archive(file, roster) {
    const result = await putFile(file, roster);
    if (result.status === 409 || result.status === 422) {
      const existing = await read(file);
      check(hashRoster(existing.roster) === hashRoster(roster), "Immutable roster archive collision");
      return;
    }
    check(result.status === 200 || result.status === 201, `Roster archive publication failed with HTTP ${result.status}`);
  }
  return {
    readRoster: ({ optional = false } = {}) => read(rosterPath, optional),
    readLatest: async (trusted) => {
      const latest = await read(rosterPath);
      const transitions = [];
      let cursor = latest.roster;
      while (hashRoster(cursor) !== hashRoster(trusted)) {
        check(cursor.rosterEpoch > trusted.rosterEpoch && transitions.length < 2048, "Roster history is missing, forked or exceeds the recovery bound");
        transitions.unshift(cursor);
        if (cursor.prevRosterHash === hashRoster(trusted)) break;
        if (cursor.recoveryCheckpoint?.baseEpoch === trusted.rosterEpoch && cursor.recoveryCheckpoint.baseRosterHash === hashRoster(trusted)) break;
        check(/^[0-9a-f]{64}$/.test(cursor.prevRosterHash), "Invalid history reference");
        const history = await read(`${rosterPath.slice(0, rosterPath.lastIndexOf("/") + 1)}history/${cursor.prevRosterHash}.json`);
        check(hashRoster(history.roster) === cursor.prevRosterHash, "History content does not match its signed hash reference");
        cursor = history.roster;
      }
      return { sha: latest.sha, transitions };
    },
    publishGenesis: async (roster) => {
      check(roster.rosterEpoch === 1 && roster.prevRosterHash === "GENESIS", "Only a genesis roster can initialize publication");
      const directory = rosterPath.slice(0, rosterPath.lastIndexOf("/") + 1);
      for (const archivePath of [`${directory}history/genesis.json`, `${directory}history/${hashRoster(roster)}.json`]) {
        await archive(archivePath, roster);
      }
      return await putFile(rosterPath, roster);
    },
    put: async ({ roster, sha }) => {
      const archivePath = `${rosterPath.slice(0, rosterPath.lastIndexOf("/") + 1)}history/${hashRoster(roster)}.json`;
      await archive(archivePath, roster);
      return await putFile(rosterPath, roster, sha);
    },
  };
}

export async function prepareGitHubPagesRepository({ repository, token, publishConsent, request = cloudRequest }) {
  check(publishConsent === true, "Public roster publication requires explicit local consent");
  check(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository), "Select a dedicated GitHub roster repository");
  check(!repository.split("/")[1].toLowerCase().endsWith(".github.io"), "Use a dedicated project-site roster repository, not a GitHub user-site repository");
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" };
  const base = `https://api.github.com/repos/${repository}`;
  const call = (url, method = "GET", body) => request(url, { method, headers, ...(body ? { body: JSON.stringify(body) } : {}) });
  const userResponse = await call("https://api.github.com/user");
  check(userResponse.status === 200, "GitHub authentication is required for owner publication");
  const user = JSON.parse(userResponse.text).login;
  const [owner, name] = repository.split("/");
  check(typeof user === "string" && user.toLowerCase() === owner.toLowerCase(), "Automatic Pages setup is limited to a dedicated repository owned by the authenticated user");
  let repo = await call(base);
  if (repo.status === 404) repo = await call("https://api.github.com/user/repos", "POST", { name, private: false, auto_init: true, description: "Signed pseudonymous Copilot Flock rosters" });
  check(repo.status === 200 || repo.status === 201, `Roster repository setup failed with HTTP ${repo.status}`);
  const metadata = JSON.parse(repo.text);
  check(metadata.private === false && metadata.permissions?.admin === true, "Pages setup requires a public repository administered by the authenticated user");
  const branch = await call(`${base}/git/ref/heads/gh-pages`);
  if (branch.status === 404) {
    const initial = await call(`${base}/git/ref/heads/${encodeURIComponent(metadata.default_branch)}`);
    check(initial.status === 200, "Roster repository must have an initial commit");
    const result = await call(`${base}/git/refs`, "POST", { ref: "refs/heads/gh-pages", sha: JSON.parse(initial.text).object.sha });
    check(result.status === 201, `Pages branch creation failed with HTTP ${result.status}`);
  } else check(branch.status === 200, `Pages branch inspection failed with HTTP ${branch.status}`);
  const pages = await call(`${base}/pages`);
  if (pages.status === 404) {
    const result = await call(`${base}/pages`, "POST", { build_type: "workflow" });
    check(result.status === 201, `Pages enablement failed with HTTP ${result.status}`);
  } else {
    check(pages.status === 200, `Pages inspection failed with HTTP ${pages.status}`);
    check(JSON.parse(pages.text).build_type === "workflow", "Existing Pages configuration differs; select a dedicated Actions-backed roster repository instead of changing another website");
  }
  const workflowUrl = `${base}/contents/.github/workflows/flock-roster-pages.yml`;
  const workflow = await call(`${workflowUrl}?ref=gh-pages`);
  if (workflow.status === 404) {
    const result = await call(workflowUrl, "PUT", { message: "Configure signed roster Pages publication", branch: "gh-pages", content: Buffer.from(PAGES_WORKFLOW).toString("base64") });
    check(result.status === 201, `Pages workflow creation failed with HTTP ${result.status}; the owner token requires workflow write permission`);
  } else {
    check(workflow.status === 200 && Buffer.from(JSON.parse(workflow.text).content, "base64").toString("utf8") === PAGES_WORKFLOW, "Existing roster Pages workflow differs; refusing an unreviewed overwrite");
  }
  return { githubUser: user.toLowerCase(), pagesBaseUrl: `https://${owner.toLowerCase()}.github.io/${name}/` };
}

export async function fetchPublicRosterChain({ rosterUrl, trustedRoster, request = cloudRequest }) {
  const base = new URL(rosterUrl);
  check(base.protocol === "https:" && !base.username && !base.password && !base.hash, "Expected pinned HTTPS public roster URL");
  async function read(url) {
    const result = await request(url.href);
    check(result.status === 200, `Public roster fetch failed with HTTP ${result.status}`);
    return JSON.parse(result.text);
  }
  const latest = await read(base);
  const transitions = [];
  let cursor = latest;
  while (hashRoster(cursor) !== hashRoster(trustedRoster)) {
    check(cursor.rosterEpoch > trustedRoster.rosterEpoch && transitions.length < 2048, "Public roster rollback, fork or unavailable history");
    transitions.unshift(cursor);
    if (cursor.prevRosterHash === hashRoster(trustedRoster)) break;
    if (cursor.recoveryCheckpoint?.baseEpoch === trustedRoster.rosterEpoch && cursor.recoveryCheckpoint.baseRosterHash === hashRoster(trustedRoster)) break;
    check(/^[0-9a-f]{64}$/.test(cursor.prevRosterHash), "Invalid public history reference");
    const parent = await read(new URL(`./history/${cursor.prevRosterHash}.json`, base));
    check(hashRoster(parent) === cursor.prevRosterHash, "Public history hash mismatch");
    cursor = parent;
  }
  return { latest, transitions };
}

export async function sendEncryptedPacket({ transport, envelope, request = cloudRequest }) {
  const body = JSON.stringify(envelope);
  const results = await Promise.allSettled([
    request(`${transport.endpoint}/api/v1/hubs/${transport.hubName}`, { method: "POST", headers: { Authorization: `Bearer ${transport.hubPublishJwt}`, "Content-Type": "application/json" }, body: JSON.stringify({ target: "zeroBrokerEnvelope", arguments: [envelope] }) }),
    request(`https://${transport.namespaceHost}/${transport.topicName}/messages`, { method: "POST", headers: { Authorization: transport.sbSendSas, "Content-Type": "application/json", toOpaquePeerId: JSON.stringify(envelope.toOpaquePeerId), BrokerProperties: JSON.stringify({ MessageId: envelope.messageId, TimeToLive: 3600 }) }, body }),
  ]);
  if (results.some((result) => result.status === "fulfilled" && (result.value.status === 200 || result.value.status === 201 || result.value.status === 202))) return { admittedToTransport: true };
  const statuses = results.map((result) => result.status === "fulfilled" ? result.value.status : "UNKNOWN");
  throw Object.assign(new Error(`Both encrypted transport attempts failed (${statuses.join(", ")})`), { ambiguous: statuses.includes("UNKNOWN") });
}

export async function peekLockEncryptedPacket({ transport, request = cloudRequest }) {
  const base = `https://${transport.namespaceHost}/${transport.topicName}/subscriptions/${transport.subscriptionName}/messages/`;
  const result = await request(`${base}head?timeout=5`, { method: "POST", headers: { Authorization: transport.sbListenSas } });
  if (result.status === 204) return null;
  check(result.status === 201, `Service Bus receive failed with HTTP ${result.status}`);
  const location = new URL(result.headers.get("location"));
  check(location.protocol === "https:" && location.href.startsWith(base) && !location.username && !location.password && !location.hash, "Service Bus returned an out-of-scope lock URI");
  return {
    envelope: JSON.parse(result.text),
    acknowledge: async () => {
      const acknowledgement = await request(location.href, { method: "DELETE", headers: { Authorization: transport.sbListenSas } });
      check(acknowledgement.status === 200 || acknowledgement.status === 204, `Service Bus acknowledgement failed with HTTP ${acknowledgement.status}`);
    },
  };
}
