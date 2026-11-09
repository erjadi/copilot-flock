# Setting Up a Brand-New Copilot Flock Instance (Case 2: BYO Azure SignalR + Service Bus)

![Two Ways to Bootstrap Copilot Flock](./assets/flock-onboarding-paths.svg)

This guide covers **Case 2**: when you are setting up a **brand-new, independent Copilot Flock instance** for yourself or your organization using your own Azure resources (**Bring Your Own Azure SignalR + Service Bus**).

> **Zero-Broker release candidate:** fresh setup now routes to SignalR
> Serverless + Service Bus Standard + a signed `github.io` roster. This
> checkout wires installation, CLI/MCP enrollment, Pages publication and the
> owner-renewal/expiry loop. Mocked cloud and Desktop-control tests are not
> live Azure/Pages or all-platform acceptance. Production remains unchanged
> until release approval and separately authorized installation.

> **Joining someone else's existing flock instead?**
> If you received an invite message or signed `copilot-flock-invite-v3` JSON from a flock owner, you do **not** need to create any Azure resources! The `bootstrapUrl` is already embedded inside your invite JSON. Jump straight to **[Joining & Sharing Guide (Case 1)](./JOINING_AND_SHARING_GUIDE.md)**.

---

## Managed ARM template setup (recommended first-machine path)

Ask Copilot: *"Deploy the managed Flock ARM template in my Azure subscription
and enroll this PC. Confirm the subscription, region, resource group, scope and
charges before installing tools or creating anything."* Copilot executes the
wrapper for you; you do not need to copy connection strings or run a sequence
of cloud commands manually.

Copilot must first confirm a dedicated public roster repository and consent
to public pseudonymous metadata/history. On Windows the managed entry point
is `.\setup.ps1 -ProvisionAzure -RosterRepository <owner>/<roster-repo> -PublishRoster`
(optionally `-Scope personal -ResourceGroup rg-copilot-flock -Location eastus`).
On Debian/Ubuntu or macOS it is `./setup.sh --provision-azure
--roster-repository <owner>/<roster-repo> --publish-roster`
(optionally `--scope personal --resource-group rg-copilot-flock --location eastus`).
Do not use this path for an existing invite or for the separate hubless LAN trial.

The wrappers require Node.js >=22.5 already installed and perform these steps:

For Node 22.5-22.12 (also obsolete Node 23.0-23.3) they propagate `--experimental-sqlite` to setup, MCP and
managed daemon/startup commands; prefer Node 22.13+ for unflagged use. Validation
here used Node 24. The npm Flock/test scripts enable SQLite explicitly; direct
CLI/API execution on older versions requires Copilot to supply that flag.
Select a dedicated **project-site** repository (not
`<owner>.github.io`). Fresh provisioning stops before Azure changes if a local
Flock configuration already exists; use the explicit legacy path for legacy
work, not automatic migration. Existing Zero-Broker installation can repair
local integration without reissuing genesis. Startup failures are explicit and
retain initialized identity/state for repair; Linux lingering requires local OS
consent for unattended boots.

1. Find Azure CLI; if missing, use Windows `winget` (possible UAC),
   Debian/Ubuntu's official installer (`sudo` unless already root), or macOS
   Homebrew. Missing prerequisites or unsupported automatic-install platforms
   fail explicitly instead of falling back to a different service.
2. Check `az account show`; authenticate with `az login` when needed, using
   device-code login on Linux without `DISPLAY`. Provisioning uses the CLI's
   currently selected subscription: Copilot must verify/set it before setup.
3. Create the requested resource group and deploy
   [`infra/azuredeploy.json`](../infra/azuredeploy.json). Resource names are
   deterministic for that group, using a prefix plus a unique suffix.
4. Capture only nonsecret resource metadata and pass that JSON over stdin to
   `flock.mjs install`. Before local identity creation, its shared native
   provisioning adapter uses explicit authorized Azure CLI key-list actions
   pinned to the returned subscription/resource names and approved resource
   group. It captures keys in memory without printing them. Pin the
   subscription ID; stage the first
   epoch topic, rules and subscriptions; publish signed genesis/history.
   Configure MCP, skills and startup without spawning privileged coordinator
   sessions. Report cloud readiness separately from process startup.

The ARM parameters are `location`, `namePrefix`, `uniqueSuffix`, `signalrSku`
(`Free_F1` or `Standard_S1`), `serviceBusSku` (`Standard` only) and
`serviceBusTopicName`. The wrappers use the template defaults; an operator can
deploy the same template with reviewed parameter overrides for an advanced
configuration. Outputs contain only the subscription ID, SignalR name/hostname,
Service Bus namespace/endpoint and topic name. **No keys, connection strings or
`listKeys` expressions are deployment outputs.** Ordinary outputs remain readable
in deployment history, so secrets must not be added there, even temporarily.
Both setup wrappers forward metadata, not credentials, over stdin. The native
adapter rejects old secret-bearing output JSON rather than silently accepting
it. Managed provisioning never puts keys in process arguments or console logs.

The template additionally defines exactly two topic-level authorization
rules: `FlockSendRule` with `Send` and `FlockListenRule` with `Listen`. Its
keys are **owner-only secrets**, retrieved after deployment with
`az signalr key list` and `az servicebus topic authorization-rule keys list`
for the two named rules, always with explicit subscription, resource group
and resource identifiers. Copilot captures JSON responses privately, never as
public output. Zero-Broker does not retrieve the namespace management key.
The explicit legacy path instead uses
`az servicebus namespace authorization-rule keys list` for
`RootManageSharedAccessKey`, as required by its existing transport.
For advanced/manual deployments, Copilot follows these same authorized
post-deployment reads or passes the metadata to the native installer; it must
not restore secret template outputs as a shortcut. Missing permissions,
malformed responses or absent keys abort before installation/initialization,
without falling back to another profile or generating replacement identity.
No new Key Vault or paid resource is introduced. Managed initialization
stores enrollment issuer material privately; never copy raw keys into guest invites.
GitHub CLI authentication needs contents/Pages/workflow publication permissions.
Azure CLI needs management rights on the pinned subscription/resources, even
when existing signing keys are available. Granting `canMintTokens` does not
create Azure RBAC or GitHub access on another PC.

**Historical exposure is not automatically remediated.** Earlier versions of
this template placed keys in ordinary deployment outputs, potentially exposing
them to principals able to read deployment history even without `listKeys`
permission. Removing outputs protects future deployments; it does not erase
earlier records, revoke copied credentials or rotate keys. Reviewing/deleting
historical deployments, restricting access and rotating affected credentials
require separate owner authorization and have not been performed here.

The Zero-Broker adapters stage a separate per-flock/epoch topic with those
two rights and recipient-filtered `sub-<opaque-peer>-e<epoch>` subscriptions.
Send SAS scopes name the normalized topic URI without `/messages`; Listen
SAS scopes name the exact subscription. An ambiguous topic-create result
reports the specific candidate resource for reconciliation, rather than
claiming creation failed or deleting an unrelated resource.

The signed-roster target provides **Encrypted Identities & Pseudonymous Public
Metadata**, not invisible hosting accounts or membership topology. Root
fingerprints must be pinned independently; unbound claims require independent
device-key verification and explicit signed approval. Owner vaults exclude
genesis signing private keys and are sealed only to the root and explicitly
mint-capable delegates.

**Bounded Revocation & Automatic Epoch Cutover** requires an available,
authorized owner issuer, correctly configured Pages publication and accurate
clocks. The maximum signed lease is one hour and fails closed when stale. An online
issuer renews when one-third remains and rotates membership expiry epochs;
issuers handling removals also need kick permission. A genesis-root publisher
adds signed bootstrap checkpoints. Pages publication uses GitHub Actions on
`gh-pages`; deployment latency, caching, Actions capacity and clock accuracy
still matter. A committed roster does not prove public Pages freshness. Compromised delegates'
Azure/GitHub administrative grants also require separate revocation; rotating
protocol credentials does not remove external RBAC access.

The template deploys SignalR in **Serverless** mode and Service Bus **Standard**
with the offline topic. SignalR Free has quotas; Service Bus Standard is paid.
Subscription/RBAC permissions, provider registration, policy, existing resource
names and regional quotas can cause a deployment failure. The wrappers do not
delete a resource group or roll back unrelated resources on failure.

**Zero-Broker does not require a Token Broker.** Copilot prepares per-flock
device key cards for owned PCs and independently verifies both fingerprints
before root-signed pre-bound enrollment. Explicit mint-enabled delegates
receive recipient-sealed issuer/control metadata, never genesis signing keys.
External guests use a separate shared flock and a provisional voucher; the
owner independently verifies and approves the signed claim before CAS redemption.
The claim's GitHub username is self-asserted, not GitHub authentication.
Native messaging targets existing Desktop sessions with local root grants;
other identities receive no automatic owner discovery, and shared access is
approved summaries only. Headless privileged spawning is explicitly denied. The ARM structure and wrapper
flows have local syntax/unit/mock coverage; a real Azure deployment still
requires separate authorization and has not been validated by those mocks.

Release review requires local source review and exact-SHA host-code-execution
consent on each voter before smoke or worker tests. Copilot records this through
the local-only `approve-release-execution --commit <full-sha>
--ack-reviewed-host-code` command from independently reviewed installed/pinned
issuer code, never from the unapproved candidate itself (its top level executes
before argument handling). Existing-device signatures bind the SHA,
machine and 30-minute expiry; missing/expired approval denies execution and
approval is checked again before ballot signing. No RPC/MCP tool, branch/origin,
incoming request or peer ballot can grant it. No key creation or repair occurs.
Tests retain the host account's filesystem/network privileges: temporary HOME,
timeouts and environment filtering are not an OS sandbox. Consent to execute
reviewed code is not release ACCEPT or permission to upgrade live reviewers.
Older ungated reviewers must not execute unreviewed source.

Release review then uses exact-commit extraction and a bounded validation worker.
Copilot supplies an independently expected full SHA (`--commit` in the CLI,
`expected_commit` in MCP), freezes the branch before broadcast and rejects
receiver-resolution or ballot mismatches. A capability-only preflight denies
older ungated peers before requesting tests. Version-3 ballots sign named
module/test coverage, local execution consent and the canonical policy hash;
aggregation compares this with the exact Git-tree inventory computed separately
by the requester. Count-only/version-2 ballots remain diagnostic, not approvals.
Any downstream merge/push must use that same `expectedCommit`, never infer
intent from unanimity over a moved branch.
The worker clears inherited Node test selectors and isolates `COPILOT_HOME`,
with local execution consent rechecked immediately before smoke/full-worker
launches and before a ballot. Launch-time validity does not cancel or retract
effects of work already launched.
Focused parent tests cannot silently skip candidate tests. Version-3
registered-key ballots sign both the full SHA and complete validation scope;
legacy smoke-only ballots and partial voter selections are not merge approval.
All seven root suites are required, including the retained legacy RPC security
suite; omission of that suite or a six-suite ballot cannot satisfy the gate.
The full serial 95-test integration took 364 seconds on the validation host.
The signed policy therefore allows a bounded ten-minute test run and an
eleven-minute worker, without dropping suites or enabling test selectors.
Review RPCs allow a bounded twelve-and-a-half-minute response window, including
the ten-minute root-test budget. No live reviewer upgrade, Azure deployment
or platform acceptance is implied.

State is private under `~/.copilot/flock/zero-broker/<uuid>`, including
per-flock device keys, SQLite trust/admission/outbox state and local grants.
Do not reconstruct a missing ledger using old keys. `resume-init` reconciles
the exact saved signed genesis after uncertain publication. If staging did
not produce genesis, inspect the reported candidate resource rather than
blindly retrying, deleting resources or generating another identity.

SignalR [Free](https://azure.microsoft.com/en-us/pricing/details/signalr-service/)
allows 20 connections and 20,000 messages/day. Hub publication incurs outbound
recipient fan-out and 2 KiB payload billing units, even though RPC is
recipient-sealed. This profile has no legacy 45-second presence broadcast,
but requests, receipts and reconciliation still consume quota. Service Bus
operations, epoch topics/subscriptions and GitHub Actions limits are separate.
No workload/SKU acceptance or paid upgrade is implied by the unit tests.

---

## Legacy broker reference (explicit compatibility only)

Everything below describes the existing broker/direct-string deployment,
not fresh Zero-Broker setup. Select `--architecture legacy` for direct
installation, or `-Legacy` / `--legacy` in wrappers. Existing configurations
and signed `copilot-flock-invite-v3` broker invites retain their original path.

## Who Is This Guide For?

| User Type | Recommended Approach | Time Required |
| :--- | :--- | :--- |
| **Everyday Copilot User** | **Managed ARM Setup / Option A**: Copilot runs the opt-in setup wrapper to provision both services and enroll your PC. | Depends on CLI installation, sign-in and Azure deployment |
| **Cloud / DevOps Engineer** | **Option B — Reviewed `az` Provisioning + Token Broker**: Deploy the base resources declaratively or with the recipes below, then host the broker for signed invites and guest passes. | Base deployment plus separately configured broker hosting |
| **Direct / Personal-Only Setup** | **Option C — Existing Connection Strings (No Token Broker)**: Copilot installs with approved existing credentials. | No new-resource deployment; local installation still required |

---

## Why Does a New Flock Use Azure SignalR + Service Bus?

`copilot-flock` contains **zero vendor-hosted cloud servers and zero hardcoded credentials**. When you create a new flock, your machines communicate through two lightweight resources in your own Azure subscription:

1. **Azure SignalR Service (`Serverless` mode)** — Provides real-time WebSocket routing (`wss://<your-signalr>.service.signalr.net/client/?hub=copilotbridge`) between online machines over outbound TCP 443 without a peer inbound application listener. Latency and VPN/proxy reachability depend on the deployed network and are not guaranteed.
   - *Cost*: Works on the **Free (`Free_F1`)** tier (up to 20 concurrent connections / 20,000 messages per day) or **Standard (`Standard_S1`)**.
2. **Azure Service Bus Namespace (`Standard` SKU + topic `copilot-bridge-offline`)** — Provides durable, at-least-once offline transport using a topic and per-machine subscriptions (`Standard`, not `Basic`, is required). Check actual receipts: confirmed Service Bus publication, legacy broker-file persistence and unknown runtime admission are distinct. Delivery requires valid authority/deadlines, retention, connectivity and reconciliation; waking a laptop does not guarantee immediate delivery or task execution, and queued release traffic does not authorize an update.
3. **Optional: Bootstrap Token Broker (`bootstrap-server.mjs`)** — A tiny, zero-dependency Node.js HTTP service (runs on a Basic/Standard Azure App Service, Container App, or VM) that verifies Ed25519 signatures and GitHub identities to mint short-lived 60-minute hub JWTs for **1-step pasteable invites**, **collaborator flocks (`<owner>/<team>`)**, and **time-bound guest passes**.

---

## Option A — Let Your Copilot Set Everything Up (Recommended)

Open GitHub Copilot Desktop (or GitHub Copilot CLI) on your first computer and say:

> *"Clone `https://github.com/erjadi/copilot-flock`, read `AGENTS.md`, and set up a brand-new Copilot Flock instance in my Azure subscription."*

### What Your Copilot Will Do Automatically:
1. Check that you are signed into Azure CLI (`az account show`) and GitHub CLI (`gh auth status`), prompting you to sign in if needed.
2. Auto-detect whether this computer is a **`personal`** or **`work`** machine from OS/domain signals and ask you to confirm with 1 click (or use `--scope personal|work` in non-interactive CLI mode).
3. Use the managed setup wrapper to create a resource group (e.g. `rg-copilot-flock`) and deploy `infra/azuredeploy.json`: **SignalR Serverless** plus **Service Bus Standard** and the offline topic.
4. Enroll your first machine (`<your-github-handle>/<scope>/<HOSTNAME>`), start the background daemon, register the `copilot-flock` MCP server, and install both the `copilot-flock` and `flock-topology` skills.
5. Optionally deploy `bootstrap-server.mjs` and generate a **Case 1 Invite JSON** that you can paste into your other computers!

---

## Option B — Step-by-Step Azure CLI Provisioning (With Token Broker for Invites)

Below are complete, copy-pasteable recipes for both **PowerShell (Windows)** and **Bash (Linux / macOS)**.

### 1. Provision Azure SignalR (`Serverless`) + Service Bus (`Standard` + Topic)

#### PowerShell (Windows)

No fork is required: clone `erjadi/copilot-flock` and configure your broker with
`ALLOWED_GITHUB_REPO="erjadi/copilot-flock"` and
`PLATFORM_MAINTAINER_USER="<your-github-login>"` (default: `erjadi`).
The broker authenticates GitHub `/user` and grants credential/management access
to that deployment maintainer, repository owners/write/maintainer/admin
collaborators, or an explicit `ALLOWED_GITHUB_USERS` allowlist. Maintainer and
allowlist access do not depend on repository write access or even repository
existence. The allowlist is comma-separated, case-insensitive and trimmed;
leave it unset unless deliberately granting deployed-instance credential access.

Authenticated teammates/guests can redeem recipient-bound, broker-stored v3
invite vouchers on `/api/v3/enroll` without repository write access. Their device
must sign the enrollment request; the full-Flock clients do this automatically.
The current broker checks the stored voucher, recipient, scope, capacity and
expiry; it does **not** verify the optional `voucherSignature` field as an
Ed25519 voucher signature. Device enrollment signatures are verified separately.
Invite-free enrollment remains privileged. Guests cannot substitute another
GitHub identity, and `/api/v3/my-flocks` exposes only their own memberships.
These paths never grant legacy bootstrap connection strings or management access.

```powershell
$RG       = "rg-copilot-flock"
$LOCATION = "eastus"
$SUFFIX   = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
$SIGNALR  = "flock-signalr-$SUFFIX"
$SB_NS    = "flock-sb-$SUFFIX"
$SB_TOPIC = "copilot-bridge-offline"

az group create --name $RG --location $LOCATION

az signalr create `
  --name $SIGNALR `
  --resource-group $RG `
  --location $LOCATION `
  --sku Free_F1 `
  --unit-count 1 `
  --service-mode Serverless

az servicebus namespace create `
  --name $SB_NS `
  --resource-group $RG `
  --location $LOCATION `
  --sku Standard

az servicebus topic create `
  --resource-group $RG `
  --namespace-name $SB_NS `
  --name $SB_TOPIC

$SIGNALR_CONN = az signalr key list --name $SIGNALR --resource-group $RG --query primaryConnectionString -o tsv
$SB_CONN      = az servicebus namespace authorization-rule keys list --resource-group $RG --namespace-name $SB_NS --name RootManageSharedAccessKey --query primaryConnectionString -o tsv
```

#### Bash (Linux / macOS)
```bash
RG="rg-copilot-flock"
LOCATION="eastus"
SUFFIX="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 6)"
SIGNALR="flock-signalr-$SUFFIX"
SB_NS="flock-sb-$SUFFIX"
SB_TOPIC="copilot-bridge-offline"

az group create --name "$RG" --location "$LOCATION"

az signalr create \
  --name "$SIGNALR" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --sku Free_F1 \
  --unit-count 1 \
  --service-mode Serverless

az servicebus namespace create \
  --name "$SB_NS" \
  --resource-group "$RG" \
  --location "$LOCATION" \
  --sku Standard

az servicebus topic create \
  --resource-group "$RG" \
  --namespace-name "$SB_NS" \
  --name "$SB_TOPIC"

SIGNALR_CONN="$(az signalr key list --name "$SIGNALR" --resource-group "$RG" --query primaryConnectionString -o tsv)"
SB_CONN="$(az servicebus namespace authorization-rule keys list --resource-group "$RG" --namespace-name "$SB_NS" --name RootManageSharedAccessKey --query primaryConnectionString -o tsv)"
```

### 2. Optional: Deploy `bootstrap-server.mjs` (For 1-Step Pasteable Invites & Multi-Flock Guest Passes)

If you want to enroll additional PCs or invite teammates using 1-step signed Enrollment JSONs (without copying Azure connection strings to every machine), deploy `bootstrap-server.mjs` to an Azure Web App with Managed Identity access to your Service Bus namespace:

#### PowerShell (Windows)
```powershell
$PLAN    = "flock-bootstrap-plan-$SUFFIX"
$WEBAPP  = "flock-bootstrap-$SUFFIX"
$GH_USER = (gh api user --jq .login)

az appservice plan create --name $PLAN --resource-group $RG --location $LOCATION --sku B1 --is-linux
az webapp create --name $WEBAPP --resource-group $RG --plan $PLAN --runtime "NODE:22-lts"

# Grant the Web App Managed Identity permission to publish/manage Service Bus offline subscriptions
$PRINCIPAL_ID = az webapp identity assign --name $WEBAPP --resource-group $RG --query principalId -o tsv
$SB_ID        = az servicebus namespace show --name $SB_NS --resource-group $RG --query id -o tsv
az role assignment create --assignee $PRINCIPAL_ID --role "Azure Service Bus Data Owner" --scope $SB_ID

# Configure environment variables (matching bootstrap-server.mjs) and startup command
az webapp config appsettings set --name $WEBAPP --resource-group $RG --settings `
  SIGNALR_CONNECTION_STRING="$SIGNALR_CONN" `
  SERVICEBUS_NAMESPACE="$SB_NS.servicebus.windows.net" `
  SERVICEBUS_TOPIC="$SB_TOPIC" `
  ALLOWED_GITHUB_REPO="erjadi/copilot-flock" `
  PLATFORM_MAINTAINER_USER="$GH_USER" `
  COPILOT_FLOCK_HUB="copilotbridge"

az webapp config set --name $WEBAPP --resource-group $RG --startup-file "node bootstrap-server.mjs"

# Package and deploy bootstrap-server.mjs + package.json, then verify /healthz
Compress-Archive -Path bootstrap-server.mjs, package.json -DestinationPath bootstrap-deploy.zip -Force
az webapp deploy --resource-group $RG --name $WEBAPP --src-path bootstrap-deploy.zip --type zip
Invoke-RestMethod "https://$WEBAPP.azurewebsites.net/healthz"
```

#### Bash (Linux / macOS)
```bash
PLAN="flock-bootstrap-plan-$SUFFIX"
WEBAPP="flock-bootstrap-$SUFFIX"
GH_USER="$(gh api user --jq .login)"

az appservice plan create --name "$PLAN" --resource-group "$RG" --location "$LOCATION" --sku B1 --is-linux
az webapp create --name "$WEBAPP" --resource-group "$RG" --plan "$PLAN" --runtime "NODE:22-lts"

PRINCIPAL_ID="$(az webapp identity assign --name "$WEBAPP" --resource-group "$RG" --query principalId -o tsv)"
SB_ID="$(az servicebus namespace show --name "$SB_NS" --resource-group "$RG" --query id -o tsv)"
az role assignment create --assignee "$PRINCIPAL_ID" --role "Azure Service Bus Data Owner" --scope "$SB_ID"

az webapp config appsettings set --name "$WEBAPP" --resource-group "$RG" --settings \
  SIGNALR_CONNECTION_STRING="$SIGNALR_CONN" \
  SERVICEBUS_NAMESPACE="$SB_NS.servicebus.windows.net" \
  SERVICEBUS_TOPIC="$SB_TOPIC" \
  ALLOWED_GITHUB_REPO="erjadi/copilot-flock" \
  PLATFORM_MAINTAINER_USER="$GH_USER" \
  COPILOT_FLOCK_HUB="copilotbridge"

az webapp config set --name "$WEBAPP" --resource-group "$RG" --startup-file "node bootstrap-server.mjs"

zip -q bootstrap-deploy.zip bootstrap-server.mjs package.json
az webapp deploy --resource-group "$RG" --name "$WEBAPP" --src-path bootstrap-deploy.zip --type zip
curl -fsSL "https://$WEBAPP.azurewebsites.net/healthz"
```

### 3. Enroll Your First Machine

```powershell
# PowerShell (Windows)
node flock.mjs install `
  --scope personal `
  --bootstrap-url "https://$WEBAPP.azurewebsites.net/api/bootstrap" `
  --bootstrap-origin-pin "https://$WEBAPP.azurewebsites.net" `
  --connection-string "$SIGNALR_CONN" `
  --servicebus-connection-string "$SB_CONN"
```

```bash
# Bash (Linux / macOS)
node ./flock.mjs install \
  --scope personal \
  --bootstrap-url "https://$WEBAPP.azurewebsites.net/api/bootstrap" \
  --bootstrap-origin-pin "https://$WEBAPP.azurewebsites.net" \
  --connection-string "$SIGNALR_CONN" \
  --servicebus-connection-string "$SB_CONN"
```

---

## Platform, Boot Persistence & Network Notes

- **Node.js Requirement**: Zero-Broker requires **Node.js `>= 22.5`** with built-in `node:sqlite`; prefer maintained Node 22.13+ or Node 24. Older versions listed above require the SQLite flag. Node 18/20 plus an external `sqlite3` CLI is only a legacy metadata-query compatibility path, not supported Zero-Broker enrollment, durable runtime or release validation.
- **Headless Linux Boot Persistence (`systemd --user`)**:
  - `node flock.mjs install` writes and enables `~/.config/systemd/user/copilot-flock.service`.
  - On headless Linux servers (`Ubuntu` / `Debian` / `Jetson`) where no user logs into a desktop session after reboot, enable systemd user lingering once so the daemon starts automatically on boot and stays alive after SSH logout:
    ```bash
    sudo loginctl enable-linger "$USER"
    systemctl --user status copilot-flock.service
    ```
- **Windows Boot Persistence (`copilot-flock.vbs`)**:
  - `node flock.mjs install` places `copilot-flock.vbs` in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, which launches the daemon at user sign-in. On unattended Windows cloud VMs, keep an active user session or configure a Windows Scheduled Task (`ONSTART`).
- **Outbound Network & VPN Resilience**:
  - SignalR uses outbound TCP 443 (HTTPS/WSS). Check the actual Service Bus
    client's configured transport and required ports; do not assume all traffic
    uses 443. GitHub, broker and Azure endpoints must also satisfy local policy.
  - The IPv4-first resolver (`ipv4Lookup` + `dns.resolve4` fallback cache)
    mitigates some broken IPv6/DNS paths; it cannot bypass VPN, proxy or egress policy.

Once your first machine is enrolled, simply tell your Copilot:
> *"Generate an invite for my other personal and work PCs"*

Your Copilot will call `invite_to_flock` and hand you a **Case 1 Invite JSON** containing your `bootstrapUrl`—so every subsequent machine you add requires **zero Azure CLI setup**!

---

## Option C — Legacy Direct Connection Strings (No Web App / Personal-Only Setup)

If you only want to connect your own computers and prefer not to run a Bootstrap App Service at all, pass your SignalR and Service Bus connection strings directly on each machine:

```powershell
node flock.mjs install `
  --architecture legacy `
  --scope personal `
  --connection-string "$SIGNALR_CONN" `
  --servicebus-connection-string "$SB_CONN"
```

All local config is stored at `~/.copilot/flock/config.json` with strict owner-only file permissions (`0600` on Linux/macOS).

---

## Verifying the Explicit Legacy Instance

Ask your Copilot in plain English:
- *"Check flock status and diagnose the flock without changing anything"* ->
  Runs legacy `diagnose_bridge_fleet` with `fix: false`. Report unknown or
  failed probes as such; they do not prove health. Obtain separate consent for
  repairs, especially session permission/mode changes.
- *"Show me a flock topology diagram in light mode"* -> Uses the bundled `flock-topology` skill to render your live `flowchart LR` Mermaid graph, Markdown Overlap Matrix, and Warm-Alabaster SVG topology map.
