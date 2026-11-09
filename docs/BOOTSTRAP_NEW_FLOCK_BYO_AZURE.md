# New Copilot Flock: bring your own Azure subscription

![Two ways to bootstrap Copilot Flock](./assets/flock-onboarding-paths.svg)

Ask Copilot:

> "Clone https://github.com/erjadi/copilot-flock, read AGENTS.md, and set up
> a new Flock in my Azure subscription. Confirm my subscription, region,
> resource group, personal/work scope, tool installation and costs first."

Copilot executes setup; you do not need to copy credentials or type cloud
commands. If you already have an invite, use the
[joining guide](./JOINING_AND_SHARING_GUIDE.md) instead: no Azure provisioning
is needed on invited machines.

## What the managed setup provisions

One ARM deployment creates:

| Component | Default | Purpose |
| --- | --- | --- |
| Azure SignalR | Serverless, `Free_F1` | Real-time rendezvous between online machines |
| Azure Service Bus | Standard namespace, `copilot-bridge-offline` topic | Durable offline messaging |
| Token Broker | Linux App Service plan `B1`, Node.js 22 Web App | GitHub-authenticated registration and signed one-step invites |
| Broker identity | System-assigned managed identity, Service Bus Data Owner at the new namespace | Create subscriptions and publish broker-managed offline messages |

SignalR Free has connection/message quotas; Service Bus Standard and App
Service B1 incur separate charges. Neither the complete stack nor its idle
resources are free. Review current regional pricing, quotas and subscription
policy before approval. ARM also supports `Standard_S1` for SignalR and `F1`
for App Service, subject to Linux/region/subscription availability. F1 disables
Always On, has shared capacity/quotas and can cold-start; B1 is the default.

The deploying Azure identity needs resource creation, resource key-listing and
role-assignment permissions. Contributor alone does not grant role-assignment
creation: use an appropriately authorized identity or have an administrator
perform the deployment. Managed identity/RBAC propagation is not instantaneous.

## Copilot's execution path

The Windows entry point is `setup.ps1 -ProvisionAzure`; Debian/Ubuntu and
macOS use `setup.sh --provision-azure`. Node.js must already be installed;
prefer maintained Node 22.13+ or Node 24 for local Flock. Copilot also checks
GitHub authentication so the deployment owner can enroll.

1. Install Azure CLI if missing: Windows uses `winget` (possibly UAC),
   Debian/Ubuntu use the official installer (possibly `sudo`), and macOS
   requires existing Homebrew.
2. Authenticate with Azure CLI as needed; headless Linux uses device-code
   login. Select the requested subscription and resolve its actual ID.
3. Resolve the broker maintainer from `GITHUB_USER`, otherwise authenticated
   `gh api user --jq .login`. This is the deployment's owner, not a hardcoded
   repository maintainer.
4. Create the resource group and deploy `infra/azuredeploy.json`. Names use
   the chosen prefix and a deterministic resource-group suffix.
5. Read **nonsecret metadata only** from deployment outputs. Retrieve keys
   separately through authorized Azure commands pinned to that subscription,
   resource group and resource names; validate their endpoints. Keys stay in
   process memory, not deployment outputs or installer command arguments.
6. Create a temporary ZIP containing only `bootstrap-server.mjs` and
   `package.json`; deploy it with `az webapp deploy --type zip`. No remote
   npm build is required because the broker uses Node built-ins only.
7. Poll the broker's HTTPS `/health` endpoint with bounded retries, requiring
   the expected service and configured SignalR/managed identity fields.
   Cold-start polling can take up to about ten minutes. Remove the local ZIP
   even when deployment fails.
8. Call the existing Flock installer in-process with the captured credentials
   and authenticated deployment origin. The origin pin remains enforced;
   conflicting explicit pins fail instead of being silently overridden.
   The installer configures the daemon, MCP server, skills and coordinators.
   Setup reports success only after confirmed member registration and a
   nonempty v3 enrollment result.

The installed `bootstrapUrl` is the deployed origin normalized to
`https://<web-app>.azurewebsites.net/api/bootstrap`. Once enrollment succeeds,
ask Copilot: **"Generate an invite for my other PC."** Additional machines use
that signed invite without Azure CLI or copying resource keys. They must
independently confirm the issuer's HTTPS origin before sending a GitHub token.

### Setup selectors used by Copilot

| Windows | Bash | Default |
| --- | --- | --- |
| `-SubscriptionId` | `--subscription` | Current authenticated subscription |
| `-ResourceGroup` | `--resource-group` | `rg-copilot-flock` |
| `-Location` | `--location` | `eastus` |
| `-NamePrefix` | `--name-prefix` | `flock`, 1-20 alphanumeric characters |
| `-Scope` | `--scope` | Confirm `personal` or `work` |
| `-MachineId` | `--machine-id` | Local installer default |
| `-SkipBroker` | `--skip-broker` | Broker enabled |

Advanced operators can deploy the same ARM template with reviewed parameter
overrides: `location`, `namePrefix`, `uniqueSuffix`, `signalrSku`,
`serviceBusSku` (Standard only), `serviceBusTopicName`, `deployTokenBroker`,
`appServiceSku`, `allowedGithubRepo` and `platformMaintainerUser`. The managed
wrappers use the standard offline topic and public Azure endpoints.

## Broker-free and existing-resource alternatives

If explicitly requested, `-SkipBroker` / `--skip-broker` provisions only
SignalR and Service Bus and installs with direct credentials. No Web App,
hosting plan, managed identity or broker role assignment is created. This
does **not** enable signed broker invites; approve a broker deployment later
if that workflow becomes necessary.

Without the provisioning flag, the wrappers retain the existing invite and
direct-credential setup paths and create no Azure resources. Copilot should
use a trusted installation machine and keep supplied credentials out of
public artifacts. Those legacy direct-input paths are not the managed
in-memory credential handoff.

## Failure, security and verification

Deployment, key access, ZIP publication or readiness failures stop before
local installation. Azure resources already created remain in place; setup
does not automatically delete the resource group or unrelated resources.
An installer/enrollment failure can leave a local partial installation:
inspect it and repair authentication/enrollment rather than assuming success
or blindly reprovisioning. Do not publish captured deployment/app settings,
key-list responses, local configuration or GitHub tokens.

App settings contain resource credentials and must remain restricted to
authorized Azure operators. Removing secret outputs prevents new key
disclosure through those output fields; it does not erase historical
deployment records or rotate previously exposed keys.

Health checks establish process/configuration readiness, not provider RBAC,
offline delivery or end-to-end enrollment acceptance. The source and mock
tests do not establish live Azure deployment, pricing, all-platform support
or guaranteed latency. Network/proxy policies can still block outbound
SignalR or Service Bus connections.

After an authorized live setup, ask Copilot to verify registration,
coordinators, daemon, MCP configuration, real online messaging and offline
delivery. Windows startup is at user sign-in; unattended Linux boot may need
approved `systemd --user` lingering. Session sharing remains explicit for
collaborators and guests; deployment is not permission to expose all threads.
