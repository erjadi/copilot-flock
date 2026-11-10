# New Copilot Flock: bring your own Azure subscription

![Two ways to bootstrap Copilot Flock](./assets/flock-onboarding-paths.svg)

Ask Copilot:

> "Clone https://github.com/erjadi/copilot-flock, read AGENTS.md, and set up
> a new Flock in my Azure subscription. Confirm my subscription, region,
> resource group, personal/work scope, tool installation and costs first."

Copilot executes setup; you do not need to copy credentials or type cloud
commands. Invited machines do not provision Azure. New broker-free enrollment uses a
device-bound Join Code and independently pinned Welcome Ticket; see
[the 3.4.0 protocol guide](./BROKER_FREE_V34.md).
Existing signed v3 broker invitations use the explicit
[legacy joining guide](./JOINING_AND_SHARING_GUIDE.md).

## What the managed setup provisions

One ARM deployment creates:

| Component | Default | Purpose |
| --- | --- | --- |
| Azure SignalR | Serverless, `Free_F1` | Real-time rendezvous between online machines |
| Azure Service Bus | Standard namespace, `copilot-bridge-offline` topic | Durable offline messaging |
| Child resources | Topic, `FlockSendRule` with Send only, `FlockListenRule` with Listen only | Separate owner-issued topic Send and per-peer subscription Listen SAS |

SignalR Free has connection/message quotas; Service Bus Standard incurs charges.
Review current regional pricing, quotas and subscription policy before approval.
ARM also supports `Standard_S1` for SignalR. The default has no
`Microsoft.Web` plan/site, managed identity or broker hosting.

The deploying Azure identity needs resource creation and resource/policy
key-listing permissions. The designated owner locally retains management
authority for exact subscription creation/deletion. Guests never receive it.
Explicit legacy hosting additionally needs role-assignment permission;
Contributor alone does not grant that permission.

## Copilot's execution path

The Windows entry point is `setup.ps1 -ProvisionAzure`; Debian/Ubuntu and
macOS use `setup.sh --provision-azure`. Node.js must already be installed;
prefer maintained Node 22.13+ or Node 24 for local Flock. Copilot also checks
GitHub authentication to resolve the deployment owner's label. That label does
not confer cryptographic owner authority.

1. Install Azure CLI if missing: Windows uses `winget` (possibly UAC),
   Debian/Ubuntu use the official installer (possibly `sudo`), and macOS
   requires existing Homebrew.
2. Authenticate with Azure CLI as needed; headless Linux uses device-code
   login. Select the requested subscription and resolve its actual ID.
3. Resolve the owner label from `GITHUB_USER`, otherwise authenticated
   `gh api user --jq .login`. This is the deployment's owner, not a hardcoded
   repository maintainer.
4. Create the resource group and deploy `infra/azuredeploy.json`. Names use
   the chosen prefix and a deterministic resource-group suffix.
5. Read **nonsecret metadata only** from deployment outputs. Retrieve keys
   separately through authorized Azure commands pinned to that subscription,
   resource group and resource names; validate their endpoints. Keys stay in
   process memory, not deployment outputs or installer command arguments.
6. Retrieve separate SignalR, Service Bus Manage, Send-only and Listen-only
   credentials in memory, pinned to the deployed resources and policy names.
   The default performs no ZIP deployment, Web App health polling or broker call.
7. Initialize the designated owner's persisted broker-free membership and exact
   peer subscription; locally install runtime, MCP, messaging/removal skill and
   strict boot persistence. Owner keys stay local.
8. Require persisted enrollment and connected daemon readiness before success.
   This is not a substitute for the live Azure positive/negative isolation gate.

The default has no `bootstrapUrl`. Ask the other PC's Copilot to create a
Join Code for the intended flock, independently verify its device fingerprint
at the owner, then accept the owner's sealed Welcome with an independently
verified owner fingerprint. Invitees need no Azure CLI or master connection
strings. Scope, expiry and explicitly permitted sessions are owner-approved.

### Setup selectors used by Copilot

| Windows | Bash | Default |
| --- | --- | --- |
| `-SubscriptionId` | `--subscription` | Current authenticated subscription |
| `-ResourceGroup` | `--resource-group` | `rg-copilot-flock` |
| `-Location` | `--location` | `eastus` |
| `-NamePrefix` | `--name-prefix` | `flock`, 1-20 alphanumeric characters |
| `-Scope` | `--scope` | Confirm `personal` or `work` |
| `-MachineId` | `--machine-id` | Local installer default |
| `-Flock` | `--flock` | Owner/scope flock selected by setup |
| `-LegacyBroker` | `--legacy-broker` | Off; explicit legacy hosted deployment |
| `-SkipBroker` | `--skip-broker` | Compatibility no-op; cannot combine with legacy hosting |

Advanced operators can deploy the same ARM template with reviewed parameter
overrides: `location`, `namePrefix`, `uniqueSuffix`, `signalrSku`,
`serviceBusSku` (Standard only), `serviceBusTopicName`, `deployTokenBroker`,
`appServiceSku`, `allowedGithubRepo` and `platformMaintainerUser`. The managed
wrappers use the standard offline topic and public Azure endpoints.

## Explicit legacy hosting and existing resources

Only `-LegacyBroker` / `--legacy-broker` opts into the old hosted broker:
Linux Node 22 Web App, B1 plan, persistent storage, system-assigned identity and
namespace-scoped Service Bus role assignment. B1 incurs additional charges.
This path ZIP-deploys `bootstrap-server.mjs` and `package.json`, polls `/health`
and requires confirmed broker registration/v3 enrollment. The normalized origin
is pinned; a conflicting explicit pin fails. Its one-step v3 invites do not
become broker-free Welcome Tickets. This is compatibility, not silent fallback.

Without provisioning flags, no cloud resources are created. Explicit legacy
invites/bootstrap configuration preserve the old path. Fresh broker-free owner
setup with existing resources requires SignalR and separate Service Bus
Manage/Send/Listen credentials: wrapper selectors are `ConnectionString`,
`ServiceBusConnectionString`, `ServiceBusSendConnectionString` and
`ServiceBusListenConnectionString` (or their kebab-case Bash equivalents).
Do not silently migrate an existing installation. Keep credentials out of
public artifacts and prefer managed in-memory handoff.

## Failure, security and verification

Deployment, key access or explicit legacy ZIP/health failures stop before
local installation. Azure resources already created remain in place; setup
does not automatically delete the resource group or unrelated resources.
An installer/enrollment failure can leave a local partial installation:
inspect it and repair authentication/enrollment rather than assuming success
or blindly reprovisioning. Do not publish captured deployment/app settings,
key-list responses, local configuration or GitHub tokens.

Legacy broker app settings contain resource credentials and must remain restricted to
authorized Azure operators. Removing secret outputs prevents new key
disclosure through those output fields; it does not erase historical
deployment records or rotate previously exposed keys.

Health checks establish process/configuration readiness, not provider RBAC,
offline delivery or end-to-end enrollment acceptance. The source and mock
tests do not establish live Azure deployment, pricing, all-platform support
or guaranteed latency. Network/proxy policies can still block outbound
SignalR or Service Bus connections.

After an authorized disposable setup, run the explicitly approved
[live audience/SAS isolation gate](./BROKER_FREE_V34.md#required-live-azure-gate)
before merge/release. Verify its exact-commit receipt; this guide alone does
not establish that a candidate passed.
Windows startup is at user sign-in; strict Linux installation requires
previously approved `systemd --user` lingering. Broker-free mode does not
automatically create privileged coordinators. Session sharing is explicit for
all remote callers; deployment is not permission to expose existing threads.
