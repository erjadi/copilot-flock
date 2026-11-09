#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVISION_AZURE=false
RESOURCE_GROUP="rg-copilot-flock"
LOCATION="eastus"
LEGACY=false
ROSTER_REPOSITORY=""
PUBLISH_ROSTER=false
VERIFIED_ROOT_FINGERPRINT=""
GITHUB_USER=""
SCOPE="${COPILOT_FLOCK_SCOPE:-${COPILOT_BRIDGE_SCOPE:-}}"
MACHINE_ID="${COPILOT_FLOCK_MACHINE_ID:-${COPILOT_BRIDGE_MACHINE_ID:-}}"
INVITE_FILE="${COPILOT_FLOCK_INVITE_FILE:-}"
BOOTSTRAP_URL="${COPILOT_FLOCK_BOOTSTRAP_URL:-}"
CONNECTION_STRING="${SIGNALR_CONNECTION_STRING:-}"
SERVICEBUS_CONNECTION_STRING="${SERVICEBUS_CONNECTION_STRING:-}"

fail() { printf '%s\n' "$1" >&2; exit 1; }
require_value() {
  [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || fail "Missing value for $1."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provision-azure) PROVISION_AZURE=true; shift ;;
    --legacy) LEGACY=true; shift ;;
    --roster-repository) require_value "$@"; ROSTER_REPOSITORY="$2"; shift 2 ;;
    --publish-roster) PUBLISH_ROSTER=true; shift ;;
    --verified-root-fingerprint) require_value "$@"; VERIFIED_ROOT_FINGERPRINT="$2"; shift 2 ;;
    --github-user) require_value "$@"; GITHUB_USER="$2"; shift 2 ;;
    --resource-group) require_value "$@"; RESOURCE_GROUP="$2"; shift 2 ;;
    --location) require_value "$@"; LOCATION="$2"; shift 2 ;;
    --scope) require_value "$@"; SCOPE="$2"; shift 2 ;;
    --machine-id) require_value "$@"; MACHINE_ID="$2"; shift 2 ;;
    --invite-file) require_value "$@"; INVITE_FILE="$2"; shift 2 ;;
    --bootstrap-url) require_value "$@"; BOOTSTRAP_URL="$2"; shift 2 ;;
    --connection-string) require_value "$@"; CONNECTION_STRING="$2"; shift 2 ;;
    --servicebus-connection-string) require_value "$@"; SERVICEBUS_CONNECTION_STRING="$2"; shift 2 ;;
    *) fail "Unknown setup option: $1" ;;
  esac
done

command -v node >/dev/null 2>&1 || fail "Node.js is required before running setup."
NODE_VERSION="$(node --version)" || fail "Cannot determine Node.js version."
[[ "$NODE_VERSION" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+) ]] || fail "Node.js >=22.5 is required."
if (( BASH_REMATCH[1] < 22 || (BASH_REMATCH[1] == 22 && BASH_REMATCH[2] < 5) )); then
  fail "Node.js >=22.5 is required before setup; no tools or resources were installed."
fi
[[ -z "$SCOPE" || "$SCOPE" == work || "$SCOPE" == personal ]] || fail "Scope must be work or personal."
NODE_FLAGS=()
if [[ "$LEGACY" == false ]] && (( (BASH_REMATCH[1] == 22 && BASH_REMATCH[2] < 13) || (BASH_REMATCH[1] == 23 && BASH_REMATCH[2] < 4) )); then
  NODE_FLAGS+=("--experimental-sqlite")
fi
if [[ "$PROVISION_AZURE" == true ]]; then
  [[ "$LEGACY" == true || ! -f "${COPILOT_HOME:-$HOME/.copilot}/flock/config.json" ]] ||
    fail "Existing Flock configuration must not be replaced by fresh provisioning; no Azure resources were created."
  [[ "$LEGACY" == true || ( -n "$ROSTER_REPOSITORY" && "$PUBLISH_ROSTER" == true ) ]] ||
    fail "Fresh Zero-Broker setup requires --roster-repository and explicit --publish-roster consent before provisioning."
  [[ -z "$INVITE_FILE" && -z "$CONNECTION_STRING" && -z "$SERVICEBUS_CONNECTION_STRING" ]] ||
    fail "--provision-azure cannot be combined with an invite or existing connection strings."
  if ! command -v az >/dev/null 2>&1; then
    case "$(uname -s)" in
      Darwin)
        command -v brew >/dev/null 2>&1 || fail "Azure CLI is missing and Homebrew is unavailable."
        brew install azure-cli
        ;;
      Linux)
        [[ -f /etc/os-release ]] || fail "Automatic Azure CLI installation requires Debian or Ubuntu."
        . /etc/os-release
        [[ "${ID:-}" == debian || "${ID:-}" == ubuntu || "${ID_LIKE:-}" =~ (debian|ubuntu) ]] ||
          fail "Automatic Azure CLI installation requires Debian or Ubuntu; install az before retrying."
        command -v curl >/dev/null 2>&1 || fail "curl is required to install Azure CLI."
        if [[ "$EUID" -eq 0 ]]; then
          curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash
        else
          command -v sudo >/dev/null 2>&1 || fail "sudo is required to install Azure CLI."
          curl -fsSL https://aka.ms/InstallAzureCLIDeb | sudo bash
        fi
        ;;
      *) fail "Automatic Azure CLI installation supports Debian/Ubuntu or macOS. Use setup.ps1 on Windows." ;;
    esac
    command -v az >/dev/null 2>&1 || fail "Azure CLI is still unavailable after installation."
  fi
  if ! az account show --output none >/dev/null 2>&1; then
    if [[ "$(uname -s)" == Linux && -z "${DISPLAY:-}" ]]; then
      az login --use-device-code --output none
    else
      az login --output none
    fi
  fi
  az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
  DEPLOYMENT_OUTPUT="$(az deployment group create --resource-group "$RESOURCE_GROUP" \
    --template-file "$SCRIPT_DIR/infra/azuredeploy.json" --query "properties.outputs" --output json)"
  output_value() {
    printf '%s' "$DEPLOYMENT_OUTPUT" | node -e '
      const fs = require("node:fs");
      let output;
      try { output = JSON.parse(fs.readFileSync(0, "utf8")); }
      catch { console.error("Azure deployment returned malformed JSON outputs."); process.exit(1); }
      const value = output?.[process.argv[1]]?.value;
      if (typeof value !== "string" || !value.trim()) {
        console.error("Azure deployment did not return the required connection string."); process.exit(1);
      }
      process.stdout.write(value);
    ' "$1"
  }
  CONNECTION_STRING="$(output_value signalrConnectionString)"
  SERVICEBUS_CONNECTION_STRING="$(output_value serviceBusConnectionString)"
  echo "Managed Azure resources are ready; installing full Flock locally."
fi

ARGS=("${NODE_FLAGS[@]}" "$SCRIPT_DIR/flock.mjs" "install")
[[ "$LEGACY" == false ]] || ARGS+=("--architecture" "legacy")
[[ -z "$ROSTER_REPOSITORY" ]] || ARGS+=("--roster-repository" "$ROSTER_REPOSITORY")
[[ "$PUBLISH_ROSTER" == false ]] || ARGS+=("--publish-roster")
[[ -z "$VERIFIED_ROOT_FINGERPRINT" ]] || ARGS+=("--verified-root-fingerprint" "$VERIFIED_ROOT_FINGERPRINT")
[[ -z "$GITHUB_USER" ]] || ARGS+=("--github-user" "$GITHUB_USER")
if [[ "$PROVISION_AZURE" == true && "$LEGACY" == false ]]; then
  ARGS+=("--resource-group" "$RESOURCE_GROUP" "--azure-output-stdin")
  CONNECTION_STRING=""
  SERVICEBUS_CONNECTION_STRING=""
fi
[[ -z "$SCOPE" ]] || ARGS+=("--scope" "$SCOPE")
[[ -z "$MACHINE_ID" ]] || ARGS+=("--machine-id" "$MACHINE_ID")
[[ -z "$INVITE_FILE" ]] || ARGS+=("--invite-file" "$INVITE_FILE")
[[ -z "$BOOTSTRAP_URL" ]] || ARGS+=("--bootstrap-url" "$BOOTSTRAP_URL")
[[ -z "$CONNECTION_STRING" ]] || ARGS+=("--connection-string" "$CONNECTION_STRING")
[[ -z "$SERVICEBUS_CONNECTION_STRING" ]] || ARGS+=("--servicebus-connection-string" "$SERVICEBUS_CONNECTION_STRING")
echo "Installing and starting Copilot Flock..."
if [[ "$PROVISION_AZURE" == true && "$LEGACY" == false ]]; then
  printf '%s' "$DEPLOYMENT_OUTPUT" | node "${ARGS[@]}"
else
  node "${ARGS[@]}"
fi
