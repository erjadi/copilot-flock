#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVISION_AZURE=false
RESOURCE_GROUP="rg-copilot-flock"
LOCATION="eastus"
SUBSCRIPTION=""
NAME_PREFIX="flock"
SKIP_BROKER=true
SCOPE="${COPILOT_FLOCK_SCOPE:-${COPILOT_BRIDGE_SCOPE:-}}"
MACHINE_ID="${COPILOT_FLOCK_MACHINE_ID:-${COPILOT_BRIDGE_MACHINE_ID:-}}"
INVITE_FILE="${COPILOT_FLOCK_INVITE_FILE:-}"
BOOTSTRAP_URL="${COPILOT_FLOCK_BOOTSTRAP_URL:-}"
CONNECTION_STRING="${SIGNALR_CONNECTION_STRING:-}"
SERVICEBUS_CONNECTION_STRING="${SERVICEBUS_CONNECTION_STRING:-}"
SERVICEBUS_SEND_CONNECTION_STRING="${SERVICEBUS_SEND_CONNECTION_STRING:-}"
SERVICEBUS_LISTEN_CONNECTION_STRING="${SERVICEBUS_LISTEN_CONNECTION_STRING:-}"
FLOCK=""

fail() { printf '%s\n' "$1" >&2; exit 1; }
require_value() {
  [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || fail "Missing value for $1."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provision-azure) PROVISION_AZURE=true; shift ;;
    --resource-group) require_value "$@"; RESOURCE_GROUP="$2"; shift 2 ;;
    --location) require_value "$@"; LOCATION="$2"; shift 2 ;;
    --subscription) require_value "$@"; SUBSCRIPTION="$2"; shift 2 ;;
    --name-prefix) require_value "$@"; NAME_PREFIX="$2"; shift 2 ;;
    --skip-broker) SKIP_BROKER=true; shift ;;
    --legacy-broker) SKIP_BROKER=false; shift ;;
    --scope) require_value "$@"; SCOPE="$2"; shift 2 ;;
    --machine-id) require_value "$@"; MACHINE_ID="$2"; shift 2 ;;
    --invite-file) require_value "$@"; INVITE_FILE="$2"; shift 2 ;;
    --bootstrap-url) require_value "$@"; BOOTSTRAP_URL="$2"; shift 2 ;;
    --connection-string) require_value "$@"; CONNECTION_STRING="$2"; shift 2 ;;
    --servicebus-connection-string) require_value "$@"; SERVICEBUS_CONNECTION_STRING="$2"; shift 2 ;;
    --servicebus-send-connection-string) require_value "$@"; SERVICEBUS_SEND_CONNECTION_STRING="$2"; shift 2 ;;
    --servicebus-listen-connection-string) require_value "$@"; SERVICEBUS_LISTEN_CONNECTION_STRING="$2"; shift 2 ;;
    --flock) require_value "$@"; FLOCK="$2"; shift 2 ;;
    *) fail "Unknown setup option: $1" ;;
  esac
done

command -v node >/dev/null 2>&1 || fail "Node.js is required before running setup."
[[ -z "$SCOPE" || "$SCOPE" == work || "$SCOPE" == personal ]] || fail "Scope must be work or personal."
if [[ "$PROVISION_AZURE" == true ]]; then
  [[ -z "$INVITE_FILE" && -z "$CONNECTION_STRING" && -z "$SERVICEBUS_CONNECTION_STRING" &&
     -z "$SERVICEBUS_SEND_CONNECTION_STRING" && -z "$SERVICEBUS_LISTEN_CONNECTION_STRING" && -z "$BOOTSTRAP_URL" ]] ||
    fail "--provision-azure cannot be combined with an invite, bootstrap URL or existing connection strings."
  [[ "$NAME_PREFIX" =~ ^[a-zA-Z0-9]{1,20}$ ]] || fail "Name prefix must be 1-20 alphanumeric characters."
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
  [[ -z "$SUBSCRIPTION" ]] || az account set --subscription "$SUBSCRIPTION"
  SUBSCRIPTION="$(az account show --query id --output tsv)"
  [[ "$SUBSCRIPTION" =~ ^[a-fA-F0-9-]{36}$ ]] || fail "Cannot resolve the selected Azure subscription."
  GITHUB_USER="${GITHUB_USER:-}"
  if [[ -z "$GITHUB_USER" ]]; then
    command -v gh >/dev/null 2>&1 || fail "Sign in to GitHub CLI or provide GITHUB_USER before provisioning."
    GITHUB_USER="$(gh api user --jq .login)"
  fi
  [[ "$GITHUB_USER" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$ ]] || fail "Invalid GitHub owner label."
  [[ -n "$SCOPE" ]] || fail "Confirm an explicit personal or work scope before provisioning."
  az group create --subscription "$SUBSCRIPTION" --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
  DEPLOYMENT_OUTPUT="$(az deployment group create --subscription "$SUBSCRIPTION" --resource-group "$RESOURCE_GROUP" \
    --template-file "$SCRIPT_DIR/infra/azuredeploy.json" \
    --parameters "location=$LOCATION" "namePrefix=$NAME_PREFIX" "deployTokenBroker=$([[ "$SKIP_BROKER" == false ]] && echo true || echo false)" \
    "platformMaintainerUser=$GITHUB_USER" --query "properties.outputs" --output json 2>/dev/null)" ||
    fail "Azure ARM deployment failed; captured output withheld."
  MANAGED_ARGS=("$SCRIPT_DIR/managed-azure-setup.mjs" "--subscription" "$SUBSCRIPTION" "--resource-group" "$RESOURCE_GROUP")
  [[ -z "$GITHUB_USER" ]] || MANAGED_ARGS+=("--github-user" "$GITHUB_USER")
  [[ -z "$SCOPE" ]] || MANAGED_ARGS+=("--scope" "$SCOPE")
  [[ -z "$MACHINE_ID" ]] || MANAGED_ARGS+=("--machine-id" "$MACHINE_ID")
  [[ "$SKIP_BROKER" == true ]] || MANAGED_ARGS+=("--legacy-broker")
  printf '%s' "$DEPLOYMENT_OUTPUT" | node "${MANAGED_ARGS[@]}"
  exit $?
fi

ARGS=("$SCRIPT_DIR/flock.mjs" "install")
[[ -z "$SCOPE" ]] || ARGS+=("--scope" "$SCOPE")
[[ -z "$MACHINE_ID" ]] || ARGS+=("--machine-id" "$MACHINE_ID")
[[ -z "$INVITE_FILE" ]] || ARGS+=("--invite-file" "$INVITE_FILE")
[[ -z "$BOOTSTRAP_URL" ]] || ARGS+=("--bootstrap-url" "$BOOTSTRAP_URL")
[[ -z "$CONNECTION_STRING" ]] || ARGS+=("--connection-string" "$CONNECTION_STRING")
[[ -z "$SERVICEBUS_CONNECTION_STRING" ]] || ARGS+=("--servicebus-connection-string" "$SERVICEBUS_CONNECTION_STRING")
[[ -z "$SERVICEBUS_SEND_CONNECTION_STRING" ]] || ARGS+=("--servicebus-send-connection-string" "$SERVICEBUS_SEND_CONNECTION_STRING")
[[ -z "$SERVICEBUS_LISTEN_CONNECTION_STRING" ]] || ARGS+=("--servicebus-listen-connection-string" "$SERVICEBUS_LISTEN_CONNECTION_STRING")
[[ -z "$FLOCK" ]] || ARGS+=("--flock" "$FLOCK")
echo "Installing and starting Copilot Flock..."
node "${ARGS[@]}"
