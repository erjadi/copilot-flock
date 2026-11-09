param(
    [string]$MachineId = $env:COMPUTERNAME,
    [ValidateSet("work", "personal")]
    [string]$Scope = $(if ($env:COPILOT_FLOCK_SCOPE) { $env:COPILOT_FLOCK_SCOPE } elseif ($env:COPILOT_BRIDGE_SCOPE) { $env:COPILOT_BRIDGE_SCOPE } else { "" }),
    [string]$InviteFile = $env:COPILOT_FLOCK_INVITE_FILE,
    [string]$BootstrapUrl = $env:COPILOT_FLOCK_BOOTSTRAP_URL,
    [string]$BootstrapOriginPin = $env:COPILOT_FLOCK_ALLOWED_BOOTSTRAP_ORIGIN,
    [string]$ConnectionString = $env:SIGNALR_CONNECTION_STRING,
    [string]$ServiceBusConnectionString = $env:SERVICEBUS_CONNECTION_STRING,
    [switch]$ProvisionAzure,
    [string]$ResourceGroup = "rg-copilot-flock",
    [string]$Location = "eastus",
    [switch]$Legacy,
    [string]$RosterRepository,
    [switch]$PublishRoster,
    [string]$VerifiedRootFingerprint,
    [string]$GitHubUser
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$FlockScript = Join-Path $ScriptDir "flock.mjs"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js is required before running setup."
}
$NodeVersion = (& node --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $NodeVersion -notmatch '^v(\d+)\.(\d+)\.(\d+)') {
    throw "Cannot determine Node.js version; Node.js >=22.5 is required."
}
if ([int]$Matches[1] -lt 22 -or ([int]$Matches[1] -eq 22 -and [int]$Matches[2] -lt 5)) {
    throw "Node.js >=22.5 is required before setup; no tools or resources were installed."
}
$NodeFlags = @()
if (-not $Legacy -and (([int]$Matches[1] -eq 22 -and [int]$Matches[2] -lt 13) -or ([int]$Matches[1] -eq 23 -and [int]$Matches[2] -lt 4))) { $NodeFlags += "--experimental-sqlite" }
if ($ProvisionAzure) {
    $CopilotHome = if ($env:COPILOT_HOME) { $env:COPILOT_HOME } else { Join-Path $HOME ".copilot" }
    if (-not $Legacy -and (Test-Path (Join-Path $CopilotHome "flock\config.json"))) {
        throw "Existing Flock configuration must not be replaced by fresh provisioning; no Azure resources were created."
    }
    if (-not $Legacy -and (-not $RosterRepository -or -not $PublishRoster)) {
        throw "Fresh Zero-Broker setup requires -RosterRepository and explicit -PublishRoster consent before provisioning. Use -Legacy only for the existing broker implementation."
    }
    if ($InviteFile -or $ConnectionString -or $ServiceBusConnectionString) {
        throw "-ProvisionAzure cannot be combined with an invite or existing connection strings."
    }
    if ([string]::IsNullOrWhiteSpace($ResourceGroup) -or [string]::IsNullOrWhiteSpace($Location)) {
        throw "ResourceGroup and Location must be nonempty."
    }
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Azure CLI is missing and winget is unavailable. Install Azure CLI before retrying."
        }
        Write-Host "Installing Azure CLI (Windows may request administrator consent)..." -ForegroundColor Cyan
        & winget install --exact --id Microsoft.AzureCLI --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            throw "Azure CLI installation failed."
        }
        $env:Path += ";C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin;C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin"
        if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
            throw "Azure CLI is still unavailable after installation. Refresh your shell and retry."
        }
    }
    $PreviousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & az account show --output none 2>$null
        $AccountStatus = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousErrorPreference
    }
    if ($AccountStatus -ne 0) {
        & az login --output none
        if ($LASTEXITCODE -ne 0) {
            throw "Azure authentication failed."
        }
    }
    & az group create --name $ResourceGroup --location $Location --output none
    if ($LASTEXITCODE -ne 0) {
        throw "Azure resource group creation failed."
    }
    $DeploymentOutput = & az deployment group create --resource-group $ResourceGroup `
        --template-file (Join-Path $ScriptDir "infra\azuredeploy.json") `
        --query "properties.outputs" --output json
    if ($LASTEXITCODE -ne 0) {
        throw "Azure ARM deployment failed."
    }
    try {
        $Deployment = ($DeploymentOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Azure deployment returned malformed JSON outputs; connection strings were not logged."
    }
    if ($Deployment.signalrConnectionString.value -isnot [string] -or
        [string]::IsNullOrWhiteSpace($Deployment.signalrConnectionString.value) -or
        $Deployment.serviceBusConnectionString.value -isnot [string] -or
        [string]::IsNullOrWhiteSpace($Deployment.serviceBusConnectionString.value)) {
        throw "Azure deployment did not return both required connection strings."
    }
    $ConnectionString = $Deployment.signalrConnectionString.value
    $ServiceBusConnectionString = $Deployment.serviceBusConnectionString.value
    Write-Host "Managed Azure resources are ready; installing full Flock locally." -ForegroundColor Cyan
}

$ArgsList = @($NodeFlags) + @($FlockScript, "install")
if ($Legacy) { $ArgsList += @("--architecture", "legacy") }
if ($RosterRepository) { $ArgsList += @("--roster-repository", $RosterRepository) }
if ($PublishRoster) { $ArgsList += "--publish-roster" }
if ($VerifiedRootFingerprint) { $ArgsList += @("--verified-root-fingerprint", $VerifiedRootFingerprint) }
if ($GitHubUser) { $ArgsList += @("--github-user", $GitHubUser) }
if ($ProvisionAzure -and -not $Legacy) {
    $ArgsList += @("--resource-group", $ResourceGroup, "--azure-output-stdin")
}
if ($Scope) {
    $ArgsList += @("--scope", $Scope)
}
if ($MachineId) {
    $ArgsList += @("--machine-id", $MachineId)
}
if ($InviteFile) {
    $ArgsList += @("--invite-file", $InviteFile)
}
if ($BootstrapUrl) {
    $ArgsList += @("--bootstrap-url", $BootstrapUrl)
}
if ($BootstrapOriginPin) {
    $ArgsList += @("--bootstrap-origin-pin", $BootstrapOriginPin)
}
if ($ConnectionString -and (-not $ProvisionAzure -or $Legacy)) {
    $ArgsList += @("--connection-string", $ConnectionString)
}
if ($ServiceBusConnectionString -and (-not $ProvisionAzure -or $Legacy)) {
    $ArgsList += @("--servicebus-connection-string", $ServiceBusConnectionString)
}

Write-Host "Installing and starting Copilot Flock..." -ForegroundColor Cyan
if ($ProvisionAzure -and -not $Legacy) {
    $DeploymentOutput -join "`n" | & node @ArgsList
} else { & node @ArgsList }
exit $LASTEXITCODE
