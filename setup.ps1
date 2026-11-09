param(
    [string]$MachineId = $env:COMPUTERNAME,
    [ValidateSet("work", "personal")]
    [string]$Scope = $(if ($env:COPILOT_FLOCK_SCOPE) { $env:COPILOT_FLOCK_SCOPE } elseif ($env:COPILOT_BRIDGE_SCOPE) { $env:COPILOT_BRIDGE_SCOPE } else { "" }),
    [string]$InviteFile = $env:COPILOT_FLOCK_INVITE_FILE,
    [string]$BootstrapUrl = $env:COPILOT_FLOCK_BOOTSTRAP_URL,
    [string]$ConnectionString = $env:SIGNALR_CONNECTION_STRING,
    [string]$ServiceBusConnectionString = $env:SERVICEBUS_CONNECTION_STRING,
    [switch]$ProvisionAzure,
    [string]$SubscriptionId,
    [string]$ResourceGroup = "rg-copilot-flock",
    [string]$Location = "eastus",
    [string]$NamePrefix = "flock",
    [switch]$SkipBroker
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$FlockScript = Join-Path $ScriptDir "flock.mjs"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js is required before running setup."
}
if ($ProvisionAzure) {
    if ($InviteFile -or $ConnectionString -or $ServiceBusConnectionString -or $BootstrapUrl) {
        throw "-ProvisionAzure cannot be combined with an invite, bootstrap URL or existing connection strings."
    }
    if ([string]::IsNullOrWhiteSpace($ResourceGroup) -or [string]::IsNullOrWhiteSpace($Location)) {
        throw "ResourceGroup and Location must be nonempty."
    }
    if ($NamePrefix -notmatch '^[a-zA-Z0-9]{1,20}$') { throw "NamePrefix must be 1-20 alphanumeric characters." }
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
    if ($SubscriptionId) {
        & az account set --subscription $SubscriptionId
        if ($LASTEXITCODE -ne 0) { throw "Azure subscription selection failed." }
    }
    $SubscriptionId = & az account show --query id --output tsv
    if ($LASTEXITCODE -ne 0 -or $SubscriptionId -notmatch '^[a-fA-F0-9-]{36}$') { throw "Cannot resolve the selected Azure subscription." }
    $GitHubUser = $env:GITHUB_USER
    if (-not $SkipBroker -and -not $GitHubUser) {
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "Sign in to GitHub CLI or provide GITHUB_USER before provisioning." }
        $GitHubUser = & gh api user --jq .login
        if ($LASTEXITCODE -ne 0) { throw "Cannot resolve the authenticated GitHub maintainer." }
    }
    if (-not $SkipBroker -and $GitHubUser -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$') { throw "Invalid GitHub maintainer." }
    & az group create --subscription $SubscriptionId --name $ResourceGroup --location $Location --output none
    if ($LASTEXITCODE -ne 0) {
        throw "Azure resource group creation failed."
    }
    try {
        $ErrorActionPreference = "Continue"
        $DeploymentOutput = & az deployment group create --subscription $SubscriptionId --resource-group $ResourceGroup `
            --template-file (Join-Path $ScriptDir "infra\azuredeploy.json") `
            --parameters "location=$Location" "namePrefix=$NamePrefix" "deployTokenBroker=$((-not $SkipBroker).ToString().ToLowerInvariant())" "platformMaintainerUser=$GitHubUser" `
            --query "properties.outputs" --output json 2>$null
        $DeploymentStatus = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousErrorPreference
    }
    if ($DeploymentStatus -ne 0) {
        throw "Azure ARM deployment failed; captured output withheld."
    }
    try {
        $null = ($DeploymentOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Azure deployment returned malformed JSON metadata."
    }
    $ManagedArgs = @((Join-Path $ScriptDir "managed-azure-setup.mjs"), "--subscription", $SubscriptionId, "--resource-group", $ResourceGroup)
    if ($GitHubUser) { $ManagedArgs += @("--github-user", $GitHubUser) }
    if ($Scope) { $ManagedArgs += @("--scope", $Scope) }
    if ($MachineId) { $ManagedArgs += @("--machine-id", $MachineId) }
    if ($SkipBroker) { $ManagedArgs += "--skip-broker" }
    try {
        $ErrorActionPreference = "Continue"
        ($DeploymentOutput -join "`n") | & node @ManagedArgs
        $ManagedStatus = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousErrorPreference
    }
    if ($ManagedStatus -ne 0) { throw "Managed Azure setup did not complete; see the sanitized error above." }
    exit $ManagedStatus
}

$ArgsList = @($FlockScript, "install")
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
if ($ConnectionString) {
    $ArgsList += @("--connection-string", $ConnectionString)
}
if ($ServiceBusConnectionString) {
    $ArgsList += @("--servicebus-connection-string", $ServiceBusConnectionString)
}

Write-Host "Installing and starting Copilot Flock..." -ForegroundColor Cyan
& node @ArgsList
exit $LASTEXITCODE
