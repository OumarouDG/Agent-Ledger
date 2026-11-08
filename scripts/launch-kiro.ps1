<#
.SYNOPSIS
  Start Kiro with an AgentLedger agent token, grant and workflow in its environment.

.DESCRIPTION
  .kiro/settings/mcp.json reads ${AGENTLEDGER_TOKEN}, ${AGENTLEDGER_GRANT_ID} and
  ${AGENTLEDGER_WORKFLOW_ID}. Kiro only sees variables that exist when it STARTS, so this
  script sets them and then launches Kiro itself. The token lives in this process's
  environment only: it is never printed, written to a file, or passed on a command line.

  Close every Kiro window first. A new window of an already-running Kiro reuses that
  process and does not get these variables.

.EXAMPLE
  .\scripts\launch-kiro.ps1
  .\scripts\launch-kiro.ps1 -Agent agent_coder -GrantId grant_001 -WorkflowId wf_001
#>
[CmdletBinding()]
param(
    [string]$Agent = "agent_coder",
    [string]$GrantId = "grant_001",
    [string]$WorkflowId = "wf_001",
    [string]$InstanceId = "i-02d94a2f0bf2a72db",
    [int]$LocalPort = 18000,
    [int]$RemotePort = 8000,
    [string]$Workspace = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Workspace) { $Workspace = $root }

# 1. Kiro must not already be running, or it will ignore the variables set below.
if (Get-Process -Name "Kiro" -ErrorAction SilentlyContinue) {
    throw "Kiro is already running. Close every Kiro window, then run this script again."
}

# 2. Make sure the SSM tunnel (laptop LocalPort -> EC2 RemotePort) is up.
$tunnel = Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue
if (-not $tunnel) {
    Write-Host "Starting SSM tunnel to $InstanceId on port $LocalPort ..."
    Start-Process -FilePath "aws" -WindowStyle Hidden -ArgumentList @(
        "ssm", "start-session", "--target", $InstanceId,
        "--document-name", "AWS-StartPortForwardingSession",
        "--parameters", "portNumber=$RemotePort,localPortNumber=$LocalPort")
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue)) {
        if ((Get-Date) -gt $deadline) { throw "The SSM tunnel did not come up. Check 'aws sts get-caller-identity'." }
        Start-Sleep -Milliseconds 500
    }
}

# 3. Mint the agent token with the project's trusted tooling. Kept in a variable, never echoed.
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Missing $python. Create the venv first (see docs/gateway.md)." }
$code = "import sys; from controlplane.auth.agent_tokens import mint_agent_token; sys.stdout.write(mint_agent_token(sys.argv[1]).access_token)"
Push-Location $root
try { $token = & $python -c $code $Agent } finally { Pop-Location }
if ($LASTEXITCODE -ne 0 -or -not $token) { throw "Could not mint a token for $Agent. Check your AWS login." }

# 4. Put the values in this process's environment; Kiro inherits them.
$env:AGENTLEDGER_TOKEN = $token
$env:AGENTLEDGER_GRANT_ID = $GrantId
$env:AGENTLEDGER_WORKFLOW_ID = $WorkflowId
$token = $null

Write-Host "Launching Kiro as $Agent (grant $GrantId, workflow $WorkflowId). Token valid ~12 hours."
$kiro = Join-Path $env:LOCALAPPDATA "Programs\Kiro\Kiro.exe"
if (-not (Test-Path $kiro)) { throw "Kiro.exe not found at $kiro" }
Start-Process -FilePath $kiro -ArgumentList @("`"$Workspace`"")

# Clear them from this shell so they do not linger in the terminal session.
Remove-Item Env:AGENTLEDGER_TOKEN, Env:AGENTLEDGER_GRANT_ID, Env:AGENTLEDGER_WORKFLOW_ID -ErrorAction SilentlyContinue
