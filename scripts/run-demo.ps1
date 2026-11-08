<#
.SYNOPSIS
  Runtime part of the demo: check the tunnel, check the sign-in, then run the stepped workflow.

.EXAMPLE
  .\scripts\run-demo.ps1 -Workflow wf_002
  .\scripts\run-demo.ps1 -Workflow wf_002 -Probe
#>
[CmdletBinding()]
param(
    [string]$Workflow = "wf_002",
    [int]$Issue = 1,
    [int]$LocalPort = 18000,
    [switch]$NoStep,
    [switch]$Probe
)

$ErrorActionPreference = "Stop"

# 1. The gateway tunnel must be up.
if (-not (Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue)) {
    throw "No tunnel on port $LocalPort. Run .\scripts\start-tunnel.ps1 first (use -LocalPort 18001 for a second tunnel)."
}
if ($LocalPort -ne 18000) { $env:AGENTLEDGER_GATEWAY_URL = "http://127.0.0.1:$LocalPort/mcp" }

# 2. A human must be signed in.
agentledger whoami
if ($LASTEXITCODE -ne 0) { throw "Not signed in. Run: agentledger login" }

# 3. Run, or probe.
if ($Probe) {
    agentledger probe --workflow $Workflow
} elseif ($NoStep) {
    agentledger run --issue $Issue --workflow $Workflow
} else {
    agentledger run --issue $Issue --workflow $Workflow --step
}
exit $LASTEXITCODE
