<#
.SYNOPSIS
  Open the SSM tunnel to the AgentLedger gateway on EC2 and leave it running.

.DESCRIPTION
  Laptop 127.0.0.1:18000 -> EC2 127.0.0.1:8000. The gateway's MCP address is then
  http://127.0.0.1:18000/mcp. It needs your AWS login (aws sts get-caller-identity must work)
  and the Session Manager plugin. This script starts no Kiro and mints no token.

  The tunnel runs in the background. If the port is already open, nothing is started.
  Stop it with:  Get-NetTCPConnection -LocalPort 18000 -State Listen | % { Stop-Process -Id $_.OwningProcess }

.EXAMPLE
  .\scripts\start-tunnel.ps1
#>
[CmdletBinding()]
param(
    [string]$InstanceId = "i-02d94a2f0bf2a72db",
    [int]$LocalPort = 18000,
    [int]$RemotePort = 8000
)

$ErrorActionPreference = "Stop"

if (Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue) {
    Write-Host "Port $LocalPort is already listening. Tunnel (or something else) is up: http://127.0.0.1:$LocalPort/mcp"
    return
}

Start-Process -FilePath "aws" -WindowStyle Hidden -ArgumentList @(
    "ssm", "start-session", "--target", $InstanceId,
    "--document-name", "AWS-StartPortForwardingSession",
    "--parameters", "portNumber=$RemotePort,localPortNumber=$LocalPort")

$deadline = (Get-Date).AddSeconds(30)
while (-not (Get-NetTCPConnection -LocalPort $LocalPort -State Listen -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) {
        throw "The SSM tunnel did not come up. Check 'aws sts get-caller-identity' and that the Session Manager plugin is installed."
    }
    Start-Sleep -Milliseconds 500
}
Write-Host "Tunnel up: http://127.0.0.1:$LocalPort/mcp  (EC2 $InstanceId port $RemotePort)"
