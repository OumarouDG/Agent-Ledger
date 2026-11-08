<#
.SYNOPSIS
  Put the demo GitHub repo back to its starting state, and print the EC2 reset steps.

.DESCRIPTION
  On the demo repo this:
    1. deletes every branch that starts with agentledger/ (this also closes their pull requests)
    2. removes greeting.py from main if a merged demo run left it there, with a normal commit
       (nothing is force-pushed and no history is rewritten)
  Then it lists what is left. Run with -DryRun first to see what it would do.

  It never touches main otherwise, never deletes the repo, and only works on the repo named by
  -Repo. It needs the GitHub CLI signed in (gh auth status).

  The EC2 side (grants, lock file, audit file) can only be reset from an SSM shell. The steps
  are printed at the end.

.EXAMPLE
  .\scripts\reset-demo.ps1 -DryRun
  .\scripts\reset-demo.ps1
#>
[CmdletBinding()]
param(
    [string]$Repo = "OumarouDG/agentledger-demo",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# gh writes errors to stderr; in Windows PowerShell 5 that would stop the script even for an
# expected 404. Run it with errors tolerated and return the exit code and the output.
function Invoke-Gh {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $out = & gh @args 2>&1 } finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Code = $LASTEXITCODE; Out = @($out | ForEach-Object { "$_" }) }
}

function Say([string]$text) { if ($DryRun) { Write-Host "[dry run] $text" } else { Write-Host $text } }

if ($Repo -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$') { throw "Bad repo name: $Repo" }
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "The GitHub CLI (gh) is not installed or not on PATH." }
if ((Invoke-Gh auth status).Code -ne 0) { throw "gh is not signed in. Run: gh auth login" }

# 1. agent branches
$r = Invoke-Gh api "repos/$Repo/branches?per_page=100" --paginate --jq '.[].name'
if ($r.Code -ne 0) { throw "Could not list branches of $Repo : $($r.Out -join ' ')" }
$branches = @($r.Out) | Where-Object { $_ -like 'agentledger/*' }
if (-not $branches) { Write-Host "No agentledger/ branches to delete." }
foreach ($b in $branches) {
    Say "delete branch $b"
    if (-not $DryRun) {
        if ((Invoke-Gh api -X DELETE "repos/$Repo/git/refs/heads/$b").Code -ne 0) {
            Write-Warning "could not delete $b"
        }
    }
}

# 2. greeting.py left on main by a merged run
$sha = $null
$r = Invoke-Gh api "repos/$Repo/contents/greeting.py?ref=main"
if ($r.Code -eq 0) { $sha = (($r.Out -join "`n") | ConvertFrom-Json).sha }
if ($sha) {
    Say "remove greeting.py from main (new commit, no history rewrite)"
    if (-not $DryRun) {
        $d = Invoke-Gh api -X DELETE "repos/$Repo/contents/greeting.py" -f message="Reset demo: remove greeting.py" -f sha=$sha -f branch=main
        if ($d.Code -ne 0) { Write-Warning "could not remove greeting.py from main" }
    }
} else {
    Write-Host "main has no greeting.py. Nothing to reset there."
}

# state
Write-Host ""
$left = Invoke-Gh api "repos/$Repo/branches" --jq '.[].name'
Write-Host "Branches now: $(@($left.Out) -join ', ')"
$open = Invoke-Gh pr list -R $Repo --state open --json number --jq '.[].number'
Write-Host "Open pull requests: $(if ($open.Out) { @($open.Out) -join ', ' } else { 'none' })"

Write-Host @"

EC2 side (run in an SSM shell, from /home/ssm-user/Agent-Ledger):
  rm -f gateway-quarantine.json                       # release any Sentinel lock
  mv gateway-audit.jsonl gateway-audit.old.jsonl      # optional: start the audit file clean
Grants live in DynamoDB. Create fresh ones right before the demo:
  agentledger grant create ... (grants last at most 4 hours)
"@
