<#
.SYNOPSIS
  RedHunt engagement scaffolder. Creates engagements/<target>/ from the template
  so you can fill auth.json + ENGAGEMENT.md and start.

.EXAMPLE
  pwsh .\engage.ps1 offshore
  pwsh .\engage.ps1 acme-bugbounty -Base "C:\work\engagements"
#>
param(
  [Parameter(Mandatory=$true, Position=0)]
  [string]$Target,
  [string]$Base = (Join-Path (Get-Location) "engagements")
)

$ErrorActionPreference = "Stop"
$skillDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$template = Join-Path $skillDir "engagements\_TEMPLATE"
$safe     = ($Target -replace '[^\w.\-]', '_')
$dest     = Join-Path $Base $safe

if (Test-Path $dest) { Write-Host "[!] $dest already exists — opening it." -ForegroundColor Yellow }
else {
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  # Copy template docs
  Copy-Item (Join-Path $template "ENGAGEMENT.md") $dest
  Copy-Item (Join-Path $template "coverage.md")   $dest
  # auth.json from the example
  Copy-Item (Join-Path $skillDir "auth.example.json") (Join-Path $dest "auth.json")
  # Working subfolders
  foreach ($d in @("findings","recon","loot","pivot","report","docs")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $dest $d) | Out-Null
  }
  # Stamp the target name into the docs
  foreach ($f in @("ENGAGEMENT.md","coverage.md")) {
    $p = Join-Path $dest $f
    (Get-Content $p -Raw) -replace '<TARGET>', $Target -replace '<target>', $safe | Set-Content $p
  }
}

Write-Host "`n[+] Engagement ready: $dest" -ForegroundColor Green
Write-Host "    1. Edit auth.json      (scope + cookies/tokens/creds)"
Write-Host "    2. Edit ENGAGEMENT.md  (authorization + goals)"
Write-Host "    3. Drop scope/policy/BloodHound into docs\"
Write-Host "    4. Tell Claude: ""start engagement on $safe""`n"
Get-ChildItem $dest | Select-Object Mode, Name | Format-Table -AutoSize
