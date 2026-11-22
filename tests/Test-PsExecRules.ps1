<#
.SYNOPSIS
  Generates real Windows 7045 (service installed) events and checks which Sigma
  rules Chainsaw matches against them.

.DESCRIPTION
  Creates three throwaway services, exports the System log, runs Chainsaw once
  per rule, compares the result with the expected matrix, then deletes the
  services. Needs an elevated PowerShell on a Windows host. Run it on a test
  machine or a VM: it creates (and removes) service entries. The binaries do
  not exist and the services never start (start type is demand).

  Expected matrix:
                                      PsExec Service Installation   Suspicious Service Binary
    PSEXESVC  (C:\Windows\...)        match                         match
    testsvc   (C:\Windows\...)        no match                      match
    cleansvc  (C:\Windows\System32)   no match                      no match

.PARAMETER Chainsaw
  Path to chainsaw.exe.
.PARAMETER Mapping
  Path to a Chainsaw mapping file. It must map StartType to
  Event.EventData.StartType (the stock sigma-event-logs-all.yml has
  ServiceStartType, not StartType).
.PARAMETER RulesDir
  Folder with the rule files (default: ..\rules\windows\system).
.PARAMETER ShowRaw
  Print Chainsaw's raw output for each rule (use this if a result surprises you).

.EXAMPLE
  .\Test-PsExecRules.ps1 -Chainsaw C:\tools\chainsaw\chainsaw.exe -Mapping C:\tools\chainsaw\mappings\sigma-event-logs-custom.yml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Chainsaw,
    [Parameter(Mandatory = $true)][string]$Mapping,
    [string]$RulesDir = (Join-Path $PSScriptRoot '..\rules\windows\system'),
    [switch]$ShowRaw
)

$ErrorActionPreference = 'Stop'

# --- preconditions -----------------------------------------------------------
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}
foreach ($p in @($Chainsaw, $Mapping, $RulesDir)) {
    if (-not (Test-Path $p)) { throw "Not found: $p" }
}

# --- test definitions --------------------------------------------------------
# Service name -> binary path (the file does not need to exist).
$services = [ordered]@{
    'PSEXESVC' = 'C:\Windows\PSEXESVC.exe'
    'testsvc'  = 'C:\Windows\testsvc.exe'
    'cleansvc' = 'C:\Windows\System32\cleansvc.exe'
}

# Rule file -> expected matches (service name -> $true/$false)
$rules = [ordered]@{
    'win_system_service_install_psexec.yml' = @{
        'PSEXESVC' = $true;  'testsvc' = $false; 'cleansvc' = $false
    }
    'win_system_service_install_suspicious_binary_windows_dir.yml' = @{
        'PSEXESVC' = $true;  'testsvc' = $true;  'cleansvc' = $false
    }
}

$outDir  = Join-Path $PSScriptRoot 'out'
$evtx    = Join-Path $outDir 'system-7045-recent.evtx'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (Test-Path $evtx) { Remove-Item $evtx -Force }

$failures = 0

try {
    # --- 1. create the services ---------------------------------------------
    foreach ($name in $services.Keys) {
        Write-Host "Creating service $name -> $($services[$name])"
        & sc.exe create $name binPath= $services[$name] | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create $name failed (exit $LASTEXITCODE)" }
    }
    Start-Sleep -Seconds 3

    # --- 2. export only recent 7045 events (last 10 minutes) -----------------
    $query = '*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= 600000]]]'
    & wevtutil.exe epl System $evtx "/q:$query" /ow:true
    if ($LASTEXITCODE -ne 0) { throw 'wevtutil export failed' }
    Write-Host "Exported recent 7045 events to $evtx"

    # --- 3. run Chainsaw once per rule and compare with the expected matrix --
    foreach ($ruleFile in $rules.Keys) {
        $rulePath = Join-Path $RulesDir $ruleFile
        if (-not (Test-Path $rulePath)) { throw "Rule not found: $rulePath" }
	
        $prevEap = $ErrorActionPreference
	$ErrorActionPreference = 'Continue'
	$raw = (& $Chainsaw hunt $evtx -s $rulePath --mapping $Mapping --json 2>&1 |
        ForEach-Object { $_.ToString() }) -join "`n"
	$ErrorActionPreference = $prevEap
        if ($ShowRaw) { Write-Host "---- raw Chainsaw output for $ruleFile ----"; Write-Host $raw }
	
        Write-Host ""
        Write-Host "Rule: $ruleFile"
        foreach ($name in $services.Keys) {
            $expected = $rules[$ruleFile][$name]
            # Chainsaw prints only documents that matched, so the service name
            # appearing in the output means "this rule matched that event".
            $actual = $raw -match [regex]::Escape($name)
            if ($actual -eq $expected) {
                Write-Host ("  PASS  {0,-9} expected match={1}, got match={2}" -f $name, $expected, $actual) -ForegroundColor Green
            } else {
                Write-Host ("  FAIL  {0,-9} expected match={1}, got match={2}" -f $name, $expected, $actual) -ForegroundColor Red
                $failures++
            }
        }
    }
}
finally {
    # --- 4. always clean up --------------------------------------------------
    foreach ($name in $services.Keys) {
        & sc.exe delete $name 2>&1 | Out-Null
    }
    Write-Host ""
    Write-Host 'Test services removed.'
}

if ($failures -gt 0) {
    Write-Host "$failures check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
