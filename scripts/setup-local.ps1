<#
.SYNOPSIS
  Install or update everything SENTINEL needs (safe to run again; only changed parts are redone).
.EXAMPLE
  .\scripts\setup-local.ps1
.EXAMPLE
  .\scripts\setup-local.ps1 -Docker   # also require a running Docker Desktop (Dev mode)
#>
[CmdletBinding()]
param(
    [switch]$Docker,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Fail([string]$message) {
    Write-Host "  FAIL $message" -ForegroundColor Red
    exit 2
}

Write-Host ''
Write-Host 'SENTINEL setup (Windows)'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Fail 'Git is not installed: install Git for Windows from https://git-scm.com'
}

# Find Python >= 3.11 (the py launcher first; the Microsoft Store alias is skipped).
$python = $null
$candidates = @(@('py', '-3.11'), @('py', '-3.12'), @('py', '-3.13'), @('py', '-3'), @('python'), @('python3'))
foreach ($candidate in $candidates) {
    $exe = $candidate[0]
    $prefix = @($candidate | Select-Object -Skip 1)
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
    try {
        $version = & $exe @prefix -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>$null
    } catch { continue }
    if ($LASTEXITCODE -ne 0 -or -not $version) { continue }
    $parts = "$version".Trim().Split('.')
    if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11) {
        $python = $candidate
        Write-Host "  OK   Python $version ($($candidate -join ' '))"
        break
    }
}
if (-not $python) {
    Fail 'Python 3.11 or newer is required: install it from https://www.python.org (tick "Add python.exe to PATH")'
}

$venv = Join-Path $repo '.venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "  >>   creating the virtual environment in $venv"
    $exe = $python[0]
    $prefix = @($python | Select-Object -Skip 1)
    & $exe @prefix -m venv "$venv"
    if ($LASTEXITCODE -ne 0) { Fail 'could not create the virtual environment' }
} else {
    Write-Host "  OK   virtual environment $venv"
}

$arguments = @('setup')
if ($Docker) { $arguments += '--docker' }
if ($Force) { $arguments += '--force' }
Push-Location -LiteralPath $repo
try {
    & $venvPython (Join-Path $PSScriptRoot 'sentinel.py') @arguments
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
