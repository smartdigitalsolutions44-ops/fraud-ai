# Shared by the SENTINEL PowerShell wrappers (Stage 14). Dot-sourced, never run directly.
# The logic lives in scripts/localrun (Python); these wrappers only find the interpreter.
$ErrorActionPreference = 'Stop'
$script:Repo = Split-Path -Parent $PSScriptRoot
$script:VenvPython = Join-Path $script:Repo '.venv\Scripts\python.exe'
$script:Entry = Join-Path $PSScriptRoot 'sentinel.py'

function Invoke-Sentinel {
    param([Parameter(Mandatory)][string[]]$Arguments)
    if (-not (Test-Path -LiteralPath $script:VenvPython)) {
        Write-Host '  FAIL SENTINEL is not set up yet: run .\scripts\setup-local.ps1 first' -ForegroundColor Red
        exit 2
    }
    Push-Location -LiteralPath $script:Repo
    try {
        & $script:VenvPython $script:Entry @Arguments
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    exit $code
}
