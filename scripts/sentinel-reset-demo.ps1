<#
.SYNOPSIS
  Rebuild the synthetic demo world through the guarded `fraud-ai demo reset`.
.DESCRIPTION
  Asks you to type RESET DEMO. The guard refuses any database that is not a demo database.
.EXAMPLE
  .\scripts\sentinel-reset-demo.ps1
.EXAMPLE
  .\scripts\sentinel-reset-demo.ps1 -Confirmation 'RESET DEMO'   # non-interactive
#>
[CmdletBinding()]
param([string]$Confirmation)
. (Join-Path $PSScriptRoot '_sentinel.ps1')
$arguments = @('reset')
if ($Confirmation) { $arguments += @('--confirm', $Confirmation) }
Invoke-Sentinel -Arguments $arguments
