<#
.SYNOPSIS
  Show the API, console, PostgreSQL, Redis, active policy, models, demo mode and LLM.
#>
[CmdletBinding()]
param([switch]$Json)
. (Join-Path $PSScriptRoot '_sentinel.ps1')
$arguments = @('status')
if ($Json) { $arguments += '--json' }
Invoke-Sentinel -Arguments $arguments
