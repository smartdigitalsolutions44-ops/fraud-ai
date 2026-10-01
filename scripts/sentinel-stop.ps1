<#
.SYNOPSIS
  Stop what the SENTINEL scripts started (tracked processes and containers only; nothing else).
#>
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot '_sentinel.ps1')
Invoke-Sentinel -Arguments @('stop')
