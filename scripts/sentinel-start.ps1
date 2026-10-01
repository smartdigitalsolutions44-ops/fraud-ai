<#
.SYNOPSIS
  Start SENTINEL: the fraud API and the analyst console, in one command.
.EXAMPLE
  .\scripts\sentinel-start.ps1 -Mode Demo          # synthetic demo world, no Docker needed
.EXAMPLE
  .\scripts\sentinel-start.ps1 -Mode Dev           # PostgreSQL + Redis in Docker, console dev server
.EXAMPLE
  .\scripts\sentinel-start.ps1 -Mode StagingLike   # the existing deploy/staging stack (Docker, bash)
#>
[CmdletBinding()]
param(
    [ValidateSet('Demo', 'Dev', 'StagingLike')][string]$Mode = 'Demo',
    [switch]$Reset,
    [switch]$Foreground,
    [switch]$NoBrowser,
    [ValidateSet('start', 'dev')][string]$Console
)
. (Join-Path $PSScriptRoot '_sentinel.ps1')
$arguments = @('start', '--mode', $Mode.ToLowerInvariant())
if ($Reset) { $arguments += '--reset' }
if ($Foreground) { $arguments += '--foreground' }
if ($NoBrowser) { $arguments += '--no-browser' }
if ($Console) { $arguments += @('--console', $Console) }
Invoke-Sentinel -Arguments $arguments
