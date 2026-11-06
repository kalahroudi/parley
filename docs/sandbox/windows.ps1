# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Parley: run a bot as a different Windows user, so it cannot open the daemon's socket directory (its access list
# grants only the daemon's user, SYSTEM and Administrators).
#
#   windows.ps1 -Bot C:\path\to\bot.exe [-User parley-bot] [-DryRun]
#
# -DryRun prints the commands and runs nothing. NOT VERIFIED on a second user account: Parley's tests check this
# script's syntax and its dry run only. Run it from an administrator prompt the first time (it creates the user).
param(
  [Parameter(Mandatory = $true)][string]$Bot,
  [string]$User = 'parley-bot',
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if ($User -notmatch '^[A-Za-z0-9_-]{1,20}$') { throw 'the user name may only hold letters, digits, - and _' }
if ($Bot -match '["\r\n]') { throw 'the bot path may not hold quotes or line breaks' }
$commands = @("net user $User * /add", "runas /user:$User `"$Bot`"")
foreach ($c in $commands) {
  if ($DryRun) { Write-Output "would run: $c" } else { cmd /c $c; if ($LASTEXITCODE -ne 0) { throw "failed: $c" } }
}
