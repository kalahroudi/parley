# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0
#
# Parley on Windows: per-user install, autostart at logon, uninstall. No administrator needed: it writes only under
# your profile (%LOCALAPPDATA%\Parley) and your own HKCU Run key, never HKLM, Program Files or a service.
#
#   install.ps1 -Action Install   [-BinDir .] [-InstallDir <dir>] [-DaemonHome <dir>] [-RunName Parley] [-NoStart]
#   install.ps1 -Action Uninstall [-InstallDir <dir>] [-RunName Parley]
#
# Install copies parleyd.exe and parley-cli.exe from -BinDir, writes the launcher start-parleyd.ps1, sets the Run key
# to start it at every logon, and starts the daemon now (unless -NoStart). -DaemonHome sets PARLEY_HOME for the daemon.
# Uninstall stops the daemon, removes the Run key and the files it installed. Your configuration, device key and
# state (PARLEY_HOME, or %APPDATA%\parley) are NOT touched: delete that folder yourself to forget the device.
param(
  [Parameter(Mandatory = $true)][ValidateSet('Install', 'Uninstall')][string]$Action,
  [string]$BinDir = (Get-Location).Path,
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Parley\bin'),
  [string]$DaemonHome = '',
  [string]$RunName = 'Parley',
  [switch]$NoStart
)
$ErrorActionPreference = 'Stop'

# Paths go into a registry command line and a script: refuse anything that could end the quoting.
foreach ($p in @($BinDir, $InstallDir, $DaemonHome)) {
  if ($p -match '["''`$\r\n;&|<>%]') { throw "a path may not hold quotes, `$, %, `` ; & | < > or line breaks: $p" }
}
if ($RunName -notmatch '^[A-Za-z0-9_-]{1,40}$') { throw 'the run name may only hold letters, digits, - and _' }

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$exe = Join-Path $InstallDir 'parleyd.exe'
$cli = Join-Path $InstallDir 'parley-cli.exe'
$launcher = Join-Path $InstallDir 'start-parleyd.ps1'

function Stop-Daemon {
  # Only the daemon installed here, found by its full path. It is stopped by terminating it: its state is safe to
  # stop at any moment (see the guide); a graceful stop is CTRL_BREAK from the console it runs in.
  $found = @(Get-Process -Name parleyd -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
  foreach ($p in $found) { Stop-Process -Id $p.Id -Force; $p.WaitForExit(15000) | Out-Null }
}

if ($Action -eq 'Install') {
  foreach ($f in @('parleyd.exe', 'parley-cli.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $BinDir $f))) { throw "$f not found in $BinDir" }
  }
  Stop-Daemon
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -LiteralPath (Join-Path $BinDir 'parleyd.exe') -Destination $exe -Force
  Copy-Item -LiteralPath (Join-Path $BinDir 'parley-cli.exe') -Destination $cli -Force
  $setHome = ''
  if ($DaemonHome -ne '') { $setHome = "`$env:PARLEY_HOME = '$DaemonHome'`r`n" }
  $body = "# Written by Parley's install.ps1. Starts the daemon with no window; it needs no console input.`r`n" +
    $setHome + "Start-Process -FilePath '$exe' -WindowStyle Hidden`r`n"
  Set-Content -LiteralPath $launcher -Value $body -Encoding ASCII
  $command = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$launcher`""
  New-ItemProperty -Path $runKey -Name $RunName -Value $command -PropertyType String -Force | Out-Null
  if (-not $NoStart) { & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File $launcher }
  Write-Output "installed to $InstallDir; starts at logon (HKCU Run key '$RunName')"
}
else {
  Stop-Daemon
  Remove-ItemProperty -Path $runKey -Name $RunName -ErrorAction SilentlyContinue
  foreach ($f in @($exe, $cli, $launcher)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
  if ((Test-Path -LiteralPath $InstallDir) -and -not (Get-ChildItem -LiteralPath $InstallDir -Force)) { Remove-Item -LiteralPath $InstallDir -Force }
  Write-Output "uninstalled from $InstallDir; your configuration and device key were left in place"
}
