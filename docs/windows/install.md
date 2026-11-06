# Windows: install, autostart and stop (no administrator needed)

Parley's daemon `parleyd` runs as a normal process of your user. It is not a Windows service and needs no
administrator rights. `install.ps1` puts it under your profile and starts it at every logon.

## Install

1. Get `parleyd.exe` and `parley-cli.exe` (release download, or `go build ./cmd/parleyd ./cmd/parley-cli`) into one folder.
2. In a normal (not elevated) PowerShell, from that folder:

   ```powershell
   powershell -ExecutionPolicy Bypass -File docs\windows\install.ps1 -Action Install
   ```

   This copies both programs to `%LOCALAPPDATA%\Parley\bin`, writes `start-parleyd.ps1` there, sets the value
   `Parley` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to run it at logon, and starts the daemon now.
   It writes nothing outside your profile and your own registry hive: no `HKLM`, no Program Files, no service, no
   scheduled task. Use `-InstallDir`, `-RunName` and `-NoStart` to change the folder, the Run key name, or to skip the
   start; `-DaemonHome <dir>` sets `PARLEY_HOME` for the daemon (several daemons on one machine).
3. Enroll this device (`parley-cli login`, see the main README). Until a `config.json` exists the daemon exits with
   "invalid configuration" at start: that is expected before enrollment. Check with `parley-cli list`.

## Stop, restart, uninstall

- **Graceful stop:** a daemon started in a console stops on Ctrl+Break (Ctrl+C when it runs in the foreground). It
  finishes its work in order, removes its socket, wipes its key and releases the instance lock. Closing the console,
  logging off and shutting down reach it as a terminate request, which it handles the same way. A daemon started by
  the Run key has a hidden console, so `install.ps1 -Action Uninstall` ends it by terminating it. That is safe: the
  lock is released by Windows when the process ends, state files are replaced atomically, and the next start replaces
  a stale socket (all tested on Windows: `TestWindowsDaemonLifecycle`, `TestWindowsInstallAutostartUninstall`).
- **One daemon per configuration:** a second `parleyd` for the same folder exits at once with "already running".
- **Uninstall:**

  ```powershell
  powershell -ExecutionPolicy Bypass -File docs\windows\install.ps1 -Action Uninstall
  ```

  It stops the daemon, removes the Run value and the files it installed. Your configuration, device key and state
  (`%APPDATA%\parley`, or `PARLEY_HOME`) stay; delete that folder to forget the device, and revoke the device in the
  dashboard.

## What is and is not verified

Verified on a real Windows runner in CI (workflow "Windows daemon (T505)" and the Windows job of CI): the install,
the Run command starting a daemon that answers on its socket, a restart after the daemon was terminated, the
uninstall leaving nothing behind, the CTRL_BREAK stop with the socket and lock released, the key-memory scan, and the
M1 echo between two daemons through the real gateway. GitHub's runner account is an administrator, so "no
administrator needed" is shown by what the script touches (only `HKCU` and the profile, asserted by the test), not by
running it as a limited user. The Task Scheduler is not used. Logging off and rebooting with the Run key are not
exercised in CI.
