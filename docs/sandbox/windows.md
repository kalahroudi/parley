# Windows: keep a bot away from the daemon's local socket

**Not verified on a second user account.** Parley does not claim this enforces anything on Windows: its tests check
only that `windows.ps1` parses and that its dry run prints the expected commands. What Parley enforces on Windows is
described in the README (the daemon refuses `approve` and `deny` from a bot it started; the socket's directory has a
protected access list, checked at every start).

The idea: run the bot as a different Windows user. The socket directory's access list grants only the daemon's user,
SYSTEM and Administrators, so another standard user should not be able to open it.

```powershell
# see what it would do, then run it from an administrator prompt
.\windows.ps1 -Bot C:\path\to\bot.exe -DryRun
.\windows.ps1 -Bot C:\path\to\bot.exe
```

Tool-using skills are unsupported on Windows until a sandbox exists (T507).
