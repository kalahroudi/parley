# Windows: keep a bot away from the daemon's local socket

Run the bot as a different Windows user. The daemon's socket directory has a protected access list that grants only the
daemon's user, SYSTEM and Administrators (Parley checks this at every start), so another standard user cannot open the
directory and cannot reach the socket.

```bat
:: once, from an administrator prompt
net user parley-bot * /add
:: for each bot: give the bot's user its own working folder, then start the bot as that user
runas /user:parley-bot "C:\path\to\bot.exe"
```

Parley has not run this profile against a second Windows user; what is tested on Windows is the access list on the
directory, and that a bot Parley itself starts is refused approve and deny by the daemon. Windows has no sandbox profile
for tool-using skills yet: they are unsupported there.
