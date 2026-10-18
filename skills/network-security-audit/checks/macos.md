# macOS checks (read-only)

**Not yet tested on a real Mac**, and shorter than the Linux and Windows checks. Say so in the report, and treat anything surprising here as a question for the user rather than a finding. Contributions from Mac users are welcome.

## Listening ports

```
sudo lsof -nP -iTCP -sTCP:LISTEN
sudo lsof -nP -iUDP
```

## Application firewall

```
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps
sudo pfctl -s info | Select-Object -First 1       # Status: Enabled / Disabled
sudo pfctl -s rules
```

The application firewall filters by program; pf (the packet filter) by address and port, and is off unless something enabled it.

## Sharing and remote access

```
sudo systemsetup -getremotelogin
sudo launchctl print-disabled system | grep -Ei 'ssh|screensharing|smbd'
```

When Remote Login is on, read sshd's effective settings as in [linux.md](linux.md#ssh--the-effective-configuration).

## Platform protection

```
fdesetup status     # FileVault
spctl --status      # Gatekeeper
csrutil status      # System Integrity Protection
softwareupdate -l
```

## Accounts

```
dscl . -read /Groups/admin GroupMembership
```
