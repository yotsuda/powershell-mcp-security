# Report format

Write the report in the user's language. Keep it short; put raw command output only where it is the evidence, and keep the Evidence column to the command and the one line that shows it (e.g. ``sysctl: `net.ipv6.conf.eth0.accept_redirects = 1` ``) — the reasoning goes in Finding or Suggested fix.

```
## Target
<hostname> — <OS and version> — <role, or "<role> (inferred, not confirmed)"> — audited <date> from <this machine's address>
<changed nothing / what was changed — on Linux, `journalctl _COMM=sudo --since <audit start>` lists the commands this audit ran with sudo (not `sudo -v` / `sudo -l`, and it includes that journalctl itself)>

## Seen from outside
<open ports and what answers on them, one line each>

## Findings (most severe first)
| # | Severity | Finding | Evidence | Suggested fix |
|---|---|---|---|---|
| 1 | High | ... | <the command and the line that shows it> | ... |

## Fine
<checks that passed, one line each — so the user knows they were checked>

## Not checked
<what you could not check and why — always state the vantage point of the outside checks
 (e.g. "from the Hyper-V host only, not from the LAN"), the ports covered, and whether UDP was checked>

## Cleanup
<how to end remote control, `sudo -k`, and how to confirm 42777 is closed afterwards>

---
<one line, in the user's language: checks the network-security-audit skill should add, or anything it got wrong, are welcome as an issue at https://github.com/yotsuda/powershell-mcp-security/issues (feedback on the skill, not this report) — and Claude can draft one>
```

The audit's own channel shows up as an open port. It is not a finding; list it as such and close it under "Cleanup":

- **The target listens** (`Enable-MCPRemoteControl`): TCP 42777 on the target. After `Disable-MCPRemoteControl`, `ss -tln` (macOS: `lsof -nP -iTCP:42777`; Windows: `Get-NetTCPConnection -LocalPort 42777 -State Listen`) should no longer show it. A standing firewall rule that allows 42777 does no harm while nothing listens, but it stays open for whatever listens there next: list it as Info and offer removing it under "Cleanup" (or keeping it if the user audits often). Higher only if it allows far more than the audit machine for no reason.
- **The target dialed in** (`accept_remote_console` / `-ConnectTo`): nothing listens on the target; **this machine** listens on the port `accept_remote_console` reported, on all interfaces, until `disconnect_remote_console`. Afterwards check `Get-NetTCPConnection -LocalPort <port> -State Listen` returns nothing. If the user allowed `PowerShell.MCP.Proxy.exe` in a Windows firewall dialog, that rule stays (and covers every port): say so, and how to remove it if it is no longer wanted.

Severity — the examples are starting points; move a finding up or down by who can actually reach it (e.g. ICMP redirects can only come from the same link, so on a NAT-ed VM with no global IPv6 they may be Low) and say why. "The same link" on a Hyper-V Default Switch includes the host and every other guest (WSL, Windows Sandbox, other VMs): Low still fits when those are the user's own machines; move it up when the switch also carries machines that run untrusted code (a sandbox for malware or unknown downloads):

- **High** — reachable from outside and directly exploitable or credential-exposing (no firewall with services exposed, password SSH open to the network, SMB1, RDP without NLA).
- **Medium** — weakens defense in depth (passwordless sudo, forwarding enabled, ICMP redirects, missing updates).
- **Low** — hygiene and information leaks (version banners, idle services bound to loopback only). On Debian/Ubuntu, `DebianBanner no` in sshd removes the distribution part of the SSH banner; the OpenSSH version itself cannot be hidden.
- **Info** — nothing to fix, but the user should confirm or know it: a key whose owner is unclear, a wide rule judged to be a deliberate compromise, CRLF in a key file.

After fixing, add:

```
## Before / after
| Item | Before | After | Verified by |
|---|---|---|---|
```
