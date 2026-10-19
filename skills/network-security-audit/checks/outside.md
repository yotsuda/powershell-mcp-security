# Outside checks (from this machine)

Run these on the machine **you** run on, against the target's address only. They show what an attacker standing where this machine stands sees — and only that.

**Know your vantage point.** If this machine is the target's NAT gateway — a Hyper-V Default Switch or WSL VM audited from its own host — you are seeing it from the inside of the NAT. Whether anything is reachable from the LAN depends on port forwarding you cannot fully rule out from here (`Get-NetNatStaticMapping` does not cover the Default Switch, which uses ICS). Say so under "Not checked".

**UDP is not covered** by these probes. Always say so in the report. If the target has non-loopback UDP listeners other than a DHCP client, suggest `nmap -sU -p <those ports> <target>` (with the user's agreement).

## Reachable TCP ports

Probe ports 1–1024, every port found listening inside, and common higher ones. Connections run in parallel, so this takes 15–30 seconds even when a firewall drops packets (tell the user before you start).

With the helpers loaded (`scripts/common.ps1` on this machine):

```powershell
Test-TcpPort <target> -Port ((1..1024) + 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 27017 + <ports found inside>) -Responding
```

`Open` is reachable; `Closed` means the host answered with a reset (no firewall dropped it); `Filtered` means no answer — usually a firewall. **A Windows target with its firewall on never answers closed ports (stealth mode)**, even ports a rule allows: there `Filtered` does not mean "blocked". To claim the firewall blocks something, show a port that is listening inside and still not reachable. It also takes scoped IPv6 addresses (`fe80::…%<ifIndex>`) as they are. From a Windows machine a refused connection takes about 2 seconds to surface, which is why the default timeout there is 2.5 s. Without the helpers:

```powershell
$target = '<target address>'
$inside = @()   # ports found listening inside, e.g. 42777
$ports  = @(1..1024) + 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 27017 + $inside | Sort-Object -Unique
$ports | ForEach-Object -ThrottleLimit 128 -Parallel {
    $c = [System.Net.Sockets.TcpClient]::new()
    try { if ($c.ConnectAsync($using:target, $_).Wait(1500) -and $c.Connected) { $_ } } catch {} finally { $c.Dispose() }
} | Sort-Object
```

If `nmap` is installed and the user agrees, `nmap -Pn -sT -p- <target>` covers all ports. Say in the report which ports were covered.

**IPv6** — firewall rules for IPv6 are often forgotten. If the target has a global IPv6 address, run the same probe against it. If it has only a link-local address (`fe80::…`) and this machine is on the same link (the Hyper-V host, the same LAN segment), probe that with the zone index of this machine's interface: `fe80::…%<ifIndex>` (`Get-NetIPAddress -AddressFamily IPv6` shows the index). **Positive control first:** a failed TCP connect cannot tell "dropped by a firewall" from "no route". Make `Test-Connection 'fe80::…%<ifIndex>' -Count 1` succeed (ufw lets ICMPv6 echo through) before you read a closed port as blocked — in its own call: put in one call with `Test-TcpPort`, the second table may not be shown. If neither works, say so under "Not checked". A scoped address needs an IPv6 socket and a parsed address:

```powershell
$addr = [System.Net.IPAddress]::Parse('fe80::…%<ifIndex>')
$ports | ForEach-Object -ThrottleLimit 128 -Parallel {
    $c = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    try { if ($c.ConnectAsync($using:addr, $_).Wait(1500) -and $c.Connected) { $_ } } catch {} finally { $c.Dispose() }
} | Sort-Object
```

**Other guests on the same switch** can reach the target too. `Get-VM` needs Hyper-V Administrators — run it without `-ErrorAction SilentlyContinue`, so a permission error can be told apart from "no VMs". Without it, `Get-NetNeighbor -InterfaceIndex <vEthernet index>` gives a hint: look at the **IPv6** entries whose MAC starts with `00-15-5D` (Hyper-V). The IPv4 table goes through ICS and may not list even the target itself. `Stale` entries may be guests that no longer exist (each Windows Sandbox start gets a new MAC); only `Get-VM` settles it.

## What the open ports say about the target

- **SSH banner** — reveals the OpenSSH and distribution version:
  ```powershell
  $c = [System.Net.Sockets.TcpClient]::new($target, 22); $r = [IO.StreamReader]::new($c.GetStream()); $r.ReadLine(); $c.Dispose()
  ```
- **TLS certificates** on HTTPS or other TLS ports — subject and issuer can identify the product or the organization.

## Does password login really fail?

Without typing any password — `BatchMode` makes ssh give up instead of prompting. The host-key options keep a first contact from stopping at `Host key verification failed` (which says nothing about passwords, yet reads like a pass), and leave this machine's known_hosts untouched:

```powershell
$nul = if ($IsWindows) { 'NUL' } else { '/dev/null' }
ssh -n -o BatchMode=yes -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive `
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=$nul -o ConnectTimeout=5 <user>@<target> exit
```

The "Permanently added … to the list of known hosts" warning refers to the null device; known_hosts is not changed.

Expected after hardening: `Permission denied (publickey)`. If the list after "Permission denied" includes `password` or `keyboard-interactive`, password login is still offered. Any other error (timeout, host key) means the check did not run — report it under "Not checked".

## Does key login still work?

After any change to SSH or the firewall, prove the lifeline with a real login. Two traps:

- **Use the key that is actually used.** Without `-i`, ssh offers this machine's default keys, which may not be the one the target accepts — `Permission denied (publickey)` then looks like a lockout you caused. The target's log names the key that logs in (`Accepted publickey … SHA256:…`, from the Authentication history check); find it here with `Get-ChildItem ~/.ssh/*.pub | ForEach-Object { ssh-keygen -lf $_ }`.
- **`-n`**: a successful ssh keeps reading this console's input and never returns. `-n` gives it no input.

```powershell
ssh -n -o BatchMode=yes -o IdentitiesOnly=yes -i <that key> -o ConnectTimeout=5 <user>@<target> 'echo key-login-ok'
```

`key-login-ok` is the proof. Put the outcome in the before/after table.

## From the target back to this machine

Only when the target's role is a sandbox, a malware-analysis VM or any place that runs untrusted code: there the real attack surface is what the **guest** can reach. Run on the **target**, against **this machine's own addresses only** — its address on the target's network (the NAT gateway) and its LAN address — and a handful of ports. This stays within the rule of probing nothing but machines the user owns; never sweep ranges or other hosts from the target.

```powershell
foreach ($h in '<this machine on the target network>', '<this machine on the LAN>') {
    foreach ($p in 135, 139, 445, 3389, 5985, 5986) {
        $c = [System.Net.Sockets.TcpClient]::new()
        try { $ok = $c.ConnectAsync($h, $p).Wait(1500) -and $c.Connected } catch { $ok = $false } finally { $c.Dispose() }
        "$h $p $ok"
    }
}
```

The two addresses can give different answers (e.g. 139 reachable on the LAN address but not on the virtual switch address): traffic to the LAN address is judged by the LAN interface's profile (often **Private**), and a `LocalSubnet` rule there also counts this machine's virtual switch subnet as local. Report each address as its own row, check Private `LocalSubnet` rules as well as Public ones, and re-test both addresses after a host-side fix.

Check this machine's LAN profile too: `Get-NetConnectionProfile`. If the LAN interface (Wi-Fi, Ethernet) is **Public**, a rule enabled for Public with remote `Any` — e.g. `File and Printer Sharing (Restrictive) (SMB-In)` — opens this machine to everyone on that network, not only to guests: on a café or hotel Wi-Fi, to strangers. Report it as its own host-side finding (High on a network the user does not control), and say it was inferred from the rules and not tested from another machine on that network.

For each port that is reachable, collect the evidence for a fix on the host side — on **this machine**, where the helper files work just as well (`. <skill dir>/scripts/common.ps1` and `windows.ps1`):

- what listens: `Get-ListeningPort` (or `Get-NetTCPConnection -LocalPort <port> -State Listen`);
- which rule lets it in: `Find-PermissiveFirewallRule -All -Port 135, 139, 445, 5985, RPCEPMap` (every profile, `Any` and `LocalSubnet` alike).

`vEthernet (Default Switch)` has no network profile (it is missing from `Get-NetConnectionProfile`), so this machine's firewall treats traffic from guests as **Public**: its Public rules are the ones that apply. Rules often found: `File and Printer Sharing (Restrictive) (SMB-In)` (a rule group added in Windows 11 24H2; seen enabled for Private and Public, remote Any, on a host with a shared folder, probably turned on when the folder was shared), `Hyper-V (RPC-EPMAP)`, `Windows Remote Management (HTTP-In)` (Public, LocalSubnet — which includes the guest's subnet).

Reachable host services are a finding against the sandbox setup, and worth a note for the host itself. Fixes to offer: `<Networking>Disable</Networking>` in the `.wsb` when testing untrusted files (note it also rules out this kind of remote audit), or, when the guest needs the network, a host firewall rule blocking inbound from the virtual switch's subnet (`vEthernet (Default Switch)`) to those ports.

## Cross-check

For each port:

| Listening inside | Reachable outside | Meaning |
|---|---|---|
| yes | yes | Exposed — must be intended and restricted to the right sources |
| yes | no | Blocked by a firewall — name the rule |
| no | yes | Something else answers (NAT, port forward, another host) — investigate |

Compare per address family. A port bound to `0.0.0.0` or an IPv4 address only is not listening on IPv6, and one bound to `::` only (without dual-stack) not on IPv4. On a Windows target in stealth mode, such a port shows `Filtered` on the other family — that is "not listening there", not a firewall block. Probe IPv6 with the ports bound to `::` or the link-local address, and read the rest accordingly.
