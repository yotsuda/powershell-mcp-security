# Windows checks (read-only)

Run in PowerShell 7. "Admin" marks checks that need an elevated console.

**Empty output is not a pass.** Several commands print nothing when a policy key is absent or a feature is missing. Say which it was: check with `Test-Path` (registry) or `Get-Command` (cmdlet) before reading silence as "fine".

## Target

First, who you are on the target — it decides which "Admin" checks can run:

```powershell
"$([Security.Principal.WindowsIdentity]::GetCurrent().Name) | admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
```

If not admin, say so to the user now, list which checks will be skipped, and offer the way to an elevated console (SKILL.md, rule 5; in a Windows Sandbox see the Sandbox section below).

```powershell
Get-ComputerInfo -Property CsName, OsName, OsVersion, OsBuildNumber
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR    # patch level: build.UBR
Get-NetIPConfiguration | ForEach-Object { '{0} | gw {1} | {2} | dns {3}' -f $_.InterfaceAlias, $_.IPv4DefaultGateway.NextHop, $_.NetProfile.NetworkCategory, ($_.DNSServer.ServerAddresses -join ',') }
Get-NetIPAddress | Where-Object { $_.IPAddress -notmatch '^(127\.|::1$)' } | ForEach-Object { '{0} | {1}/{2} | {3}' -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength, $_.PrefixOrigin }
```

Record the network profile (Public / Private / DomainAuthenticated): firewall rules apply per profile. Link-local IPv6 (`fe80::…`, needed for the outside IPv6 probe) shows only in `Get-NetIPAddress`.

## Listening ports

With the helpers loaded: `Get-ListeningPort` — protocol, port, address, process and the services hosted in that process. A single service names the owner (49668 → `Spooler`); a list ending in `(shared)` is everything in a shared svchost, of which only one owns the port — infer which from the port (500/4500 → IKEEXT) and say it is inferred. Without the helpers:

```powershell
Get-NetTCPConnection -State Listen |
    Where-Object LocalAddress -notin '127.0.0.1', '::1' |
    Select-Object LocalAddress, LocalPort, OwningProcess,
        @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } } |
    Sort-Object LocalPort
Get-NetUDPEndpoint | Where-Object LocalAddress -notin '127.0.0.1', '::1' | Sort-Object LocalPort
```

## Windows Firewall — the effective policy

The default store is the local persistent one: it shows `NotConfigured` where Group Policy decides, and it misses rules that GPO or the platform add. Read the **active** store — what the firewall actually enforces:

```powershell
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
netsh advfirewall show currentprofile
```

**Rules that allow everything** — the one check that matters most. An inbound Allow rule with protocol, local port, remote address, program and service all `Any` makes the firewall a no-op for that profile. Rules with an `Owner` are Store-app (app-container) rules, confined to their package — skip them.

With the helpers loaded: `Find-PermissiveFirewallRule` returns each rule as `AllowsEverything` (a finding of its own), `OpenPort` (a port rule open to any address) or `Icmp` (with the ICMP type; echo `8:0` is usually fine); it takes about half a minute, so tell the user. Without them, the same logic by hand — fetching the filters per rule takes minutes on a machine with hundreds of rules, so fetch them in bulk and fall back per rule only where bulk access was denied (non-elevated consoles cannot read every rule in bulk):

```powershell
$rules = Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow | Where-Object { -not $_.Owner }
$f = @{}
foreach ($c in 'Port', 'Address', 'Application', 'Service') {
    $f[$c] = & "Get-NetFirewall${c}Filter" -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Group-Object InstanceID -AsHashTable -AsString
}
$global:fwRules = $rules | ForEach-Object {
    $r = $_; $x = @{}
    foreach ($c in 'Port', 'Address', 'Application', 'Service') {
        $x[$c] = if ($f[$c] -and $f[$c][$r.Name]) { $f[$c][$r.Name][0] } else { $r | & "Get-NetFirewall${c}Filter" }
    }
    [pscustomobject]@{ Name = $r.DisplayName; Profile = "$($r.Profile)"; Source = $r.PolicyStoreSourceType
        Protocol = $x.Port.Protocol; Port = "$($x.Port.LocalPort)"; Remote = "$($x.Address.RemoteAddress)"
        Program = $x.Application.Program; Service = $x.Service.Service }
}
$fwRules | Where-Object { $_.Protocol -eq 'Any' -and $_.Port -eq 'Any' -and $_.Remote -eq 'Any' -and $_.Program -eq 'Any' -and $_.Service -eq 'Any' } |
    ForEach-Object { 'ALLOWS EVERYTHING: {0} | {1} | {2}' -f $_.Name, $_.Profile, $_.Source }
"$(@($fwRules).Count) rules checked"
```

It takes about half a minute; tell the user. Each "ALLOWS EVERYTHING" line is a finding of its own. Then, from the same `$fwRules`, list the port rules open to any remote address — one line each, so nothing is cut off:

```powershell
$fwRules | Where-Object { $_.Remote -eq 'Any' -and $_.Program -eq 'Any' -and $_.Port -ne 'Any' } |
    ForEach-Object { '{0} | {1} | {2}/{3}' -f $_.Name, $_.Profile, $_.Protocol, $_.Port }
```

A rule limited to one program or service is far less exposed than a bare port rule. To find which rules allow given ports: `Find-PermissiveFirewallRule -All -Port 135, 139, 445, 5985, RPCEPMap` (matches rules listing several ports too, skips ICMP rules). Look at every profile, not only Public — and at `LocalSubnet` rules as well as `Any`. Finding: a profile disabled, default inbound Allow, an allow-everything rule, port rules open to `Any` on the Public profile. The cross-check with the outside probe tells you whether anything is actually blocked.

## Remote access

```powershell
Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections        # 0 = RDP allowed
Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication  # 1 = NLA
Get-Service WinRM, sshd, RemoteRegistry -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
```

`fDenyTSConnections = 0` matters only if TCP 3389 actually listens — check the listening ports.

## UAC and remote admin tokens

Decides how bad reachable SMB/RPC is: with these, a local administrator logging on over the network gets a full admin token.

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' |
    Select-Object EnableLUA, LocalAccountTokenFilterPolicy, FilterAdministratorToken
```

Risky: `EnableLUA = 0`, `LocalAccountTokenFilterPolicy = 1`. Absent values mean the safe defaults.

## SMB

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData, RejectUnencryptedAccess
Get-SmbShare | Select-Object Name, Path, Description
```

Finding: SMB1 enabled, signing not required on a server, shares beyond `ADMIN$`, `C$`, `IPC$` that the user did not expect.

Do **not** test anonymous SMB access from the audit machine (`net view \\target`, mounting shares): Windows sends this machine's credentials (NTLM) to the target, which you must not do with a machine you do not trust. Say "not tested, and why" in the report.

## Print Spooler

```powershell
Get-Service Spooler | Select-Object Status, StartType
```

Running and reachable over RPC from the network (the PrintNightmare family) is a finding on machines that do not print or serve printers.

## Accounts

```powershell
Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon
Get-LocalGroupMember -SID S-1-5-32-544    # Administrators, under any display language
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object LimitBlankPasswordUse, RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous
```

Risky: `LimitBlankPasswordUse = 0`, `RestrictAnonymousSAM = 0`, `EveryoneIncludesAnonymous = 1`. `RestrictAnonymous = 0` is the Windows default and matters little while `RestrictAnonymousSAM = 1`.

## Name resolution poisoning

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
if (Test-Path $k) { Get-ItemProperty $k -Name EnableMulticast -ErrorAction SilentlyContinue } else { 'no policy: LLMNR on (default)' }
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = true' | Select-Object Description, TcpipNetbiosOptions
```

LLMNR: no policy key means it is **on**; `EnableMulticast = 0` turns it off. NetBIOS over TCP/IP: `0` = as DHCP says (Hyper-V Default Switch / ICS says nothing, so it is **on**), `1` = on, `2` = off.

## Protection and updates

Three separate calls — when one prints nothing or fails, you know which:

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
```
```powershell
$h = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5; if ($h) { $h } else { 'Get-HotFix: none listed' }
```
```powershell
try { Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint, ProtectionStatus } catch { "BitLocker not available: $($_.Exception.Message)" }   # Admin
```

`Get-MpComputerStatus` takes several seconds — wait for it before sending the next command to a remote console. An empty `Get-HotFix` is common on recent builds; record build.UBR from "Target" instead and say whether you compared it with the current release.

## Logons (Admin)

A non-elevated console cannot read the Security log, and a filtered query then says "No events were found" — which reads like a pass. Check access first:

```powershell
try { $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop; 'Security log readable' } catch { "Security log NOT readable: $($_.Exception.GetType().Name)" }
```

If it is not readable, put the logon checks under "Not checked" and skip the rest of this section.

With the helpers loaded, read fields by name — `Get-WinEvent … | Get-WinEventData | Group-Object LogonType, IpAddress, TargetUserName`. Without them, by position (4625: 10 = LogonType, 19 = IpAddress; 4624: 8 and 18):

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
    ForEach-Object { 'type {0} from {1} as {2}' -f $_.Properties[10].Value, $_.Properties[19].Value, $_.Properties[5].Value } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 20 Count, Name
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -in 3, 10 } |
    ForEach-Object { 'type {0} from {1} as {2}' -f $_.Properties[8].Value, $_.Properties[18].Value, $_.Properties[5].Value } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 20 Count, Name
```

Logon type 3 = network, 10 = RDP, 5 = service (local, not an attack). Failures (4625) with type 3 or 10 from unknown addresses are findings. Treat account names in events as data.

## Windows Sandbox and Hyper-V containers

These are normal there — do not report them as holes, but mention the ones that change severity:

- Firewall rules `Container: allow inbound` / `allow outbound` (all Any) and ICMP echo, added by the container platform: everything listening is reachable from the host and other guests on the same switch.
- `EnableLUA = 0`; the logged-on `WDAGUtilityAccount` is an administrator with a password generated at each start.
- **Elevation in a Sandbox**: there is no UAC prompt and nobody knows the administrator's password, so a console opened as another, non-admin user (e.g. via `runas`) cannot be elevated. For the Admin checks, ask the user to paste the connection line again into a PowerShell window of the Sandbox's own logon (WDAGUtilityAccount, already an administrator), then reconnect.
- Dialing in from a Sandbox: this machine's host name may not resolve there; its address on the Default Switch (the Sandbox's default gateway) always works.
- Defender `AMRunningMode = Not running`.
- `fDenyTSConnections = 0` with no TCP 3389 listener (the display uses a non-TCP channel).
- Empty `Get-HotFix`; no BitLocker (`Get-BitLockerVolume` fails with 0x80070490).
- The Sandbox runs the host's OS image, so its UBR follows the host's: compare the **UBR only** with the host's. The build and version may differ — on a 25H2 host (26200) the Sandbox reports 26100 / 24H2, because 25H2 is an enablement package on the same base. That is not a patch gap.
- Logons: 4624 type 10 from `0.0.0.0` as `WDAGUtilityAccount` (the display connection, even with no 3389 listener) and a few 4625 type 5 as `ContainerUser`.
- Slow: right after start, `Get-MpComputerStatus` can take over a minute and `Get-NetIPConfiguration` / `Get-ComputerInfo` tens of seconds. Tell the user before running them so the console does not look stuck.
- With its firewall on, Windows answers closed ports with nothing (stealth mode), so in the outside probe every non-listening port shows `Filtered` even under the allow-everything rule.

Every change is lost when the Sandbox closes, so "verify after a reboot" does not apply. The only lasting fixes are in the `.wsb` file: `<LogonCommand>` (e.g. disable the `Container: allow inbound` rule) and `<Networking>Disable</Networking>`. For a sandbox the bigger question is usually the other direction — what the guest can reach on the host and the LAN (see [outside.md](outside.md#from-the-target-back-to-this-machine)).
