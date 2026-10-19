# NetworkSecurityAudit — any OS.

function Test-NsaTcpPort {
    <#
    .SYNOPSIS
    Probes TCP ports in parallel. State is Open (connected), Closed (refused — the host
    answered with RST), Filtered (no answer before the timeout — typically a firewall
    dropping packets), or a socket error such as HostUnreachable.
    .PARAMETER Open
    Return only Open ports.
    .PARAMETER Responding
    Return only ports that answered (Open or Closed) — leaves out Filtered.
    .EXAMPLE
    Test-NsaTcpPort 192.0.2.10 -Port ((1..1024) + 42777) -Open
    .EXAMPLE
    Test-NsaTcpPort 'fe80::1234:5678:9abc:def0%30' -Port 22, 42777
    .NOTES
    Windows retries the SYN before reporting a refused connection, so from a Windows machine
    a closed port takes about 2 seconds to show as Closed; with a shorter timeout it shows as
    Filtered. Hence the 2500 ms default there.
    A Windows target with its firewall on answers closed ports with nothing at all (stealth
    mode), even where a rule allows them: Filtered then does not mean "blocked". To show that
    the firewall blocks something, test a port that is listening inside.
    #>
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        # object[] so nested lists such as (135, 445, (49664..49670)) are accepted and flattened.
        [object[]]$Port = (1..1024),
        [int]$TimeoutMs = $(if ($IsWindows) { 2500 } else { 1500 }),
        [int]$ThrottleLimit = 128,
        [switch]$Open,
        [switch]$Responding
    )
    $Port = [int[]]@($Port | ForEach-Object { $_ })
    $ip = $null
    $target = if ([System.Net.IPAddress]::TryParse($ComputerName, [ref]$ip)) { $ip } else { $ComputerName }
    $result = $Port | Sort-Object -Unique | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $t = $using:target
        $c = if ($t -is [System.Net.IPAddress]) { [System.Net.Sockets.TcpClient]::new($t.AddressFamily) } else { [System.Net.Sockets.TcpClient]::new() }
        $state = 'Filtered'
        try {
            if ($c.ConnectAsync($t, $_).Wait($using:TimeoutMs)) { $state = 'Open' }
        } catch {
            $e = $_.Exception.GetBaseException()
            $state = if ($e -is [System.Net.Sockets.SocketException]) {
                switch ($e.SocketErrorCode) { 'ConnectionRefused' { 'Closed' } 'TimedOut' { 'Filtered' } default { "$($e.SocketErrorCode)" } }
            } else { 'Error' }
        } finally { $c.Dispose() }
        [pscustomobject]@{ ComputerName = "$t"; Port = $_; State = $state }
    } | Sort-Object Port
    if ($Open) { $result | Where-Object State -eq 'Open' }
    elseif ($Responding) { $result | Where-Object State -in 'Open', 'Closed' }
    else { $result }
}

function Get-NsaListeningPort {
    <#
    .SYNOPSIS
    Lists listening TCP and UDP sockets with process and service. Exposed = bound to
    something other than loopback.
    Windows: ServicesInProcess lists every service hosted in that process. A shared svchost
    hosts several, and only one of them owns the port — such entries end in "(shared)", so do
    not read them as "these services opened the port".
    Linux: ServicesInProcess is the systemd unit of the process.
    Windows: UDP includes many sockets on high ports (49152 and up) bound by clients such as
    the DNS client; they are not services waiting for connections.
    .PARAMETER Sudo
    Linux/macOS: run ss/lsof through `sudo -n` so processes of other users are shown.
    .PARAMETER IncludeLoopback
    Also return sockets bound to loopback only.
    .PARAMETER Protocol
    TCP or UDP only.
    #>
    param([switch]$IncludeLoopback, [switch]$Sudo, [ValidateSet('TCP', 'UDP')][string]$Protocol)

    $isLoopback = { param($a) $a -match '^(127\.|::1$|\[::1\])' -or $a -match '%lo$' }
    $finish = { $input | Where-Object { ($IncludeLoopback -or $_.Exposed) -and (-not $Protocol -or $_.Protocol -eq $Protocol) } | Sort-Object Protocol, Port, Address }

    if ($IsWindows) {
        $svc = Get-CimInstance Win32_Service -Filter 'ProcessId > 0' | Group-Object ProcessId -AsHashTable -AsString
        $procName = @{}
        Get-Process | ForEach-Object { $procName[$_.Id] = $_.ProcessName }
        $rows = @(
            Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{ Protocol = 'TCP'; Address = $_.LocalAddress; Port = $_.LocalPort; PID = $_.OwningProcess } }
            Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{ Protocol = 'UDP'; Address = $_.LocalAddress; Port = $_.LocalPort; PID = $_.OwningProcess } }
        )
        $rows | ForEach-Object {
            $s = $svc["$($_.PID)"]
            [pscustomobject]@{
                Protocol = $_.Protocol; Port = $_.Port; Exposed = -not (& $isLoopback $_.Address)
                Address  = $_.Address; PID = $_.PID
                Process  = $procName[[int]$_.PID]
                ServicesInProcess = if (-not $s) { '' } elseif (@($s).Count -gt 1) { (($s.Name | Sort-Object) -join ', ') + ' (shared)' } else { $s[0].Name }
            }
        } | & $finish
        return
    }

    if ($IsLinux) {
        $lines = if ($Sudo) { sudo -n ss -H -tulpn } else { ss -H -tulpn }
        & { foreach ($l in $lines) {
            $f = $l -split '\s+'
            if ($f.Count -lt 5) { continue }
            $local = $f[4]
            $i = $local.LastIndexOf(':')
            $addr = $local.Substring(0, $i).Trim('[', ']'); $port = [int]$local.Substring($i + 1)
            $proc = ''; $procId = $null; $unit = ''
            if ($l -match 'users:\(\("([^"]+)",pid=(\d+)') {
                $proc = $Matches[1]; $procId = [int]$Matches[2]
                $cg = Get-Content "/proc/$procId/cgroup" -ErrorAction SilentlyContinue | Select-Object -Last 1
                if ($cg -match '/([^/]+\.(service|socket|scope))$') { $unit = $Matches[1] }
            }
            [pscustomobject]@{
                Protocol = $f[0].ToUpper(); Port = $port; Exposed = -not (& $isLoopback $addr)
                # ss writes "address%interface" for sockets bound to a device; keep the zone only where it matters (fe80::).
                Address = $(if ($addr -notmatch '^fe80') { $addr -replace '%.*' } else { $addr }); PID = $procId; Process = $proc; ServicesInProcess = $unit
            }
        } } | & $finish
        return
    }

    if ($IsMacOS) {
        # Not yet verified on a real Mac.
        $out = if ($Sudo) { @(sudo -n lsof -nP -iTCP -sTCP:LISTEN 2>$null) + @(sudo -n lsof -nP -iUDP 2>$null) }
               else { @(lsof -nP -iTCP -sTCP:LISTEN 2>$null) + @(lsof -nP -iUDP 2>$null) }
        & { foreach ($l in $out | Where-Object { $_ -notmatch '^COMMAND' }) {
            $f = $l -split '\s+'
            if ($f.Count -lt 9) { continue }
            $name = $f[8]; $i = $name.LastIndexOf(':')
            if ($i -lt 0 -or $name -match '->') { continue }   # connected UDP sockets are not listeners
            $addr = $name.Substring(0, $i).Trim('[', ']')
            [pscustomobject]@{
                Protocol = $f[7]; Port = [int]$name.Substring($i + 1); Exposed = -not (& $isLoopback $addr)
                Address = $addr; PID = [int]$f[1]; Process = $f[0]; ServicesInProcess = ''
            }
        } } | & $finish
    }
}
