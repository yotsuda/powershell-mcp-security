# Helpers for the network-security-audit skill — Linux targets.
# Functions are defined in the global scope so they survive between PowerShell.MCP calls.
# Load remotely: pass this file's text as one of var1, var2 … and run  . ([scriptblock]::Create($var<N>))

function global:Get-SysctlEffective {
    <#
    .SYNOPSIS
    Computes the value the kernel actually uses for the redirect / source-route / rp_filter /
    martian settings on each non-loopback interface, from all, default and the interface
    value, using each key's own rule. No root needed (reads /proc/sys).
      IPv4 accept_redirects     all OR iface (AND if the interface forwards)
      IPv4 send_redirects       all OR iface
      IPv4 accept_source_route  all AND iface
      IPv4 rp_filter            max(all, iface)
      IPv4 log_martians         all OR iface
      IPv6 accept_redirects     iface only (ignored while the interface forwards);
                                'default' only reaches interfaces created later
    #>
    $read = { param($p) $v = Get-Content $p -ErrorAction SilentlyContinue; if ($null -ne $v) { [int]$v } }
    $v4 = '/proc/sys/net/ipv4/conf'; $v6 = '/proc/sys/net/ipv6/conf'
    $ifaces = Get-ChildItem $v4 -Directory | Where-Object Name -notin 'all', 'default', 'lo' | ForEach-Object Name

    $rules = [ordered]@{
        accept_redirects    = @{ Rule = 'OR (AND if forwarding)'; Expected = 0 }
        send_redirects      = @{ Rule = 'OR';  Expected = 0 }
        accept_source_route = @{ Rule = 'AND'; Expected = 0 }
        rp_filter           = @{ Rule = 'MAX'; Expected = '>=1' }
        log_martians        = @{ Rule = 'OR';  Expected = 1 }
    }
    foreach ($i in $ifaces) {
        $fwd = & $read "$v4/$i/forwarding"
        foreach ($k in $rules.Keys) {
            $a = & $read "$v4/all/$k"; $d = & $read "$v4/default/$k"; $n = & $read "$v4/$i/$k"
            $eff = switch ($k) {
                'accept_redirects'    { if ($fwd) { [int]($a -and $n) } else { [int]($a -or $n) } }
                'accept_source_route' { [int]($a -and $n) }
                'rp_filter'           { [Math]::Max($a, $n) }
                default               { [int]($a -or $n) }
            }
            $exp = $rules[$k].Expected
            [pscustomobject]@{
                Family = 'IPv4'; Interface = $i; Key = $k; All = $a; Default = $d; Value = $n
                Effective = $eff; Rule = $rules[$k].Rule; Expected = $exp
                Ok = if ($exp -eq '>=1') { $eff -ge 1 } else { $eff -eq $exp }
            }
        }
        if (Test-Path "$v6/$i") {
            $n = & $read "$v6/$i/accept_redirects"; $f6 = & $read "$v6/$i/forwarding"
            $eff = [int]($n -and -not $f6)
            [pscustomobject]@{
                Family = 'IPv6'; Interface = $i; Key = 'accept_redirects'
                All = (& $read "$v6/all/accept_redirects"); Default = (& $read "$v6/default/accept_redirects"); Value = $n
                Effective = $eff; Rule = 'iface only'; Expected = 0; Ok = $eff -eq 0
            }
        }
    }
    foreach ($k in 'ip_forward', 'tcp_syncookies') {
        $eff = & $read "/proc/sys/net/ipv4/$k"; $exp = if ($k -eq 'ip_forward') { 0 } else { 1 }
        [pscustomobject]@{ Family = 'IPv4'; Interface = '(global)'; Key = $k; All = $null; Default = $null; Value = $eff
            Effective = $eff; Rule = 'global'; Expected = $exp; Ok = $eff -eq $exp }
    }
}

function global:Compare-SysctlConfig {
    <#
    .SYNOPSIS
    Compares the merged sysctl configuration (systemd-sysctl --cat-config, last file wins)
    and ufw's /etc/ufw/sysctl.conf (applied when ufw starts, after systemd-sysctl) with the
    values the kernel uses now. Returns the keys that differ; -All returns every key.
    Status:
      match         — effective value equals the configuration
      ufw overrides — ufw's file sets another value and ufw is enabled: it wins at boot
      differs       — something else changed it after boot (a script, a service, by hand)
    Keys with wildcards (net.ipv4.conf.*.x) are skipped, and so are keys for interfaces with a
    dot in the name (VLANs such as eth0.100): the dot cannot be told from a separator.
    #>
    param([switch]$All)
    $norm = { param($k) ($k.Trim() -replace '^-', '') -replace '/', '.' }
    $conf = [ordered]@{}; $file = ''
    $cat = '/usr/lib/systemd/systemd-sysctl'
    if (-not (Test-Path $cat)) { $cat = '/lib/systemd/systemd-sysctl' }
    foreach ($l in & $cat --cat-config 2>$null) {
        if ($l -match '^# (/\S+\.conf)') { $file = $Matches[1]; continue }
        if ($l -match '^\s*[#;]' -or $l -notmatch '=') { continue }
        $k, $v = $l -split '=', 2
        $k = & $norm $k
        if ($k -match '\*') { continue }
        $conf[$k] = [pscustomobject]@{ Value = $v.Trim(); File = $file }
    }
    $ufw = @{}
    $ufwOn = (Test-Path /etc/ufw/ufw.conf) -and (Select-String -Path /etc/ufw/ufw.conf -Pattern '^\s*ENABLED\s*=\s*yes' -Quiet)
    if (Test-Path /etc/ufw/sysctl.conf) {
        $n = 0
        foreach ($l in Get-Content /etc/ufw/sysctl.conf) {
            $n++
            if ($l -match '^\s*[#;]' -or $l -notmatch '=') { continue }
            $k, $v = $l -split '=', 2
            $ufw[(& $norm $k)] = [pscustomobject]@{ Value = $v.Trim(); Line = $n }
        }
    }
    foreach ($k in @($conf.Keys) + @($ufw.Keys | Where-Object { -not $conf.Contains($_) }) | Select-Object -Unique) {
        $path = '/proc/sys/' + ($k -replace '\.', '/')
        $eff = Get-Content $path -ErrorAction SilentlyContinue
        if ($null -eq $eff) { continue }
        $eff = "$eff".Trim() -replace '\s+', ' '
        $c = $conf[$k]; $u = $ufw[$k]
        $configured = if ($c) { $c.Value -replace '\s+', ' ' } else { $null }
        $status =
            if ($null -eq $configured) { if ($u -and $eff -eq $u.Value) { 'match' } else { 'differs' } }   # set by ufw only
            elseif ($u -and $ufwOn -and $u.Value -ne $configured -and $eff -eq $u.Value) { 'ufw overrides' }
            elseif ($eff -eq $configured) { 'match' }
            else { 'differs' }
        if ($All -or $status -ne 'match') {
            [pscustomobject]@{
                Key = $k; Configured = $configured; ConfiguredIn = if ($c) { $c.File } else { '' }
                Ufw = if ($u) { "$($u.Value) (/etc/ufw/sysctl.conf:$($u.Line))" } else { '' }
                Effective = $eff; Status = $status
            }
        }
    }
}

function global:Get-SshAuthSummary {
    <#
    .SYNOPSIS
    Summarizes sshd authentication from the journal: one line per result, method, user,
    source and key fingerprint, with counts and first/last time — instead of hundreds of
    near-identical log lines. Reading the journal usually needs root: use -Sudo.
    #>
    param([int]$Days = 7, [switch]$Sudo)
    $jargs = @('-u', 'ssh', '-u', 'sshd', '--since', "-$Days days", '--no-pager', '-o', 'short-iso')
    $lines = if ($Sudo) { sudo -n journalctl @jargs } else { journalctl @jargs }
    $events = foreach ($l in $lines) {
        $time = ($l -split '\s+')[0]
        # "… port 51234 ssh2: ED25519 SHA256:…" — the fingerprint is there for publickey only.
        if ($l -match 'Accepted (\S+) for (\S+) from (\S+) port \d+ \w+(?:: \S+ (SHA256:\S+))?') {
            [pscustomobject]@{ Time = $time; Result = 'Accepted'; Method = $Matches[1]; User = $Matches[2]; From = $Matches[3]; Key = $Matches[4] }
        } elseif ($l -match 'Failed (\S+) for (invalid user )?(\S+) from (\S+)') {
            [pscustomobject]@{ Time = $time; Result = if ($Matches[2]) { 'Failed (invalid user)' } else { 'Failed' }; Method = $Matches[1]; User = $Matches[3]; From = $Matches[4]; Key = $null }
        } elseif ($l -match 'Invalid user (\S*) from (\S+)') {
            [pscustomobject]@{ Time = $time; Result = 'Invalid user'; Method = ''; User = $Matches[1]; From = $Matches[2]; Key = $null }
        }
    }
    $events | Group-Object Result, Method, User, From, Key | ForEach-Object {
        $g = $_.Group
        [pscustomobject]@{
            Count = $_.Count; Result = $g[0].Result; Method = $g[0].Method; User = $g[0].User
            From = $g[0].From; Key = $g[0].Key; First = $g[0].Time; Last = $g[-1].Time
        }
    } | Sort-Object Result, @{ Expression = 'Count'; Descending = $true }
}

function global:Get-SshAuthorizedKey {
    <#
    .SYNOPSIS
    Lists the keys in authorized_keys and authorized_keys2 under /root and /home/* with type,
    bits, fingerprint and comment, flags CRLF files and empty files, and — from the journal —
    when each key was last used to log in. Needs root: runs through `sudo -n`.
    Homes elsewhere and other AuthorizedKeysFile paths (see `sshd -T`) are not covered.
    #>
    param([int]$Days = 7)
    $used = @{}
    Get-SshAuthSummary -Days $Days -Sudo | Where-Object { $_.Result -eq 'Accepted' -and $_.Key } |
        ForEach-Object { if (-not $used[$_.Key] -or $_.Last -gt $used[$_.Key]) { $used[$_.Key] = $_.Last } }
    $files = sudo -n sh -c 'ls -1 /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2 2>/dev/null'
    foreach ($file in $files) {
        $bytes = [int](sudo -n stat -c %s $file)
        # Native output reaches PowerShell split into lines with the CRs dropped, so look at the bytes.
        $crlf = [bool](sudo -n od -c $file | Select-String '\\r' -Quiet)
        if ($bytes -eq 0) {
            [pscustomobject]@{ File = $file; Bytes = 0; Type = ''; Bits = $null; Fingerprint = ''; Comment = '(empty)'; Crlf = $false; LastUsed = '' }
            continue
        }
        # A CRLF file leaves a CR at the end of each comment, which can push "(TYPE)" onto its own line.
        $text = (sudo -n ssh-keygen -lf $file 2>$null | Out-String) -replace "`r", '' -replace '\n\s*(\(\w+\))', ' $1'
        foreach ($k in $text -split '\n' | Where-Object { $_ }) {
            if ($k -match '^(\d+) (SHA256:\S+) (.*?)\s*\((\w+)\)\s*$') {
                [pscustomobject]@{
                    File = $file; Bytes = $bytes; Type = $Matches[4]; Bits = [int]$Matches[1]; Fingerprint = $Matches[2]
                    Comment = $Matches[3]; Crlf = $crlf; LastUsed = if ($used[$Matches[2]]) { $used[$Matches[2]] } else { "not in the last $Days days" }
                }
            }
        }
    }
}
