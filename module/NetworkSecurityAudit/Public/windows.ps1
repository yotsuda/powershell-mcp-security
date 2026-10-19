# NetworkSecurityAudit — Windows.

function Find-NsaPermissiveFirewallRule {
    <#
    .SYNOPSIS
    Reads the ACTIVE firewall policy and returns enabled inbound Allow rules that are open
    to any remote address:
      AllowsEverything — protocol, port, program and service all Any: the firewall is a
                         no-op for the rule's profiles. Each one is a finding.
      OpenPort         — a port rule (not tied to a program or service) open to Any.
      Icmp             — an ICMP rule open to Any; Port shows the ICMP type (8:0 = echo).
    Store-app rules (those with an Owner) are confined to their package and skipped.
    Always ends with a line saying how many rules were checked, so "no output" can be told
    apart from "nothing could be read". Takes up to half a minute with a few hundred rules.
    .PARAMETER All
    Return every enabled inbound Allow rule with its filters, not only the kinds above.
    .PARAMETER Port
    Only rules whose local ports include one of these (e.g. 135, 445, RPCEPMap) — among the
    kinds above, or among every rule with -All. A number also matches a range such as
    49152-65535. A rule whose port is Any matches too when it is not tied to a program or
    service (Program Any or System) — e.g. an allow-everything rule. Rules for one program
    with port Any are left out: they let a port in only if that program listens on it, so
    check them by the listening process. ICMP rules are never matched (their Port shows ICMP
    types).
    .EXAMPLE
    Find-NsaPermissiveFirewallRule -All -Port 135, 139, 445, 5985, RPCEPMap
    #>
    param([switch]$All, [string[]]$Port)
    Assert-Platform 'Find-NsaPermissiveFirewallRule' $IsWindows 'Windows'
    $allRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow)
    $rules = @($allRules | Where-Object { -not $_.Owner })
    # Bulk reads are fast; a non-elevated console is denied some rules in bulk, so fall back per rule.
    $f = @{}
    foreach ($c in 'Port', 'Address', 'Application', 'Service') {
        $f[$c] = & "Get-NetFirewall${c}Filter" -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Group-Object InstanceID -AsHashTable -AsString
    }
    foreach ($r in $rules) {
        $x = @{}
        foreach ($c in 'Port', 'Address', 'Application', 'Service') {
            $x[$c] = if ($f[$c] -and $f[$c][$r.Name]) { $f[$c][$r.Name][0] } else { $r | & "Get-NetFirewall${c}Filter" }
        }
        # Name last: long (often localized) display names would push the other columns off screen.
        $o = [pscustomobject]@{
            Kind     = ''
            Port     = "$($x.Port.LocalPort)"
            Protocol = "$($x.Port.Protocol)"
            Profile  = "$($r.Profile)"
            Remote   = "$($x.Address.RemoteAddress)"
            Program  = "$($x.Application.Program)"
            Service  = "$($x.Service.Service)"
            Source   = "$($r.PolicyStoreSourceType)"
            Name     = $r.DisplayName
        }
        if ($o.Protocol -match '^ICMP') {
            # ICMP rules carry LocalPort 'RPC' as a placeholder; what they allow is the ICMP type.
            $o.Port = "type $($x.Port.IcmpType)"
            if ($o.Remote -eq 'Any') { $o.Kind = 'Icmp' }
        } elseif ($o.Remote -eq 'Any' -and $o.Program -eq 'Any' -and $o.Service -eq 'Any') {
            $o.Kind = if ($o.Protocol -eq 'Any' -and $o.Port -eq 'Any') { 'AllowsEverything' } elseif ($o.Port -ne 'Any') { 'OpenPort' } else { '' }
        }
        if ($Port) {
            $hit = @($x.Port.LocalPort) | Where-Object {
                $lp = "$_"
                if ($lp -in $Port) { return $true }
                # Any port: relevant only when not tied to one program (System = kernel listeners such as SMB).
                if ($lp -eq 'Any') { return $o.Program -in 'Any', 'System' -and $o.Service -eq 'Any' }
                if ($lp -match '^(\d+)-(\d+)$') {
                    $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                    [bool]($Port | Where-Object { "$_" -match '^\d+$' -and [int]"$_" -ge $lo -and [int]"$_" -le $hi })
                }
            }
            if ($o.Protocol -match '^ICMP' -or -not $hit) { continue }
        }
        if ($All -or $o.Kind) { $o }
    }
    Write-Host "Find-NsaPermissiveFirewallRule: $($rules.Count) enabled inbound Allow rules checked ($($allRules.Count - $rules.Count) store-app rules skipped)."
}

function ConvertFrom-NsaWinEvent {
    <#
    .SYNOPSIS
    Expands an event's EventData into named properties, so fields are read by name
    (IpAddress, LogonType, TargetUserName) instead of by position, which differs per event ID.
    Events that carry UserData instead (e.g. 1102, log cleared) get its elements; unnamed
    Data elements become Data0, Data1, …
    .EXAMPLE
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-7) } |
        ConvertFrom-NsaWinEvent | Group-Object LogonType, IpAddress, TargetUserName | Select-Object Count, Name
    #>
    param([Parameter(Mandatory, ValueFromPipeline)][Alias('Event')][System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord)
    process {
        $h = [ordered]@{ TimeCreated = $EventRecord.TimeCreated; Id = $EventRecord.Id }
        $x = ([xml]$EventRecord.ToXml()).Event
        if ($x.EventData) {
            $n = 0
            foreach ($d in $x.EventData.ChildNodes) {
                if ($d.LocalName -ne 'Data') { continue }
                $h[$(if ($d.GetAttribute('Name')) { $d.GetAttribute('Name') } else { "Data$n" })] = $d.InnerText
                $n++
            }
        } elseif ($x.UserData -and $x.UserData.FirstChild) {
            foreach ($d in $x.UserData.FirstChild.ChildNodes) { $h[$d.LocalName] = $d.InnerText }
        }
        [pscustomobject]$h
    }
}
