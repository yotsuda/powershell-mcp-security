BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'NetworkSecurityAudit') -Force
}

Describe 'Module' {
    It 'exports the documented functions and nothing else' {
        $expected = 'Compare-NsaSysctlConfig', 'ConvertFrom-NsaWinEvent', 'Find-NsaPermissiveFirewallRule', 'Get-NsaListeningPort',
                    'Get-NsaSshAuthorizedKey', 'Get-NsaSshLogin', 'Get-NsaSysctl', 'Test-NsaTcpPort'
        (Get-Module NetworkSecurityAudit).ExportedFunctions.Keys | Sort-Object | Should -Be $expected
    }

    It 'has help for every function' {
        foreach ($f in (Get-Module NetworkSecurityAudit).ExportedFunctions.Keys) {
            (Get-Help $f).Synopsis | Should -Not -BeNullOrEmpty -Because $f
        }
    }
}

Describe 'Test-NsaTcpPort' {
    BeforeAll {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $openPort = $listener.LocalEndpoint.Port
        # A port that was free a moment ago: bind and release it.
        $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $probe.Start(); $closedPort = $probe.LocalEndpoint.Port; $probe.Stop()
    }
    AfterAll { $listener.Stop() }

    It 'reports a listening port as Open and a free one as Closed' {
        $r = Test-NsaTcpPort 127.0.0.1 -Port $openPort, $closedPort
        ($r | Where-Object Port -eq $openPort).State | Should -Be 'Open'
        ($r | Where-Object Port -eq $closedPort).State | Should -Be 'Closed'
    }

    It 'flattens nested port lists' {
        (Test-NsaTcpPort 127.0.0.1 -Port ($openPort, ($closedPort))).Count | Should -Be 2
    }

    It '-Open and -Responding filter the states' {
        (Test-NsaTcpPort 127.0.0.1 -Port $openPort, $closedPort -Open).Port | Should -Be $openPort
        (Test-NsaTcpPort 127.0.0.1 -Port $openPort, $closedPort -Responding).Count | Should -Be 2
    }
}

Describe 'Get-NsaListeningPort' {
    It 'returns sorted objects and leaves out loopback by default' {
        $r = @(Get-NsaListeningPort)
        $r | Where-Object { -not $_.Exposed } | Should -BeNullOrEmpty
        if ($r.Count -gt 1) { $r[0].Protocol | Should -BeLessOrEqual $r[-1].Protocol }
    }

    It '-Protocol TCP returns TCP only' {
        Get-NsaListeningPort -Protocol TCP -IncludeLoopback | Where-Object Protocol -ne 'TCP' | Should -BeNullOrEmpty
    }
}

Describe 'Platform guards' {
    It 'Windows-only functions refuse to run elsewhere' -Skip:$IsWindows {
        { Find-NsaPermissiveFirewallRule } | Should -Throw '*Windows only*'
    }
    It 'Linux-only functions refuse to run elsewhere' -Skip:$IsLinux {
        { Get-NsaSysctl } | Should -Throw '*Linux only*'
        { Compare-NsaSysctlConfig } | Should -Throw '*Linux only*'
        { Get-NsaSshLogin } | Should -Throw '*Linux only*'
    }
}

Describe 'ConvertFrom-NsaWinEvent' -Skip:(-not $IsWindows) {
    It 'expands named EventData' {
        $e = Get-WinEvent -LogName System -MaxEvents 20 | Where-Object { ([xml]$_.ToXml()).Event.EventData } | Select-Object -First 1
        if (-not $e) { Set-ItResult -Skipped -Because 'no System event with EventData'; return }
        $d = $e | ConvertFrom-NsaWinEvent
        $d.Id | Should -Be $e.Id
        ($d.PSObject.Properties.Name.Count) | Should -BeGreaterThan 2
    }
}
