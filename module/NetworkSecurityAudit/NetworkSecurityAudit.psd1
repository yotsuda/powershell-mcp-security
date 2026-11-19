@{
    RootModule           = 'NetworkSecurityAudit.psm1'
    ModuleVersion        = '0.19.1'
    GUID                 = '6f1d2c43-8b7e-4b9a-9c55-3e2a7d4f0b81'
    Author               = 'Yoshifumi Tsuda'
    Copyright            = '(c) 2026 Yoshifumi Tsuda. MIT License.'
    Description          = 'Read-only checks of what a Windows, Linux or macOS machine exposes to the network: parallel TCP probes that tell closed from filtered, listening ports with their process and service, Windows firewall rules open to any address, effective Linux sysctl values and SSH logins. Used by the network-security-audit skill for Claude Code, and usable on its own.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Test-NsaTcpPort'
        'Get-NsaListeningPort'
        'Find-NsaPermissiveFirewallRule'
        'ConvertFrom-NsaWinEvent'
        'Get-NsaSysctl'
        'Compare-NsaSysctlConfig'
        'Get-NsaSshLogin'
        'Get-NsaSshAuthorizedKey'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'Audit', 'Network', 'Firewall', 'SSH', 'Linux', 'Windows', 'MacOS', 'PowerShell.MCP')
            LicenseUri   = 'https://github.com/yotsuda/powershell-mcp-security/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/yotsuda/powershell-mcp-security'
            ReleaseNotes = '0.19.1: the module is unchanged; the skill changed. Works with PowerShell.MCP 1.17.0, where wait_for_completion also waits for remote consoles and wait_for_remote_completion is gone (the skill names both). A sandbox audit probes every TCP port this machine listens on from the guest, over IPv4 and link-local IPv6, instead of a fixed list that missed Hyper-V VM connect, UPnP/WSD, CDPSvc and third-party agents; rules for profile Any and remote Any are their own finding. The Windows check says how to list LocalSubnet rules, which Find-NsaPermissiveFirewallRule leaves out without -All. The report''s "Not checked" covers the NAT-gateway caveat, the other guests on the switch and checks skipped as not applicable. 0.19.0: released together with the network-security-audit skill 0.19.0, under one version number. Find-NsaPermissiveFirewallRule -Port matches only TCP, UDP and Any rules (not IPv6-in-IPv4, IGMP or other port-less protocols). 0.1.1: Find-NsaPermissiveFirewallRule sets Kind on every rule (adds AllPorts, Program, Service), shows a compact default table (Kind, Port, Protocol, Profile, Remote, Name), supports -InformationVariable for its summary line, and explains the Wi-Fi Direct driver rules. 0.1.0: first release, the helper functions of the network-security-audit skill as a module.'
        }
    }
}
