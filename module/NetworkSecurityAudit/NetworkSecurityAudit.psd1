@{
    RootModule           = 'NetworkSecurityAudit.psm1'
    ModuleVersion        = '0.1.1'
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
            ReleaseNotes = '0.1.1: Find-NsaPermissiveFirewallRule sets Kind on every rule (adds AllPorts, Program, Service), shows a compact default table (Kind, Port, Protocol, Profile, Remote, Name), supports -InformationVariable for its summary line, and explains the Wi-Fi Direct driver rules. 0.1.0: first release, the helper functions of the network-security-audit skill as a module.'
        }
    }
}
