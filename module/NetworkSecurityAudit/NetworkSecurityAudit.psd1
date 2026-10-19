@{
    RootModule           = 'NetworkSecurityAudit.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '6f1d2c43-8b7e-4b9a-9c55-3e2a7d4f0b81'
    Author               = 'Yoshifumi Tsuda'
    Copyright            = '(c) 2026 Yoshifumi Tsuda. MIT License.'
    Description          = 'Read-only checks of what a Windows, Linux or macOS machine exposes to the network: parallel TCP probes that tell closed from filtered, listening ports with their process and service, Windows firewall rules open to any address, effective Linux sysctl values and SSH logins. Used by the network-security-audit skill for Claude Code, and usable on its own.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'Test-TcpPort'
        'Get-ListeningPort'
        'Find-PermissiveFirewallRule'
        'Get-WinEventData'
        'Get-SysctlEffective'
        'Compare-SysctlConfig'
        'Get-SshAuthSummary'
        'Get-SshAuthorizedKey'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'Audit', 'Network', 'Firewall', 'SSH', 'Linux', 'Windows', 'MacOS', 'PowerShell.MCP')
            LicenseUri   = 'https://github.com/yotsuda/powershell-mcp-security/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/yotsuda/powershell-mcp-security'
            ReleaseNotes = 'First release: the helper functions of the network-security-audit skill as a module.'
        }
    }
}
