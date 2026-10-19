# NetworkSecurityAudit — read-only checks of what a machine exposes to the network.
# Every function reads; none changes the machine.

foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter *.ps1) {
    . $file.FullName
}

# The default table keeps the columns that decide a finding; long program paths would push them off screen.
Update-TypeData -TypeName NetworkSecurityAudit.FirewallRule -DefaultDisplayPropertySet Kind, Port, Protocol, Profile, Remote, Name -Force

function Assert-Platform([string]$Name, [bool]$Ok, [string]$Os) {
    if (-not $Ok) { throw "$Name runs on $Os only." }
}
