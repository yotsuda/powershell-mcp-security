# NetworkSecurityAudit — read-only checks of what a machine exposes to the network.
# Every function reads; none changes the machine.

foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter *.ps1) {
    . $file.FullName
}

function Assert-Platform([string]$Name, [bool]$Ok, [string]$Os) {
    if (-not $Ok) { throw "$Name runs on $Os only." }
}
