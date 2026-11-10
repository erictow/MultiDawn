#requires -Version 5.1
<# Tests the launcher transport through this PC's LAN interface. Both peers run
on this PC; this cannot establish whether another PC's firewall/router permits access. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Address,
    [string] $LauncherPath,
    [string] $ReportPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LauncherPath) {
    $LauncherPath = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))) 'build/launcher/MultiDawn.Launcher.exe'
}
$ip = [Net.IPAddress]::Parse($Address)
if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Use this PC''s IPv4 LAN address.' }
[void][Reflection.Assembly]::LoadFrom((Get-Item -LiteralPath $LauncherPath).FullName)
$hostSession = New-Object MultiDawn.Launcher.PairSession
$guestSession = New-Object MultiDawn.Launcher.PairSession
try {
    [void]$hostSession.HostAsync($ip, 0).GetAwaiter().GetResult()
    $listenPort = $hostSession.Port
    [void]$guestSession.JoinAsync($hostSession.Code).GetAwaiter().GetResult()
    if (-not $hostSession.IsPaired -or -not $guestSession.IsPaired -or
        $hostSession.PeerId -ne $guestSession.LocalPeerId -or $guestSession.PeerId -ne $hostSession.LocalPeerId) {
        throw 'The two local test peers did not authenticate through the LAN endpoint.'
    }
    Start-Sleep -Seconds 3
    if (-not $hostSession.IsPaired -or -not $guestSession.IsPaired) { throw 'The LAN endpoint heartbeat failed.' }
    $hostSession.Disconnect()
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ($guestSession.IsPaired -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 30 }
    if ($guestSession.IsPaired) { throw 'Guest failed to observe host disconnect.' }
    $report = [ordered]@{
        result = 'passed'
        address = $Address
        port = $listenPort
        scope = 'two local peers through this PC LAN interface'
        authenticatedPairing = $true
        heartbeat = $true
        disconnect = $true
        secondComputerVerified = $false
        gameLaunched = $false
    } | ConvertTo-Json
    if ($ReportPath) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($ReportPath), $report) }
    Write-Output $report
} finally {
    $guestSession.Dispose()
    $hostSession.Dispose()
}
