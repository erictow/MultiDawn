#requires -Version 5.1
<#
.SYNOPSIS
Packages the prebuilt MultiDawn launcher without game files or local settings.
.EXAMPLE
.\tools\launcher\Build-Launcher.ps1
.\tools\install\New-MultiDawnLauncherRelease.ps1 -Release '0.4.0-preview.1'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string] $Release,
    [string] $LauncherPath,
    [string] $OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $LauncherPath) { $LauncherPath = Join-Path $repo 'build/launcher/MultiDawn.Launcher.exe' }
$launcher = Get-Item -LiteralPath $LauncherPath
if ($launcher.PSIsContainer -or ($launcher.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The launcher input must be a plain EXE file.'
}
if ($launcher.VersionInfo.ProductName -cne 'MultiDawn Launcher' -or $launcher.VersionInfo.IsDebug) {
    throw 'Use a Release MultiDawn Launcher EXE from tools/launcher/Build-Launcher.ps1.'
}
if ([version]$launcher.VersionInfo.FileVersion -lt [version]'0.4.0.0') {
    throw 'Build MultiDawn Launcher 0.4 or later for this invitation-control package.'
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo "build/releases/MultiDawn-Launcher-$Release" }
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$zip = $output + '.zip'
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $zip)) {
    throw "Output already exists: $output (or its ZIP). Choose a new release directory."
}
$inputs = @(
    @{ Source = $launcher.FullName; Path = 'MultiDawn.Launcher.exe' },
    @{ Source = (Join-Path $repo 'Launch-MultiDawn.cmd'); Path = 'Launch-MultiDawn.cmd' },
    @{ Source = (Join-Path $PSScriptRoot 'release/READ-ME-MultiDawn.txt'); Path = 'READ-ME-MultiDawn.txt' },
    @{ Source = (Join-Path $repo 'LICENSE'); Path = 'LICENSE' }
)
# Validate every input before creating the output. Never collect a game directory.
foreach ($inputFile in $inputs) {
    $item = Get-Item -LiteralPath $inputFile.Source
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Not a plain input file: $($inputFile.Source)"
    }
    $inputFile.Hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
}
[IO.Directory]::CreateDirectory($output) | Out-Null
$files = @(
    foreach ($inputFile in $inputs) {
        $destination = Join-Path $output $inputFile.Path
        Copy-Item -LiteralPath $inputFile.Source -Destination $destination
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -cne $inputFile.Hash) {
            throw "Source changed while packaging: $($inputFile.Source)"
        }
        [ordered]@{
            path = $inputFile.Path
            size = (Get-Item -LiteralPath $destination).Length
            sha256 = $inputFile.Hash.ToLowerInvariant()
        }
    }
)
$manifest = [ordered]@{
    schema = 1
    release = $Release
    product = 'MultiDawn Launcher'
    launcherVersion = $launcher.VersionInfo.ProductVersion
    createdUtc = [DateTime]::UtcNow.ToString('o')
    capabilities = [ordered]@{
        soloLaunch = $true
        launcherPairing = $true
        savedLauncherFriends = $true
        manualPairingAddress = $true
        gameplayMultiplayer = $false
        inGameFriends = $false
    }
    files = $files
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $output 'launcher-release.json'), ($manifest | ConvertTo-Json -Depth 10), $utf8)
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
$archive = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $output -File | Sort-Object Name) {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $archive, $file.FullName, $file.Name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $archive.Dispose() }
Write-Host "Launcher ZIP: $zip"
Write-Host "SHA256: $((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash)"
return $zip
