#requires -Version 5.1
<#
.SYNOPSIS
Packages an already-built Dawn Release DLL and runtime content for players.
.EXAMPLE
.\tools\install\New-DawnRelease.ps1 -Release '0.1.0-test1'
.DESCRIPTION
Publisher tool only. Builds no code, installs nothing, and never includes local
settings, saves, caches, source, tests, PDBs, or development tools in the ZIP.
Use a DLL and content validated together. Packaging is not a playtest.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')] [string] $Release,
    [string] $DllPath,
    [string] $OutputDirectory,
    [string] $ReleaseNotesPath,
    [string] $LauncherPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $DllPath) { $DllPath = Join-Path $repo 'build/x64/Release/steam_api64.dll' }
$dll = (Get-Item -LiteralPath $DllPath).FullName
$version = (Get-Item -LiteralPath $dll).VersionInfo
if ($version.ProductName -ne 'Dawn' -or $version.IsDebug) { throw 'Use an already-built Dawn Release DLL.' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo "build/releases/Dawn-$Release" }
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$zip = $output + '.zip'
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $zip)) { throw "Output already exists: $output (or its ZIP). Choose a new release directory." }

# The optional launcher stays beside the installer, outside the game payload.
# Build it separately so the runtime publisher tool still builds no code.
$launcher = $null
$launcherHash = $null
if ($LauncherPath) {
    $launcher = Get-Item -LiteralPath $LauncherPath
    if ($launcher.PSIsContainer -or ($launcher.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $launcher.VersionInfo.ProductName -cne 'MultiDawn Launcher' -or $launcher.VersionInfo.IsDebug) {
        throw 'Use a Release MultiDawn Launcher EXE from tools/launcher/Build-Launcher.ps1.'
    }
    $launcherHash = (Get-FileHash -LiteralPath $launcher.FullName -Algorithm SHA256).Hash
}

# An explicit list separates release content from ignored local player state.
$inputs = New-Object 'System.Collections.Generic.List[object]'
function Add-Payload([string] $Source, [string] $Relative) {
    $item = Get-Item -LiteralPath $Source
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Not a plain input file: $Source" }
    $inputs.Add([pscustomobject]@{ Source = $item.FullName; Path = $Relative; Hash = (Get-FileHash -LiteralPath $item.FullName).Hash })
}
Add-Payload $dll 'steam_api64.dll'
foreach ($name in @('settings', 'hud', 'movement', 'player')) {
    Add-Payload (Join-Path $repo "Dawn/resources/default_$name.json") "Dawn/$name.json"
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repo 'Dawn/scripts') -File | Sort-Object Name) {
    if ($file.Extension -in @('.lua', '.json')) { Add-Payload $file.FullName ('Dawn/scripts/' + $file.Name) }
}
foreach ($name in @('vendor_catalog.txt', 'vendor_bounty_roll.txt', 'vendor_exchange.txt', 'vendor_item_substitute.txt')) {
    Add-Payload (Join-Path $repo "Dawn/resources/vendor_rules/$name") ('Dawn/' + $name)
}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repo 'Dawn/resources/event_presets') -File | Sort-Object Name) {
    if ($file.Extension -eq '.txt') { Add-Payload $file.FullName ('Dawn/event_presets/' + $file.Name) }
}
foreach ($license in @(
    @('Dawn/vendor/lua/LICENSE.txt', 'Lua.txt'),
    @('Dawn/vendor/imgui/LICENSE.txt', 'ImGui.txt'),
    @('Dawn/vendor/detours/LICENSE.md', 'Detours.md'),
    @('Dawn/vendor/sundial/LICENSE', 'Sundial.txt')
)) { Add-Payload (Join-Path $repo $license[0]) ('Dawn/licenses/' + $license[1]) }

$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.Directory]::CreateDirectory($output) | Out-Null
$files = @($inputs | ForEach-Object {
    $destination = Join-Path $output ('payload/' + $_.Path)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
    Copy-Item -LiteralPath $_.Source -Destination $destination
    if ((Get-FileHash -LiteralPath $destination).Hash -ne $_.Hash) { throw "Source changed while packaging: $($_.Source)" }
    [ordered]@{ path = $_.Path; size = (Get-Item -LiteralPath $destination).Length; sha256 = $_.Hash.ToLowerInvariant() }
})
foreach ($name in @('Install-Dawn.ps1', 'Install-Dawn.cmd', 'Update-Dawn.ps1', 'Update-Dawn.cmd', 'Uninstall-Dawn.ps1', 'Uninstall-Dawn.cmd', 'READ-ME.txt')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "release/$name") -Destination (Join-Path $output $name)
}
if ($ReleaseNotesPath) {
    Copy-Item -LiteralPath $ReleaseNotesPath -Destination (Join-Path $output 'RELEASE-NOTES.md')
}
if ($null -ne $launcher) {
    $launcherDestination = Join-Path $output 'MultiDawn.Launcher.exe'
    Copy-Item -LiteralPath $launcher.FullName -Destination $launcherDestination
    if ((Get-FileHash -LiteralPath $launcherDestination -Algorithm SHA256).Hash -cne $launcherHash) {
        throw 'Launcher input changed while packaging.'
    }
    Copy-Item -LiteralPath (Join-Path $repo 'Launch-MultiDawn.cmd') -Destination $output
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'release/READ-ME-MultiDawn.txt') -Destination $output
}
$manifest = [ordered]@{
    schema = 1; release = $Release; gameBuild = 86657; runtimeDirectory = 'Dawn';
    createdUtc = [DateTime]::UtcNow.ToString('o'); files = $files
}
[IO.File]::WriteAllText((Join-Path $output 'release.json'), ($manifest | ConvertTo-Json -Depth 10), $utf8)
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
# Entries are written one by one with forward-slash names: ZipFile.CreateFromDirectory under Windows PowerShell
# stores backslashes, which Linux and macOS extractors keep as literal file names instead of folders.
$archive = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $output -Recurse -File | Sort-Object FullName) {
        $name = $file.FullName.Substring($output.Length + 1).Replace([char]92, [char]47)
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $archive.Dispose() }
Write-Host "Player ZIP: $zip"
Write-Host "SHA256: $((Get-FileHash -LiteralPath $zip).Hash)"
Write-Host 'Contains the installer and runtime payload, plus the launcher when requested. Test this release on a separate game installation before publication.'
return $zip
