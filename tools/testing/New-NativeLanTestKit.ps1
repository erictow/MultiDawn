#requires -Version 5.1
<# Packages a matched development launcher/runtime and isolated-install helpers.
   Includes no game files, account state, saved launcher identities or player saves. #>
[CmdletBinding()]
param(
    [string] $DllPath,
    [string] $LauncherPath,
    [string] $OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $DllPath) { $DllPath = Join-Path $repo 'build/portable/Dawn/Release/artifacts/steam_api64.dll' }
if (-not $LauncherPath) { $LauncherPath = Join-Path $repo 'build/launcher/MultiDawn.Launcher.exe' }
$runtime = Get-Item -LiteralPath $DllPath
$launcher = Get-Item -LiteralPath $LauncherPath
if ($runtime.VersionInfo.ProductName -cne 'Dawn' -or $runtime.VersionInfo.IsDebug) { throw 'Build the Dawn Release DLL first.' }
if ($launcher.VersionInfo.ProductName -cne 'MultiDawn Launcher' -or $launcher.VersionInfo.IsDebug) { throw 'Build the Release launcher first.' }
$sourceCommit = (& git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot identify the source commit.' }
$pending = @(& git -C $repo status --porcelain)
if ($LASTEXITCODE -ne 0 -or $pending.Count -ne 0) { throw 'Commit source changes before packaging the test kit.' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo ('build/releases/MultiDawn-Native-LAN-' + $sourceCommit.Substring(0, 8)) }
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$zipPath = $output + '.zip'
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $zipPath)) { throw 'Choose a new output directory; an existing kit is never overwritten.' }
$inputs = New-Object 'System.Collections.Generic.List[object]'
function Add-KitInput([string] $Source, [string] $Relative) {
    $file = Get-Item -LiteralPath $Source
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Not a plain kit input: $Source" }
    $inputs.Add([pscustomobject]@{ Source = $file.FullName; Path = $Relative; Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash })
}
Add-KitInput $runtime.FullName 'runtime/steam_api64.dll'
Add-KitInput $launcher.FullName 'MultiDawn.Launcher.exe'
Add-KitInput (Join-Path $repo 'LICENSE') 'LICENSE'
Add-KitInput (Join-Path $repo 'docs/TWO-PC-NATIVE-PREFLIGHT.md') 'README.md'
foreach ($helper in @('Prepare-NativeGamePreflight.ps1', 'New-IsolatedDawnTestInstall.ps1', 'Find-NativeTestLog.ps1')) {
    Add-KitInput (Join-Path $PSScriptRoot $helper) ('tools/testing/' + $helper)
}
foreach ($name in @('settings', 'hud', 'movement', 'player')) {
    Add-KitInput (Join-Path $repo "Dawn/resources/default_$name.json") "Dawn/resources/default_$name.json"
}
foreach ($folder in @('Dawn/scripts', 'Dawn/resources/vendor_rules', 'Dawn/resources/event_presets')) {
    $directory = Get-Item -LiteralPath (Join-Path $repo $folder)
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Redirected content folder: $folder" }
    foreach ($file in Get-ChildItem -LiteralPath $directory.FullName -File | Sort-Object Name) {
        if ($file.Extension -in @('.lua', '.json', '.txt')) { Add-KitInput $file.FullName ($folder + '/' + $file.Name) }
    }
}
foreach ($license in @(
    @('Dawn/vendor/lua/LICENSE.txt', 'licenses/Lua.txt'),
    @('Dawn/vendor/imgui/LICENSE.txt', 'licenses/ImGui.txt'),
    @('Dawn/vendor/detours/LICENSE.md', 'licenses/Detours.md'),
    @('Dawn/vendor/sundial/LICENSE', 'licenses/Sundial.txt')
)) { Add-KitInput (Join-Path $repo $license[0]) $license[1] }

[IO.Directory]::CreateDirectory($output) | Out-Null
foreach ($inputFile in $inputs) {
    $destination = Join-Path $output $inputFile.Path
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
    Copy-Item -LiteralPath $inputFile.Source -Destination $destination
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -cne $inputFile.Hash) { throw "Input changed while packaging: $($inputFile.Path)" }
}
$runtimeHash = ($inputs | Where-Object { $_.Path -eq 'runtime/steam_api64.dll' }).Hash
$launcherHash = ($inputs | Where-Object { $_.Path -eq 'MultiDawn.Launcher.exe' }).Hash
$utf8 = New-Object Text.UTF8Encoding($false)
$launchLines = @('@echo off', ('start "" "%~dp0MultiDawn.Launcher.exe" --native-game-preflight ' + $runtimeHash))
[IO.File]::WriteAllText((Join-Path $output 'Start-Native-Test.cmd'), (($launchLines -join "`r`n") + "`r`n"), $utf8)
$prepareLines = @(
    '@echo off'
    'setlocal DisableDelayedExpansion'
    'if not "%~2"=="" ('
    '    echo Drop one Dawn game folder onto this file.'
    '    pause'
    '    exit /b 1'
    ')'
    'set "MULTIDAWN_PREPARE_SOURCE=%~1"'
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\testing\Prepare-NativeGamePreflight.ps1" -OpenLauncher'
    'if errorlevel 1 ('
    '    pause'
    '    exit /b 1'
    ')'
)
[IO.File]::WriteAllText((Join-Path $output 'Prepare-Test-Game.cmd'), (($prepareLines -join "`r`n") + "`r`n"), $utf8)
$logLines = @(
    '@echo off'
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\testing\Find-NativeTestLog.ps1"'
    'if errorlevel 1 ('
    '    pause'
    '    exit /b 1'
    ')'
)
[IO.File]::WriteAllText((Join-Path $output 'Collect-Test-Log.cmd'), (($logLines -join "`r`n") + "`r`n"), $utf8)
$files = @(Get-ChildItem -LiteralPath $output -Recurse -File | Sort-Object FullName | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($output.Length + 1).Replace([char]92, [char]47); size = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$manifest = [ordered]@{
    schema = 1; sourceCommit = $sourceCommit; gameVersion = '86657.20.08.23.1800.d2_rc'
    runtimeSha256 = $runtimeHash; launcherSha256 = $launcherHash
    gameplayMultiplayer = $false; gameFilesIncluded = $false; playerSavesIncluded = $false
    twoPcGameConnectionVerified = $false; files = $files
}
[IO.File]::WriteAllText((Join-Path $output 'native-lan-test.json'), ($manifest | ConvertTo-Json -Depth 8), $utf8)
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression
$archive = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $output -Recurse -File | Sort-Object FullName) {
        $entry = $file.FullName.Substring($output.Length + 1).Replace([char]92, [char]47)
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $archive.Dispose() }
Write-Host ('Native LAN test ZIP: ' + $zipPath)
Write-Host ('SHA256: ' + (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash)
Write-Output $zipPath
