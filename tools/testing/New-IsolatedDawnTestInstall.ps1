#requires -Version 5.1
<#
.SYNOPSIS
Creates a disposable native-game test installation with fresh Dawn settings.
.DESCRIPTION
Copies executables and DLLs, links only immutable package assets, and seeds runtime
content from this checkout. No existing saves, settings, logs or caches are copied.
The source and output must be on the same volume for package hard links. Never
run a game updater against this test installation: its package files are shared.
Does not launch the game or change the source installation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $SourceGame,
    [Parameter(Mandatory)] [string] $DllPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$source = (Get-Item -LiteralPath $SourceGame).FullName
$dll = Get-Item -LiteralPath $DllPath
$exe = Get-Item -LiteralPath (Join-Path $source 'destiny2.exe')
if ($exe.VersionInfo.FileVersion -cne '86657.20.08.23.1800.d2_rc') { throw 'Unsupported Destiny executable version.' }
if ($dll.VersionInfo.ProductName -cne 'Dawn') { throw 'Expected a compiled Dawn DLL.' }
if (Test-Path -LiteralPath (Join-Path $source 'steam_api64.dll')) { throw 'This test fixture currently supports the bin/x64 Dawn installation layout only.' }
if ([IO.Path]::GetPathRoot($source) -ine [IO.Path]::GetPathRoot($repo)) { throw 'Package hard links require the same volume.' }
$assets = @(Get-ChildItem -LiteralPath (Join-Path $source 'packages') -Recurse -File)
if ($assets.Count -eq 0) { throw 'The game packages folder is empty.' }
if (@($assets | Where-Object { $_.Extension -ne '.pkg' }).Count -ne 0) { throw 'Only immutable .pkg assets may be shared.' }
$fonts = @(Get-ChildItem -LiteralPath (Join-Path $source 'fonts') -Recurse -File)
$binaries = @(Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Name -eq 'destiny2.exe' -or $_.Extension -eq '.dll' -or $_.Name -eq 'sku_config.txt' })
$binFiles = @(Get-ChildItem -LiteralPath (Join-Path $source 'bin/x64') -File | Where-Object { $_.Extension -eq '.dll' -and $_.Name -ne 'steam_api64.dll' })
# Refuse redirected sources before creating any output.
$sourceDirectories = @('', 'packages', 'fonts', 'bin', 'bin/x64') | ForEach-Object { Get-Item -LiteralPath (Join-Path $source $_) }
foreach ($item in @($exe, $dll) + $assets + $fonts + $binaries + $binFiles + $sourceDirectories + @(Get-ChildItem -LiteralPath (Join-Path $source 'packages') -Directory -Recurse) + @(Get-ChildItem -LiteralPath (Join-Path $source 'fonts') -Directory -Recurse)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Redirected source is unsupported: ' + $item.FullName) }
}
$output = Join-Path $repo ('build/gameplay-tests/session-' + [Guid]::NewGuid().ToString('N'))
$runtime = Join-Path $output 'bin/x64/Dawn'
[IO.Directory]::CreateDirectory($runtime) | Out-Null
foreach ($item in $binaries) { Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $output $item.Name) }
foreach ($item in $binFiles) { Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $output ('bin/x64/' + $item.Name)) }
Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $output 'bin/x64/steam_api64.dll')
foreach ($item in $fonts + $assets) {
    $relative = $item.FullName.Substring($source.Length).TrimStart('\', '/')
    $destination = Join-Path $output $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
    if ($item -in $assets) { New-Item -ItemType HardLink -Path $destination -Target $item.FullName | Out-Null }
    else { Copy-Item -LiteralPath $item.FullName -Destination $destination }
}
foreach ($name in @('settings', 'hud', 'movement', 'player')) {
    Copy-Item -LiteralPath (Join-Path $repo "Dawn/resources/default_$name.json") -Destination (Join-Path $runtime ($name + '.json'))
}
foreach ($folder in @('scripts', 'event_presets')) {
    [IO.Directory]::CreateDirectory((Join-Path $runtime $folder)) | Out-Null
    $from = if ($folder -eq 'scripts') { Join-Path $repo 'Dawn/scripts' } else { Join-Path $repo 'Dawn/resources/event_presets' }
    foreach ($item in Get-ChildItem -LiteralPath $from -File) {
        if ($item.Extension -in @('.lua', '.json', '.txt')) { Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $runtime ($folder + '/' + $item.Name)) }
    }
}
foreach ($item in Get-ChildItem -LiteralPath (Join-Path $repo 'Dawn/resources/vendor_rules') -File -Filter '*.txt') {
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $runtime $item.Name)
}
$record = [ordered]@{
    schema = 1; gameVersion = $exe.VersionInfo.FileVersion
    executableSha256 = (Get-FileHash -LiteralPath $exe.FullName).Hash
    runtimeSha256 = (Get-FileHash -LiteralPath $dll.FullName).Hash
    sharedPackageCount = $assets.Count; playerState = 'fresh'; packages = 'hard-linked; do not update'
}
[IO.File]::WriteAllText((Join-Path $output 'native-test-install.json'), ($record | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
Write-Output $output
