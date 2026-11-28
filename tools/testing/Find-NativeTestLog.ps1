#requires -Version 5.1
<# Collects the current kit's Dawn log in a ZIP. PathOnly returns the verified source path. #>
[CmdletBinding()]
param(
    [string] $KitRoot,
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string] $SourceCommit,
    [switch] $PathOnly,
    [switch] $NoExplorer
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$games = @(Get-Process -Name destiny2 -ErrorAction SilentlyContinue)
if (-not $KitRoot -and $env:MULTIDAWN_LOG_KIT) { $KitRoot = $env:MULTIDAWN_LOG_KIT }
if (-not $KitRoot -and $SourceCommit) {
    # The standalone collector can live outside an already extracted LAN kit.
    $folders = @($games | Where-Object Path | ForEach-Object { [IO.Path]::GetDirectoryName($_.Path) })
    $saved = Join-Path $env:LOCALAPPDATA 'MultiDawn/launcher-path.txt'
    if (Test-Path -LiteralPath $saved -PathType Leaf) { $folders += ([IO.File]::ReadAllText($saved)).Trim() }
    $candidates = @(foreach ($folder in $folders) {
        if ($folder -and [IO.Path]::IsPathRooted($folder) -and [IO.Path]::GetFileName($folder) -match '^session-[0-9a-f]{32}$') {
            [IO.Path]::GetFullPath((Join-Path $folder '../../..'))
        }
    })
    $kitName = 'MultiDawn-Native-LAN-' + $SourceCommit.Substring(0,8)
    $download = Join-Path (Join-Path $env:USERPROFILE 'Downloads') $kitName
    foreach ($candidate in @($candidates) + @($download, (Join-Path $download $kitName))) {
        $record = Join-Path $candidate 'native-lan-test.json'
        if ((Test-Path -LiteralPath $record -PathType Leaf) -and
            (Get-Content -LiteralPath $record -Raw | ConvertFrom-Json).sourceCommit -ieq $SourceCommit) {
            $KitRoot = $candidate
            break
        }
    }
    if (-not $KitRoot) { throw "Drag the extracted $kitName folder onto Collect-Test-Log.cmd." }
}
if (-not $KitRoot) { $KitRoot = Join-Path $PSScriptRoot '../..' }
$kit = (Get-Item -LiteralPath $KitRoot).FullName.TrimEnd('\')
$sessions = Join-Path $kit 'build\gameplay-tests'

function Get-KitFile([string] $Path) {
    $file = Get-Item -LiteralPath $Path -Force
    if ($file.PSIsContainer -or -not $file.FullName.StartsWith(($kit + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The selected file is outside this kit.'
    }
    for ($item = $file; $item.FullName -ine $kit; $item = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($item.FullName)) -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A redirected kit path cannot identify this test log.' }
    }
    return $file
}
function Test-SessionPath([string] $Path) {
    return ([IO.Path]::GetDirectoryName($Path) -ieq $sessions -and [IO.Path]::GetFileName($Path) -match '^session-[0-9a-f]{32}$')
}

$manifest = Get-Content -Raw -LiteralPath (Get-KitFile (Join-Path $kit 'native-lan-test.json')).FullName | ConvertFrom-Json
if ($manifest.schema -ne 1 -or $manifest.runtimeSha256 -notmatch '^[0-9a-f]{64}$' -or $manifest.sourceCommit -notmatch '^[0-9a-f]{40}([0-9a-f]{24})?$') {
    throw 'This folder needs the native LAN test kit manifest.'
}
if ($SourceCommit -and $manifest.sourceCommit -ine $SourceCommit) { throw 'This collector needs the LAN kit from the paired test run.' }
$loadedDll = $null
if ($games.Count) {
    $matching = @($games | Where-Object { $_.Path -and (Test-SessionPath ([IO.Path]::GetDirectoryName($_.Path))) })
    if ($matching.Count -ne 1) { throw 'Could not identify one running Destiny 2 from this kit. Open Collect-Test-Log.cmd in the kit used to launch the game.' }
    $game = $matching[0]
    $fixture = [IO.Path]::GetDirectoryName($game.Path)
    $modules = @($game.Modules | Where-Object ModuleName -ieq 'steam_api64.dll')
    if ($modules.Count -ne 1) { throw 'The test game has not loaded one Dawn runtime yet. Retry after character select.' }
    $loadedDll = $modules[0].FileName
} else {
    $pointer = Get-KitFile (Join-Path $kit 'build/latest-native-test-path.txt')
    $fixture = [IO.Path]::GetFullPath([IO.File]::ReadAllText($pointer.FullName).Trim())
    if (-not (Test-SessionPath $fixture)) { throw 'The latest prepared folder does not belong to this kit.' }
}
$marker = Get-Content -Raw -LiteralPath (Get-KitFile (Join-Path $fixture 'native-test-install.json')).FullName | ConvertFrom-Json
if ($marker.schema -ne 1 -or $marker.runtimeSha256 -ine $manifest.runtimeSha256 -or $marker.sourceCommit -ine $manifest.sourceCommit -or $marker.gameVersion -cne $manifest.gameVersion) {
    throw 'The prepared game does not match this kit.'
}
$logs = @(foreach ($folder in @($fixture, (Join-Path $fixture 'bin\x64'))) {
    $dll = Join-Path $folder 'steam_api64.dll'
    if ($loadedDll -and $dll -ine $loadedDll) { continue }
    $path = Join-Path $folder 'Dawn\logs\dawn.log'
    if (Test-Path -LiteralPath $path -PathType Leaf) { Get-KitFile $path }
})
if (-not $logs.Count) { throw 'No current dawn.log in this prepared game. Start its native test and retry after character select.' }
$logs = @($logs | Sort-Object LastWriteTimeUtc -Descending)
$log = $logs[0]
if ($logs.Count -gt 1 -and $log.LastWriteTimeUtc -eq $logs[1].LastWriteTimeUtc) { throw 'Both layouts have equally recent logs. Run the helper while the test game is open to identify its loaded runtime.' }
if ($loadedDll -and $log.LastWriteTimeUtc -lt $game.StartTime.ToUniversalTime()) { throw 'This game has not written its log yet. Retry after character select.' }

$runtimeDir = $log.Directory.Parent.Parent.FullName
$dll = Get-KitFile (Join-Path $runtimeDir 'steam_api64.dll')
$source = [IO.File]::Open($log.FullName, 'Open', 'Read', ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
try {
    $remaining = $source.Length
    $reader = [IO.StreamReader]::new($source, [Text.Encoding]::UTF8, $true, 4096, $true)
    try {
        $matchingIdentity = $false
        for ($i = 0; $i -lt 32; $i++) {
            $line = $reader.ReadLine()
            if ($null -eq $line) { break }
            if ($line -match '(?:^| )ev=build_identity .*?\bmodule_sha256=([0-9a-f]{64})(?:\s|$)') {
                $matchingIdentity = $Matches[1] -ieq $manifest.runtimeSha256
                break
            }
        }
    } finally { $reader.Dispose() }
    if (-not $matchingIdentity -or (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash -ine $manifest.runtimeSha256) {
        throw 'The log or its Dawn runtime does not match this test kit.'
    }
    if ($PathOnly) { return $log.FullName }
    $source.Position = 0
    $output = [IO.Directory]::CreateDirectory((Join-Path $kit 'build/test-logs'))
    $zip = Join-Path $output.FullName ('MultiDawn-log-' + [Guid]::NewGuid().ToString('N') + '.zip')
    Add-Type -AssemblyName System.IO.Compression
    $file = [IO.File]::Open($zip, 'CreateNew', 'Write', 'None')
    try {
        $archive = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $entry = $archive.CreateEntry('dawn.log').Open()
            try {
                $buffer = [byte[]]::new(65536)
                while ($remaining -gt 0) {
                    $count = $source.Read($buffer, 0, [int][Math]::Min([long]$buffer.Length, $remaining))
                    if ($count -eq 0) { throw 'The source log was shortened during collection. Retry.' }
                    $entry.Write($buffer, 0, $count)
                    $remaining -= $count
                }
            } finally { $entry.Dispose() }
        } finally { $archive.Dispose() }
    } catch {
        $file.Dispose()
        [IO.File]::Delete($zip)
        throw
    } finally { $file.Dispose() }
} finally { $source.Dispose() }
Write-Output $zip
if (-not $NoExplorer) {
    Start-Process -FilePath explorer.exe -ArgumentList ('/select,"{0}"' -f $zip)
}
