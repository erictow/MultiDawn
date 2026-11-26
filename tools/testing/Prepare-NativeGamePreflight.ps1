#requires -Version 5.1
<#
.SYNOPSIS
Prepares a separate native test installation, retaining this PC's offline progress.
.DESCRIPTION
Checks the supplied runtime against its expected SHA-256 before creating a fixture.
The existing isolated-install helper validates the supported game build and shares
only immutable package assets. Source saves are opened read-only with writes and
deletes denied until preparation finishes. No game or launcher is started.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $SourceGame,
    [string] $DllPath,
    [string] $ExpectedRuntimeSha256,
    [switch] $FreshProfile
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$utf8 = New-Object Text.UTF8Encoding($false)

function Assert-GameClosed {
    $running = @(Get-Process -Name destiny2 -ErrorAction SilentlyContinue)
    if ($running.Count -ne 0) { throw 'Close every Destiny 2 process before copying local progress, then run preparation again.' }
}
function Assert-PlainItem([IO.FileSystemInfo] $Item) {
    if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw ('Redirected source is unsupported: ' + $Item.FullName)
    }
}
function Copy-LockedSave([IO.FileStream] $InputStream, [string] $Destination) {
    $target = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $InputStream.Position = 0; $InputStream.CopyTo($target) }
    finally { $target.Dispose() }
}

$manifest = $null
$sourceCommit = ''
$manifestPath = Join-Path $repo 'native-lan-test.json'
if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 1) { throw 'Unsupported native LAN test manifest schema.' }
    if ($manifest.PSObject.Properties['sourceCommit']) {
        $sourceCommit = [string] $manifest.sourceCommit
        if ($sourceCommit -notmatch '^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$') { throw 'Invalid source commit in the native LAN test manifest.' }
    }
}
if ([string]::IsNullOrWhiteSpace($DllPath)) { $DllPath = Join-Path $repo 'runtime/steam_api64.dll' }
if ([string]::IsNullOrWhiteSpace($ExpectedRuntimeSha256)) {
    if ($null -eq $manifest) { throw 'Supply ExpectedRuntimeSha256 or use a kit containing native-lan-test.json.' }
    $ExpectedRuntimeSha256 = [string] $manifest.runtimeSha256
}
if ($ExpectedRuntimeSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ExpectedRuntimeSha256 must contain exactly 64 hexadecimal characters.' }
$expectedHash = $ExpectedRuntimeSha256.ToUpperInvariant()
$dll = Get-Item -LiteralPath $DllPath
if ($dll.PSIsContainer) { throw 'DllPath must identify a file.' }
Assert-PlainItem $dll
$source = Get-Item -LiteralPath $SourceGame
if (-not $source.PSIsContainer) { throw 'SourceGame must identify the game directory.' }
$helper = Join-Path $PSScriptRoot 'New-IsolatedDawnTestInstall.ps1'

# Each DLL loads its own adjacent Dawn folder. Keep the stores independent.
$placements = @('bin/x64')
$hasRootDll = Test-Path -LiteralPath (Join-Path $source.FullName 'steam_api64.dll') -PathType Leaf
if ($hasRootDll) { $placements += '.' }

# These handles stay open across creation, copying, metadata and final publication.
$dllStream = $null
$profiles = @()
try {
    $dllStream = [IO.File]::Open($dll.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actualHash = [BitConverter]::ToString($sha.ComputeHash($dllStream)).Replace('-', '') }
    finally { $sha.Dispose() }
    if ($actualHash -cne $expectedHash) { throw 'Runtime SHA-256 does not match the expected test build. No fixture was created.' }

    if (-not $FreshProfile) {
        foreach ($placement in $placements) {
            $relative = Join-Path $placement 'Dawn'
            $runtime = Join-Path $source.FullName $relative
            $databasePath = Join-Path $runtime 'player-state.db'
            if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) { continue }
            Assert-GameClosed
            foreach ($path in @($source.FullName, (Join-Path $source.FullName $placement), $runtime, $databasePath)) {
                Assert-PlainItem (Get-Item -LiteralPath $path)
            }
            if ($placement -eq 'bin/x64') { Assert-PlainItem (Get-Item -LiteralPath (Join-Path $source.FullName 'bin')) }
            $profile = [pscustomobject]@{ Relative = $relative; Database = $null; WalPath = $databasePath + '-wal'; Wal = $null }
            $profiles += $profile
            try {
                $profile.Database = [IO.File]::Open($databasePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                if (Test-Path -LiteralPath $profile.WalPath) {
                    Assert-PlainItem (Get-Item -LiteralPath $profile.WalPath)
                    $profile.Wal = [IO.File]::Open($profile.WalPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                }
            } catch { throw ('Local progress is busy or cannot be locked for an offline copy. Close Destiny 2 and other save tools, then retry. ' + $_.Exception.Message) }
        }
    }
    $copyProgress = $profiles.Count -gt 0
    if ($copyProgress) { Assert-GameClosed }

    $created = @(& $helper -SourceGame $source.FullName -DllPath $dll.FullName)
    if ($created.Count -ne 1) { throw 'The isolated-install helper did not return one fixture path.' }
    $output = [IO.Path]::GetFullPath([string] $created[0])
    $testRoot = [IO.Path]::GetFullPath((Join-Path $repo 'build/gameplay-tests')) + [IO.Path]::DirectorySeparatorChar
    if (-not $output.StartsWith($testRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'The isolated-install helper returned an unexpected fixture path.' }
    foreach ($relative in @('', 'bin', 'bin/x64', 'bin/x64/Dawn')) { Assert-PlainItem (Get-Item -LiteralPath (Join-Path $output $relative)) }
    if ($hasRootDll -ne (Test-Path -LiteralPath (Join-Path $output 'steam_api64.dll') -PathType Leaf)) {
        throw 'The game layout changed during test preparation. Retry with the game closed.'
    }
    foreach ($placement in $placements) {
        $bin = Join-Path $output $placement
        $runtime = Join-Path $bin 'Dawn'
        Assert-PlainItem (Get-Item -LiteralPath $runtime)
        $installedDll = Get-Item -LiteralPath (Join-Path $bin 'steam_api64.dll')
        Assert-PlainItem $installedDll
        $installedHash = (Get-FileHash -LiteralPath $installedDll.FullName -Algorithm SHA256).Hash
        if ($installedHash -cne $expectedHash) { throw 'The isolated runtime does not match the verified test build.' }

        $settingsPath = Join-Path $runtime 'settings.json'
        $settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
        $settings.core.logging.file_sink = $true
        foreach ($channel in @('core', 'client', 'server')) { $settings.core.logging.levels.$channel = 'info' }
        [IO.File]::WriteAllText($settingsPath, ($settings | ConvertTo-Json -Depth 100), $utf8)
    }

    if ($copyProgress) {
        Assert-GameClosed
        foreach ($profile in $profiles) {
            if (($null -ne $profile.Wal) -ne (Test-Path -LiteralPath $profile.WalPath -PathType Leaf)) { throw 'The source save WAL changed during offline preparation. Retry after closing save tools.' }
            $runtime = Join-Path $output $profile.Relative
            Copy-LockedSave $profile.Database (Join-Path $runtime 'player-state.db')
            if ($null -ne $profile.Wal) { Copy-LockedSave $profile.Wal (Join-Path $runtime 'player-state.db-wal') }
        }
    }

    $recordPath = Join-Path $output 'native-test-install.json'
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    foreach ($required in @('schema', 'gameVersion', 'executableSha256', 'runtimeSha256', 'sharedPackageCount', 'playerState', 'packages')) {
        if (-not $record.PSObject.Properties[$required]) { throw ('The isolated install record is missing ' + $required + '.') }
    }
    if ($record.schema -ne 1 -or $record.runtimeSha256 -ine $expectedHash) { throw 'The isolated install record does not describe the verified runtime.' }
    if (-not $sourceCommit -and (Test-Path -LiteralPath (Join-Path $repo '.git')) -and (Get-Command git -ErrorAction SilentlyContinue)) {
        $revision = @(& git -C $repo rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $revision.Count -eq 1 -and $revision[0] -match '^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$') { $sourceCommit = [string] $revision[0] }
    }
    $record.playerState = if ($copyProgress) { 'copied-local-offline' } else { 'fresh' }
    if ($sourceCommit) { $record | Add-Member -NotePropertyName sourceCommit -NotePropertyValue $sourceCommit -Force }
    [IO.File]::WriteAllText($recordPath, ($record | ConvertTo-Json -Depth 20), $utf8)
    if ($copyProgress) { Assert-GameClosed }
    $ready = Join-Path $repo 'build/latest-native-test-path.txt'
    $pendingReady = $ready + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($pendingReady, $output + [Environment]::NewLine, $utf8)
    Move-Item -LiteralPath $pendingReady -Destination $ready -Force
    Write-Output $output
} finally {
    foreach ($profile in $profiles) {
        if ($null -ne $profile.Wal) { $profile.Wal.Dispose() }
        if ($null -ne $profile.Database) { $profile.Database.Dispose() }
    }
    if ($null -ne $dllStream) { $dllStream.Dispose() }
}
