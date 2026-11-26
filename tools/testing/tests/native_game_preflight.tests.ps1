#requires -Version 5.1
<# Small disposable fixtures and a stub isolation helper; no game is copied or launched. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$testRoot = Join-Path $repo ('build/native-preflight-tests/' + [Guid]::NewGuid().ToString('N'))
$kit = Join-Path $testRoot 'kit [literal]'
$testing = Join-Path $kit 'tools/testing'
[IO.Directory]::CreateDirectory($testing) | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'tools/testing/Prepare-NativeGamePreflight.ps1') -Destination $testing
$prepare = Join-Path $testing 'Prepare-NativeGamePreflight.ps1'
$script:passed = 0
function Assert([bool] $Value, [string] $Message) { if (-not $Value) { throw ('ASSERTION FAILED: ' + $Message) } }
function Pass([string] $Message) { $script:passed++; Write-Host ('PASS: ' + $Message) }
function Write-File([string] $Path, [string] $Text) {
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path)) | Out-Null
    [IO.File]::WriteAllText($Path, $Text)
}
function Snapshot([string] $Root) {
    return (@(Get-ChildItem -LiteralPath $Root -File -Recurse | Sort-Object FullName | ForEach-Object {
        $_.FullName.Substring($Root.Length) + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }) -join "`n")
}
function Refuses([scriptblock] $Action, [string] $Pattern) {
    $message = ''
    try { & $Action | Out-Null } catch { $message = $_.Exception.Message }
    Assert ($message -like $Pattern) ('Expected ' + $Pattern + '; received ' + $message)
}
function New-Source([string] $Name, [switch] $NoDatabase, [switch] $NoWal) {
    $folder = Join-Path $testRoot $Name
    Write-File (Join-Path $folder 'destiny2.exe') 'not an executable; isolation is stubbed'
    Write-File (Join-Path $folder 'bin/x64/Dawn/settings.json') 'personal source settings'
    Write-File (Join-Path $folder 'bin/x64/Dawn/device_identity.key') 'private source identity'
    if (-not $NoDatabase) {
        Write-File (Join-Path $folder 'bin/x64/Dawn/player-state.db') ('local progress: ' + $Name)
        Write-File (Join-Path $folder 'bin/x64/Dawn/player-state.db-shm') 'transient shared memory; do not copy'
        if (-not $NoWal) { Write-File (Join-Path $folder 'bin/x64/Dawn/player-state.db-wal') ('pending local progress: ' + $Name) }
    }
    return $folder
}
function Calls { return [IO.File]::ReadAllText((Join-Path $kit 'helper-calls.txt')) }
function Assert-Writable([string] $Path) {
    $handle = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $handle.Dispose()
}

# Deterministically cover process refusal without starting any executable.
$global:NativePreflightPretendRunning = $false
function Get-Process {
    [CmdletBinding()] param([string] $Name)
    if ($Name -ne 'destiny2') { throw 'Unexpected process query.' }
    if ($global:NativePreflightPretendRunning) { [pscustomobject]@{ Id = 123; ProcessName = 'destiny2' } }
}

$stub = @'
[CmdletBinding()]
param([string] $SourceGame, [string] $DllPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$calls = Join-Path $root 'helper-calls.txt'
[IO.File]::WriteAllText($calls, ([int]([IO.File]::ReadAllText($calls)) + 1).ToString())
if (Test-Path -LiteralPath (Join-Path $root 'expect-save-locks.txt')) {
    foreach ($folder in @('bin/x64/Dawn', 'Dawn')) {
        foreach ($name in @('player-state.db', 'player-state.db-wal')) {
            $path = Join-Path $SourceGame ($folder + '/' + $name)
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $blocked = $false; $writer = $null
            try { $writer = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite) }
            catch [IO.IOException] { $blocked = $true }
            finally { if ($null -ne $writer) { $writer.Dispose() } }
            if (-not $blocked) { throw ('Save was not locked during fixture preparation: ' + $path) }
        }
    }
}
if (Test-Path -LiteralPath (Join-Path $root 'fail-isolation.txt')) { throw 'Simulated isolation refusal.' }
$output = Join-Path $root ('build/gameplay-tests/session-' + [Guid]::NewGuid().ToString('N'))
$runtime = Join-Path $output 'bin/x64/Dawn'
[IO.Directory]::CreateDirectory($runtime) | Out-Null
Copy-Item -LiteralPath $DllPath -Destination (Join-Path $output 'bin/x64/steam_api64.dll')
[IO.File]::WriteAllText((Join-Path $runtime 'settings.json'), '{"core":{"logging":{"file_sink":false,"levels":{"core":"warn","client":"warn","state":"warn","server":"warn","middleware":"warn"}}},"keep":"unchanged"}')
if (Test-Path -LiteralPath (Join-Path $SourceGame 'steam_api64.dll') -PathType Leaf) {
    Copy-Item -LiteralPath $runtime -Destination (Join-Path $output 'Dawn') -Recurse
    Copy-Item -LiteralPath $DllPath -Destination (Join-Path $output 'steam_api64.dll')
}
$record = [ordered]@{ schema=1; gameVersion='fixture-version'; executableSha256=('A' * 64); runtimeSha256=(Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash; sharedPackageCount=7; playerState='fresh'; packages='hard-linked; do not update'; extra='preserved' }
[IO.File]::WriteAllText((Join-Path $output 'native-test-install.json'), ($record | ConvertTo-Json))
Write-Output $output
'@
Write-File (Join-Path $testing 'New-IsolatedDawnTestInstall.ps1') $stub
Write-File (Join-Path $kit 'helper-calls.txt') '0'
$dll = Join-Path $kit 'runtime/steam_api64.dll'
Write-File $dll 'small test runtime bytes; never loaded'
$hash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
$commit = '0123456789abcdef0123456789abcdef01234567'
$manifestPath = Join-Path $kit 'native-lan-test.json'
Write-File $manifestPath (([ordered]@{ schema=1; sourceCommit=$commit; runtimeSha256=$hash; launcherSha256=('B' * 64) }) | ConvertTo-Json)
$lockMarker = Join-Path $kit 'expect-save-locks.txt'
Write-File $lockMarker 'required'
$source = New-Source 'own game [literal]'
$before = Snapshot $source
$output = & $prepare -SourceGame $source
$runtime = Join-Path $output 'bin/x64/Dawn'
Assert ([IO.File]::ReadAllText((Join-Path $runtime 'player-state.db')) -ceq 'local progress: own game [literal]') 'Database bytes changed'
Assert ([IO.File]::ReadAllText((Join-Path $runtime 'player-state.db-wal')) -ceq 'pending local progress: own game [literal]') 'WAL bytes changed'
Assert (-not (Test-Path -LiteralPath (Join-Path $runtime 'player-state.db-shm'))) 'Shared memory was copied'
Assert (-not (Test-Path -LiteralPath (Join-Path $runtime 'device_identity.key'))) 'A source identity was copied'
Assert ((Snapshot $source) -ceq $before) 'Source files changed'
Assert-Writable (Join-Path $source 'bin/x64/Dawn/player-state.db')
Assert-Writable (Join-Path $source 'bin/x64/Dawn/player-state.db-wal')
Pass 'Manifest defaults preserve own DB and WAL under read locks, omit SHM and identities, and leave source unchanged'
$record = Get-Content -LiteralPath (Join-Path $output 'native-test-install.json') -Raw | ConvertFrom-Json
Assert ($record.playerState -ceq 'copied-local-offline' -and $record.sourceCommit -ceq $commit -and $record.extra -ceq 'preserved' -and
    $record.gameVersion -ceq 'fixture-version' -and $record.sharedPackageCount -eq 7 -and $record.runtimeSha256 -ceq $hash) 'Install metadata was not preserved'
$settings = Get-Content -LiteralPath (Join-Path $runtime 'settings.json') -Raw | ConvertFrom-Json
Assert ($settings.core.logging.file_sink -and $settings.core.logging.levels.client -ceq 'info' -and $settings.core.logging.levels.server -ceq 'info' -and
    $settings.core.logging.levels.core -ceq 'info' -and $settings.core.logging.levels.state -ceq 'warn' -and $settings.keep -ceq 'unchanged') 'Logging changed unrelated settings'
$ready = Join-Path $kit 'build/latest-native-test-path.txt'
Assert ([IO.File]::ReadAllText($ready).Trim() -ceq $output) 'Ready path does not identify the completed fixture'
Pass 'Fixture logging, provenance, existing metadata and latest-ready path are correct'
$calls = Calls
$readyBefore = [IO.File]::ReadAllText($ready)
Refuses { & $prepare -SourceGame $source -ExpectedRuntimeSha256 ('0' * 64) } '*SHA-256 does not match*'
Refuses { & $prepare -SourceGame $source -ExpectedRuntimeSha256 'bad' } '*exactly 64 hexadecimal*'
Assert ((Calls) -ceq $calls -and [IO.File]::ReadAllText($ready) -ceq $readyBefore) 'Rejected hash created or published a fixture'
Assert-Writable $dll
Pass 'Hash mismatch and malformed hash refuse before fixture creation and release the runtime lock'
$global:NativePreflightPretendRunning = $true
try { Refuses { & $prepare -SourceGame $source } '*Close every Destiny 2 process*' }
finally { $global:NativePreflightPretendRunning = $false }
Assert ((Calls) -ceq $calls) 'A running game allowed save preparation'
Pass 'Running-game refusal occurs before invoking the isolation helper'
foreach ($name in @('player-state.db', 'player-state.db-wal')) {
    $path = Join-Path $source ('bin/x64/Dawn/' + $name)
    $busy = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try { Refuses { & $prepare -SourceGame $source } '*progress is busy or cannot be locked*' }
    finally { $busy.Dispose() }
    Assert ((Calls) -ceq $calls) 'Busy progress created a fixture'
    Assert-Writable (Join-Path $source 'bin/x64/Dawn/player-state.db')
    Assert-Writable (Join-Path $source 'bin/x64/Dawn/player-state.db-wal')
    Pass ('Busy ' + $name + ' refuses safely and releases every acquired save handle')
}
$failureMarker = Join-Path $kit 'fail-isolation.txt'
Write-File $failureMarker 'refuse'
try { Refuses { & $prepare -SourceGame $source } '*Simulated isolation refusal*' }
finally { Remove-Item -LiteralPath $failureMarker }
Assert-Writable (Join-Path $source 'bin/x64/Dawn/player-state.db')
Assert-Writable (Join-Path $source 'bin/x64/Dawn/player-state.db-wal')
Assert-Writable $dll
Assert ([IO.File]::ReadAllText($ready) -ceq $readyBefore) 'Isolation refusal changed the latest-ready fixture'
Pass 'Isolation failure releases source/runtime locks and leaves the previous ready fixture intact'
$databaseOnly = New-Source 'database only' -NoWal
$onlyOutput = & $prepare -SourceGame $databaseOnly
Assert (Test-Path -LiteralPath (Join-Path $onlyOutput 'bin/x64/Dawn/player-state.db')) 'Database-only progress was omitted'
Assert (-not (Test-Path -LiteralPath (Join-Path $onlyOutput 'bin/x64/Dawn/player-state.db-wal'))) 'An absent WAL was invented'
Pass 'A database without WAL is preserved'
$dual = New-Source 'dual DLL layout' -NoWal
Write-File (Join-Path $dual 'steam_api64.dll') 'old root Steam DLL'
Write-File (Join-Path $dual 'bin/x64/steam_api64.dll') 'old bin Steam DLL'
Write-File (Join-Path $dual 'Dawn/player-state.db') 'local root progress'
Write-File (Join-Path $dual 'Dawn/player-state.db-wal') 'pending root progress'
Write-File (Join-Path $dual 'Dawn/player-state.db-shm') 'omit transient root memory'
$dualBefore = Snapshot $dual
$dualOutput = & $prepare -SourceGame $dual
Assert ([IO.File]::ReadAllText((Join-Path $dualOutput 'Dawn/player-state.db')) -ceq 'local root progress') 'Root save was lost or moved'
Assert ([IO.File]::ReadAllText((Join-Path $dualOutput 'Dawn/player-state.db-wal')) -ceq 'pending root progress') 'Root WAL was lost or moved'
Assert ([IO.File]::ReadAllText((Join-Path $dualOutput 'bin/x64/Dawn/player-state.db')) -ceq 'local progress: dual DLL layout') 'Bin profile was overwritten by root profile'
Assert (-not (Test-Path -LiteralPath (Join-Path $dualOutput 'bin/x64/Dawn/player-state.db-wal'))) 'Root WAL was copied to the bin profile'
Assert (-not (Test-Path -LiteralPath (Join-Path $dualOutput 'Dawn/player-state.db-shm'))) 'Root SHM was copied'
foreach ($placement in @('.', 'bin/x64')) {
    $location = Join-Path $dualOutput $placement
    Assert ((Get-FileHash -LiteralPath (Join-Path $location 'steam_api64.dll') -Algorithm SHA256).Hash -ceq $hash) 'A fixture Steam DLL did not match the kit'
    $settings = Get-Content -LiteralPath (Join-Path $location 'Dawn/settings.json') -Raw | ConvertFrom-Json
    Assert ($settings.core.logging.levels.core -ceq 'info' -and $settings.core.logging.levels.client -ceq 'info' -and $settings.core.logging.levels.server -ceq 'info') 'A DLL placement is missing diagnostic logging'
}
Assert ((Snapshot $dual) -ceq $dualBefore) 'Preparing both runtimes changed the source'
Pass 'Dual layout keeps root and bin progress independent and enables companion logging beside both pinned DLLs'
$calls = Calls
$busy = [IO.File]::Open((Join-Path $dual 'Dawn/player-state.db-wal'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
try { Refuses { & $prepare -SourceGame $dual } '*progress is busy or cannot be locked*' }
finally { $busy.Dispose() }
Assert ((Calls) -ceq $calls) 'A busy root WAL allowed preparation'
Assert-Writable (Join-Path $dual 'bin/x64/Dawn/player-state.db')
Assert-Writable (Join-Path $dual 'Dawn/player-state.db')
Assert-Writable (Join-Path $dual 'Dawn/player-state.db-wal')
Pass 'A busy root WAL releases the already held bin and root database handles'
Remove-Item -LiteralPath $lockMarker
$busy = [IO.File]::Open((Join-Path $source 'bin/x64/Dawn/player-state.db'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
$global:NativePreflightPretendRunning = $true
try { $freshOutput = & $prepare -SourceGame $source -FreshProfile }
finally { $busy.Dispose(); $global:NativePreflightPretendRunning = $false }
$freshRecord = Get-Content -LiteralPath (Join-Path $freshOutput 'native-test-install.json') -Raw | ConvertFrom-Json
Assert ($freshRecord.playerState -ceq 'fresh' -and -not (Test-Path -LiteralPath (Join-Path $freshOutput 'bin/x64/Dawn/player-state.db'))) 'FreshProfile copied progress'
Pass 'FreshProfile ignores busy source progress and does not require a stopped game for save copying'
$bareArchive = New-Source 'bare archived game' -NoDatabase
Write-File (Join-Path $bareArchive 'steam_api64.dll') 'archived root Steam DLL'
$bareOutput = & $prepare -SourceGame $bareArchive
$bareRecord = Get-Content -LiteralPath (Join-Path $bareOutput 'native-test-install.json') -Raw | ConvertFrom-Json
Assert ($bareRecord.playerState -ceq 'fresh' -and -not (Test-Path -LiteralPath (Join-Path $bareOutput 'Dawn/player-state.db'))) 'A bare archived source should start a fresh profile'
Assert ((Get-FileHash -LiteralPath (Join-Path $bareOutput 'steam_api64.dll') -Algorithm SHA256).Hash -ceq $hash) 'The bare archive did not receive the pinned root DLL'
Pass 'A bare archived source with a root Steam DLL receives the fresh Dawn runtime'
$noDatabase = New-Source 'no database' -NoDatabase
$emptyOutput = & $prepare -SourceGame $noDatabase
$emptyRecord = Get-Content -LiteralPath (Join-Path $emptyOutput 'native-test-install.json') -Raw | ConvertFrom-Json
Assert ($emptyRecord.playerState -ceq 'fresh') 'Missing progress was not marked fresh'
Pass 'A source without a database creates a fresh fixture'
Remove-Item -LiteralPath $manifestPath
$calls = Calls
Refuses { & $prepare -SourceGame $noDatabase } '*Supply ExpectedRuntimeSha256*'
Assert ((Calls) -ceq $calls) 'A missing expected hash created a fixture'
$explicitOutput = & $prepare -SourceGame $noDatabase -DllPath $dll -ExpectedRuntimeSha256 $hash.ToLowerInvariant()
Assert (Test-Path -LiteralPath (Join-Path $explicitOutput 'native-test-install.json')) 'Explicit runtime/hash overrides failed'
Pass 'Explicit DLL/hash support checkout use without a kit manifest; missing hash refuses safely'
Assert ((Snapshot $source) -ceq $before) 'A refusal or fresh-profile operation changed source files'
Write-Host ('PASS native game preflight: ' + $script:passed + ' checks; no game copied or launched')
