#requires -Version 5.1
<# Package integration tests. Uses a disposable fake Dawn DLL; never runs a game. #>
[CmdletBinding()]
param([string] $LauncherPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
if (-not $LauncherPath) { $LauncherPath = Join-Path $repo 'build/launcher/MultiDawn.Launcher.exe' }
$fixture = Join-Path $repo ('build/launcher-package-tests/' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixture) | Out-Null
$beforeHash = (Get-FileHash -LiteralPath $LauncherPath -Algorithm SHA256).Hash
$standalone = Join-Path $fixture 'standalone'
$null = & (Join-Path $repo 'tools/install/New-MultiDawnLauncherRelease.ps1') `
    -Release 'package-test' -LauncherPath $LauncherPath -OutputDirectory $standalone
function Check([bool] $Passed, [string] $Message) {
    if (-not $Passed) { throw "FAIL: $Message" }
    Write-Host "PASS: $Message"
}
function Reject([scriptblock] $Action, [string] $Pattern) {
    $message = $null
    try { & $Action | Out-Null } catch { $message = $_.Exception.Message }
    Check ($null -ne $message -and $message -like $Pattern) "Rejected: $Pattern"
}
$manifestText = [IO.File]::ReadAllText((Join-Path $standalone 'launcher-release.json'))
$manifest = $manifestText | ConvertFrom-Json
Check ($manifest.capabilities.launcherPairing -and -not $manifest.capabilities.gameplayMultiplayer -and
    -not $manifest.capabilities.inGameFriends) 'Manifest distinguishes pairing from gameplay and friends'
Check ($manifestText -notmatch [regex]::Escape($repo)) 'Manifest contains no local workspace paths'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($standalone + '.zip')
try {
    $expected = @('Launch-MultiDawn.cmd', 'LICENSE', 'MultiDawn.Launcher.exe', 'READ-ME-MultiDawn.txt', 'launcher-release.json')
    $actual = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
    Check (($actual -join '|') -ceq (($expected | Sort-Object) -join '|')) 'ZIP contains exactly the portable launcher bundle'
    foreach ($entry in $manifest.files) {
        $packed = $archive.GetEntry($entry.path)
        Check ($null -ne $packed -and $packed.Length -eq $entry.size) "Archive size: $($entry.path)"
        $stream = $packed.Open()
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $stream.Dispose(); $sha.Dispose() }
        Check ($hash -ceq $entry.sha256) "Archive hash: $($entry.path)"
    }
} finally { $archive.Dispose() }
Reject {
    & (Join-Path $repo 'tools/install/New-MultiDawnLauncherRelease.ps1') `
        -Release 'package-test' -LauncherPath $LauncherPath -OutputDirectory $standalone
} '*Output already exists*'
$invalidExe = Join-Path $fixture 'not-a-launcher.exe'
[IO.File]::WriteAllText($invalidExe, 'invalid fixture')
Reject {
    & (Join-Path $repo 'tools/install/New-MultiDawnLauncherRelease.ps1') `
        -Release 'bad-input' -LauncherPath $invalidExe -OutputDirectory (Join-Path $fixture 'invalid')
} '*Release MultiDawn Launcher*'
Check (-not (Test-Path -LiteralPath (Join-Path $fixture 'invalid'))) 'Invalid launcher rejected before output creation'

# A metadata-only DLL isolates packaging tests from any installed game/runtime.
$fixtureSource = Join-Path $fixture 'FakeDawn.cs'
[IO.File]::WriteAllText($fixtureSource, '[assembly: System.Reflection.AssemblyProduct("Dawn")] public class FakeDawn {}')
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/csc.exe' }
$fakeDll = Join-Path $fixture 'steam_api64.dll'
& $compiler /nologo /target:library /optimize+ /out:$fakeDll $fixtureSource
if ($LASTEXITCODE -ne 0) { throw 'Could not compile the metadata-only packaging fixture.' }
$combined = Join-Path $fixture 'combined'
$null = & (Join-Path $repo 'tools/install/New-DawnRelease.ps1') -Release 'combined-test' `
    -DllPath $fakeDll -LauncherPath $LauncherPath -OutputDirectory $combined
$runtimeManifest = Get-Content -LiteralPath (Join-Path $combined 'release.json') -Raw | ConvertFrom-Json
Check ((Test-Path -LiteralPath (Join-Path $combined 'MultiDawn.Launcher.exe')) -and
    (Test-Path -LiteralPath (Join-Path $combined 'Launch-MultiDawn.cmd'))) 'Runtime bundle includes the optional launcher beside the installer'
Check (@($runtimeManifest.files | Where-Object { $_.path -like '*Launcher*' }).Count -eq 0) 'Launcher stays outside the installed game payload'
Check ($runtimeManifest.files.Count -gt 10 -and (Test-Path -LiteralPath (Join-Path $combined 'payload/steam_api64.dll'))) 'Runtime payload contract remains present'
Check ((Get-FileHash -LiteralPath $LauncherPath -Algorithm SHA256).Hash -ceq $beforeHash) 'Packaging preserves its launcher input'
Write-Host 'PASS: standalone and optional runtime launcher packaging. No game was launched.'
