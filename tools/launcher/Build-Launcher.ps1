#requires -Version 5.1
[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [switch] $RunTests
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'build/launcher' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/csc.exe' }
if (-not (Test-Path -LiteralPath $compiler)) { throw 'The Windows .NET Framework 4 C# compiler was not found.' }
[IO.Directory]::CreateDirectory($output) | Out-Null
$exe = Join-Path $output 'MultiDawn.Launcher.exe'
$sources = @((Join-Path $PSScriptRoot 'Program.cs'), (Join-Path $PSScriptRoot 'Pairing.cs'), (Join-Path $PSScriptRoot 'RuntimeBridge.cs'), (Join-Path $PSScriptRoot 'RuntimeBridgeTests.cs'), (Join-Path $PSScriptRoot 'NativeCompanionTest.cs'), (Join-Path $PSScriptRoot 'Friends.cs'), (Join-Path $PSScriptRoot 'FriendsTests.cs'))
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /out:$exe /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll $sources
if ($LASTEXITCODE -ne 0) { throw 'Launcher compilation failed.' }
if ($RunTests) {
    $report = Join-Path $output 'self-test-results.txt'
    $process = Start-Process -FilePath $exe -ArgumentList @('--self-test', ('"' + $report + '"')) -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'Launcher self-tests exceeded 60 seconds.' }
    if (Test-Path -LiteralPath $report) { Get-Content -LiteralPath $report }
    if ($process.ExitCode -ne 0) { throw "Launcher self-tests failed (exit $($process.ExitCode))." }
}
Write-Output "Built $exe"
