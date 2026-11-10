# MultiDawn launcher

`MultiDawn.Launcher.exe` is a portable Windows x64 app using the Windows .NET
Framework. It launches an already installed Dawn copy; it does not download game
files, install the DLL, or change saves and settings.

## Build

From the repository root:

```powershell
.\tools\launcher\Build-Launcher.ps1 -RunTests
```

The output is `build/launcher/MultiDawn.Launcher.exe`. Only that EXE is needed to
run the launcher. The game remains a separate installation. Publisher bundles
can include it alongside the existing Dawn installer.

## Solo Play

Select the folder containing your separate Dawn `destiny2.exe`. Source builds
also look for `expectedOutput/Destiny 2 Dawn` within two parent folders. A
portable EXE beside `destiny2.exe` detects that game folder directly. Browse
always lets you select another separate installation.

Play validates build `86657.20.08.23.1800.d2_rc`, the installed Dawn DLLs,
settings, and existence of the packages folder. Legacy installations with the
Dawn runtime only in `bin/x64` are supported. If a root `steam_api64.dll` exists,
it must also identify as Dawn and have its matching settings. Each installed
`client.external_server.enabled` value must be false. The
launcher reports configuration conflicts without changing the files. It starts
the game in its own folder, watches only the process it starts, and never kills
another game or server process. Closing the launcher leaves a solo game running.
The only saved preference is the folder path under `%LOCALAPPDATA%/MultiDawn`.
The child environment includes `DAWN_FOREST_BASELINE=1`, matching the existing
`launch-destiny.cmd` normal launch behavior.

## Host and Join pairing preview

The Multiplayer switch opens an actual two-person pairing lobby. It does **not**
enable multiplayer gameplay. This fork still needs native player replication,
shared activity authority, per-player server state, friends, invites, and game
notifications. MP Play is disabled until those systems exist. No remote server
handoff or local server shutdown is attempted.

1. Both people enable Multiplayer. The game folder is then locked.
2. The host selects the IPv4 address reachable by their partner, then Host.
3. Share the generated pair code privately. The partner pastes it and uses Join.
4. Disconnect closes the connection and listener. A host remains available when
   a partner disconnects, until the host chooses Disconnect.

Use the same LAN or a VPN that provides reachable IPv4 addresses. The default
TCP port is 30979; allow that port through the host firewall if needed. Pairing
does not configure firewall rules, router forwarding, NAT traversal, a relay, or
Internet discovery. A pair code encodes the selected endpoint and a random
128-bit bearer token. It is not a globally registered short ID.

Pairing uses plain TCP with a versioned handshake, mutual HMAC authentication,
fresh nonces, timeouts, one authenticated partner, and heartbeat checks. The
bearer token is never sent over the connection. Session traffic is unencrypted,
so use a trusted LAN or encrypted VPN. Keep the code private; it grants access
to the lobby. Codes are not saved or written to logs. The checksum detects
typing mistakes; it is not encryption.

## Verification

`-RunTests` exercises code parsing, loopback TCP pairing and disconnect behavior,
plus solo validation and process environment isolation. Tests do not launch
Destiny 2 or prove gameplay compatibility.

Capture the form without starting the game:

```powershell
$p = Start-Process .\build\launcher\MultiDawn.Launcher.exe `
  -ArgumentList '--capture-preview', 'C:\Temp\launcher.png' -PassThru -WindowStyle Hidden
$p.WaitForExit()
```

Validate a real installation without starting the game or changing its files:

```powershell
$p = Start-Process .\build\launcher\MultiDawn.Launcher.exe `
  -ArgumentList '--validate-install', '"D:\Games\Destiny 2 Dawn"', '"C:\Temp\validation.txt"' `
  -PassThru -WindowStyle Hidden
$p.WaitForExit()
Get-Content C:\Temp\validation.txt
```

The validation command exits 0 for an eligible installation and 1 for a failed
check. It checks metadata and configuration, not the contents of all game
packages or successful in-game behavior.

Test the pairing transport through an address assigned to the current PC:

```powershell
.\tools\launcher\Test-LanPairing.ps1 -Address '192.168.1.124'
```

This creates two local test peers, checks mutual authentication and heartbeat,
and closes both connections. It does not verify reachability from a second PC.
Use your own PC's LAN address when running the check on another computer.

Reserved `DAWN_SESSION_*` variables are removed from the solo child environment,
then `DAWN_SESSION_MODE=solo` is set for a future explicit launch contract. The
current Dawn DLL does not consume that variable. No MP variables are passed.
A future gameplay implementation needs a real authenticated runtime
contract rather than trusting a launcher flag or a capability text file.
