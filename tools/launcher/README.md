# MultiDawn launcher

`MultiDawn.Launcher.exe` is a portable Windows x64 app using the Windows .NET
Framework. It launches an already installed Dawn copy; it does not download game
files, install the DLL, or change saves and settings.

Launcher 0.5 uses the `MD3` connection protocol with encrypted, authenticated
control frames. Pair codes retain their `MD2-` format. Both people need launcher
0.5 or later; older connection handshakes are rejected before pairing. The
native companion pipe still uses its separate invitation protocol versions.

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
The saved folder path lives under `%LOCALAPPDATA%/MultiDawn`. Creating a pairing
bridge also creates `steam-id.txt` there once, so each device retains its own
distinct native social identity. This file does not change a Dawn save.
The child environment includes `DAWN_FOREST_BASELINE=1`, matching the existing
`launch-destiny.cmd` normal launch behavior.

## Host and Join pairing preview

The Multiplayer switch opens an actual two-person pairing lobby. It does **not**
enable multiplayer gameplay. Native player replication and shared activity
authority still need implementation and verification. MP Play stays disabled.
No remote account-server handoff or local server shutdown is attempted.

1. Both people enable Multiplayer. The game folder is then locked.
2. The host selects the IPv4 address reachable by their partner, then Host.
3. Share the generated pair code privately. The partner pastes it and uses Join.
4. Disconnect closes the connection and listener. A host remains available when
   a partner disconnects, until the host chooses Disconnect.

### Saved MultiDawn friends and manual addresses

After pairing, enter a nickname and select **Save paired partner**. This saves
the authenticated launcher's stable identity, nickname, last reachable IPv4
address, and advertised hosting port. Select a saved friend before joining to
prefill the optional destination fields and require that same authenticated
launcher identity. A mismatch stops the join before admission; there is no
automatic fallback to an unpinned connection.

Paste the host's **current pair code** every time. Friend records contain no
pair codes, tokens, or companion credentials. Restarting the hosting lobby
creates a new token, so an old code will fail even when the saved address and
identity are correct. If a friend's address or hosting port changes, edit the
join override fields while keeping that friend selected, then save the paired
partner again after connecting.

The **Join IPv4 override** and **Join port** fields can also be used without a
saved friend. Leave either field blank to use that value from the current pair
code. Overrides change the destination only; both sides still perform the same
pair-code HMAC authentication. An IP address alone cannot join a lobby. The
host's address and pairing-port controls remain separate from these join fields.

Friends are stored in `%LOCALAPPDATA%/MultiDawn/friends.json`, with a maximum of
64 friends and 64 characters per nickname. Saves replace the file atomically.
Invalid or corrupt files are preserved and saving is disabled until they can
be read. The launcher's own stable identity lives in `peer-id.txt` beside it;
keep that file when moving the launcher to preserve existing friend pins. This
identity is separate from `steam-id.txt`, which is used by the native social
companion. Removing a saved friend removes only that local record.

This list contains MultiDawn friends added after pairing. It does not import a
Steam friends list, contact Steam, or require a new Steam login. It does not
change how the separately installed game uses Steam.

Use the same LAN or a VPN that provides reachable IPv4 addresses. The default
TCP port is 30979; allow that port through the host firewall if needed. Pairing
does not configure firewall rules, router forwarding, NAT traversal, a relay, or
Internet discovery. A pair code encodes the selected endpoint and a random
128-bit bearer token. It is not a globally registered short ID.
VPN addresses such as `25.x.x.x` and `100.64.x.x` are accepted when the network
provides connectivity. Saving an address does not make an otherwise unreachable
PC reachable.

Pairing uses TCP with a versioned handshake, mutual HMAC authentication, fresh
nonces, timeouts, one authenticated partner, and heartbeat checks. The bearer
token is never sent over the connection. Every post-handshake frame is encrypted
and authenticated, including social controls, endpoint announcements and
heartbeats. Separate directional keys and sequence numbers reject modification,
replay and frames from another connection. There is no plaintext fallback.
Keep the code private; it grants access to the lobby. Codes are not saved or
written to logs. The code checksum detects typing mistakes; it is not encryption.
See [the control transport](../../docs/PROTECTED-PAIRING-CONTROL.md) for its scope.

## Verification

`-RunTests` exercises code parsing, loopback TCP pairing and disconnect behavior,
solo validation, process environment isolation, and the native companion pipe
protocol through two fake native consumers. These tests do not launch Destiny 2
or prove gameplay compatibility.
Saved-friend tests also exercise bounded/corrupt-file handling, atomic-write
failure, persistent identity, actual TCP destination overrides, rejected host
identity pins, and rejection of stale tokens and IP-only joins.

## Native social companion

This source branch adds bounded social control messages to an authenticated
pair. An optional named pipe connects a newly built native runtime to its local
launcher. The pipe permits the current Windows user and denies network logons;
the runtime verifies the launcher PID and a per-bridge nonce before publishing
the paired identity. The launcher checks invitation sender and recipient IDs,
and distinguishes a connected launcher from a connected native game consumer.

The native companion does not forward account or gameplay packets. Its supplied
environment uses `DAWN_SESSION_MODE=solo`; it does not assert that a shared native
world exists. The current installed Dawn 1.7.2 binary has no companion support.
Normal UI Play therefore remains solo, and MP Play remains unavailable while
the gameplay path is incomplete. Native source and C# pipe tests are separate
from an in-game friend-roster or party-invitation test.

After building the standalone `Dawn/unit/companion_bridge_harness.vcxproj`, test
the actual C++ companion across two disposable native workers:

```powershell
$p = Start-Process .\build\launcher\MultiDawn.Launcher.exe `
  -ArgumentList '--native-companion-test', '"C:\Path\companion_bridge_harness.exe"', '"C:\Temp\native-pipe-test.txt"' `
  -PassThru -WindowStyle Hidden
$p.WaitForExit()
Get-Content C:\Temp\native-pipe-test.txt
```

The workers have a 25-second execution deadline and use the actual pipe client,
separate identities, and invitations. They do not load Destiny or a game DLL.

Launcher 0.4 and later request native companion protocol 2. Invitation tickets expire
after 60 seconds and bind both native runtime instances and the current pairing.
Acceptance reports an intent to the host and waits for authorization. It does
not queue a game join callback or grant access to a shared world. Protocol 2
requires another protocol 2 runtime for invitations; legacy invitations cannot
bypass that waiting state. See [the protocol contract](../../docs/INVITATION-CONTROL-V2.md).

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

Reserved `DAWN_SESSION_*` and `DAWN_COMPANION_*` variables are removed from an
ordinary solo child environment, then `DAWN_SESSION_MODE=solo` is set. Explicit
native-social preflight can add pipe credentials to that isolated child only.
A gameplay implementation still needs a verified native session contract.
