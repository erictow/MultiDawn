# Two-PC native connection test

This test connects two running Dawn games to their paired MultiDawn launchers.
It checks the real native companion, presence and invitation path across the
LAN. Shared activities and remote Guardian movement remain unfinished;
multiplayer Play stays disabled. It does not pass the two-player milestone.

Start with this PC and one other PC. A third PC becomes useful after the
two-player milestone, for the three-player fireteam work.

## Prepare each PC

1. Use the same native LAN test ZIP on both PCs. Extract it on the same drive
   as that PC's separate Dawn game installation. Each PC needs the complete
   archived game build `86657.20.08.23.1800.d2_rc`; the ZIP contains no game files.
2. Close Destiny on that PC. Run `Prepare-Test-Game.cmd` and enter the existing
   local Dawn game folder when prompted. The helper creates a new isolated
   installation under the extracted kit's `build/gameplay-tests/` directory.
   It installs the kit's DLL and runtime content in that new directory only.
3. When available, the helper copies that PC's own closed local player database
   into the test install. The source save and settings remain unchanged. With
   no existing save, it creates a fresh profile. `-FreshProfile` explicitly
   skips the local save copy when invoking the PowerShell helper directly.
4. Keep the printed test-game folder path. Immutable package assets use local
   hard links to avoid another roughly 90 GB download. Never run a game updater
   against the isolated test directory, because those package files are shared.
5. Keep Steam running as required by your existing Dawn installation. Let each
   PC generate its own `%LOCALAPPDATA%/MultiDawn` identities. Do not copy
   `peer-id.txt` or `steam-id.txt` between PCs.

The preparation helper supports the existing `bin/x64` Dawn layout. A root Steam
DLL or a game on another drive is refused by the isolated-install helper. Move
the extracted kit to the game's drive rather than moving the game.

## Pair and launch

1. Run `Start-Native-Test.cmd` on both PCs. This enables a separate **Launch native
   test** control. Opening `MultiDawn.Launcher.exe` normally keeps the ordinary UI.
2. Select the newly prepared test-game folder before enabling Multiplayer.
3. On the host, enable Multiplayer, select its LAN IPv4 address and choose Host.
   On the other PC, enable Multiplayer, enter the host's current pair code and
   choose Join. Share pair codes privately.
4. Once paired, choose **Launch native test** on each PC. This starts each game
   with its local profile service and the exact current companion connection.
   The launcher verifies the fixture marker and pinned DLL before starting.
5. Leave the launchers open. Watch the test status for the local game connection
   and the other game's presence. Enter the Tower in each game when ready.
6. Check the Dawn Friends page for the paired identity. An invitation and its
   acceptance should remain an intent awaiting gameplay handoff. They do not
   place the two Guardians together yet.

Closing or disconnecting the launcher retires its companion connection. It does
not kill the game or migrate its profile. A reconnect requires a fresh test
launch; the game cannot silently attach to a replacement pairing.

The host's usual pairing port is TCP 30979. If Windows asks about access, use the
private-network option for the launcher. The account BAP service stays local;
this test does not expose it or change router settings.

## Record the result

Record both PCs' LAN IPv4 addresses, the kit's `sourceCommit`, whether each
launcher reports its native game connected, whether each game sees the paired
friend, and any error code. Keep pair codes, pipe nonces and account databases
out of reports. The isolated game's log is under `bin/x64/Dawn/logs/`; preparation
enables client/server information logging in the new test settings only.

The launcher enables the existing bounded native session, identity and activity
traces in this explicit test launch. It does not enable the legacy unsafe probe
bundle. A native connection or a visible friend verifies that component only;
two Guardians seeing and moving together remains milestone 1's acceptance test.

## Build a kit from source

Cloning is optional on the test PCs when using the compiled ZIP. Developers
should select the experimental branch explicitly:

```powershell
git clone --branch main --single-branch https://github.com/erictow/MultiDawn.git MultiDawn
```

Build the Release DLL and launcher from the same committed source, then run:

```powershell
.\tools\testing\New-NativeLanTestKit.ps1
```

The publisher refuses a dirty checkout and an existing output path. Its manifest
pins both binaries and the source commit. The kit includes only the compiled
components, isolated-install helpers, runtime content and licenses.
