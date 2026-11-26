# Two-PC native connection test

This test connects two running Dawn games to their paired MultiDawn launchers.
It checks the real native companion, presence and invitation path across the
LAN. Shared activities and remote Guardian movement remain unfinished;
multiplayer Play stays disabled. It does not pass the two-player milestone.

Start with this PC and one other PC. A third PC becomes useful after the
two-player milestone, for the three-player fireteam work.

## Prepare each PC

1. Use the same native LAN test ZIP on both PCs. Extract it on the same drive
   as that PC's separate game installation. Each PC needs the complete archived
   game build `86657.20.08.23.1800.d2_rc`. The kit supplies the matching Dawn
   runtime, so there is no separate Dawn or Sunrise installation step.
2. Close Destiny on that PC. Run `Prepare-Test-Game.cmd` and enter the existing
   local archived game folder when prompted. The helper creates a new isolated
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

The preparation helper supports both the legacy `bin/x64` layout and an archived
installation with a root Steam DLL. Extract the kit on the game's drive so the
helper can share packages through hard links.

## Pair and launch

1. Run `Start-Native-Test.cmd` on both PCs. This enables a separate **Launch native
   test** control. Opening `MultiDawn.Launcher.exe` normally keeps the ordinary UI.
2. Select the newly prepared test-game folder before enabling Multiplayer.
3. On the host, enable Multiplayer, select its LAN IPv4 address and choose Host.
   On the other PC, enable Multiplayer, enter the host's current pair code and
   choose Join. Share pair codes privately.
4. Once paired, choose **Launch native test** near the bottom of each launcher.
   Scroll down if needed. This starts each game
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
out of reports. Look for the log under `bin/x64/Dawn/logs/` or `Dawn/logs/`, next
to the loaded runtime. Preparation enables core, client and server information
logging in the test settings.

The launcher enables the existing bounded native session, identity and activity
traces in this explicit test launch. It does not enable the legacy unsafe probe
bundle. A native connection or a visible friend verifies that component only;
two Guardians seeing and moving together remains milestone 1's acceptance test.

### First two-PC run

On November 26, 2026, the `bc41f378` kit paired two PCs on the same LAN. Both
launchers saved their partner and reported both native game companions connected.
Each game loaded its own Tower. The host snapshot verified the pinned runtime,
normal spawn completion, and zero remote gameplay peers. The guest reported a
frozen camera outside the Tower wall even after fast travel. Camera input and
Dawn's noclip and forward movement controls had no visible effect. The same
Courtyard wall view was later reported on the host.

The left landing point near Bazaar showed a static view over the exterior
wall, with mostly sky. Choosing Courtyard fast travel on the right switched
the Director briefly to its orbit view. A Courtyard arrival notification then
appeared and the camera showed a closer exterior wall view. Control remained
unavailable in both locations. The change in view and arrival notification
establish travel feedback. Both logs confirm Tower world entry and a completed
native teleportation. The guest completed transitions between slices 48 and 0
and back. Both reached the initial spawn gate. Neither log provides a positive
controlled-Guardian observation after the affected travel. A completed teleport
does not establish that the Guardian became controllable.

The host's in-game roster showed `1 Friend Online`, with the paired peer in
**Friends** and only the local player in **Game**. The guest's Director also
showed `1 Friend Online`. The roster listed the connected peer as `Player` and
displayed `In Orbit`. The kit's default persona is `Player`, and the connection
currently publishes whether the peer's game is running, with no live activity
location.
Use the guest's own Tower log to verify the activity and spawn. The roster's
orbit label cannot distinguish the two.

The updated launcher uses a printable ASCII nickname saved for the exact paired
identity in the local in-game roster. The nickname stays on that PC. If there
is no matching nickname, the game sees the peer's advertised persona.

If the camera problem appears again, capture the affected game's log before
relaunching. Compare the `spawn_hold_loader`, `spawn_gate`, `fly_in_complete`,
`spawn_arrival`, and `tower_spawn_recovery` events with the host's normal
`spawn_gate result=native_allowed` and `fly_in_complete`. Check whether the
Guardian is visible and responds to movement with the game focused and the Dawn
menu closed. An `ev=noclip stage=toggle` line indicates that Dawn handled the
key, while actual movement also requires a character physics body. A comparison
using Solo Play from the same isolated folder, character, and landing zone can
help narrow down whether the symptom is specific to the paired test launch.

A development runtime running with `DAWN_ACTIVITY_BINDING_TRACE=1` also emits
`stage=tower_control` from existing Tower camera frame observations. This shows
whether the local game has a controlled entity, whether the runtime slot is
present, and whether the game reported readiness. It samples at most four
times per second and reports changes or a sustained missing entity, with at
most 64 records per DLL lifetime. It adds no native reads or recovery actions.

## Build a kit from source

The compiled ZIP works without a clone on the test PCs. To build from source,
clone `production`:

```powershell
git clone --branch production --single-branch https://github.com/erictow/MultiDawn.git MultiDawn
```

Build the Release DLL and launcher from the same committed source, then run:

```powershell
.\tools\testing\New-NativeLanTestKit.ps1
```

The publisher refuses a dirty checkout and an existing output path. Its manifest
pins both binaries and the source commit. The kit includes only the compiled
components, isolated-install helpers, runtime content and licenses.
