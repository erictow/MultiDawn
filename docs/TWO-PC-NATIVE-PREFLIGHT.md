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
2. Close Destiny on that PC. Drag the existing Dawn game folder that contains
   `destiny2.exe` onto `Prepare-Test-Game.cmd`. You can also double-click the
   command and paste the folder path. The helper creates an isolated installation
   under `build/gameplay-tests/`, installs the kit's runtime there, and opens the
   launcher with the new test folder selected.
3. When available, the helper copies that PC's own closed local player database
   into the test install. The source save and settings remain unchanged. With
   no existing save, it creates a fresh profile. `-FreshProfile` explicitly
   skips the local save copy when invoking the PowerShell helper directly.
4. Use `Start-Native-Test.cmd` to reopen the launcher with this kit's latest
   prepared folder. Run preparation again to create a new test copy. Immutable
   package assets use local hard links to avoid another roughly 90 GB download.
   Never run a game updater against the isolated test directory, because those
   package files are shared.
5. Keep Steam running as required by your existing Dawn installation. Let each
   PC generate its own `%LOCALAPPDATA%/MultiDawn` identities. Do not copy
   `peer-id.txt` or `steam-id.txt` between PCs.

The preparation helper supports both the legacy `bin/x64` layout and an archived
installation with a root Steam DLL. Extract the kit on the game's drive so the
helper can share packages through hard links.

## Pair and launch

1. Use the launcher opened by preparation or run `Start-Native-Test.cmd` on
   both PCs. This enables **Launch native test**.
2. Confirm that the **Game Folder** box shows the prepared `session-...` folder,
   then enable Multiplayer.
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
out of reports. Open **Collect-Test-Log.cmd** in the extracted kit. Explorer
selects a ZIP containing the complete current `dawn.log`. Send the ZIP as
a file attachment. Its filename includes the kit commit so you can check that
both PCs used the same kit. While Destiny is running, the helper
uses the loaded test DLL. After exit, it checks the last prepared folder.
It checks the log's runtime hash against the kit in both cases.

For older kits, use Task Manager's **Details** tab. Right-click the running
`destiny2.exe`, choose **Open file location**, and look under
`bin/x64/Dawn/logs/` or `Dawn/logs/`. Preparation enables core, client and
server information logging in the test settings.

The launcher enables the existing bounded native session, identity and activity
traces in this explicit test launch. It does not enable the legacy unsafe probe
bundle. A native connection or a visible friend verifies that component only;
two Guardians seeing and moving together remains milestone 1's acceptance test.

### First two-PC run

On November 26, 2026, the `bc41f378` kit paired two PCs on the same LAN. Both
launchers saved their partner and reported both native game companions connected.
Each game loaded its own Tower. The host snapshot verified the pinned runtime
and zero remote gameplay peers. The host log recorded the initial spawn gate
allowing arrival. The guest reported a
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
`spawn_arrival`, and `tower_spawn_recovery` events on both PCs. The host's
`spawn_gate result=native_allowed` and `fly_in_complete` mark loader progress.
Check whether the Guardian is visible and responds to movement with the game
focused and the Dawn menu closed. An `ev=noclip stage=toggle` line indicates
that Dawn handled the key, while movement also requires a character physics
body. A comparison using Solo Play from the same isolated folder, character,
and landing zone can identify whether the symptom depends on pairing.

A development runtime running with `DAWN_ACTIVITY_BINDING_TRACE=1` also emits
`stage=tower_control` from existing Tower camera frame observations. This shows
whether the local game has a controlled entity, whether the runtime slot is
present, and whether the game reported readiness. It samples at most four
times per second and reports changes or a sustained missing entity, with at
most 64 records per DLL lifetime. It adds no native reads or recovery actions.

### Follow-up with the control trace

The `3447a492` kit displayed saved nicknames in the game roster. Invitations
produced Dawn's in-game accept and decline popup. Accepting reached the waiting
state in either direction. This build has no live activity handoff controller
to grant a shared fireteam. Dawn's `In game` label reflects a running game and
does not change when its player leaves the Tower. Destiny's roster still
received no live location.

Both logs show that the Tower loader finished and the engine reported an
allowed spawn gate and world state 3. On each PC the frame trace recorded
`controlled=0` and a present runtime slot with the loader idle and local
readiness set. The host also recorded noclip key toggles. The fly-in marker
therefore accompanies a completed world load on these runs, while the camera
frame still has no controlled Guardian.

The first supplied solo log reached the same Tower spawn gate and contained no
`tower_control` samples. In the matched `9b90b04a` comparison, the same host
fixture reached `controlled=1` 78 ms after fly-in in solo mode. In the paired
run, it stayed at `controlled=0` with loader idle, before any invite acceptance.
Both runs completed local address resolution. The successful solo run also
reattached the local replication connection as control became available.
The paired host later logged `accepted_ticket_verified`, confirming the
invitation reached the host after the spawn failure.

The paired test now keeps the same in-process Steam identity as solo for
the local player and loopback lobby. Pairing continues to use the launcher's
separate identity for friends and invitations.

### Paired run with local identity preserved

On November 27, 2026, both logs matched the runtime hash from the `f89bd0ad`
kit. The host reported `controlled=1` 47 ms after Tower fly-in. The guest
reported it 141 ms after fly-in and again after fast travel. Neither log
reported a sustained missing Guardian. The guest also verified an accepted
invite ticket. These observations confirm local Guardian control and invite
delivery in the same paired run. Shared membership and movement between the
two games remain unverified.

The guest's character screen displayed `Player` and three 1060 Human Male
characters. This matches the kit's default persona and character presentation.
If the source of a test profile is unclear, check `playerState` in that PC's
`native-test-install.json`. A value of `copied-local-offline` records that the
helper copied at least one database from the selected local install. For a
dual-layout install, check the database beside the DLL that produced the log.
The Friends roster can independently display the saved nickname for the
paired player.

For a controlled solo comparison, close the game and launcher on one PC after
saving its log. Run these commands in PowerShell from its extracted kit:

```powershell
$env:DAWN_ACTIVITY_BINDING_TRACE = '1'
$env:DAWN_NATIVE_ADDRESS_RESOLUTION = '1'
$env:DAWN_NATIVE_SESSION_TRACE = '1'
$env:DAWN_NATIVE_IDENTITY_OBSERVATION = '1'
Start-Process .\MultiDawn.Launcher.exe
```

Choose the same prepared folder and use **Play solo** with the same character
and landing point. This keeps the tracing settings and DLL matched while the
launcher omits the companion connection. Record whether control returns and
compare the `stage=tower_control` lines.

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
