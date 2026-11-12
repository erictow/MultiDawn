# Native multiplayer evidence capture

`multiplayer_runtime_snapshot.py` reads an already running, separate test copy of
Destiny build `86657.20.08.23.1800.d2_rc`. It does not launch the game, change
process memory, install hooks, suspend threads, or change settings/saves. It
opens the specified PID with `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.

Use 64-bit Python 3.11 or later. The executable path is explicit and must match
the running PID. The tool verifies the executable's exact Windows FileVersion,
the loaded AMD64 PE header, and three known native code signatures before
interpreting any gameplay layout. It records the executable SHA256 and the
loaded `steam_api64.dll` paths/SHA256 values for provenance. A signature mismatch
produces a report with `layout_verified: false` and no interpreted gameplay data.
There is no override for an unsupported build or a modified signature.

To prepare a disposable installation with the local development DLL:

```powershell
.\tools\testing\New-IsolatedDawnTestInstall.ps1 `
  -SourceGame 'expectedOutput/Destiny 2 Dawn' `
  -DllPath 'build/portable/Dawn/Release/artifacts/steam_api64.dll'
```

It returns a new path under `build/gameplay-tests/`. Executables and runtime
files are copied; settings start from this checkout's defaults and no existing
save is copied. Only immutable `.pkg` files use hard links to avoid duplicating
roughly 98 GB. Never run a game updater against this test folder because those
package files are shared. The tool neither launches the game nor changes the
original installation. Start the test executable with `DAWN_FOREST_BASELINE=1`
and `DAWN_SESSION_MODE=solo` in its child environment. For connection evidence,
set the test settings' `core.logging.levels.client` and `server` to `info`
before launch; default warning-level logging omits those diagnostic events.

Run from the repository root, supplying the PID of the isolated test copy:

```powershell
python tools/testing/multiplayer_runtime_snapshot.py --pid 12345 `
  --game-exe 'C:\path\to\isolated-test\destiny2.exe' `
  --output build/runtime-snapshot-01.json
```

That invocation verifies the runtime only. To capture gameplay structures, add
addresses observed in **that same running process**:

| Option | Address source and reported evidence |
| --- | --- |
| `--group 0xADDRESS` | The `group=` field in the current game's `ev=native_replication stage=connect` or `facet_add` log. Reports native peer identities, member indices, facet ownership, and handle mappings. Repeat for each group. |
| `--session 0xADDRESS` | The `manager=` field in an opt-in `ev=native_session stage=manager_update` event, or another independently verified native session address. Reports membership, current/succession/pending member, manager mode, and a sanitized migration-cache description. Repeat as needed. |
| `--fireteam-manager 0xADDRESS` | A separately verified native world manager, the value returned by `C03430`. The tool reads its primary index and selects `manager+0x18+primary*0x1C8A0`; it never calls the native function. |
| `--managed-definition 0xADDRESS` | A non-null `definition=` field in the same opt-in event, or another independently verified managed-session definition address. Reports role, enabled/pending flags, and sanitized current/pending descriptions. |

Addresses from previous runs are invalid. Group, session, world-manager, and
managed-definition addresses are different structures and are not interchangeable.
The existing replication observer supplies group addresses. Session and definition
addresses can come from the optional trace below. The fireteam world manager
requires an independently observed address; this tool does not discover it by
guessing, scanning memory, or activating the quarantined legacy probe bundle.

For a future isolated launch with the rebuilt development DLL, set
`DAWN_NATIVE_SESSION_TRACE=1` in the game's child environment and set
`core.logging.levels.client` to `info` in the test settings. The environment value
must be exactly `1`; it is read once during hook installation. Changing the
environment after startup does not enable the trace in an existing game.
The trace reuses the normal manager-update hook's existing snapshots; it adds no
detours, game-memory reads, game function calls, or game-memory writes. It does
not enable the legacy probe bundle.

`ev=native_session stage=manager_update` records only the process `pid`, `manager`,
`mode`, the numeric `identity` index, and `definition`. Only use events matching
the running test PID. The `manager` field is a session pointer for
`--session`, **not** the world-manager pointer for `--fireteam-manager`. Null
definitions and identity `-1` can occur before initialization. A fixed cache tracks
up to 32 manager addresses and logs their first observation or a change in those
four fields, with a total limit of 128 events per loaded DLL lifetime. A busy
trace lock skips that update instead of blocking the game thread. If the trace
reaches its limit, a new isolated launch is needed for more events. These events
locate structures for the read-only snapshot tool; they do not establish a peer
connection or working gameplay replication.

Use `--trace-log` to select the latest initialized session/definition addresses
from records matching the requested PID, rather than copying hexadecimal
addresses by hand:

```powershell
python tools/testing/multiplayer_runtime_snapshot.py --pid 12345 `
  --game-exe 'C:\path\to\isolated-test\destiny2.exe' `
  --trace-log 'C:\path\to\isolated-test\bin\x64\Dawn\logs\dawn.log' `
  --output build/runtime-session-snapshot.json
```

The reader accepts Windows `%p` hexadecimal formatting, skips other PIDs, drops
retired observations, and refuses missing or excessive initialized sessions.
Log input is bounded to 32 MiB; session and definition lists each remain bounded
to 16 entries. Existing explicit address options can be combined with the trace.

Add `--native-players` to a session/trace capture to include public native player
IDs and their owning membership slots. This reads only each player's 25-byte
identity/ownership prefix. Counts, masks, unique nonzero IDs, member ownership,
and the supported one-local-player index must agree before any player result is
reported. The remaining player configuration is not read. This is an opt-in
observation of the native table, not a Steam-ID or character-SOID substitute and
not permission to admit a player to a host. Inspect `player_header_stable` along
with `membership_header_stable`; neither makes the sample atomic.

Output files must be new and their parent directory must exist. Exit code 0
means requested reads passed the tool's checks; exit code 2 indicates refusal or
a section error. Inspect the per-section stability fields even when the exit
code is 0. Two matching reads reduce inconsistent samples but do not make the
report an atomic snapshot. Rows with invalid lengths, indices, or back-pointers
are rejected. No raw memory dumps, security keys, opaque online identities, or
player profile bodies are written. Public machine/join identifiers and direct-IP
LAN endpoints remain in the report. Steam-format NetAddr methods 6/7 report only
their transport method and presence; their opaque bytes are never decoded as IP
addresses or included in the report.

The evidence can establish whether an actual human peer has a native connection
and facet ownership, and whether the manager is in its documented authority
state range. It cannot establish movement, weapons, damage, invite acceptance,
or a working two-player session. Compare host and guest captures from the same
activity and correlate them with the corresponding native logs and visible
gameplay before drawing those conclusions.

## Layout sources

- `Dawn/src/client/hooks/bootflow/native_replication_observer.cpp`: group+0x270,
  peer/view back-pointers and identity fields.
- `tools/testing/native_actor_snapshot.py`: facet mapping/ownership tables.
- `Dawn/src/middleware/gameplay/group/session_state.cpp`: applied membership
  fields. The native session stores this replica at +0x868, corroborated by
  the handoff consumer's current/selected fields (+0x874/+0x87C), member NetAddr
  (+0x8B0), and peer state table (+0x1FB8).
- `Dawn/src/client/hooks/bootflow/activity_script_upstream_probe.cpp`: pinned
  code signatures, session controls, cached kind-22 description (+0x1AF04),
  managed current/pending descriptions (+0x57C/+0x94E), and flags (+0x94C).
  This file is a layout reference only. Its legacy hooks remain disabled.
- `Dawn/src/middleware/gameplay/group/session_messages.h`: kind-22 description
  shape. Removing its leading session ID leaves machine ID, 86-byte NetAddr,
  16-byte security identity and 18-byte online identity. The last two are reduced
  to presence flags in reports.
- `Dawn/src/client/hooks/bootflow/omega_activity_handoff.inl` and
  `Dawn/docs/NATIVE-ACTIVITY-HANDOFF-EVIDENCE.md`: primary fireteam selection and
  native authority states 6 through 9.

Offline verification does not open a game process:

```powershell
python -m unittest discover -s tools/testing -p test_multiplayer_runtime_snapshot.py -v
python tools/testing/multiplayer_runtime_snapshot.py --help
```

Fixtures cover table layouts, state-range classification, back-pointer checks,
unstable reads, invalid counts/ranges, and omission of known secret test bytes.
