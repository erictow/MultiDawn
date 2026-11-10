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
| `--session 0xADDRESS` | A verified native session/manager address. Reports membership, current/succession/pending member, manager mode, and a sanitized migration-cache description. Repeat as needed. |
| `--fireteam-manager 0xADDRESS` | A separately verified native world manager, the value returned by `C03430`. The tool reads its primary index and selects `manager+0x18+primary*0x1C8A0`; it never calls the native function. |
| `--managed-definition 0xADDRESS` | A separately verified managed-session definition address. Reports role, enabled/pending flags, and sanitized current/pending descriptions. |

Addresses from previous runs are invalid. Group, session, world-manager, and
managed-definition addresses are different structures and are not interchangeable.
The existing replication observer supplies group addresses. The other options
require independently observed addresses; this tool does not discover them by
guessing, scanning memory, or activating the quarantined legacy probe bundle.

Output files must be new and their parent directory must exist. Exit code 0
means requested reads passed the tool's checks; exit code 2 indicates refusal or
a section error. Inspect the per-section stability fields even when the exit
code is 0. Two matching reads reduce inconsistent samples but do not make the
report an atomic snapshot. Rows with invalid lengths, indices, or back-pointers
are rejected. No raw memory dumps, security keys, opaque online identities, or
player profile bodies are written. Addresses, public machine/join identifiers,
and LAN endpoints remain in the report.

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
