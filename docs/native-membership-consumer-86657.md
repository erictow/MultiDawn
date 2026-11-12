# Native membership consumer, build 86657

The native world-peer synchronizer is RVA `1702580`. This was established in
the isolated Tower run PID4868 through the existing connection hook at
`1703910`, with `DAWN_ACTIVITY_BINDING_TRACE=1`. No unsafe diagnostic bundle,
native calls, target writes, stack-body reads, or profile-body reads were used.
The read-only code probes verified all three supported-build signatures.

The captured return chain begins `170272D,170983B,16F674B`. PE exception-directory
binary search identifies chained ranges beginning `1702595,1709819,16F673C`;
the decoded call instructions establish the full entries `1702580,1709800`.
`1709800` ticks the world group and calls the synchronizer. Its table comes
from `4F5800` (client + `6C30`) plus eight bytes.

## Connection selection

Offsets below are relative to the table passed to the `4DFxxx` getters.
Member records begin at table + 8 and have stride `2AC0` (10,944 bytes).

| Native code | Observed operation |
| --- | --- |
| `4DF470` | Returns the 32-bit mask at table + `59248` (mask0). |
| `4DF480`, `4DF4B0` | Enumerate set bits in table + `5924C` (mask1). |
| `4DF500` | Returns table + 8 + memberIndex * `2AC0`. |
| `3CB2F0` -> `4DD640` | Finds the local member by matching its machine key. |
| `4DF600` | Tests the byte at table + (memberIndex + 1) * `2AC0`. |
| `4DD470` | Tests bit four of the byte at table + memberIndex * `2AC0` + `38`. |
| `4DF620` | Compares identity.field1 as unsigned with `1FF`; passes the result as the role argument. |
| `4DF650` | Reads the selected bit from a third mask at table + `59250`, used as the activation argument. |

`1702580` considers a non-local member for `1703910` only when both mask0 and
mask1 include that member, the `4DF600` skip byte is clear, and detail bit four
is set. The activation mask does not replace either selection mask. Field1
supplies a separate role argument; it is not the skip byte.

At `17026F1..1702728`, the call passes the member index, the role predicate,
the 86-byte NetAddr at **member record + `142`**, an opaque argument at member
record + `1EE`, and the activation predicate. The opaque argument remains
unclassified and must not be logged or substituted from another identity.

`E22250` also compares the per-member byte at table + memberIndex * `2AC0` +
`2A91` with the native teleport command token. This confirms a per-member
synchronization comparison, not permission to copy one recipient's receipt
into every remote lane. Region-transition tokens form a separate domain.

## Current encoder and remaining proof

The production encoder still emits local human0, optional embedded control1,
and absent slots2..31. Its two present top-level masks remain1 or3; the third
mask is absent. This change preserves those bytes and does not publish humans.
The contract tests decode the production writer output to check its identity,
connection gate, address, masks, and absent member tail against these facts.

These selection conditions do not prove a visible Guardian or replication.
The actual type12 BAP schema/dispatcher linkage, the human detail14/profile
body, the separate skip byte's wire mapping, the opaque connection argument,
and remote appearance/property linkage remain unverified. Actual type23
field5 also remains unnamed; preserve its raw published value. An additional
human writer must wait for that proof and actual guest publications.

Local evidence files from this run are `build/native-world-stack-4868.json`,
`build/native-group-code-4868-1702580.txt`, the matching `4DFxxx` / `4DD470`
code files, and `build/native-group-code-4868-E22250.txt`. They are ignored
diagnostic artifacts, not release inputs or evidence of two-player gameplay.
