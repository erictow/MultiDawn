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

## Exact wire dispatcher and schema

The later isolated capture in PID 36692 recovered the notification dispatcher
at `4F7DF0`. Its exact 21-row table at `1F92360` maps wire type 12 to the leaf
thunk `4F2830`, which forwards to `4F7240`. That thunk has no `.pdata` entry;
enumerating unwind records alone had missed the actual membership handler.
Known wire types 1 and 2 independently matched their established handlers.
The old probe names typeEight/typeNine actually identify wire types 19 and 24.

The type-12 handler uses schema owner global `1FA4180`, schema tag `808086A8`,
and a 365,152-byte decoded table aligned to eight bytes. Its generic decoding
path starts at `4C72E0`; owner offsets `10` and `18` contain metadata here, not
callable codec pointers. `3CD500` installs the table after the native owner's
eight-byte local-machine prefix. The authority call proceeds through `3BCF90`,
vtable slot `328`, `B42C80` and `16F0BA0`, producing engine event 29.

The recovered root fields 4, 5 and 6 occupy decoded offsets 365128, 365132 and
365136, exactly matching the two selection masks and separate activation mask
used below. The decoder starts from a copy of the prior table. Optional absence
therefore preserves prior field data; it does not generally reset a field.

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

The schema now identifies that skip byte as the low byte of member field 2's
stored leave value at record offset 10936. It is a signed five-bit value with
bias one. Wire value one stores logical zero and keeps the skip test clear.
The required B2 trailing boolean is a different field and is not this test.

At `17026F1..1702728`, the call passes the member index, the role predicate,
the 86-byte NetAddr at **member record + `142`**, an opaque argument at member
record + `1EE`, and the activation predicate. The opaque argument remains
unclassified and must not be logged or substituted from another identity.

`E22250` also compares the per-member byte at table + memberIndex * `2AC0` +
`2A91` with the native teleport command token. This confirms a per-member
synchronization comparison, not permission to copy one recipient's receipt
into every remote lane. Region-transition tokens form a separate domain.

## Recovered member detail

Member tag `808086AF` has size 10944. Its identity begins at offset zero, its
B1 detail begins at 48, and its optional leave value is at 10936. B1 begins with
B2 player state and places D4 synchronization at offset 10520.

| B2 field | Decoded offset in B2 | Wire form |
| --- | --- | --- |
| 0 | 0 | Six-bit connection flags; bit four gates a connection attempt. |
| 3 and 5 | 144 and 160 | Independent unsigned 64-bit identity scalars. Field5 remains unnamed. |
| 11 | 274 | 86 unsigned NetAddr bytes, at member record + `142`. |
| 13 | 446 | Fixed 64 signed bytes biased by `80`, at member record + `1EE`. Its contents remain unclassified. |
| 14 | 512 | Fourteen-bit byte count followed by unsigned bytes, capacity 10000. This establishes framing, not profile meaning. |
| 15 | 10516 | Required trailing boolean, separate from the member leave/skip value. |

Logical byte patterns in field 13 require XOR `80` on the wire. NetAddr and
profile bytes have no such bias. D4 field 3's synchronization token is at its
own offset 321; adding the table/member/B1 offsets gives the observed `2A91`.

## Encoder and remaining work

The runtime still supplies local human 0, optional control 1 and no additional
humans. With those inputs the emitted bytes remain identical. The encoder now
also accepts explicit additional-human inputs in stable slots 2 through 6;
[its contract](REMOTE-HUMAN-MEMBERSHIP.md) describes identity, opaque-field,
token, validation and size rules. This capability has no live handoff caller.

These selection conditions do not prove a visible Guardian or replication.
The wire dispatcher, member layout, profile byte-list framing, skip mapping
and opaque-field location are now established. The opaque field's meaning,
complete remote appearance/player properties and successful human connection
remain unverified. Actual type-23 field5 remains unnamed. The next runtime work
must use actual guest publications, exact grants and registered human routes.

Local evidence files from this run are `build/native-world-stack-4868.json`,
`build/native-group-code-4868-1702580.txt`, the matching `4DFxxx` / `4DD470`
code files, and `build/native-group-code-4868-E22250.txt`. They are ignored
diagnostic artifacts, not release inputs or evidence of two-player gameplay.
The later schema evidence is in PID-36692 `native-notification-dispatch`,
`native-type12-schema-header` and `native-type12-wire-*` JSON artifacts, also
ignored. Only schema metadata and bounded code were read; no live profile or
opaque connection contents were captured for these definitions.
