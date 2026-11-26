# Additional-human BAP membership encoding

The type-12 BAP membership encoder can now represent the local human, a
non-player control host and up to five additional humans. This is an offline
codec capability. Normal runtime callers still supply no additional humans;
no remote Guardian, activity handoff or gameplay relay is activated.

The [build-86657 schema recovery](native-membership-consumer-86657.md) establishes
the dispatcher, nested field types and native connection-selection conditions.
The implementation is in `replicate_membership.h` and the three
`activity_*membership*` writers under `Dawn/src/middleware/bap/activity_message/`.

## Stable slots and masks

| Native slot | Source |
| --- | --- |
| 0 | This recipient's actual local identity. |
| 1 | The optional non-player control host. |
| 2 through 6 | `remoteHumans[0]` through `remoteHumans[4]`. |
| 7 through 31 | Absent. |

`remoteHumanCount` is the reserved array extent, not the number of active
humans. It is bounded to five. A present entry beyond the extent is invalid.
An extent greater than zero requires the control host, including when all
reserved entries are currently absent. Removing one entry leaves the other
native slot numbers unchanged. Absent entries emit three absent member fields
and are excluded from both root selection masks.

The separate activation mask remains omitted, preserving its prior native
value. The codec does not declare native activation or supply a new lifetime
for reused slots. The future admission owner must manage those lifetimes.

## Per-human input

Each present `RemoteHuman` supplies its own seven raw client-identity scalars,
86-byte direct-method NetAddr, region-transition token, optional D4
synchronization receipt, and optional current/pending region legs. The encoder
does not derive those values from a Steam ID, pair code, local player, or
another recipient's receipt. Each of the 64 region records puts that human's
transition token into its exact member lane.

The B2 player state combines the native connection gate, independent identity
fields 3 and 5, address field 11, optional opaque connection field 13 and the
existing minimal 18-byte player body in field 14. The final required B2 boolean
is false. The member's separate leave value is explicitly logical zero, which
keeps the native leave/skip test clear.

Field 13 accepts 64 logical byte patterns. Its recovered signed-byte schema
requires XOR `0x80` for each wire byte. NetAddr and player-body bytes are
unsigned and are written without that bias. The opaque contents remain
unclassified; the encoder neither manufactures nor logs them. Omitting field
13 preserves cached native slot data, as do absent D4 legs. Omission must never
be treated as a reliable way to clear a previously occupied slot.

The minimal player body establishes structural framing and repeats the exact
identity. Complete remote appearance and player properties remain unverified.
Producing a decodable row does not establish a visible or controllable Guardian.

## Validation and output

Validation precedes any output modification. Failure sets `written` to zero
and leaves the caller's output buffer unchanged. Checks include:

- Bounded extent, control-host presence and representable identity/region fields.
- Nonzero, distinct member keys for present humans and the control host.
- Nonzero remote account and field5 values without substituting local fallbacks.
- Canonical method-0 addresses: unicast IPv4, nonzero even port, matching local
  and public endpoints, unused endpoint entries zero, open NAT and method zero.
- Distinct direct address bodies across the control host and present humans.
- Sufficient buffer capacity for the exact encoded size.

Opaque NetAddr tail bytes remain intact. The registration layer separately
matches all 86 bytes and the exact local authentication owner; an encoded
address alone grants no route or player admission.

The largest supported BAP body is 5,315 bytes with all five additional humans,
opaque fields and D4 options. The current BAP scratch capacity accommodates it.
This is a different codec from the managed gameplay UDP membership writer:
that writer still refuses its maximum-width six-human 1,048-byte body under
the existing 1,024-byte writer and 24-by-32-byte reliable queue limits. The
four-endpoint association limit also remains unchanged.

## Verification and runtime boundary

`Dawn/unit/remote_human_membership_tests.vcxproj` independently decodes every
member row, all region token lanes, root masks and final padding. It exercises
two-, three- and six-human layouts, sparse stable slots, optional opaque/D4
fields, maximum size and rejection without output modification. Four SHA-256
goldens captured before the change preserve the existing solo/control output.
`membership_consumer_contract_tests` independently covers the recovered skip,
role and signed-byte rules. Both projects compile with warnings as errors.

Before this codec receives live additional-human input, the runtime must obtain
the actual guest publication over a protected channel, validate its current
activity grant and identity provenance, assign a stable slot generation, install
the exact registered human route and retire both on revocation. It must also
supply any required native player properties and connection data. These inputs
are not exposed through ordinary social commands. See the
[local-profile activity handoff](LOCAL-PROFILE-ACTIVITY-HANDOFF.md) and
[explicit route contract](EXPLICIT-NATIVE-ROUTES.md).

Milestone 1 still requires two real PCs to share an activity and display each
other's Guardian and live movement. Codec tests do not pass that milestone.
