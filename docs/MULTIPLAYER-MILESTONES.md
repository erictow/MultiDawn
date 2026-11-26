# Multiplayer milestones

These milestones define the project's completion order. Storage limits and
component tests do not mark a gameplay milestone complete.

| Milestone | Target | Acceptance |
| --- | --- | --- |
| 1 | Two players | Host and guest join one actual lobby/activity through MultiDawn. Both games show the other Guardian and its live movement. Each player retains their own local profile and save. |
| 2 | Three-player fireteam | The host and two guests share the activity and see both other players. Invitations, join/leave and failure handling preserve each player's identity and ownership. |
| 3 | Six players and project completion | Six Guardians can play together, including the restored raids. Combat, enemies, objectives, death/revive and activity transitions synchronize, with independent saves and bounded disconnect cleanup. |

Milestone 1 is the current implementation target. The launcher still blocks
multiplayer Play while activity handoff and remote Guardian replication are
incomplete. No milestone has yet passed its multi-PC gameplay checks.

Each PC keeps its account, inventory, local profile service and saves. The host
owns the shared activity. Guests must not replace the host's account or disable
their entire local backend when changing gameplay hosts.

Native membership storage now reserves up to six human identities plus one
control host. This preserves future capacity without advertising six-player
support. The separate BAP type-12 encoder can represent those six humans with
stable slots and per-human tokens; its offline tests do not activate admission
or replication. See [additional-human BAP membership](REMOTE-HUMAN-MEMBERSHIP.md).
Three maximum-width human gameplay membership rows fit the current tested queue;
six require further transport work. The current association table holds four
endpoints, and the reliable outbound queue holds 24 fragments of 32 bytes. A
maximum-width six-human membership body measures 1,048 bytes and is refused by
the current writer and queue. An offline sender now stages that body and feeds
its 33 fragments into the existing 24-entry send queue as acknowledgements
retire the prefix. This uses the same framing and acknowledgement code as the
live transport. An offline receiver assembles all 33 by draining contiguous
fragments from the existing 32-slot reorder window while awaiting the final
fragment. The existing live receiver still stops at 32. Integrating the new
assembler requires a per-link lifetime and acknowledgement policy for duplicates
and out-of-window fragments. Archived-game receiver support still needs a live
check before the longer message can be used for gameplay.

Launcher pairing, native social presence and invitation controls also currently
have one-partner assumptions. They must gain per-player connections and state
before milestone 2. The [activity handoff design](LOCAL-PROFILE-ACTIVITY-HANDOFF.md)
and [identity correspondence notes](IDENTITY-ACTIVITY-CORRELATION.md) describe the
current runtime boundary.

For milestone 1, first confirm each game can spawn and control its own Guardian.
Then correlate the live invitation and guest publication with the host's exact
world instance and install the recipient-specific membership and routes. Use
the existing local profile service for each player and validate bidirectional
movement before extending combat or activity authority.

For milestone 2, give each guest their own authenticated launcher connection,
invite and grant lifetime, route, and reliable queues. Keep surviving players'
slots stable across departure, and test disconnect and rejoin in a real
three-player activity. The current one-partner launcher remains the ceiling.

For milestone 3, verify whether the archived game accepts the longer reliable
message. If its receiver cannot assemble that run, recover a native update
sequence that splits the roster into smaller valid publications. Confirm
capacity for five guests on their own routes before bringing up all six clients.
Use one authority for each shared encounter, with client movement and combat
inputs tied to the exact player and activity. A raid test must cover encounter
transitions, combat, death and revive, a wipe, and a player leaving or returning
while each PC's save stays local. This is the implementation direction, pending
native gameplay evidence.
