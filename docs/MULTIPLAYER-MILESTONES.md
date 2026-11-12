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
support. Three maximum-width human membership rows fit the current tested queue;
six require further transport work. The current association table holds four
endpoints, and the reliable outbound queue holds 24 fragments of 32 bytes. A
maximum-width six-human membership body measures 1,048 bytes and is refused by
the current writer/queue. Those limits remain unchanged until their native
protocol behavior is recovered and tested.

Launcher pairing, native social presence and invitation controls also currently
have one-partner assumptions. They must gain per-player connections and state
before milestone 2. The [activity handoff design](LOCAL-PROFILE-ACTIVITY-HANDOFF.md)
and [identity correspondence notes](IDENTITY-ACTIVITY-CORRELATION.md) describe the
current runtime boundary.
