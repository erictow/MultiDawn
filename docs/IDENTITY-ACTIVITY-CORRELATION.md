# Native identity and activity correspondence

`core/multiplayer/identity_activity_correlation.h` correlates copied routing
observations. It grants no access and does not select a native role by its number.
This is the managed SessionState path. A BAP world/facet group uses a different
native structure; its relationship to that session table remains under
investigation. `noMatch` must not be interpreted as proof that world replication
is disconnected or that a native group-join request is missing.

Two source relationships support the comparison:

- `server/gameplay/gameplay_advertisement.cpp` constructs the region's advertised
  control machine and stores it as `CitizenAdvertisement.memberKey`. The same
  value is the group-session key held by the exact host-activity lineage row.
- `server/gameplay/group/group_host.cpp`, in `publish_snapshot`, writes that group
  key into the control-host member and obtains the human machine from State's
  committed BAP member key. The native membership schema names the host member
  explicitly. `middleware/gameplay/group/session_state.cpp` writes that native
  host-member index at replica offset 12.

The correlator takes an exact creator machine key, the exact advertised group key,
and a bounded collection of native observations. Exactly one fresh observation
must contain both distinct machines. Its actual native host-member index must
name the advertised control machine. That member must own no player. The creator
machine must own one validated nonzero native player ID. This observation shape
permits one control host and at most six player-owning humans. This is not a claim
that three-player fireteams or six-player raid networking is enabled. Extra unidentified members,
duplicate identities, inconsistent masks, empty observation lifetimes and malformed
rows are refused.

No role number is preferred. A local fireteam and local activity may expose the
same genuine human machine/player IDs in separate raw roles. Without the exact
advertised control machine in their membership, those observations return
`noMatch`. Multiple matching observations return `ambiguous`, even if their
public IDs agree. Observations older than one second or ahead of the supplied
monotonic time cannot match.

The result copies manager/lifetime/generation, raw role/mode, matched member/slot,
native player ID and both input machine keys. It does not derive a player from
Steam, a character ID or a seeded BAP join identity. Reading a native player table
does not by itself prove the player's complete native properties were published
by a remote human. The result therefore remains an observation.

The caller must acquire and revalidate the exact creator BAP binding, activity
incarnation, creator-root region, pinned advertisement lineage and authenticated
gameplay route. Process-local BAP/authentication generations must never be accepted
as remote-PC credentials. This header neither reads native memory nor acquires
those lifetimes, publishes membership, stops services or performs a gameplay grant.

The unit suite covers matching through every raw role, client mode 4, up to six
observed humans, sparse member/player slot 31, host-index mismatch, repeated local-only
identities, stale samples, ambiguity and malformed ownership/identity data.
