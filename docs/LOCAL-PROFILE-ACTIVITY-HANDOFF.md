# Local profiles and shared activity handoff

The public activity observation is implemented. The typed activity proxy,
gameplay grant, and endpoint handoff below remain planned. Each PC
keeps its own saves and profile service; the host owns the shared activity.

## Existing observations

[`snapshot_hud_region`](../Dawn/src/server/bap/bap_route.cpp#L560) already copies
an exact creator-owned binding, activity incarnation, host-region generation,
destination, and reported region. It holds the BAP shared lock while validating
the committed HUD anchor and requesting a coherent State region view. This is a
better starting point than selecting the newest activity or using scalar session
IDs. The [lifecycle keys](../Dawn/src/state/activity/lifecycle_generation.h#L91)
include connection, authentication, binding, activity, and region generations to
reject reused lifetimes.

The exact-activity overloads of
[`member_key` and `join_identity`](../Dawn/src/state/activity/membership/activity_membership_query.cpp#L187)
read the local BAP machine and join identities, but each takes its own State lock.
Combining those calls with a region snapshot does not produce one coherent
identity/region observation. Also, the existing
[`seed_identity`](../Dawn/src/server/bap/encrypted/push/activity/activity_keepalive_seed.cpp#L27)
can initialize `joinIdentity` from the member key before a client identity message
arrives. A BAP join identity must not be treated as a verified native player ID.

The [client identity receipt](CLIENT-IDENTITY-PROVENANCE.md) now keeps the actual
type-23 values separately from this seeded/reflected identity. A local-only
creator capture checks the exact current binding and State region before
returning that receipt. Its private account fields remain outside the public
activity snapshot and companion controls.

[`matchmaking::LatestSnapshot`](../Dawn/src/state/matchmaking/definition.h#L69)
contains the full 128-byte secret-bearing runtime descriptor. Do not export that
object, raw descriptor, account SOIDs, nonces, tokens, or keys to a companion
message or diagnostic log. A native NetAddr also contains opaque method-dependent
data; forwarding its private body is not a substitute for a public routing API.

## Public snapshot implementation

The State [`RegionView`](../Dawn/src/state/activity/membership/activity_membership_query.h#L31)
captures the committed member key, stored join identity, identity presence, and
member-key agreement with the existing destination and reported-region fields
under the same State read lock. It does not claim client or native provenance.

[`snapshot_creator_activity` and `snapshot_current_creator_activity`](../Dawn/src/server/bap/runtime.h#L21)
follow the HUD locking pattern. Both require the exact committed HUD creator
anchor; neither selects the newest session. Their public value-only result
contains:

- The exact current `BindingKey` and `ActivityInstanceKey`.
- The exact `RegionLineage` and `HostRegionKey`, plus reported region.
- The public destination package, activity index, reason, and coherent BAP
  machine/join routing scalars. Opaque descriptor bytes and account fields are
  excluded.

The API requires an authenticated, current, non-retiring binding that owns its
creator record, a joined exact State record, and matching nonzero machine
identity. Failure clears the output. Missing membership identity is reported
accurately, and a stored zero join identity is not replaced with a guessed value.
A creator snapshot is an observation, not a retained lease.
Any later derived activity must additionally prove and pin its exact
[`HostActivityLineageLease`](../Dawn/src/server/gameplay/group/group_host_sessions.h#L16),
then revalidate it before using that group edge.

Two other observations remain separate:

- The [native identity reader](../Dawn/src/core/multiplayer/native_identity_observation_state.h#L19)
  observes actual native member/player ownership and freshness. Its samples do
  not alone identify the local human or authenticate a BAP account. Correlate
  exact machine identity and native session role; never substitute a Steam ID,
  character SOID, or seeded BAP value for the native player ID.
- [`lookup_authenticated_route` and `validate_authenticated_route`](../Dawn/src/server/gameplay/resolution/address_resolution_host.h#L60)
  expose a public source endpoint and generation checked against an exact BAP
  authentication lifetime. They expose no resolver material and grant no group
  admission. The observed gameplay source port is distinct from the launcher's
  TCP pairing port.

`creator_activity_snapshot_tests.vcxproj` links the production BAP coordinator,
State query, exact lookup, and retirement code. Its 67 checks cover stale
lifetimes, creator selection, identity consistency, private-byte exclusion,
teardown, and concurrent State reads. Unused frame, resolver, and derived-group
services are stubbed; the test opens no game, account service, or save.

## Future handoff

Implement a typed guest-local activity proxy that forwards only the approved
activity operations while account, inventory, and save operations stay local.
The local BAP handshake and its permissive
[`serverHello` handling](../Dawn/src/server/bap/plaintext.cpp#L217) are not remote
identity credentials and must not become a shared account service.

Before issuing any future gameplay grant, revalidate the current launcher pair,
ticket/deadline, both native epochs and identities, exact BAP binding, activity,
region, pinned group lineage, and authenticated gameplay route. An
[`AcceptedInvitationIntent`](INVITATION-CONTROL-V2.md) records the player's choice;
it must never directly call `authorize_shared_peer`. Retire guest-local gameplay
service only after a valid handoff is confirmed, with bounded failure cleanup.
Real two-PC shared activity, invitations, and independent save/reload remain the
acceptance checks.

The opt-in version-three companion now supplies a dedicated
[accepted-ticket preflight](INVITATION-CONTROL-V2.md#opt-in-version-three-preflight).
It checks the launcher's live record without consuming the earlier intent event.
Its expiring result is an observation of invitation state; it does not establish
the BAP world relationship, carry a guest identity publication or authorize a
human route. Local validation of a consumed result is not a retained host lease.

## Recipient roster projection

`world_roster::Projection` prepares a BAP membership snapshot for one exact
recipient binding, host-region lifetime and native membership epoch. The
handoff controller must supply an already validated human publication and
grant. It gives the projection the exact resolver registration for that NetAddr
and the grant deadline. The projection checks the registration again before it
copies the row into a snapshot. The host control row and local player's row
remain those of the recipient's existing BAP snapshot.

The projection assigns each human one native slot for the epoch. Revoking a
row leaves a gap and returns the exact address registration to its owner for
revocation. The projector refuses stale scopes, expired grants, retired
registrations and conflicting snapshots without changing the caller's output.
It refuses to recycle a slot under the same epoch because optional native
fields can retain the former occupant's data. Moving to a new projection scope
requires retiring the old rows and proving a new native epoch.

The resolver's `validate_peer_address` checks all 86 bytes with the exact
registration handle under its own lock. This is a point-in-time check. A
future controller must serialize grant changes and revalidate before
committing a publication or forwarding a datagram. The projector neither
starts a shared session nor validates a guest's opaque properties. It has no
live caller yet. The membership tests project and decode six-human rows,
including sparse rows after a departure and retirement across epochs.
