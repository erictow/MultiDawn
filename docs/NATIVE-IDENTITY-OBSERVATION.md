# Native identity observations

Experimental `main` includes an opt-in, read-only observer for the pinned Destiny 2
build `86657.20.08.23.1800.d2_rc`. Set
`DAWN_NATIVE_IDENTITY_OBSERVATION=1` before launching an isolated test process to
request it. The flag is cached for the DLL lifetime. Three native layout signatures
must also match. Ordinary launches keep this observer disabled.

The existing native manager update hook calls the observer after its original
function returns, on the native manager's thread. The observer copies only scalar
membership/player routing fields. It does not read or store NetAddr blobs,
security identities, player configuration, account data or save data.

The layout comes from `middleware/gameplay/group/session_state.cpp` and the
independently checked read-only runtime snapshot tool. The parser requires matching
member counts/masks, unique nonzero machine IDs, matching player counts/masks,
unique nonzero player IDs and exact member-to-player ownership. Two complete
scalar samples must agree. This detects observed instability; it is not an atomic
snapshot of native state. Join ID and player sequence zero are valid observations.

`client/hooks/bootflow/native_identity_observation.h` exposes a copied observation
by raw managed role `0..6`. The result includes every validated member and its
owned player ID, where present. It does not establish which member is the local
human, decode a network endpoint, or equate a Steam identity with a native player.
If several fresh managers have the same role, the lookup fails as ambiguous.

The fixed mailbox has sixteen manager slots. Results expire after one second;
expired slots can be reclaimed. Malformed samples invalidate their manager's
previous result. Role changes, observed initialization loss and sampling gaps
start a new observation incarnation. Every changed sample receives a monotonically
increasing generation. These are observer-owned counters, not recovered native
session incarnation keys. A manager reused between observations may therefore
require additional native lifecycle proof before it can support authorization.

Hook quiescence clears observations. A capture begun before stop/restart cannot
publish into the new collector lifetime. Generation counters remain monotonic
across reset and reinstall. Snapshot callers receive values only; they never read
native memory through this API.

No companion message publishes these observations. No admission controller consumes
them, and they do not authorize `authorize_shared_peer`, supply a gameplay grant,
or stop a guest's local services. Future authorization still needs an exact current
BAP binding/activity lifetime, authenticated gameplay source and ticket context.

The `native_identity_observation_tests` project exercises the production membership
encoder, malformed ownership/identity data, changing samples, scalar-read privacy,
bit-31 slots, expiry, capacity reclamation, ambiguity and lifecycle fencing. Its
`--layout-refused` mode checks that explicit opt-in still refuses an unsupported
executable. An in-game comparison against the independent runtime snapshot remains
required before treating this observer as live-validated.
