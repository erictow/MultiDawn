# Actual client identity publications

Multiplayer needs the identity published by each player's own game. Dawn also
seeds a local identity before a type-23 message arrives, and its local reflection
fills missing account/field5 values for a foreign activity instance. Those
fallback values must not be presented as a remote client's publication.

## Separate receipt

`MembershipState::clientIdentityReceipt` retains the actual parsed type-23
scalars, including zero account/field5 values, separately from the reflected
identity used by the existing solo encoder. Field5 remains unnamed. A local
fallback to a selected character does not establish its native meaning.

The dedicated `prepare_client_identity` path stages the raw and reflected
values together. Only their two fallback lanes may differ, and a nonzero raw
lane must match its reflected value. Both identities must name the activity's
committed nonzero member key. The raw input and its guard are checked again at
commit, along with the existing exact activity, region, record, account and
transaction lifetime guards.

The seeded/reflected `prepare_identity` path cannot create or replace this
receipt. The receipt is runtime State, not a new save-file format or a native
player-ID assertion. Session retirement and slot reuse clear it with the owning
record. Authoritative region/state updates preserve it.

## Revisions and observation

The receipt records the root State revision that committed the last changed raw
publication. An identical duplicate preserves that revision. A receipt-only
change advances root and record State revisions while preserving the native
membership revision, acknowledgement and delivery behavior. A reflected wire
identity change retains the existing native membership publication behavior.

`snapshot_client_identity` requires an exact `ActivityInstanceKey` and expected
`HostRegionKey`. It copies the receipt and current record/root revisions under
one State read lock, clears output on failure, and refuses missing, stale or
inconsistent provenance. The returned host region describes the current
observation. A later region move does not rewrite the original receipt revision.

## Exact BAP creator boundary

The separate local-only
[`snapshot_creator_client_identity`](../Dawn/src/server/bap/local_identity_snapshot.h)
requires the exact current committed HUD creator binding. It holds the BAP
shared lock while checking that creator's authentication, ownership and machine
key and obtaining the coherent State receipt for its current region. It never
selects a newer session or substitutes a seeded identity.

This private result contains account fields. It must not be logged, added to
the public `CreatorActivitySnapshot`, or forwarded through ordinary companion
messages. The existing public activity snapshot remains unchanged and carries
no account identity. The private capture is an observation, not a retained
lease or gameplay authorization.

The receipt and creator checks supply provenance for later handoff work. They
do not publish another Guardian, authorize a human route, associate an account
with a Steam login, or send identity data to another PC. The native world
membership schema, actual player properties and two-machine activity test
remain separate requirements.

## Verification

The dedicated receipt suite passes 215 strict checks with the production
type-23 parser, server route, State transactions, query and retirement path.
It covers zero raw fields, seed/duplicate behavior, receipt-only revisions,
guard and mutation-kind changes, stale lifetimes, reuse, region updates,
malformed snapshots and revision exhaustion. Unrelated parsers, account
selection and log sinks are substituted; no game or save is opened.

The creator snapshot suite passes 82 strict checks using the production BAP
coordinator and State query. Its private capture checks include seed refusal,
raw zero preservation, stale binding/machine/region rejection and authentication
teardown. The existing public snapshot checks remain part of that suite.
