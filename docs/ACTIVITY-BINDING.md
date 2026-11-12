# Activity binding observations

`core/multiplayer/activity_binding` observes the exact current creator BAP
binding, its creator-root region, a pinned advertisement, native managed-session
membership and a current authenticated gameplay route. It does not authorize a
player, publish membership, forward activity traffic or stop any local service.

The BAP snapshot copies only public destination selectors and routing scalars
under coherent BAP/State locks. The advertisement observation retains an exact
host-row pin without provisioning, registering a descriptor or publishing a
control host. Native collection copies every fresh manager, including repeated
roles, so ambiguous candidates cannot disappear from selection.

For the managed-session path, exactly one native membership table must contain
the advertised control machine at its actual host index and the creator machine
owning a native player. A Steam ID, character ID or seeded BAP join value cannot
substitute for that player. The BAP snapshot, native correspondence, route and
lineage are rechecked before a copied observation is returned. Pins are released
before return, so every later use still needs revalidation.

The BAP world/facet replication group and the native managed SessionState are
distinct structures. Their exact relationship is not yet established. In
particular, `no_managed_group` does not prove the world connection failed or that
the game should have sent OOB JoinId10. It must not be used as a gameplay grant
condition without recovering the applicable native path.

For an isolated development run, set `DAWN_ACTIVITY_BINDING_TRACE=1` alongside
`DAWN_NATIVE_IDENTITY_OBSERVATION=1`. The probe runs at most twice per second and
logs at most 128 result/source changes per server lifetime. Events report PID,
result, region and a diagnostic `source_fingerprint`; no private descriptors,
account data or route material are logged. The fingerprint is FNV-1a64 over the
little-endian creator-machine ID followed by the advertised control-machine ID.
It is a diagnostic comparison, not an authentication hash.

The existing native connection hook also emits an opt-in `native_group_owner`
event with the current owner/group pointers and member index. This adds no
native memory read or detour. Those pointers are valid only for that process and
help locate the typed world/facet membership fields without scanning memory.

The component suites cover:

- 67 checks using the production BAP coordinator, State query and retirement.
- 133 checks using the production advertisement helper and descriptor builder,
  including absence of publication side effects on observation.
- 95 native managed-session correspondence checks.
- 85 binding-boundary checks with substituted providers, including stale epochs,
  ambiguous membership, changed routes and released pins on failure.

The whole binding probe still needs live validation. None of these component
checks completes [multiplayer milestone 1](MULTIPLAYER-MILESTONES.md).
