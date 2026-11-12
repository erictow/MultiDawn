#pragma once

#include <cstddef>
#include <cstdint>

#include "../definition.h"

namespace dawn::state::activity::membership {

/**
 * Value-owned semantic after-image for one authoritative region operation.
 * Every field is captured under the same State read lock and commit installs this exact value.
 */
struct PreparedRegionTransition final {
    ActivityInstanceKey activity{};
    HostRegionKey expectedHostRegion{};
    HostRegionKey nextHostRegion{};
    MembershipState before{};
    MembershipState after{};
    destination::DestinationSelection destination{};
    bubble_authority::AuthorityState grantBefore{};
    std::uint64_t expectedStateRevision{};
    std::uint64_t expectedRecordRevision{};
    std::int32_t effectiveRegion{kAbsentRegionIndex};
    bool movesRegion{};
    bool publishesMembership{};

};

/** One exact, coherent region view copied under the State shared lock. */
struct RegionView final {
    ActivityInstanceKey activity{};
    HostRegionKey hostRegion{};
    destination::DestinationSelection destination{};
    std::int32_t reportedRegion{kAbsentRegionIndex};
    /** Committed activity-join key, captured with this region under the same State lock. */
    std::uint64_t memberKey{};
    /** Stored BAP join identity only; this can be a seeded fallback, never a native player ID. */
    std::uint64_t joinIdentity{};
    bool hasIdentity{};
    /** A stored identity agrees with the record's independently committed join key. */
    bool identityMatchesMemberKey{};
};

/**
 * Bound-destination and creator-source inputs used to finalize one BAP region snapshot.
 * The bound record supplies destination/grants while the source supplies player membership and the selected activity for its runtime.
 */
struct RegionSnapshotInputs final {
    ActivityInstanceKey bound{};
    ActivityInstanceKey source{};
    HostRegionKey sourceHostRegion{};
    destination::DestinationSelection destination{};
    destination::DestinationSelection sourceDestination{};
    bubble_authority::AuthorityState grantBefore{};
    MembershipState sourceMembership{};
    defaults::ActivityDefaults defaults{};
    std::uint64_t stateRevision{};
    std::uint64_t boundRecordRevision{};
    std::uint64_t sourceRecordRevision{};
};

/**
 * One periodic BAP refresh captured with its exact region inputs under a single State lock.
 * Republish is an uncommitted membership after-image until the whole wire bundle is ready.
 */
struct PeriodicRegionRefresh final {
    RegionSnapshotInputs inputs{};
    bool regionChanged{};
    bool publishesMembership{};
};

/** Snapshot and revision guards for one deferred membership operation. */
struct PendingMutation final {
    Snapshot snapshot{};
    /** A second copy, so a changed identity plan is caught before commit. */
    Identity identityGuard{};
    /** Sparse authoritative input, kept whether or not a delivery snapshot exists. */
    AuthoritativeUpdate authoritativeInput{};
    /** A second copy, so a changed authoritative plan is caught before commit. */
    AuthoritativeUpdate authoritativeGuard{};
    /** Exact semantic after-image for authoritative operations, including pure region moves. */
    PreparedRegionTransition regionTransition{};
    /** Bit-for-bit guard of the prepared semantic after-image. */
    PreparedRegionTransition regionTransitionGuard{};
    /** Exact activity and host-region predecessor captured with the revision guards. */
    HostRegionKey expectedHostRegion{};
    /** Exact activity lifetime selected by prepare and revalidated by commit. */
    ActivityInstanceKey instanceKey{};
    std::uint64_t expectedStateRevision{};
    std::uint64_t expectedRecordRevision{};
    std::uint64_t expectedPrimarySoid{};
    std::uint64_t refreshRequestGuard{};
    std::uint32_t requestedRevision{};
    std::uint32_t acknowledgement{};
    std::int32_t bubbleIndex{};
    std::size_t targetSlot{kInvalidSessionSlot};
    MutationKind kind{};
    bool hasSnapshot{};
    bool changesState{};
    /**
     * Set when the delta moves the player to a different region.
     * The region is not a published membership field, so this is separate from changesState. The
     * citizen advertisement is rebuilt from it, so a move advances the revision and sends the
     * roster at once.
     */
    bool movesRegion{};
    /**
     * Set when the delta changes the client's transition token.
     * The token goes up once per load, so a change is the only start signal on the wire.
     */
    bool movesTransitionToken{};
    bool prepared{};
};

/**
 * Prepares one exact identity for a joined activity session.
 * @param sessionId Existing joined activity session id.
 * @param identity Copied into the candidate refresh snapshot.
 * @param mutation Cleared, then receives the snapshot and revision guards.
 * @return True when the identity is valid, including an unchanged duplicate.
 */
[[nodiscard]] bool prepare_identity(ActivityInstanceKey key,
                                    const Identity& identity,
                                    PendingMutation& mutation) noexcept;

/**
 * Prepares sparse host-state changes for one joined activity session.
 * @param sessionId Existing joined activity session id.
 * @param update Kept fields, each with its own presence flag.
 * @param mutation Cleared, then receives State guards and an optional new snapshot.
 * @return True for a joined session, including an unchanged no-op.
 */
[[nodiscard]] bool prepare_authoritative(ActivityInstanceKey key,
                                         const AuthoritativeUpdate& update,
                                         PendingMutation& mutation) noexcept;

/**
 * Captures the current membership snapshot without changing stored State.
 * @param sessionId Existing joined activity session id.
 * @param requestedRevision Membership revision the client last saw.
 * @param bubbleIndex Logical bubble the client reported, carried through unchecked.
 * @param mutation Cleared output; hasSnapshot is false before the first identity.
 * @return True when the session is joined.
 */
[[nodiscard]] bool prepare_refresh(ActivityInstanceKey key,
                                   std::uint32_t requestedRevision,
                                   std::int32_t bubbleIndex,
                                   PendingMutation& mutation) noexcept;

/**
 * Captures one periodic self-owned region refresh and its optional next revision atomically.
 * `advertisedRegion` is connection delivery state; it is compared while State is copied but never
 * written here. The returned mutation commits read-only validation or one exact republish.
 * An explicit host-command change may force a new revision without changing native mirrors.
 */
[[nodiscard]] bool prepare_periodic_region_refresh(ActivityInstanceKey key,
                                                   std::int32_t advertisedRegion,
                                                   PendingMutation& mutation,
                                                   PeriodicRegionRefresh& refresh,
                                                   bool forceMembershipRepublish = false) noexcept;

/**
 * Tests whether the client has applied the current membership revision.
 * Every membership push makes the client rebuild its region table and its player snapshots, so an
 * acknowledged snapshot is re-sent only when something changes it.
 * @param sessionId Joined activity session.
 * @return True when the published revision has been acknowledged.
 */
[[nodiscard]] bool acknowledged(std::uint64_t sessionId) noexcept;

/** Exact-incarnation overload used by binding-owned publishers. */
[[nodiscard]] bool acknowledged(ActivityInstanceKey key) noexcept;

/**
 * Advances the published membership revision so an already-applied snapshot can be corrected.
 * The client applies one update per revision and drops every repeat. A body published with a
 * stale citizen advertisement can only be replaced at a new revision.
 * @param sessionId Joined activity session.
 * @return True when the revision advanced.
 */
[[nodiscard]] bool republish(std::uint64_t sessionId) noexcept;

/** Exact-incarnation overload used by binding-owned publishers. */
[[nodiscard]] bool republish(ActivityInstanceKey key) noexcept;

/**
 * Reads the region the client last reported it was in.
 * The client names its own position and it changes as the player crosses a bubble boundary, so it
 * beats the destination's own arrival slice set wherever the host must say where the player is.
 * @param sessionId Joined activity session.
 * @return The reported region index, or -1 when none has arrived.
 */
[[nodiscard]] std::int32_t reported_region(std::uint64_t sessionId) noexcept;

/** Exact-incarnation overload used by binding-owned publishers. */
[[nodiscard]] std::int32_t reported_region(ActivityInstanceKey key) noexcept;

/**
 * Copies one exact joined region view and validates its exact host-region generation.
 * Owner proof is deliberately outside State and must be established by the BAP caller first.
 */
[[nodiscard]] bool snapshot_region_view(ActivityInstanceKey activity,
                                        HostRegionKey expected,
                                        RegionView& output) noexcept;

/**
 * Copies the exact bound/source inputs for one region publication under one State shared lock.
 * An absent expectedSource accepts the source's current host-region key; a present value must
 * match exactly.
 */
[[nodiscard]] bool snapshot_region_inputs(ActivityInstanceKey bound,
                                          ActivityInstanceKey source,
                                          HostRegionKey expectedSource,
                                          RegionSnapshotInputs& output) noexcept;

/**
 * Reads the stable machine key the client's activity join committed.
 * The gameplay group membership uses this as the joining peer's machine identity.
 * @param sessionId Joined activity session.
 * @return The member key, or zero before the activity join commits.
 */
[[nodiscard]] std::uint64_t member_key(std::uint64_t sessionId) noexcept;

/** Exact-incarnation overload used before gameplay derives a member identity. */
[[nodiscard]] std::uint64_t member_key(ActivityInstanceKey key) noexcept;

/**
 * Reads the identity value message 12 publishes at member record `+16`.
 * The seed fills it with the join's member key. The client's own identity message replaces it.
 * @param sessionId Joined activity session.
 * @return The join identity, or zero before any identity is published.
 */
[[nodiscard]] std::uint64_t join_identity(std::uint64_t sessionId) noexcept;

/** Exact-incarnation overload used by binding-owned publishers. */
[[nodiscard]] std::uint64_t join_identity(ActivityInstanceKey key) noexcept;

/**
 * Prepares an acknowledgement mark for the current membership revision.
 * @param sessionId Existing joined activity session id.
 * @param revision Revision the client applied; stale and future values are valid no-ops.
 * @param mutation Cleared, then receives the revision guards.
 * @return True when the joined session and its current membership State are valid.
 */
[[nodiscard]] bool prepare_acknowledgement(ActivityInstanceKey key,
                                           std::uint32_t revision,
                                           PendingMutation& mutation) noexcept;

/**
 * Commits one identity, authoritative, refresh, or acknowledgement operation.
 * @param mutation Prepared plan. Always cleared before this function returns.
 * @return True when the operation commits or needs no State change.
 */
[[nodiscard]] bool commit(PendingMutation& mutation) noexcept;

} // namespace dawn::state::activity::membership
