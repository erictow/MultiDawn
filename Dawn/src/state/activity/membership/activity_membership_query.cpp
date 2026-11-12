#include "activity_membership_query.h"

#include <Windows.h>

#include "../../runtime/storage/internal.h"
#include "../destination/activity_destination_validation.h"
#include "../transactions/internal.h"

namespace dawn::state::activity::membership {

/** Tests whether the client has applied the current membership revision. */
bool acknowledged(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return false;
    }
    bool applied = false;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, sessionId);
    if (target != kInvalidSessionSlot) {
        const MembershipState& membership = state.sessions[target].membership;
        applied = membership.revision != kAbsentRevision
                  && membership.acknowledgedRevision == membership.revision;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return applied;
}

/** Tests whether the client applied the revision for one exact activity lifetime. */
bool acknowledged(ActivityInstanceKey key) noexcept {
    if (!static_cast<bool>(key)) {
        return false;
    }
    bool applied = false;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, key);
    if (target != kInvalidSessionSlot) {
        const MembershipState& membership = state.sessions[target].membership;
        applied = membership.revision != kAbsentRevision
                  && membership.acknowledgedRevision == membership.revision;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return applied;
}

/** Reads the region the client last reported it was in. */
std::int32_t reported_region(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return kAbsentRegionIndex;
    }
    std::int32_t region = kAbsentRegionIndex;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, sessionId);
    if (target != kInvalidSessionSlot) {
        region = state.sessions[target].membership.region.index;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return region;
}

/** Reads the region for one exact activity lifetime. */
std::int32_t reported_region(ActivityInstanceKey key) noexcept {
    if (!static_cast<bool>(key)) {
        return kAbsentRegionIndex;
    }
    std::int32_t region = kAbsentRegionIndex;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, key);
    if (target != kInvalidSessionSlot) {
        region = state.sessions[target].membership.region.index;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return region;
}

/** Copies one exact owner-proved region view under a single State lock. */
bool snapshot_region_view(ActivityInstanceKey activity,
                          HostRegionKey expected,
                          RegionView& output) noexcept {
    output = {};
    if (!static_cast<bool>(activity) || !static_cast<bool>(expected)
        || expected.activity != activity) {
        return false;
    }

    RegionView selected{};
    bool found = false;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, activity);
    if (target != kInvalidSessionSlot) {
        const SessionRecord& record = state.sessions[target];
        const HostRegionKey current = activity::transactions::host_region_key(record);
        if (record.joined && record.joinedRevision != kInvalidRevision
            && record.membership.region.index > kAbsentRegionIndex && current == expected) {
            selected.activity = activity;
            selected.hostRegion = current;
            selected.destination = record.destination;
            selected.reportedRegion = record.membership.region.index;
            selected.memberKey = record.memberKey;
            selected.hasIdentity = record.membership.hasIdentity;
            if (selected.hasIdentity) {
                selected.joinIdentity = record.membership.identity.joinIdentity;
                selected.identityMatchesMemberKey =
                    record.memberKey != 0 && record.membership.identity.memberKey == record.memberKey;
            }
            found = true;
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    if (!found || !destination::valid(selected.destination)) {
        return false;
    }
    output = selected;
    return true;
}

/** Copies exact bound/source transaction inputs under one State shared lock. */
bool snapshot_region_inputs(ActivityInstanceKey bound,
                            ActivityInstanceKey source,
                            HostRegionKey expectedSource,
                            RegionSnapshotInputs& output) noexcept {
    output = {};
    if (!static_cast<bool>(bound) || !static_cast<bool>(source)
        || (static_cast<bool>(expectedSource) && expectedSource.activity != source)) {
        return false;
    }

    RegionSnapshotInputs selected{};
    bool found = false;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t boundSlot = activity::transactions::find_session(state, bound);
    const std::size_t sourceSlot = activity::transactions::find_session(state, source);
    if (boundSlot != kInvalidSessionSlot && sourceSlot != kInvalidSessionSlot) {
        const SessionRecord& boundRecord = state.sessions[boundSlot];
        const SessionRecord& sourceRecord = state.sessions[sourceSlot];
        const HostRegionKey sourceHost = activity::transactions::host_region_key(sourceRecord);
        if (boundRecord.joined && sourceRecord.joined
            && boundRecord.joinedRevision != kInvalidRevision
            && sourceRecord.joinedRevision != kInvalidRevision
            && static_cast<bool>(sourceHost)
            && (!static_cast<bool>(expectedSource) || sourceHost == expectedSource)) {
            selected.bound = bound;
            selected.source = source;
            selected.sourceHostRegion = sourceHost;
            selected.destination = boundRecord.destination;
            selected.sourceDestination = sourceRecord.destination;
            selected.grantBefore = boundRecord.bubbleAuthority;
            selected.sourceMembership = sourceRecord.membership;
            selected.defaults = state.defaults;
            selected.stateRevision = state.stateRevision;
            selected.boundRecordRevision = boundRecord.recordRevision;
            selected.sourceRecordRevision = sourceRecord.recordRevision;
            found = true;
        }
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    if (!found || !destination::valid(selected.destination)
        || !destination::valid(selected.sourceDestination)) {
        return false;
    }
    output = selected;
    return true;
}

/** Reads the stable machine key the client's activity join committed. */
std::uint64_t member_key(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return 0;
    }
    std::uint64_t key = 0;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, sessionId);
    if (target != kInvalidSessionSlot && state.sessions[target].joined) {
        key = state.sessions[target].memberKey;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return key;
}

/** Reads the stable machine key for one exact joined activity lifetime. */
std::uint64_t member_key(ActivityInstanceKey key) noexcept {
    if (!static_cast<bool>(key)) {
        return 0;
    }
    std::uint64_t member = 0;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, key);
    if (target != kInvalidSessionSlot && state.sessions[target].joined) {
        member = state.sessions[target].memberKey;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return member;
}

/** Reads the identity value message 12 publishes at member record `+16`. */
std::uint64_t join_identity(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return 0;
    }
    std::uint64_t identity = 0;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, sessionId);
    if (target != kInvalidSessionSlot && state.sessions[target].membership.hasIdentity) {
        identity = state.sessions[target].membership.identity.joinIdentity;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return identity;
}

/** Reads the join identity for one exact activity lifetime. */
std::uint64_t join_identity(ActivityInstanceKey key) noexcept {
    if (!static_cast<bool>(key)) {
        return 0;
    }
    std::uint64_t identity = 0;
    AcquireSRWLockShared(&runtime::storage::g_stateLock);
    const ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, key);
    if (target != kInvalidSessionSlot && state.sessions[target].membership.hasIdentity) {
        identity = state.sessions[target].membership.identity.joinIdentity;
    }
    ReleaseSRWLockShared(&runtime::storage::g_stateLock);
    return identity;
}

} // namespace dawn::state::activity::membership
