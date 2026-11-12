#include <Windows.h>

#include <cstdint>
#include <cstring>
#include "../../vanilla/one_au/selection.h"
#include "../../vanilla/homecoming/selection.h"

#include "../../../runtime/storage/internal.h"
#include "../../transactions/internal.h"
#include "../activity_membership_query.h"
#include "internal.h"

namespace dawn::state::activity::membership {
namespace {

/**
 * Applies one client identity operation to current State.
 * @param state Activity State held under the root write lock.
 * @param record Target joined session record.
 * @param prepared Identity plan, consumed here.
 * @return True when the candidate matches and commits, or is unchanged.
 */
[[nodiscard]] bool commit_identity(ActivityState& state,
                                   SessionRecord& record,
                                   const PendingMutation& prepared) noexcept {
    if (!prepared.hasSnapshot
        || !transactions::equal(prepared.snapshot.identity, prepared.identityGuard)
        || !transactions::valid_identity(prepared.snapshot.identity, record.memberKey)) {
        return false;
    }
    const bool clientPublication = prepared.kind == MutationKind::clientIdentity;
    if (clientPublication) {
        if (!transactions::equal(prepared.clientIdentityInput, prepared.clientIdentityGuard)
            || !transactions::valid_client_identity(prepared.clientIdentityInput,
                prepared.snapshot.identity, record.memberKey)) {
            return false;
        }
    } else if (prepared.changesReceipt || prepared.clientIdentityInput != Identity{}
        || prepared.clientIdentityGuard != Identity{}) {
        return false;
    }
    // Current State decides the outcome. Comparing it against the prepared plan and refusing on a
    // difference would drop the identity whenever State moved between prepare and commit, so no
    // membership would ever publish.
    const bool changed =
        !record.membership.hasIdentity
        || !transactions::equal(record.membership.identity, prepared.snapshot.identity);
    const bool receiptChanged = clientPublication
        && (record.membership.clientIdentityReceipt.revision == 0
            || !transactions::equal(record.membership.clientIdentityReceipt.raw,
                prepared.clientIdentityInput));
    if (clientPublication && (prepared.changesState != changed || prepared.changesReceipt != receiptChanged)) {
        return false;
    }
    if (((changed || receiptChanged) && state.stateRevision == activity::kMaximumRevision)
        || (changed && record.membership.revision == kMaximumMembershipRevision)) {
        return false;
    }
    if (!changed && !receiptChanged) {
        return true;
    }

    MembershipState updated = record.membership;
    if (changed) {
        if (!updated.hasTransitionToken) {
            updated.transitionToken = kInitialTransitionToken;
            updated.hasTransitionToken = true;
        }
        updated.identity = prepared.snapshot.identity;
        updated.revision = record.membership.hasIdentity ? record.membership.revision + 1U : kInitialRevision;
        updated.acknowledgedRevision = kAbsentRevision;
        updated.hasIdentity = true;
    }
    if (receiptChanged) {
        updated.clientIdentityReceipt = {prepared.clientIdentityInput, state.stateRevision + 1U};
    }
    record.membership = updated;
    transactions::publish_change(state, record);
    return true;
}

/**
 * Checks one read-only refresh plan against current State.
 * @param record Target joined session record.
 * @param prepared Refresh plan, consumed here.
 * @return True when the request guard and snapshot still match.
 */
[[nodiscard]] bool commit_refresh(const SessionRecord& record,
                                  const PendingMutation& prepared) noexcept {
    if (prepared.refreshRequestGuard
        != transactions::refresh_guard(prepared.requestedRevision, prepared.bubbleIndex)) {
        return false;
    }
    if (!record.membership.hasIdentity) {
        return !prepared.hasSnapshot;
    }
    if (!prepared.hasSnapshot) {
        return false;
    }
    const Snapshot expected = transactions::make_snapshot(
        record.membership, record.membership.identity, record.membership.revision);
    return transactions::equal(prepared.snapshot, expected);
}

/** Installs the exact next revision prepared for one all-or-none periodic region bundle. */
[[nodiscard]] bool commit_republish(ActivityState& state,
                                    SessionRecord& record,
                                    const PendingMutation& prepared) noexcept {
    const PreparedRegionTransition& transition = prepared.regionTransition;
    if (!transactions::equal(transition, prepared.regionTransitionGuard)
        || transition.activity != activity::transactions::instance_key(record)
        || transition.expectedHostRegion != activity::transactions::host_region_key(record)
        || transition.nextHostRegion != transition.expectedHostRegion
        || (!vanilla::one_au::selected(record.destination) && !vanilla::homecoming::selected(record.destination) && transition.expectedStateRevision != state.stateRevision)
        || transition.expectedRecordRevision != record.recordRevision
        || transition.movesRegion || !transition.publishesMembership
        || !prepared.hasSnapshot || !transactions::equal(transition.before, record.membership)
        || !record.membership.hasIdentity
        || state.stateRevision == activity::kMaximumRevision
        || record.membership.revision == kMaximumMembershipRevision) {
        return false;
    }
    MembershipState expected = transition.before;
    ++expected.revision;
    expected.acknowledgedRevision = kAbsentRevision;
    const Snapshot expectedSnapshot = transactions::make_snapshot(
        expected, expected.identity, expected.revision);
    if (!transactions::equal(transition.after, expected)
        || transition.effectiveRegion != expected.region.index
        || !transactions::equal(prepared.snapshot, expectedSnapshot)) {
        return false;
    }
    record.membership = transition.after;
    transactions::publish_change(state, record);
    return true;
}

/**
 * Applies one membership acknowledgement to current State.
 * @param state Activity State held under the root write lock.
 * @param record Target joined session record.
 * @param prepared Acknowledgement plan, consumed here.
 * @return True when the mark commits or the revision is a no-op.
 */
[[nodiscard]] bool commit_acknowledgement(ActivityState& state,
                                          SessionRecord& record,
                                          const PendingMutation& prepared) noexcept {
    const bool changed = record.membership.hasIdentity
                         && prepared.acknowledgement == record.membership.revision
                         && prepared.acknowledgement != record.membership.acknowledgedRevision;
    if (changed && state.stateRevision == activity::kMaximumRevision) {
        return false;
    }
    if (changed) {
        record.membership.acknowledgedRevision = prepared.acknowledgement;
        transactions::publish_change(state, record);
    }
    return true;
}

} // namespace

/** Advances the published membership revision so an already-applied snapshot can be corrected. */
bool republish(std::uint64_t sessionId) noexcept {
    if (sessionId == kAbsentSessionId) {
        return false;
    }
    bool advanced = false;
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    auto& root = runtime::storage::g_state;
    ActivityState& state = root.activity;
    for (SessionRecord& record : state.sessions) {
        if (!record.occupied || !record.joined || record.sessionId != sessionId) {
            continue;
        }
        // A record with no identity has published nothing. Its first identity carries the
        // current body anyway.
        if (record.membership.hasIdentity && state.stateRevision != activity::kMaximumRevision
            && record.membership.revision != kMaximumMembershipRevision) {
            ++record.membership.revision;
            record.membership.acknowledgedRevision = kAbsentRevision;
            transactions::publish_change(state, record);
            advanced = true;
        }
        break;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return advanced;
}

/** Advances the published membership revision for one exact activity lifetime. */
bool republish(ActivityInstanceKey key) noexcept {
    if (!static_cast<bool>(key)) {
        return false;
    }
    bool advanced = false;
    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    ActivityState& state = runtime::storage::g_state.activity;
    const std::size_t target = activity::transactions::find_session(state, key);
    if (target != kInvalidSessionSlot) {
        SessionRecord& record = state.sessions[target];
        if (record.joined && record.membership.hasIdentity
            && state.stateRevision != activity::kMaximumRevision
            && record.membership.revision != kMaximumMembershipRevision) {
            ++record.membership.revision;
            record.membership.acknowledgedRevision = kAbsentRevision;
            transactions::publish_change(state, record);
            advanced = true;
        }
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return advanced;
}

/** Commits one identity, authoritative, refresh, or acknowledgement operation. */
bool commit(PendingMutation& mutation) noexcept {
    const PendingMutation prepared = mutation;
    mutation = {};
    if (!prepared.prepared || prepared.kind == MutationKind::none
        || !static_cast<bool>(prepared.instanceKey)
        || !static_cast<bool>(prepared.expectedHostRegion)
        || prepared.expectedHostRegion.activity != prepared.instanceKey
        || prepared.expectedStateRevision == kInvalidRevision
        || prepared.expectedRecordRevision == kInvalidRevision
        || prepared.targetSlot >= kSessionCapacity
        || (prepared.kind != MutationKind::clientIdentity
            && (prepared.changesReceipt || prepared.clientIdentityInput != Identity{}
                || prepared.clientIdentityGuard != Identity{}))) {
        return false;
    }

    AcquireSRWLockExclusive(&runtime::storage::g_stateLock);
    auto& root = runtime::storage::g_state;
    ActivityState& state = root.activity;
    SessionRecord& record = state.sessions[prepared.targetSlot];
    // 1AU allocates sibling cinematic hosts during this handshake. Keep its exact
    // record/identity guards; unrelated missions retain their global revision guard.
    bool committed = (state.stateRevision == prepared.expectedStateRevision
                      || vanilla::one_au::selected(record.destination) || vanilla::homecoming::selected(record.destination)) && record.occupied
                     && record.joined && record.joinedRevision != kInvalidRevision
                     && dawn::state::activity::transactions::instance_key(record)
                            == prepared.instanceKey
                     && dawn::state::activity::transactions::host_region_key(record)
                            == prepared.expectedHostRegion
                     && record.recordRevision == prepared.expectedRecordRevision
                     && root.account.primarySoid == prepared.expectedPrimarySoid;
    if (committed && (prepared.kind == MutationKind::identity || prepared.kind == MutationKind::clientIdentity)) {
        committed = commit_identity(state, record, prepared);
    } else if (committed && prepared.kind == MutationKind::authoritative) {
        committed = transactions::commit_authoritative(state, record, prepared);
    } else if (committed && prepared.kind == MutationKind::refresh) {
        committed = commit_refresh(record, prepared);
    } else if (committed && prepared.kind == MutationKind::republish) {
        committed = commit_republish(state, record, prepared);
    } else if (committed && prepared.kind == MutationKind::acknowledgement) {
        committed = commit_acknowledgement(state, record, prepared);
    } else {
        committed = false;
    }
    ReleaseSRWLockExclusive(&runtime::storage::g_stateLock);
    return committed;
}

} // namespace dawn::state::activity::membership
