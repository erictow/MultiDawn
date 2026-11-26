#include "activity_membership_route.h"

#include <algorithm>
#include <array>
#include <cstdio>

#include "../../../../../core/logging/log.h"
#include "../../../../../middleware/bap/activity_message/activity_membership_acknowledgement_parser.h"
#include "../../../../../middleware/bap/activity_message/activity_client_identity_parser.h"
#include "../../../../../middleware/bap/activity_message/activity_state_refresh_parser.h"
#include "../../../../../middleware/bap/activity_message/client_authoritative_data.h"
#include "../../../../../state/account/account_state.h"
#include "../../../../../state/activity/membership/activity_membership_query.h"
#include "../../../../../state/runtime/runtime.h"

namespace dawn::server::bap::encrypted::activity_message::membership {
namespace {

namespace service = middleware::bap::activity_message;
namespace membership_state = state::activity::membership;

void report_authoritative(
    const char* result,
    state::activity::ActivityInstanceKey owner,
    std::size_t bytes,
    const service::client_authoritative_data::ClientAuthoritativeData& parsed,
    const membership_state::PendingMutation* mutation,
    std::string_view destination = {}) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=activity stage=client_authoritative result=%s owner=0x%016llX incarnation=%llu bytes=%zu "
        "destination=%.*s mission_run=%llu region_policy=%s "
        "transition_present=%u transition_token=%u sync_present=%u sync_token=%u "
        "spawn_present=%u spawn_state=%d "
        "teleport_present=%u teleport_state=%d teleport_token=%u teleport_slice=%d "
        "teleport_hash=0x%08X region_present=%u region=%d region_hash_present=%u "
        "region_hash=0x%08X changes=%u snapshot=%u region_moved=%u transition_started=%u "
        "revision=%u held_present=%u held_region=%d publication_region=%d before_region=%d before_revision=%u",
        result,
        static_cast<unsigned long long>(owner.sessionId),
        static_cast<unsigned long long>(owner.incarnation.value),
        bytes,
        static_cast<int>(destination.empty() ? 7 : destination.size()),
        destination.empty() ? "unknown" : destination.data(),
        static_cast<unsigned long long>(state::activity::mission_run_generation()),
        destination.empty() ? "unknown" : retains_held_region(destination) ? "held_prefetch" : "second_leg",
        parsed.hasTransitionToken ? 1U : 0U,
        static_cast<unsigned>(parsed.transitionToken),
        parsed.hasSynchronizationToken ? 1U : 0U,
        static_cast<unsigned>(parsed.synchronizationToken),
        parsed.hasSpawn ? 1U : 0U,
        static_cast<int>(parsed.spawn.state),
        parsed.hasTeleport ? 1U : 0U,
        static_cast<int>(parsed.teleport.state),
        static_cast<unsigned>(parsed.teleport.token),
        parsed.teleport.sliceSetIndex,
        parsed.teleport.sliceSetHash,
        parsed.hasRegion ? 1U : 0U,
        parsed.region.index,
        parsed.region.hasHash ? 1U : 0U,
        parsed.region.hash,
        mutation != nullptr && mutation->changesState ? 1U : 0U,
        mutation != nullptr && mutation->hasSnapshot ? 1U : 0U,
        mutation != nullptr && mutation->movesRegion ? 1U : 0U,
        mutation != nullptr && mutation->movesTransitionToken ? 1U : 0U,
        mutation != nullptr && mutation->hasSnapshot ? mutation->snapshot.revision : 0U,
        parsed.hasCurrentRegion?1U:0U,parsed.currentRegion.index,
        mutation!=nullptr?mutation->regionTransition.after.region.index:-1,

        mutation != nullptr ? mutation->regionTransition.before.region.index : -1,
        mutation != nullptr ? mutation->regionTransition.before.revision : 0U);
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         result[0] == 'o' ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), (std::min)(static_cast<std::size_t>(written), line.size() - 1)});
    }
}

/**
 * Maps one parsed client identity into State's protocol-neutral storage.
 * @param parsed Typed Middleware identity whose source bytes expire after routing.
 * @return Whole State identity, with no borrowed payload views.
 */
[[nodiscard]] membership_state::Identity
make_raw_identity(const service::client_identity::ClientIdentity& parsed) noexcept {
    membership_state::Identity identity{};
    identity.memberKey = parsed.memberKey;
    identity.smallOpaque = parsed.field1;
    identity.signedOpaque = parsed.field2;
    identity.joinIdentity = parsed.field3;
    identity.accountSoid = parsed.accountSoid;
    identity.opaqueSoid = parsed.field5;
    identity.secondaryOpaque = parsed.field6;
    return identity;
}

/** Existing local reflection fallback; the separate raw receipt never receives these values. */
[[nodiscard]] membership_state::Identity
make_identity(const service::client_identity::ClientIdentity& parsed) noexcept {
    const state::AccountState account = state::account_snapshot();
    membership_state::Identity identity = make_raw_identity(parsed);
    // The second (foreign) activity instance sends the same fixed identity schema but leaves its
    // account and character lanes clear. Reflecting those clear lanes replaces the valid identity
    // seeded by its join, and the simulation membership watcher then refuses member zero. The
    // primary activity instance supplies both values, so this fallback is inert on its full update.
    identity.accountSoid = parsed.accountSoid != 0 ? parsed.accountSoid : account.primarySoid;
    identity.opaqueSoid = parsed.field5 != 0
                              ? parsed.field5
                              : state::account::selected_character_soid(account);
    return identity;
}

/**
 * Reports one client identity update.
 * Without it, a run where the client sent its own identity looks the same as one where message 12
 * shipped the seeded fallback all the way.
 * @param parsed Typed identity the client sent.
 */
void report_identity(const service::client_identity::ClientIdentity& parsed) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written =
        std::snprintf(line.data(),
                      line.size(),
                      "ev=activity stage=identity result=ok key=0x%llX field1=%d field2=%d "
                      "field3=0x%llX acct=0x%llX field5=0x%llX field6=0x%llX",
                      static_cast<unsigned long long>(parsed.memberKey),
                      static_cast<int>(parsed.field1),
                      static_cast<int>(parsed.field2),
                      static_cast<unsigned long long>(parsed.field3),
                      static_cast<unsigned long long>(parsed.accountSoid),
                      static_cast<unsigned long long>(parsed.field5),
                      static_cast<unsigned long long>(parsed.field6));
    if (written > 0) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(written)});
    }
}

} // namespace

/** Stages a changed identity push or an unchanged transactional no-op. */
bool prepare_identity(state::activity::ActivityInstanceKey key,
                      const service::Request& request,
                      ActivityPlan& plan) noexcept {
    service::client_identity::ClientIdentity parsed{};
    if (!static_cast<bool>(key) || request.accountHandle != key.sessionId
        || !service::client_identity::parse_client_identity(request.payload, parsed)) {
        return false;
    }
    report_identity(parsed);
    if (!membership_state::prepare_client_identity(key, make_raw_identity(parsed),
            make_identity(parsed), plan.membershipMutation)) {
        core::log::write(core::log::Channel::server,
                         core::log::Level::warn,
                         "ev=activity stage=identity result=refused");
        return false;
    }
    plan.instanceKey = plan.membershipMutation.instanceKey;
    plan.sessionId = key.sessionId;
    plan.delivery =
        plan.membershipMutation.changesState ? Delivery::membershipNotification : Delivery::none;
    plan.mutationDomain = MutationDomain::membership;
    return true;
}

/** Stages the kept host-state changes, and an updated snapshot only when needed. */
bool prepare_authoritative(state::activity::ActivityInstanceKey key,
                           const service::Request& request,
                           ActivityPlan& plan) noexcept {
    service::client_authoritative_data::ClientAuthoritativeData parsed{};
    if (!static_cast<bool>(key) || request.accountHandle != key.sessionId
        || !service::client_authoritative_data::parse_client_authoritative_data(request.payload,
                                                                                parsed)) {
        report_authoritative("parse_failed", key, request.payload.size(), parsed, nullptr);
        return false;
    }
    membership_state::RegionSnapshotInputs inputs{};
    if(!membership_state::snapshot_region_inputs(key,key,{},inputs)) { return false; }
    const std::string_view destination(
        reinterpret_cast<const char*>(inputs.destination.packageName.data()),
        inputs.destination.packageNameLength);
    if (!membership_state::prepare_authoritative(
            key, make_authoritative(parsed,destination), plan.membershipMutation)) {
        report_authoritative("state_refused", key, request.payload.size(), parsed, nullptr, destination);
        return false;
    }
    plan.instanceKey = plan.membershipMutation.instanceKey;
    plan.sessionId = key.sessionId;
    plan.regionMoved = plan.membershipMutation.movesRegion;
    plan.transitionStarted = plan.membershipMutation.movesTransitionToken;
    // A region move sends the roster even when the host state did not change, because the bubble
    // the player just entered has no authority until the roster grants it.
    plan.delivery = plan.membershipMutation.hasSnapshot || plan.regionMoved
                        ? Delivery::authoritativeNotifications
                        : Delivery::none;
    plan.mutationDomain = MutationDomain::membership;
    report_authoritative("ok", key, request.payload.size(), parsed, &plan.membershipMutation, destination);
    return true;
}

/** Stages a stable membership resend guarded by the current State revisions. */
bool prepare_refresh(state::activity::ActivityInstanceKey key,
                     const service::Request& request,
                     ActivityPlan& plan) noexcept {
    service::state_refresh::StateRefresh parsed{};
    if (!static_cast<bool>(key) || request.accountHandle != key.sessionId
        || !service::state_refresh::parse_state_refresh(request.payload, parsed)
        || !membership_state::prepare_refresh(key,
                                              parsed.membershipRevision,
                                              parsed.bubbleIndex,
                                              plan.membershipMutation)) {
        return false;
    }
    plan.instanceKey = plan.membershipMutation.instanceKey;
    plan.sessionId = key.sessionId;
    // A refresh asks for the whole host snapshot. Answering with membership alone leaves the
    // client's own request half answered, and the global state and roster are what it re-reads.
    plan.delivery = Delivery::refreshNotifications;
    plan.mutationDomain = MutationDomain::membership;
    return true;
}

/** Stages a matching acknowledgement update or a transactional no-op. */
bool prepare_acknowledgement(state::activity::ActivityInstanceKey key,
                             const service::Request& request,
                             ActivityPlan& plan) noexcept {
    service::membership_acknowledgement::MembershipAcknowledgement parsed{};
    if (!static_cast<bool>(key) || request.accountHandle != key.sessionId
        || !service::membership_acknowledgement::parse_membership_acknowledgement(request.payload,
                                                                                  parsed)
        || !membership_state::prepare_acknowledgement(
            key, parsed.membershipRevision, plan.membershipMutation)) {
        return false;
    }
    plan.instanceKey = plan.membershipMutation.instanceKey;
    plan.sessionId = key.sessionId;
    plan.delivery = Delivery::none;
    plan.mutationDomain = MutationDomain::membership;
    return true;
}

} // namespace dawn::server::bap::encrypted::activity_message::membership
