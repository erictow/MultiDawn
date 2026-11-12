#include "gameplay_advertisement.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../client/hooks/retail_log/retail_log_enqueue_observer.h"
#include "../../state/activity/definition.h"
#include "../../state/activity/runtime.h"
#include "../../state/gameplay/replication_roles.h"
#include "endpoint/gameplay_endpoint.h"
#include "gameplay_log.h"
#include "group/group_host.h"

namespace dawn::server::gameplay {

namespace {

namespace message = middleware::bap::activity_message::replicate_membership;

/** Member-slot fields are 6 bits at bias 1, so the slot itself cannot exceed 62. */
constexpr std::uint8_t kMaximumMemberSlot = 62;
/** Slot a readiness query stands in with. Every publisher names the one member it publishes. */
constexpr std::uint8_t kQueriedMemberSlot = 0;
/** Odd multiplier that spreads one region index across the whole 64-bit space. */
constexpr std::uint64_t kRegionStride = 0x9E3779B97F4A7C15ULL;

/**
 * Derives one region's copy of an identity field.
 * It is derived rather than allocated so every push for a region names the same value with no
 * table.
 * @param base Whole-process identity field.
 * @param regionIndex Region the record belongs to.
 * @return Nonzero value for that region.
 */
[[nodiscard]] std::uint64_t region_identity(std::uint64_t base, std::int32_t regionIndex) noexcept {
    const auto region = static_cast<std::uint64_t>(static_cast<std::uint32_t>(regionIndex));
    const std::uint64_t derived = base ^ (kRegionStride * (region + 1U));
    // The descriptor refuses a zero machine id and a zero session id alike.
    return derived == 0 ? kRegionStride : derived;
}

/**
 * Derives the descriptor machine id one region advertises.
 * It is also the key of that region's activity host session, so a readiness query has to derive it
 * the same way the advertisement does.
 * @param regionIndex Region the record belongs to.
 * @return The region's machine id.
 */
[[nodiscard]] std::uint64_t region_machine_id(std::int32_t regionIndex) noexcept {
    return region_identity(endpoint::identity().machineId, regionIndex);
}

/** No outcome packs to this, so the first advertisement always reports. */
constexpr std::uint64_t kNoOutcome = ~0ULL;
/** Ambassador slot sits above the region index, which holds the low 32 bits. */
constexpr unsigned kSlotShift = 32;
/** Skip reason sits above the ambassador slot. */
constexpr unsigned kReasonShift = 40;
/** Region source sits above the skip reason. */
constexpr unsigned kSourceShift = 48;

/** Why an advertisement was not built. Reported so a silent skip cannot look like a send. */
enum class Skip : std::uint64_t {
    none,
    notReady,
    noRegion,
    slotRange,
    descriptor,
    noHostSession,
    hostSessionFull
};

std::atomic<std::uint64_t> g_reported{kNoOutcome};

/** Log names for RegionSource, in its declaration order. */
constexpr const char* kSources[] = {"reported", "arrival"};

/**
 * Reports one advertisement outcome, and only when it differs from the last.
 * A membership push runs every few seconds, so an unchanged outcome must stay silent.
 * @param skip Check that refused the build, or Skip::none.
 * @param regionIndex Region the outcome belongs to.
 * @param regionSource Where that index came from.
 * @param ambassadorSlot Slot the advertisement named, or zero when it did not build.
 */
void report_outcome(Skip skip,
                    std::int32_t regionIndex,
                    RegionSource regionSource,
                    std::uint8_t ambassadorSlot) noexcept {
    const auto outcome = static_cast<std::uint64_t>(static_cast<std::uint32_t>(regionIndex))
                         | (static_cast<std::uint64_t>(ambassadorSlot) << kSlotShift)
                         | (static_cast<std::uint64_t>(skip) << kReasonShift)
                         | (static_cast<std::uint64_t>(regionSource) << kSourceShift);
    if (g_reported.exchange(outcome, std::memory_order_relaxed) == outcome) {
        return;
    }
    const char* source = kSources[static_cast<std::size_t>(regionSource)];
    if (skip == Skip::none) {
        report(core::log::Level::info,
               "ev=gameplay stage=advertise result=ok region=%d region_source=%s "
               "ambassador_slot=%u",
               static_cast<int>(regionIndex),
               source,
               static_cast<unsigned>(ambassadorSlot));
        return;
    }
    // Log names for Skip, in its declaration order.
    static constexpr const char* kReasons[] = {"none",
                                               "not_ready",
                                               "no_region",
                                               "slot_range",
                                               "descriptor",
                                               "no_host_session",
                                               "host_session_full"};
    report(core::log::Level::info,
           "ev=gameplay stage=advertise result=skip reason=%s region=%d region_source=%s",
           kReasons[static_cast<std::size_t>(skip)],
           static_cast<int>(regionIndex),
           source);
}

/**
 * Picks an ambassador slot that is not the joining client's own.
 * An equal slot sends the peer into the local-ambassador stage, and it never reaches the citizen
 * join.
 * @param localMemberSlot Slot the joining client occupies.
 * @return A different, encodable member slot.
 */
[[nodiscard]] std::uint8_t ambassador_slot(std::uint8_t localMemberSlot) noexcept {
    return localMemberSlot == 0 ? 1 : 0;
}

/** Builds the endpoint-derived, record-independent descriptor inputs for one region. */
[[nodiscard]] Skip prepare_join(std::int32_t regionIndex,
                                std::uint8_t localMemberSlot,
                                middleware::gameplay::descriptor::JoinEndpoint& join) noexcept {
    join = {};
    if (!endpoint::ready()) {
        return Skip::notReady;
    }
    if (regionIndex < 0) {
        return Skip::noRegion;
    }
    if (localMemberSlot > kMaximumMemberSlot) {
        return Skip::slotRange;
    }
    const state::gameplay::Endpoint advertised = endpoint::advertised();
    join.address = advertised.address;
    join.port = advertised.port;
    join.machineId = region_machine_id(regionIndex);
    join.onlineSessionId = region_identity(endpoint::identity().onlineSessionId, regionIndex);
    return Skip::none;
}

/**
 * Builds one region's advertisement, or names the first check that refused it.
 * Every caller runs this same body, so a readiness query and the advertisement itself can never
 * disagree about whether a descriptor is coming.
 * @param regionIndex Region the record belongs to.
 * @param localMemberSlot Member slot of the joining client.
 * @param candidate Cleared, then filled when the whole advertisement builds.
 * @return Skip::none when it built, otherwise the check that refused.
 */
template <class SourceActivity>
[[nodiscard]] Skip build_candidate(SourceActivity sourceActivity,
                                   std::int32_t regionIndex,
                                   std::uint8_t localMemberSlot,
                                   message::CitizenAdvertisement& candidate) noexcept {
    candidate = {};
    middleware::gameplay::descriptor::JoinEndpoint join{};
    const Skip prepared = prepare_join(regionIndex, localMemberSlot, join);
    if (prepared != Skip::none) {
        return prepared;
    }
    // The region compares this against the `activity-host` parameter and errors out with
    // `public_activity_host_mismatch` when they disagree, so both carry the same allocated id.
    // The key is the machine id, because that is what the peer echoes in every later message.
    bool claimedSlot = false;
    const std::uint64_t hostSession =
        group::activity_host_session(
            join.machineId, regionIndex, sourceActivity, claimedSlot);
    if (hostSession == state::activity::kAbsentSessionId) {
        // A claimed slot is filled by the next service slice. An unclaimed one never will be, so
        // the two must not read the same to a caller deciding whether to wait.
        return claimedSlot ? Skip::noHostSession : Skip::hostSessionFull;
    }
    if (!middleware::gameplay::descriptor::build(join, candidate.descriptor)) {
        candidate = {};
        return Skip::descriptor;
    }
    client::hooks::retail_log::register_gameplay_join_descriptor(candidate.descriptor.data(),
                                                                 candidate.descriptor.size(),
                                                                 regionIndex,
                                                                 hostSession);
    candidate.memberKey = join.machineId;
    middleware::gameplay::descriptor::write_net_addr(
        join.address, join.port, candidate.address);
    candidate.onlineSessionId = hostSession;
    candidate.regionIndex = regionIndex;
    candidate.ambassadorSlot = ambassador_slot(localMemberSlot);
    candidate.present = true;
    state::gameplay::replication::Address roleAddress{};
    for(std::size_t i=0;i<roleAddress.size();++i)roleAddress[i]=std::to_integer<unsigned char>(candidate.address[i]);
    (void)state::gameplay::replication::publish_control_host(join.machineId,roleAddress);
    return Skip::none;
}

} // namespace

/** Requests exact creator-root advertisement provisioning without building wire data. */
AdvertisementReadiness request_advertisement_host(
    state::activity::ActivityInstanceKey source,
    std::int32_t region) noexcept {
    middleware::gameplay::descriptor::JoinEndpoint join{};
    const Skip prepared = prepare_join(region, kQueriedMemberSlot, join);
    if (prepared != Skip::none) {
        return AdvertisementReadiness::absent;
    }
    if (!static_cast<bool>(source) || !state::activity::contains(source)) {
        return AdvertisementReadiness::stale;
    }
    bool claimed = false;
    const std::uint64_t host =
        group::activity_host_session(join.machineId, region, source, claimed);
    if (host != state::activity::kAbsentSessionId) {
        return AdvertisementReadiness::ready;
    }
    return claimed ? AdvertisementReadiness::pending : AdvertisementReadiness::absent;
}

namespace {

/** Shared exact acquisition; diagnostic observation deliberately skips publication hooks. */
[[nodiscard]] bool acquire_snapshot(state::activity::ActivityInstanceKey source,
                                     std::int32_t region,
                                     AdvertisementSnapshot& output,
                                     group::HostActivityLineageLease& lease,
                                     bool publish) noexcept {
    output = {};
    group::release_host_activity_lineage(lease);
    middleware::gameplay::descriptor::JoinEndpoint join{};
    const Skip prepared = prepare_join(region, kQueriedMemberSlot, join);
    if (prepared != Skip::none) {
        output.readiness = AdvertisementReadiness::absent;
        return true;
    }
    if (!static_cast<bool>(source) || !state::activity::contains(source)) {
        output.readiness = AdvertisementReadiness::stale;
        return false;
    }
    const state::activity::ActivityInstanceKey host =
        group::held_host_activity(join.machineId);
    if (!static_cast<bool>(host)
        || !group::acquire_host_activity_lineage(host, lease)
        || lease.groupSessionId != join.machineId || lease.host != host
        || lease.source != source || lease.regionIndex != region
        || !state::activity::contains(host)) {
        group::release_host_activity_lineage(lease);
        output.readiness = AdvertisementReadiness::stale;
        return false;
    }
    message::CitizenAdvertisement citizen{};
    if (!middleware::gameplay::descriptor::build(join, citizen.descriptor)) {
        group::release_host_activity_lineage(lease);
        return false;
    }
    citizen.memberKey = join.machineId;
    middleware::gameplay::descriptor::write_net_addr(join.address, join.port, citizen.address);
    citizen.onlineSessionId = host.sessionId;
    citizen.regionIndex = region;
    citizen.ambassadorSlot = ambassador_slot(kQueriedMemberSlot);
    citizen.present = true;
    if (publish) {
        state::gameplay::replication::Address roleAddress{};
        for(std::size_t i=0;i<roleAddress.size();++i)roleAddress[i]=std::to_integer<unsigned char>(citizen.address[i]);
        (void)state::gameplay::replication::publish_control_host(join.machineId,roleAddress);
        client::hooks::retail_log::register_gameplay_join_descriptor(citizen.descriptor.data(),
                                                                     citizen.descriptor.size(),
                                                                     region,
                                                                     host.sessionId);
    }
    output.citizen = citizen;
    output.host = host;
    output.source = source;
    output.regionIndex = region;
    output.readiness = AdvertisementReadiness::ready;
    return true;
}

} // namespace

/** Acquires a complete exact advertisement snapshot without provisioning or State selection. */
bool acquire_advertisement_snapshot(state::activity::ActivityInstanceKey source,
                                    std::int32_t region,
                                    AdvertisementSnapshot& output,
                                    group::HostActivityLineageLease& lease) noexcept {
    return acquire_snapshot(source, region, output, lease, true);
}

bool acquire_advertisement_observation(state::activity::ActivityInstanceKey source,
                                       std::int32_t region,
                                       AdvertisedActivityObservation& output,
                                       group::HostActivityLineageLease& lease) noexcept {
    output = {};
    AdvertisementSnapshot snapshot{};
    const bool acquired = acquire_snapshot(source, region, snapshot, lease, false);
    output.readiness = snapshot.readiness;
    if (acquired && snapshot.readiness == AdvertisementReadiness::ready) {
        output.groupMachineId = snapshot.citizen.memberKey;
        output.host = snapshot.host;
        output.source = snapshot.source;
        output.regionIndex = snapshot.regionIndex;
    }
    return acquired;
}

/** Builds the citizen advertisement for one region record. */
void build_advertisement(std::uint64_t sourceSessionId,
                         std::int32_t regionIndex,
                         RegionSource regionSource,
                         std::uint8_t localMemberSlot,
                         message::CitizenAdvertisement& output) noexcept {
    const Skip skip = build_candidate(sourceSessionId, regionIndex, localMemberSlot, output);
    report_outcome(skip, regionIndex, regionSource, output.ambassadorSlot);
}

/** Builds the citizen advertisement for one exact source activity lifetime. */
void build_advertisement(state::activity::ActivityInstanceKey sourceActivity,
                         std::int32_t regionIndex,
                         RegionSource regionSource,
                         std::uint8_t localMemberSlot,
                         message::CitizenAdvertisement& output) noexcept {
    const Skip skip = build_candidate(sourceActivity, regionIndex, localMemberSlot, output);
    report_outcome(skip, regionIndex, regionSource, output.ambassadorSlot);
}

/** Reports whether one region's advertisement can be built now. */
AdvertisementState advertisement_state(std::uint64_t sourceSessionId,
                                       std::int32_t regionIndex) noexcept {
    message::CitizenAdvertisement candidate{};
    // The same body the advertisement runs, so it cannot promise a descriptor the build refuses.
    // It also claims the region's host-session slot, so the service slice allocates one.
    switch (build_candidate(sourceSessionId, regionIndex, kQueriedMemberSlot, candidate)) {
    case Skip::none:
        return AdvertisementState::ready;
    case Skip::noHostSession:
        return AdvertisementState::pending;
    default:
        return AdvertisementState::absent;
    }
}


/** Reports advertisement readiness for one exact source activity lifetime. */
AdvertisementState advertisement_state(state::activity::ActivityInstanceKey sourceActivity,
                                       std::int32_t regionIndex) noexcept {
    message::CitizenAdvertisement candidate{};
    switch (build_candidate(sourceActivity, regionIndex, kQueriedMemberSlot, candidate)) {
    case Skip::none:
        return AdvertisementState::ready;
    case Skip::noHostSession:
        return AdvertisementState::pending;
    default:
        return AdvertisementState::absent;
    }
}

} // namespace dawn::server::gameplay
