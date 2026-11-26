#pragma once

#include <cstdint>

#include "../../middleware/bap/activity_message/replicate_membership.h"
#include "../../state/activity/lifecycle_generation.h"
#include "group/group_host_sessions.h"

namespace dawn::server::gameplay {

/** Where an advertised region index came from. Reported so a stand-in cannot look like a report. */
enum class RegionSource : std::uint8_t {
    /** The client reported the region it is in. */
    reported,
    /** No report has arrived, so the destination's arrival slice set stood in. */
    arrival,
};

/**
 * Builds the citizen advertisement for one region record.
 * It stays empty unless the endpoint is bound and the region index names a real record, so a
 * disabled or unbound channel publishes exactly the membership body it published before.
 * @param sourceSessionId Activity session whose destination the advertised host must inherit.
 * @param regionIndex Region the roster publishes for this session.
 * @param regionSource Where that index came from.
 * @param localMemberSlot Member slot of the joining client.
 * @param output Cleared, then filled when the channel can be advertised.
 */
void build_advertisement(
    std::uint64_t sourceSessionId,
    std::int32_t regionIndex,
    RegionSource regionSource,
    std::uint8_t localMemberSlot,
    middleware::bap::activity_message::replicate_membership::CitizenAdvertisement& output) noexcept;

/** Exact source-activity overload used by BAP binding-owned publishers. */
void build_advertisement(
    state::activity::ActivityInstanceKey sourceActivity,
    std::int32_t regionIndex,
    RegionSource regionSource,
    std::uint8_t localMemberSlot,
    middleware::bap::activity_message::replicate_membership::CitizenAdvertisement& output) noexcept;

/** Whether one region's advertisement can be built now. */
enum class AdvertisementState : std::uint8_t {
    /** It builds, so a push carries the descriptor and the host session. */
    ready,
    /** Only the region's activity host session is missing, and the next service slice fills it. */
    pending,
    /** The channel advertises nothing at all, so the published body is unchanged either way. */
    absent,
};

/** Provisioning/readiness result for one exact creator-root region host. */
enum class AdvertisementReadiness : std::uint8_t {
    ready,
    pending,
    absent,
    stale,
};

/** Immutable exact advertisement after-image held with a group-row lineage lease. */
struct AdvertisementSnapshot final {
    middleware::bap::activity_message::replicate_membership::CitizenAdvertisement citizen{};
    state::activity::ActivityInstanceKey host{};
    state::activity::ActivityInstanceKey source{};
    std::int32_t regionIndex{-1};
    AdvertisementReadiness readiness{AdvertisementReadiness::absent};
};

/** Idempotently requests one exact advertisement host without building a wire body. */
[[nodiscard]] AdvertisementReadiness request_advertisement_host(
    state::activity::ActivityInstanceKey source,
    std::int32_t region) noexcept;

/** Acquires one complete immutable advertisement snapshot and its stable group-row pin. */
[[nodiscard]] bool acquire_advertisement_snapshot(
    state::activity::ActivityInstanceKey source,
    std::int32_t region,
    AdvertisementSnapshot& output,
    group::HostActivityLineageLease& lease) noexcept;

/** Public identity/lineage scalars only; no descriptor or NetAddr body is exposed. */
struct AdvertisedActivityObservation final {
    std::uint64_t groupMachineId{};
    state::activity::ActivityInstanceKey host{};
    state::activity::ActivityInstanceKey source{};
    std::int32_t regionIndex{-1};
    AdvertisementReadiness readiness{AdvertisementReadiness::absent};
    friend constexpr bool operator==(const AdvertisedActivityObservation&,
                                      const AdvertisedActivityObservation&) noexcept = default;
};

/**
 * Acquires the existing exact host-row pin without provisioning, publishing a control-host
 * role or registering a native descriptor. Non-ready results contain no routing identities.
 */
[[nodiscard]] bool acquire_advertisement_observation(
    state::activity::ActivityInstanceKey source,
    std::int32_t region,
    AdvertisedActivityObservation& output,
    group::HostActivityLineageLease& lease) noexcept;

/**
 * Reports whether one region's advertisement can be built now.
 * The client applies one membership update per revision. Publishing during `pending` spends that
 * revision on a region record with no descriptor, so a publisher must hold instead.
 * @param sourceSessionId Activity session whose destination the advertised host must inherit.
 * @param regionIndex Region the roster publishes for this session.
 * @return Which of the three states the advertisement is in.
 */
[[nodiscard]] AdvertisementState advertisement_state(std::uint64_t sourceSessionId,
                                                     std::int32_t regionIndex) noexcept;

/** Exact source-activity overload used by BAP binding-owned publishers. */
[[nodiscard]] AdvertisementState advertisement_state(
    state::activity::ActivityInstanceKey sourceActivity,
    std::int32_t regionIndex) noexcept;

} // namespace dawn::server::gameplay
