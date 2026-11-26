#pragma once

#include <cstddef>

#include "../../client/network/consumer.h"
#include "../../state/activity/definition.h"
#include "region_lineage.h"

namespace dawn::server::bap {

/** One owner-validated, exact destination/region tuple for the diagnostic HUD. */
struct HudRegionSnapshot final {
    HudRegionAnchor lineage{};
    state::activity::destination::DestinationSelection destination{};
    std::int32_t reportedRegion{-1};
};

/** Copies one coherent current creator-owned HUD region view, or fails closed. */
[[nodiscard]] bool snapshot_hud_region(HudRegionSnapshot& output) noexcept;

/** Known public destination selectors only, without opaque captured descriptor bytes. */
struct CreatorDestination final {
    std::array<std::int8_t, state::activity::destination::kPackageNameCapacity> packageName{};
    std::uint8_t packageNameLength{};
    std::int16_t activityIndex{state::activity::destination::kAbsentActivityIndex};
    std::int8_t reason{state::activity::destination::kMinimumReason};
    friend constexpr bool operator==(const CreatorDestination&, const CreatorDestination&) noexcept = default;
};

/**
 * One current creator-owned BAP activity observation. Contains no account identity,
 * private descriptor, resolver material or native player-ID substitution.
 */
struct CreatorActivitySnapshot final {
    state::activity::BindingKey binding{};
    RegionLineage lineage{};
    state::activity::HostRegionKey hostRegion{};
    CreatorDestination destination{};
    std::int32_t reportedRegion{state::activity::membership::kAbsentRegionIndex};
    std::uint64_t memberKey{};
    /** BAP membership value only. Presence does not prove a native client publication. */
    std::uint64_t joinIdentity{};
    bool hasIdentity{};
    bool identityMatchesMemberKey{};
    friend constexpr bool operator==(const CreatorActivitySnapshot&, const CreatorActivitySnapshot&) noexcept = default;
};

/**
 * Observes the requested binding only if it still owns the exact current committed HUD
 * creator activity and region. Failure clears output. No lifetime is retained or authorized.
 */
[[nodiscard]] bool snapshot_creator_activity(state::activity::BindingKey requested,
                                             CreatorActivitySnapshot& output) noexcept;

/** Atomically selects and observes that same current creator; never chooses the newest session. */
[[nodiscard]] bool snapshot_current_creator_activity(CreatorActivitySnapshot& output) noexcept;

/** Applies one connection-scoped BAP lifecycle event. */
[[nodiscard]] bool consume(const client::network::BapRequest& request,
                           client::network::BapResponse& response) noexcept;

/**
 * Arms every authenticated account peer for a full refresh after an out-of-band account change.
 * A BAP request commits its own mutation and arms the other peers itself. The loadout editor has
 * no request and no origin session, so it publishes through here instead and every peer, including
 * the local Client, is armed. The refresh goes out on the next service poll.
 * @return Number of peers armed. Zero means no authenticated peer holds the account family yet.
 */
std::size_t publish_external_account_mutation() noexcept;

/**
 * Serializes borrower invalidation and exact retirement of one group-owned record.
 * Group code calls this only after transferring the exact owner out of its table and dropping
 * its lock, or from the fenced source-cascade coordinator before that transfer is committed.
 */
[[nodiscard]] state::activity::RetireResult retire_group_owned_activity(
    state::activity::ActivityInstanceKey activity) noexcept;

/** Best-effort nonblocking retry used after a group lineage pin is released. */
void retry_pending_activity_retirements() noexcept;

/** Wipes every connection-owned nonce and transform buffer. */
void shutdown() noexcept;

} // namespace dawn::server::bap
