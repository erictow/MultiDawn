#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

#include "../../middleware/bap/activity_message/replicate_membership.h"
#include "../../server/gameplay/resolution/address_resolution_host.h"

namespace dawn::core::multiplayer::world_roster {

namespace bap = middleware::bap::activity_message::replicate_membership;
namespace resolver = server::gameplay::resolution;

/** One recipient's exact local activity and native membership table lifetime. */
struct Recipient final {
    state::activity::BindingKey binding{};
    /** Exact owner from the authenticated control route. The primary BAP channel can differ from the creator. */
    state::activity::AuthenticationKey resolverOwner{};
    state::activity::HostRegionKey region{};
    std::uint64_t localMachine{}, controlMachine{};
    /** Monotonic native table lifetime proven by its owner. Region/facet changes alone are insufficient. */
    std::uint64_t tableGeneration{};
    /** The current on-wire epoch may be zero or repeat across different native tables. */
    std::uint32_t wireEpoch{};
    std::int32_t regionIndex{-1};

    [[nodiscard]] explicit constexpr operator bool() const noexcept {
        return binding && resolverOwner && region && localMachine != 0 && controlMachine != 0
            && localMachine != controlMachine && tableGeneration != 0
            && regionIndex >= 0 && regionIndex <= bap::kMaximumRegionIndex;
    }
    friend constexpr bool operator==(Recipient, Recipient) noexcept = default;
};

/** Input from a trusted handoff owner after validating the guest and the grant. */
struct Peer final {
    bap::RemoteHuman human{};
    resolver::PeerAddressHandle registeredAddress{};
    std::uint64_t grantGeneration{}, deadline{};
};

struct SlotHandle final {
    std::uint64_t generation{};
    std::uint8_t nativeSlot{};
    [[nodiscard]] explicit constexpr operator bool() const noexcept { return generation != 0; }
    friend constexpr bool operator==(SlotHandle, SlotHandle) noexcept = default;
};

/** Observes that an exact address registration still exists, without retaining it. */
using CheckAddress = bool (*)(resolver::PeerAddressHandle, std::span<const std::byte>) noexcept;

/**
 * Projects admitted rows for one recipient. This owns no resolver registrations,
 * invitation tickets, BAP connections or network callbacks. The caller serializes
 * use, revalidates grant/binding/lineage before each operation and owns cleanup.
 * Retired slots cannot be reused until the caller has verified a fresh native table.
 * Changing a wire value, resolver authentication, region or facet does not supply that proof.
 */
class Projection final {
public:
    Projection() = default;
    Projection(const Projection&) = delete;
    Projection& operator=(const Projection&) = delete;

    [[nodiscard]] bool open(Recipient current) noexcept {
        if (!current) return false;
        if (current == recipient_) return true;
        if (current.tableGeneration <= recipient_.tableGeneration
            || std::any_of(rows_.begin(), rows_.end(), [](const Row& row) { return row.active; })) {
            return false;
        }
        recipient_ = current;
        rows_ = {};
        extent_ = 0;
        return true;
    }

    /** Failure clears the output handle and makes no change to the roster. */
    [[nodiscard]] bool add(Recipient current, const bap::MembershipSnapshot& base,
                           const Peer& peer, std::uint64_t now, CheckAddress checkAddress,
                           SlotHandle& added) noexcept {
        added = {};
        if (extent_ == rows_.size() || nextGeneration_ == UINT64_MAX || !peer.human.present
            || !peer.registeredAddress || peer.registeredAddress.owner != current.resolverOwner
            || peer.grantGeneration == 0 || peer.deadline <= now || checkAddress == nullptr) return false;

        for (std::size_t index = 0; index < extent_; ++index) {
            const auto& row = rows_[index];
            if (row.memberKey == peer.human.identity.memberKey || row.grantGeneration == peer.grantGeneration
                || (row.active && row.peer.registeredAddress == peer.registeredAddress)) return false;
        }
        bap::MembershipSnapshot candidate{};
        if (!project(current, base, now, checkAddress, candidate)) return false;
        candidate.remoteHumans[extent_] = peer.human;
        candidate.remoteHumanCount = static_cast<std::uint8_t>(extent_ + 1);
        if (!bap::valid(candidate) || !checkAddress(peer.registeredAddress, peer.human.address)) return false;

        const SlotHandle handle{++nextGeneration_, static_cast<std::uint8_t>(bap::kFirstRemoteHumanSlot + extent_)};
        rows_[extent_++] = {peer, handle, peer.human.identity.memberKey, peer.grantGeneration, true};
        added = handle;
        return true;
    }

    /** Leaves output untouched on refusal. The caller rechecks before committing a BAP send. */
    [[nodiscard]] bool project(Recipient current, const bap::MembershipSnapshot& base,
                               std::uint64_t now, CheckAddress checkAddress,
                               bap::MembershipSnapshot& output) const noexcept {
        if (!current || current != recipient_ || base.epoch != current.wireEpoch
            || base.identity.memberKey != current.localMachine || !base.citizen.present
            || base.citizen.memberKey != current.controlMachine || base.citizen.regionIndex != current.regionIndex
            || base.remoteHumanCount != 0) return false;
        for (const auto& human : base.remoteHumans) {
            if (human.present) return false;
        }

        auto candidate = base;
        candidate.remoteHumans = {};
        candidate.remoteHumanCount = extent_;
        for (std::size_t index = 0; index < extent_; ++index) {
            const auto& row = rows_[index];
            if (!row.active) continue;
            if (row.peer.deadline <= now || checkAddress == nullptr
                || !checkAddress(row.peer.registeredAddress, row.peer.human.address)) return false;
            candidate.remoteHumans[index] = row.peer.human;
        }
        if (!bap::valid(candidate)) return false;
        output = candidate;
        return true;
    }

    /** Retires the exact slot and hands its registration back to the owner for revocation. */
    [[nodiscard]] bool retire(Recipient owner, SlotHandle handle, resolver::PeerAddressHandle& revoke) noexcept {
        revoke = {};
        if (owner != recipient_ || !handle || handle.nativeSlot < bap::kFirstRemoteHumanSlot) return false;
        const auto index = handle.nativeSlot - bap::kFirstRemoteHumanSlot;
        if (index >= extent_) return false;
        auto& row = rows_[index];
        if (!row.active || row.handle != handle) return false;
        revoke = row.peer.registeredAddress;
        row.peer = {};
        row.active = false;
        return true;
    }

private:
    struct Row final {
        Peer peer{};
        SlotHandle handle{};
        std::uint64_t memberKey{}, grantGeneration{};
        bool active{};
    };

    Recipient recipient_{};
    std::array<Row, bap::kMaximumRemoteHumans> rows_{};
    std::uint64_t nextGeneration_{};
    std::uint8_t extent_{};
};

} // namespace dawn::core::multiplayer::world_roster
