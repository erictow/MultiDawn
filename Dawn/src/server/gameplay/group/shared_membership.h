#pragma once

#include <array>
#include <span>

#include "../../../core/multiplayer/fireteam_limits.h"
#include "../../../middleware/gameplay/group/session_messages.h"
#include "../../../state/gameplay/definition.h"

namespace dawn::server::gameplay::group {

inline constexpr std::uint32_t kSharedHumanCapacity = core::multiplayer::fireteam::kMaximumHumans;
inline constexpr std::uint32_t kInvalidSharedHumanSlot = kSharedHumanCapacity;
static_assert(kSharedHumanCapacity + 1 <= middleware::gameplay::group::kMemberCapacity);
static_assert(kSharedHumanCapacity <= middleware::gameplay::group::kPlayerCapacity);

/** Stable native slot ownership for one group's lifetime, independent of live endpoints. */
struct SharedSlotAssignments {
    struct Owner { std::uint64_t machineId{}; std::uint64_t initialPlayerId{}; };
    std::array<Owner, kSharedHumanCapacity> owners{};

    /** A disconnected identity retains its slot; a new identity cannot replace it. */
    [[nodiscard]] bool reserve(std::uint64_t machineId, std::uint64_t initialPlayerId,
                               std::uint32_t& slot) noexcept {
        if (machineId == 0 || initialPlayerId == 0) { return false; }
        for (std::uint32_t index = 0; index < owners.size(); ++index) {
            const auto& owner = owners[index];
            if (owner.machineId == machineId || owner.initialPlayerId == initialPlayerId) {
                if (owner.machineId != machineId || owner.initialPlayerId != initialPlayerId) { return false; }
                slot = index;
                return true;
            }
        }
        for (std::uint32_t index = 0; index < owners.size(); ++index) {
            if (owners[index].machineId == 0) {
                owners[index] = {machineId, initialPlayerId};
                slot = index;
                return true;
            }
        }
        return false;
    }
};

/** An authenticated human's exact native identity and current group state. */
struct SharedHuman {
    state::gameplay::Endpoint endpoint{};
    std::array<std::byte, middleware::gameplay::descriptor::kNetAddrSize> address{};
    std::uint64_t machineId{};
    std::uint64_t joinId{};
    std::uint64_t playerId{};
    std::uint32_t addSequence{};
    /** Stable global player slot; its owning member index is slot + 1. */
    std::uint32_t slot{kInvalidSharedHumanSlot};
    bool hasPlayer{};
    bool established{};
};

/** Owns every row referenced by six humans and one activity control host. */
struct SharedMembershipSnapshot {
    std::array<middleware::gameplay::group::MembershipMember, kSharedHumanCapacity + 1> members{};
    std::array<middleware::gameplay::group::MembershipPlayer, kSharedHumanCapacity> players{};
    std::size_t memberCount{};
    std::size_t playerCount{};
    std::uint64_t hostMachineId{};
    std::uint32_t revision{};

    [[nodiscard]] middleware::gameplay::group::MembershipUpdate update() const noexcept {
        return {hostMachineId, revision, 0, 0,
                std::span(members).first(memberCount), std::span(players).first(playerCount)};
    }
};
static_assert(sizeof(SharedMembershipSnapshot) <= 2 * 1024);
static_assert(sizeof(SharedHuman) * kSharedHumanCapacity <= 1024);

/**
 * Builds the exact existing native membership schema for one through six human peers.
 * It does not invent profile/entity property bodies. The inputs must come from the
 * authenticated runtime boundary and the peers' own native publications.
 * Failure leaves output unchanged.
 */
[[nodiscard]] inline bool build_shared_membership(
    std::uint64_t hostMachineId,
    const std::array<std::byte, middleware::gameplay::descriptor::kNetAddrSize>& hostAddress,
    std::uint64_t joiningId,
    std::uint32_t revision,
    std::span<const SharedHuman> humans,
    SharedMembershipSnapshot& output) noexcept {
    if (hostMachineId == 0 || joiningId == 0 || revision == 0
        || humans.empty() || humans.size() > kSharedHumanCapacity) { return false; }
    const auto usableAddress = [](const auto& address) noexcept {
        bool any = false;
        for (const auto byte : address) { any = any || byte != std::byte{}; }
        return any && std::to_integer<unsigned>(address.back()) <= 7;
    };
    if (!usableAddress(hostAddress)) { return false; }
    bool joiningPresent = false;
    std::array<const SharedHuman*, kSharedHumanCapacity> bySlot{};
    for (std::size_t index = 0; index < humans.size(); ++index) {
        const auto& human = humans[index];
        if (human.machineId == 0 || human.machineId == hostMachineId || human.joinId == 0
            || human.endpoint.address == 0 || human.endpoint.port == 0
            || !usableAddress(human.address)
            || (human.hasPlayer && human.playerId == 0)
            || human.slot >= bySlot.size() || bySlot[human.slot] != nullptr) { return false; }
        bySlot[human.slot] = &human;
        joiningPresent = joiningPresent || human.joinId == joiningId;
        for (std::size_t earlier = 0; earlier < index; ++earlier) {
            const auto& other = humans[earlier];
            if (human.machineId == other.machineId
                || (human.endpoint.address == other.endpoint.address && human.endpoint.port == other.endpoint.port)
                || (human.hasPlayer && other.hasPlayer && human.playerId == other.playerId)) { return false; }
        }
    }
    if (!joiningPresent) { return false; }
    // The recovered member codec and native hash use contiguous occupied member
    // indices. Until a sparse-member codec is recovered, refuse a lower-slot gap
    // instead of moving a surviving human into another member/player identity.
    for (std::size_t index = 0; index < humans.size(); ++index) {
        if (bySlot[index] == nullptr) { return false; }
    }
    namespace wire = middleware::gameplay::group;
    SharedMembershipSnapshot candidate{};
    candidate.hostMachineId = hostMachineId;
    candidate.revision = revision;
    candidate.memberCount = humans.size() + 1;
    auto& host = candidate.members[0];
    host.address = hostAddress;
    host.machineId = hostMachineId;
    host.joinId = joiningId;
    host.connectionPresent = true;
    host.state = wire::MemberState::established;
    for (std::size_t index = 0; index < humans.size(); ++index) {
        const auto& human = *bySlot[index];
        auto& member = candidate.members[index + 1];
        member.address = human.address;
        member.machineId = human.machineId;
        member.joinId = human.joinId;
        member.connectionPresent = true;
        member.state = human.established ? wire::MemberState::established : wire::MemberState::ready;
        if (!human.established && human.joinId == joiningId) { host.state = wire::MemberState::ready; }
        if (human.hasPlayer) {
            member.ownsPlayerSlot = true;
            member.playerSlot = static_cast<std::uint32_t>(index);
            auto& player = candidate.players[candidate.playerCount++];
            player.slot = static_cast<std::uint32_t>(index);
            player.memberIndex = static_cast<std::uint32_t>(index + 1);
            player.playerId = human.playerId;
            player.addSequence = human.addSequence;
        }
    }
    output = candidate;
    return true;
}

} // namespace dawn::server::gameplay::group
