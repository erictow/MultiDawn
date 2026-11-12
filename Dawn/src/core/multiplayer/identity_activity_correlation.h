#pragma once

#include <bit>
#include <span>

#include "native_identity_observation_state.h"
#include "fireteam_limits.h"

namespace dawn::core::multiplayer::identity_activity {

enum class Result { matched, noMatch, ambiguous, invalidInput };
/** Observation shape only; this does not enable six-player networking or replication. */
inline constexpr auto kMaximumHumanObservations = fireteam::kMaximumHumans;

/** Copied scalar correspondence only. No local-human identity or gameplay access is granted. */
struct Correlation final {
    std::uintptr_t manager{};
    std::uint64_t incarnation{}, generation{}, sampledAt{};
    std::uint64_t creatorMachineId{}, groupMachineId{}, playerId{};
    std::uint32_t hostMemberIndex{}, humanMemberIndex{}, playerSlot{}, playerSequence{};
    std::int32_t role{-1}, mode{-1};
    friend constexpr bool operator==(const Correlation&, const Correlation&) noexcept = default;
};

/** Exact copied correspondence except capture time; native generations are never ignored. */
[[nodiscard]] inline bool same_correspondence(Correlation first, Correlation second) noexcept {
    first.sampledAt = second.sampledAt = 0;
    return first == second;
}

namespace detail {
/** Validate the scalar after-image again so a malformed caller value cannot manufacture a match. */
[[nodiscard]] inline bool consistent(const identity_observation::Sample& sample) noexcept {
    if (sample.role < 0 || sample.role >= 7 || sample.mode < 0 || sample.memberMask == 0
        || sample.hostMemberIndex < 0 || sample.hostMemberIndex >= 32
        || (sample.memberMask & (std::uint32_t{1} << static_cast<unsigned>(sample.hostMemberIndex))) == 0) return false;
    std::uint32_t ownedMask{};
    for (std::size_t index = 0; index < identity_observation::kMemberCapacity; ++index) {
        const auto& member = sample.members[index];
        if ((sample.memberMask & (std::uint32_t{1} << index)) == 0) {
            if (member != identity_observation::Member{}) return false;
            continue;
        }
        if (member.machineId == 0) return false;
        for (std::size_t earlier = 0; earlier < index; ++earlier)
            if (sample.members[earlier].machineId == member.machineId) return false;
        if (!member.ownsPlayer) {
            if (member.playerId != 0 || member.playerSlot != 0 || member.playerSequence != 0) return false;
            continue;
        }
        if (member.playerId == 0 || member.playerSlot >= 32) return false;
        const auto bit = std::uint32_t{1} << member.playerSlot;
        if ((ownedMask & bit) != 0) return false;
        ownedMask |= bit;
        for (std::size_t earlier = 0; earlier < index; ++earlier)
            if (sample.members[earlier].ownsPlayer && sample.members[earlier].playerId == member.playerId) return false;
    }
    return ownedMask == sample.playerMask;
}
} // namespace detail

/**
 * Correlates an exact creator BAP member key and advertised control-group machine with one
 * fresh native after-image. No raw managed-role semantics, Steam ID, join seed or account ID
 * is used to derive a player ID. Caller owns validation of BAP/advertisement/route lifetimes.
 */
[[nodiscard]] inline Result correlate(std::uint64_t creatorMachineId,
    std::uint64_t advertisedGroupId,
    std::span<const identity_observation::Observation> observations,
    std::uint64_t now, Correlation& output) noexcept {
    output = {};
    if (creatorMachineId == 0 || advertisedGroupId == 0 || creatorMachineId == advertisedGroupId
        || observations.size() > identity_observation::kManagerCapacity) return Result::invalidInput;
    bool found{};
    Correlation candidate{};
    for (const auto& observed : observations) {
        if (now < observed.sampledAt) return Result::invalidInput;
        if (now - observed.sampledAt > identity_observation::kMaximumAgeMs) continue;
        if (observed.manager == 0 || observed.incarnation == 0 || observed.generation == 0
            || !detail::consistent(observed.sample)) return Result::invalidInput;
        const auto& sample = observed.sample;
        std::size_t human = identity_observation::kMemberCapacity;
        std::size_t control = identity_observation::kMemberCapacity;
        for (std::size_t index = 0; index < sample.members.size(); ++index) {
            if ((sample.memberMask & (std::uint32_t{1} << index)) == 0) continue;
            if (sample.members[index].machineId == creatorMachineId) human = index;
            if (sample.members[index].machineId == advertisedGroupId) control = index;
        }
        if (human == identity_observation::kMemberCapacity || control == identity_observation::kMemberCapacity) continue;
        if (control != static_cast<std::size_t>(sample.hostMemberIndex)) continue;
        if (sample.members[control].ownsPlayer || !sample.members[human].ownsPlayer) return Result::invalidInput;
        const auto members = std::popcount(sample.memberMask);
        const auto players = std::popcount(sample.playerMask);
        // Accept the target six-human observation shape without enabling gameplay capacity.
        if (members < 2 || members > static_cast<int>(kMaximumHumanObservations + 1)
            || players != members - 1) return Result::invalidInput;
        if (found) return Result::ambiguous;
        const auto& member = sample.members[human];
        candidate = {observed.manager, observed.incarnation, observed.generation, observed.sampledAt,
            creatorMachineId, advertisedGroupId, member.playerId, static_cast<std::uint32_t>(control),
            static_cast<std::uint32_t>(human), member.playerSlot, member.playerSequence, sample.role, sample.mode};
        found = true;
    }
    if (!found) return Result::noMatch;
    output = candidate;
    return Result::matched;
}

} // namespace dawn::core::multiplayer::identity_activity
