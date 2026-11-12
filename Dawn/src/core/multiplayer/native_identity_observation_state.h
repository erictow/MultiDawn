#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace dawn::core::multiplayer::identity_observation {

inline constexpr std::size_t kMemberCapacity = 32;
inline constexpr std::size_t kManagerCapacity = 16;
inline constexpr std::uint64_t kMaximumAgeMs = 1'000;
inline constexpr std::size_t kReplicaOffset = 0x868;
inline constexpr std::size_t kModeOffset = 0x1AEF8;
inline constexpr std::size_t kRoleOffset = 0x1C7C0;

/** Public routing scalars only. This does not identify which member is the local human. */
struct Member final {
    std::uint64_t machineId{}, playerId{}, joinId{};
    std::uint32_t playerSlot{}, playerSequence{}, state{};
    bool ownsPlayer{};
    friend constexpr bool operator==(const Member&, const Member&) noexcept = default;
};

/** A validated observation of one native manager, never an admission or identity credential. */
struct Sample final {
    std::int32_t role{-1}, mode{-1};
    std::uint32_t revision{}, memberMask{}, playerMask{};
    std::array<Member, kMemberCapacity> members{};
    friend constexpr bool operator==(const Sample&, const Sample&) noexcept = default;
};

/** Reads only the requested scalar bytes relative to a verified current native manager. */
using Reader = bool (*)(void*, std::size_t, std::span<std::byte>) noexcept;

namespace detail {
template <typename Value>
[[nodiscard]] bool scalar(Reader read, void* context, std::size_t offset, Value& value) noexcept {
    std::array<std::byte, sizeof(Value)> bytes{};
    if (!read(context, offset, bytes)) return false;
    std::uint64_t number{};
    for (std::size_t index = 0; index < bytes.size(); ++index)
        number |= std::to_integer<std::uint64_t>(bytes[index]) << (index * 8U);
    value = static_cast<Value>(number);
    return true;
}

[[nodiscard]] inline bool once(Reader read, void* context, Sample& output) noexcept {
    Sample candidate{};
    std::uint32_t count{}, players{};
    std::uint64_t mask{}, arrayCount{};
    if (!scalar(read, context, kRoleOffset, candidate.role) || candidate.role < 0 || candidate.role >= 7
        || !scalar(read, context, kModeOffset, candidate.mode) || candidate.mode < 0
        || !scalar(read, context, kReplicaOffset + 4, candidate.revision)
        || !scalar(read, context, kReplicaOffset + 28, count)
        || !scalar(read, context, kReplicaOffset + 40, mask)
        || !scalar(read, context, kReplicaOffset + 48, arrayCount)
        || count == 0 || count > kMemberCapacity || (mask >> 32U) != 0
        || count != static_cast<std::uint32_t>(std::popcount(mask)) || arrayCount != count
        || !scalar(read, context, kReplicaOffset + 15184, players)
        || !scalar(read, context, kReplicaOffset + 15188, candidate.playerMask)
        || players > kMemberCapacity || players != static_cast<std::uint32_t>(std::popcount(candidate.playerMask))) return false;
    candidate.memberMask = static_cast<std::uint32_t>(mask);
    std::uint32_t ownedMask{};
    for (std::size_t index = 0; index < kMemberCapacity; ++index) {
        if ((candidate.memberMask & (std::uint32_t{1} << index)) == 0) continue;
        auto& member = candidate.members[index];
        const auto base = kReplicaOffset + 56 + index * 184;
        std::uint64_t addressLength{}, machineLength{}, ownedCount{};
        if (!scalar(read, context, base + 8, addressLength) || addressLength != 86
            || !scalar(read, context, base + 112, machineLength) || machineLength != 8
            || !scalar(read, context, base + 120, member.machineId) || member.machineId == 0
            || !scalar(read, context, base + 136, member.joinId)
            || !scalar(read, context, base + 168, ownedCount) || ownedCount > 1
            || !scalar(read, context, kReplicaOffset + 5968 + index * 288, member.state)) return false;
        for (std::size_t earlier = 0; earlier < index; ++earlier)
            if ((candidate.memberMask & (std::uint32_t{1} << earlier)) != 0
                && candidate.members[earlier].machineId == member.machineId) return false;
        member.ownsPlayer = ownedCount == 1;
        if (!member.ownsPlayer) continue;
        if (!scalar(read, context, base + 176, member.playerSlot) || member.playerSlot >= 32) return false;
        const auto bit = std::uint32_t{1} << member.playerSlot;
        if ((ownedMask & bit) != 0 || (candidate.playerMask & bit) == 0) return false;
        ownedMask |= bit;
        const auto player = kReplicaOffset + 15192 + static_cast<std::size_t>(member.playerSlot) * 424;
        std::uint32_t owner{}, ownedIndex{};
        if (!scalar(read, context, player + 4, member.playerId) || member.playerId == 0
            || !scalar(read, context, player + 12, owner) || owner != index
            || !scalar(read, context, player + 16, ownedIndex) || ownedIndex != 0
            || !scalar(read, context, player + 20, member.playerSequence)) return false;
        for (std::size_t earlier = 0; earlier < index; ++earlier)
            if (candidate.members[earlier].ownsPlayer && candidate.members[earlier].playerId == member.playerId) return false;
    }
    if (ownedMask != candidate.playerMask) return false;
    output = candidate;
    return true;
}
} // namespace detail

/**
 * Two complete scalar samples must agree. This detects observed instability, not an atomic
 * native snapshot. No NetAddr/security blob or bytes after player sequence are ever requested.
 */
[[nodiscard]] inline bool capture(Reader read, void* context, Sample& output) noexcept {
    output = {};
    Sample first{}, second{};
    if (read == nullptr || !detail::once(read, context, first) || !detail::once(read, context, second)
        || first != second) return false;
    output = first;
    return true;
}

struct Observation final {
    Sample sample{};
    std::uintptr_t manager{};
    /** Monotonic observed lifetime, not a recovered native session incarnation. */
    std::uint64_t incarnation{}, generation{}, sampledAt{};
};

/** Caller serializes access. Expiry and ambiguity fail closed; storage never allocates. */
class Mailbox final {
public:
    [[nodiscard]] bool publish(std::uintptr_t manager, const Sample* sample, std::uint64_t now) noexcept {
        if (manager == 0 || exhausted_) return false;
        Row* row{};
        Row* reusable{};
        for (auto& entry : rows_) {
            if (entry.value.manager == manager) { row = &entry; break; }
            if ((!entry.valid || (now >= entry.value.sampledAt
                && now - entry.value.sampledAt > kMaximumAgeMs)) && reusable == nullptr) reusable = &entry;
        }
        if (sample == nullptr) {
            if (row != nullptr) row->valid = false;
            return false;
        }
        if (row == nullptr) row = reusable;
        if (row == nullptr) return false;
        const bool newLifetime = !row->valid || row->value.manager != manager || row->value.sample.role != sample->role
            || now < row->value.sampledAt || now - row->value.sampledAt > kMaximumAgeMs;
        if (newLifetime || row->value.sample != *sample) {
            if (clock_ == std::numeric_limits<std::uint64_t>::max()) { rows_ = {}; exhausted_ = true; return false; }
            ++clock_;
            if (newLifetime) row->value.incarnation = clock_;
            row->value.generation = clock_;
        }
        row->value.manager = manager;
        row->value.sample = *sample;
        row->value.sampledAt = now;
        row->valid = true;
        return true;
    }

    /** More than one fresh manager for a role is ambiguous, even when its IDs agree. */
    [[nodiscard]] bool snapshot(std::int32_t role, std::uint64_t now, Observation& output) const noexcept {
        output = {};
        if (role < 0 || role >= 7 || exhausted_) return false;
        const Row* selected{};
        for (const auto& row : rows_) {
            if (!row.valid || row.value.sample.role != role || now < row.value.sampledAt
                || now - row.value.sampledAt > kMaximumAgeMs) continue;
            if (selected != nullptr) return false;
            selected = &row;
        }
        if (selected == nullptr) return false;
        output = selected->value;
        return true;
    }

    /** Reset never reuses an observation generation across hook uninstall/reinstall. */
    void reset() noexcept { rows_ = {}; }

private:
    struct Row { Observation value{}; bool valid{}; };
    std::array<Row, kManagerCapacity> rows_{};
    std::uint64_t clock_{};
    bool exhausted_{};
};

/** Lifecycle fence for a capture performed outside the caller's mailbox lock. */
class Collector final {
public:
    void start() noexcept {
        mailbox_.reset();
        active_ = epoch_ != std::numeric_limits<std::uint64_t>::max();
        if (active_) ++epoch_;
    }
    void stop() noexcept { active_ = false; mailbox_.reset(); }
    [[nodiscard]] std::uint64_t capture_token() const noexcept { return active_ ? epoch_ : 0; }
    [[nodiscard]] bool publish(std::uint64_t token, std::uintptr_t manager,
        const Sample* sample, std::uint64_t now) noexcept {
        return active_ && token != 0 && token == epoch_ && mailbox_.publish(manager, sample, now);
    }
    [[nodiscard]] bool snapshot(std::int32_t role, std::uint64_t now, Observation& output) const noexcept {
        output = {};
        return active_ && mailbox_.snapshot(role, now, output);
    }
private:
    Mailbox mailbox_{};
    std::uint64_t epoch_{};
    bool active_{};
};

} // namespace dawn::core::multiplayer::identity_observation
