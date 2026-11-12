#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>

namespace dawn::middleware::bap::activity_message::replicate_membership::consumer_contract {

/**
 * Build86657 native world-peer selection, observed from the existing connect hook.
 * 1702580 calls 4DF480/4DF4B0 to enumerate mask1, tests mask0, excludes the
 * local machine's member index, then checks 4DF600 and 4DD470 before 1703910.
 * These conditions establish selection for a connection attempt, not avatar creation.
 * See docs/native-membership-consumer-86657.md for evidence and unresolved fields.
 */
inline constexpr std::size_t kMemberCount = 32;
inline constexpr std::uint8_t kConnectionGate = 0x10;

/** Offsets are relative to the table passed to 4DFxxx, not to its first member. */
struct Layout final {
    static constexpr std::size_t memberStart = 8;
    static constexpr std::size_t memberStride = 0x2AC0;
    static constexpr std::size_t identityField1 = 0x10;
    static constexpr std::size_t detailFlags = 0x38;
    static constexpr std::size_t mask0 = 0x59248;
    static constexpr std::size_t mask1 = 0x5924C;
    static constexpr std::size_t activationMask = 0x59250;
    /** Relative to one member record returned by 4DF500. */
    static constexpr std::size_t memberNetAddr = 0x142;
    /** Its wire-field correspondence and meaning remain unclassified. */
    static constexpr std::size_t memberOpaqueConnectIdentity = 0x1EE;
    /** Table + memberIndex*stride + this byte; wire-field mapping is unverified. */
    static constexpr std::size_t skipByte = 0x2AC0;
    /** E22250 compares this per-member byte with the teleport command token. */
    static constexpr std::size_t synchronizationByte = 0x2A91;
};

struct Masks final {
    std::uint32_t mask0{}, mask1{}, activation{};
};

[[nodiscard]] constexpr bool contains(std::uint32_t mask, std::size_t member) noexcept {
    return member < kMemberCount && ((mask >> member) & 1U) != 0;
}

/**
 * The local index is found by machine-key equality (3CB2F0 -> 4DD640), not by
 * assuming slot zero. The separate native skip byte is not identity.field1.
 */
[[nodiscard]] constexpr bool selects_remote(Masks masks, std::size_t member,
    std::size_t localMember, bool nativeSkip, std::uint8_t detailFlags) noexcept {
    return member != localMember && contains(masks.mask0, member)
        && contains(masks.mask1, member) && !nativeSkip
        && (detailFlags & kConnectionGate) != 0;
}

/** 4DF620 passes this unsigned comparison as 1703910's role argument. */
[[nodiscard]] constexpr bool role_argument(std::int32_t identityField1) noexcept {
    return std::bit_cast<std::uint32_t>(identityField1) <= 0x1FFU;
}

/** 4DF650 supplies a separate argument; its bit does not replace either mask. */
[[nodiscard]] constexpr bool activation_argument(Masks masks, std::size_t member) noexcept {
    return contains(masks.activation, member);
}

} // namespace dawn::middleware::bap::activity_message::replicate_membership::consumer_contract
