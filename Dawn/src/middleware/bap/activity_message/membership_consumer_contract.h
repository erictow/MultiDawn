#pragma once

#include <array>
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

/** Recovered through wire type12 -> 4F2830 -> 4F7240 -> 808086A8, not vtable arithmetic. */
struct Schema final {
    static constexpr std::uint32_t membershipTag = 0x808086A8U;
    static constexpr std::uint32_t memberArrayTag = 0x808086A9U;
    static constexpr std::uint32_t memberTag = 0x808086AFU;
    static constexpr std::uint32_t identityTag = 0x808086BCU;
    static constexpr std::uint32_t detailTag = 0x808086B1U;
    static constexpr std::uint32_t playerStateTag = 0x808086B2U;
    static constexpr std::uint32_t profileTag = 0x808086B4U;
    static constexpr std::size_t membershipSize = 365'152;
    /** 3CD500 installs the table at owner+8; 3CB2F0 uses the preceding local machine key. */
    static constexpr std::size_t ownerPrefixSize = 8;
    static constexpr std::size_t ownerSize = ownerPrefixSize + membershipSize;
    static constexpr std::size_t memberSize = 10'944;
    static constexpr std::size_t memberDetail = 48;
    static constexpr std::size_t memberLeaveValue = 10'936;
    static constexpr std::size_t identityField1 = 8;
    static constexpr std::size_t detailSynchronization = 10'520;
    static constexpr std::size_t synchronizationToken = 321;
    static constexpr std::size_t mask0 = 365'128;
    static constexpr std::size_t mask1 = 365'132;
    static constexpr std::size_t activationMask = 365'136;
};

/** Native B2 metadata offsets. These describe layout, not the meaning of private bytes. */
struct PlayerState final {
    static constexpr std::size_t decodedSize = 10'520;
    static constexpr std::array<std::size_t, 16> offsets{
        0, 1, 136, 144, 152, 160, 168, 172, 176, 184, 188, 274, 360, 446, 512, 10'516};
    static constexpr std::size_t connectionGateField = 0;
    static constexpr std::size_t addressField = 11;
    static constexpr std::size_t opaqueConnectionField = 13;
    static constexpr std::size_t profileField = 14;
    static constexpr std::size_t trailingBoolField = 15;
    static constexpr std::size_t profileByteCountOffset = offsets[profileField];
    static constexpr std::size_t profileBytesOffset = profileByteCountOffset + sizeof(std::uint32_t);
};

inline constexpr std::size_t kOpaqueConnectionByteCount = 64;
inline constexpr std::size_t kProfileMaximumBytes = 10'000;
inline constexpr unsigned kProfileCountBits = 14;
inline constexpr unsigned kMemberLeaveValueBits = 5;
inline constexpr int kMemberLeaveValueBias = 1;

/** Fields1/13 use signed-byte arrays biased by 0x80; NetAddr/profile bytes do not. */
[[nodiscard]] constexpr std::uint8_t encode_signed_byte(std::uint8_t decoded) noexcept {
    return static_cast<std::uint8_t>(decoded ^ std::uint8_t{0x80});
}
[[nodiscard]] constexpr std::uint8_t decode_signed_byte(std::uint8_t wire) noexcept {
    return static_cast<std::uint8_t>(wire ^ std::uint8_t{0x80});
}

/** Offsets are relative to the table passed to 4DFxxx, not to its first member. */
struct Layout final {
    static constexpr std::size_t memberStart = 8;
    static constexpr std::size_t memberStride = Schema::memberSize;
    static constexpr std::size_t identityField1 = memberStart + Schema::identityField1;
    static constexpr std::size_t detailFlags = memberStart + Schema::memberDetail + PlayerState::offsets[0];
    static constexpr std::size_t mask0 = Schema::mask0;
    static constexpr std::size_t mask1 = Schema::mask1;
    static constexpr std::size_t activationMask = Schema::activationMask;
    /** Relative to one member record returned by 4DF500. */
    static constexpr std::size_t memberNetAddr = Schema::memberDetail + PlayerState::offsets[11];
    /** B2 field13's fixed64 block; its meaning remains unclassified. Never log it. */
    static constexpr std::size_t memberOpaqueConnectIdentity = Schema::memberDetail + PlayerState::offsets[13];
    /** Table + memberIndex*stride + this byte: member field2's stored leave/skip value. */
    static constexpr std::size_t skipByte = memberStart + Schema::memberLeaveValue;
    /** E22250 compares this per-member byte with the teleport command token. */
    static constexpr std::size_t synchronizationByte = memberStart + Schema::memberDetail
        + Schema::detailSynchronization + Schema::synchronizationToken;
};

static_assert(Layout::memberNetAddr == 0x142 && Layout::memberOpaqueConnectIdentity == 0x1EE);
static_assert(Layout::skipByte == Layout::memberStride && Layout::synchronizationByte == 0x2A91);
static_assert(PlayerState::offsets[13] + kOpaqueConnectionByteCount <= PlayerState::offsets[14]);
static_assert(PlayerState::offsets[14] + sizeof(std::uint32_t) + kProfileMaximumBytes
    == PlayerState::offsets[15]);
static_assert((1U << kProfileCountBits) > kProfileMaximumBytes);

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
