#include <bit>
#include <limits>

#include "replicate_membership.h"
#include "membership_consumer_contract.h"

namespace dawn::middleware::bap::activity_message::replicate_membership {
namespace {

/** 8 elements, low byte first, encode a member or host key. */
constexpr std::size_t kMemberKeyByteCount = 8;
/** The membership table has 32 fixed member slots. */
constexpr std::size_t kMemberCount = consumer_contract::kMemberCount;
/** Each absent member adds 3 clear presence bits. */
constexpr std::uint8_t kAbsentMemberBitCount = 3;
/**
 * Member field 1 uses 10 bits with bias 1. Native 4DF620 compares its stored unsigned
 * value with 0x1FF to supply the connection's role argument. The actual skip byte
 * tested by 4DF600 is separate. Preserve the client's published value verbatim.
 */
constexpr std::uint32_t kField1Bias = 1;
/** Member field 2 uses the signed 32-bit midpoint as its bias. */
constexpr std::uint32_t kField2Bias = 0x80000000U;
/** A present local member carries a zero logical leave reason at bias 1. */
constexpr std::uint8_t kLeaveReasonWire = 1;
/** The nested identity block has presence bits on fields 0 through 14. */
constexpr std::size_t kIdentityPresenceFieldCount = 15;
/** The minimal nested player blob is 18 bytes, including one zero pad bit. */
constexpr std::uint16_t kPlayerBlobByteCount = 18;
/** Native 4DD470 checks bit four before the world-peer connection attempt. */
constexpr std::uint8_t kRemoteViewGate = consumer_contract::kConnectionGate;
/** NetAddr is detail field 11 in the 16-field nested player-state block. */
constexpr std::size_t kRemoteAddressField = 11;
/** The non-local identity stores -1 in its signed 32-bit opaque field. */
constexpr std::uint32_t kRemoteField2Wire = 0x7FFFFFFFU;

/**
 * Writes one 8-element key, low byte first.
 * @param writer Fixed-buffer MSB-first writer.
 * @param key Host-order key to split into byte elements.
 * @return True when all 8 elements fit.
 */
[[nodiscard]] bool write_member_key(encoding::bits::Writer& writer, std::uint64_t key) noexcept {
    for (std::size_t index = 0; index < kMemberKeyByteCount; ++index) {
        if (!writer.write((key >> (index * 8U)) & 0xFFU, 8)) {
            return false;
        }
    }
    return true;
}

/** Writes raw bytes in the order the activity tag-reflection array consumes them. */
template <std::size_t Size>
[[nodiscard]] bool write_bytes(encoding::bits::Writer& writer,
                               const std::array<std::byte, Size>& bytes) noexcept {
    for (const std::byte value : bytes) {
        if (!writer.write(std::to_integer<std::uint64_t>(value), 8)) {
            return false;
        }
    }
    return true;
}

/**
 * Writes the nested 18-byte player blob with matching identity values.
 * @param writer Fixed-buffer writer sitting after the 14-bit byte count.
 * @param identity Identity values repeated inside the nested player record.
 * @return True when all 144 blob bits fit.
 */
[[nodiscard]] bool write_player_blob(encoding::bits::Writer& writer,
                                     const client_identity::ClientIdentity& identity) noexcept {
    return writer.write(1, 3) && writer.write(0, 1) && writer.write(0, 10) && writer.write(1, 1)
           && writer.write(identity.accountSoid, 64) && writer.write(identity.field5, 64)
           && writer.write(0, 1);
}

/**
 * Writes the present fields of the nested player identity block.
 * @param writer Fixed-buffer writer sitting at identity field zero.
 * @param identity Values mirrored from the client identity update.
 * @return True when fields 3, 5 and 14 and all presence bits fit.
 */
[[nodiscard]] bool write_player_identity(encoding::bits::Writer& writer,
                                         const client_identity::ClientIdentity& identity) noexcept {
    for (std::size_t field = 0; field < kIdentityPresenceFieldCount; ++field) {
        const bool present = field == 3 || field == 5 || field == 14;
        if (!writer.write(present ? 1U : 0U, 1)) {
            return false;
        }
        if (field == 3 && !writer.write(identity.accountSoid, 64)) {
            return false;
        }
        if (field == 5 && !writer.write(identity.field5, 64)) {
            return false;
        }
        if (field == 14
            && (!writer.write(kPlayerBlobByteCount, 14) || !write_player_blob(writer, identity))) {
            return false;
        }
    }
    return writer.write(0, 1);
}

/** Writes the fixed client-identity record for the non-player activity host. */
[[nodiscard]] bool write_remote_identity(encoding::bits::Writer& writer,
                                         const CitizenAdvertisement& host) noexcept {
    return write_member_key(writer, host.memberKey) && writer.write(0, 10)
           && writer.write(kRemoteField2Wire, 32) && writer.write(host.onlineSessionId, 64)
           && writer.write(0, 64) && writer.write(0, 64)
           && writer.write(host.memberKey, 64);
}

/**
 * Writes B2 with only the view gate and the established host NetAddr present.
 * The trailing bool has no presence bit and therefore always contributes one clear bit.
 */
[[nodiscard]] bool write_remote_player_state(encoding::bits::Writer& writer,
                                             const CitizenAdvertisement& host) noexcept {
    for (std::size_t field = 0; field < kIdentityPresenceFieldCount; ++field) {
        const bool present = field == 0 || field == kRemoteAddressField;
        if (!writer.write(present ? 1U : 0U, 1)) {
            return false;
        }
        if (field == 0 && !writer.write(kRemoteViewGate, 6)) {
            return false;
        }
        if (field == kRemoteAddressField && !write_bytes(writer, host.address)) {
            return false;
        }
    }
    return writer.write(0, 1);
}

/** D6's five scalars are copied from the native client; auxiliary children stay unchanged. */
[[nodiscard]] bool write_region_leg(encoding::bits::Writer& writer,const RegionLeg& leg) noexcept {
    return writer.write(leg.present?1U:0U,1) && (!leg.present
        || (writer.write(static_cast<std::uint32_t>(leg.sliceSetIndex+1),10)
            && writer.write(leg.sliceSetHash,32)
            && writer.write(std::bit_cast<std::uint32_t>(leg.regionIndex)+0x80000000U,32)
            && writer.write(static_cast<std::uint8_t>(leg.publicState+1),2)
            && writer.write(static_cast<std::uint8_t>(leg.auxState+1),2)
            && writer.write(0,2)));
}
[[nodiscard]] bool valid_leg(const RegionLeg& leg) noexcept {
    return !leg.present || (leg.sliceSetIndex>=-1 && leg.sliceSetIndex<=1022
        && leg.publicState>=-1 && leg.publicState<=2 && leg.auxState>=-1 && leg.auxState<=2);
}

/** B1.D4.field3 maps to native PAH peer+2A91. Other D4 fields and C9/C0 stay absent. */
[[nodiscard]] bool write_synchronization(encoding::bits::Writer& writer,
                                         bool present,std::uint8_t token,const RegionLeg& current={},const RegionLeg& pending={}) noexcept {
    const bool active=present || current.present || pending.present;
    return writer.write(active?1U:0U,1)
           && (!active || (write_region_leg(writer,current) && write_region_leg(writer,pending)
                            && writer.write(0,1) && writer.write(present?1U:0U,1)
                            && (!present || writer.write(token,8)) && writer.write(0,1)))
           && writer.write(0,2);
}

/** Writes one non-local, non-player member whose detail creates the peer view. */
[[nodiscard]] bool write_remote_member(encoding::bits::Writer& writer,
                                       const CitizenAdvertisement& host,
                                       bool hasSynchronizationToken,std::uint8_t synchronizationToken) noexcept {
    return writer.write(1, 1) && write_remote_identity(writer, host)
           && writer.write(1, 1) && writer.write(1, 1)
           && write_remote_player_state(writer, host)
           && write_synchronization(writer,hasSynchronizationToken,synchronizationToken)
           && writer.write(1, 1) && writer.write(kLeaveReasonWire, 5);
}

} // namespace

/** Rejects fields that cannot name the exact native member/region records. */
bool valid(const MembershipSnapshot& snapshot) noexcept {
    namespace authoritative = client_authoritative_data;
    const bool sliceSetValid =
        snapshot.teleport.sliceSetIndex >= authoritative::kAbsentSliceSetIndex
        && snapshot.teleport.sliceSetIndex <= authoritative::kMaximumSliceSetIndex;
    for (std::size_t bubble = 0; bubble < kRegionCount; ++bubble) {
        const auto selected = snapshot.activeRegions[bubble].index;
        if (selected != -1
            && (selected < 0 || selected > kMaximumRegionIndex
                || static_cast<std::size_t>(selected / kStatesPerBubble) != bubble)) {
            return false;
        }
    }
    const auto citizenRegion = snapshot.citizen.regionIndex;
    const bool citizenRegionValid = citizenRegion >= 0 && citizenRegion <= kMaximumRegionIndex
        && active_region(snapshot, static_cast<std::size_t>(citizenRegion / kStatesPerBubble)) == citizenRegion;
    const bool hostValid = !snapshot.citizen.present
                           || (snapshot.citizen.memberKey != 0
                               && snapshot.citizen.memberKey != snapshot.identity.memberKey
                               && snapshot.citizen.ambassadorSlot == 1 && citizenRegionValid);
    return valid_leg(snapshot.currentLeg) && valid_leg(snapshot.pendingLeg) && sliceSetValid && hostValid
           && (!snapshot.hasHostSynchronizationToken || snapshot.citizen.present);
}

/** Writes the local member, the optional non-local activity host, and the absent tail. */
bool write_member_table(encoding::bits::Writer& writer,
                        const MembershipSnapshot& snapshot) noexcept {
    const client_identity::ClientIdentity& identity = snapshot.identity;
    const std::uint32_t field1Wire = std::bit_cast<std::uint32_t>(identity.field1) + kField1Bias;
    const std::uint32_t field2Wire = std::bit_cast<std::uint32_t>(identity.field2) + kField2Bias;
    bool encoded = writer.bit_count() == kMemberStartBit && writer.write(1, 1)
                   && write_member_key(writer, identity.memberKey) && writer.write(field1Wire, 10)
                   && writer.write(field2Wire, 32) && writer.write(identity.field3, 64)
                   && writer.write(identity.accountSoid, 64) && writer.write(identity.field5, 64)
                   && writer.write(identity.field6, 64) && writer.write(1, 1) && writer.write(1, 1)
                   && write_player_identity(writer, identity)
                   && write_synchronization(writer,snapshot.hasSynchronizationToken,snapshot.synchronizationToken,snapshot.currentLeg,snapshot.pendingLeg)
                   && writer.write(1, 1) && writer.write(kLeaveReasonWire, 5);
    std::size_t firstAbsent = 1;
    if (encoded && snapshot.citizen.present) {
        const std::size_t before = writer.bit_count();
        encoded = write_remote_member(writer, snapshot.citizen,
                      snapshot.hasHostSynchronizationToken,snapshot.hostSynchronizationToken)
                  && writer.bit_count() - before == kRemoteMemberBitCount + kAbsentMemberBitCount
                     + (snapshot.hasHostSynchronizationToken?kSynchronizationBitCount:0U);
        firstAbsent = 2;
    }
    for (std::size_t member = firstAbsent; encoded && member < kMemberCount; ++member) {
        encoded = writer.write(0, kAbsentMemberBitCount);
    }
    return encoded && writer.bit_count() + 1 == region_block_start_bit(snapshot);
}

} // namespace dawn::middleware::bap::activity_message::replicate_membership
