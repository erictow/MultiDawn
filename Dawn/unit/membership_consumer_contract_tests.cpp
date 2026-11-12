#include "../src/middleware/bap/activity_message/membership_consumer_contract.h"
#include "../src/middleware/bap/activity_message/replicate_membership.h"

#include <array>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace membership = dawn::middleware::bap::activity_message::replicate_membership;
namespace contract = membership::consumer_contract;
namespace {
unsigned checks{};
void check(bool value, int line) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL membership consumer contract line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)

// Independent bit extraction checks the production encoder, without its Reader or Writer.
struct Cursor {
    std::span<const std::byte> bytes;
    std::size_t bit{};
    std::uint64_t take(unsigned width) {
        CHECK(width <= 64 && bit + width <= bytes.size() * 8U);
        std::uint64_t value{};
        for (unsigned n = 0; n < width; ++n, ++bit)
            value = (value << 1U) | ((std::to_integer<unsigned>(bytes[bit / 8U]) >> (7U - bit % 8U)) & 1U);
        return value;
    }
};
struct Member {
    std::uint64_t key{}, account{}, field5{}, detailAccount{}, detailField5{};
    std::int32_t field1{}, field2{};
    std::uint16_t detailMask{};
    std::uint8_t flags{}, leave{}, synchronization{};
    std::array<std::byte, 86> address{};
    std::array<std::byte, 18> blob{};
    bool identity{}, detail{}, hasSynchronization{}, hasBlob{};
};
void read_leg(Cursor& cursor) {
    if (!cursor.take(1)) return;
    cursor.take(10); cursor.take(32); cursor.take(32);
    cursor.take(2); cursor.take(2); CHECK(cursor.take(2) == 0);
}
Member read_member(Cursor& cursor) {
    Member member{};
    member.identity = cursor.take(1) != 0;
    if (member.identity) {
        for (unsigned index = 0; index < 8; ++index) member.key |= cursor.take(8) << (8U * index);
        member.field1 = static_cast<std::int32_t>(cursor.take(10)) - 1;
        member.field2 = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(cursor.take(32)) - 0x80000000U);
        cursor.take(64); member.account = cursor.take(64); member.field5 = cursor.take(64); cursor.take(64);
    }
    member.detail = cursor.take(1) != 0;
    if (member.detail) {
        CHECK(cursor.take(1) == 1); // Present B2 block inside B1.
        for (unsigned field = 0; field < 15; ++field) {
            if (!cursor.take(1)) continue;
            member.detailMask |= static_cast<std::uint16_t>(1U << field);
            switch (field) {
            case 0: member.flags = static_cast<std::uint8_t>(cursor.take(6)); break;
            case 3: member.detailAccount = cursor.take(64); break;
            case 5: member.detailField5 = cursor.take(64); break;
            case 11: for (auto& value : member.address) value = static_cast<std::byte>(cursor.take(8)); break;
            case 14:
                CHECK(cursor.take(14) == member.blob.size());
                for (auto& value : member.blob) value = static_cast<std::byte>(cursor.take(8));
                member.hasBlob = true;
                break;
            default: CHECK(false);
            }
        }
        CHECK(cursor.take(1) == 0); // B2's trailing bool.
        if (cursor.take(1)) {
            read_leg(cursor); read_leg(cursor); CHECK(cursor.take(1) == 0);
            member.hasSynchronization = cursor.take(1) != 0;
            if (member.hasSynchronization) member.synchronization = static_cast<std::uint8_t>(cursor.take(8));
            CHECK(cursor.take(1) == 0);
        }
        CHECK(cursor.take(2) == 0); // Other auxiliary children stay absent.
    }
    if (cursor.take(1)) member.leave = static_cast<std::uint8_t>(cursor.take(5));
    return member;
}

membership::MembershipSnapshot fixture(bool control) {
    membership::MembershipSnapshot value{};
    value.identity = {0x1020304050607080ULL, -1, -1, 0x8090A0B0C0D0E0F0ULL,
        0x1111222233334444ULL, 0x5555666677778888ULL, 0x9999AAAABBBBCCCCULL};
    value.revision = 0x13579BDF; value.epoch = 0x2468ACE0;
    value.citizen.present = control;
    value.citizen.memberKey = 0xFFEEDDCCBBAA9988ULL;
    value.citizen.onlineSessionId = 0x8877665544332211ULL;
    value.citizen.regionIndex = 56; value.citizen.ambassadorSlot = 1;
    for (std::size_t i = 0; i < value.citizen.address.size(); ++i)
        value.citizen.address[i] = static_cast<std::byte>(i);
    return value;
}

void inspect_wire(const membership::MembershipSnapshot& value) {
    std::array<std::byte, membership::kMaximumEncodedSize> bytes{};
    std::size_t written{};
    CHECK(membership::encode_replicate_membership(value, bytes, written));
    CHECK(written == membership::encoded_size(value));
    Cursor cursor{std::span(bytes).first(written)};
    CHECK(cursor.take(1) == 1 && cursor.take(32) == value.revision && cursor.take(32) == value.epoch);
    const auto local = read_member(cursor);
    CHECK(local.identity && local.detail && local.key == value.identity.memberKey);
    CHECK(local.field1 == value.identity.field1 && local.field2 == value.identity.field2);
    CHECK(local.account == value.identity.accountSoid && local.detailAccount == local.account);
    CHECK(local.field5 == value.identity.field5 && local.detailField5 == local.field5);
    CHECK(local.detailMask == ((1U << 3U) | (1U << 5U) | (1U << 14U)));
    CHECK(local.hasBlob && local.leave == 1 && local.flags == 0);
    Cursor blob{local.blob};
    CHECK(blob.take(3) == 1 && blob.take(1) == 0 && blob.take(10) == 0 && blob.take(1) == 1);
    CHECK(blob.take(64) == local.account && blob.take(64) == local.field5 && blob.take(1) == 0);
    CHECK(local.hasSynchronization == value.hasSynchronizationToken);
    if (local.hasSynchronization) CHECK(local.synchronization == value.synchronizationToken);
    std::size_t firstAbsent = 1;
    if (value.citizen.present) {
        const auto control = read_member(cursor);
        CHECK(control.identity && control.detail && control.key == value.citizen.memberKey);
        CHECK(control.field1 == -1 && control.field2 == -1);
        CHECK(control.account == 0 && control.field5 == 0 && !control.hasBlob);
        CHECK(control.detailMask == ((1U << 0U) | (1U << 11U)));
        CHECK(control.flags == contract::kConnectionGate && control.address == value.citizen.address);
        CHECK(control.hasSynchronization == value.hasHostSynchronizationToken);
        if (control.hasSynchronization) CHECK(control.synchronization == value.hostSynchronizationToken);
        firstAbsent = 2;
    }
    for (auto slot = firstAbsent; slot < 32; ++slot) {
        const auto before = cursor.bit;
        const auto absent = read_member(cursor);
        CHECK(!absent.identity && !absent.detail && !absent.hasBlob && absent.leave == 0);
        CHECK(cursor.bit - before == 3);
    }
    CHECK(cursor.bit + 1 == membership::region_block_start_bit(value));
    cursor.bit = membership::region_block_end_bit(value);
    const auto expectedMask = value.citizen.present ? 3U : 1U;
    CHECK(cursor.take(1) == 1 && cursor.take(32) == expectedMask);
    CHECK(cursor.take(1) == 1 && cursor.take(32) == expectedMask);
    CHECK(cursor.take(3) == 0); // Third mask and final optional fields stay absent.
    CHECK(cursor.bit == membership::meaningful_bits(value));
}

void native_selection() {
    for (std::size_t slot = 0; slot < 32; ++slot) {
        const auto lane = std::uint32_t{1} << slot;
        const contract::Masks both{lane, lane, 0};
        const auto otherLocal = (slot + 1U) % 32U;
        CHECK(contract::selects_remote(both, slot, otherLocal, false, 0x10));
        CHECK(!contract::selects_remote(both, slot, slot, false, 0x10));
        CHECK(!contract::selects_remote({lane, 0, lane}, slot, otherLocal, false, 0x10));
        CHECK(!contract::selects_remote({0, lane, lane}, slot, otherLocal, false, 0x10));
        CHECK(!contract::selects_remote(both, slot, otherLocal, true, 0x10));
        CHECK(!contract::activation_argument(both, slot));
        CHECK(contract::activation_argument({lane, lane, lane}, slot));
        for (unsigned flags = 0; flags < 64; ++flags)
            CHECK(contract::selects_remote(both, slot, otherLocal, false,
                static_cast<std::uint8_t>(flags)) == ((flags & 0x10U) != 0));
    }
    CHECK(!contract::contains(UINT32_MAX, 32));
    CHECK(!contract::contains(UINT32_MAX, (std::numeric_limits<std::size_t>::max)()));
    CHECK(!contract::selects_remote({UINT32_MAX, UINT32_MAX, UINT32_MAX}, 32, 0, false, 0x10));
    CHECK(!contract::role_argument(-1) && !contract::role_argument(-2));
    CHECK(contract::role_argument(0) && contract::role_argument(511));
    CHECK(!contract::role_argument(512) && !contract::role_argument(1022));
    CHECK(!contract::role_argument((std::numeric_limits<std::int32_t>::min)()));
}
} // namespace

int main() {
    native_selection();
    for (const bool control : {false, true}) {
        auto value = fixture(control);
        inspect_wire(value);
        value.hasSynchronizationToken = true; value.synchronizationToken = 0xA7;
        value.hasHostSynchronizationToken = control; value.hostSynchronizationToken = 0x59;
        value.currentLeg = {3, 0x24681357, 56, 1, 2, true};
        inspect_wire(value);
        for (const auto field1 : {-1, 0, 511, 512, 1022}) {
            value.identity.field1 = field1;
            inspect_wire(value);
        }
        for (const auto field2 : {(std::numeric_limits<std::int32_t>::min)(), -1, 0, 1,
                                 (std::numeric_limits<std::int32_t>::max)()}) {
            value.identity.field2 = field2;
            inspect_wire(value);
        }
    }
    std::printf("PASS membership consumer contract %u checks\n", checks);
}
