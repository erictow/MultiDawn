#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <algorithm>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <limits>
#include <vector>

#include "middleware/bap/activity_message/replicate_membership.h"
#include "core/multiplayer/world_roster_projection.h"

namespace membership = dawn::middleware::bap::activity_message::replicate_membership;
namespace client_identity = dawn::middleware::bap::activity_message::client_identity;
namespace {
unsigned checks{};
void check(bool passed, int line) {
    ++checks;
    if (!passed) { std::fprintf(stderr, "FAIL remote membership line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)

struct Cursor {
    std::span<const std::byte> bytes;
    std::size_t bit{};
    std::uint64_t take(unsigned width) {
        CHECK(width <= 64 && bit + width <= bytes.size() * 8U);
        std::uint64_t value{};
        for (unsigned index = 0; index < width; ++index, ++bit)
            value = (value << 1U) | ((std::to_integer<unsigned>(bytes[bit / 8U]) >> (7U - bit % 8U)) & 1U);
        return value;
    }
};

struct DecodedMember {
    client_identity::ClientIdentity identity{};
    std::uint16_t fields{};
    std::uint8_t flags{}, sync{};
    std::array<std::byte, 86> address{};
    std::array<std::uint8_t, 64> opaqueWire{};
    membership::RegionLeg current{}, pending{};
    bool present{}, hasDetail{}, hasSync{}, trailing{};
    bool hasLeave{};
    int leave{};
    std::uint64_t account{}, field5{}, blobAccount{}, blobField5{};
};

membership::RegionLeg read_leg(Cursor& cursor) {
    membership::RegionLeg result{};
    result.present = cursor.take(1) != 0;
    if (result.present) {
        result.sliceSetIndex = static_cast<std::int32_t>(cursor.take(10)) - 1;
        result.sliceSetHash = static_cast<std::uint32_t>(cursor.take(32));
        result.regionIndex = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(cursor.take(32)) - 0x80000000U);
        result.publicState = static_cast<std::int8_t>(static_cast<int>(cursor.take(2)) - 1);
        result.auxState = static_cast<std::int8_t>(static_cast<int>(cursor.take(2)) - 1);
        CHECK(cursor.take(2) == 0);
    }
    return result;
}

DecodedMember read_member(Cursor& cursor) {
    DecodedMember member{};
    member.present = cursor.take(1) != 0;
    if (member.present) {
        for (unsigned index = 0; index < 8; ++index) member.identity.memberKey |= cursor.take(8) << (8U * index);
        member.identity.field1 = static_cast<std::int32_t>(cursor.take(10)) - 1;
        member.identity.field2 = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(cursor.take(32)) - 0x80000000U);
        member.identity.field3 = cursor.take(64); member.identity.accountSoid = cursor.take(64);
        member.identity.field5 = cursor.take(64); member.identity.field6 = cursor.take(64);
    }
    member.hasDetail = cursor.take(1) != 0;
    if (member.hasDetail) {
        CHECK(cursor.take(1) == 1);
        for (unsigned field = 0; field < 15; ++field) {
            if (cursor.take(1) == 0) continue;
            member.fields |= static_cast<std::uint16_t>(1U << field);
            switch (field) {
            case 0: member.flags = static_cast<std::uint8_t>(cursor.take(6)); break;
            case 3: member.account = cursor.take(64); break;
            case 5: member.field5 = cursor.take(64); break;
            case 11:
                for (auto& value : member.address) value = static_cast<std::byte>(cursor.take(8));
                break;
            case 13:
                for (auto& value : member.opaqueWire) value = static_cast<std::uint8_t>(cursor.take(8));
                break;
            case 14: {
                CHECK(cursor.take(14) == 18);
                std::array<std::byte, 18> body{};
                for (auto& value : body) value = static_cast<std::byte>(cursor.take(8));
                Cursor blob{body};
                CHECK(blob.take(3) == 1 && blob.take(1) == 0 && blob.take(10) == 0 && blob.take(1) == 1);
                member.blobAccount = blob.take(64); member.blobField5 = blob.take(64);
                CHECK(blob.take(1) == 0 && blob.bit == 144);
                break;
            }
            default: CHECK(false);
            }
        }
        member.trailing = cursor.take(1) != 0;
        if (cursor.take(1)) {
            member.current = read_leg(cursor); member.pending = read_leg(cursor);
            CHECK(cursor.take(1) == 0);
            member.hasSync = cursor.take(1) != 0;
            if (member.hasSync) member.sync = static_cast<std::uint8_t>(cursor.take(8));
            CHECK(cursor.take(1) == 0);
        }
        CHECK(cursor.take(2) == 0);
    }
    member.hasLeave = cursor.take(1) != 0;
    if (member.hasLeave) member.leave = static_cast<int>(cursor.take(5)) - 1;
    return member;
}

membership::MembershipSnapshot fixture(bool control, bool synchronize = false) {
    membership::MembershipSnapshot value{};
    value.identity = {0x1020304050607080ULL, -1, -1, 0x8090A0B0C0D0E0F0ULL,
        0x1111222233334444ULL, 0x5555666677778888ULL, 0x9999AAAABBBBCCCCULL};
    value.revision = 0x13579BDF; value.epoch = 0x2468ACE0;
    value.transitionToken = 0x21;
    value.citizen.present = control;
    value.citizen.memberKey = 0xFFEEDDCCBBAA9988ULL;
    value.citizen.onlineSessionId = 0x8877665544332211ULL;
    value.citizen.regionIndex = 56; value.citizen.ambassadorSlot = 1;
    for (std::size_t index = 0; index < value.citizen.address.size(); ++index)
        value.citizen.address[index] = static_cast<std::byte>(index);
    if (synchronize) {
        value.hasSynchronizationToken = true; value.synchronizationToken = 0xA7;
        value.hasHostSynchronizationToken = control; value.hostSynchronizationToken = 0x59;
        value.currentLeg = {3, 0x24681357, 56, 1, 2, true};
        value.pendingLeg = {4, 0xABCDEF01, 64, 0, -1, true};
    }
    return value;
}

std::string digest(std::span<const std::byte> input) {
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    std::array<unsigned char, 32> bytes{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0
        || BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0
        || BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(input.data())),
            static_cast<ULONG>(input.size()), 0) < 0
        || BCryptFinishHash(hash, bytes.data(), static_cast<ULONG>(bytes.size()), 0) < 0) std::abort();
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (const auto byte : bytes) { result += digits[byte >> 4U]; result += digits[byte & 15U]; }
    return result;
}

void same_identity(const client_identity::ClientIdentity& actual,
                   const client_identity::ClientIdentity& expected) {
    CHECK(actual.memberKey == expected.memberKey && actual.field1 == expected.field1
        && actual.field2 == expected.field2 && actual.field3 == expected.field3
        && actual.accountSoid == expected.accountSoid && actual.field5 == expected.field5
        && actual.field6 == expected.field6);
}

void same_leg(const membership::RegionLeg& actual, const membership::RegionLeg& expected) {
    CHECK(actual.present == expected.present);
    if (expected.present) CHECK(actual == expected);
}

std::vector<std::byte> inspect(const membership::MembershipSnapshot& value) {
    std::array<std::byte, membership::kMaximumEncodedSize> output{};
    output.fill(std::byte{0xD3});
    std::size_t written{};
    CHECK(membership::encode_replicate_membership(value, output, written));
    CHECK(written == membership::encoded_size(value));
    CHECK(std::all_of(output.begin() + written, output.end(), [](auto byte) { return byte == std::byte{0xD3}; }));
    Cursor cursor{std::span(output).first(written)};
    CHECK(cursor.take(1) == 1 && cursor.take(32) == value.revision && cursor.take(32) == value.epoch);
    std::uint32_t mask{};
    for (std::size_t slot = 0; slot < 32; ++slot) {
        const auto before = cursor.bit;
        const auto decoded = read_member(cursor);
        const bool control = slot == 1 && value.citizen.present;
        const auto remoteIndex = slot >= 2 ? slot - 2 : value.remoteHumans.size();
        const bool remote = remoteIndex < value.remoteHumanCount
            && remoteIndex < value.remoteHumans.size() && value.remoteHumans[remoteIndex].present;
        const bool present = slot == 0 || control || remote;
        CHECK(decoded.present == present && decoded.hasDetail == present && decoded.hasLeave == present);
        if (!present) { CHECK(cursor.bit - before == 3); continue; }
        mask |= std::uint32_t{1} << slot;
        CHECK(decoded.leave == 0 && !decoded.trailing);
        if (control) {
            CHECK(decoded.identity.memberKey == value.citizen.memberKey);
            CHECK(decoded.flags == 0x10 && decoded.address == value.citizen.address);
            CHECK(decoded.fields == ((1U << 0U) | (1U << 11U)));
            CHECK(decoded.hasSync == value.hasHostSynchronizationToken);
            if (decoded.hasSync) CHECK(decoded.sync == value.hostSynchronizationToken);
            CHECK(cursor.bit - before == 1084U + (decoded.hasSync ? 13U : 0U));
        } else {
            const auto& expected = remote ? value.remoteHumans[remoteIndex].identity : value.identity;
            same_identity(decoded.identity, expected);
            CHECK(decoded.account == expected.accountSoid && decoded.field5 == expected.field5);
            CHECK(decoded.blobAccount == expected.accountSoid && decoded.blobField5 == expected.field5);
            std::uint16_t fields = (1U << 3U) | (1U << 5U) | (1U << 14U);
            const auto& current = remote ? value.remoteHumans[remoteIndex].currentLeg : value.currentLeg;
            const auto& pending = remote ? value.remoteHumans[remoteIndex].pendingLeg : value.pendingLeg;
            const bool hasSync = remote ? value.remoteHumans[remoteIndex].hasSynchronizationToken : value.hasSynchronizationToken;
            const auto sync = remote ? value.remoteHumans[remoteIndex].synchronizationToken : value.synchronizationToken;
            same_leg(decoded.current, current);
            same_leg(decoded.pending, pending);
            CHECK(decoded.hasSync == hasSync);
            if (hasSync) CHECK(decoded.sync == sync);
            std::size_t expectedBits = remote ? 1370U : 676U;
            const bool active = current.present || pending.present || hasSync;
            expectedBits += (active ? 5U : 0U) + (hasSync ? 8U : 0U)
                + (current.present ? 80U : 0U) + (pending.present ? 80U : 0U);
            if (remote) {
                const auto& human = value.remoteHumans[remoteIndex];
                fields |= (1U << 0U) | (1U << 11U);
                CHECK(decoded.flags == 0x10 && decoded.address == human.address);
                if (human.hasOpaqueConnectIdentity) {
                    fields |= 1U << 13U; expectedBits += 512;
                    for (std::size_t byte = 0; byte < decoded.opaqueWire.size(); ++byte)
                        CHECK(decoded.opaqueWire[byte] == (human.opaqueConnectIdentity[byte] ^ 0x80U));
                }
            }
            CHECK(decoded.fields == fields && cursor.bit - before == expectedBits);
        }
    }
    CHECK(cursor.bit + 1 == membership::region_block_start_bit(value));
    CHECK(cursor.take(1) == 1);
    for (std::size_t bubble = 0; bubble < 64; ++bubble) {
        const auto region = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(cursor.take(32)) - 0x80000000U);
        CHECK(region == membership::active_region(value, bubble));
        const bool advertise = value.citizen.present && region == value.citizen.regionIndex;
        CHECK(cursor.take(2) == 1 && cursor.take(8) == 0 && cursor.take(2) == 2);
        CHECK(cursor.take(6) == (value.localAmbassador ? 1U : 2U));
        CHECK(cursor.take(1) == 0 && cursor.take(32) == 0 && cursor.take(8) == 0 && cursor.take(32) == 0);
        for (std::size_t slot = 0; slot < 32; ++slot) {
            auto token = value.transitionToken;
            if (slot >= 2 && slot - 2 < value.remoteHumanCount && value.remoteHumans[slot - 2].present)
                token = value.remoteHumans[slot - 2].transitionToken;
            CHECK(cursor.take(8) == token);
        }
        CHECK(cursor.take(8) == (advertise ? 128U : 0U));
        if (advertise) for (const auto byte : value.citizen.descriptor) CHECK(cursor.take(8) == std::to_integer<unsigned>(byte));
        CHECK(cursor.take(64) == (advertise ? value.citizen.onlineSessionId : 0U));
    }
    CHECK(cursor.take(8) == value.spawn.opaqueByte);
    CHECK(cursor.take(3) == static_cast<unsigned>((value.spawn.state < 0 ? 0 : value.spawn.state) + 1));
    CHECK(cursor.take(64) == value.spawn.opaqueValue && cursor.take(4) == 0);
    CHECK(cursor.take(3) == static_cast<unsigned>((value.teleport.state < 0 ? 0 : value.teleport.state) + 1));
    CHECK(cursor.take(8) == value.teleport.token && cursor.take(10) == static_cast<unsigned>(value.teleport.sliceSetIndex + 1));
    CHECK(cursor.take(32) == value.teleport.sliceSetHash && cursor.take(1) == 0 && cursor.take(1) == 1);
    std::uint64_t hostKey{};
    for (unsigned byte = 0; byte < 8; ++byte) hostKey |= cursor.take(8) << (8U * byte);
    CHECK(hostKey == value.identity.memberKey && cursor.take(2) == 0);
    CHECK(cursor.bit == membership::region_block_end_bit(value));
    CHECK(cursor.take(1) == 1 && cursor.take(32) == mask);
    CHECK(cursor.take(1) == 1 && cursor.take(32) == mask && cursor.take(3) == 0);
    CHECK(cursor.bit == membership::meaningful_bits(value));
    const auto padding = static_cast<unsigned>(written * 8U - cursor.bit);
    CHECK(cursor.take(padding) == 0);
    return {output.begin(), output.begin() + written};
}

membership::MembershipSnapshot with_humans(std::uint8_t extent) {
    auto value = fixture(true);
    dawn::middleware::gameplay::descriptor::write_net_addr(0x7F000002U, 30976, value.citizen.address);
    value.remoteHumanCount = extent;
    constexpr std::array<int, 5> roles{-1, 0, 511, 512, 1022};
    constexpr std::array<std::uint8_t, 4> pattern{0, 0x7F, 0x80, 0xFF};
    for (std::size_t index = 0; index < extent && index < value.remoteHumans.size(); ++index) {
        auto& human = value.remoteHumans[index];
        human.present = true;
        human.identity = {0xABCDEF0000000100ULL + index, roles[index],
            (std::numeric_limits<std::int32_t>::min)() + static_cast<std::int32_t>(index),
            0x12340000ULL + index, 0x11110000ULL + index, 0x22220000ULL + index, 0x33330000ULL + index};
        dawn::middleware::gameplay::descriptor::write_net_addr(0x7F000010U + static_cast<std::uint32_t>(index),
            30976, human.address);
        human.address[60] = static_cast<std::byte>(index + 0xA0U);
        human.transitionToken = static_cast<std::uint8_t>(index + 0x30U);
        human.synchronizationToken = static_cast<std::uint8_t>(index + 0x80U);
        human.hasOpaqueConnectIdentity = (index & 1U) == 0;
        for (std::size_t byte = 0; byte < human.opaqueConnectIdentity.size(); ++byte)
            human.opaqueConnectIdentity[byte] = pattern[(byte + index) % pattern.size()];
    }
    return value;
}

void baselines() {
    constexpr std::array<const char*, 4> hashes{
        "e9d0b1bad8623d4354ca9e8fc48d23fb7e55b184b43d44efb8cfd8d15a8485b7",
        "b790462fc184a68f01be77b305c9f67b0dd4b571d64b1e45bd1d9b47f7eae079",
        "64775b5608a734d586c1e98f7a406d2531cfc2f4d8557201b06199a25a383369",
        "e35fdc71fa8f6c7cfc9af485846ed0d8aef85c23d18c74b6cec7c7a0b9d54775"};
    std::size_t index{};
    for (const bool control : {false, true}) for (const bool sync : {false, true}) {
        const auto encoded = inspect(fixture(control, sync));
        CHECK(digest(encoded) == hashes[index++]);
    }
}

void human_cases() {
    for (unsigned flags = 0; flags < 16; ++flags) {
        auto value = with_humans(1);
        auto& human = value.remoteHumans[0];
        human.hasSynchronizationToken = (flags & 1U) != 0;
        if (flags & 2U) human.currentLeg = {3, 0x12345678, 56, 1, 2, true};
        if (flags & 4U) human.pendingLeg = {1022, 0xFFFFFFFFU, -1, -1, 0, true};
        human.hasOpaqueConnectIdentity = (flags & 8U) != 0;
        inspect(value);
    }
    inspect(with_humans(2));
    auto gap = with_humans(3);
    gap.remoteHumans[1].present = false;
    inspect(gap);
    gap.remoteHumans[0].present = false;
    inspect(gap);
    auto maximum = with_humans(5);
    maximum.hasSynchronizationToken = maximum.hasHostSynchronizationToken = true;
    maximum.currentLeg = maximum.pendingLeg = {1022, 0xFFFFFFFFU, 511, 2, 2, true};
    for (auto& human : maximum.remoteHumans) {
        human.hasSynchronizationToken = human.hasOpaqueConnectIdentity = true;
        human.currentLeg = maximum.currentLeg; human.pendingLeg = maximum.pendingLeg;
    }
    CHECK(inspect(maximum).size() == membership::kMaximumEncodedSize);
    maximum.localAmbassador = true;
    inspect(maximum);
    for (const auto field2 : {(std::numeric_limits<std::int32_t>::min)(), -1, 0,
                             (std::numeric_limits<std::int32_t>::max)()}) {
        auto value = with_humans(1); value.remoteHumans[0].identity.field2 = field2;
        inspect(value);
    }
    for (const bool sync : {false, true}) {
        auto clean = with_humans(1);
        clean.hasSynchronizationToken = clean.remoteHumans[0].hasSynchronizationToken = sync;
        auto retained = clean;
        const membership::RegionLeg absentLeg{(std::numeric_limits<std::int32_t>::min)(),
            0xDEADBEEFU, (std::numeric_limits<std::int32_t>::max)(), 127, -128, false};
        retained.currentLeg = retained.pendingLeg = absentLeg;
        retained.remoteHumans[0].currentLeg = retained.remoteHumans[0].pendingLeg = absentLeg;
        CHECK(inspect(retained) == inspect(clean));
    }
}

void refuses(const membership::MembershipSnapshot& value, bool shortOutput = false) {
    std::array<std::byte, membership::kMaximumEncodedSize> output{};
    output.fill(std::byte{0xD3});
    const auto before = output;
    std::size_t written = 99;
    const auto size = shortOutput ? membership::encoded_size(value) - 1 : output.size();
    CHECK(!membership::encode_replicate_membership(value, std::span(output).first(size), written));
    CHECK(written == 0 && output == before);
}

void invalid_inputs() {
    const auto good = with_humans(2);
    refuses(good, true);
    for (unsigned variant = 0; variant < 31; ++variant) {
        auto bad = good; auto& human = bad.remoteHumans[0];
        switch (variant) {
        case 0: bad.remoteHumanCount = 6; break;
        case 1: bad.remoteHumanCount = 255; break;
        case 2: bad.citizen.present = false; break;
        case 3: bad.remoteHumanCount = 1; break;
        case 4: human.identity.memberKey = 0; break;
        case 5: human.identity.memberKey = bad.identity.memberKey; break;
        case 6: human.identity.memberKey = bad.citizen.memberKey; break;
        case 7: human.identity.memberKey = bad.remoteHumans[1].identity.memberKey; break;
        case 8: human.identity.accountSoid = 0; break;
        case 9: human.identity.field5 = 0; break;
        case 10: human.identity.field1 = -2; break;
        case 11: human.identity.field1 = 1023; break;
        case 12: human.address.back() = std::byte{6}; break;
        case 13: human.address[0] = human.address[30] = std::byte{0}; break;
        case 14: human.address[0] = human.address[30] = std::byte{224}; break;
        case 15: human.address[4] |= std::byte{1}; human.address[34] = human.address[4]; break;
        case 16: human.address[4] = human.address[5] = human.address[34] = human.address[35] = std::byte{0}; break;
        case 17: human.address[30] ^= std::byte{1}; break;
        case 18: human.address[6] = std::byte{1}; break;
        case 19: human.address[40] = std::byte{0}; break;
        case 20: human.address = bad.citizen.address; break;
        case 21: human.address = bad.remoteHumans[1].address; human.address[84] ^= std::byte{1}; break;
        case 22: human.currentLeg = {-2, 0, 0, 0, 0, true}; break;
        case 23: human.pendingLeg = {1023, 0, 0, 0, 0, true}; break;
        case 24: human.currentLeg = {0, 0, 0, 3, 0, true}; break;
        case 25: human.pendingLeg = {0, 0, 0, 0, -2, true}; break;
        case 26: bad.identity.memberKey = 0; break;
        case 27: bad.spawn.state = 7; break;
        case 28: bad.identity.field1 = -2; break;
        case 29: bad.identity.field1 = 1023; break;
        case 30: bad.teleport.state = 7; break;
        }
        refuses(bad);
    }
    auto zeroExtent = good; zeroExtent.remoteHumanCount = 0; refuses(zeroExtent);
    auto absent = good;
    absent.remoteHumans = {}; absent.remoteHumanCount = 5;
    inspect(absent);
    absent.citizen.present = false;
    refuses(absent);
}

namespace roster = dawn::core::multiplayer::world_roster;
std::array<roster::Peer, membership::kMaximumRemoteHumans> registrations{};

bool live_address(roster::resolver::PeerAddressHandle handle, std::span<const std::byte> address) noexcept {
    for (const auto& row : registrations) {
        if (row.registeredAddress && row.registeredAddress == handle && address.size() == row.human.address.size()
            && std::equal(address.begin(), address.end(), row.human.address.begin())) return true;
    }
    return false;
}

void projection_lifecycle() {
    auto source = with_humans(5);
    source.epoch = 0; // The runtime uses zero for Tower on the wire.
    auto base = source;
    base.remoteHumans = {};
    base.remoteHumanCount = 0;
    // The activity creator uses FAH while address resolution uses primary BAP.
    const roster::Recipient recipient{{{{2, {2}}, {3}}, {4}}, {{1, {1}}, {2}}, {{800, {5}}, {6}},
        base.identity.memberKey, base.citizen.memberKey, 10, base.epoch, base.citizen.regionIndex};
    roster::Projection rosterView;
    CHECK(!rosterView.open({}) && rosterView.open(recipient));
    CHECK(rosterView.open(recipient));

    std::array<roster::SlotHandle, membership::kMaximumRemoteHumans> handles{};
    for (std::size_t index = 0; index < handles.size(); ++index) {
        registrations[index] = {source.remoteHumans[index], {recipient.resolverOwner, 20 + index}, 80 + index, 1000};
    }
    auto refused = [&](const roster::Peer& peer) {
        roster::SlotHandle handle{999, 2};
        CHECK(!rosterView.add(recipient, base, peer, 100, &live_address, handle));
        CHECK(!handle);
    };
    auto wrong = registrations[0]; wrong.registeredAddress.owner.generation.value++;
    refused(wrong);
    const auto primaryRegistration = registrations[0];
    // Even a live, exact address registration on the FAH authentication is the wrong owner.
    registrations[0].registeredAddress.owner = recipient.binding.authentication;
    CHECK(live_address(registrations[0].registeredAddress, registrations[0].human.address));
    refused(registrations[0]);
    registrations[0] = primaryRegistration;
    auto missingResolverOwner = recipient;
    missingResolverOwner.resolverOwner = {};
    CHECK(!rosterView.open(missingResolverOwner));
    auto missingTable = recipient;
    missingTable.tableGeneration = 0;
    CHECK(!rosterView.open(missingTable));
    wrong = registrations[0]; wrong.deadline = 100;
    refused(wrong);
    wrong = registrations[0]; wrong.human.address[60] ^= std::byte{1};
    refused(wrong);
    for (std::size_t index = 0; index < handles.size(); ++index) {
        CHECK(rosterView.add(recipient, base, registrations[index], 100, &live_address, handles[index]));
        CHECK(handles[index].nativeSlot == membership::kFirstRemoteHumanSlot + index);
        refused(registrations[index]);
    }
    membership::MembershipSnapshot output{};
    CHECK(rosterView.project(recipient, base, 999, &live_address, output));
    CHECK(inspect(output) == inspect(source));
    auto other = recipient; ++other.region.generation.value;
    CHECK(!rosterView.open(other));
    CHECK(!rosterView.project(other, base, 999, &live_address, output));
    CHECK(!rosterView.project(recipient, base, 1000, &live_address, output));
    CHECK(output.remoteHumanCount == 5 && membership::member_mask(output) == 127);
    auto baseWithOwner = base; baseWithOwner.remoteHumans[0] = source.remoteHumans[0];
    CHECK(!rosterView.project(recipient, baseWithOwner, 999, &live_address, output));

    // Simulate resolver revocation between publications. Refuse the whole projection
    // until the owner retires the exact row, rather than shifting another player's slot.
    const auto retiredAddress = registrations[2].registeredAddress;
    registrations[2].registeredAddress = {};
    CHECK(!rosterView.project(recipient, base, 999, &live_address, output));
    roster::resolver::PeerAddressHandle revoke{};
    CHECK(!rosterView.retire(other, handles[2], revoke) && !revoke);
    CHECK(rosterView.retire(recipient, handles[2], revoke) && revoke == retiredAddress);
    CHECK(!rosterView.retire(recipient, handles[2], revoke) && !revoke);
    CHECK(rosterView.project(recipient, base, 999, &live_address, output));
    auto sparse = source; sparse.remoteHumans[2] = {};
    CHECK(inspect(output) == inspect(sparse));
    refused(registrations[0]);

    auto reauthenticated = recipient;
    ++reauthenticated.resolverOwner.generation.value;
    CHECK(!rosterView.open(reauthenticated));
    CHECK(!rosterView.project(reauthenticated, base, 999, &live_address, output));
    CHECK(!rosterView.retire(reauthenticated, handles[0], revoke) && !revoke);

    auto changedWire = reauthenticated;
    ++changedWire.wireEpoch;
    auto newTable = reauthenticated;
    ++newTable.tableGeneration;
    CHECK(!rosterView.open(newTable));
    for (std::size_t index : {0U, 1U, 3U, 4U}) {
        CHECK(rosterView.retire(recipient, handles[index], revoke) && revoke == registrations[index].registeredAddress);
    }
    CHECK(!rosterView.open(other) && !rosterView.open(reauthenticated) && !rosterView.open(changedWire));
    CHECK(rosterView.open(newTable));
    roster::SlotHandle fresh{};
    // Reauthentication of the same primary socket never reuses the previous registration.
    CHECK(live_address(registrations[0].registeredAddress, registrations[0].human.address));
    CHECK(!rosterView.add(newTable, base, registrations[0], 100, &live_address, fresh) && !fresh);
    registrations[0].registeredAddress = {newTable.resolverOwner, 100};
    CHECK(rosterView.add(newTable, base, registrations[0], 100, &live_address, fresh));
    CHECK(fresh.nativeSlot == handles[0].nativeSlot && fresh.generation != handles[0].generation);
    CHECK(!rosterView.retire(newTable, handles[0], revoke) && !revoke);
    CHECK(!rosterView.project(recipient, base, 100, &live_address, output));
    CHECK(rosterView.project(newTable, base, 100, &live_address, output));
    CHECK(output.remoteHumanCount == 1);
    same_identity(output.remoteHumans[0].identity, registrations[0].human.identity);
    auto wrongWire = base;
    ++wrongWire.epoch;
    CHECK(!rosterView.project(newTable, wrongWire, 100, &live_address, output));
    CHECK(rosterView.retire(newTable, fresh, revoke) && revoke == registrations[0].registeredAddress);
    CHECK(!rosterView.open(recipient)); // An empty new table still cannot reopen an old generation.
}

} // namespace

int main() {
    baselines(); human_cases(); invalid_inputs(); projection_lifecycle();
    std::printf("PASS remote human membership %u checks; structural encoding only\n", checks);
}
