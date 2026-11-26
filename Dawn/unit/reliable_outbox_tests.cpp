#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>

#include "../src/middleware/gameplay/peer/reliable_assembly.h"
#include "../src/middleware/gameplay/peer/reliable_outbox.h"
#include "../src/server/gameplay/group/shared_membership.h"

namespace bits = dawn::middleware::encoding::bits;
namespace game = dawn::state::gameplay;
namespace group = dawn::server::gameplay::group;
namespace wire = dawn::middleware::gameplay::group;
namespace peer = dawn::middleware::gameplay::peer;
namespace descriptor = dawn::middleware::gameplay::descriptor;

static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s\n", __LINE__, #value); std::abort(); } } while (false)

static constexpr auto kMembershipId = static_cast<std::uint8_t>(wire::SessionMessageId::membershipUpdate);
static_assert(kMembershipId == 30 && wire::kMembershipUpdateSize == 31'104);
static_assert(peer::kRollingFragmentCapacity == 33);

static peer::AckState acknowledgement(std::uint16_t packet) {
    peer::AckState ack{};
    ack.ringInitialized = true;
    ack.receiveHead = static_cast<std::uint16_t>(packet % peer::kPacketRingSize);
    return ack;
}

static peer::QueueRecords encode_flight(const game::OutboundQueue& queue) {
    std::array<std::byte, 128> packet{};
    bits::Writer writer(packet);
    CHECK(peer::write_head_and_ack(writer, 0, {}));
    CHECK(peer::write_queue(writer, queue, queue.sentCount));
    CHECK(peer::write_empty_queue(writer) && peer::write_absent_filler(writer));
    std::size_t size{};
    CHECK(writer.finish(size));
    peer::EstablishedPacket decoded{};
    CHECK(peer::decode_established(std::span(packet).first(size), false, decoded));
    CHECK(decoded.large.count == 1 && decoded.small.count == 0);
    return decoded.large;
}

static void boundary_golden() {
    peer::RollingReliableOutbox outbox{};
    CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, {}, 0));
    CHECK(outbox.begin_packet(10));
    const auto record = encode_flight(outbox.queue()).records.front();
    CHECK(record.sequence == 1 && record.bitCount == 24 && record.shortFragment);
    CHECK(record.bytes[0] == std::byte{0x78} && record.bytes[1] == std::byte{0x79}
        && record.bytes[2] == std::byte{0x80});
    CHECK(outbox.acknowledge(acknowledgement(10)) == 1 && outbox.queue().count == 0);

    std::array<std::byte, 29> exact{};
    exact.fill(std::byte{0xA5});
    CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, exact, exact.size() * 8));
    CHECK(outbox.queue().count == 2 && outbox.pending() == 0);
    CHECK(outbox.begin_packet(11));
    const auto payload = encode_flight(outbox.queue()).records.front();
    CHECK(payload.sequence == 2 && payload.bitCount == 256 && !payload.shortFragment);
    CHECK(payload.bytes.back() == std::byte{0xA5});
    CHECK(outbox.acknowledge(acknowledgement(11)) == 1);
    CHECK(outbox.begin_packet(12));
    const auto marker = encode_flight(outbox.queue()).records.front();
    CHECK(marker.sequence == 3 && marker.shortFragment && marker.bitCount == 1);
    CHECK(marker.bytes[0] == std::byte{});
    CHECK(outbox.acknowledge(acknowledgement(12)) == 1);

    // Normal messages keep the exact original fragment stream, including a partial body bit.
    game::OutboundQueue legacy{};
    legacy.nextSequence = outbox.queue().nextSequence;
    CHECK(peer::enqueue_message(legacy, kMembershipId, wire::kMembershipUpdateSize, exact, 229));
    CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, exact, 229));
    const auto& left = legacy.fragments.front();
    const auto& right = outbox.queue().fragments.front();
    CHECK(legacy.count == 1 && outbox.queue().count == 1);
    CHECK(left.sequence == right.sequence && left.bytes == right.bytes
        && left.bitCount == right.bitCount && left.shortFragment == right.shortFragment);
    CHECK(right.bitCount == 253 && right.shortFragment);
}

static group::SharedMembershipSnapshot maximum_roster() {
    std::array<std::byte, descriptor::kNetAddrSize> hostAddress{};
    descriptor::write_net_addr(0xC0A8017CU, 30000, hostAddress);
    std::array<group::SharedHuman, group::kSharedHumanCapacity> humans{};
    for (std::size_t index = 0; index < humans.size(); ++index) {
        auto& human = humans[index];
        human.endpoint = {static_cast<std::uint32_t>(0xC0A80180U + index),
                          static_cast<std::uint16_t>(30002U + index * 2U)};
        descriptor::write_net_addr(human.endpoint.address, human.endpoint.port, human.address);
        human.address.back() = std::byte{6};
        human.address[64] = static_cast<std::byte>(0xA0U + index);
        human.machineId = 0x4000000000000000ULL + index;
        human.joinId = (std::numeric_limits<std::uint64_t>::max)() - index;
        human.playerId = 0x6000000000000000ULL + index;
        human.addSequence = 0xFFFFFU - static_cast<std::uint32_t>(index);
        human.slot = static_cast<std::uint32_t>(index);
        human.established = human.hasPlayer = true;
    }
    group::SharedMembershipSnapshot snapshot{};
    CHECK(group::build_shared_membership(10, hostAddress, humans.back().joinId,
        (std::numeric_limits<std::uint32_t>::max)(), humans, snapshot));
    return snapshot;
}

static void six_human_round_trip() {
    const auto snapshot = maximum_roster();
    const auto update = snapshot.update();
    std::array<std::byte, peer::kRollingBodyCapacity> encoded{};
    bits::Writer body(encoded);
    CHECK(wire::write_membership_update(body, update));
    std::size_t encodedBytes{};
    CHECK(body.finish(encodedBytes) && encodedBytes == 1048);

    game::OutboundQueue production{};
    CHECK(!peer::enqueue_message(production, kMembershipId, wire::kMembershipUpdateSize,
        encoded, body.bit_count()));
    CHECK(production.count == 0 && production.nextSequence == game::kFirstMessageSequence);

    peer::RollingReliableOutbox outbox{};
    CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, encoded, body.bit_count()));
    CHECK(outbox.queue().count == 24 && outbox.pending() == 9);
    CHECK(!outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, {}, 0));
    CHECK(outbox.queue().count == 24 && outbox.pending() == 9);
    CHECK(!outbox.begin_packet(game::kPacketSequenceModulus));

    // Capture the actual decoded records in a test-sized collector. The existing receive window
    // is checked separately and deliberately remains too small for this experiment.
    std::array<std::byte, peer::kRollingFramedCapacity> collected{};
    bits::Writer frame(collected);
    game::ReliableQueue currentReceiver{};
    peer::AssembledMessage tooLarge{};
    constexpr auto kAfterId = static_cast<std::uint8_t>(wire::SessionMessageId::leaveAcknowledge);
    constexpr std::size_t kRecordCount = 33;
    for (std::size_t index = 0; index < kRecordCount; ++index) {
        if (index == 9) {
            CHECK(outbox.queue().count == 24 && outbox.pending() == 0);
            CHECK(outbox.enqueue(kAfterId, wire::kLeaveAcknowledgeSize, {}, 0));
            CHECK(outbox.pending() == 1);
        }
        const auto packet = static_cast<std::uint16_t>((1022 + index) % game::kPacketSequenceModulus);
        CHECK(outbox.begin_packet(packet));
        CHECK(!outbox.begin_packet(static_cast<std::uint16_t>((packet + 1) % game::kPacketSequenceModulus)));
        CHECK(outbox.queue().sentInPacket == packet);
        const auto records = encode_flight(outbox.queue());
        const auto& fragment = records.records.front();
        CHECK(fragment.sequence == index + 1);
        CHECK(fragment.shortFragment == (index + 1 == kRecordCount));
        if (index + 1 < kRecordCount) CHECK(fragment.bitCount == 256);
        CHECK(peer::accept_records(records, currentReceiver) == (index + 1 == kRecordCount ? 1U : 0U));
        CHECK(!peer::drain_message(currentReceiver, tooLarge));

        bits::Reader reader(fragment.bytes);
        for (std::size_t remaining = fragment.bitCount; remaining != 0;) {
            const auto width = static_cast<std::uint8_t>(remaining < 64 ? remaining : 64);
            std::uint64_t value{};
            CHECK(reader.read(width, value) && frame.write(value, width));
            remaining -= width;
        }
        const auto pendingBeforeAck = outbox.pending();
        CHECK(outbox.acknowledge(acknowledgement(static_cast<std::uint16_t>((packet + 1023) % 1024))) == 0);
        CHECK(outbox.pending() == pendingBeforeAck && outbox.queue().awaitingAcknowledgement);
        CHECK(outbox.acknowledge(acknowledgement(packet)) == 1);
        CHECK(outbox.acknowledge(acknowledgement(packet)) == 0);
    }
    CHECK(outbox.pending() == 0 && outbox.queue().count == 1);
    CHECK(outbox.begin_packet(31));
    const auto after = encode_flight(outbox.queue()).records.front();
    CHECK(after.sequence == 34 && after.shortFragment && after.bitCount == 24);
    bits::Reader afterReader(after.bytes);
    std::uint64_t value{};
    CHECK(afterReader.read(6, value) && value == kAfterId);
    CHECK(afterReader.read(18, value) && value == wire::kLeaveAcknowledgeSize);

    // The declaration is the native decoded object size, never the wire-body byte count.
    CHECK(frame.bit_count() == body.bit_count() + 24);
    bits::Reader actual(collected), expected(encoded);
    CHECK(actual.read(6, value) && value == kMembershipId);
    CHECK(actual.read(18, value) && value == 31'104);
    for (std::size_t remaining = body.bit_count(); remaining != 0;) {
        const auto width = static_cast<std::uint8_t>(remaining < 64 ? remaining : 64);
        std::uint64_t expectedValue{};
        CHECK(actual.read(width, value) && expected.read(width, expectedValue) && value == expectedValue);
        remaining -= width;
    }
}

static void malformed_wrap_and_reset() {
    peer::RollingReliableOutbox outbox{};
    CHECK(!outbox.enqueue(255, wire::kMembershipUpdateSize, {}, 0));
    CHECK(!outbox.enqueue(kMembershipId, 1U << 18, {}, 0));
    CHECK(!outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, {}, 1));
    std::array<std::byte, peer::kRollingBodyCapacity + 1> oversized{};
    CHECK(!outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, oversized, oversized.size() * 8));
    CHECK(outbox.queue().count == 0 && outbox.queue().nextSequence == 1 && outbox.pending() == 0);

    // Exercise the real modulo increment without adding an arbitrary sequence setter to the API.
    for (std::uint16_t sequence = 1; sequence < game::kMessageSequenceModulus - 1; ++sequence) {
        CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, {}, 0));
        CHECK(outbox.queue().fragments.front().sequence == sequence);
        const auto packet = static_cast<std::uint16_t>(sequence % game::kPacketSequenceModulus);
        CHECK(outbox.begin_packet(packet));
        CHECK(outbox.acknowledge(acknowledgement(packet)) == 1);
    }
    const auto body = std::span(oversized).first(peer::kRollingBodyCapacity);
    CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, body, body.size() * 8));
    CHECK(outbox.queue().fragments[0].sequence == 8191 && outbox.queue().fragments[1].sequence == 0);
    CHECK(outbox.begin_packet(77));
    auto missing = acknowledgement(78);
    missing.reportedCount = 1;
    CHECK(outbox.acknowledge(missing) == 0);
    missing.reportedCount = 100;
    CHECK(outbox.acknowledge(missing) == 0 && outbox.queue().count == 24 && outbox.pending() == 9);
    outbox.reset();
    CHECK(outbox.acknowledge(acknowledgement(77)) == 0);
    CHECK(outbox.queue().count == 0 && outbox.queue().nextSequence == 1 && outbox.pending() == 0);
    CHECK(!outbox.queue().awaitingAcknowledgement);

    CHECK(outbox.enqueue(kMembershipId, wire::kMembershipUpdateSize, {}, 0));
    CHECK(outbox.begin_packet(127));
    auto acrossRing = acknowledgement(128);
    acrossRing.reportedCount = 1;
    CHECK(outbox.acknowledge(acrossRing) == 0);
    acrossRing.received[0] = true;
    CHECK(outbox.acknowledge(acrossRing) == 1);
}

int main() {
    boundary_golden();
    six_human_round_trip();
    malformed_wrap_and_reset();
    std::printf("PASS %u rolling reliable outbox checks\n", checks);
}
