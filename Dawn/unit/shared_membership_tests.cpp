#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>

#include "../src/server/gameplay/group/shared_membership.h"
#include "../src/server/gameplay/peer/peer_link_lookup.h"
#include "../src/middleware/gameplay/group/session_state.h"
#include "../src/middleware/gameplay/peer/established_packet.h"
#include "../src/middleware/gameplay/peer/reliable_assembly.h"

namespace group = dawn::server::gameplay::group;
namespace wire = dawn::middleware::gameplay::group;
namespace descriptor = dawn::middleware::gameplay::descriptor;
namespace bits = dawn::middleware::encoding::bits;
namespace gameplay = dawn::state::gameplay;
namespace peer_wire = dawn::middleware::gameplay::peer;
static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s\n", __LINE__, #value); std::abort(); } } while (false)

static std::uint64_t little(const wire::SessionState& state, std::size_t offset, std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) {
        value |= std::to_integer<std::uint64_t>(state[offset + index]) << (8U * index);
    }
    return value;
}

static std::size_t verify_native_snapshot(const group::SharedMembershipSnapshot& snapshot,
                                          std::span<const group::SharedHuman> humans) {
    const auto update = snapshot.update();
    CHECK(update.members.size() == humans.size() + 1 && update.players.size() == humans.size());
    static wire::SessionState state{};
    wire::build_session_state(update, state);
    CHECK(little(state, 28, 4) == humans.size() + 1);
    CHECK(little(state, 40, 8) == (std::uint64_t{1} << (humans.size() + 1)) - 1);
    CHECK(little(state, 15184, 4) == humans.size());
    CHECK(little(state, 15188, 4) == (std::uint64_t{1} << humans.size()) - 1);
    for (const auto& human : humans) {
        const auto member = static_cast<std::size_t>(human.slot) + 1;
        CHECK(update.members[member].machineId == human.machineId);
        CHECK(update.members[member].address == human.address);
        CHECK(update.members[member].playerSlot == human.slot);
        CHECK(little(state, 56 + 184 * member + 120, 8) == human.machineId);
        CHECK(little(state, 56 + 184 * member + 136, 8) == human.joinId);
        CHECK(little(state, 15192 + 424 * human.slot + 4, 8) == human.playerId);
        CHECK(little(state, 15192 + 424 * human.slot + 12, 4) == member);
        CHECK(little(state, 15192 + 424 * human.slot + 16, 4) == 0);
        CHECK(little(state, 15192 + 424 * human.slot + 20, 4) == human.addSequence);
    }
    // This larger test buffer measures the schema. It does not enlarge the
    // production reliable queue or imply that a six-human update can be sent.
    std::array<std::byte, 2048> body{};
    bits::Writer writer(body);
    std::size_t size{};
    CHECK(wire::write_membership_update(writer, update));
    CHECK(writer.finish(size));
    bits::Reader reader(std::span(body).first(size));
    CHECK(reader.skip(writer.bit_count() - 32));
    std::uint64_t hash{};
    CHECK(reader.read(32, hash) && hash == wire::session_state_hash(update));
    gameplay::OutboundQueue outgoing{};
    const auto initialSequence = outgoing.nextSequence;
    const bool queued = peer_wire::enqueue_message(outgoing,
        static_cast<std::uint8_t>(wire::SessionMessageId::membershipUpdate),
        wire::kMembershipUpdateSize, std::span(body).first(size), writer.bit_count());
    if (humans.size() == 3) {
        CHECK(queued && outgoing.count == 20 && outgoing.count <= gameplay::kOutboundSlots);
        std::array<std::byte, 1500> datagram{};
        bits::Writer transport(datagram);
        CHECK(peer_wire::write_head_and_ack(transport, 0, {}));
        CHECK(peer_wire::write_queue(transport, outgoing, outgoing.count));
        CHECK(peer_wire::write_empty_queue(transport) && peer_wire::write_absent_filler(transport));
        std::size_t datagramSize{};
        CHECK(transport.finish(datagramSize));
        peer_wire::EstablishedPacket decoded{};
        CHECK(peer_wire::decode_established(std::span(datagram).first(datagramSize), false, decoded));
        gameplay::ReliableQueue incoming{};
        CHECK(peer_wire::accept_records(decoded.large, incoming) == 0);
        peer_wire::AssembledMessage assembled{};
        CHECK(peer_wire::drain_message(incoming, assembled));
        CHECK(assembled.id == static_cast<std::uint8_t>(wire::SessionMessageId::membershipUpdate)
              && assembled.declaredSize == wire::kMembershipUpdateSize);
        CHECK(assembled.bitCount == writer.bit_count() + assembled.bodyBitOffset);
        bits::Reader actual(assembled.bytes), expected(std::span(body).first(size));
        CHECK(actual.skip(assembled.bodyBitOffset));
        for (std::size_t offset = 0; offset < writer.bit_count();) {
            const auto width = static_cast<std::uint8_t>((std::min)(std::size_t{64}, writer.bit_count() - offset));
            std::uint64_t first{}, second{};
            CHECK(actual.read(width, first) && expected.read(width, second) && first == second);
            offset += width;
        }
    } else {
        CHECK(!queued && outgoing.count == 0 && outgoing.nextSequence == initialSequence);
        CHECK(std::none_of(outgoing.fragments.begin(), outgoing.fragments.end(),
                          [](const auto& fragment) { return fragment.occupied; }));
    }
    return size;
}

static void fireteam_membership_targets() {
    static_assert(group::kSharedHumanCapacity == 6);
    std::array<std::byte, descriptor::kNetAddrSize> hostAddress{};
    descriptor::write_net_addr(0xC0A8017CU, 30000, hostAddress);
    std::array<group::SharedHuman, group::kSharedHumanCapacity> humans{};
    group::SharedSlotAssignments assignments{};
    for (std::size_t index = 0; index < humans.size(); ++index) {
        auto& human = humans[index];
        human.endpoint = {static_cast<std::uint32_t>(0xC0A80180U + index),
                          static_cast<std::uint16_t>(30002U + index * 2U)};
        descriptor::write_net_addr(human.endpoint.address, human.endpoint.port, human.address);
        // Preserve full native long-form addresses and full-width join IDs.
        // Small synthetic IDs would hide the current reliable transport limit.
        human.address.back() = std::byte{6};
        human.address[64] = static_cast<std::byte>(0xA0U + index);
        human.machineId = 0x4000000000000000ULL + index;
        human.joinId = (std::numeric_limits<std::uint64_t>::max)() - index;
        human.playerId = 0x6000000000000000ULL + index;
        human.addSequence = 0xFFFFFU - static_cast<std::uint32_t>(index);
        human.hasPlayer = true;
        human.established = true;
        CHECK(assignments.reserve(human.machineId, human.playerId, human.slot));
        CHECK(human.slot == index);
    }
    for (const std::size_t count : {std::size_t{3}, std::size_t{6}}) {
        const auto active = std::span(humans).first(count);
        group::SharedMembershipSnapshot snapshot{};
        CHECK(group::build_shared_membership(10, hostAddress, active.back().joinId,
              (std::numeric_limits<std::uint32_t>::max)(), active, snapshot));
        const auto encodedSize = verify_native_snapshot(snapshot, active);
        auto reversed = humans;
        std::reverse(reversed.begin(), reversed.begin() + count);
        group::SharedMembershipSnapshot reordered{};
        CHECK(group::build_shared_membership(10, hostAddress, active.back().joinId,
              snapshot.revision, std::span(reversed).first(count), reordered));
        CHECK(wire::session_state_hash(snapshot.update()) == wire::session_state_hash(reordered.update()));
        // Highest-slot disconnect leaves the remaining native slots unchanged.
        group::SharedMembershipSnapshot disconnected{};
        CHECK(group::build_shared_membership(10, hostAddress, active.front().joinId,
              20, active.first(count - 1), disconnected));
        CHECK(disconnected.members[count - 1].machineId == active[count - 2].machineId);
        std::uint32_t rejoined = group::kInvalidSharedHumanSlot;
        CHECK(assignments.reserve(active.back().machineId, active.back().playerId, rejoined));
        CHECK(rejoined == active.back().slot);
        CHECK(group::build_shared_membership(10, hostAddress, active.back().joinId,
              snapshot.revision, active, reordered));
        CHECK(wire::session_state_hash(snapshot.update()) == wire::session_state_hash(reordered.update()));
        const auto unchanged = reordered;
        // A missing lower member pauses publication rather than renumbering survivors.
        CHECK(!group::build_shared_membership(10, hostAddress, active.back().joinId,
               21, active.subspan(1), reordered));
        CHECK(reordered.revision == unchanged.revision && reordered.members[1].machineId == active[0].machineId);
        std::array<std::byte, gameplay::kReassemblyCapacity> bounded{};
        bits::Writer boundedWriter(bounded);
        const bool fits = wire::write_membership_update(boundedWriter, snapshot.update());
        if (count == 3) { CHECK(fits && encodedSize <= bounded.size()); }
        else { CHECK(!fits && encodedSize > bounded.size()); }
        std::printf("Native membership target %zu humans: %zu encoded bytes; current reliable capacity %zu.\n",
                    count, encodedSize, bounded.size());
    }
    std::uint32_t slot = group::kInvalidSharedHumanSlot;
    CHECK(!assignments.reserve(0x7000000000000000ULL, 0x7000000000000001ULL, slot));
    CHECK(slot == group::kInvalidSharedHumanSlot);
    CHECK(!assignments.reserve(humans[5].machineId, humans[0].playerId, slot));
    std::array<group::SharedHuman, group::kSharedHumanCapacity + 1> seventh{};
    std::copy(humans.begin(), humans.end(), seventh.begin());
    seventh.back() = humans.back();
    seventh.back().machineId += 1; seventh.back().playerId += 1;
    seventh.back().joinId -= 1;
    seventh.back().endpoint.address += 1; seventh.back().endpoint.port += 2;
    descriptor::write_net_addr(seventh.back().endpoint.address, seventh.back().endpoint.port,
                               seventh.back().address);
    seventh.back().slot = group::kSharedHumanCapacity;
    group::SharedMembershipSnapshot rejected{};
    rejected.revision = 123;
    CHECK(!group::build_shared_membership(10, hostAddress, humans[0].joinId, 22, seventh, rejected));
    CHECK(rejected.revision == 123);
}

int main() {
    group::SharedSlotAssignments assignments{};
    std::uint32_t localSlot = group::kInvalidSharedHumanSlot;
    std::uint32_t remoteSlot = group::kInvalidSharedHumanSlot;
    CHECK(assignments.reserve(100, 300, localSlot) && localSlot == 0);
    CHECK(assignments.reserve(101, 301, remoteSlot) && remoteSlot == 1);
    // Disconnect drops endpoint authorization, not the native identity reservation.
    std::uint32_t rejoinedSlot = group::kInvalidSharedHumanSlot;
    CHECK(assignments.reserve(101, 301, rejoinedSlot) && rejoinedSlot == remoteSlot);
    for (std::uint32_t index = 2; index < group::kSharedHumanCapacity; ++index) {
        CHECK(assignments.reserve(100 + index, 300 + index, rejoinedSlot) && rejoinedSlot == index);
    }
    CHECK(!assignments.reserve(100 + group::kSharedHumanCapacity,
           300 + group::kSharedHumanCapacity, rejoinedSlot) && rejoinedSlot == group::kSharedHumanCapacity - 1);
    CHECK(!assignments.reserve(101, 302, rejoinedSlot));
    CHECK(!assignments.reserve(102, 301, rejoinedSlot));
    CHECK(!assignments.reserve(0, 301, rejoinedSlot) && !assignments.reserve(101, 0, rejoinedSlot));
    std::array<std::byte, descriptor::kNetAddrSize> hostAddress{};
    descriptor::write_net_addr(0xC0A8017CU, 30000, hostAddress);
    std::array<group::SharedHuman, 2> humans{};
    humans[0].endpoint = {0x7F000001U, 30002};
    humans[1].endpoint = {0xC0A8017DU, 30004};
    for (std::size_t index = 0; index < humans.size(); ++index) {
        auto& human = humans[index];
        descriptor::write_net_addr(human.endpoint.address, human.endpoint.port, human.address);
        human.machineId = 100 + index;
        human.joinId = 200 + index;
        human.playerId = 300 + index;
        human.addSequence = static_cast<std::uint32_t>(index + 4);
        human.slot = static_cast<std::uint32_t>(index);
        human.hasPlayer = true;
        human.established = index == 0;
    }
    // The peer's own opaque long-form address must survive without reconstruction.
    humans[1].address.back() = std::byte{6};
    humans[1].address[64] = std::byte{0xA5};
    group::SharedMembershipSnapshot snapshot{};
    CHECK(group::build_shared_membership(10, hostAddress, 201, 7, humans, snapshot));
    const auto update = snapshot.update();
    CHECK(update.members.size() == 3 && update.players.size() == 2);
    CHECK(update.members[0].machineId == 10 && !update.members[0].ownsPlayerSlot);
    CHECK(update.members[0].joinId == 201 && update.members[0].state == wire::MemberState::ready);
    CHECK(update.members[1].state == wire::MemberState::established);
    CHECK(update.members[2].state == wire::MemberState::ready);
    CHECK(update.members[1].address == humans[0].address && update.members[2].address == humans[1].address);
    CHECK(update.players[0].memberIndex == 1 && update.players[1].memberIndex == 2);
    CHECK(update.players[0].playerId == 300 && update.players[1].playerId == 301);
    CHECK(update.players[0].addSequence == 4 && update.players[1].addSequence == 5);
    const auto copied = snapshot;
    CHECK(copied.update().members.data() == copied.members.data());
    static wire::SessionState state{};
    wire::build_session_state(update, state);
    // These are the build-86657 native receiver offsets, independent of roster construction.
    CHECK(little(state, 28, 4) == 3);
    CHECK(little(state, 15184, 4) == 2 && little(state, 15188, 4) == 3);
    CHECK(little(state, 15192 + 4, 8) == 300 && little(state, 15192 + 424 + 4, 8) == 301);
    CHECK(little(state, 15192 + 12, 4) == 1 && little(state, 15192 + 424 + 12, 4) == 2);
    // Remove requests name a member-local player index. Both are index 0 even
    // though the second human's global player slot is 1.
    CHECK(little(state, 15192 + 16, 4) == 0 && little(state, 15192 + 424 + 16, 4) == 0);
    std::array<std::byte, 1024> body{};
    bits::Writer writer(body);
    CHECK(wire::write_membership_update(writer, update));
    std::size_t size{};
    CHECK(writer.finish(size) && size > 0 && size <= body.size());
    bits::Reader reader(std::span(body).first(size));
    CHECK(reader.skip(writer.bit_count() - 32));
    std::uint64_t trailingHash{};
    CHECK(reader.read(32, trailingHash) && trailingHash == wire::session_state_hash(update));
    const auto twoPlayerHash = wire::session_state_hash(update);

    auto reversed = humans;
    reversed[0] = humans[1]; reversed[1] = humans[0];
    group::SharedMembershipSnapshot reordered{};
    CHECK(group::build_shared_membership(10, hostAddress, 201, 7, reversed, reordered));
    CHECK(reordered.members[1].machineId == 100 && reordered.members[2].machineId == 101);
    CHECK(reordered.players[0].playerId == 300 && reordered.players[1].slot == 1);
    CHECK(wire::session_state_hash(reordered.update()) == twoPlayerHash);

    auto changed = humans;
    changed[1].hasPlayer = false;
    CHECK(group::build_shared_membership(10, hostAddress, 201, 8, changed, snapshot));
    CHECK(snapshot.playerCount == 1 && !snapshot.members[2].ownsPlayerSlot
          && snapshot.players[0].slot == 0 && snapshot.players[0].playerId == 300);
    CHECK(wire::session_state_hash(snapshot.update()) != twoPlayerHash);
    changed = humans;
    changed[0].hasPlayer = false;
    CHECK(group::build_shared_membership(10, hostAddress, 201, 8, changed, snapshot));
    CHECK(snapshot.playerCount == 1 && snapshot.players[0].slot == 1 && snapshot.players[0].memberIndex == 2);
    changed = humans;
    changed[1].hasPlayer = true;
    changed[1].established = true;
    CHECK(group::build_shared_membership(10, hostAddress, 201, 9, changed, snapshot));
    CHECK(snapshot.members[0].state == wire::MemberState::established);
    CHECK(group::build_shared_membership(10, hostAddress, 200, 10, std::span(humans).first(1), snapshot));
    CHECK(snapshot.memberCount == 2 && snapshot.playerCount == 1);
    const auto unchanged = snapshot;
    // Losing lower member 1 cannot renumber the surviving human into it. Player
    // holes above were legal, but member holes are not supported by this codec.
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, std::span(humans).subspan(1), snapshot));
    CHECK(snapshot.revision == unchanged.revision && snapshot.members[1].machineId == 100);
    changed = humans; changed[1].slot = changed[0].slot;
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, changed, snapshot));
    changed = humans; changed[1].slot = group::kInvalidSharedHumanSlot;
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, changed, snapshot));
    changed = humans; changed[1].machineId = changed[0].machineId;
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, changed, snapshot));
    CHECK(snapshot.revision == unchanged.revision && snapshot.memberCount == unchanged.memberCount);
    changed = humans; changed[1].playerId = changed[0].playerId;
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, changed, snapshot));
    changed = humans; changed[1].endpoint = changed[0].endpoint;
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, changed, snapshot));
    changed = humans; changed[1].address.fill(std::byte{});
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, changed, snapshot));
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 0, humans, snapshot));
    CHECK(!group::build_shared_membership(10, hostAddress, 999, 11, humans, snapshot));
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, {}, snapshot));
    std::array<group::SharedHuman, 3> third{};
    CHECK(!group::build_shared_membership(10, hostAddress, 201, 11, third, snapshot));
    CHECK(assignments.reserve(100, 300, rejoinedSlot) && rejoinedSlot == 0);
    CHECK(group::build_shared_membership(10, hostAddress, 200, 12, humans, snapshot));
    CHECK(snapshot.members[2].machineId == 101 && snapshot.players[1].slot == 1);
    assignments = {};
    CHECK(assignments.reserve(102, 302, rejoinedSlot) && rejoinedSlot == 0);

    static std::array<gameplay::PeerLink, 3> links{};
    namespace lookup = dawn::server::gameplay::peer::lookup;
    links[0].endpoint = humans[0].endpoint; links[0].sessions[0] = 10;
    links[1].endpoint = humans[1].endpoint; links[1].sessions[0] = 10;
    links[0].stage = links[1].stage = gameplay::PeerStage::connected;
    CHECK(lookup::find(links, 10) == nullptr);
    CHECK(lookup::find(links, 10, &humans[0].endpoint) == &links[0]);
    CHECK(lookup::find(links, 10, &humans[1].endpoint) == &links[1]);
    CHECK(lookup::find(links, 0) == nullptr && lookup::find(links, 11) == nullptr);
    links[1].sessions[0] = 11;
    CHECK(lookup::find(links, 10) == &links[0] && lookup::find(links, 11) == &links[1]);
    links[1].stage = gameplay::PeerStage::absent;
    CHECK(lookup::find(links, 11, &humans[1].endpoint) == nullptr);
    links[0].sessions[1] = 12;
    CHECK(lookup::find(links, 12, &humans[0].endpoint) == &links[0]);
    fireteam_membership_targets();
    std::printf("PASS: %u native membership and scoped-link checks. No game simulation was run.\n", checks);
}
