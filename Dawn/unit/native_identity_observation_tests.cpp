#include "../src/core/multiplayer/native_identity_observation_state.h"
#include "../src/middleware/gameplay/group/session_state.h"
#include "../src/client/hooks/bootflow/native_identity_observation.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace observation = dawn::core::multiplayer::identity_observation;
namespace wire = dawn::middleware::gameplay::group;
namespace {
unsigned checks{};
void check(bool value, int line) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL native identity observation line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)

struct Fixture final {
    std::vector<std::byte> bytes = std::vector<std::byte>(observation::kRoleOffset + 4);
    std::size_t failOffset = bytes.size();
    unsigned roleReads{};
    bool mutateSecond{}, forbiddenRead{};

    void put(std::size_t offset, std::uint64_t value, std::size_t width) noexcept {
        for (std::size_t index = 0; index < width; ++index)
            bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 255U);
    }

    Fixture() {
        // Build a real production membership replica, not a second encoder in the fixture.
        std::array<wire::MembershipMember, 3> members{};
        for (std::size_t index = 0; index < members.size(); ++index) {
            members[index].machineId = 0x1000 + index;
            members[index].connectionPresent = true;
            members[index].state = wire::MemberState::established;
        }
        members[1].ownsPlayerSlot = members[2].ownsPlayerSlot = true;
        members[1].playerSlot = 0;
        members[2].playerSlot = 1;
        std::array<wire::MembershipPlayer, 2> players{};
        for (std::size_t index = 0; index < players.size(); ++index) {
            players[index].slot = static_cast<std::uint32_t>(index);
            players[index].memberIndex = static_cast<std::uint32_t>(index + 1);
            players[index].playerId = 0x7000 + index;
        }
        wire::SessionState replica{};
        wire::build_session_state({members[0].machineId, 19, 0, 0, members, players}, replica);
        std::copy(replica.begin(), replica.end(), bytes.begin() + observation::kReplicaOffset);
        put(observation::kRoleOffset, 1, 4);
        put(observation::kModeOffset, 6, 4);
    }

    /** The reader actively refuses all address blobs and all player configuration fields. */
    [[nodiscard]] bool allowed(std::size_t offset, std::size_t size) const noexcept {
        if (size != 4 && size != 8) return false;
        if (size == 4 && (offset == observation::kRoleOffset || offset == observation::kModeOffset
            || offset == observation::kReplicaOffset + 4 || offset == observation::kReplicaOffset + 28
            || offset == observation::kReplicaOffset + 15184 || offset == observation::kReplicaOffset + 15188)) return true;
        if (size == 8 && (offset == observation::kReplicaOffset + 40 || offset == observation::kReplicaOffset + 48)) return true;
        for (std::size_t index = 0; index < 32; ++index) {
            const auto member = observation::kReplicaOffset + 56 + index * 184;
            if (size == 8 && (offset == member + 8 || offset == member + 112 || offset == member + 120
                || offset == member + 136 || offset == member + 168)) return true;
            if (size == 4 && (offset == member + 176 || offset == observation::kReplicaOffset + 5968 + index * 288)) return true;
            const auto player = observation::kReplicaOffset + 15192 + index * 424;
            if (size == 8 && offset == player + 4) return true;
            if (size == 4 && (offset == player + 12 || offset == player + 16 || offset == player + 20)) return true;
        }
        return false;
    }

    static bool read(void* context, std::size_t offset, std::span<std::byte> output) noexcept {
        auto& fixture = *static_cast<Fixture*>(context);
        if (!fixture.allowed(offset, output.size())) { fixture.forbiddenRead = true; return false; }
        if (offset == fixture.failOffset || offset + output.size() > fixture.bytes.size()) return false;
        if (offset == observation::kRoleOffset && ++fixture.roleReads == 2 && fixture.mutateSecond)
            fixture.put(observation::kReplicaOffset + 15192 + 4, 0xABCDEF, 8);
        std::memcpy(output.data(), fixture.bytes.data() + offset, output.size());
        return true;
    }
};

void malformed(std::size_t offset, std::uint64_t value, std::size_t width) {
    Fixture fixture;
    fixture.put(offset, value, width);
    observation::Sample output{};
    output.revision = 100;
    CHECK(!observation::capture(&Fixture::read, &fixture, output));
    CHECK(output.revision == 0 && output.memberMask == 0 && output.role == -1);
    CHECK(!fixture.forbiddenRead);
}

void parser_tests() {
    Fixture fixture;
    observation::Sample sample{};
    CHECK(observation::capture(&Fixture::read, &fixture, sample));
    CHECK(!fixture.forbiddenRead && fixture.roleReads == 2);
    CHECK(sample.role == 1 && sample.mode == 6 && sample.revision == 19);
    CHECK(sample.memberMask == 7 && sample.playerMask == 3);
    CHECK(sample.members[0].machineId == 0x1000 && !sample.members[0].ownsPlayer);
    CHECK(sample.members[1].machineId == 0x1001 && sample.members[1].playerId == 0x7000 && sample.members[1].playerSlot == 0);
    CHECK(sample.members[2].machineId == 0x1002 && sample.members[2].playerId == 0x7001 && sample.members[2].playerSlot == 1);
    CHECK(sample.members[1].joinId == 0 && sample.members[1].playerSequence == 0);
    CHECK(sample.members[3].machineId == 0 && sample.members[3].playerId == 0);
    CHECK(!observation::capture(nullptr, nullptr, sample) && sample.role == -1);

    constexpr auto replica = observation::kReplicaOffset;
    constexpr auto member = replica + 56;
    constexpr auto player = replica + 15192;
    malformed(observation::kRoleOffset, 7, 4);
    malformed(observation::kRoleOffset, UINT32_MAX, 4);
    malformed(observation::kModeOffset, UINT32_MAX, 4);
    malformed(replica + 28, 33, 4);
    malformed(replica + 28, 0, 4);
    malformed(replica + 28, 2, 4);
    malformed(replica + 40, std::uint64_t{1} << 32U, 8);
    malformed(replica + 48, 2, 8);
    malformed(member + 8, 85, 8);
    malformed(member + 112, 7, 8);
    malformed(member + 120, 0, 8);
    malformed(member + 184 + 120, 0x1000, 8);
    malformed(member + 168, 2, 8);
    malformed(member + 184 + 176, 32, 4);
    malformed(member + 2 * 184 + 176, 0, 4);
    malformed(replica + 15184, 33, 4);
    malformed(replica + 15184, 1, 4);
    malformed(replica + 15188, 5, 4);
    malformed(player + 4, 0, 8);
    malformed(player + 424 + 4, 0x7000, 8);
    malformed(player + 12, 0, 4);
    malformed(player + 16, 1, 4);

    Fixture failedRead;
    failedRead.failOffset = member + 184 + 120;
    CHECK(!observation::capture(&Fixture::read, &failedRead, sample));
    Fixture unstable;
    unstable.mutateSecond = true;
    CHECK(!observation::capture(&Fixture::read, &unstable, sample) && sample.role == -1);
    CHECK(!unstable.forbiddenRead);

    Fixture sparse;
    sparse.put(replica + 28, 1, 4);
    sparse.put(replica + 40, std::uint64_t{1} << 31U, 8);
    sparse.put(replica + 48, 1, 8);
    sparse.put(replica + 15184, 1, 4);
    sparse.put(replica + 15188, std::uint64_t{1} << 31U, 4);
    constexpr auto lastMember = member + 31 * 184;
    sparse.put(lastMember + 8, 86, 8);
    sparse.put(lastMember + 112, 8, 8);
    sparse.put(lastMember + 120, 0xFFFF0001, 8);
    sparse.put(lastMember + 168, 1, 8);
    sparse.put(lastMember + 176, 31, 4);
    constexpr auto lastPlayer = player + 31 * 424;
    sparse.put(lastPlayer + 4, 0xFFFF0002, 8);
    sparse.put(lastPlayer + 12, 31, 4);
    CHECK(observation::capture(&Fixture::read, &sparse, sample));
    CHECK(!sparse.forbiddenRead && sample.memberMask == 0x80000000U && sample.playerMask == 0x80000000U);
    CHECK(sample.members[31].playerSlot == 31 && sample.members[31].playerId == 0xFFFF0002);
    CHECK(sample.members[0].machineId == 0);
}

void mailbox_tests() {
    Fixture fixture;
    observation::Sample sample{};
    CHECK(observation::capture(&Fixture::read, &fixture, sample));
    observation::Mailbox box;
    observation::Observation first{}, current{};
    CHECK(!box.snapshot(1, 100, current) && current.manager == 0);
    CHECK(!box.publish(0, &sample, 100));
    CHECK(box.publish(0x10000, &sample, 100));
    CHECK(box.snapshot(1, 100, first) && first.manager == 0x10000 && first.incarnation != 0 && first.generation != 0);
    CHECK(box.publish(0x10000, &sample, 110));
    CHECK(box.snapshot(1, 110, current) && current.generation == first.generation && current.incarnation == first.incarnation);
    ++sample.revision;
    CHECK(box.publish(0x10000, &sample, 120));
    CHECK(box.snapshot(1, 120, current) && current.generation > first.generation && current.incarnation == first.incarnation);
    CHECK(!box.snapshot(1, 119, current));
    CHECK(!box.snapshot(1, 1121, current) && current.manager == 0);
    CHECK(box.publish(0x10000, &sample, 1122));
    CHECK(box.snapshot(1, 1122, current) && current.incarnation > first.incarnation);
    const auto incarnation = current.incarnation;
    sample.role = 2;
    CHECK(box.publish(0x10000, &sample, 1123));
    CHECK(!box.snapshot(1, 1123, current));
    CHECK(box.snapshot(2, 1123, current) && current.incarnation > incarnation);
    CHECK(!box.publish(0x10000, nullptr, 1124));
    CHECK(!box.snapshot(2, 1124, current));
    CHECK(box.publish(0x10000, &sample, 1125));
    CHECK(box.snapshot(2, 1125, first));
    box.reset();
    CHECK(!box.snapshot(2, 1125, current));
    CHECK(box.publish(0x10000, &sample, 1126));
    CHECK(box.snapshot(2, 1126, current) && current.incarnation > first.incarnation);
    CHECK(box.publish(0x20000, &sample, 1126));
    CHECK(!box.snapshot(2, 1126, current) && current.manager == 0);
    CHECK(!box.publish(0x20000, nullptr, 1127));
    CHECK(box.snapshot(2, 1127, current) && current.manager == 0x10000);
    CHECK(!box.snapshot(-1, 1127, current));
    CHECK(!box.snapshot(7, 1127, current));

    observation::Mailbox full;
    for (std::size_t index = 0; index < observation::kManagerCapacity; ++index)
        CHECK(full.publish(0x10000 + index, &sample, 100));
    CHECK(!full.publish(0x30000, &sample, 100));
    CHECK(full.publish(0x10000, &sample, 101));
    CHECK(!full.publish(0x10000, nullptr, 102));
    CHECK(full.publish(0x30000, &sample, 103));
    CHECK(full.publish(0x40000, &sample, 1104));
    CHECK(full.snapshot(2, 1104, first) && first.manager == 0x40000);

    observation::Collector collector;
    CHECK(collector.capture_token() == 0 && !collector.snapshot(2, 100, current));
    collector.start();
    const auto oldToken = collector.capture_token();
    CHECK(oldToken != 0 && collector.publish(oldToken, 0x10000, &sample, 100));
    CHECK(collector.snapshot(2, 100, first));
    collector.stop();
    CHECK(collector.capture_token() == 0 && !collector.snapshot(2, 100, current));
    CHECK(!collector.publish(oldToken, 0x10000, &sample, 100));
    collector.start();
    const auto newToken = collector.capture_token();
    CHECK(newToken > oldToken);
    CHECK(!collector.publish(oldToken, 0x10000, &sample, 101));
    CHECK(!collector.snapshot(2, 101, current));
    CHECK(collector.publish(newToken, 0x10000, &sample, 101));
    CHECK(collector.snapshot(2, 101, current) && current.incarnation > first.incarnation);
    collector.start();
    CHECK(!collector.publish(newToken, 0x10000, &sample, 102));
    CHECK(!collector.snapshot(2, 102, current));
}
} // namespace

int main(int argc, char** argv) {
    namespace adapter = dawn::client::hooks::bootflow::native_identity_observation;
    if (argc == 2 && std::strcmp(argv[1], "--layout-refused") == 0) {
        CHECK(SetEnvironmentVariableW(L"DAWN_NATIVE_IDENTITY_OBSERVATION", L"1") != FALSE);
        // This test executable is not build 86657. Opt-in must not bypass layout checks.
        CHECK(!adapter::enabled());
        adapter::start();
        adapter::observe(reinterpret_cast<std::byte*>(1));
        observation::Observation empty{};
        CHECK(!adapter::snapshot(1, GetTickCount64(), empty) && empty.manager == 0);
        std::printf("PASS: %u unsupported-layout identity observation checks\n", checks);
        return 0;
    }
    if (argc != 1) return 2;
    parser_tests();
    mailbox_tests();
    CHECK(SetEnvironmentVariableW(L"DAWN_NATIVE_IDENTITY_OBSERVATION", nullptr) != FALSE);
    CHECK(!adapter::enabled());
    adapter::start();
    // Disabled observation must not dereference a manager at all.
    adapter::observe(reinterpret_cast<std::byte*>(1));
    observation::Observation empty{};
    CHECK(!adapter::snapshot(1, GetTickCount64(), empty) && empty.manager == 0);
    adapter::reset();
    std::printf("PASS: %u native identity observation checks; no gameplay admission\n", checks);
    return 0;
}
