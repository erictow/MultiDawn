#include "../src/core/multiplayer/identity_activity_correlation.h"

#include <array>
#include <cstdio>
#include <cstdlib>

namespace identity = dawn::core::multiplayer::identity_observation;
namespace correlation = dawn::core::multiplayer::identity_activity;
namespace {
unsigned checks{};
void check(bool value, int line) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL identity/activity correlation line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)
constexpr std::uint64_t creator = 0x1101;
constexpr std::uint64_t group = 0x2202;
constexpr std::uint64_t player = 0x3303;

identity::Observation fixture() {
    identity::Observation result{};
    result.manager = 0x10000;
    result.incarnation = 17;
    result.generation = 19;
    result.sampledAt = 100;
    auto& sample = result.sample;
    sample.role = 2;
    sample.mode = 4; // Observed client-group mode; no mode-6 or role-1 shortcut.
    sample.hostMemberIndex = 0;
    sample.memberMask = 3;
    sample.playerMask = 1;
    sample.members[0].machineId = group;
    sample.members[0].state = 10;
    sample.members[1].machineId = creator;
    sample.members[1].state = 10;
    sample.members[1].ownsPlayer = true;
    sample.members[1].playerId = player;
    sample.members[1].playerSequence = 32;
    return result;
}

correlation::Result match(const identity::Observation& observed, correlation::Correlation& output,
    std::uint64_t now = 100) {
    return correlation::correlate(creator, group, {&observed, 1}, now, output);
}

void rejected(identity::Observation observed, correlation::Result expected = correlation::Result::invalidInput) {
    correlation::Correlation output{};
    output.manager = 123;
    CHECK(match(observed, output) == expected);
    CHECK(output.manager == 0 && output.playerId == 0 && output.role == -1);
}

void tests() {
    auto observed = fixture();
    correlation::Correlation output{};
    CHECK(match(observed, output) == correlation::Result::matched);
    CHECK(output.manager == observed.manager && output.incarnation == 17 && output.generation == 19 && output.sampledAt == 100);
    CHECK(output.creatorMachineId == creator && output.groupMachineId == group && output.playerId == player);
    CHECK(output.hostMemberIndex == 0 && output.humanMemberIndex == 1 && output.playerSlot == 0 && output.playerSequence == 32);
    CHECK(output.role == 2 && output.mode == 4);
    auto refreshed = output;
    CHECK(refreshed == output && correlation::same_correspondence(refreshed, output));
    ++refreshed.sampledAt;
    CHECK(refreshed != output && correlation::same_correspondence(refreshed, output));
    ++refreshed.generation;
    CHECK(!correlation::same_correspondence(refreshed, output));
    refreshed = output; ++refreshed.incarnation;
    CHECK(!correlation::same_correspondence(refreshed, output));
    refreshed = output; ++refreshed.playerId;
    CHECK(!correlation::same_correspondence(refreshed, output));
    for (std::int32_t role = 0; role < 7; ++role) {
        observed.sample.role = role;
        CHECK(match(observed, output) == correlation::Result::matched && output.role == role);
    }
    observed = fixture();
    CHECK(match(observed, output, 1100) == correlation::Result::matched);
    CHECK(match(observed, output, 1101) == correlation::Result::noMatch && output.manager == 0);
    CHECK(match(observed, output, 99) == correlation::Result::invalidInput && output.playerId == 0);

    auto other = observed;
    other.manager = 0x20000;
    std::array<identity::Observation, 2> two{observed, other};
    CHECK(correlation::correlate(creator, group, two, 100, output) == correlation::Result::ambiguous);
    CHECK(output.manager == 0 && output.playerId == 0);
    two[1] = two[0];
    CHECK(correlation::correlate(creator, group, two, 100, output) == correlation::Result::ambiguous);
    two[1].sampledAt = 1200;
    CHECK(correlation::correlate(creator, group, two, 100, output) == correlation::Result::invalidInput);
    two[1] = two[0]; two[0].sampledAt = 0; two[1].sampledAt = 1100;
    CHECK(correlation::correlate(creator, group, two, 1101, output) == correlation::Result::matched);

    observed = fixture();
    observed.sample.memberMask = 7;
    observed.sample.playerMask = 3;
    observed.sample.members[2].machineId = 0x4404;
    observed.sample.members[2].ownsPlayer = true;
    observed.sample.members[2].playerSlot = 1;
    observed.sample.members[2].playerId = 0x5505;
    CHECK(match(observed, output) == correlation::Result::matched && output.playerId == player);
    observed.sample.members[2].playerId = player;
    rejected(observed);
    observed.sample.members[2].playerId = 0x5505;
    observed.sample.members[2].machineId = creator;
    rejected(observed);
    observed = fixture();
    observed.sample.memberMask = 7;
    observed.sample.members[2].machineId = 0x4404;
    rejected(observed); // Extra non-player member has no supported control/human role.

    for (unsigned humans = 3; humans <= 7; ++humans) {
        observed = fixture();
        observed.sample.memberMask = (1U << (humans + 1U)) - 1U;
        observed.sample.playerMask = (1U << humans) - 1U;
        for (unsigned index = 2; index <= humans; ++index) {
            auto& member = observed.sample.members[index];
            member.machineId = creator + index;
            member.playerId = player + index;
            member.ownsPlayer = true;
            member.playerSlot = index - 1U;
            member.state = 10;
        }
        CHECK(match(observed, output) == (humans <= 6 ? correlation::Result::matched : correlation::Result::invalidInput));
        CHECK(humans > 6 || output.playerId == player);
    }

    observed = fixture();
    const auto control = observed.sample.members[0];
    const auto human = observed.sample.members[1];
    observed.sample.members = {};
    observed.sample.memberMask = (1U << 31U) | (1U << 7U);
    observed.sample.playerMask = 1U << 31U;
    observed.sample.hostMemberIndex = 31;
    observed.sample.members[31] = control;
    observed.sample.members[7] = human;
    observed.sample.members[7].playerSlot = 31;
    CHECK(match(observed, output) == correlation::Result::matched);
    CHECK(output.hostMemberIndex == 31 && output.humanMemberIndex == 7 && output.playerSlot == 31);
    observed.sample.hostMemberIndex = 7;
    rejected(observed, correlation::Result::noMatch); // Exact control-host row must be the native host.

    // Local-only sessions can repeat the same genuine IDs in several raw roles. Neither
    // contains the advertised control group, so neither provides an activity correspondence.
    observed = fixture();
    observed.sample.members[0] = human;
    observed.sample.members[1] = {};
    observed.sample.memberMask = observed.sample.playerMask = 1;
    observed.sample.role = 0;
    other = observed; other.sample.role = 1; other.manager = 0x20000;
    two = {observed, other};
    CHECK(correlation::correlate(creator, group, two, 100, output) == correlation::Result::noMatch);
    CHECK(output.manager == 0 && output.playerId == 0);

    observed = fixture(); observed.manager = 0; rejected(observed);
    observed = fixture(); observed.incarnation = 0; rejected(observed);
    observed = fixture(); observed.generation = 0; rejected(observed);
    observed = fixture(); observed.sample.role = -1; rejected(observed);
    observed = fixture(); observed.sample.role = 7; rejected(observed);
    observed = fixture(); observed.sample.mode = -1; rejected(observed);
    observed = fixture(); observed.sample.memberMask = 0; rejected(observed);
    observed = fixture(); observed.sample.hostMemberIndex = -1; rejected(observed);
    observed = fixture(); observed.sample.hostMemberIndex = 32; rejected(observed);
    observed = fixture(); observed.sample.hostMemberIndex = 3; rejected(observed);
    observed = fixture(); observed.sample.members[0].machineId = 0; rejected(observed);
    observed = fixture(); observed.sample.members[1].machineId = group; rejected(observed);
    observed = fixture(); observed.sample.members[3].machineId = 0x9999; rejected(observed);
    observed = fixture(); observed.sample.members[0].playerId = 0x9999; rejected(observed);
    observed = fixture(); observed.sample.members[0].playerSequence = 1; rejected(observed);
    observed = fixture(); observed.sample.members[0].playerSlot = 1; rejected(observed);
    observed = fixture(); observed.sample.members[0].ownsPlayer = true; rejected(observed);
    observed = fixture(); observed.sample.members[1].playerId = 0; rejected(observed);
    observed = fixture(); observed.sample.members[1].playerSlot = 32; rejected(observed);
    observed = fixture(); observed.sample.playerMask = 2; rejected(observed);
    observed = fixture(); observed.sample.members[1].ownsPlayer = false; rejected(observed);

    observed = fixture();
    CHECK(correlation::correlate(0, group, {&observed, 1}, 100, output) == correlation::Result::invalidInput);
    CHECK(correlation::correlate(creator, 0, {&observed, 1}, 100, output) == correlation::Result::invalidInput);
    CHECK(correlation::correlate(creator, creator, {&observed, 1}, 100, output) == correlation::Result::invalidInput);
    CHECK(correlation::correlate(creator, group, {}, 100, output) == correlation::Result::noMatch);
    std::array<identity::Observation, 17> tooMany{};
    CHECK(correlation::correlate(creator, group, tooMany, 100, output) == correlation::Result::invalidInput);
}
} // namespace

int main() {
    tests();
    std::printf("PASS: %u identity/activity scalar correlation checks; no gameplay admission\n", checks);
    return 0;
}
