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

identity::Observation local_only(std::int32_t role, std::uintptr_t manager, std::uint64_t sampledAt) {
    auto observed = fixture();
    observed.manager = manager;
    observed.sampledAt = sampledAt;
    observed.sample.role = role;
    observed.sample.mode = 6;
    observed.sample.memberMask = observed.sample.playerMask = 1;
    observed.sample.members[0] = observed.sample.members[1];
    observed.sample.members[1] = {};
    return observed;
}

void world_human_tests() {
    constexpr auto matched = correlation::Result::matched;
    constexpr auto noMatch = correlation::Result::noMatch;
    constexpr auto invalid = correlation::Result::invalidInput;
    constexpr auto ambiguous = correlation::Result::ambiguous;
    const std::array local{local_only(0, 0x10000, 100), local_only(1, 0x20000, 120)};
    correlation::WorldHuman output{};
    CHECK(correlation::corroborate_world_human(creator, local, 130, output) == matched);
    CHECK(output.creatorMachineId == creator && output.playerId == player && output.sampledAt == 100);
    CHECK(output.witnesses[0].mode == 6 && output.witnesses[1].mode == 6 && output.witnesses[2].manager == 0);
    CHECK(output.witnesses[0].manager == local[0].manager && output.witnesses[1].manager == local[1].manager);
    CHECK(output.witnesses[0].incarnation == 17 && output.witnesses[1].generation == 19
        && output.witnesses[1].sampledAt == 120);
    CHECK(output.witnesses[0].memberIndex == 0 && output.witnesses[0].member == local[0].sample.members[0]);
    const auto baseline = output;

    const auto expect = [&](std::span<const identity::Observation> observations, correlation::Result result,
                            std::uint64_t now = 130) {
        output = baseline;
        CHECK(correlation::corroborate_world_human(creator, observations, now, output) == result);
        if (result != matched) CHECK(output == correlation::WorldHuman{});
    };
    std::array reversed{local[1], local[0]};
    ++reversed[0].sampledAt;
    ++reversed[1].sampledAt;
    expect(reversed, matched);
    CHECK(output != baseline && correlation::same_world_human(output, baseline));
    ++reversed[0].generation;
    expect(reversed, matched);
    CHECK(!correlation::same_world_human(output, baseline));
    --reversed[0].generation;
    ++reversed[0].incarnation;
    expect(reversed, matched);
    CHECK(!correlation::same_world_human(output, baseline));
    reversed[0] = local[1];
    ++reversed[0].sample.members[0].joinId;
    expect(reversed, matched);
    CHECK(!correlation::same_world_human(output, baseline));
    reversed[0] = local[1];
    reversed[0].sample.role = 6;
    expect(reversed, matched);
    CHECK(output.witnesses[1].manager == 0 && output.witnesses[6].manager == local[1].manager
        && !correlation::same_world_human(output, baseline));

    expect({}, noMatch);
    expect(std::span(local).first(1), noMatch);
    expect(local, matched, 1100);
    expect(local, noMatch, 1101);
    expect(local, invalid, 119);
    auto changed = local;
    changed[1].sample.members[0].playerId += 1;
    expect(changed, ambiguous);
    changed = local; changed[1].sample.role = 0;
    expect(changed, ambiguous);
    changed = local; changed[1].manager = changed[0].manager;
    expect(changed, ambiguous);
    changed = local; changed[1] = changed[0];
    expect(changed, ambiguous);

    changed = local; changed[1].sample.members[0].machineId = group;
    expect(changed, noMatch);
    changed[1].sample.members[31].machineId = creator;
    expect(changed, invalid);
    changed = local; changed[1].sample.members[0] = {creator}; changed[1].sample.playerMask = 0;
    expect(changed, invalid);
    changed = local; changed[1].incarnation = 0;
    expect(changed, invalid);
    changed = local; changed[1].generation = 0;
    expect(changed, invalid);
    changed = local; changed[1].sample.role = 7;
    expect(changed, invalid);
    std::array<identity::Observation, identity::kManagerCapacity + 1> tooMany{};
    expect(tooMany, invalid);
    CHECK(correlation::corroborate_world_human(0, local, 130, output) == invalid);
}
} // namespace

int main() {
    tests();
    world_human_tests();
    std::printf("PASS: %u identity/activity scalar correlation checks; no gameplay admission\n", checks);
    return 0;
}
