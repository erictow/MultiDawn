#include "../src/core/multiplayer/activity_binding.h"
#include "../src/core/multiplayer/companion.h"
#include "../src/client/hooks/bootflow/native_identity_observation.h"
#include "../src/core/logging/log.h"
#include "../src/server/gameplay/gameplay_advertisement.h"

#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstdlib>

namespace mp = dawn::core::multiplayer;
namespace binding = mp::activity_binding;
namespace bap = dawn::server::bap;
namespace gameplay = dawn::server::gameplay;
namespace observation = mp::identity_observation;
namespace world_view = dawn::client::hooks::bootflow::native_replication_observer;

namespace {
unsigned checks{};
void check(bool value, int line) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL activity binding line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)

struct Fixture {
    bap::CreatorActivitySnapshot creator{};
    gameplay::AdvertisedActivityObservation advertisement{};
    gameplay::group::HostActivityLineageLease lineage{};
    gameplay::resolution::AuthenticatedRoute route{};
    world_view::WorldConnection world{};
    std::array<observation::Observation, 2> observations{};
    std::size_t count{1};
    bool enabled{true}, creatorAvailable{true}, advertisementAvailable{true}, routeAvailable{true};
    bool creatorChanges{}, nativeChanges{}, routeChanges{}, lineageChanges{}, collectFails{};
    bool worldChanges{}, invalidateInviteDuringCapture{};
    bool sawWorldInvite{};
    unsigned creatorCalls{}, collectCalls{}, lineageChecks{}, worldReads{}, inviteChecks{}, pins{}, releases{}, logs{};

    Fixture() {
        using namespace dawn::state::activity;
        creator.binding = {{{17, {3}}, {4}}, {5}};
        const ActivityInstanceKey source{0xA1, {6}}, host{0xB1, {7}};
        creator.lineage = {source, source, bap::RegionLineageKind::ownedActivity};
        creator.hostRegion = {source, {8}};
        creator.reportedRegion = 4;
        creator.memberKey = 0x1001;
        creator.hasIdentity = creator.identityMatchesMemberKey = true;
        creator.joinIdentity = creator.memberKey; // A BAP seed is deliberately not the player ID.
        advertisement.groupMachineId = 0x2001;
        advertisement.host = host; advertisement.source = source;
        advertisement.regionIndex = 4; advertisement.readiness = gameplay::AdvertisementReadiness::ready;
        lineage = {0x2001, host, source, 4, 9, 2, true};
        route = {{creator.binding.authentication, 10}, {0x7F000001, 45000}};
        world.creatorMachineId = creator.memberKey;
        world.controlMachineId = advertisement.groupMachineId;
        world.controlEpoch = 31;
        world.generation = 17;
        auto& row = observations[0];
        row.manager = 0x10000; row.incarnation = 1; row.generation = 2; row.sampledAt = 100;
        row.sample.role = 4; row.sample.mode = 4; row.sample.hostMemberIndex = 0;
        row.sample.memberMask = 3; row.sample.playerMask = 1;
        row.sample.members[0].machineId = advertisement.groupMachineId;
        row.sample.members[0].state = 10;
        auto& human = row.sample.members[1];
        human.machineId = creator.memberKey; human.playerId = 0x3001;
        human.ownsPlayer = true; human.state = 10;
    }
} fixture;

void reset() { fixture = Fixture{}; }
void rejected(binding::Result expected) {
    binding::Observation output{};
    output.groupMachineId = 123;
    CHECK(binding::inspect(100, output) == expected);
    CHECK(output.groupMachineId == 0 && output.native.manager == 0 && !static_cast<bool>(output.creator.binding));
    CHECK(fixture.pins == fixture.releases);
}

void boundary_tests() {
    reset(); fixture.enabled = false; rejected(binding::Result::disabled);
    CHECK(fixture.creatorCalls == 0);
    reset(); fixture.creatorAvailable = false; rejected(binding::Result::noCreator);
    reset(); fixture.creator.memberKey = 0; rejected(binding::Result::noCreator);
    reset(); fixture.creator.lineage.kind = bap::RegionLineageKind::groupDerivedBorrow;
    rejected(binding::Result::noCreator);
    reset(); fixture.advertisementAvailable = false; rejected(binding::Result::noAdvertisement);
    reset(); fixture.advertisement.readiness = gameplay::AdvertisementReadiness::pending;
    rejected(binding::Result::noAdvertisement);
    reset(); ++fixture.advertisement.source.incarnation.value; rejected(binding::Result::noAdvertisement);
    reset(); ++fixture.lineage.regionIndex; rejected(binding::Result::noAdvertisement);
    reset(); fixture.lineage.rowGeneration = 0; rejected(binding::Result::noAdvertisement);
    reset(); ++fixture.advertisement.groupMachineId; rejected(binding::Result::noAdvertisement);
    reset(); fixture.collectFails = true; rejected(binding::Result::changed);
    reset(); fixture.count = 0; rejected(binding::Result::noManagedGroup);
    reset(); fixture.observations[0].sample.members[0].machineId = 0x9999;
    rejected(binding::Result::noManagedGroup);
    reset(); fixture.count = 2; fixture.observations[1] = fixture.observations[0];
    fixture.observations[1].manager += 0x10000; rejected(binding::Result::ambiguousManagedGroup);
    reset(); fixture.observations[0].sample.members[1].playerId = 0;
    rejected(binding::Result::malformedManagedGroup);
    reset(); fixture.routeAvailable = false; rejected(binding::Result::noAuthenticatedRoute);
    reset(); ++fixture.route.handle.owner.generation.value; rejected(binding::Result::noAuthenticatedRoute);
    reset(); fixture.route.source.port = 0; rejected(binding::Result::noAuthenticatedRoute);
    reset(); fixture.creatorChanges = true; rejected(binding::Result::changed);
    reset(); fixture.nativeChanges = true; rejected(binding::Result::changed);
    reset(); fixture.routeChanges = true; rejected(binding::Result::changed);
    reset(); fixture.lineageChanges = true; rejected(binding::Result::changed);
}

void lifetime_tests() {
    reset();
    binding::Observation output{};
    CHECK(binding::inspect(100, output) == binding::Result::observed);
    CHECK(output.creator == fixture.creator && output.host == fixture.advertisement.host);
    CHECK(output.native.playerId == 0x3001 && output.native.playerId != fixture.creator.joinIdentity);
    CHECK(output.native.hostMemberIndex == 0 && output.native.humanMemberIndex == 1);
    CHECK(output.route.handle == fixture.route.handle && output.lineageGeneration == 9);
    CHECK(fixture.pins == 1 && fixture.releases == 1);
    CHECK(binding::validate(output, 100));
    fixture.observations[0].sampledAt = 150;
    CHECK(binding::validate(output, 150)); // Refreshing time alone cannot change correspondence.
    CHECK(!binding::validate(output, 99));
    CHECK(!binding::validate(output, 1101));
    ++fixture.route.handle.generation;
    CHECK(!binding::validate(output, 150));
    --fixture.route.handle.generation;
    ++fixture.lineage.rowGeneration;
    CHECK(!binding::validate(output, 150));
    --fixture.lineage.rowGeneration;
    ++fixture.observations[0].incarnation;
    CHECK(!binding::validate(output, 150));
    --fixture.observations[0].incarnation;
    ++fixture.creator.hostRegion.generation.value;
    CHECK(!binding::validate(output, 150));
    CHECK(fixture.pins == fixture.releases);
    CHECK(!binding::validate({}, 150));
}

void world_fixture(std::uint64_t now) {
    reset();
    fixture.count = 2;
    auto& local = fixture.observations[0];
    local.sampledAt = now;
    local.sample.role = 0;
    local.sample.mode = 6;
    local.sample.memberMask = 1;
    local.sample.members[0] = local.sample.members[1];
    local.sample.members[1] = {};
    fixture.observations[1] = local;
    auto& second = fixture.observations[1];
    second.sample.role = 1;
    second.manager += 0x10000;
    second.incarnation += 3;
    second.generation += 3;
}

void world_rejected(binding::Result expected, std::uint64_t now) {
    binding::WorldObservation output{};
    output.world.generation = 500;
    CHECK(binding::inspect_world(now, output) == expected);
    CHECK(!static_cast<bool>(output.creator.binding) && output.world.generation == 0 && output.human.playerId == 0);
    CHECK(fixture.pins == fixture.releases);
}

void world_binding_tests() {
    constexpr std::uint64_t now = 100;
    world_fixture(now);
    binding::Observation managed{};
    CHECK(binding::inspect(now, managed) == binding::Result::noManagedGroup);
    binding::WorldObservation output{};
    CHECK(binding::inspect_world(now, output) == binding::Result::observed);
    CHECK(output.creator == fixture.creator && output.host == fixture.advertisement.host);
    CHECK(output.world == fixture.world && output.human.playerId == 0x3001);
    CHECK(output.lineageGeneration == fixture.lineage.rowGeneration && output.route.handle == fixture.route.handle);
    CHECK(fixture.pins == fixture.releases && binding::validate_world(output, now));
    for (auto& row : fixture.observations) row.sampledAt = now + 25;
    CHECK(binding::validate_world(output, now + 25));
    ++fixture.world.generation;
    CHECK(!binding::validate_world(output, now + 25));
    CHECK(!binding::validate_world(output, now + observation::kMaximumAgeMs + 1));

    world_fixture(now); fixture.world.controlMachineId++;
    world_rejected(binding::Result::noWorldConnection, now);
    world_fixture(now); fixture.count = 1;
    world_rejected(binding::Result::noWorldHuman, now);
    world_fixture(now); fixture.observations[1].sample.members[0].playerId++;
    world_rejected(binding::Result::ambiguousWorldHuman, now);
    world_fixture(now); fixture.observations[0].sample.members[0].playerId = 0;
    world_rejected(binding::Result::malformedWorldHuman, now);
    world_fixture(now); fixture.routeAvailable = false;
    world_rejected(binding::Result::noAuthenticatedRoute, now);
    world_fixture(now); fixture.worldChanges = true;
    world_rejected(binding::Result::changed, now);
    world_fixture(now); fixture.nativeChanges = true;
    world_rejected(binding::Result::changed, now);
    world_fixture(now); fixture.creatorChanges = true;
    world_rejected(binding::Result::changed, now);
    world_fixture(now); fixture.routeChanges = true;
    world_rejected(binding::Result::changed, now);
    world_fixture(now); fixture.lineageChanges = true;
    world_rejected(binding::Result::changed, now);

    CHECK(!binding::validate_world({}, now));
    world_fixture(GetTickCount64());
    mp::InvitationPreflightObservation invitation{};
    invitation.requestGeneration = 10;
    binding::trace_invitation_world(invitation);
    CHECK(fixture.logs == 1 && fixture.inviteChecks == 2 && fixture.sawWorldInvite);
    world_fixture(GetTickCount64());
    fixture.invalidateInviteDuringCapture = true;
    binding::trace_invitation_world(invitation);
    CHECK(fixture.logs == 0 && fixture.inviteChecks == 2);
}
} // namespace

namespace dawn::server::bap {
bool snapshot_current_creator_activity(CreatorActivitySnapshot& output) noexcept {
    ++fixture.creatorCalls; output = {};
    if (!fixture.creatorAvailable) return false;
    output = fixture.creator; return true;
}
bool snapshot_creator_activity(state::activity::BindingKey requested, CreatorActivitySnapshot& output) noexcept {
    output = {};
    if (!fixture.creatorAvailable || requested != fixture.creator.binding) return false;
    output = fixture.creator;
    if (fixture.creatorChanges) ++output.destination.activityIndex;
    return true;
}
}
namespace dawn::server::gameplay {
bool acquire_advertisement_observation(state::activity::ActivityInstanceKey, std::int32_t,
    AdvertisedActivityObservation& output, group::HostActivityLineageLease& lease) noexcept {
    output = fixture.advertisement; lease = fixture.lineage;
    if (lease.pinned) ++fixture.pins;
    return fixture.advertisementAvailable;
}
}
namespace dawn::server::gameplay::group {
bool validate_host_activity_lineage(const HostActivityLineageLease& lease) noexcept {
    ++fixture.lineageChecks;
    return lease.pinned && !(fixture.lineageChanges && fixture.lineageChecks >= 2);
}
void release_host_activity_lineage(HostActivityLineageLease& lease) noexcept {
    if (lease.pinned) ++fixture.releases;
    lease = {};
}
}
namespace dawn::server::gameplay::resolution {
bool lookup_authenticated_route(state::activity::AuthenticationKey, AuthenticatedRoute& output) noexcept {
    output = {};
    if (!fixture.routeAvailable) return false;
    output = fixture.route; return true;
}
bool validate_authenticated_route(const AuthenticatedRoute&) noexcept { return !fixture.routeChanges; }
}
namespace dawn::client::hooks::bootflow::native_identity_observation {
bool enabled() noexcept { return fixture.enabled; }
bool collect(std::span<observation::Observation> output, std::uint64_t, std::size_t& count) noexcept {
    ++fixture.collectCalls;
    for (auto& row : output) row = {};
    count = 0;
    if (fixture.collectFails || fixture.count > output.size()) return false;
    for (std::size_t index = 0; index < fixture.count; ++index) output[index] = fixture.observations[index];
    count = fixture.count;
    if (fixture.nativeChanges && fixture.collectCalls >= 2) ++output[0].generation;
    return true;
}
}
namespace dawn::client::hooks::bootflow::native_replication_observer {
bool snapshot_world_connection(std::uint64_t creator, std::uint64_t control, WorldConnection& output) noexcept {
    output = {};
    if (creator != fixture.world.creatorMachineId || control != fixture.world.controlMachineId) return false;
    output = fixture.world;
    ++fixture.worldReads;
    if (fixture.worldChanges && fixture.worldReads >= 2) ++output.generation;
    return true;
}
}
namespace dawn::core::multiplayer {
bool validate_traced_invitation_preflight(const InvitationPreflightObservation& observed) noexcept {
    ++fixture.inviteChecks;
    return observed.requestGeneration == 10 && !(fixture.invalidateInviteDuringCapture && fixture.inviteChecks == 2);
}
}
namespace dawn::core::log {
void write(Channel, Level, std::string_view line) noexcept {
    ++fixture.logs;
    if (line == "ev=world_activity_binding stage=accepted_invite result=observed admission=0")
        fixture.sawWorldInvite = true;
}
}

int main() {
    boundary_tests(); lifetime_tests(); world_binding_tests();
    CHECK(SetEnvironmentVariableW(L"DAWN_ACTIVITY_BINDING_TRACE", nullptr) != FALSE);
    reset(); binding::service(100); binding::reset();
    CHECK(fixture.creatorCalls == 0 && fixture.logs == 0);
    std::printf("PASS: %u activity binding boundary checks; no gameplay admission\n", checks);
}
