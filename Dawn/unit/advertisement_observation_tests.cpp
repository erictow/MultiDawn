#include "../src/server/gameplay/gameplay_advertisement.h"
#include "../src/server/gameplay/endpoint/gameplay_endpoint.h"
#include "../src/server/gameplay/group/group_host.h"
#include "../src/server/gameplay/gameplay_log.h"
#include "../src/client/hooks/retail_log/retail_log_enqueue_observer.h"
#include "../src/state/activity/runtime.h"
#include "../src/state/gameplay/replication_roles.h"

#include <array>
#include <cstdio>
#include <cstdlib>

namespace activity = dawn::state::activity;
namespace gameplay = dawn::server::gameplay;
namespace descriptor = dawn::middleware::gameplay::descriptor;

namespace {
unsigned checks{};
void check(bool condition, int line) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "FAIL advertisement observation line %d\n", line); std::exit(1); }
}
#define CHECK(condition) check((condition), __LINE__)

constexpr std::uint64_t regionStride = 0x9E3779B97F4A7C15ULL;
struct Fixture {
    activity::ActivityInstanceKey source{0xA100, {3}}, host{0xB200, {4}};
    gameplay::endpoint::Identity identity{0x10000, 0x20000};
    dawn::state::gameplay::Endpoint endpoint{0xC0A8017C, 30976};
    std::int32_t region{4};
    bool ready{true}, sourceValid{true}, hostValid{true}, hostHeld{true}, pinAvailable{true};
    bool wrongGroup{}, wrongSource{}, wrongHost{}, wrongRegion{}, failureAfterPin{};
    unsigned allocations{}, acquisitions{}, releases{}, rolePublications{}, descriptorPublications{};
    std::uint64_t publishedMachine{};
    std::array<std::byte, descriptor::kDescriptorSize> publishedDescriptor{};

    [[nodiscard]] std::uint64_t group() const noexcept {
        const auto value = identity.machineId ^ (regionStride * (static_cast<std::uint32_t>(region) + 1ULL));
        return value == 0 ? regionStride : value;
    }
} fixture;

void reset() { fixture = Fixture{}; }

void assert_empty(const gameplay::AdvertisedActivityObservation& output) {
    CHECK(output.groupMachineId == 0 && !static_cast<bool>(output.host)
          && !static_cast<bool>(output.source) && output.regionIndex == -1);
}

void observation_does_not_publish() {
    reset();
    gameplay::AdvertisedActivityObservation output{};
    gameplay::group::HostActivityLineageLease lease{};
    for (unsigned iteration = 0; iteration < 8; ++iteration) {
        CHECK(gameplay::acquire_advertisement_observation(fixture.source, fixture.region, output, lease));
        CHECK(output.readiness == gameplay::AdvertisementReadiness::ready);
        CHECK(output.groupMachineId == fixture.group() && output.host == fixture.host
              && output.source == fixture.source && output.regionIndex == fixture.region);
        CHECK(lease.pinned && lease.groupSessionId == output.groupMachineId
              && lease.host == output.host && lease.source == output.source);
        CHECK(fixture.rolePublications == 0 && fixture.descriptorPublications == 0
              && fixture.allocations == 0);
    }
    CHECK(fixture.acquisitions == 8 && fixture.releases == 7);
    gameplay::group::release_host_activity_lineage(lease);
    CHECK(fixture.releases == 8 && !lease.pinned);
}

void publishing_path_is_preserved() {
    reset();
    gameplay::AdvertisementSnapshot output{};
    gameplay::group::HostActivityLineageLease lease{};
    CHECK(gameplay::acquire_advertisement_snapshot(fixture.source, fixture.region, output, lease));
    CHECK(output.readiness == gameplay::AdvertisementReadiness::ready && output.citizen.present);
    CHECK(output.citizen.memberKey == fixture.group() && output.host == fixture.host
          && output.source == fixture.source && output.citizen.onlineSessionId == fixture.host.sessionId);
    CHECK(fixture.rolePublications == 1 && fixture.descriptorPublications == 1
          && fixture.allocations == 0 && fixture.publishedMachine == fixture.group());
    CHECK(fixture.publishedDescriptor == output.citizen.descriptor);
    gameplay::group::release_host_activity_lineage(lease);
    CHECK(fixture.acquisitions == fixture.releases);

    reset();
    dawn::middleware::bap::activity_message::replicate_membership::CitizenAdvertisement citizen{};
    gameplay::build_advertisement(fixture.source, fixture.region, gameplay::RegionSource::reported, 0, citizen);
    CHECK(citizen.present && fixture.allocations == 1);
    CHECK(fixture.rolePublications == 1 && fixture.descriptorPublications == 1);
}

void refusal(bool expectedResult, gameplay::AdvertisementReadiness expectedReadiness) {
    gameplay::AdvertisedActivityObservation output{123, fixture.host, fixture.source, 123,
        gameplay::AdvertisementReadiness::ready};
    gameplay::group::HostActivityLineageLease lease{};
    CHECK(gameplay::acquire_advertisement_observation(fixture.source, fixture.region, output, lease) == expectedResult);
    CHECK(output.readiness == expectedReadiness);
    assert_empty(output);
    CHECK(!lease.pinned && fixture.acquisitions == fixture.releases);
    CHECK(fixture.rolePublications == 0 && fixture.descriptorPublications == 0 && fixture.allocations == 0);
}

void invalid_lifetimes_and_configuration() {
    reset(); fixture.ready = false; refusal(true, gameplay::AdvertisementReadiness::absent);
    reset(); fixture.region = -1; refusal(true, gameplay::AdvertisementReadiness::absent);
    reset(); fixture.sourceValid = false; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.source = {}; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.hostHeld = false; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.hostValid = false; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.pinAvailable = false; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.wrongGroup = true; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.wrongSource = true; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.wrongHost = true; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.wrongRegion = true; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.failureAfterPin = true; refusal(false, gameplay::AdvertisementReadiness::stale);
    reset(); fixture.endpoint.address = 0; refusal(false, gameplay::AdvertisementReadiness::absent);
    reset(); fixture.endpoint.port = 0; refusal(false, gameplay::AdvertisementReadiness::absent);
    reset(); ++fixture.endpoint.port; refusal(false, gameplay::AdvertisementReadiness::absent);

    // Even a non-ready early return must retire a pin supplied from an earlier call.
    reset();
    gameplay::AdvertisedActivityObservation output{};
    gameplay::group::HostActivityLineageLease lease{};
    CHECK(gameplay::acquire_advertisement_observation(fixture.source, fixture.region, output, lease));
    fixture.ready = false;
    CHECK(gameplay::acquire_advertisement_observation(fixture.source, fixture.region, output, lease));
    CHECK(output.readiness == gameplay::AdvertisementReadiness::absent && !lease.pinned);
    assert_empty(output);
    CHECK(fixture.acquisitions == 1 && fixture.releases == 1);
    CHECK(fixture.rolePublications == 0 && fixture.descriptorPublications == 0 && fixture.allocations == 0);
}
} // namespace

namespace dawn::server::gameplay::endpoint {
bool ready() noexcept { return fixture.ready; }
state::gameplay::Endpoint advertised() noexcept { return fixture.endpoint; }
Identity identity() noexcept { return fixture.identity; }
}

namespace dawn::state::activity {
bool contains(ActivityInstanceKey key) noexcept {
    return (fixture.sourceValid && key == fixture.source && static_cast<bool>(key))
        || (fixture.hostValid && key == fixture.host && static_cast<bool>(key));
}
}

namespace dawn::server::gameplay::group {
state::activity::ActivityInstanceKey held_host_activity(std::uint64_t group) noexcept {
    return fixture.hostHeld && group == fixture.group() ? fixture.host : state::activity::ActivityInstanceKey{};
}
bool acquire_host_activity_lineage(state::activity::ActivityInstanceKey host,
                                  HostActivityLineageLease& output) noexcept {
    output = {};
    if (!fixture.pinAvailable || host != fixture.host) return false;
    output = {fixture.group(), fixture.host, fixture.source, fixture.region, 7, 2, true};
    ++fixture.acquisitions;
    if (fixture.wrongGroup) ++output.groupSessionId;
    if (fixture.wrongHost) ++output.host.incarnation.value;
    if (fixture.wrongSource) ++output.source.incarnation.value;
    if (fixture.wrongRegion) ++output.regionIndex;
    return !fixture.failureAfterPin;
}
void release_host_activity_lineage(HostActivityLineageLease& lease) noexcept {
    if (lease.pinned) ++fixture.releases;
    lease = {};
}
std::uint64_t activity_host_session(std::uint64_t, std::int32_t, std::uint64_t, bool& claimed) noexcept {
    ++fixture.allocations; claimed = true; return fixture.host.sessionId;
}
std::uint64_t activity_host_session(std::uint64_t, std::int32_t, state::activity::ActivityInstanceKey,
                                    bool& claimed) noexcept {
    ++fixture.allocations; claimed = true; return fixture.host.sessionId;
}
}

namespace dawn::state::gameplay::replication {
bool publish_control_host(std::uint64_t machine, const Address&) noexcept {
    ++fixture.rolePublications; fixture.publishedMachine = machine; return true;
}
}

namespace dawn::client::hooks::retail_log {
void register_gameplay_join_descriptor(const std::byte* bytes, std::size_t size,
                                        std::int32_t, std::uint64_t) noexcept {
    ++fixture.descriptorPublications;
    CHECK(size == fixture.publishedDescriptor.size());
    for (std::size_t index = 0; index < size; ++index) fixture.publishedDescriptor[index] = bytes[index];
}
}

namespace dawn::server::gameplay {
void report(core::log::Level, const char*, ...) noexcept {}
}

int main() {
    observation_does_not_publish();
    publishing_path_is_preserved();
    invalid_lifetimes_and_configuration();
    std::printf("PASS: %u production advertisement observation checks; no gameplay admission\n", checks);
}
