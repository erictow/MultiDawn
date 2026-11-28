#include "activity_binding.h"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdio>

#include "../../server/transport/process_socket.h"
#include "companion.h"
#include "../logging/log.h"
#include "../../client/hooks/bootflow/native_identity_observation.h"
#include "../../server/bap/local_identity_snapshot.h"
#include "../../server/gameplay/gameplay_advertisement.h"
#include "../../server/gameplay/peer/peer_transport.h"

namespace dawn::core::multiplayer::activity_binding {
namespace {
namespace native = client::hooks::bootflow::native_identity_observation;
namespace world_view = client::hooks::bootflow::native_replication_observer;
namespace gameplay = server::gameplay;

struct DiagnosticSource { std::uint64_t fingerprint{}; std::int32_t region{-1}; };
/** Diagnostic comparison only, over creator then control-machine scalars in little-endian order. */
[[nodiscard]] std::uint64_t source_fingerprint(std::uint64_t creator, std::uint64_t control) noexcept {
    std::uint64_t value = 14695981039346656037ULL;
    for (const auto machine : {creator, control}) {
        for (unsigned byte = 0; byte < 8; ++byte) {
            value ^= (machine >> (byte * 8U)) & 0xFFU;
            value *= 1099511628211ULL;
        }
    }
    return value;
}

class LineagePin final {
public:
    gameplay::group::HostActivityLineageLease value{};
    ~LineagePin() { gameplay::group::release_host_activity_lineage(value); }
    LineagePin() = default;
    LineagePin(const LineagePin&) = delete;
    LineagePin& operator=(const LineagePin&) = delete;
};

struct Source final {
    server::bap::CreatorActivitySnapshot creator{};
    gameplay::AdvertisedActivityObservation advertisement{};
    LineagePin pin{};
};

[[nodiscard]] bool same_route(const gameplay::resolution::AuthenticatedRoute& a,
                               const gameplay::resolution::AuthenticatedRoute& b) noexcept {
    return a.handle == b.handle && a.source.address == b.source.address && a.source.port == b.source.port
        && a.purpose == b.purpose && a.peerAddress == b.peerAddress;
}

[[nodiscard]] bool trace_requested() noexcept {
    static const bool value = []() noexcept {
        std::array<wchar_t, 2> text{};
        return GetEnvironmentVariableW(L"DAWN_ACTIVITY_BINDING_TRACE", text.data(),
            static_cast<DWORD>(text.size())) == 1 && text[0] == L'1';
    }();
    return value;
}

[[nodiscard]] const char* name(Result result) noexcept {
    switch (result) {
    case Result::observed: return "observed";
    case Result::disabled: return "identity_observer_disabled";
    case Result::noCreator: return "no_current_creator";
    case Result::noAdvertisement: return "no_exact_advertisement";
    case Result::noManagedGroup: return "no_managed_group";
    case Result::ambiguousManagedGroup: return "ambiguous_managed_group";
    case Result::malformedManagedGroup: return "malformed_managed_group";
    case Result::noAuthenticatedRoute: return "no_authenticated_route";
    case Result::changed: return "changed_during_capture";
    case Result::noWorldConnection: return "no_exact_world_connection";
    case Result::noWorldHuman: return "no_corroborated_world_human";
    case Result::ambiguousWorldHuman: return "ambiguous_world_human";
    case Result::malformedWorldHuman: return "malformed_world_human";
    case Result::noLocalRouteSource: return "no_local_route_source";
    }
    return "unknown";
}

struct DiagnosticHistory {
    Result result{};
    DiagnosticSource source{};
    unsigned events{};

    [[nodiscard]] bool record(Result latest, DiagnosticSource value) noexcept {
        if (events >= 128 || (events != 0 && result == latest
            && source.fingerprint == value.fingerprint && source.region == value.region)) return false;
        ++events;
        result = latest;
        source = value;
        return true;
    }
};

SRWLOCK g_traceLock = SRWLOCK_INIT;
SRWLOCK g_worldProbeLock = SRWLOCK_INIT;
std::uint64_t g_lastPoll{};
bool g_polled{};
DiagnosticHistory g_managedHistory{}, g_worldHistory{};

struct PendingWorldProbe {
    WorldProbeToken token{};
    InvitationPreflightObservation invitation{};
    WorldObservation world{};
    std::uint64_t deadline{};
};

PendingWorldProbe g_pendingWorldProbe{};

enum class PlayerSourceResult {
    observed,
    noIdentityReceipt,
    incompleteIdentity,
    noResolvedConnect,
    changed,
};

struct LocalPlayerSource {
    server::bap::LocalClientIdentitySnapshot identity{};
    gameplay::peer::ResolvedConnectObservation connect{};
};

[[nodiscard]] bool read_identity(const WorldObservation& world,
                                 server::bap::LocalClientIdentitySnapshot& out) noexcept {
    return server::bap::snapshot_creator_client_identity(world.creator.binding, out)
        && out.binding == world.creator.binding && out.lineage == world.creator.lineage
        && out.publication.activity == world.creator.lineage.bound
        && out.publication.hostRegion == world.creator.hostRegion
        && out.publication.receipt.revision != 0
        && out.publication.receipt.raw.memberKey == world.human.creatorMachineId;
}

[[nodiscard]] PlayerSourceResult read_local_player_source(const WorldObservation& world,
                                                          LocalPlayerSource& output) noexcept {
    output = {};
    LocalPlayerSource candidate{};
    if (!read_identity(world, candidate.identity)) return PlayerSourceResult::noIdentityReceipt;
    const auto& identity = candidate.identity.publication.receipt.raw;
    if (identity.joinIdentity == 0 || identity.accountSoid == 0 || identity.opaqueSoid == 0)
        return PlayerSourceResult::incompleteIdentity;
    if (!gameplay::peer::snapshot_resolved_connect(world.route, candidate.connect))
        return PlayerSourceResult::noResolvedConnect;

    // The BAP receipt and gameplay transport are observed under separate locks.
    server::bap::LocalClientIdentitySnapshot current{};
    gameplay::peer::ResolvedConnectObservation connect{};
    if (!validate_world(world, GetTickCount64()) || !read_identity(world, current)
        || current.publication.receipt != candidate.identity.publication.receipt
        || current.publication.region != candidate.identity.publication.region
        || !gameplay::peer::snapshot_resolved_connect(world.route, connect)
        || connect != candidate.connect) return PlayerSourceResult::changed;

    candidate.identity = current;
    output = candidate;
    return PlayerSourceResult::observed;
}

void trace_local_player_source(const char* stage, const WorldObservation& world) noexcept {
    LocalPlayerSource player{};
    const auto result = read_local_player_source(world, player);
    const char* label = "changed_during_capture";
    switch (result) {
    case PlayerSourceResult::observed: label = "observed"; break;
    case PlayerSourceResult::noIdentityReceipt: label = "no_identity_receipt"; break;
    case PlayerSourceResult::incompleteIdentity: label = "incomplete_identity"; break;
    case PlayerSourceResult::noResolvedConnect: label = "no_resolved_connect"; break;
    case PlayerSourceResult::changed: break;
    }
    // Report readiness and wire shape only. Raw receipts and addresses stay in this process.
    const bool observed = result == PlayerSourceResult::observed;
    const int method = observed ? std::to_integer<int>(player.connect.remoteAddress.back()) : -1;
    std::array<char, 152> line{};
    const int size = std::snprintf(line.data(), line.size(),
        "ev=world_player_source stage=%s result=%s netaddr_method=%d transition=%u synchronization=%u",
        stage, label, method,
        observed && player.identity.publication.region.hasTransitionToken ? 1U : 0U,
        observed && player.identity.publication.region.hasSynchronizationToken ? 1U : 0U);
    if (size > 0 && static_cast<std::size_t>(size) < line.size())
        log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(size)});
}

[[nodiscard]] WorldDestination destination_of(const server::bap::CreatorActivitySnapshot& creator) noexcept {
    WorldDestination destination{};
    if (creator.destination.packageNameLength > creator.destination.packageName.size()) return destination;
    for (std::size_t index = 0; index < creator.destination.packageNameLength; ++index)
        destination.package[index] = static_cast<char>(creator.destination.packageName[index]);
    destination.activity = creator.destination.activityIndex;
    destination.region = creator.reportedRegion;
    return destination;
}

[[nodiscard]] bool same_world(const WorldObservation& a, const WorldObservation& b) noexcept {
    return a.creator == b.creator && a.host == b.host && a.lineageGeneration == b.lineageGeneration
        && a.world == b.world && identity_activity::same_world_human(a.human, b.human)
        && same_route(a.route, b.route);
}

void report_world_probe(const char* stage, const char* result) noexcept {
    std::array<char, 128> line{};
    const int count = std::snprintf(line.data(), line.size(),
        "ev=world_probe stage=%s result=%s admission=0", stage, result);
    if (count > 0 && static_cast<std::size_t>(count) < line.size())
        log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(count)});
}

[[nodiscard]] Result inspect_source(Source& source, DiagnosticSource* diagnostic) noexcept {
    if (diagnostic != nullptr) *diagnostic = {};
    if (!native::enabled()) return Result::disabled;
    auto& creator = source.creator;
    if (!server::bap::snapshot_current_creator_activity(creator)) return Result::noCreator;
    if (!static_cast<bool>(creator.binding) || !creator.lineage.owns(creator.hostRegion.activity)
        || creator.hostRegion.activity != creator.lineage.bound || creator.memberKey == 0
        || creator.reportedRegion < 0) return Result::noCreator;

    auto& pin = source.pin;
    auto& advertisement = source.advertisement;
    if (!gameplay::acquire_advertisement_observation(creator.lineage.bound, creator.reportedRegion,
                                                 advertisement, pin.value)
        || advertisement.readiness != gameplay::AdvertisementReadiness::ready
        || !pin.value.pinned
        || !static_cast<bool>(advertisement.host) || pin.value.rowGeneration == 0
        || advertisement.source != creator.lineage.bound || pin.value.source != creator.lineage.bound
        || advertisement.host != pin.value.host || advertisement.regionIndex != creator.reportedRegion
        || pin.value.regionIndex != creator.reportedRegion
        || advertisement.groupMachineId == 0
        || advertisement.groupMachineId != pin.value.groupSessionId
        || !gameplay::group::validate_host_activity_lineage(pin.value)) return Result::noAdvertisement;

    if (diagnostic != nullptr)
        *diagnostic = {source_fingerprint(creator.memberKey, advertisement.groupMachineId), creator.reportedRegion};
    return Result::observed;
}

[[nodiscard]] bool read_route(const Source& source, gameplay::resolution::AuthenticatedRoute& route) noexcept {
    const auto owner = source.creator.binding.authentication;
    return gameplay::resolution::lookup_authenticated_route(owner, route)
        && route.handle.owner == owner && static_cast<bool>(route.handle)
        && route.source.address != 0 && route.source.port != 0;
}

[[nodiscard]] bool read_world_route(const Source& source, gameplay::resolution::AuthenticatedRoute& route) noexcept {
    // The primary BAP channel can own the transport while the FAH channel owns the current world.
    return server::bap::snapshot_creator_control_route(source.creator.binding, route)
        && static_cast<bool>(route.handle)
        && route.purpose == gameplay::resolution::RoutePurpose::control
        && route.peerAddress == gameplay::resolution::PeerAddressHandle{};
}

[[nodiscard]] bool current_creator(const Source& source) noexcept {
    server::bap::CreatorActivitySnapshot latest{};
    return server::bap::snapshot_creator_activity(source.creator.binding, latest) && latest == source.creator;
}

[[nodiscard]] bool current_route_and_lineage(const Source& source,
                                             const gameplay::resolution::AuthenticatedRoute& route) noexcept {
    return gameplay::resolution::validate_authenticated_route(route)
        && gameplay::group::validate_host_activity_lineage(source.pin.value);
}

[[nodiscard]] bool read_world(const Source& source, world_view::WorldConnection& output) noexcept {
    return world_view::snapshot_world_connection(source.creator.memberKey, source.advertisement.groupMachineId, output)
        && output.creatorMachineId == source.creator.memberKey
        && output.controlMachineId == source.advertisement.groupMachineId
        && output.controlEpoch != 0 && output.generation != 0;
}

[[nodiscard]] Result read_world_human(const Source& source, std::uint64_t now,
                                      identity_activity::WorldHuman& output) noexcept {
    std::array<identity_observation::Observation, identity_observation::kManagerCapacity> observations{};
    std::size_t count{};
    if (!native::collect(observations, now, count) || count > observations.size()) return Result::changed;
    switch (identity_activity::corroborate_world_human(source.creator.memberKey,
                                             std::span(observations).first(count), now, output)) {
    case identity_activity::Result::matched: return Result::observed;
    case identity_activity::Result::noMatch: return Result::noWorldHuman;
    case identity_activity::Result::ambiguous: return Result::ambiguousWorldHuman;
    case identity_activity::Result::invalidInput: return Result::malformedWorldHuman;
    }
    return Result::changed;
}

[[nodiscard]] Result inspect_world_impl(std::uint64_t now, WorldObservation& output,
                                        DiagnosticSource* diagnostic) noexcept {
    output = {};
    Source source{};
    if (const auto result = inspect_source(source, diagnostic); result != Result::observed) return result;
    WorldObservation candidate{};
    if (!read_world(source, candidate.world)) return Result::noWorldConnection;
    if (const auto result = read_world_human(source, now, candidate.human); result != Result::observed) return result;
    if (!read_world_route(source, candidate.route)) return Result::noAuthenticatedRoute;
    if (!server::transport::process_socket::udp_source_in_current_process(candidate.route.source))
        return Result::noLocalRouteSource;

    world_view::WorldConnection currentWorld{};
    identity_activity::WorldHuman currentHuman{};
    gameplay::resolution::AuthenticatedRoute currentRoute{};
    if (!current_creator(source)
        || read_world_human(source, now, currentHuman) != Result::observed
        || !identity_activity::same_world_human(candidate.human, currentHuman)
        || !read_world(source, currentWorld) || currentWorld != candidate.world
        || !read_world_route(source, currentRoute) || !same_route(currentRoute, candidate.route)
        || !current_route_and_lineage(source, candidate.route)) return Result::changed;

    candidate.creator = source.creator;
    candidate.host = source.advertisement.host;
    candidate.lineageGeneration = source.pin.value.rowGeneration;
    candidate.human = currentHuman;
    output = candidate;
    return Result::observed;
}

[[nodiscard]] Result inspect_impl(std::uint64_t now, Observation& output, DiagnosticSource* diagnostic) noexcept {
    output = {};
    Source source{};
    if (const auto result = inspect_source(source, diagnostic); result != Result::observed) return result;
    const auto& creator = source.creator;
    const auto& advertisement = source.advertisement;

    std::array<identity_observation::Observation, identity_observation::kManagerCapacity> observations{};
    std::size_t count{};
    if (!native::collect(observations, now, count) || count > observations.size()) return Result::changed;
    identity_activity::Correlation match{};
    switch (identity_activity::correlate(creator.memberKey, advertisement.groupMachineId,
                                        std::span(observations).first(count), now, match)) {
    case identity_activity::Result::noMatch: return Result::noManagedGroup;
    case identity_activity::Result::ambiguous: return Result::ambiguousManagedGroup;
    case identity_activity::Result::invalidInput: return Result::malformedManagedGroup;
    case identity_activity::Result::matched: break;
    }

    gameplay::resolution::AuthenticatedRoute route{};
    if (!read_route(source, route)) return Result::noAuthenticatedRoute;

    // Reobserve after crossing independently locked boundaries. No resolver/group lock is held
    // while asking BAP or the native collector for a current copied value.
    if (!current_creator(source)
        || !native::collect(observations, now, count) || count > observations.size()) return Result::changed;
    identity_activity::Correlation again{};
    if (identity_activity::correlate(creator.memberKey, advertisement.groupMachineId,
            std::span(observations).first(count), now, again) != identity_activity::Result::matched
        || !identity_activity::same_correspondence(again, match)
        || !current_route_and_lineage(source, route)) return Result::changed;

    output.creator = creator;
    output.host = advertisement.host;
    output.groupMachineId = advertisement.groupMachineId;
    output.lineageGeneration = source.pin.value.rowGeneration;
    output.native = again;
    output.route = route;
    return Result::observed;
}
} // namespace

Result inspect(std::uint64_t now, Observation& output) noexcept {
    return inspect_impl(now, output, nullptr);
}

bool validate(const Observation& previous, std::uint64_t now) noexcept {
    if (!static_cast<bool>(previous.creator.binding) || previous.native.manager == 0
        || now < previous.native.sampledAt
        || now - previous.native.sampledAt > identity_observation::kMaximumAgeMs) return false;
    Observation current{};
    if (inspect(now, current) != Result::observed) return false;
    return current.creator == previous.creator && current.host == previous.host
        && current.groupMachineId == previous.groupMachineId
        && current.lineageGeneration == previous.lineageGeneration
        && identity_activity::same_correspondence(current.native, previous.native)
        && same_route(current.route, previous.route);
}

Result inspect_world(std::uint64_t now, WorldObservation& output) noexcept {
    return inspect_world_impl(now, output, nullptr);
}

bool validate_world(const WorldObservation& previous, std::uint64_t now) noexcept {
    if (!static_cast<bool>(previous.creator.binding) || previous.world.generation == 0
        || previous.human.playerId == 0 || now < previous.human.sampledAt
        || now - previous.human.sampledAt > identity_observation::kMaximumAgeMs) return false;
    WorldObservation current{};
    if (inspect_world(now, current) != Result::observed) return false;
    return same_world(current, previous);
}

void trace_invitation_world(const InvitationPreflightObservation& invitation) noexcept {
    if (!validate_traced_invitation_preflight(invitation)) return;
    WorldObservation observed{};
    const auto result = inspect_world(GetTickCount64(), observed);
    if (!validate_traced_invitation_preflight(invitation)) return;
    std::array<char, 144> line{};
    const int size = std::snprintf(line.data(), line.size(),
        "ev=world_activity_binding stage=accepted_invite result=%s admission=0", name(result));
    if (size > 0 && static_cast<std::size_t>(size) < line.size())
        log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(size)});
    if (result != Result::observed) return;
    WorldProbeToken token{};
    AcquireSRWLockExclusive(&g_worldProbeLock);
    const bool sent = request_world_probe(invitation, destination_of(observed.creator), token);
    if (sent) g_pendingWorldProbe = {token, invitation, observed,
        (std::min)(invitation.deadline, GetTickCount64() + kWorldProbeTimeoutMs)};
    ReleaseSRWLockExclusive(&g_worldProbeLock);
    if (sent) report_world_probe("host", "request_sent");
}

void service_world_probe(const WorldProbeEvent& event) noexcept {
    const auto now = GetTickCount64();
    if (event.kind == WorldProbeKind::none) {
        AcquireSRWLockExclusive(&g_worldProbeLock);
        const bool expired = g_pendingWorldProbe.deadline != 0 && now >= g_pendingWorldProbe.deadline;
        if (expired) g_pendingWorldProbe = {};
        ReleaseSRWLockExclusive(&g_worldProbeLock);
        if (expired) report_world_probe("host", "timeout");
        return;
    }
    if (now >= event.deadline) return;
    if (event.kind == WorldProbeKind::request) {
        WorldObservation guest{};
        const auto result = inspect_world(now, guest);
        const bool matching = result == Result::observed && event.destination == destination_of(guest.creator);
        const bool ready = matching && validate_world(guest, GetTickCount64());
        const char* reason = result != Result::observed ? name(result)
            : !matching ? "different_destination" : ready ? "observed" : "changed_during_capture";
        if (respond_world_probe(event, ready)) {
            report_world_probe("guest", reason);
            if (ready) trace_local_player_source("guest", guest);
        }
        return;
    }

    PendingWorldProbe pending{};
    AcquireSRWLockExclusive(&g_worldProbeLock);
    if (event.token == g_pendingWorldProbe.token
        && event.generation == g_pendingWorldProbe.invitation.companionGeneration) {
        pending = g_pendingWorldProbe;
        g_pendingWorldProbe = {};
    }
    ReleaseSRWLockExclusive(&g_worldProbeLock);
    if (pending.deadline <= now || !validate_traced_invitation_preflight(pending.invitation)) return;
    WorldObservation host{};
    const bool current = inspect_world(now, host) == Result::observed && same_world(host, pending.world)
        && validate_traced_invitation_preflight(pending.invitation);
    if (!current) report_world_probe("host", "world_changed");
    else if (event.kind == WorldProbeKind::ready) {
        report_world_probe("host", "both_worlds_observed");
        trace_local_player_source("host", host);
    } else report_world_probe("host", "guest_unavailable");
}

void service(std::uint64_t now) noexcept {
    if (!trace_requested() || !TryAcquireSRWLockExclusive(&g_traceLock)) return;
    const bool due = !g_polled || now < g_lastPoll || now - g_lastPoll >= 500;
    if (due) { g_lastPoll = now; g_polled = true; }
    ReleaseSRWLockExclusive(&g_traceLock);
    if (!due) return;
    Observation observed{};
    DiagnosticSource source{};
    const Result result = inspect_impl(GetTickCount64(), observed, &source);
    WorldObservation world{};
    DiagnosticSource worldSource{};
    const auto worldResult = inspect_world_impl(GetTickCount64(), world, &worldSource);

    AcquireSRWLockExclusive(&g_traceLock);
    const bool reportManaged = g_managedHistory.record(result, source);
    const bool reportWorld = g_worldHistory.record(worldResult, worldSource);
    ReleaseSRWLockExclusive(&g_traceLock);
    if (reportManaged) {
        std::array<char, 192> line{};
        const int size = std::snprintf(line.data(), line.size(),
            "ev=activity_binding pid=%lu result=%s source_fingerprint=0x%016llX region=%d admission=0",
            GetCurrentProcessId(), name(result), static_cast<unsigned long long>(source.fingerprint), source.region);
        if (size > 0 && static_cast<std::size_t>(size) < line.size())
            log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(size)});
    }

    if (reportWorld) {
        std::array<char, 144> line{};
        const int size = std::snprintf(line.data(), line.size(),
            "ev=world_activity_binding stage=local_world result=%s region=%d admission=0",
            name(worldResult), worldSource.region);
        if (size > 0 && static_cast<std::size_t>(size) < line.size())
            log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(size)});
    }
}

void reset() noexcept {
    AcquireSRWLockExclusive(&g_traceLock);
    g_lastPoll = 0;
    g_polled = false;
    g_managedHistory = {};
    g_worldHistory = {};
    ReleaseSRWLockExclusive(&g_traceLock);
    AcquireSRWLockExclusive(&g_worldProbeLock);
    g_pendingWorldProbe = {};
    ReleaseSRWLockExclusive(&g_worldProbeLock);
}

} // namespace dawn::core::multiplayer::activity_binding
