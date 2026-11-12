#include "activity_binding.h"

#include <Windows.h>
#include <array>
#include <cstdio>

#include "../logging/log.h"
#include "../../client/hooks/bootflow/native_identity_observation.h"
#include "../../server/gameplay/gameplay_advertisement.h"

namespace dawn::core::multiplayer::activity_binding {
namespace {
namespace native = client::hooks::bootflow::native_identity_observation;
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

[[nodiscard]] bool same_route(const gameplay::resolution::AuthenticatedRoute& a,
                               const gameplay::resolution::AuthenticatedRoute& b) noexcept {
    return a.handle == b.handle && a.source.address == b.source.address && a.source.port == b.source.port;
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
    }
    return "unknown";
}

SRWLOCK g_traceLock = SRWLOCK_INIT;
std::uint64_t g_lastPoll{};
unsigned g_events{};
Result g_lastResult{};
DiagnosticSource g_lastSource{};
bool g_polled{}, g_reported{};
} // namespace

static Result inspect_impl(std::uint64_t now, Observation& output, DiagnosticSource* source) noexcept {
    output = {};
    if (source != nullptr) *source = {};
    if (!native::enabled()) return Result::disabled;
    server::bap::CreatorActivitySnapshot creator{};
    if (!server::bap::snapshot_current_creator_activity(creator)) return Result::noCreator;
    if (!static_cast<bool>(creator.binding) || !creator.lineage.owns(creator.hostRegion.activity)
        || creator.hostRegion.activity != creator.lineage.bound || creator.memberKey == 0
        || creator.reportedRegion < 0) return Result::noCreator;

    LineagePin pin;
    gameplay::AdvertisedActivityObservation advertisement{};
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

    if (source != nullptr)
        *source = {source_fingerprint(creator.memberKey, advertisement.groupMachineId), creator.reportedRegion};

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
    if (!gameplay::resolution::lookup_authenticated_route(creator.binding.authentication, route)
        || route.handle.owner != creator.binding.authentication || !static_cast<bool>(route.handle)
        || route.source.address == 0 || route.source.port == 0) return Result::noAuthenticatedRoute;

    // Reobserve after crossing independently locked boundaries. No resolver/group lock is held
    // while asking BAP or the native collector for a current copied value.
    server::bap::CreatorActivitySnapshot current{};
    if (!server::bap::snapshot_creator_activity(creator.binding, current) || current != creator
        || !native::collect(observations, now, count) || count > observations.size()) return Result::changed;
    identity_activity::Correlation again{};
    if (identity_activity::correlate(creator.memberKey, advertisement.groupMachineId,
            std::span(observations).first(count), now, again) != identity_activity::Result::matched
        || !identity_activity::same_correspondence(again, match)
        || !gameplay::resolution::validate_authenticated_route(route)
        || !gameplay::group::validate_host_activity_lineage(pin.value)) return Result::changed;

    output.creator = creator;
    output.host = advertisement.host;
    output.groupMachineId = advertisement.groupMachineId;
    output.lineageGeneration = pin.value.rowGeneration;
    output.native = again;
    output.route = route;
    return Result::observed;
}

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

void service(std::uint64_t now) noexcept {
    if (!trace_requested() || !TryAcquireSRWLockExclusive(&g_traceLock)) return;
    const bool due = !g_polled || now < g_lastPoll || now - g_lastPoll >= 500;
    if (due) { g_lastPoll = now; g_polled = true; }
    ReleaseSRWLockExclusive(&g_traceLock);
    if (!due) return;
    Observation observed{};
    DiagnosticSource source{};
    const Result result = inspect_impl(GetTickCount64(), observed, &source);
    bool report{};
    AcquireSRWLockExclusive(&g_traceLock);
    if (g_events < 128 && (!g_reported || result != g_lastResult
        || source.fingerprint != g_lastSource.fingerprint || source.region != g_lastSource.region)) {
        ++g_events; g_reported = true; g_lastResult = result; g_lastSource = source; report = true;
    }
    ReleaseSRWLockExclusive(&g_traceLock);
    if (report) {
        std::array<char, 192> line{};
        const int size = std::snprintf(line.data(), line.size(),
            "ev=activity_binding pid=%lu result=%s source_fingerprint=0x%016llX region=%d admission=0",
            GetCurrentProcessId(), name(result), static_cast<unsigned long long>(source.fingerprint), source.region);
        if (size > 0 && static_cast<std::size_t>(size) < line.size())
            log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(size)});
    }
}

void reset() noexcept {
    AcquireSRWLockExclusive(&g_traceLock);
    g_lastPoll = 0; g_events = 0; g_polled = false; g_reported = false;
    g_lastSource = {};
    ReleaseSRWLockExclusive(&g_traceLock);
}

} // namespace dawn::core::multiplayer::activity_binding
