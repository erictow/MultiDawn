#include <Windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>

#include "../../../core/logging/log.h"
#include "../../../state/activity/forced/activity_forced_destination.h"
#include "../../../state/activity/forced/prelaunch_profile.h"
#include "../../hooking/call_gate.h"
#include "../../hooking/detour.h"
#include "../retail_log/retail_log_enqueue_observer.h"
#include "internal.h"
#include "mission_prelaunch.h"
#include "../../activity/mission_launch.h"

namespace dawn::client::hooks::bootflow {
namespace {

namespace prelaunch = state::activity::forced::prelaunch;

constexpr std::uintptr_t kManagerUpdateLoopRva = 0x1764EC0U;
constexpr std::uintptr_t kLaunchProducerRva = 0x1763B20U;
constexpr std::uintptr_t kRouteDescriptorLookupRva = 0x1751370U;
constexpr std::uintptr_t kAuthoredLaunchDispatchRva = 0x134FDF0U;
constexpr std::uintptr_t kComponentDispatchRva = 0x1766A30U;
constexpr std::uintptr_t kSelectionLaunchStateAccessorRva = 0xBF9FA0U;
constexpr std::uintptr_t kSelectionLaunchStateAccessorReturnRva = 0xBFA610U;
constexpr std::uintptr_t kSelectionLaunchPublisherRva = 0x17ADA60U;
constexpr std::uintptr_t kSelectionLaunchPublisherReturnRva = 0xBFA89BU;
constexpr std::uintptr_t kIdentityRequestRva = 0x17948F0U;
constexpr std::uintptr_t kIdentityDefinitionRva = 0x179AF00U;
constexpr std::uintptr_t kManagerEventPublishRva = 0x178A830U;
constexpr std::uintptr_t kManagerEventBeginRva = 0x178B060U;
constexpr std::uint16_t kChosenActivity = 282U;
constexpr std::uint16_t kTowerfallActivity = 266U;
constexpr std::string_view kOmegaPackage = "mission_scot";
constexpr bool kTowerfallIdentityMutationEnabled = false;
/** Activity-266 identifiers extracted from the installed public activity/package tables. */
constexpr std::uint64_t kRetryIntervalMs = 100U;
constexpr std::uint32_t kMaxDiagnosticRetryAttempts = 4U;
constexpr std::uint64_t kPrelaunchInstallRetryMs = 1000U;
constexpr std::uint64_t kIdentityBindingRetryMs = 100U;
constexpr std::size_t kIdentityDescriptorBytes = 128U;
constexpr std::size_t kRetainedRouteBytes = 0xB0U;
constexpr std::size_t kPublicationRoutePrefixBytes = 0x18U;
constexpr std::int32_t kTowerfallScriptIdentity = 1;
constexpr std::int32_t kIdentityDescriptorPublishedEvent = 10;
constexpr std::size_t kSelectionPublicationState0Offset = 0x19C0U;
constexpr std::size_t kSelectionSourceOffset = 0x12U;
constexpr std::size_t kSelectionDestinationOffset = 0x14U;
constexpr std::size_t kSelectionPackageOffset = 0x60U;
constexpr std::size_t kSelectionPackageCapacity = 40U;
constexpr std::size_t kPublicationPackageOffset = 0x58U;
constexpr std::uint32_t kMaxOmegaProducerEvents = 2048U;
constexpr std::uint32_t kMaxOmegaManagerEvents = 2048U;
constexpr std::uint32_t kMaxOmegaComponentEvents = 256U;
constexpr std::uint32_t kMaxNativeSessionTraceEvents = 128U;

constexpr std::string_view kSelectionPumpSignatureText =
    "4C 8B DC 49 89 5B 18 49 89 73 20 55 57 41 54 41 55 41 56 49 8D AB A8 FD FF FF "
    "48 81 EC 30 03 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 20 02 00 00";
constexpr auto kSelectionPumpSignature =
    signature<signature_length(kSelectionPumpSignatureText)>(kSelectionPumpSignatureText);

constexpr std::array<std::byte, 16> kManagerUpdateLoopPrefix{
    std::byte{0x40}, std::byte{0x55}, std::byte{0x56}, std::byte{0x48},
    std::byte{0x83}, std::byte{0xEC}, std::byte{0x78}, std::byte{0x8B},
    std::byte{0x81}, std::byte{0x50}, std::byte{0x08}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xF1}};
constexpr std::array<std::byte, 16> kLaunchProducerPrefix{
    std::byte{0x4C}, std::byte{0x8B}, std::byte{0xDC}, std::byte{0x55},
    std::byte{0x49}, std::byte{0x8D}, std::byte{0xAB}, std::byte{0x98},
    std::byte{0xFC}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0x48},
    std::byte{0x81}, std::byte{0xEC}, std::byte{0x60}, std::byte{0x04}};
constexpr std::array<std::byte, 21> kRouteDescriptorLookupPrefix{
    std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x08}, std::byte{0x48}, std::byte{0x89}, std::byte{0x6C},
    std::byte{0x24}, std::byte{0x18}, std::byte{0x48}, std::byte{0x89},
    std::byte{0x74}, std::byte{0x24}, std::byte{0x20}, std::byte{0x57},
    std::byte{0x41}, std::byte{0x56}, std::byte{0x41}, std::byte{0x57},
    std::byte{0x48}};
constexpr std::array<std::byte, 18> kAuthoredLaunchDispatchPrefix{
    std::byte{0x40}, std::byte{0x53}, std::byte{0x57}, std::byte{0x41},
    std::byte{0x54}, std::byte{0x41}, std::byte{0x55}, std::byte{0x41},
    std::byte{0x56}, std::byte{0x41}, std::byte{0x57}, std::byte{0x48},
    std::byte{0x81}, std::byte{0xEC}, std::byte{0x68}, std::byte{0x09},
    std::byte{0x00}, std::byte{0x00}};
constexpr std::array<std::byte, 16> kComponentDispatchPrefix{
    std::byte{0x40}, std::byte{0x55}, std::byte{0x56}, std::byte{0x57},
    std::byte{0x41}, std::byte{0x56}, std::byte{0x41}, std::byte{0x57},
    std::byte{0x48}, std::byte{0x8D}, std::byte{0xAC}, std::byte{0x24},
    std::byte{0x10}, std::byte{0xFE}, std::byte{0xFF}, std::byte{0xFF}};
constexpr std::array<std::byte, 16> kSelectionLaunchStateAccessorPrefix{
    std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x08}, std::byte{0x57}, std::byte{0x48}, std::byte{0x83},
    std::byte{0xEC}, std::byte{0x20}, std::byte{0xE8}, std::byte{0x81},
    std::byte{0x94}, std::byte{0x00}, std::byte{0x00}, std::byte{0x33}};
constexpr std::array<std::byte, 16> kSelectionLaunchPublisherPrefix{
    std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x18}, std::byte{0x56}, std::byte{0x48}, std::byte{0x83},
    std::byte{0xEC}, std::byte{0x20}, std::byte{0x48}, std::byte{0x8B},
    std::byte{0xF1}, std::byte{0x48}, std::byte{0x8B}, std::byte{0xDA}};
constexpr std::array<std::byte, 16> kSelectionPublicationState0Prefix{
    std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x08}, std::byte{0x48}, std::byte{0x89}, std::byte{0x6C},
    std::byte{0x24}, std::byte{0x18}, std::byte{0x48}, std::byte{0x89},
    std::byte{0x74}, std::byte{0x24}, std::byte{0x20}, std::byte{0x57}};
constexpr std::array<std::byte, 20> kIdentityRequestPrefix{
    std::byte{0x40}, std::byte{0x55}, std::byte{0x53}, std::byte{0x56},
    std::byte{0x57}, std::byte{0x48}, std::byte{0x8D}, std::byte{0xAC},
    std::byte{0x24}, std::byte{0x38}, std::byte{0xFD}, std::byte{0xFF},
    std::byte{0xFF}, std::byte{0x48}, std::byte{0x81}, std::byte{0xEC},
    std::byte{0xC8}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00}};
constexpr std::array<std::byte, 10> kIdentityDefinitionPrefix{
    std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x08}, std::byte{0x57}, std::byte{0x48}, std::byte{0x83},
    std::byte{0xEC}, std::byte{0x20}};
constexpr std::array<std::byte, 20> kManagerEventPublishPrefix{
    std::byte{0x4C}, std::byte{0x8B}, std::byte{0xDC}, std::byte{0x55},
    std::byte{0x53}, std::byte{0x57}, std::byte{0x49}, std::byte{0x8D},
    std::byte{0xAB}, std::byte{0x98}, std::byte{0xFD}, std::byte{0xFF},
    std::byte{0xFF}, std::byte{0x48}, std::byte{0x81}, std::byte{0xEC},
    std::byte{0x50}, std::byte{0x03}, std::byte{0x00}, std::byte{0x00}};
constexpr std::array<std::byte, 18> kManagerEventBeginPrefix{
    std::byte{0x48}, std::byte{0x89}, std::byte{0x5C}, std::byte{0x24},
    std::byte{0x18}, std::byte{0x48}, std::byte{0x89}, std::byte{0x74},
    std::byte{0x24}, std::byte{0x20}, std::byte{0x55}, std::byte{0x57},
    std::byte{0x41}, std::byte{0x54}, std::byte{0x41}, std::byte{0x56},
    std::byte{0x41}, std::byte{0x57}};

using ManagerUpdateLoop = void(__fastcall*)(std::byte*) noexcept;
using LaunchProducer = void(__fastcall*)() noexcept;
using RouteDescriptorLookup = std::byte*(__fastcall*)(std::int32_t,
                                                       std::byte**) noexcept;
using AuthoredLaunchDispatch = void(__fastcall*)(std::int32_t,
                                                  std::int32_t,
                                                  const std::byte*,
                                                  const void*,
                                                  std::uint32_t) noexcept;
using ComponentDispatch = void(__fastcall*)(std::byte*, std::int32_t) noexcept;
using SelectionLaunchStateAccessor = std::byte*(__fastcall*)(std::byte*) noexcept;
using SelectionLaunchPublisher = bool(__fastcall*)(std::byte*, std::byte*) noexcept;
using SelectionPublicationState0 = void(__fastcall*)(std::byte*) noexcept;
using IdentityRequest = void(__fastcall*)(std::int32_t, const void*) noexcept;
using IdentityDefinition = std::byte*(__fastcall*)(std::int32_t) noexcept;
using ManagerEventPublish = void(__fastcall*)(std::byte*, std::int32_t) noexcept;
using ManagerEventBegin = void(__fastcall*)(std::byte*, std::int32_t) noexcept;

enum HookIndex : std::size_t {
    managerUpdateIndex,
    launchProducerIndex,
    authoredLaunchIndex,
    componentDispatchIndex,
    routeDescriptorLookupIndex,
    identityRequestIndex,
    managerEventPublishIndex,
    managerEventBeginIndex,
    selectionLaunchStateAccessorIndex,
    selectionLaunchPublisherIndex,
    hookCount,
};

constexpr std::size_t kCoreHookCount = selectionLaunchStateAccessorIndex;

struct RouteSnapshot final {
    std::byte* descriptor{};
    std::byte* manager{};
    std::uint32_t word0{};
    std::uint32_t word4{};
    std::uint32_t word8{};
    std::uint32_t wordC{};
    std::uint32_t word10{};
    std::int16_t source{-1};
    std::int16_t destination{-1};
    std::uint8_t selector{};
    std::array<char, 41> package{};
    std::size_t packageLength{};
};

struct NativeSessionTraceState final {
    std::byte* manager{};
    std::byte* definition{};
    std::int32_t mode{-1};
    std::int32_t identity{-1};
};

[[nodiscard]] RouteSnapshot snapshot_route() noexcept;
[[nodiscard]] bool is_towerfall_route(const RouteSnapshot& route) noexcept;
void report_route(const char* stage,
                  std::uint64_t sequence,
                  std::uint32_t attempt,
                  const RouteSnapshot& route,
                  bool match) noexcept;

std::array<hooking::detour::Handle, hookCount> g_handles{};
std::atomic<ManagerUpdateLoop> g_managerUpdateOriginal{nullptr};
std::atomic<LaunchProducer> g_launchProducerOriginal{nullptr};
std::atomic<LaunchProducer> g_launchProducerEntry{nullptr};
std::atomic<RouteDescriptorLookup> g_routeLookup{nullptr};
std::atomic<AuthoredLaunchDispatch> g_authoredLaunchOriginal{nullptr};
std::atomic<ComponentDispatch> g_componentDispatchOriginal{nullptr};
std::atomic<RouteDescriptorLookup> g_routeLookupOriginal{nullptr};
std::atomic<IdentityRequest> g_identityRequestOriginal{nullptr};
std::atomic<IdentityRequest> g_identityRequestEntry{nullptr};
std::atomic<ManagerEventPublish> g_managerEventPublishOriginal{nullptr};
std::atomic<ManagerEventPublish> g_managerEventPublishEntry{nullptr};
std::atomic<ManagerEventBegin> g_managerEventBeginOriginal{nullptr};
std::atomic<ManagerEventBegin> g_managerEventBeginEntry{nullptr};
std::atomic<SelectionLaunchStateAccessor> g_selectionLaunchStateOriginal{nullptr};
std::atomic<SelectionLaunchPublisher> g_selectionLaunchPublisherOriginal{nullptr};
std::atomic<SelectionPublicationState0> g_selectionPublicationState0{nullptr};
hooking::CallGate g_callGate{};

std::atomic_bool g_armed{};
std::atomic_bool g_dispatched{};
std::atomic_bool g_retryInProgress{};
std::atomic_bool g_referenceCaptured{};
std::atomic_bool g_referenceComponentCaptured{};
std::atomic_uint32_t g_retryAttempts{};
std::atomic_uint64_t g_nextRetryTick{};
std::atomic_uint64_t g_producerSequence{};
std::atomic_uint64_t g_lastSuccessfulProducer{};
std::atomic_uint64_t g_lastSuccessfulRetryProducer{};
std::atomic_uint64_t g_lastRouteSignature{~std::uint64_t{0}};
std::array<std::atomic_uint64_t, 8> g_lastManagerSignatures{};
std::atomic_bool g_nativeSessionTraceEnabled{};
SRWLOCK g_nativeSessionTraceLock{};
std::array<NativeSessionTraceState, 32> g_nativeSessionTraceStates{};
std::uint32_t g_nativeSessionTraceEvents{};
std::atomic<std::byte*> g_lastRouteManager{nullptr};
std::atomic_bool g_prelaunchInstallInProgress{};
std::atomic<const prelaunch::Profile*> g_prelaunchPublicationPending{};
std::atomic<const prelaunch::Profile*> g_requestedPrelaunchProfile{};
std::atomic_bool g_directContractPublished{};
std::atomic_uint64_t g_nextPrelaunchInstallTick{};
std::atomic_uint32_t g_prelaunchInstallAttempts{};
std::atomic_bool g_identityBindingInProgress{};
std::atomic_bool g_identityBindingPublished{};
std::atomic_uint64_t g_nextIdentityBindingTick{};
std::atomic_uint32_t g_identityBindingAttempts{};
std::atomic_uint32_t g_identityBindingDescriptorGeneration{};
std::atomic_bool g_identityBindingQueued{};
std::atomic_uint64_t g_identityTraceSequence{};
std::atomic_uint64_t g_bindingTimelineSequence{};
std::atomic_uint32_t g_omegaProducerEvents{};
std::atomic_uint32_t g_omegaManagerEvents{};
std::atomic_uint32_t g_omegaComponentEvents{};
std::array<std::byte, kRetainedRouteBytes> g_retainedRoute{};
std::atomic_bool g_retainedRouteReady{};
std::atomic_bool g_routeFallbackActive{};
std::atomic<std::byte*> g_retainedRouteManager{nullptr};
std::atomic_bool g_prelaunchProducerInProgress{};
thread_local std::uint64_t g_activeProducerSequence{};
thread_local bool g_activeProducerDispatched{};
thread_local bool g_identityReplayInvocation{};
thread_local bool g_retryInvocation{};

[[nodiscard]] bool calls_idle() noexcept {
    return g_callGate.idle();
}

[[nodiscard]] bool report_attempt(std::uint32_t attempt) noexcept {
    return attempt <= 16U || (attempt & (attempt - 1U)) == 0U || attempt % 100U == 0U;
}

[[nodiscard]] std::uint64_t descriptor_hash(
    const std::array<std::byte, kIdentityDescriptorBytes>& descriptor) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const std::byte value : descriptor) {
        hash ^= std::to_integer<std::uint8_t>(value);
        hash *= 1099511628211ULL;
    }
    return hash;
}

template <typename Value>
[[nodiscard]] Value safe_read(const void* address, Value fallback = {}) noexcept {
    Value value = fallback;
    __try {
        if (address != nullptr) {
            value = *static_cast<const Value*>(address);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value = fallback;
    }
    return value;
}

[[nodiscard]] bool safe_copy(std::byte* destination,
                             const std::byte* source,
                             std::size_t size) noexcept {
    bool copied = false;
    __try {
        if (destination != nullptr && source != nullptr) {
            std::memcpy(destination, source, size);
            copied = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        copied = false;
    }
    return copied;
}

[[nodiscard]] std::uint64_t hash_bytes(const std::byte* bytes,
                                       std::size_t size,
                                       std::size_t& nonzero) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    nonzero = 0U;
    __try {
        for (std::size_t index = 0; bytes != nullptr && index < size; ++index) {
            const std::uint8_t value = std::to_integer<std::uint8_t>(bytes[index]);
            nonzero += value != 0U ? 1U : 0U;
            hash ^= value;
            hash *= 1099511628211ULL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hash = 0U;
        nonzero = 0U;
    }
    return hash;
}

struct IdentityDefinitionSnapshot final {
    std::byte* definition{};
    std::uint32_t flags{};
    std::uint16_t state{};
    const void* context{};
    std::int32_t activity{-1};
    std::uint16_t request{};
    std::uint8_t enabled{};
    std::uint8_t pending{};
    std::uint64_t currentHash{};
    std::uint64_t pendingHash{};
    std::size_t currentNonzero{};
    std::size_t pendingNonzero{};
};

struct ManagerSnapshot final {
    std::int32_t identity{-1};
    std::int32_t mode{-1};
    std::int32_t selected{-1};
    std::int32_t registered{-1};
    std::int32_t active{-1};
    std::int32_t activity{-1};
    std::int32_t lifecycle{-1};
    std::uint32_t flags{};
};

[[nodiscard]] ManagerSnapshot snapshot_manager(std::byte* manager) noexcept {
    ManagerSnapshot snapshot{};
    snapshot.identity = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1C7C0U : nullptr, -1);
    snapshot.mode = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1AEF8U : nullptr, -1);
    snapshot.selected = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x87CU : nullptr, -1);
    snapshot.registered = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0xE93CU : nullptr, -1);
    snapshot.active = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1AF00U : nullptr, -1);
    snapshot.activity = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x850U : nullptr, -1);
    snapshot.lifecycle = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1C820U : nullptr, -1);
    snapshot.flags = safe_read<std::uint32_t>(
        manager != nullptr ? manager + 0x1AEE8U : nullptr, 0U);
    return snapshot;
}

[[nodiscard]] std::uint64_t manager_signature(
    const ManagerSnapshot& manager,
    const IdentityDefinitionSnapshot& definition) noexcept {
    std::uint64_t signature =
        static_cast<std::uint32_t>(manager.identity)
        | (static_cast<std::uint64_t>(static_cast<std::uint16_t>(manager.mode)) << 32U)
        | (static_cast<std::uint64_t>(static_cast<std::uint8_t>(manager.selected)) << 48U)
        | (static_cast<std::uint64_t>(static_cast<std::uint8_t>(manager.registered)) << 56U);
    signature ^= static_cast<std::uint32_t>(manager.active);
    signature ^= static_cast<std::uint64_t>(static_cast<std::uint16_t>(manager.activity))
                 << 16U;
    signature ^= static_cast<std::uint64_t>(static_cast<std::uint8_t>(manager.lifecycle))
                 << 40U;
    signature ^= manager.flags;
    signature ^= definition.currentHash;
    signature ^= (definition.pendingHash << 1U) | (definition.pendingHash >> 63U);
    signature ^= static_cast<std::uint64_t>(definition.enabled) << 8U;
    signature ^= static_cast<std::uint64_t>(definition.pending) << 9U;
    signature ^= static_cast<std::uint32_t>(definition.activity);
    return signature;
}

[[nodiscard]] IdentityDefinitionSnapshot snapshot_identity_definition(
    std::int32_t identity) noexcept {
    IdentityDefinitionSnapshot snapshot{};
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto lookup = reinterpret_cast<IdentityDefinition>(
        image != nullptr ? image + kIdentityDefinitionRva : nullptr);
    __try {
        snapshot.definition = lookup != nullptr && identity >= 0 ? lookup(identity) : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snapshot.definition = nullptr;
    }
    if (snapshot.definition == nullptr) {
        return snapshot;
    }
    snapshot.flags = safe_read<std::uint32_t>(snapshot.definition + 0x04U, 0U);
    snapshot.state = safe_read<std::uint16_t>(snapshot.definition + 0x0CU, 0U);
    snapshot.context = safe_read<const void*>(snapshot.definition + 0x18U, nullptr);
    snapshot.activity = safe_read<std::int32_t>(snapshot.definition + 0x24U, -1);
    snapshot.request = safe_read<std::uint16_t>(snapshot.definition + 0x2CU, 0U);
    snapshot.enabled = safe_read<std::uint8_t>(snapshot.definition + 0x94CU, 0U);
    snapshot.pending = safe_read<std::uint8_t>(snapshot.definition + 0x94DU, 0U);
    snapshot.currentHash = hash_bytes(snapshot.definition + 0x57CU,
                                      kIdentityDescriptorBytes,
                                      snapshot.currentNonzero);
    snapshot.pendingHash = hash_bytes(snapshot.definition + 0x94EU,
                                      kIdentityDescriptorBytes,
                                      snapshot.pendingNonzero);
    return snapshot;
}

template <std::size_t Size>
[[nodiscard]] bool prefix_matches(const std::byte* target,
                                  const std::array<std::byte, Size>& prefix) noexcept {
    if (target == nullptr) {
        return false;
    }
    bool matches = false;
    __try {
        matches = std::memcmp(target, prefix.data(), prefix.size()) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = false;
    }
    return matches;
}

void write_line(core::log::Level level,
                const std::array<char, core::log::kLineCapacity>& line,
                int length) noexcept {
    if (length <= 0) {
        return;
    }
    const std::size_t bounded =
        (std::min)(static_cast<std::size_t>(length), line.size() - 1U);
    core::log::write(core::log::Channel::client, level, {line.data(), bounded});
}

[[nodiscard]] bool native_session_trace_requested() noexcept {
    // Read once during installation, never from the per-frame update hook.
    static const bool requested = []() noexcept {
        std::array<wchar_t, 2> value{};
        return GetEnvironmentVariableW(L"DAWN_NATIVE_SESSION_TRACE", value.data(),
                                       static_cast<DWORD>(value.size())) == 1U
               && value[0] == L'1';
    }();
    return requested;
}

void trace_native_session(std::byte* manager,
                          const ManagerSnapshot& snapshot,
                          const IdentityDefinitionSnapshot& definition) noexcept {
    if (!g_nativeSessionTraceEnabled.load(std::memory_order_relaxed)
        || manager == nullptr || !TryAcquireSRWLockExclusive(&g_nativeSessionTraceLock)) {
        return;
    }

    bool changed = false;
    if (g_nativeSessionTraceEvents < kMaxNativeSessionTraceEvents) {
        NativeSessionTraceState* available = nullptr;
        for (auto& state : g_nativeSessionTraceStates) {
            if (state.manager == manager) {
                available = &state;
                break;
            }
            if (state.manager == nullptr && available == nullptr) {
                available = &state;
            }
        }
        if (available != nullptr
            && (available->manager != manager || available->mode != snapshot.mode
                || available->identity != snapshot.identity
                || available->definition != definition.definition)) {
            *available = {manager, definition.definition, snapshot.mode, snapshot.identity};
            ++g_nativeSessionTraceEvents;
            changed = true;
        }
    }
    ReleaseSRWLockExclusive(&g_nativeSessionTraceLock);
    if (!changed) {
        return;
    }

    // These existing snapshots contain more data. Keep this opt-in event limited
    // to addresses and scalar session state, without descriptors or security data.
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(), line.size(),
        "ev=native_session stage=manager_update pid=%lu manager=%p mode=%d identity=%d definition=%p",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<void*>(manager), snapshot.mode, snapshot.identity,
        static_cast<void*>(definition.definition));
    write_line(core::log::Level::info, line, length);
}

[[nodiscard]] bool forced_package(std::string_view package,
                                  bool requireReady) noexcept {
    if (!state::activity::forced::override_active()
        || (requireReady && !state::activity::forced::opening_host_ready())) {
        return false;
    }
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::size_t length = forced.packageNameLength <= forced.packageName.size()
                                   ? forced.packageNameLength
                                   : forced.packageName.size();
    return std::string_view(forced.packageName.data(), length) == package;
}

[[nodiscard]] bool forced_towerfall(bool requireReady) noexcept {
    return forced_package("mission_towerfall", requireReady);
}

[[nodiscard]] bool omega_reference_active() noexcept {
    return forced_package(kOmegaPackage, false);
}

[[nodiscard]] std::uint64_t next_binding_timeline() noexcept {
    return g_bindingTimelineSequence.fetch_add(1U, std::memory_order_acq_rel) + 1U;
}

[[nodiscard]] const prelaunch::Profile* configured_prelaunch() noexcept {
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    return prelaunch::configured(forced);
}

[[nodiscard]] std::size_t bounded_package_length(const std::byte* package,
                                                 std::size_t capacity) noexcept {
    std::size_t length = 0;
    __try {
        while (package != nullptr && length < capacity && package[length] != std::byte{}) {
            ++length;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        length = 0;
    }
    return length;
}

[[nodiscard]] bool correct_selection_record(std::byte* state,
                                            const prelaunch::Profile& profile) noexcept {
    bool corrected = false;
    const std::int16_t activity = profile.activity;
    __try {
        // A direct native mission is self-selected (Omega is 299 -> 299). Setting both halves of
        // the tuple lets Destiny resolve the activity definition, type, destination and
        // matchmaking hash from the selected profile when its state-0 producer builds the publication.
        std::memcpy(state + kSelectionSourceOffset, &activity, sizeof activity);
        std::memcpy(state + kSelectionDestinationOffset, &activity, sizeof activity);
        std::memset(state + kSelectionPackageOffset, 0, kSelectionPackageCapacity);
        std::memcpy(state + kSelectionPackageOffset, profile.package.data(), profile.package.size());
        corrected = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        corrected = false;
    }
    return corrected;
}

void call_publication_state0(SelectionPublicationState0 state0,
                             std::byte* descriptor) noexcept {
    __try {
        state0(descriptor);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

[[nodiscard]] bool retain_prelaunch_route(std::byte* owner,
                                          std::byte* publication) noexcept {
    if (publication == nullptr) {
        return false;
    }
    const std::byte* const route = publication - kPublicationRoutePrefixBytes;
    const std::int16_t source = safe_read<std::int16_t>(
        route + 0x22U, static_cast<std::int16_t>(-1));
    const std::int16_t destination = safe_read<std::int16_t>(
        route + 0x24U, static_cast<std::int16_t>(-1));
    const std::size_t packageLength = bounded_package_length(route + 0x70U,
                                                             kSelectionPackageCapacity);
    if (source != static_cast<std::int16_t>(kTowerfallActivity)
        || destination != static_cast<std::int16_t>(kTowerfallActivity)
        || std::string_view(reinterpret_cast<const char*>(route + 0x70U), packageLength)
               != "mission_towerfall"
        || !safe_copy(g_retainedRoute.data(), route, g_retainedRoute.size())) {
        return false;
    }
    std::byte* const manager = safe_read<std::byte*>(
        owner != nullptr ? owner + 0x18U : nullptr, nullptr);
    g_retainedRouteManager.store(manager, std::memory_order_release);
    g_retainedRouteReady.store(true, std::memory_order_release);
    return true;
}

/** Preserve a direct native selection; redirect only an explicitly configured legacy donor launch. */
__declspec(noinline) std::byte* __fastcall selection_launch_state_accessor(
    std::byte* context) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const SelectionLaunchStateAccessor original =
        hooking::await_original(g_selectionLaunchStateOriginal);
    std::byte* const state = original(context);
    if (!call.accepts_side_effects() || state == nullptr) {
        return state;
    }

    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto* const caller = static_cast<const std::byte*>(_ReturnAddress());
    if (image == nullptr || caller != image + kSelectionLaunchStateAccessorReturnRva) {
        return state;
    }

    const std::int16_t source = safe_read<std::int16_t>(
        state + kSelectionSourceOffset, static_cast<std::int16_t>(-1));
    const std::int16_t destinationBefore = safe_read<std::int16_t>(
        state + kSelectionDestinationOffset, static_cast<std::int16_t>(-1));
    const std::size_t nativePackageLength=bounded_package_length(
        state+kSelectionPackageOffset,kSelectionPackageCapacity);
    const std::string_view nativePackage(
        reinterpret_cast<const char*>(state+kSelectionPackageOffset),nativePackageLength);
    if (state::activity::forced::release_haunted_forest_for_native_selection(
            source,destinationBefore,nativePackage)) {
        core::log::write(core::log::Channel::client,core::log::Level::info,
            "ev=haunted_forest_direct stage=native_selection override=released activity=78");
        return state;
    }
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const auto* profile = prelaunch::configured(forced);
    const bool direct = profile && source == profile->activity && destinationBefore == profile->activity
        && state::activity::forced::override_active();
    if (!direct && (!prelaunch::donor(source, destinationBefore)
        || !state::activity::forced::commit_prelaunch_authored_selection(source, destinationBefore, forced))) {
        return state;
    }
    profile = prelaunch::configured(forced);
    const bool corrected = profile != nullptr && (direct || correct_selection_record(state, *profile));
    if (corrected) {
        g_prelaunchPublicationPending.store(profile, std::memory_order_release);
        g_directContractPublished.store(false, std::memory_order_release);
    }

    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=%s stage=selection_contract result=%s caller_rva=0x%llX "
        "source_before=%d source_after=%d destination_before=%d destination_after=%d "
        "package=%.*s contract=self_contained",
        profile != nullptr ? profile->event : "mission_prelaunch",
        corrected ? (direct ? "native_identity_preserved" : "corrected") : "failed",
        static_cast<unsigned long long>(caller - image),
        static_cast<int>(source),
        corrected ? static_cast<int>(profile->activity) : static_cast<int>(source),
        static_cast<int>(destinationBefore),
        corrected ? static_cast<int>(profile->activity) : static_cast<int>(destinationBefore),
        static_cast<int>(forced.packageNameLength), forced.packageName.data());
    write_line(corrected ? core::log::Level::info : core::log::Level::warn, line, length);
    return state;
}

/** Runs Destiny's own state-0 producer, then forwards its complete launch publication unchanged. */
__declspec(noinline) bool __fastcall selection_launch_publisher(
    std::byte* owner,
    std::byte* descriptor) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const SelectionLaunchPublisher original =
        hooking::await_original(g_selectionLaunchPublisherOriginal);
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto* const caller = static_cast<const std::byte*>(_ReturnAddress());
    const bool launcherCall = image != nullptr
                              && caller == image + kSelectionLaunchPublisherReturnRva;
    const auto* profile = call.accepts_side_effects() && launcherCall
        ? g_prelaunchPublicationPending.exchange(nullptr, std::memory_order_acq_rel) : nullptr;
    const bool pending = profile != nullptr;

    std::uint8_t typeBefore = 0U;
    std::uint8_t stateBefore = 0U;
    if (pending && descriptor != nullptr) {
        typeBefore = safe_read<std::uint8_t>(descriptor + 2U, 0U);
        stateBefore = safe_read<std::uint8_t>(descriptor + 3U, 0U);
        const SelectionPublicationState0 state0 =
            g_selectionPublicationState0.load(std::memory_order_acquire);
        if (state0 != nullptr && typeBefore != 0U && stateBefore == 0U) {
            call_publication_state0(state0, descriptor);
        }
    }

    const std::int16_t source = safe_read<std::int16_t>(
        descriptor != nullptr ? descriptor + 0x0AU : nullptr,
        static_cast<std::int16_t>(-1));
    const std::int16_t destination = safe_read<std::int16_t>(
        descriptor != nullptr ? descriptor + 0x0CU : nullptr,
        static_cast<std::int16_t>(-1));
    const std::size_t packageLength = bounded_package_length(
        descriptor != nullptr ? descriptor + kPublicationPackageOffset : nullptr,
        kSelectionPackageCapacity);
    const bool populated = pending && descriptor != nullptr
        && prelaunch::matches(*profile, source, destination,
            {reinterpret_cast<const char*>(descriptor + kPublicationPackageOffset), packageLength});
    const bool published = original(owner, descriptor);

    if (pending) {
        std::byte* const manager = safe_read<std::byte*>(
            owner != nullptr ? owner + 0x18U : nullptr, nullptr);
        const std::int32_t identity = safe_read<std::int32_t>(
            manager != nullptr ? manager + 0x1C7C0U : nullptr, -1);
        const std::int32_t component = safe_read<std::int32_t>(
            manager != nullptr ? manager + 0xE93CU : nullptr, -1);
        const bool accepted = populated && published;
        const bool retained = accepted && profile == &prelaunch::kTowerfall
            && retain_prelaunch_route(owner, descriptor);
        g_directContractPublished.store(accepted && profile == &prelaunch::kTowerfall, std::memory_order_release);
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=%s stage=prelaunch_publication result=%s caller_rva=0x%llX "
            "type=%u state_before=%u state_after=%u source=%d destination=%d package=%.*s "
            "owner=%p manager=%p identity=%d component_index=%d native_publish=%u "
            "route_retained=%u expected_activity_hash=0x%08X",
            profile->event,
            accepted ? "accepted" : "rejected",
            static_cast<unsigned long long>(caller - image),
            static_cast<unsigned int>(typeBefore),
            static_cast<unsigned int>(stateBefore),
            static_cast<unsigned int>(
                safe_read<std::uint8_t>(descriptor != nullptr ? descriptor + 3U : nullptr, 0U)),
            static_cast<int>(source),
            static_cast<int>(destination),
            static_cast<int>(packageLength),
            descriptor != nullptr
                ? reinterpret_cast<const char*>(descriptor + kPublicationPackageOffset)
                : "",
            static_cast<void*>(owner),
            static_cast<void*>(manager),
            identity,
            component,
            published ? 1U : 0U,
            retained ? 1U : 0U,
            profile->investmentHash);
        write_line(accepted ? core::log::Level::info : core::log::Level::warn, line, length);

        if (retained) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::info,
                "ev=towerfall_executor stage=prelaunch_route result=retained exposure=isolated_until_manager_retry");
        }
    }
    return published;
}

void try_install_prelaunch_contract() noexcept {
    const auto* profile = g_requestedPrelaunchProfile.load(std::memory_order_acquire);
    if (profile == nullptr) { profile = configured_prelaunch(); }
    if (g_handles[selectionLaunchStateAccessorIndex].attached || profile == nullptr) {
        return;
    }
    const std::uint64_t now = GetTickCount64();
    if (now < g_nextPrelaunchInstallTick.load(std::memory_order_acquire)) {
        return;
    }
    bool expected = false;
    if (!g_prelaunchInstallInProgress.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;
    }
    g_nextPrelaunchInstallTick.store(now + kPrelaunchInstallRetryMs,
                                     std::memory_order_release);

    LateInstallGuard lateInstall;
    bool installed = false;
    if (lateInstall.accepted()) {
        auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
        std::byte* const accessor =
            image != nullptr ? image + kSelectionLaunchStateAccessorRva : nullptr;
        std::byte* const publisher =
            image != nullptr ? image + kSelectionLaunchPublisherRva : nullptr;
        std::byte* const pump =
            scan_main_image_unique(kSelectionPumpSignature, "towerfall_selection_pump");
        std::byte* const state0 =
            pump != nullptr ? pump + kSelectionPublicationState0Offset : nullptr;
        if (prefix_matches(accessor, kSelectionLaunchStateAccessorPrefix)
            && prefix_matches(publisher, kSelectionLaunchPublisherPrefix)
            && prefix_matches(state0, kSelectionPublicationState0Prefix)) {
            const std::array<hooking::detour::Spec, 2> specs{
                hooking::detour::Spec{
                    accessor, reinterpret_cast<void*>(&selection_launch_state_accessor)},
                hooking::detour::Spec{
                    publisher, reinterpret_cast<void*>(&selection_launch_publisher)},
            };
            auto outputs = std::span(g_handles).subspan(selectionLaunchStateAccessorIndex, 2U);
            installed = hooking::detour::install(specs, outputs);
            if (installed) {
                hooking::publish_original(
                    g_selectionLaunchStateOriginal,
                    reinterpret_cast<SelectionLaunchStateAccessor>(
                        g_handles[selectionLaunchStateAccessorIndex].original));
                hooking::publish_original(
                    g_selectionLaunchPublisherOriginal,
                    reinterpret_cast<SelectionLaunchPublisher>(
                        g_handles[selectionLaunchPublisherIndex].original));
                g_selectionPublicationState0.store(
                    reinterpret_cast<SelectionPublicationState0>(state0),
                    std::memory_order_release);
            }
        }
    }
    const std::uint32_t attempt =
        g_prelaunchInstallAttempts.fetch_add(1U, std::memory_order_acq_rel) + 1U;
    if (installed || report_attempt(attempt)) {
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=%s stage=install attempt=%u result=%s "
            "mode=native_prelaunch_contract activity=%d investment_hash=0x%08X "
            "definition_hash=0x%08X activity_tag=0x%08X launch_descriptor_tag=0x%08X",
            profile->event,
            attempt,
            installed ? "ok" : "deferred",
            static_cast<int>(profile->activity),
            profile->investmentHash,
            profile->packageHash,
            profile->activityTag,
            profile->launchTag);
        write_line(installed ? core::log::Level::info : core::log::Level::warn, line, length);
    }
    g_prelaunchInstallInProgress.store(false, std::memory_order_release);
}

[[nodiscard]] std::byte* call_route_lookup(RouteDescriptorLookup lookup,
                                           std::byte** managerOut) noexcept {
    std::byte* descriptor = nullptr;
    __try {
        descriptor = lookup != nullptr ? lookup(0, managerOut) : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        descriptor = nullptr;
        if (managerOut != nullptr) {
            *managerOut = nullptr;
        }
    }
    return descriptor;
}

[[nodiscard]] RouteSnapshot snapshot_route() noexcept {
    RouteSnapshot route{};
    const RouteDescriptorLookup lookup = g_routeLookup.load(std::memory_order_acquire);
    route.descriptor = call_route_lookup(lookup, &route.manager);
    route.word0 = safe_read<std::uint32_t>(route.descriptor, 0U);
    route.word4 = safe_read<std::uint32_t>(
        route.descriptor != nullptr ? route.descriptor + 0x04U : nullptr, 0U);
    route.word8 = safe_read<std::uint32_t>(
        route.descriptor != nullptr ? route.descriptor + 0x08U : nullptr, 0U);
    route.wordC = safe_read<std::uint32_t>(
        route.descriptor != nullptr ? route.descriptor + 0x0CU : nullptr, 0U);
    route.word10 = safe_read<std::uint32_t>(
        route.descriptor != nullptr ? route.descriptor + 0x10U : nullptr, 0U);
    route.source = safe_read<std::int16_t>(
        route.descriptor != nullptr ? route.descriptor + 0x22U : nullptr,
        static_cast<std::int16_t>(-1));
    route.destination = safe_read<std::int16_t>(
        route.descriptor != nullptr ? route.descriptor + 0x24U : nullptr,
        static_cast<std::int16_t>(-1));
    route.selector = safe_read<std::uint8_t>(
        route.descriptor != nullptr ? route.descriptor + 0xA0U : nullptr, 0U);
    while (route.descriptor != nullptr
           && route.packageLength + 1U < route.package.size()) {
        const char value = safe_read<char>(route.descriptor + 0x70U + route.packageLength, '\0');
        if (value == '\0') {
            break;
        }
        route.package[route.packageLength++] = value;
    }
    return route;
}

[[nodiscard]] bool is_towerfall_route(const RouteSnapshot& route) noexcept {
    return route.descriptor != nullptr
           && (static_cast<std::uint16_t>(route.source) == kTowerfallActivity
               || static_cast<std::uint16_t>(route.source) == kChosenActivity)
           && static_cast<std::uint16_t>(route.destination) == kTowerfallActivity
           && std::string_view(route.package.data(), route.packageLength)
                  == "mission_towerfall";
}

[[nodiscard]] std::uint64_t route_signature(const RouteSnapshot& route) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (std::size_t index = 0; index < route.packageLength; ++index) {
        hash ^= static_cast<std::uint8_t>(route.package[index]);
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<std::uint16_t>(route.source);
    hash *= 1099511628211ULL;
    hash ^= static_cast<std::uint16_t>(route.destination);
    hash *= 1099511628211ULL;
    hash ^= route.selector;
    hash *= 1099511628211ULL;
    hash ^= route.word10;
    return hash;
}

[[nodiscard]] std::uintptr_t address_rva(const void* address) noexcept {
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    auto* const caller = static_cast<const std::byte*>(address);
    return image != nullptr && caller >= image
               ? static_cast<std::uintptr_t>(caller - image)
               : 0U;
}

void report_route(const char* stage,
                  std::uint64_t sequence,
                  std::uint32_t attempt,
                  const RouteSnapshot& route,
                  bool match) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=%s sequence=%llu attempt=%u result=%s descriptor=%p "
        "route_manager=%p source=%d destination=%d selector=%u package=%.*s "
        "d0=0x%08X d4=0x%08X d8=0x%08X dc=0x%08X d10=0x%08X",
        stage,
        static_cast<unsigned long long>(sequence),
        attempt,
        match ? "target" : "mismatch",
        static_cast<void*>(route.descriptor),
        static_cast<void*>(route.manager),
        static_cast<int>(route.source),
        static_cast<int>(route.destination),
        static_cast<unsigned int>(route.selector),
        static_cast<int>(route.packageLength),
        route.package.data(),
        route.word0,
        route.word4,
        route.word8,
        route.wordC,
        route.word10);
    const bool retryMismatch = std::string_view(stage) == "manager_retry_gate" && !match;
    write_line(retryMismatch ? core::log::Level::warn : core::log::Level::info,
               line,
               length);
}

void log_omega_producer_event(const char* phase,
                              std::uint64_t timeline,
                              std::uint64_t sequence,
                              std::uintptr_t callerRva,
                              const RouteSnapshot& route,
                              bool dispatched,
                              const IdentityDefinitionSnapshot& definition) noexcept {
    const std::int32_t identity = safe_read<std::int32_t>(
        route.manager != nullptr ? route.manager + 0x1C7C0U : nullptr, -1);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=launch_producer scope=omega_reference timeline=%llu "
        "phase=%s sequence=%llu caller_rva=0x%llX authored_dispatch=%u descriptor=%p "
        "route_manager=%p identity=%d source=%d destination=%d selector=%u package=%.*s "
        "d0=0x%08X d4=0x%08X d8=0x%08X dc=0x%08X d10=0x%08X "
        "definition=%p context=%p activity=%d enabled=%u pending=%u "
        "current_hash=0x%016llX pending_hash=0x%016llX",
        static_cast<unsigned long long>(timeline),
        phase,
        static_cast<unsigned long long>(sequence),
        static_cast<unsigned long long>(callerRva),
        dispatched ? 1U : 0U,
        static_cast<void*>(route.descriptor),
        static_cast<void*>(route.manager),
        identity,
        static_cast<int>(route.source),
        static_cast<int>(route.destination),
        static_cast<unsigned int>(route.selector),
        static_cast<int>(route.packageLength),
        route.package.data(),
        route.word0,
        route.word4,
        route.word8,
        route.wordC,
        route.word10,
        static_cast<void*>(definition.definition),
        definition.context,
        definition.activity,
        static_cast<unsigned int>(definition.enabled),
        static_cast<unsigned int>(definition.pending),
        static_cast<unsigned long long>(definition.currentHash),
        static_cast<unsigned long long>(definition.pendingHash));
    write_line(core::log::Level::info, line, length);
}

void log_omega_manager_call(const char* phase,
                            std::uint64_t timeline,
                            std::uintptr_t callerRva,
                            std::byte* manager,
                            const ManagerSnapshot& state,
                            const IdentityDefinitionSnapshot& definition) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=manager_update_call scope=omega_reference timeline=%llu "
        "phase=%s caller_rva=0x%llX manager=%p identity=%d mode=%d selected=%d "
        "registered=%d active=%d activity=%d lifecycle=%d flags=0x%08X definition=%p "
        "context=%p definition_activity=%d enabled=%u pending=%u "
        "current_hash=0x%016llX pending_hash=0x%016llX",
        static_cast<unsigned long long>(timeline),
        phase,
        static_cast<unsigned long long>(callerRva),
        static_cast<void*>(manager),
        state.identity,
        state.mode,
        state.selected,
        state.registered,
        state.active,
        state.activity,
        state.lifecycle,
        state.flags,
        static_cast<void*>(definition.definition),
        definition.context,
        definition.activity,
        static_cast<unsigned int>(definition.enabled),
        static_cast<unsigned int>(definition.pending),
        static_cast<unsigned long long>(definition.currentHash),
        static_cast<unsigned long long>(definition.pendingHash));
    write_line(core::log::Level::info, line, length);
}

__declspec(noinline) std::byte* __fastcall route_descriptor_lookup(
    std::int32_t selector,
    std::byte** managerOut) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const RouteDescriptorLookup original = hooking::await_original(g_routeLookupOriginal);
    std::byte* descriptor = original(selector, managerOut);
    if (!call.accepts_side_effects() || descriptor != nullptr || selector != 0
        || !g_retryInvocation
        || !g_routeFallbackActive.load(std::memory_order_acquire)
        || !g_retainedRouteReady.load(std::memory_order_acquire)
        || !forced_towerfall(false)) {
        return descriptor;
    }
    if (managerOut != nullptr) {
        *managerOut = g_retainedRouteManager.load(std::memory_order_acquire);
    }
    return g_retainedRoute.data();
}

void log_identity_trace(const char* operation,
                        const char* phase,
                        const char* scope,
                        std::uint64_t timeline,
                        std::uint64_t callSequence,
                        std::int32_t identity,
                        std::uintptr_t callerRva,
                        const void* descriptor,
                        const IdentityDefinitionSnapshot& before,
                        const IdentityDefinitionSnapshot& after,
                        std::int32_t event,
                        std::uint64_t lifecycleBefore = UINT64_MAX,
                        std::uint64_t lifecycleAfter = UINT64_MAX) noexcept {
    std::array<std::uint64_t, kIdentityDescriptorBytes / sizeof(std::uint64_t)> words{};
    const auto* const bytes = static_cast<const std::byte*>(descriptor);
    for (std::size_t index = 0; index < words.size(); ++index) {
        words[index] = safe_read<std::uint64_t>(
            bytes != nullptr ? bytes + index * sizeof(std::uint64_t) : nullptr, 0U);
    }
    std::size_t descriptorNonzero = 0U;
    const std::uint64_t descriptorHash = descriptor != nullptr
                                             ? hash_bytes(bytes,
                                                          kIdentityDescriptorBytes,
                                                          descriptorNonzero)
                                             : 0U;
    std::array<char, core::log::kLineCapacity> line{};
    int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=identity_trace scope=%s timeline=%llu call=%llu "
        "phase=%s op=%s producer_sequence=%llu caller_rva=0x%llX identity=%d event=%d "
        "replay=%u descriptor=%p descriptor_hash=0x%016llX descriptor_nonzero=%u "
        "lifecycle_before=0x%016llX lifecycle_after=0x%016llX",
        scope,
        static_cast<unsigned long long>(timeline),
        static_cast<unsigned long long>(callSequence),
        phase,
        operation,
        static_cast<unsigned long long>(g_activeProducerSequence),
        static_cast<unsigned long long>(callerRva),
        identity,
        event,
        g_identityReplayInvocation ? 1U : 0U,
        descriptor,
        static_cast<unsigned long long>(descriptorHash),
        static_cast<unsigned int>(descriptorNonzero),
        static_cast<unsigned long long>(lifecycleBefore),
        static_cast<unsigned long long>(lifecycleAfter));
    write_line(core::log::Level::info, line, length);

    if (descriptor != nullptr) {
        length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=identity_descriptor scope=%s timeline=%llu call=%llu "
            "phase=%s op=%s part=1 words=%016llX,%016llX,%016llX,%016llX,%016llX,%016llX,%016llX,%016llX",
            scope,
            static_cast<unsigned long long>(timeline),
            static_cast<unsigned long long>(callSequence),
            phase,
            operation,
        static_cast<unsigned long long>(words[0]),
        static_cast<unsigned long long>(words[1]),
        static_cast<unsigned long long>(words[2]),
        static_cast<unsigned long long>(words[3]),
        static_cast<unsigned long long>(words[4]),
        static_cast<unsigned long long>(words[5]),
        static_cast<unsigned long long>(words[6]),
            static_cast<unsigned long long>(words[7]));
        write_line(core::log::Level::info, line, length);
        length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=identity_descriptor scope=%s timeline=%llu call=%llu "
            "phase=%s op=%s part=2 words=%016llX,%016llX,%016llX,%016llX,%016llX,%016llX,%016llX,%016llX",
            scope,
            static_cast<unsigned long long>(timeline),
            static_cast<unsigned long long>(callSequence),
            phase,
            operation,
        static_cast<unsigned long long>(words[8]),
        static_cast<unsigned long long>(words[9]),
        static_cast<unsigned long long>(words[10]),
        static_cast<unsigned long long>(words[11]),
        static_cast<unsigned long long>(words[12]),
        static_cast<unsigned long long>(words[13]),
        static_cast<unsigned long long>(words[14]),
            static_cast<unsigned long long>(words[15]));
        write_line(core::log::Level::info, line, length);
    }

    length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=identity_definition scope=%s timeline=%llu call=%llu "
        "phase=%s op=%s definition=%p flags_before=0x%08X flags_after=0x%08X "
        "state_before=0x%04X state_after=0x%04X context_before=%p context_after=%p "
        "activity_before=%d activity_after=%d request_before=0x%04X request_after=0x%04X "
        "enabled_before=%u enabled_after=%u pending_before=%u pending_after=%u "
        "current_hash_before=0x%016llX current_hash_after=0x%016llX "
        "current_nonzero_before=%u current_nonzero_after=%u pending_hash_before=0x%016llX "
        "pending_hash_after=0x%016llX pending_nonzero_before=%u pending_nonzero_after=%u",
        scope,
        static_cast<unsigned long long>(timeline),
        static_cast<unsigned long long>(callSequence),
        phase,
        operation,
        static_cast<void*>(before.definition != nullptr ? before.definition : after.definition),
        before.flags,
        after.flags,
        static_cast<unsigned int>(before.state),
        static_cast<unsigned int>(after.state),
        before.context,
        after.context,
        before.activity,
        after.activity,
        static_cast<unsigned int>(before.request),
        static_cast<unsigned int>(after.request),
        static_cast<unsigned int>(before.enabled),
        static_cast<unsigned int>(after.enabled),
        static_cast<unsigned int>(before.pending),
        static_cast<unsigned int>(after.pending),
        static_cast<unsigned long long>(before.currentHash),
        static_cast<unsigned long long>(after.currentHash),
        static_cast<unsigned int>(before.currentNonzero),
        static_cast<unsigned int>(after.currentNonzero),
        static_cast<unsigned long long>(before.pendingHash),
        static_cast<unsigned long long>(after.pendingHash),
        static_cast<unsigned int>(before.pendingNonzero),
        static_cast<unsigned int>(after.pendingNonzero));
    write_line(core::log::Level::info, line, length);
}

__declspec(noinline) void __fastcall identity_request_observer(
    std::int32_t identity,
    const void* descriptor) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const IdentityRequest original = hooking::await_original(g_identityRequestOriginal);
    const IdentityDefinitionSnapshot before = snapshot_identity_definition(identity);
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    const std::uint64_t callSequence =
        g_identityTraceSequence.fetch_add(1U, std::memory_order_acq_rel) + 1U;
    const bool omegaReference = omega_reference_active();
    const bool trace = call.accepts_side_effects()
                       && (omegaReference || identity == kTowerfallScriptIdentity
                           || callSequence <= 128U);
    const char* const scope = omegaReference ? "omega_reference" : "general";
    if (trace) {
        log_identity_trace("identity_request",
                           "enter",
                           scope,
                           next_binding_timeline(),
                           callSequence,
                           identity,
                           callerRva,
                           descriptor,
                           before,
                           before,
                           -1);
    }
    original(identity, descriptor);
    if (!call.accepts_side_effects()) {
        return;
    }
    const IdentityDefinitionSnapshot after = snapshot_identity_definition(identity);
    if (trace) {
        log_identity_trace("identity_request",
                           "exit",
                           scope,
                           next_binding_timeline(),
                           callSequence,
                           identity,
                           callerRva,
                           descriptor,
                           before,
                           after,
                           -1);
    }
}

__declspec(noinline) void __fastcall manager_event_publish_observer(
    std::byte* manager,
    std::int32_t event) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const ManagerEventPublish original = hooking::await_original(g_managerEventPublishOriginal);
    const std::int32_t identity = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1C7C0U : nullptr, -1);
    const IdentityDefinitionSnapshot before = snapshot_identity_definition(identity);
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    const std::uint64_t callSequence =
        g_identityTraceSequence.fetch_add(1U, std::memory_order_acq_rel) + 1U;
    const bool omegaReference = omega_reference_active();
    const bool trace = call.accepts_side_effects()
                       && (omegaReference || identity == kTowerfallScriptIdentity
                           || callSequence <= 128U);
    const char* const scope = omegaReference ? "omega_reference" : "general";
    if (trace) {
        log_identity_trace("manager_event_publish",
                           "enter",
                           scope,
                           next_binding_timeline(),
                           callSequence,
                           identity,
                           callerRva,
                           nullptr,
                           before,
                           before,
                           event);
    }
    original(manager, event);
    if (!call.accepts_side_effects()) {
        return;
    }
    const IdentityDefinitionSnapshot after = snapshot_identity_definition(identity);
    if (trace) {
        log_identity_trace("manager_event_publish",
                           "exit",
                           scope,
                           next_binding_timeline(),
                           callSequence,
                           identity,
                           callerRva,
                           nullptr,
                           before,
                           after,
                           event);
    }
}

__declspec(noinline) void __fastcall manager_event_begin_observer(
    std::byte* manager,
    std::int32_t event) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const ManagerEventBegin original = hooking::await_original(g_managerEventBeginOriginal);
    const std::int32_t identity = safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1C7C0U : nullptr, -1);
    const IdentityDefinitionSnapshot before = snapshot_identity_definition(identity);
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    const std::uint64_t lifecycleBefore = safe_read<std::uint64_t>(
        manager != nullptr ? manager + 0x1C888U : nullptr, UINT64_MAX);
    const std::uint64_t callSequence =
        g_identityTraceSequence.fetch_add(1U, std::memory_order_acq_rel) + 1U;
    const bool omegaReference = omega_reference_active();
    const bool trace = call.accepts_side_effects()
                       && (omegaReference || identity == kTowerfallScriptIdentity
                           || callSequence <= 128U);
    const char* const scope = omegaReference ? "omega_reference" : "general";
    if (trace) {
        log_identity_trace("manager_event_begin",
                           "enter",
                           scope,
                           next_binding_timeline(),
                           callSequence,
                           identity,
                           callerRva,
                           nullptr,
                           before,
                           before,
                           event,
                           lifecycleBefore,
                           lifecycleBefore);
    }
    original(manager, event);
    if (!call.accepts_side_effects()) {
        return;
    }
    const IdentityDefinitionSnapshot after = snapshot_identity_definition(identity);
    const std::uint64_t lifecycleAfter = safe_read<std::uint64_t>(
        manager != nullptr ? manager + 0x1C888U : nullptr, UINT64_MAX);
    if (trace) {
        log_identity_trace("manager_event_begin",
                           "exit",
                           scope,
                           next_binding_timeline(),
                           callSequence,
                           identity,
                           callerRva,
                           nullptr,
                           before,
                           after,
                           event,
                           lifecycleBefore,
                           lifecycleAfter);
    }
}

__declspec(noinline) void __fastcall launch_producer() noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const LaunchProducer original = hooking::await_original(g_launchProducerOriginal);
    if (!call.accepts_side_effects()) {
        original();
        return;
    }

    const RouteSnapshot route = snapshot_route();
    const bool towerfallRoute = is_towerfall_route(route);
    const bool retry = g_retryInvocation;
    const bool omegaReference = omega_reference_active();
    const std::uint32_t omegaEvent = omegaReference
                                         ? g_omegaProducerEvents.fetch_add(
                                               1U, std::memory_order_acq_rel)
                                               + 1U
                                         : 0U;
    const bool traceOmega = omegaReference && omegaEvent <= kMaxOmegaProducerEvents;
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    const std::uint64_t sequence =
        g_producerSequence.fetch_add(1U, std::memory_order_acq_rel) + 1U;
    const std::uint64_t previousSequence = g_activeProducerSequence;
    const bool previousDispatched = g_activeProducerDispatched;
    g_activeProducerSequence = sequence;
    g_activeProducerDispatched = false;

    if (traceOmega) {
        const std::int32_t identity = safe_read<std::int32_t>(
            route.manager != nullptr ? route.manager + 0x1C7C0U : nullptr, -1);
        log_omega_producer_event("enter",
                                 next_binding_timeline(),
                                 sequence,
                                 callerRva,
                                 route,
                                 false,
                                 snapshot_identity_definition(identity));
    }

    const std::uint32_t attempt = retry
                                      ? g_retryAttempts.load(std::memory_order_acquire)
                                      : 0U;
    if ((retry && report_attempt(attempt)) || (!retry && sequence <= 128U)) {
        report_route(retry ? "producer_retry_enter" : "producer_reference_enter",
                     sequence,
                     attempt,
                     route,
                     towerfallRoute);
    }
    original();
    const bool dispatched = g_activeProducerDispatched;
    if (traceOmega) {
        const RouteSnapshot routeAfter = snapshot_route();
        const std::int32_t identityAfter = safe_read<std::int32_t>(
            routeAfter.manager != nullptr ? routeAfter.manager + 0x1C7C0U : nullptr, -1);
        log_omega_producer_event("exit",
                                 next_binding_timeline(),
                                 sequence,
                                 callerRva,
                                 routeAfter,
                                 dispatched,
                                 snapshot_identity_definition(identityAfter));
    }
    if (dispatched) {
        g_lastSuccessfulProducer.store(sequence, std::memory_order_release);
    }

    if (!retry && !towerfallRoute && dispatched) {
        bool expected = false;
        if (g_referenceCaptured.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
            std::array<char, core::log::kLineCapacity> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=towerfall_executor stage=normal_reference result=captured sequence=%llu "
                "producer_rva=0x%llX dispatch_rva=0x%llX source=%d destination=%d package=%.*s",
                static_cast<unsigned long long>(sequence),
                static_cast<unsigned long long>(kLaunchProducerRva),
                static_cast<unsigned long long>(kAuthoredLaunchDispatchRva),
                static_cast<int>(route.source),
                static_cast<int>(route.destination),
                static_cast<int>(route.packageLength),
                route.package.data());
            write_line(core::log::Level::info, line, length);
        }
    }
    if ((retry && report_attempt(attempt)) || (sequence <= 128U && dispatched)) {
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=producer_exit sequence=%llu attempt=%u "
            "authored_dispatch=%u retry=%u",
            static_cast<unsigned long long>(sequence),
            attempt,
            dispatched ? 1U : 0U,
            retry ? 1U : 0U);
        write_line(core::log::Level::info, line, length);
    }

    g_activeProducerSequence = previousSequence;
    g_activeProducerDispatched = previousDispatched;
}

__declspec(noinline) void __fastcall authored_launch_dispatch(
    std::int32_t launchMode,
    std::int32_t selectionType,
    const std::byte* selection,
    const void* handle,
    std::uint32_t option) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const AuthoredLaunchDispatch original = hooking::await_original(g_authoredLaunchOriginal);
    const bool omegaReference = omega_reference_active();
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    if (call.accepts_side_effects()) {
        if (g_activeProducerSequence != 0U) {
            g_activeProducerDispatched = true;
            if (g_retryInvocation) {
                g_lastSuccessfulRetryProducer.store(g_activeProducerSequence,
                                                     std::memory_order_release);
            }
        }
        const std::uint32_t attempt = g_retryInvocation
                                          ? g_retryAttempts.load(std::memory_order_acquire)
                                          : 0U;
        if (!g_retryInvocation || report_attempt(attempt)) {
            std::array<char, core::log::kLineCapacity> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=towerfall_executor stage=authored_dispatch scope=%s timeline=%llu phase=enter "
                "sequence=%llu caller_rva=0x%llX "
                "launch_mode=%d selection_type=%d selection=%p s0=0x%08X s4=0x%08X "
                "s8=0x%08X sc=0x%08X handle=%p option=%u retry=%u",
                omegaReference ? "omega_reference" : "general",
                static_cast<unsigned long long>(
                    omegaReference ? next_binding_timeline() : 0U),
                static_cast<unsigned long long>(g_activeProducerSequence),
                static_cast<unsigned long long>(callerRva),
                launchMode,
                selectionType,
                static_cast<const void*>(selection),
                safe_read<std::uint32_t>(selection, 0U),
                safe_read<std::uint32_t>(selection != nullptr ? selection + 4U : nullptr, 0U),
                safe_read<std::uint32_t>(selection != nullptr ? selection + 8U : nullptr, 0U),
                safe_read<std::uint32_t>(selection != nullptr ? selection + 12U : nullptr, 0U),
                handle,
                option,
                g_retryInvocation ? 1U : 0U);
            write_line(core::log::Level::info, line, length);
        }
    }
    original(launchMode, selectionType, selection, handle, option);
    if (call.accepts_side_effects() && omegaReference) {
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=authored_dispatch scope=omega_reference timeline=%llu "
            "phase=exit sequence=%llu caller_rva=0x%llX launch_mode=%d selection_type=%d",
            static_cast<unsigned long long>(next_binding_timeline()),
            static_cast<unsigned long long>(g_activeProducerSequence),
            static_cast<unsigned long long>(callerRva),
            launchMode,
            selectionType);
        write_line(core::log::Level::info, line, length);
    }
}

/**
 * Publishes Towerfall's live activity-host descriptor through the same native identity producer
 * used by lifecycle stage 1. The stage gateway itself remains disabled: native code owns the
 * descriptor copy, definition flags, and event-10 publication, while subsequent manager updates
 * decide whether a component can be selected and dispatched.
 */
void attempt_native_identity_binding(std::byte* manager) noexcept {
    if (manager == nullptr || g_identityBindingPublished.load(std::memory_order_acquire)
        || g_dispatched.load(std::memory_order_acquire)
        || !g_directContractPublished.load(std::memory_order_acquire)
        || !forced_towerfall(false)
        || safe_read<std::int32_t>(manager + 0x1C7C0U, -1)
               != kTowerfallScriptIdentity
        || safe_read<std::int32_t>(manager + 0x1C820U, -1) != 2) {
        return;
    }

    const std::uint64_t now = GetTickCount64();
    if (now < g_nextIdentityBindingTick.load(std::memory_order_acquire)) {
        return;
    }
    bool expected = false;
    if (!g_identityBindingInProgress.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;
    }
    g_nextIdentityBindingTick.store(now + kIdentityBindingRetryMs,
                                    std::memory_order_release);
    const std::uint32_t attempt =
        g_identityBindingAttempts.fetch_add(1U, std::memory_order_acq_rel) + 1U;

    std::array<std::byte, kIdentityDescriptorBytes> joinDescriptor{};
    std::int32_t region = -1;
    std::uint64_t hostSession = 0U;
    std::uint32_t generation = 0U;
    const bool descriptorReady = retail_log::snapshot_gameplay_join_descriptor(
        joinDescriptor, region, hostSession, generation);
    if (!descriptorReady || hostSession == 0U || generation == 0U) {
        if (report_attempt(attempt)) {
            std::array<char, core::log::kLineCapacity> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=towerfall_executor stage=identity_binding attempt=%u result=wait "
                "reason=activity_host_descriptor manager=%p identity=1 lifecycle=2 "
                "manual_lifecycle_event=disabled",
                attempt,
                static_cast<void*>(manager));
            write_line(core::log::Level::info, line, length);
        }
        g_identityBindingInProgress.store(false, std::memory_order_release);
        return;
    }

    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    std::byte* const definitionTarget =
        image != nullptr ? image + kIdentityDefinitionRva : nullptr;
    const IdentityRequest identityRequest =
        g_identityRequestEntry.load(std::memory_order_acquire);
    const ManagerEventPublish managerEventPublish =
        g_managerEventPublishEntry.load(std::memory_order_acquire);
    const ManagerEventBegin managerEventBegin =
        g_managerEventBeginEntry.load(std::memory_order_acquire);
    if (!prefix_matches(definitionTarget, kIdentityDefinitionPrefix)
        || identityRequest == nullptr || managerEventPublish == nullptr
        || managerEventBegin == nullptr) {
        if (report_attempt(attempt)) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::error,
                "ev=towerfall_executor stage=identity_binding result=fail reason=pinned_target_validation manual_lifecycle_event=disabled");
        }
        g_identityBindingInProgress.store(false, std::memory_order_release);
        return;
    }

    std::byte* definition = nullptr;
    const auto identityDefinition = reinterpret_cast<IdentityDefinition>(definitionTarget);
    __try {
        definition = identityDefinition(kTowerfallScriptIdentity);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        definition = nullptr;
    }
    if (definition == nullptr) {
        g_identityBindingInProgress.store(false, std::memory_order_release);
        return;
    }

    const IdentityDefinitionSnapshot definitionSnapshot =
        snapshot_identity_definition(kTowerfallScriptIdentity);
    const bool activated = definitionSnapshot.context != nullptr
                           || definitionSnapshot.activity >= 0
                           || definitionSnapshot.enabled != 0U;
    if (g_identityBindingQueued.load(std::memory_order_acquire)) {
        if (activated) {
            g_identityBindingPublished.store(true, std::memory_order_release);
            g_armed.store(true, std::memory_order_release);
            std::array<char, core::log::kLineCapacity> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=towerfall_executor stage=identity_binding attempt=%u result=activated manager=%p identity=1 context=%p activity=%d enabled=%u pending=%u current_hash=0x%016llX current_nonzero=%u",
                attempt,
                static_cast<void*>(manager),
                definitionSnapshot.context,
                definitionSnapshot.activity,
                static_cast<unsigned int>(definitionSnapshot.enabled),
                static_cast<unsigned int>(definitionSnapshot.pending),
                static_cast<unsigned long long>(definitionSnapshot.currentHash),
                static_cast<unsigned int>(definitionSnapshot.currentNonzero));
            write_line(core::log::Level::info, line, length);
        }
        g_identityBindingInProgress.store(false, std::memory_order_release);
        return;
    }

    std::array<std::byte, kIdentityDescriptorBytes> descriptor{};
    if (!safe_copy(descriptor.data(), definition + 0x57CU, descriptor.size())) {
        g_identityBindingInProgress.store(false, std::memory_order_release);
        return;
    }
    std::size_t authoredNonzero = 0U;
    const std::uint64_t authoredHash = hash_bytes(descriptor.data(),
                                                  descriptor.size(),
                                                  authoredNonzero);
    if (authoredNonzero == 0U) {
        if (report_attempt(attempt)) {
            std::array<char, core::log::kLineCapacity> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=towerfall_executor stage=identity_binding attempt=%u result=wait reason=native_identity_descriptor manager=%p identity=1 definition=%p join_generation=%u join_hash=0x%016llX",
                attempt,
                static_cast<void*>(manager),
                static_cast<void*>(definition),
                generation,
                static_cast<unsigned long long>(descriptor_hash(joinDescriptor)));
            write_line(core::log::Level::info, line, length);
        }
        g_identityBindingInProgress.store(false, std::memory_order_release);
        return;
    }

    const std::uint32_t flagsBefore = safe_read<std::uint32_t>(definition + 0x04U, 0U);
    const std::uint8_t enabledBefore = safe_read<std::uint8_t>(definition + 0x94CU, 0U);
    const std::uint8_t pendingBefore = safe_read<std::uint8_t>(definition + 0x94DU, 0U);
    const void* const contextBefore = safe_read<const void*>(definition + 0x18U, nullptr);
    const std::int32_t activityBefore =
        safe_read<std::int32_t>(definition + 0x24U, -1);
    const std::uint64_t lifecycleBeginBefore =
        safe_read<std::uint64_t>(manager + 0x1C888U, UINT64_MAX);

    bool returned = false;
    __try {
        if (lifecycleBeginBefore == UINT64_MAX) {
            managerEventBegin(manager, 0);
        }
        g_identityReplayInvocation = true;
        identityRequest(kTowerfallScriptIdentity, descriptor.data());
        managerEventPublish(manager, kIdentityDescriptorPublishedEvent);
        g_identityReplayInvocation = false;
        returned = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_identityReplayInvocation = false;
        returned = false;
    }

    const std::uint32_t flagsAfter = safe_read<std::uint32_t>(definition + 0x04U, 0U);
    const std::uint8_t enabledAfter = safe_read<std::uint8_t>(definition + 0x94CU, 0U);
    const std::uint8_t pendingAfter = safe_read<std::uint8_t>(definition + 0x94DU, 0U);
    const void* const contextAfter = safe_read<const void*>(definition + 0x18U, nullptr);
    const std::int32_t activityAfter = safe_read<std::int32_t>(definition + 0x24U, -1);
    const std::uint64_t lifecycleBeginAfter =
        safe_read<std::uint64_t>(manager + 0x1C888U, UINT64_MAX);
    const bool published = returned
                           && (contextAfter != nullptr || activityAfter >= 0
                               || enabledAfter != 0U);
    const bool queued = returned && !published && pendingAfter != 0U;
    if (published) {
        g_identityBindingPublished.store(true, std::memory_order_release);
        g_identityBindingDescriptorGeneration.store(generation, std::memory_order_release);
        g_armed.store(true, std::memory_order_release);
        g_nextRetryTick.store(0U, std::memory_order_release);
    } else if (queued) {
        g_identityBindingQueued.store(true, std::memory_order_release);
        g_armed.store(true, std::memory_order_release);
        g_nextRetryTick.store(0U, std::memory_order_release);
    }

    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=identity_binding attempt=%u result=%s manager=%p "
        "identity=1 descriptor_source=definition_current descriptor_generation=%u descriptor_hash=0x%016llX descriptor_nonzero=%u region=%d "
        "host_session=0x%016llX event=10 lifecycle_begin_before=0x%llX "
        "lifecycle_begin_after=0x%llX flags_before=0x%08X flags_after=0x%08X "
        "enabled_before=%u enabled_after=%u pending_before=%u pending_after=%u "
        "context_before=%p context_after=%p activity_before=%d activity_after=%d "
        "manual_lifecycle_event=disabled",
        attempt,
        published ? "published" : (queued ? "queued" : (returned ? "rejected" : "exception")),
        static_cast<void*>(manager),
        generation,
        static_cast<unsigned long long>(authoredHash),
        static_cast<unsigned int>(authoredNonzero),
        region,
        static_cast<unsigned long long>(hostSession),
        static_cast<unsigned long long>(lifecycleBeginBefore),
        static_cast<unsigned long long>(lifecycleBeginAfter),
        flagsBefore,
        flagsAfter,
        static_cast<unsigned int>(enabledBefore),
        static_cast<unsigned int>(enabledAfter),
        static_cast<unsigned int>(pendingBefore),
        static_cast<unsigned int>(pendingAfter),
        contextBefore,
        contextAfter,
        activityBefore,
        activityAfter);
    write_line(published ? core::log::Level::info : core::log::Level::warn, line, length);
    g_identityBindingInProgress.store(false, std::memory_order_release);
}

void attempt_retry(std::byte* updateManager) noexcept {
    if (!g_armed.load(std::memory_order_acquire)
        || g_dispatched.load(std::memory_order_acquire)
        || !forced_towerfall(true)) {
        return;
    }
    const std::uint64_t now = GetTickCount64();
    if (now < g_nextRetryTick.load(std::memory_order_acquire)) {
        return;
    }
    bool expected = false;
    if (!g_retryInProgress.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;
    }
    g_nextRetryTick.store(now + kRetryIntervalMs, std::memory_order_release);

    const bool retainedRoute =
        g_retainedRouteReady.load(std::memory_order_acquire);
    g_routeFallbackActive.store(retainedRoute, std::memory_order_release);
    g_retryInvocation = true;
    const RouteSnapshot route = snapshot_route();
    const bool match = is_towerfall_route(route);
    const std::uint64_t signature = route_signature(route);
    if (!match) {
        if (g_lastRouteSignature.exchange(signature, std::memory_order_acq_rel) != signature) {
            report_route("manager_retry_gate", 0U, 0U, route, false);
        }
        g_retryInvocation = false;
        g_routeFallbackActive.store(false, std::memory_order_release);
        g_retryInProgress.store(false, std::memory_order_release);
        return;
    }

    g_lastRouteManager.store(route.manager, std::memory_order_release);
    const std::uint32_t attempt =
        g_retryAttempts.fetch_add(1U, std::memory_order_acq_rel) + 1U;
    if (attempt == 1U
        || g_lastRouteSignature.exchange(signature, std::memory_order_acq_rel) != signature) {
        report_route("manager_retry_gate", 0U, attempt, route, true);
    }

    if (report_attempt(attempt)) {
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=manager_retry attempt=%u update_manager=%p identity=%d "
            "mode=%d selected=%d registered=%d active=%d route_manager=%p",
            attempt,
            static_cast<void*>(updateManager),
            safe_read<std::int32_t>(
                updateManager != nullptr ? updateManager + 0x1C7C0U : nullptr, -1),
            safe_read<std::int32_t>(
                updateManager != nullptr ? updateManager + 0x1AEF8U : nullptr, -1),
            safe_read<std::int32_t>(
                updateManager != nullptr ? updateManager + 0x87CU : nullptr, -1),
            safe_read<std::int32_t>(
                updateManager != nullptr ? updateManager + 0xE93CU : nullptr, -1),
            safe_read<std::int32_t>(
                updateManager != nullptr ? updateManager + 0x1AF00U : nullptr, -1),
            static_cast<void*>(route.manager));
        write_line(core::log::Level::info, line, length);
    }

    const std::uint64_t successfulRetryBefore =
        g_lastSuccessfulRetryProducer.load(std::memory_order_acquire);
    const LaunchProducer producer = g_launchProducerEntry.load(std::memory_order_acquire);
    if (producer != nullptr) {
        producer();
    }
    g_retryInvocation = false;
    g_routeFallbackActive.store(false, std::memory_order_release);
    const bool authoredDispatched =
        g_lastSuccessfulRetryProducer.load(std::memory_order_acquire)
        != successfulRetryBefore;
    if (!g_dispatched.load(std::memory_order_acquire) && !authoredDispatched
        && attempt >= kMaxDiagnosticRetryAttempts) {
        g_armed.store(false, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=towerfall_executor stage=manager_retry result=stopped reason=diagnostic_limit attempts=4 authored_dispatch=0");
    }
    g_retryInProgress.store(false, std::memory_order_release);
}

__declspec(noinline) void __fastcall manager_update_loop(std::byte* manager) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const ManagerUpdateLoop original = hooking::await_original(g_managerUpdateOriginal);
    const bool omegaReference = omega_reference_active();
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    const ManagerSnapshot before = snapshot_manager(manager);
    const IdentityDefinitionSnapshot definitionBefore =
        snapshot_identity_definition(before.identity);
    const std::uint32_t omegaEvent = omegaReference
                                         ? g_omegaManagerEvents.fetch_add(
                                               1U, std::memory_order_acq_rel)
                                               + 1U
                                         : 0U;
    const bool traceOmegaCall = omegaReference && omegaEvent <= kMaxOmegaManagerEvents;
    if (traceOmegaCall && call.accepts_side_effects()) {
        log_omega_manager_call("enter",
                               next_binding_timeline(),
                               callerRva,
                               manager,
                               before,
                               definitionBefore);
    }
    original(manager);
    if (!call.accepts_side_effects()) {
        return;
    }

    const ManagerSnapshot after = snapshot_manager(manager);
    const IdentityDefinitionSnapshot definitionAfter =
        snapshot_identity_definition(after.identity);
    trace_native_session(manager, after, definitionAfter);
    if (traceOmegaCall) {
        log_omega_manager_call("exit",
                               next_binding_timeline(),
                               callerRva,
                               manager,
                               after,
                               definitionAfter);
    }

    try_install_prelaunch_contract();

    // This native session update survives orbit's missing camera. The launch
    // adapter validates primary-session identity and exact setup:orbit state;
    // it never dispatches from Present, a worker, or an in-world fallback.
    client::activity::mission_launch::poll_orbit(reinterpret_cast<std::uintptr_t>(manager));

    const bool directContract =
        g_directContractPublished.load(std::memory_order_acquire);
    if (g_armed.load(std::memory_order_acquire) || directContract || omegaReference) {
        const std::uint64_t signature = manager_signature(after, definitionAfter)
                                        ^ reinterpret_cast<std::uintptr_t>(manager);
        const std::size_t signatureSlot = after.identity >= 0 && after.identity < 7
                                              ? static_cast<std::size_t>(after.identity)
                                              : 7U;
        if (g_lastManagerSignatures[signatureSlot].exchange(
                signature, std::memory_order_acq_rel)
            != signature) {
            std::array<char, core::log::kLineCapacity> line{};
            const int length = omegaReference
                                   ? std::snprintf(
                                         line.data(),
                                         line.size(),
                                         "ev=towerfall_executor stage=manager_update scope=omega_reference "
                                         "timeline=%llu phase=edge caller_rva=0x%llX manager=%p "
                                         "identity_before=%d identity_after=%d mode_before=%d mode_after=%d "
                                         "selected_before=%d selected_after=%d registered_before=%d registered_after=%d "
                                         "active_before=%d active_after=%d activity_before=%d activity_after=%d "
                                         "lifecycle_before=%d lifecycle_after=%d flags_before=0x%08X flags_after=0x%08X "
                                         "definition_before=%p definition_after=%p context_before=%p context_after=%p "
                                         "definition_activity_before=%d definition_activity_after=%d "
                                         "enabled_before=%u enabled_after=%u pending_before=%u pending_after=%u "
                                         "current_hash_before=0x%016llX current_hash_after=0x%016llX "
                                         "pending_hash_before=0x%016llX pending_hash_after=0x%016llX",
                                         static_cast<unsigned long long>(next_binding_timeline()),
                                         static_cast<unsigned long long>(callerRva),
                                         static_cast<void*>(manager),
                                         before.identity,
                                         after.identity,
                                         before.mode,
                                         after.mode,
                                         before.selected,
                                         after.selected,
                                         before.registered,
                                         after.registered,
                                         before.active,
                                         after.active,
                                         before.activity,
                                         after.activity,
                                         before.lifecycle,
                                         after.lifecycle,
                                         before.flags,
                                         after.flags,
                                         static_cast<void*>(definitionBefore.definition),
                                         static_cast<void*>(definitionAfter.definition),
                                         definitionBefore.context,
                                         definitionAfter.context,
                                         definitionBefore.activity,
                                         definitionAfter.activity,
                                         static_cast<unsigned int>(definitionBefore.enabled),
                                         static_cast<unsigned int>(definitionAfter.enabled),
                                         static_cast<unsigned int>(definitionBefore.pending),
                                         static_cast<unsigned int>(definitionAfter.pending),
                                         static_cast<unsigned long long>(definitionBefore.currentHash),
                                         static_cast<unsigned long long>(definitionAfter.currentHash),
                                         static_cast<unsigned long long>(definitionBefore.pendingHash),
                                         static_cast<unsigned long long>(definitionAfter.pendingHash))
                                   : std::snprintf(
                                         line.data(),
                                         line.size(),
                                         "ev=towerfall_executor stage=manager_update manager=%p identity=%d mode=%d "
                                         "selected=%d registered=%d active=%d activity=%d lifecycle=%d "
                                         "manager_flags=0x%08X direct=%u attempts=%u",
                                         static_cast<void*>(manager),
                                         after.identity,
                                         after.mode,
                                         after.selected,
                                         after.registered,
                                         after.active,
                                         after.activity,
                                         after.lifecycle,
                                         after.flags,
                                         directContract ? 1U : 0U,
                                         g_retryAttempts.load(std::memory_order_acquire));
            write_line(core::log::Level::info, line, length);
        }
    }
    if constexpr (kTowerfallIdentityMutationEnabled) {
        attempt_native_identity_binding(manager);
        attempt_retry(manager);
    }
}

__declspec(noinline) void __fastcall component_dispatch(std::byte* manager,
                                                         std::int32_t componentIndex) noexcept {
    hooking::CallGate::Scope call(g_callGate);
    const ComponentDispatch original = hooking::await_original(g_componentDispatchOriginal);
    const bool omegaReference = omega_reference_active();
    const std::uintptr_t callerRva = address_rva(_ReturnAddress());
    const ManagerSnapshot before = snapshot_manager(manager);
    const IdentityDefinitionSnapshot definitionBefore =
        snapshot_identity_definition(before.identity);
    const std::uint32_t omegaEvent = omegaReference
                                         ? g_omegaComponentEvents.fetch_add(
                                               1U, std::memory_order_acq_rel)
                                               + 1U
                                         : 0U;
    const bool traceOmega = omegaReference && omegaEvent <= kMaxOmegaComponentEvents;
    if (traceOmega && call.accepts_side_effects()) {
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=component_dispatch scope=omega_reference timeline=%llu "
            "phase=enter caller_rva=0x%llX manager=%p component_index=%d identity=%d "
            "mode=%d selected=%d registered=%d active=%d activity=%d lifecycle=%d "
            "definition=%p context=%p definition_activity=%d enabled=%u pending=%u "
            "current_hash=0x%016llX pending_hash=0x%016llX",
            static_cast<unsigned long long>(next_binding_timeline()),
            static_cast<unsigned long long>(callerRva),
            static_cast<void*>(manager),
            componentIndex,
            before.identity,
            before.mode,
            before.selected,
            before.registered,
            before.active,
            before.activity,
            before.lifecycle,
            static_cast<void*>(definitionBefore.definition),
            definitionBefore.context,
            definitionBefore.activity,
            static_cast<unsigned int>(definitionBefore.enabled),
            static_cast<unsigned int>(definitionBefore.pending),
            static_cast<unsigned long long>(definitionBefore.currentHash),
            static_cast<unsigned long long>(definitionBefore.pendingHash));
        write_line(core::log::Level::info, line, length);
    }
    original(manager, componentIndex);
    if (!call.accepts_side_effects()) {
        return;
    }
    const ManagerSnapshot after = snapshot_manager(manager);
    const IdentityDefinitionSnapshot definitionAfter =
        snapshot_identity_definition(after.identity);

    if (traceOmega) {
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=towerfall_executor stage=component_dispatch scope=omega_reference timeline=%llu "
            "phase=exit caller_rva=0x%llX manager=%p component_index=%d "
            "identity_before=%d identity_after=%d mode_before=%d mode_after=%d "
            "selected_before=%d selected_after=%d registered_before=%d registered_after=%d "
            "active_before=%d active_after=%d activity_before=%d activity_after=%d "
            "lifecycle_before=%d lifecycle_after=%d definition_before=%p definition_after=%p "
            "context_before=%p context_after=%p definition_activity_before=%d "
            "definition_activity_after=%d enabled_before=%u enabled_after=%u "
            "pending_before=%u pending_after=%u current_hash_before=0x%016llX "
            "current_hash_after=0x%016llX pending_hash_before=0x%016llX "
            "pending_hash_after=0x%016llX",
            static_cast<unsigned long long>(next_binding_timeline()),
            static_cast<unsigned long long>(callerRva),
            static_cast<void*>(manager),
            componentIndex,
            before.identity,
            after.identity,
            before.mode,
            after.mode,
            before.selected,
            after.selected,
            before.registered,
            after.registered,
            before.active,
            after.active,
            before.activity,
            after.activity,
            before.lifecycle,
            after.lifecycle,
            static_cast<void*>(definitionBefore.definition),
            static_cast<void*>(definitionAfter.definition),
            definitionBefore.context,
            definitionAfter.context,
            definitionBefore.activity,
            definitionAfter.activity,
            static_cast<unsigned int>(definitionBefore.enabled),
            static_cast<unsigned int>(definitionAfter.enabled),
            static_cast<unsigned int>(definitionBefore.pending),
            static_cast<unsigned int>(definitionAfter.pending),
            static_cast<unsigned long long>(definitionBefore.currentHash),
            static_cast<unsigned long long>(definitionAfter.currentHash),
            static_cast<unsigned long long>(definitionBefore.pendingHash),
            static_cast<unsigned long long>(definitionAfter.pendingHash));
        write_line(core::log::Level::info, line, length);
    }

    const std::uint64_t retrySequence =
        g_lastSuccessfulRetryProducer.load(std::memory_order_acquire);
    const bool direct = forced_towerfall(false)
                        && g_directContractPublished.load(std::memory_order_acquire);
    const bool retried = forced_towerfall(false) && g_armed.load(std::memory_order_acquire)
                         && g_retryAttempts.load(std::memory_order_acquire) != 0U
                         && retrySequence != 0U;
    const bool towerfall = direct || retried;
    const std::uint64_t sequence = retried
                                       ? retrySequence
                                       : g_lastSuccessfulProducer.load(std::memory_order_acquire);
    if (!towerfall && sequence == 0U) {
        return;
    }
    if (!towerfall
        && g_referenceComponentCaptured.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    std::byte* const routeManager = g_lastRouteManager.load(std::memory_order_acquire);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=towerfall_executor stage=component_dispatch result=%s sequence=%llu manager=%p "
        "route_manager=%p route_manager_match=%u identity=%d component_index=%d "
        "mode_before=%d mode_after=%d registered_before=%d registered_after=%d "
        "active_before=%d active_after=%d attempts=%u",
        direct ? "towerfall_direct" : (retried ? "towerfall_retry" : "reference"),
        static_cast<unsigned long long>(sequence),
        static_cast<void*>(manager),
        static_cast<void*>(routeManager),
        manager == routeManager ? 1U : 0U,
        before.identity,
        componentIndex,
        before.mode,
        after.mode,
        before.registered,
        after.registered,
        before.active,
        after.active,
        g_retryAttempts.load(std::memory_order_acquire));
    write_line(core::log::Level::info, line, length);

    if (towerfall && after.identity >= 0 && componentIndex >= 0) {
        g_dispatched.store(true, std::memory_order_release);
        g_armed.store(false, std::memory_order_release);
    }
}

void clear_runtime_state() noexcept {
    g_armed.store(false, std::memory_order_release);
    g_dispatched.store(false, std::memory_order_release);
    g_retryInProgress.store(false, std::memory_order_release);
    g_retryAttempts.store(0U, std::memory_order_release);
    g_lastSuccessfulRetryProducer.store(0U, std::memory_order_release);
    g_nextRetryTick.store(0U, std::memory_order_release);
    g_lastRouteSignature.store(~std::uint64_t{0}, std::memory_order_release);
    for (auto& signature : g_lastManagerSignatures) {
        signature.store(~std::uint64_t{0}, std::memory_order_release);
    }
    g_lastRouteManager.store(nullptr, std::memory_order_release);
    g_prelaunchPublicationPending.store(nullptr, std::memory_order_release);
    g_requestedPrelaunchProfile.store(nullptr, std::memory_order_release);
    g_directContractPublished.store(false, std::memory_order_release);
    g_identityBindingInProgress.store(false, std::memory_order_release);
    g_identityBindingPublished.store(false, std::memory_order_release);
    g_nextIdentityBindingTick.store(0U, std::memory_order_release);
    g_identityBindingAttempts.store(0U, std::memory_order_release);
    g_identityBindingDescriptorGeneration.store(0U, std::memory_order_release);
    g_identityBindingQueued.store(false, std::memory_order_release);
    g_retainedRouteReady.store(false, std::memory_order_release);
    g_routeFallbackActive.store(false, std::memory_order_release);
    g_retainedRouteManager.store(nullptr, std::memory_order_release);
    g_prelaunchProducerInProgress.store(false, std::memory_order_release);
    g_bindingTimelineSequence.store(0U, std::memory_order_release);
    g_omegaProducerEvents.store(0U, std::memory_order_release);
    g_omegaManagerEvents.store(0U, std::memory_order_release);
    g_omegaComponentEvents.store(0U, std::memory_order_release);
}

} // namespace

bool prepare_mission_prelaunch(
    const state::activity::forced::ForcedDestination& destination) noexcept {
    const auto* profile = prelaunch::configured(destination);
    if (profile == nullptr) { return true; }
    g_requestedPrelaunchProfile.store(profile, std::memory_order_release);
    return g_callGate.accepting()
        && g_selectionLaunchStateOriginal.load(std::memory_order_acquire) != nullptr
        && g_selectionLaunchPublisherOriginal.load(std::memory_order_acquire) != nullptr
        && g_selectionPublicationState0.load(std::memory_order_acquire) != nullptr;
}

bool install_towerfall_executor_bootstrap() noexcept {
    if (g_handles[managerUpdateIndex].attached) {
        return g_callGate.accepting();
    }
    g_callGate.quiesce();
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    std::byte* const managerTarget = image != nullptr ? image + kManagerUpdateLoopRva : nullptr;
    std::byte* const producerTarget = image != nullptr ? image + kLaunchProducerRva : nullptr;
    std::byte* const routeTarget = image != nullptr ? image + kRouteDescriptorLookupRva : nullptr;
    std::byte* const authoredTarget =
        image != nullptr ? image + kAuthoredLaunchDispatchRva : nullptr;
    std::byte* const componentTarget =
        image != nullptr ? image + kComponentDispatchRva : nullptr;
    std::byte* const identityRequestTarget =
        image != nullptr ? image + kIdentityRequestRva : nullptr;
    std::byte* const managerEventPublishTarget =
        image != nullptr ? image + kManagerEventPublishRva : nullptr;
    std::byte* const managerEventBeginTarget =
        image != nullptr ? image + kManagerEventBeginRva : nullptr;
    if (!prefix_matches(managerTarget, kManagerUpdateLoopPrefix)
        || !prefix_matches(producerTarget, kLaunchProducerPrefix)
        || !prefix_matches(routeTarget, kRouteDescriptorLookupPrefix)
        || !prefix_matches(authoredTarget, kAuthoredLaunchDispatchPrefix)
        || !prefix_matches(componentTarget, kComponentDispatchPrefix)
        || !prefix_matches(identityRequestTarget, kIdentityRequestPrefix)
        || !prefix_matches(managerEventPublishTarget, kManagerEventPublishPrefix)
        || !prefix_matches(managerEventBeginTarget, kManagerEventBeginPrefix)) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=towerfall_executor stage=install result=fail reason=pinned_target_validation");
        return false;
    }

    const std::array<hooking::detour::Spec, kCoreHookCount> specs{
        hooking::detour::Spec{managerTarget, reinterpret_cast<void*>(&manager_update_loop)},
        hooking::detour::Spec{producerTarget, reinterpret_cast<void*>(&launch_producer)},
        hooking::detour::Spec{authoredTarget, reinterpret_cast<void*>(&authored_launch_dispatch)},
        hooking::detour::Spec{componentTarget, reinterpret_cast<void*>(&component_dispatch)},
        hooking::detour::Spec{routeTarget, reinterpret_cast<void*>(&route_descriptor_lookup)},
        hooking::detour::Spec{identityRequestTarget,
                              reinterpret_cast<void*>(&identity_request_observer)},
        hooking::detour::Spec{managerEventPublishTarget,
                              reinterpret_cast<void*>(&manager_event_publish_observer)},
        hooking::detour::Spec{managerEventBeginTarget,
                              reinterpret_cast<void*>(&manager_event_begin_observer)},
    };
    if (!hooking::detour::install(specs, std::span(g_handles).first(kCoreHookCount))) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=towerfall_executor stage=install result=fail reason=attach");
        return false;
    }
    hooking::publish_original(
        g_managerUpdateOriginal,
        reinterpret_cast<ManagerUpdateLoop>(g_handles[managerUpdateIndex].original));
    hooking::publish_original(
        g_launchProducerOriginal,
        reinterpret_cast<LaunchProducer>(g_handles[launchProducerIndex].original));
    hooking::publish_original(
        g_authoredLaunchOriginal,
        reinterpret_cast<AuthoredLaunchDispatch>(g_handles[authoredLaunchIndex].original));
    hooking::publish_original(
        g_componentDispatchOriginal,
        reinterpret_cast<ComponentDispatch>(g_handles[componentDispatchIndex].original));
    hooking::publish_original(
        g_routeLookupOriginal,
        reinterpret_cast<RouteDescriptorLookup>(
            g_handles[routeDescriptorLookupIndex].original));
    hooking::publish_original(
        g_identityRequestOriginal,
        reinterpret_cast<IdentityRequest>(g_handles[identityRequestIndex].original));
    hooking::publish_original(
        g_managerEventPublishOriginal,
        reinterpret_cast<ManagerEventPublish>(g_handles[managerEventPublishIndex].original));
    hooking::publish_original(
        g_managerEventBeginOriginal,
        reinterpret_cast<ManagerEventBegin>(g_handles[managerEventBeginIndex].original));
    g_launchProducerEntry.store(reinterpret_cast<LaunchProducer>(producerTarget),
                                std::memory_order_release);
    g_routeLookup.store(reinterpret_cast<RouteDescriptorLookup>(routeTarget),
                        std::memory_order_release);
    g_identityRequestEntry.store(reinterpret_cast<IdentityRequest>(identityRequestTarget),
                                 std::memory_order_release);
    g_managerEventPublishEntry.store(
        reinterpret_cast<ManagerEventPublish>(managerEventPublishTarget),
        std::memory_order_release);
    g_managerEventBeginEntry.store(reinterpret_cast<ManagerEventBegin>(managerEventBeginTarget),
                                   std::memory_order_release);
    clear_runtime_state();
    g_referenceCaptured.store(false, std::memory_order_release);
    g_referenceComponentCaptured.store(false, std::memory_order_release);
    g_lastSuccessfulProducer.store(0U, std::memory_order_release);
    g_prelaunchInstallInProgress.store(false, std::memory_order_release);
    g_nextPrelaunchInstallTick.store(0U, std::memory_order_release);
    g_prelaunchInstallAttempts.store(0U, std::memory_order_release);
    g_identityTraceSequence.store(0U, std::memory_order_release);
    g_nativeSessionTraceEnabled.store(native_session_trace_requested(),
                                      std::memory_order_release);
    g_callGate.accept();
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=towerfall_executor stage=install result=ok mode=omega_binding_timeline_native_identity_trace_retained_route_producer_retry manual_lifecycle_event=disabled");
    return true;
}

void arm_towerfall_executor_bootstrap() noexcept {
    if (!g_callGate.accepting() || !forced_towerfall(true)) {
        return;
    }
    if constexpr (!kTowerfallIdentityMutationEnabled) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=towerfall_executor stage=arm result=observe_only reason=roster_baseline identity_mutation=disabled producer_retry=disabled");
        return;
    } else {
    const bool directContract =
        g_directContractPublished.load(std::memory_order_acquire);
    const bool retainedRoute =
        g_retainedRouteReady.load(std::memory_order_acquire);
    if (directContract && !retainedRoute) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=towerfall_executor stage=arm result=deferred reason=retained_route trigger=activity_host_descriptor manual_lifecycle_event=disabled");
        return;
    }
    bool expected = false;
    if (!g_armed.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;
    }
    g_dispatched.store(false, std::memory_order_release);
    g_retryAttempts.store(0U, std::memory_order_release);
    g_lastSuccessfulRetryProducer.store(0U, std::memory_order_release);
    g_nextRetryTick.store(0U, std::memory_order_release);
    g_lastRouteSignature.store(~std::uint64_t{0}, std::memory_order_release);
    for (auto& signature : g_lastManagerSignatures) {
        signature.store(~std::uint64_t{0}, std::memory_order_release);
    }
    g_lastRouteManager.store(nullptr, std::memory_order_release);
    // The retained route is exposed only by attempt_retry while its thread-local
    // retry marker is set. Never leave the fallback visible between update ticks.
    g_routeFallbackActive.store(false, std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        directContract
            ? "ev=towerfall_executor stage=arm result=ok trigger=native_spawn_runtime route=retained direct_contract=1 manual_lifecycle_event=disabled"
            : "ev=towerfall_executor stage=arm result=ok trigger=native_spawn_runtime route=native direct_contract=0 manual_lifecycle_event=disabled");
    }
}

void quiesce_towerfall_executor_bootstrap() noexcept {
    g_callGate.quiesce();
    g_armed.store(false, std::memory_order_release);
}

bool uninstall_towerfall_executor_bootstrap() noexcept {
    quiesce_towerfall_executor_bootstrap();
    if (!g_handles[managerUpdateIndex].attached) {
        return true;
    }
    const std::array protectedEntries{
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&manager_update_loop)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&launch_producer)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&authored_launch_dispatch)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&component_dispatch)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&route_descriptor_lookup)},
        hooking::detour::ProtectedCodeEntry{reinterpret_cast<void*>(&identity_request_observer)},
        hooking::detour::ProtectedCodeEntry{
            reinterpret_cast<void*>(&manager_event_publish_observer)},
        hooking::detour::ProtectedCodeEntry{
            reinterpret_cast<void*>(&manager_event_begin_observer)},
        hooking::detour::ProtectedCodeEntry{
            reinterpret_cast<void*>(&selection_launch_state_accessor)},
        hooking::detour::ProtectedCodeEntry{
            reinterpret_cast<void*>(&selection_launch_publisher)},
        hooking::detour::ProtectedCodeEntry{
            reinterpret_cast<void*>(&hooking::call_gate_detail::enter)},
        hooking::detour::ProtectedCodeEntry{
            reinterpret_cast<void*>(&hooking::call_gate_detail::leave)},
    };
    const std::size_t attachedCount = g_handles[selectionLaunchStateAccessorIndex].attached
                                          ? hookCount
                                          : kCoreHookCount;
    const hooking::detour::UninstallResult result = hooking::detour::uninstall(
        std::span(g_handles).first(attachedCount), protectedEntries, &calls_idle);
    if (result != hooking::detour::UninstallResult::removed) {
        core::log::write(
            core::log::Channel::client,
            result == hooking::detour::UninstallResult::failed ? core::log::Level::error
                                                               : core::log::Level::warn,
            result == hooking::detour::UninstallResult::failed
                ? "ev=towerfall_executor stage=uninstall result=failed retained=1"
                : "ev=towerfall_executor stage=uninstall result=deferred retained=1");
        return false;
    }
    g_managerUpdateOriginal.store(nullptr, std::memory_order_release);
    g_launchProducerOriginal.store(nullptr, std::memory_order_release);
    g_launchProducerEntry.store(nullptr, std::memory_order_release);
    g_routeLookup.store(nullptr, std::memory_order_release);
    g_routeLookupOriginal.store(nullptr, std::memory_order_release);
    g_identityRequestOriginal.store(nullptr, std::memory_order_release);
    g_identityRequestEntry.store(nullptr, std::memory_order_release);
    g_managerEventPublishOriginal.store(nullptr, std::memory_order_release);
    g_managerEventPublishEntry.store(nullptr, std::memory_order_release);
    g_managerEventBeginOriginal.store(nullptr, std::memory_order_release);
    g_managerEventBeginEntry.store(nullptr, std::memory_order_release);
    g_authoredLaunchOriginal.store(nullptr, std::memory_order_release);
    g_componentDispatchOriginal.store(nullptr, std::memory_order_release);
    g_selectionLaunchStateOriginal.store(nullptr, std::memory_order_release);
    g_selectionLaunchPublisherOriginal.store(nullptr, std::memory_order_release);
    g_selectionPublicationState0.store(nullptr, std::memory_order_release);
    clear_runtime_state();
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=towerfall_executor stage=uninstall result=ok retained=0");
    return true;
}

} // namespace dawn::client::hooks::bootflow
