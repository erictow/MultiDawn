#include <Windows.h>
#include <TlHelp32.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <span>
#include <string_view>

#include "../../../core/filesystem/path.h"
#include "../../../core/logging/log.h"
#include "../../../state/activity/forced/activity_forced_destination.h"
#include "../../hooking/detour.h"
#include "internal.h"
#include "legacy_owner_sentinel.h"

namespace dawn::client::hooks::bootflow {
namespace {

/**
 * Activity-client state-4 update, captured from the runtime-decrypted Homecoming request path.
 * The fixed prologue and frame size continue through the first saved arguments; only the security
 * cookie displacement is wildcarded.
 */
constexpr std::string_view kRequestSignatureText =
    "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 F0 F3 FF FF 48 81 EC 10 "
    "0D 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 00 0C 00 00 48 63 DA 48 8B F9";
constexpr auto kRequestSignature =
    signature<signature_length(kRequestSignatureText)>(kRequestSignatureText);

/** Per-frame activity-client state-machine pump that owns all three 0x2d0-byte records. */
constexpr std::string_view kPumpSignatureText =
    "4C 8B DC 49 89 5B 18 49 89 73 20 55 57 41 54 41 55 41 56 49 8D AB A8 FD FF FF "
    "48 81 EC 30 03 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 20 02 00 00";
constexpr auto kPumpSignature =
    signature<signature_length(kPumpSignatureText)>(kPumpSignatureText);

/** Final in-world activity start, whose current-activity object still retained Tower index 20. */
constexpr std::string_view kStartSignatureText =
    "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 56 41 57 48 8D AC 24 C0 FC FF FF "
    "48 81 EC 40 04 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 30 03 00 00 48 8B F9 33 C9";
constexpr auto kStartSignature =
    signature<signature_length(kStartSignatureText)>(kStartSignatureText);

/** Three activity-client slots, each represented by one 0x2d0-byte record. */
constexpr std::size_t kSlotCount = 3;
constexpr std::size_t kFirstRecordOffset = 0x27D0;
constexpr std::size_t kRecordStride = 0x2D0;
/** The selection copied by the native update begins eight bytes into the record. */
constexpr std::size_t kSelectionOffset = 8;
/** Decoded selection fields recovered from the slot-0 record. */
constexpr std::size_t kSourceActivityIndexOffset = 2;
constexpr std::size_t kActivityIndexOffset = 4;
constexpr std::size_t kPackageNameOffset = 0x50;
constexpr std::size_t kPackageNameCapacity = 40;
/** Authored investment-table indices in this Season of Arrivals client. */
constexpr std::int16_t kTowerCinematicActivityIndex = 2;
constexpr std::int16_t kHomecomingActivityIndex = 266;
constexpr std::int16_t kChosenActivityIndex = 282;
/** Runtime RVAs of the exact accessors used by the captured in-world start function. */
constexpr std::uintptr_t kWorldControllerAccessorRva = 0xC26430;
constexpr std::uintptr_t kCurrentActivityPresentRva = 0x178DAB0;
constexpr std::uintptr_t kCurrentActivityValueRva = 0x1778C70;
/** Native slot-state-5 update called immediately after the request changes slot 2 to state 5. */
constexpr std::uintptr_t kState5UpdateRva = 0xC0CF30;
/** Exact nested request-builder chain recovered from the suspended state-5 fiber stack. */
constexpr std::uintptr_t kState5RequestBuilderRva = 0xBFC970;
constexpr std::uintptr_t kState5PayloadFinalizerRva = 0xC21530;
constexpr std::uintptr_t kState5PayloadSerializerRva = 0xC21820;
/** Lookup called at 0xC219B3; its saved return at 0xC219B8 is the first live game frame. */
constexpr std::uintptr_t kState5PayloadLookupRva = 0x17797B0;
/**
 * Slot snapshot accessor whose result supplies the serializer fields read at +0xDC and +0xD8.
 * Unlike the fixed-record lookup above, this accessor can return null and owns the actual freeze.
 */
constexpr std::uintptr_t kState5SlotSnapshotAccessorRva = 0xBDE7C0;
/** Legitimate component-record ingress shared by local initialization and authored ingest. */
constexpr std::uintptr_t kComponentIngressRva = 0x1777EC0;
/** Authored/network manager ingest that owns the only authored call to component ingress. */
constexpr std::uintptr_t kAuthoredComponentIngestRva = 0x178DE60;
/** Sole scheduler/caller of authored component ingest and its per-manager skip predicate. */
constexpr std::uintptr_t kAuthoredComponentDispatchOwnerRva = 0x175C7C0;
constexpr std::uintptr_t kAuthoredComponentManagerSkipPredicateRva = 0x17A22E0;
constexpr std::uintptr_t kAuthoredComponentManagerSkipPredicateReturnRva = 0x175C860;
constexpr std::uintptr_t kAuthoredComponentLaneTableRva = 0x31E10A0;
constexpr std::uintptr_t kAuthoredComponentCandidateCountRva = 0x31E1118;
/**
 * Native group-session join-request receiver, candidate queue producer, and result reporter.
 * These were initially suspected to be authored-activity ingress. The peer registry proves RVA
 * 0x16E0460 is message id 10 (join request), so this cluster is retained only as observation.
 */
constexpr std::uintptr_t kAuthoredCandidateWireReceiverRva = 0x016E0460;
constexpr std::uintptr_t kAuthoredCandidateProducerRva = 0x01755540;
constexpr std::uintptr_t kAuthoredCandidateResultReporterRva = 0x1768BA0;
constexpr std::uintptr_t kAuthoredCandidateProducerBeginRva = 0x01755540;
constexpr std::uintptr_t kAuthoredCandidateProducerEndRva = 0x01755AAF;
/** Lazy per-thread object resolver used by activity notification type 8's client apply path. */
constexpr std::uintptr_t kActivityNotificationTypeEightResolverRva = 0x004CEF90;
/** Accessor called by the native selection launcher immediately before it copies manager state. */
constexpr std::uintptr_t kSelectionLaunchStateAccessorRva = 0xBF9FA0;
/** Return address of that accessor's call inside the captured launcher at 0xBFA5A0. */
constexpr std::uintptr_t kSelectionLaunchStateAccessorReturnRva = 0xBFA610;
/** Direct native current-selection publisher called by the same launcher. */
constexpr std::uintptr_t kSelectionLaunchPublisherRva = 0x17ADA60;
/** Returns the passive 0x1B0 launch-publication owner from the manager launch context. */
constexpr std::uintptr_t kSelectionPublicationOwnerAccessorRva = 0x1778DA0;
/** Native per-frame state machine that advances the stored 0x1B0 prelaunch publication. */
constexpr std::uintptr_t kSelectionPublicationStateMachineRva = 0xC1A2D0;
/** Predicate evaluated when the prelaunch countdown expires, immediately before state 4. */
constexpr std::uintptr_t kSelectionRouteReadyQueryRva = 0xBFB500;
/** Subpredicates used by the route-ready query, traced only while that query is active. */
constexpr std::uintptr_t kSelectionRoutePairInvalidRva = 0xDE11A0;
constexpr std::uintptr_t kSelectionRouteDestinationAllowedRva = 0xC068F0;
constexpr std::uintptr_t kSelectionRoutePrimaryReadyRva = 0xBFA0D0;
constexpr std::uintptr_t kSelectionRouteFallbackReadyRva = 0xBFA310;
/** Internal stages of the destination predicate at 0xC068F0. */
constexpr std::uintptr_t kSelectionRouteRegistryReadyRva = 0xC21370;
/** Registry table accessor plus the native slot writer and the writer's readiness predicate. */
constexpr std::uintptr_t kSelectionRouteTableAccessorRva = 0xC21FE0;
constexpr std::uintptr_t kSelectionRouteRegistrySlotWriterRva = 0xC22A80;
constexpr std::uintptr_t kSelectionRouteRegistrySlotWriterPredicateRva = 0x12AADF0;
/** Queued callback wrapper that reaches the native slot writer through vtable slot +0x10. */
constexpr std::uintptr_t kSelectionRouteRegistryQueuedWrapperRva = 0x16E63B0;
/** Helper that builds the wrapper's transient argument before its virtual call. */
constexpr std::uintptr_t kSelectionRouteRegistryQueuedArgumentRva = 0x412A40;
/** Neighboring queued request wrapper and the context-owned constructor it forwards into. */
constexpr std::uintptr_t kSelectionRouteDestinationSlotRequestRva = 0xC22B30;
constexpr std::uintptr_t kSelectionRouteDestinationSlotRequestContextRva = 0xC06770;
/** Upstream activity-slot initialization and the package-index registration it owns. */
constexpr std::uintptr_t kSelectionRouteSlotInitializeRva = 0xBFE300;
constexpr std::uintptr_t kSelectionRoutePackageRegistrationRva = 0xBFE450;
/** Large native object builder called only after package registration succeeds. */
constexpr std::uintptr_t kSelectionRouteObjectBuilderRva = 0x4F77D0;
constexpr std::uintptr_t kSelectionRouteDefinitionIndexResolverRva = 0x3C6E00;
constexpr std::uintptr_t kSelectionRoutePackageIndexResolverRva = 0x3C6E50;
constexpr std::uintptr_t kSelectionRouteActivityContextRva = 0xE36C30;
constexpr std::uintptr_t kSelectionRouteResolvedPackageRva = 0x3C9450;
constexpr std::uintptr_t kSelectionRouteStrictComparisonRva = 0x50BF00;
/** Return after the same strict provider predicate is called by identity record lookup. */
constexpr std::uintptr_t kEmbeddedRouteIdentityProviderStrictReturnRva = 0xDDF144;
constexpr std::uintptr_t kSelectionRouteDestinationRegistryRva = 0x50A210;
constexpr std::uintptr_t kSelectionRoutePackageMatchesRva = 0x3CC1E0;
/** Return address immediately after the launcher's direct publisher call. */
constexpr std::uintptr_t kSelectionLaunchPublisherReturnRva = 0xBFA89B;
/** Native state-0 producer inside the captured activity-selection pump. */
constexpr std::size_t kSelectionPublicationState0Offset = 0x19C0;
constexpr std::size_t kSelectionPublicationBytes = 0x1B0;
constexpr std::size_t kSelectionPublicationOwnerProbeBytes = 0x200;
constexpr std::size_t kSelectionPublicationVtableProbeBytes = 0xC0;
constexpr std::size_t kSelectionPublicationNotifyProbeBytes = 0x800;
constexpr std::size_t kCurrentActivityContainerOffset = 0x8E08;
constexpr std::size_t kCurrentActivityProbeBytes = 0x400;
/** Includes the complete first 0xBE0 record and its 0x1B0 publication at +0xA30. */
constexpr std::size_t kSelectionLaunchStateProbeBytes = 0xE00;

constexpr std::array<std::uint8_t, 16> kSelectionPublicationState0Prologue{
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C,
    0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57};
constexpr std::array<std::uint8_t, 16> kSelectionLaunchPublisherPrologue{
    0x48, 0x89, 0x5C, 0x24, 0x18, 0x56, 0x48, 0x83,
    0xEC, 0x20, 0x48, 0x8B, 0xF1, 0x48, 0x8B, 0xDA};
constexpr std::array<std::uint8_t, 8> kSelectionPublicationOwnerAccessorPrologue{
    0x48, 0x8B, 0x81, 0x90, 0xB9, 0x00, 0x00, 0xC3};
constexpr std::array<std::uint8_t, 16> kSelectionPublicationStateMachinePrologue{
    0x40, 0x53, 0x56, 0x57, 0x48, 0x81, 0xEC, 0x00,
    0x02, 0x00, 0x00, 0x48, 0x8B, 0x05, 0xA6, 0xF7};

using RequestUpdate = void(__fastcall*)(std::byte*, std::int32_t) noexcept;
using PumpUpdate = void(__fastcall*)(std::byte*) noexcept;
using State5Update = void(__fastcall*)(std::byte*, std::int32_t) noexcept;
using State5RequestBuilder = void(__fastcall*)(void*, std::int32_t, std::byte*) noexcept;
using State5PayloadFinalizer = void(__fastcall*)(void*, bool, std::byte*) noexcept;
using State5PayloadSerializer =
    void(__fastcall*)(void*, std::int32_t, bool, std::byte*) noexcept;
using State5PayloadLookup =
    const std::byte*(__fastcall*)(const void*, std::int32_t) noexcept;
using ComponentIngress = std::int32_t(__fastcall*)(std::byte*,
                                                    std::int32_t,
                                                    std::int32_t,
                                                    const void*,
                                                    const void*,
                                                    bool,
                                                    bool,
                                                    bool,
                                                    bool,
                                                    bool) noexcept;
using AuthoredComponentIngest = void(__fastcall*)(std::byte*,
                                                  const std::byte*,
                                                  const void*,
                                                  const void*) noexcept;
using AuthoredComponentDispatchOwner = void(__fastcall*)(std::uint32_t) noexcept;
using AuthoredComponentManagerSkipPredicate = bool(__fastcall*)(std::byte*) noexcept;
using AuthoredCandidateWireReceiver = bool(__fastcall*)(std::byte*,
                                                         const void*,
                                                         const std::byte*) noexcept;
using AuthoredCandidateProducer = void(__fastcall*)(std::byte*,
                                                     const void*,
                                                     const std::byte*) noexcept;
using AuthoredCandidateResultReporter = void(__fastcall*)(std::byte*,
                                                           const void*,
                                                           std::uint64_t,
                                                           std::int32_t) noexcept;
using StartUpdate = void(__fastcall*)(void*, std::int32_t, std::int32_t) noexcept;
using WorldControllerAccessor = std::byte*(__fastcall*)(std::int32_t) noexcept;
using CurrentActivityPresent = bool(__fastcall*)(void*) noexcept;
using CurrentActivityValue = std::byte*(__fastcall*)(void*) noexcept;
using SelectionLaunchStateAccessor = std::byte*(__fastcall*)(std::byte*) noexcept;
using SelectionPublicationState0 = void(__fastcall*)(std::byte*) noexcept;
using SelectionLaunchPublisher = bool(__fastcall*)(std::byte*, std::byte*) noexcept;
using SelectionPublicationOwnerAccessor = std::byte*(__fastcall*)(std::byte*) noexcept;
using SelectionPublicationStateMachine = void(__fastcall*)(std::byte*) noexcept;
using SelectionRouteReadyQuery = bool(__fastcall*)(std::byte*) noexcept;
using SelectionRoutePairInvalid = bool(__fastcall*)(void*) noexcept;
using SelectionRouteDestinationAllowed = bool(__fastcall*)(std::uint32_t, const void*) noexcept;
using SelectionRoutePrimaryReady = bool(__fastcall*)(std::uint32_t) noexcept;
using SelectionRouteFallbackReady = bool(__fastcall*)() noexcept;
using SelectionRouteRegistryReady = bool(__fastcall*)() noexcept;
using SelectionRouteTableAccessor = std::byte*(__fastcall*)() noexcept;
using SelectionRouteRegistrySlotWriter =
    void(__fastcall*)(std::int32_t, std::int32_t, std::int32_t) noexcept;
using SelectionRouteRegistrySlotWriterPredicate = bool(__fastcall*)() noexcept;
using SelectionRouteRegistryQueuedWrapper =
    void(__fastcall*)(void*, const std::int8_t*) noexcept;
using SelectionRouteDestinationSlotRequest =
    void(__fastcall*)(std::int32_t, std::int32_t, std::int32_t) noexcept;
using SelectionRouteSlotInitialize = bool(__fastcall*)(std::byte*,
                                                        std::int32_t,
                                                        std::int32_t,
                                                        std::int32_t,
                                                        void*) noexcept;
using SelectionRoutePackageRegistration = bool(__fastcall*)(std::byte*,
                                                              std::int32_t,
                                                              void*,
                                                              std::byte*) noexcept;
using SelectionRouteObjectBuilder = void(__fastcall*)(void*,
                                                        std::int32_t,
                                                        std::int32_t,
                                                        void*,
                                                        void*,
                                                        void*,
                                                        void*,
                                                        void*) noexcept;
using SelectionRouteIndexResolver = std::int32_t*(__fastcall*)(std::int32_t*) noexcept;
using SelectionRouteActivityContext = void*(__fastcall*)() noexcept;
using SelectionRouteResolvedPackage = const char*(__fastcall*)(std::int32_t) noexcept;
using SelectionRouteStrictComparison = bool(__fastcall*)() noexcept;
using SelectionRouteDestinationRegistry = void*(__fastcall*)() noexcept;
using SelectionRoutePackageMatches = bool(__fastcall*)(const char*, const char*) noexcept;
using ActivityNotificationTypeEightResolver = std::byte*(__fastcall*)() noexcept;

hooking::detour::Handle g_handle{};
hooking::detour::Handle g_pumpHandle{};
hooking::detour::Handle g_state5Handle{};
hooking::detour::Handle g_state5RequestBuilderHandle{};
hooking::detour::Handle g_state5PayloadFinalizerHandle{};
hooking::detour::Handle g_state5PayloadSerializerHandle{};
hooking::detour::Handle g_state5PayloadLookupHandle{};
hooking::detour::Handle g_componentIngressHandle{};
hooking::detour::Handle g_authoredComponentIngestHandle{};
hooking::detour::Handle g_authoredComponentDispatchOwnerHandle{};
hooking::detour::Handle g_authoredComponentManagerSkipPredicateHandle{};
hooking::detour::Handle g_authoredCandidateWireReceiverHandle{};
hooking::detour::Handle g_authoredCandidateProducerHandle{};
hooking::detour::Handle g_authoredCandidateResultReporterHandle{};
hooking::detour::Handle g_startHandle{};
hooking::detour::Handle g_selectionLaunchStateHandle{};
hooking::detour::Handle g_selectionLaunchPublisherHandle{};
hooking::detour::Handle g_selectionPublicationOwnerAccessorHandle{};
hooking::detour::Handle g_selectionPublicationStateMachineHandle{};
hooking::detour::Handle g_selectionRouteReadyQueryHandle{};
hooking::detour::Handle g_selectionRoutePairInvalidHandle{};
hooking::detour::Handle g_selectionRouteDestinationAllowedHandle{};
hooking::detour::Handle g_selectionRoutePrimaryReadyHandle{};
hooking::detour::Handle g_selectionRouteFallbackReadyHandle{};
hooking::detour::Handle g_selectionRouteRegistryReadyHandle{};
hooking::detour::Handle g_selectionRouteRegistrySlotWriterHandle{};
hooking::detour::Handle g_selectionRouteRegistrySlotWriterPredicateHandle{};
hooking::detour::Handle g_selectionRouteRegistryQueuedWrapperHandle{};
hooking::detour::Handle g_selectionRouteDestinationSlotRequestHandle{};
hooking::detour::Handle g_selectionRouteSlotInitializeHandle{};
hooking::detour::Handle g_selectionRoutePackageRegistrationHandle{};
hooking::detour::Handle g_selectionRouteObjectBuilderHandle{};
hooking::detour::Handle g_selectionRouteDefinitionIndexResolverHandle{};
hooking::detour::Handle g_selectionRoutePackageIndexResolverHandle{};
hooking::detour::Handle g_selectionRouteActivityContextHandle{};
hooking::detour::Handle g_selectionRouteResolvedPackageHandle{};
hooking::detour::Handle g_selectionRouteStrictComparisonHandle{};
hooking::detour::Handle g_selectionRouteDestinationRegistryHandle{};
hooking::detour::Handle g_selectionRoutePackageMatchesHandle{};
hooking::detour::Handle g_activityNotificationTypeEightResolverHandle{};
std::atomic<RequestUpdate> g_original{nullptr};
std::atomic<PumpUpdate> g_pumpOriginal{nullptr};
std::atomic<State5Update> g_state5Original{nullptr};
std::atomic<State5RequestBuilder> g_state5RequestBuilderOriginal{nullptr};
std::atomic<State5PayloadFinalizer> g_state5PayloadFinalizerOriginal{nullptr};
std::atomic<State5PayloadSerializer> g_state5PayloadSerializerOriginal{nullptr};
std::atomic<State5PayloadLookup> g_state5PayloadLookupOriginal{nullptr};
std::atomic<ComponentIngress> g_componentIngressOriginal{nullptr};
std::atomic<AuthoredComponentIngest> g_authoredComponentIngestOriginal{nullptr};
std::atomic<AuthoredComponentDispatchOwner> g_authoredComponentDispatchOwnerOriginal{nullptr};
std::atomic<AuthoredComponentManagerSkipPredicate>
    g_authoredComponentManagerSkipPredicateOriginal{nullptr};
std::atomic<AuthoredCandidateWireReceiver> g_authoredCandidateWireReceiverOriginal{nullptr};
std::atomic<AuthoredCandidateProducer> g_authoredCandidateProducerOriginal{nullptr};
std::atomic<AuthoredCandidateResultReporter> g_authoredCandidateResultReporterOriginal{nullptr};
std::atomic<StartUpdate> g_startOriginal{nullptr};
std::atomic<SelectionLaunchStateAccessor> g_selectionLaunchStateOriginal{nullptr};
std::atomic<SelectionPublicationState0> g_selectionPublicationState0{nullptr};
std::atomic<SelectionLaunchPublisher> g_selectionLaunchPublisherOriginal{nullptr};
std::atomic<SelectionPublicationOwnerAccessor> g_selectionPublicationOwnerAccessorOriginal{
    nullptr};
std::atomic<SelectionPublicationStateMachine> g_selectionPublicationStateMachineOriginal{
    nullptr};
std::atomic<SelectionRouteReadyQuery> g_selectionRouteReadyQueryOriginal{nullptr};
std::atomic<SelectionRoutePairInvalid> g_selectionRoutePairInvalidOriginal{nullptr};
std::atomic<SelectionRouteDestinationAllowed> g_selectionRouteDestinationAllowedOriginal{nullptr};
std::atomic<SelectionRoutePrimaryReady> g_selectionRoutePrimaryReadyOriginal{nullptr};
std::atomic<SelectionRouteFallbackReady> g_selectionRouteFallbackReadyOriginal{nullptr};
std::atomic<SelectionRouteRegistryReady> g_selectionRouteRegistryReadyOriginal{nullptr};
std::atomic<SelectionRouteRegistrySlotWriter> g_selectionRouteRegistrySlotWriterOriginal{
    nullptr};
std::atomic<SelectionRouteRegistrySlotWriterPredicate>
    g_selectionRouteRegistrySlotWriterPredicateOriginal{nullptr};
std::atomic<SelectionRouteRegistryQueuedWrapper>
    g_selectionRouteRegistryQueuedWrapperOriginal{nullptr};
std::atomic<SelectionRouteDestinationSlotRequest>
    g_selectionRouteDestinationSlotRequestOriginal{nullptr};
std::atomic<SelectionRouteSlotInitialize> g_selectionRouteSlotInitializeOriginal{nullptr};
std::atomic<SelectionRoutePackageRegistration>
    g_selectionRoutePackageRegistrationOriginal{nullptr};
std::atomic<SelectionRouteObjectBuilder> g_selectionRouteObjectBuilderOriginal{nullptr};
std::atomic<SelectionRouteIndexResolver> g_selectionRouteDefinitionIndexResolverOriginal{
    nullptr};
std::atomic<SelectionRouteIndexResolver> g_selectionRoutePackageIndexResolverOriginal{nullptr};
std::atomic<SelectionRouteActivityContext> g_selectionRouteActivityContextOriginal{nullptr};
std::atomic<SelectionRouteResolvedPackage> g_selectionRouteResolvedPackageOriginal{nullptr};
std::atomic<SelectionRouteStrictComparison> g_selectionRouteStrictComparisonOriginal{nullptr};
std::atomic<SelectionRouteDestinationRegistry> g_selectionRouteDestinationRegistryOriginal{
    nullptr};
std::atomic<SelectionRoutePackageMatches> g_selectionRoutePackageMatchesOriginal{nullptr};
std::atomic<ActivityNotificationTypeEightResolver>
    g_activityNotificationTypeEightResolverOriginal{nullptr};
std::atomic_bool g_activityNotificationTypeEightResolverCaptured{};
std::atomic<std::byte*> g_activitySelectionPumpTarget{nullptr};
std::array<std::atomic_bool, kSlotCount> g_dumped{};
std::array<std::atomic_uint64_t, kSlotCount> g_pumpFingerprints{};
std::atomic_bool g_currentDumped{};
std::atomic_bool g_slot2RequestStarted{};
std::atomic_bool g_slot2RequestReturned{};
std::atomic_bool g_pumpReturnedAfterSlot2{};
std::atomic_bool g_state5Entered{};
std::atomic_bool g_state5Returned{};
std::atomic_bool g_state5SnapshotStarted{};
std::atomic<DWORD> g_state5ThreadId{};
std::atomic<std::uintptr_t> g_state5EntryStackTop{};
std::atomic<void*> g_state5FiberContext{};
std::atomic_bool g_state5RequestBuilderEntered{};
std::atomic_bool g_state5RequestBuilderReturned{};
std::atomic_bool g_state5PayloadFinalizerEntered{};
std::atomic_bool g_state5PayloadFinalizerReturned{};
std::atomic_bool g_state5PayloadSerializerEntered{};
std::atomic_bool g_state5PayloadSerializerReturned{};
std::atomic_bool g_state5PayloadLookupEntered{};
std::atomic_bool g_state5PayloadLookupReturned{};
std::atomic_uint32_t g_componentIngressObserved{};
std::atomic_uint32_t g_componentIngressIdentityOneObserved{};
std::atomic_uint32_t g_componentIngressIdentityTwoObserved{};
std::atomic_uint32_t g_authoredComponentIngestObserved{};
std::atomic_uint32_t g_authoredComponentIngestIdentityTwoObserved{};
std::atomic_uint32_t g_authoredComponentDispatchOwnerObserved{};
std::atomic_uint32_t g_authoredComponentDispatchOwnerPostHostReadyObserved{};
std::atomic_uint32_t g_authoredComponentManagerSkipPredicateObserved{};
std::atomic_uint32_t g_authoredComponentManagerSkipPredicatePostHostReadyObserved{};
std::atomic_bool g_authoredComponentPostHostReadyTraceAnnounced{};
std::atomic_uint32_t g_authoredCandidateWireReceiverObserved{};
std::atomic_uint32_t g_authoredCandidateProducerObserved{};
std::atomic_uint32_t g_authoredCandidateResultReporterObserved{};
std::atomic_bool g_selectionLaunchStateDumped{};
std::atomic_bool g_homecomingPrelaunchPublicationPending{};
std::atomic_bool g_prelaunchOwnerTraceArmed{};
std::atomic_uint32_t g_selectionPublicationOwnerAccessObserved{};
std::atomic<std::byte*> g_tracedPrelaunchRecord{nullptr};
std::atomic_uint32_t g_selectionPublicationStateMachineObserved{};
std::atomic_uint64_t g_selectionPublicationStateFingerprint{};
std::atomic_uint32_t g_selectionRouteReadyObserved{};
std::atomic_uint32_t g_selectionRouteRegistrySlotWriterObserved{};
std::atomic_uint32_t g_selectionRouteRegistryQueuedWrapperObserved{};
std::atomic_bool g_selectionRouteRegistryQueuedThunkDumped{};
enum class SelectionStateOneWatchStatus : std::uint32_t {
    idle = 0,
    armed = 1,
    capturing = 2,
    captured = 3,
    disabled = 4,
};
/** Completed diagnostic: the native state-1 writer is healthy at RVA 0xC06741. */
constexpr bool kEnableSelectionStateOneWriteWatch = false;
std::atomic<SelectionStateOneWatchStatus> g_selectionStateOneWatchStatus{
    SelectionStateOneWatchStatus::idle};
std::atomic_bool g_selectionStateOneWatchArmStarted{};
std::atomic_bool g_selectionStateOneWatchLogged{};
std::atomic_uint32_t g_selectionStateOneWatchIgnoredWrites{};
std::atomic_uint32_t g_selectionStateOneWatchArmedThreads{};
std::atomic<std::uintptr_t> g_selectionStateOneWatchAddress{};
std::atomic<DWORD> g_selectionStateOneWatchThreadId{};
std::atomic<std::int32_t> g_selectionStateOneWatchValue{-999};
std::atomic<std::uintptr_t> g_selectionStateOneWatchExceptionAddress{};
CONTEXT g_selectionStateOneWatchContext{};
void* g_selectionStateOneWatchVectoredHandler{};
std::atomic_uint32_t g_selectionRouteDestinationSlotRequestObserved{};
std::atomic_uint32_t g_selectionRouteSlotInitializeObserved{};
std::atomic_uint32_t g_selectionRoutePackageRegistrationObserved{};
std::atomic_bool g_selectionRouteObjectBuilderEntered{};
std::atomic_bool g_selectionRouteObjectBuilderReturned{};
std::atomic_bool g_selectionRouteObjectBuilderSnapshotStarted{};
std::atomic_uint64_t g_selectionRouteObjectBuilderEntryStack{};
std::atomic_uint32_t g_embeddedRouteIdentityProviderStrictObserved{};

struct SelectionRouteReadyDetailTrace {
    bool active{};
    bool pairInvalidCalled{};
    bool pairInvalid{};
    bool destinationAllowedCalled{};
    bool destinationAllowed{};
    bool primaryReadyCalled{};
    bool primaryReady{};
    bool fallbackReadyCalled{};
    bool fallbackReady{};
    std::uint32_t destination{};
    const void* descriptor{};
    std::uint32_t registryReadyCalls{};
    bool registryReadyFirst{};
    bool registryReadySecond{};
    void* registryTable{};
    std::int32_t registryActiveIndex{-999};
    std::int32_t registryActiveSlotState{-999};
    std::int32_t registryActivePackageIndex{-999};
    std::int32_t registryActiveMarked{-1};
    void* activityContext{};
    std::int32_t resolvedPackageIndex{-1};
    const char* resolvedPackage{};
    bool strictComparisonCalled{};
    bool strictComparison{};
    void* destinationRegistry{};
    bool packageMatchesCalled{};
    bool packageMatches{};
    std::array<char, 48> packageActual{};
    std::array<char, 48> packageExpected{};
};

thread_local SelectionRouteReadyDetailTrace g_selectionRouteReadyDetailTrace{};
thread_local bool g_selectionRouteDestinationTraceActive{};
thread_local bool g_selectionRouteRegistrySlotWriterTraceActive{};
thread_local bool g_selectionRouteRegistrySlotWriterPredicateCalled{};
thread_local bool g_selectionRouteRegistrySlotWriterPredicateResult{};
thread_local bool g_selectionRouteSlotInitializeTraceActive{};
thread_local bool g_selectionRouteDefinitionIndexResolverCalled{};
thread_local std::int32_t g_selectionRouteDefinitionIndexResolved{-999};
thread_local bool g_selectionRoutePackageRegistrationCalled{};
thread_local bool g_selectionRoutePackageRegistrationTraceActive{};
thread_local bool g_selectionRoutePackageIndexResolverCalled{};
thread_local std::int32_t g_selectionRoutePackageIndexResolved{-999};

/** Returns the loaded game-image size without importing an additional process module API. */
[[nodiscard]] std::size_t game_image_size(const std::byte* image) noexcept {
    if (image == nullptr) {
        return 0;
    }
    const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
        return 0;
    }
    const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE ? nt->OptionalHeader.SizeOfImage : 0;
}

/** Uses the loaded images' x64 unwind metadata to recover the suspended thread's true frames. */
[[nodiscard]] std::size_t unwind_state5_context(
    CONTEXT context,
    std::span<std::uintptr_t> frames) noexcept {
    std::size_t count = 0;
    while (count < frames.size() && context.Rip != 0 && context.Rsp != 0) {
        frames[count++] = static_cast<std::uintptr_t>(context.Rip);
        const DWORD64 priorRip = context.Rip;
        const DWORD64 priorRsp = context.Rsp;
        DWORD64 imageBase = 0;
        const PRUNTIME_FUNCTION function =
            RtlLookupFunctionEntry(context.Rip, &imageBase, nullptr);
        if (function != nullptr) {
            void* handlerData = nullptr;
            DWORD64 establisherFrame = 0;
            (void)RtlVirtualUnwind(UNW_FLAG_NHANDLER,
                                   imageBase,
                                   context.Rip,
                                   function,
                                   &context,
                                   &handlerData,
                                   &establisherFrame,
                                   nullptr);
        } else {
            DWORD64 returnAddress = 0;
            SIZE_T copied = 0;
            if (ReadProcessMemory(GetCurrentProcess(),
                                  reinterpret_cast<const void*>(context.Rsp),
                                  &returnAddress,
                                  sizeof returnAddress,
                                  &copied)
                    == FALSE
                || copied != sizeof returnAddress) {
                break;
            }
            context.Rip = returnAddress;
            context.Rsp += sizeof returnAddress;
        }
        if (context.Rip == priorRip && context.Rsp == priorRsp) {
            break;
        }
    }
    return count;
}

/** Briefly pauses only the recorded state-5 thread, copies its control context, then resumes it. */
void snapshot_state5_thread(std::uint32_t sample) noexcept {
    const DWORD threadId = g_state5ThreadId.load(std::memory_order_acquire);
    const HANDLE thread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
        FALSE,
        threadId);
    if (thread == nullptr || SuspendThread(thread) == static_cast<DWORD>(-1)) {
        if (thread != nullptr) {
            (void)CloseHandle(thread);
        }
        return;
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    const bool captured = GetThreadContext(thread, &context) != FALSE;
    std::array<std::uintptr_t, 2048> stack{};
    std::array<std::uintptr_t, 64> unwindFrames{};
    const std::size_t unwindCount =
        captured ? unwind_state5_context(context, unwindFrames) : 0;
    SIZE_T stackBytes = 0;
    if (captured) {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQuery(reinterpret_cast<const void*>(context.Rsp), &memory, sizeof memory)
                == sizeof memory
            && memory.State == MEM_COMMIT
            && (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            const auto regionEnd = reinterpret_cast<std::uintptr_t>(memory.BaseAddress)
                                   + memory.RegionSize;
            const std::size_t available = regionEnd > context.Rsp ? regionEnd - context.Rsp : 0;
            const std::size_t requested =
                available < sizeof stack ? available : sizeof stack;
            (void)ReadProcessMemory(GetCurrentProcess(),
                                    reinterpret_cast<const void*>(context.Rsp),
                                    stack.data(),
                                    requested,
                                    &stackBytes);
        }
    }
    (void)ResumeThread(thread);
    (void)CloseHandle(thread);
    if (!captured) {
        return;
    }

    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto imageAddress = reinterpret_cast<std::uintptr_t>(image);
    const std::size_t imageSize = game_image_size(image);
    const bool imageRip = context.Rip >= imageAddress && context.Rip - imageAddress < imageSize;
    std::array<char, 256> line{};
    const int length = imageRip
                           ? std::snprintf(
                                 line.data(),
                                 line.size(),
                                 "ev=bootflow stage=activity_selection_state5_snapshot sample=%u tid=%lu rip=0x%llX rip_rva=0x%llX rsp=0x%llX stack_bytes=%zu result=ok",
                                 sample,
                                 threadId,
                                 static_cast<unsigned long long>(context.Rip),
                                 static_cast<unsigned long long>(context.Rip - imageAddress),
                                 static_cast<unsigned long long>(context.Rsp),
                                 static_cast<std::size_t>(stackBytes))
                           : std::snprintf(
                                 line.data(),
                                 line.size(),
                                 "ev=bootflow stage=activity_selection_state5_snapshot sample=%u tid=%lu rip=0x%llX rip_rva=external rsp=0x%llX stack_bytes=%zu result=ok",
                                 sample,
                                 threadId,
                                 static_cast<unsigned long long>(context.Rip),
                                 static_cast<unsigned long long>(context.Rsp),
                                 static_cast<std::size_t>(stackBytes));
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }

    auto* const dawnImage =
        reinterpret_cast<std::byte*>(GetModuleHandleW(L"steam_api64.dll"));
    const auto dawnAddress = reinterpret_cast<std::uintptr_t>(dawnImage);
    const std::size_t dawnSize = game_image_size(dawnImage);
    std::array<char, core::log::kLineCapacity> unwound{};
    int unwindUsed = std::snprintf(
        unwound.data(),
        unwound.size(),
        "ev=bootflow stage=activity_selection_state5_unwind sample=%u tid=%lu frames=",
        sample,
        threadId);
    for (std::size_t index = 0;
         unwindUsed > 0 && index < unwindCount
         && static_cast<std::size_t>(unwindUsed) < unwound.size();
         ++index) {
        const std::uintptr_t address = unwindFrames[index];
        const char* kind = "x";
        unsigned long long value = static_cast<unsigned long long>(address);
        if (address >= imageAddress && address - imageAddress < imageSize) {
            kind = "g";
            value = static_cast<unsigned long long>(address - imageAddress);
        } else if (address >= dawnAddress && address - dawnAddress < dawnSize) {
            kind = "s";
            value = static_cast<unsigned long long>(address - dawnAddress);
        }
        const int appended = std::snprintf(
            unwound.data() + unwindUsed,
            unwound.size() - static_cast<std::size_t>(unwindUsed),
            "%s%s+0x%llX",
            index == 0 ? "" : ">",
            kind,
            value);
        if (appended <= 0
            || static_cast<std::size_t>(appended)
                   >= unwound.size() - static_cast<std::size_t>(unwindUsed)) {
            break;
        }
        unwindUsed += appended;
    }
    if (unwindUsed > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {unwound.data(), static_cast<std::size_t>(unwindUsed)});
    }

    std::array<char, core::log::kLineCapacity> frames{};
    int used = std::snprintf(frames.data(),
                             frames.size(),
                             "ev=bootflow stage=activity_selection_state5_stack sample=%u tid=%lu rvas=",
                             sample,
                             threadId);
    const std::size_t words = static_cast<std::size_t>(stackBytes) / sizeof(std::uintptr_t);
    std::size_t emitted = 0;
    for (std::size_t index = 0;
         used > 0 && index < words && emitted < 48
         && static_cast<std::size_t>(used) < frames.size();
         ++index) {
        const std::uintptr_t value = stack[index];
        if (value < imageAddress || value - imageAddress >= imageSize) {
            continue;
        }
        const int appended = std::snprintf(
            frames.data() + used,
            frames.size() - static_cast<std::size_t>(used),
            "%s0x%llX@+0x%zX",
            emitted == 0 ? "" : ",",
            static_cast<unsigned long long>(value - imageAddress),
            index * sizeof(std::uintptr_t));
        if (appended <= 0) {
            break;
        }
        used += appended;
        ++emitted;
    }
    if (used > 0) {
        const std::size_t frameLength = static_cast<std::size_t>(used) < frames.size()
                                            ? static_cast<std::size_t>(used)
                                            : frames.size() - 1;
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {frames.data(), frameLength});
    }
}

/**
 * Saves the original state-5 fiber stack rather than the worker thread's current scheduler stack.
 * The game may cooperatively switch away while the detoured state-5 call is still active, so the
 * Windows thread context alone no longer describes the suspended selection request.
 */
void dump_state5_fiber_stack(std::uint32_t sample) noexcept {
    constexpr std::size_t kBytesBelowEntry = 0x20000U;
    constexpr std::size_t kBytesAboveEntry = 0x2000U;
    constexpr std::uint64_t kHeaderMagic = 0x314B545346355453ULL; // "ST5FSTK1"
    struct Header {
        std::uint64_t magic;
        std::uint64_t begin;
        std::uint64_t entry;
        std::uint64_t end;
        std::uint32_t readableBytes;
        std::uint32_t readableRegions;
    };
    const std::uintptr_t entry = g_state5EntryStackTop.load(std::memory_order_acquire);
    const HMODULE dawn = GetModuleHandleW(L"steam_api64.dll");
    core::path::Buffer path{};
    if (entry <= kBytesBelowEntry || entry > UINTPTR_MAX - kBytesAboveEntry
        || dawn == nullptr || !core::path::artifact_directory(dawn, path)
        || !core::path::append(path, L"\\analysis")) {
        return;
    }
    if (CreateDirectoryW(path.chars.data(), nullptr) == FALSE
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }

    const std::uintptr_t begin = entry - kBytesBelowEntry;
    const std::uintptr_t end = entry + kBytesAboveEntry;
    const std::size_t requestedBytes = end - begin;
    auto* const capture = static_cast<std::byte*>(VirtualAlloc(nullptr,
                                                               requestedBytes,
                                                               MEM_COMMIT | MEM_RESERVE,
                                                               PAGE_READWRITE));
    if (capture == nullptr) {
        return;
    }
    std::memset(capture, 0, requestedBytes);

    std::size_t readableBytes = 0;
    std::uint32_t readableRegions = 0;
    for (std::uintptr_t cursor = begin; cursor < end;) {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &memory, sizeof memory)
            != sizeof memory) {
            break;
        }
        const std::uintptr_t regionBegin =
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const std::uintptr_t regionLimit = regionBegin + memory.RegionSize;
        const std::uintptr_t segmentEnd = regionLimit < end ? regionLimit : end;
        if (segmentEnd <= cursor) {
            break;
        }
        if (memory.State == MEM_COMMIT
            && (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            SIZE_T copied = 0;
            const SIZE_T segmentBytes = segmentEnd - cursor;
            if (ReadProcessMemory(GetCurrentProcess(),
                                  reinterpret_cast<const void*>(cursor),
                                  capture + (cursor - begin),
                                  segmentBytes,
                                  &copied)
                != FALSE) {
                readableBytes += static_cast<std::size_t>(copied);
                ++readableRegions;
            }
        }
        cursor = segmentEnd;
    }

    std::array<wchar_t, 80> filename{};
    const int nameLength = std::swprintf(filename.data(),
                                         filename.size(),
                                         L"\\activity_state5_fiber_stack.sample_%u.bin",
                                         sample);
    if (nameLength <= 0 || !core::path::append(path, filename.data())) {
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        (void)VirtualFree(capture, 0, MEM_RELEASE);
        return;
    }
    const Header header{kHeaderMagic,
                        static_cast<std::uint64_t>(begin),
                        static_cast<std::uint64_t>(entry),
                        static_cast<std::uint64_t>(end),
                        static_cast<std::uint32_t>(readableBytes),
                        readableRegions};
    DWORD headerWritten = 0;
    DWORD dataWritten = 0;
    const bool complete =
        WriteFile(file, &header, sizeof header, &headerWritten, nullptr) != FALSE
        && headerWritten == sizeof header
        && WriteFile(file,
                     capture,
                     static_cast<DWORD>(requestedBytes),
                     &dataWritten,
                     nullptr)
               != FALSE
        && dataWritten == requestedBytes && FlushFileBuffers(file) != FALSE;
    (void)CloseHandle(file);
    (void)VirtualFree(capture, 0, MEM_RELEASE);

    std::array<char, 256> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_state5_fiber_stack sample=%u entry=0x%llX begin=0x%llX end=0x%llX requested=%zu readable=%zu regions=%u written=%lu result=%s",
        sample,
        static_cast<unsigned long long>(entry),
        static_cast<unsigned long long>(begin),
        static_cast<unsigned long long>(end),
        requestedBytes,
        readableBytes,
        readableRegions,
        static_cast<unsigned long>(dataWritten),
        complete ? "ok" : "write");
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         complete ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Saves the inactive Windows fiber object that owns the suspended state-5 CPU context. */
void dump_state5_fiber_context(std::uint32_t sample) noexcept {
    constexpr std::size_t kRequestedBytes = 0x1000U;
    constexpr std::uint64_t kHeaderMagic = 0x3158544346355453ULL; // "ST5FCTX1"
    struct Header {
        std::uint64_t magic;
        std::uint64_t fiber;
        std::uint64_t bytes;
    };
    void* const fiber = g_state5FiberContext.load(std::memory_order_acquire);
    const HMODULE dawn = GetModuleHandleW(L"steam_api64.dll");
    MEMORY_BASIC_INFORMATION memory{};
    core::path::Buffer path{};
    if (fiber == nullptr || dawn == nullptr
        || VirtualQuery(fiber, &memory, sizeof memory) != sizeof memory
        || memory.State != MEM_COMMIT
        || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0
        || !core::path::artifact_directory(dawn, path)
        || !core::path::append(path, L"\\analysis")) {
        return;
    }
    if (CreateDirectoryW(path.chars.data(), nullptr) == FALSE
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(fiber);
    const std::uintptr_t regionEnd =
        reinterpret_cast<std::uintptr_t>(memory.BaseAddress) + memory.RegionSize;
    const std::size_t available = regionEnd > address ? regionEnd - address : 0;
    const std::size_t bytes = available < kRequestedBytes ? available : kRequestedBytes;
    if (bytes == 0 || bytes > MAXDWORD) {
        return;
    }

    std::array<wchar_t, 88> filename{};
    const int nameLength = std::swprintf(filename.data(),
                                         filename.size(),
                                         L"\\activity_state5_fiber_context.sample_%u.bin",
                                         sample);
    if (nameLength <= 0 || !core::path::append(path, filename.data())) {
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    const Header header{kHeaderMagic,
                        static_cast<std::uint64_t>(address),
                        static_cast<std::uint64_t>(bytes)};
    DWORD headerWritten = 0;
    DWORD dataWritten = 0;
    const bool complete =
        WriteFile(file, &header, sizeof header, &headerWritten, nullptr) != FALSE
        && headerWritten == sizeof header
        && WriteFile(file, fiber, static_cast<DWORD>(bytes), &dataWritten, nullptr) != FALSE
        && dataWritten == bytes && FlushFileBuffers(file) != FALSE;
    (void)CloseHandle(file);

    std::array<char, 208> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_state5_fiber_context sample=%u fiber=%p bytes=%lu result=%s",
        sample,
        fiber,
        static_cast<unsigned long>(dataWritten),
        complete ? "ok" : "write");
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         complete ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Samples the same state-5 thread four times so a transient wait cannot hide the final stall. */
DWORD WINAPI state5_snapshot_worker(void*) noexcept {
    constexpr std::array<DWORD, 4> kDelays{250, 750, 2000, 7000};
    for (std::uint32_t sample = 0; sample < kDelays.size(); ++sample) {
        Sleep(kDelays[sample]);
        dump_state5_fiber_context(sample);
        dump_state5_fiber_stack(sample);
        snapshot_state5_thread(sample);
    }
    return 0;
}

/**
 * Saves the builder's live fiber stack so the deepest native return address identifies the
 * post-registration helper that failed to return. This is observation only: no route state or
 * native argument is changed.
 */
void dump_selection_route_object_builder_stack(std::uint32_t sample) noexcept {
    constexpr std::size_t kBytesBelowEntry = 0x20000U;
    constexpr std::size_t kBytesAboveEntry = 0x2000U;
    constexpr std::uint64_t kHeaderMagic = 0x314B5453424F5253ULL; // "SROBSTK1"
    struct Header {
        std::uint64_t magic;
        std::uint64_t begin;
        std::uint64_t entry;
        std::uint64_t end;
        std::uint64_t gameImage;
        std::uint64_t gameImageSize;
        std::uint32_t readableBytes;
        std::uint32_t readableRegions;
        std::uint32_t sample;
        std::uint32_t reserved;
    };

    const std::uintptr_t entry = static_cast<std::uintptr_t>(
        g_selectionRouteObjectBuilderEntryStack.load(std::memory_order_acquire));
    const HMODULE dawn = GetModuleHandleW(L"steam_api64.dll");
    auto* const gameImage = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const std::size_t gameImageSize = game_image_size(gameImage);
    core::path::Buffer path{};
    if (entry <= kBytesBelowEntry || entry > UINTPTR_MAX - kBytesAboveEntry
        || dawn == nullptr || gameImage == nullptr || gameImageSize == 0
        || !core::path::artifact_directory(dawn, path)
        || !core::path::append(path, L"\\analysis")) {
        return;
    }
    if (CreateDirectoryW(path.chars.data(), nullptr) == FALSE
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }

    const std::uintptr_t begin = entry - kBytesBelowEntry;
    const std::uintptr_t end = entry + kBytesAboveEntry;
    const std::size_t requestedBytes = end - begin;
    auto* const capture = static_cast<std::byte*>(VirtualAlloc(nullptr,
                                                               requestedBytes,
                                                               MEM_COMMIT | MEM_RESERVE,
                                                               PAGE_READWRITE));
    if (capture == nullptr) {
        return;
    }
    std::memset(capture, 0, requestedBytes);

    std::size_t readableBytes = 0;
    std::uint32_t readableRegions = 0;
    for (std::uintptr_t cursor = begin; cursor < end;) {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQuery(reinterpret_cast<const void*>(cursor), &memory, sizeof memory)
            != sizeof memory) {
            break;
        }
        const std::uintptr_t regionBegin =
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const std::uintptr_t regionLimit = regionBegin + memory.RegionSize;
        const std::uintptr_t segmentEnd = regionLimit < end ? regionLimit : end;
        if (segmentEnd <= cursor) {
            break;
        }
        if (memory.State == MEM_COMMIT
            && (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            SIZE_T copied = 0;
            const SIZE_T segmentBytes = segmentEnd - cursor;
            if (ReadProcessMemory(GetCurrentProcess(),
                                  reinterpret_cast<const void*>(cursor),
                                  capture + (cursor - begin),
                                  segmentBytes,
                                  &copied)
                != FALSE) {
                readableBytes += static_cast<std::size_t>(copied);
                ++readableRegions;
            }
        }
        cursor = segmentEnd;
    }

    std::array<wchar_t, 96> filename{};
    const int nameLength = std::swprintf(
        filename.data(),
        filename.size(),
        L"\\activity_selection_route_object_builder_stack.sample_%u.bin",
        sample);
    if (nameLength <= 0 || !core::path::append(path, filename.data())) {
        (void)VirtualFree(capture, 0, MEM_RELEASE);
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        (void)VirtualFree(capture, 0, MEM_RELEASE);
        return;
    }
    const Header header{
        kHeaderMagic,
        static_cast<std::uint64_t>(begin),
        static_cast<std::uint64_t>(entry),
        static_cast<std::uint64_t>(end),
        static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(gameImage)),
        static_cast<std::uint64_t>(gameImageSize),
        static_cast<std::uint32_t>(readableBytes),
        readableRegions,
        sample,
        0U};
    DWORD headerWritten = 0;
    DWORD dataWritten = 0;
    const bool complete =
        WriteFile(file, &header, sizeof header, &headerWritten, nullptr) != FALSE
        && headerWritten == sizeof header
        && WriteFile(file,
                     capture,
                     static_cast<DWORD>(requestedBytes),
                     &dataWritten,
                     nullptr)
               != FALSE
        && dataWritten == requestedBytes && FlushFileBuffers(file) != FALSE;
    (void)CloseHandle(file);
    (void)VirtualFree(capture, 0, MEM_RELEASE);

    std::array<char, 320> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_route_object_builder_stack sample=%u entry=0x%llX begin=0x%llX end=0x%llX game=0x%llX game_size=0x%zX requested=%zu readable=%zu regions=%u written=%lu result=%s",
        sample,
        static_cast<unsigned long long>(entry),
        static_cast<unsigned long long>(begin),
        static_cast<unsigned long long>(end),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(gameImage)),
        gameImageSize,
        requestedBytes,
        readableBytes,
        readableRegions,
        static_cast<unsigned long>(dataWritten),
        complete ? "ok" : "write");
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         complete ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Samples the builder stack at three delays so a transient helper cannot mimic the final stall. */
DWORD WINAPI selection_route_object_builder_snapshot_worker(void*) noexcept {
    constexpr std::array<DWORD, 3> kDelays{250, 1000, 4000};
    for (std::uint32_t sample = 0; sample < kDelays.size(); ++sample) {
        Sleep(kDelays[sample]);
        if (g_selectionRouteObjectBuilderReturned.load(std::memory_order_acquire)) {
            break;
        }
        dump_selection_route_object_builder_stack(sample);
    }
    return 0;
}

/** Hashes the decoded selection prefix so the per-frame observer logs only real record changes. */
[[nodiscard]] std::uint64_t selection_fingerprint(
    std::span<const std::byte> record) noexcept {
    constexpr std::uint64_t kOffsetBasis = 14695981039346656037ULL;
    constexpr std::uint64_t kPrime = 1099511628211ULL;
    constexpr std::size_t kObservedBytes =
        kSelectionOffset + kPackageNameOffset + kPackageNameCapacity;
    std::uint64_t hash = kOffsetBasis;
    const std::size_t size = record.size() < kObservedBytes ? record.size() : kObservedBytes;
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= static_cast<std::uint8_t>(record[index]);
        hash *= kPrime;
    }
    return hash;
}

/** Records the earliest appearance and every mutation of one state-machine selection. */
void observe_pump_record(std::byte* manager,
                         std::size_t slot,
                         const char* phase) noexcept {
    const auto offset = kFirstRecordOffset + slot * kRecordStride;
    const std::span<const std::byte> record{manager + offset, kRecordStride};
    const std::uint64_t fingerprint = selection_fingerprint(record);
    if (g_pumpFingerprints[slot].exchange(fingerprint, std::memory_order_relaxed)
        == fingerprint) {
        return;
    }

    std::int32_t state = -1;
    std::int16_t sourceActivity = -1;
    std::int16_t destinationActivity = -1;
    std::memcpy(&state, record.data(), sizeof state);
    std::memcpy(&sourceActivity,
                record.data() + kSelectionOffset + kSourceActivityIndexOffset,
                sizeof sourceActivity);
    std::memcpy(&destinationActivity,
                record.data() + kSelectionOffset + kActivityIndexOffset,
                sizeof destinationActivity);
    std::array<char, kPackageNameCapacity + 1> package{};
    std::memcpy(package.data(),
                record.data() + kSelectionOffset + kPackageNameOffset,
                kPackageNameCapacity);
    std::size_t packageLength = 0;
    while (packageLength < kPackageNameCapacity && package[packageLength] != '\0') {
        ++packageLength;
    }

    std::array<char, 256> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_state_machine slot=%zu phase=%s state=%d source=%d destination=%d package=%.*s fingerprint=0x%llX manager=%p",
        slot,
        phase,
        state,
        static_cast<int>(sourceActivity),
        static_cast<int>(destinationActivity),
        static_cast<int>(packageLength),
        package.data(),
        static_cast<unsigned long long>(fingerprint),
        static_cast<void*>(manager));
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    if (slot == 0 && sourceActivity == kChosenActivityIndex
        && destinationActivity == kHomecomingActivityIndex
        && std::string_view(package.data(), packageLength) == "mission_towerfall") {
        notify_homecoming_authored_selection(record.data() + kSelectionOffset);
    }
}

/** Writes the complete client activity record while all of its opaque handles are still present. */
void dump_record(std::int32_t slot,
                 const wchar_t* phase,
                 std::span<const std::byte> record) noexcept {
    const HMODULE dawn = GetModuleHandleW(L"steam_api64.dll");
    core::path::Buffer path{};
    if (dawn == nullptr || !core::path::artifact_directory(dawn, path)
        || !core::path::append(path, L"\\analysis")) {
        return;
    }
    if (CreateDirectoryW(path.chars.data(), nullptr) == FALSE
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }
    std::array<wchar_t, 96> filename{};
    const int nameLength = std::swprintf(
        filename.data(), filename.size(), L"\\activity_client.slot_%d.%ls.bin", slot, phase);
    if (nameLength <= 0 || !core::path::append(path, filename.data())) {
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    const bool complete =
        WriteFile(file,
                  record.data(),
                  static_cast<DWORD>(record.size()),
                  &written,
                  nullptr)
            != FALSE
        && written == record.size() && FlushFileBuffers(file) != FALSE;
    (void)CloseHandle(file);
    std::array<char, 128> line{};
    const int length = std::snprintf(line.data(),
                                     line.size(),
                                     "ev=bootflow stage=activity_selection_probe slot=%d phase=%ls bytes=%lu result=%s",
                                     slot,
                                     phase,
                                     static_cast<unsigned long>(written),
                                     complete ? "ok" : "write");
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         complete ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Saves one original runtime-decrypted function before its entry point is detoured. */
void dump_code(const wchar_t* name,
               const std::byte* target,
               std::size_t requestedBytes) noexcept {
    const HMODULE dawn = GetModuleHandleW(L"steam_api64.dll");
    MEMORY_BASIC_INFORMATION memory{};
    core::path::Buffer path{};
    if (dawn == nullptr || target == nullptr || requestedBytes == 0
        || VirtualQuery(target, &memory, sizeof memory) != sizeof memory
        || memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0
        || !core::path::artifact_directory(dawn, path)
        || !core::path::append(path, L"\\analysis")) {
        return;
    }
    if (CreateDirectoryW(path.chars.data(), nullptr) == FALSE
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }
    const auto regionEnd = reinterpret_cast<std::uintptr_t>(memory.BaseAddress) + memory.RegionSize;
    const auto address = reinterpret_cast<std::uintptr_t>(target);
    const std::size_t available = regionEnd > address ? regionEnd - address : 0;
    const std::size_t bytes = available < requestedBytes ? available : requestedBytes;
    if (bytes == 0) {
        return;
    }
    std::array<wchar_t, 96> filename{};
    const int nameLength =
        std::swprintf(filename.data(), filename.size(), L"\\activity_code.%ls.bin", name);
    if (nameLength <= 0 || !core::path::append(path, filename.data())) {
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    const bool complete = WriteFile(file,
                                    target,
                                    static_cast<DWORD>(bytes),
                                    &written,
                                    nullptr)
                              != FALSE
                          && written == bytes && FlushFileBuffers(file) != FALSE;
    (void)CloseHandle(file);
    std::array<char, 144> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_code_dump name=%ls bytes=%lu result=%s",
        name,
        static_cast<unsigned long>(written),
        complete ? "ok" : "write");
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         complete ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

constexpr DWORD64 kSelectionStateOneWatchDr6Hit = 1ULL << 3U;
constexpr DWORD64 kSelectionStateOneWatchDr7SlotMask =
    (1ULL << 6U) | (1ULL << 7U) | (0xFULL << 28U);
constexpr DWORD64 kSelectionStateOneWatchDr7WriteDword =
    (1ULL << 6U) | (1ULL << 28U) | (3ULL << 30U);

/** Clears the diagnostic-register slot from every other existing process thread. */
void clear_selection_state_one_watchpoints() noexcept {
    const DWORD processId = GetCurrentProcessId();
    const DWORD currentThreadId = GetCurrentThreadId();
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof entry;
    if (Thread32First(snapshot, &entry) != FALSE) {
        do {
            if (entry.th32OwnerProcessID != processId
                || entry.th32ThreadID == currentThreadId) {
                continue;
            }
            const HANDLE thread = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
                    | THREAD_QUERY_INFORMATION,
                FALSE,
                entry.th32ThreadID);
            if (thread == nullptr
                || SuspendThread(thread) == static_cast<DWORD>(-1)) {
                if (thread != nullptr) {
                    (void)CloseHandle(thread);
                }
                continue;
            }
            CONTEXT context{};
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &context) != FALSE
                && context.Dr3
                       == g_selectionStateOneWatchAddress.load(std::memory_order_acquire)) {
                context.Dr3 = 0;
                context.Dr6 = 0;
                context.Dr7 &= ~kSelectionStateOneWatchDr7SlotMask;
                (void)SetThreadContext(thread, &context);
            }
            (void)ResumeThread(thread);
            (void)CloseHandle(thread);
        } while (Thread32Next(snapshot, &entry) != FALSE);
    }
    (void)CloseHandle(snapshot);
}

/** Records the exact instruction immediately after the first write of state 1. */
LONG CALLBACK selection_state_one_watch_handler(EXCEPTION_POINTERS* exception) noexcept {
    if (exception == nullptr || exception->ExceptionRecord == nullptr
        || exception->ContextRecord == nullptr
        || exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    CONTEXT* const context = exception->ContextRecord;
    const std::uintptr_t watched =
        g_selectionStateOneWatchAddress.load(std::memory_order_acquire);
    if ((context->Dr6 & kSelectionStateOneWatchDr6Hit) == 0U || watched == 0U
        || context->Dr3 != watched) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    const SelectionStateOneWatchStatus status =
        g_selectionStateOneWatchStatus.load(std::memory_order_acquire);
    if (status == SelectionStateOneWatchStatus::disabled
        || status == SelectionStateOneWatchStatus::captured) {
        context->Dr3 = 0;
        context->Dr6 = 0;
        context->Dr7 &= ~kSelectionStateOneWatchDr7SlotMask;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (status != SelectionStateOneWatchStatus::armed) {
        context->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    std::int32_t value = -999;
    __try {
        value = *reinterpret_cast<const std::int32_t*>(watched);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value = -999;
    }
    if (value != 1) {
        g_selectionStateOneWatchIgnoredWrites.fetch_add(1U,
                                                         std::memory_order_relaxed);
        context->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    SelectionStateOneWatchStatus expected = SelectionStateOneWatchStatus::armed;
    if (g_selectionStateOneWatchStatus.compare_exchange_strong(
            expected,
            SelectionStateOneWatchStatus::capturing,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        g_selectionStateOneWatchContext = *context;
        g_selectionStateOneWatchThreadId.store(GetCurrentThreadId(),
                                                std::memory_order_relaxed);
        g_selectionStateOneWatchValue.store(value, std::memory_order_relaxed);
        g_selectionStateOneWatchExceptionAddress.store(
            reinterpret_cast<std::uintptr_t>(
                exception->ExceptionRecord->ExceptionAddress),
            std::memory_order_relaxed);
        g_selectionStateOneWatchStatus.store(SelectionStateOneWatchStatus::captured,
                                             std::memory_order_release);
    }
    context->Dr3 = 0;
    context->Dr6 = 0;
    context->Dr7 &= ~kSelectionStateOneWatchDr7SlotMask;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/** Arms DR3 on every existing game thread without pausing the caller that requested it. */
DWORD WINAPI selection_state_one_watch_arm_worker(void* parameter) noexcept {
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(parameter);
    const DWORD processId = GetCurrentProcessId();
    const DWORD currentThreadId = GetCurrentThreadId();
    std::uint32_t attempted = 0;
    std::uint32_t armed = 0;
    std::uint32_t occupied = 0;
    std::uint32_t failed = 0;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof entry;
        if (Thread32First(snapshot, &entry) != FALSE) {
            do {
                if (entry.th32OwnerProcessID != processId
                    || entry.th32ThreadID == currentThreadId
                    || g_selectionStateOneWatchStatus.load(std::memory_order_acquire)
                           != SelectionStateOneWatchStatus::armed) {
                    continue;
                }
                ++attempted;
                const HANDLE thread = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
                        | THREAD_QUERY_INFORMATION,
                    FALSE,
                    entry.th32ThreadID);
                if (thread == nullptr
                    || SuspendThread(thread) == static_cast<DWORD>(-1)) {
                    ++failed;
                    if (thread != nullptr) {
                        (void)CloseHandle(thread);
                    }
                    continue;
                }
                CONTEXT context{};
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                bool installed = false;
                if (GetThreadContext(thread, &context) != FALSE) {
                    if (context.Dr3 == 0U
                        && (context.Dr7 & kSelectionStateOneWatchDr7SlotMask) == 0U) {
                        context.Dr3 = address;
                        context.Dr6 = 0;
                        context.Dr7 =
                            (context.Dr7 & ~kSelectionStateOneWatchDr7SlotMask)
                            | kSelectionStateOneWatchDr7WriteDword;
                        installed = SetThreadContext(thread, &context) != FALSE;
                    } else {
                        ++occupied;
                    }
                }
                if (installed) {
                    ++armed;
                } else if (context.Dr3 == 0U
                           && (context.Dr7 & kSelectionStateOneWatchDr7SlotMask) == 0U) {
                    ++failed;
                }
                (void)ResumeThread(thread);
                (void)CloseHandle(thread);
            } while (Thread32Next(snapshot, &entry) != FALSE);
        }
        (void)CloseHandle(snapshot);
    }
    g_selectionStateOneWatchArmedThreads.store(armed, std::memory_order_release);
    if (armed == 0U) {
        SelectionStateOneWatchStatus expected = SelectionStateOneWatchStatus::armed;
        (void)g_selectionStateOneWatchStatus.compare_exchange_strong(
            expected,
            SelectionStateOneWatchStatus::idle,
            std::memory_order_acq_rel,
            std::memory_order_acquire);
    }
    std::array<char, 384> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_state1_write_watch_arm result=%s target=%p attempted=%u armed=%u occupied=%u failed=%u mode=observe_only",
        armed > 0U ? "ok" : "fail",
        reinterpret_cast<void*>(address),
        attempted,
        armed,
        occupied,
        failed);
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         armed > 0U ? core::log::Level::info
                                    : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    return 0;
}

/** Starts one write watch after the first native readiness rejection exposes slot 0. */
void arm_selection_state_one_watch(void* activityContext) noexcept {
    bool expected = false;
    if (activityContext == nullptr || g_selectionStateOneWatchVectoredHandler == nullptr
        || !g_selectionStateOneWatchArmStarted.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return;
    }
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(activityContext)
                                   + kFirstRecordOffset;
    g_selectionStateOneWatchAddress.store(address, std::memory_order_release);
    g_selectionStateOneWatchStatus.store(SelectionStateOneWatchStatus::armed,
                                         std::memory_order_release);
    const HANDLE worker = CreateThread(nullptr,
                                       0,
                                       &selection_state_one_watch_arm_worker,
                                       reinterpret_cast<void*>(address),
                                       0,
                                       nullptr);
    if (worker != nullptr) {
        (void)CloseHandle(worker);
        return;
    }
    g_selectionStateOneWatchStatus.store(SelectionStateOneWatchStatus::idle,
                                         std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::warn,
        "ev=bootflow stage=activity_selection_state1_write_watch_arm result=fail reason=create_thread mode=observe_only");
}

/** Publishes the captured writer context once, immediately before the late registry callback. */
[[nodiscard]] __declspec(noinline) bool selection_state_one_write_watch_enabled() noexcept {
    return kEnableSelectionStateOneWriteWatch;
}

void log_selection_state_one_watch() noexcept {
    if (!selection_state_one_write_watch_enabled()) {
        return;
    }
    if (g_selectionStateOneWatchLogged.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    const SelectionStateOneWatchStatus status =
        g_selectionStateOneWatchStatus.load(std::memory_order_acquire);
    const bool captured = status == SelectionStateOneWatchStatus::captured;
    CONTEXT context{};
    if (captured) {
        context = g_selectionStateOneWatchContext;
    }
    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    const std::size_t imageSize = game_image_size(image);
    const std::uintptr_t nextRva =
        captured && image != nullptr
                && context.Rip >= reinterpret_cast<std::uintptr_t>(image)
                && context.Rip - reinterpret_cast<std::uintptr_t>(image) < imageSize
            ? context.Rip - reinterpret_cast<std::uintptr_t>(image)
            : 0U;
    const std::uintptr_t exceptionAddress =
        g_selectionStateOneWatchExceptionAddress.load(std::memory_order_acquire);
    const std::uintptr_t exceptionRva =
        captured && image != nullptr
                && exceptionAddress >= reinterpret_cast<std::uintptr_t>(image)
                && exceptionAddress - reinterpret_cast<std::uintptr_t>(image) < imageSize
            ? exceptionAddress - reinterpret_cast<std::uintptr_t>(image)
            : 0U;
    if (nextRva > 0x80U) {
        dump_code(L"activity_selection_state1_writer_window",
                  image + nextRva - 0x80U,
                  0x200U);
    }
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_state1_write_watch result=%s status=%u target=%p value=%d writer_thread=%lu next_rip=0x%llX next_rva=0x%llX exception_rva=0x%llX ignored_writes=%u armed_threads=%u rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX rsi=0x%llX rdi=0x%llX rbp=0x%llX rsp=0x%llX mode=observe_only",
        captured ? "captured" : "missed",
        static_cast<unsigned int>(status),
        reinterpret_cast<void*>(
            g_selectionStateOneWatchAddress.load(std::memory_order_acquire)),
        g_selectionStateOneWatchValue.load(std::memory_order_acquire),
        static_cast<unsigned long>(
            g_selectionStateOneWatchThreadId.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(context.Rip),
        static_cast<unsigned long long>(nextRva),
        static_cast<unsigned long long>(exceptionRva),
        g_selectionStateOneWatchIgnoredWrites.load(std::memory_order_acquire),
        g_selectionStateOneWatchArmedThreads.load(std::memory_order_acquire),
        static_cast<unsigned long long>(context.Rax),
        static_cast<unsigned long long>(context.Rbx),
        static_cast<unsigned long long>(context.Rcx),
        static_cast<unsigned long long>(context.Rdx),
        static_cast<unsigned long long>(context.R8),
        static_cast<unsigned long long>(context.R9),
        static_cast<unsigned long long>(context.R10),
        static_cast<unsigned long long>(context.R11),
        static_cast<unsigned long long>(context.Rsi),
        static_cast<unsigned long long>(context.Rdi),
        static_cast<unsigned long long>(context.Rbp),
        static_cast<unsigned long long>(context.Rsp));
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         captured ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    if (captured) {
        std::array<std::uintptr_t, 32> frames{};
        const std::size_t frameCount = unwind_state5_context(context, frames);
        std::array<char, core::log::kLineCapacity> stackLine{};
        int stackLength = std::snprintf(
            stackLine.data(),
            stackLine.size(),
            "ev=bootflow stage=activity_selection_state1_write_watch_stack count=%u rvas=",
            static_cast<unsigned int>(frameCount));
        for (std::size_t index = 0;
             index < frameCount && stackLength > 0
             && static_cast<std::size_t>(stackLength) < stackLine.size();
             ++index) {
            const std::uintptr_t frame = frames[index];
            const std::uintptr_t rva =
                image != nullptr && frame >= reinterpret_cast<std::uintptr_t>(image)
                        && frame - reinterpret_cast<std::uintptr_t>(image) < imageSize
                    ? frame - reinterpret_cast<std::uintptr_t>(image)
                    : 0U;
            const int appended = std::snprintf(
                stackLine.data() + stackLength,
                stackLine.size() - static_cast<std::size_t>(stackLength),
                "%s0x%llX",
                index == 0U ? "" : ",",
                static_cast<unsigned long long>(rva));
            if (appended <= 0) {
                break;
            }
            stackLength += appended;
        }
        if (stackLength > 0) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::info,
                {stackLine.data(),
                 static_cast<std::size_t>(stackLength) < stackLine.size()
                     ? static_cast<std::size_t>(stackLength)
                     : stackLine.size() - 1U});
        }
    }
    g_selectionStateOneWatchStatus.store(SelectionStateOneWatchStatus::disabled,
                                         std::memory_order_release);
    clear_selection_state_one_watchpoints();
}

/** Saves the final current-activity object that the in-world start formats and executes. */
void dump_current_activity(const wchar_t* phase, std::span<const std::byte> bytes) noexcept {
    const HMODULE dawn = GetModuleHandleW(L"steam_api64.dll");
    core::path::Buffer path{};
    if (dawn == nullptr || !core::path::artifact_directory(dawn, path)
        || !core::path::append(path, L"\\analysis")) {
        return;
    }
    if (CreateDirectoryW(path.chars.data(), nullptr) == FALSE
        && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }
    std::array<wchar_t, 72> filename{};
    const int nameLength = std::swprintf(
        filename.data(), filename.size(), L"\\activity_current.%ls.bin", phase);
    if (nameLength <= 0 || !core::path::append(path, filename.data())) {
        return;
    }
    const HANDLE file = CreateFileW(path.chars.data(),
                                    GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    const bool complete =
        WriteFile(file,
                  bytes.data(),
                  static_cast<DWORD>(bytes.size()),
                  &written,
                  nullptr)
            != FALSE
        && written == bytes.size() && FlushFileBuffers(file) != FALSE;
    (void)CloseHandle(file);
    std::array<char, 128> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=current_activity_probe phase=%ls bytes=%lu result=%s",
        phase,
        static_cast<unsigned long>(written),
        complete ? "ok" : "write");
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         complete ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

[[nodiscard]] bool force_opening_selection(std::span<std::byte> bytes,
                                           std::size_t selectionOffset,
                                           bool replaceSource,
                                           std::int16_t* forcedIndex) noexcept;

/** Corrects the native selection-manager record before the launcher copies or publishes it. */
__declspec(noinline) std::byte* __fastcall selection_launch_state_accessor(
    std::byte* context) noexcept {
    const SelectionLaunchStateAccessor original =
        g_selectionLaunchStateOriginal.load(std::memory_order_acquire);
    std::byte* const state = original != nullptr ? original(context) : nullptr;
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto* const caller = static_cast<const std::byte*>(_ReturnAddress());
    const bool launcherCall = image != nullptr && caller == image + kSelectionLaunchStateAccessorReturnRva;
    if (state != nullptr && launcherCall
        && !g_selectionLaunchStateDumped.exchange(true, std::memory_order_acq_rel)) {
        dump_current_activity(
            L"selection_launch_manager_before",
            {state, kSelectionLaunchStateProbeBytes});
        std::int16_t source = -1;
        std::int16_t destinationBefore = -1;
        std::memcpy(&source,
                    state + 8 + kSelectionOffset + kSourceActivityIndexOffset,
                    sizeof source);
        std::memcpy(&destinationBefore,
                    state + 8 + kSelectionOffset + kActivityIndexOffset,
                    sizeof destinationBefore);
        const bool committed =
            state::activity::forced::commit_homecoming_authored_selection(source,
                                                                           destinationBefore);
        std::int16_t forcedIndex = -1;
        const bool forced = source == kChosenActivityIndex
                            && destinationBefore == kChosenActivityIndex
                            && force_opening_selection(
                                {state + 8, kRecordStride},
                                kSelectionOffset,
                                false,
                                &forcedIndex);
        std::int16_t destinationAfter = destinationBefore;
        std::memcpy(&destinationAfter,
                    state + 8 + kSelectionOffset + kActivityIndexOffset,
                    sizeof destinationAfter);
        if (forced) {
            g_prelaunchOwnerTraceArmed.store(true, std::memory_order_release);
            g_selectionPublicationOwnerAccessObserved.store(0U,
                                                            std::memory_order_release);
            g_tracedPrelaunchRecord.store(nullptr, std::memory_order_release);
            g_selectionPublicationStateMachineObserved.store(0U,
                                                              std::memory_order_release);
            g_selectionPublicationStateFingerprint.store(0U,
                                                          std::memory_order_release);
            g_selectionRouteReadyObserved.store(0U,
                                                 std::memory_order_release);
            g_selectionRouteRegistrySlotWriterObserved.store(
                0U,
                std::memory_order_release);
            g_selectionRouteDestinationSlotRequestObserved.store(
                0U,
                std::memory_order_release);
            g_selectionRouteSlotInitializeObserved.store(0U,
                                                           std::memory_order_release);
            g_selectionRoutePackageRegistrationObserved.store(
                0U,
                std::memory_order_release);
            g_homecomingPrelaunchPublicationPending.store(true, std::memory_order_release);
            dump_current_activity(
                L"selection_launch_manager_after",
                {state, kSelectionLaunchStateProbeBytes});
        }
        std::array<char, 320> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_launch_state result=ok caller_rva=0x%llX context=%p state=%p source=%d destination_before=%d destination_after=%d committed=%d forced=%d",
            static_cast<unsigned long long>(caller - image),
            static_cast<void*>(context),
            static_cast<void*>(state),
            static_cast<int>(source),
            static_cast<int>(destinationBefore),
            static_cast<int>(destinationAfter),
            committed ? 1 : 0,
            forced ? 1 : 0);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    return state;
}

struct SelectionPublicationSnapshot {
    bool valid{};
    std::uint8_t generation{};
    std::uint8_t mode{};
    std::uint8_t type{};
    std::uint8_t state{};
    std::int16_t source{-1};
    std::int16_t destination{-1};
    std::uint64_t startTick{};
    std::int32_t delay{};
    std::int32_t remaining{};
};

[[nodiscard]] SelectionPublicationSnapshot snapshot_selection_publication(
    const std::byte* record) noexcept {
    SelectionPublicationSnapshot snapshot{};
    if (record == nullptr) {
        return snapshot;
    }
    __try {
        snapshot.generation = std::to_integer<std::uint8_t>(record[0]);
        snapshot.mode = std::to_integer<std::uint8_t>(record[1]);
        snapshot.type = std::to_integer<std::uint8_t>(record[2]);
        snapshot.state = std::to_integer<std::uint8_t>(record[3]);
        std::memcpy(&snapshot.source, record + 0x0A, sizeof snapshot.source);
        std::memcpy(&snapshot.destination,
                    record + 0x0C,
                    sizeof snapshot.destination);
        std::memcpy(&snapshot.startTick, record + 0x120, sizeof snapshot.startTick);
        std::memcpy(&snapshot.delay, record + 0x128, sizeof snapshot.delay);
        std::memcpy(&snapshot.remaining, record + 0x12C, sizeof snapshot.remaining);
        snapshot.valid = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snapshot = {};
    }
    return snapshot;
}

[[nodiscard]] std::uint64_t selection_publication_fingerprint(
    const SelectionPublicationSnapshot& snapshot) noexcept {
    if (!snapshot.valid) {
        return 0;
    }
    return static_cast<std::uint64_t>(snapshot.generation)
           | static_cast<std::uint64_t>(snapshot.mode) << 8U
           | static_cast<std::uint64_t>(snapshot.type) << 16U
           | static_cast<std::uint64_t>(snapshot.state) << 24U
           | static_cast<std::uint64_t>(static_cast<std::uint32_t>(snapshot.remaining)) << 32U;
}

/** Observes the native Homecoming prelaunch state transition without mutation. */
__declspec(noinline) void __fastcall selection_publication_state_machine(
    std::byte* context) noexcept {
    const SelectionPublicationStateMachine original =
        g_selectionPublicationStateMachineOriginal.load(std::memory_order_acquire);
    std::byte* record = g_tracedPrelaunchRecord.load(std::memory_order_acquire);
    SelectionPublicationSnapshot before = snapshot_selection_publication(record);
    if (original != nullptr) {
        original(context);
    }
    record = g_tracedPrelaunchRecord.load(std::memory_order_acquire);
    const SelectionPublicationSnapshot after = snapshot_selection_publication(record);
    if (!g_prelaunchOwnerTraceArmed.load(std::memory_order_acquire) || !after.valid
        || (after.source != kChosenActivityIndex
            && after.destination != kHomecomingActivityIndex)) {
        return;
    }

    const std::uint64_t fingerprint = selection_publication_fingerprint(after);
    const std::uint64_t previous =
        g_selectionPublicationStateFingerprint.exchange(fingerprint,
                                                        std::memory_order_acq_rel);
    if (fingerprint == previous) {
        return;
    }
    const std::uint32_t observation =
        g_selectionPublicationStateMachineObserved.fetch_add(1U,
                                                              std::memory_order_relaxed)
        + 1U;
    std::array<char, 640> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_prelaunch_state_machine n=%u context=%p record=%p generation_before=%u generation_after=%u mode=%u type=%u state_before=%u state_after=%u source=%d destination=%d start_tick=%llu delay=%d remaining_before=%d remaining_after=%d mutation=observe_only",
        observation,
        static_cast<void*>(context),
        static_cast<void*>(record),
        before.valid ? static_cast<unsigned int>(before.generation) : 0xFFU,
        static_cast<unsigned int>(after.generation),
        static_cast<unsigned int>(after.mode),
        static_cast<unsigned int>(after.type),
        before.valid ? static_cast<unsigned int>(before.state) : 0xFFU,
        static_cast<unsigned int>(after.state),
        static_cast<int>(after.source),
        static_cast<int>(after.destination),
        static_cast<unsigned long long>(after.startTick),
        after.delay,
        before.valid ? before.remaining : -1,
        after.remaining);
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Records whether the source/destination pair was rejected by the route-ready query. */
__declspec(noinline) bool __fastcall selection_route_pair_invalid(void* pair) noexcept {
    const SelectionRoutePairInvalid original =
        g_selectionRoutePairInvalidOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original(pair);
    if (g_selectionRouteReadyDetailTrace.active) {
        g_selectionRouteReadyDetailTrace.pairInvalidCalled = true;
        g_selectionRouteReadyDetailTrace.pairInvalid = result;
    }
    return result;
}

void copy_selection_route_probe_string(const char* source,
                                       char* destination,
                                       std::size_t capacity) noexcept {
    if (destination == nullptr || capacity == 0) {
        return;
    }
    destination[0] = '\0';
    if (source == nullptr) {
        return;
    }
    __try {
        std::size_t length = 0;
        while (length + 1 < capacity && source[length] != '\0') {
            destination[length] = source[length];
            ++length;
        }
        destination[length] = '\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        destination[0] = '\0';
    }
}

struct SelectionRouteRegistrySlotSnapshot {
    void* activityContext{};
    std::byte* table{};
    std::int32_t activeIndex{-999};
    std::int32_t requestedIndex{-999};
    std::int32_t slotState{-999};
    std::int32_t packageIndex{-999};
    std::int32_t marked{-1};
    std::int16_t source{-1};
    std::int16_t destination{-1};
    std::array<char, kPackageNameCapacity + 1> package{};
};

template <typename Value>
[[nodiscard]] Value selection_route_safe_read(const void* address,
                                              Value fallback) noexcept {
    if (address == nullptr) {
        return fallback;
    }
    __try {
        return *static_cast<const Value*>(address);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return fallback;
    }
}

/** Snapshots the exact table and 0x2d0 slot consumed by the native readiness query. */
[[nodiscard]] SelectionRouteRegistrySlotSnapshot snapshot_selection_route_registry_slot(
    std::int32_t requestedIndex) noexcept {
    SelectionRouteRegistrySlotSnapshot snapshot{};
    const SelectionRouteActivityContext contextAccessor =
        g_selectionRouteActivityContextOriginal.load(std::memory_order_acquire);
    __try {
        snapshot.activityContext = contextAccessor != nullptr ? contextAccessor() : nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snapshot.activityContext = nullptr;
    }

    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (image != nullptr) {
        const auto tableAccessor = reinterpret_cast<SelectionRouteTableAccessor>(
            image + kSelectionRouteTableAccessorRva);
        __try {
            snapshot.table = tableAccessor();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            snapshot.table = nullptr;
        }
    }
    snapshot.activeIndex = selection_route_safe_read<std::int32_t>(snapshot.table, -999);
    snapshot.requestedIndex = requestedIndex == -999 ? snapshot.activeIndex : requestedIndex;
    if (snapshot.activityContext == nullptr || snapshot.table == nullptr
        || snapshot.requestedIndex < -1 || snapshot.requestedIndex >= 16) {
        return snapshot;
    }

    const std::ptrdiff_t slotOffset =
        static_cast<std::ptrdiff_t>(snapshot.requestedIndex) * kRecordStride;
    const auto* const contextBytes = static_cast<const std::byte*>(snapshot.activityContext);
    const auto* const record = contextBytes + kFirstRecordOffset + slotOffset;
    snapshot.slotState = selection_route_safe_read<std::int32_t>(record, -999);
    snapshot.source = selection_route_safe_read<std::int16_t>(
        record + kSelectionOffset + kSourceActivityIndexOffset,
        -1);
    snapshot.destination = selection_route_safe_read<std::int16_t>(
        record + kSelectionOffset + kActivityIndexOffset,
        -1);
    copy_selection_route_probe_string(
        reinterpret_cast<const char*>(record + kSelectionOffset + kPackageNameOffset),
        snapshot.package.data(),
        snapshot.package.size());
    const std::ptrdiff_t tableOffset =
        static_cast<std::ptrdiff_t>(snapshot.requestedIndex) * 8;
    snapshot.marked = static_cast<std::int32_t>(selection_route_safe_read<std::uint8_t>(
        snapshot.table + tableOffset + 0x10,
        0xFFU));
    snapshot.packageIndex = selection_route_safe_read<std::int32_t>(
        snapshot.table + tableOffset + 0x14,
        -999);
    return snapshot;
}

/** Captures the activity-definition index resolved inside native slot initialization. */
__declspec(noinline) std::int32_t* __fastcall selection_route_definition_index_resolver(
    std::int32_t* output) noexcept {
    const SelectionRouteIndexResolver original =
        g_selectionRouteDefinitionIndexResolverOriginal.load(std::memory_order_acquire);
    std::int32_t* const result = original != nullptr ? original(output) : output;
    if (g_selectionRouteSlotInitializeTraceActive) {
        g_selectionRouteDefinitionIndexResolverCalled = true;
        g_selectionRouteDefinitionIndexResolved = selection_route_safe_read<std::int32_t>(
            result != nullptr ? result : output,
            -999);
    }
    return result;
}

/** Captures the package index whose absence prevents the runtime registry write. */
__declspec(noinline) std::int32_t* __fastcall selection_route_package_index_resolver(
    std::int32_t* output) noexcept {
    const SelectionRouteIndexResolver original =
        g_selectionRoutePackageIndexResolverOriginal.load(std::memory_order_acquire);
    std::int32_t* const result = original != nullptr ? original(output) : output;
    if (g_selectionRoutePackageRegistrationTraceActive) {
        g_selectionRoutePackageIndexResolverCalled = true;
        g_selectionRoutePackageIndexResolved = selection_route_safe_read<std::int32_t>(
            result != nullptr ? result : output,
            -999);
    }
    return result;
}

/** Observes the native function that writes the resolved package index into both route tables. */
__declspec(noinline) bool __fastcall selection_route_package_registration(
    std::byte* context,
    std::int32_t slot,
    void* definition,
    std::byte* registrationState) noexcept {
    const SelectionRoutePackageRegistration original =
        g_selectionRoutePackageRegistrationOriginal.load(std::memory_order_acquire);
    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    const auto* const returnAddress = static_cast<const std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    const SelectionRouteRegistrySlotSnapshot before =
        snapshot_selection_route_registry_slot(slot);
    const bool priorTraceActive = g_selectionRoutePackageRegistrationTraceActive;
    const bool priorResolverCalled = g_selectionRoutePackageIndexResolverCalled;
    const std::int32_t priorResolved = g_selectionRoutePackageIndexResolved;
    g_selectionRoutePackageRegistrationTraceActive = true;
    g_selectionRoutePackageIndexResolverCalled = false;
    g_selectionRoutePackageIndexResolved = -999;
    if (g_selectionRouteSlotInitializeTraceActive) {
        g_selectionRoutePackageRegistrationCalled = true;
    }
    const bool result = original != nullptr
                        && original(context, slot, definition, registrationState);
    const bool resolverCalled = g_selectionRoutePackageIndexResolverCalled;
    const std::int32_t resolvedPackageIndex = g_selectionRoutePackageIndexResolved;
    g_selectionRoutePackageRegistrationTraceActive = priorTraceActive;
    g_selectionRoutePackageIndexResolverCalled = priorResolverCalled;
    g_selectionRoutePackageIndexResolved = priorResolved;
    const SelectionRouteRegistrySlotSnapshot after =
        snapshot_selection_route_registry_slot(slot);

    if (!state::activity::forced::override_active()) {
        return result;
    }
    const std::uint32_t observation =
        g_selectionRoutePackageRegistrationObserved.fetch_add(1U,
                                                               std::memory_order_relaxed)
        + 1U;
    if (observation > 128U) {
        return result;
    }
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_destination_package_registration n=%u caller_rva=0x%llX result=%u context=%p slot=%d definition=%p registration_state=%p package_resolver_called=%u resolved_package_index=%d table_before=%p table_after=%p active_index_before=%d active_index_after=%d slot_state_before=%d slot_state_after=%d package_index_before=%d package_index_after=%d route_ready_observed=%u package=%.*s mutation=observe_only",
        observation,
        static_cast<unsigned long long>(callerRva),
        result ? 1U : 0U,
        static_cast<void*>(context),
        slot,
        definition,
        static_cast<void*>(registrationState),
        resolverCalled ? 1U : 0U,
        resolvedPackageIndex,
        static_cast<void*>(before.table),
        static_cast<void*>(after.table),
        before.activeIndex,
        after.activeIndex,
        before.slotState,
        after.slotState,
        before.packageIndex,
        after.packageIndex,
        g_selectionRouteReadyObserved.load(std::memory_order_acquire),
        static_cast<int>(package.size()),
        package.data());
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         result ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    return result;
}

/**
 * Marks entry and return around the exact post-registration builder. A delayed raw stack capture
 * records which nested helper owns a genuine stall without changing any native value.
 */
__declspec(noinline) void __fastcall selection_route_object_builder(
    void* definition,
    std::int32_t argument2,
    std::int32_t argument3,
    void* argument4,
    void* argument5,
    void* argument6,
    void* argument7,
    void* argument8) noexcept {
    const SelectionRouteObjectBuilder original =
        g_selectionRouteObjectBuilderOriginal.load(std::memory_order_acquire);
    const bool capture = g_selectionRouteSlotInitializeTraceActive
                         && state::activity::forced::override_active()
                         && !g_selectionRouteObjectBuilderEntered.exchange(
                             true,
                             std::memory_order_acq_rel);
    if (capture) {
        auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
        const auto* const returnAddress =
            static_cast<const std::byte*>(_ReturnAddress());
        const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                             ? static_cast<std::uintptr_t>(returnAddress - image)
                                             : 0U;
        g_selectionRouteObjectBuilderEntryStack.store(
            reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()),
            std::memory_order_release);
        std::array<char, 384> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_route_object_builder_entry caller_rva=0x%llX definition=%p argument2=%d argument3=%d argument4=%p argument5=%p argument6=%p argument7=%p argument8=%p mutation=observe_only",
            static_cast<unsigned long long>(callerRva),
            definition,
            argument2,
            argument3,
            argument4,
            argument5,
            argument6,
            argument7,
            argument8);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
        if (!g_selectionRouteObjectBuilderSnapshotStarted.exchange(
                true,
                std::memory_order_acq_rel)) {
            const HANDLE worker = CreateThread(
                nullptr,
                0,
                &selection_route_object_builder_snapshot_worker,
                nullptr,
                0,
                nullptr);
            if (worker != nullptr) {
                (void)CloseHandle(worker);
            }
        }
    }

    if (original != nullptr) {
        original(definition,
                 argument2,
                 argument3,
                 argument4,
                 argument5,
                 argument6,
                 argument7,
                 argument8);
    }

    if (capture) {
        g_selectionRouteObjectBuilderReturned.store(true, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_route_object_builder_return result=ok mutation=observe_only");
    }
}

/** Observes the owner that must schedule package registration before the prelaunch query. */
__declspec(noinline) bool __fastcall selection_route_slot_initialize(
    std::byte* context,
    std::int32_t slot,
    std::int32_t argument3,
    std::int32_t argument4,
    void* argument5) noexcept {
    const SelectionRouteSlotInitialize original =
        g_selectionRouteSlotInitializeOriginal.load(std::memory_order_acquire);
    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    const auto* const returnAddress = static_cast<const std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    std::array<void*, 20> callstack{};
    const USHORT callstackCount = state::activity::forced::override_active()
                                      ? RtlCaptureStackBackTrace(
                                            0,
                                            static_cast<ULONG>(callstack.size()),
                                            callstack.data(),
                                            nullptr)
                                      : 0;
    const SelectionRouteRegistrySlotSnapshot before =
        snapshot_selection_route_registry_slot(slot);
    const bool priorTraceActive = g_selectionRouteSlotInitializeTraceActive;
    const bool priorResolverCalled = g_selectionRouteDefinitionIndexResolverCalled;
    const std::int32_t priorResolved = g_selectionRouteDefinitionIndexResolved;
    const bool priorRegistrationCalled = g_selectionRoutePackageRegistrationCalled;
    g_selectionRouteSlotInitializeTraceActive = true;
    g_selectionRouteDefinitionIndexResolverCalled = false;
    g_selectionRouteDefinitionIndexResolved = -999;
    g_selectionRoutePackageRegistrationCalled = false;
    const bool result = original != nullptr
                        && original(context, slot, argument3, argument4, argument5);
    const bool resolverCalled = g_selectionRouteDefinitionIndexResolverCalled;
    const std::int32_t resolvedDefinitionIndex = g_selectionRouteDefinitionIndexResolved;
    const bool registrationCalled = g_selectionRoutePackageRegistrationCalled;
    g_selectionRouteSlotInitializeTraceActive = priorTraceActive;
    g_selectionRouteDefinitionIndexResolverCalled = priorResolverCalled;
    g_selectionRouteDefinitionIndexResolved = priorResolved;
    g_selectionRoutePackageRegistrationCalled = priorRegistrationCalled;
    const SelectionRouteRegistrySlotSnapshot after =
        snapshot_selection_route_registry_slot(slot);

    if (!state::activity::forced::override_active()) {
        return result;
    }
    const std::uint32_t observation =
        g_selectionRouteSlotInitializeObserved.fetch_add(1U,
                                                          std::memory_order_relaxed)
        + 1U;
    if (observation > 128U) {
        return result;
    }
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_destination_slot_initialize n=%u caller_rva=0x%llX result=%u context=%p slot=%d argument3=%d argument4=%d argument5=%p definition_resolver_called=%u resolved_definition_index=%d package_registration_called=%u table_before=%p table_after=%p active_index_before=%d active_index_after=%d slot_state_before=%d slot_state_after=%d package_index_before=%d package_index_after=%d route_ready_observed=%u package=%.*s mutation=observe_only",
        observation,
        static_cast<unsigned long long>(callerRva),
        result ? 1U : 0U,
        static_cast<void*>(context),
        slot,
        argument3,
        argument4,
        argument5,
        resolverCalled ? 1U : 0U,
        resolvedDefinitionIndex,
        registrationCalled ? 1U : 0U,
        static_cast<void*>(before.table),
        static_cast<void*>(after.table),
        before.activeIndex,
        after.activeIndex,
        before.slotState,
        after.slotState,
        before.packageIndex,
        after.packageIndex,
        g_selectionRouteReadyObserved.load(std::memory_order_acquire),
        static_cast<int>(package.size()),
        package.data());
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         result ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    std::array<char, core::log::kLineCapacity> stackLine{};
    int stackLength = std::snprintf(
        stackLine.data(),
        stackLine.size(),
        "ev=bootflow stage=activity_selection_destination_slot_initialize_stack n=%u count=%u rvas=",
        observation,
        static_cast<unsigned int>(callstackCount));
    const std::size_t imageSize = game_image_size(image);
    for (USHORT index = 0;
         index < callstackCount && stackLength > 0
         && static_cast<std::size_t>(stackLength) < stackLine.size();
         ++index) {
        const auto* const address = static_cast<const std::byte*>(callstack[index]);
        const std::uintptr_t rva = image != nullptr && address >= image
                                           && static_cast<std::size_t>(address - image) < imageSize
                                       ? static_cast<std::uintptr_t>(address - image)
                                       : 0U;
        const int appended = std::snprintf(
            stackLine.data() + stackLength,
            stackLine.size() - static_cast<std::size_t>(stackLength),
            "%s0x%llX",
            index == 0 ? "" : ",",
            static_cast<unsigned long long>(rva));
        if (appended <= 0) {
            break;
        }
        stackLength += appended;
    }
    if (stackLength > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {stackLine.data(),
                          static_cast<std::size_t>(stackLength) < stackLine.size()
                              ? static_cast<std::size_t>(stackLength)
                              : stackLine.size() - 1U});
    }
    return result;
}

__declspec(noinline) bool __fastcall selection_route_registry_ready() noexcept {
    const SelectionRouteRegistryReady original =
        g_selectionRouteRegistryReadyOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original();
    if (g_selectionRouteDestinationTraceActive) {
        SelectionRouteReadyDetailTrace& trace = g_selectionRouteReadyDetailTrace;
        const SelectionRouteRegistrySlotSnapshot snapshot =
            snapshot_selection_route_registry_slot(-999);
        ++trace.registryReadyCalls;
        if (trace.registryReadyCalls == 1U) {
            trace.registryReadyFirst = result;
        } else if (trace.registryReadyCalls == 2U) {
            trace.registryReadySecond = result;
        }
        trace.registryTable = snapshot.table;
        trace.registryActiveIndex = snapshot.activeIndex;
        trace.registryActiveSlotState = snapshot.slotState;
        trace.registryActivePackageIndex = snapshot.packageIndex;
        trace.registryActiveMarked = snapshot.marked;
    }
    return result;
}

/** Captures the predicate used by the registry slot writer without changing its answer. */
__declspec(noinline) bool __fastcall selection_route_registry_slot_writer_predicate() noexcept {
    const SelectionRouteRegistrySlotWriterPredicate original =
        g_selectionRouteRegistrySlotWriterPredicateOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original();
    if (g_selectionRouteRegistrySlotWriterTraceActive) {
        g_selectionRouteRegistrySlotWriterPredicateCalled = true;
        g_selectionRouteRegistrySlotWriterPredicateResult = result;
    }
    return result;
}

/** Observes the queued wrapper that prepares the state-one record before invoking its vtable thunk. */
__declspec(noinline) void __fastcall selection_route_registry_queued_wrapper(
    void* callback,
    const std::int8_t* event) noexcept {
    const SelectionRouteRegistryQueuedWrapper original =
        g_selectionRouteRegistryQueuedWrapperOriginal.load(std::memory_order_acquire);
    if (original == nullptr) {
        return;
    }
    if (!state::activity::forced::override_active()) {
        original(callback, event);
        return;
    }

    log_selection_state_one_watch();

    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    void* const vtable = selection_route_safe_read<void*>(callback, nullptr);
    void* const method = vtable != nullptr
                             ? selection_route_safe_read<void*>(
                                   static_cast<const std::byte*>(vtable) + 0x10U,
                                   nullptr)
                             : nullptr;
    const auto* const methodBytes = static_cast<const std::byte*>(method);
    const std::size_t imageSize = game_image_size(image);
    const std::uintptr_t methodRva = image != nullptr && methodBytes != nullptr
                                             && methodBytes >= image
                                             && static_cast<std::size_t>(methodBytes - image)
                                                    < imageSize
                                         ? static_cast<std::uintptr_t>(methodBytes - image)
                                         : 0U;
    const std::int32_t eventValue =
        static_cast<std::int32_t>(selection_route_safe_read<std::int8_t>(event, -128));
    const SelectionRouteRegistrySlotSnapshot before =
        snapshot_selection_route_registry_slot(0);

    if (methodRva != 0U
        && !g_selectionRouteRegistryQueuedThunkDumped.exchange(true,
                                                                std::memory_order_acq_rel)) {
        dump_code(L"activity_selection_destination_registry_queued_thunk",
                  methodBytes,
                  0x400U);
    }

    original(callback, event);

    const SelectionRouteRegistrySlotSnapshot after =
        snapshot_selection_route_registry_slot(0);
    const std::uint32_t observation =
        g_selectionRouteRegistryQueuedWrapperObserved.fetch_add(1U,
                                                                 std::memory_order_relaxed)
        + 1U;
    if (observation > 64U) {
        return;
    }

    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_destination_registry_queued_wrapper n=%u callback=%p vtable=%p method=%p method_rva=0x%llX event=%d slot_state_before=%d slot_state_after=%d source_before=%d source_after=%d destination_before=%d destination_after=%d package_before=%s package_after=%s marked_before=%d marked_after=%d package_index_before=%d package_index_after=%d route_ready_observed=%u forced=%.*s mutation=observe_only",
        observation,
        callback,
        vtable,
        method,
        static_cast<unsigned long long>(methodRva),
        eventValue,
        before.slotState,
        after.slotState,
        static_cast<int>(before.source),
        static_cast<int>(after.source),
        static_cast<int>(before.destination),
        static_cast<int>(after.destination),
        before.package.data(),
        after.package.data(),
        before.marked,
        after.marked,
        before.packageIndex,
        after.packageIndex,
        g_selectionRouteReadyObserved.load(std::memory_order_acquire),
        static_cast<int>(package.size()),
        package.data());
    if (length > 0) {
        const bool transition = before.slotState != after.slotState
                                || before.source != after.source
                                || before.destination != after.destination;
        core::log::write(core::log::Channel::client,
                         transition ? core::log::Level::warn : core::log::Level::info,
                         {line.data(),
                          static_cast<std::size_t>(length) < line.size()
                              ? static_cast<std::size_t>(length)
                              : line.size() - 1U});
    }
}

/** Records whether and when the native initializer actually prepares a destination slot. */
__declspec(noinline) void __fastcall selection_route_registry_slot_writer(
    std::int32_t index,
    std::int32_t argument2,
    std::int32_t argument3) noexcept {
    const SelectionRouteRegistrySlotWriter original =
        g_selectionRouteRegistrySlotWriterOriginal.load(std::memory_order_acquire);
    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    const auto* const returnAddress = static_cast<const std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    const SelectionRouteRegistrySlotSnapshot before =
        snapshot_selection_route_registry_slot(index);
    const bool priorTraceActive = g_selectionRouteRegistrySlotWriterTraceActive;
    const bool priorPredicateCalled = g_selectionRouteRegistrySlotWriterPredicateCalled;
    const bool priorPredicateResult = g_selectionRouteRegistrySlotWriterPredicateResult;
    g_selectionRouteRegistrySlotWriterTraceActive = true;
    g_selectionRouteRegistrySlotWriterPredicateCalled = false;
    g_selectionRouteRegistrySlotWriterPredicateResult = false;
    if (original != nullptr) {
        original(index, argument2, argument3);
    }
    const bool predicateCalled = g_selectionRouteRegistrySlotWriterPredicateCalled;
    const bool predicateResult = g_selectionRouteRegistrySlotWriterPredicateResult;
    g_selectionRouteRegistrySlotWriterTraceActive = priorTraceActive;
    g_selectionRouteRegistrySlotWriterPredicateCalled = priorPredicateCalled;
    g_selectionRouteRegistrySlotWriterPredicateResult = priorPredicateResult;
    const SelectionRouteRegistrySlotSnapshot after =
        snapshot_selection_route_registry_slot(index);

    const std::uint32_t observation =
        g_selectionRouteRegistrySlotWriterObserved.fetch_add(1U,
                                                              std::memory_order_relaxed)
        + 1U;
    if (observation > 128U) {
        return;
    }
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_destination_registry_slot_writer n=%u caller_rva=0x%llX index=%d argument2=%d argument3=%d predicate_called=%u predicate_result=%u context_before=%p context_after=%p table_before=%p table_after=%p active_index_before=%d active_index_after=%d slot_state_before=%d slot_state_after=%d marked_before=%d marked_after=%d package_index_before=%d package_index_after=%d route_ready_observed=%u forced=%u package=%.*s mutation=observe_only",
        observation,
        static_cast<unsigned long long>(callerRva),
        index,
        argument2,
        argument3,
        predicateCalled ? 1U : 0U,
        predicateResult ? 1U : 0U,
        before.activityContext,
        after.activityContext,
        static_cast<void*>(before.table),
        static_cast<void*>(after.table),
        before.activeIndex,
        after.activeIndex,
        before.slotState,
        after.slotState,
        before.marked,
        after.marked,
        before.packageIndex,
        after.packageIndex,
        g_selectionRouteReadyObserved.load(std::memory_order_acquire),
        state::activity::forced::override_active() ? 1U : 0U,
        static_cast<int>(package.size()),
        package.data());
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Observes the neighboring queued request that constructs the native destination slot. */
__declspec(noinline) void __fastcall selection_route_destination_slot_request(
    std::int32_t index,
    std::int32_t argument2,
    std::int32_t argument3) noexcept {
    const SelectionRouteDestinationSlotRequest original =
        g_selectionRouteDestinationSlotRequestOriginal.load(std::memory_order_acquire);
    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    const auto* const returnAddress = static_cast<const std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    const SelectionRouteRegistrySlotSnapshot before =
        snapshot_selection_route_registry_slot(index);
    if (original != nullptr) {
        original(index, argument2, argument3);
    }
    const SelectionRouteRegistrySlotSnapshot after =
        snapshot_selection_route_registry_slot(index);
    if (!state::activity::forced::override_active()) {
        return;
    }

    const std::uint32_t observation =
        g_selectionRouteDestinationSlotRequestObserved.fetch_add(
            1U,
            std::memory_order_relaxed)
        + 1U;
    if (observation > 64U) {
        return;
    }
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_destination_slot_request n=%u caller_rva=0x%llX index=%d argument2=%d argument3=%d context_before=%p context_after=%p table_before=%p table_after=%p active_index_before=%d active_index_after=%d slot_state_before=%d slot_state_after=%d marked_before=%d marked_after=%d package_index_before=%d package_index_after=%d route_ready_observed=%u package=%.*s mutation=observe_only",
        observation,
        static_cast<unsigned long long>(callerRva),
        index,
        argument2,
        argument3,
        before.activityContext,
        after.activityContext,
        static_cast<void*>(before.table),
        static_cast<void*>(after.table),
        before.activeIndex,
        after.activeIndex,
        before.slotState,
        after.slotState,
        before.marked,
        after.marked,
        before.packageIndex,
        after.packageIndex,
        g_selectionRouteReadyObserved.load(std::memory_order_acquire),
        static_cast<int>(package.size()),
        package.data());
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }

    if (observation <= 8U) {
        std::array<void*, 16> stack{};
        const USHORT stackCount = RtlCaptureStackBackTrace(
            0,
            static_cast<ULONG>(stack.size()),
            stack.data(),
            nullptr);
        const std::size_t imageSize = image != nullptr ? game_image_size(image) : 0U;
        std::array<char, 512> stackLine{};
        int stackLength = std::snprintf(
            stackLine.data(),
            stackLine.size(),
            "ev=bootflow stage=activity_selection_destination_slot_request_stack n=%u count=%u rvas=",
            observation,
            static_cast<unsigned int>(stackCount));
        for (USHORT frame = 0;
             frame < stackCount && stackLength > 0
             && static_cast<std::size_t>(stackLength) < stackLine.size();
             ++frame) {
            const auto* const address = static_cast<const std::byte*>(stack[frame]);
            const std::uintptr_t rva = image != nullptr && address >= image
                                               && static_cast<std::size_t>(address - image)
                                                      < imageSize
                                           ? static_cast<std::uintptr_t>(address - image)
                                           : 0U;
            const int appended = std::snprintf(
                stackLine.data() + stackLength,
                stackLine.size() - static_cast<std::size_t>(stackLength),
                "%s0x%llX",
                frame == 0 ? "" : ",",
                static_cast<unsigned long long>(rva));
            if (appended <= 0) {
                break;
            }
            stackLength += appended;
        }
        if (stackLength > 0) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::info,
                {stackLine.data(),
                 static_cast<std::size_t>(stackLength) < stackLine.size()
                     ? static_cast<std::size_t>(stackLength)
                     : stackLine.size() - 1U});
        }
    }
}

__declspec(noinline) void* __fastcall selection_route_activity_context() noexcept {
    const SelectionRouteActivityContext original =
        g_selectionRouteActivityContextOriginal.load(std::memory_order_acquire);
    void* const result = original != nullptr ? original() : nullptr;
    if (g_selectionRouteDestinationTraceActive) {
        g_selectionRouteReadyDetailTrace.activityContext = result;
    }
    return result;
}

__declspec(noinline) const char* __fastcall selection_route_resolved_package(
    std::int32_t index) noexcept {
    const SelectionRouteResolvedPackage original =
        g_selectionRouteResolvedPackageOriginal.load(std::memory_order_acquire);
    const char* const result = original != nullptr ? original(index) : nullptr;
    if (g_selectionRouteDestinationTraceActive) {
        SelectionRouteReadyDetailTrace& trace = g_selectionRouteReadyDetailTrace;
        trace.resolvedPackageIndex = index;
        trace.resolvedPackage = result;
        copy_selection_route_probe_string(
            result, trace.packageActual.data(), trace.packageActual.size());
    }
    return result;
}

__declspec(noinline) bool __fastcall selection_route_strict_comparison() noexcept {
    const SelectionRouteStrictComparison original =
        g_selectionRouteStrictComparisonOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original();
    if (g_selectionRouteDestinationTraceActive) {
        g_selectionRouteReadyDetailTrace.strictComparisonCalled = true;
        g_selectionRouteReadyDetailTrace.strictComparison = result;
    }
    const auto* const image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    const auto* const returnAddress = static_cast<const std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    if (callerRva == kEmbeddedRouteIdentityProviderStrictReturnRva
        && state::activity::forced::override_active() && package == "mission_towerfall") {
        const std::uint32_t observation =
            g_embeddedRouteIdentityProviderStrictObserved.fetch_add(
                1U,
                std::memory_order_relaxed)
            + 1U;
        if (observation > 64U) {
            return result;
        }
        std::array<char, core::log::kLineCapacity> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_script_embedded_route_identity_provider_strict n=%u caller_rva=0x%llX result=%u expected=1 package=%.*s mutation=observe_only",
            observation,
            static_cast<unsigned long long>(callerRva),
            result ? 1U : 0U,
            static_cast<int>(package.size()),
            package.data());
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    return result;
}

__declspec(noinline) void* __fastcall selection_route_destination_registry() noexcept {
    const SelectionRouteDestinationRegistry original =
        g_selectionRouteDestinationRegistryOriginal.load(std::memory_order_acquire);
    void* const result = original != nullptr ? original() : nullptr;
    if (g_selectionRouteDestinationTraceActive) {
        g_selectionRouteReadyDetailTrace.destinationRegistry = result;
    }
    return result;
}

__declspec(noinline) bool __fastcall selection_route_package_matches(
    const char* actual,
    const char* expected) noexcept {
    const SelectionRoutePackageMatches original =
        g_selectionRoutePackageMatchesOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original(actual, expected);
    if (g_selectionRouteDestinationTraceActive) {
        SelectionRouteReadyDetailTrace& trace = g_selectionRouteReadyDetailTrace;
        trace.packageMatchesCalled = true;
        trace.packageMatches = result;
        copy_selection_route_probe_string(
            actual, trace.packageActual.data(), trace.packageActual.size());
        copy_selection_route_probe_string(
            expected, trace.packageExpected.data(), trace.packageExpected.size());
    }
    return result;
}

/** Records the destination-specific predicate used by the route-ready query. */
__declspec(noinline) bool __fastcall selection_route_destination_allowed(
    std::uint32_t destination,
    const void* descriptor) noexcept {
    const SelectionRouteDestinationAllowed original =
        g_selectionRouteDestinationAllowedOriginal.load(std::memory_order_acquire);
    const bool priorTraceActive = g_selectionRouteDestinationTraceActive;
    g_selectionRouteDestinationTraceActive = g_selectionRouteReadyDetailTrace.active;
    const bool result = original != nullptr && original(destination, descriptor);
    g_selectionRouteDestinationTraceActive = priorTraceActive;
    if (g_selectionRouteReadyDetailTrace.active) {
        g_selectionRouteReadyDetailTrace.destinationAllowedCalled = true;
        g_selectionRouteReadyDetailTrace.destinationAllowed = result;
        g_selectionRouteReadyDetailTrace.destination = destination;
        g_selectionRouteReadyDetailTrace.descriptor = descriptor;
    }
    return result;
}

/** Records the primary destination readiness lookup without altering its result. */
__declspec(noinline) bool __fastcall selection_route_primary_ready(
    std::uint32_t destination) noexcept {
    const SelectionRoutePrimaryReady original =
        g_selectionRoutePrimaryReadyOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original(destination);
    if (g_selectionRouteReadyDetailTrace.active) {
        g_selectionRouteReadyDetailTrace.primaryReadyCalled = true;
        g_selectionRouteReadyDetailTrace.primaryReady = result;
        g_selectionRouteReadyDetailTrace.destination = destination;
    }
    return result;
}

/** Records the global fallback readiness lookup without altering its result. */
__declspec(noinline) bool __fastcall selection_route_fallback_ready() noexcept {
    const SelectionRouteFallbackReady original =
        g_selectionRouteFallbackReadyOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original();
    if (g_selectionRouteReadyDetailTrace.active) {
        g_selectionRouteReadyDetailTrace.fallbackReadyCalled = true;
        g_selectionRouteReadyDetailTrace.fallbackReady = result;
    }
    return result;
}

/** Records the native route-readiness decision without changing its input or return value. */
__declspec(noinline) bool __fastcall selection_route_ready_query(
    std::byte* selection) noexcept {
    const SelectionRouteReadyQuery original =
        g_selectionRouteReadyQueryOriginal.load(std::memory_order_acquire);
    const bool traceArmed = g_prelaunchOwnerTraceArmed.load(std::memory_order_acquire);
    const SelectionRouteReadyDetailTrace priorTrace = g_selectionRouteReadyDetailTrace;
    g_selectionRouteReadyDetailTrace = {};
    g_selectionRouteReadyDetailTrace.active = traceArmed;
    const bool result = original != nullptr && original(selection);
    const SelectionRouteReadyDetailTrace detail = g_selectionRouteReadyDetailTrace;
    g_selectionRouteReadyDetailTrace = priorTrace;
    if (!traceArmed) {
        return result;
    }
    const std::uint32_t observation =
        g_selectionRouteReadyObserved.fetch_add(1U, std::memory_order_relaxed) + 1U;
    if (observation > 8U) {
        return result;
    }

    const std::byte* const record = selection != nullptr ? selection - 8 : nullptr;
    const SelectionPublicationSnapshot snapshot =
        snapshot_selection_publication(record);
    if (observation == 1U && record != nullptr) {
        dump_current_activity(L"prelaunch_route_ready_query_input",
                              {const_cast<std::byte*>(record),
                               kSelectionPublicationBytes});
    }
    std::array<char, 512> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_prelaunch_route_ready n=%u result=%s selection=%p record=%p generation=%u mode=%u type=%u state=%u source=%d destination=%d start_tick=%llu delay=%d remaining=%d mutation=observe_only",
        observation,
        result ? "accepted" : "rejected",
        static_cast<void*>(selection),
        static_cast<const void*>(record),
        snapshot.valid ? static_cast<unsigned int>(snapshot.generation) : 0xFFU,
        snapshot.valid ? static_cast<unsigned int>(snapshot.mode) : 0xFFU,
        snapshot.valid ? static_cast<unsigned int>(snapshot.type) : 0xFFU,
        snapshot.valid ? static_cast<unsigned int>(snapshot.state) : 0xFFU,
        snapshot.valid ? static_cast<int>(snapshot.source) : -1,
        snapshot.valid ? static_cast<int>(snapshot.destination) : -1,
        snapshot.valid ? static_cast<unsigned long long>(snapshot.startTick) : 0ULL,
        snapshot.valid ? snapshot.delay : -1,
        snapshot.valid ? snapshot.remaining : -1);
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         result ? core::log::Level::info : core::log::Level::warn,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    const std::uint8_t selectionTag =
        selection != nullptr ? std::to_integer<std::uint8_t>(selection[0]) : 0xFFU;
    const char* blockedAt = "unknown";
    if (result) {
        blockedAt = detail.primaryReady ? "accepted_primary" : "accepted_fallback";
    } else if (detail.pairInvalidCalled && detail.pairInvalid) {
        blockedAt = "pair_invalid";
    } else if (selectionTag == 6U) {
        blockedAt = "selection_tag_6";
    } else if (detail.destinationAllowedCalled && !detail.destinationAllowed) {
        if (detail.registryReadyCalls >= 1U && !detail.registryReadyFirst) {
            blockedAt = "destination_registry_not_ready_initial";
        } else if (detail.activityContext == nullptr) {
            blockedAt = "destination_activity_context_null";
        } else if (detail.registryReadyCalls >= 2U && !detail.registryReadySecond) {
            blockedAt = "destination_registry_not_ready_repeat";
        } else if (detail.resolvedPackage == nullptr) {
            blockedAt = "destination_package_unresolved";
        } else if (detail.strictComparisonCalled && detail.strictComparison
                   && detail.destinationRegistry == nullptr) {
            blockedAt = "destination_registry_null";
        } else if (!detail.packageMatchesCalled) {
            blockedAt = "destination_entry_missing";
        } else if (!detail.packageMatches) {
            blockedAt = "destination_package_mismatch";
        } else {
            blockedAt = "destination_rejected";
        }
    } else if (detail.primaryReadyCalled && !detail.primaryReady
               && detail.fallbackReadyCalled && !detail.fallbackReady) {
        blockedAt = "fallback_rejected";
    }
    std::array<char, core::log::kLineCapacity> detailLine{};
    const int detailLength = std::snprintf(
        detailLine.data(),
        detailLine.size(),
        "ev=bootflow stage=activity_selection_prelaunch_route_ready_detail n=%u result=%s blocked_at=%s selection_tag=%u pair_called=%u pair_invalid=%u destination_called=%u destination_allowed=%u destination=%u descriptor=%p registry_ready_calls=%u registry_ready_first=%u registry_ready_second=%u registry_table=%p registry_active_index=%d registry_active_slot_state=%d registry_active_package_index=%d registry_active_marked=%d activity_context=%p resolved_package_index=%d resolved_package=%p strict_called=%u strict=%u destination_registry=%p package_compare_called=%u package_matches=%u package_actual=%s package_expected=%s primary_called=%u primary_ready=%u fallback_called=%u fallback_ready=%u mutation=observe_only",
        observation,
        result ? "accepted" : "rejected",
        blockedAt,
        static_cast<unsigned int>(selectionTag),
        detail.pairInvalidCalled ? 1U : 0U,
        detail.pairInvalid ? 1U : 0U,
        detail.destinationAllowedCalled ? 1U : 0U,
        detail.destinationAllowed ? 1U : 0U,
        detail.destination,
        detail.descriptor,
        detail.registryReadyCalls,
        detail.registryReadyFirst ? 1U : 0U,
        detail.registryReadySecond ? 1U : 0U,
        detail.registryTable,
        detail.registryActiveIndex,
        detail.registryActiveSlotState,
        detail.registryActivePackageIndex,
        detail.registryActiveMarked,
        detail.activityContext,
        detail.resolvedPackageIndex,
        static_cast<const void*>(detail.resolvedPackage),
        detail.strictComparisonCalled ? 1U : 0U,
        detail.strictComparison ? 1U : 0U,
        detail.destinationRegistry,
        detail.packageMatchesCalled ? 1U : 0U,
        detail.packageMatches ? 1U : 0U,
        detail.packageActual.data(),
        detail.packageExpected.data(),
        detail.primaryReadyCalled ? 1U : 0U,
        detail.primaryReady ? 1U : 0U,
        detail.fallbackReadyCalled ? 1U : 0U,
        detail.fallbackReady ? 1U : 0U);
    if (detailLength > 0) {
        core::log::write(core::log::Channel::client,
                         result ? core::log::Level::info : core::log::Level::warn,
                         {detailLine.data(), static_cast<std::size_t>(detailLength)});
    }
    if constexpr (kEnableSelectionStateOneWriteWatch) {
        if (observation == 1U && !result && detail.activityContext != nullptr
            && detail.registryActiveSlotState == -1) {
            arm_selection_state_one_watch(detail.activityContext);
        }
    }
    return result;
}

template <typename Function>
bool install_selection_route_ready_detail_probe(
    std::byte* image,
    std::uintptr_t rva,
    const wchar_t* dumpName,
    const char* stage,
    void* replacement,
    hooking::detour::Handle& handle,
    std::atomic<Function>& original) noexcept {
    if (handle.attached) {
        return true;
    }
    std::byte* const target = image != nullptr ? image + rva : nullptr;
    MEMORY_BASIC_INFORMATION memory{};
    const DWORD executableMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                                 | PAGE_EXECUTE_WRITECOPY;
    const bool executable = target != nullptr
                            && VirtualQuery(target, &memory, sizeof memory) == sizeof memory
                            && memory.State == MEM_COMMIT
                            && (memory.Protect & executableMask) != 0
                            && (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
    const bool stillEncrypted = executable && target[0] == std::byte{0x91}
                                && target[1] == std::byte{0xCC};
    if (!executable || stillEncrypted) {
        std::array<char, 256> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=%s result=deferred reason=validation rva=0x%llX",
            stage,
            static_cast<unsigned long long>(rva));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(length)});
        }
        return false;
    }
    dump_code(dumpName, target, 0x200U);
    if (!hooking::detour::install({target, replacement}, handle)) {
        std::array<char, 256> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=%s result=fail reason=attach rva=0x%llX",
            stage,
            static_cast<unsigned long long>(rva));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(length)});
        }
        return false;
    }
    original.store(reinterpret_cast<Function>(handle.original), std::memory_order_release);
    std::array<char, 256> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=%s result=ok mode=observe rva=0x%llX",
        stage,
        static_cast<unsigned long long>(rva));
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    return true;
}

/** Traces every native retrieval of the passive launch-publication owner after CHOSEN is armed. */
__declspec(noinline) std::byte* __fastcall selection_publication_owner_accessor(
    std::byte* context) noexcept {
    const SelectionPublicationOwnerAccessor original =
        g_selectionPublicationOwnerAccessorOriginal.load(std::memory_order_acquire);
    std::byte* const owner = original != nullptr ? original(context) : nullptr;
    if (!g_prelaunchOwnerTraceArmed.load(std::memory_order_acquire)) {
        return owner;
    }

    const std::uint32_t observation =
        g_selectionPublicationOwnerAccessObserved.fetch_add(1U, std::memory_order_relaxed) + 1U;
    if (observation > 32U) {
        return owner;
    }

    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto* const caller = static_cast<const std::byte*>(_ReturnAddress());
    const std::size_t imageSize = game_image_size(image);
    const std::uintptr_t callerRva =
        image != nullptr && caller >= image
                && static_cast<std::size_t>(caller - image) < imageSize
            ? static_cast<std::uintptr_t>(caller - image)
            : 0U;
    std::byte* const manager = context != nullptr ? context - 0xF4B8 : nullptr;
    std::int32_t managerMode = -1;
    std::int32_t lane = -1;
    const std::byte* record = nullptr;
    std::uint8_t ownerFlags = 0xFFU;
    std::uint8_t recordState = 0xFFU;
    std::int16_t source = -1;
    std::int16_t destination = -1;
    __try {
        if (manager != nullptr) {
            managerMode = *reinterpret_cast<std::int32_t*>(manager + 0x1AEF8);
            lane = *reinterpret_cast<std::int32_t*>(manager + 0xE93C);
        }
        if (owner != nullptr) {
            ownerFlags = std::to_integer<std::uint8_t>(owner[0x140]);
        }
        if (owner != nullptr && lane >= 0) {
            const std::size_t recordBase = managerMode >= 6 && managerMode <= 9
                                               ? 0x0B78U
                                               : 0x99F8U;
            record = owner + recordBase + static_cast<std::size_t>(lane) * 0x0BE0U;
            g_tracedPrelaunchRecord.store(const_cast<std::byte*>(record),
                                          std::memory_order_release);
            recordState = std::to_integer<std::uint8_t>(record[3]);
            std::memcpy(&source, record + 0x0A, sizeof source);
            std::memcpy(&destination, record + 0x0C, sizeof destination);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        managerMode = -1;
        lane = -1;
        record = nullptr;
        ownerFlags = 0xFFU;
        recordState = 0xFFU;
        source = -1;
        destination = -1;
    }

    std::array<char, 640> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_prelaunch_owner_access n=%u caller_rva=0x%llX context=%p owner=%p owner_flags=0x%02X manager=%p manager_mode=%d lane=%d record=%p record_state=%u source=%d destination=%d publication_pending=%u",
        observation,
        static_cast<unsigned long long>(callerRva),
        static_cast<void*>(context),
        static_cast<void*>(owner),
        static_cast<unsigned int>(ownerFlags),
        static_cast<void*>(manager),
        managerMode,
        lane,
        static_cast<const void*>(record),
        static_cast<unsigned int>(recordState),
        static_cast<int>(source),
        static_cast<int>(destination),
        g_homecomingPrelaunchPublicationPending.load(std::memory_order_acquire) ? 1U : 0U);
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }

    std::array<void*, 12> stack{};
    const USHORT stackCount = RtlCaptureStackBackTrace(
        1, static_cast<ULONG>(stack.size()), stack.data(), nullptr);
    std::array<char, 512> stackLine{};
    int stackLength = std::snprintf(
        stackLine.data(),
        stackLine.size(),
        "ev=bootflow stage=activity_selection_prelaunch_owner_access_stack n=%u count=%u rvas=",
        observation,
        static_cast<unsigned int>(stackCount));
    for (USHORT index = 0;
         index < stackCount && stackLength > 0
         && static_cast<std::size_t>(stackLength) < stackLine.size();
         ++index) {
        const auto* const address = static_cast<const std::byte*>(stack[index]);
        const std::uintptr_t rva =
            image != nullptr && address >= image
                    && static_cast<std::size_t>(address - image) < imageSize
                ? static_cast<std::uintptr_t>(address - image)
                : 0U;
        const int appended = std::snprintf(
            stackLine.data() + stackLength,
            stackLine.size() - static_cast<std::size_t>(stackLength),
            "%s0x%llX",
            index == 0 ? "" : ",",
            static_cast<unsigned long long>(rva));
        if (appended <= 0) {
            break;
        }
        stackLength += appended;
    }
    if (stackLength > 0) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            {stackLine.data(),
             static_cast<std::size_t>(stackLength) < stackLine.size()
                 ? static_cast<std::size_t>(stackLength)
                 : stackLine.size() - 1U});
    }
    return owner;
}

/**
 * Advances the launcher's real type-1 publication through Destiny's native state-0 producer,
 * and publishes the complete native result unchanged. The launch-state correction has already
 * made the producer's selected entry 282 -> 266 / mission_towerfall; this hook never rewrites a
 * publication field, synthesizes a route byte, or forces downstream route state.
 */
__declspec(noinline) bool __fastcall selection_launch_publisher(
    std::byte* owner,
    std::byte* descriptor) noexcept {
    const SelectionLaunchPublisher original =
        g_selectionLaunchPublisherOriginal.load(std::memory_order_acquire);
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    const auto* const caller = static_cast<const std::byte*>(_ReturnAddress());
    const bool launcherCall = image != nullptr
                              && caller == image + kSelectionLaunchPublisherReturnRva;
    const bool pending = launcherCall
                         && g_homecomingPrelaunchPublicationPending.exchange(
                             false, std::memory_order_acq_rel);
    std::byte* ownerVtable = nullptr;
    std::byte* notifyInitialTarget = nullptr;
    std::byte* notifyChangedTarget = nullptr;
    std::uint8_t ownerFlagsBefore = 0xFFU;
    bool homecomingPublicationPopulated = false;
    if (pending && owner != nullptr) {
        __try {
            ownerVtable = *reinterpret_cast<std::byte**>(owner);
            if (ownerVtable != nullptr) {
                notifyInitialTarget = *reinterpret_cast<std::byte**>(ownerVtable);
                notifyChangedTarget = *reinterpret_cast<std::byte**>(ownerVtable + 0x08);
                dump_current_activity(
                    L"prelaunch_publication_vtable",
                    {ownerVtable, kSelectionPublicationVtableProbeBytes});
            }
            ownerFlagsBefore = std::to_integer<std::uint8_t>(owner[0x140]);
            dump_current_activity(
                L"prelaunch_publication_owner_before",
                {owner, kSelectionPublicationOwnerProbeBytes});
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ownerVtable = nullptr;
            notifyInitialTarget = nullptr;
            notifyChangedTarget = nullptr;
            ownerFlagsBefore = 0xFFU;
        }
        if (image != nullptr) {
            const std::size_t imageSize = game_image_size(image);
            if (notifyInitialTarget >= image
                && static_cast<std::size_t>(notifyInitialTarget - image) < imageSize) {
                dump_code(L"activity_selection_prelaunch_notify_initial",
                          notifyInitialTarget,
                          kSelectionPublicationNotifyProbeBytes);
            }
            if (notifyChangedTarget >= image
                && static_cast<std::size_t>(notifyChangedTarget - image) < imageSize
                && notifyChangedTarget != notifyInitialTarget) {
                dump_code(L"activity_selection_prelaunch_notify_changed",
                          notifyChangedTarget,
                          kSelectionPublicationNotifyProbeBytes);
            }
        }
    }
    if (pending && descriptor != nullptr) {
        const std::uint8_t typeBefore = std::to_integer<std::uint8_t>(descriptor[2]);
        const std::uint8_t stateBefore = std::to_integer<std::uint8_t>(descriptor[3]);
        std::int16_t sourceBefore = -1;
        std::int16_t destinationBefore = -1;
        std::memcpy(&sourceBefore, descriptor + 0x0A, sizeof sourceBefore);
        std::memcpy(&destinationBefore, descriptor + 0x0C, sizeof destinationBefore);
        dump_current_activity(
            L"prelaunch_publication_before",
            {descriptor, kSelectionPublicationBytes});

        const SelectionPublicationState0 state0 =
            g_selectionPublicationState0.load(std::memory_order_acquire);
        if (state0 != nullptr && typeBefore != 0U && stateBefore == 0U) {
            state0(descriptor);
        }

        const std::uint8_t stateAfterNative = std::to_integer<std::uint8_t>(descriptor[3]);
        std::int16_t sourceAfter = -1;
        std::int16_t destinationAfter = -1;
        std::memcpy(&sourceAfter, descriptor + 0x0A, sizeof sourceAfter);
        std::memcpy(&destinationAfter, descriptor + 0x0C, sizeof destinationAfter);
        constexpr std::size_t kPublicationPackageOffset = 0x58;
        constexpr std::size_t kPublicationPackageCapacity = 40;
        std::size_t packageLength = 0;
        for (; packageLength < kPublicationPackageCapacity
               && descriptor[kPublicationPackageOffset + packageLength] != std::byte{};
             ++packageLength) {
        }
        dump_current_activity(
            L"prelaunch_publication_after",
            {descriptor, kSelectionPublicationBytes});

        homecomingPublicationPopulated = stateAfterNative != stateBefore
                                         && sourceAfter == kChosenActivityIndex
                                         && destinationAfter == kHomecomingActivityIndex;

        std::array<char, 384> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_prelaunch_publication result=%s caller_rva=0x%llX type=%u state_before=%u state_after_native=%u source_before=%d destination_before=%d source_after=%d destination_after=%d package_after=%.*s mutation=native_only",
            homecomingPublicationPopulated ? "populated" : "unchanged",
            static_cast<unsigned long long>(caller - image),
            static_cast<unsigned int>(typeBefore),
            static_cast<unsigned int>(stateBefore),
            static_cast<unsigned int>(stateAfterNative),
            static_cast<int>(sourceBefore),
            static_cast<int>(destinationBefore),
            static_cast<int>(sourceAfter),
            static_cast<int>(destinationAfter),
            static_cast<int>(packageLength),
            reinterpret_cast<const char*>(descriptor + kPublicationPackageOffset));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             homecomingPublicationPopulated
                                 ? core::log::Level::info
                                 : core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    const bool published = original != nullptr ? original(owner, descriptor) : false;
    if (pending) {
        std::byte* publisherManager = nullptr;
        std::byte* publishedRecord = nullptr;
        std::int32_t managerMode = -1;
        std::int32_t registered = -1;
        std::uint8_t ownerFlagsAfter = 0xFFU;
        __try {
            if (owner != nullptr) {
                publisherManager = *reinterpret_cast<std::byte**>(owner + 0x18);
                ownerFlagsAfter = std::to_integer<std::uint8_t>(owner[0x140]);
                dump_current_activity(
                    L"prelaunch_publication_owner_after",
                    {owner, kSelectionPublicationOwnerProbeBytes});
            }
            if (publisherManager != nullptr) {
                managerMode = *reinterpret_cast<std::int32_t*>(publisherManager + 0x1AEF8);
                registered = *reinterpret_cast<std::int32_t*>(publisherManager + 0xE93C);
            }
            if (owner != nullptr && registered >= 0) {
                const std::size_t recordBase = managerMode >= 6 && managerMode <= 9
                                                   ? 0x0B78U
                                                   : 0x99F8U;
                publishedRecord = owner + recordBase
                                  + static_cast<std::size_t>(registered) * 0x0BE0U;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            publisherManager = nullptr;
            publishedRecord = nullptr;
            managerMode = -1;
            registered = -1;
        }

        std::array<char, 640> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_prelaunch_publication_commit result=%s owner=%p vtable=%p notify_initial_rva=0x%llX notify_changed_rva=0x%llX owner_flags_before=0x%02X owner_flags_after=0x%02X manager=%p manager_mode=%d registered=%d record=%p bytes=%zu mutation=native_only",
            published ? "accepted" : "rejected",
            static_cast<void*>(owner),
            static_cast<void*>(ownerVtable),
            static_cast<unsigned long long>(
                image != nullptr && notifyInitialTarget >= image
                    ? notifyInitialTarget - image
                    : 0U),
            static_cast<unsigned long long>(
                image != nullptr && notifyChangedTarget >= image
                    ? notifyChangedTarget - image
                    : 0U),
            static_cast<unsigned int>(ownerFlagsBefore),
            static_cast<unsigned int>(ownerFlagsAfter),
            static_cast<void*>(publisherManager),
            managerMode,
            registered,
            static_cast<void*>(publishedRecord),
            kSelectionPublicationBytes);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             published
                                 ? core::log::Level::info
                                 : core::log::Level::warn,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    return published;
}

/**
 * Applies one known Red War opening activity to a decoded selection at a caller-supplied offset.
 * @param bytes Complete object holding the selection.
 * @param selectionOffset First decoded reason field.
 * @param replaceSource True for the final controller, whose base activity must also stop being
 * Tower; false for the outbound request, where the source documents what the client picked.
 */
[[nodiscard]] bool force_opening_selection(std::span<std::byte> bytes,
                                           std::size_t selectionOffset,
                                           bool replaceSource,
                                           std::int16_t* forcedIndex = nullptr) noexcept {
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    const std::int16_t activityIndex = package == "cine_110_twr"
                                           ? kTowerCinematicActivityIndex
                                       : package == "mission_towerfall"
                                           ? kHomecomingActivityIndex
                                           : -1;
    if (!state::activity::forced::override_active() || activityIndex < 0
        || bytes.size() < selectionOffset + kPackageNameOffset + kPackageNameCapacity) {
        return false;
    }
    if (replaceSource) {
        std::memcpy(bytes.data() + selectionOffset + kSourceActivityIndexOffset,
                    &activityIndex,
                    sizeof activityIndex);
    }
    std::memcpy(bytes.data() + selectionOffset + kActivityIndexOffset,
                &activityIndex,
                sizeof activityIndex);
    std::memset(bytes.data() + selectionOffset + kPackageNameOffset,
                0,
                kPackageNameCapacity);
    std::memcpy(bytes.data() + selectionOffset + kPackageNameOffset,
                forced.packageName.data(),
                forced.packageNameLength);
    if (forcedIndex != nullptr) {
        *forcedIndex = activityIndex;
    }
    return true;
}

/** Reads and updates the same optional current-activity value used by in-world startup. */
void force_current_activity() noexcept {
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (image == nullptr) {
        return;
    }
    const auto worldController =
        reinterpret_cast<WorldControllerAccessor>(image + kWorldControllerAccessorRva);
    const auto present =
        reinterpret_cast<CurrentActivityPresent>(image + kCurrentActivityPresentRva);
    const auto value = reinterpret_cast<CurrentActivityValue>(image + kCurrentActivityValueRva);
    std::byte* const world = worldController(0);
    if (world == nullptr) {
        return;
    }
    std::byte* const container = world + kCurrentActivityContainerOffset;
    if (!present(container)) {
        return;
    }
    std::byte* const activity = value(container);
    MEMORY_BASIC_INFORMATION memory{};
    if (activity == nullptr || VirtualQuery(activity, &memory, sizeof memory) != sizeof memory
        || memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return;
    }
    const auto regionEnd = reinterpret_cast<std::uintptr_t>(memory.BaseAddress) + memory.RegionSize;
    const auto activityAddress = reinterpret_cast<std::uintptr_t>(activity);
    const std::size_t available = regionEnd > activityAddress ? regionEnd - activityAddress : 0;
    const std::size_t size =
        available < kCurrentActivityProbeBytes ? available : kCurrentActivityProbeBytes;
    if (size != 0) {
        std::span<std::byte> bytes{activity, size};
        dump_current_activity(L"before", bytes);
        std::int16_t activityIndex = -1;
        const bool forced = force_opening_selection(bytes, 0, true, &activityIndex);
        dump_current_activity(L"after", bytes);
        std::array<char, 112> line{};
        const int length = forced
                               ? std::snprintf(line.data(),
                                               line.size(),
                                               "ev=bootflow stage=current_activity_force activity=%d result=ok",
                                               static_cast<int>(activityIndex))
                               : std::snprintf(line.data(),
                                               line.size(),
                                               "ev=bootflow stage=current_activity_force result=inactive");
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             forced ? core::log::Level::info : core::log::Level::debug,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
}

/**
 * Replaces the two client-local fields that select the investment activity and world package.
 * All still-unknown fields remain byte-for-byte identical to the client's Tower selection.
 */
[[nodiscard]] bool force_opening(std::span<std::byte> record,
                                 std::int16_t& activityIndex) noexcept {
    return force_opening_selection(record, kSelectionOffset, false, &activityIndex);
}

/** Observes the record immediately before the client copies its local activity selection. */
__declspec(noinline) void __fastcall request_update(std::byte* manager,
                                                     std::int32_t slot) noexcept {
    if (manager != nullptr && slot >= 0 && static_cast<std::size_t>(slot) < kSlotCount) {
        const auto offset = kFirstRecordOffset + static_cast<std::size_t>(slot) * kRecordStride;
        std::span<std::byte> record{manager + offset, kRecordStride};
        const bool first =
            !g_dumped[static_cast<std::size_t>(slot)].exchange(true, std::memory_order_relaxed);
        if (first) {
            dump_record(slot, L"before", record);
        }
        std::int16_t activityIndex = -1;
        // Slot 0 owns the authored launch selection. Slots 1 and 2 are internal activity-client
        // records; during the public-region handoff slot 2 is deliberately blank and native code
        // fills it only after the target client connects. Giving that blank record only an
        // activity index and package name creates an incomplete selection and stalls the initial
        // slice-set loading fiber.
        const bool forced = slot == 0 && force_opening(record, activityIndex);
        if (first) {
            dump_record(slot, L"after", record);
            std::array<char, 160> line{};
            const int length = forced
                                   ? std::snprintf(line.data(),
                                                   line.size(),
                                                   "ev=bootflow stage=activity_selection_force activity=%d result=ok",
                                                   static_cast<int>(activityIndex))
                                   : std::snprintf(line.data(),
                                                   line.size(),
                                                   "ev=bootflow stage=activity_selection_force result=inactive");
            if (length > 0) {
                core::log::write(core::log::Channel::client,
                                 forced ? core::log::Level::info : core::log::Level::debug,
                                 {line.data(), static_cast<std::size_t>(length)});
            }
        }
    }
    const RequestUpdate original = g_original.load(std::memory_order_acquire);
    if (original != nullptr) {
        if (slot == 2) {
            g_slot2RequestStarted.store(true, std::memory_order_release);
        }
        original(manager, slot);
        if (slot == 2
            && !g_slot2RequestReturned.exchange(true, std::memory_order_acq_rel)) {
            std::int32_t state = -1;
            if (manager != nullptr) {
                std::memcpy(&state,
                            manager + kFirstRecordOffset
                                + static_cast<std::size_t>(slot) * kRecordStride,
                            sizeof state);
            }
            std::array<char, 112> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=bootflow stage=activity_selection_request_return slot=2 state=%d result=ok",
                state);
            if (length > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(length)});
            }
        }
    }
}

void capture_activity_notification_type_eight_resolver_slots() noexcept;

/** Observes all three activity-client selections before and after each native state-machine tick. */
__declspec(noinline) void __fastcall pump_update(std::byte* manager) noexcept {
    if (manager != nullptr) {
        for (std::size_t slot = 0; slot < kSlotCount; ++slot) {
            observe_pump_record(manager, slot, "before");
        }
    }
    const PumpUpdate original = g_pumpOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(manager);
    }
    if (g_slot2RequestStarted.load(std::memory_order_acquire)
        && !g_pumpReturnedAfterSlot2.exchange(true, std::memory_order_acq_rel)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         "ev=bootflow stage=activity_selection_pump_return_after_slot2 result=ok");
    }
    if (manager != nullptr) {
        for (std::size_t slot = 0; slot < kSlotCount; ++slot) {
            observe_pump_record(manager, slot, "after");
        }
    }
    capture_activity_notification_type_eight_resolver_slots();
}

[[nodiscard]] bool state5_blocking_trace_active() noexcept {
    return g_state5Entered.load(std::memory_order_acquire)
           && !g_state5Returned.load(std::memory_order_acquire);
}

template <typename Value>
[[nodiscard]] Value component_ingress_safe_read(const void* address,
                                                Value fallback = {}) noexcept {
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

/**
 * Saves the first native type-8 resolver object that becomes visible without creating one.
 * RVA 0x4CEF90 keeps per-thread return objects in the small pointer array beginning at
 * image+0x2735F18. Polling all eight possible entries observes lazy initialization on any worker.
 */
void capture_activity_notification_type_eight_resolver_slots() noexcept {
    if (g_activityNotificationTypeEightResolverCaptured.load(std::memory_order_acquire)) {
        return;
    }
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (image == nullptr) {
        return;
    }
    for (std::size_t slot = 0; slot < 8U; ++slot) {
        auto* const object = component_ingress_safe_read<std::byte*>(
            image + 0x02735F18U + slot * sizeof(void*), nullptr);
        auto* const vtable = component_ingress_safe_read<std::byte*>(object, nullptr);
        auto* const consumer = component_ingress_safe_read<std::byte*>(
            vtable != nullptr ? vtable + 0xB0U : nullptr, nullptr);
        if (object == nullptr || vtable == nullptr || consumer == nullptr
            || g_activityNotificationTypeEightResolverCaptured.exchange(
                true, std::memory_order_acq_rel)) {
            continue;
        }
        const std::uintptr_t consumerRva = consumer >= image
                                               ? static_cast<std::uintptr_t>(consumer - image)
                                               : 0U;
        std::array<char, 384> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_notification_type8_resolver_capture source=slot slot=%zu object=%p vtable=%p consumer=%p consumer_rva=0x%llX result=ok mutation=observe_only",
            slot,
            static_cast<void*>(object),
            static_cast<void*>(vtable),
            static_cast<void*>(consumer),
            static_cast<unsigned long long>(consumerRva));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
        dump_code(L"activity_notification_type8_resolved_vtable", vtable, 0x400U);
        dump_code(L"activity_notification_type8_resolved_consumer", consumer, 0x4000U);
        return;
    }
}

/** Observes the type-8 resolver's native return and records its virtual +0xB0 consumer. */
__declspec(noinline) std::byte* __fastcall activity_notification_type_eight_resolver() noexcept {
    const ActivityNotificationTypeEightResolver original =
        g_activityNotificationTypeEightResolverOriginal.load(std::memory_order_acquire);
    std::byte* const object = original != nullptr ? original() : nullptr;
    auto* const vtable = component_ingress_safe_read<std::byte*>(object, nullptr);
    auto* const consumer = component_ingress_safe_read<std::byte*>(
        vtable != nullptr ? vtable + 0xB0U : nullptr, nullptr);
    if (object != nullptr && vtable != nullptr && consumer != nullptr
        && !g_activityNotificationTypeEightResolverCaptured.exchange(
            true, std::memory_order_acq_rel)) {
        auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
        const auto* const returnAddress = static_cast<const std::byte*>(_ReturnAddress());
        const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                             ? static_cast<std::uintptr_t>(returnAddress - image)
                                             : 0U;
        const std::uintptr_t consumerRva = image != nullptr && consumer >= image
                                               ? static_cast<std::uintptr_t>(consumer - image)
                                               : 0U;
        std::array<char, 448> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_notification_type8_resolver_capture source=return caller_rva=0x%llX object=%p vtable=%p consumer=%p consumer_rva=0x%llX result=ok mutation=observe_only",
            static_cast<unsigned long long>(callerRva),
            static_cast<void*>(object),
            static_cast<void*>(vtable),
            static_cast<void*>(consumer),
            static_cast<unsigned long long>(consumerRva));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
        dump_code(L"activity_notification_type8_resolved_vtable", vtable, 0x400U);
        dump_code(L"activity_notification_type8_resolved_consumer", consumer, 0x4000U);
    }
    return object;
}

[[nodiscard]] bool towerfall_override_active() noexcept {
    state::activity::forced::ForcedDestination forced{};
    state::activity::forced::snapshot(forced);
    const std::string_view package(forced.packageName.data(), forced.packageNameLength);
    return state::activity::forced::override_active() && package == "mission_towerfall";
}

void log_authored_component_ingest(std::uint32_t observation,
                                   std::uint32_t identityTwoObservation,
                                   const char* phase,
                                   std::uintptr_t callerRva,
                                   std::byte* manager,
                                   const std::byte* records,
                                   const void* argument2,
                                   const void* argument3) noexcept {
    const std::int32_t identity = component_ingress_safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1C7C0 : nullptr, -1);
    const std::int32_t recordCount = component_ingress_safe_read<std::int32_t>(
        records != nullptr ? records + 0x08 : nullptr, -1);
    const std::byte* const firstRecord = records != nullptr ? records + 0x0C : nullptr;
    const std::byte* const context = manager != nullptr ? manager + 0x860 : nullptr;
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_authored_component_ingest n=%u identity2_n=%u phase=%s caller_rva=0x%llX manager=%p identity=%d records=%p records_qword=0x%llX record_count=%d first_q0=0x%llX first_q8=0x%llX first_q10=0x%llX first_q18=0x%llX argument2=%p argument2_qword=0x%llX argument3=%p argument3_qword=0x%llX total=%d slot0_count=%d slot1_count=%d slot2_count=%d active=0x%08X mutation=observe_only",
        observation,
        identityTwoObservation,
        phase,
        static_cast<unsigned long long>(callerRva),
        static_cast<void*>(manager),
        identity,
        static_cast<const void*>(records),
        static_cast<unsigned long long>(
            component_ingress_safe_read<std::uint64_t>(records, 0U)),
        recordCount,
        static_cast<unsigned long long>(
            component_ingress_safe_read<std::uint64_t>(firstRecord, 0U)),
        static_cast<unsigned long long>(component_ingress_safe_read<std::uint64_t>(
            firstRecord != nullptr ? firstRecord + 0x08 : nullptr, 0U)),
        static_cast<unsigned long long>(component_ingress_safe_read<std::uint64_t>(
            firstRecord != nullptr ? firstRecord + 0x10 : nullptr, 0U)),
        static_cast<unsigned long long>(component_ingress_safe_read<std::uint64_t>(
            firstRecord != nullptr ? firstRecord + 0x18 : nullptr, 0U)),
        argument2,
        static_cast<unsigned long long>(
            component_ingress_safe_read<std::uint64_t>(argument2, 0U)),
        argument3,
        static_cast<unsigned long long>(
            component_ingress_safe_read<std::uint64_t>(argument3, 0U)),
        component_ingress_safe_read<std::int32_t>(
            context != nullptr ? context + 0x3B58 : nullptr, -1),
        component_ingress_safe_read<std::int32_t>(
            context != nullptr ? context + 0xE8 : nullptr, -1),
        component_ingress_safe_read<std::int32_t>(
            context != nullptr ? context + 0x1A0 : nullptr, -1),
        component_ingress_safe_read<std::int32_t>(
            context != nullptr ? context + 0x258 : nullptr, -1),
        component_ingress_safe_read<std::uint32_t>(
            context != nullptr ? context + 0x3B5C : nullptr, 0U));
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Observes whether authored/network ingest receives no component records or is never dispatched. */
__declspec(noinline) void __fastcall authored_component_ingest(std::byte* manager,
                                                                const std::byte* records,
                                                                const void* argument2,
                                                                const void* argument3) noexcept {
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    auto* const returnAddress = reinterpret_cast<std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    const std::int32_t identity = component_ingress_safe_read<std::int32_t>(
        manager != nullptr ? manager + 0x1C7C0 : nullptr, -1);
    const bool observe = towerfall_override_active();
    const std::uint32_t observation =
        observe ? g_authoredComponentIngestObserved.fetch_add(1U, std::memory_order_relaxed) + 1U
                : 0U;
    const std::uint32_t identityTwoObservation =
        observe && identity == 2
            ? g_authoredComponentIngestIdentityTwoObserved.fetch_add(1U,
                                                                      std::memory_order_relaxed)
                  + 1U
            : 0U;
    const bool log = observe
                     && (observation <= 128U
                         || (identity == 2 && identityTwoObservation <= 256U));
    if (log) {
        log_authored_component_ingest(observation,
                                      identityTwoObservation,
                                      "enter",
                                      callerRva,
                                      manager,
                                      records,
                                      argument2,
                                      argument3);
    }

    const AuthoredComponentIngest original =
        g_authoredComponentIngestOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(manager, records, argument2, argument3);
    }

    if (log) {
        log_authored_component_ingest(observation,
                                      identityTwoObservation,
                                      "exit",
                                      callerRva,
                                      manager,
                                      records,
                                      argument2,
                                      argument3);
    }
}

struct AuthoredComponentLaneSnapshot {
    std::int32_t candidateCount{-1};
    std::array<std::int32_t, 6> generation{};
    std::array<std::int32_t, 6> state{};
    std::array<std::uint32_t, 6> flags{};
};

[[nodiscard]] AuthoredComponentLaneSnapshot snapshot_authored_component_lanes() noexcept {
    AuthoredComponentLaneSnapshot snapshot{};
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    if (image == nullptr) {
        return snapshot;
    }
    snapshot.candidateCount = component_ingress_safe_read<std::int32_t>(
        image + kAuthoredComponentCandidateCountRva, -1);
    const std::byte* const table = image + kAuthoredComponentLaneTableRva;
    for (std::size_t lane = 0; lane < snapshot.state.size(); ++lane) {
        const std::byte* const record = table + (lane * 0x14);
        snapshot.generation[lane] =
            component_ingress_safe_read<std::int32_t>(record + 0x08, -1);
        snapshot.state[lane] = component_ingress_safe_read<std::int32_t>(record + 0x0C, -1);
        const std::uint32_t flag0 =
            component_ingress_safe_read<std::uint8_t>(record + 0x10, 0U);
        const std::uint32_t flag1 =
            component_ingress_safe_read<std::uint8_t>(record + 0x11, 0U);
        const std::uint32_t flag2 =
            component_ingress_safe_read<std::uint8_t>(record + 0x12, 0U);
        snapshot.flags[lane] = flag0 | (flag1 << 8U) | (flag2 << 16U);
    }
    return snapshot;
}

/** Observes the six-lane scheduler that owns the sole call to authored component ingest. */
__declspec(noinline) void __fastcall authored_component_dispatch_owner(
    std::uint32_t eligibleMask) noexcept {
    const bool observe = towerfall_override_active();
    const bool postHostReady =
        observe && state::activity::forced::opening_host_ready();
    const AuthoredComponentLaneSnapshot before = observe
                                                     ? snapshot_authored_component_lanes()
                                                     : AuthoredComponentLaneSnapshot{};
    const AuthoredComponentDispatchOwner original =
        g_authoredComponentDispatchOwnerOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(eligibleMask);
    }
    if (!observe) {
        return;
    }
    const std::uint32_t observation =
        postHostReady
            ? g_authoredComponentDispatchOwnerPostHostReadyObserved.fetch_add(
                  1U, std::memory_order_relaxed)
                  + 1U
            : g_authoredComponentDispatchOwnerObserved.fetch_add(
                  1U, std::memory_order_relaxed)
                  + 1U;
    const std::uint32_t observationLimit = postHostReady ? 2048U : 2048U;
    if (observation > observationLimit) {
        return;
    }
    if (postHostReady
        && !g_authoredComponentPostHostReadyTraceAnnounced.exchange(
            true, std::memory_order_acq_rel)) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_authored_component_trace_window phase=armed trigger=opening_host_ready mutation=observe_only");
    }
    const AuthoredComponentLaneSnapshot after = snapshot_authored_component_lanes();
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_authored_component_dispatch_owner window=%s n=%u caller_rva=0x17600C8 eligible_mask=0x%08X candidate_before=%d candidate_after=%d state_before=%d,%d,%d,%d,%d,%d state_after=%d,%d,%d,%d,%d,%d generation_before=%d,%d,%d,%d,%d,%d generation_after=%d,%d,%d,%d,%d,%d flags_before=%06X,%06X,%06X,%06X,%06X,%06X flags_after=%06X,%06X,%06X,%06X,%06X,%06X mutation=observe_only",
        postHostReady ? "post_host_ready" : "pre_host_ready",
        observation,
        eligibleMask,
        before.candidateCount,
        after.candidateCount,
        before.state[0],
        before.state[1],
        before.state[2],
        before.state[3],
        before.state[4],
        before.state[5],
        after.state[0],
        after.state[1],
        after.state[2],
        after.state[3],
        after.state[4],
        after.state[5],
        before.generation[0],
        before.generation[1],
        before.generation[2],
        before.generation[3],
        before.generation[4],
        before.generation[5],
        after.generation[0],
        after.generation[1],
        after.generation[2],
        after.generation[3],
        after.generation[4],
        after.generation[5],
        before.flags[0],
        before.flags[1],
        before.flags[2],
        before.flags[3],
        before.flags[4],
        before.flags[5],
        after.flags[0],
        after.flags[1],
        after.flags[2],
        after.flags[3],
        after.flags[4],
        after.flags[5]);
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
}

/** Observes the exact manager predicate that can skip a lane before candidate selection. */
__declspec(noinline) bool __fastcall authored_component_manager_skip_predicate(
    std::byte* manager) noexcept {
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    auto* const returnAddress = reinterpret_cast<std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    const AuthoredComponentManagerSkipPredicate original =
        g_authoredComponentManagerSkipPredicateOriginal.load(std::memory_order_acquire);
    const bool result = original != nullptr && original(manager);
    if (!towerfall_override_active()
        || callerRva != kAuthoredComponentManagerSkipPredicateReturnRva) {
        return result;
    }
    const bool postHostReady = state::activity::forced::opening_host_ready();
    const std::uint32_t observation =
        postHostReady
            ? g_authoredComponentManagerSkipPredicatePostHostReadyObserved.fetch_add(
                  1U, std::memory_order_relaxed)
                  + 1U
            : g_authoredComponentManagerSkipPredicateObserved.fetch_add(
                  1U, std::memory_order_relaxed)
                  + 1U;
    const std::uint32_t observationLimit = postHostReady ? 2048U : 1024U;
    if (observation > observationLimit) {
        return result;
    }
    const std::byte* const context = manager != nullptr ? manager + 0x860 : nullptr;
    std::array<char, 384> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_authored_component_manager_skip window=%s n=%u caller_rva=0x%llX manager=%p identity=%d manager_state=%d skip=%u component_total=%d component_active=0x%08X mutation=observe_only",
        postHostReady ? "post_host_ready" : "pre_host_ready",
        observation,
        static_cast<unsigned long long>(callerRva),
        static_cast<void*>(manager),
        component_ingress_safe_read<std::int32_t>(
            manager != nullptr ? manager + 0x1C7C0 : nullptr, -1),
        component_ingress_safe_read<std::int32_t>(
            manager != nullptr ? manager + 0x1AEF8 : nullptr, -1),
        result ? 1U : 0U,
        component_ingress_safe_read<std::int32_t>(
            context != nullptr ? context + 0x3B58 : nullptr, -1),
        component_ingress_safe_read<std::uint32_t>(
            context != nullptr ? context + 0x3B5C : nullptr, 0U));
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    return result;
}

/** Observes the exact wire receiver that validates a candidate before calling the producer. */
__declspec(noinline) bool __fastcall authored_candidate_wire_receiver(
    std::byte* context,
    const void* argument1,
    const std::byte* message) noexcept {
    const std::uint32_t observation =
        g_authoredCandidateWireReceiverObserved.fetch_add(1U, std::memory_order_relaxed) + 1U;
    const bool overrideActive = towerfall_override_active();
    if (observation <= 512U) {
        std::array<char, 512> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_authored_candidate_wire_receiver n=%u phase=entry rva=0x016E0460 override_active=%u context=%p manager_table=%p argument1=%p message=%p message_type=%u field4=%d field8=%d fieldC=%d id0=0x%llX id8=0x%llX candidate_count=%d mutation=observe_only",
            observation,
            overrideActive ? 1U : 0U,
            static_cast<void*>(context),
            component_ingress_safe_read<void*>(context != nullptr ? context + 0x28 : nullptr,
                                               nullptr),
            argument1,
            static_cast<const void*>(message),
            component_ingress_safe_read<std::uint16_t>(message, 0U),
            component_ingress_safe_read<std::int32_t>(
                message != nullptr ? message + 0x04 : nullptr, -1),
            component_ingress_safe_read<std::int32_t>(
                message != nullptr ? message + 0x08 : nullptr, -1),
            component_ingress_safe_read<std::int32_t>(
                message != nullptr ? message + 0x0C : nullptr, -1),
            static_cast<unsigned long long>(component_ingress_safe_read<std::uint64_t>(
                message != nullptr ? message + 0x10 : nullptr, 0U)),
            static_cast<unsigned long long>(component_ingress_safe_read<std::uint64_t>(
                message != nullptr ? message + 0x18 : nullptr, 0U)),
            snapshot_authored_component_lanes().candidateCount);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    bool result = false;
    const AuthoredCandidateWireReceiver original =
        g_authoredCandidateWireReceiverOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        result = original(context, argument1, message);
    }
    if (observation <= 512U) {
        std::array<char, 256> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_authored_candidate_wire_receiver n=%u phase=return result=%u candidate_count=%d mutation=observe_only",
            observation,
            result ? 1U : 0U,
            snapshot_authored_component_lanes().candidateCount);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    return result;
}

/** Observes entry and return of the native authored-candidate producer without altering it. */
__declspec(noinline) void __fastcall authored_candidate_producer(std::byte* manager,
                                                                  const void* argument1,
                                                                  const std::byte* candidate) noexcept {
    const bool observe = towerfall_override_active();
    const std::uint32_t observation =
        observe
            ? g_authoredCandidateProducerObserved.fetch_add(1U, std::memory_order_relaxed) + 1U
            : 0U;
    const std::int32_t countBefore = snapshot_authored_component_lanes().candidateCount;
    if (observe && observation <= 512U) {
        std::array<char, 512> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_authored_candidate_producer n=%u phase=entry rva=0x01755540 manager=%p identity=%d manager_state=%d argument1=%p candidate=%p candidate_id=0x%llX candidate_mode0=%u candidate_mode1=%u candidate_count=%d mutation=observe_only",
            observation,
            static_cast<void*>(manager),
            component_ingress_safe_read<std::int32_t>(
                manager != nullptr ? manager + 0x1C7C0 : nullptr, -1),
            component_ingress_safe_read<std::int32_t>(
                manager != nullptr ? manager + 0x1AEF8 : nullptr, -1),
            argument1,
            static_cast<const void*>(candidate),
            static_cast<unsigned long long>(
                component_ingress_safe_read<std::uint64_t>(candidate, 0U)),
            component_ingress_safe_read<std::uint8_t>(
                candidate != nullptr ? candidate + 0x1510 : nullptr, 0U),
            component_ingress_safe_read<std::uint8_t>(
                candidate != nullptr ? candidate + 0x1511 : nullptr, 0U),
            countBefore);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    const AuthoredCandidateProducer original =
        g_authoredCandidateProducerOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(manager, argument1, candidate);
    }
    if (observe && observation <= 512U) {
        std::array<char, 256> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_authored_candidate_producer n=%u phase=return candidate_count_before=%d candidate_count_after=%d mutation=observe_only",
            observation,
            countBefore,
            snapshot_authored_component_lanes().candidateCount);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
}

/** Records the native producer's rejection/result code without altering it. */
__declspec(noinline) void __fastcall authored_candidate_result_reporter(
    std::byte* manager,
    const void* argument1,
    std::uint64_t candidateIdentifier,
    std::int32_t resultCode) noexcept {
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    auto* const returnAddress = reinterpret_cast<std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    if (towerfall_override_active() && callerRva >= kAuthoredCandidateProducerBeginRva
        && callerRva < kAuthoredCandidateProducerEndRva) {
        const std::uint32_t observation =
            g_authoredCandidateResultReporterObserved.fetch_add(1U,
                                                                 std::memory_order_relaxed)
            + 1U;
        if (observation <= 512U) {
            std::array<char, 384> line{};
            const int length = std::snprintf(
                line.data(),
                line.size(),
                "ev=bootflow stage=activity_selection_authored_candidate_result n=%u caller_rva=0x%llX manager=%p identity=%d argument1=%p candidate_id=0x%llX result_code=%d candidate_count=%d mutation=observe_only",
                observation,
                static_cast<unsigned long long>(callerRva),
                static_cast<void*>(manager),
                component_ingress_safe_read<std::int32_t>(
                    manager != nullptr ? manager + 0x1C7C0 : nullptr, -1),
                argument1,
                static_cast<unsigned long long>(candidateIdentifier),
                resultCode,
                snapshot_authored_component_lanes().candidateCount);
            if (length > 0) {
                core::log::write(core::log::Channel::client,
                                 core::log::Level::info,
                                 {line.data(), static_cast<std::size_t>(length)});
            }
        }
    }
    const AuthoredCandidateResultReporter original =
        g_authoredCandidateResultReporterOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(manager, argument1, candidateIdentifier, resultCode);
    }
}

/**
 * Observes the native component-record ingress used by all three known producers. The hook only
 * records arguments and before/after counters; it never writes the manager snapshot.
 */
__declspec(noinline) std::int32_t __fastcall component_ingress(std::byte* context,
                                                               std::int32_t slot,
                                                               std::int32_t componentIndex,
                                                               const void* identifier,
                                                               const void* descriptor,
                                                               bool flag0,
                                                               bool flag1,
                                                               bool flag2,
                                                               bool flag3,
                                                               bool flag4) noexcept {
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    auto* const returnAddress = reinterpret_cast<std::byte*>(_ReturnAddress());
    const std::uintptr_t callerRva = image != nullptr && returnAddress >= image
                                         ? static_cast<std::uintptr_t>(returnAddress - image)
                                         : 0U;
    constexpr std::ptrdiff_t kContextToManagerIdentity = 0x1C7C0 - 0x860;
    const std::int32_t identity = component_ingress_safe_read<std::int32_t>(
        context != nullptr ? context + kContextToManagerIdentity : nullptr, -1);
    const bool observe = towerfall_override_active();
    const bool slotValid = context != nullptr && slot >= 0 && slot < 64;
    const bool componentValid = slotValid && componentIndex >= 0 && componentIndex < 64;
    const std::uint32_t activeBefore = observe
                                           ? component_ingress_safe_read<std::uint32_t>(
                                                 context != nullptr ? context + 0x3B5C : nullptr,
                                                 0U)
                                           : 0U;
    const std::int32_t totalBefore = observe
                                         ? component_ingress_safe_read<std::int32_t>(
                                               context != nullptr ? context + 0x3B58 : nullptr,
                                               -1)
                                         : -1;
    const std::int32_t countBefore = observe
                                         ? component_ingress_safe_read<std::int32_t>(
                                               slotValid ? context + 0xE8 + (slot * 0xB8)
                                                         : nullptr,
                                               -1)
                                         : -1;
    const std::int32_t mappingBefore = observe
                                           ? component_ingress_safe_read<std::int32_t>(
                                                 componentValid
                                                     ? context + 0xF0 + (slot * 0xB8)
                                                           + (componentIndex * 4)
                                                     : nullptr,
                                                 -1)
                                           : -1;
    const std::uint64_t identifierValue = observe
                                              ? component_ingress_safe_read<std::uint64_t>(
                                                    identifier, 0U)
                                              : 0U;
    const std::uint64_t descriptorValue = observe
                                              ? component_ingress_safe_read<std::uint64_t>(
                                                    descriptor, 0U)
                                              : 0U;

    const ComponentIngress original =
        g_componentIngressOriginal.load(std::memory_order_acquire);
    const std::int32_t result = original != nullptr
                                    ? original(context,
                                               slot,
                                               componentIndex,
                                               identifier,
                                               descriptor,
                                               flag0,
                                               flag1,
                                               flag2,
                                               flag3,
                                               flag4)
                                    : -1;
    if (!observe) {
        return result;
    }

    const std::uint32_t observation =
        g_componentIngressObserved.fetch_add(1U, std::memory_order_relaxed) + 1U;
    const std::uint32_t identityOneObservation =
        identity == 1
            ? g_componentIngressIdentityOneObserved.fetch_add(1U, std::memory_order_relaxed) + 1U
            : 0U;
    const std::uint32_t identityTwoObservation =
        identity == 2
            ? g_componentIngressIdentityTwoObserved.fetch_add(1U, std::memory_order_relaxed) + 1U
            : 0U;
    const bool focusedIdentity = (identity == 1 && identityOneObservation <= 256U)
                                 || (identity == 2 && identityTwoObservation <= 256U);
    if (observation > 256U && !focusedIdentity) {
        return result;
    }

    const std::uint32_t activeAfter = component_ingress_safe_read<std::uint32_t>(
        context != nullptr ? context + 0x3B5C : nullptr, 0U);
    const std::int32_t totalAfter = component_ingress_safe_read<std::int32_t>(
        context != nullptr ? context + 0x3B58 : nullptr, -1);
    const std::int32_t countAfter = component_ingress_safe_read<std::int32_t>(
        slotValid ? context + 0xE8 + (slot * 0xB8) : nullptr, -1);
    const std::int32_t mappingAfter = component_ingress_safe_read<std::int32_t>(
        componentValid ? context + 0xF0 + (slot * 0xB8) + (componentIndex * 4) : nullptr,
        -1);
    std::array<char, core::log::kLineCapacity> line{};
    const int length = std::snprintf(
        line.data(),
        line.size(),
        "ev=bootflow stage=activity_selection_component_ingress n=%u identity_n=%u identity2_n=%u caller_rva=0x%llX context=%p identity=%d slot=%d component_index=%d identifier=%p identifier_qword=0x%llX descriptor=%p descriptor_qword=0x%llX flags=%u%u%u%u%u result=%d total_before=%d total_after=%d count_before=%d count_after=%d mapping_before=%d mapping_after=%d active_before=0x%08X active_after=0x%08X mutation=observe_only",
        observation,
        identityOneObservation,
        identityTwoObservation,
        static_cast<unsigned long long>(callerRva),
        static_cast<void*>(context),
        identity,
        slot,
        componentIndex,
        identifier,
        static_cast<unsigned long long>(identifierValue),
        descriptor,
        static_cast<unsigned long long>(descriptorValue),
        flag0 ? 1U : 0U,
        flag1 ? 1U : 0U,
        flag2 ? 1U : 0U,
        flag3 ? 1U : 0U,
        flag4 ? 1U : 0U,
        result,
        totalBefore,
        totalAfter,
        countBefore,
        countAfter,
        mappingBefore,
        mappingAfter,
        activeBefore,
        activeAfter);
    if (length > 0) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::info,
                         {line.data(), static_cast<std::size_t>(length)});
    }
    return result;
}

/** Observes the outer slot-2 connection-payload builder recovered from the fiber stack. */
__declspec(noinline) void __fastcall state5_request_builder(void* context,
                                                            std::int32_t slot,
                                                            std::byte* output) noexcept {
    const bool trace = state5_blocking_trace_active();
    if (trace
        && !g_state5RequestBuilderEntered.exchange(true, std::memory_order_acq_rel)) {
        std::array<char, 176> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_request_builder phase=entry rva=0xBFC970 slot=%d context=%p output=%p mutation=observe_only",
            slot,
            context,
            static_cast<void*>(output));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    const State5RequestBuilder original =
        g_state5RequestBuilderOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(context, slot, output);
    }
    if (trace
        && !g_state5RequestBuilderReturned.exchange(true, std::memory_order_acq_rel)) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_state5_request_builder phase=return rva=0xBFC970 mutation=observe_only");
    }
}

/** Observes the payload finalizer tail-called by the outer state-5 request builder. */
__declspec(noinline) void __fastcall state5_payload_finalizer(void* context,
                                                              bool enabled,
                                                              std::byte* output) noexcept {
    const bool trace = state5_blocking_trace_active();
    if (trace
        && !g_state5PayloadFinalizerEntered.exchange(true, std::memory_order_acq_rel)) {
        std::array<char, 176> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_payload_finalizer phase=entry rva=0xC21530 enabled=%u context=%p output=%p mutation=observe_only",
            enabled ? 1U : 0U,
            context,
            static_cast<void*>(output));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    const State5PayloadFinalizer original =
        g_state5PayloadFinalizerOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(context, enabled, output);
    }
    if (trace
        && !g_state5PayloadFinalizerReturned.exchange(true, std::memory_order_acq_rel)) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_state5_payload_finalizer phase=return rva=0xC21530 mutation=observe_only");
    }
}

/** Observes the innermost connection-payload serializer without touching its output. */
__declspec(noinline) void __fastcall state5_payload_serializer(void* context,
                                                               std::int32_t slot,
                                                               bool enabled,
                                                               std::byte* output) noexcept {
    const bool trace = state5_blocking_trace_active();
    if (trace
        && !g_state5PayloadSerializerEntered.exchange(true, std::memory_order_acq_rel)) {
        std::array<char, 192> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_payload_serializer phase=entry rva=0xC21820 slot=%d enabled=%u context=%p output=%p mutation=observe_only",
            slot,
            enabled ? 1U : 0U,
            context,
            static_cast<void*>(output));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    const State5PayloadSerializer original =
        g_state5PayloadSerializerOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(context, slot, enabled, output);
    }
    if (trace
        && !g_state5PayloadSerializerReturned.exchange(true, std::memory_order_acq_rel)) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_state5_payload_serializer phase=return rva=0xC21820 mutation=observe_only");
    }
}

/** Observes the lookup whose call at 0xC219B3 owns the first live game return frame. */
__declspec(noinline) const std::byte* __fastcall state5_payload_lookup(
    const void* context,
    std::int32_t slot) noexcept {
    const bool trace = state5_blocking_trace_active()
        && g_state5PayloadSerializerEntered.load(std::memory_order_acquire)
        && !g_state5PayloadSerializerReturned.load(std::memory_order_acquire);
    if (trace && !g_state5PayloadLookupEntered.exchange(true, std::memory_order_acq_rel)) {
        std::array<char, 176> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_payload_lookup phase=entry rva=0x17797B0 slot=%d context=%p mutation=observe_only",
            slot,
            context);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    const State5PayloadLookup original =
        g_state5PayloadLookupOriginal.load(std::memory_order_acquire);
    const std::byte* const result = original != nullptr ? original(context, slot) : nullptr;
    if (trace && !g_state5PayloadLookupReturned.exchange(true, std::memory_order_acq_rel)) {
        std::array<char, 160> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_payload_lookup phase=return rva=0x17797B0 result=%p mutation=observe_only",
            static_cast<const void*>(result));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
    return result;
}

/** Marks entry and return around the exact native slot-state-5 boundary that currently hitches. */
__declspec(noinline) void __fastcall state5_update(std::byte* manager,
                                                   std::int32_t slot) noexcept {
    if (slot == 2 && !g_state5Entered.exchange(true, std::memory_order_acq_rel)) {
        std::int32_t state = -1;
        if (manager != nullptr) {
            std::memcpy(&state,
                        manager + kFirstRecordOffset
                            + static_cast<std::size_t>(slot) * kRecordStride,
                        sizeof state);
        }
        std::array<char, 128> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_entry slot=2 state=%d manager=%p result=ok",
            state,
            static_cast<void*>(manager));
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
        if (manager != nullptr) {
            const auto offset = kFirstRecordOffset
                                + static_cast<std::size_t>(slot) * kRecordStride;
            dump_record(slot,
                        L"state5_entry",
                        {manager + offset, kRecordStride});
        }
        g_state5EntryStackTop.store(
            reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()),
            std::memory_order_release);
        g_state5FiberContext.store(GetCurrentFiber(), std::memory_order_release);
        g_state5ThreadId.store(GetCurrentThreadId(), std::memory_order_release);
        if (!g_state5SnapshotStarted.exchange(true, std::memory_order_acq_rel)) {
            const HANDLE worker = CreateThread(nullptr,
                                               0,
                                               &state5_snapshot_worker,
                                               nullptr,
                                               0,
                                               nullptr);
            if (worker != nullptr) {
                (void)CloseHandle(worker);
            }
        }
    }
    const State5Update original = g_state5Original.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(manager, slot);
    }
    if (slot == 2 && !g_state5Returned.exchange(true, std::memory_order_acq_rel)) {
        std::int32_t state = -1;
        if (manager != nullptr) {
            std::memcpy(&state,
                        manager + kFirstRecordOffset
                            + static_cast<std::size_t>(slot) * kRecordStride,
                        sizeof state);
        }
        std::array<char, 112> line{};
        const int length = std::snprintf(
            line.data(),
            line.size(),
            "ev=bootflow stage=activity_selection_state5_return slot=2 state=%d result=ok",
            state);
        if (length > 0) {
            core::log::write(core::log::Channel::client,
                             core::log::Level::info,
                             {line.data(), static_cast<std::size_t>(length)});
        }
    }
}

/** Captures the final current-activity object immediately before native in-world startup. */
__declspec(noinline) void __fastcall start_update(void* context,
                                                  std::int32_t first,
                                                  std::int32_t second) noexcept {
    if (!g_currentDumped.exchange(true, std::memory_order_relaxed)) {
        force_current_activity();
    }
    const StartUpdate original = g_startOriginal.load(std::memory_order_acquire);
    if (original != nullptr) {
        original(context, first, second);
    }
}

[[nodiscard]] std::array<legacy_owner_sentinel::HookOwnership, 40>
activity_selection_hook_ownership() noexcept {
    // LEGACY_OWNER_SENTINEL_BEGIN(activity_selection, 40)
    return {{{g_handle.attached,
              g_original.load(std::memory_order_acquire) != nullptr},
             {g_pumpHandle.attached,
              g_pumpOriginal.load(std::memory_order_acquire) != nullptr},
             {g_state5Handle.attached,
              g_state5Original.load(std::memory_order_acquire) != nullptr},
             {g_state5RequestBuilderHandle.attached,
              g_state5RequestBuilderOriginal.load(std::memory_order_acquire) != nullptr},
             {g_state5PayloadFinalizerHandle.attached,
              g_state5PayloadFinalizerOriginal.load(std::memory_order_acquire) != nullptr},
             {g_state5PayloadSerializerHandle.attached,
              g_state5PayloadSerializerOriginal.load(std::memory_order_acquire) != nullptr},
             {g_state5PayloadLookupHandle.attached,
              g_state5PayloadLookupOriginal.load(std::memory_order_acquire) != nullptr},
             {g_componentIngressHandle.attached,
              g_componentIngressOriginal.load(std::memory_order_acquire) != nullptr},
             {g_authoredComponentIngestHandle.attached,
              g_authoredComponentIngestOriginal.load(std::memory_order_acquire) != nullptr},
             {g_authoredComponentDispatchOwnerHandle.attached,
              g_authoredComponentDispatchOwnerOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_authoredComponentManagerSkipPredicateHandle.attached,
              g_authoredComponentManagerSkipPredicateOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_authoredCandidateWireReceiverHandle.attached,
              g_authoredCandidateWireReceiverOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_authoredCandidateProducerHandle.attached,
              g_authoredCandidateProducerOriginal.load(std::memory_order_acquire) != nullptr},
             {g_authoredCandidateResultReporterHandle.attached,
              g_authoredCandidateResultReporterOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_startHandle.attached,
              g_startOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionLaunchStateHandle.attached,
              g_selectionLaunchStateOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionLaunchPublisherHandle.attached,
              g_selectionLaunchPublisherOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionPublicationOwnerAccessorHandle.attached,
              g_selectionPublicationOwnerAccessorOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionPublicationStateMachineHandle.attached,
              g_selectionPublicationStateMachineOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteReadyQueryHandle.attached,
              g_selectionRouteReadyQueryOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionRoutePairInvalidHandle.attached,
              g_selectionRoutePairInvalidOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionRouteDestinationAllowedHandle.attached,
              g_selectionRouteDestinationAllowedOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRoutePrimaryReadyHandle.attached,
              g_selectionRoutePrimaryReadyOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionRouteFallbackReadyHandle.attached,
              g_selectionRouteFallbackReadyOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionRouteRegistryReadyHandle.attached,
              g_selectionRouteRegistryReadyOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionRouteRegistrySlotWriterHandle.attached,
              g_selectionRouteRegistrySlotWriterOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteRegistrySlotWriterPredicateHandle.attached,
              g_selectionRouteRegistrySlotWriterPredicateOriginal.load(
                  std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteRegistryQueuedWrapperHandle.attached,
              g_selectionRouteRegistryQueuedWrapperOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteDestinationSlotRequestHandle.attached,
              g_selectionRouteDestinationSlotRequestOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteSlotInitializeHandle.attached,
              g_selectionRouteSlotInitializeOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRoutePackageRegistrationHandle.attached,
              g_selectionRoutePackageRegistrationOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteObjectBuilderHandle.attached,
              g_selectionRouteObjectBuilderOriginal.load(std::memory_order_acquire) != nullptr},
             {g_selectionRouteDefinitionIndexResolverHandle.attached,
              g_selectionRouteDefinitionIndexResolverOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRoutePackageIndexResolverHandle.attached,
              g_selectionRoutePackageIndexResolverOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteActivityContextHandle.attached,
              g_selectionRouteActivityContextOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteResolvedPackageHandle.attached,
              g_selectionRouteResolvedPackageOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteStrictComparisonHandle.attached,
              g_selectionRouteStrictComparisonOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRouteDestinationRegistryHandle.attached,
              g_selectionRouteDestinationRegistryOriginal.load(std::memory_order_acquire)
                  != nullptr},
             {g_selectionRoutePackageMatchesHandle.attached,
              g_selectionRoutePackageMatchesOriginal.load(std::memory_order_acquire) != nullptr},
             {g_activityNotificationTypeEightResolverHandle.attached,
              g_activityNotificationTypeEightResolverOriginal.load(std::memory_order_acquire)
                  != nullptr}}};
    // LEGACY_OWNER_SENTINEL_END(activity_selection)
}

} // namespace

bool activity_selection_probe_attached() noexcept {
    return legacy_owner_sentinel::any_handle_attached(activity_selection_hook_ownership());
}

bool activity_selection_probe_has_ownership() noexcept {
    // LEGACY_OWNER_CLAIMS_BEGIN(activity_selection, 9)
    const std::array claims{
        g_selectionPublicationState0.load(std::memory_order_acquire) != nullptr,
        g_activitySelectionPumpTarget.load(std::memory_order_acquire) != nullptr,
        g_selectionStateOneWatchVectoredHandler != nullptr,
        g_selectionStateOneWatchStatus.load(std::memory_order_acquire)
            != SelectionStateOneWatchStatus::idle,
        g_selectionStateOneWatchArmStarted.load(std::memory_order_acquire),
        g_selectionStateOneWatchArmedThreads.load(std::memory_order_acquire) != 0U,
        g_selectionStateOneWatchAddress.load(std::memory_order_acquire) != 0U,
        g_state5SnapshotStarted.load(std::memory_order_acquire),
        g_selectionRouteObjectBuilderSnapshotStarted.load(std::memory_order_acquire),
    };
    // LEGACY_OWNER_CLAIMS_END(activity_selection)
    return legacy_owner_sentinel::has_ownership(activity_selection_hook_ownership(), claims);
}

/** Arms the next launcher invocation after its code has been decrypted by a prior selection. */
void arm_activity_selection_launch_state_probe() noexcept {
    LateInstallGuard lateInstall;
    if (!lateInstall.accepted()) {
        return;
    }
    if (g_selectionLaunchStateHandle.attached && g_selectionLaunchPublisherHandle.attached
        && g_selectionPublicationOwnerAccessorHandle.attached
        && g_selectionPublicationStateMachineHandle.attached
        && g_selectionRouteReadyQueryHandle.attached
        && g_selectionRoutePairInvalidHandle.attached
        && g_selectionRouteDestinationAllowedHandle.attached
        && g_selectionRoutePrimaryReadyHandle.attached
        && g_selectionRouteFallbackReadyHandle.attached
        && g_selectionRouteRegistryReadyHandle.attached
        && g_selectionRouteActivityContextHandle.attached
        && g_selectionRouteResolvedPackageHandle.attached
        && g_selectionRouteStrictComparisonHandle.attached
        && g_selectionRouteDestinationRegistryHandle.attached
        && g_selectionRoutePackageMatchesHandle.attached) {
        return;
    }
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    std::byte* const target =
        image != nullptr ? image + kSelectionLaunchStateAccessorRva : nullptr;
    MEMORY_BASIC_INFORMATION memory{};
    const DWORD executableMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                                 | PAGE_EXECUTE_WRITECOPY;
    if (target == nullptr || VirtualQuery(target, &memory, sizeof memory) != sizeof memory
        || memory.State != MEM_COMMIT || (memory.Protect & executableMask) == 0
        || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return;
    }
    if (!g_selectionLaunchStateHandle.attached) {
        dump_code(L"activity_selection_launch_state_accessor", target, 0x200U);
        if (!hooking::detour::install(
                {target, reinterpret_cast<void*>(&selection_launch_state_accessor)},
                g_selectionLaunchStateHandle)) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::warn,
                "ev=bootflow stage=activity_selection_launch_state_probe result=fail reason=attach");
            return;
        }
        g_selectionLaunchStateOriginal.store(
            reinterpret_cast<SelectionLaunchStateAccessor>(g_selectionLaunchStateHandle.original),
            std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_launch_state_probe result=ok mode=correct");
    }

    if (!g_selectionPublicationOwnerAccessorHandle.attached) {
        std::byte* const ownerAccessorTarget =
            image + kSelectionPublicationOwnerAccessorRva;
        MEMORY_BASIC_INFORMATION ownerAccessorMemory{};
        const bool ownerAccessorExecutable =
            VirtualQuery(ownerAccessorTarget,
                         &ownerAccessorMemory,
                         sizeof ownerAccessorMemory)
                == sizeof ownerAccessorMemory
            && ownerAccessorMemory.State == MEM_COMMIT
            && (ownerAccessorMemory.Protect & executableMask) != 0
            && (ownerAccessorMemory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
        if (!ownerAccessorExecutable
            || std::memcmp(ownerAccessorTarget,
                           kSelectionPublicationOwnerAccessorPrologue.data(),
                           kSelectionPublicationOwnerAccessorPrologue.size())
                   != 0) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::warn,
                "ev=bootflow stage=activity_selection_prelaunch_owner_access_probe result=fail reason=validation");
            return;
        }
        dump_code(L"activity_selection_prelaunch_owner_accessor",
                  ownerAccessorTarget,
                  0x100U);
        if (!hooking::detour::install(
                {ownerAccessorTarget,
                 reinterpret_cast<void*>(&selection_publication_owner_accessor)},
                g_selectionPublicationOwnerAccessorHandle)) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::warn,
                "ev=bootflow stage=activity_selection_prelaunch_owner_access_probe result=fail reason=attach");
            return;
        }
        g_selectionPublicationOwnerAccessorOriginal.store(
            reinterpret_cast<SelectionPublicationOwnerAccessor>(
                g_selectionPublicationOwnerAccessorHandle.original),
            std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_prelaunch_owner_access_probe result=ok mode=observe");
    }

    if (!g_selectionPublicationStateMachineHandle.attached) {
        std::byte* const stateMachineTarget =
            image + kSelectionPublicationStateMachineRva;
        MEMORY_BASIC_INFORMATION stateMachineMemory{};
        const bool stateMachineExecutable =
            VirtualQuery(stateMachineTarget,
                         &stateMachineMemory,
                         sizeof stateMachineMemory)
                == sizeof stateMachineMemory
            && stateMachineMemory.State == MEM_COMMIT
            && (stateMachineMemory.Protect & executableMask) != 0
            && (stateMachineMemory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
        if (!stateMachineExecutable
            || std::memcmp(stateMachineTarget,
                           kSelectionPublicationStateMachinePrologue.data(),
                           kSelectionPublicationStateMachinePrologue.size())
                   != 0) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::warn,
                "ev=bootflow stage=activity_selection_prelaunch_state_machine_probe result=fail reason=validation");
            return;
        }
        dump_code(L"activity_selection_prelaunch_state_machine",
                  stateMachineTarget,
                  0x1000U);
        if (!hooking::detour::install(
                {stateMachineTarget,
                 reinterpret_cast<void*>(&selection_publication_state_machine)},
                g_selectionPublicationStateMachineHandle)) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::warn,
                "ev=bootflow stage=activity_selection_prelaunch_state_machine_probe result=fail reason=attach");
            return;
        }
        g_selectionPublicationStateMachineOriginal.store(
            reinterpret_cast<SelectionPublicationStateMachine>(
                g_selectionPublicationStateMachineHandle.original),
            std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_selection_prelaunch_state_machine_probe result=ok mode=observe");
    }
    if (!g_selectionRouteReadyQueryHandle.attached) {
        std::byte* const readyTarget = image + kSelectionRouteReadyQueryRva;
        MEMORY_BASIC_INFORMATION readyMemory{};
        const bool readyExecutable =
            VirtualQuery(readyTarget, &readyMemory, sizeof readyMemory) == sizeof readyMemory
            && readyMemory.State == MEM_COMMIT
            && (readyMemory.Protect & executableMask) != 0
            && (readyMemory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
        const bool stillEncrypted = readyExecutable
                                    && readyTarget[0] == std::byte{0x91}
                                    && readyTarget[1] == std::byte{0xCC};
        if (!readyExecutable || stillEncrypted) {
            core::log::write(
                core::log::Channel::client,
                core::log::Level::warn,
                "ev=bootflow stage=activity_selection_prelaunch_route_ready_probe result=deferred reason=validation");
        } else {
            dump_code(L"activity_selection_prelaunch_route_ready_query",
                      readyTarget,
                      0x200U);
            if (hooking::detour::install(
                    {readyTarget,
                     reinterpret_cast<void*>(&selection_route_ready_query)},
                    g_selectionRouteReadyQueryHandle)) {
                g_selectionRouteReadyQueryOriginal.store(
                    reinterpret_cast<SelectionRouteReadyQuery>(
                        g_selectionRouteReadyQueryHandle.original),
                    std::memory_order_release);
                core::log::write(
                    core::log::Channel::client,
                    core::log::Level::info,
                    "ev=bootflow stage=activity_selection_prelaunch_route_ready_probe result=ok mode=observe");
            } else {
                core::log::write(
                    core::log::Channel::client,
                    core::log::Level::warn,
                    "ev=bootflow stage=activity_selection_prelaunch_route_ready_probe result=fail reason=attach");
            }
        }
    }

    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRoutePairInvalidRva,
        L"activity_selection_prelaunch_route_pair_invalid",
        "activity_selection_prelaunch_route_pair_invalid_probe",
        reinterpret_cast<void*>(&selection_route_pair_invalid),
        g_selectionRoutePairInvalidHandle,
        g_selectionRoutePairInvalidOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteDestinationAllowedRva,
        L"activity_selection_prelaunch_route_destination_allowed",
        "activity_selection_prelaunch_route_destination_allowed_probe",
        reinterpret_cast<void*>(&selection_route_destination_allowed),
        g_selectionRouteDestinationAllowedHandle,
        g_selectionRouteDestinationAllowedOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRoutePrimaryReadyRva,
        L"activity_selection_prelaunch_route_primary_ready",
        "activity_selection_prelaunch_route_primary_ready_probe",
        reinterpret_cast<void*>(&selection_route_primary_ready),
        g_selectionRoutePrimaryReadyHandle,
        g_selectionRoutePrimaryReadyOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteFallbackReadyRva,
        L"activity_selection_prelaunch_route_fallback_ready",
        "activity_selection_prelaunch_route_fallback_ready_probe",
        reinterpret_cast<void*>(&selection_route_fallback_ready),
        g_selectionRouteFallbackReadyHandle,
        g_selectionRouteFallbackReadyOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteRegistryReadyRva,
        L"activity_selection_prelaunch_destination_registry_ready",
        "activity_selection_prelaunch_destination_registry_ready_probe",
        reinterpret_cast<void*>(&selection_route_registry_ready),
        g_selectionRouteRegistryReadyHandle,
        g_selectionRouteRegistryReadyOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteRegistrySlotWriterRva,
        L"activity_selection_destination_registry_slot_writer",
        "activity_selection_destination_registry_slot_writer_probe",
        reinterpret_cast<void*>(&selection_route_registry_slot_writer),
        g_selectionRouteRegistrySlotWriterHandle,
        g_selectionRouteRegistrySlotWriterOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteRegistrySlotWriterPredicateRva,
        L"activity_selection_destination_registry_slot_writer_predicate",
        "activity_selection_destination_registry_slot_writer_predicate_probe",
        reinterpret_cast<void*>(&selection_route_registry_slot_writer_predicate),
        g_selectionRouteRegistrySlotWriterPredicateHandle,
        g_selectionRouteRegistrySlotWriterPredicateOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteRegistryQueuedWrapperRva,
        L"activity_selection_destination_registry_queued_wrapper",
        "activity_selection_destination_registry_queued_wrapper_probe",
        reinterpret_cast<void*>(&selection_route_registry_queued_wrapper),
        g_selectionRouteRegistryQueuedWrapperHandle,
        g_selectionRouteRegistryQueuedWrapperOriginal);
    dump_code(L"activity_selection_destination_registry_queued_argument",
              image + kSelectionRouteRegistryQueuedArgumentRva,
              0x800U);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteDestinationSlotRequestRva,
        L"activity_selection_destination_slot_request",
        "activity_selection_destination_slot_request_probe",
        reinterpret_cast<void*>(&selection_route_destination_slot_request),
        g_selectionRouteDestinationSlotRequestHandle,
        g_selectionRouteDestinationSlotRequestOriginal);
    dump_code(L"activity_selection_destination_slot_request_context",
              image + kSelectionRouteDestinationSlotRequestContextRva,
              0x1000U);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteDefinitionIndexResolverRva,
        L"activity_selection_destination_definition_index_resolver",
        "activity_selection_destination_definition_index_resolver_probe",
        reinterpret_cast<void*>(&selection_route_definition_index_resolver),
        g_selectionRouteDefinitionIndexResolverHandle,
        g_selectionRouteDefinitionIndexResolverOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRoutePackageIndexResolverRva,
        L"activity_selection_destination_package_index_resolver",
        "activity_selection_destination_package_index_resolver_probe",
        reinterpret_cast<void*>(&selection_route_package_index_resolver),
        g_selectionRoutePackageIndexResolverHandle,
        g_selectionRoutePackageIndexResolverOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRoutePackageRegistrationRva,
        L"activity_selection_destination_package_registration",
        "activity_selection_destination_package_registration_probe",
        reinterpret_cast<void*>(&selection_route_package_registration),
        g_selectionRoutePackageRegistrationHandle,
        g_selectionRoutePackageRegistrationOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteObjectBuilderRva,
        L"activity_selection_route_object_builder",
        "activity_selection_route_object_builder_probe",
        reinterpret_cast<void*>(&selection_route_object_builder),
        g_selectionRouteObjectBuilderHandle,
        g_selectionRouteObjectBuilderOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteSlotInitializeRva,
        L"activity_selection_destination_slot_initialize",
        "activity_selection_destination_slot_initialize_probe",
        reinterpret_cast<void*>(&selection_route_slot_initialize),
        g_selectionRouteSlotInitializeHandle,
        g_selectionRouteSlotInitializeOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteActivityContextRva,
        L"activity_selection_prelaunch_destination_activity_context",
        "activity_selection_prelaunch_destination_activity_context_probe",
        reinterpret_cast<void*>(&selection_route_activity_context),
        g_selectionRouteActivityContextHandle,
        g_selectionRouteActivityContextOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteResolvedPackageRva,
        L"activity_selection_prelaunch_destination_resolved_package",
        "activity_selection_prelaunch_destination_resolved_package_probe",
        reinterpret_cast<void*>(&selection_route_resolved_package),
        g_selectionRouteResolvedPackageHandle,
        g_selectionRouteResolvedPackageOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteStrictComparisonRva,
        L"activity_selection_prelaunch_destination_strict_comparison",
        "activity_selection_prelaunch_destination_strict_comparison_probe",
        reinterpret_cast<void*>(&selection_route_strict_comparison),
        g_selectionRouteStrictComparisonHandle,
        g_selectionRouteStrictComparisonOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRouteDestinationRegistryRva,
        L"activity_selection_prelaunch_destination_registry",
        "activity_selection_prelaunch_destination_registry_probe",
        reinterpret_cast<void*>(&selection_route_destination_registry),
        g_selectionRouteDestinationRegistryHandle,
        g_selectionRouteDestinationRegistryOriginal);
    (void)install_selection_route_ready_detail_probe(
        image,
        kSelectionRoutePackageMatchesRva,
        L"activity_selection_prelaunch_destination_package_matches",
        "activity_selection_prelaunch_destination_package_matches_probe",
        reinterpret_cast<void*>(&selection_route_package_matches),
        g_selectionRoutePackageMatchesHandle,
        g_selectionRoutePackageMatchesOriginal);

    if (g_selectionLaunchPublisherHandle.attached) {
        return;
    }
    std::byte* const pumpTarget =
        g_activitySelectionPumpTarget.load(std::memory_order_acquire);
    std::byte* const state0Target =
        pumpTarget != nullptr ? pumpTarget + kSelectionPublicationState0Offset : nullptr;
    std::byte* const publisherTarget = image + kSelectionLaunchPublisherRva;
    MEMORY_BASIC_INFORMATION state0Memory{};
    MEMORY_BASIC_INFORMATION publisherMemory{};
    const bool state0Executable =
        state0Target != nullptr
        && VirtualQuery(state0Target, &state0Memory, sizeof state0Memory) == sizeof state0Memory
        && state0Memory.State == MEM_COMMIT && (state0Memory.Protect & executableMask) != 0
        && (state0Memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
    const bool publisherExecutable =
        VirtualQuery(publisherTarget, &publisherMemory, sizeof publisherMemory)
            == sizeof publisherMemory
        && publisherMemory.State == MEM_COMMIT && (publisherMemory.Protect & executableMask) != 0
        && (publisherMemory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0;
    if (!state0Executable || !publisherExecutable
        || std::memcmp(state0Target,
                       kSelectionPublicationState0Prologue.data(),
                       kSelectionPublicationState0Prologue.size())
               != 0
        || std::memcmp(publisherTarget,
                       kSelectionLaunchPublisherPrologue.data(),
                       kSelectionLaunchPublisherPrologue.size())
               != 0) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_prelaunch_publication_probe result=fail reason=validation");
        return;
    }
    if (!hooking::detour::install(
            {publisherTarget, reinterpret_cast<void*>(&selection_launch_publisher)},
            g_selectionLaunchPublisherHandle)) {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_prelaunch_publication_probe result=fail reason=attach");
        return;
    }
    g_selectionPublicationState0.store(
        reinterpret_cast<SelectionPublicationState0>(state0Target),
        std::memory_order_release);
    g_selectionLaunchPublisherOriginal.store(
        reinterpret_cast<SelectionLaunchPublisher>(g_selectionLaunchPublisherHandle.original),
        std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=bootflow stage=activity_selection_prelaunch_publication_probe result=ok mode=native_state0");
}

/** Attaches the read-only activity-selection record probe. */
bool install_activity_selection_probe() noexcept {
    LateInstallGuard lateInstall;
    if (!lateInstall.accepted()) {
        return false;
    }
    if (g_handle.attached && g_pumpHandle.attached && g_state5Handle.attached
        && g_state5RequestBuilderHandle.attached
        && g_state5PayloadFinalizerHandle.attached
        && g_state5PayloadSerializerHandle.attached
        && g_state5PayloadLookupHandle.attached && g_componentIngressHandle.attached
        && g_authoredComponentIngestHandle.attached
        && g_authoredComponentDispatchOwnerHandle.attached
        && g_authoredComponentManagerSkipPredicateHandle.attached
        && g_authoredCandidateWireReceiverHandle.attached
        && g_authoredCandidateProducerHandle.attached
        && g_authoredCandidateResultReporterHandle.attached && g_startHandle.attached) {
        return true;
    }
    auto* const image = reinterpret_cast<std::byte*>(GetModuleHandleW(nullptr));
    std::byte* const requestTarget =
        scan_main_image_unique(kRequestSignature, "activity_selection_request_update");
    std::byte* const pumpTarget =
        scan_main_image_unique(kPumpSignature, "activity_selection_state_machine");
    std::byte* const startTarget =
        scan_main_image_unique(kStartSignature, "activity_selection_start_update");
    std::byte* const state5Target = image != nullptr ? image + kState5UpdateRva : nullptr;
    std::byte* const state5RequestBuilderTarget =
        image != nullptr ? image + kState5RequestBuilderRva : nullptr;
    std::byte* const state5PayloadFinalizerTarget =
        image != nullptr ? image + kState5PayloadFinalizerRva : nullptr;
    std::byte* const state5PayloadSerializerTarget =
        image != nullptr ? image + kState5PayloadSerializerRva : nullptr;
    std::byte* const state5PayloadLookupTarget =
        image != nullptr ? image + kState5PayloadLookupRva : nullptr;
    std::byte* const state5SlotSnapshotAccessorTarget =
        image != nullptr ? image + kState5SlotSnapshotAccessorRva : nullptr;
    std::byte* const componentIngressTarget =
        image != nullptr ? image + kComponentIngressRva : nullptr;
    std::byte* const authoredComponentIngestTarget =
        image != nullptr ? image + kAuthoredComponentIngestRva : nullptr;
    std::byte* const authoredComponentDispatchOwnerTarget =
        image != nullptr ? image + kAuthoredComponentDispatchOwnerRva : nullptr;
    std::byte* const authoredComponentManagerSkipPredicateTarget =
        image != nullptr ? image + kAuthoredComponentManagerSkipPredicateRva : nullptr;
    std::byte* const authoredCandidateWireReceiverTarget =
        image != nullptr ? image + kAuthoredCandidateWireReceiverRva : nullptr;
    std::byte* const authoredCandidateProducerTarget =
        image != nullptr ? image + kAuthoredCandidateProducerRva : nullptr;
    std::byte* const authoredCandidateResultReporterTarget =
        image != nullptr ? image + kAuthoredCandidateResultReporterRva : nullptr;
    std::byte* const activityNotificationHandlerRegionTarget =
        image != nullptr ? image + 0x004F2600U : nullptr;
    std::byte* const activityNotificationSchemaGlobalsTarget =
        image != nullptr ? image + 0x01FA4200U : nullptr;
    std::byte* const typeOneSchemaOwner =
        image != nullptr
            ? *reinterpret_cast<std::byte**>(image + 0x01FA42D8U)
            : nullptr;
    std::byte* const typeOneSchema =
        typeOneSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeOneSchemaOwner + sizeof(void*))
            : nullptr;
    std::byte* const typeTwoSchemaOwner =
        image != nullptr
            ? *reinterpret_cast<std::byte**>(image + 0x01FA42E0U)
            : nullptr;
    std::byte* const typeTwoSchema =
        typeTwoSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeTwoSchemaOwner + sizeof(void*))
            : nullptr;
    std::byte* const typeOneSchemaCodecA =
        typeOneSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeOneSchemaOwner + 0x10U)
            : nullptr;
    std::byte* const typeOneSchemaCodecB =
        typeOneSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeOneSchemaOwner + 0x18U)
            : nullptr;
    std::byte* const typeTwoSchemaCodecA =
        typeTwoSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeTwoSchemaOwner + 0x10U)
            : nullptr;
    std::byte* const typeTwoSchemaCodecB =
        typeTwoSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeTwoSchemaOwner + 0x18U)
            : nullptr;
    // Historical typeEight/typeNine probe labels below actually refer to wire types 19/24:
    // the exact 21-row dispatcher at 1F92360 proves those mappings. Do not assume owner
    // +10/+18 are callable codec entry points: recovered type 12 uses metadata there.
    // Keep legacy dump labels for comparison; actual membership type 12 instead uses
    // schema owner global 1FA4180 and generic codecs.
    std::byte* const typeEightSchemaOwner =
        image != nullptr
            ? *reinterpret_cast<std::byte**>(image + 0x01FA3D28U)
            : nullptr;
    std::byte* const typeEightSchema =
        typeEightSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeEightSchemaOwner + sizeof(void*))
            : nullptr;
    std::byte* const typeEightSchemaCodecA =
        typeEightSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeEightSchemaOwner + 0x10U)
            : nullptr;
    std::byte* const typeEightSchemaCodecB =
        typeEightSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeEightSchemaOwner + 0x18U)
            : nullptr;
    std::byte* const typeNineSchemaOwner =
        image != nullptr
            ? *reinterpret_cast<std::byte**>(image + 0x01FA4290U)
            : nullptr;
    std::byte* const typeNineSchema =
        typeNineSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeNineSchemaOwner + sizeof(void*))
            : nullptr;
    std::byte* const typeNineSchemaCodecA =
        typeNineSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeNineSchemaOwner + 0x10U)
            : nullptr;
    std::byte* const typeNineSchemaCodecB =
        typeNineSchemaOwner != nullptr
            ? *reinterpret_cast<std::byte**>(typeNineSchemaOwner + 0x18U)
            : nullptr;
    std::byte* const activityAuthorityInterface =
        image != nullptr
            ? *reinterpret_cast<std::byte**>(image + 0x0267D5F8U)
            : nullptr;
    std::byte* const activityAuthorityVtable =
        activityAuthorityInterface != nullptr
            ? *reinterpret_cast<std::byte**>(activityAuthorityInterface)
            : nullptr;
    std::byte* const typeOneApply =
        activityAuthorityVtable != nullptr
            ? *reinterpret_cast<std::byte**>(activityAuthorityVtable + 0x310U)
            : nullptr;
    std::byte* const typeTwoApply =
        activityAuthorityVtable != nullptr
            ? *reinterpret_cast<std::byte**>(activityAuthorityVtable + 0x318U)
            : nullptr;
    std::byte* const activityEventRegisterTarget =
        image != nullptr ? image + 0x0040F500U : nullptr;
    std::byte* const activityEventPublishTarget =
        image != nullptr ? image + 0x004121B0U : nullptr;
    std::byte* const activityEventDescriptorRegionTarget =
        image != nullptr ? image + 0x02037800U : nullptr;
    // Activity notification type 2 publishes engine event 26.  Its registered listener resolves
    // the activity client and forwards the decoded body to RVA 0x003CB7A0.  Capture the containing
    // runtime-decrypted range so that the type-2 apply path can be followed without mutating it.
    std::byte* const activityNotificationTypeTwoClientApplyRegionTarget =
        image != nullptr ? image + 0x003CA000U : nullptr;
    // Legacy typeEight/typeNine diagnostic names identify the wire-19/24 consumers above.
    // Event 29 is produced by the independently recovered type-12 membership path at 16F0BA0.
    // Capture these old resolver/thunk neighborhoods only for historical comparisons.
    std::byte* const activityNotificationTypeEightObjectResolverRegionTarget =
        image != nullptr ? image + 0x004CE000U : nullptr;
    std::byte* const activityNotificationTypeNineGlobalResolverRegionTarget =
        image != nullptr ? image + 0x004FF000U : nullptr;
    std::byte* const activityNotificationAuthorityThunkRegionTarget =
        image != nullptr ? image + 0x00B42000U : nullptr;
    std::byte* const activityNotificationTypeEightResolverStateTarget =
        image != nullptr ? image + 0x02735E80U : nullptr;
    std::byte* const activityNotificationTypeNineGlobalInterface =
        image != nullptr
            ? *reinterpret_cast<std::byte**>(image + 0x02742F10U)
            : nullptr;
    std::byte* const activityNotificationTypeNineGlobalVtable =
        activityNotificationTypeNineGlobalInterface != nullptr
            ? *reinterpret_cast<std::byte**>(activityNotificationTypeNineGlobalInterface)
            : nullptr;
    std::byte* const activityNotificationTypeNineGlobalConsumer =
        activityNotificationTypeNineGlobalVtable != nullptr
            ? *reinterpret_cast<std::byte**>(activityNotificationTypeNineGlobalVtable + 0x100U)
            : nullptr;
    if (requestTarget == nullptr || pumpTarget == nullptr || state5Target == nullptr
        || state5RequestBuilderTarget == nullptr || state5PayloadFinalizerTarget == nullptr
        || state5PayloadSerializerTarget == nullptr || state5PayloadLookupTarget == nullptr
        || state5SlotSnapshotAccessorTarget == nullptr
        || componentIngressTarget == nullptr || authoredComponentIngestTarget == nullptr
        || authoredComponentDispatchOwnerTarget == nullptr
        || authoredComponentManagerSkipPredicateTarget == nullptr
        || authoredCandidateWireReceiverTarget == nullptr
        || authoredCandidateProducerTarget == nullptr
        || authoredCandidateResultReporterTarget == nullptr || startTarget == nullptr) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=activity_selection_probe result=fail reason=target");
        return false;
    }
    dump_code(L"activity_selection_request", requestTarget, 0x1200U);
    dump_code(L"activity_selection_pump", pumpTarget, 0x2000U);
    dump_code(L"activity_selection_state5", state5Target, 0x4000U);
    dump_code(L"activity_selection_state5_request_builder",
              state5RequestBuilderTarget,
              0x500U);
    dump_code(L"activity_selection_state5_payload_finalizer",
              state5PayloadFinalizerTarget,
              0x300U);
    dump_code(L"activity_selection_state5_payload_serializer",
              state5PayloadSerializerTarget,
              0x500U);
    dump_code(L"activity_selection_state5_payload_lookup",
              state5PayloadLookupTarget,
              0x800U);
    dump_code(L"activity_selection_state5_slot_snapshot_accessor",
              state5SlotSnapshotAccessorTarget,
              0x1000U);
    dump_code(L"activity_selection_component_ingress", componentIngressTarget, 0x500U);
    dump_code(L"activity_selection_authored_component_ingest",
              authoredComponentIngestTarget,
              0x1800U);
    dump_code(L"activity_selection_authored_component_dispatch_owner",
              authoredComponentDispatchOwnerTarget,
              0x500U);
    dump_code(L"activity_selection_authored_component_manager_skip_predicate",
              authoredComponentManagerSkipPredicateTarget,
              0x400U);
    dump_code(L"activity_selection_authored_candidate_wire_receiver",
              authoredCandidateWireReceiverTarget,
              0x500U);
    dump_code(L"activity_selection_authored_candidate_producer",
              authoredCandidateProducerTarget,
              0x600U);
    dump_code(L"activity_selection_authored_candidate_result_reporter",
              authoredCandidateResultReporterTarget,
              0x300U);
    // Capture the complete runtime-decrypted svc9 notification-handler cluster. This includes
    // the unimplemented type-2 handler at RVA 0x4F2C50 and its neighboring known handlers,
    // allowing their schema/apply chains to be compared without altering any network state.
    dump_code(L"activity_notification_handler_region",
              activityNotificationHandlerRegionTarget,
              0x1900U);
    dump_code(L"activity_notification_schema_globals",
              activityNotificationSchemaGlobalsTarget,
              0x400U);
    dump_code(L"activity_notification_type1_schema_owner", typeOneSchemaOwner, 0x200U);
    dump_code(L"activity_notification_type1_schema", typeOneSchema, 0x4000U);
    dump_code(L"activity_notification_type1_schema_codec_a", typeOneSchemaCodecA, 0x2000U);
    dump_code(L"activity_notification_type1_schema_codec_b", typeOneSchemaCodecB, 0x2000U);
    dump_code(L"activity_notification_type2_schema_owner", typeTwoSchemaOwner, 0x200U);
    dump_code(L"activity_notification_type2_schema", typeTwoSchema, 0x4000U);
    dump_code(L"activity_notification_type2_schema_codec_a", typeTwoSchemaCodecA, 0x2000U);
    dump_code(L"activity_notification_type2_schema_codec_b", typeTwoSchemaCodecB, 0x2000U);
    dump_code(L"activity_notification_type8_schema_owner", typeEightSchemaOwner, 0x200U);
    dump_code(L"activity_notification_type8_schema", typeEightSchema, 0x8000U);
    dump_code(L"activity_notification_type8_schema_codec_a", typeEightSchemaCodecA, 0x4000U);
    dump_code(L"activity_notification_type8_schema_codec_b", typeEightSchemaCodecB, 0x4000U);
    dump_code(L"activity_notification_type9_schema_owner", typeNineSchemaOwner, 0x200U);
    dump_code(L"activity_notification_type9_schema", typeNineSchema, 0x10000U);
    dump_code(L"activity_notification_type9_schema_codec_a", typeNineSchemaCodecA, 0x8000U);
    dump_code(L"activity_notification_type9_schema_codec_b", typeNineSchemaCodecB, 0x8000U);
    dump_code(L"activity_authority_interface", activityAuthorityInterface, 0x600U);
    dump_code(L"activity_authority_vtable", activityAuthorityVtable, 0x600U);
    dump_code(L"activity_notification_type1_apply", typeOneApply, 0x1000U);
    dump_code(L"activity_notification_type2_apply", typeTwoApply, 0x1800U);
    dump_code(L"activity_event_register", activityEventRegisterTarget, 0x1000U);
    dump_code(L"activity_event_publish", activityEventPublishTarget, 0x2000U);
    dump_code(L"activity_event_descriptor_region",
              activityEventDescriptorRegionTarget,
              0x1000U);
    dump_code(L"activity_notification_type2_client_apply_region",
              activityNotificationTypeTwoClientApplyRegionTarget,
              0x10000U);
    dump_code(L"activity_notification_type8_object_resolver_region",
              activityNotificationTypeEightObjectResolverRegionTarget,
              0x3000U);
    dump_code(L"activity_notification_type9_global_resolver_region",
              activityNotificationTypeNineGlobalResolverRegionTarget,
              0x3000U);
    dump_code(L"activity_notification_authority_thunk_region",
              activityNotificationAuthorityThunkRegionTarget,
              0x1000U);
    dump_code(L"activity_notification_type8_resolver_state",
              activityNotificationTypeEightResolverStateTarget,
              0x200U);
    dump_code(L"activity_notification_type9_global_interface",
              activityNotificationTypeNineGlobalInterface,
              0x1000U);
    dump_code(L"activity_notification_type9_global_vtable",
              activityNotificationTypeNineGlobalVtable,
              0x400U);
    dump_code(L"activity_notification_type9_global_consumer",
              activityNotificationTypeNineGlobalConsumer,
              0x4000U);
    const hooking::detour::Spec requestSpec{requestTarget,
                                            reinterpret_cast<void*>(&request_update)};
    const hooking::detour::Spec startSpec{startTarget, reinterpret_cast<void*>(&start_update)};
    if (!hooking::detour::install(requestSpec, g_handle)) {
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=activity_selection_probe result=fail reason=attach");
        return false;
    }
    g_original.store(reinterpret_cast<RequestUpdate>(g_handle.original), std::memory_order_release);
    const hooking::detour::Spec pumpSpec{pumpTarget, reinterpret_cast<void*>(&pump_update)};
    if (!hooking::detour::install(pumpSpec, g_pumpHandle)) {
        (void)hooking::detour::uninstall(g_handle);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=activity_selection_probe result=fail reason=pump_attach");
        return false;
    }
    g_pumpOriginal.store(reinterpret_cast<PumpUpdate>(g_pumpHandle.original),
                         std::memory_order_release);
    const hooking::detour::Spec state5Spec{state5Target,
                                           reinterpret_cast<void*>(&state5_update)};
    if (!hooking::detour::install(state5Spec, g_state5Handle)) {
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=activity_selection_probe result=fail reason=state5_attach");
        return false;
    }
    g_state5Original.store(reinterpret_cast<State5Update>(g_state5Handle.original),
                           std::memory_order_release);
    if (!hooking::detour::install(
            {state5RequestBuilderTarget, reinterpret_cast<void*>(&state5_request_builder)},
            g_state5RequestBuilderHandle)) {
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_state5_blocking_chain_probe result=fail reason=request_builder_attach");
        return false;
    }
    g_state5RequestBuilderOriginal.store(
        reinterpret_cast<State5RequestBuilder>(g_state5RequestBuilderHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {state5PayloadFinalizerTarget, reinterpret_cast<void*>(&state5_payload_finalizer)},
            g_state5PayloadFinalizerHandle)) {
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_state5_blocking_chain_probe result=fail reason=payload_finalizer_attach");
        return false;
    }
    g_state5PayloadFinalizerOriginal.store(
        reinterpret_cast<State5PayloadFinalizer>(g_state5PayloadFinalizerHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {state5PayloadSerializerTarget, reinterpret_cast<void*>(&state5_payload_serializer)},
            g_state5PayloadSerializerHandle)) {
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_state5_blocking_chain_probe result=fail reason=payload_serializer_attach");
        return false;
    }
    g_state5PayloadSerializerOriginal.store(
        reinterpret_cast<State5PayloadSerializer>(g_state5PayloadSerializerHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {state5PayloadLookupTarget, reinterpret_cast<void*>(&state5_payload_lookup)},
            g_state5PayloadLookupHandle)) {
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_state5_blocking_chain_probe result=fail reason=payload_lookup_attach");
        return false;
    }
    g_state5PayloadLookupOriginal.store(
        reinterpret_cast<State5PayloadLookup>(g_state5PayloadLookupHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {componentIngressTarget, reinterpret_cast<void*>(&component_ingress)},
            g_componentIngressHandle)) {
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_component_ingress_probe result=fail reason=attach");
        return false;
    }
    g_componentIngressOriginal.store(
        reinterpret_cast<ComponentIngress>(g_componentIngressHandle.original),
        std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=bootflow stage=activity_selection_component_ingress_probe result=ok mode=observe");
    if (!hooking::detour::install(
            {authoredComponentIngestTarget,
             reinterpret_cast<void*>(&authored_component_ingest)},
            g_authoredComponentIngestHandle)) {
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_authored_component_ingest_probe result=fail reason=attach");
        return false;
    }
    g_authoredComponentIngestOriginal.store(
        reinterpret_cast<AuthoredComponentIngest>(g_authoredComponentIngestHandle.original),
        std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=bootflow stage=activity_selection_authored_component_ingest_probe result=ok mode=observe");
    if (!hooking::detour::install(
            {authoredComponentDispatchOwnerTarget,
             reinterpret_cast<void*>(&authored_component_dispatch_owner)},
            g_authoredComponentDispatchOwnerHandle)) {
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_authored_component_dispatch_owner_probe result=fail reason=attach");
        return false;
    }
    g_authoredComponentDispatchOwnerOriginal.store(
        reinterpret_cast<AuthoredComponentDispatchOwner>(
            g_authoredComponentDispatchOwnerHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {authoredComponentManagerSkipPredicateTarget,
             reinterpret_cast<void*>(&authored_component_manager_skip_predicate)},
            g_authoredComponentManagerSkipPredicateHandle)) {
        (void)hooking::detour::uninstall(g_authoredComponentDispatchOwnerHandle);
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_authoredComponentDispatchOwnerOriginal.store(nullptr, std::memory_order_release);
        g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_authored_component_manager_skip_probe result=fail reason=attach");
        return false;
    }
    g_authoredComponentManagerSkipPredicateOriginal.store(
        reinterpret_cast<AuthoredComponentManagerSkipPredicate>(
            g_authoredComponentManagerSkipPredicateHandle.original),
        std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=bootflow stage=activity_selection_authored_component_dispatch_probe result=ok mode=observe");
    if (!hooking::detour::install(
            {authoredCandidateResultReporterTarget,
             reinterpret_cast<void*>(&authored_candidate_result_reporter)},
            g_authoredCandidateResultReporterHandle)) {
        (void)hooking::detour::uninstall(g_authoredComponentManagerSkipPredicateHandle);
        (void)hooking::detour::uninstall(g_authoredComponentDispatchOwnerHandle);
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_authoredComponentManagerSkipPredicateOriginal.store(nullptr,
                                                               std::memory_order_release);
        g_authoredComponentDispatchOwnerOriginal.store(nullptr,
                                                        std::memory_order_release);
        g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_authored_candidate_result_probe result=fail reason=attach");
        return false;
    }
    g_authoredCandidateResultReporterOriginal.store(
        reinterpret_cast<AuthoredCandidateResultReporter>(
            g_authoredCandidateResultReporterHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {authoredCandidateProducerTarget,
             reinterpret_cast<void*>(&authored_candidate_producer)},
            g_authoredCandidateProducerHandle)) {
        (void)hooking::detour::uninstall(g_authoredCandidateResultReporterHandle);
        (void)hooking::detour::uninstall(g_authoredComponentManagerSkipPredicateHandle);
        (void)hooking::detour::uninstall(g_authoredComponentDispatchOwnerHandle);
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_authoredCandidateResultReporterOriginal.store(nullptr,
                                                         std::memory_order_release);
        g_authoredComponentManagerSkipPredicateOriginal.store(nullptr,
                                                               std::memory_order_release);
        g_authoredComponentDispatchOwnerOriginal.store(nullptr,
                                                        std::memory_order_release);
        g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_authored_candidate_producer_probe result=fail reason=attach");
        return false;
    }
    g_authoredCandidateProducerOriginal.store(
        reinterpret_cast<AuthoredCandidateProducer>(g_authoredCandidateProducerHandle.original),
        std::memory_order_release);
    if (!hooking::detour::install(
            {authoredCandidateWireReceiverTarget,
             reinterpret_cast<void*>(&authored_candidate_wire_receiver)},
            g_authoredCandidateWireReceiverHandle)) {
        (void)hooking::detour::uninstall(g_authoredCandidateProducerHandle);
        (void)hooking::detour::uninstall(g_authoredCandidateResultReporterHandle);
        (void)hooking::detour::uninstall(g_authoredComponentManagerSkipPredicateHandle);
        (void)hooking::detour::uninstall(g_authoredComponentDispatchOwnerHandle);
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_authoredCandidateProducerOriginal.store(nullptr, std::memory_order_release);
        g_authoredCandidateResultReporterOriginal.store(nullptr,
                                                         std::memory_order_release);
        g_authoredComponentManagerSkipPredicateOriginal.store(nullptr,
                                                               std::memory_order_release);
        g_authoredComponentDispatchOwnerOriginal.store(nullptr,
                                                        std::memory_order_release);
        g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_selection_authored_candidate_wire_receiver_probe result=fail reason=attach");
        return false;
    }
    g_authoredCandidateWireReceiverOriginal.store(
        reinterpret_cast<AuthoredCandidateWireReceiver>(
            g_authoredCandidateWireReceiverHandle.original),
        std::memory_order_release);
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=bootflow stage=activity_selection_authored_candidate_probe result=ok mode=observe corrected_rva=0x01755540");
    core::log::write(
        core::log::Channel::client,
        core::log::Level::info,
        "ev=bootflow stage=activity_selection_state5_blocking_chain_probe result=ok mode=observe");
    if (!hooking::detour::install(startSpec, g_startHandle)) {
        (void)hooking::detour::uninstall(g_authoredCandidateWireReceiverHandle);
        (void)hooking::detour::uninstall(g_authoredCandidateProducerHandle);
        (void)hooking::detour::uninstall(g_authoredCandidateResultReporterHandle);
        (void)hooking::detour::uninstall(g_authoredComponentManagerSkipPredicateHandle);
        (void)hooking::detour::uninstall(g_authoredComponentDispatchOwnerHandle);
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
        (void)hooking::detour::uninstall(g_componentIngressHandle);
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
        (void)hooking::detour::uninstall(g_state5Handle);
        (void)hooking::detour::uninstall(g_pumpHandle);
        (void)hooking::detour::uninstall(g_handle);
        g_authoredCandidateResultReporterOriginal.store(nullptr,
                                                         std::memory_order_release);
        g_authoredCandidateProducerOriginal.store(nullptr, std::memory_order_release);
        g_authoredCandidateWireReceiverOriginal.store(nullptr,
                                                       std::memory_order_release);
        g_authoredComponentManagerSkipPredicateOriginal.store(nullptr,
                                                               std::memory_order_release);
        g_authoredComponentDispatchOwnerOriginal.store(nullptr,
                                                        std::memory_order_release);
        g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
        g_componentIngressOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
        g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
        g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
        g_state5Original.store(nullptr, std::memory_order_release);
        g_pumpOriginal.store(nullptr, std::memory_order_release);
        g_original.store(nullptr, std::memory_order_release);
        core::log::write(core::log::Channel::client,
                         core::log::Level::warn,
                         "ev=bootflow stage=activity_selection_probe result=fail reason=start_attach");
        return false;
    }
    g_startOriginal.store(reinterpret_cast<StartUpdate>(g_startHandle.original),
                          std::memory_order_release);
    g_activitySelectionPumpTarget.store(pumpTarget, std::memory_order_release);
    std::byte* const typeEightResolverTarget =
        image != nullptr ? image + kActivityNotificationTypeEightResolverRva : nullptr;
    if (typeEightResolverTarget != nullptr
        && hooking::detour::install(
            {typeEightResolverTarget,
             reinterpret_cast<void*>(&activity_notification_type_eight_resolver)},
            g_activityNotificationTypeEightResolverHandle)) {
        g_activityNotificationTypeEightResolverOriginal.store(
            reinterpret_cast<ActivityNotificationTypeEightResolver>(
                g_activityNotificationTypeEightResolverHandle.original),
            std::memory_order_release);
        core::log::write(
            core::log::Channel::client,
            core::log::Level::info,
            "ev=bootflow stage=activity_notification_type8_resolver_probe result=ok rva=0x004CEF90 mode=observe");
    } else {
        core::log::write(
            core::log::Channel::client,
            core::log::Level::warn,
            "ev=bootflow stage=activity_notification_type8_resolver_probe result=deferred reason=attach");
    }
    if constexpr (kEnableSelectionStateOneWriteWatch) {
        if (g_selectionStateOneWatchVectoredHandler == nullptr) {
            g_selectionStateOneWatchVectoredHandler =
                AddVectoredExceptionHandler(1, &selection_state_one_watch_handler);
        }
        core::log::write(
            core::log::Channel::client,
            g_selectionStateOneWatchVectoredHandler != nullptr ? core::log::Level::info
                                                               : core::log::Level::warn,
            g_selectionStateOneWatchVectoredHandler != nullptr
                ? "ev=bootflow stage=activity_selection_state1_write_watch_probe result=ok mode=observe_only"
                : "ev=bootflow stage=activity_selection_state1_write_watch_probe result=fail reason=veh mode=observe_only");
    }
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     "ev=bootflow stage=activity_selection_probe result=ok");
    return true;
}

/** Detaches the activity-selection record probe. */
void uninstall_activity_selection_probe() noexcept {
    g_selectionStateOneWatchStatus.store(SelectionStateOneWatchStatus::disabled,
                                         std::memory_order_release);
    clear_selection_state_one_watchpoints();
    if (g_selectionStateOneWatchVectoredHandler != nullptr) {
        (void)RemoveVectoredExceptionHandler(g_selectionStateOneWatchVectoredHandler);
        g_selectionStateOneWatchVectoredHandler = nullptr;
    }
    if (g_activityNotificationTypeEightResolverHandle.attached) {
        (void)hooking::detour::uninstall(g_activityNotificationTypeEightResolverHandle);
    }
    if (g_selectionLaunchPublisherHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionLaunchPublisherHandle);
    }
    if (g_selectionRouteRegistrySlotWriterHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteRegistrySlotWriterHandle);
    }
    if (g_selectionRouteRegistryQueuedWrapperHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteRegistryQueuedWrapperHandle);
    }
    if (g_selectionRouteDestinationSlotRequestHandle.attached) {
        (void)hooking::detour::uninstall(
            g_selectionRouteDestinationSlotRequestHandle);
    }
    if (g_selectionRouteRegistrySlotWriterPredicateHandle.attached) {
        (void)hooking::detour::uninstall(
            g_selectionRouteRegistrySlotWriterPredicateHandle);
    }
    if (g_selectionRouteSlotInitializeHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteSlotInitializeHandle);
    }
    if (g_selectionRouteObjectBuilderHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteObjectBuilderHandle);
    }
    if (g_selectionRoutePackageRegistrationHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRoutePackageRegistrationHandle);
    }
    if (g_selectionRouteDefinitionIndexResolverHandle.attached) {
        (void)hooking::detour::uninstall(
            g_selectionRouteDefinitionIndexResolverHandle);
    }
    if (g_selectionRoutePackageIndexResolverHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRoutePackageIndexResolverHandle);
    }
    if (g_selectionRoutePackageMatchesHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRoutePackageMatchesHandle);
    }
    if (g_selectionRouteDestinationRegistryHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteDestinationRegistryHandle);
    }
    if (g_selectionRouteStrictComparisonHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteStrictComparisonHandle);
    }
    if (g_selectionRouteResolvedPackageHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteResolvedPackageHandle);
    }
    if (g_selectionRouteActivityContextHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteActivityContextHandle);
    }
    if (g_selectionRouteRegistryReadyHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteRegistryReadyHandle);
    }
    if (g_selectionRouteFallbackReadyHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteFallbackReadyHandle);
    }
    if (g_selectionRoutePrimaryReadyHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRoutePrimaryReadyHandle);
    }
    if (g_selectionRouteDestinationAllowedHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteDestinationAllowedHandle);
    }
    if (g_selectionRoutePairInvalidHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRoutePairInvalidHandle);
    }
    if (g_selectionRouteReadyQueryHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionRouteReadyQueryHandle);
    }
    if (g_selectionPublicationStateMachineHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionPublicationStateMachineHandle);
    }
    if (g_selectionPublicationOwnerAccessorHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionPublicationOwnerAccessorHandle);
    }
    if (g_selectionLaunchStateHandle.attached) {
        (void)hooking::detour::uninstall(g_selectionLaunchStateHandle);
    }
    if (g_startHandle.attached) {
        (void)hooking::detour::uninstall(g_startHandle);
    }
    if (g_authoredCandidateWireReceiverHandle.attached) {
        (void)hooking::detour::uninstall(g_authoredCandidateWireReceiverHandle);
    }
    if (g_authoredCandidateProducerHandle.attached) {
        (void)hooking::detour::uninstall(g_authoredCandidateProducerHandle);
    }
    if (g_authoredCandidateResultReporterHandle.attached) {
        (void)hooking::detour::uninstall(g_authoredCandidateResultReporterHandle);
    }
    if (g_authoredComponentManagerSkipPredicateHandle.attached) {
        (void)hooking::detour::uninstall(g_authoredComponentManagerSkipPredicateHandle);
    }
    if (g_authoredComponentDispatchOwnerHandle.attached) {
        (void)hooking::detour::uninstall(g_authoredComponentDispatchOwnerHandle);
    }
    if (g_authoredComponentIngestHandle.attached) {
        (void)hooking::detour::uninstall(g_authoredComponentIngestHandle);
    }
    if (g_componentIngressHandle.attached) {
        (void)hooking::detour::uninstall(g_componentIngressHandle);
    }
    if (g_state5PayloadLookupHandle.attached) {
        (void)hooking::detour::uninstall(g_state5PayloadLookupHandle);
    }
    if (g_state5PayloadSerializerHandle.attached) {
        (void)hooking::detour::uninstall(g_state5PayloadSerializerHandle);
    }
    if (g_state5PayloadFinalizerHandle.attached) {
        (void)hooking::detour::uninstall(g_state5PayloadFinalizerHandle);
    }
    if (g_state5RequestBuilderHandle.attached) {
        (void)hooking::detour::uninstall(g_state5RequestBuilderHandle);
    }
    if (g_state5Handle.attached) {
        (void)hooking::detour::uninstall(g_state5Handle);
    }
    if (g_pumpHandle.attached) {
        (void)hooking::detour::uninstall(g_pumpHandle);
    }
    if (g_handle.attached) {
        (void)hooking::detour::uninstall(g_handle);
    }
    g_startOriginal.store(nullptr, std::memory_order_release);
    g_authoredCandidateWireReceiverOriginal.store(nullptr, std::memory_order_release);
    g_authoredCandidateProducerOriginal.store(nullptr, std::memory_order_release);
    g_authoredCandidateResultReporterOriginal.store(nullptr, std::memory_order_release);
    g_authoredComponentManagerSkipPredicateOriginal.store(nullptr,
                                                           std::memory_order_release);
    g_authoredComponentDispatchOwnerOriginal.store(nullptr, std::memory_order_release);
    g_authoredComponentIngestOriginal.store(nullptr, std::memory_order_release);
    g_componentIngressOriginal.store(nullptr, std::memory_order_release);
    g_state5PayloadLookupOriginal.store(nullptr, std::memory_order_release);
    g_state5PayloadSerializerOriginal.store(nullptr, std::memory_order_release);
    g_state5PayloadFinalizerOriginal.store(nullptr, std::memory_order_release);
    g_state5RequestBuilderOriginal.store(nullptr, std::memory_order_release);
    g_state5Original.store(nullptr, std::memory_order_release);
    g_pumpOriginal.store(nullptr, std::memory_order_release);
    g_original.store(nullptr, std::memory_order_release);
    g_selectionLaunchStateOriginal.store(nullptr, std::memory_order_release);
    g_selectionPublicationState0.store(nullptr, std::memory_order_release);
    g_selectionLaunchPublisherOriginal.store(nullptr, std::memory_order_release);
    g_selectionPublicationOwnerAccessorOriginal.store(nullptr,
                                                       std::memory_order_release);
    g_selectionPublicationStateMachineOriginal.store(nullptr,
                                                      std::memory_order_release);
    g_selectionRouteReadyQueryOriginal.store(nullptr,
                                             std::memory_order_release);
    g_selectionRoutePairInvalidOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteDestinationAllowedOriginal.store(nullptr, std::memory_order_release);
    g_selectionRoutePrimaryReadyOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteFallbackReadyOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteRegistryReadyOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteRegistrySlotWriterOriginal.store(nullptr,
                                                       std::memory_order_release);
    g_selectionRouteRegistryQueuedWrapperOriginal.store(nullptr,
                                                          std::memory_order_release);
    g_selectionRouteDestinationSlotRequestOriginal.store(
        nullptr,
        std::memory_order_release);
    g_selectionRouteRegistrySlotWriterPredicateOriginal.store(
        nullptr,
        std::memory_order_release);
    g_selectionRouteSlotInitializeOriginal.store(nullptr,
                                                   std::memory_order_release);
    g_selectionRouteObjectBuilderOriginal.store(nullptr,
                                                  std::memory_order_release);
    g_selectionRoutePackageRegistrationOriginal.store(nullptr,
                                                        std::memory_order_release);
    g_selectionRouteDefinitionIndexResolverOriginal.store(nullptr,
                                                            std::memory_order_release);
    g_selectionRoutePackageIndexResolverOriginal.store(nullptr,
                                                         std::memory_order_release);
    g_selectionRouteActivityContextOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteResolvedPackageOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteStrictComparisonOriginal.store(nullptr, std::memory_order_release);
    g_selectionRouteDestinationRegistryOriginal.store(nullptr,
                                                       std::memory_order_release);
    g_selectionRoutePackageMatchesOriginal.store(nullptr, std::memory_order_release);
    g_activityNotificationTypeEightResolverOriginal.store(nullptr,
                                                           std::memory_order_release);
    g_activityNotificationTypeEightResolverCaptured.store(false,
                                                            std::memory_order_release);
    g_activitySelectionPumpTarget.store(nullptr, std::memory_order_release);
    for (std::atomic_bool& dumped : g_dumped) {
        dumped.store(false, std::memory_order_release);
    }
    for (std::atomic_uint64_t& fingerprint : g_pumpFingerprints) {
        fingerprint.store(0, std::memory_order_release);
    }
    g_currentDumped.store(false, std::memory_order_release);
    g_slot2RequestStarted.store(false, std::memory_order_release);
    g_slot2RequestReturned.store(false, std::memory_order_release);
    g_pumpReturnedAfterSlot2.store(false, std::memory_order_release);
    g_state5Entered.store(false, std::memory_order_release);
    g_state5Returned.store(false, std::memory_order_release);
    g_state5SnapshotStarted.store(false, std::memory_order_release);
    g_state5ThreadId.store(0, std::memory_order_release);
    g_state5EntryStackTop.store(0, std::memory_order_release);
    g_state5FiberContext.store(nullptr, std::memory_order_release);
    g_state5RequestBuilderEntered.store(false, std::memory_order_release);
    g_state5RequestBuilderReturned.store(false, std::memory_order_release);
    g_state5PayloadFinalizerEntered.store(false, std::memory_order_release);
    g_state5PayloadFinalizerReturned.store(false, std::memory_order_release);
    g_state5PayloadSerializerEntered.store(false, std::memory_order_release);
    g_state5PayloadSerializerReturned.store(false, std::memory_order_release);
    g_state5PayloadLookupEntered.store(false, std::memory_order_release);
    g_state5PayloadLookupReturned.store(false, std::memory_order_release);
    g_componentIngressObserved.store(0U, std::memory_order_release);
    g_componentIngressIdentityOneObserved.store(0U, std::memory_order_release);
    g_componentIngressIdentityTwoObserved.store(0U, std::memory_order_release);
    g_authoredComponentIngestObserved.store(0U, std::memory_order_release);
    g_authoredComponentIngestIdentityTwoObserved.store(0U,
                                                        std::memory_order_release);
    g_authoredComponentDispatchOwnerObserved.store(0U, std::memory_order_release);
    g_authoredComponentDispatchOwnerPostHostReadyObserved.store(
        0U, std::memory_order_release);
    g_authoredComponentManagerSkipPredicateObserved.store(0U,
                                                           std::memory_order_release);
    g_authoredComponentManagerSkipPredicatePostHostReadyObserved.store(
        0U, std::memory_order_release);
    g_authoredComponentPostHostReadyTraceAnnounced.store(
        false, std::memory_order_release);
    g_authoredCandidateWireReceiverObserved.store(0U, std::memory_order_release);
    g_authoredCandidateProducerObserved.store(0U, std::memory_order_release);
    g_authoredCandidateResultReporterObserved.store(0U,
                                                     std::memory_order_release);
    g_selectionLaunchStateDumped.store(false, std::memory_order_release);
    g_homecomingPrelaunchPublicationPending.store(false, std::memory_order_release);
    g_prelaunchOwnerTraceArmed.store(false, std::memory_order_release);
    g_selectionPublicationOwnerAccessObserved.store(0U, std::memory_order_release);
    g_tracedPrelaunchRecord.store(nullptr, std::memory_order_release);
    g_selectionPublicationStateMachineObserved.store(0U,
                                                      std::memory_order_release);
    g_selectionPublicationStateFingerprint.store(0U, std::memory_order_release);
    g_selectionRouteReadyObserved.store(0U, std::memory_order_release);
    g_selectionRouteRegistrySlotWriterObserved.store(0U,
                                                       std::memory_order_release);
    g_selectionRouteRegistryQueuedWrapperObserved.store(0U,
                                                          std::memory_order_release);
    g_selectionRouteRegistryQueuedThunkDumped.store(false,
                                                      std::memory_order_release);
    g_selectionStateOneWatchStatus.store(SelectionStateOneWatchStatus::idle,
                                         std::memory_order_release);
    g_selectionStateOneWatchArmStarted.store(false, std::memory_order_release);
    g_selectionStateOneWatchLogged.store(false, std::memory_order_release);
    g_selectionStateOneWatchIgnoredWrites.store(0U, std::memory_order_release);
    g_selectionStateOneWatchArmedThreads.store(0U, std::memory_order_release);
    g_selectionStateOneWatchAddress.store(0U, std::memory_order_release);
    g_selectionStateOneWatchThreadId.store(0U, std::memory_order_release);
    g_selectionStateOneWatchValue.store(-999, std::memory_order_release);
    g_selectionStateOneWatchExceptionAddress.store(0U,
                                                     std::memory_order_release);
    g_selectionStateOneWatchContext = {};
    g_selectionRouteDestinationSlotRequestObserved.store(0U,
                                                           std::memory_order_release);
    g_selectionRouteSlotInitializeObserved.store(0U, std::memory_order_release);
    g_selectionRoutePackageRegistrationObserved.store(0U,
                                                        std::memory_order_release);
    g_selectionRouteObjectBuilderEntered.store(false, std::memory_order_release);
    g_selectionRouteObjectBuilderReturned.store(false, std::memory_order_release);
    g_selectionRouteObjectBuilderSnapshotStarted.store(false,
                                                         std::memory_order_release);
    g_selectionRouteObjectBuilderEntryStack.store(0U, std::memory_order_release);
    g_embeddedRouteIdentityProviderStrictObserved.store(0U, std::memory_order_release);
}

} // namespace dawn::client::hooks::bootflow
