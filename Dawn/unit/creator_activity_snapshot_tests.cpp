#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <thread>
#include <type_traits>

#include "core/logging/log.h"
#include "middleware/bap/frame.h"
#include "server/bap/activity_retirement_test_support.h"
#include "server/bap/runtime.h"
#include "server/gameplay/group/group_host_sessions.h"
#include "server/gameplay/resolution/address_resolution_host.h"
#include "state/activity/membership/activity_membership_query.h"
#include "state/activity/runtime.h"
#include "state/matchmaking/matchmaking_state.h"
#include "state/runtime/storage/internal.h"

// The real BAP coordinator and State query/retirement are linked. Unused frame,
// resolver and derived-group services are inert; no account, game or socket opens.
namespace dawn::state::runtime::storage { State g_state{}; SRWLOCK g_stateLock = SRWLOCK_INIT; }
namespace dawn::core::log { void write(Channel, Level, std::string_view) noexcept {} }
namespace dawn::middleware::bap { bool parse_frame(std::span<const std::byte>, OuterFrame&) noexcept { return false; } }
namespace dawn::server::bap::plaintext {
bool consume(Session&, Scratch&, const middleware::bap::OuterFrame&, std::span<std::byte>, std::size_t&) noexcept { return false; }
}
namespace dawn::server::bap::encrypted {
bool consume(Session&, Scratch&, const middleware::bap::OuterFrame&, std::span<std::byte>, std::size_t&) noexcept { return false; }
bool consume_deferred(Session&, Scratch&, std::span<std::byte>, std::size_t&, bool&) noexcept { return false; }
}
namespace dawn::state::matchmaking { bool release_context(ContextHandle) noexcept { return true; } }
namespace dawn::server::gameplay::resolution { void release_owner(state::activity::AuthenticationKey) noexcept {} }
namespace dawn::server::gameplay::group {
bool acquire_host_activity_lineage(state::activity::ActivityInstanceKey, HostActivityLineageLease& output) noexcept { output = {}; return false; }
bool validate_host_activity_lineage(const HostActivityLineageLease&) noexcept { return false; }
void release_host_activity_lineage(HostActivityLineageLease& lease) noexcept { lease = {}; }
bool begin_host_session_source_retirement(state::activity::ActivityInstanceKey, std::span<state::activity::ActivityInstanceKey>, std::size_t& count) noexcept { count = 0; return true; }
void commit_host_session_derived_retirement(state::activity::ActivityInstanceKey, state::activity::ActivityInstanceKey) noexcept {}
void commit_host_session_source_retirement(state::activity::ActivityInstanceKey) noexcept {}
void finish_host_session_source_retirement(state::activity::ActivityInstanceKey) noexcept {}
}

namespace {
namespace activity = dawn::state::activity;
namespace membership = activity::membership;
namespace storage = dawn::state::runtime::storage;
namespace bap = dawn::server::bap;
namespace fixture = bap::test_support;
using Snapshot = bap::CreatorActivitySnapshot;
constexpr activity::ActivityInstanceKey kActivity{0x1234, {9}};
constexpr std::uint64_t kMember = 0x1234567887654321ULL, kJoin = 0x2345678987654321ULL;
unsigned checks{};

void check(bool passed, const char* label) {
    ++checks;
    if (!passed) { std::fprintf(stderr, "FAIL %u: %s\n", checks, label); std::exit(1); }
}

bool absent(const Snapshot& value) noexcept {
    return !static_cast<bool>(value.binding) && !static_cast<bool>(value.lineage)
        && !static_cast<bool>(value.hostRegion) && value.memberKey == 0 && value.joinIdentity == 0
        && !value.hasIdentity && !value.identityMatchesMemberKey
        && value.reportedRegion == -1 && value.destination.packageNameLength == 0;
}

activity::SessionRecord& record() noexcept { return storage::g_state.activity.sessions[0]; }

void install_state() {
    AcquireSRWLockExclusive(&storage::g_stateLock);
    storage::g_state = {};
    auto& value = record();
    value.sessionId = kActivity.sessionId; value.lifecycle = {kActivity.incarnation, {3}, false};
    value.occupied = value.joined = true; value.joinedRevision = value.recordRevision = 7;
    value.memberKey = kMember; value.membership.hasIdentity = true;
    value.membership.identity.memberKey = kMember; value.membership.identity.joinIdentity = kJoin;
    value.membership.identity.accountSoid = 0xF3F3F3F3F3F3F3F3ULL;
    value.membership.identity.opaqueSoid = 0xF4F4F4F4F4F4F4F4ULL;
    value.membership.region = {11, 0x1234}; value.destination.activityIndex = 17; value.destination.reason = 2;
    constexpr char package[] = "city_tower_social_d2";
    value.destination.packageNameLength = static_cast<std::uint8_t>(sizeof(package) - 1);
    std::memcpy(value.destination.packageName.data(), package, sizeof(package) - 1);
    // Tail and opaque bytes must never escape the public projection.
    std::fill(value.destination.packageName.begin() + sizeof(package) - 1, value.destination.packageName.end(), std::int8_t{0x6E});
    value.destination.descriptorBits.fill(std::byte{0xF5}); value.destination.descriptorBitLength = 128;
    ReleaseSRWLockExclusive(&storage::g_stateLock);
}

bool select_creator(bap::Session& session) noexcept {
    session.activity.memberKey = kMember;
    bap::publish_hud_region_locked(session, {kActivity, {3}});
    return true;
}

activity::BindingKey open_creator(std::uint32_t id = 1) {
    dawn::client::network::BapResponse response{};
    check(bap::consume({dawn::client::network::BapEvent::open, id, {}, {}}, response), "production BAP connection opens");
    check(fixture::configure_session(id, kActivity, true), "fixture authenticates an exact creator binding");
    check(fixture::with_session_locked(id, select_creator), "production publisher selects committed creator anchor");
    bap::Session session{};
    check(fixture::snapshot_session(id, session), "fixture captures the exact binding key");
    return session.activity.key;
}

void rejects(activity::BindingKey binding, const char* label) {
    Snapshot value{}; value.memberKey = kMember; value.joinIdentity = kJoin; value.reportedRegion = 8;
    check(!bap::snapshot_creator_activity(binding, value) && absent(value), label);
}

void state_queries() {
    install_state();
    membership::RegionView view{};
    check(membership::snapshot_region_view(kActivity, {kActivity, {3}}, view)
        && view.memberKey == kMember && view.joinIdentity == kJoin && view.hasIdentity
        && view.identityMatchesMemberKey && view.reportedRegion == 11, "real State query captures routing and region together");
    record().membership.hasIdentity = false;
    check(membership::snapshot_region_view(kActivity, {kActivity, {3}}, view) && !view.hasIdentity
        && !view.identityMatchesMemberKey && view.joinIdentity == 0 && view.memberKey == kMember,
        "absent identity does not leak stale stored join identity or invent provenance");
    record().membership.hasIdentity = true; record().membership.identity.memberKey = kMember + 1;
    check(membership::snapshot_region_view(kActivity, {kActivity, {3}}, view) && view.hasIdentity
        && !view.identityMatchesMemberKey, "State observation marks mismatched stored identity accurately");
    record().membership.identity.memberKey = kMember; record().membership.identity.joinIdentity = kMember;
    check(membership::snapshot_region_view(kActivity, {kActivity, {3}}, view)
        && view.joinIdentity == kMember && view.hasIdentity, "a seeded BAP join identity remains BAP data without native provenance");
    check(!membership::snapshot_region_view(kActivity, {kActivity, {4}}, view)
        && !static_cast<bool>(view.activity) && view.memberKey == 0 && !view.hasIdentity,
        "stale region generation clears the whole State observation");
    check(!membership::snapshot_region_view({kActivity.sessionId, {10}}, {{kActivity.sessionId, {10}}, {3}}, view), "reused scalar session with wrong incarnation is rejected");
    record().joined = false;
    check(!membership::snapshot_region_view(kActivity, {kActivity, {3}}, view), "unjoined State record is unavailable");
    record().joined = true; record().joinedRevision = 0;
    check(!membership::snapshot_region_view(kActivity, {kActivity, {3}}, view), "join without a committed revision is unavailable");
    record().joinedRevision = 7; record().destination.packageNameLength = 41;
    check(!membership::snapshot_region_view(kActivity, {kActivity, {3}}, view) && view.memberKey == 0, "invalid destination fails closed before public publication");
}

void bap_queries() {
    fixture::reset_storage(); install_state();
    Snapshot value{};
    check(!bap::snapshot_current_creator_activity(value) && absent(value), "no HUD creator means no implicit newest-session selection");
    const auto binding = open_creator();
    check(bap::snapshot_creator_activity(binding, value) && value.binding == binding
        && value.lineage.owns(kActivity) && value.hostRegion == activity::HostRegionKey{kActivity, {3}}
        && value.memberKey == kMember && value.joinIdentity == kJoin && value.hasIdentity
        && value.identityMatchesMemberKey && value.reportedRegion == 11, "real BAP and State path returns exact coherent creator identity and region");
    check(value.destination.activityIndex == 17 && value.destination.reason == 2
        && value.destination.packageNameLength == 20, "only public destination selectors are projected");
    check(std::all_of(value.destination.packageName.begin() + value.destination.packageNameLength,
        value.destination.packageName.end(), [](std::int8_t byte) { return byte == 0; }), "unused package bytes are cleared rather than copied from State");
    const auto bytes = std::as_bytes(std::span(&value, 1));
    for (const auto marker : {std::byte{0xF3}, std::byte{0xF4}, std::byte{0xF5}}) {
        const std::array<std::byte, 8> privateBytes{marker, marker, marker, marker, marker, marker, marker, marker};
        check(std::search(bytes.begin(), bytes.end(), privateBytes.begin(), privateBytes.end()) == bytes.end(), "account and opaque descriptor markers are absent from public output");
    }
    check(bap::snapshot_current_creator_activity(value) && value.binding == binding, "current creator API observes the same exact anchor");
    auto wrong = binding; ++wrong.generation.value; rejects(wrong, "wrong binding generation is rejected and output cleared");
    wrong = binding; ++wrong.authentication.generation.value; rejects(wrong, "wrong authentication lifetime is rejected");
    wrong = binding; ++wrong.authentication.connection.generation.value; rejects(wrong, "wrong connection lifetime is rejected");
    rejects({}, "empty requested binding is rejected");
    record().membership.hasIdentity = false;
    check(bap::snapshot_creator_activity(binding, value) && !value.hasIdentity && value.joinIdentity == 0,
        "BAP snapshot reports missing membership identity without pretending a native publication");
    record().membership.hasIdentity = true; record().membership.identity.joinIdentity = 0;
    check(bap::snapshot_creator_activity(binding, value) && value.hasIdentity && value.joinIdentity == 0,
        "present State identity with a zero join scalar stays accurate");
    record().membership.identity.memberKey = kMember + 1; rejects(binding, "mismatched State identity cannot escape as creator identity");
    record().membership.identity.memberKey = kMember; record().memberKey = kMember + 1;
    rejects(binding, "BAP and State committed machine keys must match");
    record().memberKey = 0; rejects(binding, "zero State machine key is unavailable");
    record().memberKey = kMember;
    check(fixture::with_session_locked(1, [](bap::Session& session) noexcept { session.activity.memberKey = 0; return true; }), "fixture clears BAP member under real coordinator lock");
    rejects(binding, "zero BAP machine key cannot be replaced by State's key");
    check(fixture::with_session_locked(1, select_creator), "fixture restores exact BAP member and anchor");
    record().lifecycle.hostRegion.value = 4;
    rejects(binding, "a moved State region invalidates the older committed anchor");
    record().lifecycle.hostRegion.value = 3;
    check(fixture::with_session_locked(1, [](bap::Session& session) noexcept { session.authenticated = false; return true; }), "fixture changes authentication state under real BAP lock");
    rejects(binding, "an unauthenticated session cannot publish an otherwise matching binding");
    check(fixture::with_session_locked(1, [](bap::Session& session) noexcept { session.authenticated = true; session.matchmakingRetirementPending = true; return true; }), "fixture marks retirement under real BAP lock");
    rejects(binding, "retiring BAP session is unavailable");
    // The fixture access helper deliberately refuses quarantined sessions; clear it by a fresh open.
    install_state(); const auto replacement = open_creator();
    rejects(binding, "reopening a connection retires the previous exact binding even when slot is reused");
    install_state();
    check(fixture::with_session_locked(1, select_creator), "replacement anchor uses current State region");
    check(bap::snapshot_creator_activity(replacement, value), "fresh connection generation remains observable");
    check(fixture::with_session_locked(1, [](bap::Session& session) noexcept { session.activity.ownerLease = {}; return true; }), "fixture removes creator ownership");
    rejects(replacement, "a borrowed activity cannot impersonate its creator");
    check(fixture::with_session_locked(1, [](bap::Session& session) noexcept { session.activity.ownerLease = {kActivity, bap::ActivityRecordCreator::bapService6}; session.activity.lineage.kind = bap::RegionLineageKind::groupDerivedBorrow; return true; }), "fixture changes lineage role");
    rejects(replacement, "a borrowed lineage cannot inherit creator authority");
    check(fixture::reset_authentication(1), "production authentication teardown runs");
    rejects(replacement, "authentication teardown retires the creator observation");
    bap::shutdown(); fixture::reset_storage();
}

void anchor_selection() {
    install_state();
    const auto first = open_creator();
    const activity::ActivityInstanceKey other{kActivity.sessionId + 1, {10}};
    AcquireSRWLockExclusive(&storage::g_stateLock);
    storage::g_state.activity.sessions[1] = record();
    auto& newer = storage::g_state.activity.sessions[1];
    newer.sessionId = other.sessionId; newer.lifecycle.incarnation = other.incarnation;
    newer.createdRevision = 9000; newer.memberKey = kMember + 1;
    newer.membership.identity.memberKey = newer.memberKey;
    ReleaseSRWLockExclusive(&storage::g_stateLock);
    dawn::client::network::BapResponse response{};
    check(bap::consume({dawn::client::network::BapEvent::open, 2, {}, {}}, response)
        && fixture::configure_session(2, other, true), "a newer independent creator uses another real BAP connection");
    check(fixture::with_session_locked(2, [](bap::Session& session) noexcept { session.activity.memberKey = kMember + 1; return true; }), "newer creator has its own committed machine key");
    bap::Session session{};
    check(fixture::snapshot_session(2, session), "fixture captures independent binding");
    const auto second = session.activity.key;
    rejects(second, "a newer live creator is unavailable until a committed HUD report selects it");
    Snapshot view{};
    check(bap::snapshot_current_creator_activity(view) && view.binding == first, "newest State activity never silently changes the selected creator");
    check(fixture::with_session_locked(2, [](bap::Session& current) noexcept { bap::publish_hud_region_locked(current, {current.activity.instance, {3}}); return true; }), "production publisher selects the other exact creator");
    rejects(first, "an older still-live creator cannot stand in for the current anchor");
    check(bap::snapshot_creator_activity(second, view) && view.binding == second && view.lineage.owns(other), "explicit creator switch selects exact lineage and identity");
    check(fixture::with_session_locked(1, select_creator), "explicit report restores the first creator");
    check(bap::consume({dawn::client::network::BapEvent::close, 2, {}, {}}, response), "real connection close retires the other creator lifetime");
    check(bap::snapshot_creator_activity(first, view) && view.binding == first, "unrelated creator retirement preserves selected creator");
    bap::shutdown(); fixture::reset_storage();
}

void concurrent_query() {
    install_state();
    std::atomic_bool ready{}, done{}, mismatch{};
    std::thread writer([&] {
        ready.store(true, std::memory_order_release);
        for (unsigned index = 0; index < 10000; ++index) {
            const bool second = (index & 1U) != 0;
            AcquireSRWLockExclusive(&storage::g_stateLock);
            record().membership.identity.joinIdentity = second ? kJoin + 1 : kJoin;
            record().membership.region.index = second ? 12 : 11;
            ReleaseSRWLockExclusive(&storage::g_stateLock);
        }
        done.store(true, std::memory_order_release);
    });
    while (!ready.load(std::memory_order_acquire)) SwitchToThread();
    unsigned observations = 0;
    do {
        membership::RegionView view{};
        if (!membership::snapshot_region_view(kActivity, {kActivity, {3}}, view)
            || view.memberKey != kMember || !view.identityMatchesMemberKey
            || !((view.reportedRegion == 11 && view.joinIdentity == kJoin)
                 || (view.reportedRegion == 12 && view.joinIdentity == kJoin + 1))) mismatch.store(true);
        ++observations;
    } while (!done.load(std::memory_order_acquire));
    writer.join();
    check(observations != 0 && !mismatch.load(), "real State lock keeps region and routing identity coherent during concurrent writes");
}
} // namespace

int main() {
    static_assert(std::is_trivially_copyable_v<Snapshot> && sizeof(Snapshot) < 256);
    state_queries(); bap_queries(); anchor_selection(); concurrent_query();
    std::printf("PASS %u creator snapshot checks with production BAP coordinator and State query; no game or save\n", checks);
}
