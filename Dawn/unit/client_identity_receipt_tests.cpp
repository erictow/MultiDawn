#include <Windows.h>
#include <array>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <limits>

#include "state/runtime/storage/internal.h"
#include "state/activity/runtime.h"
#include "state/activity/membership/activity_membership_query.h"
#include "state/activity/membership/transactions/internal.h"
#include "state/activity/transactions/internal.h"
#include "server/bap/encrypted/activity_message/membership/activity_membership_route.h"
#include "middleware/bap/activity_message/activity_client_identity_parser.h"
#include "middleware/bap/activity_message/activity_membership_acknowledgement_parser.h"
#include "middleware/bap/activity_message/activity_state_refresh_parser.h"
#include "middleware/encoding/bit_writer.h"
#include "core/logging/log.h"

namespace dawn::state::runtime::storage {
State g_state{};
SRWLOCK g_stateLock = SRWLOCK_INIT;
}
// Only unrelated account selection/log sinks and non-identity parsers are substituted.
namespace dawn::state {
AccountState account_snapshot() noexcept { return runtime::storage::g_state.account; }
}
namespace dawn::state::account {
std::uint64_t selected_character_soid(const AccountState&) noexcept { return 0x9988; }
}
namespace dawn::state::activity {
std::uint64_t mission_run_generation() noexcept { return 1; }
}
namespace dawn::core::log {
void write(Channel, Level, std::string_view) noexcept {}
}
namespace dawn::middleware::bap::activity_message::client_authoritative_data {
bool parse_client_authoritative_data(std::span<const std::byte>, ClientAuthoritativeData&) noexcept { return false; }
}
namespace dawn::middleware::bap::activity_message::membership_acknowledgement {
bool parse_membership_acknowledgement(std::span<const std::byte>, MembershipAcknowledgement&) noexcept { return false; }
}
namespace dawn::middleware::bap::activity_message::state_refresh {
bool parse_state_refresh(std::span<const std::byte>, StateRefresh&) noexcept { return false; }
}

namespace {
namespace activity = dawn::state::activity;
namespace membership = activity::membership;
namespace storage = dawn::state::runtime::storage;
namespace route = dawn::server::bap::encrypted::activity_message::membership;
namespace service = dawn::middleware::bap::activity_message;
using membership::Identity;
using membership::PendingMutation;
constexpr activity::ActivityInstanceKey kActivity{42, {7}};
constexpr std::uint64_t kMember = 0x123456789ABCDEF0ULL;
unsigned checks{};
void check(bool value, int line) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL client identity receipt line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)
activity::SessionRecord& record() { return storage::g_state.activity.sessions[0]; }
activity::HostRegionKey region() { return {kActivity, record().lifecycle.hostRegion}; }
Identity identity() { return {kMember, -1, -1, 0x11223344, 0x5566, 0x7788, 0x99AA}; }
void reset() {
    storage::g_state = {};
    storage::g_state.account.primarySoid = 0xBEEF;
    auto& value = record();
    value.occupied = value.joined = true;
    value.sessionId = kActivity.sessionId;
    value.lifecycle = {kActivity.incarnation, {3}, false};
    value.memberKey = kMember;
    value.createdRevision = value.joinedRevision = value.recordRevision = 1;
    value.membership.region.index = 56;
}
void seed(const Identity& value) {
    PendingMutation pending{};
    CHECK(membership::prepare_identity(kActivity, value, pending));
    CHECK(pending.kind == membership::MutationKind::identity && !pending.changesReceipt);
    CHECK(membership::commit(pending));
    CHECK(record().membership.clientIdentityReceipt.revision == 0);
}
membership::ClientIdentityPublication publication() {
    membership::ClientIdentityPublication result{};
    CHECK(membership::snapshot_client_identity(kActivity, region(), result));
    CHECK(result.activity == kActivity && result.hostRegion == region());
    CHECK(result.receipt.revision != 0 && result.receipt.revision <= result.recordRevision
        && result.recordRevision <= result.stateRevision);
    return result;
}
void refuses_query(activity::ActivityInstanceKey key, activity::HostRegionKey expected) {
    membership::ClientIdentityPublication result{};
    result.receipt.raw = identity(); result.receipt.revision = 99;
    CHECK(!membership::snapshot_client_identity(key, expected, result));
    CHECK(!static_cast<bool>(result.activity) && !static_cast<bool>(result.hostRegion)
        && result.receipt.revision == 0 && result.receipt.raw == Identity{}
        && result.stateRevision == 0 && result.recordRevision == 0);
}
void receipt_without_wire_change() {
    reset(); const auto raw = identity(); seed(raw);
    refuses_query(kActivity, region());
    auto& value = record().membership;
    value.acknowledgedRevision = value.revision;
    const auto wireRevision = value.revision;
    const auto stateRevision = storage::g_state.activity.stateRevision;
    PendingMutation pending{};
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    CHECK(!pending.changesState && pending.changesReceipt && pending.hasSnapshot);
    CHECK(pending.snapshot.revision == wireRevision);
    CHECK(membership::commit(pending) && !pending.prepared);
    CHECK(value.revision == wireRevision && value.acknowledgedRevision == wireRevision);
    CHECK(storage::g_state.activity.stateRevision == stateRevision + 1
        && record().recordRevision == stateRevision + 1);
    const auto first = publication();
    CHECK(first.receipt.raw == raw && first.receipt.revision == stateRevision + 1);
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    CHECK(!pending.changesReceipt && !pending.changesState);
    CHECK(membership::commit(pending));
    CHECK(publication().receipt == first.receipt
        && storage::g_state.activity.stateRevision == stateRevision + 1);
    Identity laterSeed = raw; laterSeed.accountSoid = 0x111111;
    CHECK(membership::prepare_identity(kActivity, laterSeed, pending) && membership::commit(pending));
    CHECK(publication().receipt == first.receipt);
}
void receipt_and_wire_change() {
    reset(); const auto raw = identity();
    PendingMutation pending{};
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    CHECK(pending.changesState && pending.changesReceipt);
    CHECK(membership::commit(pending));
    CHECK(record().membership.revision == membership::kInitialRevision
        && record().membership.acknowledgedRevision == membership::kAbsentRevision);
    const auto first = publication();
    auto next = raw; next.joinIdentity++;
    CHECK(membership::prepare_client_identity(kActivity, next, next, pending));
    CHECK(pending.changesState && pending.changesReceipt && membership::commit(pending));
    CHECK(publication().receipt.revision > first.receipt.revision);
    CHECK(record().membership.revision == membership::kInitialRevision + 1);
}
void raw_zeroes_are_not_fallback() {
    reset(); auto reflected = identity(); seed(reflected);
    auto raw = reflected; raw.accountSoid = 0; raw.opaqueSoid = 0;
    PendingMutation pending{};
    CHECK(membership::prepare_client_identity(kActivity, raw, reflected, pending));
    CHECK(!pending.changesState && pending.changesReceipt && membership::commit(pending));
    CHECK(publication().receipt.raw == raw && record().membership.identity == reflected);
    const auto initialReceipt = publication().receipt;
    raw.accountSoid = reflected.accountSoid;
    CHECK(membership::prepare_client_identity(kActivity, raw, reflected, pending));
    CHECK(!pending.changesState && pending.changesReceipt && membership::commit(pending));
    CHECK(publication().receipt.raw.accountSoid == reflected.accountSoid
        && publication().receipt.raw.opaqueSoid == 0
        && publication().receipt.revision > initialReceipt.revision);
}
void invalid_inputs_and_tampering() {
    reset(); const auto raw = identity(); seed(raw);
    PendingMutation pending{};
    for (const auto bad : {-2, 1023, (std::numeric_limits<std::int32_t>::min)()}) {
        auto invalid = raw; invalid.smallOpaque = bad;
        CHECK(!membership::prepare_client_identity(kActivity, invalid, invalid, pending));
        CHECK(!pending.prepared);
    }
    auto invalid = raw; invalid.memberKey = 0;
    CHECK(!membership::prepare_client_identity(kActivity, invalid, invalid, pending));
    invalid = raw; invalid.memberKey++;
    CHECK(!membership::prepare_client_identity(kActivity, invalid, invalid, pending));
    invalid = raw; invalid.secondaryOpaque++;
    CHECK(!membership::prepare_client_identity(kActivity, raw, invalid, pending));
    invalid = raw; invalid.accountSoid++;
    CHECK(!membership::prepare_client_identity(kActivity, raw, invalid, pending));
    invalid = raw; invalid.opaqueSoid++;
    CHECK(!membership::prepare_client_identity(kActivity, raw, invalid, pending));
    const auto before = record().membership;
    for (unsigned variant = 0; variant < 7; ++variant) {
        CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
        if (variant == 0) pending.clientIdentityInput.opaqueSoid++;
        if (variant == 1) pending.clientIdentityGuard.accountSoid++;
        if (variant == 2) pending.changesReceipt = false;
        if (variant == 3) pending.changesState = true;
        if (variant == 4) pending.kind = membership::MutationKind::identity;
        if (variant == 5) pending.snapshot.identity.secondaryOpaque++;
        if (variant == 6) pending.kind = membership::MutationKind::refresh;
        CHECK(!membership::commit(pending) && !pending.prepared);
        CHECK(record().membership == before);
    }
}
void stale_lifetimes_and_retirement() {
    reset(); const auto raw = identity(); seed(raw);
    PendingMutation pending{};
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    storage::g_state.account.primarySoid++;
    CHECK(!membership::commit(pending));
    storage::g_state.account.primarySoid--;
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    ++record().lifecycle.hostRegion.value;
    CHECK(!membership::commit(pending));
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    ++record().recordRevision;
    CHECK(!membership::commit(pending));
    --record().recordRevision;
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    ++storage::g_state.activity.stateRevision;
    CHECK(!membership::commit(pending));
    record().recordRevision = storage::g_state.activity.stateRevision;
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending) && membership::commit(pending));
    const auto first = publication();
    refuses_query(kActivity, {kActivity, {first.hostRegion.generation.value - 1}});
    refuses_query({}, region());
    refuses_query(kActivity, {});
    refuses_query({kActivity.sessionId, {kActivity.incarnation.value + 1}}, region());
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    CHECK(activity::retire_session_exact(kActivity) == activity::RetireResult::retired);
    CHECK(record().membership.clientIdentityReceipt.revision == 0 && !membership::commit(pending));
    refuses_query(kActivity, first.hostRegion);
    record().occupied = record().joined = true; record().sessionId = kActivity.sessionId;
    record().lifecycle = {{kActivity.incarnation.value + 1}, {1}, false};
    record().createdRevision = record().joinedRevision = record().recordRevision = storage::g_state.activity.stateRevision;
    record().memberKey = kMember;
    refuses_query(kActivity, first.hostRegion);
    const activity::ActivityInstanceKey reused{kActivity.sessionId, record().lifecycle.incarnation};
    refuses_query(reused, {reused, record().lifecycle.hostRegion});
}
void merge_and_revision_limits() {
    reset(); const auto raw = identity(); PendingMutation pending{};
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending) && membership::commit(pending));
    const auto initial = publication().receipt;
    membership::AuthoritativeUpdate update{}; update.hasRegion = true; update.region = {64, 0xABCDEF};
    CHECK(membership::prepare_authoritative(kActivity, update, pending) && membership::commit(pending));
    CHECK(publication().receipt == initial && region().generation.value == 4);
    CHECK(publication().receipt.revision < publication().recordRevision);
    const auto merged = membership::transactions::merge(record().membership, {});
    CHECK(merged.clientIdentityReceipt == initial);
    auto tampered = merged; tampered.clientIdentityReceipt.raw.opaqueSoid++;
    CHECK(!membership::transactions::equal(tampered, merged));
    update.region.index = 72;
    CHECK(membership::prepare_authoritative(kActivity, update, pending));
    pending.regionTransition.after.clientIdentityReceipt.raw.opaqueSoid++;
    pending.regionTransitionGuard = pending.regionTransition;
    CHECK(!membership::commit(pending) && publication().receipt == initial);
    reset(); seed(raw);
    record().membership.revision = membership::kMaximumMembershipRevision;
    record().membership.acknowledgedRevision = membership::kMaximumMembershipRevision;
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending));
    CHECK(!pending.changesState && pending.changesReceipt && membership::commit(pending));
    CHECK(record().membership.revision == membership::kMaximumMembershipRevision
        && record().membership.acknowledgedRevision == membership::kMaximumMembershipRevision);
    storage::g_state.activity.stateRevision = activity::kMaximumRevision;
    record().recordRevision = activity::kMaximumRevision;
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending) && membership::commit(pending));
    auto changed = raw; changed.joinIdentity++;
    CHECK(!membership::prepare_client_identity(kActivity, changed, changed, pending));
    auto partial = raw; partial.opaqueSoid = 0;
    CHECK(!membership::prepare_client_identity(kActivity, partial, raw, pending));
}
void malformed_receipts_fail_query() {
    reset(); const auto raw = identity(); PendingMutation pending{};
    CHECK(membership::prepare_client_identity(kActivity, raw, raw, pending) && membership::commit(pending));
    const auto good = record().membership;
    for (unsigned variant = 0; variant < 8; ++variant) {
        auto& value = record().membership;
        value = good;
        if (variant == 0) value.identity.memberKey++;
        if (variant == 1) value.revision = membership::kAbsentRevision;
        if (variant == 2) value.hasIdentity = false;
        if (variant == 3) value.clientIdentityReceipt.revision = record().recordRevision + 1;
        if (variant == 4) value.clientIdentityReceipt.raw.memberKey++;
        if (variant == 5) value.clientIdentityReceipt.raw.smallOpaque = 1023;
        if (variant == 6) record().joined = false;
        if (variant == 7) record().recordRevision = storage::g_state.activity.stateRevision + 1;
        refuses_query(kActivity, region());
        record().joined = true;
        record().recordRevision = storage::g_state.activity.stateRevision;
    }
}
void actual_route_preserves_raw_values() {
    reset(); auto raw = identity(); raw.accountSoid = raw.opaqueSoid = 0;
    auto reflected = raw; reflected.accountSoid = storage::g_state.account.primarySoid; reflected.opaqueSoid = 0x9988;
    seed(reflected);
    std::array<std::byte, service::client_identity::kEncodedSize> bytes{};
    dawn::middleware::encoding::bits::Writer writer(bytes);
    for (unsigned index = 0; index < 8; ++index) CHECK(writer.write((raw.memberKey >> (8U * index)) & 0xFFU, 8));
    CHECK(writer.write(static_cast<std::uint32_t>(raw.smallOpaque) + 1U, 10));
    CHECK(writer.write(std::bit_cast<std::uint32_t>(raw.signedOpaque) + 0x80000000U, 32));
    CHECK(writer.write(raw.joinIdentity, 64) && writer.write(raw.accountSoid, 64)
        && writer.write(raw.opaqueSoid, 64) && writer.write(raw.secondaryOpaque, 64));
    CHECK(writer.write(0, 6)); std::size_t written{}; CHECK(writer.finish(written) && written == bytes.size());
    service::Request request{kActivity.sessionId, 23, 0, bytes};
    dawn::server::bap::encrypted::activity_message::ActivityPlan plan{};
    CHECK(route::prepare_identity(kActivity, request, plan));
    CHECK(plan.delivery == dawn::server::bap::encrypted::activity_message::Delivery::none
        && plan.membershipMutation.changesReceipt && !plan.membershipMutation.changesState);
    CHECK(membership::commit(plan.membershipMutation));
    CHECK(publication().receipt.raw == raw && record().membership.identity == reflected);
    request.payload = std::span(bytes).first(bytes.size() - 1);
    plan = {};
    CHECK(!route::prepare_identity(kActivity, request, plan));
    CHECK(publication().receipt.raw == raw);
}
} // namespace

int main() {
    receipt_without_wire_change(); receipt_and_wire_change(); raw_zeroes_are_not_fallback();
    invalid_inputs_and_tampering(); stale_lifetimes_and_retirement(); merge_and_revision_limits();
    malformed_receipts_fail_query();
    actual_route_preserves_raw_values();
    std::printf("PASS client identity receipts %u checks\n", checks);
}
