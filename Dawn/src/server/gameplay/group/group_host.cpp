#include "group_host.h"

#include <Windows.h>

#include <array>
#include <atomic>
#include <string_view>

#include "../../../core/settings/settings.h"
#include "../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../middleware/gameplay/group/member_messages.h"
#include "../../../middleware/gameplay/group/parameter_messages.h"
#include "../../../middleware/gameplay/group/parameter_registry.h"
#include "../../../middleware/gameplay/group/session_messages.h"
#include "../../../middleware/gameplay/group/session_state.h"
#include "../../../middleware/gameplay/group/view_message.h"
#include "../../../state/activity/membership/activity_membership_query.h"
#include "../../../state/activity/forced/activity_forced_destination.h"
#include "../../../state/activity/runtime.h"
#include "../../../steam/runtime/runtime.h"
#include "../dtls/dtls_host.h"
#include "../endpoint/gameplay_endpoint.h"
#include "../gameplay_log.h"
#include "../peer/peer_transport.h"
#include "group_host_sessions.h"
#include "shared_membership.h"
#include "../../../steam/runtime/social.h"

namespace dawn::server::gameplay::group {

namespace {

namespace wire = middleware::gameplay::group;
namespace bits = middleware::encoding::bits;
namespace descriptor = middleware::gameplay::descriptor;

/**
 * One reliable body staged before it is split into fragments. A method-6/7 kind-22 NetAddr uses
 * 1,083 encoded bits, so the historical 128-byte staging buffer rejected a native descriptor
 * before it reached the reliable queue.
 */
constexpr std::size_t kBodyCapacity = wire::kHostReestablishSize;
/** A membership snapshot is far larger, and the peer's reliable send queue bounds it. */
constexpr std::size_t kMembershipBodyCapacity = 512;
/** Only the low 25 bitmap bits name a registry parameter. */
constexpr std::uint64_t kParameterMaskBits = 0x1FFFFFF;
/** Room for every registry name plus its separators. */
constexpr std::size_t kParameterNameCapacity = 640;
/** Member index this host takes, and the index it nominates to succeed it. */
constexpr std::uint32_t kHostMemberIndex = 0;
/** Member index the admitted peer takes. */
constexpr std::size_t kPeerMemberIndex = 1;
/** Members one snapshot names: this host and the admitted peer. */
constexpr std::size_t kSnapshotMemberCount = 2;
/** Registry index the join-latch update names. Any of the 25 would do; none is ever filled. */
constexpr std::uint8_t kJoinLatchParameter = 0;
/** Each human retains current/target regions and may stage one replacement before eviction. */
constexpr std::size_t kAdmittedCapacity = kSharedHumanCapacity * 3;
/** Loopback address the BAP listener binds, in host order. */
constexpr std::uint32_t kLoopbackAddress = 0x7F000001;
/** Every member index the `activity-host` parameter covers. The peer needs its own bit set. */
constexpr std::uint32_t kAllMembers = 0xFFFFFFFF;
/** Shortest gap between two retries of an owed publish. */
constexpr std::uint64_t kRetryInterval = 250;
/**
 * Reproduce the baseline host-reestablish that previously let the authored manager finish mode 5.
 * All migration delays are measured from activity-host publication.
 */
constexpr std::uint64_t kInitialHostReestablishDelay = 5000;
/** Begin migration while the authored manager is stably in mode 4 and the group link is live. */
constexpr std::uint64_t kHostHandoffDelay = 15000;
/** Kind 21 follows kind 19 on the same reliable channel after a visible scheduling gap. */
constexpr std::uint64_t kHostTransitionDelay = kHostHandoffDelay + 750;
/** A second kind 19 arms member 0 after kind 21 has moved the current member to 1. */
constexpr std::uint64_t kHostReturnHandoffDelay = kHostTransitionDelay + 750;
/** Kind 22 reaches the native writer with current member 1 and pending member 0. */
constexpr std::uint64_t kHostReestablishDelay = kHostReturnHandoffDelay + 750;
/** Player slot the admitted peer's player takes. */
constexpr std::uint32_t kPeerPlayerSlot = 0;
/** Counter the first player of a session carries. The consumer's own add starts here too. */
constexpr std::uint32_t kFirstAddSequence = 0;

/** One admitted peer and the player it asked this host to add. */
struct Admitted {
    state::gameplay::Endpoint endpoint{};
    std::uint64_t joinId{};
    std::uint64_t playerId{};
    /** Group-session id the peer named in its join request, which its parameters must echo. */
    std::uint64_t sessionId{};
    /** Populated only by the authenticated shared-session boundary. */
    std::uint64_t machineId{};
    std::uint64_t initialPlayerId{};
    std::uint64_t joinOrder{};
    std::uint32_t playerAddSequence{};
    std::uint32_t sharedPlayerSlot{kInvalidSharedHumanSlot};
    bool sharedAuthorized{};
    bool membershipDirty{};
    bool occupied{};
    bool hasPlayer{};
    /** Set once the initial ready-state membership for this exact join attempt was queued. */
    bool initialMembershipPublished{};
    /** Set once the join-latch parameter update for this exact join attempt was queued. */
    bool initialParametersPublished{};
    /** Set once the peer reports its join finished, which is what promotes it to `established`. */
    bool joinComplete{};
    /** Set once a snapshot carrying that promotion is on the peer's reliable channel. */
    bool joinPublished{};
    /** Set once the `activity-host` parameter is on the peer's reliable channel. */
    bool activityHostPublished{};
    /** Tick when `activity-host` was first queued, used to delay the stable-state handoff. */
    std::uint64_t activityHostPublishedAt{};
    /** Set once the baseline kind 22 naming member 0 is on the reliable channel. */
    bool initialHostReestablishPublished{};
    /** Set once kind 19 has asked the native manager to make member 1 pending. */
    bool hostHandoffPublished{};
    /** Set once kind 21 has advanced the native host-transition exchange. */
    bool hostTransitionPublished{};
    /** Set once a second kind 19 has made member 0 pending after the transition to member 1. */
    bool hostReturnHandoffPublished{};
    /** Set once the final kind-22 host-reestablish is on the reliable channel. */
    bool hostReestablishPublished{};
    /** Number of native kind-25 peer-reestablish completions received for this session. */
    std::uint64_t peerReestablishGeneration{};
    /** Last peer-reestablish generation acknowledged by a fresh membership snapshot. */
    std::uint64_t peerReestablishMembershipGeneration{};
    /** Complete native managed-session descriptor captured from the peer's migration kind 22. */
    wire::HostReestablish migrationDescriptor{};
    bool migrationIdentityCaptured{};
    /** New group id installed by the retained migration descriptor. */
    std::uint64_t migratedSessionId{};
    /** Set once the existing activity host is republished under migratedSessionId. */
    bool migratedActivityHostPublished{};
    /** Set once a snapshot naming the peer's player is on that channel. The queue can refuse it. */
    bool playerPublished{};
    /**
     * Set after the joining peer removes the seeded platform row and until its replacement
     * player-add arrives. The removal snapshot is required to release the old row, but publishing
     * the join promotion between that snapshot and the replacement creates a second empty-player
     * snapshot. On the reliable channel that stale promotion can arrive immediately before the
     * activity-host parameter and leave state 5 with no player record to serialize.
     */
    bool playerReplacementPending{};
    /** Tick of the last retry, so a full queue is retried on a timer rather than every packet. */
    std::uint64_t lastRetry{};
    /** Order in which the peer last named this session. The lowest is the least recently used. */
    std::uint64_t lastUse{};
};

/**
 * Public group sessions the peer holds at once: one current and one target.
 * The peer resolves a session through a two-element array, so a third is one it left.
 */
constexpr std::size_t kPublicSessionCapacity = 2;

/** Revision of the last published snapshot. The consumer refuses one that does not increase. */
std::atomic<std::uint32_t> g_membershipRevision{0};
/** Stamps `Admitted::lastUse`. It only has to order the records, so it never has to be a clock. */
std::atomic<std::uint64_t> g_admitClock{0};
/** Guards the admitted table against the worker and the callback pump. */
SRWLOCK g_admittedLock{SRWLOCK_INIT};
/** Admitted peers. A join claims a slot and a leave never reclaims one in this POC. */
std::array<Admitted, kAdmittedCapacity> g_admitted{};
static_assert(sizeof(g_admitted) <= 8 * 1024, "The admitted table must remain bounded static storage.");

/** Endpoint authorization is transient; slot identity survives disconnect/rejoin. */
struct SharedGroupSlots {
    std::uint64_t sessionId{};
    SharedSlotAssignments assignments{};
};
// Bounded independently of live endpoint slots. A full table refuses a new shared
// group; reset clears these reservations together with the held host sessions.
std::array<SharedGroupSlots, kHostRecordRetirementCapacity> g_sharedGroupSlots{};

/** Reports presence without exposing security material in gameplay logs. */
template <std::size_t Size>
[[nodiscard]] bool identity_present(const std::array<std::byte, Size>& bytes) noexcept {
    for (const auto value : bytes) {
        if (value != std::byte{}) { return true; }
    }
    return false;
}

/** Member state this host publishes for every member carrying the join id. */
constexpr wire::MemberState kJoinMemberState = wire::MemberState::ready;

// Three peer checks pin this to exactly `ready`. The joining peer's entry must be at least
// `joined`, must not be `established`, and the request waits until every member carrying the
// join id reads `ready`.
static_assert(static_cast<std::uint8_t>(kJoinMemberState)
                  >= static_cast<std::uint8_t>(wire::MemberState::joined),
              "the published member state must clear the peer's own join bar");
static_assert(kJoinMemberState == wire::MemberState::ready,
              "the request advances only when every member carrying the join id reads ready");

/**
 * Sends one reliable group-session message.
 * @param sessionId Group session whose reliable channel carries it.
 * @param id Registry message id.
 * @param declaredSize Decoded structure size the registry declares.
 * @param write Callback that writes the body.
 * @return True when the message was queued.
 */
template <typename Body>
[[nodiscard]] bool send_reliable(const state::gameplay::Endpoint& to,
                                 std::uint64_t sessionId,
                                 std::uint8_t id,
                                 std::uint32_t declaredSize,
                                 Body write) noexcept {
    std::array<std::byte, kBodyCapacity> body{};
    bits::Writer writer(body);
    std::size_t size = 0;
    if (!write(writer) || !writer.finish(size)) {
        report(core::log::Level::error,
               "ev=gameplay stage=reliable_encode result=rejected session=0x%016llX id=%u "
               "declared_size=%u capacity=%llu bits_written=%llu",
               static_cast<unsigned long long>(sessionId),
               static_cast<unsigned>(id),
               declaredSize,
               static_cast<unsigned long long>(body.size()),
               static_cast<unsigned long long>(writer.bit_count()));
        return false;
    }
    const bool queued = peer::enqueue_reliable(
        to, sessionId, id, declaredSize, {body.data(), size}, writer.bit_count());
    if (!queued) {
        report(core::log::Level::debug,
               "ev=gameplay stage=reliable_enqueue result=deferred session=0x%016llX id=%u "
               "declared_size=%u body_bytes=%llu body_bits=%llu",
               static_cast<unsigned long long>(sessionId),
               static_cast<unsigned>(id),
               declaredSize,
               static_cast<unsigned long long>(size),
               static_cast<unsigned long long>(writer.bit_count()));
    }
    return queued;
}

/**
 * Finds or claims the record for one peer.
 * @param peer Peer endpoint.
 * @param sessionId Group session the record is keyed by. Zero claims nothing.
 * @return Record for that session, or null when the table is full.
 */
[[nodiscard]] Admitted* claim(const state::gameplay::Endpoint& peer,
                              std::uint64_t sessionId,
                              bool authorizing = false) noexcept {
    if (sessionId == 0) {
        return nullptr;
    }
    // Each human has its own native link, while all can name the same actual group session.
    const std::uint64_t use = g_admitClock.fetch_add(1) + 1;
    bool sharedGroup = false;
    for (const auto& slots : g_sharedGroupSlots) {
        sharedGroup = sharedGroup || slots.sessionId == sessionId;
    }
    for (const auto& entry : g_admitted) {
        sharedGroup = sharedGroup || (entry.occupied && entry.sessionId == sessionId && entry.sharedAuthorized);
    }
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId
            && entry.endpoint.address == peer.address && entry.endpoint.port == peer.port) {
            if (sharedGroup && !authorizing && !entry.sharedAuthorized) { return nullptr; }
            entry.lastUse = use;
            return &entry;
        }
    }
    if (sharedGroup && !authorizing) { return nullptr; }
    for (Admitted& entry : g_admitted) {
        if (!entry.occupied) {
            entry.occupied = true;
            entry.endpoint = peer;
            entry.sessionId = sessionId;
            entry.lastUse = use;
            return &entry;
        }
    }
    return nullptr;
}

/** The caller holds the admitted lock. Every recipient gets its own reliable publication. */
void dirty_shared_membership(std::uint64_t sessionId) noexcept {
    for (auto& entry : g_admitted) {
        if (entry.occupied && entry.sharedAuthorized && entry.sessionId == sessionId) {
            entry.membershipDirty = true;
        }
    }
}

/** Builds a shared update only from explicitly authorized humans and captured native data. */
[[nodiscard]] bool publish_shared_snapshot(const Admitted& record) noexcept {
    std::array<SharedHuman, kSharedHumanCapacity> humans{};
    std::size_t count = 0;
    const Admitted* joining = nullptr;
    for (const auto& held : g_admitted) {
        if (!held.occupied || !held.sharedAuthorized || held.sessionId != record.sessionId) { continue; }
        const auto& entry = held.endpoint.address == record.endpoint.address
            && held.endpoint.port == record.endpoint.port ? record : held;
        if (entry.joinId == 0) { continue; }
        if (count == humans.size()) { return false; }
        auto& human = humans[count++];
        human.endpoint = entry.endpoint;
        human.machineId = entry.machineId;
        human.joinId = entry.joinId;
        human.playerId = entry.playerId;
        human.addSequence = entry.playerAddSequence;
        human.slot = entry.sharedPlayerSlot;
        human.hasPlayer = entry.hasPlayer;
        human.established = entry.joinComplete;
        if (!peer::remote_address(entry.endpoint, entry.sessionId, human.address)) {
            // Never fabricate the peer's own native identity blob in the shared path.
            return false;
        }
        if (joining == nullptr || (!entry.joinComplete && joining->joinComplete)
            || (entry.joinComplete == joining->joinComplete && entry.joinOrder > joining->joinOrder)) {
            joining = &entry;
        }
    }
    if (joining == nullptr) { return false; }
    std::uint32_t slots = 0;
    for (const auto& human : std::span(humans).first(count)) {
        if (human.slot >= kSharedHumanCapacity) { return false; }
        slots |= 1U << human.slot;
    }
    if (slots != (1U << count) - 1U) {
        report(core::log::Level::debug,
            "ev=gameplay stage=shared_membership result=deferred reason=member_slot_gap session=0x%016llX",
            static_cast<unsigned long long>(record.sessionId));
        return false;
    }
    std::array<std::byte, descriptor::kNetAddrSize> hostAddress{};
    const auto host = endpoint::advertised();
    descriptor::write_net_addr(host.address, host.port, hostAddress);
    SharedMembershipSnapshot snapshot{};
    if (!build_shared_membership(record.sessionId, hostAddress, joining->joinId,
                                  g_membershipRevision.fetch_add(1) + 1,
                                  std::span(humans).first(count), snapshot)) { return false; }
    std::array<std::byte, 1024> body{};
    bits::Writer writer(body);
    std::size_t size = 0;
    const auto update = snapshot.update();
    if (!wire::write_membership_update(writer, update) || !writer.finish(size)) { return false; }
    const bool queued = peer::enqueue_reliable(record.endpoint, record.sessionId,
        static_cast<std::uint8_t>(wire::SessionMessageId::membershipUpdate),
        wire::kMembershipUpdateSize, std::span(body).first(size), writer.bit_count());
    report(queued ? core::log::Level::info : core::log::Level::debug,
        "ev=gameplay stage=shared_membership result=%s session=0x%016llX humans=%zu players=%zu revision=%u",
        queued ? "queued" : "deferred", static_cast<unsigned long long>(record.sessionId),
        count, update.players.size(), update.revision);
    return queued;
}

/**
 * Publishes one snapshot naming this host, one admitted peer, and that peer's player if it has
 * one. The caller holds the admitted lock.
 * @param record Admitted peer the snapshot names.
 * @return True when the snapshot was queued on the peer's reliable channel.
 */
[[nodiscard]] bool publish_snapshot(const Admitted& record) noexcept {
    if (record.sharedAuthorized) { return publish_shared_snapshot(record); }
    for (const auto& slots : g_sharedGroupSlots) {
        if (slots.sessionId == record.sessionId) { return false; }
    }
    for (const auto& entry : g_admitted) {
        if (entry.occupied && entry.sharedAuthorized && entry.sessionId == record.sessionId) {
            return false;
        }
    }
    const state::activity::ActivityInstanceKey activity = held_host_activity(record.sessionId);
    state::activity::ActivityInstanceKey identityActivity = activity;
    std::uint64_t peerMachineId = state::activity::membership::member_key(identityActivity);
    if (peerMachineId == 0) {
        // The target region is advertised before its activity join commits. Until then, the
        // current joined activity is the authoritative source for this same client's stable
        // machine identity; the gameplay join id is only a per-attempt correlation value.
        identityActivity = state::activity::newest_joined_activity();
        peerMachineId = state::activity::membership::member_key(identityActivity);
    }
    if (peerMachineId == 0) {
        report(core::log::Level::debug,
               "ev=gameplay stage=membership result=deferred reason=peer_identity "
               "session=0x%016llX activity=0x%016llX identity_source=0x%016llX",
               static_cast<unsigned long long>(record.sessionId),
               static_cast<unsigned long long>(activity.sessionId),
               static_cast<unsigned long long>(identityActivity.sessionId));
        return false;
    }
    const state::gameplay::Endpoint host = endpoint::advertised();
    std::array<wire::MembershipMember, kSnapshotMemberCount> members{};
    descriptor::write_net_addr(host.address, host.port, members[kHostMemberIndex].address);
    // The session id is the machine id this region's descriptor advertised, and the client joined
    // through it. The whole-process identity would name a host this session never saw.
    members[kHostMemberIndex].machineId = record.sessionId;
    // The consumer refuses a table with no entry it recognises as itself, so the peer's own blob is
    // echoed. A blob rebuilt from the endpoint it arrived from is not the same bytes.
    if (!peer::remote_address(record.endpoint, record.sessionId, members[kPeerMemberIndex].address)) {
        descriptor::write_net_addr(
            record.endpoint.address, record.endpoint.port, members[kPeerMemberIndex].address);
    }
    // The activity join identifies this same client before the gameplay channel opens. Its stable
    // member key is the machine identity; the gameplay join id is only this attempt's correlation.
    members[kPeerMemberIndex].machineId = peerMachineId;
    members[kPeerMemberIndex].joinId = record.joinId;
    // The peer ends its join request once no session holds more than one member with that id, so
    // both entries carry it. A table naming it once says the join is over.
    members[kHostMemberIndex].joinId = record.joinId;
    for (wire::MembershipMember& member : members) {
        // The connection group is what makes the consumer resolve the member's peer link. This
        // host has no value for join compatibility or the join timestamp, so both stay cleared.
        member.connectionPresent = true;
    }
    // Both entries carry the join id, so both take the same state. Once the peer reports its join
    // finished they move to `established`, which is what stops it re-sending that report.
    const wire::MemberState state =
        record.joinComplete ? wire::MemberState::established : kJoinMemberState;
    members[kHostMemberIndex].state = state;
    members[kPeerMemberIndex].state = state;

    std::array<wire::MembershipPlayer, 1> players{};
    players[0].slot = kPeerPlayerSlot;
    players[0].playerId = record.playerId;
    players[0].memberIndex = static_cast<std::uint32_t>(kPeerMemberIndex);
    players[0].addSequence = record.playerAddSequence;
    if (record.hasPlayer) {
        members[kPeerMemberIndex].ownsPlayerSlot = true;
        members[kPeerMemberIndex].playerSlot = kPeerPlayerSlot;
    }

    wire::MembershipUpdate update{};
    // The same per-region machine id the member table carries.
    update.hostMachineId = record.sessionId;
    update.revision = g_membershipRevision.fetch_add(1) + 1;
    update.hostMemberIndex = kHostMemberIndex;
    update.successionIndex = kHostMemberIndex;
    update.members = members;
    if (record.hasPlayer) {
        update.players = players;
    }

    std::array<std::byte, kMembershipBodyCapacity> body{};
    bits::Writer writer(body);
    std::size_t size = 0;
    if (!wire::write_membership_update(writer, update) || !writer.finish(size)) {
        return false;
    }
    // The peer logs the hash it wanted, so ours has to be logged next to it to read a mismatch.
    report(core::log::Level::info,
           "ev=gameplay stage=membership result=built revision=%u members=%zu players=%zu "
           "hash=0x%08X peer_machine=0x%016llX identity_source=0x%016llX "
           "player=0x%016llX player_source=%s",
           update.revision,
           update.members.size(),
           update.players.size(),
           wire::session_state_hash(update),
           static_cast<unsigned long long>(peerMachineId),
           static_cast<unsigned long long>(identityActivity.sessionId),
           static_cast<unsigned long long>(record.playerId),
           record.hasPlayer ? "steam_local" : "none");
    return peer::enqueue_reliable(
        record.endpoint, record.sessionId,
        static_cast<std::uint8_t>(wire::SessionMessageId::membershipUpdate),
        wire::kMembershipUpdateSize,
        {body.data(), size},
        writer.bit_count());
}

/**
 * Fills the `activity-host` body this host publishes.
 * The peer creates no activity client until it holds this parameter, and the public-region
 * slice-set switch waits behind that client.
 * @param body Cleared body to fill.
 * @param groupSessionId Group session whose region this parameter is published for.
 */
void fill_activity_host(wire::ActivityHostParameter& body, std::uint64_t groupSessionId) noexcept {
    // The peer's `current-activity` carries this host's empty delta, so its nonce is the
    // descriptor default and the comparand is the empty id.
    body.selectionId = 0;
    // The peer addresses its activity join request to this id, and the activity route refuses one
    // that names no committed activity session. A gameplay identity is not one.
    body.hostId = held_host_activity(groupSessionId).sessionId;
    // The peer tests only the bit for its own member index, and this host does not decode which
    // index that is, so every bit is set.
    body.memberMask = kAllMembers;
    body.address = kLoopbackAddress;
    body.port = core::settings::get().server.bapPort;
}

/**
 * Publishes the `activity-host` parameter for one group id over an admitted peer's reliable link.
 * The caller holds the admitted lock.
 * @param record Admitted peer whose reliable link carries the update.
 * @param parameterSessionId Group id whose parameter table receives the update.
 * @return True when the update was queued on the peer's reliable channel.
 */
[[nodiscard]] bool publish_activity_host_for_session(const Admitted& record,
                                                     std::uint64_t parameterSessionId) noexcept {
    if (!static_cast<bool>(held_host_activity(parameterSessionId))) {
        // Publishing a zero host id latches an unusable parameter on the peer, and the peer only
        // reads it once. The region's advertisement allocates and this retries.
        report(core::log::Level::debug, "ev=gameplay stage=activityhost result=nosession");
        return false;
    }
    wire::ParameterUpdate update{};
    update.sessionId = parameterSessionId;
    // Both go in one update, so the peer never holds the host without the activity it belongs to.
    // `current-activity` carries an empty delta, which leaves the peer's own descriptor defaults.
    update.carriedMask =
        (std::uint64_t{1} << static_cast<std::uint8_t>(wire::Parameter::activityHost))
        | (std::uint64_t{1} << static_cast<std::uint8_t>(wire::Parameter::currentActivity));
    fill_activity_host(update.activityHost, parameterSessionId);

    const bool sent = send_reliable(
        record.endpoint, record.sessionId,
        wire::kParameterUpdateId,
        wire::kParameterUpdateSize,
        [&update](bits::Writer& writer) { return wire::write_parameter_update(writer, update); });
    std::array<char, kParameterNameCapacity> names{};
    report(sent ? core::log::Level::info : core::log::Level::debug,
           "ev=gameplay stage=activityhost result=%s link=0x%016llX session=0x%016llX "
           "host=0x%llX address=0x%08X port=%u names=%s",
           sent ? "queued" : "deferred",
           static_cast<unsigned long long>(record.sessionId),
           static_cast<unsigned long long>(parameterSessionId),
           static_cast<unsigned long long>(update.activityHost.hostId),
           update.activityHost.address,
           static_cast<unsigned>(update.activityHost.port),
           wire::parameter_names(update.carriedMask, names.data(), names.size()));
    return sent;
}

/**
 * Publishes the membership refresh that completes native peer-reestablish.
 *
 * Kind 25 means the peer finished reopening its channels. The native migration ladder waits for a
 * newer membership revision after that message before it reports `membership update complete`.
 * A generation is retained until its snapshot reaches the reliable queue, so queue pressure cannot
 * silently consume the transition.
 */
[[nodiscard]] bool publish_peer_reestablish_membership(Admitted& record) noexcept {
    if (record.peerReestablishMembershipGeneration >= record.peerReestablishGeneration) {
        return true;
    }
    const std::uint64_t generation = record.peerReestablishGeneration;
    const bool queued = publish_snapshot(record);
    if (queued) {
        record.peerReestablishMembershipGeneration = generation;
    }
    report(queued ? core::log::Level::info : core::log::Level::debug,
           "ev=gameplay stage=peer_reestablish result=%s session=0x%016llX "
           "generation=%llu membership_generation=%llu",
           queued ? "membership_queued" : "membership_deferred",
           static_cast<unsigned long long>(record.sessionId),
           static_cast<unsigned long long>(generation),
           static_cast<unsigned long long>(record.peerReestablishMembershipGeneration));
    return queued;
}

/** Resolves the exact machine identity and NetAddr already published for member 1. */
[[nodiscard]] bool resolve_peer_member(const Admitted& record,
                                       std::uint64_t& machineId,
                                       std::uint64_t& identitySource,
                                       std::array<std::byte, descriptor::kNetAddrSize>& address)
    noexcept {
    state::activity::ActivityInstanceKey identityActivity =
        held_host_activity(record.sessionId);
    machineId = state::activity::membership::member_key(identityActivity);
    if (record.sharedAuthorized) {
        machineId = record.machineId;
    }
    if (machineId == 0) {
        identityActivity = state::activity::newest_joined_activity();
        machineId = state::activity::membership::member_key(identityActivity);
    }
    identitySource = identityActivity.sessionId;
    if (machineId == 0) {
        return false;
    }
    if (!peer::remote_address(record.endpoint, record.sessionId, address)) {
        descriptor::write_net_addr(record.endpoint.address, record.endpoint.port, address);
    }
    return true;
}

/** Resolves the exact machine identity and NetAddr already published for member 0. */
void resolve_host_member(const Admitted& record,
                         std::uint64_t& machineId,
                         std::uint64_t& identitySource,
                         std::array<std::byte, descriptor::kNetAddrSize>& address) noexcept {
    const state::gameplay::Endpoint host = endpoint::advertised();
    identitySource = record.sessionId;
    machineId = record.sessionId;
    descriptor::write_net_addr(host.address, host.port, address);
}

/** Publishes kind 19, the sole native message that can arm manager+0xE938. */
[[nodiscard]] bool publish_host_handoff(const Admitted& record,
                                        std::uint32_t targetMember,
                                        std::string_view phase) noexcept {
    wire::HostHandoff body{};
    body.sessionId = record.sessionId;
    body.memberIndex = targetMember;
    std::uint64_t targetMachineId = 0;
    std::uint64_t identitySource = 0;
    if (targetMember == kHostMemberIndex) {
        resolve_host_member(record, targetMachineId, identitySource, body.address);
    }
    else if (targetMember == static_cast<std::uint32_t>(kPeerMemberIndex)) {
        if (!resolve_peer_member(record, targetMachineId, identitySource, body.address)) {
            report(core::log::Level::debug,
                   "ev=gameplay stage=host_handoff phase=%.*s result=deferred "
                   "reason=peer_identity session=0x%016llX target_member=%u",
                   static_cast<int>(phase.size()),
                   phase.data(),
                   static_cast<unsigned long long>(record.sessionId),
                   static_cast<unsigned>(body.memberIndex));
            return false;
        }
    }
    else {
        report(core::log::Level::debug,
               "ev=gameplay stage=host_handoff phase=%.*s result=rejected "
               "reason=member_index session=0x%016llX target_member=%u",
               static_cast<int>(phase.size()),
               phase.data(),
               static_cast<unsigned long long>(record.sessionId),
               static_cast<unsigned>(body.memberIndex));
        return false;
    }

    const bool sent = send_reliable(
        record.endpoint, record.sessionId,
        static_cast<std::uint8_t>(wire::SessionMessageId::hostHandoff),
        wire::kHostHandoffSize,
        [&body](bits::Writer& writer) noexcept { return wire::write_host_handoff(writer, body); });
    report(sent ? core::log::Level::info : core::log::Level::debug,
           "ev=gameplay stage=host_handoff phase=%.*s result=%s session=0x%016llX "
           "target_member=%u target_machine=0x%016llX identity_source=0x%016llX decoded_size=%u",
           static_cast<int>(phase.size()),
           phase.data(),
           sent ? "queued" : "deferred",
           static_cast<unsigned long long>(body.sessionId),
           static_cast<unsigned>(body.memberIndex),
           static_cast<unsigned long long>(targetMachineId),
           static_cast<unsigned long long>(identitySource),
           wire::kHostHandoffSize);
    return sent;
}

/** Publishes the activity host under the admitted group's original id. */
[[nodiscard]] bool publish_activity_host(const Admitted& record) noexcept {
    return publish_activity_host_for_session(record, record.sessionId);
}

/** Publishes the native fixed-shape kind-21 transition message. */
[[nodiscard]] bool publish_host_transition(const Admitted& record) noexcept {
    wire::HostTransition body{};
    body.sessionId = record.sessionId;
    const bool sent = send_reliable(
        record.endpoint, record.sessionId,
        static_cast<std::uint8_t>(wire::SessionMessageId::hostTransition),
        wire::kHostTransitionSize,
        [&body](bits::Writer& writer) noexcept {
            return wire::write_host_transition(writer, body);
        });
    report(sent ? core::log::Level::info : core::log::Level::debug,
           "ev=gameplay stage=host_transition result=%s session=0x%016llX count=%u value=0x%08X "
           "decoded_size=%u",
           sent ? "queued" : "deferred",
           static_cast<unsigned long long>(body.sessionId),
           body.count,
           body.value,
           wire::kHostTransitionSize);
    return sent;
}

/**
 * Publishes kind 22 from the session host. The manager resolves this packet to member record 0;
 * machineId is not the record selector.
 *
 * The baseline has no migration descriptor yet. For the activation packet, preserve the opaque
 * identity blocks from the peer's native host-migration writer: the manager's activation writer
 * requires them. Its machine id must also remain distinct from the current session's security id.
 * The managed-session migration registers that id with the captured key, while cleanup removes
 * the old session's key. Reusing the old id makes that cleanup remove the new session's key too.
 * Only replace the captured method-6/7 address with the admitted host's direct address.
 */
[[nodiscard]] bool publish_host_reestablish(const Admitted& record,
                                            std::string_view phase) noexcept {
    const bool descriptorRetained = phase == "activate" && record.migrationIdentityCaptured;
    wire::HostReestablish body{};
    std::uint64_t identitySource = 0;
    if (descriptorRetained) {
        body = record.migrationDescriptor;
        // The group id remains authoritative, but the migration security id and key stay paired.
        // Point that new identity at the local activity host without reusing the old security id.
        body.sessionId = record.sessionId;
        identitySource = record.migrationDescriptor.machineId;
        const state::gameplay::Endpoint host = endpoint::advertised();
        descriptor::write_net_addr(host.address, host.port, body.address);
    }
    else {
        body.sessionId = record.sessionId;
        resolve_host_member(record, body.machineId, identitySource, body.address);
    }

    const bool sent = send_reliable(
        record.endpoint, record.sessionId,
        static_cast<std::uint8_t>(wire::SessionMessageId::hostReestablish),
        wire::kHostReestablishSize,
        [&body](bits::Writer& writer) noexcept {
            return wire::write_host_reestablish(writer, body);
        });
    if (sent && descriptorRetained) {
        // Registration is safe before delivery because it does not change outbound routing. It
        // lets the peer's speculative migration handshake derive with the same key kind 22 carries.
        dtls::register_security_key(record.endpoint, body.machineId, body.identity128);
    }
    report(sent ? core::log::Level::info : core::log::Level::debug,
           "ev=gameplay stage=host_reestablish phase=%.*s result=%s session=0x%016llX "
           "machine=0x%016llX target_member=%u identity_source=0x%016llX decoded_size=%u "
           "descriptor=%s address_method=%u captured_machine=0x%016llX",
           static_cast<int>(phase.size()),
           phase.data(),
           sent ? "queued" : "deferred",
           static_cast<unsigned long long>(body.sessionId),
           static_cast<unsigned long long>(body.machineId),
           static_cast<unsigned>(kHostMemberIndex),
           static_cast<unsigned long long>(identitySource),
           wire::kHostReestablishSize,
           descriptorRetained ? "retained_identity_direct_address" : "emulated_host",
           static_cast<unsigned>(body.address[descriptor::kNetAddrSize - 1]),
           static_cast<unsigned long long>(descriptorRetained
                                               ? record.migrationDescriptor.machineId
                                               : 0));
    return sent;
}

/**
 * Answers one view establishment by binding and echoing the peer's own signature.
 * What a host's own view should hold is unknown. Echoing is the only answer that cannot produce
 * a signature mismatch.
 * @param sessionId Group session the link carries.
 * @param view Decoded view body.
 */
void bind_view(const state::gameplay::Endpoint& from,
               std::uint64_t sessionId, const wire::ViewEstablishment& view) noexcept {
    state::gameplay::ViewSignature signature{};
    signature.token = view.sessionToken;
    signature.kind = view.kind;
    signature.listCount = view.listCount;
    signature.hasList = view.hasList;
    signature.list = view.list;
    signature.bound = true;
    const bool sent = send_reliable(
        from, sessionId,
        wire::kViewMessageId,
        wire::kViewMessageSize,
        [&view](bits::Writer& writer) noexcept { return wire::write_view(writer, view); });
    if (sent) { peer::bind_view(from, sessionId, signature); }
    report(sent ? core::log::Level::info : core::log::Level::warn,
           "ev=gameplay stage=view result=%s kind=%u token=0x%llX list=%u "
           "group=0x%016llX endpoint=0x%08X:%u reason=%s",
           sent ? "bound" : "fail",
           static_cast<unsigned>(view.kind),
           static_cast<unsigned long long>(view.sessionToken),
           static_cast<unsigned>(view.listCount),
           static_cast<unsigned long long>(sessionId), from.address, static_cast<unsigned>(from.port),
           sent ? "echo_queued" : sessionId == 0 ? "unresolved_group" : "enqueue_refused");
}

/**
 * Answers one parameter request with the parameters this host can encode.
 * An empty answer leaves the peer waiting, so the answer carries every requested parameter that
 * has an encoder and names the rest as unheld.
 * @param sessionId Session the request named, which is also the link it goes back on.
 * @param requested Requested parameter mask, already reduced to its meaningful bits.
 */
void answer_parameters(const state::gameplay::Endpoint& from,
                       std::uint64_t sessionId, std::uint64_t requested) noexcept {
    std::uint64_t carried = requested & wire::kEncodableParameters;
    const std::uint64_t activityHostBit =
        std::uint64_t{1} << static_cast<std::uint8_t>(wire::Parameter::activityHost);
    // The BAP advertisement coordinator is the only caller that owns an exact creator-root
    // lineage, so it is also the only path allowed to provision this row. A parameter request may
    // publish an already-provisioned exact host, but must never guess a source from global State.
    // The peer retries the parameter after the coordinator's service slice fills the row.
    if ((carried & activityHostBit) != 0
        && held_host_session(sessionId) == state::activity::kAbsentSessionId) {
        // See publish_activity_host: a zero host id is worse than no answer for this one.
        carried &= ~activityHostBit;
    }
    if (carried == 0) {
        report(core::log::Level::debug,
               "ev=gameplay stage=parameters result=unheld mask=0x%08X",
               static_cast<unsigned>(requested));
        return;
    }

    wire::ParameterUpdate update{};
    update.sessionId = sessionId;
    update.carriedMask = carried;
    // A zero host id latches an unusable parameter on the peer, so the answer carries the same
    // body the unsolicited publish does.
    fill_activity_host(update.activityHost, sessionId);

    const bool sent = send_reliable(
        from, sessionId,
        wire::kParameterUpdateId,
        wire::kParameterUpdateSize,
        [&update](bits::Writer& writer) { return wire::write_parameter_update(writer, update); });
    std::array<char, kParameterNameCapacity> names{};
    report(sent ? core::log::Level::info : core::log::Level::warn,
           "ev=gameplay stage=parameters result=%s carried=0x%08X names=%s",
           sent ? "answered" : "fail",
           static_cast<unsigned>(carried),
           wire::parameter_names(carried, names.data(), names.size()));
}

/**
 * Answers one time-synchronize probe with the same form it arrived in.
 * @param from Peer endpoint.
 * @param probe Decoded probe.
 */
void answer_time(const state::gameplay::Endpoint& from,
                 const wire::TimeSynchronize& probe) noexcept {
    // The exchange must never block the event loop, so the samples are echoed unchanged.
    if (!peer::send_out_of_band(from,
                                static_cast<std::uint8_t>(wire::SessionMessageId::timeSynchronize),
                                wire::kTimeSynchronizeSize,
                                [&probe](bits::Writer& writer) noexcept {
                                    return wire::write_time_synchronize(writer, probe);
                                })) {
        report(core::log::Level::debug, "ev=gameplay stage=time result=fail");
    }
}

/**
 * Drops one session's link and its admitted record together.
 * A leave names one region's session, and the client's other region must keep its own link.
 * @param sessionId Session the peer is leaving.
 */
void release(const state::gameplay::Endpoint& from, std::uint64_t sessionId) noexcept {
    peer::drop(from, sessionId);
    // The region's activity host stays. A leave is also how the peer fast travels to the region it
    // is already in, and a fresh id there is `public_activity_host_mismatch`.
    AcquireSRWLockExclusive(&g_admittedLock);
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId
            && entry.endpoint.address == from.address && entry.endpoint.port == from.port) {
            entry = {};
        }
    }
    dirty_shared_membership(sessionId);
    ReleaseSRWLockExclusive(&g_admittedLock);
}

} // namespace

/** Frees every admitted record at one endpoint. */
void release_endpoint(const state::gameplay::Endpoint& endpoint) noexcept {
    std::size_t count = 0;
    AcquireSRWLockExclusive(&g_admittedLock);
    for (Admitted& entry : g_admitted) {
        if (entry.occupied && entry.endpoint.address == endpoint.address
            && entry.endpoint.port == endpoint.port) {
            const auto sharedSession = entry.sharedAuthorized ? entry.sessionId : 0;
            ++count;
            entry = {};
            if (sharedSession != 0) { dirty_shared_membership(sharedSession); }
        }
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    if (count != 0) {
        report(core::log::Level::info,
               "ev=gameplay stage=admitted result=dropped endpoint=0x%08X:%u sessions=%zu",
               endpoint.address,
               static_cast<unsigned>(endpoint.port),
               count);
    }
}

/** Consumes one group-session message. */
bool consume(const state::gameplay::Endpoint& from,
             std::uint64_t sessionId,
             std::uint8_t id,
             bits::Reader& reader,
             std::uint64_t now) noexcept {
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::timeSynchronize)) {
        wire::TimeSynchronize probe{};
        if (!wire::read_time_synchronize(reader, probe)) {
            return false;
        }
        answer_time(from, probe);
        return true;
    }
    if (id == wire::kViewMessageId) {
        wire::ViewEstablishment view{};
        if (!wire::read_view(reader, view)) {
            return false;
        }
        bind_view(from, sessionId, view);
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::leaveSession)) {
        std::uint64_t leaving = 0;
        if (!wire::read_session_only(reader, leaving)) {
            return false;
        }
        const bool sent = peer::send_out_of_band(
            from,
            static_cast<std::uint8_t>(wire::SessionMessageId::leaveAcknowledge),
            wire::kLeaveAcknowledgeSize,
            [leaving](bits::Writer& writer) noexcept {
                return wire::write_session_only(writer, leaving);
            });
        report(core::log::Level::info,
               "ev=gameplay stage=leave result=%s session=0x%016llX",
               sent ? "acknowledged" : "fail",
               static_cast<unsigned long long>(leaving));
        release(from, leaving);
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::peerEstablish)) {
        std::uint64_t established = 0;
        if (!wire::read_session_only(reader, established)) {
            return false;
        }
        report(core::log::Level::info,
               "ev=gameplay stage=establish result=ok session=0x%016llX",
               static_cast<unsigned long long>(established));
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::peerReestablish)) {
        std::uint64_t reestablished = 0;
        if (!wire::read_session_only(reader, reestablished)) {
            return false;
        }
        AcquireSRWLockExclusive(&g_admittedLock);
        Admitted* record = nullptr;
        bool migrationAlias = false;
        for (Admitted& candidate : g_admitted) {
            if (!candidate.occupied || candidate.endpoint.address != from.address
                || candidate.endpoint.port != from.port) {
                continue;
            }
            const bool direct = candidate.sessionId == reestablished;
            const bool retainedMigrationAlias =
                candidate.migrationIdentityCaptured
                && candidate.migrationDescriptor.sessionId == candidate.sessionId
                && candidate.migrationDescriptor.machineId == reestablished;
            if (!direct && !retainedMigrationAlias) {
                continue;
            }
            record = &candidate;
            migrationAlias = retainedMigrationAlias;
            break;
        }
        bool queued = false;
        bool openingHostReadyChanged = false;
        bool migratedActivityHostQueued = false;
        std::uint64_t migratedActivityHost = state::activity::kAbsentSessionId;
        std::uint64_t generation = 0;
        if (record != nullptr) {
            report(core::log::Level::info,
                   "ev=gameplay stage=peer_reestablish result=resolved "
                   "body_session=0x%016llX link_session=0x%016llX "
                   "membership_session=0x%016llX source=%s",
                   static_cast<unsigned long long>(reestablished),
                   static_cast<unsigned long long>(sessionId),
                   static_cast<unsigned long long>(record->sessionId),
                   migrationAlias ? "migration_machine" : "session");
            // The migration alias is the peer's acknowledgement that it consumed the final
            // kind-22 descriptor. Only now is its distinct security id/key installed and safe for
            // the membership response and all later channel traffic.
            if (migrationAlias) {
                dtls::prefer_security_id(from, record->migrationDescriptor.machineId);
                migratedActivityHost =
                    alias_host_session(record->sessionId, reestablished);
                record->migratedSessionId = reestablished;
                record->migratedActivityHostPublished = false;
            }
            ++record->peerReestablishGeneration;
            generation = record->peerReestablishGeneration;
            queued = publish_peer_reestablish_membership(*record);
            if (migrationAlias
                && migratedActivityHost != state::activity::kAbsentSessionId) {
                migratedActivityHostQueued =
                    publish_activity_host_for_session(*record, reestablished);
                record->migratedActivityHostPublished = migratedActivityHostQueued;
            }
            if (migrationAlias
                && state::activity::forced::mission_host_reestablishment_enabled()) {
                // The alias is the acknowledgement of the retained final kind-22 descriptor,
                // not the earlier baseline host message. It is therefore the first safe point at
                // which a host-owned mission-director transition can be published.
                openingHostReadyChanged =
                    state::activity::forced::mark_opening_host_ready();
            }
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        if (migrationAlias) {
            report(migratedActivityHostQueued ? core::log::Level::info
                                              : core::log::Level::warn,
                   "ev=gameplay stage=activityhost_alias result=%s source=0x%016llX "
                   "migrated=0x%016llX host=0x%016llX",
                   migratedActivityHostQueued
                       ? "published"
                       : migratedActivityHost == state::activity::kAbsentSessionId
                             ? "missing_source"
                             : "retry_armed",
                   static_cast<unsigned long long>(record != nullptr ? record->sessionId : 0),
                   static_cast<unsigned long long>(reestablished),
                   static_cast<unsigned long long>(migratedActivityHost));
        }
        if (record == nullptr) {
            report(core::log::Level::warn,
                   "ev=gameplay stage=peer_reestablish result=missing_session "
                   "session=0x%016llX link_session=0x%016llX endpoint=0x%08X:%u",
                   static_cast<unsigned long long>(reestablished),
                   static_cast<unsigned long long>(sessionId),
                   from.address,
                   static_cast<unsigned>(from.port));
        }
        else if (!queued) {
            report(core::log::Level::debug,
                   "ev=gameplay stage=peer_reestablish result=retry_armed "
                   "session=0x%016llX generation=%llu",
                   static_cast<unsigned long long>(reestablished),
                   static_cast<unsigned long long>(generation));
        }
        if (openingHostReadyChanged) {
            state::activity::forced::ForcedDestination destination{};
            state::activity::forced::snapshot(destination);
            const std::size_t packageLength =
                destination.packageNameLength <= destination.packageName.size()
                    ? destination.packageNameLength
                    : destination.packageName.size();
            report(core::log::Level::info,
                   "ev=gameplay stage=opening_host_ready result=latched "
                   "session=0x%016llX package=%.*s "
                   "trigger=peer_reestablish_migration_alias",
                   static_cast<unsigned long long>(reestablished),
                   static_cast<int>(packageLength),
                   destination.packageName.data());
        }
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::hostReestablish)) {
        wire::HostReestablish body{};
        if (!wire::read_host_reestablish(reader, body)) {
            return false;
        }
        bool identityNonzero = false;
        for (const std::byte value : body.identity128) {
            identityNonzero = identityNonzero || value != std::byte{};
        }
        for (const std::byte value : body.identity144) {
            identityNonzero = identityNonzero || value != std::byte{};
        }
        AcquireSRWLockExclusive(&g_admittedLock);
        Admitted* const record = claim(from, body.sessionId);
        const bool retained = record != nullptr && identityNonzero;
        if (retained) {
            record->migrationDescriptor = body;
            record->migrationIdentityCaptured = true;
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        report(core::log::Level::info,
               "ev=gameplay stage=host_reestablish_capture result=%s session=0x%016llX "
               "machine=0x%016llX identity_nonzero=%u "
               "identity128_present=%u identity144_present=%u "
               "address_method=%u",
               retained ? "retained" : record == nullptr ? "missing_session" : "empty_identity",
               static_cast<unsigned long long>(body.sessionId),
               static_cast<unsigned long long>(body.machineId),
               static_cast<unsigned>(identityNonzero ? 1U : 0U),
               static_cast<unsigned>(identity_present(body.identity128)),
               static_cast<unsigned>(identity_present(body.identity144)),
               static_cast<unsigned>(body.address[descriptor::kNetAddrSize - 1]));
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::joinComplete)) {
        wire::JoinComplete body{};
        if (!wire::read_join_complete(reader, body)) {
            return false;
        }
        // The peer repeats this until its membership shows every member of the join at
        // `established`, so the answer is a snapshot that promotes them. Keyed by the body's
        // session, not the link's: one link carries every region the client joined over it.
        AcquireSRWLockExclusive(&g_admittedLock);
        Admitted* const record = claim(from, body.sessionId);
        bool queued = false;
        const bool owed = record != nullptr && !record->joinPublished;
        if (record != nullptr) {
            if (record->sharedAuthorized && record->machineId != body.machineId) {
                ReleaseSRWLockExclusive(&g_admittedLock);
                report(core::log::Level::warn,
                    "ev=gameplay stage=shared_membership result=rejected reason=machine_identity");
                return true;
            }
            record->joinComplete = true;
            if (record->sharedAuthorized) { dirty_shared_membership(record->sessionId); }
            // A pre-establishment player remove is the first half of the managed-session handoff
            // from the seeded platform row to the player's native id. The peer must first receive
            // that removal before it sends player-add. Hold the promotion until that add arrives,
            // so one snapshot can carry both `established` and the replacement player.
            if (owed && !record->playerReplacementPending) {
                queued = publish_snapshot(*record);
                record->joinPublished = queued;
            }
            // The peer only reads the parameter once its join is finished, and the queue is at its
            // fullest right here, so a refusal is expected and the service slice retries it.
            if (record->joinPublished && !record->activityHostPublished) {
                record->activityHostPublished = publish_activity_host(*record);
                if (record->activityHostPublished) {
                    record->activityHostPublishedAt = now;
                }
                record->lastRetry = now;
            }
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        report(queued ? core::log::Level::info : core::log::Level::debug,
               "ev=gameplay stage=join result=%s session=0x%llX machine=0x%llX update=%u",
               queued              ? "completed"
               : record == nullptr ? "fail"
               : owed              ? "deferred"
                                   : "repeat",
               static_cast<unsigned long long>(body.sessionId),
               static_cast<unsigned long long>(body.machineId),
               body.joinSequence);
        return true;
    }
    if (id == static_cast<std::uint8_t>(wire::SessionMessageId::joinAbort)) {
        wire::SessionNotice notice{};
        if (!wire::read_join_abort(reader, notice)) {
            return false;
        }
        report(core::log::Level::info,
               "ev=gameplay stage=join result=abort session=0x%016llX",
               static_cast<unsigned long long>(notice.sessionId));
        release(from, notice.sessionId);
        return true;
    }
    if (id == wire::kParameterRequestId) {
        wire::ParameterRequestHeader header{};
        if (!wire::read_parameter_request(reader, header)) {
            return false;
        }
        // The selected bodies after the header have per-parameter codecs this host does not
        // write, so their widths are unknown and this container cannot be walked further.
        const std::uint64_t mask = header.requestedMask & kParameterMaskBits;
        std::array<char, kParameterNameCapacity> names{};
        report(core::log::Level::info,
               "ev=gameplay stage=parameters result=request mask=0x%08X mode=%u names=%s",
               static_cast<unsigned>(mask),
               static_cast<unsigned>(header.modeFlag ? 1U : 0U),
               wire::parameter_names(mask, names.data(), names.size()));
        answer_parameters(from, header.sessionId, mask);
        return false;
    }
    if (id == wire::kPeerPropertiesId) {
        wire::PeerPropertiesHeader header{};
        if (!wire::read_peer_properties_header(reader, header)) {
            return false;
        }
        // The 304-byte property block behind the address is not decoded, so the body is
        // reported and not consumed.
        report(core::log::Level::info,
               "ev=gameplay stage=properties result=read session=0x%llX method=%u",
               static_cast<unsigned long long>(header.sessionId),
               static_cast<unsigned>(header.addressMethod));
        return false;
    }
    if (id == wire::kPlayerAddId) {
        wire::PlayerAddRequest request{};
        if (!wire::read_player_add(reader, request)) {
            return false;
        }
        // The published row carries the identity group only. The profile block behind it has no
        // encoder here, and the peer's clear-flag arm accepts a row without one.
        AcquireSRWLockExclusive(&g_admittedLock);
        // The body's session, for the same reason join-complete uses its own.
        Admitted* const record = claim(from, request.sessionId);
        bool published = false;
        bool held = false;
        if (record != nullptr) {
            bool duplicateIdentity = request.playerId == 0;
            if (record->sharedAuthorized) {
                for (const auto& other : g_admitted) {
                    if (&other != record && other.occupied && other.sharedAuthorized
                        && other.sessionId == record->sessionId && other.hasPlayer
                        && other.playerId == request.playerId) { duplicateIdentity = true; }
                }
            }
            if (duplicateIdentity) {
                ReleaseSRWLockExclusive(&g_admittedLock);
                report(core::log::Level::warn,
                    "ev=gameplay stage=player result=rejected reason=duplicate_or_empty_identity");
                return false;
            }
            const bool samePlayer = record->hasPlayer && record->playerId == request.playerId
                && record->playerAddSequence == request.sequence;
            held = samePlayer && record->playerPublished;
            if (!held) {
                record->hasPlayer = true;
                record->playerId = request.playerId;
                record->playerAddSequence = request.sequence;
                record->playerReplacementPending = false;
                if (record->sharedAuthorized) { dirty_shared_membership(record->sessionId); }
                published = publish_snapshot(*record);
                // The queue is at its fullest here, right after the join promotion, so a refusal
                // is ordinary and the service slice retries it. A duplicate request must not
                // clear a previously successful publish or enqueue another full snapshot.
                record->playerPublished = published;
                // When join-complete arrived between the remove and add, this same snapshot is
                // also the withheld promotion. Mark it once rather than queueing another full
                // membership body behind the replacement.
                if (published && record->joinComplete) {
                    record->joinPublished = true;
                }
            }
        }
        ReleaseSRWLockExclusive(&g_admittedLock);
        // The player block and its tail are not decoded, so the body is reported and not consumed.
        report(published ? core::log::Level::info : core::log::Level::debug,
               "ev=gameplay stage=player result=%s session=0x%llX player=0x%llX seq=%u kind=%u",
               published          ? "added"
               : held             ? "held"
               : record == nullptr ? "missing_session"
                                   : "deferred",
               static_cast<unsigned long long>(request.sessionId),
               static_cast<unsigned long long>(request.playerId),
               request.sequence,
               static_cast<unsigned>(request.kind));
        return false;
    }
    if (id == wire::kPlayerRemoveId) {
        wire::PlayerRemoveRequest request{};
        if (!wire::read_player_remove(reader, request)) {
            return false;
        }

        AcquireSRWLockExclusive(&g_admittedLock);
        Admitted* const record = claim(from, request.sessionId);
        bool published = false;
        bool held = false;
        // This request indexes the sender's LOCAL-player array, not the global
        // membership player table. Each human owns local index 0 even when its
        // stable global player slot is 1.
        const bool supported = request.playerIndex == kPeerPlayerSlot;
        if (record != nullptr && supported) {
            held = !record->hasPlayer;
            if (!held) {
                // Commit the removal only after its authoritative snapshot is on the reliable
                // queue. If the queue is full, the unchanged row makes the client's repeated
                // request a safe retry instead of leaving host state ahead of the peer.
                Admitted candidate = *record;
                candidate.hasPlayer = false;
                candidate.playerId = 0;
                candidate.playerPublished = false;
                published = publish_snapshot(candidate);
                if (published) {
                    record->hasPlayer = false;
                    record->playerId = 0;
                    record->playerPublished = false;
                    // During the join the client immediately replaces the seeded platform row.
                    // Outside that handoff, a removal is final and needs no withheld promotion.
                    record->playerReplacementPending = !record->joinComplete;
                    if (record->sharedAuthorized) { dirty_shared_membership(record->sessionId); }
                }
            }
        }
        ReleaseSRWLockExclusive(&g_admittedLock);

        report(published ? core::log::Level::info : core::log::Level::debug,
               "ev=gameplay stage=player_remove result=%s session=0x%016llX index=%u",
               published          ? "removed"
               : held             ? "held"
               : record == nullptr ? "missing_session"
               : !supported       ? "unsupported_index"
                                  : "deferred",
               static_cast<unsigned long long>(request.sessionId),
               static_cast<unsigned>(request.playerIndex));
        return true;
    }
    return false;
}

/** Publishes the membership snapshot that completes one peer's join. */
bool publish_membership(const state::gameplay::Endpoint& peer,
                        std::uint64_t peerJoinId,
                        std::uint64_t sessionId) noexcept {
    AcquireSRWLockExclusive(&g_admittedLock);
    Admitted* const record = claim(peer, sessionId);
    bool published = false;
    bool held = false;
    if (record != nullptr) {
        const bool newAttempt = record->joinId != peerJoinId;
        if (newAttempt) {
            // The join body carries address and player tables after the admission prefix. That
            // tail is not decoded yet, but this host has exactly one local user, so its Steam
            // identity is a stable seed. The Client replaces it with the native player id from
            // its managed-session player-add after first asking us to remove this row. The initial
            // snapshot must still name a player: that remove/add handoff starts only after the
            // peer has accepted membership.
            record->joinId = peerJoinId;
            record->joinOrder = g_admitClock.fetch_add(1) + 1;
            record->sessionId = sessionId;
            record->playerId = record->sharedAuthorized ? record->initialPlayerId : steam::social::local_steam_id();
            record->playerAddSequence = kFirstAddSequence;
            record->hasPlayer = record->playerId != 0;
            record->initialMembershipPublished = false;
            record->initialParametersPublished = false;
            record->joinComplete = false;
            record->joinPublished = false;
            record->activityHostPublished = false;
            record->activityHostPublishedAt = 0;
            record->initialHostReestablishPublished = false;
            record->hostHandoffPublished = false;
            record->hostTransitionPublished = false;
            record->hostReturnHandoffPublished = false;
            record->hostReestablishPublished = false;
            record->peerReestablishGeneration = 0;
            record->peerReestablishMembershipGeneration = 0;
            record->migrationDescriptor = {};
            record->migrationIdentityCaptured = false;
            record->migratedSessionId = 0;
            record->migratedActivityHostPublished = false;
            record->playerPublished = false;
            record->playerReplacementPending = false;
            record->lastRetry = 0;
            if (record->sharedAuthorized) { dirty_shared_membership(record->sessionId); }
        }
        held = record->initialMembershipPublished;
        if (!held) {
            published = publish_snapshot(*record);
            record->initialMembershipPublished = published;
            record->playerPublished = record->hasPlayer && published;
        }
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    if (held) {
        report(core::log::Level::debug,
               "ev=gameplay stage=membership result=held session=0x%016llX join=0x%016llX",
               static_cast<unsigned long long>(sessionId),
               static_cast<unsigned long long>(peerJoinId));
    }
    return published || held;
}

bool authorize_shared_peer(std::uint64_t sessionId,
                            const state::gameplay::Endpoint& endpoint,
                            std::uint64_t machineId,
                            std::uint64_t initialPlayerId) noexcept {
    if (sessionId == 0 || machineId == 0 || machineId == sessionId || initialPlayerId == 0
        || endpoint.address == 0 || endpoint.port == 0
        || !static_cast<bool>(held_host_activity(sessionId))) { return false; }
    AcquireSRWLockExclusive(&g_admittedLock);
    std::size_t humans = 0;
    const Admitted* existing = nullptr;
    for (const auto& entry : g_admitted) {
        if (entry.occupied && entry.sessionId == sessionId
            && entry.endpoint.address == endpoint.address && entry.endpoint.port == endpoint.port) {
            existing = &entry;
            break;
        }
    }
    for (const auto& entry : g_admitted) {
        if (!entry.occupied || !entry.sharedAuthorized || entry.sessionId != sessionId) { continue; }
        const bool sameEndpoint = entry.endpoint.address == endpoint.address && entry.endpoint.port == endpoint.port;
        if (sameEndpoint) {
            // Idempotent registration is allowed, but a live identity cannot be reassigned.
            const bool same = entry.machineId == machineId && entry.initialPlayerId == initialPlayerId;
            ReleaseSRWLockExclusive(&g_admittedLock);
            return same;
        }
        if (entry.machineId == machineId || entry.initialPlayerId == initialPlayerId
            || (entry.hasPlayer && entry.playerId == initialPlayerId)
            || (existing != nullptr && existing->hasPlayer && entry.hasPlayer
                && existing->playerId == entry.playerId)) {
            ReleaseSRWLockExclusive(&g_admittedLock);
            return false;
        }
        ++humans;
    }
    SharedGroupSlots* slots = nullptr;
    SharedGroupSlots* freeSlots = nullptr;
    for (auto& held : g_sharedGroupSlots) {
        if (held.sessionId == sessionId) { slots = &held; break; }
        if (held.sessionId == 0 && freeSlots == nullptr) { freeSlots = &held; }
    }
    if (slots == nullptr) { slots = freeSlots; }
    auto assignments = slots == nullptr ? SharedSlotAssignments{} : slots->assignments;
    std::uint32_t slot = kInvalidSharedHumanSlot;
    const bool assigned = slots != nullptr && assignments.reserve(machineId, initialPlayerId, slot);
    // A previously published solo member is already member 1/player 0. Converting
    // it to a different slot would silently reassign native ownership.
    const bool stableUpgrade = existing == nullptr || !existing->initialMembershipPublished || slot == 0;
    Admitted* record = humans < kSharedHumanCapacity && assigned && stableUpgrade ? claim(endpoint, sessionId, true) : nullptr;
    if (record != nullptr) {
        slots->sessionId = sessionId;
        slots->assignments = assignments;
        record->sharedAuthorized = true;
        record->machineId = machineId;
        record->initialPlayerId = initialPlayerId;
        record->sharedPlayerSlot = slot;
        dirty_shared_membership(sessionId);
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    if (record == nullptr) {
        report(core::log::Level::warn,
            "ev=gameplay stage=shared_authorization result=rejected reason=%s",
            slots == nullptr ? "slot_registry_full" : !assigned ? "slot_identity_conflict"
            : !stableUpgrade ? "live_member_slot_change" : "endpoint_capacity");
    }
    return record != nullptr;
}

/** Retries any publish a full reliable queue refused. */
void service(std::uint64_t now) noexcept {
    // Outside any staged push, so the state revision it advances cannot fail a transaction guard.
    allocate_claimed_host_sessions();
    // The peer drops a stale target locally and sends no leave for it. Such a record shows up
    // only as the least recently named one over the capacity.
    std::uint64_t retired = 0;
    state::gameplay::Endpoint retiredEndpoint{};
    AcquireSRWLockExclusive(&g_admittedLock);
    std::size_t occupied = 0;
    Admitted* oldest = nullptr;
    for (Admitted& record : g_admitted) {
        if (!record.occupied) {
            continue;
        }
        ++occupied;
        std::size_t endpointSessions = 0;
        for (const auto& other : g_admitted) {
            if (other.occupied && other.endpoint.address == record.endpoint.address
                && other.endpoint.port == record.endpoint.port) { ++endpointSessions; }
        }
        if (endpointSessions > kPublicSessionCapacity
            && (oldest == nullptr || record.lastUse < oldest->lastUse)) {
            oldest = &record;
        }
    }
    if (oldest != nullptr) {
        retired = oldest->sessionId;
        retiredEndpoint = oldest->endpoint;
        *oldest = {};
        dirty_shared_membership(retired);
    }
    for (Admitted& record : g_admitted) {
        if (record.occupied && record.sharedAuthorized && record.membershipDirty
            && record.initialMembershipPublished
            && now - record.lastRetry >= kRetryInterval) {
            record.lastRetry = now;
            record.membershipDirty = !publish_snapshot(record);
            continue;
        }
        const bool owed =
            record.occupied
            && ((record.joinComplete && !record.joinPublished
                 && !record.playerReplacementPending)
                || (record.joinPublished && !record.activityHostPublished)
                || (record.joinPublished && record.hasPlayer && !record.playerPublished)
                || (record.peerReestablishMembershipGeneration
                    < record.peerReestablishGeneration)
                || (record.migratedSessionId != 0
                    && !record.migratedActivityHostPublished)
                || (!record.sharedAuthorized
                    && state::activity::forced::mission_host_reestablishment_enabled()
                    && record.activityHostPublished
                    && record.activityHostPublishedAt != 0
                    && ((!record.initialHostReestablishPublished
                         && now - record.activityHostPublishedAt
                                >= kInitialHostReestablishDelay)
                        || (record.initialHostReestablishPublished
                            && !record.hostHandoffPublished
                            && now - record.activityHostPublishedAt >= kHostHandoffDelay)
                        || (record.hostHandoffPublished && !record.hostTransitionPublished
                            && now - record.activityHostPublishedAt >= kHostTransitionDelay)
                        || (record.hostTransitionPublished && !record.hostReturnHandoffPublished
                            && now - record.activityHostPublishedAt
                                   >= kHostReturnHandoffDelay)
                        || (record.hostReturnHandoffPublished
                            && !record.hostReestablishPublished
                            && now - record.activityHostPublishedAt
                                   >= kHostReestablishDelay))));
        if (!owed || now - record.lastRetry < kRetryInterval) {
            continue;
        }
        record.lastRetry = now;
        if (!record.joinPublished) {
            record.joinPublished = publish_snapshot(record);
            continue;
        }
        if (!record.activityHostPublished) {
            record.activityHostPublished = publish_activity_host(record);
            if (record.activityHostPublished) {
                record.activityHostPublishedAt = now;
            }
            continue;
        }
        if (record.hasPlayer && !record.playerPublished) {
            // Keep the authoritative player row ahead of the migration sequence.
            record.playerPublished = publish_snapshot(record);
            continue;
        }
        if (record.peerReestablishMembershipGeneration < record.peerReestablishGeneration) {
            (void)publish_peer_reestablish_membership(record);
            continue;
        }
        if (record.migratedSessionId != 0 && !record.migratedActivityHostPublished) {
            record.migratedActivityHostPublished =
                publish_activity_host_for_session(record, record.migratedSessionId);
            continue;
        }
        if (!record.initialHostReestablishPublished) {
            record.initialHostReestablishPublished =
                publish_host_reestablish(record, "baseline");
            continue;
        }
        if (!record.hostHandoffPublished) {
            record.hostHandoffPublished = publish_host_handoff(
                record, static_cast<std::uint32_t>(kPeerMemberIndex), "to_peer");
            continue;
        }
        if (!record.hostTransitionPublished) {
            record.hostTransitionPublished = publish_host_transition(record);
            continue;
        }
        if (!record.hostReturnHandoffPublished) {
            record.hostReturnHandoffPublished =
                publish_host_handoff(record, kHostMemberIndex, "to_host");
            continue;
        }
        record.hostReestablishPublished = publish_host_reestablish(record, "activate");
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    // Outside the lock, in the order `release` already uses. The region's activity host stays: the
    // peer rotates back into a region it has not left, and a fresh id there is a hard error.
    if (retired != 0) {
        peer::drop(retiredEndpoint, retired);
        report(core::log::Level::info,
               "ev=gameplay stage=admitted result=retired session=0x%016llX held=%zu",
               static_cast<unsigned long long>(retired),
               occupied - 1);
    }
}

/** Publishes the parameter update a joining peer needs before it will finish its join. */
bool publish_join_parameters(const state::gameplay::Endpoint& endpoint,
                              std::uint64_t sessionId) noexcept {
    // A joining peer finishes only once it has applied one parameter update. Any update with a
    // named parameter and no body sets that latch. This host has no values, so it releases a slot
    // the peer never filled, which leaves the peer's state alone.
    wire::ParameterUpdate update{};
    update.sessionId = sessionId;
    update.releasedMask = std::uint64_t{1} << kJoinLatchParameter;

    AcquireSRWLockExclusive(&g_admittedLock);
    Admitted* record = nullptr;
    for (Admitted& candidate : g_admitted) {
        if (candidate.occupied && candidate.sessionId == sessionId
            && candidate.endpoint.address == endpoint.address && candidate.endpoint.port == endpoint.port) {
            record = &candidate;
            break;
        }
    }
    const bool held = record != nullptr && record->initialParametersPublished;
    const bool sent = record != nullptr && !held
                      && send_reliable(
                          endpoint, sessionId,
                          wire::kParameterUpdateId,
                          wire::kParameterUpdateSize,
                          [&update](bits::Writer& writer) {
                              return wire::write_parameter_update(writer, update);
                          });
    if (record != nullptr && sent) {
        record->initialParametersPublished = true;
    }
    ReleaseSRWLockExclusive(&g_admittedLock);
    std::array<char, kParameterNameCapacity> names{};
    report(sent ? core::log::Level::info
                : held ? core::log::Level::debug : core::log::Level::warn,
           "ev=gameplay stage=parameters result=%s released=0x%08X names=%s",
           sent ? "queued" : held ? "held" : "fail",
           static_cast<unsigned>(update.releasedMask),
           wire::parameter_names(update.releasedMask, names.data(), names.size()));
    return sent || held;
}

bool publish_join_parameters(std::uint64_t sessionId) noexcept {
    state::gameplay::Endpoint selected{};
    bool found = false;
    AcquireSRWLockShared(&g_admittedLock);
    for (const auto& entry : g_admitted) {
        if (!entry.occupied || entry.sessionId != sessionId) { continue; }
        if (found) { ReleaseSRWLockShared(&g_admittedLock); return false; }
        selected = entry.endpoint;
        found = true;
    }
    ReleaseSRWLockShared(&g_admittedLock);
    return found && publish_join_parameters(selected, sessionId);
}

/** Reports whether replication may produce entity output for one peer. */
bool view_accepted(std::uint64_t sessionId) noexcept {
    return peer::view_bound(sessionId);
}

bool view_accepted(const state::gameplay::Endpoint& endpoint, std::uint64_t sessionId) noexcept {
    return peer::view_bound(endpoint, sessionId);
}

/** Copies every admitted group-session record. */
void snapshot_admitted(std::span<AdmittedRow> output, std::size_t& count) noexcept {
    count = 0;
    AcquireSRWLockShared(&g_admittedLock);
    for (const Admitted& entry : g_admitted) {
        if (!entry.occupied || count >= output.size()) {
            continue;
        }
        output[count] = {entry.sessionId,
                         entry.endpoint,
                         entry.joinComplete,
                         entry.activityHostPublished,
                         entry.hasPlayer,
                         entry.playerPublished,
                         entry.machineId,
                         entry.playerId,
                         entry.sharedAuthorized,
                         entry.sharedPlayerSlot};
        ++count;
    }
    ReleaseSRWLockShared(&g_admittedLock);
}

/** Clears every group-session record. */
void reset() noexcept {
    g_membershipRevision.store(0);
    // Every host session goes back to State as well, or its records are stranded there.
    reset_host_sessions();
    AcquireSRWLockExclusive(&g_admittedLock);
    g_admitted = {};
    g_sharedGroupSlots = {};
    ReleaseSRWLockExclusive(&g_admittedLock);
}

} // namespace dawn::server::gameplay::group
