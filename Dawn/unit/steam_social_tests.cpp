#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../src/core/settings/settings.h"
#include "../src/steam/interfaces/internal.h"
#include "../src/steam/runtime/social.h"
#include "../src/steam/runtime/callbacks/callback_registry.h"

namespace {
unsigned checks{};
struct Event { int id{}; std::vector<std::byte> bytes; };
std::vector<Event> events;
bool allowEvents = true;
bool allowSend = true;
std::uint64_t sentTo{};
std::string sentConnect;
constexpr std::uint64_t localId = 0x0110000111111111ULL;
constexpr std::uint64_t remoteId = 0x0110000122222222ULL;
void check(bool result, const char* label) {
    ++checks;
    if (!result) { std::fprintf(stderr, "FAIL %u: %s\n", checks, label); std::abort(); }
}
bool sender(void*, std::uint64_t recipient, std::string_view connect) noexcept {
    sentTo = recipient; sentConnect = connect; return allowSend;
}
template <std::size_t Size>
void text(std::array<char, Size>& out, const char* value) { std::memcpy(out.data(), value, std::strlen(value) + 1); }
} // namespace

namespace dawn::core::settings {
const Settings& get() noexcept { static const Settings settings{}; return settings; }
}
namespace dawn::steam {
DWORD app_id() noexcept { return 1085660; }
bool queue_callback(int id, ApiCall call, const void* payload, std::size_t length) noexcept {
    if (!allowEvents || call != 0 || length > runtime::callbacks::kEventPayloadCapacity) { return false; }
    const auto* bytes = static_cast<const std::byte*>(payload);
    events.push_back({id, std::vector<std::byte>(bytes, bytes + length)}); return true;
}
}

namespace {
namespace social = dawn::steam::social;
constexpr std::string_view ticketA = "0123456789ABCDEF0123456789ABCDEF";
constexpr std::string_view ticketB = "FEDCBA9876543210FEDCBA9876543210";
enum class AcceptAction { none, reenter, replace, dismiss, revoke, clear, reset, changeSender };
struct AcceptProbe {
    unsigned calls{};
    std::uint64_t from{};
    std::string ticket;
    AcceptAction action{};
    bool allowed{true}, outsideRead{}, nested{}, changed{};
};

bool accept_sender(void* context, std::uint64_t from, std::string_view ticket) noexcept {
    auto& probe = *static_cast<AcceptProbe*>(context);
    ++probe.calls; probe.from = from; probe.ticket = ticket;
    social::PendingInvitation pending{};
    probe.outsideRead = social::pending_invitation(pending);
    switch (probe.action) {
    case AcceptAction::reenter: probe.nested = social::accept_invitation(pending.id); break;
    case AcceptAction::replace: probe.changed = social::receive_invitation(remoteId, "replacement", ticketB); break;
    case AcceptAction::dismiss: probe.changed = social::dismiss_invitation(pending.id); break;
    case AcceptAction::revoke: probe.changed = social::revoke_invitation(ticket); break;
    case AcceptAction::clear: social::clear_peer(); break;
    case AcceptAction::reset: social::reset(); break;
    case AcceptAction::changeSender: social::set_invite_accepted_sender(accept_sender, context); break;
    case AcceptAction::none: break;
    }
    return probe.allowed;
}

void seed_social() {
    social::reset();
    check(social::set_local_identity(localId, "Local"), "ticket fixture local identity configured");
    social::PeerProfile profile{}; profile.steamId = remoteId; text(profile.name, "Remote");
    check(social::set_peer(profile), "ticket fixture authenticated peer configured");
    events.clear(); allowEvents = true;
}

social::PendingInvitation ticket_invite(std::string_view ticket = ticketA) {
    check(social::receive_invitation(remoteId, "ticket-connect", ticket), "ticketed invitation received");
    social::PendingInvitation pending{};
    check(social::pending_invitation(pending), "ticketed invitation is pending");
    return pending;
}

void ticketed_invitation_tests() {
    seed_social();
    auto pending = ticket_invite(); const auto original = pending.id;
    check(!social::accept_invitation(original) && events.empty(), "ticket acceptance needs authenticated intent sender");
    const std::string embedded = std::string(15, 'A') + '\0' + std::string(16, 'A');
    for (const auto& invalid : {std::string(), std::string(31, 'A'), std::string(33, 'A'),
                               std::string(32, 'a'), std::string(32, 'G'), std::string(32, ' '), embedded}) {
        check(!social::receive_invitation(remoteId, "bad-ticket", invalid), "noncanonical ticket rejected");
        check(!social::revoke_invitation(invalid), "noncanonical revoke rejected");
        check(social::pending_invitation(pending) && pending.id == original, "bad ticket preserves exact pending request");
    }
    check(!social::receive_invitation(localId, "wrong-from", ticketB)
          && !social::receive_invitation(0, "wrong-from", ticketB)
          && !social::receive_invitation(remoteId + 1, "wrong-from", ticketB), "ticketed invite must name authenticated paired sender");
    check(!social::receive_invitation(remoteId, "bad\nconnect", ticketB), "ticket does not relax connect text validation");
    AcceptProbe probe{}; probe.allowed = false;
    social::set_invite_accepted_sender(accept_sender, &probe);
    check(!social::accept_invitation(original) && probe.calls == 1, "failed acceptance send propagates failure");
    check(probe.outsideRead && probe.from == remoteId && probe.ticket == ticketA, "sender runs outside lock with exact authenticated sender and ticket");
    check(social::pending_invitation(pending) && pending.id == original && !pending.waitingForAuthorization,
          "failed acceptance remains retryable");
    probe.allowed = true;
    check(social::accept_invitation(original) && probe.calls == 2, "retry sends accepted intent once");
    check(social::pending_invitation(pending) && pending.id == original && pending.waitingForAuthorization,
          "successful intent retains invitation while waiting for host authorization");
    check(events.empty(), "ticketed acceptance never queues GameRichPresenceJoinRequested");
    check(!social::accept_invitation(original) && probe.calls == 2, "waiting invitation cannot resend acceptance");
    check(!social::revoke_invitation(ticketB) && social::pending_invitation(pending), "stale revoke cannot clear another ticket");
    check(social::revoke_invitation(ticketA) && !social::pending_invitation(pending), "matching host revoke clears waiting invitation");
    check(pending.ticket[0] == '\0' && !pending.waitingForAuthorization, "revoked ticket and waiting state are wiped");
    check(!social::revoke_invitation(ticketA), "revocation cannot replay");

    for (const auto action : {AcceptAction::reenter, AcceptAction::replace, AcceptAction::dismiss,
                               AcceptAction::revoke, AcceptAction::clear, AcceptAction::reset, AcceptAction::changeSender}) {
        seed_social(); probe = {}; probe.action = action;
        social::set_invite_accepted_sender(accept_sender, &probe);
        const auto before = ticket_invite();
        const bool accepted = social::accept_invitation(before.id);
        check(probe.calls == 1 && probe.outsideRead, "reentrant sender may query pending state without deadlock");
        check(events.empty(), "reentrant ticket acceptance cannot trigger game join callback");
        if (action == AcceptAction::reenter) {
            check(accepted && !probe.nested, "inflight guard rejects recursive duplicate acceptance");
            check(social::pending_invitation(pending) && pending.waitingForAuthorization, "original successful attempt enters waiting state once");
        } else if (action == AcceptAction::replace) {
            check(!accepted && probe.changed, "stale completion cannot accept reentrantly replaced invitation");
            check(social::pending_invitation(pending) && pending.id != before.id && !pending.waitingForAuthorization
                  && std::string_view(pending.ticket.data()) == ticketB, "replacement retains its own ticket and retry state");
        } else if (action == AcceptAction::changeSender) {
            check(!accepted && social::pending_invitation(pending) && !pending.waitingForAuthorization,
                  "sender replacement invalidates inflight acceptance completion");
            probe.action = AcceptAction::none;
            check(social::accept_invitation(pending.id), "sender replacement leaves pending invitation retryable");
        } else {
            check(!accepted && !social::pending_invitation(pending), "dismiss revoke disconnect or reset defeats inflight completion");
            if (action == AcceptAction::dismiss || action == AcceptAction::revoke) {
                check(probe.changed, "reentrant cancellation matched exact pending invitation");
            }
        }
    }
    seed_social(); probe = {};
    social::set_invite_accepted_sender(accept_sender, &probe);
    pending = ticket_invite(); check(social::accept_invitation(pending.id), "waiting invite prepared for dismissal");
    check(social::dismiss_invitation(pending.id) && !social::pending_invitation(pending), "user can decline while waiting for authorization");
    social::clear_peer();
    social::PeerProfile profile{}; profile.steamId = remoteId; text(profile.name, "Remote");
    check(social::set_peer(profile), "new peer after clear configured");
    pending = ticket_invite();
    check(!social::accept_invitation(pending.id), "clear_peer removes accepted-intent sender until bridge reinstalls it");
    social::reset();
    check(social::set_peer(profile), "peer after reset configured"); pending = ticket_invite();
    check(!social::accept_invitation(pending.id), "reset removes accepted-intent sender and pending ticket");
    check(social::receive_invitation(remoteId, "legacy-after-ticket"), "legacy invite can replace ticketed pending request");
    check(social::pending_invitation(pending) && pending.ticket[0] == '\0' && !pending.waitingForAuthorization,
          "legacy request has no ticket or authorization wait");
    check(social::accept_invitation(pending.id) && events.size() == 1 && events[0].id == 337,
          "legacy acceptance retains original native game callback");
}

struct BlockProbe { std::atomic<bool> entered{}, release{}, expired{}; std::atomic<unsigned> calls{}; };
bool blocking_sender(void* context, std::uint64_t, std::string_view) noexcept {
    auto& probe = *static_cast<BlockProbe*>(context);
    ++probe.calls; probe.entered.store(true, std::memory_order_release);
    const auto deadline = GetTickCount64() + 5000;
    while (!probe.release.load(std::memory_order_acquire)) {
        if (GetTickCount64() >= deadline) { probe.expired = true; return false; }
        Sleep(1);
    }
    return true;
}
void concurrent_acceptance_tests() {
    seed_social(); BlockProbe blocked{};
    social::set_invite_accepted_sender(blocking_sender, &blocked);
    const auto first = ticket_invite();
    bool oldAccepted{};
    std::thread worker([&] { oldAccepted = social::accept_invitation(first.id); });
    const auto deadline = GetTickCount64() + 2000;
    while (!blocked.entered.load(std::memory_order_acquire) && GetTickCount64() < deadline) { Sleep(1); }
    check(blocked.entered.load(std::memory_order_acquire), "concurrent intent sender entered outside social lock");
    check(!social::accept_invitation(first.id) && blocked.calls == 1, "concurrent duplicate click cannot send a second intent");
    const auto replacement = ticket_invite(ticketB);
    AcceptProbe current{};
    social::set_invite_accepted_sender(accept_sender, &current);
    check(social::accept_invitation(replacement.id), "replacement invitation can accept through its own sender generation");
    blocked.release.store(true, std::memory_order_release); worker.join();
    social::PendingInvitation pending{};
    check(!blocked.expired && !oldAccepted, "delayed old callback cannot complete after pending replacement");
    check(social::pending_invitation(pending) && pending.id == replacement.id && pending.waitingForAuthorization
          && std::string_view(pending.ticket.data()) == ticketB, "old completion preserves replacement waiting state");
    check(events.empty() && current.calls == 1, "concurrent ticket acceptance queues no game callback");
    // Reinstalling a sender can start a new attempt for the SAME pending ID.
    // Its separate attempt generation must defeat the blocked old completion.
    seed_social(); BlockProbe sameBlocked{};
    social::set_invite_accepted_sender(blocking_sender, &sameBlocked);
    const auto same = ticket_invite();
    bool sameOldAccepted{};
    std::thread sameWorker([&] { sameOldAccepted = social::accept_invitation(same.id); });
    const auto sameDeadline = GetTickCount64() + 2000;
    while (!sameBlocked.entered.load(std::memory_order_acquire) && GetTickCount64() < sameDeadline) { Sleep(1); }
    check(sameBlocked.entered.load(std::memory_order_acquire), "same-ID race reaches old sender");
    AcceptProbe newSender{};
    social::set_invite_accepted_sender(accept_sender, &newSender);
    check(social::accept_invitation(same.id), "new sender starts independent attempt for same pending ID");
    sameBlocked.release.store(true, std::memory_order_release); sameWorker.join();
    check(!sameBlocked.expired && !sameOldAccepted && newSender.calls == 1,
          "old attempt generation cannot complete a newer attempt with the same invitation ID");
    check(social::pending_invitation(pending) && pending.id == same.id && pending.waitingForAuthorization,
          "same-ID delayed completion preserves current authorization wait");
    check(events.empty(), "same-ID race cannot queue native game join");
    social::reset();
}
} // namespace

int main() {
    namespace social = dawn::steam::social;
    namespace method = dawn::steam::interfaces::methods;
    using dawn::steam::interfaces::SteamId;
    using dawn::steam::interfaces::FriendGameInfo;
    social::reset();
    check(method::get_friend_count(nullptr, 0xFFFF) == 0, "no phantom friends before authenticated connection");
    SteamId id{123};
    check(method::get_friend_by_index(nullptr, &id, 0, 4) == &id && id.value == 0, "empty enumeration writes nil Steam ID");
    check(!social::set_local_identity(0, "Local"), "invalid local identity rejected");
    check(!social::set_local_identity(localId, std::string_view("Bad\0Name", 8)), "embedded name terminator rejected");
    check(!social::set_local_identity(localId, "\xC0\xAF"), "overlong UTF-8 rejected");
    check(social::set_local_identity(localId, "Local"), "session identity accepted");
    check(social::local_steam_id() == localId && std::strcmp(method::persona_name(nullptr), "Local") == 0, "local persona identity answered");
    check(method::get_friend_persona_state(nullptr, localId) == 1, "local persona stays online");
    social::PeerProfile profile{};
    profile.steamId = localId; text(profile.name, "Remote");
    check(!social::set_peer(profile), "peer cannot impersonate local identity");
    profile.steamId = remoteId;
    text(profile.connect, "dawn-connect=example"); text(profile.status, "In orbit");
    profile.lobbyId = 0x0109000000000123ULL; profile.ipv4 = 0xC0A8017CU; profile.gamePort = 30980;
    check(social::set_peer(profile), "authenticated peer published");
    check(!social::set_local_identity(localId + 1, "Changed"), "identity cannot change during paired session");
    check(method::get_friend_count(nullptr, 4) == 1 && method::get_friend_count(nullptr, 0) == 0
          && method::get_friend_count(nullptr, 1) == 0, "friend flag filtering");
    check(method::get_friend_by_index(nullptr, &id, 0, 4) == &id && id.value == remoteId, "friend enumeration returns paired ID");
    method::get_friend_by_index(nullptr, &id, -1, 4);
    check(id.value == 0, "negative enumeration index writes nil");
    method::get_friend_by_index(nullptr, &id, 1, 4);
    check(id.value == 0, "out of range index writes nil");
    check(method::get_friend_by_index(nullptr, nullptr, 0, 4) == nullptr, "missing ID output handled");
    check(method::has_friend(nullptr, remoteId, 4) && !method::has_friend(nullptr, localId, 4), "HasFriend matches only paired identity");
    check(method::get_friend_relationship(nullptr, remoteId) == 3 && method::get_friend_relationship(nullptr, 42) == 0, "relationship lookup");
    check(method::get_friend_persona_state(nullptr, remoteId) == 1 && method::get_friend_persona_state(nullptr, 42) == 0, "persona presence lookup");
    check(std::strcmp(method::get_friend_persona_name(nullptr, remoteId), "Remote") == 0
          && std::strcmp(method::get_friend_persona_name(nullptr, 42), "") == 0, "friend names and safe unknown lookup");
    check(std::strcmp(method::get_friend_persona_name_history(nullptr, remoteId, 0), "") == 0, "unavailable name history is safe empty text");
    FriendGameInfo game{1, 2, 3, 4, 5};
    check(!method::get_friend_game_played(nullptr, remoteId, &game) && game.gameId == 0, "paired launcher alone is not game-running presence");
    profile.gameRunning = true; check(social::set_peer(profile), "peer native-game presence updated");
    check(method::get_friend_game_played(nullptr, remoteId, &game) && game.gameId == 1085660
          && game.ipv4 == profile.ipv4 && game.gamePort == profile.gamePort && game.lobbyId == profile.lobbyId, "FriendGameInfo ABI data");
    check(method::get_friend_count(nullptr, 0x10) == 0, "running separate local backends is not a shared game server");
    profile.sameGameServer = true;
    check(social::set_peer(profile) && method::get_friend_count(nullptr, 0x10) == 1, "shared-server filter requires explicit native authority confirmation");
    check(method::get_friend_rich_presence_key_count(nullptr, remoteId) == 2, "peer presence key count");
    check(std::strcmp(method::get_friend_rich_presence_key_by_index(nullptr, remoteId, 0), "connect") == 0
          && std::strcmp(method::get_friend_rich_presence_key_by_index(nullptr, remoteId, 1), "status") == 0
          && std::strcmp(method::get_friend_rich_presence_key_by_index(nullptr, remoteId, 2), "") == 0, "presence key enumeration bounds");
    check(std::strcmp(method::get_friend_rich_presence(nullptr, remoteId, "status"), "In orbit") == 0, "peer presence value lookup");
    check(!method::invite_user_to_game(nullptr, remoteId, "test"), "invite cannot fabricate transport success");
    social::set_invite_sender(sender, nullptr);
    check(method::invite_user_to_game(nullptr, remoteId, "join-test") && sentTo == remoteId && sentConnect == "join-test", "outbound invite routed to authenticated transport");
    check(!method::invite_user_to_game(nullptr, localId, "test") && !method::invite_user_to_game(nullptr, remoteId, nullptr), "invalid invite targets rejected");
    std::string longConnect(256, 'x');
    check(!social::send_invitation(remoteId, longConnect) && !social::send_invitation(remoteId, "bad\nconnect"), "oversized and control-bearing invitations rejected");
    allowSend = false;
    check(!method::invite_user_to_game(nullptr, remoteId, "test"), "transport failure propagated"); allowSend = true;
    check(!social::receive_invitation(42, "join"), "incoming invite must name paired identity");
    check(social::receive_invitation(remoteId, "join-first"), "incoming invite retained");
    social::PendingInvitation pending{};
    check(social::pending_invitation(pending), "pending invite can be displayed"); const auto first = pending.id;
    check(events.empty(), "incoming invite does not autojoin or run game callback");
    check(social::receive_invitation(remoteId, "join-second"), "new invite replaces pending request");
    check(!social::accept_invitation(first), "stale prompt cannot accept a newer invitation");
    check(social::pending_invitation(pending) && pending.id != first, "invitation generation is distinct");
    allowEvents = false;
    check(!social::accept_invitation(pending.id) && social::pending_invitation(pending), "full callback queue retains pending invitation");
    allowEvents = true;
    check(social::accept_invitation(pending.id) && !social::pending_invitation(pending), "accept queues once and consumes pending request");
    check(events.size() == 1 && events[0].id == 337 && events[0].bytes.size() == 264, "accepted invite uses exact callback ID and payload size");
    std::uint64_t callbackFrom{}; std::memcpy(&callbackFrom, events[0].bytes.data(), sizeof callbackFrom);
    check(callbackFrom == remoteId && std::strcmp(reinterpret_cast<const char*>(events[0].bytes.data() + 8), "join-second") == 0, "accepted callback carries peer and connect text");
    check(!social::accept_invitation(first), "accepted invitation is not replayable");
    check(social::receive_invitation(remoteId, "dismiss"), "invite for dismissal received"); (void)social::pending_invitation(pending);
    check(social::dismiss_invitation(pending.id) && !social::pending_invitation(pending), "decline does not join");
    check(method::set_rich_presence(nullptr, "connect", "native-party")
          && std::strcmp(method::get_friend_rich_presence(nullptr, localId, "connect"), "native-party") == 0, "local rich presence retained for bridge");
    method::clear_rich_presence(nullptr);
    for (int i = 0; i < 30; ++i) {
        const std::string key = "key" + std::to_string(i);
        check(method::set_rich_presence(nullptr, key.c_str(), "value"), "documented presence capacity available");
    }
    check(!method::set_rich_presence(nullptr, "overflow", "value"), "presence capacity bounded");
    check(method::get_friend_rich_presence_key_count(nullptr, localId) == 30
          && std::strcmp(method::get_friend_rich_presence_key_by_index(nullptr, localId, 0), "key0") == 0
          && std::strcmp(method::get_friend_rich_presence_key_by_index(nullptr, localId, 30), "") == 0,
          "local presence enumeration matches actual bounded keys");
    check(method::set_rich_presence(nullptr, "key1", nullptr) && method::set_rich_presence(nullptr, "replacement", "value"), "presence deletion releases its slot");
    method::clear_rich_presence(nullptr);
    std::array<char, social::kConnectCapacity> value{};
    check(!social::local_presence("replacement", value), "clear removes local presence");
    events.clear(); allowEvents = false; social::service();
    check(events.empty(), "deferred persona notifications respect queue backpressure");
    allowEvents = true; social::service();
    check(events.size() == 2 && events[0].id == 304 && events[1].id == 336, "persona and rich presence callbacks retried");
    check(social::set_peer(profile), "unchanged peer heartbeat accepted"); social::service();
    check(events.size() == 2, "unchanged presence does not spam online callbacks");
    social::clear_peer();
    check(method::get_friend_count(nullptr, 4) == 0 && !social::receive_invitation(remoteId, "join"), "disconnect removes roster and rejects stale invitations");
    social::service();
    check(events.back().id == 304, "disconnect queues offline persona change");
    social::reset();
    check(social::local_steam_id() == dawn::steam::kLocalSteamId && !social::peer_profile(profile), "reset restores solo identity");
    ticketed_invitation_tests();
    concurrent_acceptance_tests();
    std::printf("PASS: %u native social checks; no game session claimed.\n", checks);
}
