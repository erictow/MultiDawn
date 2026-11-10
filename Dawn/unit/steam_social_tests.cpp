#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
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
    std::printf("PASS: %u native social checks; no game session claimed.\n", checks);
}
