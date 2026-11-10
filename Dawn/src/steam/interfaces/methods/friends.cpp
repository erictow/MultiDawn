#include <array>
#include <cstring>
#include <string_view>

#include "../../../core/settings/settings.h"
#include "../../runtime/social.h"
#include "../internal.h"

namespace dawn::steam::social {
namespace {

// ABI reference: ValveSoftware/source-sdk-2013/src/public/steam/isteamfriends.h.
// These process identities belong to the local mod session, not authenticated Steam accounts.
constexpr int kPersonaStateChanged = 304;
constexpr int kFriendRichPresenceUpdated = 336;
constexpr int kGameRichPresenceJoinRequested = 337;
constexpr std::uint64_t kIndividualPrefix = 0x0110000100000000ULL;
constexpr int kFriendImmediate = 0x04;
constexpr int kFriendOnGameServer = 0x10;

struct PersonaChange { std::uint64_t id{}; std::int32_t flags{}; std::uint32_t padding{}; };
struct PresenceChange { std::uint64_t id{}; std::uint32_t app{}; std::uint32_t padding{}; };
struct JoinRequested { std::uint64_t from{}; std::array<char, kConnectCapacity> connect{}; };
static_assert(sizeof(PersonaChange) == 16);
static_assert(sizeof(PresenceChange) == 16);
static_assert(sizeof(JoinRequested) == 264);

struct PresenceEntry {
    std::array<char, kPresenceKeyCapacity> key{};
    std::array<char, kConnectCapacity> value{};
};

SRWLOCK g_socialLock = SRWLOCK_INIT;
std::uint64_t g_localId{kLocalSteamId};
std::array<char, kPersonaCapacity> g_localName{};
PeerProfile g_peer{};
PendingInvitation g_invitation{};
std::uint64_t g_nextInvitation{};
InviteSender g_sender{};
void* g_senderContext{};
std::array<PresenceEntry, kPresenceCapacity> g_localPresence{};
std::uint64_t g_notifyId{};
int g_notifyFlags{};
bool g_presenceDirty{};

[[nodiscard]] bool valid_id(std::uint64_t id) noexcept {
    return (id & 0xFFFFFFFF00000000ULL) == kIndividualPrefix && (id & 0xFFFFFFFFULL) != 0;
}

/** Reject embedded terminators, control bytes, overlong and malformed UTF-8. */
[[nodiscard]] bool valid_text(std::string_view text, std::size_t capacity, bool empty = false) noexcept {
    if ((!empty && text.empty()) || text.size() >= capacity) { return false; }
    std::uint32_t value{}, minimum{};
    unsigned remaining{};
    for (const char raw : text) {
        const auto byte = static_cast<unsigned char>(raw);
        if (remaining != 0) {
            if ((byte & 0xC0U) != 0x80U) { return false; }
            value = (value << 6U) | (byte & 0x3FU);
            --remaining;
            if (remaining == 0 && (value < minimum || value > 0x10FFFFU
                                   || (value >= 0xD800U && value <= 0xDFFFU))) { return false; }
        } else if (byte < 0x80U) {
            if (byte < 0x20U || byte == 0x7FU) { return false; }
        } else if (byte >= 0xC2U && byte <= 0xDFU) {
            remaining = 1; value = byte & 0x1FU; minimum = 0x80U;
        } else if (byte >= 0xE0U && byte <= 0xEFU) {
            remaining = 2; value = byte & 0x0FU; minimum = 0x800U;
        } else if (byte >= 0xF0U && byte <= 0xF4U) {
            remaining = 3; value = byte & 0x07U; minimum = 0x10000U;
        } else { return false; }
    }
    return remaining == 0;
}

template <std::size_t Capacity>
[[nodiscard]] std::string_view text_of(const std::array<char, Capacity>& value) noexcept {
    const void* end = std::memchr(value.data(), '\0', value.size());
    return end == nullptr ? std::string_view(value.data(), value.size())
                          : std::string_view(value.data(), static_cast<const char*>(end) - value.data());
}
template <std::size_t Capacity>
void assign(std::array<char, Capacity>& output, std::string_view value) noexcept {
    output = {};
    if (!value.empty()) { std::memcpy(output.data(), value.data(), value.size()); }
}
/** Caller holds the social lock. */
[[nodiscard]] bool friend_flags(int flags) noexcept {
    return g_peer.steamId != 0 && ((flags & kFriendImmediate) != 0
           || ((flags & kFriendOnGameServer) != 0 && g_peer.gameRunning && g_peer.sameGameServer));
}

} // namespace

bool set_local_identity(std::uint64_t id, std::string_view name) noexcept {
    if (!valid_id(id) || !valid_text(name, kPersonaCapacity)) { return false; }
    AcquireSRWLockExclusive(&g_socialLock);
    const bool accepted = g_peer.steamId == 0 && g_invitation.id == 0;
    if (accepted) { g_localId = id; assign(g_localName, name); }
    ReleaseSRWLockExclusive(&g_socialLock);
    return accepted;
}
std::uint64_t local_steam_id() noexcept {
    AcquireSRWLockShared(&g_socialLock);
    const auto value = g_localId;
    ReleaseSRWLockShared(&g_socialLock);
    return value;
}
const char* local_persona_name() noexcept {
    thread_local std::array<char, kPersonaCapacity> name{};
    AcquireSRWLockShared(&g_socialLock);
    name = g_localName;
    ReleaseSRWLockShared(&g_socialLock);
    if (name[0] == '\0') {
        const auto& setting = core::settings::get().steam.user.personaName;
        const auto end = std::memchr(setting.data(), '\0', setting.size());
        const auto length = end == nullptr ? setting.size() - 1
                           : static_cast<std::size_t>(static_cast<const char*>(end) - setting.data());
        std::memcpy(name.data(), setting.data(), length);
        name[length] = '\0';
    }
    return name.data();
}
bool set_peer(const PeerProfile& profile) noexcept {
    const auto name = text_of(profile.name), connect = text_of(profile.connect), status = text_of(profile.status);
    if (!valid_id(profile.steamId) || !valid_text(name, kPersonaCapacity)
        || !valid_text(connect, kConnectCapacity, true) || !valid_text(status, kConnectCapacity, true)) { return false; }
    AcquireSRWLockExclusive(&g_socialLock);
    if (profile.steamId == g_localId) { ReleaseSRWLockExclusive(&g_socialLock); return false; }
    const bool samePeer = g_peer.steamId == profile.steamId;
    int changed = samePeer ? 0 : 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0200 | 0x4000;
    const bool presenceChanged = !samePeer || text_of(g_peer.connect) != connect || text_of(g_peer.status) != status;
    if (samePeer) {
        if (text_of(g_peer.name) != name) { changed |= 0x0001; }
        if (g_peer.gameRunning != profile.gameRunning) { changed |= 0x0002 | 0x0010; }
        if (g_peer.lobbyId != profile.lobbyId || g_peer.ipv4 != profile.ipv4 || g_peer.gamePort != profile.gamePort
            || g_peer.sameGameServer != profile.sameGameServer) { changed |= 0x0020; }
        if (presenceChanged) { changed |= 0x4000; }
    } else { g_invitation = {}; }
    g_peer = profile;
    assign(g_peer.name, name); assign(g_peer.connect, connect); assign(g_peer.status, status);
    g_notifyId = profile.steamId;
    g_notifyFlags = samePeer ? g_notifyFlags | changed : changed;
    g_presenceDirty = g_presenceDirty || presenceChanged;
    ReleaseSRWLockExclusive(&g_socialLock);
    return true;
}
bool peer_profile(PeerProfile& profile) noexcept {
    AcquireSRWLockShared(&g_socialLock); profile = g_peer; ReleaseSRWLockShared(&g_socialLock);
    return profile.steamId != 0;
}
void clear_peer() noexcept {
    AcquireSRWLockExclusive(&g_socialLock);
    if (g_peer.steamId != 0) { g_notifyId = g_peer.steamId; g_notifyFlags = 0x0002 | 0x0008 | 0x0010 | 0x0200 | 0x4000; }
    g_peer = {}; g_invitation = {}; g_presenceDirty = false;
    ReleaseSRWLockExclusive(&g_socialLock);
}
void set_invite_sender(InviteSender sender, void* context) noexcept {
    AcquireSRWLockExclusive(&g_socialLock); g_sender = sender; g_senderContext = context; ReleaseSRWLockExclusive(&g_socialLock);
}
bool send_invitation(std::uint64_t recipient, std::string_view connect) noexcept {
    if (!valid_text(connect, kConnectCapacity)) { return false; }
    AcquireSRWLockShared(&g_socialLock);
    const bool target = recipient != 0 && recipient == g_peer.steamId;
    const auto sender = g_sender; void* const context = g_senderContext;
    ReleaseSRWLockShared(&g_socialLock);
    return target && sender != nullptr && sender(context, recipient, connect);
}
bool receive_invitation(std::uint64_t from, std::string_view connect) noexcept {
    if (!valid_text(connect, kConnectCapacity)) { return false; }
    AcquireSRWLockExclusive(&g_socialLock);
    const bool accepted = from != 0 && from == g_peer.steamId;
    if (accepted) {
        if (++g_nextInvitation == 0) { ++g_nextInvitation; }
        g_invitation = {}; g_invitation.id = g_nextInvitation; g_invitation.from = from;
        assign(g_invitation.connect, connect);
    }
    ReleaseSRWLockExclusive(&g_socialLock);
    return accepted;
}
bool pending_invitation(PendingInvitation& invitation) noexcept {
    AcquireSRWLockShared(&g_socialLock); invitation = g_invitation; ReleaseSRWLockShared(&g_socialLock);
    return invitation.id != 0;
}
bool accept_invitation(std::uint64_t id) noexcept {
    AcquireSRWLockExclusive(&g_socialLock);
    bool accepted = false;
    if (id != 0 && id == g_invitation.id && g_invitation.from == g_peer.steamId) {
        const JoinRequested event{g_invitation.from, g_invitation.connect};
        accepted = queue_callback(kGameRichPresenceJoinRequested, 0, &event, sizeof event);
        if (accepted) { g_invitation = {}; }
    }
    ReleaseSRWLockExclusive(&g_socialLock);
    return accepted;
}
bool dismiss_invitation(std::uint64_t id) noexcept {
    AcquireSRWLockExclusive(&g_socialLock);
    const bool dismissed = id != 0 && id == g_invitation.id;
    if (dismissed) { g_invitation = {}; }
    ReleaseSRWLockExclusive(&g_socialLock);
    return dismissed;
}
bool local_presence(std::string_view key, std::array<char, kConnectCapacity>& value) noexcept {
    value = {};
    AcquireSRWLockShared(&g_socialLock);
    bool found = false;
    for (const auto& entry : g_localPresence) {
        if (entry.key[0] != '\0' && text_of(entry.key) == key) { value = entry.value; found = true; break; }
    }
    ReleaseSRWLockShared(&g_socialLock);
    return found;
}
void service() noexcept {
    AcquireSRWLockExclusive(&g_socialLock);
    if (g_notifyId != 0 && g_notifyFlags != 0) {
        const PersonaChange event{g_notifyId, g_notifyFlags, 0};
        if (queue_callback(kPersonaStateChanged, 0, &event, sizeof event)) { g_notifyFlags = 0; }
    }
    if (g_presenceDirty && g_peer.steamId != 0) {
        const PresenceChange event{g_peer.steamId, app_id(), 0};
        if (queue_callback(kFriendRichPresenceUpdated, 0, &event, sizeof event)) { g_presenceDirty = false; }
    }
    ReleaseSRWLockExclusive(&g_socialLock);
}
void reset() noexcept {
    AcquireSRWLockExclusive(&g_socialLock);
    g_localId = kLocalSteamId; g_localName = {}; g_peer = {}; g_invitation = {};
    g_sender = nullptr; g_senderContext = nullptr; g_localPresence = {};
    g_notifyId = 0; g_notifyFlags = 0; g_presenceDirty = false;
    // Do not reuse invitation IDs while an old UI event might still be queued.
    ReleaseSRWLockExclusive(&g_socialLock);
}

} // namespace dawn::steam::social

namespace dawn::steam::interfaces::methods {
namespace {
[[nodiscard]] bool steam_text(const char* value, std::size_t capacity, std::string_view& text) noexcept {
    if (value == nullptr) { return false; }
    std::size_t length{};
    while (length < capacity && value[length] != '\0') { ++length; }
    if (length == capacity) { return false; }
    text = {value, length}; return true;
}
} // namespace

const char* persona_name([[maybe_unused]] void* self) noexcept { return social::local_persona_name(); }
int persona_state([[maybe_unused]] void* self) noexcept { return 1; }
int get_friend_count([[maybe_unused]] void* self, int flags) noexcept {
    AcquireSRWLockShared(&social::g_socialLock);
    const int count = social::friend_flags(flags) ? 1 : 0;
    ReleaseSRWLockShared(&social::g_socialLock); return count;
}
SteamId* get_friend_by_index([[maybe_unused]] void* self, SteamId* output, int index, int flags) noexcept {
    if (output == nullptr) { return nullptr; }
    AcquireSRWLockShared(&social::g_socialLock);
    output->value = index == 0 && social::friend_flags(flags) ? social::g_peer.steamId : 0;
    ReleaseSRWLockShared(&social::g_socialLock); return output;
}
int get_friend_relationship([[maybe_unused]] void* self, std::uint64_t id) noexcept {
    social::PeerProfile profile;
    return social::peer_profile(profile) && profile.steamId == id ? 3 : 0;
}
int get_friend_persona_state([[maybe_unused]] void* self, std::uint64_t id) noexcept {
    if (id == social::local_steam_id()) { return 1; }
    social::PeerProfile profile;
    return social::peer_profile(profile) && profile.steamId == id ? 1 : 0;
}
const char* get_friend_persona_name([[maybe_unused]] void* self, std::uint64_t id) noexcept {
    if (id == social::local_steam_id()) { return social::local_persona_name(); }
    thread_local std::array<char, social::kPersonaCapacity> name{};
    social::PeerProfile profile;
    name = social::peer_profile(profile) && profile.steamId == id ? profile.name : decltype(name){};
    return name.data();
}
const char* get_friend_persona_name_history([[maybe_unused]] void* self,
                                           [[maybe_unused]] std::uint64_t id,
                                           [[maybe_unused]] int index) noexcept { return ""; }
bool get_friend_game_played([[maybe_unused]] void* self, std::uint64_t id, FriendGameInfo* output) noexcept {
    if (output == nullptr) { return false; }
    *output = {};
    social::PeerProfile profile;
    if (!social::peer_profile(profile) || profile.steamId != id || !profile.gameRunning) { return false; }
    *output = {app_id(), profile.ipv4, profile.gamePort, 0, profile.lobbyId}; return true;
}
bool has_friend([[maybe_unused]] void* self, std::uint64_t id, int flags) noexcept {
    AcquireSRWLockShared(&social::g_socialLock);
    const bool found = social::g_peer.steamId == id && social::friend_flags(flags);
    ReleaseSRWLockShared(&social::g_socialLock); return found;
}
/** Authenticated presence is already local; no asynchronous fetch is needed. */
bool request_user_information([[maybe_unused]] void* self, [[maybe_unused]] std::uint64_t id,
                              [[maybe_unused]] bool nameOnly) noexcept { return false; }
bool set_rich_presence([[maybe_unused]] void* self, const char* key, const char* value) noexcept {
    std::string_view keyText, valueText;
    if (!steam_text(key, social::kPresenceKeyCapacity, keyText)
        || !social::valid_text(keyText, social::kPresenceKeyCapacity)
        || (value != nullptr && (!steam_text(value, social::kConnectCapacity, valueText)
                                 || !social::valid_text(valueText, social::kConnectCapacity, true)))) { return false; }
    AcquireSRWLockExclusive(&social::g_socialLock);
    social::PresenceEntry* free{}; social::PresenceEntry* found{};
    for (auto& entry : social::g_localPresence) {
        if (entry.key[0] == '\0' && free == nullptr) { free = &entry; }
        if (entry.key[0] != '\0' && social::text_of(entry.key) == keyText) { found = &entry; }
    }
    bool accepted = true;
    if (value == nullptr || valueText.empty()) { if (found != nullptr) { *found = {}; } }
    else {
        social::PresenceEntry* const entry = found != nullptr ? found : free;
        accepted = entry != nullptr;
        if (entry != nullptr) { social::assign(entry->key, keyText); social::assign(entry->value, valueText); }
    }
    ReleaseSRWLockExclusive(&social::g_socialLock); return accepted;
}
void clear_rich_presence([[maybe_unused]] void* self) noexcept {
    AcquireSRWLockExclusive(&social::g_socialLock); social::g_localPresence = {}; ReleaseSRWLockExclusive(&social::g_socialLock);
}
const char* get_friend_rich_presence([[maybe_unused]] void* self, std::uint64_t id, const char* key) noexcept {
    thread_local std::array<char, social::kConnectCapacity> text{};
    text = {}; std::string_view keyText;
    if (!steam_text(key, social::kPresenceKeyCapacity, keyText)) { return text.data(); }
    if (id == social::local_steam_id()) { (void)social::local_presence(keyText, text); return text.data(); }
    social::PeerProfile profile;
    if (social::peer_profile(profile) && profile.steamId == id) {
        if (keyText == "connect") { text = profile.connect; }
        else if (keyText == "status") { text = profile.status; }
    }
    return text.data();
}
int get_friend_rich_presence_key_count([[maybe_unused]] void* self, std::uint64_t id) noexcept {
    if (id == social::local_steam_id()) {
        int count{};
        AcquireSRWLockShared(&social::g_socialLock);
        for (const auto& entry : social::g_localPresence) { if (entry.key[0] != '\0') { ++count; } }
        ReleaseSRWLockShared(&social::g_socialLock);
        return count;
    }
    social::PeerProfile profile;
    if (!social::peer_profile(profile) || profile.steamId != id) { return 0; }
    return (profile.connect[0] != '\0' ? 1 : 0) + (profile.status[0] != '\0' ? 1 : 0);
}
const char* get_friend_rich_presence_key_by_index([[maybe_unused]] void* self, std::uint64_t id, int index) noexcept {
    if (index < 0) { return ""; }
    if (id == social::local_steam_id()) {
        thread_local std::array<char, social::kPresenceKeyCapacity> key{};
        key = {};
        AcquireSRWLockShared(&social::g_socialLock);
        for (const auto& entry : social::g_localPresence) {
            if (entry.key[0] != '\0') { if (index-- == 0) { key = entry.key; break; } }
        }
        ReleaseSRWLockShared(&social::g_socialLock);
        return key.data();
    }
    social::PeerProfile profile;
    if (!social::peer_profile(profile) || profile.steamId != id) { return ""; }
    if (profile.connect[0] != '\0') { if (index == 0) { return "connect"; } --index; }
    return profile.status[0] != '\0' && index == 0 ? "status" : "";
}
void request_friend_rich_presence([[maybe_unused]] void* self, std::uint64_t id) noexcept {
    AcquireSRWLockExclusive(&social::g_socialLock);
    if (social::g_peer.steamId != 0 && social::g_peer.steamId == id) { social::g_presenceDirty = true; }
    ReleaseSRWLockExclusive(&social::g_socialLock);
}
bool invite_user_to_game([[maybe_unused]] void* self, std::uint64_t id, const char* connect) noexcept {
    std::string_view text;
    return steam_text(connect, social::kConnectCapacity, text) && social::send_invitation(id, text);
}

} // namespace dawn::steam::interfaces::methods
