#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"
#include "../internal.h"
#include "../../runtime/social.h"

namespace dawn::steam::interfaces::methods {
namespace {

/** Steam callback id for a finished lobby entry. */
constexpr int kLobbyEnterCallback = 504;
/** Steam callback id announcing that lobby or member metadata is ready. */
constexpr int kLobbyDataUpdateCallback = 505;
/** Steam callback id for a finished lobby creation. */
constexpr int kLobbyCreatedCallback = 513;
/** Steam result code for success. */
constexpr int kResultOk = 1;
/** Steam lobby-entry response for a successful join. */
constexpr DWORD kLobbyEnterSuccess = 1;
/** Made-up lobby ids use Steam's chat-lobby account-type prefix. */
constexpr std::uint64_t kLobbySteamIdPrefix = 0x0109000000000000ULL;
/** Padding aligns the response field after the one-byte lock flag. */
constexpr std::size_t kLobbyLockPadding = 3;
/** Steam's lobby-entry callback is 24 bytes. */
constexpr std::size_t kLobbyEnterSize = 24;
/** Steam's lobby-created callback is 16 bytes. */
constexpr std::size_t kLobbyCreatedSize = 16;
/** Steam's lobby-data-update callback is 24 bytes after native alignment. */
constexpr std::size_t kLobbyDataUpdateSize = 24;
/** A bounded local process never needs more simultaneous managed-session lobbies than this. */
constexpr std::size_t kLobbyCapacity = 32;
/** Metadata entries retained per lobby. */
constexpr std::size_t kLobbyDataCapacity = 16;
/** Steam lobby keys are at most 255 bytes, plus the terminator. */
constexpr std::size_t kLobbyDataKeyCapacity = 256;
/** Steam lobby metadata values are at most 8192 bytes, plus the terminator. */
constexpr std::size_t kLobbyDataValueCapacity = 8193;
/** The embedded group host needs a non-local owner identity when the client joins its lobby. */
constexpr std::uint64_t kEmbeddedHostSteamId = kLocalSteamId + 1;

/** Steam lobby-entry callback payload layout. */
struct LobbyEnter {
    std::uint64_t lobby{};
    DWORD permissions{};
    bool locked{};
    std::array<std::byte, kLobbyLockPadding> padding{};
    DWORD response{};
};

/** Steam lobby-created callback payload layout. */
struct LobbyCreated {
    int result{};
    DWORD padding{};
    std::uint64_t lobby{};
};

/** Payload of LobbyDataUpdate_t. */
struct LobbyDataUpdate {
    std::uint64_t lobby{};
    std::uint64_t member{};
    std::uint8_t success{};
    std::array<std::byte, 7> padding{};
};

/** One textual Steam lobby metadata entry. */
struct LobbyDataEntry {
    std::array<char, kLobbyDataKeyCapacity> key{};
    std::array<char, kLobbyDataValueCapacity> value{};
    bool occupied{};
};

static_assert(sizeof(LobbyEnter) == kLobbyEnterSize);
static_assert(sizeof(LobbyCreated) == kLobbyCreatedSize);
static_assert(sizeof(LobbyDataUpdate) == kLobbyDataUpdateSize);

/** Minimal lobby membership retained for host-migration ownership queries. */
struct LobbyState {
    std::uint64_t id{};
    std::uint64_t owner{};
    bool joined{};
    bool occupied{};
    std::array<LobbyDataEntry, kLobbyDataCapacity> data{};
    std::array<LobbyDataEntry, kLobbyDataCapacity> localMemberData{};
};

SRWLOCK g_lobbyLock{SRWLOCK_INIT};
std::array<LobbyState, kLobbyCapacity> g_lobbies{};

/** @return Lobby state for an id, or null. The caller holds the lobby lock. */
[[nodiscard]] LobbyState* find_lobby_locked(std::uint64_t lobby) noexcept {
    for (LobbyState& entry : g_lobbies) {
        if (entry.occupied && entry.id == lobby) {
            return &entry;
        }
    }
    return nullptr;
}

/** Finds or creates local state for one nonzero lobby. The caller holds the lobby lock. */
[[nodiscard]] LobbyState* claim_lobby_locked(std::uint64_t lobby) noexcept {
    if (lobby == 0) {
        return nullptr;
    }
    if (LobbyState* const existing = find_lobby_locked(lobby); existing != nullptr) {
        return existing;
    }
    for (LobbyState& entry : g_lobbies) {
        if (!entry.occupied) {
            entry.occupied = true;
            entry.id = lobby;
            return &entry;
        }
    }
    return nullptr;
}

/** @return Metadata entry for one key, or null. The caller holds the lobby lock. */
[[nodiscard]] LobbyDataEntry* find_data_locked(
    std::array<LobbyDataEntry, kLobbyDataCapacity>& entries,
    const char* key) noexcept {
    if (key == nullptr || *key == '\0') {
        return nullptr;
    }
    for (LobbyDataEntry& entry : entries) {
        if (entry.occupied && std::strcmp(entry.key.data(), key) == 0) {
            return &entry;
        }
    }
    return nullptr;
}

/** Finds or creates a bounded metadata entry. The caller holds the lobby lock. */
[[nodiscard]] LobbyDataEntry* claim_data_locked(
    std::array<LobbyDataEntry, kLobbyDataCapacity>& entries,
    const char* key) noexcept {
    if (LobbyDataEntry* const existing = find_data_locked(entries, key); existing != nullptr) {
        return existing;
    }
    if (key == nullptr) {
        return nullptr;
    }
    const std::size_t keyLength = std::strlen(key);
    if (keyLength == 0 || keyLength >= kLobbyDataKeyCapacity) {
        return nullptr;
    }
    for (LobbyDataEntry& entry : entries) {
        if (!entry.occupied) {
            std::memcpy(entry.key.data(), key, keyLength + 1U);
            entry.value[0] = '\0';
            entry.occupied = true;
            return &entry;
        }
    }
    return nullptr;
}

/** Copies one nul-terminated Steam string into a caller-owned bounded buffer. */
[[nodiscard]] bool copy_out(const char* source, char* destination, int capacity) noexcept {
    if (source == nullptr || destination == nullptr || capacity <= 0) {
        return false;
    }
    const std::size_t length = std::strlen(source);
    if (length >= static_cast<std::size_t>(capacity)) {
        destination[0] = '\0';
        return false;
    }
    std::memcpy(destination, source, length + 1U);
    return true;
}

/** Queues Steam's metadata-ready notification for a lobby or one of its members. */
[[nodiscard]] bool queue_lobby_data_update(std::uint64_t lobby,
                                           std::uint64_t member) noexcept {
    const LobbyDataUpdate update{lobby, member, 1, {}};
    return queue_callback(kLobbyDataUpdateCallback, 0, &update, sizeof(update));
}

/** Emits one bounded metadata-contract diagnostic. */
void report_lobby_data(const char* action,
                       std::uint64_t lobby,
                       std::uint64_t member,
                       const char* key,
                       const char* value,
                       bool result) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=steam stage=lobby_data action=%s result=%s lobby=0x%016llX member=0x%016llX key=%.96s value=%.160s",
        action,
        result ? "ok" : "miss",
        static_cast<unsigned long long>(lobby),
        static_cast<unsigned long long>(member),
        key == nullptr ? "" : key,
        value == nullptr ? "" : value);
    if (written <= 0) {
        return;
    }
    const std::size_t length =
        (std::min)(static_cast<std::size_t>(written), line.size() - 1U);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     {line.data(), length});
}

/** Records one successful create or join without changing an already known owner. */
[[nodiscard]] bool retain_lobby(std::uint64_t lobby, std::uint64_t defaultOwner) noexcept {
    AcquireSRWLockExclusive(&g_lobbyLock);
    LobbyState* const entry = claim_lobby_locked(lobby);
    if (entry != nullptr) {
        if (entry->owner == 0) {
            entry->owner = defaultOwner;
        }
        entry->joined = true;
    }
    ReleaseSRWLockExclusive(&g_lobbyLock);
    return entry != nullptr;
}

/** Emits one bounded lobby-state diagnostic. */
void report_lobby(const char* action,
                  std::uint64_t lobby,
                  std::uint64_t owner,
                  bool result) noexcept {
    std::array<char, core::log::kLineCapacity> line{};
    const int written = std::snprintf(
        line.data(),
        line.size(),
        "ev=steam stage=lobby action=%s result=%s lobby=0x%016llX owner=0x%016llX",
        action,
        result ? "ok" : "fail",
        static_cast<unsigned long long>(lobby),
        static_cast<unsigned long long>(owner));
    if (written <= 0) {
        return;
    }
    const std::size_t length =
        (std::min)(static_cast<std::size_t>(written), line.size() - 1U);
    core::log::write(core::log::Channel::client,
                     core::log::Level::info,
                     {line.data(), length});
}

} // namespace

/**
 * Makes up a lobby, then queues the created and entered callbacks.
 * @return API call id, or zero when either callback cannot be queued.
 */
ApiCall create_lobby([[maybe_unused]] void* self,
                     [[maybe_unused]] int lobbyType,
                     [[maybe_unused]] int maxMembers) noexcept {
    const ApiCall call = next_api_call();
    const std::uint64_t lobby = kLobbySteamIdPrefix | call;
    const LobbyCreated created{kResultOk, 0, lobby};
    const LobbyEnter entered{lobby, 0, false, {}, kLobbyEnterSuccess};
    if (!queue_callback(kLobbyCreatedCallback, call, &created, sizeof(created))) {
        return 0;
    }
    // Entry follows creation, so a reader sees a valid lobby first.
    if (!queue_callback(kLobbyEnterCallback, 0, &entered, sizeof(entered))) {
        return 0;
    }
    const bool retained = retain_lobby(lobby, social::local_steam_id());
    report_lobby("create", lobby, social::local_steam_id(), retained);
    const bool notified = retained && queue_lobby_data_update(lobby, lobby);
    report_lobby_data("create_update", lobby, lobby, "", "", notified);
    return notified ? call : 0;
}

/**
 * Queues a successful entry for an existing nonzero lobby.
 * @return API call id, or zero when the lobby id is zero or the queue is full.
 */
ApiCall join_lobby([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    if (lobby == 0) {
        return 0;
    }
    const ApiCall call = next_api_call();
    const LobbyEnter entered{lobby, 0, false, {}, kLobbyEnterSuccess};
    if (!queue_callback(kLobbyEnterCallback, call, &entered, sizeof(entered))) {
        return 0;
    }
    const bool retained = retain_lobby(lobby, kEmbeddedHostSteamId);
    report_lobby("join", lobby, kEmbeddedHostSteamId, retained);
    const bool notified = retained && queue_lobby_data_update(lobby, lobby);
    report_lobby_data("join_update", lobby, lobby, "", "", notified);
    return notified ? call : 0;
}

/** Leaves one known lobby while retaining its owner for a later migration query. */
void leave_lobby([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    AcquireSRWLockExclusive(&g_lobbyLock);
    LobbyState* const entry = find_lobby_locked(lobby);
    if (entry != nullptr) {
        entry->joined = false;
    }
    const std::uint64_t owner = entry == nullptr ? 0 : entry->owner;
    ReleaseSRWLockExclusive(&g_lobbyLock);
    report_lobby("leave", lobby, owner, entry != nullptr);
}

/** @return One local member, plus the emulated host when it is a different identity. */
int get_num_lobby_members([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    AcquireSRWLockShared(&g_lobbyLock);
    const LobbyState* const entry = find_lobby_locked(lobby);
    const int count = entry == nullptr || !entry->joined ? 0 : entry->owner == social::local_steam_id() ? 1 : 2;
    const std::uint64_t owner = entry == nullptr ? 0 : entry->owner;
    ReleaseSRWLockShared(&g_lobbyLock);
    report_lobby("member_count", lobby, owner, count != 0);
    return count;
}

/** Returns the retained owner first and the local user second for an emulated remote lobby. */
SteamId* get_lobby_member_by_index([[maybe_unused]] void* self,
                                   SteamId* result,
                                   std::uint64_t lobby,
                                   int memberIndex) noexcept {
    std::uint64_t member = 0;
    AcquireSRWLockShared(&g_lobbyLock);
    const LobbyState* const entry = find_lobby_locked(lobby);
    if (entry != nullptr && entry->joined) {
        if (memberIndex == 0) {
            member = entry->owner;
        }
        else if (memberIndex == 1 && entry->owner != social::local_steam_id()) {
            member = social::local_steam_id();
        }
    }
    ReleaseSRWLockShared(&g_lobbyLock);
    if (result != nullptr) {
        result->value = member;
    }
    report_lobby("member", lobby, member, member != 0);
    return result;
}

/** @return A stable lobby metadata value, or an empty string when absent. */
const char* get_lobby_data([[maybe_unused]] void* self,
                           std::uint64_t lobby,
                           const char* key) noexcept {
    static constexpr char kEmpty[] = "";
    const char* value = kEmpty;
    AcquireSRWLockShared(&g_lobbyLock);
    LobbyState* const state = find_lobby_locked(lobby);
    LobbyDataEntry* const entry =
        state == nullptr ? nullptr : find_data_locked(state->data, key);
    if (entry != nullptr) {
        value = entry->value.data();
    }
    ReleaseSRWLockShared(&g_lobbyLock);
    report_lobby_data("get", lobby, lobby, key, value, entry != nullptr);
    return value;
}

/** Stores one owner-authored lobby metadata value and announces the update. */
bool set_lobby_data([[maybe_unused]] void* self,
                    std::uint64_t lobby,
                    const char* key,
                    const char* value) noexcept {
    const std::size_t valueLength =
        value == nullptr ? kLobbyDataValueCapacity : std::strlen(value);
    bool updated = false;
    AcquireSRWLockExclusive(&g_lobbyLock);
    LobbyState* const state = find_lobby_locked(lobby);
    if (state != nullptr && state->joined && state->owner == social::local_steam_id() &&
        valueLength < kLobbyDataValueCapacity) {
        LobbyDataEntry* const entry = claim_data_locked(state->data, key);
        if (entry != nullptr) {
            std::memcpy(entry->value.data(), value, valueLength + 1U);
            updated = true;
        }
    }
    ReleaseSRWLockExclusive(&g_lobbyLock);
    const bool notified = updated && queue_lobby_data_update(lobby, lobby);
    report_lobby_data("set", lobby, lobby, key, value, updated && notified);
    return updated;
}

/** @return Number of occupied lobby metadata entries. */
int get_lobby_data_count([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    int count = 0;
    AcquireSRWLockShared(&g_lobbyLock);
    const LobbyState* const state = find_lobby_locked(lobby);
    if (state != nullptr) {
        for (const LobbyDataEntry& entry : state->data) {
            count += entry.occupied ? 1 : 0;
        }
    }
    ReleaseSRWLockShared(&g_lobbyLock);
    report_lobby_data("count", lobby, lobby, "", "", state != nullptr);
    return count;
}

/** Enumerates occupied lobby metadata in stable insertion order. */
bool get_lobby_data_by_index([[maybe_unused]] void* self,
                             std::uint64_t lobby,
                             int metadataIndex,
                             char* key,
                             int keyCapacity,
                             char* value,
                             int valueCapacity) noexcept {
    bool copied = false;
    const char* loggedKey = "";
    const char* loggedValue = "";
    AcquireSRWLockShared(&g_lobbyLock);
    LobbyState* const state = find_lobby_locked(lobby);
    int currentIndex = 0;
    if (state != nullptr && metadataIndex >= 0) {
        for (LobbyDataEntry& entry : state->data) {
            if (!entry.occupied) {
                continue;
            }
            if (currentIndex == metadataIndex) {
                loggedKey = entry.key.data();
                loggedValue = entry.value.data();
                copied = copy_out(loggedKey, key, keyCapacity) &&
                         copy_out(loggedValue, value, valueCapacity);
                break;
            }
            ++currentIndex;
        }
    }
    ReleaseSRWLockShared(&g_lobbyLock);
    report_lobby_data("enumerate", lobby, lobby, loggedKey, loggedValue, copied);
    return copied;
}

/** Deletes one owner-authored lobby metadata key and announces the update. */
bool delete_lobby_data([[maybe_unused]] void* self,
                       std::uint64_t lobby,
                       const char* key) noexcept {
    bool removed = false;
    AcquireSRWLockExclusive(&g_lobbyLock);
    LobbyState* const state = find_lobby_locked(lobby);
    LobbyDataEntry* const entry =
        state == nullptr ? nullptr : find_data_locked(state->data, key);
    if (state != nullptr && state->joined && state->owner == social::local_steam_id() && entry != nullptr) {
        *entry = {};
        removed = true;
    }
    ReleaseSRWLockExclusive(&g_lobbyLock);
    const bool notified = removed && queue_lobby_data_update(lobby, lobby);
    report_lobby_data("delete", lobby, lobby, key, "", removed && notified);
    return removed;
}

/** @return Local member metadata, or an empty string for absent/remote data. */
const char* get_lobby_member_data([[maybe_unused]] void* self,
                                  std::uint64_t lobby,
                                  std::uint64_t member,
                                  const char* key) noexcept {
    static constexpr char kEmpty[] = "";
    const char* value = kEmpty;
    LobbyDataEntry* entry = nullptr;
    AcquireSRWLockShared(&g_lobbyLock);
    LobbyState* const state = find_lobby_locked(lobby);
    if (state != nullptr && state->joined && member == social::local_steam_id()) {
        entry = find_data_locked(state->localMemberData, key);
        if (entry != nullptr) {
            value = entry->value.data();
        }
    }
    ReleaseSRWLockShared(&g_lobbyLock);
    report_lobby_data("member_get", lobby, member, key, value, entry != nullptr);
    return value;
}

/** Stores local member metadata and announces the member-specific update. */
void set_lobby_member_data([[maybe_unused]] void* self,
                           std::uint64_t lobby,
                           const char* key,
                           const char* value) noexcept {
    const std::size_t valueLength =
        value == nullptr ? kLobbyDataValueCapacity : std::strlen(value);
    bool updated = false;
    AcquireSRWLockExclusive(&g_lobbyLock);
    LobbyState* const state = find_lobby_locked(lobby);
    if (state != nullptr && state->joined && valueLength < kLobbyDataValueCapacity) {
        LobbyDataEntry* const entry = claim_data_locked(state->localMemberData, key);
        if (entry != nullptr) {
            std::memcpy(entry->value.data(), value, valueLength + 1U);
            updated = true;
        }
    }
    ReleaseSRWLockExclusive(&g_lobbyLock);
    const bool notified = updated && queue_lobby_data_update(lobby, social::local_steam_id());
    report_lobby_data("member_set", lobby, social::local_steam_id(), key, value, updated && notified);
}

/** Drops a lobby chat payload. Nothing is kept. @return True for a size of zero or more. */
bool send_lobby_chat([[maybe_unused]] void* self,
                     [[maybe_unused]] std::uint64_t lobby,
                     [[maybe_unused]] const void* data,
                     int size) noexcept {
    return size >= 0;
}

/** @return Zero. The shim keeps no lobby chat history. */
int get_lobby_chat_entry([[maybe_unused]] void* self,
                         [[maybe_unused]] std::uint64_t lobby,
                         [[maybe_unused]] int messageIndex,
                         [[maybe_unused]] std::uint64_t* sender,
                         [[maybe_unused]] void* data,
                         [[maybe_unused]] int dataCapacity,
                         [[maybe_unused]] int* entryType) noexcept {
    return 0;
}

/** Re-announces that retained metadata for a joined lobby is ready. */
bool request_lobby_data([[maybe_unused]] void* self, std::uint64_t lobby) noexcept {
    AcquireSRWLockShared(&g_lobbyLock);
    const LobbyState* const state = find_lobby_locked(lobby);
    const bool present = state != nullptr && state->joined;
    ReleaseSRWLockShared(&g_lobbyLock);
    const bool queued = present && queue_lobby_data_update(lobby, lobby);
    report_lobby_data("request", lobby, lobby, "", "", queued);
    return queued;
}

/** Returns a stable owner for every lobby this process created or joined. */
SteamId* get_lobby_owner([[maybe_unused]] void* self,
                         SteamId* result,
                         std::uint64_t lobby) noexcept {
    AcquireSRWLockShared(&g_lobbyLock);
    const LobbyState* const entry = find_lobby_locked(lobby);
    const std::uint64_t owner = entry == nullptr || !entry->joined ? 0 : entry->owner;
    ReleaseSRWLockShared(&g_lobbyLock);
    if (result != nullptr) {
        result->value = owner;
    }
    report_lobby("owner_get", lobby, owner, owner != 0);
    return result;
}

/** Transfers ownership between the two identities represented in this local lobby. */
bool set_lobby_owner([[maybe_unused]] void* self,
                     std::uint64_t lobby,
                     std::uint64_t newOwner) noexcept {
    AcquireSRWLockExclusive(&g_lobbyLock);
    LobbyState* const entry = find_lobby_locked(lobby);
    const bool changed = entry != nullptr && entry->joined && newOwner != 0;
    if (changed) {
        entry->owner = newOwner;
    }
    ReleaseSRWLockExclusive(&g_lobbyLock);
    report_lobby("owner_set", lobby, newOwner, changed);
    return changed;
}

} // namespace dawn::steam::interfaces::methods
