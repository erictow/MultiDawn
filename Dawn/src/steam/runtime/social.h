#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace dawn::steam::social {

inline constexpr std::size_t kPersonaCapacity = 128;
inline constexpr std::size_t kConnectCapacity = 256;
inline constexpr std::size_t kPresenceKeyCapacity = 64;
inline constexpr std::size_t kPresenceCapacity = 30;

/** Authenticated remote player's current native-game presence, supplied by the session bridge. */
struct PeerProfile {
    std::uint64_t steamId{};
    std::array<char, kPersonaCapacity> name{};
    std::array<char, kConnectCapacity> connect{};
    std::array<char, kConnectCapacity> status{};
    std::uint64_t lobbyId{};
    /** IPv4 address in host byte order, matching FriendGameInfo_t. */
    std::uint32_t ipv4{};
    std::uint16_t gamePort{};
    bool gameRunning{};
    /** True only after native authority confirms both players use the same game server. */
    bool sameGameServer{};
};

/** A pending request is delivered to the game only after this exact invitation is accepted. */
struct PendingInvitation {
    std::uint64_t id{};
    std::uint64_t from{};
    std::array<char, kConnectCapacity> connect{};
};

/** Called outside the social lock. True means the authenticated transport accepted the request. */
using InviteSender = bool (*)(void*, std::uint64_t, std::string_view) noexcept;

/** Configure identity before the game first asks SteamUser for its Steam ID. */
[[nodiscard]] bool set_local_identity(std::uint64_t id, std::string_view name) noexcept;
[[nodiscard]] std::uint64_t local_steam_id() noexcept;
/** Thread-local copied name; valid until the next name lookup on that thread. */
[[nodiscard]] const char* local_persona_name() noexcept;

/** Only the authenticated native session bridge may publish a connected peer. */
[[nodiscard]] bool set_peer(const PeerProfile& profile) noexcept;
[[nodiscard]] bool peer_profile(PeerProfile& profile) noexcept;
void clear_peer() noexcept;

/** The sender/context must remain valid until all in-flight send calls have returned. */
void set_invite_sender(InviteSender sender, void* context) noexcept;
[[nodiscard]] bool send_invitation(std::uint64_t recipient, std::string_view connect) noexcept;
[[nodiscard]] bool receive_invitation(std::uint64_t from, std::string_view connect) noexcept;
[[nodiscard]] bool pending_invitation(PendingInvitation& invitation) noexcept;
[[nodiscard]] bool accept_invitation(std::uint64_t id) noexcept;
[[nodiscard]] bool dismiss_invitation(std::uint64_t id) noexcept;

/** Copy a locally authored presence key for publication over the authenticated bridge. */
[[nodiscard]] bool local_presence(std::string_view key,
                                   std::array<char, kConnectCapacity>& value) noexcept;
/** Retry deferred persona/presence callbacks before each Steam callback batch. */
void service() noexcept;
/** Runtime shutdown only; clears the remote peer, sender, pending invite, and session identity. */
void reset() noexcept;

} // namespace dawn::steam::social
