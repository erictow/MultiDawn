#pragma once
#include <array>
#include <cstdint>

namespace dawn::core::multiplayer {

/** Optional, authenticated launcher IPC. An absent configuration keeps direct solo launch. */
[[nodiscard]] bool initialize() noexcept;
/** Polls bounded local IPC work; never opens the existing account backend to a remote PC. */
void service(std::uint64_t now) noexcept;
void shutdown() noexcept;
[[nodiscard]] bool connected() noexcept;
/** True only when both current runtimes support ticketed intent exchange, not gameplay joining. */
[[nodiscard]] bool invitation_intents_ready() noexcept;

/** User intent reported by the authenticated launcher; this grants no gameplay access. */
struct AcceptedInvitationIntent {
    std::uint64_t peerSteamId{};
    std::array<char, 33> ticket{};
    std::uint64_t deadline{};
};

/** Takes the current unexpired intent once; no account, group or endpoint is authorized. */
[[nodiscard]] bool take_accepted_invitation(AcceptedInvitationIntent& output) noexcept;

} // namespace dawn::core::multiplayer
