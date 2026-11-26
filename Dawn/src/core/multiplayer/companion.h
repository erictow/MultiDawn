#pragma once
#include <array>
#include <cstdint>
#include <string_view>

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

/** Fresh launcher observation only. It grants no account, route or gameplay permission. */
struct InvitationPreflightObservation {
    std::uint64_t peerSteamId{}, pairGeneration{}, companionGeneration{}, requestGeneration{}, deadline{};
    std::array<char, 33> ticket{}, localEpoch{}, peerEpoch{};
    friend constexpr bool operator==(const InvitationPreflightObservation&,
                                     const InvitationPreflightObservation&) noexcept = default;
};

/** Protocol3 only: queries one exact ticket without consuming the accepted-intent mailbox. */
[[nodiscard]] bool request_invitation_preflight(std::uint64_t peer, std::string_view ticket) noexcept;
/** Takes a current unexpired observation once. Later use must revalidate its local lifetime. */
[[nodiscard]] bool take_invitation_preflight(InvitationPreflightObservation& output) noexcept;
/** Rechecks current local pipe/epochs and revocation; not a fresh launcher requery or lease. */
[[nodiscard]] bool validate_invitation_preflight(const InvitationPreflightObservation& observed) noexcept;

} // namespace dawn::core::multiplayer
