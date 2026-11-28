#pragma once
#include <array>
#include <cstdint>
#include <string_view>

namespace dawn::core::multiplayer {

struct InvitationPreflightObservation;
struct WorldProbeEvent;

/**
 * Optional authenticated launcher IPC; absent configuration keeps direct solo launch.
 * Protocol3 child pair/peer pins, when supplied together, must match WELCOME before publication.
 */
[[nodiscard]] bool initialize() noexcept;
/** Polls bounded local IPC work and optionally copies the one-shot private trace receipt. */
void service(std::uint64_t now, InvitationPreflightObservation* traced = nullptr,
             WorldProbeEvent* world = nullptr) noexcept;
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
/** Rechecks the private trace receipt and its current accepted intent after local observation. */
[[nodiscard]] bool validate_traced_invitation_preflight(const InvitationPreflightObservation& observed) noexcept;

/** Public destination selectors. No native handles or private player identity. */
struct WorldDestination {
    std::array<char, 41> package{};
    std::int32_t activity{-1}, region{-1};
    friend constexpr bool operator==(const WorldDestination&, const WorldDestination&) noexcept = default;
};

struct WorldProbeToken {
    std::array<char, 33> ticket{}, nonce{};
    friend constexpr bool operator==(const WorldProbeToken&, const WorldProbeToken&) noexcept = default;
};

enum class WorldProbeKind : std::uint8_t { none, request, ready, unavailable };
inline constexpr std::uint64_t kWorldProbeTimeoutMs = 5'000;

struct WorldProbeEvent {
    WorldProbeKind kind{};
    WorldProbeToken token{};
    WorldDestination destination{};
    std::uint64_t generation{}, deadline{};
    friend constexpr bool operator==(const WorldProbeEvent&, const WorldProbeEvent&) noexcept = default;
};

/** Asks the invite recipient to verify its own world, through the opt-in protected bridge. */
[[nodiscard]] bool request_world_probe(const InvitationPreflightObservation& invitation,
                                      const WorldDestination& destination, WorldProbeToken& output) noexcept;
/** Responds once to a copied request for the guest's still-current accepted invite. */
[[nodiscard]] bool respond_world_probe(const WorldProbeEvent& request, bool ready) noexcept;

} // namespace dawn::core::multiplayer
