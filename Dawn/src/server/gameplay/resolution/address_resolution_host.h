#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../state/activity/lifecycle_generation.h"
#include "../../../state/gameplay/definition.h"

namespace dawn::server::gameplay::resolution {

enum class PacketResult : std::uint8_t { notRouted, rejected, complete };

struct Statistics {
    std::size_t live{};
    std::uint64_t created{}, opened{}, rejected{}, replayed{}, wrapped{};
};

/** One resolver context lifetime, scoped to its exact BAP authentication lifetime. */
struct RouteHandle {
    state::activity::AuthenticationKey owner{};
    std::uint64_t generation{};

    [[nodiscard]] explicit constexpr operator bool() const noexcept {
        return static_cast<bool>(owner) && generation != 0;
    }
    friend constexpr bool operator==(RouteHandle, RouteHandle) noexcept = default;
};

/** Internal per-human address registration; never a remote credential or player grant. */
struct PeerAddressHandle {
    state::activity::AuthenticationKey owner{};
    std::uint64_t generation{};

    [[nodiscard]] explicit constexpr operator bool() const noexcept {
        return static_cast<bool>(owner) && generation != 0;
    }
    friend constexpr bool operator==(PeerAddressHandle, PeerAddressHandle) noexcept = default;
};

enum class RoutePurpose : std::uint8_t { control, human };

/** Public routing identity only. Contains no resolver keys, tokens or account data. */
struct AuthenticatedRoute {
    RouteHandle handle{};
    state::gameplay::Endpoint source{};
    RoutePurpose purpose{RoutePurpose::control};
    PeerAddressHandle peerAddress{};
};

/** Explicit development opt-in, cached for this loaded DLL's lifetime. */
[[nodiscard]] bool enabled() noexcept;

/**
 * Registers one exact 86-byte canonical direct-method address (unicast IPv4 and
 * nonzero even port) for an internal human
 * routing consumer. Requires explicit native-resolution opt-in and embedded topology.
 * Colliding control/peer address bodies and duplicate registrations are refused.
 * Failure clears output. A trusted caller must separately validate its gameplay grant
 * and retire this registration on revocation; no social/companion RPC exposes this API.
 */
[[nodiscard]] bool register_peer_address(state::activity::AuthenticationKey owner,
                                         std::span<const std::byte> exactAddress,
                                         PeerAddressHandle& output) noexcept;

/** Retires only this registration and all its contexts, preserving control/sibling routes. */
[[nodiscard]] bool revoke_peer_address(PeerAddressHandle registered) noexcept;

/** Verifies this exact current registration and complete NetAddr without retaining a lease. */
[[nodiscard]] bool validate_peer_address(PeerAddressHandle registered,
                                         std::span<const std::byte> exactAddress) noexcept;

/**
 * Answers BAP300 for the configured embedded method-0 control endpoint or an exact
 * registered peer address owned by this authentication. Material remains local and
 * belongs to this exact BAP authentication lifetime. No account data is shared.
 */
[[nodiscard]] bool resolve_address(state::activity::AuthenticationKey owner,
                                    std::span<const std::byte> request,
                                    std::span<std::byte> response,
                                    std::size_t& written) noexcept;

/** Authenticates, pins the sender endpoint, then commits replay state. */
[[nodiscard]] PacketResult unwrap(const state::gameplay::Endpoint& source,
                                  std::span<const std::byte> packet,
                                  std::span<std::byte> plaintext,
                                  std::size_t& written) noexcept;

/**
 * Also returns the exact context that authenticated this packet. Failure clears matched;
 * success contains its owner, context generation, pinned source, purpose and local
 * peer-registration handle. A different
 * context using the same source endpoint cannot replace this packet's routing identity.
 */
[[nodiscard]] PacketResult unwrap(const state::gameplay::Endpoint& source,
                                  std::span<const std::byte> packet,
                                  std::span<std::byte> plaintext,
                                  std::size_t& written,
                                  AuthenticatedRoute& matched) noexcept;

/**
 * Uses the destination's most recently authenticated control route; consumes each IV
 * once. A human-only destination is rejected so a caller cannot fall back to raw UDP.
 */
[[nodiscard]] PacketResult wrap(const state::gameplay::Endpoint& destination,
                                std::span<const std::byte> plaintext,
                                std::span<std::byte> packet,
                                std::size_t& written) noexcept;

/**
 * Seals with this exact still-live bound context, even when another context is the
 * endpoint's most recently heard route. Invalid/stale ownership, generation, source,
 * purpose or peer registration
 * is rejected without falling back. IV state is shared with the endpoint-based wrapper.
 * This selects an authenticated transport context; it grants no human/gameplay admission.
 */
[[nodiscard]] PacketResult wrap_authenticated_route(const AuthenticatedRoute& route,
                                                    std::span<const std::byte> plaintext,
                                                    std::span<std::byte> packet,
                                                    std::size_t& written) noexcept;

/**
 * Observes this owner's currently selected authenticated control route. Unbound contexts
 * and routes superseded for the same owner or endpoint are unavailable. Failure
 * clears output. This observation grants no admission or gameplay authorization.
 */
[[nodiscard]] bool lookup_authenticated_route(state::activity::AuthenticationKey owner,
                                             AuthenticatedRoute& output) noexcept;

/**
 * Observes the sole selected control route across the supplied exact authentication owners.
 * The caller proves owner eligibility. Each distinct current endpoint counts separately,
 * and multiple matches clear output even when they have the same owner.
 */
[[nodiscard]] bool lookup_unique_authenticated_route(
    std::span<const state::activity::AuthenticationKey> owners,
    AuthenticatedRoute& output) noexcept;

/**
 * Rechecks exact ownership, context generation, pinned source and current route
 * selection. Release, reset and slot reuse invalidate handles without reuse.
 * The result is an observation under the resolver lock, not a retained lease.
 */
[[nodiscard]] bool validate_authenticated_route(const AuthenticatedRoute& observed) noexcept;

/**
 * Erases one bound or unbound context by exact owner and generation. Stale, forged or
 * repeated releases return false and do not affect any sibling route for that owner.
 * This internal lifetime operation accepts no endpoint-based or newest-route fallback.
 */
[[nodiscard]] bool release_route(RouteHandle route) noexcept;

void release_owner(state::activity::AuthenticationKey owner) noexcept;
void reset() noexcept;
[[nodiscard]] Statistics snapshot() noexcept;

} // namespace dawn::server::gameplay::resolution
