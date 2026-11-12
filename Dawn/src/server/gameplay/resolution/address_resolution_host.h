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

/** Public routing identity only. Contains no resolver keys, tokens or account data. */
struct AuthenticatedRoute {
    RouteHandle handle{};
    state::gameplay::Endpoint source{};
};

/** Explicit development opt-in, cached for this loaded DLL's lifetime. */
[[nodiscard]] bool enabled() noexcept;

/**
 * Answers BAP300 only for the configured embedded method-0 endpoint. Material
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
 * success contains only its owner, context generation and pinned UDP source. A different
 * context using the same source endpoint cannot replace this packet's routing identity.
 */
[[nodiscard]] PacketResult unwrap(const state::gameplay::Endpoint& source,
                                  std::span<const std::byte> packet,
                                  std::span<std::byte> plaintext,
                                  std::size_t& written,
                                  AuthenticatedRoute& matched) noexcept;

/** Uses the destination's most recently authenticated route; consumes each IV once. */
[[nodiscard]] PacketResult wrap(const state::gameplay::Endpoint& destination,
                                std::span<const std::byte> plaintext,
                                std::span<std::byte> packet,
                                std::size_t& written) noexcept;

/**
 * Seals with this exact still-live bound context, even when another context is the
 * endpoint's most recently heard route. Invalid/stale ownership, generation or source
 * is rejected without falling back. IV state is shared with the endpoint-based wrapper.
 * This selects an authenticated transport context; it grants no human/gameplay admission.
 */
[[nodiscard]] PacketResult wrap_authenticated_route(const AuthenticatedRoute& route,
                                                    std::span<const std::byte> plaintext,
                                                    std::span<std::byte> packet,
                                                    std::size_t& written) noexcept;

/**
 * Observes this owner's currently selected authenticated route. Unbound contexts
 * and routes superseded for the same owner or endpoint are unavailable. Failure
 * clears output. This observation grants no admission or gameplay authorization.
 */
[[nodiscard]] bool lookup_authenticated_route(state::activity::AuthenticationKey owner,
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
