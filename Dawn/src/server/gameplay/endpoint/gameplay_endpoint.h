#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../state/gameplay/definition.h"
#include "../resolution/address_resolution_host.h"

namespace dawn::server::gameplay::endpoint {

/**
 * Binds the gameplay UDP endpoint when the configured topology is embedded.
 * External topology binds no socket, because another process owns it. Disabled topology succeeds
 * and does nothing.
 * @return True when the configured topology is ready to be advertised.
 */
[[nodiscard]] bool initialize() noexcept;

/**
 * Drains a bounded number of datagrams and expires stale associations.
 * @param now Monotonic tick count in milliseconds.
 */
void service(std::uint64_t now) noexcept;

/** A bound native route must never fall back to an unprotected send on failure. */
enum class RoutedSendResult : std::uint8_t { notRouted, failed, sent };

/** An internal route consumer chooses whether an authenticated packet belongs to it. */
enum class RoutedIngressResult : std::uint8_t { unhandled, handled, rejected };
using RoutedConsumer = RoutedIngressResult (*)(const resolution::AuthenticatedRoute&,
    std::span<const std::byte>, std::uint64_t) noexcept;

/**
 * Installs one process-lifetime server callback on a bound embedded endpoint. This grants
 * nothing: the callback must validate its own current peer/route authorization. It runs
 * outside endpoint/resolver locks; payload storage is borrowed until it returns. Callers
 * own module quiescence, and must not unload callback code while service is in flight.
 */
[[nodiscard]] bool register_routed_consumer(RoutedConsumer consumer) noexcept;
/**
 * Removes only that callback. Shutdown also clears registration. A callback already copied
 * by service may finish afterward; neither operation waits for it. Revoke individual peers
 * through their route/grant lifetimes, not by removing a module-wide callback.
 */
void unregister_routed_consumer(RoutedConsumer consumer) noexcept;

/** Sends an engine payload only when an authenticated native route owns the destination. */
[[nodiscard]] RoutedSendResult send_resolved_to(
    const state::gameplay::Endpoint& destination,
    std::span<const std::byte> payload) noexcept;

/** Exact-context send. Always sent or failed; it never selects another route or raw fallback. */
[[nodiscard]] RoutedSendResult send_resolved_on_route(
    const resolution::AuthenticatedRoute& route,
    std::span<const std::byte> payload) noexcept;

/**
 * Sends one datagram to a client endpoint.
 * @param destination Host-order address and port.
 * @param datagram Complete datagram bytes.
 * @return True when the whole datagram was handed to Winsock.
 */
[[nodiscard]] bool send_to(const state::gameplay::Endpoint& destination,
                           std::span<const std::byte> datagram) noexcept;

/** Closes the socket and releases the Winsock reference this module took. */
void shutdown() noexcept;

/** @return True once an embedded endpoint is bound, or external topology is preflighted. */
[[nodiscard]] bool ready() noexcept;

/** @return Endpoint published in the join descriptor. Zero when the channel is disabled. */
[[nodiscard]] state::gameplay::Endpoint advertised() noexcept;

/** Identity the join descriptor publishes beside the endpoint. */
struct Identity {
    /** Nonzero machine identity. A zero identity makes the descriptor read as absent. */
    std::uint64_t machineId{};
    /** Nonzero online session id, which is also the lobby the client is told to join. */
    std::uint64_t onlineSessionId{};
};

/** @return Identity generated when the endpoint bound, or zeroes when it did not. */
[[nodiscard]] Identity identity() noexcept;

} // namespace dawn::server::gameplay::endpoint
