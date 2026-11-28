#pragma once

#include <WinSock2.h>

#include "../../state/gameplay/definition.h"

namespace dawn::server::transport::process_socket {

/** Checks both sides of the live IPv4 loopback TCP tuple against this process. */
[[nodiscard]] bool tcp_peer_in_current_process(SOCKET accepted) noexcept;

/**
 * Checks for a unique current IPv4 loopback source socket owned by this process.
 * An IPv4 wildcard bind counts as matching. This is a socket-table observation
 * for a previously authenticated route and does not authenticate a UDP packet.
 */
[[nodiscard]] bool udp_source_in_current_process(const state::gameplay::Endpoint& source) noexcept;

} // namespace dawn::server::transport::process_socket
