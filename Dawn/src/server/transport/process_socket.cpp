#include "process_socket.h"

#include <WS2tcpip.h>
#include <Windows.h>
#include <Iphlpapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <memory>
#include <new>

namespace dawn::server::transport::process_socket {
namespace {

constexpr DWORD kInitialTableBytes = 16 * 1024;
constexpr DWORD kMaximumTableBytes = 2 * 1024 * 1024;
constexpr unsigned kReadAttempts = 3;

// The MIB tables declare one row but may return more. Copy each row after
// checking the returned byte count, to avoid indexing the declared one-row array.
template <class Row, class Query, class Visitor>
[[nodiscard]] bool visit_table(Query query, std::size_t firstRow, Visitor visitor) noexcept {
    DWORD capacity = kInitialTableBytes;
    for (unsigned attempt = 0; attempt < kReadAttempts; ++attempt) {
        const std::unique_ptr<std::byte[]> buffer(new (std::nothrow) std::byte[capacity]);
        if (!buffer) return false;
        DWORD bytes = capacity;
        const DWORD result = query(buffer.get(), &bytes);
        if (result == ERROR_INSUFFICIENT_BUFFER && bytes > capacity && bytes <= kMaximumTableBytes) {
            capacity = bytes;
            continue;
        }
        if (result != NO_ERROR || bytes > capacity || bytes < firstRow) return false;
        DWORD count{};
        std::memcpy(&count, buffer.get(), sizeof count);
        if (count > (bytes - firstRow) / sizeof(Row)) return false;
        for (DWORD i = 0; i < count; ++i) {
            Row row{};
            std::memcpy(&row, buffer.get() + firstRow + i * sizeof(Row), sizeof row);
            visitor(row);
        }
        return true;
    }
    return false;
}

[[nodiscard]] constexpr bool loopback(std::uint32_t hostAddress) noexcept {
    return (hostAddress >> 24) == 127;
}

[[nodiscard]] bool tuple_matches(const MIB_TCPROW_OWNER_PID& row,
                                 const sockaddr_in& local, const sockaddr_in& remote) noexcept {
    // The SDK stores the network-order port in the low 16 bits.
    return row.dwLocalAddr == local.sin_addr.s_addr
        && static_cast<u_short>(row.dwLocalPort) == local.sin_port
        && row.dwRemoteAddr == remote.sin_addr.s_addr
        && static_cast<u_short>(row.dwRemotePort) == remote.sin_port;
}

[[nodiscard]] bool possible_ipv4_bind(const MIB_UDP6ROW_OWNER_PID& row,
                                      std::uint32_t networkAddress) noexcept {
    // The UDP table has no IPV6_V6ONLY flag. Treat an IPv6 wildcard or a
    // matching mapped address as an ambiguous competing bind.
    constexpr std::array<UCHAR, 12> mappedPrefix{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (std::all_of(std::begin(row.ucLocalAddr), std::end(row.ucLocalAddr),
                    [](UCHAR byte) noexcept { return byte == 0; })) return true;
    return std::equal(mappedPrefix.begin(), mappedPrefix.end(), row.ucLocalAddr)
        && std::memcmp(row.ucLocalAddr + mappedPrefix.size(), &networkAddress, sizeof networkAddress) == 0;
}

} // namespace

bool tcp_peer_in_current_process(SOCKET accepted) noexcept {
    if (accepted == INVALID_SOCKET) return false;
    sockaddr_in local{}, remote{};
    constexpr auto ipv4Size = static_cast<int>(sizeof(sockaddr_in));
    int localSize = ipv4Size;
    int remoteSize = ipv4Size;
    if (getsockname(accepted, reinterpret_cast<sockaddr*>(&local), &localSize) != 0
        || getpeername(accepted, reinterpret_cast<sockaddr*>(&remote), &remoteSize) != 0
        || localSize != ipv4Size || remoteSize != ipv4Size
        || local.sin_family != AF_INET || remote.sin_family != AF_INET
        || local.sin_port == 0 || remote.sin_port == 0
        || !loopback(ntohl(local.sin_addr.s_addr)) || !loopback(ntohl(remote.sin_addr.s_addr))
        || (local.sin_port == remote.sin_port && local.sin_addr.s_addr == remote.sin_addr.s_addr)) {
        return false;
    }
    const DWORD process = GetCurrentProcessId();
    unsigned forward{}, reverse{};
    bool owned = true;
    const bool complete = visit_table<MIB_TCPROW_OWNER_PID>([](void* buffer, DWORD* bytes) noexcept {
        return GetExtendedTcpTable(buffer, bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    }, offsetof(MIB_TCPTABLE_OWNER_PID, table), [&](const MIB_TCPROW_OWNER_PID& row) noexcept {
        if (row.dwState != MIB_TCP_STATE_ESTAB) return;
        if (tuple_matches(row, local, remote)) {
            ++forward;
            owned = owned && row.dwOwningPid == process;
        } else if (tuple_matches(row, remote, local)) {
            ++reverse;
            owned = owned && row.dwOwningPid == process;
        }
    });
    return complete && owned && forward == 1 && reverse == 1;
}

bool udp_source_in_current_process(const state::gameplay::Endpoint& source) noexcept {
    if (!loopback(source.address) || source.port == 0) return false;
    const auto address = htonl(source.address);
    const auto port = htons(source.port);
    const DWORD process = GetCurrentProcessId();
    unsigned matches{};
    bool owned = true;
    const bool ipv4 = visit_table<MIB_UDPROW_OWNER_PID>([](void* buffer, DWORD* bytes) noexcept {
        return GetExtendedUdpTable(buffer, bytes, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    }, offsetof(MIB_UDPTABLE_OWNER_PID, table), [&](const MIB_UDPROW_OWNER_PID& row) noexcept {
        if (static_cast<u_short>(row.dwLocalPort) == port
            && (row.dwLocalAddr == INADDR_ANY || row.dwLocalAddr == address)) {
            ++matches;
            owned = owned && row.dwOwningPid == process;
        }
    });
    if (!ipv4 || !owned || matches != 1) return false;

    bool ambiguous = false;
    const bool ipv6 = visit_table<MIB_UDP6ROW_OWNER_PID>([](void* buffer, DWORD* bytes) noexcept {
        return GetExtendedUdpTable(buffer, bytes, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    }, offsetof(MIB_UDP6TABLE_OWNER_PID, table), [&](const MIB_UDP6ROW_OWNER_PID& row) noexcept {
        if (static_cast<u_short>(row.dwLocalPort) == port && possible_ipv4_bind(row, address)) {
            ambiguous = true;
        }
    });
    return ipv6 && !ambiguous;
}

} // namespace dawn::server::transport::process_socket
