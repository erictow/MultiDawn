#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "core/logging/log.h"
#include "core/settings/settings.h"
#include "server/bap/runtime.h"
#include "server/gameplay/resolution/address_resolution_host.h"
#include "server/transport/bap_listener.h"
#include "server/transport/internal.h"
#include "server/transport/process_socket.h"

namespace {
using namespace dawn;
namespace transport = server::transport;
std::vector<std::uint32_t> received;
unsigned checks{};
unsigned polls{};
unsigned processOpens{};
bool captureProvenance{};

void require(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", label);
        std::exit(1);
    }
}

std::uint32_t read32(std::span<const std::byte> bytes) {
    std::uint32_t value{};
    for (const auto byte : bytes.first(4)) {
        value = (value << 8U) | std::to_integer<std::uint32_t>(byte);
    }
    return value;
}

std::vector<std::byte> frame(std::uint32_t sequence, bool reply = false,
                             std::size_t size = 3528) {
    std::vector<std::byte> bytes(size);
    bytes[0] = std::byte{0xAB};
    bytes[1] = std::byte{1};
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[2 + i] = static_cast<std::byte>((size - 6) >> (24 - 8 * i));
        bytes[7 + i] = static_cast<std::byte>(sequence >> (24 - 8 * i));
    }
    bytes[6] = static_cast<std::byte>(reply);
    return bytes;
}

void append(transport::Peer& peer, const std::vector<std::byte>& bytes,
            std::size_t begin = 0, std::size_t count = SIZE_MAX) {
    count = (std::min)(count, bytes.size() - begin);
    require(peer.streamSize + count <= peer.stream.size(), "test ingress fits");
    std::memcpy(peer.stream.data() + peer.streamSize, bytes.data() + begin, count);
    peer.streamSize += count;
}

void reset() {
    auto& peer = transport::g_listener.peers[0];
    peer.streamSize = peer.outputSize = peer.outputOffset = 0;
    received.clear();
}

void buffered_contract() {
    reset();
    auto& peer = transport::g_listener.peers[0];
    for (std::uint32_t i = 0; i < 50; ++i) append(peer, frame(i));
    require(transport::drain_stream(0), "coalesced frames accepted");
    require(received.size() == 32, "one callback drains a fair bounded batch");
    require(peer.streamSize == 18 * 3528, "remaining frames retained");
    require(transport::drain_stream(0), "next slice drains remaining burst");
    require(received.size() == 50 && peer.streamSize == 0, "burst drained completely");
    for (std::uint32_t i = 0; i < 50; ++i)
        require(received[i] == i, "burst ordering preserved");

    reset();
    append(peer, frame(1));
    append(peer, frame(2, true));
    append(peer, frame(3));
    require(transport::drain_stream(0), "mixed request burst accepted");
    require(received.size() == 2 && peer.outputSize == 4, "reply stops ingress batch");
    require(transport::advance_output(peer, 1), "short write advances output");
    require(transport::drain_stream(0) && received.size() == 2,
            "partially sent reply blocks later request");
    require(!transport::advance_output(peer, 4), "oversized write rejected");
    require(transport::advance_output(peer, 3), "reply suffix completes");
    require(transport::drain_stream(0) && received.size() == 3 && received[2] == 3,
            "later request follows reply completion");

    reset();
    const auto split = frame(7);
    append(peer, frame(6));
    append(peer, split, 0, 4);
    require(transport::drain_stream(0) && received.size() == 1 && peer.streamSize == 4,
            "partial header survives previous complete frame");
    append(peer, split, 4, 19);
    require(transport::drain_stream(0) && received.size() == 1 && peer.streamSize == 23,
            "partial payload is retained");
    append(peer, split, 23);
    require(transport::drain_stream(0) && received.size() == 2 && received[1] == 7,
            "split payload offered exactly once");

    reset();
    append(peer, frame(9, false, transport::kStreamCapacity));
    require(transport::drain_stream(0) && received.size() == 1 && peer.streamSize == 0,
            "maximum supported frame is accepted without byte-budget starvation");
}

SOCKET connect_peer(std::uint16_t port) {
    const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(socket != INVALID_SOCKET, "create loopback client");
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(connect(socket, reinterpret_cast<const sockaddr*>(&target), sizeof target) == 0,
            "connect ephemeral loopback listener");
    BOOL enabled = TRUE;
    require(setsockopt(socket, IPPROTO_TCP, TCP_NODELAY,
                      reinterpret_cast<const char*>(&enabled), sizeof enabled) == 0,
            "disable test client Nagle delay");
    u_long nonblocking = 1;
    require(ioctlsocket(socket, FIONBIO, &nonblocking) == 0, "nonblocking test client");
    return socket;
}

struct BoundUdp {
    SOCKET socket{};
    std::uint16_t port{};
};

BoundUdp bind_udp(std::uint32_t address, std::uint16_t port = 0) {
    const SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    require(udp != INVALID_SOCKET, "create UDP test source");
    const BOOL reuse = TRUE;
    require(setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof reuse) == 0,
            "allow overlapping test binds");
    sockaddr_in bindAddress{};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_addr.s_addr = htonl(address);
    bindAddress.sin_port = htons(port);
    require(bind(udp, reinterpret_cast<const sockaddr*>(&bindAddress), sizeof bindAddress) == 0,
            "bind UDP test source");
    int length = sizeof bindAddress;
    require(getsockname(udp, reinterpret_cast<sockaddr*>(&bindAddress), &length) == 0,
            "find UDP test source port");
    return {udp, ntohs(bindAddress.sin_port)};
}

void udp_provenance() {
    const auto wildcard = bind_udp(INADDR_ANY);
    const state::gameplay::Endpoint source{INADDR_LOOPBACK, wildcard.port};
    require(transport::process_socket::udp_source_in_current_process(source),
            "wildcard socket proves its IPv4 loopback source belongs to this process");
    require(!transport::process_socket::udp_source_in_current_process({0xC0A80101, source.port}),
            "the same bound port cannot prove a non-loopback source");
    require(!transport::process_socket::udp_source_in_current_process({INADDR_LOOPBACK, 0}),
            "a missing port cannot prove source ownership");
    const auto overlapping = bind_udp(INADDR_LOOPBACK, wildcard.port);
    require(!transport::process_socket::udp_source_in_current_process(source),
            "overlapping binds remain ambiguous even within this process");
    closesocket(wildcard.socket);
    require(transport::process_socket::udp_source_in_current_process(source),
            "a unique explicit loopback bind proves its source");
    closesocket(overlapping.socket);
    require(!transport::process_socket::udp_source_in_current_process(source),
            "closing the UDP source retires its ownership");
}

void provenance_child(std::uint16_t tcpPort, std::uint16_t udpPort) {
    WSADATA data{};
    require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "initialize child Winsock");
    const SOCKET tcp = connect_peer(tcpPort);
    u_long blocking = 0;
    const DWORD timeout = 8000;
    require(ioctlsocket(tcp, FIONBIO, &blocking) == 0
            && setsockopt(tcp, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof timeout) == 0,
            "hold child connection until parent finishes");
    const auto udp = bind_udp(INADDR_ANY);
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(udpPort);
    char message = 'x';
    require(sendto(udp.socket, &message, 1, 0, reinterpret_cast<const sockaddr*>(&target), sizeof target) == 1,
            "send from the foreign UDP source");
    require(recv(tcp, &message, 1, 0) == 0, "parent releases the test connection");
    closesocket(udp.socket);
    closesocket(tcp);
    WSACleanup();
}

void foreign_process_provenance(SOCKET listener, std::uint16_t tcpPort) {
    const auto receiver = bind_udp(INADDR_LOOPBACK);
    const DWORD timeout = 8000;
    require(setsockopt(receiver.socket, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof timeout) == 0, "bound UDP test wait");
    std::array<wchar_t, 32768> executable{};
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    require(length != 0 && length < executable.size(), "find the test executable for a foreign PID");
    auto command = std::wstring(L"\"") + executable.data() + L"\" --provenance-child "
        + std::to_wstring(tcpPort) + L" " + std::to_wstring(receiver.port);
    STARTUPINFOW startup{};
    startup.cb = sizeof startup;
    PROCESS_INFORMATION child{};
    require(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                           nullptr, nullptr, &startup, &child) != FALSE,
            "start another process on local test sockets");
    CloseHandle(child.hThread);
    fd_set readers{};
    FD_SET(listener, &readers);
    timeval deadline{8, 0};
    require(select(0, &readers, nullptr, nullptr, &deadline) == 1, "wait for foreign TCP connection");
    const SOCKET accepted = accept(listener, nullptr, nullptr);
    require(accepted != INVALID_SOCKET && !transport::process_socket::tcp_peer_in_current_process(accepted),
            "the accepted socket cannot prove another process's TCP peer");
    char message{};
    sockaddr_in source{};
    int sourceLength = sizeof source;
    require(recvfrom(receiver.socket, &message, 1, 0, reinterpret_cast<sockaddr*>(&source), &sourceLength) == 1,
            "read a packet from the foreign UDP socket");
    require(!transport::process_socket::udp_source_in_current_process(
                {ntohl(source.sin_addr.s_addr), ntohs(source.sin_port)}),
            "a loopback datagram cannot prove another process's UDP source");
    closesocket(accepted);
    closesocket(receiver.socket);
    DWORD exitCode{};
    require(WaitForSingleObject(child.hProcess, timeout) == WAIT_OBJECT_0
            && GetExitCodeProcess(child.hProcess, &exitCode) != FALSE && exitCode == 0,
            "foreign test process exits cleanly");
    CloseHandle(child.hProcess);
}

void socket_burst() {
    reset();
    captureProvenance = true;
    require(transport::initialize_on_port(0), "start real listener on ephemeral port");
    udp_provenance();
    require(!transport::process_socket::tcp_peer_in_current_process(transport::g_listener.acceptor),
            "a listener has no established peer to prove");
    sockaddr_in address{};
    int length = sizeof address;
    require(getsockname(transport::g_listener.acceptor,
                        reinterpret_cast<sockaddr*>(&address), &length) == 0,
            "resolve ephemeral listener port");
    foreign_process_provenance(transport::g_listener.acceptor, ntohs(address.sin_port));
    const SOCKET client = connect_peer(ntohs(address.sin_port));
    const SOCKET other = connect_peer(ntohs(address.sin_port));
    std::uint64_t tick = 1;
    transport::service(tick++);
    transport::service(tick++);
    std::vector<std::byte> pending;
    std::size_t sent{};
    for (std::uint32_t i = 0; i < 400; ++i) {
        const auto packet = frame(i);
        pending.insert(pending.end(), packet.begin(), packet.end());
    }
    const auto separate = frame(1000, true);
    require(send(other, reinterpret_cast<const char*>(separate.data()),
                 static_cast<int>(separate.size()), 0) == static_cast<int>(separate.size()),
            "second peer request queued");
    bool otherReceived = false;
    std::size_t otherBytes = 0;
    std::array<char, 4> reply{};
    for (unsigned slice = 0; slice < 250 && received.size() < 401; ++slice) {
        if (sent < pending.size()) {
            const auto count = send(client, reinterpret_cast<const char*>(pending.data() + sent),
                                    static_cast<int>(pending.size() - sent), 0);
            require(count > 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK),
                    "bulk send accepts or applies backpressure");
            if (count > 0) sent += static_cast<std::size_t>(count);
        }
        transport::service(tick * 16);
        ++tick;
        if (!otherReceived) {
            const auto count = recv(other, reply.data() + otherBytes,
                                    static_cast<int>(reply.size() - otherBytes), 0);
            require(count > 0 || (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK),
                    "second peer reply accepts or remains pending");
            if (count > 0) otherBytes += static_cast<std::size_t>(count);
            otherReceived = otherBytes == reply.size();
        }
        Sleep(1);
    }
    require(sent == pending.size() && received.size() == 401,
            "real socket burst drains faster than one frame per callback");
    require(otherReceived && polls != 0, "other peer and due polls remain serviced");
    std::uint32_t next = 0;
    for (const auto sequence : received) {
        if (sequence != 1000) require(sequence == next++, "socket order exactly preserved");
    }
    require(next == 400, "all heartbeat-sized frames delivered once");
    require(processOpens == 2,
            "both accepted BAP peers prove their complete reversed TCP tuple at open");
    closesocket(client);
    closesocket(other);
    transport::shutdown();
}
} // namespace

namespace dawn::core::log {
void write(Channel, Level, std::string_view) noexcept {}
}
namespace dawn::core::settings {
const Settings& get() noexcept { static Settings settings{}; return settings; }
}
namespace dawn::server::gameplay::resolution {
bool enabled() noexcept { return captureProvenance; }
}
namespace dawn::server::bap {
bool consume(const client::network::BapRequest& request,
             client::network::BapResponse& response) noexcept {
    response.size = 0;
    if (request.peerInCurrentProcess) {
        require(request.event == client::network::BapEvent::open, "only an open carries TCP provenance");
        ++processOpens;
    }
    if (request.event == client::network::BapEvent::poll) ++polls;
    if (request.event != client::network::BapEvent::frame) return true;
    require(request.frame.size() >= 11, "route receives complete fixture");
    const auto sequence = read32(request.frame.subspan(7));
    received.push_back(sequence);
    if (request.frame[6] == std::byte{1}) {
        std::copy_n(request.frame.begin() + 7, 4, request.response.begin());
        response.size = 4;
    }
    return true;
}
}

int main(int argc, char** argv) {
    if (argc == 4 && std::strcmp(argv[1], "--provenance-child") == 0) {
        const auto tcpPort = std::strtoul(argv[2], nullptr, 10);
        const auto udpPort = std::strtoul(argv[3], nullptr, 10);
        require(tcpPort > 0 && tcpPort <= UINT16_MAX && udpPort > 0 && udpPort <= UINT16_MAX,
                "child sockets require valid ports");
        provenance_child(static_cast<std::uint16_t>(tcpPort), static_cast<std::uint16_t>(udpPort));
        return 0;
    }
    if (argc != 2 || std::strcmp(argv[1], "--socket-only") != 0) buffered_contract();
    socket_burst();
    std::printf("PASS: %u transport checks; coalesced ingress, reply ordering, partial frames, "
                "bounded fairness and real loopback throughput\n", checks);
}
