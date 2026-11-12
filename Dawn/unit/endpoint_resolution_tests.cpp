#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

#include "../src/core/settings/settings.h"
#include "../src/middleware/bap/address_resolution.h"
#include "../src/middleware/encoding/bit_raw.h"
#include "../src/middleware/gameplay/descriptor/join_descriptor.h"
#include "../src/middleware/gameplay/peer/connect_messages.h"
#include "../src/middleware/gameplay/peer/peer_container.h"
#include "../src/middleware/gameplay/routed_datagram.h"
#include "../src/server/gameplay/association/association_host.h"
#include "../src/server/gameplay/dtls/dtls_host.h"
#include "../src/server/gameplay/endpoint/gameplay_endpoint.h"
#include "../src/server/gameplay/gameplay_log.h"
#include "../src/server/gameplay/peer/peer_transport.h"
#include "../src/server/gameplay/resolution/address_resolution_host.h"
#include "../src/state/gameplay/replication_roles.h"

namespace endpoint = dawn::server::gameplay::endpoint;
namespace host = dawn::server::gameplay::resolution;
namespace wire = dawn::middleware::bap::address_resolution;
namespace packet = dawn::middleware::gameplay::routed_datagram;
namespace container = dawn::middleware::gameplay::peer;
namespace bits = dawn::middleware::encoding::bits;
using Endpoint = dawn::state::gameplay::Endpoint;
using Owner = dawn::state::activity::AuthenticationKey;
using Bytes = std::vector<std::byte>;
static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s (Winsock %d)\n", __LINE__, #value, WSAGetLastError()); std::abort(); } } while (false)

// The production endpoint, host store, wire codecs, RNG and cryptography are
// linked below. Only downstream protocol handlers and process services are
// substituted; no game process, save, or non-loopback address is accessed.
static dawn::core::settings::Settings testSettings{};
static unsigned peerCalls{}, dtlsCalls{}, associationCalls{}, receiveReports{};
static Endpoint lastPeer{};
static Bytes lastPeerPayload, lastLegacyPayload, automaticReply;
static bool consumeLegacyDtls{};
static endpoint::RoutedSendResult replyResult = endpoint::RoutedSendResult::notRouted;
static std::uint64_t epoch{};
static unsigned routedCalls{};
static host::AuthenticatedRoute lastRouted{};
static Bytes lastRoutedPayload, routedReply;
static endpoint::RoutedIngressResult routedDecision = endpoint::RoutedIngressResult::handled;
static endpoint::RoutedSendResult routedReplyResult = endpoint::RoutedSendResult::failed;

static endpoint::RoutedIngressResult routed_consumer(const host::AuthenticatedRoute& route,
    std::span<const std::byte> payload, std::uint64_t) noexcept {
    ++routedCalls; lastRouted = route;
    lastRoutedPayload.assign(payload.begin(), payload.end());
    if (routedDecision == endpoint::RoutedIngressResult::handled && !routedReply.empty())
        routedReplyResult = endpoint::send_resolved_on_route(route, routedReply);
    return routedDecision;
}
static endpoint::RoutedIngressResult other_consumer(const host::AuthenticatedRoute&,
    std::span<const std::byte>, std::uint64_t) noexcept {
    return endpoint::RoutedIngressResult::rejected;
}

namespace dawn::core::settings {
const Settings& get() noexcept { return testSettings; }
}
namespace dawn::state::gameplay::replication {
void begin_control_host_epoch(std::uint64_t value) noexcept { epoch = value; }
}
namespace dawn::server::gameplay {
void report(core::log::Level, const char* format, ...) noexcept {
    if (std::string_view(format).find("stage=receive result=ok") != std::string_view::npos) {
        ++receiveReports;
    }
}
}
namespace dawn::server::gameplay::peer {
void deliver_resolved(const state::gameplay::Endpoint& from, std::span<const std::byte> payload,
             std::uint64_t) noexcept {
    ++peerCalls;
    lastPeer = from;
    lastPeerPayload.assign(payload.begin(), payload.end());
    if (!automaticReply.empty()) {
        // A handler may reply synchronously. The endpoint and resolver locks
        // must already be released before dispatching this callback.
        replyResult = endpoint::send_resolved_to(from, automaticReply);
    }
}
}
namespace dawn::server::gameplay::dtls {
bool route(const state::gameplay::Endpoint&, std::span<const std::byte> payload,
           std::uint64_t) noexcept {
    ++dtlsCalls;
    lastLegacyPayload.assign(payload.begin(), payload.end());
    return consumeLegacyDtls;
}
}
namespace dawn::server::gameplay::association {
void route(const state::gameplay::Endpoint&, std::span<const std::byte> payload,
           std::uint64_t) noexcept {
    ++associationCalls;
    lastLegacyPayload.assign(payload.begin(), payload.end());
}
void expire(std::uint64_t) noexcept {}
}

class Socket final {
public:
    Socket() {
        value = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        CHECK(value != INVALID_SOCKET);
        const BOOL exclusive = TRUE;
        CHECK(setsockopt(value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive), sizeof exclusive) == 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(value, reinterpret_cast<const sockaddr*>(&address), sizeof address) == 0);
        int length = sizeof address;
        CHECK(getsockname(value, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        local = {ntohl(address.sin_addr.s_addr), ntohs(address.sin_port)};
        u_long nonblocking = 1;
        CHECK(ioctlsocket(value, FIONBIO, &nonblocking) == 0);
    }
    ~Socket() { if (value != INVALID_SOCKET) { closesocket(value); } }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    SOCKET value{INVALID_SOCKET};
    Endpoint local{};
};

static void initialize_endpoint() {
    host::reset();
    testSettings.server.gameplay.bindAddress = {127, 0, 0, 1};
    testSettings.server.gameplay.advertisedAddress = {127, 0, 0, 1};
    testSettings.server.gameplay.transportAddress = {127, 0, 0, 1};
    // Production validates an even nonzero port. Discover an ephemeral one,
    // release the probe socket, then retry if another process wins the bind.
    bool started = false;
    for (unsigned attempt = 0; attempt < 64 && !started; ++attempt) {
        std::uint16_t port = 0;
        { const Socket probe; port = probe.local.port; }
        if (port % 2 != 0) { continue; }
        testSettings.server.gameplay.port = port;
        started = endpoint::initialize();
    }
    CHECK(started && endpoint::ready());
    CHECK(endpoint::advertised().address == INADDR_LOOPBACK);
    CHECK(endpoint::advertised().port == testSettings.server.gameplay.port);
    CHECK(epoch != 0 && epoch == endpoint::identity().machineId);
}

static wire::Response resolve(Owner owner) {
    wire::NetAddr address{};
    dawn::middleware::gameplay::descriptor::write_net_addr(
        INADDR_LOOPBACK, testSettings.server.gameplay.port, address);
    std::array<std::byte, wire::kRequestSize> request{};
    request[1] = std::byte{86};
    std::copy(address.begin(), address.end(), request.begin() + 2);
    request[89] = std::byte{16};
    request[91] = std::byte{1};
    std::array<std::byte, wire::kIpv4ResponseSize> encoded{};
    std::size_t written = 0;
    CHECK(host::resolve_address(owner, request, encoded, written));
    CHECK(written == encoded.size());
    wire::Response response{};
    CHECK(wire::parse_response(encoded, response));
    CHECK(response.port == endpoint::advertised().port);
    return response;
}

static std::uint64_t counter(const packet::Iv& vector) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < vector.size(); ++index) {
        value |= std::to_integer<std::uint64_t>(vector[index]) << (index * 8);
    }
    return value;
}

static packet::Iv iv(std::uint64_t value) {
    packet::Iv result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(value >> (index * 8));
    }
    return result;
}

static packet::DirectionKeys keys(const wire::Response& response, bool inbound) {
    packet::DirectionKeys result{};
    const auto& cipher = inbound ? response.material.a : response.material.d;
    std::copy_n(cipher.begin(), result.cipher.size(), result.cipher.begin());
    result.mac = response.material.f;
    return result;
}

static Bytes client_packet(const wire::Response& response, std::uint64_t value,
                           std::span<const std::byte> payload) {
    Bytes output(packet::kMaximumDatagram);
    std::size_t written = 0;
    CHECK(packet::seal(keys(response, true), response.routeTag, iv(value), payload, output, written));
    output.resize(written);
    return output;
}

static Bytes connect_container(const Endpoint& peer, bool response) {
    std::array<std::byte, 256> output{};
    std::array<std::byte, 86> address{};
    dawn::middleware::gameplay::descriptor::write_net_addr(peer.address, peer.port, address);
    bits::Writer writer(output);
    CHECK(container::open_container(writer));
    CHECK(container::write_header(writer,
        {static_cast<std::uint8_t>(response ? 6 : 5), response ? 104U : 96U}));
    if (response) {
        const container::ConnectResponse body{7, 12, 8, 13, address};
        CHECK(container::write_response(writer, body));
    } else {
        CHECK(writer.write(7, 32) && writer.write(12, 32));
        CHECK(bits::write_raw(writer, address));
    }
    CHECK(container::close_container(writer));
    std::size_t written = 0;
    CHECK(writer.finish(written));
    if (!response) {
        CHECK(written == 98 && output[0] == std::byte{0xC5});
        bits::Reader reader(std::span(output).first(written));
        container::MessageHeader header{};
        bool present = false;
        container::ConnectRequest parsed{};
        CHECK(container::read_marker(reader) && container::read_header(reader, header, present));
        CHECK(present && header.id == 5 && header.declaredSize == 96);
        CHECK(container::read_request(reader, parsed));
        CHECK(parsed.channelId == 7 && parsed.sequence == 12 && parsed.address == address);
    }
    return {output.begin(), output.begin() + written};
}

static void send(const Socket& source, std::span<const std::byte> datagram) {
    const auto destination = endpoint::advertised();
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(destination.address);
    address.sin_port = htons(destination.port);
    CHECK(sendto(source.value, reinterpret_cast<const char*>(datagram.data()),
        static_cast<int>(datagram.size()), 0, reinterpret_cast<const sockaddr*>(&address),
        sizeof address) == static_cast<int>(datagram.size()));
}

template <typename Condition>
static void pump_until(Condition condition) {
    const auto deadline = GetTickCount64() + 2000;
    while (!condition() && GetTickCount64() < deadline) {
        endpoint::service(GetTickCount64());
        if (!condition()) { Sleep(1); }
    }
    CHECK(condition());
}

static Bytes receive(const Socket& socket) {
    std::array<std::byte, packet::kMaximumDatagram> bytes{};
    sockaddr_in from{};
    int length = sizeof from;
    int received = SOCKET_ERROR;
    const auto deadline = GetTickCount64() + 2000;
    while (GetTickCount64() < deadline) {
        received = recvfrom(socket.value, reinterpret_cast<char*>(bytes.data()),
            static_cast<int>(bytes.size()), 0, reinterpret_cast<sockaddr*>(&from), &length);
        if (received >= 0) { break; }
        CHECK(WSAGetLastError() == WSAEWOULDBLOCK);
        Sleep(1);
    }
    CHECK(received > 0);
    CHECK(ntohl(from.sin_addr.s_addr) == INADDR_LOOPBACK);
    CHECK(ntohs(from.sin_port) == testSettings.server.gameplay.port);
    return {bytes.begin(), bytes.begin() + received};
}

static void quiet(const Socket& socket) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(socket.value, &readable);
    timeval timeout{0, 25000};
    CHECK(select(0, &readable, nullptr, nullptr, &timeout) == 0);
}

static void verify_reply(const Socket& client, const wire::Response& response,
                         std::uint64_t expectedCounter, std::span<const std::byte> expected) {
    const auto datagram = receive(client);
    CHECK(datagram.size() >= packet::kMinimumDatagram);
    Bytes output(packet::kMaximumPayload);
    packet::Iv vector{};
    std::size_t written = 0;
    CHECK(packet::open(keys(response, false), response.routeTag, datagram, output, vector, written));
    CHECK(counter(vector) == expectedCounter && written == expected.size());
    CHECK(std::equal(expected.begin(), expected.end(), output.begin()));
}

static void exercise_endpoint() {
    initialize_endpoint();
    const Socket client, stranger, legacy;
    const Owner owner{{1, {1}}, {1}};
    const auto response = resolve(owner);
    const auto request = connect_container(client.local, false);
    const auto reply = connect_container(client.local, true);
    const auto firstCounter = counter(response.material.b) + 1;
    const auto first = client_packet(response, firstCounter, request);
    CHECK(first.size() == 126); // The live native connect container's outer size.

    CHECK(endpoint::send_resolved_to(client.local, reply) == endpoint::RoutedSendResult::notRouted);
    quiet(client); // Explicit resolved API must never fall back to raw send.

    auto tampered = first;
    tampered.back() ^= std::byte{1};
    auto rejected = host::snapshot().rejected;
    send(stranger, tampered);
    pump_until([&] { return host::snapshot().rejected > rejected; });
    CHECK(peerCalls == 0 && dtlsCalls == 0 && associationCalls == 0);
    CHECK(endpoint::send_resolved_to(stranger.local, reply) == endpoint::RoutedSendResult::notRouted);
    quiet(stranger);

    automaticReply = reply;
    send(client, first);
    pump_until([] { return peerCalls == 1; });
    CHECK(lastPeer.address == client.local.address && lastPeer.port == client.local.port);
    CHECK(lastPeerPayload == request && dtlsCalls == 0 && associationCalls == 0);
    CHECK(replyResult == endpoint::RoutedSendResult::sent);
    verify_reply(client, response, counter(response.material.e), reply);

    const auto replayed = host::snapshot().replayed;
    send(client, first);
    pump_until([&] { return host::snapshot().replayed > replayed; });
    CHECK(peerCalls == 1 && dtlsCalls == 0 && associationCalls == 0);
    quiet(client);

    const auto second = client_packet(response, firstCounter + 1, request);
    tampered = second;
    tampered[packet::kHeaderSize] ^= std::byte{1};
    rejected = host::snapshot().rejected;
    send(client, tampered);
    pump_until([&] { return host::snapshot().rejected > rejected; });
    CHECK(peerCalls == 1 && dtlsCalls == 0 && associationCalls == 0);
    quiet(client);
    send(client, second);
    pump_until([] { return peerCalls == 2; });
    verify_reply(client, response, counter(response.material.e) + 1, reply);

    const auto third = client_packet(response, firstCounter + 2, request);
    rejected = host::snapshot().rejected;
    send(stranger, third);
    pump_until([&] { return host::snapshot().rejected > rejected; });
    CHECK(peerCalls == 2 && dtlsCalls == 0 && associationCalls == 0);
    quiet(stranger);
    send(client, third);
    pump_until([] { return peerCalls == 3; });
    verify_reply(client, response, counter(response.material.e) + 2, reply);

    // Once bound, unwrapped packets from that source must not reach a legacy
    // handler. The bounded receive event provides a processing barrier here.
    const auto receivedBefore = receiveReports;
    send(client, request);
    pump_until([&] { return receiveReports > receivedBefore; });
    CHECK(peerCalls == 3 && dtlsCalls == 0 && associationCalls == 0);

    // Authenticated established payloads use the same direct peer boundary even
    // if their first byte overlaps a legacy DTLS type value.
    automaticReply.clear();
    const Bytes fragment{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    send(client, client_packet(response, firstCounter + 3, fragment));
    pump_until([] { return peerCalls == 4; });
    CHECK(lastPeerPayload == fragment && dtlsCalls == 0 && associationCalls == 0);

    // A source without a resolved context retains the raw legacy dispatch path.
    consumeLegacyDtls = true;
    send(legacy, fragment);
    pump_until([] { return dtlsCalls == 1; });
    CHECK(associationCalls == 0 && peerCalls == 4 && lastLegacyPayload == fragment);
    consumeLegacyDtls = false;
    send(legacy, request);
    pump_until([] { return associationCalls == 1; });
    CHECK(dtlsCalls == 2 && peerCalls == 4 && lastLegacyPayload == request);
    CHECK(endpoint::send_resolved_to(legacy.local, reply) == endpoint::RoutedSendResult::notRouted);
    quiet(legacy);

    // Legacy send_to still transmits raw data for an unbound destination.
    CHECK(endpoint::send_to(legacy.local, fragment));
    CHECK(receive(legacy) == fragment);

    // NAT introductions remain unwrapped even for a bound resolved peer.
    Bytes introduction(29, std::byte{0x5A});
    introduction[0] = std::byte{13};
    send(client, introduction);
    const auto traversalBefore = receiveReports;
    pump_until([&] { return receiveReports > traversalBefore; });
    introduction[0] = std::byte{12};
    CHECK(receive(client) == introduction);
    CHECK(peerCalls == 4 && dtlsCalls == 2 && associationCalls == 1);

    const Bytes oversized(packet::kMaximumPayload + 1, std::byte{0xC5});
    CHECK(endpoint::send_resolved_to(client.local, oversized) == endpoint::RoutedSendResult::failed);
    quiet(client);
    CHECK(peerCalls == 4 && dtlsCalls == 2 && associationCalls == 1);

    // A real socket-send failure is distinct from absence of a route. Do not
    // permit a caller to retry that bound route as plaintext on another path.
    endpoint::shutdown();
    CHECK(!endpoint::ready() && epoch == 0);
    CHECK(endpoint::send_resolved_to(client.local, reply) == endpoint::RoutedSendResult::failed);
    quiet(client);
    host::release_owner(owner);
    CHECK(endpoint::send_resolved_to(client.local, reply) == endpoint::RoutedSendResult::notRouted);
    quiet(client);
    CHECK(host::snapshot().live == 0);
}

static void exercise_explicit_routes() {
    CHECK(!endpoint::register_routed_consumer(nullptr));
    CHECK(!endpoint::register_routed_consumer(&routed_consumer)); // Previous exercise shut it down.
    initialize_endpoint();
    CHECK(endpoint::register_routed_consumer(&routed_consumer));
    CHECK(endpoint::register_routed_consumer(&routed_consumer));
    CHECK(!endpoint::register_routed_consumer(&other_consumer));
    endpoint::unregister_routed_consumer(&other_consumer); // Cannot remove another registration.

    const Socket client;
    const Owner ownerA{{2, {1}}, {1}}, ownerB{{3, {1}}, {1}};
    const auto responseA = resolve(ownerA), responseB = resolve(ownerB);
    const auto request = connect_container(client.local, false);
    const Bytes reply{std::byte{0xA5}, std::byte{0x5A}, std::byte{0x23}};
    const auto peerBefore = peerCalls, dtlsBefore = dtlsCalls, associationBefore = associationCalls;
    automaticReply.clear(); routedReply = reply; routedCalls = 0;
    routedDecision = endpoint::RoutedIngressResult::handled;

    auto first = client_packet(responseA, counter(responseA.material.b) + 1, request);
    auto forged = first; forged.back() ^= std::byte{1};
    auto rejected = host::snapshot().rejected;
    send(client, forged);
    pump_until([&] { return host::snapshot().rejected > rejected; });
    CHECK(routedCalls == 0 && peerCalls == peerBefore);
    quiet(client);

    send(client, first);
    pump_until([] { return routedCalls == 1; });
    const auto routeA = lastRouted;
    CHECK(routeA.handle.owner == ownerA && routeA.handle.generation != 0);
    CHECK(routeA.source.address == client.local.address && routeA.source.port == client.local.port);
    CHECK(lastRoutedPayload == request && routedReplyResult == endpoint::RoutedSendResult::sent);
    verify_reply(client, responseA, counter(responseA.material.e), reply);

    send(client, client_packet(responseB, counter(responseB.material.b) + 1, request));
    pump_until([] { return routedCalls == 2; });
    const auto routeB = lastRouted;
    CHECK(routeB.handle.owner == ownerB && routeB.handle.generation != routeA.handle.generation);
    CHECK(routeB.source.address == routeA.source.address && routeB.source.port == routeA.source.port);
    verify_reply(client, responseB, counter(responseB.material.e), reply);
    CHECK(peerCalls == peerBefore && dtlsCalls == dtlsBefore && associationCalls == associationBefore);

    // One physical socket, distinct crypto contexts. The latest endpoint route is B,
    // while an explicit A reply must remain encrypted under A's keys and counter.
    CHECK(endpoint::send_resolved_on_route(routeA, reply) == endpoint::RoutedSendResult::sent);
    verify_reply(client, responseA, counter(responseA.material.e) + 1, reply);
    CHECK(endpoint::send_resolved_to(client.local, reply) == endpoint::RoutedSendResult::sent);
    verify_reply(client, responseB, counter(responseB.material.e) + 1, reply);

    routedReply.clear(); routedDecision = endpoint::RoutedIngressResult::rejected;
    const auto denied = client_packet(responseA, counter(responseA.material.b) + 2, request);
    send(client, denied);
    pump_until([] { return routedCalls == 3; });
    CHECK(peerCalls == peerBefore && dtlsCalls == dtlsBefore && associationCalls == associationBefore);
    quiet(client);
    auto replayed = host::snapshot().replayed;
    send(client, denied);
    pump_until([&] { return host::snapshot().replayed > replayed; });
    CHECK(routedCalls == 3 && peerCalls == peerBefore);

    routedDecision = endpoint::RoutedIngressResult::unhandled;
    send(client, client_packet(responseA, counter(responseA.material.b) + 3, request));
    pump_until([&] { return peerCalls == peerBefore + 1; });
    CHECK(routedCalls == 4 && lastPeerPayload == request);
    CHECK(dtlsCalls == dtlsBefore && associationCalls == associationBefore);

    // Removing the extension restores the ordinary control consumer.
    endpoint::unregister_routed_consumer(&routed_consumer);
    send(client, client_packet(responseB, counter(responseB.material.b) + 2, request));
    pump_until([&] { return peerCalls == peerBefore + 2; });
    CHECK(routedCalls == 4);

    CHECK(endpoint::register_routed_consumer(&routed_consumer));
    CHECK(host::release_route(routeA.handle));
    CHECK(endpoint::send_resolved_on_route(routeA, reply) == endpoint::RoutedSendResult::failed);
    quiet(client);
    const auto receivedAfterRelease = receiveReports;
    send(client, client_packet(responseA, counter(responseA.material.b) + 4, request));
    pump_until([&] { return receiveReports > receivedAfterRelease; });
    CHECK(routedCalls == 4 && peerCalls == peerBefore + 2);

    auto wrong = routeB; ++wrong.handle.generation;
    CHECK(endpoint::send_resolved_on_route(wrong, reply) == endpoint::RoutedSendResult::failed);
    wrong = routeB; ++wrong.source.port;
    CHECK(endpoint::send_resolved_on_route(wrong, reply) == endpoint::RoutedSendResult::failed);
    quiet(client);
    endpoint::shutdown();
    CHECK(endpoint::send_resolved_on_route(routeB, reply) == endpoint::RoutedSendResult::failed);
    quiet(client);
    initialize_endpoint();
    CHECK(endpoint::register_routed_consumer(&other_consumer)); // Shutdown cleared the old callback.
    endpoint::unregister_routed_consumer(&other_consumer);
    endpoint::shutdown();
    host::reset();
}

int main() {
    CHECK(SetEnvironmentVariableW(L"DAWN_NATIVE_ADDRESS_RESOLUTION", L"1") != 0);
    WSADATA data{};
    CHECK(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    exercise_endpoint();
    exercise_explicit_routes();
    host::reset();
    CHECK(WSACleanup() == 0);
    std::printf("endpoint_resolution_tests: PASS %u checks (real loopback UDP, production routing/crypto)\n", checks);
}
