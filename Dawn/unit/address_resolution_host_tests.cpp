#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <span>
#include <string_view>
#include <vector>

#include "../src/core/settings/settings.h"
#include "../src/middleware/bap/address_resolution.h"
#include "../src/middleware/crypto/hmac.h"
#include "../src/middleware/crypto/legacy_des_cbc.h"
#include "../src/middleware/gameplay/descriptor/join_descriptor.h"
#include "../src/middleware/gameplay/routed_datagram.h"
#include "../src/server/gameplay/gameplay_log.h"
#include "../src/server/gameplay/resolution/address_resolution_host.h"

namespace host = dawn::server::gameplay::resolution;
namespace wire = dawn::middleware::bap::address_resolution;
namespace packet = dawn::middleware::gameplay::routed_datagram;
namespace activity = dawn::state::activity;
using Endpoint = dawn::state::gameplay::Endpoint;
using Owner = activity::AuthenticationKey;
using Request = std::array<std::byte, wire::kRequestSize>;
static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s\n", __LINE__, #value); std::abort(); } } while (false)

// Only settings and logging are replaced. The store, RNG, packet codec,
// DES-CBC, HMAC, address writer and service-301 codec are production sources.
static dawn::core::settings::Settings testSettings{};
namespace dawn::core::settings {
const Settings& get() noexcept { return testSettings; }
}
namespace dawn::server::gameplay {
void report(core::log::Level, const char*, ...) noexcept {}
}

static Owner owner(std::uint32_t id, std::uint64_t authentication = 1,
                   std::uint64_t connection = 1) {
    return {{id, {connection}}, {authentication}};
}

static void configure() {
    testSettings.server.gameplay.topology = dawn::core::settings::server::gameplay::Topology::embedded;
    testSettings.server.gameplay.advertisedAddress = {192, 168, 1, 124};
    testSettings.server.gameplay.transportAddress = {127, 0, 0, 1};
    testSettings.server.gameplay.port = 30976;
    host::reset();
}

static Request request() {
    wire::NetAddr address{};
    dawn::middleware::gameplay::descriptor::write_net_addr(0xC0A8017C, 30976, address);
    // Preserve the native opaque tail without treating it as another endpoint.
    for (std::size_t index = 41; index < 85; ++index) {
        address[index] = static_cast<std::byte>(index);
    }
    Request bytes{};
    bytes[1] = std::byte{86};
    std::copy(address.begin(), address.end(), bytes.begin() + 2);
    bytes[89] = std::byte{16};
    bytes[91] = std::byte{1};
    return bytes;
}

static std::uint64_t counter(const packet::Iv& iv) {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < iv.size(); ++index) {
        result |= std::to_integer<std::uint64_t>(iv[index]) << (8 * index);
    }
    return result;
}

static packet::Iv iv(std::uint64_t value) {
    packet::Iv result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(value >> (8 * index));
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

static std::vector<std::byte> payload(std::size_t size = 19) {
    std::vector<std::byte> result(size);
    for (std::size_t index = 0; index < size; ++index) {
        result[index] = static_cast<std::byte>(index * 17 + 3);
    }
    return result;
}

static wire::Response resolve(Owner who) {
    const auto input = request();
    std::array<std::byte, wire::kIpv4ResponseSize> output{};
    std::size_t written = 999;
    CHECK(host::resolve_address(who, input, output, written));
    CHECK(written == output.size());
    wire::Response response{};
    CHECK(wire::parse_response(output, response));
    CHECK(response.routeTag != 0 && response.port == 30976 && response.valueC == 16);
    CHECK(response.family == wire::IpFamily::ipv4);
    CHECK(response.ip[0] == std::byte{127} && response.ip[1] == std::byte{0}
          && response.ip[2] == std::byte{0} && response.ip[3] == std::byte{1});
    CHECK(std::equal(response.address.begin(), response.address.end(), input.begin() + 2));
    CHECK(counter(response.material.b) < (std::uint64_t{1} << 63));
    CHECK(counter(response.material.e) < (std::uint64_t{1} << 63));
    // Both DES keys must be usable, with the common authentication key.
    for (const bool inbound : {true, false}) {
        std::array<std::byte, 8> zero{}, encrypted{}, decrypted{};
        const auto direction = keys(response, inbound);
        CHECK(dawn::middleware::crypto::legacy_des::encrypt(direction.cipher, zero, zero, encrypted));
        CHECK(dawn::middleware::crypto::legacy_des::decrypt(direction.cipher, zero, encrypted, decrypted));
        CHECK(decrypted == zero);
    }
    return response;
}

static std::vector<std::byte> client_packet(const wire::Response& response,
                                           std::uint64_t value,
                                           std::span<const std::byte> plain) {
    std::vector<std::byte> result(packet::kMaximumDatagram);
    std::size_t written = 999;
    CHECK(packet::seal(keys(response, true), response.routeTag, iv(value), plain, result, written));
    result.resize(written);
    return result;
}

static void accepted(Endpoint peer, const std::vector<std::byte>& encoded,
                     std::span<const std::byte> expected) {
    std::vector<std::byte> output(packet::kMaximumPayload, std::byte{0xA5});
    std::size_t written = 999;
    CHECK(host::unwrap(peer, encoded, output, written) == host::PacketResult::complete);
    CHECK(written == expected.size());
    CHECK(std::equal(expected.begin(), expected.end(), output.begin()));
    CHECK(std::all_of(output.begin() + written, output.end(), [](auto b) { return b == std::byte{0xA5}; }));
}

static void rejected(Endpoint peer, std::span<const std::byte> encoded,
                     host::PacketResult expected = host::PacketResult::rejected,
                     std::size_t capacity = packet::kMaximumPayload) {
    std::vector<std::byte> output(capacity, std::byte{0xA5});
    const auto before = output;
    std::size_t written = 999;
    CHECK(host::unwrap(peer, encoded, output, written) == expected);
    CHECK(written == 0 && output == before);
}

static void rejects_resolution(Owner who, std::span<const std::byte> input,
                               std::size_t capacity = wire::kIpv4ResponseSize) {
    std::vector<std::byte> output(capacity, std::byte{0xA5});
    const auto before = output;
    const auto statistics = host::snapshot();
    std::size_t written = 999;
    CHECK(!host::resolve_address(who, input, output, written));
    CHECK(written == 0 && output == before);
    CHECK(host::snapshot().live == statistics.live && host::snapshot().created == statistics.created);
}

static void request_policy() {
    configure();
    const auto input = request();
    rejects_resolution({}, input);
    rejects_resolution(owner(7, 0), input);
    rejects_resolution(owner(7, 1, 0), input);
    for (std::size_t length = 0; length < input.size(); ++length) {
        rejects_resolution(owner(7), std::span(input).first(length));
    }
    rejects_resolution(owner(7), input, wire::kIpv4ResponseSize - 1);
    for (std::size_t index = 0; index < 41; ++index) {
        auto altered = input;
        altered[index + 2] ^= std::byte{1};
        rejects_resolution(owner(7), altered);
    }
    for (const unsigned method : {1U, 5U, 6U, 7U, 8U, 255U}) {
        auto altered = input;
        altered[87] = static_cast<std::byte>(method);
        altered[91] = method == 6 || method == 7 ? std::byte{2} : std::byte{1};
        rejects_resolution(owner(7), altered);
    }
    for (const unsigned capability : {0U, 15U, 17U, 255U, 65535U}) {
        auto altered = input;
        altered[88] = static_cast<std::byte>(capability >> 8);
        altered[89] = static_cast<std::byte>(capability);
        rejects_resolution(owner(7), altered);
    }
    using Topology = dawn::core::settings::server::gameplay::Topology;
    for (const auto topology : {Topology::disabled, Topology::external}) {
        testSettings.server.gameplay.topology = topology;
        rejects_resolution(owner(7), input);
    }
    testSettings.server.gameplay.topology = Topology::embedded;
    const auto response = resolve(owner(0)); // Protocol connection ID zero is valid.
    CHECK(response.routeTag != 0 && host::snapshot().live == 1);
}

static void authentication_binding_and_replay() {
    configure();
    const auto response = resolve(owner(10));
    const Endpoint peer{0xC0A8017C, 45000}, alternate{0xC0A8017D, 45000};
    const auto plain = payload();
    const auto floor = counter(response.material.b) + 1;
    const auto first = client_packet(response, floor, plain);

    // A rejected MAC cannot pin a peer or consume its counter.
    auto tampered = first;
    tampered.back() ^= std::byte{1};
    rejected(alternate, tampered);
    CHECK(host::snapshot().opened == 0 && host::snapshot().replayed == 0);
    rejected({0, peer.port}, first);
    rejected({peer.address, 0}, first);
    rejected(peer, client_packet(response, floor - 1, plain));
    rejected(alternate, first, host::PacketResult::rejected, plain.size() - 1);
    accepted(peer, first, plain);
    rejected(peer, first);
    CHECK(host::snapshot().replayed == 2); // Below-floor packet and duplicate.

    const auto next = client_packet(response, floor + 1, plain);
    rejected(alternate, next);
    rejected({peer.address, static_cast<std::uint16_t>(peer.port + 1)}, next);
    accepted(peer, next, plain);
    auto badNext = client_packet(response, floor + 2, plain);
    badNext[packet::kHeaderSize] ^= std::byte{1};
    rejected(peer, badNext);
    accepted(peer, client_packet(response, floor + 2, plain), plain);

    accepted(peer, client_packet(response, floor + 200, plain), plain);
    accepted(peer, client_packet(response, floor + 73, plain), plain); // Distance127.
    rejected(peer, client_packet(response, floor + 72, plain));
    rejected(peer, client_packet(response, floor + 73, plain));
    accepted(peer, client_packet(response, floor + 137, plain), plain); // Distance63.
    accepted(peer, client_packet(response, floor + 136, plain), plain); // Distance64.

    auto unknown = client_packet(response, floor + 201, plain);
    std::fill_n(unknown.begin(), 4, std::byte{}); // Zero is never a live route tag.
    rejected(peer, unknown);
    rejected(alternate, unknown, host::PacketResult::notRouted);
    rejected(peer, std::span<const std::byte>{});
    rejected(alternate, std::span<const std::byte>{}, host::PacketResult::notRouted);
}

static void authenticated_bad_padding() {
    configure();
    const auto response = resolve(owner(20));
    const Endpoint peer{0x7F000001, 45100}, alternate{0x7F000001, 45101};
    const auto first = counter(response.material.b) + 1;
    const auto packetIv = iv(first);
    const auto direction = keys(response, true);
    auto malformed = client_packet(response, first, payload(7));
    std::array<std::byte, 8> invalid{}; // Last byte zero is invalid PKCS#7.
    CHECK(dawn::middleware::crypto::legacy_des::encrypt(direction.cipher, packetIv,
        invalid, std::span(malformed).subspan(packet::kHeaderSize, 8)));
    dawn::middleware::crypto::hmac::Digest digest{};
    const auto covered = std::span(malformed).first(malformed.size() - packet::kTagSize);
    CHECK(dawn::middleware::crypto::hmac::authenticate(
        dawn::middleware::crypto::hmac::Algorithm::sha1, direction.mac, covered, {}, digest));
    std::copy_n(digest.bytes.begin(), packet::kTagSize, malformed.end() - packet::kTagSize);
    rejected(alternate, malformed);
    CHECK(host::snapshot().opened == 0 && host::snapshot().replayed == 0);
    accepted(peer, client_packet(response, first, payload(7)), payload(7));

    // Payload lengths exercise every padding width, including full-block padding.
    for (std::size_t size = 0; size <= 17; ++size) {
        const auto plain = payload(size);
        accepted(peer, client_packet(response, first + size + 1, plain), plain);
    }
}

static std::vector<std::byte> wrapped(Endpoint peer, const wire::Response& response,
                                     std::uint64_t expectedCounter,
                                     std::span<const std::byte> plain) {
    std::vector<std::byte> output(packet::kMaximumDatagram, std::byte{0xA5});
    std::size_t written = 999;
    CHECK(host::wrap(peer, plain, output, written) == host::PacketResult::complete);
    output.resize(written);
    std::array<std::byte, packet::kMaximumPayload> decoded{};
    packet::Iv received{};
    std::size_t decodedSize = 999;
    CHECK(packet::open(keys(response, false), response.routeTag, output, decoded, received, decodedSize));
    CHECK(counter(received) == expectedCounter && decodedSize == plain.size());
    CHECK(std::equal(plain.begin(), plain.end(), decoded.begin()));
    return output;
}

static void outbound_and_rekey() {
    configure();
    const auto who = owner(30);
    const auto response = resolve(who);
    const Endpoint peer{0xC0A8017D, 45200};
    const auto plain = payload();
    std::array<std::byte, 8> shortOutput{};
    shortOutput.fill(std::byte{0xA5});
    const auto untouched = shortOutput;
    std::size_t written = 999;
    CHECK(host::wrap(peer, plain, shortOutput, written) == host::PacketResult::notRouted);
    CHECK(written == 0 && shortOutput == untouched);
    accepted(peer, client_packet(response, counter(response.material.b) + 1, plain), plain);
    const auto initial = counter(response.material.e);
    static_cast<void>(wrapped(peer, response, initial, plain));
    static_cast<void>(wrapped(peer, response, initial + 1, plain));

    // Even a failed seal consumes its attempted outbound IV.
    written = 999;
    CHECK(host::wrap(peer, plain, shortOutput, written) == host::PacketResult::rejected);
    CHECK(written == 0 && shortOutput == untouched);
    static_cast<void>(wrapped(peer, response, initial + 3, plain));

    const auto newer = resolve(who);
    CHECK(newer.routeTag != response.routeTag && host::snapshot().live == 2);
    // Merely resolving a replacement cannot steal outbound traffic.
    static_cast<void>(wrapped(peer, response, initial + 4, plain));
    auto forged = client_packet(newer, counter(newer.material.b) + 1, plain);
    forged.back() ^= std::byte{1};
    rejected(peer, forged);
    static_cast<void>(wrapped(peer, response, initial + 5, plain));
    accepted(peer, client_packet(newer, counter(newer.material.b) + 1, plain), plain);
    static_cast<void>(wrapped(peer, newer, counter(newer.material.e), plain));
}

static void owner_lifecycle_and_capacity() {
    configure();
    const auto a = owner(40, 8, 7), b = owner(41, 8, 7);
    const auto responseA = resolve(a), responseB = resolve(b);
    const Endpoint peerA{0xC0A8017C, 45300}, peerB{0xC0A8017D, 45301};
    const auto plain = payload();
    accepted(peerA, client_packet(responseA, counter(responseA.material.b) + 1, plain), plain);
    accepted(peerB, client_packet(responseB, counter(responseB.material.b) + 1, plain), plain);
    host::release_owner(owner(40, 9, 7));
    host::release_owner(owner(40, 8, 8));
    host::release_owner({});
    CHECK(host::snapshot().live == 2);
    accepted(peerA, client_packet(responseA, counter(responseA.material.b) + 2, plain), plain);
    host::release_owner(a);
    CHECK(host::snapshot().live == 1);
    rejected(peerA, client_packet(responseA, counter(responseA.material.b) + 3, plain), host::PacketResult::notRouted);
    accepted(peerB, client_packet(responseB, counter(responseB.material.b) + 2, plain), plain);
    static_cast<void>(wrapped(peerB, responseB, counter(responseB.material.e), plain));
    host::release_owner(a); // Idempotent exact-generation release.
    CHECK(host::snapshot().live == 1);

    configure();
    std::set<std::uint32_t> tags;
    for (std::uint32_t index = 0; index < 16; ++index) {
        CHECK(tags.insert(resolve(owner(index + 100)).routeTag).second);
    }
    CHECK(host::snapshot().live == 16);
    rejects_resolution(owner(999), request());
    host::release_owner(owner(107, 2));
    rejects_resolution(owner(999), request());
    host::release_owner(owner(107));
    CHECK(host::snapshot().live == 15);
    static_cast<void>(resolve(owner(999)));
    CHECK(host::snapshot().live == 16);
    host::reset();
    const auto empty = host::snapshot();
    CHECK(empty.live == 0 && empty.created == 0 && empty.opened == 0
          && empty.rejected == 0 && empty.replayed == 0 && empty.wrapped == 0);
}

static void disabled_mode() {
    CHECK(SetEnvironmentVariableW(L"DAWN_NATIVE_ADDRESS_RESOLUTION", nullptr) != 0);
    CHECK(!host::enabled());
    configure();
    rejects_resolution(owner(1), request());
    rejected({0x7F000001, 45000}, payload(), host::PacketResult::notRouted);
    std::array<std::byte, 128> output{};
    output.fill(std::byte{0xA5});
    const auto before = output;
    std::size_t written = 999;
    CHECK(host::wrap({0x7F000001, 45000}, payload(), output, written) == host::PacketResult::notRouted);
    CHECK(written == 0 && output == before && host::snapshot().live == 0);
    CHECK(SetEnvironmentVariableW(L"DAWN_NATIVE_ADDRESS_RESOLUTION", L"1") != 0);
    CHECK(!host::enabled()); // This DLL/process lifetime keeps its initial policy.
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--disabled") {
        disabled_mode();
    } else {
        CHECK(SetEnvironmentVariableW(L"DAWN_NATIVE_ADDRESS_RESOLUTION", L"1") != 0);
        CHECK(host::enabled());
        request_policy();
        authentication_binding_and_replay();
        authenticated_bad_padding();
        outbound_and_rekey();
        owner_lifecycle_and_capacity();
    }
    host::reset();
    std::printf("address_resolution_host_tests: PASS %u checks\n", checks);
}
