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

static void unavailable_route(Owner who) {
    host::AuthenticatedRoute output{{owner(999), 999}, {0x01020304, 12345}};
    CHECK(!host::lookup_authenticated_route(who, output));
    CHECK(!static_cast<bool>(output.handle) && output.handle.owner == Owner{}
          && output.handle.generation == 0 && output.source.address == 0 && output.source.port == 0);
}

static host::AuthenticatedRoute observed_route(Owner who, Endpoint source) {
    host::AuthenticatedRoute output{};
    CHECK(host::lookup_authenticated_route(who, output));
    CHECK(output.handle.owner == who && output.handle.generation != 0);
    CHECK(output.source.address == source.address && output.source.port == source.port);
    CHECK(host::validate_authenticated_route(output));
    return output;
}

static void absent_metadata(const host::AuthenticatedRoute& matched) {
    CHECK(matched.handle.owner == Owner{} && matched.handle.generation == 0);
    CHECK(matched.source.address == 0 && matched.source.port == 0);
}

static host::AuthenticatedRoute accepted_with_metadata(
    Endpoint source, const std::vector<std::byte>& encoded,
    std::span<const std::byte> expected, Owner who) {
    std::vector<std::byte> output(packet::kMaximumPayload, std::byte{0xA5});
    std::size_t written = 999;
    host::AuthenticatedRoute matched{{owner(999), 999}, {1, 2}};
    CHECK(host::unwrap(source, encoded, output, written, matched) == host::PacketResult::complete);
    CHECK(written == expected.size() && std::equal(expected.begin(), expected.end(), output.begin()));
    CHECK(std::all_of(output.begin() + written, output.end(), [](auto b) { return b == std::byte{0xA5}; }));
    CHECK(matched.handle.owner == who && matched.handle.generation != 0);
    CHECK(matched.source.address == source.address && matched.source.port == source.port);
    return matched;
}

static void rejected_with_metadata(
    Endpoint source, std::span<const std::byte> encoded,
    host::PacketResult expected = host::PacketResult::rejected,
    std::size_t capacity = packet::kMaximumPayload) {
    std::vector<std::byte> output(capacity, std::byte{0xA5});
    const auto before = output;
    std::size_t written = 999;
    host::AuthenticatedRoute matched{{owner(999), 999}, {1, 2}};
    CHECK(host::unwrap(source, encoded, output, written, matched) == expected);
    CHECK(written == 0 && output == before);
    absent_metadata(matched);
}

static void rejected_explicit(const host::AuthenticatedRoute& route,
                              host::PacketResult expected = host::PacketResult::rejected,
                              std::size_t capacity = packet::kMaximumDatagram) {
    std::vector<std::byte> output(capacity, std::byte{0xA5});
    const auto before = output;
    const auto wrappedBefore = host::snapshot().wrapped;
    std::size_t written = 999;
    CHECK(host::wrap_authenticated_route(route, payload(), output, written) == expected);
    CHECK(written == 0 && output == before);
    CHECK(host::snapshot().wrapped == wrappedBefore);
}

static std::vector<std::byte> wrapped_explicit(
    const host::AuthenticatedRoute& route, const wire::Response& response,
    std::uint64_t expectedCounter, std::span<const std::byte> plain) {
    std::vector<std::byte> output(packet::kMaximumDatagram, std::byte{0xA5});
    std::size_t written = 999;
    CHECK(host::wrap_authenticated_route(route, plain, output, written) == host::PacketResult::complete);
    output.resize(written);
    std::array<std::byte, packet::kMaximumPayload> decoded{};
    packet::Iv received{};
    std::size_t decodedSize = 999;
    CHECK(packet::open(keys(response, false), response.routeTag, output, decoded, received, decodedSize));
    CHECK(counter(received) == expectedCounter && decodedSize == plain.size());
    CHECK(std::equal(plain.begin(), plain.end(), decoded.begin()));
    return output;
}

static void rejects_other_context(const wire::Response& other,
                                  std::span<const std::byte> encoded) {
    std::array<std::byte, packet::kMaximumPayload> decoded{};
    packet::Iv ignored{};
    std::size_t written = 999;
    CHECK(!packet::open(keys(other, false), other.routeTag, encoded, decoded, ignored, written));
    CHECK(written == 0);
}

static void exact_ingress_and_reply_routes() {
    configure();
    const auto a = owner(80, 2, 3), b = owner(81, 2, 3);
    const auto responseA = resolve(a), responseB = resolve(b);
    const Endpoint source{0x7F000001, 45500}, otherSource{0x7F000001, 45501};
    const auto plain = payload();
    const auto floorA = counter(responseA.material.b) + 1;
    const auto floorB = counter(responseB.material.b) + 1;
    const auto sendA = counter(responseA.material.e), sendB = counter(responseB.material.e);
    rejected_explicit({});

    // A handle is disclosed only by a fully authenticated, accepted packet.
    const std::array<std::byte, 4> unknown{}; // Route tag zero is never allocated.
    rejected_with_metadata(otherSource, unknown, host::PacketResult::notRouted);
    rejected_with_metadata(otherSource, {}, host::PacketResult::notRouted);
    const auto firstA = client_packet(responseA, floorA, plain);
    auto forged = firstA;
    forged.back() ^= std::byte{1};
    rejected_with_metadata(source, forged);
    rejected_with_metadata({0, source.port}, firstA);
    rejected_with_metadata({source.address, 0}, firstA);
    rejected_with_metadata(source, client_packet(responseA, floorA - 1, plain));
    rejected_with_metadata(source, firstA, host::PacketResult::rejected, plain.size() - 1);
    const auto routeA = accepted_with_metadata(source, firstA, plain, a);
    CHECK(host::validate_authenticated_route(routeA));
    rejected_with_metadata(source, firstA); // Replay cannot expose the old route as a success.
    rejected_with_metadata(otherSource, client_packet(responseA, floorA + 1, plain));
    rejected_with_metadata(source, unknown);

    // A valid MAC with malformed padding still cannot publish a route or consume replay state.
    auto malformed = client_packet(responseB, floorB, payload(7));
    std::array<std::byte, 8> invalid{};
    const auto inboundB = keys(responseB, true);
    CHECK(dawn::middleware::crypto::legacy_des::encrypt(inboundB.cipher, iv(floorB),
        invalid, std::span(malformed).subspan(packet::kHeaderSize, 8)));
    dawn::middleware::crypto::hmac::Digest digest{};
    CHECK(dawn::middleware::crypto::hmac::authenticate(
        dawn::middleware::crypto::hmac::Algorithm::sha1, inboundB.mac,
        std::span(malformed).first(malformed.size() - packet::kTagSize), {}, digest));
    std::copy_n(digest.bytes.begin(), packet::kTagSize, malformed.end() - packet::kTagSize);
    rejected_with_metadata(source, malformed);
    const auto routeB = accepted_with_metadata(source, client_packet(responseB, floorB, plain), plain, b);
    CHECK(routeA.handle != routeB.handle && routeA.source.address == routeB.source.address
          && routeA.source.port == routeB.source.port);
    CHECK(!host::validate_authenticated_route(routeA)); // Legacy selected-route semantics remain.
    unavailable_route(a);
    CHECK(host::validate_authenticated_route(routeB));

    const auto encodedA = wrapped_explicit(routeA, responseA, sendA, plain);
    rejects_other_context(responseB, encodedA);
    static_cast<void>(wrapped(source, responseB, sendB, plain));
    const auto encodedB = wrapped_explicit(routeB, responseB, sendB + 1, plain);
    rejects_other_context(responseA, encodedB);
    static_cast<void>(wrapped_explicit(routeA, responseA, sendA + 1, plain));
    // Explicit replies never steal the legacy endpoint selection or reset its IV.
    static_cast<void>(wrapped(source, responseB, sendB + 2, plain));

    // Reusing a prior metadata object as both the source and output is well-defined.
    auto alias = routeA;
    std::array<std::byte, packet::kMaximumPayload> decoded{};
    std::size_t written = 999;
    CHECK(host::unwrap(alias.source, client_packet(responseA, floorA + 1, plain), decoded, written, alias)
          == host::PacketResult::complete);
    CHECK(alias.handle == routeA.handle && alias.source.address == source.address && alias.source.port == source.port);
    CHECK(written == plain.size() && std::equal(plain.begin(), plain.end(), decoded.begin()));
    static_cast<void>(wrapped(source, responseA, sendA + 2, plain));
    static_cast<void>(wrapped_explicit(routeA, responseA, sendA + 3, plain));
    static_cast<void>(wrapped_explicit(routeB, responseB, sendB + 3, plain));

    // Multiple contexts owned by one authentication also remain individually addressable.
    const auto responseA2 = resolve(a);
    unavailable_route(b);
    const auto routeA2 = accepted_with_metadata(source,
        client_packet(responseA2, counter(responseA2.material.b) + 1, plain), plain, a);
    CHECK(routeA2.handle.owner == routeA.handle.owner && routeA2.handle.generation > routeA.handle.generation);
    CHECK(!host::validate_authenticated_route(routeA) && host::validate_authenticated_route(routeA2));
    const auto sendA2 = counter(responseA2.material.e);
    static_cast<void>(wrapped(source, responseA2, sendA2, plain));
    static_cast<void>(wrapped_explicit(routeA, responseA, sendA + 4, plain));
    static_cast<void>(wrapped_explicit(routeB, responseB, sendB + 4, plain));

    // Both APIs share the same context IV, including valid attempts that cannot seal.
    rejected_explicit(routeA, host::PacketResult::rejected, 8);
    static_cast<void>(wrapped_explicit(routeA, responseA, sendA + 6, plain));
    static_cast<void>(wrapped(source, responseA2, sendA2 + 1, plain));
    std::array<std::byte, 8> shortOutput{};
    shortOutput.fill(std::byte{0xA5});
    const auto untouched = shortOutput;
    written = 999;
    CHECK(host::wrap(source, plain, shortOutput, written) == host::PacketResult::rejected);
    CHECK(written == 0 && shortOutput == untouched);
    static_cast<void>(wrapped_explicit(routeA2, responseA2, sendA2 + 3, plain));

    for (unsigned change = 0; change < 8; ++change) {
        auto altered = routeA;
        switch (change) {
        case 0: altered.handle.owner = b; break;
        case 1: ++altered.handle.owner.connection.generation.value; break;
        case 2: ++altered.handle.owner.generation.value; break;
        case 3: altered.handle.generation = routeB.handle.generation; break;
        case 4: altered.handle.generation = 0; break;
        case 5: ++altered.source.address; break;
        case 6: ++altered.source.port; break;
        case 7: altered.source = {}; break;
        }
        rejected_explicit(altered);
    }
    static_cast<void>(wrapped_explicit(routeA, responseA, sendA + 7, plain)); // Bad handles consume no IV.

    // Exact owner teardown invalidates all of its contexts without falling back to B.
    host::release_owner(a);
    rejected_explicit(routeA);
    rejected_explicit(routeA2);
    static_cast<void>(wrapped(source, responseB, sendB + 5, plain));
    static_cast<void>(wrapped_explicit(routeB, responseB, sendB + 6, plain));
    host::release_owner(b);
    rejected_explicit(routeB);

    // Slot reuse and reset cannot turn a stale generation into a new matching context.
    const auto reused = resolve(a);
    const auto afterRelease = accepted_with_metadata(source,
        client_packet(reused, counter(reused.material.b) + 1, plain), plain, a);
    CHECK(afterRelease.handle.generation > routeA2.handle.generation);
    rejected_explicit(routeA);
    rejected_explicit(routeA2);
    static_cast<void>(wrapped_explicit(afterRelease, reused, counter(reused.material.e), plain));
    host::reset();
    rejected_explicit(afterRelease);
    const auto recreated = resolve(a);
    const auto afterReset = accepted_with_metadata(source,
        client_packet(recreated, counter(recreated.material.b) + 1, plain), plain, a);
    CHECK(afterReset.handle.generation > afterRelease.handle.generation);
    rejected_explicit(afterRelease);
    static_cast<void>(wrapped_explicit(afterReset, recreated, counter(recreated.material.e), plain));
}

static void exact_route_retirement() {
    configure();
    const auto a = owner(90, 5, 6), b = owner(91, 5, 6);
    const Endpoint source{0x7F000001, 45600};
    const auto plain = payload();
    const auto responseA1 = resolve(a), responseA2 = resolve(a), responseB = resolve(b);
    const auto routeA1 = accepted_with_metadata(source,
        client_packet(responseA1, counter(responseA1.material.b) + 1, plain), plain, a);
    const auto routeB = accepted_with_metadata(source,
        client_packet(responseB, counter(responseB.material.b) + 1, plain), plain, b);
    const auto routeA2 = accepted_with_metadata(source,
        client_packet(responseA2, counter(responseA2.material.b) + 1, plain), plain, a);
    CHECK(host::snapshot().live == 3);
    CHECK(host::validate_authenticated_route(routeA2));

    CHECK(!host::release_route({}));
    auto wrong = routeA1.handle;
    wrong.owner = b;
    CHECK(!host::release_route(wrong));
    wrong = routeA1.handle; ++wrong.owner.connection.generation.value;
    CHECK(!host::release_route(wrong));
    wrong = routeA1.handle; ++wrong.owner.generation.value;
    CHECK(!host::release_route(wrong));
    wrong = routeA1.handle; wrong.generation = routeB.handle.generation;
    CHECK(!host::release_route(wrong));
    CHECK(host::snapshot().live == 3 && host::validate_authenticated_route(routeA2));

    CHECK(host::release_route(routeA1.handle));
    CHECK(!host::release_route(routeA1.handle) && host::snapshot().live == 2);
    rejected_explicit(routeA1);
    rejected_with_metadata(source, client_packet(responseA1, counter(responseA1.material.b) + 2, plain));
    // Releasing an older sibling must not change current owner or endpoint selection.
    CHECK(host::validate_authenticated_route(routeA2));
    static_cast<void>(wrapped(source, responseA2, counter(responseA2.material.e), plain));
    static_cast<void>(wrapped_explicit(routeA2, responseA2, counter(responseA2.material.e) + 1, plain));
    static_cast<void>(wrapped_explicit(routeB, responseB, counter(responseB.material.e), plain));

    const auto responseReused = resolve(a);
    const auto reused = accepted_with_metadata(source,
        client_packet(responseReused, counter(responseReused.material.b) + 1, plain), plain, a);
    CHECK(reused.handle.generation > routeA2.handle.generation);
    CHECK(!host::release_route(routeA1.handle));
    CHECK(host::snapshot().live == 3 && host::validate_authenticated_route(reused));
    rejected_explicit(routeA1);

    // Removing the selected route falls back only for the endpoint API, never for its handle.
    CHECK(host::release_route(reused.handle));
    CHECK(!host::release_route(reused.handle));
    rejected_explicit(reused);
    CHECK(host::validate_authenticated_route(routeA2));
    static_cast<void>(wrapped(source, responseA2, counter(responseA2.material.e) + 2, plain));
    CHECK(host::release_route(routeA2.handle));
    CHECK(host::validate_authenticated_route(routeB));
    static_cast<void>(wrapped(source, responseB, counter(responseB.material.e) + 1, plain));
    CHECK(host::release_route(routeB.handle) && host::snapshot().live == 0);
    CHECK(!host::release_route(routeB.handle));
    rejected_explicit(routeB);
}

static void authenticated_route_observation() {
    configure();
    const auto a = owner(60, 2, 3), b = owner(61, 2, 3);
    const Endpoint firstSource{0xC0A8017C, 45400}, currentSource{0xC0A8017D, 45401};
    const auto plain = payload();
    unavailable_route({});
    unavailable_route(a);
    CHECK(!host::validate_authenticated_route({}));
    const auto response = resolve(a);
    unavailable_route(a); // BAP resolution alone is not proof of a UDP source.
    const auto floor = counter(response.material.b) + 1;
    auto tampered = client_packet(response, floor, plain);
    tampered.back() ^= std::byte{1};
    rejected(firstSource, tampered);
    unavailable_route(a);
    rejected({0, firstSource.port}, client_packet(response, floor, plain));
    unavailable_route(a);
    rejected(firstSource, client_packet(response, floor - 1, plain));
    unavailable_route(a);
    rejected(firstSource, client_packet(response, floor, plain), host::PacketResult::rejected, plain.size() - 1);
    unavailable_route(a);
    accepted(firstSource, client_packet(response, floor, plain), plain);
    const auto initial = observed_route(a, firstSource);
    unavailable_route(owner(60, 3, 3));
    unavailable_route(owner(60, 2, 4));
    unavailable_route(b);
    for (const auto wrongOwner : {owner(60, 3, 3), owner(60, 2, 4), b}) {
        auto altered = initial;
        altered.handle.owner = wrongOwner;
        CHECK(!host::validate_authenticated_route(altered));
    }
    auto altered = initial;
    ++altered.handle.generation;
    CHECK(!host::validate_authenticated_route(altered));
    altered = initial; ++altered.source.address;
    CHECK(!host::validate_authenticated_route(altered));
    altered = initial; ++altered.source.port;
    CHECK(!host::validate_authenticated_route(altered));

    // An unbound or forged replacement cannot change the selected observation.
    const auto newer = resolve(a);
    CHECK(host::validate_authenticated_route(initial));
    tampered = client_packet(newer, counter(newer.material.b) + 1, plain);
    tampered.back() ^= std::byte{1};
    rejected(currentSource, tampered);
    CHECK(host::validate_authenticated_route(initial));
    accepted(currentSource, client_packet(newer, counter(newer.material.b) + 1, plain), plain);
    const auto current = observed_route(a, currentSource);
    CHECK(current.handle.generation != initial.handle.generation);
    CHECK(!host::validate_authenticated_route(initial)); // Old context is still allocated.

    // Endpoint equality cannot alias another authentication owner's current route.
    const auto otherResponse = resolve(b);
    accepted(currentSource, client_packet(otherResponse, counter(otherResponse.material.b) + 1, plain), plain);
    const auto other = observed_route(b, currentSource);
    unavailable_route(a);
    CHECK(!host::validate_authenticated_route(current));
    altered = other; altered.handle.owner = a;
    CHECK(!host::validate_authenticated_route(altered));
    // Existing wrap selection follows the newest authenticated packet, not resolution order.
    accepted(currentSource, client_packet(newer, counter(newer.material.b) + 2, plain), plain);
    CHECK(host::validate_authenticated_route(current));
    CHECK(!host::validate_authenticated_route(other));
    unavailable_route(b);
    host::release_owner(owner(60, 3, 3));
    CHECK(host::validate_authenticated_route(current));
    host::release_owner(a);
    CHECK(!host::validate_authenticated_route(current));
    unavailable_route(a);

    // Reusing a free slot with the same owner and endpoint never reuses its handle.
    const auto reused = resolve(a);
    accepted(currentSource, client_packet(reused, counter(reused.material.b) + 1, plain), plain);
    const auto afterRelease = observed_route(a, currentSource);
    CHECK(afterRelease.handle.generation > current.handle.generation);
    CHECK(!host::validate_authenticated_route(current));
    host::reset();
    unavailable_route(a);
    CHECK(!host::validate_authenticated_route(afterRelease));
    const auto resetResponse = resolve(a);
    unavailable_route(a);
    accepted(currentSource, client_packet(resetResponse, counter(resetResponse.material.b) + 1, plain), plain);
    const auto afterReset = observed_route(a, currentSource);
    CHECK(afterReset.handle.generation > afterRelease.handle.generation);
    CHECK(!host::validate_authenticated_route(afterRelease));
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
    unavailable_route(owner(1));
    CHECK(!host::validate_authenticated_route({{owner(1), 1}, {0x7F000001, 45000}}));
    rejected_with_metadata({0x7F000001, 45000}, payload(), host::PacketResult::notRouted);
    rejected_explicit({{owner(1), 1}, {0x7F000001, 45000}}, host::PacketResult::notRouted);
    CHECK(!host::release_route({owner(1), 1}));
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
        authenticated_route_observation();
        exact_ingress_and_reply_routes();
        exact_route_retirement();
    }
    host::reset();
    std::printf("address_resolution_host_tests: PASS %u checks\n", checks);
}
