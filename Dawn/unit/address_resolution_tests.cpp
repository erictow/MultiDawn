#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>

#include "../src/middleware/bap/address_resolution.h"
#include "../src/middleware/bap/frame.h"
#include "../src/middleware/encoding/byte_order.h"

namespace wire = dawn::middleware::bap::address_resolution;
static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s\n", __LINE__, #value); std::abort(); } } while (false)

template <std::size_t Size>
static std::array<std::byte, Size> hex(std::string_view text) {
    std::array<std::byte, Size> result{};
    CHECK(text.size() == Size * 2);
    const auto digit = [](char value) -> unsigned {
        if (value >= '0' && value <= '9') { return static_cast<unsigned>(value - '0'); }
        if (value >= 'a' && value <= 'f') { return static_cast<unsigned>(value - 'a') + 10U; }
        std::abort();
    };
    for (std::size_t index = 0; index < Size; ++index) {
        result[index] = static_cast<std::byte>((digit(text[index * 2]) << 4U) | digit(text[index * 2 + 1]));
    }
    return result;
}

template <std::size_t Size>
static void sequence(std::array<std::byte, Size>& output, unsigned first) {
    for (std::size_t index = 0; index < Size; ++index) {
        output[index] = static_cast<std::byte>(first + static_cast<unsigned>(index));
    }
}

static wire::Response sample_response(wire::IpFamily family) {
    wire::Response response{};
    sequence(response.material.a, 0);
    sequence(response.material.b, 0x10);
    sequence(response.material.d, 0x80);
    sequence(response.material.e, 0x90);
    sequence(response.material.f, 0xA0);
    sequence(response.address, 0x20);
    response.address.back() = std::byte{6};
    response.valueC = 0xBEEF;
    response.port = 12345;
    response.family = family;
    response.routeTag = 0x12345678;
    if (family == wire::IpFamily::ipv4) {
        response.ip[0] = std::byte{192}; response.ip[1] = std::byte{168};
        response.ip[2] = std::byte{1}; response.ip[3] = std::byte{124};
    } else {
        response.ip = hex<16>("20010db8000000000000000000000001");
    }
    return response;
}

static void request_tests() {
    auto bytes = hex<92>(
        "0056"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737406"
        "00100002");
    wire::Request parsed{};
    CHECK(wire::parse_request(bytes, parsed));
    CHECK(parsed.address == sample_response(wire::IpFamily::ipv4).address);
    CHECK(parsed.capability == 16 && parsed.kind == 2);
    const wire::Request sentinel = parsed;
    // Every truncation and a trailing byte must fail without publishing partial state.
    for (std::size_t length = 0; length < bytes.size(); ++length) {
        CHECK(!wire::parse_request(std::span(bytes).first(length), parsed) && parsed == sentinel);
    }
    std::array<std::byte, 93> trailing{};
    std::copy(bytes.begin(), bytes.end(), trailing.begin());
    CHECK(!wire::parse_request(trailing, parsed) && parsed == sentinel);
    for (unsigned method = 0; method <= 7; ++method) {
        auto changed = bytes;
        changed[87] = static_cast<std::byte>(method);
        changed[91] = method < 6 ? std::byte{1} : std::byte{2};
        CHECK(wire::parse_request(changed, parsed));
        CHECK(parsed.address.back() == static_cast<std::byte>(method));
        const auto before = parsed;
        changed[91] = method < 6 ? std::byte{2} : std::byte{1};
        CHECK(!wire::parse_request(changed, parsed) && parsed == before);
    }
    for (const unsigned method : {8U, 255U}) {
        auto changed = bytes;
        changed[87] = static_cast<std::byte>(method);
        const auto before = parsed;
        CHECK(!wire::parse_request(changed, parsed) && parsed == before);
    }
    for (const unsigned length : {0U, 85U, 87U, 255U}) {
        auto changed = bytes;
        changed[1] = static_cast<std::byte>(length);
        const auto before = parsed;
        CHECK(!wire::parse_request(changed, parsed) && parsed == before);
    }
    // The capability is not a port. Preserve unknown values, including zero.
    for (const unsigned capability : {0U, 16U, 255U, 65535U}) {
        bytes[88] = static_cast<std::byte>(capability >> 8U);
        bytes[89] = static_cast<std::byte>(capability);
        CHECK(wire::parse_request(bytes, parsed) && parsed.capability == capability);
    }
    auto littleEndianLength = bytes;
    littleEndianLength[0] = std::byte{86}; littleEndianLength[1] = std::byte{};
    CHECK(!wire::parse_request(littleEndianLength, parsed));
}

template <std::size_t Size>
static void response_tests(const std::array<std::byte, Size>& golden, wire::IpFamily family) {
    const auto expected = sample_response(family);
    wire::Response parsed{};
    CHECK(wire::parse_response(golden, parsed) && parsed == expected);
    std::array<std::byte, 200> output{};
    output.fill(std::byte{0xCC});
    std::size_t written = 999;
    CHECK(wire::encode_response(expected, output, written) && written == Size);
    CHECK(std::equal(golden.begin(), golden.end(), output.begin()));
    CHECK(std::all_of(output.begin() + Size, output.end(), [](auto value) { return value == std::byte{0xCC}; }));
    CHECK(output[24] == std::byte{} && output[25] == std::byte{86});
    CHECK(output[112] == std::byte{0xBE} && output[113] == std::byte{0xEF});
    CHECK(output[154] == std::byte{0x30} && output[155] == std::byte{0x39});
    CHECK(output[Size - 4] == std::byte{0x12} && output[Size - 1] == std::byte{0x78});
    CHECK(parsed.material == expected.material && parsed.address == expected.address);
    // The encoder stages the whole record before publishing, including when
    // caller-provided output aliases the object containing security material.
    struct AliasStorage { wire::Response response; std::array<std::byte, 32> spare{}; };
    AliasStorage aliased{expected};
    auto aliasedBytes = std::as_writable_bytes(std::span(&aliased, 1));
    CHECK(wire::encode_response(aliased.response, aliasedBytes, written) && written == Size);
    CHECK(std::equal(golden.begin(), golden.end(), aliasedBytes.begin()));
    for (std::size_t length = 0; length < Size; ++length) {
        CHECK(!wire::parse_response(std::span(golden).first(length), parsed) && parsed == expected);
        output.fill(std::byte{0xCC});
        const auto untouched = output;
        written = 999;
        CHECK(!wire::encode_response(expected, std::span(output).first(length), written));
        CHECK(written == 0 && output == untouched);
    }
    std::array<std::byte, Size + 1> trailing{};
    std::copy(golden.begin(), golden.end(), trailing.begin());
    CHECK(!wire::parse_response(trailing, parsed) && parsed == expected);
    for (const unsigned length : {0U, 85U, 87U, 255U}) {
        auto changed = golden;
        changed[25] = static_cast<std::byte>(length);
        CHECK(!wire::parse_response(changed, parsed) && parsed == expected);
    }
    for (const unsigned ipLength : {0U, 1U, 6U, 32U, 255U}) {
        auto changed = golden;
        changed[157] = static_cast<std::byte>(ipLength);
        CHECK(!wire::parse_response(changed, parsed) && parsed == expected);
    }
    auto otherFamilyLength = golden;
    otherFamilyLength[157] = family == wire::IpFamily::ipv4 ? std::byte{16} : std::byte{4};
    CHECK(!wire::parse_response(otherFamilyLength, parsed) && parsed == expected);
    auto invalidMethod = golden;
    invalidMethod[111] = std::byte{8};
    CHECK(!wire::parse_response(invalidMethod, parsed) && parsed == expected);
    for (const unsigned method : {0U, 5U, 6U, 7U}) {
        auto changed = expected;
        changed.address.back() = static_cast<std::byte>(method);
        CHECK(wire::encode_response(changed, output, written));
        CHECK(wire::parse_response(std::span(output).first(written), parsed) && parsed == changed);
    }
    // Native 301 accepts zero port/tag and arbitrary C. They are not kind/family
    // constraints. A future authenticated route must validate usable endpoints.
    for (const std::uint32_t tag : {0U, 1U, 2U, 0xFFFFFFFFU}) {
        auto changed = expected;
        changed.port = 0; changed.routeTag = tag; changed.valueC = tag == 0 ? 0 : 0xFFFF;
        CHECK(wire::encode_response(changed, output, written));
        CHECK(wire::parse_response(std::span(output).first(written), parsed) && parsed == changed);
    }
    for (const bool invalidFamily : {false, true}) {
        auto invalid = expected;
        if (invalidFamily) { invalid.family = static_cast<wire::IpFamily>(255); }
        else { invalid.address.back() = std::byte{255}; }
        output.fill(std::byte{0xCC});
        const auto untouched = output;
        written = 999;
        CHECK(!wire::encode_response(invalid, output, written) && written == 0 && output == untouched);
    }
}

static void notification_framing_tests() {
    namespace bap = dawn::middleware::bap;
    namespace encoding = dawn::middleware::encoding;
    for (const auto family : {wire::IpFamily::ipv4, wire::IpFamily::ipv6}) {
        const auto expected = sample_response(family);
        std::array<std::byte, wire::kIpv6ResponseSize> body{};
        std::array<std::byte, 256> payload{};
        std::size_t bodySize{}, size{};
        CHECK(wire::encode_response(expected, body, bodySize));
        const auto bytes = std::span(body).first(bodySize);
        CHECK(bap::encode_response_payload(bap::ResponseService::resolvePeerAddress,
              0x12345678, bytes, payload, size));
        CHECK(size == 6 + bodySize);
        CHECK(encoding::read_u16_be(std::span(payload).first<2>()) == 301);
        CHECK(encoding::read_u32_be(std::span(payload).subspan<2, 4>()) == 0x12345678);
        // Follow the native push decoder: skip only service/task, then decode.
        wire::Response decoded{};
        CHECK(wire::parse_response(std::span(payload).subspan(6, size - 6), decoded));
        CHECK(decoded == expected);
        CHECK(std::equal(bytes.begin(), bytes.end(), payload.begin() + 6));
        const auto untouched = payload;
        size = 999;
        CHECK(!bap::encode_response_payload(bap::ResponseService::resolvePeerAddress,
              1, bytes, std::span(payload).first(5 + bodySize), size));
        CHECK(size == 0 && payload == untouched);
        // Other service replies retain their status-200 field and body offset.
        CHECK(bap::encode_response_payload(bap::ResponseService::echo,
              0x87654321, bytes, payload, size));
        CHECK(size == 8 + bodySize);
        CHECK(encoding::read_u16_be(std::span(payload).subspan<6, 2>()) == 200);
        CHECK(std::equal(bytes.begin(), bytes.end(), payload.begin() + 8));
        std::array<std::byte, 280> framed{};
        CHECK(bap::encode_response(bap::ResponseService::resolvePeerAddress,
              0x12345678, bap::FrameType::plaintext2, bytes, framed, size));
        bap::RequestFrame notification{};
        CHECK(bap::parse_request(std::span(framed).first(size), notification));
        CHECK(notification.messageId == 301 && notification.taskId == 0x12345678);
        CHECK(wire::parse_response(notification.body, decoded) && decoded == expected);
    }
}

int main() {
    request_tests();
    notification_framing_tests();
    const auto ipv4 = hex<166>(
        "000102030405060708090a0b0c0d0e0f1011121314151617"
        "0056"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737406"
        "beef808182838485868788898a8b8c8d8e8f9091929394959697"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf30390004c0a8017c12345678");
    const auto ipv6 = hex<178>(
        "000102030405060708090a0b0c0d0e0f1011121314151617"
        "0056"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f707172737406"
        "beef808182838485868788898a8b8c8d8e8f9091929394959697"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf3039001020010db800000000000000000000000112345678");
    response_tests(ipv4, wire::IpFamily::ipv4);
    response_tests(ipv6, wire::IpFamily::ipv6);
    // Unused IPv4 storage is never serialized or retained by the decoder.
    auto padded = sample_response(wire::IpFamily::ipv4);
    std::fill(padded.ip.begin() + 4, padded.ip.end(), std::byte{0xEE});
    std::array<std::byte, 166> bytes{};
    std::size_t written{};
    CHECK(wire::encode_response(padded, bytes, written) && bytes == ipv4);
    wire::Response normalized{};
    CHECK(wire::parse_response(bytes, normalized) && normalized == sample_response(wire::IpFamily::ipv4));
    std::puts("Address resolution codecs: canonical bodies only, no live routing exercised.");
    std::printf("PASS: %u address resolution checks\n", checks);
}
