#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dawn::middleware::bap::address_resolution {

inline constexpr std::uint16_t kRequestMessageId = 300;
inline constexpr std::uint16_t kResponseMessageId = 301;
inline constexpr std::size_t kNetAddrSize = 86;
inline constexpr std::size_t kRequestSize = 92;
inline constexpr std::size_t kIpv4ResponseSize = 166;
inline constexpr std::size_t kIpv6ResponseSize = 178;
using NetAddr = std::array<std::byte, kNetAddrSize>;

/** The canonical build-86657 BAP300 body, excluding the outer BAP frame. */
struct Request {
    NetAddr address{};
    /** Wire offset 88: a capability/protocol value, not a UDP port. Preserve it. */
    std::uint16_t capability{};
    /** Wire offset 90: 1 for NetAddr methods 0..5, 2 for methods 6/7. */
    std::uint16_t kind{};
    bool operator==(const Request&) const = default;
};

/**
 * Caller-provided native security/counter material. The codec preserves every
 * byte; it neither generates values nor supplies a usable production default.
 * Do not log these fields. Their directional binding belongs to a future policy
 * boundary, not this wire codec.
 */
struct OpaqueMaterial {
    std::array<std::byte, 16> a{};
    std::array<std::byte, 8> b{};
    std::array<std::byte, 16> d{};
    std::array<std::byte, 8> e{};
    std::array<std::byte, 16> f{};
    bool operator==(const OpaqueMaterial&) const = default;
};

enum class IpFamily : std::uint8_t { ipv4, ipv6 };

/**
 * Canonical BAP301 body. Native decoded storage is 182 bytes, but the wire is
 * 166/178 bytes. IP bytes are already in network order. IPv4 uses only the first
 * four bytes; decoding clears the unused twelve bytes.
 */
struct Response {
    OpaqueMaterial material{};
    NetAddr address{};
    /** Wire offset 112: native parses this value; its meaning is unresolved. */
    std::uint16_t valueC{};
    std::uint16_t port{};
    IpFamily family{IpFamily::ipv4};
    std::array<std::byte, 16> ip{};
    /** Final BE32 field, later prefixed to wrapped UDP; not an IP family kind. */
    std::uint32_t routeTag{};
    bool operator==(const Response&) const = default;
};

/** Strict canonical lengths and known method/kind forms. Failure leaves output unchanged. */
[[nodiscard]] bool parse_request(std::span<const std::byte> input, Request& output) noexcept;

/**
 * Encodes only a caller-supplied body. Failure leaves output unchanged and sets
 * written to zero. Success touches exactly written bytes. Port/tag zero and all
 * opaque values are preserved; usable routing/security require separate policy.
 */
[[nodiscard]] bool encode_response(const Response& response,
                                   std::span<std::byte> output,
                                   std::size_t& written) noexcept;

/** Strict canonical parser. Failure leaves output unchanged, including security material. */
[[nodiscard]] bool parse_response(std::span<const std::byte> input, Response& output) noexcept;

} // namespace dawn::middleware::bap::address_resolution
