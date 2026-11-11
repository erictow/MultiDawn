#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace dawn::middleware::gameplay::routed_datagram {

inline constexpr std::size_t kCipherKeySize = 8;
inline constexpr std::size_t kMacKeySize = 16;
inline constexpr std::size_t kIvSize = 8;
inline constexpr std::size_t kBlockSize = 8;
inline constexpr std::size_t kHeaderSize = 12;
inline constexpr std::size_t kTagSize = 10;
inline constexpr std::size_t kMaximumCiphertext = 5120;
inline constexpr std::size_t kMaximumPayload = kMaximumCiphertext - 1;
inline constexpr std::size_t kMinimumDatagram = kHeaderSize + kBlockSize + kTagSize;
inline constexpr std::size_t kMaximumDatagram = kHeaderSize + kMaximumCiphertext + kTagSize;

/** One direction's service-301 DES key and shared authentication key. */
struct DirectionKeys {
    std::array<std::byte, kCipherKeySize> cipher{};
    std::array<std::byte, kMacKeySize> mac{};
};

using Iv = std::array<std::byte, kIvSize>;

/**
 * Encodes build-86657's resolved-route envelope: BE32 route tag, verbatim IV,
 * DES-CBC with PKCS#7 padding, and HMAC-SHA1 truncated to its first ten bytes.
 * The IV is explicit and never incremented here. Counter/replay policy belongs
 * to the route owner. Output is committed only on success; written is zero on
 * failure. Input/output may overlap. Caller keys and IV are not modified.
 */
[[nodiscard]] bool seal(const DirectionKeys& keys, std::uint32_t routeTag,
                        std::span<const std::byte> iv,
                        std::span<const std::byte> payload,
                        std::span<std::byte> output, std::size_t& written) noexcept;

/**
 * Verifies the expected route tag and constant-time MAC before decrypting.
 * Rejects malformed lengths and noncanonical padding. On failure output and
 * iv remain unchanged and written is zero; on success iv receives the packet's
 * authenticated IV. An empty plaintext is valid. Input/output may overlap.
 */
[[nodiscard]] bool open(const DirectionKeys& keys, std::uint32_t expectedRouteTag,
                        std::span<const std::byte> datagram,
                        std::span<std::byte> output, Iv& iv,
                        std::size_t& written) noexcept;

} // namespace dawn::middleware::gameplay::routed_datagram
