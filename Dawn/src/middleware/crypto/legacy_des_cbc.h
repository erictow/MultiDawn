#pragma once

#include <cstddef>
#include <span>

namespace dawn::middleware::crypto::legacy_des {

// Build 86657's routed gameplay envelope requires DES-CBC. This primitive is
// confined to wire compatibility; its caller must authenticate before decrypting.
inline constexpr std::size_t kKeySize = 8;
inline constexpr std::size_t kBlockSize = 8;

/** Whole blocks only. No padding is added; input/output may overlap exactly. */
[[nodiscard]] bool encrypt(std::span<const std::byte> key,
                           std::span<const std::byte> iv,
                           std::span<const std::byte> input,
                           std::span<std::byte> output) noexcept;

/** Whole blocks only. Caller-owned key/IV are never modified. */
[[nodiscard]] bool decrypt(std::span<const std::byte> key,
                           std::span<const std::byte> iv,
                           std::span<const std::byte> input,
                           std::span<std::byte> output) noexcept;

} // namespace dawn::middleware::crypto::legacy_des
