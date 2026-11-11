#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../state/activity/lifecycle_generation.h"
#include "../../../state/gameplay/definition.h"

namespace dawn::server::gameplay::resolution {

enum class PacketResult : std::uint8_t { notRouted, rejected, complete };

struct Statistics {
    std::size_t live{};
    std::uint64_t created{}, opened{}, rejected{}, replayed{}, wrapped{};
};

/** Explicit development opt-in, cached for this loaded DLL's lifetime. */
[[nodiscard]] bool enabled() noexcept;

/**
 * Answers BAP300 only for the configured embedded method-0 endpoint. Material
 * belongs to this exact BAP authentication lifetime. No account data is shared.
 */
[[nodiscard]] bool resolve_address(state::activity::AuthenticationKey owner,
                                    std::span<const std::byte> request,
                                    std::span<std::byte> response,
                                    std::size_t& written) noexcept;

/** Authenticates, pins the sender endpoint, then commits replay state. */
[[nodiscard]] PacketResult unwrap(const state::gameplay::Endpoint& source,
                                  std::span<const std::byte> packet,
                                  std::span<std::byte> plaintext,
                                  std::size_t& written) noexcept;

/** Uses the destination's most recently authenticated route; consumes each IV once. */
[[nodiscard]] PacketResult wrap(const state::gameplay::Endpoint& destination,
                                std::span<const std::byte> plaintext,
                                std::span<std::byte> packet,
                                std::size_t& written) noexcept;

void release_owner(state::activity::AuthenticationKey owner) noexcept;
void reset() noexcept;
[[nodiscard]] Statistics snapshot() noexcept;

} // namespace dawn::server::gameplay::resolution
