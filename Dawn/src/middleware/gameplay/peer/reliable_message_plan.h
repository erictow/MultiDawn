#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../../../state/gameplay/definition.h"

namespace dawn::middleware::gameplay::peer::detail {

/** Plans a whole reliable message into caller-owned scratch before assigning sequences. */
[[nodiscard]] bool plan_reliable_message(std::uint8_t id, std::uint32_t declaredSize,
    std::span<const std::byte> body, std::size_t bodyBits,
    std::span<std::byte> staging, std::span<state::gameplay::OutboundFragment> fragments,
    std::size_t& count) noexcept;

/** Moves one planned fragment into the ordered send queue and advances its sequence. */
void append_planned_fragment(state::gameplay::OutboundQueue& queue,
                             state::gameplay::OutboundFragment fragment) noexcept;

} // namespace dawn::middleware::gameplay::peer::detail
