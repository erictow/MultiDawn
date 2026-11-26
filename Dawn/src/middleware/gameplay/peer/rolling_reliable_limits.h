#pragma once

#include <cstddef>

#include "established_packet.h"

namespace dawn::middleware::gameplay::peer {

/** Bounds the offline six-human membership experiment. Live limits are separate. */
inline constexpr std::size_t kRollingBodyCapacity = 1'048;
inline constexpr std::size_t kRollingFramedCapacity = kRollingBodyCapacity + 3;
inline constexpr std::size_t kRollingFragmentCapacity = kRollingFramedCapacity / kLargeFragmentBytes + 1;

} // namespace dawn::middleware::gameplay::peer
