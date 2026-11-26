#pragma once

#include <cstdint>

namespace dawn::core::multiplayer::fireteam {

// Project targets, not advertised runtime capabilities. Each stage needs its
// own native gameplay, transport, launcher and save-preservation verification.
inline constexpr std::uint32_t kFirstMilestoneHumans = 2;
inline constexpr std::uint32_t kFireteamMilestoneHumans = 3;
inline constexpr std::uint32_t kMaximumHumans = 6;

} // namespace dawn::core::multiplayer::fireteam
