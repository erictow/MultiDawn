#pragma once

#include <cstddef>
#include <cstdint>

#include "../../../core/multiplayer/native_identity_observation_state.h"

namespace dawn::client::hooks::bootflow::native_identity_observation {

/** Explicit DAWN_NATIVE_IDENTITY_OBSERVATION=1 opt-in and pinned build signatures required. */
[[nodiscard]] bool enabled() noexcept;
/** Starts a fresh observed lifetime after the native manager hook is installed. */
void start() noexcept;
/** Called only after the original manager update, on that manager's native thread. */
void observe(std::byte* manager) noexcept;
/** Copies public routing observations only; no local-human identity or access is asserted. */
[[nodiscard]] bool snapshot(std::int32_t managedRole, std::uint64_t now,
    core::multiplayer::identity_observation::Observation& output) noexcept;
/** Invalidates every prior observation without resetting its monotonic generation allocator. */
void reset() noexcept;

} // namespace dawn::client::hooks::bootflow::native_identity_observation
