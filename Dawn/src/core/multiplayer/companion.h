#pragma once
#include <cstdint>

namespace dawn::core::multiplayer {

/** Optional, authenticated launcher IPC. An absent configuration keeps direct solo launch. */
[[nodiscard]] bool initialize() noexcept;
/** Polls bounded local IPC work; never opens the existing account backend to a remote PC. */
void service(std::uint64_t now) noexcept;
void shutdown() noexcept;
[[nodiscard]] bool connected() noexcept;

} // namespace dawn::core::multiplayer
