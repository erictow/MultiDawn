#pragma once

#include <cstdint>

namespace dawn::client::hooks::bootflow::native_replication_observer {
/** One accepted, process-local world/facet control connection. This grants no access. */
struct WorldConnection final {
    std::uint64_t creatorMachineId{}, controlMachineId{}, controlEpoch{}, generation{};
    friend constexpr bool operator==(const WorldConnection&, const WorldConnection&) noexcept = default;
};

/** Copies the unique live control binding for the exact pair. No native pointers are returned. */
[[nodiscard]] bool snapshot_world_connection(std::uint64_t creatorMachineId,
    std::uint64_t controlMachineId, WorldConnection& output) noexcept;

// Separates server-published control-only hosts from native physics peers.
// Unmatched peers retain normal native registration and acknowledgements.
[[nodiscard]] bool install() noexcept;
void quiesce() noexcept;
[[nodiscard]] bool uninstall() noexcept;
}
