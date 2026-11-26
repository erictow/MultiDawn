#pragma once

#include "region_lineage.h"
#include "../../state/activity/membership/activity_membership_query.h"

namespace dawn::server::bap {

/**
 * Local-only observation of an actual type-23 publication from the current creator.
 * Contains account fields and unnamed raw scalars. Never log it, expose it as a
 * public activity snapshot, or send it through an ordinary companion message.
 */
struct LocalClientIdentitySnapshot final {
    state::activity::BindingKey binding{};
    RegionLineage lineage{};
    state::activity::membership::ClientIdentityPublication publication{};
};

/**
 * Requires the exact current HUD creator binding and its coherent current State
 * region. Seeded/reflected values cannot substitute for a real client receipt.
 * Failure clears output. This observes a lifetime; it grants or retains nothing.
 */
[[nodiscard]] bool snapshot_creator_client_identity(state::activity::BindingKey requested,
    LocalClientIdentitySnapshot& output) noexcept;

} // namespace dawn::server::bap
