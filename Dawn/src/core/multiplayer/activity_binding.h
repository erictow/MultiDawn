#pragma once

#include <cstdint>

#include "identity_activity_correlation.h"
#include "../../server/bap/runtime.h"
#include "../../server/gameplay/resolution/address_resolution_host.h"

namespace dawn::core::multiplayer::activity_binding {

enum class Result : std::uint8_t {
    observed,
    disabled,
    noCreator,
    noAdvertisement,
    noManagedGroup,
    ambiguousManagedGroup,
    malformedManagedGroup,
    noAuthenticatedRoute,
    changed,
};

/** Public copied observations only. No row pin, account data, descriptor or grant is retained. */
struct Observation final {
    server::bap::CreatorActivitySnapshot creator{};
    state::activity::ActivityInstanceKey host{};
    std::uint64_t groupMachineId{}, lineageGeneration{};
    identity_activity::Correlation native{};
    server::gameplay::resolution::AuthenticatedRoute route{};
};

/**
 * Observes the managed-session path: creator activity, exact pinned advertisement, native
 * SessionState host/member table and authenticated UDP source. This does not establish the
 * relationship to the distinct BAP world/facet group. Failure clears output. Pins are released before
 * returning, so even success is an observation requiring later revalidation, never admission.
 */
[[nodiscard]] Result inspect(std::uint64_t now, Observation& output) noexcept;
/** Reobserves all boundaries and compares their exact lifetimes and public values. */
[[nodiscard]] bool validate(const Observation& previous, std::uint64_t now) noexcept;

/** Bounded diagnostics only, enabled with DAWN_ACTIVITY_BINDING_TRACE=1. */
void service(std::uint64_t now) noexcept;
void reset() noexcept;

} // namespace dawn::core::multiplayer::activity_binding
