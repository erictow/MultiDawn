#pragma once

#include <span>

#include "../../../state/gameplay/definition.h"

namespace dawn::server::gameplay::peer::lookup {

/** One native group session can be carried by several independently owned links. */
[[nodiscard]] inline state::gameplay::PeerLink*
find(std::span<state::gameplay::PeerLink> links,
     std::uint64_t sessionId,
     const state::gameplay::Endpoint* endpoint = nullptr) noexcept {
    if (sessionId == 0) { return nullptr; }
    state::gameplay::PeerLink* found = nullptr;
    for (auto& link : links) {
        if (link.stage == state::gameplay::PeerStage::absent
            || (endpoint != nullptr
                && (link.endpoint.address != endpoint->address || link.endpoint.port != endpoint->port))) {
            continue;
        }
        bool carries = false;
        for (const auto held : link.sessions) { carries = carries || held == sessionId; }
        if (!carries) { continue; }
        // A legacy session-only call must never silently select the first human's link.
        if (found != nullptr) { return nullptr; }
        found = &link;
    }
    return found;
}

} // namespace dawn::server::gameplay::peer::lookup
