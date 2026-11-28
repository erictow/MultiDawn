#pragma once

#include "peer_transport.h"

namespace dawn::server::gameplay::peer::detail {

/** Tracks provenance only. Native peer progress and routing never depend on it. */
class ResolvedConnectReceipt final {
public:
    void connect_request(const ResolvedConnectObservation& observed, bool fresh) noexcept {
        if (!observed.route || (!fresh && observation_ != observed)) {
            *this = {};
        } else if (fresh) {
            observation_ = observed;
            ready_ = false;
        }
    }

    /** Call for each decoded established packet, using the pre-packet native stage. */
    void established(resolution::RouteHandle route, bool wasConnected) noexcept {
        if (!observation_.route) return;
        if (route != observation_.route) {
            *this = {};
        } else if (wasConnected) {
            ready_ = true;
        }
    }

    [[nodiscard]] ResolvedConnectObservation snapshot(resolution::RouteHandle route) const noexcept {
        return ready_ && observation_.route == route ? observation_ : ResolvedConnectObservation{};
    }

private:
    ResolvedConnectObservation observation_{};
    bool ready_{};
};

} // namespace dawn::server::gameplay::peer::detail
