#include "gameplay_runtime.h"

#include "association/association_host.h"
#include "dtls/dtls_host.h"
#include "endpoint/gameplay_endpoint.h"
#include "group/group_host.h"
#include "peer/peer_transport.h"
#include "resolution/address_resolution_host.h"

namespace dawn::server::gameplay {

/** Binds the gameplay endpoint for the configured topology. */
bool initialize() noexcept {
    resolution::reset();
    association::reset();
    dtls::reset();
    peer::reset();
    group::reset();
    return endpoint::initialize();
}

/** Runs one bounded gameplay slice. */
void service(std::uint64_t now) noexcept {
    endpoint::service(now);
    // The retries run before the send so anything they queue leaves in this slice.
    group::service(now);
    peer::service(now);
}

/** Stops the endpoint and clears every association and peer. */
void shutdown() noexcept {
    endpoint::shutdown();
    peer::reset();
    group::reset();
    dtls::reset();
    association::reset();
    resolution::reset();
}

} // namespace dawn::server::gameplay
