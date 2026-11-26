# Explicit native routes

Milestone 1 needs a control connection and real human peer connections to coexist.
One native UDP socket can own several authenticated resolver contexts. Choosing
the latest context for its IP/port cannot identify which virtual peer should
receive a reply.

The resolver now provides an `unwrap` overload that returns an
`AuthenticatedRoute` only after authentication, replay validation and source
pinning succeed. It contains the exact process-local authentication owner,
non-reused context generation and pinned UDP source. Failed input clears this
metadata and publishes no plaintext. No key material is returned.

The metadata now also identifies `control` versus a registered `human` route,
with a typed process-local `PeerAddressHandle` for the latter. The classification
comes from the context that authenticated the datagram. It is checked again for
an exact-context send and cannot be changed by editing the returned fields.

`wrap_authenticated_route` selects that exact allocated context, even when a
different context is now selected by the legacy endpoint-based API. Both send
paths share the same context IV allocator. A failed seal or socket send consumes
its IV; stale owners, generations and sources cannot select another context.
`release_route` securely retires one exact context while preserving its siblings,
including contexts belonging to the same local authentication lifetime.

`endpoint::send_resolved_on_route` sends the exact protected reply and reports
only success or failure. It never falls back to another context or a raw send.
The endpoint-based wrapper and owner lookup select only control contexts. A
new human context sharing a game's UDP source therefore cannot replace the
control connection's encryption keys. A human-only destination is rejected by
the legacy wrapper, preventing a raw-send fallback. Their selected-route
observation/validation policy remains different from the exact-context API.

## Registered native peer addresses

`register_peer_address` permits a trusted internal caller to register an exact
86-byte direct-method NetAddr for one BAP authentication lifetime. Its recovered
41-byte address body must be canonical, with a nonzero unicast IPv4 address and
an even nonzero port. The opaque tail is retained without interpretation. A
control address collision, duplicate peer body, wrong owner or partial match is
refused. Human resolution requires all 86 bytes to match; the established
control resolver retains its 41-byte matching rule.

There are sixteen registration slots and sixteen crypto-context slots. These
are separate bounded stores, not a claim of six-player support. Both handle
generation counters survive cleanup and reset, so slot reuse cannot revive a
stale registration or route. `revoke_peer_address` clears that registration and
all of its contexts while preserving control and other peer contexts. Owner
release and reset clear the associated registrations too.

Both address kinds still resolve to the configured embedded transport endpoint.
This API exports no keys, changes no account service or outbound-network policy,
and has no social/companion RPC. A future trusted runtime caller must first
validate the player/activity grant and own revocation and deadline handling.
No production caller currently registers a human address.

## Internal receive boundary

The bound embedded endpoint supports one process-lifetime routed consumer. It is
called only after successful authentication, with copied route metadata and a
borrowed plaintext span. It runs outside the endpoint and resolver locks, so it
can send a protected reply synchronously. Its decisions are:

- `unhandled`: retain the embedded peer path for control routes only.
- `handled`: the consumer completed its work; do not dispatch to the control peer.
- `rejected`: discard the packet without any control/legacy fallback.

Unknown decisions also stop dispatch. No production code currently installs a
human-route consumer. The callback is a transport extension, not authorization.
A future relay must validate its own current grant, identities and exact
per-human requested native address before accepting a packet.
An unclaimed human packet is discarded even when no consumer is installed.

Registration is allowed only on a ready embedded socket. It cannot replace a
different consumer. Unregistration and shutdown clear registration but do not
wait for an already-copied callback. The owning module must quiesce before
unloading. Per-player revocation must invalidate that player's route/grant,
rather than remove the shared module callback.
Revocation cannot retract a callback that already received plaintext; current
grant validation remains the consumer's responsibility. Unknown-tag legacy
behavior after full route teardown is unchanged; this adds no endpoint tombstone.

Route handles are local to their issuing process. They are not remote-PC
credentials and must not be accepted from an ordinary social control message as
proof of a permitted human connection. Protected control transport, peer leases,
recipient-specific BAP world membership and exact egress mapping remain required
before the relay is activated.

## Verification

The resolver suite passes 2,851 enabled and 27 disabled-mode checks with
production crypto. It covers overlapping endpoints and owners, exact replies,
IV progression across both APIs, metadata clearing, teardown, forged handles,
slot reuse and single-context cleanup.
It also covers exact peer address ownership, classification forgery, registration
capacity, input/output aliasing, revocation and control-context isolation.

The endpoint suite uses real loopback UDP and production framing/crypto, with
substituted downstream handlers. Recorded runs pass more than 440 checks,
including two contexts sharing one socket, synchronous callback replies,
context-specific replies after selection changes, authentication/replay refusal,
consumer rejection, restored control dispatch and shutdown cleanup. Polling can
change the numeric check count. Both suites compile with `/W4 /WX`.

A test-owned forwarding consumer also sends 1,500-byte binary payloads between
two real UDP clients in both directions while a control context shares one
client's socket. It verifies the original bytes under the correct destination
keys, interleaved control replies, rejection of oversized/tampered/replayed
input, and registration revocation/reuse. The runtime still has no active
cross-PC human relay. Existing 1,024-character social/companion message limits
are unchanged and are not used as a gameplay datagram channel.

These tests neither start Destiny nor establish remote Guardian replication.
