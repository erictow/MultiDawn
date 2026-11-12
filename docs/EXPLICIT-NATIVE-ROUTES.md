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

`wrap_authenticated_route` selects that exact allocated context, even when a
different context is now selected by the legacy endpoint-based API. Both send
paths share the same context IV allocator. A failed seal or socket send consumes
its IV; stale owners, generations and sources cannot select another context.
`release_route` securely retires one exact context while preserving its siblings,
including contexts belonging to the same local authentication lifetime.

`endpoint::send_resolved_on_route` sends the exact protected reply and reports
only success or failure. It never falls back to another context or a raw send.
The original endpoint-based APIs retain their existing selection behavior.
Their selected-route observation/validation policy is deliberately different
from the exact-context API.

## Internal receive boundary

The bound embedded endpoint supports one process-lifetime routed consumer. It is
called only after successful authentication, with copied route metadata and a
borrowed plaintext span. It runs outside the endpoint and resolver locks, so it
can send a protected reply synchronously. Its decisions are:

- `unhandled`: retain the existing embedded control-peer path.
- `handled`: the consumer completed its work; do not dispatch to the control peer.
- `rejected`: discard the packet without any control/legacy fallback.

Unknown decisions also stop dispatch. No production code currently installs a
human-route consumer. The callback is a transport extension, not authorization.
A future relay must validate its own current grant, identities and exact
per-human requested native address before accepting a packet.

Registration is allowed only on a ready embedded socket. It cannot replace a
different consumer. Unregistration and shutdown clear registration but do not
wait for an already-copied callback. The owning module must quiesce before
unloading. Per-player revocation must invalidate that player's route/grant,
rather than remove the shared module callback.

Route handles are local to their issuing process. They are not remote-PC
credentials and must not be accepted from an ordinary social control message as
proof of a permitted human connection. Protected control transport, peer leases,
recipient-specific BAP world membership and exact egress mapping remain required
before the relay is activated.

## Verification

The resolver suite passes 1,721 enabled and 22 disabled-mode checks with
production crypto. It covers overlapping endpoints and owners, exact replies,
IV progression across both APIs, metadata clearing, teardown, forged handles,
slot reuse and single-context cleanup.

The endpoint suite uses real loopback UDP and production framing/crypto, with
substituted downstream handlers. Recorded runs pass more than 260 checks,
including two contexts sharing one socket, synchronous callback replies,
context-specific replies after selection changes, authentication/replay refusal,
consumer rejection, restored control dispatch and shutdown cleanup. Polling can
change the numeric check count. Both suites compile with `/W4 /WX`.

These tests neither start Destiny nor establish remote Guardian replication.
