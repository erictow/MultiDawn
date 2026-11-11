# Build 86657 experimental address resolution

`src/middleware/bap/address_resolution.{h,cpp}` implements bounded BAP300 request
parsing and BAP301 response encoding/parsing for build
`86657.20.08.23.1800.d2_rc`. These are body codecs, excluding the outer BAP frame.
The embedded backend conditionally registers service 300/301 when
`DAWN_NATIVE_ADDRESS_RESOLUTION=1` is present before the runtime starts. This
development opt-in is cached for the DLL lifetime and is off by default.
The implementation has passed isolated component tests. Native channel
establishment and multiplayer gameplay remain unverified.

Native evidence is the request serializer at RVA `0xE0C2C0`, the response parser
at `0xE0AF80`, the response installation path at `0xE00ED0` / `0xE08890`, and the
wrapped UDP sender at `0x17CC020`. Raw-array reader `0x351070` preserves the wire
byte order of opaque arrays. Scalar integers below use big-endian wire order.
The parser's 182-byte decoded object includes native padding; 182 is not the
encoded response length.

## Request 300

The canonical body is exactly 92 bytes.

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 2 | Big-endian NetAddr length, exactly 86 |
| 2 | 86 | Exact opaque native NetAddr; method is its last byte |
| 88 | 2 | Big-endian capability/protocol field |
| 90 | 2 | Big-endian request kind: 1 for methods 0 through 5, 2 for methods 6/7 |

Offset 88 is **not a UDP port**. Native getter `0x9E0E80` returns 16 on the
observed path, with an alternate 255 branch. The codec preserves any 16-bit
value because its complete protocol meaning has not been established. Unknown
NetAddr methods and mismatched request kinds are rejected.

## Response 301

The canonical body is 166 bytes for IPv4 and 178 bytes for IPv6.

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 16 | A: first eight bytes are the client-to-server DES key |
| 16 | 8 | B: initial client-to-server IV/counter |
| 24 | 2 | Big-endian NetAddr length, exactly 86 |
| 26 | 86 | Exact opaque native NetAddr |
| 112 | 2 | Big-endian C; parsed by native code, meaning unresolved |
| 114 | 16 | D: first eight bytes are the server-to-client DES key |
| 130 | 8 | E: initial server-to-client IV/counter |
| 138 | 16 | F: shared HMAC-SHA1 key |
| 154 | 2 | Big-endian destination UDP port |
| 156 | 2 | Big-endian IP byte count, exactly 4 or 16 |
| 158 | 4 or 16 | IP address bytes in network order |
| 162 or 174 | 4 | Big-endian routing tag |

The final 32-bit field is **not an IP-family selector**. Native code stores it
at resolver offset 0 and prefixes it to wrapped UDP packets. It is preserved
independently of the NetAddr method and IP byte count. `IpFamily` in the C++ API
selects only the IP byte count; it does not become the routing tag.

The native response parser does not reject a zero port or routing tag, and C
is not consumed by the inspected installation path. The codec therefore
preserves these values. The backend separately supplies the configured UDP port,
a nonzero routing tag, and C equal to the requested capability, currently 16.

A/B/D/E/F contain security and counter material and are copied verbatim by the
body codec. Native constructor `0x16BAAA0` registers SHA1 through `0x3484F0`
and DES through `0x3484B0`; this confirms the algorithms independently of their
runtime registry indices. The body codec does not generate or log secrets.

## Service-301 push framing

The native consumer treats 301 as a push with a six-byte service/task header:

```text
BE16 service 301 | BE32 task | 166-byte IPv4 body (178 bytes for IPv6)
```

There is no two-byte status field. `bap_frame.cpp` routes service 301 through
the notification encoder; other response services retain their status-200
header. Refused resolver requests remain quiet instead of sending an invalid
empty 301 push.

An isolated live attempt sent 301 with the former status-200 prefix. The native
push decoder therefore received 168 bytes instead of the 166-byte IPv4 body,
reported invalid endpoint lengths, and disconnected the BAP link before UDP
establishment. The framing correction and full-payload/plaintext-frame
regressions are now in source.

The corrected isolated run accepted 301, installed one native resolver entry,
and sent 126-byte wrapped UDP packets that the embedded backend authenticated.
The native channel advanced to `connecting3`, then timed out and retried after
roughly 30 seconds. No DTLS exchange or native peer connection was observed.
Wrapped server-to-client delivery and complete channel establishment remain
unverified.

A subsequent bounded diagnostic observed 98-byte plaintext packets beginning
with `C5`. Native senders `0x16D6150`, `0x16E3D80`, and `0x16E3470` independently
confirm this path carries an engine peer container directly: marker/follows,
six-bit message ID 5, eighteen-bit decoded size 96, a 94-byte request body, and
the final follows bit. No DTLS/SRP layer is nested inside the native wrapper.
The endpoint now hands authenticated payloads to the existing peer handler and
selects the authenticated native route first for its replies. Live verification
of this direct routing change remains pending.

## Embedded backend policy

`src/server/gameplay/resolution/address_resolution_host.{h,cpp}` accepts only a
current authenticated BAP owner, capability 16, request kind 1, and method 0.
The direct address's first 41 bytes must exactly match the configured embedded
descriptor. The response preserves all 86 requested NetAddr bytes and resolves
only to the configured IPv4 transport address and gameplay port. The backend
does not resolve arbitrary LAN endpoints or Steam-format peer addresses.

Each of the 16 bounded contexts owns fresh random directional DES keys, a shared
MAC key, counter seeds, and a unique live route tag. Its owner includes both
connection and authentication generations. BAP authentication reset, connection
cleanup, or runtime shutdown erases the corresponding material. Unbound contexts
may be replaced after 30 seconds when allocating a context; bound contexts remain
owned until explicit cleanup.

The first authenticated, valid packet pins its source IP and port. Later packets
cannot rebind that context. MAC, padding, output-capacity, or replay failures do
not publish plaintext or commit endpoint/replay state. The server permits each
counter once within a 128-packet window, with a floor of B + 1. This is a server
policy, not a claim about the native client's replay-window size.

## Routed UDP envelope

`src/middleware/gameplay/routed_datagram.{h,cpp}` implements:

```text
BE32 route tag | 8-byte IV | DES-CBC ciphertext | first 10 bytes of HMAC-SHA1
```

The MAC covers the header and ciphertext. Plaintext uses 1 through 8 bytes of
PKCS#7 padding. IV counters are little-endian; the pure packet codec never
increments them. The host accepts client counters starting at B + 1 and sends
its first response with E, then increments for each attempted wrapped send.
An IV is consumed even when sealing or the later socket send fails.

The gameplay endpoint delivers successfully authenticated native packets directly
to the engine peer handler. Replies use the destination's most recently
authenticated context. An explicit three-state send result prevents a failed
native send from falling back to a different transport. Unrouted legacy packets
retain their DTLS/association handlers. Native introduction probes remain
unwrapped. This adds
the resolved-route envelope; it does not establish shared activity membership,
remote account services, or replicated Guardians.

## Codec guarantees and verification

Both parsers leave the destination unchanged on failure. The response encoder
checks method, family, and output capacity before publishing bytes; failure
sets `written` to zero and leaves the output untouched. Success writes exactly
the canonical body length. IPv4 ignores the unused twelve bytes of the C++ IP
array and parsing clears them. Staging also permits the output span to overlap
the response object without corrupting later source fields.

The local codecs reject all trailing bytes. This is deliberately stricter than
the native response parser's upper input-buffer bound. No native padding is
accepted as wire data. Malformed and unknown forms are rejected rather than
guessed.

Build and run the isolated tests with:

```powershell
py -3.14 tools/build/build_portable_windows.py --project Dawn/unit/address_resolution_tests.vcxproj --run
```

The unit project checks independently specified IPv4/IPv6 golden bytes, opaque
field preservation, scalar offsets and byte order, every truncated input and
short output length, trailing bytes, invalid method/kind/length combinations,
zero and arbitrary capability/tag/C values, and unchanged outputs on failure.
It opens no sockets and does not start Destiny. The native multiplayer workflow
includes these isolated suites. Current local results are:

| Unit project | Passed checks |
| --- | ---: |
| `address_resolution_tests.vcxproj` | 1,288 |
| `des_cbc_tests.vcxproj` | 53 |
| `routed_datagram_tests.vcxproj` | 535 |
| `resolution_replay_tests.vcxproj` | 16,554 |
| `address_resolution_host_tests.vcxproj` | 1,084 enabled; 11 with `--disabled` |
| `endpoint_resolution_tests.vcxproj` | 136 in the recorded loopback run |

The backend tests link the production store, random generator, packet codec,
DES and HMAC with test settings/log sinks. They exercise endpoint pinning,
authenticated malformed padding, replay boundaries, rekey selection, generation
cleanup and capacity limits. The address codec suite also verifies status-free
301 payloads and complete plaintext frames while retaining status 200 on other
responses. These tests use no sockets, game processes, or
player saves. A workflow definition is not evidence of a remote CI pass, and
component passes do not verify the native gameplay path.

The endpoint integration suite uses real ephemeral loopback UDP sockets with
the production endpoint, context store, crypto, and container codecs. It stubs
the peer and legacy handlers to verify dispatch boundaries: a valid native
request reaches only the peer handler, its reply is wrapped with the supplied
server material, tampering/replay/rebinding cannot publish plaintext, and
legacy traffic retains its prior routing. It also checks explicit unbound sends
emit nothing and bound send failures do not select another transport. It does
not load Destiny or exercise the real peer handshake.
