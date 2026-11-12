# Protected launcher control

Launcher 0.5 requires the `MD3` connection protocol. The existing `MD2-` pair
code continues to carry the IPv4 endpoint and a random 128-bit bearer secret.
Code formatting, saved-friend identity pins and LAN/VPN destination overrides
remain compatible. Earlier launchers cannot complete the new handshake.

## Connection binding

The host and guest authenticate the handshake with HMAC-SHA256, using fresh
client and host nonces and both persistent launcher identities. The version and
role are included in each proof. The final welcome carries its own distinct
`welcome` proof and must verify before the guest publishes a paired connection.
The bearer secret is not transmitted.

`PairProtection` derives a connection root with HMAC-SHA256 over the explicitly
labelled `MD3` transcript. Four further purpose-labelled HMAC operations derive
separate AES-256 encryption and HMAC-SHA256 authentication keys for each
direction. Fresh handshake nonces therefore give a reconnect different keys,
even when the host keeps its lobby code. A selected saved friend's identity
must still match before the guest admits the connection.

Every post-handshake message uses this protection, including heartbeat traffic,
friend endpoint announcements and social/invitation controls. The handshake's
welcome is authenticated separately from encrypted application frames. Busy
and rejection responses can stop an attempted connection but cannot admit one
or authorize a gameplay connection.

## Frame

Each line starts with `MD3 FRAME ` followed by canonical unpadded base64url:

| Field | Size | Encoding |
| --- | --- | --- |
| Version | 1 byte | `3` |
| Directional sequence | 8 bytes | Big-endian, starts at one |
| IV | 16 bytes | Fresh cryptographic random bytes for each frame |
| Ciphertext | A positive multiple of 16 bytes | AES-256-CBC with PKCS7 padding |
| Authentication tag | 32 bytes | HMAC-SHA256 over all preceding binary fields |

The complete authentication tag is compared before decryption or padding
validation. Each direction accepts exactly its next sequence. Modification,
duplicates, gaps, reflected frames and frames from another transcript are
rejected. This strict ordering is appropriate for the underlying TCP stream.
There is no plaintext or older-protocol fallback after pairing.

The existing application control limit remains 1,024 printable ASCII bytes.
The protected plaintext limit is 1,032 bytes including `CONTROL `, and the
maximum encoded line is 1,473 characters. Invalid syntax, length, authentication,
sequence, padding or application messages terminate that connection. Errors do
not disclose the rejected plaintext or cryptographic material.

## Lifetime and concurrency

The connection's serialized write gate covers sequence allocation, encryption
and the complete network write. Concurrent heartbeats and social sends cannot
put a later sequence ahead of an earlier one. A failed write closes that stream;
it cannot continue after consuming a sequence.

Senders capture the exact current TCP client, protection object, cancellation
token and connection generation. Reconnection does not let a queued old send
use the new keys or socket. Teardown clears the four retained key arrays.
The protection object's lock prevents disposal from clearing a key during a
cryptographic operation.

## Scope

This protects the launcher channel against an observer or modifier without the
pair secret. Anyone holding the code can authenticate to the lobby, so the code
must remain private. This pre-shared-secret construction does not provide
forward secrecy after disclosure of that secret. Launcher identity pins are
local contact records, not Steam authentication or native game identities.

The channel currently carries launcher and invitation controls. No native
resolver keys, account data or gameplay grants are exported by this change.
Protected framing is a prerequisite for later handoff work; a paired channel
still does not authorize a human route or establish a shared Destiny activity.

## Verification

The launcher self-tests cover byte-by-byte frame modification, replay and
ordering, connection/direction binding, canonical lengths, authenticated bad
padding and invalid text, old protocol refusal and forged welcome responses.
The complete suite also exercises saved-friend pins, concurrent social sends,
reconnect generations and invitation expiry through actual loopback TCP.

The production C++ companion workers pass both native invitation protocol
versions through the MD3 launcher connection, including accepted intent and
native exit cleanup while the launcher pair remains connected. These workers
do not load Destiny or prove that two Guardians share an activity.
