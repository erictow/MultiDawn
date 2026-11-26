# Invitation acceptance and preflight

Version 2 carries a player's invitation acceptance from the Dawn Friends panel
through two paired launchers to the inviting native runtime. Acceptance records
user intent only. It does not authorize a gameplay peer, publish group membership,
redirect account services, or stop a local gameplay endpoint.

Each PC keeps its own saves and local profile service. The intended multiplayer
architecture gives the host ownership of the shared activity. A later host
controller must validate the current invitation, native identities, activity,
and authenticated gameplay endpoint before granting a guest access. Multiplayer
Play remains disabled until that path and two-PC gameplay are verified.

## Transport and identities

Native IPC uses the existing user-restricted `MultiDawn-<id>` Windows named pipe.
Frames contain a four-byte little-endian length followed by 1 to 1,024 printable
ASCII bytes. Fields use one space, without empty fields, and messages have at
most eight fields. Names and connect strings use canonical uppercase hex;
names decode to at most 127 bytes and nonempty connect strings to at most 255.

The launcher passes a pipe ID, nonce, launcher PID, and
`DAWN_COMPANION_PROTOCOL=2` only in the explicit preflight child environment.
The native client checks the expected pipe server process and authenticates
with the nonce. Ordinary solo launch removes inherited companion variables.
Omitting the protocol environment variable selects the legacy version-one
native handshake; unsupported values fail closed.

The identities below are the existing persistent MultiDawn device identities in
Steam's individual-account integer format. They are not proof of a Steam login,
Steam friend import, a native player ID, or a BAP account binding.

Each authenticated native connection receives a fresh 32-character uppercase
hex runtime epoch. Invitation tickets use the same form and are generated anew
for each outgoing offer. Neither is an account credential. Pair control messages
travel only through the existing authenticated TCP pairing channel.

## Native pipe messages

The common handshake is:

```text
native -> launcher: HELLO 2 <nonce>
launcher -> native: WELCOME 2 <localSteamId> <peerSteamId> <nameHex> <running:0|1>
```

The launcher also accepts `HELLO 1` and replies with `WELCOME 1` for old native
clients. Version-one native clients retain their legacy invitation behavior.

| Direction | Message | Meaning |
| --- | --- | --- |
| Native to launcher | `INVITE <targetSteamId> <connectHex>` | Create an offer for the currently paired native peer. |
| Launcher to native | `PEER <peerSteamId> <nameHex> <running:0|1>` | Existing peer presence. |
| Launcher to v2 native | `RUNTIME <peerSteamId> <epochOrDash> <protocol:0|1|2>` | Current peer native capability. Protocol zero uses `-` for the epoch. |
| Launcher to v2 native | `INVITEFROM2 <fromSteamId> <ticket> <connectHex>` | Present a ticketed invitation. |
| V2 native to launcher | `ACCEPT <fromSteamId> <ticket>` | The player accepted that exact invitation. |
| Launcher to v2 native | `ACCEPTED <peerSteamId> <ticket> <ttlMilliseconds>` | Publish a bounded accepted-intent event to the inviter. The TTL is 1 to 60,000. |
| Launcher to v2 native | `REVOKED <ticket>` | Retire the matching pending invitation or accepted intent. |
| Launcher to native | `PING` | Existing pipe heartbeat. |

A v2 native runtime may send invitations only when both current runtimes
announce protocol two. Its launcher also enforces this condition. Missing or
legacy peer capability never causes a v2 invitation to fall back to
`SOCIAL1 INVITE`. Incoming legacy invitations are ignored for a v2 native
consumer, and the v2 native parser rejects legacy `INVITEFROM` messages. These
rules prevent a legacy immediate-join callback from bypassing ticketed acceptance.

## Paired launcher messages

```text
SOCIAL2 RUNTIME <steamId> <nameHex> <epochOrDash> <protocol:0|1|2> <revision>
SOCIAL2 OFFER <ticket> <targetSteamId> <hostEpoch> <guestEpoch> <connectHex>
SOCIAL2 ACCEPT <ticket> <hostEpoch> <guestEpoch>
SOCIAL2 REVOKE <ticket> <hostEpoch> <guestEpoch>
```

In this protocol, `host` means the invitation sender and `guest` means its
recipient. Those labels do not elect the shared-world host or grant gameplay
authority. The invitation sender and recipient may exchange invitations in
either direction.

Runtime revisions increase when a launcher authenticates or loses a native
consumer. Receivers ignore older revisions and reject conflicting contents at
the same revision. Once a version-two runtime announcement is known, a legacy
`SOCIAL1 PROFILE` cannot roll its epoch or capability back. The launcher still
publishes legacy profiles for old companion consumers.

The invitation ledger binds each record to the pairing connection generation,
authenticated partner launcher identity, both device identities, and both native
epochs. It holds at most one incoming and one outgoing record, with a bounded
cache of 64 recent tickets. A replacement offer revokes the old one. Repeating
an offer does not extend its lifetime or replace its current record.

Every record has a 60-second lifetime measured by its launcher's monotonic local
clock. No comparison between the PCs' wall clocks is required. Acceptance must
match the exact ticket and both current epochs; duplicate acceptance produces no
second event. Expiry, disconnect, native replacement, and runtime epoch changes
invalidate the corresponding context. Queued controls from an older pairing
generation cannot affect a replacement connection.

## Native acceptance behavior

For ticketed invitations, the Dawn Friends panel sends `ACCEPT` and enters a
waiting state. It does not emit Steam callback 337
(`GameRichPresenceJoinRequested_t`). A failed local send remains retryable;
duplicate clicks after a successful send do not send another acceptance. Sender
callbacks run outside the social mutex, and completion checks the pending
invitation ID, sender identity, ticket, and sender generation again before
changing state.

The inviter receives a value-only `AcceptedInvitationIntent` with the peer device
identity, ticket, and a native monotonic deadline. It can be taken once through
`take_accepted_invitation`. Duplicate delivery does not extend the same ticket's
deadline or recreate a consumed event. Revocation, expiry, runtime changes, and
shutdown clear it. This small mailbox is not an authorization or replay database.

Delivery may be delayed by asynchronous pipe writes. The native deadline is an
event retention limit, not an authoritative host lease. A future controller must
revalidate the launcher's live record and deadline before a gameplay grant and
bind that grant to the actual native session and authenticated UDP peer. There
is no gameplay grant message in version two.

## Opt-in version-three preflight

Version three extends the local native pipe only. Set
`DAWN_COMPANION_PROTOCOL=3` explicitly in an isolated companion test environment.
Normal launcher preflight continues to select version two; solo Play remains
unchanged. Native clients using versions one and two keep their existing
handshakes and behavior.

The new handshake supplies the native client with its exact launcher-issued
runtime epoch and current pairing generation:

```text
native -> launcher: HELLO 3 <nonce>
launcher -> native: WELCOME 3 <localSteamId> <peerSteamId> <nameHex> <running:0|1> <localEpoch> <pairGeneration>
```

The explicit game preflight also stamps optional child startup pins
`DAWN_COMPANION_PAIR_GENERATION` and `DAWN_COMPANION_PEER_ID`. When either is
present, both must be valid, protocol three is required, and the welcome must
match them before native identity publication. This prevents a delayed child
from attaching to a replacement pairing. Unpinned protocol-one/two/three test
workers retain their existing behavior.

The dedicated query and response never travel as ordinary `SOCIAL` payloads:

```text
native -> launcher: PREFLIGHT <requestNonce> <peerSteamId> <ticket>
launcher -> native: PREFLIGHT_OK <requestNonce> <peerSteamId> <ticket> <pairGeneration> <localEpoch> <peerEpoch> <ttlMilliseconds>
launcher -> native: PREFLIGHT_NO <requestNonce>
```

Request nonces, epochs and tickets use the canonical 32-character uppercase hex
form. Pairing generations are positive decimal values; TTL is 1 to 60,000
milliseconds. The success message remains within the existing eight-field and
1,024-byte limits. No account identity, profile data or gameplay packets are
added to this channel.

Under its bridge lock, the launcher checks the current native connection,
pairing context and an exact live accepted incoming or outgoing invitation.
The query does not consume the acceptance record or recreate its notification.
The serialized pipe send rechecks that same record and context and recomputes
its remaining lifetime. Replacement, revocation, expiry or an epoch change
cannot reuse an earlier successful lookup for a later send.

The native runtime accepts a result only for its one outstanding request, with
the matching nonce, ticket, peer, pairing generation and both current epochs.
Its deadline conservatively subtracts elapsed request time from the returned
TTL. A pending request times out after five seconds. Well-formed responses to
old nonces are ignored without installing a result or disconnecting a healthy
pipe. Pending and completed results are cleared on their relevant
revocation, runtime replacement, disconnect or expiry. A consumed observation
can be checked against current local companion state, but that check does not
query the launcher again.

Version three retains version-two invitation semantics. Launcher-to-launcher
`SOCIAL2` runtime announcements continue to advertise the compatible version-two
intent capability. An older paired launcher does not need to understand the
new local pipe query.

`request_invitation_preflight`, `take_invitation_preflight` and
`validate_invitation_preflight` expose this observation boundary to a future
native controller. A successful preflight grants no gameplay access. The
controller still needs the exact current BAP binding and actual identity
receipt, activity/region, world lineage, remote player publication and human
route. No runtime handoff controller currently calls these APIs.

When `DAWN_ACTIVITY_BINDING_TRACE=1`, the inviter's version-three companion
also checks a newly received accepted ticket using the existing preflight
protocol. Its result is kept separately from the controller mailbox. The trace
reports `request_sent` and `accepted_ticket_verified` without printing IDs,
tickets, nonces or epochs. A duplicate acceptance sends no new trace query.
A revocation processed in the same batch suppresses the query. This confirms
live invitation relay only and does not authorize party joining.

## Verification

`tools/launcher/Build-Launcher.ps1 -RunTests` compiles with warnings treated as
errors and runs the ledger and real TCP/named-pipe tests. They cover expiry,
duplicate delivery, identity and epoch mismatch, native replacement with queued
acceptance, pairing disconnect, version-one compatibility, and both incoming and
outgoing downgrade rejection, including an unknown peer capability.

The native protocol, pipe-client, and social test projects cover the C++ side.
`--native-companion-test` runs the production C++ companion in disposable workers
through two real C# bridges for versions three, two and one. The version-three
workers successfully query the current invitation after consuming its intent
event. These checks do not load the game, open saves, prove
the game's own roster UI, or demonstrate two Guardians sharing an activity.
The cross-language test also waits for both native connections and published
runtime epochs to retire, checks that invitation contexts are cleared, and
confirms that the launcher pair remains connected after both workers exit.

Version-three ledger and real TCP/pipe tests also cover wrong tickets and peers,
unaccepted records, the exact expiry boundary, TTL recomputation behind a held
writer, queued revocation/replacement, native restart and pairing reconnect.
Native request-state checks cover nonce/generation/epoch binding, replay,
request timeout, clock rollback and deadline overflow.
