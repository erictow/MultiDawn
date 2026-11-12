# Multiplayer runtime status

MultiDawn's launcher provides solo launch and a two-person pairing connection.
Pairing does not yet put two Guardians into the same Destiny activity. Multiplayer
game launch is blocked until the game runtime supports that behavior.

## Native implementation added

The source now includes these native components:

- Endpoint-scoped reliable queues, addresses, views, readiness and disconnects.
  Two human peers that name the same group no longer resolve to the first link.
- A two-human membership builder using the existing native encoder and state
  hash. `authorize_shared_peer` requires actual group, endpoint, machine and
  player identities. A launcher pair code does not authorize a game descriptor.
- SteamFriends017 enumeration, persona, presence, and invitation methods.
  Protocol 2 invitations stay pending after explicit acceptance while the host
  receives an expiring intent. They do not queue the native game-join callback.
  Legacy protocol 1 retains its callback behavior between legacy runtimes.
- A Dawn Friends page and an invitation notice in the game overlay.
- A local named-pipe companion client, bound to the launcher's process ID and
  a per-launch nonce. The launcher restricts the pipe to the current Windows
  user and forwards social messages through the authenticated pairing channel.
  A paired launcher is distinguished from a running native game consumer.
- An experimental BAP300/301 resolver and authenticated gameplay UDP envelope,
  enabled only with `DAWN_NATIVE_ADDRESS_RESOLUTION=1`. The resolver targets the
  configured embedded endpoint and owns bounded contexts for each BAP
  authentication lifetime. An isolated native game completed the channel
  handshake and acknowledged view replies. Two-player gameplay remains unverified.

These changes have not been installed over the existing game. The approved
Windows SDK is installed locally. The full DLL and native component tests now
build with Clang 23.1.5. An earlier development DLL ran in the isolated test game
and passed the read-only executable/signature checks. The latest invitation and
identity-observer changes still need in-game testing. This is a development build, not a
verified multiplayer release. The installed Dawn 1.7.2 DLL does not gain these
features from a launcher update alone.

The shared membership path is not activated by the social companion. It still
needs authenticated native descriptors, complete player properties, and working
view/entity authority before multiplayer Play can be enabled.

## Live Tower baseline

An isolated build-86657 game reached `city_tower_social_d2` using a verified copy
of the existing player database. The read-only capture passed the native code
signatures and found 26 owned entity/facet entries, a stable ownership sample,
and no connected native peers in the sampled group. The in-game session overlay
also showed no embedded-server connections.

Before the experimental resolver was added, the embedded UDP endpoint answered a
direct native introduction probe correctly, while the game repeatedly timed out
in `securing2`. Read-only tracing found the lower transport waiting for an address
resolver entry: native command 16 requests BAP service 300, which previously had
no response route. The new route and packet envelope address that missing code
path. The serialized Steam certificate call returning zero alone did not
establish the cause of the timeout.

The first live resolver attempt sent service 301, but the native push decoder
rejected it: the generic response encoder inserted a two-byte status-200 field
ahead of the expected 166-byte IPv4 body. This shifted the endpoint fields and
disconnected BAP before a gameplay UDP exchange. Service 301 now uses its
status-free notification header, with payload and full-frame regression tests.
Refused requests no longer send an empty malformed push.

The corrected isolated Tower run accepted 301 and installed one native resolver
entry. Its 126-byte wrapped UDP packets reached the embedded backend and passed
authentication. The channel advanced to `connecting3`, then timed out and retried
after roughly 30 seconds. No DTLS handshake or native peer connection was
observed; the bounded snapshot still showed 26 owned facets and zero peers.
This was the state before direct engine-payload routing was added.

The next isolated trace identified 98-byte native payloads beginning with `C5`.
Independent native sender inspection matched the existing engine container and
ID5 connection request. This path carries engine messages directly inside the
authenticated route, so the endpoint now delivers them to the peer handler
without a nested DTLS/SRP exchange. The peer reply path selects the native route
first and never falls back after a native send failure.

The next isolated Tower run completed the native connection: Dawn answered
ID5/decoded96, queued establishment, and received the game's reliable ID8 with
`peerstage=5`. The native observer reported `accepted=1`, followed by ID40 view
messages. This verifies bidirectional native packet protection and the peer
handshake against the actual archived game. ID40 currently reaches the group
handler before group membership exists and is refused as `unresolved_group`.
No view token is treated as authorization or guessed to be a group ID. Remote
human admission, shared membership and two-Guardian gameplay remain unverified.

Experimental `main` now handles that pre-join view as a link-level exchange on
the exact authenticated native channel. It requires connected/application-ready
state and empty group slots, checks both channel incarnation values, and queues
the reply and binds its signature atomically. It grants no group membership and
does not reinterpret the view token. Existing admitted-group and legacy paths
are unchanged. Unit checks pass. In the isolated Tower test, the native client
acknowledged all eleven queued view replies and Dawn retired their reliable
fragments with the queue empty. The former `unresolved_group` errors were absent.
This proves transport delivery; native view compatibility flags and two-player
gameplay remain unverified.

The read-only snapshot tool also has an opt-in `--native-players` capture. It
reports native player IDs only after count/mask and member-slot ownership checks,
without reading player configuration. The isolated game's populated player rows
passed those checks with stable membership/player headers. This manual evidence
is not yet an in-process identity publisher or a gameplay authorization grant.

The new [in-process observation reader](NATIVE-IDENTITY-OBSERVATION.md) captures
those public routing scalars on the native manager thread. It requires
`DAWN_NATIVE_IDENTITY_OBSERVATION=1` and pinned build signatures, rejects ambiguous
roles and inconsistent ownership, and expires samples after one second. Its
component tests pass; comparison against a live game is still pending. It neither
identifies a unique local human nor publishes identities to another PC.

The opt-in trace also located the actual fireteam and activity sessions.
Both sampled sessions were in native mode 6, with one established local member,
and both current managed descriptions used Steam-format NetAddr method 6.
The read-only reporter distinguishes that opaque transport address from a direct
IPv4 endpoint. These session observations do not establish a second human peer.

## Experimental native address resolution

Set `DAWN_NATIVE_ADDRESS_RESOLUTION=1` before an isolated test runtime starts to
enable service 300/301 and routed UDP handling. The setting is cached for that
DLL lifetime and defaults off. It does not enable multiplayer Play.

The route requires a current BAP authentication, capability 16, method 0, and an
exact match to the configured embedded descriptor's 41-byte direct address body.
It echoes the full native NetAddr and returns the configured IPv4 transport
endpoint. It does not resolve another player's Steam-format address or expose
the account backend to the LAN.

The UDP envelope uses DES-CBC, authenticated by HMAC-SHA1 truncated to ten bytes,
as required by this game build. Sixteen bounded contexts own random keys,
directional counters and route tags. A valid packet pins its source endpoint;
authentication reset and connection cleanup erase its context. The server's
128-packet replay window permits authenticated reordering once and rejects
duplicates. That window size is server policy, not a recovered native constant.
Introduction probes remain unwrapped.

Wire layouts, lifecycle policy and component test details are in
[the address-resolution notes](../Dawn/docs/ADDRESS-RESOLUTION.md). Component
passes alone do not verify a shared activity or remote Guardian replication.
The isolated native connection evidence above covers one client and its embedded
server.

## What the launcher connection means

The standalone Windows launcher is built with
`tools/launcher/Build-Launcher.ps1`. The output is
`build/launcher/MultiDawn.Launcher.exe`.

Solo Play starts the selected installation with `DAWN_SESSION_MODE=solo` in that
child process. The launcher does not replace the installed account or settings.
The multiplayer controls establish a separate authenticated TCP connection for
one host and one guest, with connection health and disconnect handling.
This connection is a control channel, not Destiny's BAP or gameplay channel.

The pairing address must be reachable over a LAN or a configured VPN. A pair code
does not provide a public directory, NAT traversal, or an internet relay. A successful
pair proves that the launchers can communicate. It does not prove that Destiny's
native player, activity, inventory, or invitation protocols work across machines.

## Verified runtime constraints

These findings come from this source tree. They describe the existing code paths,
not a claim about an untested two-machine game session.

| Area | Existing implementation | Consequence for multiplayer |
| --- | --- | --- |
| Startup | `src/core/runtime/core_runtime.cpp`, `core::initialize`, initializes State, middleware, and `server::initialize` in the game process. | The local server is part of the DLL, not a separate process the launcher can safely terminate. |
| SignOn | `src/server/http/server_http.cpp`, `http::consume`, answers a registered in-process HTTP request. `src/state/runtime/state_runtime.cpp` initializes the SignOn relay address to loopback. | Opening a TCP port does not expose SignOn or a complete external game backend. |
| External server mode | `src/client/hooks/network/http/http_descriptor_route.cpp`, `route_descriptor`, delegates requests to the native HTTP transport when `externalServer.enabled` is true. `src/client/hooks/external_server/external_server_route.cpp`, `rewrite_host`, rewrites the URL host. | This mode expects a real remote service. Setting its host to a paired PC does not create that service or stop the local server. |
| BAP transport | `src/server/transport/bap_listener.cpp`, `initialize_on_port`, binds `INADDR_LOOPBACK`. | Other machines cannot directly connect to this listener. Changing the bind address alone leaves the other constraints unresolved. |
| Accounts and secrets | `src/state/runtime/state.h`, `State`, contains one `AccountState`, one `SignOnState`, and one `BapState`. `src/state/runtime/storage/internal.h` exposes one process-wide root State. | Two network connections are not two isolated player accounts. |
| Account mutation | `src/server/bap/bap_route.cpp`, `publish_account_mutation`, refreshes other active sessions from the shared account. `src/server/web_service/web_service_runtime.cpp` can change the primary account globally. | Forwarding a guest into the host's current backend could operate on the host's save. |
| Gameplay endpoint | `src/server/gameplay/endpoint/gameplay_endpoint.cpp`, `initialize`, can bind the configured embedded UDP endpoint. Defaults in `src/core/settings/server/gameplay/definition.h` use loopback addresses. | A UDP endpoint exists, but its presence does not establish a shared two-player world. |
| Address resolution | `src/server/gameplay/resolution/address_resolution_host.cpp` conditionally handles BAP300/301 and the DES-CBC/HMAC envelope for the configured embedded endpoint. | The isolated game established a native channel and acknowledged view replies behind a development opt-in. Remote human resolution remains unverified. |
| Group membership | `src/server/gameplay/group/shared_membership.h` builds a control host and up to two authenticated humans. `group_host.cpp` requires endpoint-scoped authorization and real captured NetAddr values. | The base native roster now has a shared path, but the companion does not yet have the actual game descriptors needed to activate it. |
| Player properties | `group_host.cpp`, `consume`, reads the peer-properties header and player-add identity prefix; its comments explicitly identify undecoded profile/property bodies. `bind_view` echoes the peer's view signature. | The existing handshake is insufficient evidence of complete remote Guardian replication. |
| Steam friend interface | `src/steam/interfaces/tables/common_tables.cpp` registers Friends017 enumeration, persona, presence and invitation methods. `src/steam/interfaces/methods/friends.cpp` exposes only a peer published by the authenticated companion. | The native APIs and Dawn Friends overlay are implemented in source. Visibility in the game's own roster and party acceptance still require actual game verification and a joinable native session. |
| Steam networking | `src/steam/interfaces/methods/serialized_networking.cpp` drops rendezvous notifications, connection-state messages, and relay tickets, and returns no certificate. | Pairing is not a substitute for a working native peer connection path. |
| Lobby shim | `src/steam/interfaces/methods/matchmaking.cpp` retains process-local lobby metadata and synthesizes local callbacks. | A successful local lobby callback does not confirm membership on another machine. |

Paths beginning with `src/` in this table are relative to `Dawn/`.

## Required runtime work

The following is an implementation sequence. These items are not supplied by the
launcher pairing protocol.

1. **Keep player services local.** Each PC retains its own account identity,
   selected character, inventory, keys, persistence and local profile/BAP service.
   The host owns the shared activity. Do not forward account operations into the
   host's single process-wide account or infer native player IDs from Steam IDs.
2. **Add a typed activity boundary.** Introduce a guest-local proxy for only the
   authorized activity operations. Bind its messages to the exact BAP connection,
   authentication generation, activity instance and host lineage. The host must
   advertise reachable gameplay endpoints. The ordinary account BAP listener
   remains on loopback; publishing it to the LAN would not provide this boundary.
3. **Make gameplay handoff conditional.** Disable the guest's embedded gameplay
   endpoint only after a validated host grant and compatible native session are
   ready. Keep its local profile services running. A lost connection must not
   silently fall back to a separate local world. Do not call the existing broad
   `server::shutdown` during live gameplay: client hooks and native activity work
   can still depend on its state.
4. **Activate a shared native session.** Connect the guarded two-human membership
   builder to authenticated native descriptors and a working peer channel.
   Preserve stable and distinct player/machine IDs, assign entity ownership, and
   publish per-recipient session data. Complete the required property codecs and
   activity join sequence before claiming a second Guardian is replicated.
5. **Carry gameplay state in both directions.** Integrate the native peer channel
   with the shared activity host. Verify movement, remote appearance, weapons,
   damage, enemy state, death/revive, objectives, and activity transitions. A generic
   packet relay cannot by itself supply missing ownership or serialization rules.
6. **Complete the in-game social path.** Connect the implemented friend,
   presence and invitation APIs to a verified shared-session join path. Verify
   the paired player in the game's own roster, the receiving notification, and
   invitation acceptance in game. The new [ticketed acceptance protocol](INVITATION-CONTROL-V2.md)
   supplies intent only. A future grant must revalidate the current native epochs,
   activity binding, native machine/player identities and authenticated UDP source.
7. **Advertise tested capabilities.** Enable multiplayer Play only when the actual
   loaded runtime implements the above contract. A launcher flag or editable file
   is not sufficient proof that a stock installed DLL can host multiplayer.

The current launcher blocks multiplayer Play. The updated native startup rejects
unsupported `DAWN_SESSION_MODE` values before persistent State initialization.
An optional `DAWN_COMPANION_*` configuration enables the social IPC preflight while
the game remains in solo mode. Ordinary solo launches strip inherited companion
configuration. Direct launch without these variables retains the existing solo
runtime behavior.

The account backend remains local to each player. This avoids forwarding a
guest's inventory transactions into the host's single process-wide account.
Changing the platform identity can still affect the account's sign-in identity;
native game testing must use isolated copies of saves until preservation is
verified. No automated live server shutdown or account migration is implemented.

The [local-profile handoff design](LOCAL-PROFILE-ACTIVITY-HANDOFF.md) records the
remaining exact BAP activity boundary. Existing seeded join IDs and local BAP
handshake state are not proof of a remote native player identity.

## Component verification

The launcher self-tests exercise authenticated TCP pairing, bounded control
messages, native pipe framing/authentication, identity binding, invitations,
disconnects and UI state using test native clients. Connection generations
prevent queued profiles, invitations, sends, and errors from affecting a later
pairing, including reconnection to the same identity. They do not start the game.

Before protocol 2, local verification passed 155 launcher assertions and 227
social/IPC/membership checks. Protocol 2 now has 78 protocol, 292 native IPC,
and 221 Social checks. Its launcher and cross-language checks are described in
the invitation protocol notes.
Shared member/player slots now remain assigned to the same native identity
across disconnect/rejoin. If a missing member would require an unsupported
sparse native membership, publication stops rather than renumbering a survivor.

The native test projects are:

- `Dawn/unit/companion_protocol_tests.vcxproj`: numeric, framing-field and
  text validation at the IPC boundary.
- `Dawn/unit/companion_client_tests.vcxproj`: the production native pipe client
  against an isolated Windows pipe server, including fragmented input.
- `Dawn/unit/steam_social_tests.vcxproj`: social ABI values, callback payloads,
  invitation acceptance, stale IDs, transport failures and queue backpressure.
- `Dawn/unit/shared_membership_tests.vcxproj`: two distinct human rows, native
  membership encoding/hash state and endpoint-scoped link lookup.
- `Dawn/unit/address_resolution_tests.vcxproj`: 1,288 body-codec and service-301
  framing checks, including preservation of other services' status-200 headers.
- `Dawn/unit/des_cbc_tests.vcxproj`: 53 compatibility-primitive checks.
- `Dawn/unit/routed_datagram_tests.vcxproj`: 535 envelope and failure checks.
- `Dawn/unit/resolution_replay_tests.vcxproj`: 16,554 replay-window checks.
- `Dawn/unit/address_resolution_host_tests.vcxproj`: 1,276 enabled-backend checks
  and 14 checks in a separate `--disabled` process. These link production crypto
  and the context store without sockets, game processes, or saves.
- `Dawn/unit/endpoint_resolution_tests.vcxproj`: 136 checks in the recorded
  loopback run, using real UDP and production endpoint/crypto code with stubbed
  peer/legacy handlers. Covers authenticated dispatch, wrapped replies, rejected
  tampering/replay/rebinding, preserved legacy traffic and send failures.
- `Dawn/unit/peer_view_echo_tests.vcxproj`: 2,006 checks with compiler warnings
  treated as errors, covering
  exact link ownership, malformed views, queue rollback and unchanged group slots.
- `Dawn/unit/native_identity_observation_tests.vcxproj`: 301 checks plus three
  unsupported-layout checks, with the real adapter and production membership
  encoder. Covers scalar-read restrictions, native ownership, unstable samples,
  ambiguous roles, expiry, capacity reclamation and lifecycle fencing.

`companion_bridge_harness.vcxproj` builds a small native test worker that links
the production companion client with test social/log sinks. The launcher's
`--native-companion-test <harness.exe> <report.txt>` command runs two workers
through two real paired launchers. This verifies cross-language IPC and control
forwarding without loading Destiny or opening a player database. This two-worker
test passed locally in both directions with the production C++ companion client.
It does not verify the game's friend roster or a shared activity.

Native build instructions are in
[`tools/build/PORTABLE-WINDOWS.md`](../tools/build/PORTABLE-WINDOWS.md).
The native GitHub workflow builds and runs the twelve component test projects;
preparing the workflow does not mean a remote run has passed.

For production commit `21c2a980`, the remote
[native component workflow](https://github.com/erictow/MultiDawn/actions/runs/42975247251)
and [launcher workflow](https://github.com/erictow/MultiDawn/actions/runs/42975247367)
both completed successfully. Later experimental changes need their own checks.

For experimental commit `066a9bf6`, the
[native component and interoperability workflow](https://github.com/erictow/MultiDawn/actions/runs/43137042609)
passed all twelve component suites, the Python snapshot tests and both companion
versions. The preceding invitation checkpoint also passed the
[launcher and package workflow](https://github.com/erictow/MultiDawn/actions/runs/43136233523).

The [runtime snapshot tool](../tools/testing/MULTIPLAYER-RUNTIME-SNAPSHOT.md)
verifies the actual loaded build and reads bounded native session/facet state.
Its eighteen offline tests cover layout checks, consistency, key redaction,
Steam-address redaction, and PID-scoped trace parsing. An optional bounded native session trace reuses the
existing session-update hook to locate structures without enabling legacy probes.

## Acceptance checks before enabling multiplayer Play

Use two owned test installations of the same supported game build and the same
MultiDawn runtime version. Use disposable copies of two different player profiles.
Keep each original profile and game installation available for comparison.

- Launch solo through the launcher and directly. Confirm ordinary sign-in, play,
  save/reload, and process exit still work.
- Pair two launchers over loopback for transport tests, then over a real LAN or VPN.
  Reject malformed/incorrect codes, incompatible protocol versions, and a third
  participant. Verify timeout, disconnect, and session cleanup on both sides.
- Confirm that both game processes negotiate the intended host and distinct player
  identities. Confirm that the guest uses the host's gameplay endpoint while its
  own profile/BAP service and saves remain local. Check the actual loaded DLL and
  endpoint logs, not just launcher status.
- Put both Guardians in the same activity. Observe each player's movement and
  appearance from the other machine. Exercise weapons, damage, enemies, revive,
  objective progression, loading, and return to orbit.
- Change inventory and progress independently on each profile. Exit, reload, and
  compare both saves. Verify that no guest action changes the host's account and
  that no host action replaces the guest's account.
- Show the paired player in the in-game friend roster. Send an invitation in each
  direction, observe the receiving notification, accept it, and join the same party.
- Stop the host during gameplay and interrupt the network. Confirm a clear session
  failure, bounded cleanup, and intact saves. Test reconnect only once its ownership
  and session lifecycle are explicitly implemented.

Launcher self-tests and native unit tests are useful checks for their respective
layers. Neither replaces these two-machine gameplay checks.
