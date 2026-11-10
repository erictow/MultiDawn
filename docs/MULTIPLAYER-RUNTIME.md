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
  Incoming invitations stay pending until explicit acceptance queues the
  native 264-byte `GameRichPresenceJoinRequested_t` callback.
- A Dawn Friends page and an invitation notice in the game overlay.
- A local named-pipe companion client, bound to the launcher's process ID and
  a per-launch nonce. The launcher restricts the pipe to the current Windows
  user and forwards social messages through the authenticated pairing channel.
  A paired launcher is distinguished from a running native game consumer.

These changes have not been installed over the existing game. The approved
Windows SDK is installed locally, and the native component tests now compile
and pass with Clang 23.1.5. The installed Dawn 1.7.2 DLL does not gain these
features from a launcher update alone.

The shared membership path is not activated by the social companion. It still
needs authenticated native descriptors, complete player properties, and working
view/entity authority before multiplayer Play can be enabled.

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
| Group membership | `src/server/gameplay/group/shared_membership.h` builds a control host and up to two authenticated humans. `group_host.cpp` requires endpoint-scoped authorization and real captured NetAddr values. | The base native roster now has a shared path, but the companion does not yet have the actual game descriptors needed to activate it. |
| Player properties | `group_host.cpp`, `consume`, reads the peer-properties header and player-add identity prefix; its comments explicitly identify undecoded profile/property bodies. `bind_view` echoes the peer's view signature. | The existing handshake is insufficient evidence of complete remote Guardian replication. |
| Steam friend interface | `src/steam/interfaces/tables/common_tables.cpp` registers Friends017 enumeration, persona, presence and invitation methods. `src/steam/interfaces/methods/friends.cpp` exposes only a peer published by the authenticated companion. | The native APIs and Dawn Friends overlay are implemented in source. Visibility in the game's own roster and party acceptance still require actual game verification and a joinable native session. |
| Steam networking | `src/steam/interfaces/methods/serialized_networking.cpp` drops rendezvous notifications, connection-state messages, and relay tickets, and returns no certificate. | Pairing is not a substitute for a working native peer connection path. |
| Lobby shim | `src/steam/interfaces/methods/matchmaking.cpp` retains process-local lobby metadata and synthesizes local callbacks. | A successful local lobby callback does not confirm membership on another machine. |

Paths beginning with `src/` in this table are relative to `Dawn/`.

## Required runtime work

The following is an implementation sequence. These items are not supplied by the
launcher pairing protocol.

1. **Separate player state from the activity host.** Introduce authenticated player
   contexts for account identity, selected character, inventory transactions, keys,
   and persistence. Thread the context through BAP and web-service handlers rather
   than resolving every request through `state::account_snapshot()`. A guest must
   never inherit the host's account merely because both use the same process.
2. **Provide a complete remote backend boundary.** Either expose the required
   SignOn/config/BAP services through an authenticated transport or implement an
   explicit proxy for the existing client-consumer boundary. The host must publish
   reachable endpoints and connection-scoped credentials. The guest runtime must
   select this boundary before registering its embedded server consumers.
3. **Make guest startup conditional.** Add a supported guest runtime branch in
   `core::initialize` before `state::initialize` and `server::initialize`. Only a
   successfully validated, compatible host session may enter that branch. A lost
   connection must not silently fall back to a local world or a different account.
   Do not call the existing broad `server::shutdown` during live gameplay: client
   hooks and native activity work can still depend on its state.
4. **Implement a shared native session.** Replace the one-player snapshot shape in
   `group::publish_snapshot` with the exact membership required for two players.
   Preserve stable and distinct player/machine IDs, assign entity ownership, and
   publish per-recipient session data. Complete the required property codecs and
   activity join sequence before claiming a second Guardian is replicated.
5. **Carry gameplay state in both directions.** Integrate the native peer channel
   with the shared activity host. Verify movement, remote appearance, weapons,
   damage, enemy state, death/revive, objectives, and activity transitions. A generic
   packet relay cannot by itself supply missing ownership or serialization rules.
6. **Implement the in-game social path.** Add friend enumeration, persona state,
   presence, and the invitation callbacks used by this game build to the Steam
   shim. Route invitations to the paired identity and then into the shared session
   join path. Verify both the receiving notification and acceptance in game.
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

## Component verification

The launcher self-tests exercise authenticated TCP pairing, bounded control
messages, native pipe framing/authentication, identity binding, invitations,
disconnects and UI state using test native clients. Connection generations
prevent queued profiles, invitations, sends, and errors from affecting a later
pairing, including reconnection to the same identity. They do not start the game.

Local verification on November 10, 2026 passed 98 launcher assertions and 207
native checks (40 protocol, 33 IPC, 90 social, and 44 membership/link checks).

The native test projects are:

- `Dawn/unit/companion_protocol_tests.vcxproj`: numeric, framing-field and
  text validation at the IPC boundary.
- `Dawn/unit/companion_client_tests.vcxproj`: the production native pipe client
  against an isolated Windows pipe server, including fragmented input.
- `Dawn/unit/steam_social_tests.vcxproj`: social ABI values, callback payloads,
  invitation acceptance, stale IDs, transport failures and queue backpressure.
- `Dawn/unit/shared_membership_tests.vcxproj`: two distinct human rows, native
  membership encoding/hash state and endpoint-scoped link lookup.

`companion_bridge_harness.vcxproj` builds a small native test worker that links
the production companion client with test social/log sinks. The launcher's
`--native-companion-test <harness.exe> <report.txt>` command runs two workers
through two real paired launchers. This verifies cross-language IPC and control
forwarding without loading Destiny or opening a player database. This two-worker
test passed locally in both directions with the production C++ companion client.
It does not verify the game's friend roster or a shared activity.

Native build instructions are in
[`tools/build/PORTABLE-WINDOWS.md`](../tools/build/PORTABLE-WINDOWS.md).
The native GitHub workflow builds and runs the four component test projects;
preparing the workflow does not mean a remote run has passed.

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
  identities. Confirm that the guest does not bind or use an embedded gameplay/BAP
  backend. Check the actual loaded DLL and endpoint logs, not just launcher status.
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
