# Multiplayer runtime status

MultiDawn's launcher provides solo launch and a two-person pairing connection.
Pairing does not yet put two Guardians into the same Destiny activity. Multiplayer
game launch is blocked until the game runtime supports that behavior.

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
| Group membership | `src/server/gameplay/group/group_host.cpp`, `publish_snapshot`, builds host and admitted-peer member records with an array of one player. `publish_membership` seeds the player with `steam::kLocalSteamId`. | Existing snapshots do not describe two human players with independent identities. |
| Player properties | `group_host.cpp`, `consume`, reads the peer-properties header and player-add identity prefix; its comments explicitly identify undecoded profile/property bodies. `bind_view` echoes the peer's view signature. | The existing handshake is insufficient evidence of complete remote Guardian replication. |
| Steam friend interface | `src/steam/interfaces/tables/common_tables.cpp`, `initialize_common`, registers persona and invite methods but does not implement friend enumeration. `src/steam/interfaces/methods/friends.cpp`, `invite_user_to_game`, returns false. | The paired player cannot currently appear and accept an invitation through this shim. |
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

The current launcher blocks multiplayer Play. The native runtime has not been
changed and does not consume the launcher's session-mode environment variable.
If a later version adds host or guest game startup, its native startup guard must
run before persistent State initialization and server registration. An unsupported
mode must fail before starting another backend or opening a save. Direct launch
currently retains the existing solo runtime behavior.

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
