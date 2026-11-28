// Cross-language test worker. Runs the production companion client without a game or save.
#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>

#include "../src/core/multiplayer/companion.h"
#include "../src/core/multiplayer/companion_protocol.h"
#include "../src/core/logging/log.h"
#include "../src/steam/runtime/runtime.h"
#include "../src/steam/runtime/social.h"

namespace fixture {
dawn::steam::social::PeerProfile peer{};
dawn::steam::social::InviteSender sender{};
void* senderContext{};
dawn::steam::social::InviteAcceptedSender acceptedSender{};
void* acceptedContext{};
std::uint64_t local{}, from{};
std::array<char, 256> connect{};
std::array<char, 33> ticket{};
}

namespace dawn::core::log { void write(Channel, Level, std::string_view) noexcept {} }
namespace dawn::steam::social {
bool set_local_identity(std::uint64_t id, std::string_view) noexcept {
    if (!core::multiplayer::protocol::steam_identity(id)) return false;
    fixture::local = id; return true;
}
const char* local_persona_name() noexcept { return "Native fixture"; }
bool set_peer(const PeerProfile& profile) noexcept {
    if (!core::multiplayer::protocol::steam_identity(profile.steamId) || profile.steamId == fixture::local) return false;
    fixture::peer = profile; return true;
}
void clear_peer() noexcept { fixture::peer = {}; }
void set_invite_sender(InviteSender sender, void* context) noexcept { fixture::sender = sender; fixture::senderContext = context; }
void set_invite_accepted_sender(InviteAcceptedSender sender, void* context) noexcept {
    fixture::acceptedSender = sender; fixture::acceptedContext = context;
}
bool receive_invitation(std::uint64_t from, std::string_view connect) noexcept {
    if (from != fixture::peer.steamId || connect.size() >= fixture::connect.size()) return false;
    fixture::from = from;
    std::memcpy(fixture::connect.data(), connect.data(), connect.size());
    fixture::connect[connect.size()] = '\0';
    return true;
}
bool receive_invitation(std::uint64_t from, std::string_view connect, std::string_view ticket) noexcept {
    if (!core::multiplayer::protocol::ticket(ticket) || !receive_invitation(from, connect)) return false;
    fixture::ticket = {};
    std::memcpy(fixture::ticket.data(), ticket.data(), ticket.size());
    return true;
}
bool pending_invitation(PendingInvitation& pending) noexcept {
    pending = {};
    if (fixture::ticket[0] == '\0') return false;
    pending.id = 1; pending.from = fixture::from; pending.ticket = fixture::ticket;
    return true;
}
bool revoke_invitation(std::string_view ticket) noexcept {
    if (ticket != fixture::ticket.data()) return false;
    fixture::ticket = {}; fixture::from = 0; fixture::connect = {}; return true;
}
void reset() noexcept {
    clear_peer(); set_invite_sender(nullptr, nullptr); set_invite_accepted_sender(nullptr, nullptr);
    fixture::ticket = {}; fixture::from = 0; fixture::connect = {};
}
}

int main(int argc, char** argv) {
    if (argc != 2 || (std::string_view(argv[1]) != "side-a" && std::string_view(argv[1]) != "side-b")) return 2;
    namespace client = dawn::core::multiplayer;
    const bool host = std::string_view(argv[1]) == "side-a";
    const std::string outgoing = std::string("+fixture ") + argv[1];
    const std::string expected = host ? "+fixture side-b" : "+fixture side-a";
    if (!client::initialize() || !client::connected()) {
        std::fprintf(stderr, "FAIL: native worker could not authenticate its launcher pipe\n");
        client::shutdown(); return 1;
    }
    std::array<wchar_t, 4> configuredVersion{};
    const auto versionSize = GetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", configuredVersion.data(),
                                                     static_cast<DWORD>(configuredVersion.size()));
    const bool v3 = versionSize == 1 && configuredVersion[0] == L'3';
    const bool v2 = v3 || (versionSize == 1 && configuredVersion[0] == L'2');
    std::array<wchar_t, 2> configuredWorld{};
    const bool worldProbe = v3 && GetEnvironmentVariableW(L"DAWN_COMPANION_WORLD_PROBE",
        configuredWorld.data(), static_cast<DWORD>(configuredWorld.size())) == 1 && configuredWorld[0] == L'1';
    const bool sendInvite = !worldProbe || host;
    const bool receiveInvite = !worldProbe || !host;
    client::WorldDestination destination{};
    constexpr std::string_view package = "city_tower_social_d2";
    static_assert(package.size() < client::WorldDestination{}.package.size());
    std::memcpy(destination.package.data(), package.data(), package.size());
    destination.activity = 20;
    destination.region = 56;
    if (v3 && fixture::local != dawn::steam::kLocalSteamId) {
        std::fputs("FAIL: preflight changed the native worker's solo identity\n", stderr);
        client::shutdown(); return 1;
    }
    bool sent = false, received = false, accepted = false, intentReceived = false;
    bool preflightRequested = false, preflightObserved = false;
    bool probeRequested = false, probeObserved = false;
    client::InvitationPreflightObservation preflight{};
    client::WorldProbeToken token{};
    std::array<char, 33> intentTicket{};
    std::array<char, 33> incomingTicket{};
    std::uint64_t completedAt = 0;
    const std::uint64_t deadline = GetTickCount64() + 15000;
    while (client::connected() && GetTickCount64() < deadline) {
        const auto now = GetTickCount64();
        client::WorldProbeEvent world{};
        client::service(now, nullptr, worldProbe ? &world : nullptr);
        if (sendInvite && !sent && fixture::peer.gameRunning && fixture::sender != nullptr
            && (!v2 || client::invitation_intents_ready())) {
            sent = fixture::sender(fixture::senderContext, fixture::peer.steamId, outgoing);
        }
        // Record completed delivery. The other worker may exit during our final
        // linger window, which correctly revokes its pending invitation locally.
        received = received || (fixture::from == fixture::peer.steamId && fixture::from != 0
                   && std::string_view(fixture::connect.data()) == expected);
        if (receiveInvite && v2 && received && !accepted && fixture::acceptedSender != nullptr && fixture::ticket[0] != '\0') {
            accepted = fixture::acceptedSender(fixture::acceptedContext, fixture::from, fixture::ticket.data());
            if (accepted) incomingTicket = fixture::ticket;
        }
        client::AcceptedInvitationIntent intent{};
        if (v2 && client::take_accepted_invitation(intent)) {
            intentReceived = intent.peerSteamId == fixture::peer.steamId
                && client::protocol::ticket(intent.ticket.data()) && intent.deadline > now;
            if (intentReceived) intentTicket = intent.ticket;
        }
        if (v3 && intentReceived && !preflightRequested)
            preflightRequested = client::request_invitation_preflight(fixture::peer.steamId, intentTicket.data());
        client::InvitationPreflightObservation observation{};
        if (v3 && client::take_invitation_preflight(observation)) {
            preflightObserved = observation.peerSteamId == fixture::peer.steamId
                && observation.ticket == intentTicket && observation.deadline > now
                && client::validate_invitation_preflight(observation);
            if (preflightObserved) preflight = observation;
        }
        if (worldProbe && host && preflightObserved && !probeRequested)
            probeRequested = client::request_world_probe(preflight, destination, token);
        if (worldProbe && world.generation != 0 && world.deadline > now) {
            if (host && probeRequested && world.kind == client::WorldProbeKind::ready && world.token == token)
                probeObserved = true;
            if (!host && accepted && world.kind == client::WorldProbeKind::request
                && world.destination == destination && world.token.ticket == incomingTicket
                && client::protocol::ticket(world.token.nonce.data()))
                probeObserved = client::respond_world_probe(world, true);
        }
        const bool sentComplete = !sendInvite || (sent && (!v2 || intentReceived) && (!v3 || preflightObserved));
        const bool receivedComplete = !receiveInvite || (received && (!v2 || accepted));
        if (sentComplete && receivedComplete && (!worldProbe || probeObserved)) {
            if (completedAt == 0) completedAt = now;
            if (now - completedAt >= 1000) break;
        }
        Sleep(10);
    }
    client::shutdown();
    if ((sendInvite && (!sent || (v2 && !intentReceived) || (v3 && !preflightObserved)))
        || (receiveInvite && (!received || (v2 && !accepted))) || (worldProbe && !probeObserved)) {
        std::fprintf(stderr, "FAIL: native worker send=%u receive=%u accept=%u intent=%u preflight=%u probe_sent=%u probe_observed=%u protocol=%u\n",
                     sent ? 1U : 0U, received ? 1U : 0U, accepted ? 1U : 0U, intentReceived ? 1U : 0U,
                     preflightObserved ? 1U : 0U, probeRequested ? 1U : 0U, probeObserved ? 1U : 0U, v3 ? 3U : v2 ? 2U : 1U);
        return 1;
    }
    if (worldProbe) {
        std::puts(host ? "PASS: host native companion received readiness for its accepted-ticket challenge"
                       : "PASS: guest native companion replied to the accepted-ticket challenge for the expected Tower destination");
    } else {
        std::puts(v3 ? "PASS: native v3 companion observed current preflight after consuming accepted intents through both launchers"
                     : v2 ? "PASS: native v2 companion exchanged invitations and accepted intents through both launchers"
                     : "PASS: production native companion exchanged invitations through both launchers");
    }
    return 0;
}
