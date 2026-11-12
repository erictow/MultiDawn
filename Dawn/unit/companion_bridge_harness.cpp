// Cross-language test worker. Runs the production companion client without a game or save.
#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>

#include "../src/core/multiplayer/companion.h"
#include "../src/core/multiplayer/companion_protocol.h"
#include "../src/core/logging/log.h"
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
    const std::string outgoing = std::string("+fixture ") + argv[1];
    const std::string expected = std::string_view(argv[1]) == "side-a" ? "+fixture side-b" : "+fixture side-a";
    if (!client::initialize() || !client::connected()) {
        std::fprintf(stderr, "FAIL: native worker could not authenticate its launcher pipe\n");
        client::shutdown(); return 1;
    }
    std::array<wchar_t, 4> configuredVersion{};
    const auto versionSize = GetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", configuredVersion.data(),
                                                     static_cast<DWORD>(configuredVersion.size()));
    const bool v2 = versionSize == 1 && configuredVersion[0] == L'2';
    bool sent = false, received = false, accepted = false, intentReceived = false;
    std::uint64_t completedAt = 0;
    const std::uint64_t deadline = GetTickCount64() + 15000;
    while (client::connected() && GetTickCount64() < deadline) {
        const auto now = GetTickCount64();
        client::service(now);
        if (!sent && fixture::peer.gameRunning && fixture::sender != nullptr
            && (!v2 || client::invitation_intents_ready())) {
            sent = fixture::sender(fixture::senderContext, fixture::peer.steamId, outgoing);
        }
        // Record completed delivery. The other worker may exit during our final
        // linger window, which correctly revokes its pending invitation locally.
        received = received || (fixture::from == fixture::peer.steamId && fixture::from != 0
                   && std::string_view(fixture::connect.data()) == expected);
        if (v2 && received && !accepted && fixture::acceptedSender != nullptr && fixture::ticket[0] != '\0') {
            accepted = fixture::acceptedSender(fixture::acceptedContext, fixture::from, fixture::ticket.data());
        }
        client::AcceptedInvitationIntent intent{};
        if (v2 && client::take_accepted_invitation(intent)) {
            intentReceived = intent.peerSteamId == fixture::peer.steamId
                && client::protocol::ticket(intent.ticket.data()) && intent.deadline > now;
        }
        if (sent && received && (!v2 || (accepted && intentReceived))) {
            if (completedAt == 0) completedAt = now;
            if (now - completedAt >= 1000) break;
        }
        Sleep(10);
    }
    client::shutdown();
    if (!sent || !received || (v2 && (!accepted || !intentReceived))) {
        std::fprintf(stderr, "FAIL: native worker send=%u receive=%u accept=%u intent=%u protocol=%u\n",
                     sent ? 1U : 0U, received ? 1U : 0U, accepted ? 1U : 0U, intentReceived ? 1U : 0U, v2 ? 2U : 1U);
        return 1;
    }
    std::puts(v2 ? "PASS: native v2 companion exchanged invitations and accepted intents through both launchers; no gameplay grant"
                 : "PASS: production native companion exchanged invitations through both launchers");
    return 0;
}
