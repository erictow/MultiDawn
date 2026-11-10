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
std::uint64_t local{}, from{};
std::array<char, 256> connect{};
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
bool receive_invitation(std::uint64_t from, std::string_view connect) noexcept {
    if (from != fixture::peer.steamId || connect.size() >= fixture::connect.size()) return false;
    fixture::from = from;
    std::memcpy(fixture::connect.data(), connect.data(), connect.size());
    fixture::connect[connect.size()] = '\0';
    return true;
}
void reset() noexcept { clear_peer(); set_invite_sender(nullptr, nullptr); }
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
    bool sent = false, received = false;
    std::uint64_t completedAt = 0;
    const std::uint64_t deadline = GetTickCount64() + 15000;
    while (client::connected() && GetTickCount64() < deadline) {
        const auto now = GetTickCount64();
        client::service(now);
        if (!sent && fixture::peer.gameRunning && fixture::sender != nullptr) {
            sent = fixture::sender(fixture::senderContext, fixture::peer.steamId, outgoing);
        }
        received = fixture::from == fixture::peer.steamId && fixture::from != 0
                   && std::string_view(fixture::connect.data()) == expected;
        if (sent && received) {
            if (completedAt == 0) completedAt = now;
            if (now - completedAt >= 500) break;
        }
        Sleep(10);
    }
    client::shutdown();
    if (!sent || !received) {
        std::fprintf(stderr, "FAIL: native worker send=%u receive=%u\n", sent ? 1U : 0U, received ? 1U : 0U);
        return 1;
    }
    std::puts("PASS: production native companion exchanged invitations through both launchers");
    return 0;
}
