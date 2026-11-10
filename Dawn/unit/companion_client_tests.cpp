#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "../src/core/multiplayer/companion.h"
#include "../src/core/multiplayer/companion_protocol.h"
#include "../src/core/logging/log.h"
#include "../src/steam/runtime/social.h"

// The test replaces only the social/log boundary. It exercises the production pipe client.
namespace fixture {
constexpr std::uint64_t localId = 0x0110000100000001ULL, remoteId = 0x0110000100000002ULL;
constexpr wchar_t pipeId[] = L"0123456789abcdef0123456789abcdef";
constexpr char nonce[] = "fedcba9876543210fedcba9876543210";
std::atomic<unsigned> checks{0};
dawn::steam::social::PeerProfile peer{};
dawn::steam::social::InviteSender sender{};
void* senderContext{};
std::uint64_t incoming{};
std::array<char, 256> incomingConnect{};
void check(bool condition, int line) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "FAIL companion client line %d (Windows %lu)\n", line, GetLastError()); std::exit(1); }
}
#define CHECK(value) fixture::check((value), __LINE__)
void send(HANDLE pipe, const std::string& text, bool fragmented = false) {
    const auto size = static_cast<std::uint32_t>(text.size());
    std::array<unsigned char, 4> header{};
    for (unsigned i = 0; i < 4; ++i) header[i] = static_cast<unsigned char>(size >> (i * 8U));
    DWORD written = 0;
    if (fragmented) {
        for (unsigned i = 0; i < 4; ++i) { CHECK(WriteFile(pipe, header.data() + i, 1, &written, nullptr)); Sleep(2); }
    } else CHECK(WriteFile(pipe, header.data(), 4, &written, nullptr));
    CHECK(WriteFile(pipe, text.data(), size, &written, nullptr) && written == size);
}
std::string receive(HANDLE pipe) {
    std::array<unsigned char, 4> header{};
    DWORD got = 0;
    CHECK(ReadFile(pipe, header.data(), 4, &got, nullptr) && got == 4);
    std::uint32_t size = 0;
    for (unsigned i = 0; i < 4; ++i) size |= static_cast<std::uint32_t>(header[i]) << (i * 8U);
    CHECK(size > 0 && size <= 1024);
    std::string text(size, '\0');
    CHECK(ReadFile(pipe, text.data(), size, &got, nullptr) && got == size);
    return text;
}
}

namespace dawn::core::log { void write(Channel, Level, std::string_view) noexcept {} }
namespace dawn::steam::social {
bool set_local_identity(std::uint64_t id, std::string_view) noexcept { return id == fixture::localId; }
const char* local_persona_name() noexcept { return "Local fixture"; }
bool set_peer(const PeerProfile& profile) noexcept { fixture::peer = profile; return profile.steamId == fixture::remoteId; }
void clear_peer() noexcept { fixture::peer = {}; }
void set_invite_sender(InviteSender sender, void* context) noexcept { fixture::sender = sender; fixture::senderContext = context; }
bool receive_invitation(std::uint64_t from, std::string_view connect) noexcept {
    if (connect.size() >= fixture::incomingConnect.size()) return false;
    fixture::incoming = from;
    std::memcpy(fixture::incomingConnect.data(), connect.data(), connect.size());
    fixture::incomingConnect[connect.size()] = '\0';
    return true;
}
void reset() noexcept { clear_peer(); set_invite_sender(nullptr, nullptr); }
}

int main() {
    namespace client = dawn::core::multiplayer;
    SetEnvironmentVariableW(L"DAWN_COMPANION_ID", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_NONCE", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PID", nullptr);
    SetEnvironmentVariableW(L"DAWN_SESSION_MODE", nullptr);
    CHECK(client::initialize() && !client::connected());
    SetEnvironmentVariableW(L"DAWN_SESSION_MODE", L"join");
    CHECK(!client::initialize() && !client::connected());
    SetEnvironmentVariableW(L"DAWN_SESSION_MODE", L"solo");
    SetEnvironmentVariableW(L"DAWN_COMPANION_ID", L"\\\\remote\\pipe\\bad");
    CHECK(!client::initialize());
    SetEnvironmentVariableW(L"DAWN_COMPANION_ID", fixture::pipeId);
    SetEnvironmentVariableA("DAWN_COMPANION_NONCE", fixture::nonce);
    const std::wstring pid = std::to_wstring(GetCurrentProcessId());
    SetEnvironmentVariableW(L"DAWN_COMPANION_PID", pid.c_str());
    const HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MultiDawn-0123456789abcdef0123456789abcdef",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 1000, nullptr);
    CHECK(pipe != INVALID_HANDLE_VALUE);
    const HANDLE inboundReady = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const HANDLE releaseServer = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    CHECK(inboundReady != nullptr && releaseServer != nullptr);
    std::thread server([&] {
        CHECK(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
        CHECK(fixture::receive(pipe) == std::string("HELLO 1 ") + fixture::nonce);
        fixture::send(pipe, "WELCOME 1 76561197960265729 76561197960265730 50656572 1", true);
        CHECK(fixture::receive(pipe) == "INVITE 76561197960265730 2B6A6F696E20313233");
        fixture::send(pipe, "INVITEFROM 76561197960265730 2B6A6F696E20343536");
        fixture::send(pipe, "PING");
        SetEvent(inboundReady);
        CHECK(WaitForSingleObject(releaseServer, 5000) == WAIT_OBJECT_0);
        // Oversized frames fail before reading an attacker-selected payload length.
        const std::array<unsigned char, 4> oversized{1, 4, 0, 0};
        DWORD written = 0;
        CHECK(WriteFile(pipe, oversized.data(), 4, &written, nullptr));
        // Keep the pipe open until the native client closes its rejected connection.
        char ignored = 0;
        (void)ReadFile(pipe, &ignored, 1, &written, nullptr);
    });
    CHECK(client::initialize() && client::connected());
    CHECK(fixture::peer.steamId == fixture::remoteId && std::string_view(fixture::peer.name.data()) == "Peer");
    CHECK(fixture::sender != nullptr);
    CHECK(!fixture::sender(fixture::senderContext, fixture::localId, "+join 123"));
    CHECK(fixture::sender(fixture::senderContext, fixture::remoteId, "+join 123"));
    CHECK(WaitForSingleObject(inboundReady, 5000) == WAIT_OBJECT_0);
    client::service(GetTickCount64());
    CHECK(fixture::incoming == fixture::remoteId && std::string_view(fixture::incomingConnect.data()) == "+join 456");
    SetEvent(releaseServer);
    for (unsigned retry = 0; client::connected() && retry < 100; ++retry) { Sleep(10); client::service(GetTickCount64()); }
    CHECK(!client::connected() && fixture::peer.steamId == 0 && fixture::sender == nullptr);
    server.join();
    CloseHandle(releaseServer);
    CloseHandle(inboundReady);
    CloseHandle(pipe);
    client::shutdown();
    std::printf("PASS: %u native companion IPC checks\n", fixture::checks.load());
}
