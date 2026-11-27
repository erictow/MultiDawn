#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "../src/core/multiplayer/companion.h"
#include "../src/core/multiplayer/companion_protocol.h"
#include "../src/core/logging/log.h"
#include "../src/steam/runtime/runtime.h"
#include "../src/steam/runtime/social.h"

// The test replaces only the social/log boundary. It exercises the production pipe client.
namespace fixture {
constexpr std::uint64_t localId = 0x0110000100000001ULL, remoteId = 0x0110000100000002ULL;
constexpr std::string_view localPersona = "Local fixture";
constexpr wchar_t pipeId[] = L"0123456789abcdef0123456789abcdef";
constexpr char nonce[] = "fedcba9876543210fedcba9876543210";
std::atomic<unsigned> checks{0};
std::atomic<unsigned> localPublications{0}, peerPublications{0};
std::uint64_t publishedLocal{};
std::atomic<unsigned> tracedRequests{0}, tracedResults{0};
dawn::steam::social::PeerProfile peer{};
dawn::steam::social::InviteSender sender{};
void* senderContext{};
dawn::steam::social::InviteAcceptedSender acceptedSender{};
void* acceptedContext{};
dawn::steam::social::PendingInvitation invitation{};
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

namespace dawn::core::log {
void write(Channel, Level, std::string_view line) noexcept {
    if (line == "ev=multiplayer_companion stage=invitation_preflight result=request_sent") ++fixture::tracedRequests;
    if (line == "ev=multiplayer_companion stage=invitation_preflight result=accepted_ticket_verified") ++fixture::tracedResults;
}
}
namespace dawn::steam::social {
bool set_local_identity(std::uint64_t id, std::string_view name) noexcept {
    ++fixture::localPublications;
    fixture::publishedLocal = id;
    return (id == fixture::localId || id == kLocalSteamId) && name == fixture::localPersona;
}
const char* local_persona_name() noexcept { return fixture::localPersona.data(); }
bool set_peer(const PeerProfile& profile) noexcept {
    ++fixture::peerPublications; fixture::peer = profile; return profile.steamId == fixture::remoteId;
}
void clear_peer() noexcept { fixture::peer = {}; }
void set_invite_sender(InviteSender sender, void* context) noexcept { fixture::sender = sender; fixture::senderContext = context; }
void set_invite_accepted_sender(InviteAcceptedSender sender, void* context) noexcept {
    fixture::acceptedSender = sender; fixture::acceptedContext = context;
}
bool receive_invitation(std::uint64_t from, std::string_view connect) noexcept {
    if (connect.size() >= fixture::incomingConnect.size()) return false;
    fixture::incoming = from;
    std::memcpy(fixture::incomingConnect.data(), connect.data(), connect.size());
    fixture::incomingConnect[connect.size()] = '\0';
    return true;
}
bool receive_invitation(std::uint64_t from, std::string_view connect, std::string_view ticket) noexcept {
    if (!core::multiplayer::protocol::ticket(ticket) || !receive_invitation(from, connect)) return false;
    fixture::invitation = {};
    fixture::invitation.id = 1; fixture::invitation.from = from;
    std::memcpy(fixture::invitation.ticket.data(), ticket.data(), ticket.size());
    return true;
}
bool pending_invitation(PendingInvitation& pending) noexcept {
    pending = fixture::invitation; return pending.id != 0;
}
bool revoke_invitation(std::string_view ticket) noexcept {
    if (ticket != fixture::invitation.ticket.data()) return false;
    fixture::invitation = {}; return true;
}
void reset() noexcept {
    clear_peer(); set_invite_sender(nullptr, nullptr); set_invite_accepted_sender(nullptr, nullptr);
    fixture::invitation = {};
}
}

static void v2_case(const std::vector<std::string>& messages, bool malformed, bool roundtrip) {
    namespace client = dawn::core::multiplayer;
    constexpr char ticket[] = "0123456789ABCDEF0123456789ABCDEF";
    constexpr char other[] = "ABCDEF0123456789ABCDEF0123456789";
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", L"2");
    const HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MultiDawn-0123456789abcdef0123456789abcdef",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 1000, nullptr);
    CHECK(pipe != INVALID_HANDLE_VALUE);
    const HANDLE ready = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    const HANDLE advance = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    CHECK(ready != nullptr && advance != nullptr);
    std::thread server([&] {
        CHECK(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
        CHECK(fixture::receive(pipe) == std::string("HELLO 2 ") + fixture::nonce);
        fixture::send(pipe, "WELCOME 2 76561197960265729 76561197960265730 50656572 1", true);
        for (const auto& message : messages) fixture::send(pipe, message);
        SetEvent(ready);
        if (roundtrip) {
            CHECK(fixture::receive(pipe) == std::string("ACCEPT 76561197960265730 ") + ticket);
            fixture::send(pipe, std::string("ACCEPTED 76561197960265730 ") + ticket + " 60000");
            SetEvent(ready);
            CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
            fixture::send(pipe, std::string("ACCEPTED 76561197960265730 ") + ticket + " 60000");
            SetEvent(ready);
            CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
            fixture::send(pipe, std::string("REVOKED ") + ticket);
            fixture::send(pipe, std::string("ACCEPTED 76561197960265730 ") + other + " 60000");
            fixture::send(pipe, std::string("RUNTIME 76561197960265730 ") + other + " 2");
            SetEvent(ready);
            CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
            fixture::send(pipe, std::string("RUNTIME 76561197960265730 ") + other + " 1");
            SetEvent(ready);
            CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
            fixture::send(pipe, "INVITEFROM 76561197960265730 2B6C6567616379");
            SetEvent(ready);
        }
        CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
        char ignored{}; DWORD got{};
        (void)ReadFile(pipe, &ignored, 1, &got, nullptr);
    });
    CHECK(client::initialize() && client::connected());
    CHECK(fixture::publishedLocal == fixture::localId);
    // The native caller cannot downgrade to a ticketless invitation while its
    // protocol-2 peer's runtime capability is unknown, even before service polls.
    CHECK(fixture::sender != nullptr && !fixture::sender(fixture::senderContext, fixture::remoteId, "+too-early"));
    CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
    const auto incomingBefore = fixture::incomingConnect;
    client::service(GetTickCount64());
    if (malformed) {
        CHECK(!client::connected() && fixture::acceptedSender == nullptr);
        CHECK(fixture::incomingConnect == incomingBefore);
    } else if (roundtrip) {
        CHECK(client::invitation_intents_ready());
        CHECK(fixture::acceptedSender != nullptr && fixture::invitation.id != 0);
        CHECK(!fixture::acceptedSender(fixture::acceptedContext, fixture::localId, ticket));
        CHECK(!fixture::acceptedSender(fixture::acceptedContext, fixture::remoteId, "bad"));
        CHECK(fixture::acceptedSender(fixture::acceptedContext, fixture::remoteId, ticket));
        CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
        client::service(GetTickCount64());
        client::AcceptedInvitationIntent intent{};
        CHECK(client::take_accepted_invitation(intent) && intent.peerSteamId == fixture::remoteId
              && std::string_view(intent.ticket.data()) == ticket && intent.deadline > GetTickCount64());
        CHECK(!client::take_accepted_invitation(intent) && intent.peerSteamId == 0);
        SetEvent(advance);
        CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
        client::service(GetTickCount64());
        CHECK(!client::take_accepted_invitation(intent));
        SetEvent(advance);
        CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
        client::service(GetTickCount64());
        CHECK(!client::take_accepted_invitation(intent) && fixture::invitation.id == 0);
        SetEvent(advance);
        CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
        client::service(GetTickCount64());
        CHECK(client::connected());
        CHECK(!client::invitation_intents_ready());
        CHECK(!fixture::sender(fixture::senderContext, fixture::remoteId, "+legacy-unavailable"));
        CHECK(!fixture::acceptedSender(fixture::acceptedContext, fixture::remoteId, ticket));
        // A protocol-2 runtime never delivers a ticketless join callback, even
        // when its paired runtime has announced legacy capability.
        const auto beforeLegacy = fixture::incomingConnect;
        SetEvent(advance);
        CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
        client::service(GetTickCount64());
        CHECK(!client::connected() && fixture::acceptedSender == nullptr);
        CHECK(fixture::incomingConnect == beforeLegacy);
    }
    SetEvent(advance);
    client::shutdown();
    server.join();
    CloseHandle(advance); CloseHandle(ready); CloseHandle(pipe);
}

static void v3_case(unsigned variant) {
    namespace client = dawn::core::multiplayer;
    static client::InvitationPreflightObservation priorConnection{};
    constexpr char ticket[] = "0123456789ABCDEF0123456789ABCDEF";
    constexpr char other[] = "ABCDEF0123456789ABCDEF0123456789";
    constexpr char localEpoch[] = "11111111111111111111111111111111";
    constexpr char peerEpoch[] = "22222222222222222222222222222222";
    constexpr char nextEpoch[] = "33333333333333333333333333333333";
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", L"3");
    const HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MultiDawn-0123456789abcdef0123456789abcdef",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 1000, nullptr);
    CHECK(pipe != INVALID_HANDLE_VALUE);
    const HANDLE ready = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    const HANDLE advance = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    CHECK(ready != nullptr && advance != nullptr);
    std::thread server([&] {
        CHECK(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
        CHECK(fixture::receive(pipe) == std::string("HELLO 3 ") + fixture::nonce);
        fixture::send(pipe, std::string("WELCOME 3 76561197960265729 76561197960265730 50656572 1 ") + localEpoch + " 9");
        fixture::send(pipe, std::string("RUNTIME 76561197960265730 ") + peerEpoch + " 2");
        fixture::send(pipe, std::string("ACCEPTED 76561197960265730 ") + ticket + " 60000");
        SetEvent(ready);
        const auto request = fixture::receive(pipe);
        client::protocol::Fields fields;
        CHECK(client::protocol::split(request, fields) && fields.count == 4
            && fields.values[0] == "PREFLIGHT" && client::protocol::ticket(fields.values[1])
            && fields.values[2] == "76561197960265730" && fields.values[3] == ticket);
        const std::string nonce(fields.values[1]);
        auto ok = [&](const std::string& responseNonce, const char* identity = "76561197960265730",
                      const char* responseTicket = "0123456789ABCDEF0123456789ABCDEF", const char* generation = "9",
                      const char* local = "11111111111111111111111111111111",
                      const char* peer = "22222222222222222222222222222222", const char* ttl = "60000") {
            return "PREFLIGHT_OK " + responseNonce + " " + identity + " " + responseTicket + " "
                + generation + " " + local + " " + peer + " " + ttl;
        };
        const auto good = ok(nonce);
        CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
        if (variant == 1) fixture::send(pipe, "PREFLIGHT_NO " + nonce);
        else if (variant == 2) {
            auto wrong = nonce; wrong[0] = wrong[0] == 'A' ? 'B' : 'A';
            fixture::send(pipe, ok(wrong));
        } else if (variant == 3) fixture::send(pipe, ok(nonce, "76561197960265729"));
        else if (variant == 4) fixture::send(pipe, ok(nonce, "76561197960265730", other));
        else if (variant == 5) fixture::send(pipe, ok(nonce, "76561197960265730", ticket, "9", nextEpoch));
        else if (variant == 6) fixture::send(pipe, ok(nonce, "76561197960265730", ticket, "9", localEpoch, nextEpoch));
        else if (variant == 7) fixture::send(pipe, ok(nonce, "76561197960265730", ticket, "10"));
        else if (variant == 8) fixture::send(pipe, ok(nonce, "76561197960265730", ticket, "9", localEpoch, peerEpoch, "60001"));
        else if (variant == 9) {
            Sleep(20);
            fixture::send(pipe, ok(nonce, "76561197960265730", ticket, "9", localEpoch, peerEpoch, "1"));
        } else {
            if (variant == 10) fixture::send(pipe, std::string("RUNTIME 76561197960265730 ") + nextEpoch + " 2");
            if (variant == 11) fixture::send(pipe, "PEER 76561197960265730 50656572 0");
            if (variant == 12) fixture::send(pipe, std::string("REVOKED ") + ticket);
            if (variant == 13) fixture::send(pipe, std::string("INVITEFROM2 76561197960265730 ") + other + " 2B6E6577");
            if (variant == 14) fixture::send(pipe, std::string("ACCEPTED 76561197960265730 ") + other + " 1000");
            fixture::send(pipe, good);
        }
        SetEvent(ready);
        if (variant == 0 || variant == 2 || variant >= 20) {
            CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
            if (variant == 0) {
                const auto secondRequest = fixture::receive(pipe);
                CHECK(client::protocol::split(secondRequest, fields) && fields.count == 4
                    && fields.values[0] == "PREFLIGHT" && fields.values[1] != nonce
                    && fields.values[3] == ticket);
                fixture::send(pipe, good); // Old success cannot satisfy the fresh request.
                fixture::send(pipe, "PREFLIGHT_NO " + std::string(fields.values[1]));
            } else if (variant == 2) fixture::send(pipe, good);
            else {
                if (variant == 20) fixture::send(pipe, std::string("REVOKED ") + ticket);
                if (variant == 21) fixture::send(pipe, std::string("RUNTIME 76561197960265730 ") + nextEpoch + " 2");
                if (variant == 22) fixture::send(pipe, std::string("RUNTIME 76561197960265730 ") + peerEpoch + " 1");
                if (variant == 23) fixture::send(pipe, "PEER 76561197960265730 50656572 0");
                if (variant == 24) fixture::send(pipe, std::string("ACCEPTED 76561197960265730 ") + other + " 1000");
                if (variant == 25) fixture::send(pipe, std::string("INVITEFROM2 76561197960265730 ") + other + " 2B6E6577");
                if (variant == 26) fixture::send(pipe, std::string("REVOKED ") + other);
                fixture::send(pipe, good); // Replay cannot recreate or extend a consumed result.
            }
            SetEvent(ready);
        }
        CHECK(WaitForSingleObject(advance, 5000) == WAIT_OBJECT_0);
        char ignored{}; DWORD got{};
        (void)ReadFile(pipe, &ignored, 1, &got, nullptr);
    });
    CHECK(client::initialize() && client::connected());
    CHECK(!client::validate_invitation_preflight(priorConnection));
    CHECK(!client::request_invitation_preflight(fixture::remoteId, ticket)); // No peer epoch yet.
    CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
    client::service(GetTickCount64());
    client::AcceptedInvitationIntent intent{};
    CHECK(client::take_accepted_invitation(intent));
    CHECK(!client::take_accepted_invitation(intent));
    CHECK(!client::request_invitation_preflight(fixture::localId, ticket));
    CHECK(!client::request_invitation_preflight(fixture::remoteId, "bad"));
    CHECK(client::request_invitation_preflight(fixture::remoteId, ticket));
    CHECK(!client::request_invitation_preflight(fixture::remoteId, ticket));
    if (variant == 15) client::service(GetTickCount64() + 5000);
    SetEvent(advance);
    CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
    client::service(GetTickCount64());
    client::InvitationPreflightObservation observation{}, copied{};
    const bool malformed = variant >= 3 && variant <= 8;
    const bool success = variant == 0 || variant >= 20;
    CHECK(client::connected() != malformed);
    CHECK(client::take_invitation_preflight(observation) == success);
    if (success) {
        CHECK(observation.peerSteamId == fixture::remoteId && observation.pairGeneration == 9
            && observation.companionGeneration != 0 && observation.requestGeneration != 0
            && std::string_view(observation.ticket.data()) == ticket
            && std::string_view(observation.localEpoch.data()) == localEpoch
            && std::string_view(observation.peerEpoch.data()) == peerEpoch
            && client::validate_invitation_preflight(observation));
        copied = observation;
        CHECK(!client::validate_invitation_preflight(priorConnection));
        priorConnection = copied;
        auto unterminated = copied; unterminated.peerEpoch.fill('A');
        CHECK(!client::validate_invitation_preflight(unterminated));
        CHECK(!client::take_invitation_preflight(observation) && observation == client::InvitationPreflightObservation{});
    } else CHECK(observation == client::InvitationPreflightObservation{});
    if (variant == 0 || variant == 2 || variant >= 20) {
        if (variant == 0) {
            CHECK(client::request_invitation_preflight(fixture::remoteId, ticket));
            CHECK(!client::validate_invitation_preflight(copied));
        }
        if (variant == 2) CHECK(!client::request_invitation_preflight(fixture::remoteId, ticket));
        SetEvent(advance);
        CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
        client::service(GetTickCount64());
        CHECK(client::connected());
        CHECK(client::take_invitation_preflight(observation) == (variant == 2));
        if (variant == 2) CHECK(client::validate_invitation_preflight(observation));
        else CHECK(client::validate_invitation_preflight(copied) == (variant == 26));
    }
    SetEvent(advance);
    client::shutdown();
    CHECK(!client::validate_invitation_preflight(copied));
    server.join();
    CloseHandle(advance); CloseHandle(ready); CloseHandle(pipe);
}

static void traced_acceptance_case(bool revoked) {
    namespace client = dawn::core::multiplayer;
    const std::string ticket = "0123456789ABCDEF0123456789ABCDEF";
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", L"3");
    SetEnvironmentVariableW(L"DAWN_ACTIVITY_BINDING_TRACE", L"1");
    const HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MultiDawn-0123456789abcdef0123456789abcdef",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 1000, nullptr);
    const HANDLE ready = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    const HANDLE drained = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    CHECK(pipe != INVALID_HANDLE_VALUE && ready != nullptr && drained != nullptr);
    const auto requestsBefore = fixture::tracedRequests.load(), resultsBefore = fixture::tracedResults.load();
    std::thread server([&] {
        CHECK(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
        CHECK(fixture::receive(pipe) == std::string("HELLO 3 ") + fixture::nonce);
        fixture::send(pipe, "WELCOME 3 76561197960265729 76561197960265730 50656572 1 11111111111111111111111111111111 9");
        fixture::send(pipe, "RUNTIME 76561197960265730 22222222222222222222222222222222 2");
        fixture::send(pipe, "ACCEPTED 76561197960265730 " + ticket + " 60000");
        fixture::send(pipe, "ACCEPTED 76561197960265730 " + ticket + " 60000");
        if (revoked) fixture::send(pipe, "REVOKED " + ticket);
        SetEvent(ready);
        CHECK(WaitForSingleObject(drained, 5000) == WAIT_OBJECT_0);
        DWORD queued{};
        CHECK(PeekNamedPipe(pipe, nullptr, 0, nullptr, &queued, nullptr) && (queued != 0) == !revoked);
        if (!revoked) {
            const auto request = fixture::receive(pipe);
            client::protocol::Fields fields;
            CHECK(client::protocol::split(request, fields) && fields.count == 4
                && fields.values[0] == "PREFLIGHT" && client::protocol::ticket(fields.values[1])
                && fields.values[2] == "76561197960265730" && fields.values[3] == ticket);
            CHECK(PeekNamedPipe(pipe, nullptr, 0, nullptr, &queued, nullptr) && queued == 0);
            fixture::send(pipe, "PREFLIGHT_OK " + std::string(fields.values[1]) + " 76561197960265730 "
                + ticket + " 9 11111111111111111111111111111111 22222222222222222222222222222222 59000");
        }
        SetEvent(ready);
        char ignored{}; DWORD got{};
        (void)ReadFile(pipe, &ignored, 1, &got, nullptr);
    });
    CHECK(client::initialize());
    CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
    client::service(GetTickCount64());
    client::AcceptedInvitationIntent intent{};
    CHECK(client::take_accepted_invitation(intent) == !revoked);
    if (!revoked) CHECK(intent.ticket.data() == ticket && intent.peerSteamId == fixture::remoteId);
    SetEvent(drained);
    CHECK(WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0);
    client::service(GetTickCount64());
    CHECK(client::connected());
    CHECK(fixture::tracedRequests == requestsBefore + (revoked ? 0U : 1U));
    CHECK(fixture::tracedResults == resultsBefore + (revoked ? 0U : 1U));
    client::InvitationPreflightObservation publicResult{};
    CHECK(!client::take_invitation_preflight(publicResult));
    client::shutdown();
    server.join();
    CloseHandle(drained); CloseHandle(ready); CloseHandle(pipe);
    SetEnvironmentVariableW(L"DAWN_ACTIVITY_BINDING_TRACE", nullptr);
}

static void pinned_handshake_case(const wchar_t* pairGeneration, const wchar_t* peerId, bool expected,
                                  std::uint64_t welcomePeer = fixture::remoteId) {
    namespace client = dawn::core::multiplayer;
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", L"3");
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", pairGeneration);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", peerId);
    const HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\MultiDawn-0123456789abcdef0123456789abcdef",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 4096, 1000, nullptr);
    CHECK(pipe != INVALID_HANDLE_VALUE);
    const auto localsBefore = fixture::localPublications.load();
    const auto peersBefore = fixture::peerPublications.load();
    std::thread server([&] {
        CHECK(ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED);
        CHECK(fixture::receive(pipe) == std::string("HELLO 3 ") + fixture::nonce);
        fixture::send(pipe, "WELCOME 3 76561197960265729 " + std::to_string(welcomePeer)
            + " 50656572 1 11111111111111111111111111111111 9");
        char ignored{}; DWORD got{};
        (void)ReadFile(pipe, &ignored, 1, &got, nullptr);
    });
    CHECK(client::initialize() == expected);
    CHECK(client::connected() == expected);
    CHECK(fixture::localPublications.load() == localsBefore + (expected ? 1U : 0U));
    CHECK(fixture::peerPublications.load() == peersBefore + (expected ? 1U : 0U));
    CHECK((fixture::sender != nullptr) == expected);
    if (expected) {
        CHECK(fixture::publishedLocal == dawn::steam::kLocalSteamId);
        CHECK(fixture::peer.steamId == fixture::remoteId && std::string_view(fixture::peer.name.data()) == "Peer");
    }
    client::shutdown();
    server.join();
    CloseHandle(pipe);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", nullptr);
}

static void malformed_pin_cases() {
    namespace client = dawn::core::multiplayer;
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", L"3");
    for (const auto* malformed : {L"0", L"-1", L"+1", L" 9", L"9 ", L"9.0", L"\u0669",
             L"18446744073709551616", L"000000000000000000009"}) {
        SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", malformed);
        SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", L"76561197960265730");
        CHECK(!client::initialize() && !client::connected());
    }
    const std::wstring oversized(500, L'9');
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", oversized.c_str());
    CHECK(!client::initialize() && !client::connected());
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", L"9");
    for (const auto* malformed : {L"0", L"1", L"76561197960265728", L"-76561197960265730",
             L"+76561197960265730", L"76561197960265730 ", L"18446744073709551616"}) {
        SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", malformed);
        CHECK(!client::initialize() && !client::connected());
    }
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", oversized.c_str());
    CHECK(!client::initialize() && !client::connected());
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", nullptr);
    CHECK(!client::initialize() && !client::connected());
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", L"76561197960265730");
    CHECK(!client::initialize() && !client::connected());
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", L"9");
    for (const auto* version : {L"1", L"2"}) {
        SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", version);
        CHECK(!client::initialize() && !client::connected());
    }
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", nullptr);
}

int main() {
    namespace client = dawn::core::multiplayer;
    SetEnvironmentVariableW(L"DAWN_ACTIVITY_BINDING_TRACE", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_ID", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_NONCE", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PID", nullptr);
    SetEnvironmentVariableW(L"DAWN_SESSION_MODE", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PAIR_GENERATION", nullptr);
    SetEnvironmentVariableW(L"DAWN_COMPANION_PEER_ID", nullptr);
    malformed_pin_cases();
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", L"4");
    CHECK(!client::initialize());
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", nullptr);
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
    CHECK(fixture::publishedLocal == fixture::localId);
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
    const std::string ticket = "0123456789ABCDEF0123456789ABCDEF";
    const std::string runtime = "RUNTIME 76561197960265730 " + ticket + " 2";
    v2_case({runtime, "INVITEFROM2 76561197960265730 " + ticket + " 2B6A6F696E"}, false, true);
    v2_case({"INVITEFROM 76561197960265730 2B6C6567616379"}, true, false);
    for (const auto& malformed : std::vector<std::string>{
             "INVITEFROM 76561197960265730 2B6C6567616379",
             "RUNTIME 76561197960265729 " + ticket + " 2",
             "RUNTIME 76561197960265730 " + ticket + " 3",
             "INVITEFROM2 76561197960265729 " + ticket + " 2B6A6F696E",
             "INVITEFROM2 76561197960265730 bad 2B6A6F696E",
             "ACCEPTED 76561197960265729 " + ticket + " 1000",
             "ACCEPTED 76561197960265730 " + ticket + " 60001",
             "REVOKED bad"}) {
        v2_case({runtime, malformed}, true, false);
    }
    for (unsigned variant = 0; variant <= 15; ++variant) v3_case(variant);
    for (unsigned variant = 20; variant <= 26; ++variant) v3_case(variant);
    traced_acceptance_case(false);
    traced_acceptance_case(true);
    pinned_handshake_case(L"9", L"76561197960265730", true);
    pinned_handshake_case(L"8", L"76561197960265730", false);
    pinned_handshake_case(L"9", L"76561197960265729", false);
    pinned_handshake_case(L"18446744073709551615", L"76561197960265730", false);
    for (const auto reserved : {dawn::steam::kLocalSteamId, dawn::steam::kEmbeddedHostSteamId}) {
        const auto peerId = std::to_wstring(reserved);
        pinned_handshake_case(L"9", peerId.c_str(), false, reserved);
    }
    SetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", nullptr);
    std::printf("PASS: %u native companion IPC checks\n", fixture::checks.load());
}
