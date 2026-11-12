#include "companion.h"
#include "companion_protocol.h"
#include "companion_invitation_state.h"

#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstring>

#include "../logging/log.h"
#include "../../steam/runtime/social.h"

namespace dawn::core::multiplayer {
namespace {

SRWLOCK g_lock = SRWLOCK_INIT;
HANDLE g_pipe{INVALID_HANDLE_VALUE};
std::uint64_t g_peer{};
bool g_peerGameRunning{};
std::uint64_t g_lastReceived{};
std::uint32_t g_version{protocol::kVersion};
steam::social::PeerProfile g_profile{};
InvitationIntentState g_invitations{};

void clear_ticketed_invitation() noexcept {
    steam::social::PendingInvitation pending{};
    if (steam::social::pending_invitation(pending) && pending.ticket[0] != '\0') {
        (void)steam::social::revoke_invitation(pending.ticket.data());
    }
}

/** Every operation is cancellable; a stopped launcher cannot block the game indefinitely. */
[[nodiscard]] bool transfer(HANDLE pipe, bool write, void* buffer, DWORD size, DWORD timeout) noexcept {
    const HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (event == nullptr) return false;
    const std::uint64_t deadline = GetTickCount64() + timeout;
    DWORD offset = 0;
    while (offset < size) {
        OVERLAPPED operation{};
        operation.hEvent = event;
        ResetEvent(event);
        DWORD completed = 0;
        auto* bytes = static_cast<unsigned char*>(buffer) + offset;
        BOOL result = write ? WriteFile(pipe, bytes, size - offset, &completed, &operation)
                            : ReadFile(pipe, bytes, size - offset, &completed, &operation);
        if (!result && GetLastError() == ERROR_IO_PENDING) {
            const std::uint64_t now = GetTickCount64();
            if (now < deadline && WaitForSingleObject(event, static_cast<DWORD>(deadline - now)) == WAIT_OBJECT_0) {
                result = GetOverlappedResult(pipe, &operation, &completed, FALSE);
            } else {
                (void)CancelIoEx(pipe, &operation);
                // Cancellation must finish before OVERLAPPED storage goes out of scope.
                (void)GetOverlappedResult(pipe, &operation, &completed, TRUE);
                result = FALSE;
            }
        }
        if (!result || completed == 0 || completed > size - offset) break;
        offset += completed;
    }
    CloseHandle(event);
    return offset == size;
}

[[nodiscard]] bool send_locked(const protocol::Message& message, DWORD timeout = 250) noexcept {
    if (g_pipe == INVALID_HANDLE_VALUE || message.size == 0 || message.size > protocol::kMaximumMessage) return false;
    std::array<char, protocol::kMaximumMessage + 4> frame{};
    for (unsigned index = 0; index < 4; ++index) frame[index] = static_cast<char>((message.size >> (index * 8U)) & 0xFFU);
    std::memcpy(frame.data() + 4, message.bytes.data(), message.size);
    return transfer(g_pipe, true, frame.data(), static_cast<DWORD>(message.size + 4), timeout);
}

[[nodiscard]] bool receive_locked(protocol::Message& message, DWORD timeout) noexcept {
    std::array<unsigned char, 4> header{};
    if (!transfer(g_pipe, false, header.data(), static_cast<DWORD>(header.size()), timeout)) return false;
    std::uint32_t size = 0;
    for (unsigned index = 0; index < 4; ++index) size |= static_cast<std::uint32_t>(header[index]) << (index * 8U);
    if (size == 0 || size > protocol::kMaximumMessage) return false;
    message = {};
    message.size = size;
    return transfer(g_pipe, false, message.bytes.data(), size, timeout);
}

void close_locked() noexcept {
    if (g_pipe != INVALID_HANDLE_VALUE) CloseHandle(g_pipe);
    g_pipe = INVALID_HANDLE_VALUE;
    g_peer = 0;
    g_peerGameRunning = false;
    g_lastReceived = 0;
    g_version = protocol::kVersion;
    g_profile = {};
    g_invitations = {};
}

[[nodiscard]] bool accepted_sender(void*, std::uint64_t from, std::string_view ticket) noexcept {
    if (!protocol::ticket(ticket)) return false;
    protocol::Message message;
    std::array<char, 48> prefix{};
    const int count = std::snprintf(prefix.data(), prefix.size(), "ACCEPT %llu ",
                                    static_cast<unsigned long long>(from));
    if (count <= 0 || static_cast<std::size_t>(count) >= prefix.size()
        || !protocol::append(message, {prefix.data(), static_cast<std::size_t>(count)})
        || !protocol::append(message, ticket)) return false;
    AcquireSRWLockExclusive(&g_lock);
    const bool sent = g_version == protocol::kIntentVersion && from == g_peer
        && g_peerGameRunning && g_invitations.ready() && send_locked(message);
    ReleaseSRWLockExclusive(&g_lock);
    return sent;
}

[[nodiscard]] bool invite_sender(void*, std::uint64_t target, std::string_view connect) noexcept {
    protocol::Message message;
    std::array<char, 48> prefix{};
    const int count = std::snprintf(prefix.data(), prefix.size(), "INVITE %llu ", static_cast<unsigned long long>(target));
    if (count <= 0 || static_cast<std::size_t>(count) >= prefix.size()
        || !protocol::append(message, {prefix.data(), static_cast<std::size_t>(count)})
        || !protocol::append_hex(message, connect)) return false;
    AcquireSRWLockExclusive(&g_lock);
    const bool sent = target == g_peer && g_peerGameRunning
        && (g_version != protocol::kIntentVersion || g_invitations.ready()) && send_locked(message);
    ReleaseSRWLockExclusive(&g_lock);
    return sent;
}

[[nodiscard]] bool apply_peer(const protocol::Fields& fields, bool welcome) noexcept {
    // WELCOME 1 localId peerId nameHex running; PEER peerId nameHex running.
    const std::size_t offset = welcome ? 3 : 1;
    if (fields.count != (welcome ? 6U : 4U)) return false;
    std::uint64_t peerId = 0;
    if (!protocol::decimal(fields.values[offset], peerId) || !protocol::steam_identity(peerId)) return false;
    steam::social::PeerProfile profile{};
    if (!protocol::decode_text(fields.values[offset + 1], profile.name)
        || profile.name[0] == '\0'
        || (fields.values[offset + 2] != "0" && fields.values[offset + 2] != "1")) return false;
    profile.steamId = peerId;
    profile.gameRunning = fields.values[offset + 2] == "1";
    if (!steam::social::set_peer(profile)) return false;
    g_peer = peerId;
    g_peerGameRunning = profile.gameRunning;
    g_profile = profile;
    if (!profile.gameRunning) {
        g_invitations = {};
        clear_ticketed_invitation();
    }
    return true;
}

/** Only bounded IPC fields are logged. Session nonces and invitation content are never logged. */
void report(const char* result) noexcept {
    std::array<char, 112> line{};
    const int count = std::snprintf(line.data(), line.size(), "ev=multiplayer_companion result=%s", result);
    if (count > 0 && static_cast<std::size_t>(count) < line.size())
        log::write(log::Channel::core, log::Level::info, {line.data(), static_cast<std::size_t>(count)});
}

} // namespace

bool initialize() noexcept {
    std::array<wchar_t, 16> mode{};
    const DWORD modeSize = GetEnvironmentVariableW(L"DAWN_SESSION_MODE", mode.data(), static_cast<DWORD>(mode.size()));
    if (modeSize >= mode.size() || (modeSize != 0 && std::wstring_view(mode.data(), modeSize) != L"solo")) {
        report("unsupported_gameplay_mode");
        return false;
    }
    std::array<wchar_t, 4> version{};
    const DWORD versionSize = GetEnvironmentVariableW(L"DAWN_COMPANION_PROTOCOL", version.data(),
                                                       static_cast<DWORD>(version.size()));
    if (versionSize >= version.size()
        || (versionSize != 0 && std::wstring_view(version.data(), versionSize) != L"1"
            && std::wstring_view(version.data(), versionSize) != L"2")) return false;
    const std::uint32_t selectedVersion = versionSize == 1 && version[0] == L'2'
        ? protocol::kIntentVersion : protocol::kVersion;
    std::array<wchar_t, 40> id{}, nonce{};
    std::array<wchar_t, 16> process{};
    const DWORD idSize = GetEnvironmentVariableW(L"DAWN_COMPANION_ID", id.data(), static_cast<DWORD>(id.size()));
    const DWORD nonceSize = GetEnvironmentVariableW(L"DAWN_COMPANION_NONCE", nonce.data(), static_cast<DWORD>(nonce.size()));
    const DWORD processSize = GetEnvironmentVariableW(L"DAWN_COMPANION_PID", process.data(), static_cast<DWORD>(process.size()));
    if (idSize == 0 && nonceSize == 0 && processSize == 0) return true;
    if (idSize >= id.size() || nonceSize >= nonce.size() || processSize == 0 || processSize >= process.size()
        || !protocol::identifier({id.data(), idSize}) || !protocol::identifier({nonce.data(), nonceSize})) return false;
    std::array<char, 16> processText{};
    for (DWORD index = 0; index < processSize; ++index) {
        if (process[index] < L'0' || process[index] > L'9') return false;
        processText[index] = static_cast<char>(process[index]);
    }
    std::uint64_t expectedProcess = 0;
    if (!protocol::decimal({processText.data(), processSize}, expectedProcess) || expectedProcess == 0 || expectedProcess > MAXDWORD) return false;
    std::array<wchar_t, 80> path{};
    const int pathSize = _snwprintf_s(path.data(), path.size(), _TRUNCATE, L"\\\\.\\pipe\\MultiDawn-%ls", id.data());
    if (pathSize <= 0 || !WaitNamedPipeW(path.data(), 3000)) return false;
    AcquireSRWLockExclusive(&g_lock);
    if (g_pipe != INVALID_HANDLE_VALUE) { ReleaseSRWLockExclusive(&g_lock); return false; }
    g_pipe = CreateFileW(path.data(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    ULONG actualProcess = 0;
    bool accepted = g_pipe != INVALID_HANDLE_VALUE && GetNamedPipeServerProcessId(g_pipe, &actualProcess)
                    && actualProcess == expectedProcess;
    g_version = selectedVersion;
    protocol::Message hello;
    accepted = accepted && protocol::append(hello, selectedVersion == 2 ? "HELLO 2 " : "HELLO 1 ");
    for (DWORD index = 0; accepted && index < nonceSize; ++index) {
        const char value = static_cast<char>(nonce[index]);
        accepted = protocol::append(hello, {&value, 1});
    }
    protocol::Message response;
    protocol::Fields fields;
    accepted = accepted && send_locked(hello, 3000) && receive_locked(response, 3000)
               && protocol::split(response.view(), fields) && fields.count == 6
               && fields.values[0] == "WELCOME"
               && fields.values[1] == (selectedVersion == 2 ? "2" : "1");
    std::uint64_t local = 0, remote = 0;
    if (accepted) {
        accepted = protocol::decimal(fields.values[2], local) && protocol::steam_identity(local)
                   && protocol::decimal(fields.values[3], remote) && remote != local;
    }
    if (accepted) accepted = steam::social::set_local_identity(local, steam::social::local_persona_name()) && apply_peer(fields, true);
    if (accepted) g_lastReceived = GetTickCount64();
    else close_locked();
    ReleaseSRWLockExclusive(&g_lock);
    if (accepted) {
        steam::social::set_invite_sender(&invite_sender, nullptr);
        steam::social::set_invite_accepted_sender(selectedVersion == 2 ? &accepted_sender : nullptr, nullptr);
    }
    else { steam::social::reset(); report("handshake_failed"); }
    if (accepted) report("authenticated");
    return accepted;
}

void service(std::uint64_t now) noexcept {
    if (!TryAcquireSRWLockExclusive(&g_lock)) return;
    bool failed = false;
    for (unsigned budget = 0; g_pipe != INVALID_HANDLE_VALUE && budget < 8; ++budget) {
        std::array<unsigned char, 4> peek{};
        DWORD copied = 0, available = 0;
        if (!PeekNamedPipe(g_pipe, peek.data(), static_cast<DWORD>(peek.size()), &copied, &available, nullptr)) { failed = true; break; }
        if (copied < 4) break;
        std::uint32_t size = 0;
        for (unsigned index = 0; index < 4; ++index) size |= static_cast<std::uint32_t>(peek[index]) << (index * 8U);
        if (size == 0 || size > protocol::kMaximumMessage) { failed = true; break; }
        if (available < size + 4) break;
        protocol::Message message;
        protocol::Fields fields;
        if (!receive_locked(message, 50) || !protocol::split(message.view(), fields)) { failed = true; break; }
        g_lastReceived = now;
        if (fields.values[0] == "PING" && fields.count == 1) continue;
        if (fields.values[0] == "PEER") {
            std::uint64_t identity = 0;
            if (fields.count != 4 || !protocol::decimal(fields.values[1], identity) || identity != g_peer || !apply_peer(fields, false)) { failed = true; break; }
            continue;
        }
        if (g_version == protocol::kIntentVersion && fields.values[0] == "RUNTIME") {
            std::uint64_t peer{}, version{};
            bool changed = false;
            if (fields.count != 4 || !protocol::decimal(fields.values[1], peer) || peer != g_peer
                || !protocol::decimal(fields.values[3], version)
                || !g_invitations.runtime(fields.values[2], version, changed)) { failed = true; break; }
            if (changed) clear_ticketed_invitation();
            g_peerGameRunning = version != 0;
            g_profile.gameRunning = g_peerGameRunning;
            if (!steam::social::set_peer(g_profile)) { failed = true; break; }
            continue;
        }
        if (g_version == protocol::kIntentVersion && fields.values[0] == "INVITEFROM2") {
            std::uint64_t sender{};
            std::array<char, steam::social::kConnectCapacity> connect{};
            if (fields.count != 4 || !g_peerGameRunning || !g_invitations.ready()
                || !protocol::decimal(fields.values[1], sender) || sender != g_peer
                || !protocol::ticket(fields.values[2]) || !protocol::decode_text(fields.values[3], connect)
                || !steam::social::receive_invitation(sender, connect.data(), fields.values[2])) { failed = true; break; }
            continue;
        }
        if (g_version == protocol::kIntentVersion && fields.values[0] == "ACCEPTED") {
            std::uint64_t peer{}, ttl{};
            if (fields.count != 4 || !g_peerGameRunning || !protocol::decimal(fields.values[1], peer)
                || peer != g_peer || !protocol::decimal(fields.values[3], ttl)
                || !g_invitations.accepted(peer, fields.values[2], ttl, now)) { failed = true; break; }
            continue;
        }
        if (g_version == protocol::kIntentVersion && fields.values[0] == "REVOKED") {
            if (fields.count != 2 || !protocol::ticket(fields.values[1])) { failed = true; break; }
            g_invitations.revoke(fields.values[1]);
            (void)steam::social::revoke_invitation(fields.values[1]);
            continue;
        }
        if (g_version == protocol::kVersion && fields.values[0] == "INVITEFROM" && fields.count == 3) {
            std::uint64_t sender = 0;
            std::array<char, steam::social::kConnectCapacity> connect{};
            if (!g_peerGameRunning || !protocol::decimal(fields.values[1], sender) || sender != g_peer
                || !protocol::decode_text(fields.values[2], connect)
                || !steam::social::receive_invitation(sender, connect.data())) { failed = true; break; }
            continue;
        }
        failed = true;
        break;
    }
    g_invitations.expire(now);
    if (g_pipe != INVALID_HANDLE_VALUE && now > g_lastReceived && now - g_lastReceived > 15000) failed = true;
    if (failed) close_locked();
    ReleaseSRWLockExclusive(&g_lock);
    if (failed) {
        steam::social::set_invite_sender(nullptr, nullptr);
        steam::social::set_invite_accepted_sender(nullptr, nullptr);
        steam::social::clear_peer(); report("disconnected");
    }
}

void shutdown() noexcept {
    steam::social::set_invite_sender(nullptr, nullptr);
    steam::social::set_invite_accepted_sender(nullptr, nullptr);
    AcquireSRWLockExclusive(&g_lock);
    close_locked();
    ReleaseSRWLockExclusive(&g_lock);
    steam::social::reset();
}

bool connected() noexcept {
    AcquireSRWLockShared(&g_lock);
    const bool result = g_pipe != INVALID_HANDLE_VALUE;
    ReleaseSRWLockShared(&g_lock);
    return result;
}

bool take_accepted_invitation(AcceptedInvitationIntent& output) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    const bool found = g_pipe != INVALID_HANDLE_VALUE && g_invitations.take(GetTickCount64(), output);
    if (!found) output = {};
    ReleaseSRWLockExclusive(&g_lock);
    return found;
}

bool invitation_intents_ready() noexcept {
    AcquireSRWLockShared(&g_lock);
    const bool ready = g_pipe != INVALID_HANDLE_VALUE && g_version == protocol::kIntentVersion
        && g_peerGameRunning && g_invitations.ready();
    ReleaseSRWLockShared(&g_lock);
    return ready;
}

} // namespace dawn::core::multiplayer
