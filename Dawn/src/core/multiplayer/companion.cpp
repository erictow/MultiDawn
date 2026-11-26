#include "companion.h"
#include "companion_protocol.h"
#include "companion_invitation_state.h"

#include <Windows.h>
#include <bcrypt.h>
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
InvitationPreflightState g_preflight{};
std::array<char, 33> g_localEpoch{};
std::uint64_t g_pairGeneration{}, g_companionGeneration{};
// These counters survive teardown; stale copied observations cannot revive after slot reuse.
std::uint64_t g_companionGenerationClock{}, g_requestGenerationClock{};

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
    g_preflight = {};
    g_localEpoch = {};
    g_pairGeneration = g_companionGeneration = 0;
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
    const bool sent = g_version >= protocol::kIntentVersion && from == g_peer
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
        && (g_version < protocol::kIntentVersion || g_invitations.ready()) && send_locked(message);
    ReleaseSRWLockExclusive(&g_lock);
    return sent;
}

[[nodiscard]] bool apply_peer(const protocol::Fields& fields, bool welcome) noexcept {
    // WELCOME 1 localId peerId nameHex running; PEER peerId nameHex running.
    const std::size_t offset = welcome ? 3 : 1;
    if (fields.count != (welcome ? (g_version == protocol::kPreflightVersion ? 8U : 6U) : 4U)) return false;
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
        g_preflight = {};
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

/** Optional child-process pins use bounded positive decimal fields; empty is not absent. */
[[nodiscard]] bool read_pair_pin(const wchar_t* name, bool& present, std::uint64_t& output) noexcept {
    std::array<wchar_t, 22> text{};
    SetLastError(ERROR_SUCCESS);
    const DWORD size = GetEnvironmentVariableW(name, text.data(), static_cast<DWORD>(text.size()));
    present = size != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    output = 0;
    if (!present) return true;
    if (size == 0 || size > 20 || size >= text.size()) return false;
    std::array<char, 20> decimal{};
    for (DWORD index = 0; index < size; ++index) {
        if (text[index] < L'0' || text[index] > L'9') return false;
        decimal[index] = static_cast<char>(text[index]);
    }
    return protocol::decimal({decimal.data(), size}, output) && output != 0;
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
            && std::wstring_view(version.data(), versionSize) != L"2"
            && std::wstring_view(version.data(), versionSize) != L"3")) return false;
    const std::uint32_t selectedVersion = versionSize == 1
        ? static_cast<std::uint32_t>(version[0] - L'0') : protocol::kVersion;
    bool hasPairGeneration{}, hasPeerId{};
    std::uint64_t expectedPairGeneration{}, expectedPeerId{};
    if (!read_pair_pin(L"DAWN_COMPANION_PAIR_GENERATION", hasPairGeneration, expectedPairGeneration)
        || !read_pair_pin(L"DAWN_COMPANION_PEER_ID", hasPeerId, expectedPeerId)
        || hasPairGeneration != hasPeerId
        || (hasPairGeneration && (selectedVersion != protocol::kPreflightVersion
            || !protocol::steam_identity(expectedPeerId)))) return false;
    std::array<wchar_t, 40> id{}, nonce{};
    std::array<wchar_t, 16> process{};
    const DWORD idSize = GetEnvironmentVariableW(L"DAWN_COMPANION_ID", id.data(), static_cast<DWORD>(id.size()));
    const DWORD nonceSize = GetEnvironmentVariableW(L"DAWN_COMPANION_NONCE", nonce.data(), static_cast<DWORD>(nonce.size()));
    const DWORD processSize = GetEnvironmentVariableW(L"DAWN_COMPANION_PID", process.data(), static_cast<DWORD>(process.size()));
    if (idSize == 0 && nonceSize == 0 && processSize == 0) return !hasPairGeneration;
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
    const std::string_view versionText = selectedVersion == protocol::kPreflightVersion ? "3"
        : selectedVersion == protocol::kIntentVersion ? "2" : "1";
    accepted = accepted && protocol::append(hello, "HELLO ") && protocol::append(hello, versionText)
        && protocol::append(hello, " ");
    for (DWORD index = 0; accepted && index < nonceSize; ++index) {
        const char value = static_cast<char>(nonce[index]);
        accepted = protocol::append(hello, {&value, 1});
    }
    protocol::Message response;
    protocol::Fields fields;
    accepted = accepted && send_locked(hello, 3000) && receive_locked(response, 3000)
               && protocol::split(response.view(), fields)
               && fields.count == (selectedVersion == protocol::kPreflightVersion ? 8U : 6U)
               && fields.values[0] == "WELCOME"
               && fields.values[1] == versionText;
    std::uint64_t local = 0, remote = 0;
    if (accepted) {
        accepted = protocol::decimal(fields.values[2], local) && protocol::steam_identity(local)
                   && protocol::decimal(fields.values[3], remote) && remote != local;
    }
    if (accepted && selectedVersion == protocol::kPreflightVersion) {
        accepted = protocol::ticket(fields.values[6])
            && protocol::decimal(fields.values[7], g_pairGeneration) && g_pairGeneration != 0;
        if (accepted) std::memcpy(g_localEpoch.data(), fields.values[6].data(), fields.values[6].size());
    }
    // A child started for an earlier pair must not publish identities after reconnect.
    if (accepted && hasPairGeneration)
        accepted = g_pairGeneration == expectedPairGeneration && remote == expectedPeerId;
    if (accepted) {
        accepted = g_companionGenerationClock != UINT64_MAX;
        if (accepted) g_companionGeneration = ++g_companionGenerationClock;
    }
    if (accepted) accepted = steam::social::set_local_identity(local, steam::social::local_persona_name()) && apply_peer(fields, true);
    if (accepted) g_lastReceived = GetTickCount64();
    else close_locked();
    ReleaseSRWLockExclusive(&g_lock);
    if (accepted) {
        steam::social::set_invite_sender(&invite_sender, nullptr);
        steam::social::set_invite_accepted_sender(selectedVersion >= protocol::kIntentVersion ? &accepted_sender : nullptr, nullptr);
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
        if (g_version >= protocol::kIntentVersion && fields.values[0] == "RUNTIME") {
            std::uint64_t peer{}, version{};
            bool changed = false;
            if (fields.count != 4 || !protocol::decimal(fields.values[1], peer) || peer != g_peer
                || !protocol::decimal(fields.values[3], version)
                || version > (g_version == protocol::kPreflightVersion ? 3U : 2U)
                || !g_invitations.runtime(fields.values[2], version > 2 ? 2 : version, changed)) { failed = true; break; }
            if (changed) { clear_ticketed_invitation(); g_preflight = {}; }
            g_peerGameRunning = version != 0;
            g_profile.gameRunning = g_peerGameRunning;
            if (!steam::social::set_peer(g_profile)) { failed = true; break; }
            continue;
        }
        if (g_version >= protocol::kIntentVersion && fields.values[0] == "INVITEFROM2") {
            std::uint64_t sender{};
            std::array<char, steam::social::kConnectCapacity> connect{};
            if (fields.count != 4 || !g_peerGameRunning || !g_invitations.ready()
                || !protocol::decimal(fields.values[1], sender) || sender != g_peer
                || !protocol::ticket(fields.values[2]) || !protocol::decode_text(fields.values[3], connect)
                || !steam::social::receive_invitation(sender, connect.data(), fields.values[2])) { failed = true; break; }
            g_preflight.replace(fields.values[2]);
            continue;
        }
        if (g_version >= protocol::kIntentVersion && fields.values[0] == "ACCEPTED") {
            std::uint64_t peer{}, ttl{};
            if (fields.count != 4 || !g_peerGameRunning || !protocol::decimal(fields.values[1], peer)
                || peer != g_peer || !protocol::decimal(fields.values[3], ttl)
                || !g_invitations.accepted(peer, fields.values[2], ttl, now)) { failed = true; break; }
            g_preflight.replace(fields.values[2]);
            continue;
        }
        if (g_version >= protocol::kIntentVersion && fields.values[0] == "REVOKED") {
            if (fields.count != 2 || !protocol::ticket(fields.values[1])) { failed = true; break; }
            g_invitations.revoke(fields.values[1]);
            g_preflight.revoke(fields.values[1]);
            (void)steam::social::revoke_invitation(fields.values[1]);
            continue;
        }
        if (g_version == protocol::kPreflightVersion
            && (fields.values[0] == "PREFLIGHT_OK" || fields.values[0] == "PREFLIGHT_NO")) {
            if (!g_preflight.response(fields, now)) { failed = true; break; }
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
    g_preflight.expire(now);
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
    const bool ready = g_pipe != INVALID_HANDLE_VALUE && g_version >= protocol::kIntentVersion
        && g_peerGameRunning && g_invitations.ready();
    ReleaseSRWLockShared(&g_lock);
    return ready;
}

bool request_invitation_preflight(std::uint64_t peer, std::string_view ticket) noexcept {
    if (!protocol::steam_identity(peer) || !protocol::ticket(ticket)) return false;
    std::array<unsigned char, 16> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return false;
    constexpr char digits[] = "0123456789ABCDEF";
    std::array<char, 33> nonce{};
    for (std::size_t index = 0; index < random.size(); ++index) {
        nonce[index * 2] = digits[random[index] >> 4U];
        nonce[index * 2 + 1] = digits[random[index] & 15U];
    }
    protocol::Message request;
    std::array<char, 32> peerText{};
    const int count = std::snprintf(peerText.data(), peerText.size(), "%llu", static_cast<unsigned long long>(peer));
    if (count <= 0 || static_cast<std::size_t>(count) >= peerText.size()
        || !protocol::append(request, "PREFLIGHT ") || !protocol::append(request, nonce.data())
        || !protocol::append(request, " ") || !protocol::append(request, {peerText.data(), static_cast<std::size_t>(count)})
        || !protocol::append(request, " ") || !protocol::append(request, ticket)) return false;
    AcquireSRWLockExclusive(&g_lock);
    bool started = g_pipe != INVALID_HANDLE_VALUE && g_version == protocol::kPreflightVersion
        && g_peerGameRunning && peer == g_peer && g_invitations.ready()
        && g_requestGenerationClock != UINT64_MAX
        && g_preflight.begin(nonce.data(), peer, ticket, g_localEpoch.data(), g_invitations.epoch(),
                             g_pairGeneration, g_companionGeneration, g_requestGenerationClock + 1, GetTickCount64());
    if (started) {
        ++g_requestGenerationClock;
        if (!send_locked(request)) { g_preflight = {}; started = false; }
    }
    ReleaseSRWLockExclusive(&g_lock);
    return started;
}

bool take_invitation_preflight(InvitationPreflightObservation& output) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    const bool found = g_pipe != INVALID_HANDLE_VALUE && g_version == protocol::kPreflightVersion
        && g_peerGameRunning && g_invitations.ready() && g_preflight.take(GetTickCount64(), output);
    if (!found) output = {};
    ReleaseSRWLockExclusive(&g_lock);
    return found;
}

bool validate_invitation_preflight(const InvitationPreflightObservation& observed) noexcept {
    AcquireSRWLockExclusive(&g_lock);
    const bool valid = g_pipe != INVALID_HANDLE_VALUE && g_version == protocol::kPreflightVersion
        && g_peerGameRunning && g_invitations.ready()
        && observed.companionGeneration == g_companionGeneration && observed.pairGeneration == g_pairGeneration
        && observed.localEpoch == g_localEpoch
        && std::string_view(observed.peerEpoch.data(), 32) == g_invitations.epoch()
        && g_preflight.validate(GetTickCount64(), observed);
    ReleaseSRWLockExclusive(&g_lock);
    return valid;
}

} // namespace dawn::core::multiplayer
