#include "address_resolution_host.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <limits>

#include "../../../core/settings/settings.h"
#include "../../../middleware/bap/address_resolution.h"
#include "../../../middleware/crypto/legacy_des_cbc.h"
#include "../../../middleware/crypto/random_bytes.h"
#include "../../../middleware/encoding/byte_order.h"
#include "../../../middleware/gameplay/descriptor/join_descriptor.h"
#include "../../../middleware/gameplay/routed_datagram.h"
#include "../gameplay_log.h"
#include "replay_window.h"

namespace dawn::server::gameplay::resolution {
namespace {
namespace codec = middleware::bap::address_resolution;
namespace packet = middleware::gameplay::routed_datagram;
namespace random = middleware::crypto::random;
namespace encoding = middleware::encoding;

constexpr std::size_t kCapacity = 16;
constexpr std::uint64_t kUnboundReplacementAgeMs = 30'000;

struct Context {
    state::activity::AuthenticationKey owner{};
    packet::DirectionKeys inbound{}, outbound{};
    codec::NetAddr requested{};
    state::gameplay::Endpoint peer{};
    ReplayWindow replay{};
    std::uint64_t nextSend{}, heard{}, createdAt{};
    std::uint32_t tag{};
    bool occupied{}, bound{}, sendExhausted{};
};

SRWLOCK g_lock = SRWLOCK_INIT;
std::array<Context, kCapacity> g_contexts{};
Statistics g_statistics{};
std::uint64_t g_heardClock{};

class Lock final {
public:
    Lock() noexcept { AcquireSRWLockExclusive(&g_lock); }
    ~Lock() noexcept { ReleaseSRWLockExclusive(&g_lock); }
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
};

class Wipe final {
public:
    Wipe(void* bytes, std::size_t size) noexcept : bytes_(bytes), size_(size) {}
    ~Wipe() noexcept { SecureZeroMemory(bytes_, size_); }
    Wipe(const Wipe&) = delete;
    Wipe& operator=(const Wipe&) = delete;
private:
    void* bytes_;
    std::size_t size_;
};

[[nodiscard]] bool same_endpoint(const state::gameplay::Endpoint& a,
                                 const state::gameplay::Endpoint& b) noexcept {
    return a.address == b.address && a.port == b.port;
}

[[nodiscard]] std::uint32_t ipv4(const std::array<unsigned char, 4>& bytes) noexcept {
    std::uint32_t result = 0;
    for (const auto byte : bytes) { result = (result << 8U) | byte; }
    return result;
}

[[nodiscard]] std::uint64_t counter(const packet::Iv& bytes) noexcept {
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        result |= std::to_integer<std::uint64_t>(bytes[i]) << (i * 8U);
    }
    return result;
}

[[nodiscard]] packet::Iv counter_bytes(std::uint64_t value) noexcept {
    packet::Iv result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<std::byte>((value >> (i * 8U)) & 0xFFU);
    }
    return result;
}

[[nodiscard]] bool generate_cipher(std::array<std::byte, 8>& key) noexcept {
    std::array<std::byte, 8> zero{}, encrypted{};
    const Wipe clear(encrypted.data(), encrypted.size());
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (!random::fill(key)) { return false; }
        if (middleware::crypto::legacy_des::encrypt(key, zero, zero, encrypted)) { return true; }
    }
    return false;
}

[[nodiscard]] Context* by_tag(std::uint32_t tag) noexcept {
    for (auto& context : g_contexts) {
        if (context.occupied && context.tag == tag) { return &context; }
    }
    return nullptr;
}

[[nodiscard]] bool bound_source(const state::gameplay::Endpoint& source) noexcept {
    for (const auto& context : g_contexts) {
        if (context.occupied && context.bound && same_endpoint(context.peer, source)) { return true; }
    }
    return false;
}
} // namespace

bool enabled() noexcept {
    static const bool value = []() noexcept {
        std::array<wchar_t, 2> text{};
        return GetEnvironmentVariableW(L"DAWN_NATIVE_ADDRESS_RESOLUTION", text.data(),
                                       static_cast<DWORD>(text.size())) == 1 && text[0] == L'1';
    }();
    return value;
}

bool resolve_address(state::activity::AuthenticationKey owner,
                       std::span<const std::byte> request,
                       std::span<std::byte> response, std::size_t& written) noexcept {
    written = 0;
    if (!enabled() || !static_cast<bool>(owner) || response.size() < codec::kIpv4ResponseSize) { return false; }
    codec::Request parsed{};
    if (!codec::parse_request(request, parsed) || parsed.capability != 16 || parsed.kind != 1
        || parsed.address.back() != std::byte{0}) { return false; }
    const auto& settings = core::settings::get().server.gameplay;
    if (settings.topology != core::settings::server::gameplay::Topology::embedded
        || settings.port == 0 || ipv4(settings.advertisedAddress) == 0
        || ipv4(settings.transportAddress) == 0) { return false; }
    codec::NetAddr expected{};
    middleware::gameplay::descriptor::write_net_addr(ipv4(settings.advertisedAddress), settings.port, expected);
    // Only the documented 41-byte direct address body participates. Preserve all
    // 86 request bytes in the reply so native self/address matching remains exact.
    if (!std::equal(expected.begin(), expected.begin() + 41, parsed.address.begin())) { return false; }

    Context candidate{};
    const Wipe wipeCandidate(&candidate, sizeof candidate);
    codec::Response body{};
    const Wipe wipeBody(&body, sizeof body);
    std::array<std::byte, codec::kIpv4ResponseSize> encoded{};
    const Wipe wipeEncoded(encoded.data(), encoded.size());
    if (!generate_cipher(candidate.inbound.cipher) || !generate_cipher(candidate.outbound.cipher)
        || !random::fill(candidate.inbound.mac) || !random::fill(body.material.b)
        || !random::fill(body.material.e)) { return false; }
    candidate.outbound.mac = candidate.inbound.mac;
    body.material.b.back() &= std::byte{0x7F};
    body.material.e.back() &= std::byte{0x7F};
    std::copy(candidate.inbound.cipher.begin(), candidate.inbound.cipher.end(), body.material.a.begin());
    std::copy(candidate.outbound.cipher.begin(), candidate.outbound.cipher.end(), body.material.d.begin());
    body.material.f = candidate.inbound.mac;
    body.address = parsed.address;
    body.valueC = parsed.capability;
    body.family = codec::IpFamily::ipv4;
    body.port = settings.port;
    for (std::size_t i = 0; i < 4; ++i) { body.ip[i] = static_cast<std::byte>(settings.transportAddress[i]); }
    candidate.owner = owner;
    candidate.requested = parsed.address;
    candidate.replay.floor = counter(body.material.b) + 1;
    candidate.nextSend = counter(body.material.e);
    candidate.createdAt = GetTickCount64();

    const Lock lock;
    Context* slot = nullptr;
    for (auto& context : g_contexts) {
        if (!context.occupied) { slot = &context; break; }
        if (!context.bound && candidate.createdAt - context.createdAt >= kUnboundReplacementAgeMs
            && (slot == nullptr || context.createdAt < slot->createdAt)) { slot = &context; }
    }
    if (slot == nullptr) { return false; }
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        std::array<std::byte, 4> randomTag{};
        if (!random::fill(randomTag)) { return false; }
        candidate.tag = encoding::read_u32_be(randomTag);
        if (candidate.tag != 0 && by_tag(candidate.tag) == nullptr) { break; }
        candidate.tag = 0;
    }
    if (candidate.tag == 0) { return false; }
    body.routeTag = candidate.tag;
    std::size_t size = 0;
    if (!codec::encode_response(body, encoded, size)) { return false; }
    candidate.occupied = true;
    SecureZeroMemory(slot, sizeof *slot);
    *slot = candidate;
    ++g_statistics.created;
    std::copy_n(encoded.begin(), size, response.begin());
    written = size;
    report(core::log::Level::info,
           "ev=gameplay stage=address_resolution result=created connection=%u route=%u capability=%u",
           owner.connection.connectionId, candidate.tag, parsed.capability);
    return true;
}

PacketResult unwrap(const state::gameplay::Endpoint& source,
                     std::span<const std::byte> datagram,
                     std::span<std::byte> plaintext, std::size_t& written) noexcept {
    written = 0;
    if (!enabled()) { return PacketResult::notRouted; }
    const Lock lock;
    Context* context = datagram.size() >= 4 ? by_tag(encoding::read_u32_be(datagram.first<4>())) : nullptr;
    if (context == nullptr) {
        return bound_source(source) ? PacketResult::rejected : PacketResult::notRouted;
    }
    if ((context->bound && !same_endpoint(context->peer, source)) || source.address == 0 || source.port == 0) {
        ++g_statistics.rejected;
        return PacketResult::rejected;
    }
    std::array<std::byte, packet::kMaximumPayload> staged{};
    const Wipe wipe(staged.data(), staged.size());
    packet::Iv iv{};
    std::size_t size = 0;
    if (!packet::open(context->inbound, context->tag, datagram, staged, iv, size)
        || size > plaintext.size()) {
        ++g_statistics.rejected;
        return PacketResult::rejected;
    }
    auto replay = context->replay;
    if (!replay.accept(counter(iv))) {
        ++g_statistics.rejected;
        ++g_statistics.replayed;
        return PacketResult::rejected;
    }
    const bool first = !context->bound;
    context->replay = replay;
    context->peer = source;
    context->bound = true;
    context->heard = ++g_heardClock;
    std::copy_n(staged.begin(), size, plaintext.begin());
    written = size;
    ++g_statistics.opened;
    if (first) {
        report(core::log::Level::info,
               "ev=gameplay stage=resolved_route result=authenticated route=%u peer=0x%08X:%u",
               context->tag, source.address, static_cast<unsigned>(source.port));
    }
    return PacketResult::complete;
}

PacketResult wrap(const state::gameplay::Endpoint& destination,
                   std::span<const std::byte> plaintext,
                   std::span<std::byte> datagram, std::size_t& written) noexcept {
    written = 0;
    if (!enabled()) { return PacketResult::notRouted; }
    const Lock lock;
    Context* selected = nullptr;
    for (auto& context : g_contexts) {
        if (context.occupied && context.bound && same_endpoint(context.peer, destination)
            && (selected == nullptr || context.heard > selected->heard)) { selected = &context; }
    }
    if (selected == nullptr) { return PacketResult::notRouted; }
    if (selected->sendExhausted) { return PacketResult::rejected; }
    const auto iv = counter_bytes(selected->nextSend);
    if (selected->nextSend == (std::numeric_limits<std::uint64_t>::max)()) { selected->sendExhausted = true; }
    else { ++selected->nextSend; }
    // Consume the IV even if encryption or the later OS send fails.
    if (!packet::seal(selected->outbound, selected->tag, iv, plaintext, datagram, written)) {
        return PacketResult::rejected;
    }
    ++g_statistics.wrapped;
    return PacketResult::complete;
}

void release_owner(state::activity::AuthenticationKey owner) noexcept {
    if (!static_cast<bool>(owner)) { return; }
    const Lock lock;
    for (auto& context : g_contexts) {
        if (context.occupied && context.owner == owner) { SecureZeroMemory(&context, sizeof context); }
    }
}

void reset() noexcept {
    const Lock lock;
    SecureZeroMemory(g_contexts.data(), sizeof g_contexts);
    g_statistics = {};
    g_heardClock = 0;
}

Statistics snapshot() noexcept {
    const Lock lock;
    auto result = g_statistics;
    for (const auto& context : g_contexts) { result.live += context.occupied ? 1U : 0U; }
    return result;
}
} // namespace dawn::server::gameplay::resolution
