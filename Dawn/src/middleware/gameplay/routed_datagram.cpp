#include "routed_datagram.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstring>

#include "../crypto/hmac.h"
#include "../crypto/legacy_des_cbc.h"

namespace dawn::middleware::gameplay::routed_datagram {
namespace {

template <std::size_t Size>
struct WipedBytes final {
    std::array<std::byte, Size> bytes{};
    ~WipedBytes() noexcept { SecureZeroMemory(bytes.data(), bytes.size()); }
};

struct WipedDigest final {
    crypto::hmac::Digest value{};
    ~WipedDigest() noexcept { SecureZeroMemory(&value, sizeof(value)); }
};

[[nodiscard]] bool authenticate(const DirectionKeys& keys,
                                 std::span<const std::byte> covered,
                                 WipedDigest& digest) noexcept {
    return crypto::hmac::authenticate(crypto::hmac::Algorithm::sha1, keys.mac,
                                      covered, {}, digest.value)
           && digest.value.size == 20;
}

[[nodiscard]] bool same_tag(std::span<const std::byte, kTagSize> received,
                            const crypto::hmac::Digest& calculated) noexcept {
    // Volatile accumulation prevents an early-exit comparison from replacing
    // this fixed ten-byte authentication check.
    volatile unsigned char difference = 0;
    for (std::size_t index = 0; index < kTagSize; ++index) {
        difference = static_cast<unsigned char>(difference
            | std::to_integer<unsigned char>(received[index] ^ calculated.bytes[index]));
    }
    return difference == 0;
}

void write_route_tag(std::span<std::byte> output, std::uint32_t tag) noexcept {
    for (unsigned index = 0; index < 4; ++index) {
        output[index] = static_cast<std::byte>((tag >> ((3U - index) * 8U)) & 0xFFU);
    }
}

[[nodiscard]] std::uint32_t read_route_tag(std::span<const std::byte> input) noexcept {
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
        value = (value << 8U) | std::to_integer<std::uint32_t>(input[index]);
    }
    return value;
}

} // namespace

bool seal(const DirectionKeys& keys, std::uint32_t routeTag,
           std::span<const std::byte> iv, std::span<const std::byte> payload,
           std::span<std::byte> output, std::size_t& written) noexcept {
    written = 0;
    if (iv.size() != kIvSize || payload.size() > kMaximumPayload) {
        return false;
    }
    const std::size_t padding = kBlockSize - payload.size() % kBlockSize;
    const std::size_t cipherSize = payload.size() + padding;
    const std::size_t coveredSize = kHeaderSize + cipherSize;
    const std::size_t total = coveredSize + kTagSize;
    if (output.size() < total) {
        return false;
    }

    WipedBytes<kMaximumDatagram> staged{};
    auto packet = std::span(staged.bytes).first(total);
    write_route_tag(packet, routeTag);
    std::copy(iv.begin(), iv.end(), packet.begin() + 4);
    auto ciphertext = packet.subspan(kHeaderSize, cipherSize);
    std::copy(payload.begin(), payload.end(), ciphertext.begin());
    std::fill(ciphertext.begin() + payload.size(), ciphertext.end(),
              static_cast<std::byte>(padding));
    WipedDigest digest{};
    if (!crypto::legacy_des::encrypt(keys.cipher, iv, ciphertext, ciphertext)
        || !authenticate(keys, packet.first(coveredSize), digest)) {
        return false;
    }
    std::copy_n(digest.value.bytes.begin(), kTagSize, packet.begin() + coveredSize);
    std::memcpy(output.data(), packet.data(), total);
    written = total;
    return true;
}

bool open(const DirectionKeys& keys, std::uint32_t expectedRouteTag,
           std::span<const std::byte> datagram, std::span<std::byte> output,
           Iv& iv, std::size_t& written) noexcept {
    written = 0;
    if (datagram.size() < kMinimumDatagram || datagram.size() > kMaximumDatagram
        || read_route_tag(datagram) != expectedRouteTag) {
        return false;
    }
    const std::size_t cipherSize = datagram.size() - kHeaderSize - kTagSize;
    if (cipherSize % kBlockSize != 0) {
        return false;
    }
    const std::size_t coveredSize = datagram.size() - kTagSize;
    WipedDigest digest{};
    if (!authenticate(keys, datagram.first(coveredSize), digest)
        || !same_tag(datagram.last<kTagSize>(), digest.value)) {
        return false;
    }

    WipedBytes<kMaximumCiphertext> plaintext{};
    const auto packetIv = datagram.subspan(4, kIvSize);
    if (!crypto::legacy_des::decrypt(keys.cipher, packetIv,
                                     datagram.subspan(kHeaderSize, cipherSize),
                                     plaintext.bytes)) {
        return false;
    }
    const unsigned padding = std::to_integer<unsigned>(plaintext.bytes[cipherSize - 1]);
    if (padding == 0 || padding > kBlockSize) {
        return false;
    }
    unsigned difference = 0;
    for (std::size_t index = cipherSize - padding; index < cipherSize; ++index) {
        difference |= std::to_integer<unsigned>(plaintext.bytes[index]) ^ padding;
    }
    const std::size_t payloadSize = cipherSize - padding;
    if (difference != 0 || output.size() < payloadSize) {
        return false;
    }

    // Capture authenticated metadata before committing possibly overlapping output.
    Iv receivedIv{};
    std::copy(packetIv.begin(), packetIv.end(), receivedIv.begin());
    if (payloadSize != 0) {
        std::memcpy(output.data(), plaintext.bytes.data(), payloadSize);
    }
    iv = receivedIv;
    written = payloadSize;
    return true;
}

} // namespace dawn::middleware::gameplay::routed_datagram
