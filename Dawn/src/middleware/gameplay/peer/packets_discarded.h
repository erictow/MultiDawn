#pragma once

#include <cstdint>

#include "../../encoding/bit_reader.h"
#include "reliable_assembly.h"

namespace dawn::middleware::gameplay::peer::packets_discarded {

inline constexpr std::uint8_t kMessageId = 4;
inline constexpr std::uint32_t kDeclaredSize = 4;
inline constexpr std::size_t kHeaderBits = 24;
inline constexpr std::size_t kBodyBits = 5;

/**
 * Build 86657 encodes one unsigned five-bit increment without bias. The native consumer
 * adds it to the receiver's discarded-packet counter; it is neither an enum nor a total.
 * Only the exact logical message or its zero-padded byte-rounded form is accepted.
 * Failure leaves output unchanged. Bytes outside bitCount are never interpreted.
 */
[[nodiscard]] inline bool decode(const AssembledMessage& message, std::uint32_t& output) noexcept {
    constexpr auto logicalBits = kHeaderBits + kBodyBits;
    constexpr auto roundedBits = 32U;
    if (message.id != kMessageId || message.declaredSize != kDeclaredSize
        || message.bodyBitOffset != kHeaderBits
        || (message.bitCount != logicalBits && message.bitCount != roundedBits)) return false;

    encoding::bits::Reader reader({message.bytes.data(), roundedBits / 8U});
    std::uint64_t id{}, declared{}, count{}, padding{};
    if (!reader.read(6, id) || id != kMessageId
        || !reader.read(18, declared) || declared != kDeclaredSize
        || !reader.read(static_cast<std::uint8_t>(kBodyBits), count)
        || (message.bitCount == roundedBits && (!reader.read(3, padding) || padding != 0))) return false;
    output = static_cast<std::uint32_t>(count);
    return true;
}

} // namespace dawn::middleware::gameplay::peer::packets_discarded
