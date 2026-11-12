#include "../src/middleware/gameplay/peer/packets_discarded.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>

namespace wire = dawn::middleware::gameplay::peer;
namespace discarded = wire::packets_discarded;
namespace {
unsigned checks{};
void check(bool condition, int line) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "FAIL packets discarded line %d\n", line); std::exit(1); }
}
#define CHECK(condition) check((condition), __LINE__)

wire::AssembledMessage golden(unsigned count, std::size_t bits = 32) {
    wire::AssembledMessage message{};
    // Independently specified MSB-first header: ID 4 in six bits and size 4 in eighteen.
    message.bytes[0] = std::byte{0x10};
    message.bytes[1] = std::byte{0x00};
    message.bytes[2] = std::byte{0x04};
    message.bytes[3] = static_cast<std::byte>(count << 3U);
    message.id = 4; message.declaredSize = 4; message.bodyBitOffset = 24; message.bitCount = bits;
    return message;
}

void refuse(const wire::AssembledMessage& message) {
    std::uint32_t output = 0x12345678;
    CHECK(!discarded::decode(message, output));
    CHECK(output == 0x12345678);
}

void exact_fields() {
    for (unsigned count = 0; count <= 31; ++count) {
        for (const auto bits : {29U, 32U}) {
            auto message = golden(count, bits);
            std::uint32_t output = 99;
            CHECK(discarded::decode(message, output) && output == count);
            // The fixed reassembly allocation may contain unrelated bytes beyond this message.
            message.bytes[4] = message.bytes.back() = std::byte{0xFF};
            CHECK(discarded::decode(message, output) && output == count);
        }
    }
    auto logical = golden(17, 29);
    logical.bytes[3] |= std::byte{0x07}; // Outside bitCount, not rounded-message padding.
    std::uint32_t output{};
    CHECK(discarded::decode(logical, output) && output == 17);
}

void bounds_and_padding() {
    for (std::size_t bits = 0; bits < 29; ++bits) refuse(golden(31, bits));
    for (const std::size_t bits : {30U, 31U, 33U, 40U, 8192U, 8193U}) refuse(golden(31, bits));
    refuse(golden(31, (std::numeric_limits<std::size_t>::max)()));
    for (unsigned count = 0; count <= 31; ++count) {
        for (unsigned poison = 1; poison <= 7; ++poison) {
            auto message = golden(count);
            message.bytes[3] |= static_cast<std::byte>(poison);
            refuse(message);
        }
    }
}

void metadata_and_header() {
    for (unsigned id = 0; id < 64; ++id) {
        if (id == 4) continue;
        auto message = golden(7); message.id = static_cast<std::uint8_t>(id); refuse(message);
        message = golden(7);
        message.bytes[0] = static_cast<std::byte>(id << 2U); refuse(message);
    }
    for (const std::uint32_t declared : {0U, 1U, 3U, 5U, 0x3FFFFU, 0xFFFFFFFFU}) {
        auto message = golden(7); message.declaredSize = declared; refuse(message);
    }
    for (const std::size_t offset : {0U, 1U, 23U, 25U, 8192U}) {
        auto message = golden(7); message.bodyBitOffset = offset; refuse(message);
    }
    auto message = golden(7);
    message.bodyBitOffset = (std::numeric_limits<std::size_t>::max)(); refuse(message);
    for (unsigned byte = 0; byte < 3; ++byte) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            message = golden(7); message.bytes[byte] ^= static_cast<std::byte>(1U << bit); refuse(message);
        }
    }
}
} // namespace

int main() {
    exact_fields(); bounds_and_padding(); metadata_and_header();
    std::printf("PASS: %u packets-discarded codec checks; five-bit incremental count\n", checks);
}
