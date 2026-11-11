#pragma once

#include <cstdint>

namespace dawn::server::gameplay::resolution {

// This 128-packet window is the server's replay policy, not a claim about the
// native client's window size. Set floor to the initial IV counter plus one;
// reject an exhausted initial counter before constructing a live context.
// Invoke only after authentication and padding validation. Callers can accept
// on a copy and publish that copy when the rest of packet processing succeeds.
struct ReplayWindow {
    std::uint64_t floor{};
    std::uint64_t highest{};
    // Bit zero of low denotes highest; bit 63 of high denotes highest - 127.
    std::uint64_t low{};
    std::uint64_t high{};
    bool seen{};

    [[nodiscard]] bool accept(std::uint64_t counter) noexcept {
        if (counter < floor) {
            return false;
        }
        if (!seen) {
            highest = counter;
            low = 1;
            high = 0;
            seen = true;
            return true;
        }
        if (counter > highest) {
            const auto distance = counter - highest;
            if (distance >= 128) {
                high = 0;
                low = 1;
            } else if (distance >= 64) {
                high = low << (distance - 64);
                low = 1;
            } else {
                high = (high << distance) | (low >> (64 - distance));
                low = (low << distance) | 1;
            }
            highest = counter;
            return true;
        }

        const auto distance = highest - counter;
        if (distance >= 128) {
            return false;
        }
        auto& bits = distance < 64 ? low : high;
        const auto mask = std::uint64_t{1} << (distance % 64);
        if ((bits & mask) != 0) {
            return false;
        }
        bits |= mask;
        return true;
    }
};

} // namespace dawn::server::gameplay::resolution
