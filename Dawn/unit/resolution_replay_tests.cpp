#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <set>

#include "../src/server/gameplay/resolution/replay_window.h"

using dawn::server::gameplay::resolution::ReplayWindow;
static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s\n", __LINE__, #value); std::abort(); } } while (false)

static bool same(const ReplayWindow& left, const ReplayWindow& right) {
    return left.floor == right.floor && left.highest == right.highest &&
        left.low == right.low && left.high == right.high && left.seen == right.seen;
}

static void rejects_unchanged(ReplayWindow& window, std::uint64_t counter) {
    const auto before = window;
    CHECK(!window.accept(counter));
    CHECK(same(window, before));
}

static void floor_and_first_packet() {
    ReplayWindow raw{};
    CHECK(raw.accept(0));
    CHECK(raw.seen && raw.highest == 0 && raw.low == 1 && raw.high == 0);
    rejects_unchanged(raw, 0);

    ReplayWindow initial{100, 99, 0x1234, 0x5678, false};
    rejects_unchanged(initial, 0);
    rejects_unchanged(initial, 99);
    CHECK(initial.accept(105));
    CHECK(initial.floor == 100 && initial.highest == 105 && initial.low == 1 && initial.high == 0 && initial.seen);
    CHECK(initial.accept(100));
    rejects_unchanged(initial, 99);
    rejects_unchanged(initial, 100);

    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    ReplayWindow last{maximum};
    rejects_unchanged(last, maximum - 1);
    CHECK(last.accept(maximum));
    CHECK(last.highest == maximum && last.low == 1 && last.high == 0);
    rejects_unchanged(last, maximum);
    rejects_unchanged(last, 0);
}

static void reordered_window() {
    ReplayWindow window{1000};
    CHECK(window.accept(1200));
    // Permuting every offset in the window exercises both words without
    // assuming that packets arrive in increasing counter order.
    for (std::uint64_t index = 1; index < 128; ++index) {
        const auto distance = (index * 67) % 128;
        CHECK(window.accept(1200 - distance));
        rejects_unchanged(window, 1200 - distance);
    }
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    CHECK(window.low == maximum && window.high == maximum);
    rejects_unchanged(window, 1072);
    rejects_unchanged(window, 1000);
    CHECK(window.accept(1201));
    rejects_unchanged(window, 1073);
    rejects_unchanged(window, 1200);

    // An accepted reorder must not move the high-water mark backwards.
    ReplayWindow holes{};
    CHECK(holes.accept(200));
    CHECK(holes.accept(137));
    CHECK(holes.accept(136));
    CHECK(holes.accept(73));
    CHECK(holes.highest == 200);
    CHECK(holes.low == (std::uint64_t{1} | (std::uint64_t{1} << 63)));
    CHECK(holes.high == (std::uint64_t{1} | (std::uint64_t{1} << 63)));
    rejects_unchanged(holes, 72);
}

static void every_shift() {
    constexpr std::array<std::uint64_t, 8> oldDistances{0, 1, 31, 63, 64, 65, 95, 127};
    // Includes the split-word boundaries 1, 63, 64, 65, 127, 128 and
    // every surrounding shift. Expected bits are built from packet identities,
    // independently of the implementation's bitmap shifting branches.
    for (std::uint64_t shift = 1; shift <= 256; ++shift) {
        ReplayWindow window{};
        for (const auto distance : oldDistances) {
            CHECK(window.accept(256 - distance));
        }
        CHECK(window.accept(256 + shift));
        std::uint64_t expectedLow = 1;
        std::uint64_t expectedHigh = 0;
        for (const auto oldDistance : oldDistances) {
            const auto distance = oldDistance + shift;
            if (distance < 64) {
                expectedLow |= std::uint64_t{1} << distance;
            } else if (distance < 128) {
                expectedHigh |= std::uint64_t{1} << (distance - 64);
            }
        }
        CHECK(window.highest == 256 + shift && window.low == expectedLow && window.high == expectedHigh);
        for (const auto distance : oldDistances) {
            rejects_unchanged(window, 256 - distance);
        }
        // A missing counter at the oldest retained distance is still accepted.
        const auto oldest = window.highest - 127;
        if ((expectedHigh & (std::uint64_t{1} << 63)) == 0) {
            CHECK(window.accept(oldest));
            rejects_unchanged(window, oldest);
        }
        rejects_unchanged(window, window.highest - 128);
    }
}

static void counter_limits_and_copy_commit() {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    ReplayWindow hugeGap{};
    CHECK(hugeGap.accept(0));
    CHECK(hugeGap.accept(maximum));
    CHECK(hugeGap.highest == maximum && hugeGap.low == 1 && hugeGap.high == 0);
    rejects_unchanged(hugeGap, 0);
    CHECK(hugeGap.accept(maximum - 127));
    rejects_unchanged(hugeGap, maximum - 128);
    rejects_unchanged(hugeGap, maximum);

    ReplayWindow nearEnd{maximum - 200};
    CHECK(nearEnd.accept(maximum - 128));
    CHECK(nearEnd.accept(maximum - 1));
    CHECK(nearEnd.high == (std::uint64_t{1} << 63));
    CHECK(nearEnd.accept(maximum));
    CHECK(nearEnd.low == 3 && nearEnd.high == 0);
    rejects_unchanged(nearEnd, maximum - 128);
    CHECK(nearEnd.accept(maximum - 127));

    ReplayWindow live{42};
    const auto untouched = live;
    auto candidate = live;
    CHECK(candidate.accept(42));
    CHECK(same(live, untouched));
    // A caller may discard candidate on a later validation failure.
    candidate = live;
    CHECK(candidate.accept(42));
    live = candidate;
    rejects_unchanged(live, 42);
}

static void packet_history_oracle() {
    // Compare against an ordinary set of accepted counters, with no bitmap.
    // The history deliberately includes reordered packets, repeats, large
    // jumps and near-maximum counters.
    ReplayWindow window{37};
    std::set<std::uint64_t> accepted;
    std::uint64_t random = 0xA0761D6478BD642FULL;
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    for (unsigned index = 0; index < 4096; ++index) {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        std::uint64_t counter = random % 700;
        if (index >= 2048) {
            counter = maximum - (random % 700);
        }
        bool expected = counter >= window.floor;
        if (!accepted.empty() && counter <= *accepted.rbegin()) {
            expected = expected && (*accepted.rbegin() - counter < 128) && !accepted.contains(counter);
        }
        const auto before = window;
        CHECK(window.accept(counter) == expected);
        if (expected) {
            accepted.insert(counter);
            CHECK(window.highest == *accepted.rbegin());
        } else {
            CHECK(same(window, before));
        }
    }
}

int main() {
    floor_and_first_packet();
    reordered_window();
    every_shift();
    counter_limits_and_copy_commit();
    packet_history_oracle();
    std::printf("resolution_replay_tests: PASS %u checks\n", checks);
}
