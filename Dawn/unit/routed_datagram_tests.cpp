#include "../src/middleware/gameplay/routed_datagram.h"
#include "../src/middleware/crypto/hmac.h"
#include "../src/middleware/crypto/legacy_des_cbc.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <vector>

namespace {
namespace wire = dawn::middleware::gameplay::routed_datagram;
namespace crypto = dawn::middleware::crypto;
constexpr std::uint32_t kRoute = 0x10203040U;
constexpr std::byte kSentinel{0xA5};
unsigned checks{};

void check(bool value, const char* label) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", label); std::exit(1); }
}

std::vector<std::byte> hex(std::string_view text) {
    if (text.size() % 2 != 0) { std::abort(); }
    std::vector<std::byte> result(text.size() / 2);
    const auto digit = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>((digit(text[index * 2]) << 4)
                                               | digit(text[index * 2 + 1]));
    }
    return result;
}

wire::DirectionKeys fixture_keys() {
    wire::DirectionKeys result{};
    const auto cipher = hex("133457799bbcdff1");
    const auto mac = hex("000102030405060708090a0b0c0d0e0f");
    std::copy(cipher.begin(), cipher.end(), result.cipher.begin());
    std::copy(mac.begin(), mac.end(), result.mac.begin());
    return result;
}

bool untouched(std::span<const std::byte> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](auto byte) { return byte == kSentinel; });
}

void rejected(const wire::DirectionKeys& keys, std::span<const std::byte> packet,
               std::uint32_t route = kRoute, std::size_t capacity = wire::kMaximumPayload) {
    std::array<std::byte, wire::kMaximumPayload> output{};
    output.fill(kSentinel);
    wire::Iv iv{};
    iv.fill(std::byte{0x3C});
    const auto before = iv;
    std::size_t written = 123;
    check(!wire::open(keys, route, packet, std::span(output).first(capacity), iv, written),
          "malformed/authentication failure rejected");
    check(written == 0, "failure reports zero bytes");
    check(untouched(output), "failure leaves whole output unchanged");
    check(iv == before, "failure leaves IV metadata unchanged");
}

// Generates deliberately invalid plaintext padding with a valid MAC. This is
// not the packet encoder: the lower primitives encrypt the exact bytes supplied.
std::vector<std::byte> authenticated_plaintext(const wire::DirectionKeys& keys,
                                              std::span<const std::byte> plaintext) {
    const auto iv = hex("0907060504030201");
    auto packet = hex("102030400907060504030201");
    packet.resize(wire::kHeaderSize + plaintext.size() + wire::kTagSize);
    check(crypto::legacy_des::encrypt(keys.cipher, iv, plaintext,
          std::span(packet).subspan(wire::kHeaderSize, plaintext.size())),
          "construct authenticated malformed-padding fixture");
    crypto::hmac::Digest mac{};
    const auto covered = std::span(packet).first(packet.size() - wire::kTagSize);
    check(crypto::hmac::authenticate(crypto::hmac::Algorithm::sha1, keys.mac,
                                    covered, {}, mac), "authenticate malformed-padding fixture");
    std::copy_n(mac.bytes.begin(), wire::kTagSize, packet.end() - wire::kTagSize);
    return packet;
}

void independent_vectors(const wire::DirectionKeys& keys) {
    // Independent OpenSSL EDE3-CBC with three equal DES keys (equivalent to
    // DES-CBC), checked against DES block 85E813540F0AB405; Python hashlib
    // HMAC-SHA1 supplies the truncated tags. All keys and data are synthetic.
    struct Fixture { const char* iv; const char* payload; const char* packet; };
    constexpr std::array fixtures{
        Fixture{"0907060504030201", "4d756c74694461776e206e617469766520656e76656c6f70652074657374",
            "102030400907060504030201fe9be6e46120c6180244d904c201624cae25fbc2adaf9b12811717a8b12ceb82f21bb804577639be978e"},
        Fixture{"0001000000000000", "3132333435363738",
            "1020304000010000000000008fab11f68a05ab7ae6907b7b27c1ae1000d741869678a429208f"},
        Fixture{"0100000000000000", "",
            "102030400100000000000000210f19c74f3b6fccf971c646c0d498425286"},
    };
    for (const auto& fixture : fixtures) {
        const auto iv = hex(fixture.iv), payload = hex(fixture.payload), expected = hex(fixture.packet);
        std::array<std::byte, wire::kMaximumDatagram> packet{};
        packet.fill(kSentinel);
        std::size_t written = 123;
        check(wire::seal(keys, kRoute, iv, payload, packet, written), "seal independent vector");
        check(written == expected.size()
              && std::equal(expected.begin(), expected.end(), packet.begin()),
              "exact independent packet bytes");
        check(untouched(std::span(packet).subspan(written)), "seal leaves output tail untouched");
        const auto first = packet;
        check(wire::seal(keys, kRoute, iv, payload, packet, written) && first == packet,
              "codec is stateless and never increments supplied IV");

        std::array<std::byte, wire::kMaximumPayload> opened{};
        opened.fill(kSentinel);
        wire::Iv received{};
        check(wire::open(keys, kRoute, expected, opened, received, written), "open independent vector");
        check(written == payload.size() && std::equal(payload.begin(), payload.end(), opened.begin()),
              "independent plaintext recovered");
        check(std::equal(received.begin(), received.end(), iv.begin()), "authenticated IV recovered");
        check(untouched(std::span(opened).subspan(written)), "open leaves output tail untouched");
        check(iv == hex(fixture.iv), "caller IV unchanged");

        packet.fill(kSentinel);
        std::copy(payload.begin(), payload.end(), packet.begin());
        check(wire::seal(keys, kRoute, iv, std::span(packet).first(payload.size()), packet, written)
              && std::equal(expected.begin(), expected.end(), packet.begin()), "overlapping seal");
        check(wire::open(keys, kRoute, std::span(packet).first(written), packet, received, written)
              && written == payload.size()
              && std::equal(payload.begin(), payload.end(), packet.begin()), "overlapping open");
    }
}

void failures(const wire::DirectionKeys& keys) {
    const auto packet = hex("102030400907060504030201fe9be6e46120c6180244d904c201624cae25fbc2adaf9b12811717a8b12ceb82f21bb804577639be978e");
    for (std::size_t index = 0; index < packet.size(); ++index) {
        auto tampered = packet;
        tampered[index] ^= std::byte{0x80};
        rejected(keys, tampered);
    }
    auto retagged = packet;
    retagged[0] ^= std::byte{0x80};
    rejected(keys, retagged, kRoute ^ 0x80000000U); // Header covered by MAC, even if tag lookup matches.
    for (std::size_t length = 0; length < packet.size(); ++length) {
        rejected(keys, std::span(packet).first(length));
    }
    auto extra = packet;
    extra.push_back(std::byte{});
    rejected(keys, extra);
    extra.resize(packet.size() + 8);
    rejected(keys, extra);
    rejected(keys, packet, kRoute + 1);
    rejected(keys, packet, kRoute, 29);
    rejected(keys, packet, kRoute, 0);
    auto wrong = keys;
    wrong.mac[0] ^= std::byte{0x80};
    rejected(wrong, packet);
    wrong = keys;
    wrong.cipher[0] ^= std::byte{0x80};
    rejected(wrong, packet);

    for (const auto invalid : {"4141414141414100", "4141414141414109",
                               "0707070707070708", "4141414141410102"}) {
        rejected(keys, authenticated_plaintext(keys, hex(invalid)));
    }
    const auto empty = hex("102030400100000000000000210f19c74f3b6fccf971c646c0d498425286");
    wire::Iv received{};
    std::size_t written = 99;
    check(wire::open(keys, kRoute, empty, {}, received, written) && written == 0,
          "valid empty payload accepts empty output");

    std::array<std::byte, wire::kMaximumDatagram> overlap{};
    std::copy(packet.begin(), packet.end(), overlap.begin());
    overlap[packet.size() - 1] ^= std::byte{1};
    const auto before = overlap;
    received.fill(kSentinel);
    const auto beforeIv = received;
    check(!wire::open(keys, kRoute, std::span(overlap).first(packet.size()), overlap, received, written)
          && written == 0 && overlap == before && received == beforeIv,
          "failed overlapping open commits no output or metadata");
}

void boundaries(const wire::DirectionKeys& keys) {
    const auto iv = hex("0907060504030201");
    std::array<std::byte, wire::kMaximumPayload + 1> payload{};
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index & 0xFFU);
    }
    std::array<std::byte, wire::kMaximumDatagram + 1> packet{};
    packet.fill(kSentinel);
    std::size_t written = 99;
    const auto maximum = std::span(payload).first(wire::kMaximumPayload);
    check(wire::seal(keys, kRoute, iv, maximum, packet, written)
          && written == wire::kMaximumDatagram && packet.back() == kSentinel,
          "maximum plaintext and ciphertext bounds");
    std::array<std::byte, wire::kMaximumPayload> decoded{};
    wire::Iv received{};
    check(wire::open(keys, kRoute, std::span(packet).first(written), decoded, received, written)
          && written == maximum.size() && std::equal(decoded.begin(), decoded.end(), maximum.begin()),
          "maximum datagram round trip");
    rejected(keys, packet);
    packet.fill(kSentinel);
    check(!wire::seal(keys, kRoute, iv, payload, packet, written)
          && written == 0 && untouched(packet), "reject payload requiring ciphertext beyond 5120");
    check(!wire::seal(keys, kRoute, std::span(iv).first(7), maximum, packet, written)
          && written == 0 && untouched(packet), "reject short IV without partial output");
    auto longIv = iv;
    longIv.push_back(std::byte{});
    check(!wire::seal(keys, kRoute, longIv, maximum, packet, written)
          && written == 0 && untouched(packet), "reject long IV without partial output");
    check(!wire::seal(keys, kRoute, iv, maximum,
                      std::span(packet).first(wire::kMaximumDatagram - 1), written)
          && written == 0 && untouched(packet), "reject insufficient maximum-output capacity");
    check(!wire::seal(keys, kRoute, iv, {}, std::span(packet).first(wire::kMinimumDatagram - 1), written)
          && written == 0 && untouched(packet), "empty payload still needs one padding block");
}

} // namespace

int main() {
    const auto keys = fixture_keys();
    independent_vectors(keys);
    failures(keys);
    boundaries(keys);
    const auto expectedKeys = fixture_keys();
    check(keys.cipher == expectedKeys.cipher && keys.mac == expectedKeys.mac, "caller keys unchanged");
    std::printf("PASS: %u routed datagram checks\n", checks);
}
