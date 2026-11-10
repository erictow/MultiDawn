#include "../src/core/multiplayer/companion_protocol.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace wire = dawn::core::multiplayer::protocol;
namespace {
unsigned checks = 0;
void check(bool condition, int line) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "FAIL companion protocol line %d\n", line); std::exit(1); }
}
#define CHECK(value) check((value), __LINE__)
}

int main() {
    std::uint64_t number = 77;
    CHECK(wire::decimal("76561198000000001", number) && number == 76561198000000001ULL);
    CHECK(wire::decimal("18446744073709551615", number) && number == UINT64_MAX);
    CHECK(!wire::decimal("18446744073709551616", number) && number == UINT64_MAX);
    CHECK(!wire::decimal("", number));
    CHECK(!wire::decimal("-1", number));
    CHECK(!wire::decimal("12x", number));
    CHECK(!wire::decimal(" 12", number));
    CHECK(!wire::decimal("000000000000000000001", number));
    CHECK(wire::steam_identity(0x0110000100000001ULL));
    CHECK(!wire::steam_identity(0x0110000100000000ULL));
    CHECK(!wire::steam_identity(0x0210000100000001ULL));
    CHECK(wire::identifier(L"0123456789abcdef0123456789abcdef"));
    CHECK(!wire::identifier(L"0123456789ABCDEF0123456789ABCDEF"));
    CHECK(!wire::identifier(L"\\\\remote\\pipe\\test"));
    CHECK(!wire::identifier(L"../0123456789abcdef0123456789abcd"));
    wire::Message message;
    CHECK(wire::append(message, "INVITE 76561198000000001 "));
    CHECK(wire::append_hex(message, "+connect_lobby 123"));
    CHECK(message.view() == "INVITE 76561198000000001 2B636F6E6E6563745F6C6F62627920313233");
    wire::Fields fields;
    CHECK(wire::split(message.view(), fields) && fields.count == 3);
    CHECK(fields.values[0] == "INVITE");
    std::array<char, 256> text{};
    CHECK(wire::decode_text(fields.values[2], text) && std::string_view(text.data()) == "+connect_lobby 123");
    CHECK(wire::decode_text("-", text) && text[0] == '\0');
    CHECK(!wire::decode_text("00", text));
    CHECK(!wire::decode_text("0A", text));
    CHECK(!wire::decode_text("7F", text));
    CHECK(!wire::decode_text("GG", text));
    CHECK(!wire::decode_text("7", text));
    CHECK(!wire::decode_text("", text));
    std::array<char, 1> tooSmall{};
    CHECK(!wire::decode_text("41", tooSmall));
    CHECK(!wire::split(" INVITE 1 -", fields));
    CHECK(!wire::split("INVITE  1 -", fields));
    CHECK(!wire::split("INVITE 1 - ", fields));
    CHECK(!wire::split("INVITE\n1 -", fields));
    CHECK(!wire::split("a b c d e f g h i", fields));
    CHECK(!wire::split(std::string(wire::kMaximumMessage + 1, 'A'), fields));
    message = {};
    const std::string maximumConnect(255, 'A');
    CHECK(wire::append_hex(message, maximumConnect));
    CHECK(wire::decode_text(message.view(), text) && std::string_view(text.data()) == maximumConnect);
    CHECK(!wire::decode_text(std::string(message.view()) + "41", text));
    message = {};
    CHECK(wire::append(message, std::string(wire::kMaximumMessage, 'A')));
    CHECK(!wire::append(message, "A") && message.size == wire::kMaximumMessage);
    std::printf("PASS: %u companion protocol checks\n", checks);
}
