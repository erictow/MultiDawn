#include "../src/core/multiplayer/companion_protocol.h"
#include "../src/core/multiplayer/companion_invitation_state.h"
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

void preflight_cases() {
    using namespace dawn::core::multiplayer;
    constexpr std::string_view nonce = "00000000000000000000000000000001";
    constexpr std::string_view nextNonce = "00000000000000000000000000000002";
    constexpr std::string_view ticket = "0123456789ABCDEF0123456789ABCDEF";
    constexpr std::string_view localEpoch = "11111111111111111111111111111111";
    constexpr std::string_view peerEpoch = "22222222222222222222222222222222";
    constexpr std::uint64_t peer = 0x0110000100000002ULL;
    InvitationPreflightState state;
    InvitationPreflightObservation observation{};
    auto begin = [&](std::uint64_t now, std::string_view requestNonce = "00000000000000000000000000000001") {
        return state.begin(requestNonce, peer, ticket, localEpoch, peerEpoch, 9, 11, 13, now);
    };
    auto reply = [&](const std::string& text, std::uint64_t now) {
        wire::Fields fields;
        CHECK(wire::split(text, fields));
        return state.response(fields, now);
    };
    const std::string success = "PREFLIGHT_OK " + std::string(nonce) + " 76561197960265730 "
        + std::string(ticket) + " 9 " + std::string(localEpoch) + " " + std::string(peerEpoch) + " 1000";
    CHECK(!state.take(0, observation) && observation == InvitationPreflightObservation{});
    CHECK(reply(success, 0) && !state.take(0, observation)); // Unsolicited is ignored.
    for (unsigned variant = 0; variant < 8; ++variant) {
        CHECK(!state.begin(variant == 0 ? "bad" : nonce, variant == 1 ? 0 : peer,
            variant == 2 ? "bad" : ticket, variant == 3 ? "bad" : localEpoch,
            variant == 4 ? "bad" : peerEpoch, variant == 5 ? 0 : 9,
            variant == 6 ? 0 : 11, variant == 7 ? 0 : 13, 1000));
    }
    CHECK(begin(1000) && state.pending());
    CHECK(!begin(1001, nextNonce));
    CHECK(reply(success, 1050) && !state.pending());
    CHECK(state.take(1051, observation) && observation.deadline == 2000
        && observation.peerSteamId == peer && observation.pairGeneration == 9
        && observation.companionGeneration == 11 && observation.requestGeneration == 13
        && std::string_view(observation.ticket.data()) == ticket
        && std::string_view(observation.localEpoch.data()) == localEpoch
        && std::string_view(observation.peerEpoch.data()) == peerEpoch);
    const auto copied = observation;
    CHECK(!state.take(1052, observation) && observation == InvitationPreflightObservation{});
    CHECK(state.validate(1999, copied));
    CHECK(reply(success, 1999) && state.validate(1999, copied)); // Replay cannot extend.
    for (unsigned variant = 0; variant < 8; ++variant) {
        auto forged = copied;
        switch (variant) {
        case 0: ++forged.peerSteamId; break;
        case 1: ++forged.pairGeneration; break;
        case 2: ++forged.companionGeneration; break;
        case 3: ++forged.requestGeneration; break;
        case 4: ++forged.deadline; break;
        case 5: forged.ticket.fill('A'); break;
        case 6: forged.localEpoch.fill('A'); break;
        case 7: forged.peerEpoch.fill('A'); break;
        }
        CHECK(!state.validate(1999, forged));
    }
    CHECK(!state.validate(2000, copied));
    CHECK(begin(3000, nextNonce));
    CHECK(reply(success, 3001) && state.pending()); // Old nonce never consumes new request.
    CHECK(reply("PREFLIGHT_NO " + std::string(nonce), 3001) && state.pending());
    CHECK(reply("PREFLIGHT_NO " + std::string(nextNonce), 3001) && !state.pending());
    CHECK(!state.take(3001, observation));
    // Every binding lane is required for the matching request nonce.
    for (unsigned variant = 0; variant < 9; ++variant) {
        state = {}; CHECK(begin(1000));
        wire::Fields fields; CHECK(wire::split(success, fields));
        switch (variant) {
        case 0: fields.values[2] = "76561197960265729"; break;
        case 1: fields.values[3] = localEpoch; break;
        case 2: fields.values[4] = "10"; break;
        case 3: fields.values[5] = peerEpoch; break;
        case 4: fields.values[6] = localEpoch; break;
        case 5: fields.values[7] = "0"; break;
        case 6: fields.values[7] = "60001"; break;
        case 7: fields.count = 7; break;
        case 8: fields.values[1] = "bad"; break;
        }
        CHECK(!state.response(fields, 1001) && state.pending());
        CHECK(!state.take(1001, observation));
    }
    state = {}; CHECK(begin(1000));
    state.expire(5999); CHECK(state.pending());
    state.expire(6000); CHECK(!state.pending());
    CHECK(reply(success, 6000) && !state.take(6000, observation));
    state = {}; CHECK(begin(1000));
    CHECK(reply(success, 2000) && !state.take(2000, observation)); // TTL exhausted in transit.
    state = {}; CHECK(begin(UINT64_MAX - 20));
    CHECK(reply(success, UINT64_MAX - 10) && !state.take(UINT64_MAX - 10, observation));
    state = {}; CHECK(begin(1000));
    CHECK(reply(success, 1001) && state.take(1001, observation));
    CHECK(!state.validate(999, observation)); // A backwards clock cannot revive a lifetime.
    for (const bool afterReply : {false, true}) {
        state = {}; CHECK(begin(1000));
        if (afterReply) CHECK(reply(success, 1001) && state.take(1001, observation));
        state.revoke(localEpoch); CHECK(afterReply ? state.validate(1001, observation) : state.pending());
        state.revoke(ticket); CHECK(!state.pending() && !state.validate(1001, observation));
        CHECK(reply(success, 1002) && !state.take(1002, observation));
        state = {}; CHECK(begin(1000));
        if (afterReply) CHECK(reply(success, 1001) && state.take(1001, observation));
        state.replace(ticket); CHECK(afterReply ? state.validate(1001, observation) : state.pending());
        state.replace(localEpoch); CHECK(!state.pending() && !state.validate(1001, observation));
    }
}
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
    constexpr std::string_view ticket = "0123456789ABCDEF0123456789ABCDEF";
    constexpr std::string_view other = "ABCDEF0123456789ABCDEF0123456789";
    CHECK(wire::ticket(ticket));
    CHECK(!wire::ticket("0123456789abcdef0123456789abcdef"));
    CHECK(!wire::ticket(std::string(31, 'A')));
    CHECK(!wire::ticket(std::string(33, 'A')));
    CHECK(!wire::ticket(std::string(32, 'G')));
    dawn::core::multiplayer::InvitationIntentState intents;
    dawn::core::multiplayer::AcceptedInvitationIntent intent;
    constexpr std::uint64_t peer = 0x0110000100000002ULL;
    bool changed = true;
    CHECK(!intents.take(0, intent) && intent.peerSteamId == 0);
    CHECK(!intents.accepted(peer, ticket, 100, 1));
    CHECK(!intents.runtime(ticket, 0, changed));
    CHECK(!intents.runtime("-", 2, changed));
    CHECK(!intents.runtime(ticket, 3, changed));
    CHECK(intents.runtime("-", 0, changed) && !changed);
    CHECK(intents.runtime(ticket, 1, changed) && changed && !intents.ready());
    CHECK(!intents.accepted(peer, ticket, 100, 1));
    CHECK(intents.runtime(ticket, 2, changed) && changed && intents.ready());
    CHECK(intents.runtime(ticket, 2, changed) && !changed);
    CHECK(!intents.accepted(0, ticket, 100, 1));
    CHECK(!intents.accepted(peer, "bad", 100, 1));
    CHECK(!intents.accepted(peer, ticket, 0, 1));
    CHECK(!intents.accepted(peer, ticket, 60'001, 1));
    CHECK(!intents.accepted(peer, ticket, 100, UINT64_MAX - 99));
    CHECK(intents.accepted(peer, ticket, 100, 1000));
    CHECK(intents.accepted(peer, ticket, 60'000, 1050));
    CHECK(intents.take(1099, intent) && intent.deadline == 1100 && intent.peerSteamId == peer);
    CHECK(std::string_view(intent.ticket.data()) == ticket);
    CHECK(!intents.take(1099, intent));
    CHECK(intents.accepted(peer, ticket, 100, 1099) && !intents.take(1099, intent));
    CHECK(intents.accepted(peer, other, 100, 1100));
    intents.revoke(ticket);
    CHECK(intents.take(1101, intent) && std::string_view(intent.ticket.data()) == other);
    CHECK(intents.accepted(peer, ticket, 100, 1200));
    intents.revoke(ticket);
    CHECK(!intents.take(1201, intent));
    CHECK(intents.accepted(peer, ticket, 100, 1201) && !intents.take(1202, intent));
    CHECK(intents.accepted(peer, other, 100, 1300));
    CHECK(!intents.take(1400, intent));
    CHECK(intents.accepted(peer, ticket, 100, 1500));
    CHECK(intents.runtime(other, 2, changed) && changed && !intents.take(1501, intent));
    CHECK(intents.accepted(peer, ticket, 100, 1600));
    CHECK(intents.runtime("-", 0, changed) && changed && !intents.ready());
    CHECK(!intents.take(1601, intent));
    preflight_cases();
    std::printf("PASS: %u companion protocol checks\n", checks);
}
