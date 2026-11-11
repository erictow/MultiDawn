#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>

#include "../src/server/gameplay/peer/peer_view_echo.h"

namespace echo = dawn::server::gameplay::peer::view_echo;
namespace state = dawn::state::gameplay;
namespace wire = dawn::middleware::gameplay::peer;
namespace views = dawn::middleware::gameplay::group;
namespace bits = dawn::middleware::encoding::bits;
static unsigned checks{};
#define CHECK(value) do { ++checks; if (!(value)) { std::fprintf(stderr, "FAIL:%d %s\n", __LINE__, #value); std::abort(); } } while (false)

static bool same_queue(const state::OutboundQueue& a, const state::OutboundQueue& b) {
    if (a.count != b.count || a.nextSequence != b.nextSequence || a.sentInPacket != b.sentInPacket
        || a.sentCount != b.sentCount || a.awaitingAcknowledgement != b.awaitingAcknowledgement) { return false; }
    for (std::size_t i = 0; i < a.fragments.size(); ++i) {
        const auto& x = a.fragments[i]; const auto& y = b.fragments[i];
        if (x.bytes != y.bytes || x.sequence != y.sequence || x.bitCount != y.bitCount
            || x.shortFragment != y.shortFragment || x.occupied != y.occupied) { return false; }
    }
    return true;
}

static bool same_view(const state::ViewSignature& a, const state::ViewSignature& b) {
    return a.list == b.list && a.token == b.token && a.kind == b.kind && a.listCount == b.listCount
        && a.hasList == b.hasList && a.bound == b.bound;
}

static void unchanged(const state::PeerLink& now, const state::PeerLink& before) {
    CHECK(same_queue(now.outbound, before.outbound));
    CHECK(same_view(now.view, before.view));
    CHECK(now.sessions == before.sessions && now.acknowledgementOwed == before.acknowledgementOwed);
    CHECK(now.stage == before.stage && now.applicationReady == before.applicationReady);
}

static state::PeerLink link(unsigned ordinal = 0) {
    state::PeerLink result{};
    result.endpoint = {0x7F000001U + ordinal, static_cast<std::uint16_t>(31000U + ordinal)};
    result.localConnectionSequence = 41U + ordinal;
    result.remoteConnectionSequence = 7U + ordinal;
    result.stage = state::PeerStage::connected;
    result.applicationReady = true;
    return result;
}

static views::ViewEstablishment sample(bool complex = false) {
    views::ViewEstablishment view{};
    view.sessionToken = 0x9EAA300100200001ULL;
    view.kind = complex ? 1 : 0;
    view.hasOptionalValue = complex;
    view.optionalValue = complex ? -1234567 : 0;
    view.hasList = complex;
    view.listCount = complex ? 16 : 0;
    for (std::size_t i = 0; i < view.listCount; ++i) { view.list[i] = static_cast<std::byte>(i + 3); }
    return view;
}

static wire::AssembledMessage message(const views::ViewEstablishment& view) {
    wire::AssembledMessage result{};
    result.id = views::kViewMessageId;
    result.declaredSize = views::kViewMessageSize;
    result.bodyBitOffset = 24;
    bits::Writer writer(result.bytes);
    CHECK(writer.write(result.id, 6) && writer.write(result.declaredSize, 18));
    CHECK(views::write_view(writer, view));
    std::size_t written{};
    CHECK(writer.finish(written));
    result.bitCount = writer.bit_count();
    return result;
}

static views::ViewEstablishment queued_view(const state::OutboundQueue& queue) {
    wire::QueueRecords records{};
    records.count = queue.count;
    for (std::size_t i = 0; i < records.count; ++i) {
        const auto& fragment = queue.fragments[i];
        records.records[i] = {fragment.sequence, fragment.shortFragment, fragment.bitCount, fragment.bytes};
    }
    state::ReliableQueue receive{};
    CHECK(wire::accept_records(records, receive) == 0);
    wire::AssembledMessage decoded{};
    CHECK(wire::drain_message(receive, decoded));
    CHECK(decoded.id == views::kViewMessageId && decoded.declaredSize == views::kViewMessageSize);
    bits::Reader reader({decoded.bytes.data(), (decoded.bitCount + 7U) / 8U});
    CHECK(reader.skip(decoded.bodyBitOffset));
    views::ViewEstablishment result{};
    CHECK(views::read_view(reader, result));
    return result;
}

static void accepted_views() {
    for (const bool complex : {false, true}) {
        for (const std::uint64_t token : {0ULL, 0x9EAA300100200001ULL, 0xFFFFFFFFFFFFFFFFULL}) {
            auto peer = link();
            auto view = sample(complex); view.sessionToken = token;
            const auto input = message(view);
            CHECK(echo::queue(peer, echo::key_for(peer), input) == echo::Result::queued);
            CHECK(echo::unaffiliated(peer));
            CHECK(peer.acknowledgementOwed && peer.view.bound && peer.view.token == token);
            const auto response = queued_view(peer.outbound);
            CHECK(views::compatible(response, view));
            CHECK(response.hasOptionalValue == view.hasOptionalValue && response.optionalValue == view.optionalValue);
            CHECK(peer.localConnectionSequence == 41 && peer.remoteConnectionSequence == 7);
        }
    }
    auto first = link(), second = link(1);
    const auto untouched = first;
    auto secondView = sample(true); secondView.sessionToken = 123;
    CHECK(echo::queue(second, echo::key_for(second), message(secondView)) == echo::Result::queued);
    unchanged(first, untouched);
    CHECK(second.view.token == 123 && echo::unaffiliated(second));
}

static void key_and_stage_guards() {
    const auto input = message(sample());
    for (unsigned change = 0; change < 9; ++change) {
        auto peer = link(); auto key = echo::key_for(peer);
        if (change == 0) { ++key.endpoint.address; }
        if (change == 1) { ++key.endpoint.port; }
        if (change == 2) { ++key.localChannelId; }
        if (change == 3) { ++key.remoteChannelId; }
        if (change == 4) { peer.stage = state::PeerStage::absent; }
        if (change == 5) { peer.stage = state::PeerStage::connecting; }
        if (change == 6) { peer.applicationReady = false; }
        if (change == 7) { peer.endpoint.address = key.endpoint.address = 0; }
        if (change == 8) { peer.endpoint.port = key.endpoint.port = 0; }
        const auto before = peer;
        CHECK(echo::queue(peer, key, input) == echo::Result::rejected);
        unchanged(peer, before);
    }
    for (const bool multiple : {false, true}) {
        auto peer = link(); peer.sessions[0] = 991;
        if (multiple) { peer.sessions[1] = 992; }
        const auto before = peer;
        CHECK(echo::queue(peer, echo::key_for(peer), input) == echo::Result::notApplicable);
        unchanged(peer, before);
    }
}

static void malformed_and_capacity() {
    for (const bool complex : {false, true}) {
        const auto original = message(sample(complex));
        for (std::size_t count = 0; count < original.bitCount; ++count) {
            auto peer = link(); auto truncated = original; truncated.bitCount = count;
            const auto before = peer;
            CHECK(echo::queue(peer, echo::key_for(peer), truncated) == echo::Result::rejected);
            unchanged(peer, before);
        }
        auto padded = original; padded.bitCount = ((padded.bitCount + 7U) / 8U) * 8U;
        auto peer = link();
        CHECK(echo::queue(peer, echo::key_for(peer), padded) == echo::Result::queued);
        padded.bytes[(original.bitCount - 1U) / 8U] |= std::byte{1};
        peer = link(); const auto before = peer;
        CHECK(echo::queue(peer, echo::key_for(peer), padded) == echo::Result::rejected);
        unchanged(peer, before);
    }
    for (unsigned change = 0; change < 6; ++change) {
        auto peer = link(); auto input = message(sample());
        if (change == 0) { input.declaredSize = 39; }
        if (change == 1) { input.bodyBitOffset = 23; }
        if (change == 2) { input.bytes[2] ^= std::byte{1}; }
        if (change == 3) { input.bitCount = input.bytes.size() * 8U + 1; }
        if (change == 4) { input.bytes[3] = std::byte{0xE0}; }
        if (change == 5) { input.bitCount += 8; }
        const auto before = peer;
        CHECK(echo::queue(peer, echo::key_for(peer), input) == echo::Result::rejected);
        unchanged(peer, before);
    }
    auto peer = link();
    auto input = message(sample()); input.id = 31;
    const auto noView = peer;
    CHECK(echo::queue(peer, echo::key_for(peer), input) == echo::Result::notApplicable);
    unchanged(peer, noView);
    for (unsigned available = 0; available < 2; ++available) {
        peer = link();
        peer.view.token = 321; peer.view.bound = true;
        peer.outbound.count = state::kOutboundSlots - available;
        peer.outbound.nextSequence = 100;
        peer.outbound.awaitingAcknowledgement = true;
        // Preserve even unused storage when a multi-fragment append runs out
        // of room after staging its first fragment.
        peer.outbound.fragments.back().bytes[0] = std::byte{0xCC};
        const auto before = peer;
        CHECK(echo::queue(peer, echo::key_for(peer), message(sample(true))) == echo::Result::queueFull);
        unchanged(peer, before);
    }
}

int main() {
    accepted_views();
    key_and_stage_guards();
    malformed_and_capacity();
    std::printf("PASS: %u native view echo checks; no sockets, games, profiles or group memberships opened.\n", checks);
}
