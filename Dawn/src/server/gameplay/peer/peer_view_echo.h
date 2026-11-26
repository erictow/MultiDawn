#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../middleware/encoding/bit_reader.h"
#include "../../../middleware/encoding/bit_writer.h"
#include "../../../middleware/gameplay/group/view_message.h"
#include "../../../middleware/gameplay/peer/established_packet.h"
#include "../../../middleware/gameplay/peer/reliable_assembly.h"
#include "../../../state/gameplay/definition.h"

namespace dawn::server::gameplay::peer::view_echo {

/** Identity of the exact connected link consuming an authenticated native packet. */
struct LinkKey {
    state::gameplay::Endpoint endpoint{};
    std::uint32_t localChannelId{};
    std::uint32_t remoteChannelId{};
};

enum class Result : std::uint8_t { notApplicable, rejected, queueFull, queued };

[[nodiscard]] inline LinkKey key_for(const state::gameplay::PeerLink& link) noexcept {
    return {link.endpoint, link.localConnectionSequence, link.remoteConnectionSequence};
}

[[nodiscard]] inline bool unaffiliated(const state::gameplay::PeerLink& link) noexcept {
    for (const auto session : link.sessions) { if (session != 0) { return false; } }
    return true;
}

/**
 * Echoes only a complete ID40 on an authenticated native link with no group
 * membership. Caller holds the peer lock and obtained key from that packet's
 * current link. The compatibility token never creates or selects a group.
 * Failure preserves queue, signature, and acknowledgement state.
 */
[[nodiscard]] inline Result queue(state::gameplay::PeerLink& link,
                                   const LinkKey& key,
                                   const middleware::gameplay::peer::AssembledMessage& message) noexcept {
    namespace views = middleware::gameplay::group;
    namespace wire = middleware::gameplay::peer;
    namespace bits = middleware::encoding::bits;
    if (message.id != views::kViewMessageId || !unaffiliated(link)) { return Result::notApplicable; }
    if (link.stage != state::gameplay::PeerStage::connected || !link.applicationReady
        || key.endpoint.address == 0 || key.endpoint.port == 0
        || link.endpoint.address != key.endpoint.address || link.endpoint.port != key.endpoint.port
        || link.localConnectionSequence != key.localChannelId
        || link.remoteConnectionSequence != key.remoteChannelId
        || message.declaredSize != views::kViewMessageSize || message.bodyBitOffset != 24
        || message.bitCount < message.bodyBitOffset || message.bitCount > message.bytes.size() * 8U) {
        return Result::rejected;
    }
    const std::size_t bytes = (message.bitCount + 7U) / 8U;
    bits::Reader reader({message.bytes.data(), bytes});
    std::uint64_t id{}, declared{};
    views::ViewEstablishment view{};
    if (!reader.read(6, id) || id != views::kViewMessageId
        || !reader.read(18, declared) || declared != views::kViewMessageSize
        || !views::read_view(reader, view)) { return Result::rejected; }
    const auto consumed = bytes * 8U - reader.remaining_bits();
    if (consumed > message.bitCount) { return Result::rejected; }
    const auto padding = message.bitCount - consumed;
    std::uint64_t paddingValue{};
    if (padding > 7 || (padding != 0 && message.bitCount % 8U != 0)
        || !reader.read(static_cast<std::uint8_t>(padding), paddingValue) || paddingValue != 0) {
        return Result::rejected;
    }
    std::array<std::byte, 64> encoded{};
    bits::Writer writer(encoded);
    std::size_t written{};
    if (!views::write_view(writer, view) || !writer.finish(written)) { return Result::rejected; }
    auto pending = link.outbound;
    if (!wire::enqueue_message(pending, views::kViewMessageId, views::kViewMessageSize,
                               {encoded.data(), written}, writer.bit_count())) { return Result::queueFull; }
    state::gameplay::ViewSignature signature{};
    signature.token = view.sessionToken;
    signature.kind = view.kind;
    signature.listCount = view.listCount;
    signature.hasList = view.hasList;
    signature.list = view.list;
    signature.bound = true;
    link.outbound = pending;
    link.view = signature;
    link.acknowledgementOwed = true;
    return Result::queued;
}

} // namespace dawn::server::gameplay::peer::view_echo
