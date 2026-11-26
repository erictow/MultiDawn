#include "reliable_outbox.h"

#include "reliable_message_plan.h"

namespace dawn::middleware::gameplay::peer {

bool RollingReliableOutbox::enqueue(std::uint8_t id, std::uint32_t declaredSize,
    std::span<const std::byte> body, std::size_t bodyBits) noexcept {
    constexpr std::uint32_t kDeclaredSizeLimit = 1U << 18;
    if (pending() != 0 || declaredSize >= kDeclaredSizeLimit || bodyBits > kRollingBodyCapacity * 8U) {
        return false;
    }
    std::array<std::byte, kRollingFramedCapacity> framing{};
    std::array<state::gameplay::OutboundFragment, kRollingFragmentCapacity> planned{};
    std::size_t count{};
    if (!detail::plan_reliable_message(id, declaredSize, body, bodyBits,
        framing, planned, count)) {
        return false;
    }
    staged_ = planned;
    stagedCount_ = count;
    refill();
    return true;
}

bool RollingReliableOutbox::begin_packet(std::uint16_t packetSequence) noexcept {
    if (queue_.count == 0 || queue_.awaitingAcknowledgement
        || packetSequence >= state::gameplay::kPacketSequenceModulus) {
        return false;
    }
    queue_.sentInPacket = packetSequence;
    queue_.sentCount = 1;
    queue_.awaitingAcknowledgement = true;
    return true;
}

std::size_t RollingReliableOutbox::acknowledge(const AckState& ack) noexcept {
    const std::size_t retired = retire_acknowledged_prefix(queue_, ack);
    if (retired != 0) refill();
    return retired;
}

void RollingReliableOutbox::reset() noexcept { *this = {}; }

void RollingReliableOutbox::refill() noexcept {
    while (queue_.count < queue_.fragments.size() && stagedHead_ < stagedCount_) {
        detail::append_planned_fragment(queue_, staged_[stagedHead_]);
        staged_[stagedHead_++] = {};
    }
    if (stagedHead_ == stagedCount_) stagedHead_ = stagedCount_ = 0;
}

} // namespace dawn::middleware::gameplay::peer
