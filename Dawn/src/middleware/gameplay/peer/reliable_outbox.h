#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "established_packet.h"

namespace dawn::middleware::gameplay::peer {

/** Covers the measured six-human membership update without changing live transport limits. */
inline constexpr std::size_t kRollingBodyCapacity = 1'048;
inline constexpr std::size_t kRollingFramedCapacity = kRollingBodyCapacity + 3;
inline constexpr std::size_t kRollingFragmentCapacity = kRollingFramedCapacity / kLargeFragmentBytes + 1;

/**
 * Stages one whole reliable message and feeds the existing prefix flight queue as ACKs retire it.
 * Experimental standalone send state. Callers must serialize access and bind ACKs to the exact
 * current peer lifetime. No receive capacity or wire-level capability is implied.
 */
class RollingReliableOutbox final {
public:
    /** A stalled suffix blocks later messages. Failure leaves the outbox unchanged. */
    [[nodiscard]] bool enqueue(std::uint8_t id, std::uint32_t declaredSize,
        std::span<const std::byte> body, std::size_t bodyBits) noexcept;

    /** Stamps one record before the first send. Retransmits retain its original ACK target. */
    [[nodiscard]] bool begin_packet(std::uint16_t packetSequence) noexcept;

    /** Retires the acknowledged prefix and copies newly unblocked records into the send queue. */
    std::size_t acknowledge(const AckState& ack) noexcept;

    [[nodiscard]] const state::gameplay::OutboundQueue& queue() const noexcept { return queue_; }
    [[nodiscard]] std::size_t pending() const noexcept { return stagedCount_ - stagedHead_; }
    void reset() noexcept;

private:
    void refill() noexcept;

    state::gameplay::OutboundQueue queue_{};
    std::array<state::gameplay::OutboundFragment, kRollingFragmentCapacity> staged_{};
    std::size_t stagedHead_{}, stagedCount_{};
};

} // namespace dawn::middleware::gameplay::peer
