#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "../../../state/gameplay/definition.h"
#include "established_packet.h"
#include "rolling_reliable_limits.h"

namespace dawn::middleware::gameplay::peer {

/** One message reassembled from a contiguous run of fragments. */
struct AssembledMessage {
    std::array<std::byte, state::gameplay::kReassemblyCapacity> bytes{};
    /** Message bits, before the inner header is read. */
    std::size_t bitCount{};
    std::uint8_t id{};
    /** Decoded C-structure size the registry declares for that id. */
    std::uint32_t declaredSize{};
    /** Body bit offset, just after the inner header. */
    std::size_t bodyBitOffset{};
};

/**
 * Files one packet's records into a queue.
 * A record outside the buffered window is dropped. The sender retransmits it once the window
 * moves, so a queue that never drains shows up only as a rising drop count.
 * @param records Records the packet carried, in wire order.
 * @param queue Queue receiving them.
 * @return How many records the window refused.
 */
std::size_t accept_records(const QueueRecords& records,
                           state::gameplay::ReliableQueue& queue) noexcept;

/**
 * Takes the next complete message off a queue.
 * A message is a contiguous run of fragments ending in a short one. An incomplete run stays
 * buffered until its missing fragment arrives.
 * @param queue Queue to drain.
 * @param output Receives the message and its decoded inner header.
 * @return True when one whole message was drained.
 */
[[nodiscard]] bool drain_message(state::gameplay::ReliableQueue& queue,
                                 AssembledMessage& output) noexcept;

struct RollingAssembledMessage {
    std::array<std::byte, kRollingFramedCapacity> bytes{};
    std::size_t bitCount{};
    std::uint8_t id{};
    std::uint32_t declaredSize{};
    std::size_t bodyBitOffset{};
};

enum class RollingDrainResult : std::uint8_t { pending, complete, refused };

/**
 * Offline large-queue receiver. Moves a contiguous prefix out of the existing
 * reorder window before the terminal record arrives. Caller owns the exact link
 * lifetime and packet acknowledgement. The dropped count includes both past
 * retransmits and records beyond the reorder window. An oversized or malformed
 * assembled run fences this receiver until reset. No live receive path uses it.
 */
class RollingReliableInbox final {
public:
    [[nodiscard]] bool reset(std::uint16_t firstSequence = state::gameplay::kFirstMessageSequence) noexcept;
    [[nodiscard]] bool accept(const QueueRecords& records, std::size_t& dropped) noexcept;
    [[nodiscard]] RollingDrainResult drain(RollingAssembledMessage& output) noexcept;

private:
    state::gameplay::ReliableQueue queue_{{}, state::gameplay::kFirstMessageSequence, true};
    RollingAssembledMessage pending_{};
    bool refused_{};
};

} // namespace dawn::middleware::gameplay::peer
