#include "replicate_membership.h"

namespace dawn::middleware::bap::activity_message::replicate_membership {
namespace {

static_assert(kMeaningfulBitCount == kEncodedSize * 8U);

} // namespace

/** Encodes one fixed full-player membership snapshot without allocation. */
bool encode_replicate_membership(const MembershipSnapshot& snapshot,
                                 std::span<std::byte> output,
                                 std::size_t& written) noexcept {
    written = 0;
    const std::size_t size = encoded_size(snapshot);
    if (output.size() < size || !valid(snapshot)) {
        return false;
    }

    encoding::bits::Writer writer(output.first(size));
    const std::uint32_t memberMask = member_mask(snapshot);
    const bool encoded = writer.write(1, 1) && writer.write(snapshot.revision, 32)
                         && writer.write(snapshot.epoch, 32)
                         && write_member_table(writer, snapshot) && writer.write(1, 1)
                         && write_region_block(writer, snapshot) && writer.write(1, 1)
                         && writer.write(memberMask, 32) && writer.write(1, 1)
                         && writer.write(memberMask, 32) && writer.write(0, 1)
                         && writer.write(0, 1) && writer.write(0, 1);
    std::size_t encodedSize = 0;
    const std::size_t meaningfulBits = meaningful_bits(snapshot);
    if (!encoded || writer.bit_count() != meaningfulBits || !writer.finish(encodedSize)
        || encodedSize != size) {
        return false;
    }

    written = encodedSize;
    return true;
}

} // namespace dawn::middleware::bap::activity_message::replicate_membership
