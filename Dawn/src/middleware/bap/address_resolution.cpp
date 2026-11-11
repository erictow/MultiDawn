#include "address_resolution.h"

#include <algorithm>

#include "../encoding/byte_order.h"

namespace dawn::middleware::bap::address_resolution {
namespace {

// Recovered from exact build 86657: BAP300 serializer RVA E0C2C0 and BAP301
// parser RVA E0AF80. This is a body codec, not an authenticated backend route.
// E0AF80 permits port/tag zero. The final route tag is consumed by the wrapped
// UDP path at 17CC020; it is unrelated to the IP byte-count selector.
constexpr std::size_t kResponseAddressLength = 24;
constexpr std::size_t kResponseAddress = 26;
constexpr std::size_t kResponseC = 112;
constexpr std::size_t kResponseD = 114;
constexpr std::size_t kResponseE = 130;
constexpr std::size_t kResponseF = 138;
constexpr std::size_t kResponsePort = 154;
constexpr std::size_t kResponseIpLength = 156;
constexpr std::size_t kResponseIp = 158;

[[nodiscard]] bool known_method(const NetAddr& address) noexcept {
    return std::to_integer<unsigned>(address.back()) <= 7;
}

template <std::size_t Count>
void read_bytes(std::span<const std::byte> source,
                std::size_t offset,
                std::array<std::byte, Count>& output) noexcept {
    std::copy_n(source.begin() + offset, Count, output.begin());
}

template <std::size_t Count>
void write_bytes(std::span<std::byte> output,
                 std::size_t offset,
                 const std::array<std::byte, Count>& source) noexcept {
    std::copy(source.begin(), source.end(), output.begin() + offset);
}

} // namespace

bool parse_request(std::span<const std::byte> input, Request& output) noexcept {
    if (input.size() != kRequestSize || encoding::read_u16_be(input.first<2>()) != kNetAddrSize) {
        return false;
    }
    Request candidate{};
    read_bytes(input, 2, candidate.address);
    if (!known_method(candidate.address)) { return false; }
    candidate.capability = encoding::read_u16_be(input.subspan<88, 2>());
    candidate.kind = encoding::read_u16_be(input.subspan<90, 2>());
    const std::uint16_t expected = std::to_integer<unsigned>(candidate.address.back()) < 6 ? 1 : 2;
    if (candidate.kind != expected) { return false; }
    output = candidate;
    return true;
}

bool encode_response(const Response& response,
                      std::span<std::byte> output,
                      std::size_t& written) noexcept {
    written = 0;
    if (!known_method(response.address)) { return false; }
    std::uint16_t ipSize{};
    switch (response.family) {
    case IpFamily::ipv4: ipSize = 4; break;
    case IpFamily::ipv6: ipSize = 16; break;
    default: return false;
    }
    const std::size_t size = kResponseIp + ipSize + sizeof(std::uint32_t);
    if (output.size() < size) { return false; }
    // Stage before touching the caller's output. This also permits output to
    // overlap response storage without corrupting a later source field.
    std::array<std::byte, kIpv6ResponseSize> bytes{};
    const std::span body(bytes);
    write_bytes(body, 0, response.material.a);
    write_bytes(body, 16, response.material.b);
    encoding::write_u16_be(body.subspan<kResponseAddressLength, 2>(), static_cast<std::uint16_t>(kNetAddrSize));
    write_bytes(body, kResponseAddress, response.address);
    encoding::write_u16_be(body.subspan<kResponseC, 2>(), response.valueC);
    write_bytes(body, kResponseD, response.material.d);
    write_bytes(body, kResponseE, response.material.e);
    write_bytes(body, kResponseF, response.material.f);
    encoding::write_u16_be(body.subspan<kResponsePort, 2>(), response.port);
    encoding::write_u16_be(body.subspan<kResponseIpLength, 2>(), ipSize);
    std::copy_n(response.ip.begin(), ipSize, body.begin() + kResponseIp);
    encoding::write_u32_be(std::span<std::byte, 4>(body.data() + kResponseIp + ipSize, 4), response.routeTag);
    std::copy_n(body.begin(), size, output.begin());
    written = size;
    return true;
}

bool parse_response(std::span<const std::byte> input, Response& output) noexcept {
    if ((input.size() != kIpv4ResponseSize && input.size() != kIpv6ResponseSize)
        || encoding::read_u16_be(input.subspan<kResponseAddressLength, 2>()) != kNetAddrSize) {
        return false;
    }
    const auto ipSize = encoding::read_u16_be(input.subspan<kResponseIpLength, 2>());
    if ((ipSize != 4 && ipSize != 16)
        || input.size() != kResponseIp + ipSize + sizeof(std::uint32_t)) { return false; }
    Response candidate{};
    read_bytes(input, kResponseAddress, candidate.address);
    if (!known_method(candidate.address)) { return false; }
    read_bytes(input, 0, candidate.material.a);
    read_bytes(input, 16, candidate.material.b);
    candidate.valueC = encoding::read_u16_be(input.subspan<kResponseC, 2>());
    read_bytes(input, kResponseD, candidate.material.d);
    read_bytes(input, kResponseE, candidate.material.e);
    read_bytes(input, kResponseF, candidate.material.f);
    candidate.port = encoding::read_u16_be(input.subspan<kResponsePort, 2>());
    candidate.family = ipSize == 4 ? IpFamily::ipv4 : IpFamily::ipv6;
    std::copy_n(input.begin() + kResponseIp, ipSize, candidate.ip.begin());
    candidate.routeTag = encoding::read_u32_be(std::span<const std::byte, 4>(input.data() + kResponseIp + ipSize, 4));
    output = candidate;
    return true;
}

} // namespace dawn::middleware::bap::address_resolution
