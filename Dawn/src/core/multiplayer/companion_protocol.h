#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace dawn::core::multiplayer::protocol {

inline constexpr std::size_t kMaximumMessage = 1024;
inline constexpr std::uint32_t kVersion = 1;

/** A bounded local IPC message. No game packet or account data crosses this channel. */
struct Message {
    std::array<char, kMaximumMessage + 1> bytes{};
    std::size_t size{};
    [[nodiscard]] std::string_view view() const noexcept { return {bytes.data(), size}; }
};

[[nodiscard]] inline bool decimal(std::string_view text, std::uint64_t& output) noexcept {
    if (text.empty() || text.size() > 20) return false;
    std::uint64_t value = 0;
    for (const char byte : text) {
        if (byte < '0' || byte > '9') return false;
        const auto digit = static_cast<std::uint64_t>(byte - '0');
        if (value > (UINT64_MAX - digit) / 10) return false;
        value = value * 10 + digit;
    }
    output = value;
    return true;
}

[[nodiscard]] inline unsigned hex_digit(char byte) noexcept {
    return byte >= '0' && byte <= '9' ? static_cast<unsigned>(byte - '0')
         : byte >= 'A' && byte <= 'F' ? static_cast<unsigned>(byte - 'A') + 10U : 16U;
}

/** Empty fields use '-', so splitting by spaces never changes their position. */
[[nodiscard]] inline bool decode_text(std::string_view hex, std::span<char> output) noexcept {
    if (output.empty()) return false;
    if (hex == "-") { output[0] = '\0'; return true; }
    if (hex.empty() || hex.size() % 2 != 0 || hex.size() / 2 >= output.size()) return false;
    for (std::size_t index = 0; index < hex.size() / 2; ++index) {
        const unsigned high = hex_digit(hex[index * 2]);
        const unsigned low = hex_digit(hex[index * 2 + 1]);
        if (high > 15 || low > 15) return false;
        const auto value = static_cast<unsigned char>((high << 4U) | low);
        // Steam names and connect strings in this shim are printable ASCII.
        if (value < 32 || value > 126) return false;
        output[index] = static_cast<char>(value);
    }
    output[hex.size() / 2] = '\0';
    return true;
}

[[nodiscard]] inline bool append(Message& message, std::string_view text) noexcept {
    if (text.size() > kMaximumMessage - message.size) return false;
    for (const char value : text) message.bytes[message.size++] = value;
    message.bytes[message.size] = '\0';
    return true;
}

[[nodiscard]] inline bool append_hex(Message& message, std::string_view text) noexcept {
    if (text.empty()) return append(message, "-");
    if (text.size() > (kMaximumMessage - message.size) / 2) return false;
    constexpr char digits[] = "0123456789ABCDEF";
    for (const char value : text) {
        const auto byte = static_cast<unsigned char>(value);
        if (byte < 32 || byte > 126) return false;
        message.bytes[message.size++] = digits[byte >> 4U];
        message.bytes[message.size++] = digits[byte & 15U];
    }
    message.bytes[message.size] = '\0';
    return true;
}

struct Fields {
    std::array<std::string_view, 8> values{};
    std::size_t count{};
};

[[nodiscard]] inline bool split(std::string_view text, Fields& result) noexcept {
    result = {};
    if (text.empty() || text.size() > kMaximumMessage) return false;
    while (!text.empty()) {
        if (result.count == result.values.size()) return false;
        const std::size_t end = text.find(' ');
        const auto field = text.substr(0, end);
        if (field.empty()) return false;
        for (const char byte : field) if (byte < 33 || byte > 126) return false;
        result.values[result.count++] = field;
        if (end == std::string_view::npos) return true;
        text.remove_prefix(end + 1);
        if (text.empty()) return false;
    }
    return false;
}

[[nodiscard]] inline bool steam_identity(std::uint64_t id) noexcept {
    return (id & 0xFFFFFFFF00000000ULL) == 0x0110000100000000ULL && (id & 0xFFFFFFFFULL) != 0;
}

/** Named pipe identifiers and nonces cannot redirect a client onto another machine. */
[[nodiscard]] inline bool identifier(std::wstring_view value) noexcept {
    if (value.size() != 32) return false;
    for (const wchar_t byte : value) if (!((byte >= L'0' && byte <= L'9') || (byte >= L'a' && byte <= L'f'))) return false;
    return true;
}

} // namespace dawn::core::multiplayer::protocol
