#include "../src/middleware/crypto/legacy_des_cbc.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>

namespace {
unsigned checks{};
void check(bool value, const char* label) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL: %s\n", label); std::exit(1); }
}
template<std::size_t Size> std::array<std::byte, Size> hex(std::string_view text) {
    std::array<std::byte, Size> result{};
    const auto digit = [](char value) { return value <= '9' ? value - '0' : value - 'a' + 10; };
    for (std::size_t i = 0; i < Size; ++i) {
        result[i] = static_cast<std::byte>((digit(text[i * 2]) << 4) | digit(text[i * 2 + 1]));
    }
    return result;
}
}

int main() {
    namespace des = dawn::middleware::crypto::legacy_des;
    const auto key = hex<8>("0123456789abcdef");
    const auto iv = hex<8>("1234567890abcdef");
    const auto plain = hex<24>("4e6f77206973207468652074696d6520666f7220616c6c20");
    // Independently verified with OpenSSL 3.5.9's legacy DES-CBC provider,
    // using no salt or padding and these public fixture key/IV bytes.
    const auto cipher = hex<24>("e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6");
    std::array<std::byte, 24> result{};
    check(des::encrypt(key, iv, plain, result) && result == cipher, "independent DES-CBC vector");
    check(des::decrypt(key, iv, cipher, result) && result == plain, "independent decrypt vector");
    result = plain;
    check(des::encrypt(key, iv, result, result) && result == cipher, "in-place encrypt");
    check(des::decrypt(key, iv, result, result) && result == plain, "in-place decrypt");
    check(key == hex<8>("0123456789abcdef") && iv == hex<8>("1234567890abcdef"), "fixture key and IV unchanged");
    result.fill(std::byte{0x5A});
    const auto unchanged = result;
    for (std::size_t length = 0; length < 24; ++length) {
        if (length == 8 || length == 16) { continue; }
        check(!des::encrypt(key, iv, std::span(plain).first(length), result), "reject non-block input");
        check(result == unchanged, "invalid input leaves output untouched");
    }
    check(!des::encrypt(std::span(key).first(7), iv, plain, result), "reject short key");
    check(!des::decrypt(key, std::span(iv).first(7), cipher, result), "reject short IV");
    check(!des::encrypt(key, iv, plain, std::span(result).first(23)), "reject short output");
    check(result == unchanged, "validation failures leave output untouched");
    std::printf("PASS: %u legacy DES-CBC compatibility checks\n", checks);
}
