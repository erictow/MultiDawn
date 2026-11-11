#include "legacy_des_cbc.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <limits>

namespace dawn::middleware::crypto::legacy_des {
namespace {

[[nodiscard]] bool succeeded(NTSTATUS status) noexcept { return status >= 0; }

class Key final {
public:
    explicit Key(std::span<const std::byte> bytes) noexcept {
        if (!succeeded(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_DES_ALGORITHM, nullptr, 0))) {
            algorithm_ = nullptr;
            return;
        }
        auto* mode = reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC));
        if (!succeeded(BCryptSetProperty(algorithm_, BCRYPT_CHAINING_MODE, mode,
                                         sizeof(BCRYPT_CHAIN_MODE_CBC), 0))
            || !succeeded(BCryptGenerateSymmetricKey(algorithm_, &key_, nullptr, 0,
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data())),
                static_cast<ULONG>(bytes.size()), 0))) {
            if (key_ != nullptr) { BCryptDestroyKey(key_); }
            key_ = nullptr;
        }
    }
    ~Key() noexcept {
        if (key_ != nullptr) { BCryptDestroyKey(key_); }
        if (algorithm_ != nullptr) { BCryptCloseAlgorithmProvider(algorithm_, 0); }
    }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    [[nodiscard]] BCRYPT_KEY_HANDLE handle() const noexcept { return key_; }
private:
    BCRYPT_ALG_HANDLE algorithm_{};
    BCRYPT_KEY_HANDLE key_{};
};

[[nodiscard]] bool transform(bool decrypting, std::span<const std::byte> key,
                              std::span<const std::byte> iv,
                              std::span<const std::byte> input,
                              std::span<std::byte> output) noexcept {
    if (key.size() != kKeySize || iv.size() != kBlockSize || input.empty()
        || input.size() % kBlockSize != 0 || output.size() < input.size()
        || input.size() > (std::numeric_limits<ULONG>::max)()) { return false; }
    const Key opened{key};
    if (opened.handle() == nullptr) { return false; }
    std::array<std::byte, kBlockSize> vector{};
    std::copy(iv.begin(), iv.end(), vector.begin());
    ULONG produced = 0;
    const auto operation = decrypting ? &BCryptDecrypt : &BCryptEncrypt;
    const NTSTATUS status = operation(opened.handle(),
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(input.data())),
        static_cast<ULONG>(input.size()), nullptr,
        reinterpret_cast<PUCHAR>(vector.data()), static_cast<ULONG>(vector.size()),
        reinterpret_cast<PUCHAR>(output.data()), static_cast<ULONG>(input.size()), &produced, 0);
    SecureZeroMemory(vector.data(), vector.size());
    return succeeded(status) && produced == input.size();
}
} // namespace

bool encrypt(std::span<const std::byte> key, std::span<const std::byte> iv,
              std::span<const std::byte> input, std::span<std::byte> output) noexcept {
    return transform(false, key, iv, input, output);
}

bool decrypt(std::span<const std::byte> key, std::span<const std::byte> iv,
              std::span<const std::byte> input, std::span<std::byte> output) noexcept {
    return transform(true, key, iv, input, output);
}
} // namespace dawn::middleware::crypto::legacy_des
