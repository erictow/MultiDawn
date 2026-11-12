#include "native_identity_observation.h"

#include <Windows.h>
#include <array>
#include <cstdio>
#include <cstring>

#include "../../../core/logging/log.h"

namespace dawn::client::hooks::bootflow::native_identity_observation {
namespace {
namespace observation = core::multiplayer::identity_observation;
SRWLOCK g_lock{};
observation::Collector g_collector{};
observation::DiagnosticEvents g_diagnostics{};

/** Match the same three build-86657 layout anchors as the read-only snapshot tool. */
[[nodiscard]] bool layout_matches() noexcept {
    const auto* image = reinterpret_cast<const std::byte*>(GetModuleHandleW(nullptr));
    if (image == nullptr) return false;
    constexpr std::array<unsigned char, 16> decode{0x48,0x8B,0xC4,0x53,0x41,0x56,0x48,0x83,0xEC,0x78,0x48,0x89,0x68,0x08,0x4D,0x8B};
    constexpr std::array<unsigned char, 24> activate{0x48,0x89,0x5C,0x24,0x18,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0x40,0xFD,0xFF,0xFF};
    constexpr std::array<unsigned char, 23> migration{0x40,0x55,0x53,0x56,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0x80,0xFC,0xFF,0xFF,0x48,0x81,0xEC,0x80,0x04,0x00,0x00};
    __try {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0
            || dos->e_lfanew > 0x100000) return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
            && nt->OptionalHeader.SizeOfImage >= 0x1796000 + migration.size()
            && std::memcmp(image + 0x173BFC0, decode.data(), decode.size()) == 0
            && std::memcmp(image + 0x177E940, activate.data(), activate.size()) == 0
            && std::memcmp(image + 0x1796000, migration.data(), migration.size()) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

[[nodiscard]] bool read_scalar(void* context, std::size_t offset, std::span<std::byte> output) noexcept {
    const auto address = reinterpret_cast<std::uintptr_t>(context);
    if (address < 0x10000 || address > 0x7FFFFFFFFFFFULL - observation::kRoleOffset - 4
        || offset > observation::kRoleOffset || output.empty() || output.size() > 8) return false;
    __try {
        std::memcpy(output.data(), reinterpret_cast<const void*>(address + offset), output.size());
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
} // namespace

bool enabled() noexcept {
    static const bool value = []() noexcept {
        std::array<wchar_t, 2> text{};
        return GetEnvironmentVariableW(L"DAWN_NATIVE_IDENTITY_OBSERVATION", text.data(),
            static_cast<DWORD>(text.size())) == 1 && text[0] == L'1' && layout_matches();
    }();
    return value;
}

void observe(std::byte* manager) noexcept {
    if (!enabled() || manager == nullptr) return;
    AcquireSRWLockShared(&g_lock);
    const auto token = g_collector.capture_token();
    ReleaseSRWLockShared(&g_lock);
    if (token == 0) return;
    observation::Sample sample{};
    const bool valid = observation::capture(&read_scalar, manager, sample);
    observation::Observation current{};
    bool report{};
    AcquireSRWLockExclusive(&g_lock);
    const auto now = GetTickCount64();
    const auto address = reinterpret_cast<std::uintptr_t>(manager);
    if (g_collector.publish(token, address, valid ? &sample : nullptr, now)
        && g_collector.snapshot(sample.role, now, current) && current.manager == address)
        report = g_diagnostics.changed(current);
    ReleaseSRWLockExclusive(&g_lock);
    if (report) {
        std::array<char, 256> line{};
        const int count = std::snprintf(line.data(), line.size(),
            "ev=native_identity_observation pid=%lu role=%d mode=%d member_mask=0x%08X player_mask=0x%08X fingerprint=0x%016llX",
            static_cast<unsigned long>(GetCurrentProcessId()), current.sample.role, current.sample.mode,
            current.sample.memberMask, current.sample.playerMask,
            static_cast<unsigned long long>(observation::fingerprint(current.sample)));
        if (count > 0 && static_cast<std::size_t>(count) < line.size())
            core::log::write(core::log::Channel::client, core::log::Level::info,
                {line.data(), static_cast<std::size_t>(count)});
    }
}

bool snapshot(std::int32_t managedRole, std::uint64_t now, observation::Observation& output) noexcept {
    output = {};
    if (!enabled()) return false;
    AcquireSRWLockShared(&g_lock);
    const bool found = g_collector.snapshot(managedRole, now, output);
    ReleaseSRWLockShared(&g_lock);
    return found;
}

bool collect(std::span<observation::Observation> output, std::uint64_t now, std::size_t& count) noexcept {
    count = 0;
    for (auto& value : output) value = {};
    if (!enabled()) return false;
    AcquireSRWLockShared(&g_lock);
    const bool found = g_collector.collect(output, now, count);
    ReleaseSRWLockShared(&g_lock);
    return found;
}

void start() noexcept {
    const bool active = enabled();
    AcquireSRWLockExclusive(&g_lock);
    if (active) g_collector.start();
    else g_collector.stop();
    g_diagnostics.reset();
    ReleaseSRWLockExclusive(&g_lock);
}

void reset() noexcept {
    AcquireSRWLockExclusive(&g_lock);
    g_collector.stop();
    g_diagnostics.reset();
    ReleaseSRWLockExclusive(&g_lock);
}

} // namespace dawn::client::hooks::bootflow::native_identity_observation
