#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

#include "native_replication_observer.h"
#include "../../../state/gameplay/replication_roles.h"

namespace dawn::client::hooks::bootflow::replication_bindings {
struct Binding {
    std::uintptr_t manager{}, peer{};
    std::uint32_t index{};
    friend constexpr bool operator==(const Binding&, const Binding&) noexcept = default;
};

class Excluded final {
public:
    using WorldConnection = native_replication_observer::WorldConnection;
    using Address = state::gameplay::replication::Address;

    [[nodiscard]] bool remember(Binding binding,std::uintptr_t nativeSlot,std::uint32_t nativeMask) noexcept {
        if(!binding.manager || !binding.peer || binding.index>=31 || nativeSlot || (nativeMask&(1U<<binding.index)))return false;
        if (const auto existing = find(binding.manager, binding.index); existing != used_)
            return rows_[existing].binding == binding;
        if(used_==rows_.size())return false;
        rows_[used_++] = {binding};
        return true;
    }

    // Only an earlier exclusion can suppress removal. An occupied/rebound native
    // slot is forwarded normally, even if stale local bookkeeping exists.
    [[nodiscard]] bool remove(std::uintptr_t manager,std::uint32_t index,std::uintptr_t nativeSlot,std::uint32_t nativeMask) noexcept {
        const auto entry = find(manager, index);
        if (entry == used_) return false;
        rows_[entry] = rows_[--used_];
        rows_[used_] = {};
        return !nativeSlot && index<31 && !(nativeMask&(1U<<index));
    }

    [[nodiscard]] std::size_t size() const noexcept {return used_;}

    /** Stage the exact exclusion, pending the enclosing native connect's result. */
    [[nodiscard]] std::uint64_t stage_world(Binding binding, std::uint64_t creator,
        std::uint64_t control, std::uint64_t epoch, const Address& address) noexcept {
        const auto entry = find(binding.manager, binding.index);
        if (entry == used_ || rows_[entry].binding != binding) return 0;
        auto& row = rows_[entry];
        clear_world(row);
        if (creator == 0 || control == 0 || creator == control || epoch == 0
            || worldGeneration_ == UINT64_MAX) return 0;
        row.world = {creator, control, epoch, ++worldGeneration_};
        row.address = address;
        return row.world.generation;
    }

    /** A late completion cannot attach itself to a reused native facet slot. */
    void complete_world(Binding binding, std::uint64_t generation, bool accepted) noexcept {
        const auto entry = find(binding.manager, binding.index);
        if (entry == used_ || rows_[entry].binding != binding || generation == 0
            || rows_[entry].world.generation != generation) return;
        if (accepted) rows_[entry].accepted = true;
        else clear_world(rows_[entry]);
    }

    void invalidate_world(std::uintptr_t manager, std::uint32_t index) noexcept {
        const auto entry = find(manager, index);
        if (entry != used_) clear_world(rows_[entry]);
    }

    void clear_world_observations() noexcept {
        for (std::size_t index = 0; index < used_; ++index) clear_world(rows_[index]);
    }

    /** Caller holds the binding lock and separately checks the copied control address/epoch. */
    [[nodiscard]] bool snapshot_world(std::uint64_t creator, std::uint64_t control,
        WorldConnection& output, Address& address) const noexcept {
        output = {};
        address = {};
        const Row* match = nullptr;
        for (std::size_t index = 0; index < used_; ++index) {
            const auto& row = rows_[index];
            if (row.world.generation == 0 || row.world.creatorMachineId != creator
                || row.world.controlMachineId != control) continue;
            if (match != nullptr || !row.accepted) return false;
            match = &row;
        }
        if (match == nullptr) return false;
        output = match->world;
        address = match->address;
        return true;
    }

private:
    struct Row {
        Binding binding{};
        WorldConnection world{};
        Address address{};
        bool accepted{};
    };
    std::array<Row, 128> rows_{};
    std::size_t used_{};
    std::uint64_t worldGeneration_{};

    [[nodiscard]] std::size_t find(std::uintptr_t manager, std::uint32_t index) const noexcept {
        for (std::size_t offset = 0; offset < used_; ++offset)
            if (rows_[offset].binding.manager == manager && rows_[offset].binding.index == index) return offset;
        return used_;
    }

    static void clear_world(Row& row) noexcept {
        row.world = {};
        row.address = {};
        row.accepted = false;
    }
};
}
