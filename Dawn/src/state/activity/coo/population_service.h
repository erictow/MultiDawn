#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include "stall_diagnostics.h"

namespace dawn::state::activity::coo {
enum class Admission : std::uint8_t { ignored, accepted, overflow };
enum class EnemyIntent : std::uint8_t { combat, idleReveal };
struct EnemyPolicy final {
    bool verify{};EnemyIntent intent{};
    std::uint32_t tacticalRegistry{};std::uint16_t tacticalSlot{};std::int8_t tacticalRow{-1};
    friend bool operator==(const EnemyPolicy&,const EnemyPolicy&)=default;
};
struct EnemyReadiness final {
    bool created{},health{},ai{},tactical{};
    std::uint32_t healthHandle{UINT32_MAX},tacticalRegistry{};
    std::uint16_t tacticalSlot{};std::int8_t tacticalRow{-1};
};
struct PopulationCapacity final { bool known{};std::uint32_t used{},maximum{}; };

// The mission selects cohorts and native summon timing. This ledger owns
// admission, salted identity retention, verified deaths, and clearance joins.
template<class Receipt, std::size_t Groups, std::size_t MaximumPopulation>
class PopulationService final {
    static_assert(Groups > 0 && MaximumPopulation > 0 && MaximumPopulation <= UINT8_MAX);
    static_assert(std::is_trivially_copyable_v<Receipt>);
public:
    void policy(std::size_t index,EnemyPolicy policy) noexcept {
        if(index>=Groups || policies_[index]==policy) { return; }policies_[index]=policy;
        for(std::uint8_t n=0;n<counts_[index];++n) { actors_[index][n].ready=matches(policy,actors_[index][n].readiness); }
    }
    void capacity(PopulationCapacity value) noexcept {
        capacity_=(value.known && value.maximum>0 && value.used<=value.maximum)?value:PopulationCapacity{};
    }
    PopulationCapacity capacity() const noexcept { return capacity_; }
    bool observe(const Receipt& receipt,EnemyReadiness readiness) noexcept {
        if(!receipt.valid()) { return false; }
        for(std::size_t i=0;i<Groups;++i) for(std::uint8_t n=0;n<counts_[i];++n) {
            auto& actor=actors_[i][n];if(actor.receipt!=receipt || actor.dead) { continue; }
            // Retain readiness through later damage and intentional scene holds.
            actor.readiness=readiness;actor.ready|=matches(policies_[i],readiness);return true;
        }
        return false;
    }
    template<class Visit> void pending(Visit visit) const noexcept {
        for(std::size_t i=0;i<Groups;++i) for(std::uint8_t n=0;n<counts_[i];++n) {
            const auto& a=actors_[i][n];if(policies_[i].verify && !a.ready && !a.dead) { visit(a.receipt); }
        }
    }
    // Read-side consumers (for example occupied combat plates) need the same
    // admitted identities and terminal deaths as the clearance ledger.
    template<class Visit> void living(Visit visit) const noexcept {
        for(std::size_t i=0;i<Groups;++i) for(std::uint8_t n=0;n<counts_[i];++n) {
            const auto& actor=actors_[i][n];if(!actor.dead) {visit(actor.receipt);}
        }
    }
    bool ready(std::size_t index,std::uint8_t requested) const noexcept {
        if(!admitted(index,requested)) { return false; }
        for(std::uint8_t n=0;n<counts_[index];++n) {
            const auto& a=actors_[index][n];if(policies_[index].verify && !a.ready && !a.dead) { return false; }
        }return true;
    }
    StallDetail missing(std::size_t index,std::uint8_t requested,bool deaths) const noexcept {
        if(index>=Groups) { return {Missing::admission,{},requested,0}; }
        if(counts_[index]!=requested) { return {capacity_.known && capacity_.used==capacity_.maximum?Missing::capacity:Missing::admission,{},requested,counts_[index],capacity_.known?capacity_.maximum:0}; }
        for(std::uint8_t n=0;n<counts_[index];++n) {
            const auto& a=actors_[index][n];if(a.dead) { continue; }
            if(policies_[index].verify && !a.ready) {
                const auto& r=a.readiness;
                return {!r.created?Missing::admission:(!r.health || r.healthHandle==UINT32_MAX)?Missing::health:!r.ai?Missing::ai:Missing::tactical,{},requested,counts_[index],a.receipt.actor};
            }
        }
        if(deaths) {
            std::uint32_t dead{};for(std::uint8_t n=0;n<counts_[index];++n) { dead+=actors_[index][n].dead?1U:0U; }
            if(dead!=requested) { return {Missing::death,{},requested,dead}; }
        }return {};
    }
    void enable(std::size_t index) noexcept { if (index < Groups) { enabled_[index] = true; } }
    // Retire one source's observation lease. Native teardown is a separate
    // operation; clearing this ledger never supplies a death or a clear receipt.
    void reset_source(std::size_t index) noexcept {
        if(index>=Groups) return;
        actors_[index]={};counts_[index]=0;enabled_[index]=false;policies_[index]={};
    }
    // Explicit source recreation, not a death or an area-wide reset. The caller
    // must retire the old command generation before accepting new admissions.
    bool restart(std::size_t index) noexcept {
        if(index>=Groups || !enabled_[index]) {return false;}
        actors_[index]={};counts_[index]=0;return true;
    }
    [[nodiscard]] bool enabled(std::size_t index) const noexcept { return index < Groups && enabled_[index]; }
    template<class Catalog>
    [[nodiscard]] bool source_enabled(const Catalog& catalog, std::uint16_t source, std::uint32_t registry) const noexcept {
        if (catalog.size() != Groups) { return false; }
        for (std::size_t i = 0; i < Groups; ++i) {
            if (catalog[i].source == source && catalog[i].registry == registry && enabled_[i]) { return true; }
        }
        return false;
    }
    template<class Catalog>
    [[nodiscard]] Admission admit(const Catalog& catalog, const Receipt& receipt,
                                  std::uint64_t run, std::uint32_t generation) noexcept {
        if (!receipt.valid() || receipt.run != run || receipt.generation != generation
            || !source_enabled(catalog, receipt.source, receipt.registry)) { return Admission::ignored; }
        for (std::size_t i = 0; i < Groups; ++i) for (std::uint8_t n = 0; n < counts_[i]; ++n) {
            if (actors_[i][n].receipt.actor == receipt.actor) { return Admission::ignored; }
        }
        for (std::size_t i = 0; i < Groups; ++i) {
            const auto& group = catalog[i];
            if (group.source == receipt.source && group.registry == receipt.registry && enabled_[i]
                && counts_[i] < group.count) {
                if (counts_[i] >= MaximumPopulation) { return Admission::overflow; }
                actors_[i][counts_[i]++].receipt = receipt;
                return Admission::accepted;
            }
        }
        // Excess actors from a nonblocking cohort cannot become a kill barrier.
        for (std::size_t i = 0; i < Groups; ++i) {
            const auto& group = catalog[i];
            if (group.source == receipt.source && group.registry == receipt.registry && enabled_[i] && !group.required) {
                return Admission::ignored;
            }
        }
        return Admission::overflow;
    }
    // A verified native streaming lifetime can acquire a new salted actor. Only
    // its exact living predecessor may be replaced; genuine deaths remain terminal.
    [[nodiscard]] bool rebind(const Receipt& previous,const Receipt& replacement) noexcept {
        if(!previous.valid() || !replacement.valid() || previous==replacement
            || previous.run!=replacement.run || previous.registry!=replacement.registry || previous.source!=replacement.source) {return false;}
        for(std::size_t i=0;i<Groups;++i) for(std::uint8_t n=0;n<counts_[i];++n) {
            if(actors_[i][n].receipt.actor==replacement.actor) {return false;}
        }
        for(std::size_t i=0;i<Groups;++i) for(std::uint8_t n=0;n<counts_[i];++n) {
            auto& a=actors_[i][n];if(a.receipt!=previous || a.dead) {continue;}
            a.receipt=replacement;a.ready=false;a.readiness={};return true;
        }
        return false;
    }
    [[nodiscard]] bool died(const Receipt& receipt, std::uint64_t run, std::uint32_t generation) noexcept {
        if (!receipt.valid() || receipt.run != run || receipt.generation != generation) { return false; }
        for (std::size_t i = 0; i < Groups; ++i) for (std::uint8_t n = 0; n < counts_[i]; ++n) {
            if (actors_[i][n].receipt == receipt) {
                if (actors_[i][n].dead) { return false; }
                actors_[i][n].dead = true; return true;
            }
        }
        return false;
    }
    [[nodiscard]] bool admitted(std::size_t index, std::uint8_t requested) const noexcept {
        return index < Groups && enabled_[index] && counts_[index] == requested;
    }
    [[nodiscard]] bool cleared(std::size_t index, std::uint8_t requested) const noexcept {
        if (index >= Groups || !enabled_[index] || counts_[index] != requested) { return false; }
        for (std::uint8_t n = 0; n < counts_[index]; ++n) { if (!actors_[index][n].dead) { return false; } }
        return true;
    }
private:
    static bool matches(const EnemyPolicy& p,const EnemyReadiness& r) noexcept {
        return r.created && r.health && r.healthHandle!=UINT32_MAX && r.ai
            && (p.intent==EnemyIntent::idleReveal || (r.tactical && r.tacticalRegistry==p.tacticalRegistry
                && r.tacticalSlot==p.tacticalSlot && r.tacticalRow==p.tacticalRow));
    }
    struct Actor final { Receipt receipt{}; bool dead{},ready{};EnemyReadiness readiness{}; };
    std::array<std::array<Actor, MaximumPopulation>, Groups> actors_{};
    std::array<std::uint8_t, Groups> counts_{};
    std::array<bool, Groups> enabled_{};
    std::array<EnemyPolicy,Groups> policies_{};
    PopulationCapacity capacity_{};
};
} // namespace dawn::state::activity::coo
