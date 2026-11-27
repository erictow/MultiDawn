#pragma once
#include "adventure_authored_overlay.h"
#include "adventure_native_bridge.h"
#include "adventure_dialogue_bridge.h"
#include "adventure_start_plan.h"
#include "adventure_gateway_service.h"
#include "../../../state/activity/coo/mission_script.h"

namespace dawn::server::runtime::activity::adventure {
namespace coo=state::activity::coo;
struct OpeningBinding final {
    std::int16_t activity{-1};std::string_view role;
    const authored_overlay::Binding* overlay{};
    cue_feedback::Ticket cue{}; // Immutable authored fields; lifetime fields are filled by the owner.
    dialogue_feedback::Authored dialogue{};
    const gateway::Binding* gateway{};
};
struct OpeningFrame final {
    const OpeningBinding* binding{};
    cue_feedback::wire::Request cue{};
    bool requested{},nativeReady{},conflictingSelection{};
    dialogue_feedback::wire::Request dialogue{};
    bool dialogueRequested{},dialogueSubmitted{};
    bool gatewayRequested{};
};
// One selected opening overlay retained by its existing persistent-world owner.
// The immutable definition selects a shared executor graph. Publication and
// native presentation acceptance remain separate; graph completion here means
// only that its opening cue was accepted, never Adventure completion.
class OpeningRuntime final {
public:
    template<class Activity,class Document>
    [[nodiscard]] static bool valid(const Activity& activity,const Document& document) noexcept {
        if(activity.adventureOpenings.size()>3)return false;
        for(std::size_t i=0;i<activity.adventureOpenings.size();++i) {
            const auto& b=activity.adventureOpenings[i];const auto* o=b.overlay;
            if(!o || b.activity<0 || b.role.empty() || o->bubble!=activity.bubble
                || !authored_overlay::valid(o->root) || !authored_overlay::valid(o->local)
                || b.cue.request.registry!=o->root.key || b.cue.request.ring!=0
                || b.cue.nativeScope!=UINT32_MAX || b.cue.activity!=b.activity)return false;
            auto ticket=b.cue;ticket.owner={1,{1}};ticket.boot=1;ticket.definitionRevision=1;ticket.selectionRevision=1;
            if(!cue_feedback::valid(ticket))return false;
            unsigned slots{};for(const auto& slot:o->root.slots)
                if(slot.index==b.cue.request.slot && slot.type==68 && slot.componentClass==0x80804F53
                    && slot.authSchema==0x80804F67 && slot.descriptorTag==b.cue.definition)++slots;
            if(slots!=1)return false;
            const auto* graph=document.views().role(b.role);
            if(!graph || graph->domain!="adventureOpening" || graph->definition.schema!=activity.profile->schema
                || !coo::Executor::valid(graph->definition) || graph->definition.steps.size()!=(b.gateway?2U:1U)
                || graph->definition.steps[0].commands.size()!=(b.dialogue.definition?2U:1U))return false;
            const auto& c=graph->definition.steps[0].commands[0];
            if(c.operation!=coo::Operation::objective || c.wait!=coo::Wait::nativeReady
                || c.asset!=coo::Asset{o->root.key,b.cue.definition,68,b.cue.request.slot}
                || c.argument!=b.cue.request.event)return false;
            if(b.dialogue.definition) {
                if(!dialogue_feedback::valid(b.dialogue))return false;
                unsigned voiceSlots{};
                for(const auto& slot:o->root.slots)if(slot.index==2 && slot.type==53 && slot.componentClass==0x80804F4B
                    && slot.authSchema==0x80804F77 && slot.descriptorTag==b.dialogue.definition)++voiceSlots;
                const auto& voice=graph->definition.steps[0].commands[1];
                if(voiceSlots!=1 || voice.operation!=coo::Operation::dialogue || voice.wait!=coo::Wait::nativeReady
                    || voice.asset!=coo::Asset{o->root.key,b.dialogue.definition,53,2} || voice.argument!=b.dialogue.selector)return false;
            }
            if(b.gateway) {
                if(!gateway::valid(*b.gateway,*o))return false;
                const auto& step=graph->definition.steps[1];
                if(step.dependencies!=1 || step.commands.size()!=3)return false;
                for(std::size_t j=0;j<2;++j) {
                    const auto& endpoint=b.gateway->endpoints[j];const auto& command=step.commands[j];
                    if(command.operation!=coo::Operation::device || command.wait!=coo::Wait::requested
                        || command.asset!=gateway::asset(endpoint) || command.argument!=endpoint.generation)return false;
                }
                const auto& permission=step.commands[2];
                if(permission.operation!=coo::Operation::traversal || permission.wait!=coo::Wait::requested
                    || permission.asset!=gateway::asset(b.gateway->endpoints[0])
                    || permission.argument!=b.gateway->predicate)return false;
            }
            unsigned routes{};
            for(const auto& r:activity.startRoutes)if(r.activity==b.activity && r.rootPackage==activity.activity
                && r.scenario==o->hostScenario && r.bubble==o->bubble)++routes;
            if(routes!=1)return false;
            for(std::size_t j=0;j<i;++j)
                if(activity.adventureOpenings[j].activity==b.activity || activity.adventureOpenings[j].role==b.role
                    || activity.adventureOpenings[j].cue.definition==b.cue.definition)return false;
        }
        return true;
    }
    template<class Activity,class Document>
    [[nodiscard]] bool begin(cue_feedback::Owner owner,std::uint64_t boot,const Activity& activity,const Document& document) noexcept {
        if(owner_ || !owner || !boot || !valid(activity,document))return false;
        owner_=owner;boot_=boot;bindings_=activity.adventureOpenings;host_=activity.activity;
        document_=&document;return true;
    }
    [[nodiscard]] OpeningFrame update(std::uint32_t bubble,bool arrived,const adventure_start::wire::Request& selected) noexcept {
        if constexpr (!adventure_start::kLaunchesEnabled) return {};
        if (!owner_) return {};
        if(!binding_) {
            if(!arrived || selected.selection.reason!=1 || selected.selection.activityIndex!=selected.selection.sourceActivityIndex
                || !selected.hasAccount || !selected.hasNonce || !selected.revision
                || adventure_start::package(selected)!=host_)return {};
            for(const auto& b:bindings_)if(b.activity==selected.selection.activityIndex && b.overlay->bubble==bubble)binding_=&b;
            if(!binding_)return {};
            ticket_=binding_->cue;ticket_.owner=owner_;ticket_.boot=boot_;ticket_.definitionRevision=document_->fingerprint();
            ticket_.selectionRevision=selected.revision;
            if(binding_->dialogue.definition) {
                voiceTicket_.owner=owner_;voiceTicket_.boot=boot_;voiceTicket_.definitionRevision=document_->fingerprint();
                voiceTicket_.selectionRevision=selected.revision;voiceTicket_.activity=binding_->activity;voiceTicket_.authored=binding_->dialogue;
                voiceTicket_.request.registry=binding_->overlay->root.key;voiceTicket_.request.slot=2;
                voiceTicket_.request.bankRows=binding_->dialogue.bankRows;voiceTicket_.request.activeRow=binding_->dialogue.row;
                voiceTicket_.request.generations[binding_->dialogue.row]=static_cast<std::uint32_t>(selected.revision%0x7FFFFFFEULL)+1;
                if(!dialogue_feedback::valid(voiceTicket_)){failed_=true;return {};}
            }
            if(!cue_feedback::valid(ticket_) || !executor_.start(document_->views().role(binding_->role)->definition,selected.revision)) {
                failed_=true;return {};
            }
        }
        // There is no fabricated retirement for an unimplemented return/switch.
        // Keep already-published descriptors/authority attached to their lease.
        if(selected.selection.activityIndex!=binding_->activity || selected.revision!=ticket_.selectionRevision)
            conflicting_=true;
        std::array<native_bridge::Event,1> observations{};
        const auto n=native_bridge::drain(ticket_,observations);
        for(std::size_t i=0;i<n;++i) {
            if(observations[i].observation.ticket!=ticket_ || observations[i].binding.ticket!=ticket_
                || !requested_ || !executor_.enqueue({token_,coo::Milestone::nativeReady})) {failed_=true;continue;}
            ready_=true;
        }
        std::array<dialogue_bridge::Event,1> voiceObservations{};
        const auto voiceCount=dialogue_bridge::drain(voiceTicket_,voiceObservations);
        for(std::size_t i=0;i<voiceCount;++i) {
            if(voiceObservations[i].observation.ticket!=voiceTicket_ || voiceObservations[i].binding.ticket!=voiceTicket_
                || !voiceRequested_ || !executor_.enqueue({voiceToken_,coo::Milestone::nativeReady})) {failed_=true;continue;}
            voiceSubmitted_=true;
        }
        if(!failed_ && !conflicting_ && arrived && bubble==binding_->overlay->bubble) {
            Driver driver(*this);executor_.update(driver);
            if(executor_.diagnostics().phase==coo::Phase::failed)failed_=true;
        }
        return frame();
    }
    [[nodiscard]] OpeningFrame frame() const noexcept {
        if(!binding_)return {};
        auto voice=voiceTicket_.request;if(voiceSubmitted_)voice.activeRow=dialogue_feedback::wire::kNoRow;
        return {binding_,ticket_.request,requested_,ready_,conflicting_,voice,voiceRequested_,voiceSubmitted_,
            gatewayDevices_==3 && gatewayPermission_ && ready_ && (!binding_->dialogue.definition || voiceSubmitted_)};
    }
    [[nodiscard]] const cue_feedback::Ticket& ticket() const noexcept {return ticket_;}
    [[nodiscard]] const dialogue_feedback::Ticket& dialogue_ticket() const noexcept {return voiceTicket_;}
    [[nodiscard]] bool failed() const noexcept {return failed_;}
    [[nodiscard]] bool retains_region(std::uint32_t bubble,const adventure_start::wire::Request& selected) const noexcept {
        if(!binding_ || !binding_->overlay || !binding_->gateway || failed_ || conflicting_
            || !frame().gatewayRequested || selected.revision!=ticket_.selectionRevision
            || selected.selection.activityIndex!=binding_->activity
            || selected.selection.sourceActivityIndex!=binding_->activity
            || adventure_start::package(selected)!=host_ || !gateway::valid(*binding_->gateway,*binding_->overlay))return false;
        return bubble==binding_->gateway->region->bubble;
    }
private:
    struct Driver final:coo::Services {
        OpeningRuntime& owner;explicit Driver(OpeningRuntime& value):owner(value){}
        bool publish(const coo::Command& c) noexcept override {
            if(c.spec.operation==coo::Operation::device || c.spec.operation==coo::Operation::traversal) {
                const auto* binding=owner.binding_->gateway;
                if(!binding || !owner.ready_ || (owner.binding_->dialogue.definition && !owner.voiceSubmitted_))return false;
                if(c.spec.operation==coo::Operation::traversal) {
                    if(owner.gatewayDevices_!=3 || owner.gatewayPermission_)return false;
                    owner.gatewayPermission_=true;return true;
                }
                for(std::size_t i=0;i<binding->endpoints.size();++i)
                    if(c.spec.asset==gateway::asset(binding->endpoints[i])) {
                        const auto bit=static_cast<std::uint8_t>(1U<<i);
                        if(owner.gatewayDevices_&bit)return false;
                        owner.gatewayDevices_|=bit;return true;
                    }
                return false;
            }
            if(c.spec.operation==coo::Operation::dialogue) {
                if(owner.voiceRequested_ || !dialogue_bridge::bind(owner.voiceTicket_))return false;
                owner.voiceToken_=c.token;owner.voiceRequested_=true;return true;
            }
            if(owner.requested_ || !native_bridge::bind(owner.ticket_))return false;
            owner.token_=c.token;owner.requested_=true;return true;
        }
        void cancel(const coo::Command&) noexcept override {}
    };
    cue_feedback::Owner owner_{};std::uint64_t boot_{};std::string_view host_;
    std::span<const OpeningBinding> bindings_;
    const coo::script::MissionDocument* document_{};
    const OpeningBinding* binding_{};
    cue_feedback::Ticket ticket_{};coo::Token token_{};coo::Executor executor_;
    dialogue_feedback::Ticket voiceTicket_{};coo::Token voiceToken_{};
    bool voiceRequested_{},voiceSubmitted_{};
    std::uint8_t gatewayDevices_{};bool gatewayPermission_{};
    bool requested_{},ready_{},failed_{},conflicting_{};
};
}
