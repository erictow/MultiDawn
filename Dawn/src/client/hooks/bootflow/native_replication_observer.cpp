#include "native_replication_observer.h"
#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include "native_replication_bindings.h"
#include "../../../state/gameplay/replication_roles.h"
#include "../../hooking/call_gate.h"
#include "../../hooking/detour.h"
#include "../../../core/logging/log.h"

namespace dawn::client::hooks::bootflow::native_replication_observer {
namespace {
using Connect=bool(__fastcall*)(std::uintptr_t,int,std::uint8_t,const void*,const void*,std::uint8_t) noexcept;
using Add=void(__fastcall*)(std::uintptr_t,std::uint32_t,std::uintptr_t) noexcept;
using Remove=void(__fastcall*)(std::uintptr_t,std::uint32_t) noexcept;
hooking::CallGate g_gate;
std::atomic<Connect> g_connect{};
std::atomic<Add> g_add{};
std::atomic<Remove> g_remove{};
std::array<hooking::detour::Handle,3> g_handles{};
std::atomic_uint32_t g_lines{};
namespace roles=state::gameplay::replication;
struct Context {std::uintptr_t group{};std::uint64_t machine{},epoch{};int member{-1};roles::Address address{};};
thread_local Context g_context;
std::mutex g_bindingLock;
replication_bindings::Excluded g_excluded;
std::atomic_size_t g_excludedCount{};
struct ConnectionReport {std::uintptr_t group{};std::uint64_t machine{};bool accepted{};};
std::array<ConnectionReport,32> g_connections{};std::size_t g_connectionCount{};
bool changed_connection(std::uintptr_t group,std::uint64_t machine,bool accepted) noexcept {
    std::lock_guard lock(g_bindingLock);
    for(std::size_t i=0;i<g_connectionCount;++i)if(g_connections[i].group==group && g_connections[i].machine==machine) {
        if(g_connections[i].accepted==accepted)return false;
        g_connections[i].accepted=accepted;return true;
    }
    if(g_connectionCount==g_connections.size())return false;
    g_connections[g_connectionCount++]={group,machine,accepted};return true;
}

template<class T> bool read(std::uintptr_t address,T& value) noexcept {
    SIZE_T copied{};
    return address>=0x10000 && ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(address),
        &value,sizeof(value),&copied)!=FALSE && copied==sizeof(value);
}
template<class... Args> void report(const char* format,Args... args) noexcept {
    if(g_lines.fetch_add(1,std::memory_order_relaxed)>=128) return;
    std::array<char,768> line{};
    const int size=std::snprintf(line.data(),line.size(),format,args...);
    if(size>0 && static_cast<std::size_t>(size)<line.size())
        core::log::write(core::log::Channel::client,core::log::Level::info,{line.data(),static_cast<std::size_t>(size)});
}
bool binding_trace_requested() noexcept {
    static const bool requested=[]() noexcept {
        std::array<wchar_t,2> value{};
        return GetEnvironmentVariableW(L"DAWN_ACTIVITY_BINDING_TRACE",value.data(),
            static_cast<DWORD>(value.size()))==1 && value[0]==L'1';
    }();
    return requested;
}
// 1703910 validates the transport, then 16FF3C0 -> 16E8200 installs the peer.
// Its fourth parameter is the public 86-byte NetAddr. Never log its fifth
// parameter: that opaque 16-byte identity has not been classified as public.
__declspec(noinline) bool __fastcall connect_hook(std::uintptr_t owner,int member,std::uint8_t role,
    const void* address,const void* identity,std::uint8_t activate) noexcept {
    const hooking::CallGate::Scope scope{g_gate};
    const auto original=hooking::await_original(g_connect);
    std::uintptr_t group{};std::uint64_t machine{};std::array<unsigned char,86> net{};
    const bool qualified=scope.accepts_side_effects() && member>=0 && member<31
        && read(owner+8,group) && read(owner+0x2C+static_cast<std::uintptr_t>(member)*8,machine)
        && read(reinterpret_cast<std::uintptr_t>(address),net);
    const auto previous=g_context;
    g_context={};
    if(qualified)g_context={group,machine,roles::control_host_epoch(machine,net),member,net};
    const auto epoch=g_context.epoch;
    const bool result=original(owner,member,role,address,identity,activate);
    g_context=previous;
    if(qualified && scope.accepts_side_effects() && changed_connection(group,machine,result)) {
        report("ev=native_replication stage=connect thread=%lu group=%p member=%d machine=%016llX role=%u activate=%u address=%u.%u.%u.%u:%u public=%u.%u.%u.%u:%u method=%u control_epoch=%016llX accepted=%u",
        GetCurrentThreadId(),reinterpret_cast<void*>(group),member,static_cast<unsigned long long>(machine),
        static_cast<unsigned>(role),static_cast<unsigned>(activate),net[0],net[1],net[2],net[3],net[4]+256U*net[5],
        net[30],net[31],net[32],net[33],net[34]+256U*net[35],net[85],static_cast<unsigned long long>(epoch),result?1U:0U);
        if(binding_trace_requested())
            report("ev=native_group_owner pid=%lu owner=%p group=%p member=%d accepted=%u",
                GetCurrentProcessId(),reinterpret_cast<void*>(owner),reinterpret_cast<void*>(group),
                member,result?1U:0U);
    }
    return result;
}
__declspec(noinline) void __fastcall add_hook(std::uintptr_t manager,std::uint32_t index,std::uintptr_t view) noexcept {
    const hooking::CallGate::Scope scope{g_gate};
    const auto original=hooking::await_original(g_add);
    std::uintptr_t group{},viewManager{},nativeSlot{};std::uint32_t peerIndex{},viewIndex{},before{},after{},member{};
    std::uint64_t machine{};
    // The facet view is an embedded subobject of the native peer at +A8.
    const auto peer=view>=0x100A8?view-0xA8:0;
    const bool qualified=scope.accepts_side_effects() && index<31 && peer
        && read(peer+0x48,group) && read(peer+0x50,peerIndex) && read(peer+0x54,machine)
        && read(view+0x10,viewManager) && read(view+0xC,viewIndex) && read(manager+0x110,before)
        && group+0x270==manager && viewManager==manager && peerIndex==index && viewIndex==index;
    bool excluded{};
    // The classification comes from the server's advertised identity/endpoint,
    // captured during this native connection. Neither role bytes nor slot zero
    // are sufficient. Every unknown, external or unmatched peer is forwarded.
    if(qualified && g_context.epoch && g_context.group==group && g_context.machine==machine
        && read(peer+0x5C,member) && member==static_cast<std::uint32_t>(g_context.member)
        && roles::control_host_epoch(machine,g_context.address)==g_context.epoch
        && read(manager+0x18+static_cast<std::uintptr_t>(index)*8,nativeSlot)) {
        std::lock_guard lock(g_bindingLock);
        excluded=g_excluded.remember({manager,peer,index},nativeSlot,before);
        g_excludedCount.store(g_excluded.size(),std::memory_order_release);
    }
    if(excluded) {
        report("ev=native_replication stage=facet_add thread=%lu group=%p manager=%p peer=%p index=%u machine=%016llX action=control_host_excluded",
            GetCurrentThreadId(),reinterpret_cast<void*>(group),reinterpret_cast<void*>(manager),reinterpret_cast<void*>(peer),
            index,static_cast<unsigned long long>(machine));
        return;
    }
    original(manager,index,view);
    if(qualified && scope.accepts_side_effects() && read(manager+0x110,after))
        report("ev=native_replication stage=facet_add thread=%lu group=%p manager=%p peer=%p index=%u machine=%016llX mask_before=%08X mask_after=%08X action=forwarded",
            GetCurrentThreadId(),reinterpret_cast<void*>(group),reinterpret_cast<void*>(manager),reinterpret_cast<void*>(peer),
            index,static_cast<unsigned long long>(machine),before,after);
}
__declspec(noinline) void __fastcall remove_hook(std::uintptr_t manager,std::uint32_t index) noexcept {
    const hooking::CallGate::Scope scope{g_gate};
    const auto original=hooking::await_original(g_remove);
    std::uintptr_t view{};std::uint32_t before{},after{};
    const bool qualified=index<31 && read(manager+0x110,before)
        && read(manager+0x18+static_cast<std::uintptr_t>(index)*8,view);
    bool excluded{};
    if(qualified) {
        std::lock_guard lock(g_bindingLock);
        excluded=g_excluded.remove(manager,index,view,before);
        g_excludedCount.store(g_excluded.size(),std::memory_order_release);
    }
    // Honor prior exclusions while quiescing too. Native remove dereferences the
    // slot unconditionally; a slot we never registered has no native teardown.
    if(excluded) {
        report("ev=native_replication stage=facet_remove thread=%lu manager=%p index=%u action=excluded_binding_retired",
            GetCurrentThreadId(),reinterpret_cast<void*>(manager),index);return;
    }
    original(manager,index);
    if(qualified && scope.accepts_side_effects() && read(manager+0x110,after))
        report("ev=native_replication stage=facet_remove thread=%lu manager=%p index=%u view=%p mask_before=%08X mask_after=%08X action=forwarded",
            GetCurrentThreadId(),reinterpret_cast<void*>(manager),index,reinterpret_cast<void*>(view),before,after);
}
void* target(std::uintptr_t image,std::uintptr_t rva,const std::array<unsigned char,16>& expected) noexcept {
    std::array<unsigned char,16> actual{};
    return read(image+rva,actual) && actual==expected?reinterpret_cast<void*>(image+rva):nullptr;
}
bool idle() noexcept {return g_gate.idle() && g_excludedCount.load(std::memory_order_acquire)==0;}
}
bool install() noexcept {
    if(g_handles[0].attached)return g_gate.accepting();
    const auto image=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const std::array<hooking::detour::Spec,3> specs{{
        {target(image,0x1703910,{0x40,0x55,0x53,0x56,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24}),reinterpret_cast<void*>(&connect_hook)},
        {target(image,0x1719130,{0x48,0x89,0x5C,0x24,0x10,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57}),reinterpret_cast<void*>(&add_hook)},
        {target(image,0x1710030,{0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xEC,0x20,0x48}),reinterpret_cast<void*>(&remove_hook)}
    }};
    if(!specs[0].target || !specs[1].target || !specs[2].target || !hooking::detour::install(specs,g_handles)) {
        report("ev=native_replication stage=install result=unavailable");return false;
    }
    hooking::publish_original(g_connect,reinterpret_cast<Connect>(g_handles[0].original));
    hooking::publish_original(g_add,reinterpret_cast<Add>(g_handles[1].original));
    hooking::publish_original(g_remove,reinterpret_cast<Remove>(g_handles[2].original));
    g_gate.accept();report("ev=native_replication stage=install result=ok mode=qualified_control_hosts");return true;
}
void quiesce() noexcept {g_gate.quiesce();}
bool uninstall() noexcept {
    quiesce();if(!g_handles[0].attached)return true;
    const std::array<hooking::detour::ProtectedCodeEntry,5> code{{
        {reinterpret_cast<void*>(&connect_hook)},{reinterpret_cast<void*>(&add_hook)},{reinterpret_cast<void*>(&remove_hook)},
        {reinterpret_cast<void*>(&hooking::call_gate_detail::enter)},{reinterpret_cast<void*>(&hooking::call_gate_detail::leave)}
    }};
    if(hooking::detour::uninstall(g_handles,code,idle)!=hooking::detour::UninstallResult::removed)return false;
    g_connect.store(nullptr,std::memory_order_release);g_add.store(nullptr,std::memory_order_release);g_remove.store(nullptr,std::memory_order_release);
    g_lines.store(0,std::memory_order_relaxed);g_connections={};g_connectionCount=0;return true;
}
}
