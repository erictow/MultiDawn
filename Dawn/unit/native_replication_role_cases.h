#pragma once
#include "state/gameplay/replication_roles.h"
#include "client/hooks/bootflow/native_replication_bindings.h"
void native_replication_role_cases() {
    namespace r=dawn::state::gameplay::replication;
    namespace b=dawn::client::hooks::bootflow::replication_bindings;
    r::Roles roles;r::Address address{};
    address[0]=address[30]=127;address[3]=address[33]=1;address[4]=address[34]=0;
    address[5]=address[35]=121;address[40]=1;
    CHECK(!roles.publish(91,address)); // Disabled/external topology cannot publish.
    roles.begin(10);CHECK(roles.publish(91,address));CHECK(roles.lookup(91,address)==10);
    CHECK(roles.publish(91,address));CHECK(!roles.lookup(92,address)); // Same endpoint, real different peer.
    auto remote=address;remote[3]=2;
    CHECK(!roles.lookup(91,remote));CHECK(!roles.publish(91,remote)); // No identity reclassification.
    remote=address;remote[85]=6;CHECK(!roles.lookup(91,remote)); // Relay/direct mismatch.
    roles.begin(11);CHECK(!roles.lookup(91,address));CHECK(roles.publish(91,address));
    CHECK(roles.lookup(91,address)!=10); // Old native connection epoch cannot authorize exclusion.
    roles.begin(0);CHECK(!roles.lookup(91,address));CHECK(!roles.publish(91,address));
    b::Excluded bindings;
    for(const auto index:{0U,7U,30U}) {
        CHECK(bindings.remember({100,200+index,index},0,0));
        CHECK(bindings.remember({100,200+index,index},0,0)); // Exact duplicate is idempotent.
        CHECK(!bindings.remember({100,900+index,index},0,0)); // Reused slot is a different peer.
    }
    CHECK(bindings.size()==3);
    CHECK(!bindings.remove(101,0,0,0));CHECK(bindings.size()==3);
    CHECK(!bindings.remove(100,7,444,1U<<7)); // Native slot now occupied: forward its native removal.
    CHECK(bindings.size()==2);
    CHECK(bindings.remove(100,30,0,0));CHECK(bindings.remove(100,0,0,0));
    CHECK(bindings.size()==0);CHECK(!bindings.remove(100,0,0,0));
    CHECK(!bindings.remember({100,200,31},0,0));CHECK(!bindings.remember({100,200,0},300,0));
    CHECK(!bindings.remember({100,200,0},0,1));CHECK(!bindings.remember({0,200,0},0,0));
    for(unsigned i=0;i<128;++i)CHECK(bindings.remember({100+i,200+i,5},0,0));
    CHECK(!bindings.remember({999,888,5},0,0)); // Capacity exhaustion forwards native registration.
    for(unsigned i=0;i<128;++i)CHECK(bindings.remove(100+i,5,0,0));
    CHECK(bindings.size()==0);

    const b::Binding first{100,200,0}, second{101,201,0};
    const auto snapshot = [&](b::Excluded::WorldConnection& observation) {
        r::Address observedAddress{};
        const bool found = bindings.snapshot_world(90,91,observation,observedAddress);
        CHECK(observedAddress == (found ? address : r::Address{}));
        return found;
    };
    b::Excluded::WorldConnection observation{};
    CHECK(!bindings.stage_world(first,90,91,10,address));
    CHECK(bindings.remember(first,0,0));
    const auto pending = bindings.stage_world(first,90,91,10,address);
    CHECK(pending && !snapshot(observation));
    bindings.complete_world(first,pending,false);
    CHECK(!snapshot(observation) && observation == b::Excluded::WorldConnection{});
    const auto accepted = bindings.stage_world(first,90,91,10,address);
    CHECK(accepted > pending);
    bindings.complete_world(first,pending,true);
    CHECK(!snapshot(observation));
    bindings.complete_world(first,accepted,true);
    CHECK(snapshot(observation));
    CHECK(observation.generation==accepted && observation.controlEpoch==10
        && observation.creatorMachineId==90 && observation.controlMachineId==91);

    CHECK(bindings.remember(second,0,0));
    const auto duplicate = bindings.stage_world(second,90,91,10,address);
    CHECK(duplicate > accepted && !snapshot(observation));
    bindings.complete_world(second,duplicate,true);
    CHECK(!snapshot(observation) && observation == b::Excluded::WorldConnection{});
    CHECK(!bindings.remove(second.manager,second.index,999,1)); // Reused native slot still retires observation.
    CHECK(snapshot(observation) && observation.generation==accepted);
    CHECK(bindings.remove(first.manager,first.index,0,0));
    CHECK(!snapshot(observation));

    CHECK(bindings.remember(first,0,0));
    const auto reused = bindings.stage_world(first,90,91,11,address);
    bindings.complete_world(first,accepted,true);
    CHECK(reused > duplicate && !snapshot(observation));
    bindings.complete_world(first,reused,true);
    CHECK(snapshot(observation) && observation.generation==reused && observation.controlEpoch==11);
    bindings.invalidate_world(first.manager,first.index);
    CHECK(!snapshot(observation) && bindings.size()==1);
    const auto afterInvalidation = bindings.stage_world(first,90,91,11,address);
    bindings.complete_world(first,afterInvalidation,true);
    CHECK(!bindings.stage_world(first,91,91,11,address) && !snapshot(observation));
    const auto beforeQuiesce = bindings.stage_world(first,90,91,11,address);
    bindings.clear_world_observations();
    bindings.complete_world(first,beforeQuiesce,true);
    CHECK(!snapshot(observation) && bindings.remove(first.manager,first.index,0,0));
    CHECK(bindings.remember(first,0,0));
    CHECK(bindings.stage_world(first,90,91,12,address)>beforeQuiesce);
}
