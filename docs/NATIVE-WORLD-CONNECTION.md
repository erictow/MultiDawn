# Native world connection evidence

The isolated Tower run at commit `c478247c`, PID 17184, established a native world
connection using the development runtime. The exact executable, loaded DLL and
three layout signatures were verified by the independent read-only tools. These
findings concern one game and its local backend, not a second human player.

## Two native group structures

The existing native connection hook provided the current world/facet owner and
group pointers. Typed reads of that owner's member-machine fields showed that
slot zero and accepted remote member one exactly matched the current BAP
creator/control-machine fingerprint for Tower region 56. Slot zero also matched
the player-owning machine in both sampled managed SessionState roles, zero and
one.

Those managed tables each contained one human and no control-host member. The
world/facet table contained the creator and advertised control host. Therefore
the managed-session correlation's `no_managed_group` result is not evidence of a
failed world connection. The structures must remain distinct in the handoff
design. An absent OOB JoinId10 likewise does not by itself prove failure on this
world path.

## Application-level view compatibility

Read-only lookup followed the actual native ID40 consumer and its view lookup.
The selected view belonged to the accepted world control-host member one. Its
native peer-array slot was zero; those two indexes are not interchangeable.

The native compatibility field at view offset `0xA5` was true. Local and remote
view kinds were both five, their optional-value presence flags were both true,
and the native view state was zero. An independent evaluation of the recovered
`16F6CE0` compatibility predicate also returned true. This establishes
application-level compatibility for that sampled world link, beyond reliable
fragment acknowledgement. It does not establish remote Guardian replication.

## ID4 packet-loss notices

The current message registry names ID4 `packets-discarded`. Its decoded native
structure size is four bytes, but its wire body is only five unsigned bits.
The encoder at `173EAF0` and decoder at `173C4B0` agree on that layout. Consumer
`16E0AC0` calls `17E5260`, which adds the value to a per-receiver discarded-packet
counter. The value is an increment from zero through 31.

`middleware/gameplay/peer/packets_discarded.h` now decodes the exact logical
29-bit message or its 32-bit form with three zero padding bits. Optional bounded
diagnostics report increments without changing dispatch or reliable queues.
The codec has 973 strict component checks. The preserved older message-ID logs
do not contain the increments, so they cannot establish packet-loss values.

## Remaining milestone 1 work

For the next schema capture, `DAWN_ACTIVITY_BINDING_TRACE=1` also permits at most
eight `native_world_stack` events from the already installed connection hook.
Each records at most sixteen native-image return RVAs from a bounded stack walk.
It records no stack contents, original argument buffers or opaque peer identity,
adds no detour and does not enable `unsafeDiagnostics`. The caller functions can
then be read as code in the exact current process to locate the member-to-view
synchronizer. A guessed authority-vtable offset is not a substitute for that
consumer proof.

The world connection and its compatible view are foundations. The guest-local
profile/activity projection, protected control transport, authorized remote
human routes, native player publication and world-state transfer still need
implementation and real two-PC verification. Current managed-session
observations cannot substitute for the world/facet relationship proven above.
