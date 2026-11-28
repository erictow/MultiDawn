using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MultiDawn.Launcher
{
    /** Launcher IPC for native social intent and preflight observations; no account or gameplay packets. */
    internal sealed class RuntimeBridge : IDisposable
    {
        private sealed class NativeConnection
        {
            internal readonly NamedPipeServerStream Pipe;
            internal readonly SemaphoreSlim Writes = new SemaphoreSlim(1, 1);
            internal bool Authenticated;
            internal long Generation;
            internal int Protocol;
            internal bool WorldProbeCapable;
            internal readonly string Epoch = Guid.NewGuid().ToString("N").ToUpperInvariant();
            internal NativeConnection(string name)
            {
                PipeSecurity security = new PipeSecurity();
                SecurityIdentifier user;
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) user = identity.User;
                security.SetOwner(user);
                security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
                security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
                Pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                    4096, 4096, security);
            }
        }

        private sealed class WorldProbe
        {
            internal readonly NativeConnection Connection;
            internal readonly InviteRecord Invite;
            internal readonly string Nonce;
            internal readonly long Started;
            internal bool Delivered, Complete;

            internal WorldProbe(NativeConnection connection, InviteRecord invite, string nonce, long started)
            { Connection = connection; Invite = invite; Nonce = nonce; Started = started; }

            internal string ProtectedFields
            { get { return Invite.Ticket + " " + Invite.HostEpoch + " " + Invite.GuestEpoch + " " + Nonce; } }

            internal string NativeFields
            { get { return Invite.Ticket + " " + Nonce; } }
        }

        private const int WorldProbeLifetimeMilliseconds = 10000;
        private readonly object sync = new object(), queueLock = new object();
        private readonly PairSession session;
        private readonly CancellationTokenSource lifetime = new CancellationTokenSource();
        private readonly CancellationToken cancellation;
        private readonly ulong localId;
        private readonly InviteLedger invitations;
        private readonly Func<long> clock;
        private static readonly Stopwatch monotonic = Stopwatch.StartNew();
        private readonly string localName;
        private readonly Task listenerWorker, presenceWorker;
        private Task queued = Task.FromResult(0);
        private int queuedCount;
        private int pendingPreflights;
        private NativeConnection native;
        private WorldProbe worldProbe;
        private Dictionary<string, string> savedNicknames = new Dictionary<string, string>(StringComparer.Ordinal);
        private string boundPeer = "", remoteName = "Paired player";
        private ulong remoteId;
        private long boundGeneration;
        private bool remoteRunning, disposed;
        private int remoteProtocol;
        private string remoteEpoch = "-";
        private string remoteWorldEpoch = "-";
        private ulong runtimeRevision = 1, remoteRevision;
        private bool remoteRuntimeKnown;
        internal readonly string PipeId = Guid.NewGuid().ToString("N");
        internal readonly string Nonce = Guid.NewGuid().ToString("N");

        internal RuntimeBridge(PairSession paired, string persona) : this(paired, DeviceIdentity.Load(), persona) { }
        internal RuntimeBridge(PairSession paired, ulong identity, string persona) : this(paired, identity, persona, delegate { return monotonic.ElapsedMilliseconds; }) { }
        internal RuntimeBridge(PairSession paired, ulong identity, string persona, Func<long> clock)
        {
            if (paired == null || !ValidSteamId(identity)) throw new ArgumentException("Invalid native session identity.");
            ValidateText(persona, 127, false);
            session = paired; localId = identity; localName = persona;
            invitations = new InviteLedger(clock); this.clock = clock;
            cancellation = lifetime.Token;
            session.ConnectionControlReceived += ControlReceived;
            session.PeerChanged += PeerChanged;
            long generation; string identityKey;
            session.ConnectionSnapshot(out generation, out identityKey);
            lock (sync) { if (generation >= boundGeneration) { boundGeneration = generation; boundPeer = identityKey; } }
            listenerWorker = ListenAsync();
            presenceWorker = PublishLoopAsync();
            ObserveWorkers();
        }

        internal ulong LocalSteamId { get { return localId; } }
        internal ulong PeerSteamId { get { lock (sync) return remoteId; } }
        internal bool NativeConnected { get { lock (sync) return native != null && native.Authenticated; } }

        internal void SetSavedFriends(IEnumerable<SavedFriend> friends)
        {
            var snapshot = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (SavedFriend friend in friends) {
                if (snapshot.Count == FriendStore.MaximumFriends) break;
                // Saved names support Unicode. The native pipe currently accepts printable ASCII.
                string nickname = friend.Nickname;
                if (!PairSession.ValidIdentity(friend.PeerId) || String.IsNullOrWhiteSpace(nickname) || nickname.Length > 64) continue;
                bool printable = true;
                foreach (char character in nickname) {
                    if (character < 32 || character > 126) { printable = false; break; }
                }
                if (printable) snapshot[friend.PeerId] = nickname;
            }
            lock (sync) savedNicknames = snapshot;
        }

        // Use the authenticated launcher identity. The advertised persona still travels over TCP.
        private string NativePeerNameLocked()
        {
            string nickname;
            return savedNicknames.TryGetValue(boundPeer, out nickname) ? nickname : remoteName;
        }

        internal bool TryCaptureGamePreflight(out GamePreflightLaunchContext context)
        {
            long generation; string partner;
            session.ConnectionSnapshot(out generation, out partner);
            lock (sync) {
                context = null;
                if (!CurrentControl(generation, partner) || generation <= 0 || !ValidSteamId(remoteId)) return false;
                context = new GamePreflightLaunchContext(generation, partner, remoteId);
            }
            if (ValidateGamePreflight(context)) return true;
            context = null;
            return false;
        }
        private bool CurrentGamePreflightLocked(GamePreflightLaunchContext context, long generation, string partner)
        {
            return context != null && CurrentControl(generation, partner) && generation == context.PairGeneration
                && partner == context.PartnerLauncherId && remoteId == context.PeerSteamId && ValidSteamId(remoteId);
        }
        internal bool ValidateGamePreflight(GamePreflightLaunchContext context)
        {
            long generation; string partner;
            session.ConnectionSnapshot(out generation, out partner);
            lock (sync) if (!CurrentGamePreflightLocked(context, generation, partner)) return false;
            // Pair callbacks acquire the bridge lock while holding their own session lock.
            // Reobserve outside this lock order before accepting a copied bridge context.
            session.ConnectionSnapshot(out generation, out partner);
            return generation == context.PairGeneration && partner == context.PartnerLauncherId;
        }
        internal bool ApplyGamePreflightEnvironment(ProcessStartInfo info, GamePreflightLaunchContext context)
        {
            if (info == null || info.UseShellExecute) throw new ArgumentException("Use an isolated child process environment.");
            long generation; string partner;
            session.ConnectionSnapshot(out generation, out partner);
            lock (sync) {
                if (!CurrentGamePreflightLocked(context, generation, partner)) return false;
                ApplyEnvironment(info);
                info.EnvironmentVariables["DAWN_COMPANION_PROTOCOL"] = "3";
                info.EnvironmentVariables["DAWN_COMPANION_PAIR_GENERATION"] = context.PairGeneration.ToString(CultureInfo.InvariantCulture);
                info.EnvironmentVariables["DAWN_COMPANION_PEER_ID"] = context.PeerSteamId.ToString(CultureInfo.InvariantCulture);
                info.EnvironmentVariables["DAWN_COMPANION_WORLD_PROBE"] = "1";
                info.EnvironmentVariables["DAWN_NATIVE_ADDRESS_RESOLUTION"] = "1";
                info.EnvironmentVariables["DAWN_NATIVE_SESSION_TRACE"] = "1";
                info.EnvironmentVariables["DAWN_NATIVE_IDENTITY_OBSERVATION"] = "1";
                info.EnvironmentVariables["DAWN_ACTIVITY_BINDING_TRACE"] = "1";
            }
            return ValidateGamePreflight(context);
        }
        internal string GamePreflightStatus
        {
            get {
                long generation; string partner;
                session.ConnectionSnapshot(out generation, out partner);
                lock (sync) {
                    if (!CurrentControl(generation, partner)) return "Native test: pair with another launcher.";
                    if (!ValidSteamId(remoteId)) return "Native test: waiting for the partner profile.";
                    if (!CurrentNativeLocked(native)) return "Native test: local game companion is not connected.";
                    if (native.Protocol != 3) return "Native test: the local game companion needs protocol 3.";
                    if (!remoteRunning || remoteProtocol < 2 || !InviteLedger.Token(remoteEpoch))
                        return "Native test: local game connected; waiting for the partner's game.";
                    return "Native test: both game companions connected. Shared gameplay remains unavailable.";
                }
            }
        }
        internal string NativeEpochForTest { get { lock (sync) return native != null && native.Authenticated ? native.Epoch : "-"; } }
        internal string PeerEpochForTest { get { lock (sync) return remoteEpoch; } }
        internal int PeerProtocolForTest { get { lock (sync) return remoteProtocol; } }
        internal bool PeerSupportsWorldProbeForTest { get { lock (sync) return remoteRunning && remoteProtocol >= 2 && remoteWorldEpoch == remoteEpoch; } }
        internal bool AcceptedIntentForTest { get { lock (sync) return invitations.Outgoing != null && invitations.Outgoing.Accepted; } }
        internal string IncomingTicketForTest { get { lock (sync) return invitations.Incoming == null ? "" : invitations.Incoming.Ticket; } }
        internal Task ExpireForTest() { return ExpireInvitationsAsync(); }
        internal int PendingPreflightsForTest { get { return Thread.VolatileRead(ref pendingPreflights); } }
        internal async Task HoldNativeWritesForTest(Task barrier, TaskCompletionSource<bool> entered)
        {
            NativeConnection target;
            lock (sync) target = CurrentNativeLocked(native) ? native : null;
            if (target == null) throw new IOException("No native consumer to hold.");
            await target.Writes.WaitAsync(cancellation).ConfigureAwait(false);
            try { entered.TrySetResult(true); await barrier.ConfigureAwait(false); }
            finally { target.Writes.Release(); }
        }

        /** Only use for explicit native-social preflight; this does not enable multiplayer Play. */
        internal void ApplyEnvironment(ProcessStartInfo info)
        {
            if (info == null || info.UseShellExecute) throw new ArgumentException("Use an isolated child process environment.");
            var inherited = new System.Collections.Generic.List<string>();
            foreach (string key in info.EnvironmentVariables.Keys)
                if (key.StartsWith("DAWN_SESSION_", StringComparison.OrdinalIgnoreCase) || key.StartsWith("DAWN_COMPANION_", StringComparison.OrdinalIgnoreCase)) inherited.Add(key);
            foreach (string key in inherited) info.EnvironmentVariables.Remove(key);
            info.EnvironmentVariables["DAWN_COMPANION_ID"] = PipeId;
            info.EnvironmentVariables["DAWN_COMPANION_NONCE"] = Nonce;
            info.EnvironmentVariables["DAWN_COMPANION_PROTOCOL"] = "2";
            using (Process launcher = Process.GetCurrentProcess()) info.EnvironmentVariables["DAWN_COMPANION_PID"] = launcher.Id.ToString(CultureInfo.InvariantCulture);
            info.EnvironmentVariables["DAWN_SESSION_MODE"] = "solo";
        }

        private void Enqueue(Func<Task> action, long generation)
        {
            bool overflow = false;
            lock (queueLock)
            {
                if (Thread.VolatileRead(ref queuedCount) >= 32) overflow = true;
                else
                {
                    Interlocked.Increment(ref queuedCount);
                    queued = queued.ContinueWith(async delegate {
                        try { if (!cancellation.IsCancellationRequested) await action().ConfigureAwait(false); }
                        finally { Interlocked.Decrement(ref queuedCount); }
                    }, CancellationToken.None, TaskContinuationOptions.None, TaskScheduler.Default).Unwrap();
                }
            }
            if (overflow) { session.Disconnect(generation); return; }
            Observe(queued);
        }

        private void ControlReceived(long generation, string source, string message)
        {
            Enqueue(delegate { return ReceiveControlAsync(generation, source, message); }, generation);
        }
        // Hold the real TCP queue at a known point during reconnect regression tests.
        internal void HoldControlsForTest(Task barrier) { Enqueue(delegate { return barrier; }, session.ConnectionGeneration); }
        internal Task DrainControlsForTest() { lock (queueLock) return queued; }
        private void PeerChanged(bool paired)
        {
            long generation; string peerKey;
            session.ConnectionSnapshot(out generation, out peerKey);
            NativeConnection close;
            lock (sync)
            {
                if (generation < boundGeneration) return;
                if (generation == boundGeneration && boundPeer == peerKey) return;
                boundGeneration = generation; boundPeer = peerKey; remoteId = 0; remoteRunning = false; remoteName = "Paired player";
                remoteProtocol = 0; remoteEpoch = "-"; remoteRevision = 0; remoteRuntimeKnown = false;
                remoteWorldEpoch = "-"; worldProbe = null;
                close = native; native = null;
                if (close != null && close.Authenticated) AdvanceRuntimeLocked();
                invitations.SetContext(null);
            }
            // Close synchronously on the pairing transition. A queued old invitation cannot
            // keep a previous native consumer connected after its partner has disconnected.
            if (close != null) close.Pipe.Dispose();
            if (paired) Enqueue(PublishProfileAsync, generation);
        }

        private async Task ReceiveControlAsync(long generation, string source, string message)
        {
            lock (sync) if (!CurrentControl(generation, source)) return;
            if (!message.StartsWith("SOCIAL1 ", StringComparison.Ordinal) && !message.StartsWith("SOCIAL2 ", StringComparison.Ordinal)
                && !message.StartsWith("WORLD1 ", StringComparison.Ordinal)) return;
            try
            {
                string[] fields = Split(message);
                if (fields[0] == "WORLD1")
                {
                    await ReceiveWorldControlAsync(generation, source, fields).ConfigureAwait(false);
                    return;
                }
                if (fields[0] == "SOCIAL2")
                {
                    await ReceiveVersionTwoAsync(generation, source, fields).ConfigureAwait(false);
                    return;
                }
                if (fields.Length == 5 && fields[1] == "PROFILE")
                {
                    ulong id = Identity(fields[2]);
                    string name = Unhex(fields[3], 127, false);
                    if (id == localId || (fields[4] != "0" && fields[4] != "1")) throw new IOException("Invalid peer social identity.");
                    NativeConnection destination;
                    lock (sync)
                    {
                        if (!CurrentControl(generation, source)) return;
                        if (remoteId != 0 && remoteId != id) throw new IOException("Peer identity changed during the session.");
                        remoteId = id;
                        if (!remoteRuntimeKnown) { remoteName = name; remoteRunning = fields[4] == "1"; }
                        destination = native != null && native.Authenticated ? native : null;
                    }
                    if (destination != null) await PublishPeerToNativeAsync(destination).ConfigureAwait(false);
                    return;
                }
                if (fields.Length == 4 && fields[1] == "INVITE")
                {
                    ulong id = Identity(fields[2]);
                    Unhex(fields[3], 255, false);
                    NativeConnection destination;
                    lock (sync)
                    {
                        if (!CurrentControl(generation, source)) return;
                        if (id != remoteId || !remoteRunning) throw new IOException("Invitation identity does not match the paired player.");
                        destination = native != null && native.Authenticated ? native : null;
                        // Protocol two must wait for a ticketed acceptance and host authorization.
                        // A legacy invitation cannot bypass that path, including mixed-version pairs.
                        if (destination != null && destination.Protocol >= 2) return;
                    }
                    if (destination != null) await TrySendNativeAsync(destination, "INVITEFROM " + fields[2] + " " + fields[3]).ConfigureAwait(false);
                    return;
                }
                throw new IOException("Invalid social control message.");
            }
            catch (Exception error)
            {
                if (error is IOException || error is FormatException || error is ArgumentException || error is OverflowException)
                {
                    session.Disconnect(generation);
                    return;
                }
                throw;
            }
        }

        private bool CurrentControl(long generation, string source)
        { return !disposed && boundGeneration == generation && boundPeer.Length != 0 && boundPeer == source; }

        private bool CurrentNativeLocked(NativeConnection connection)
        { return connection != null && native == connection && connection.Authenticated && !disposed && connection.Generation == boundGeneration && boundPeer.Length != 0; }

        private void AdvanceRuntimeLocked()
        { if (runtimeRevision == UInt64.MaxValue) throw new IOException("Native runtime revision exhausted."); ++runtimeRevision; }

        private List<InviteRecord> UpdateInvitationsLocked()
        {
            InviteContext context = CurrentNativeLocked(native) && native.Protocol >= 2 && remoteProtocol >= 2 && remoteRunning
                && InviteLedger.Token(remoteEpoch)
                ? new InviteContext(boundGeneration, boundPeer, localId, remoteId, native.Epoch, remoteEpoch) : null;
            return invitations.SetContext(context);
        }

        private InviteRecord WorldInviteLocked(NativeConnection connection, string ticket, bool outgoing)
        {
            if (!CurrentNativeLocked(connection) || connection.Protocol != 3 || !connection.WorldProbeCapable
                || !remoteRunning || remoteProtocol < 2 || remoteWorldEpoch != remoteEpoch
                || connection.Generation <= 0) return null;
            InviteRecord record = invitations.Accepted(remoteId, ticket);
            return record != null && record.Outgoing == outgoing && record.Context.Generation == connection.Generation
                && record.Context.Launcher == boundPeer && record.Context.LocalEpoch == connection.Epoch
                && record.Context.PeerEpoch == remoteEpoch ? record : null;
        }

        private WorldProbe StartWorldProbeLocked(NativeConnection connection, InviteRecord record, string nonce)
        {
            if (record == null) return null;
            // Keep even a completed attempt until its accepted ticket is retired.
            if (worldProbe != null && WorldInviteLocked(worldProbe.Connection, worldProbe.Invite.Ticket,
                    worldProbe.Invite.Outgoing) == worldProbe.Invite) return null;
            worldProbe = new WorldProbe(connection, record, nonce, clock());
            return worldProbe;
        }

        private bool CurrentWorldProbeLocked(WorldProbe attempt)
        {
            if (attempt == null || worldProbe != attempt || attempt.Complete
                || WorldInviteLocked(attempt.Connection, attempt.Invite.Ticket, attempt.Invite.Outgoing) != attempt.Invite)
                return false;
            long now = clock();
            return now >= attempt.Started && now - attempt.Started < WorldProbeLifetimeMilliseconds;
        }

        private static void CheckWorldIndex(string text, int maximum)
        {
            int value;
            if (!Int32.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) || value > maximum
                || text != value.ToString(CultureInfo.InvariantCulture))
                throw new IOException("Invalid world destination selector.");
        }

        private async Task ReceiveWorldControlAsync(long generation, string source, string[] fields)
        {
            if (fields.Length == 3 && fields[1] == "CAP") {
                if (!InviteLedger.Token(fields[2])) throw new IOException("Invalid world capability epoch.");
                lock (sync) {
                    if (CurrentControl(generation, source) && remoteRunning && remoteProtocol >= 2 && remoteEpoch == fields[2])
                        remoteWorldEpoch = fields[2];
                }
                return;
            }

            bool probe = fields.Length == 8 && fields[1] == "PROBE";
            bool result = fields.Length == 6 && (fields[1] == "READY" || fields[1] == "NO");
            if ((!probe && !result) || !InviteLedger.Token(fields[2]) || !InviteLedger.Token(fields[3])
                || !InviteLedger.Token(fields[4]) || !InviteLedger.Token(fields[5]))
                throw new IOException("Invalid world control message.");
            string[] selectors = null;
            if (probe) {
                Unhex(fields[6], 40, false);
                selectors = fields[7].Split('.');
                if (selectors.Length != 2) throw new IOException("Invalid world destination selectors.");
                CheckWorldIndex(selectors[0], Int16.MaxValue);
                CheckWorldIndex(selectors[1], Int32.MaxValue);
            }

            // PairSession callbacks may hold their lock while acquiring sync.
            bool pairingHost = session.IsHost;
            WorldProbe attempt;
            lock (sync) {
                if (!CurrentControl(generation, source) || probe == pairingHost) return;
                InviteRecord record = WorldInviteLocked(native, fields[2], pairingHost);
                if (record == null || record.HostEpoch != fields[3] || record.GuestEpoch != fields[4]) return;
                if (probe) attempt = StartWorldProbeLocked(native, record, fields[5]);
                else {
                    attempt = worldProbe;
                    if (!CurrentWorldProbeLocked(attempt) || attempt.Invite != record || attempt.Nonce != fields[5]) return;
                }
            }
            if (attempt == null) return;
            string message = "WORLD1_" + fields[1] + " " + attempt.NativeFields;
            if (probe) message += " " + fields[6] + " " + selectors[0] + " " + selectors[1];
            await SendWorldNativeAsync(attempt, message, result).ConfigureAwait(false);
        }

        private async Task ReceiveNativeWorldAsync(NativeConnection connection, string[] fields)
        {
            if (fields.Length == 1 && fields[0] == "WORLD1_CAP") {
                lock (sync) {
                    if (!CurrentNativeLocked(connection) || connection.WorldProbeCapable) return;
                    connection.WorldProbeCapable = true;
                }
                await PublishProfileAsync().ConfigureAwait(false);
                return;
            }

            bool probe = fields.Length == 6 && fields[0] == "WORLD1_PROBE";
            bool result = fields.Length == 3 && (fields[0] == "WORLD1_READY" || fields[0] == "WORLD1_NO");
            if ((!probe && !result) || !InviteLedger.Token(fields[1]) || !InviteLedger.Token(fields[2]))
                throw new IOException("Invalid native world message.");
            if (probe) {
                Unhex(fields[3], 40, false);
                CheckWorldIndex(fields[4], Int16.MaxValue);
                CheckWorldIndex(fields[5], Int32.MaxValue);
            }

            bool pairingHost = session.IsHost;
            WorldProbe attempt;
            lock (sync) {
                if (!CurrentNativeLocked(connection) || !connection.WorldProbeCapable) return;
                if (probe) {
                    InviteRecord record = pairingHost ? WorldInviteLocked(connection, fields[1], true) : null;
                    if (worldProbe != null && worldProbe.Invite == record && worldProbe.Nonce == fields[2]) return;
                    attempt = StartWorldProbeLocked(connection, record, fields[2]);
                } else {
                    attempt = worldProbe;
                    if (pairingHost || !CurrentWorldProbeLocked(attempt) || !attempt.Delivered
                        || attempt.Connection != connection || attempt.Invite.Outgoing
                        || attempt.Invite.Ticket != fields[1] || attempt.Nonce != fields[2]) return;
                    attempt.Complete = true;
                }
            }
            if (attempt == null) {
                await TrySendNativeAsync(connection, "WORLD1_NO " + fields[1] + " " + fields[2]).ConfigureAwait(false);
                return;
            }
            string message = "WORLD1 " + fields[0].Substring("WORLD1_".Length) + " " + attempt.ProtectedFields;
            if (probe) message += " " + fields[3] + " " + fields[4] + "." + fields[5];
            await TrySendControlAsync(message, connection.Generation).ConfigureAwait(false);
        }

        private async Task SendWorldNativeAsync(WorldProbe attempt, string message, bool finish)
        {
            NativeConnection target = attempt.Connection;
            await target.Writes.WaitAsync(cancellation).ConfigureAwait(false);
            try {
                Task write;
                lock (sync) {
                    if (!CurrentWorldProbeLocked(attempt)) return;
                    if (finish) attempt.Complete = true;
                    else attempt.Delivered = true;
                    // Start the exact native write after revalidating the accepted ticket and lane.
                    write = WriteFrameCoreAsync(target.Pipe, message, cancellation);
                }
                await write.ConfigureAwait(false);
            }
            catch (IOException) { target.Pipe.Dispose(); }
            catch (ObjectDisposedException) { target.Pipe.Dispose(); }
            finally { target.Writes.Release(); }
        }

        private async Task PublishPeerToNativeAsync(NativeConnection connection)
        {
            ulong id; string name, epoch; int protocol; bool running;
            lock (sync) {
                if (!CurrentNativeLocked(connection)) return;
                id = remoteId; name = NativePeerNameLocked(); running = remoteRunning; epoch = remoteEpoch; protocol = remoteProtocol;
            }
            await TrySendNativeAsync(connection, "PEER " + id.ToString(CultureInfo.InvariantCulture) + " " + Hex(name) + " " + (running ? "1" : "0")).ConfigureAwait(false);
            // Version-two native parsers only know versions zero through two.
            if (connection.Protocol == 2 && protocol == 3) protocol = 2;
            if (connection.Protocol >= 2)
                await TrySendNativeAsync(connection, "RUNTIME " + id.ToString(CultureInfo.InvariantCulture) + " " + epoch + " " + protocol.ToString(CultureInfo.InvariantCulture)).ConfigureAwait(false);
        }

        private async Task NotifyRevokedAsync(IEnumerable<InviteRecord> records, bool forward)
        {
            foreach (InviteRecord record in records) {
                NativeConnection target;
                lock (sync) target = CurrentNativeLocked(native) && native.Protocol >= 2 && native.Epoch == record.Context.LocalEpoch ? native : null;
                if (target != null) await TrySendNativeAsync(target, "REVOKED " + record.Ticket).ConfigureAwait(false);
                if (forward) {
                    try { await session.SendControlAsync("SOCIAL2 REVOKE " + record.Ticket + " " + record.HostEpoch + " " + record.GuestEpoch, record.Context.Generation).ConfigureAwait(false); }
                    catch (IOException) { } catch (OperationCanceledException) { } catch (ObjectDisposedException) { }
                }
            }
        }

        private async Task ExpireInvitationsAsync()
        {
            List<InviteRecord> expired;
            lock (sync) expired = invitations.Expire();
            await NotifyRevokedAsync(expired, true).ConfigureAwait(false);
        }

        private async Task ReceiveVersionTwoAsync(long generation, string source, string[] fields)
        {
            if (fields.Length == 7 && fields[1] == "RUNTIME") {
                ulong id = Identity(fields[2]), revision;
                string name = Unhex(fields[3], 127, false), epoch = fields[4]; int protocol;
                if (!Int32.TryParse(fields[5], NumberStyles.None, CultureInfo.InvariantCulture, out protocol) || protocol < 0 || protocol > 3
                    || !UInt64.TryParse(fields[6], NumberStyles.None, CultureInfo.InvariantCulture, out revision) || revision == 0
                    || (protocol == 0 ? epoch != "-" : !InviteLedger.Token(epoch)) || id == localId)
                    throw new IOException("Invalid native runtime announcement.");
                NativeConnection destination; List<InviteRecord> revoked;
                lock (sync) {
                    if (!CurrentControl(generation, source)) return;
                    if (remoteId != 0 && remoteId != id) throw new IOException("Peer identity changed during the session.");
                    if (remoteRuntimeKnown && revision < remoteRevision) return;
                    if (remoteRuntimeKnown && revision == remoteRevision) {
                        if (remoteEpoch != epoch || remoteProtocol != protocol || remoteName != name) throw new IOException("Conflicting native runtime revision.");
                        return;
                    }
                    remoteId = id; remoteName = name; remoteRunning = protocol != 0;
                    if (remoteEpoch != epoch || protocol < 2) remoteWorldEpoch = "-";
                    remoteRuntimeKnown = true; remoteRevision = revision; remoteEpoch = epoch; remoteProtocol = protocol;
                    revoked = UpdateInvitationsLocked(); destination = CurrentNativeLocked(native) ? native : null;
                }
                await NotifyRevokedAsync(revoked, true).ConfigureAwait(false);
                if (destination != null) await PublishPeerToNativeAsync(destination).ConfigureAwait(false);
                return;
            }
            if (fields.Length == 7 && fields[1] == "OFFER") {
                ulong target = Identity(fields[3]); Unhex(fields[6], 255, false);
                if (!InviteLedger.Token(fields[2]) || !InviteLedger.Token(fields[4]) || !InviteLedger.Token(fields[5])) throw new IOException("Invalid invitation offer.");
                InviteRecord record, replaced; NativeConnection destination;
                lock (sync) {
                    if (!CurrentControl(generation, source)) return;
                    record = invitations.Receive(fields[2], target, fields[4], fields[5], fields[6], out replaced);
                    destination = record != null && CurrentNativeLocked(native) ? native : null;
                }
                if (replaced != null) await NotifyRevokedAsync(new[] { replaced }, true).ConfigureAwait(false);
                if (destination != null) await TrySendNativeAsync(destination, "INVITEFROM2 " + record.Context.PeerId.ToString(CultureInfo.InvariantCulture) + " " + record.Ticket + " " + record.ConnectHex).ConfigureAwait(false);
                return;
            }
            if (fields.Length == 5 && fields[1] == "ACCEPT") {
                if (!InviteLedger.Token(fields[2]) || !InviteLedger.Token(fields[3]) || !InviteLedger.Token(fields[4])) throw new IOException("Invalid invitation acceptance.");
                InviteRecord record; NativeConnection destination; int remaining;
                lock (sync) {
                    if (!CurrentControl(generation, source)) return;
                    record = invitations.AcceptOutgoing(fields[2], fields[3], fields[4]);
                    destination = record != null && CurrentNativeLocked(native) ? native : null;
                    remaining = record == null ? 0 : invitations.Remaining(record);
                }
                if (destination != null && remaining > 0)
                    await TrySendNativeAsync(destination, "ACCEPTED " + record.Context.PeerId.ToString(CultureInfo.InvariantCulture) + " " + record.Ticket + " " + remaining.ToString(CultureInfo.InvariantCulture)).ConfigureAwait(false);
                return;
            }
            if (fields.Length == 5 && fields[1] == "REVOKE") {
                if (!InviteLedger.Token(fields[2]) || !InviteLedger.Token(fields[3]) || !InviteLedger.Token(fields[4])) throw new IOException("Invalid invitation revocation.");
                InviteRecord record;
                lock (sync) { if (!CurrentControl(generation, source)) return; record = invitations.Revoke(fields[2], fields[3], fields[4]); }
                if (record != null) await NotifyRevokedAsync(new[] { record }, false).ConfigureAwait(false);
                return;
            }
            throw new IOException("Invalid version-two control message.");
        }

        private async Task ReceiveNativeAsync(NativeConnection connection, string[] fields)
        {
            if (connection.Protocol == 3 && fields[0].StartsWith("WORLD1_", StringComparison.Ordinal)) {
                await ReceiveNativeWorldAsync(connection, fields).ConfigureAwait(false);
                return;
            }
            if (connection.Protocol == 3 && fields.Length == 4 && fields[0] == "PREFLIGHT") {
                if (!InviteLedger.Token(fields[1]) || !InviteLedger.Token(fields[3])) throw new IOException("Invalid preflight token.");
                ulong peer = Identity(fields[2]);
                InviteRecord selected;
                lock (sync) {
                    if (!CurrentNativeLocked(connection)) return;
                    selected = invitations.Accepted(peer, fields[3]);
                }
                Interlocked.Increment(ref pendingPreflights);
                try { await SendPreflightAsync(connection, fields[1], peer, fields[3], selected).ConfigureAwait(false); }
                finally { Interlocked.Decrement(ref pendingPreflights); }
                return;
            }
            if (fields.Length != 3) throw new IOException("Unexpected native message.");
            if (fields[0] == "INVITE") {
                ulong target = Identity(fields[1]); Unhex(fields[2], 255, false);
                InviteRecord record = null, replaced = null; bool versionTwo;
                lock (sync) {
                    if (!CurrentNativeLocked(connection) || target != remoteId || !remoteRunning) throw new IOException("Invitation recipient is unavailable.");
                    versionTwo = connection.Protocol >= 2;
                    if (versionTwo && remoteProtocol < 2) throw new IOException("The peer native runtime does not support ticketed invitations.");
                    if (versionTwo)
                        record = invitations.Offer(Guid.NewGuid().ToString("N").ToUpperInvariant(), fields[2], out replaced);
                }
                if (versionTwo && record == null) throw new IOException("Native invitation context is unavailable.");
                if (replaced != null) await NotifyRevokedAsync(new[] { replaced }, true).ConfigureAwait(false);
                string control = record == null
                    ? "SOCIAL1 INVITE " + localId.ToString(CultureInfo.InvariantCulture) + " " + fields[2]
                    : "SOCIAL2 OFFER " + record.Ticket + " " + target.ToString(CultureInfo.InvariantCulture) + " " + record.HostEpoch + " " + record.GuestEpoch + " " + record.ConnectHex;
                await session.SendControlAsync(control, connection.Generation).ConfigureAwait(false);
                return;
            }
            if (fields[0] == "ACCEPT" && connection.Protocol >= 2) {
                ulong from = Identity(fields[1]);
                if (!InviteLedger.Token(fields[2])) throw new IOException("Invalid invitation ticket.");
                InviteRecord record;
                lock (sync) { if (!CurrentNativeLocked(connection)) return; record = invitations.AcceptIncoming(from, fields[2]); }
                if (record != null) await session.SendControlAsync("SOCIAL2 ACCEPT " + record.Ticket + " " + record.HostEpoch + " " + record.GuestEpoch, connection.Generation).ConfigureAwait(false);
                return;
            }
            throw new IOException("Unexpected native message.");
        }

        private async Task PublishLoopAsync()
        {
            try
            {
                while (true)
                {
                    await PublishProfileAsync().ConfigureAwait(false);
                    await ExpireInvitationsAsync().ConfigureAwait(false);
                    NativeConnection target;
                    lock (sync) target = native != null && native.Authenticated ? native : null;
                    if (target != null) await TrySendNativeAsync(target, "PING").ConfigureAwait(false);
                    await Task.Delay(2000, cancellation).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { if (!cancellation.IsCancellationRequested) Dispose(); }
            catch (ObjectDisposedException) { }
        }

        private async Task PublishProfileAsync()
        {
            if (!session.IsPaired || cancellation.IsCancellationRequested) return;
            bool running, worldCap; long generation; int protocol; string epoch; ulong revision;
            lock (sync) {
                generation = boundGeneration; running = CurrentNativeLocked(native);
                // Protocol three advertises ticketed invitations as version two.
                // The optional world exchange announces its own capability and epoch.
                protocol = running ? Math.Min(native.Protocol, 2) : 0; epoch = running ? native.Epoch : "-"; revision = runtimeRevision;
                worldCap = running && native.WorldProbeCapable;
            }
            try {
                await session.SendControlAsync("SOCIAL1 PROFILE " + localId.ToString(CultureInfo.InvariantCulture) + " " + Hex(localName) + " " + (running ? "1" : "0"), generation).ConfigureAwait(false);
                await session.SendControlAsync("SOCIAL2 RUNTIME " + localId.ToString(CultureInfo.InvariantCulture) + " " + Hex(localName) + " " + epoch + " " + protocol.ToString(CultureInfo.InvariantCulture) + " " + revision.ToString(CultureInfo.InvariantCulture), generation).ConfigureAwait(false);
                if (worldCap) await session.SendControlAsync("WORLD1 CAP " + epoch, generation).ConfigureAwait(false);
            }
            catch (IOException) { }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        }

        private async Task ListenAsync()
        {
            while (!cancellation.IsCancellationRequested)
            {
                NativeConnection connection = null;
                List<InviteRecord> endedRecords = new List<InviteRecord>();
                try
                {
                    connection = new NativeConnection("MultiDawn-" + PipeId);
                    lock (sync) { if (disposed) { connection.Pipe.Dispose(); break; } native = connection; }
                    using (cancellation.Register(delegate { connection.Pipe.Dispose(); }))
                    {
                        await Task.Factory.FromAsync(connection.Pipe.BeginWaitForConnection, connection.Pipe.EndWaitForConnection, null).ConfigureAwait(false);
                        string hello = await ReadFrameAsync(connection.Pipe, cancellation, 5000).ConfigureAwait(false);
                        connection.Protocol = FixedEquals(hello, "HELLO 3 " + Nonce) ? 3 : FixedEquals(hello, "HELLO 2 " + Nonce) ? 2 : FixedEquals(hello, "HELLO 1 " + Nonce) ? 1 : 0;
                        if (connection.Protocol == 0) throw new IOException("Native companion authentication failed.");
                        DateTime deadline = DateTime.UtcNow.AddSeconds(5);
                        ulong peerId;
                        string name;
                        bool running;
                        do
                        {
                            lock (sync)
                            {
                                if (native != connection || disposed) throw new IOException("Native connection was superseded.");
                                peerId = remoteId; name = NativePeerNameLocked(); running = remoteRunning;
                                connection.Generation = boundGeneration;
                            }
                            if (peerId != 0) break;
                            await Task.Delay(30, cancellation).ConfigureAwait(false);
                        } while (DateTime.UtcNow < deadline);
                        if (peerId == 0) throw new IOException("The native companion has no authenticated peer profile.");
                        string welcome = "WELCOME " + connection.Protocol.ToString(CultureInfo.InvariantCulture) + " " + localId.ToString(CultureInfo.InvariantCulture) + " " + peerId.ToString(CultureInfo.InvariantCulture) + " " + Hex(name) + " " + (running ? "1" : "0");
                        if (connection.Protocol == 3)
                            welcome += " " + connection.Epoch + " " + connection.Generation.ToString(CultureInfo.InvariantCulture);
                        await SendNativeAsync(connection, welcome).ConfigureAwait(false);
                        List<InviteRecord> revoked;
                        lock (sync) {
                            if (native != connection || connection.Generation != boundGeneration) throw new IOException("Native connection was superseded.");
                            connection.Authenticated = true; AdvanceRuntimeLocked(); revoked = UpdateInvitationsLocked();
                        }
                        await NotifyRevokedAsync(revoked, true).ConfigureAwait(false);
                        await PublishPeerToNativeAsync(connection).ConfigureAwait(false);
                        await PublishProfileAsync().ConfigureAwait(false);
                        while (true)
                        {
                            string[] fields = Split(await ReadFrameAsync(connection.Pipe, cancellation, 0).ConfigureAwait(false));
                            await ReceiveNativeAsync(connection, fields).ConfigureAwait(false);
                        }
                    }
                }
                catch (IOException) { }
                catch (OperationCanceledException) { }
                catch (ObjectDisposedException) { }
                catch (ArgumentException) { }
                finally
                {
                    if (connection != null)
                    {
                        lock (sync) {
                            if (native == connection) {
                                native = null; worldProbe = null; if (connection.Authenticated) AdvanceRuntimeLocked();
                                endedRecords = UpdateInvitationsLocked();
                            }
                        }
                        connection.Pipe.Dispose();
                    }
                }
                await NotifyRevokedAsync(endedRecords, true).ConfigureAwait(false);
                await PublishProfileAsync().ConfigureAwait(false);
                if (!cancellation.IsCancellationRequested)
                    try { await Task.Delay(100, cancellation).ConfigureAwait(false); } catch (OperationCanceledException) { }
            }
        }

        private async Task SendNativeAsync(NativeConnection target, string message)
        {
            try { await WriteFrameAsync(target.Pipe, target.Writes, message, cancellation).ConfigureAwait(false); }
            catch (IOException) { target.Pipe.Dispose(); throw; }
            catch (ObjectDisposedException) { target.Pipe.Dispose(); throw new IOException("Native companion disconnected."); }
        }
        private async Task TrySendNativeAsync(NativeConnection target, string message)
        {
            try { await SendNativeAsync(target, message).ConfigureAwait(false); }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }

        private async Task SendPreflightAsync(NativeConnection target, string nonce, ulong peer, string ticket, InviteRecord selected)
        {
            await target.Writes.WaitAsync(cancellation).ConfigureAwait(false);
            try {
                Task write;
                lock (sync) {
                    if (!CurrentNativeLocked(target) || target.Protocol != 3) return;
                    int remaining = invitations.RemainingAccepted(selected, peer, ticket);
                    bool current = remaining > 0 && selected.Context.Generation > 0
                        && selected.Context.Generation == target.Generation && selected.Context.Generation == boundGeneration
                        && selected.Context.Launcher == boundPeer && selected.Context.LocalId == localId
                        && selected.Context.PeerId == remoteId && selected.Context.PeerId == peer
                        && selected.Context.LocalEpoch == target.Epoch && selected.Context.PeerEpoch == remoteEpoch
                        && remoteRunning && remoteProtocol >= 2;
                    string reply = current
                        ? "PREFLIGHT_OK " + nonce + " " + peer.ToString(CultureInfo.InvariantCulture) + " " + ticket
                            + " " + selected.Context.Generation.ToString(CultureInfo.InvariantCulture)
                            + " " + target.Epoch + " " + remoteEpoch + " " + remaining.ToString(CultureInfo.InvariantCulture)
                        : "PREFLIGHT_NO " + nonce;
                    // Serialize, revalidate and initiate the exact pipe write before releasing
                    // the context lock. No lock is held while awaiting asynchronous I/O.
                    write = WriteFrameCoreAsync(target.Pipe, reply, cancellation);
                }
                await write.ConfigureAwait(false);
            }
            catch (IOException) { target.Pipe.Dispose(); throw; }
            catch (ObjectDisposedException) { target.Pipe.Dispose(); throw new IOException("Native companion disconnected."); }
            finally { target.Writes.Release(); }
        }

        internal static async Task WriteFrameAsync(Stream stream, SemaphoreSlim writes, string message, CancellationToken cancellation)
        {
            ValidateText(message, 1024, false);
            await writes.WaitAsync(cancellation).ConfigureAwait(false);
            try { await WriteFrameCoreAsync(stream, message, cancellation).ConfigureAwait(false); }
            finally { writes.Release(); }
        }

        private static async Task WriteFrameCoreAsync(Stream stream, string message, CancellationToken cancellation)
        {
            ValidateText(message, 1024, false);
            byte[] text = Encoding.ASCII.GetBytes(message), frame = new byte[message.Length + 4];
            byte[] length = BitConverter.GetBytes(text.Length);
            if (!BitConverter.IsLittleEndian) Array.Reverse(length);
            Array.Copy(length, frame, 4); Array.Copy(text, 0, frame, 4, text.Length);
            using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                timeout.CancelAfter(5000);
                using (timeout.Token.Register(delegate { stream.Dispose(); }))
                    await stream.WriteAsync(frame, 0, frame.Length, timeout.Token).ConfigureAwait(false);
            }
        }

        internal static async Task<string> ReadFrameAsync(Stream stream, CancellationToken cancellation, int firstByteTimeout)
        {
            byte[] header = new byte[4];
            using (CancellationTokenSource first = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                if (firstByteTimeout != 0) first.CancelAfter(firstByteTimeout);
                using (first.Token.Register(delegate { stream.Dispose(); }))
                    await ReadExactlyAsync(stream, header, 0, 1, first.Token).ConfigureAwait(false);
            }
            using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                timeout.CancelAfter(5000);
                using (timeout.Token.Register(delegate { stream.Dispose(); }))
                {
                    await ReadExactlyAsync(stream, header, 1, 3, timeout.Token).ConfigureAwait(false);
                    if (!BitConverter.IsLittleEndian) Array.Reverse(header);
                    int size = BitConverter.ToInt32(header, 0);
                    if (size < 1 || size > 1024) throw new IOException("Invalid native frame size.");
                    byte[] body = new byte[size];
                    await ReadExactlyAsync(stream, body, 0, size, timeout.Token).ConfigureAwait(false);
                    foreach (byte value in body) if (value < 32 || value > 126) throw new IOException("Invalid native frame encoding.");
                    return Encoding.ASCII.GetString(body);
                }
            }
        }
        private static async Task ReadExactlyAsync(Stream stream, byte[] bytes, int offset, int count, CancellationToken cancellation)
        {
            while (count > 0)
            {
                int read = await stream.ReadAsync(bytes, offset, count, cancellation).ConfigureAwait(false);
                if (read == 0) throw new IOException("Native companion disconnected.");
                offset += read; count -= read;
            }
        }
        internal static bool ValidSteamId(ulong id) { return (id & 0xFFFFFFFF00000000UL) == 0x0110000100000000UL && (id & 0xFFFFFFFFUL) != 0; }
        private static ulong Identity(string text)
        {
            ulong result;
            if (!UInt64.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out result) || !ValidSteamId(result)) throw new IOException("Invalid Steam identity.");
            return result;
        }
        internal static string Hex(string text)
        {
            ValidateText(text, 255, true);
            return text.Length == 0 ? "-" : BitConverter.ToString(Encoding.ASCII.GetBytes(text)).Replace("-", "");
        }
        internal static string Unhex(string text, int maximum, bool empty)
        {
            if (text == "-") { if (empty) return ""; throw new IOException("Empty field."); }
            if (String.IsNullOrEmpty(text) || text.Length % 2 != 0 || text.Length / 2 > maximum) throw new IOException("Invalid hex field length.");
            byte[] bytes = new byte[text.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int high = HexDigit(text[i * 2]), low = HexDigit(text[i * 2 + 1]);
                if (high < 0 || low < 0) throw new IOException("Invalid hex field encoding.");
                bytes[i] = (byte)((high << 4) | low);
            }
            string decoded = Encoding.ASCII.GetString(bytes);
            foreach (byte value in bytes) if (value < 32 || value > 126) throw new IOException("Invalid field text.");
            ValidateText(decoded, maximum, empty);
            return decoded;
        }
        private static int HexDigit(char value) { return value >= '0' && value <= '9' ? value - '0' : value >= 'A' && value <= 'F' ? value - 'A' + 10 : -1; }
        private static string[] Split(string message)
        {
            string[] fields = message.Split(' ');
            if (fields.Length > 8) throw new IOException("Too many message fields.");
            foreach (string field in fields) if (field.Length == 0) throw new IOException("Empty message field.");
            return fields;
        }
        private static void ValidateText(string text, int maximum, bool empty)
        {
            if (text == null || text.Length > maximum || (!empty && text.Length == 0)) throw new ArgumentException("Invalid text length.");
            foreach (char value in text) if (value < 32 || value > 126) throw new ArgumentException("Text must be printable ASCII.");
        }
        private static bool FixedEquals(string left, string right)
        {
            if (left.Length != right.Length) return false;
            int mismatch = 0;
            for (int i = 0; i < left.Length; i++) mismatch |= left[i] ^ right[i];
            return mismatch == 0;
        }
        private async void ObserveWorkers()
        {
            try
            {
                await Task.WhenAny(listenerWorker, presenceWorker).ConfigureAwait(false);
                // A failed listener must cancel the otherwise infinite presence worker too.
                if (!cancellation.IsCancellationRequested) Dispose();
                await Task.WhenAll(listenerWorker, presenceWorker).ConfigureAwait(false);
            }
            catch (Exception) { Dispose(); }
            Task controls;
            lock (queueLock) controls = queued;
            try { await controls.ConfigureAwait(false); } catch (Exception) { }
            lifetime.Dispose();
        }
        private static async void Observe(Task worker) { try { await worker.ConfigureAwait(false); } catch (Exception) { } }

        public void Dispose()
        {
            NativeConnection close; long generation; string ended;
            lock (sync) {
                if (disposed) return;
                disposed = true; close = native; native = null; remoteId = 0; remoteRunning = false;
                invitations.SetContext(null); AdvanceRuntimeLocked(); generation = boundGeneration;
                ended = "SOCIAL2 RUNTIME " + localId.ToString(CultureInfo.InvariantCulture) + " " + Hex(localName) + " - 0 " + runtimeRevision.ToString(CultureInfo.InvariantCulture);
            }
            Observe(TrySendControlAsync(ended, generation));
            session.ConnectionControlReceived -= ControlReceived; session.PeerChanged -= PeerChanged;
            lifetime.Cancel();
            if (close != null) close.Pipe.Dispose();
        }
        private async Task TrySendControlAsync(string message, long generation)
        { try { await session.SendControlAsync(message, generation).ConfigureAwait(false); } catch (IOException) { } catch (OperationCanceledException) { } catch (ObjectDisposedException) { } }
    }

    internal static class DeviceIdentity
    {
        internal static ulong Load()
        {
            string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MultiDawn");
            Directory.CreateDirectory(folder);
            string path = Path.Combine(folder, "steam-id.txt");
            if (!File.Exists(path))
            {
                byte[] random = new byte[4];
                using (RandomNumberGenerator generator = RandomNumberGenerator.Create()) generator.GetBytes(random);
                uint account = BitConverter.ToUInt32(random, 0); if (account == 0) account = 1;
                ulong created = 0x0110000100000000UL | account;
                try
                {
                    using (FileStream file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                    using (StreamWriter writer = new StreamWriter(file)) writer.Write(created.ToString(CultureInfo.InvariantCulture));
                }
                catch (IOException) { if (!File.Exists(path)) throw; }
            }
            ulong result;
            if (!UInt64.TryParse(File.ReadAllText(path).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out result) || !RuntimeBridge.ValidSteamId(result))
                throw new IOException("The MultiDawn device identity is invalid. Preserve the file and correct it before pairing native games.");
            return result;
        }
    }
}
