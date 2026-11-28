using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MultiDawn.Launcher
{
    internal static class InvitationV2SelfTests
    {
        private const ulong Alice = 0x0110000100001011UL, Bob = 0x0110000100002022UL, Other = 0x0110000100003033UL;
        private const string FirstEpoch = "11111111111111111111111111111111", SecondEpoch = "22222222222222222222222222222222";
        private static readonly StringBuilder report = new StringBuilder();
        private static string Number(ulong value) { return value.ToString(CultureInfo.InvariantCulture); }
        private static string Ticket(int value) { return value.ToString("X32", CultureInfo.InvariantCulture); }
        private static void Check(bool condition, string label)
        { report.AppendLine((condition ? "PASS: " : "FAIL: ") + label); if (!condition) throw new IOException("Invitation v2 test failed: " + label); }
        internal static string Run() { report.Clear(); Ledger(); NetworkAsync().GetAwaiter().GetResult(); PreflightAsync().GetAwaiter().GetResult(); PreflightCompatibilityAsync().GetAwaiter().GetResult(); WorldProbeAsync().GetAwaiter().GetResult(); LegacyAsync().GetAwaiter().GetResult(); NoDowngradeAsync().GetAwaiter().GetResult(); return report.ToString(); }

        private static void Ledger()
        {
            long now = 100;
            InviteLedger ledger = new InviteLedger(delegate { return now; });
            InviteContext context = new InviteContext(1, "launcher-one", Alice, Bob, FirstEpoch, SecondEpoch);
            ledger.SetContext(context);
            Check(InviteLedger.Token(FirstEpoch) && !InviteLedger.Token("-") && !InviteLedger.Token(new string('a', 32)), "Invitation epochs and tickets require canonical 128-bit uppercase hex");
            InviteRecord replaced;
            InviteRecord outgoing = ledger.Offer(Ticket(1), "4142", out replaced);
            Check(outgoing != null && replaced == null && ledger.Remaining(outgoing) == 60000, "Outgoing intent starts with a local monotonic sixty-second lifetime");
            Check(ledger.Accepted(Bob, Ticket(1)) == null, "An unaccepted offer is unavailable to preflight");
            Check(ledger.AcceptOutgoing(Ticket(1), SecondEpoch, FirstEpoch) == null && !outgoing.Accepted, "Acceptance cannot swap the host and guest runtime epochs");
            Check(ledger.AcceptOutgoing(Ticket(1), FirstEpoch, SecondEpoch) == outgoing && outgoing.Accepted, "Only the exact current outgoing offer records accepted intent");
            Check(ledger.Accepted(Bob, Ticket(1)) == outgoing && ledger.RemainingAccepted(outgoing, Bob, Ticket(1)) == 60000,
                "Preflight observes accepted intent without consuming or extending it");
            Check(ledger.Accepted(Other, Ticket(1)) == null && ledger.Accepted(Bob, Ticket(999)) == null
                && ledger.RemainingAccepted(new InviteRecord(context, Ticket(1), "4142", now, true), Bob, Ticket(1)) == 0,
                "Preflight requires exact peer, ticket and retained record reference");
            Check(ledger.AcceptOutgoing(Ticket(1), FirstEpoch, SecondEpoch) == null, "A duplicate acceptance cannot create a second accepted intent");
            InviteRecord incoming = ledger.Receive(Ticket(2), Alice, SecondEpoch, FirstEpoch, "4142", out replaced);
            Check(incoming != null && ledger.Receive(Ticket(2), Alice, SecondEpoch, FirstEpoch, "4142", out replaced) == null, "A repeated incoming offer cannot extend or replace its original lifetime");
            Check(ledger.Receive(Ticket(3), Other, SecondEpoch, FirstEpoch, "4142", out replaced) == null && ledger.Incoming == incoming, "An offer for another Steam identity cannot replace an incoming ticket");
            Check(ledger.AcceptIncoming(Other, Ticket(2)) == null && ledger.AcceptIncoming(Bob, Ticket(3)) == null, "Native acceptance checks both sender and exact incoming ticket");
            Check(ledger.AcceptIncoming(Bob, Ticket(2)) == incoming && ledger.AcceptIncoming(Bob, Ticket(2)) == null, "An incoming invitation can be accepted only once");
            Check(ledger.Accepted(Bob, Ticket(2)) == incoming, "Preflight can observe accepted incoming intent");
            now += 59999;
            Check(ledger.Remaining(outgoing) == 1 && ledger.Expire().Count == 0, "An accepted intent remains valid only through its original deadline");
            ++now;
            Check(ledger.Remaining(outgoing) == 0 && ledger.AcceptOutgoing(Ticket(1), FirstEpoch, SecondEpoch) == null, "An expired acceptance cannot revive its intent");
            Check(ledger.RemainingAccepted(outgoing, Bob, Ticket(1)) == 0 && ledger.Accepted(Bob, Ticket(2)) == null,
                "The exact preflight expiry boundary needs no separate expiry poll");
            Check(ledger.Expire().Count == 2 && ledger.Expire().Count == 0 && ledger.Outgoing == null && ledger.Incoming == null, "Expiry revokes both bounded records once without persisting credentials");
            Check(ledger.Receive(Ticket(2), Alice, SecondEpoch, FirstEpoch, "4142", out replaced) == null, "A recently expired incoming ticket cannot be replayed");
            outgoing = ledger.Offer(Ticket(4), "4142", out replaced);
            InviteRecord next = ledger.Offer(Ticket(5), "4142", out replaced);
            Check(next != null && replaced == outgoing && !outgoing.Active, "Replacing an offer revokes the former outgoing record");
            Check(ledger.RemainingAccepted(outgoing, Bob, Ticket(4)) == 0, "A retained preflight candidate cannot survive offer replacement");
            Check(ledger.Revoke(Ticket(5), SecondEpoch, FirstEpoch) == null && ledger.Outgoing == next, "Wrong-epoch revocation cannot erase another intent");
            Check(ledger.SetContext(new InviteContext(1, "launcher-one", Alice, Bob, FirstEpoch, SecondEpoch)).Count == 0, "A duplicate runtime announcement preserves the current intent");
            Check(ledger.SetContext(new InviteContext(2, "launcher-one", Alice, Bob, FirstEpoch, SecondEpoch)).Count == 1 && ledger.Outgoing == null, "The same launcher reconnecting with a new pairing generation invalidates intent");
            ledger.Offer(Ticket(6), "4142", out replaced);
            Check(ledger.SetContext(new InviteContext(2, "launcher-two", Alice, Bob, FirstEpoch, SecondEpoch)).Count == 1, "Replacing the authenticated partner launcher invalidates intent");
            ledger.Offer(Ticket(7), "4142", out replaced);
            Check(ledger.SetContext(new InviteContext(2, "launcher-two", Alice, Bob, SecondEpoch, FirstEpoch)).Count == 1, "Replacing either native runtime epoch invalidates intent");
            ledger.Offer(Ticket(8), "4142", out replaced);
            Check(ledger.SetContext(null).Count == 1 && ledger.Offer(Ticket(9), "4142", out replaced) == null, "No invitation intent can exist without a current authenticated runtime context");
        }

        private sealed class FakeNative : IDisposable
        {
            internal readonly NamedPipeClientStream Pipe;
            internal string Welcome;
            private readonly SemaphoreSlim writes = new SemaphoreSlim(1, 1);
            private readonly CancellationTokenSource lifetime = new CancellationTokenSource();
            private readonly List<string> received = new List<string>();
            private Task reader;
            private int disposed;
            private FakeNative(NamedPipeClientStream pipe) { Pipe = pipe; }
            internal static async Task<FakeNative> OpenAsync(RuntimeBridge bridge, int protocol, ulong local, ulong peer)
            {
                NamedPipeClientStream pipe = new NamedPipeClientStream(".", "MultiDawn-" + bridge.PipeId, PipeDirection.InOut, PipeOptions.Asynchronous);
                try {
                    await Task.Run(delegate { pipe.Connect(5000); }).ConfigureAwait(false);
                    FakeNative result = new FakeNative(pipe);
                    await result.SendAsync("HELLO " + protocol.ToString(CultureInfo.InvariantCulture) + " " + bridge.Nonce).ConfigureAwait(false);
                    string welcome = await RuntimeBridge.ReadFrameAsync(pipe, CancellationToken.None, 5000).ConfigureAwait(false);
                    if (!welcome.StartsWith("WELCOME " + protocol.ToString(CultureInfo.InvariantCulture) + " " + Number(local) + " " + Number(peer) + " ", StringComparison.Ordinal)) throw new IOException("Incorrect native version handshake.");
                    result.Welcome = welcome;
                    result.reader = result.ReadAsync();
                    await UntilAsync(delegate { return bridge.NativeConnected; }, "Versioned native pipe authenticates").ConfigureAwait(false);
                    return result;
                } catch { pipe.Dispose(); throw; }
            }
            internal Task SendAsync(string text) { return RuntimeBridge.WriteFrameAsync(Pipe, writes, text, lifetime.Token); }
            private async Task ReadAsync()
            {
                try {
                    while (!lifetime.IsCancellationRequested) {
                        string message = await RuntimeBridge.ReadFrameAsync(Pipe, lifetime.Token, 0).ConfigureAwait(false);
                        lock (received) received.Add(message);
                    }
                } catch (IOException) { } catch (OperationCanceledException) { } catch (ObjectDisposedException) { }
            }
            internal int Count(string prefix) { lock (received) return received.FindAll(delegate(string item) { return item.StartsWith(prefix, StringComparison.Ordinal); }).Count; }
            internal async Task<string> WaitAsync(string prefix, int skip)
            {
                string result = null;
                await UntilAsync(delegate {
                    lock (received) {
                        List<string> matches = received.FindAll(delegate(string item) { return item.StartsWith(prefix, StringComparison.Ordinal); });
                        if (matches.Count > skip) result = matches[skip];
                    }
                    return result != null;
                }, "Expected native control arrives: " + prefix).ConfigureAwait(false);
                return result;
            }
            internal async Task<string> PreflightAsync(string nonce, ulong peer, string ticket)
            {
                await SendAsync("PREFLIGHT " + nonce + " " + Number(peer) + " " + ticket).ConfigureAwait(false);
                return await PreflightReplyAsync(nonce).ConfigureAwait(false);
            }
            internal async Task<string> PreflightReplyAsync(string nonce)
            {
                string result = null;
                await UntilAsync(delegate {
                    lock (received) result = received.Find(delegate(string item) {
                        return item == "PREFLIGHT_NO " + nonce || item.StartsWith("PREFLIGHT_OK " + nonce + " ", StringComparison.Ordinal);
                    });
                    return result != null;
                }, "Exact native preflight response arrives").ConfigureAwait(false);
                return result;
            }
            public void Dispose()
            {
                if (Interlocked.Exchange(ref disposed, 1) != 0) return;
                lifetime.Cancel(); Pipe.Dispose();
                // Read cancellation owns the final pending operation; do not block the UI thread.
                if (reader != null) reader.ContinueWith(delegate(Task task) { if (task.IsFaulted) { var ignored = task.Exception; } lifetime.Dispose(); }, TaskScheduler.Default);
                else lifetime.Dispose();
            }
        }

        private sealed class Fixture : IDisposable
        {
            internal readonly PairSession Host = new PairSession(), Guest = new PairSession();
            internal RuntimeBridge A, B;
            internal long Now;
            private readonly List<string> toHost = new List<string>(), toGuest = new List<string>();
            internal async Task StartAsync()
            {
                await Host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                await Guest.JoinAsync(Host.Code).ConfigureAwait(false);
                Host.ControlReceived += delegate(string message) { lock (toHost) toHost.Add(message); };
                Guest.ControlReceived += delegate(string message) { lock (toGuest) toGuest.Add(message); };
                A = new RuntimeBridge(Host, Alice, "Alice", delegate { return Interlocked.Read(ref Now); });
                B = new RuntimeBridge(Guest, Bob, "Bob", delegate { return Interlocked.Read(ref Now); });
                await UntilAsync(delegate { return A.PeerSteamId == Bob && B.PeerSteamId == Alice; }, "V2 fixture uses authenticated TCP pairing and distinct Steam identities").ConfigureAwait(false);
            }
            internal async Task ReadyAsync()
            { await UntilAsync(delegate { return A.PeerProtocolForTest == 2 && B.PeerProtocolForTest == 2 && A.PeerEpochForTest == B.NativeEpochForTest && B.PeerEpochForTest == A.NativeEpochForTest; }, "Both native runtime epochs are published over the authenticated pair").ConfigureAwait(false); }
            internal int Controls(bool host, string prefix)
            { List<string> list = host ? toHost : toGuest; lock (list) return list.FindAll(delegate(string item) { return item.StartsWith(prefix, StringComparison.Ordinal); }).Count; }
            internal async Task ProcessAsync(bool host, string control)
            {
                int before = Controls(host, control);
                await (host ? Guest : Host).SendControlAsync(control).ConfigureAwait(false);
                await UntilAsync(delegate { return Controls(host, control) > before; }, "Authenticated control is observed before checking rejection").ConfigureAwait(false);
                await (host ? A : B).DrainControlsForTest().ConfigureAwait(false);
            }
            public void Dispose() { if (A != null) A.Dispose(); if (B != null) B.Dispose(); Host.Dispose(); Guest.Dispose(); }
        }

        private static async Task NetworkAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 2, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 2, Bob, Alice).ConfigureAwait(false)) {
                    await test.ReadyAsync().ConfigureAwait(false);
                    System.Diagnostics.ProcessStartInfo environment = GameLaunch.CreateStartInfo(Path.GetTempPath()); test.A.ApplyEnvironment(environment);
                    Check(environment.EnvironmentVariables["DAWN_COMPANION_PROTOCOL"] == "2", "Explicit native preflight negotiates companion protocol two");
                    string connect = RuntimeBridge.Hex("intent-only:86657");
                    await alice.SendAsync("INVITE " + Number(Bob) + " " + connect).ConfigureAwait(false);
                    string[] offer = (await bob.WaitAsync("INVITEFROM2 ", 0).ConfigureAwait(false)).Split(' ');
                    Check(offer.Length == 4 && offer[1] == Number(Alice) && InviteLedger.Token(offer[2]) && offer[3] == connect, "A v2 invite reaches only the target native consumer with a fresh ticket");
                    string ticket = offer[2];
                    await bob.SendAsync("ACCEPT " + Number(Alice) + " " + ticket).ConfigureAwait(false);
                    string[] accepted = (await alice.WaitAsync("ACCEPTED ", 0).ConfigureAwait(false)).Split(' ');
                    int ttl;
                    Check(accepted.Length == 4 && accepted[1] == Number(Bob) && accepted[2] == ticket
                        && Int32.TryParse(accepted[3], out ttl) && ttl > 0 && ttl <= 60000 && test.A.AcceptedIntentForTest, "Exact target acceptance creates a bounded host-native intent without a gameplay grant");
                    int acceptControls = test.Controls(true, "SOCIAL2 ACCEPT ");
                    await bob.SendAsync("ACCEPT " + Number(Alice) + " " + ticket).ConfigureAwait(false);
                    await Task.Delay(100).ConfigureAwait(false);
                    Check(test.Controls(true, "SOCIAL2 ACCEPT ") == acceptControls, "Duplicate local acceptance does not send a second remote acceptance");
                    string hostEpoch = test.A.NativeEpochForTest, guestEpoch = test.B.NativeEpochForTest;
                    await test.ProcessAsync(true, "SOCIAL2 ACCEPT " + ticket + " " + hostEpoch + " " + guestEpoch).ConfigureAwait(false);
                    Check(alice.Count("ACCEPTED ") == 1 && test.Host.IsPaired, "A replayed remote acceptance cannot publish another accepted intent");
                    await test.ProcessAsync(false, "SOCIAL2 OFFER " + Ticket(900) + " " + Number(Other) + " " + hostEpoch + " " + guestEpoch + " " + connect).ConfigureAwait(false);
                    Check(bob.Count("INVITEFROM2 ") == 1 && test.B.IncomingTicketForTest == ticket, "An authenticated offer addressed to another identity is ignored without replacing the current ticket");
                    await test.ProcessAsync(true, "SOCIAL2 RUNTIME " + Number(Bob) + " " + RuntimeBridge.Hex("Bob") + " - 0 1").ConfigureAwait(false);
                    await test.ProcessAsync(true, "SOCIAL1 PROFILE " + Number(Bob) + " " + RuntimeBridge.Hex("Old Bob") + " 0").ConfigureAwait(false);
                    Check(test.A.PeerEpochForTest == guestEpoch && test.A.PeerProtocolForTest == 2 && test.A.AcceptedIntentForTest, "Older runtime revisions and legacy profiles cannot roll back known v2 epochs");
                    Interlocked.Exchange(ref test.Now, 60000);
                    await test.A.ExpireForTest().ConfigureAwait(false); await test.B.ExpireForTest().ConfigureAwait(false);
                    await alice.WaitAsync("REVOKED " + ticket, 0).ConfigureAwait(false);
                    await bob.WaitAsync("REVOKED " + ticket, 0).ConfigureAwait(false);
                    Check(!test.A.AcceptedIntentForTest && test.B.IncomingTicketForTest == "", "Expiry revokes native accepted and waiting intents without comparing PC wall clocks");
                    await test.ProcessAsync(true, "SOCIAL2 ACCEPT " + ticket + " " + hostEpoch + " " + guestEpoch).ConfigureAwait(false);
                    await test.ProcessAsync(false, "SOCIAL2 OFFER " + ticket + " " + Number(Bob) + " " + hostEpoch + " " + guestEpoch + " " + connect).ConfigureAwait(false);
                    Check(alice.Count("ACCEPTED ") == 1 && bob.Count("INVITEFROM2 ") == 1, "Expired offers and acceptances cannot be replayed");
                    await alice.SendAsync("INVITE " + Number(Bob) + " " + connect).ConfigureAwait(false);
                    string replacementTicket = (await bob.WaitAsync("INVITEFROM2 ", 1).ConfigureAwait(false)).Split(' ')[2];
                    await test.ProcessAsync(true, "SOCIAL2 ACCEPT " + replacementTicket + " " + hostEpoch + " " + Ticket(999)).ConfigureAwait(false);
                    Check(!test.A.AcceptedIntentForTest, "An acceptance carrying the wrong native runtime epoch fails closed");
                    TaskCompletionSource<bool> release = new TaskCompletionSource<bool>();
                    test.A.HoldControlsForTest(release.Task);
                    await test.Guest.SendControlAsync("SOCIAL2 ACCEPT " + replacementTicket + " " + hostEpoch + " " + guestEpoch).ConfigureAwait(false);
                    alice.Dispose();
                    await UntilAsync(delegate { return !test.A.NativeConnected; }, "Closing the old native runtime retires its invitation context").ConfigureAwait(false);
                    using (FakeNative newAlice = await FakeNative.OpenAsync(test.A, 2, Alice, Bob).ConfigureAwait(false)) {
                        Check(test.A.NativeEpochForTest != hostEpoch, "A replacement native consumer receives a fresh runtime epoch");
                        release.TrySetResult(true);
                        await test.A.DrainControlsForTest().ConfigureAwait(false);
                        await test.ReadyAsync().ConfigureAwait(false);
                        await Task.Delay(100).ConfigureAwait(false);
                        Check(newAlice.Count("ACCEPTED ") == 0 && !test.A.AcceptedIntentForTest, "A queued acceptance from the old runtime cannot reach its replacement");
                        test.Guest.Disconnect();
                        await UntilAsync(delegate { return !test.A.NativeConnected && !test.B.NativeConnected; }, "Pair disconnect closes both native pipes and clears ticket contexts").ConfigureAwait(false);
                        Check(!test.A.AcceptedIntentForTest && test.B.IncomingTicketForTest == "", "Disconnect leaves no accepted or waiting invitation intent");
                    }
                }
            }
        }

        private static void CheckPreflight(string text, string nonce, ulong peer, string ticket, RuntimeBridge local, RuntimeBridge remote, long generation, int ttl)
        {
            string[] fields = text.Split(' ');
            Check(fields.Length == 8 && fields[0] == "PREFLIGHT_OK" && fields[1] == nonce && fields[2] == Number(peer)
                && fields[3] == ticket && fields[4] == generation.ToString(CultureInfo.InvariantCulture)
                && fields[5] == local.NativeEpochForTest && fields[6] == remote.NativeEpochForTest
                && fields[7] == ttl.ToString(CultureInfo.InvariantCulture),
                "Preflight binds exact nonce, peer, ticket, pairing generation, both epochs and current TTL");
        }

        private static async Task PreflightAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 3, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 3, Bob, Alice).ConfigureAwait(false)) {
                    await test.ReadyAsync().ConfigureAwait(false);
                    string[] welcome = alice.Welcome.Split(' ');
                    Check(welcome.Length == 8 && welcome[6] == test.A.NativeEpochForTest && welcome[7] == test.Host.ConnectionGeneration.ToString(CultureInfo.InvariantCulture),
                        "Opt-in companion three handshake supplies the local native epoch and pairing generation");
                    Check(test.A.PeerProtocolForTest == 2 && test.B.PeerProtocolForTest == 2,
                        "Local preflight capability preserves remote version-two invitation announcements");
                    Check(await alice.PreflightAsync(Ticket(1000), Bob, Ticket(700)).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1000),
                        "Unknown tickets receive a bounded refusal without disconnecting the native pipe");
                    string connect = RuntimeBridge.Hex("preflight-intent-only");
                    await alice.SendAsync("INVITE " + Number(Bob) + " " + connect).ConfigureAwait(false);
                    string ticket = (await bob.WaitAsync("INVITEFROM2 ", 0).ConfigureAwait(false)).Split(' ')[2];
                    Check(await alice.PreflightAsync(Ticket(1001), Bob, ticket).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1001),
                        "A current unaccepted ticket cannot pass native preflight");
                    await bob.SendAsync("ACCEPT " + Number(Alice) + " " + ticket).ConfigureAwait(false);
                    await alice.WaitAsync("ACCEPTED ", 0).ConfigureAwait(false);
                    CheckPreflight(await alice.PreflightAsync(Ticket(1002), Bob, ticket).ConfigureAwait(false), Ticket(1002), Bob, ticket,
                        test.A, test.B, test.Host.ConnectionGeneration, 60000);
                    CheckPreflight(await bob.PreflightAsync(Ticket(1003), Alice, ticket).ConfigureAwait(false), Ticket(1003), Alice, ticket,
                        test.B, test.A, test.Guest.ConnectionGeneration, 60000);
                    Check(await alice.PreflightAsync(Ticket(1004), Other, ticket).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1004)
                        && await alice.PreflightAsync(Ticket(1005), Bob, Ticket(701)).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1005),
                        "Preflight cannot substitute a different peer or ticket for accepted intent");

                    TaskCompletionSource<bool> release = new TaskCompletionSource<bool>(), entered = new TaskCompletionSource<bool>();
                    Task hold = test.A.HoldNativeWritesForTest(release.Task, entered);
                    await entered.Task.ConfigureAwait(false);
                    try {
                        await alice.SendAsync("PREFLIGHT " + Ticket(1006) + " " + Number(Bob) + " " + ticket).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.A.PendingPreflightsForTest == 1; }, "A real native query waits behind the serialized pipe writer").ConfigureAwait(false);
                        Interlocked.Exchange(ref test.Now, 12345);
                    } finally { release.TrySetResult(true); }
                    await hold.ConfigureAwait(false);
                    CheckPreflight(await alice.PreflightReplyAsync(Ticket(1006)).ConfigureAwait(false), Ticket(1006), Bob, ticket,
                        test.A, test.B, test.Host.ConnectionGeneration, 47655);

                    release = new TaskCompletionSource<bool>(); entered = new TaskCompletionSource<bool>();
                    hold = test.A.HoldNativeWritesForTest(release.Task, entered); await entered.Task.ConfigureAwait(false);
                    try {
                        await alice.SendAsync("PREFLIGHT " + Ticket(1007) + " " + Number(Bob) + " " + ticket).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.A.PendingPreflightsForTest == 1; }, "An expiring query has captured its accepted candidate").ConfigureAwait(false);
                        Interlocked.Exchange(ref test.Now, 60000);
                    } finally { release.TrySetResult(true); }
                    await hold.ConfigureAwait(false);
                    Check(await alice.PreflightReplyAsync(Ticket(1007)).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1007),
                        "A queued response rechecks the authoritative expiry boundary before its write");

                    await alice.SendAsync("INVITE " + Number(Bob) + " " + connect).ConfigureAwait(false);
                    string revokeTicket = (await bob.WaitAsync("INVITEFROM2 ", 1).ConfigureAwait(false)).Split(' ')[2];
                    await bob.SendAsync("ACCEPT " + Number(Alice) + " " + revokeTicket).ConfigureAwait(false);
                    await alice.WaitAsync("ACCEPTED ", 1).ConfigureAwait(false);
                    release = new TaskCompletionSource<bool>(); entered = new TaskCompletionSource<bool>();
                    hold = test.A.HoldNativeWritesForTest(release.Task, entered); await entered.Task.ConfigureAwait(false);
                    try {
                        await alice.SendAsync("PREFLIGHT " + Ticket(1008) + " " + Number(Bob) + " " + revokeTicket).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.A.PendingPreflightsForTest == 1; }, "A revocation test waits at the production send fence").ConfigureAwait(false);
                        await test.Guest.SendControlAsync("SOCIAL2 REVOKE " + revokeTicket + " " + test.A.NativeEpochForTest + " " + test.B.NativeEpochForTest).ConfigureAwait(false);
                        await UntilAsync(delegate { return !test.A.AcceptedIntentForTest; }, "Revocation retires the exact record while its response is queued").ConfigureAwait(false);
                    } finally { release.TrySetResult(true); }
                    await hold.ConfigureAwait(false);
                    Check(await alice.PreflightReplyAsync(Ticket(1008)).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1008),
                        "A captured accepted record cannot pass after revocation during a delayed send");

                    await bob.SendAsync("INVITE " + Number(Alice) + " " + connect).ConfigureAwait(false);
                    string incoming = (await alice.WaitAsync("INVITEFROM2 ", 0).ConfigureAwait(false)).Split(' ')[2];
                    await alice.SendAsync("ACCEPT " + Number(Bob) + " " + incoming).ConfigureAwait(false);
                    await bob.WaitAsync("ACCEPTED ", 0).ConfigureAwait(false);
                    release = new TaskCompletionSource<bool>(); entered = new TaskCompletionSource<bool>();
                    hold = test.A.HoldNativeWritesForTest(release.Task, entered); await entered.Task.ConfigureAwait(false);
                    try {
                        await alice.SendAsync("PREFLIGHT " + Ticket(1009) + " " + Number(Bob) + " " + incoming).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.A.PendingPreflightsForTest == 1; }, "An incoming record is retained before a replacement offer").ConfigureAwait(false);
                        await bob.SendAsync("INVITE " + Number(Alice) + " " + connect).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.A.IncomingTicketForTest != incoming; }, "A new remote offer replaces the accepted incoming record").ConfigureAwait(false);
                    } finally { release.TrySetResult(true); }
                    await hold.ConfigureAwait(false);
                    Check(await alice.PreflightReplyAsync(Ticket(1009)).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1009),
                        "A replacement invitation cannot satisfy a queued query for the old record");
                    string oldEpoch = test.A.NativeEpochForTest;
                    alice.Dispose();
                    await UntilAsync(delegate { return !test.A.NativeConnected; }, "Native exit retires its preflight context").ConfigureAwait(false);
                    using (FakeNative replacement = await FakeNative.OpenAsync(test.A, 3, Alice, Bob).ConfigureAwait(false)) {
                        await test.ReadyAsync().ConfigureAwait(false);
                        Check(test.A.NativeEpochForTest != oldEpoch
                            && await replacement.PreflightAsync(Ticket(1010), Bob, incoming).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1010),
                            "A restarted native consumer cannot validate its predecessor's accepted ticket");
                    }
                    Check(test.Controls(true, "PREFLIGHT") == 0 && test.Controls(false, "PREFLIGHT") == 0 && test.Host.IsPaired,
                        "Preflight requests stay on the local pipe without social forwarding or gameplay admission");
                }
            }
            await PreflightReconnectAsync().ConfigureAwait(false);
        }

        private static async Task PreflightReconnectAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                string code = test.Host.Code;
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 3, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 2, Bob, Alice).ConfigureAwait(false)) {
                    await test.ReadyAsync().ConfigureAwait(false);
                    await alice.SendAsync("INVITE " + Number(Bob) + " " + RuntimeBridge.Hex("reconnect-preflight")).ConfigureAwait(false);
                    string ticket = (await bob.WaitAsync("INVITEFROM2 ", 0).ConfigureAwait(false)).Split(' ')[2];
                    await bob.SendAsync("ACCEPT " + Number(Alice) + " " + ticket).ConfigureAwait(false);
                    await alice.WaitAsync("ACCEPTED ", 0).ConfigureAwait(false);
                    long oldGeneration = test.Host.ConnectionGeneration;
                    CheckPreflight(await alice.PreflightAsync(Ticket(1099), Bob, ticket).ConfigureAwait(false), Ticket(1099), Bob, ticket,
                        test.A, test.B, oldGeneration, 60000);
                    TaskCompletionSource<bool> release = new TaskCompletionSource<bool>(), entered = new TaskCompletionSource<bool>();
                    Task hold = test.A.HoldNativeWritesForTest(release.Task, entered); await entered.Task.ConfigureAwait(false);
                    try {
                        await alice.SendAsync("PREFLIGHT " + Ticket(1100) + " " + Number(Bob) + " " + ticket).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.A.PendingPreflightsForTest == 1; }, "An old native preflight waits before pairing disconnect").ConfigureAwait(false);
                        test.Guest.Disconnect();
                        await UntilAsync(delegate { return !test.Host.IsPaired && !test.A.NativeConnected && !test.B.NativeConnected; },
                            "Pair disconnect retires native contexts while the old write is held").ConfigureAwait(false);
                    } finally { release.TrySetResult(true); }
                    await hold.ConfigureAwait(false);
                    await UntilAsync(delegate { return test.A.PendingPreflightsForTest == 0; }, "A stale preflight send retires without targeting a new pipe").ConfigureAwait(false);
                    await test.Guest.JoinAsync(code).ConfigureAwait(false);
                    await UntilAsync(delegate { return test.A.PeerSteamId == Bob && test.B.PeerSteamId == Alice; }, "The same launchers reconnect after an outstanding preflight").ConfigureAwait(false);
                    using (FakeNative nextAlice = await FakeNative.OpenAsync(test.A, 3, Alice, Bob).ConfigureAwait(false))
                    using (FakeNative nextBob = await FakeNative.OpenAsync(test.B, 2, Bob, Alice).ConfigureAwait(false)) {
                        await test.ReadyAsync().ConfigureAwait(false);
                        Check(test.Host.ConnectionGeneration > oldGeneration && nextAlice.Count("PREFLIGHT_OK ") == 0
                            && await nextAlice.PreflightAsync(Ticket(1101), Bob, ticket).ConfigureAwait(false) == "PREFLIGHT_NO " + Ticket(1101),
                            "A new pairing generation receives neither an old success nor a valid old ticket");
                    }
                }
            }
        }

        private static async Task PreflightCompatibilityAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 3, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 2, Bob, Alice).ConfigureAwait(false)) {
                    await test.ReadyAsync().ConfigureAwait(false);
                    Check(bob.Welcome.Split(' ').Length == 6, "Protocol-two handshake framing remains unchanged beside an opt-in protocol-three peer");
                    await bob.SendAsync("PREFLIGHT " + Ticket(1200) + " " + Number(Alice) + " " + Ticket(800)).ConfigureAwait(false);
                    await UntilAsync(delegate { return !test.B.NativeConnected; }, "A version-two pipe cannot invoke the version-three preflight command").ConfigureAwait(false);
                    Check(test.Host.IsPaired && test.A.NativeConnected, "Unsupported local preflight does not break launcher pairing or the other native pipe");
                }
                string[] malformed = {
                    "PREFLIGHT " + new string('a', 32) + " " + Number(Alice) + " " + Ticket(800),
                    "PREFLIGHT " + Ticket(1201) + " 0 " + Ticket(800),
                    "PREFLIGHT " + Ticket(1202) + " " + Number(Alice) + " " + new string('a', 32),
                    "PREFLIGHT " + Ticket(1203) + " " + Number(Alice) + " " + Ticket(800) + " EXTRA"
                };
                foreach (string request in malformed) {
                    using (FakeNative invalid = await FakeNative.OpenAsync(test.B, 3, Bob, Alice).ConfigureAwait(false)) {
                        await invalid.SendAsync(request).ConfigureAwait(false);
                        await UntilAsync(delegate { return !test.B.NativeConnected; }, "Malformed preflight tokens, identities and field counts close only their native pipe").ConfigureAwait(false);
                        Check(test.Host.IsPaired && test.Guest.IsPaired, "Malformed local preflight does not terminate authenticated launcher pairing");
                    }
                }
            }
        }

        private static async Task LegacyAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 1, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 1, Bob, Alice).ConfigureAwait(false)) {
                    await UntilAsync(delegate { return test.A.PeerProtocolForTest == 1 && test.B.PeerProtocolForTest == 1; }, "Legacy native protocol versions are announced accurately").ConfigureAwait(false);
                    string connect = RuntimeBridge.Hex("legacy-invitation");
                    await alice.SendAsync("INVITE " + Number(Bob) + " " + connect).ConfigureAwait(false);
                    await bob.WaitAsync("INVITEFROM " + Number(Alice) + " " + connect, 0).ConfigureAwait(false);
                    await bob.SendAsync("INVITE " + Number(Alice) + " " + connect).ConfigureAwait(false);
                    await alice.WaitAsync("INVITEFROM " + Number(Bob) + " " + connect, 0).ConfigureAwait(false);
                    Check(!test.A.AcceptedIntentForTest && !test.B.AcceptedIntentForTest, "Version-one invitation forwarding remains compatible in both directions without creating v2 intents");
                }
            }
        }
        private static async Task<string> AcceptWorldInviteAsync(FakeNative alice, FakeNative bob, int index)
        {
            await alice.SendAsync("INVITE " + Number(Bob) + " " + RuntimeBridge.Hex("world-test")).ConfigureAwait(false);
            string ticket = (await bob.WaitAsync("INVITEFROM2 ", index).ConfigureAwait(false)).Split(' ')[2];
            await bob.SendAsync("ACCEPT " + Number(Alice) + " " + ticket).ConfigureAwait(false);
            await alice.WaitAsync("ACCEPTED " + Number(Bob) + " " + ticket + " ", 0).ConfigureAwait(false);
            return ticket;
        }

        private static async Task WorldProbeAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 3, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 3, Bob, Alice).ConfigureAwait(false)) {
                    await test.ReadyAsync().ConfigureAwait(false);
                    string hostEpoch = test.A.NativeEpochForTest, guestEpoch = test.B.NativeEpochForTest;
                    string destination = RuntimeBridge.Hex("city_tower_social_d2");
                    await alice.SendAsync("WORLD1_CAP").ConfigureAwait(false);
                    await UntilAsync(delegate { return test.B.PeerSupportsWorldProbeForTest; }, "Guest launcher sees the host runtime's exact world capability epoch").ConfigureAwait(false);
                    await test.ProcessAsync(true, "WORLD1 CAP " + Ticket(999)).ConfigureAwait(false);
                    string ticket = await AcceptWorldInviteAsync(alice, bob, 0).ConfigureAwait(false);
                    string nonce = Ticket(1300);
                    await alice.SendAsync("WORLD1_PROBE " + ticket + " " + nonce + " " + destination + " 20 56").ConfigureAwait(false);
                    await alice.WaitAsync("WORLD1_NO " + ticket + " " + nonce, 0).ConfigureAwait(false);
                    Check(!test.A.PeerSupportsWorldProbeForTest && test.Controls(false, "WORLD1 PROBE ") == 0
                        && bob.Count("WORLD1_") == 0 && test.Host.IsPaired,
                        "A previous capability epoch or legacy runtime receives no probe and keeps its invitation connection");

                    await bob.SendAsync("WORLD1_CAP").ConfigureAwait(false);
                    await UntilAsync(delegate { return test.A.PeerSupportsWorldProbeForTest; }, "Host launcher sees the guest runtime's exact world capability epoch").ConfigureAwait(false);
                    nonce = Ticket(1301);
                    string localFields = ticket + " " + nonce;
                    string wirePrefix = ticket + " " + hostEpoch + " " + guestEpoch + " ";
                    string wireFields = wirePrefix + nonce;
                    string probe = "WORLD1_PROBE " + localFields + " " + destination + " 20 56";
                    await test.ProcessAsync(false, "WORLD1 PROBE " + ticket + " " + guestEpoch + " " + hostEpoch + " "
                        + nonce + " " + destination + " 20.56").ConfigureAwait(false);
                    await test.ProcessAsync(true, "WORLD1 PROBE " + wireFields + " " + destination + " 20.56").ConfigureAwait(false);
                    Check(bob.Count("WORLD1_PROBE ") == 0 && alice.Count("WORLD1_PROBE ") == 0,
                        "The pairing host only initiates probes and swapped epochs are refused");
                    await alice.SendAsync(probe).ConfigureAwait(false);
                    Check(await bob.WaitAsync("WORLD1_PROBE " + localFields, 0).ConfigureAwait(false) == probe,
                        "The private exchange preserves the accepted ticket, nonce and public Tower selectors");
                    await test.ProcessAsync(false, "WORLD1 PROBE " + wireFields + " " + destination + " 20.56").ConfigureAwait(false);
                    await bob.SendAsync("WORLD1_READY " + ticket + " " + Ticket(1302)).ConfigureAwait(false);
                    await test.ProcessAsync(true, "WORLD1 READY " + wirePrefix + Ticket(1302)).ConfigureAwait(false);
                    Check(bob.Count("WORLD1_PROBE ") == 1 && alice.Count("WORLD1_READY ") == 0,
                        "The same protected probe cannot restart guest capture, and an unrelated nonce cannot complete it");
                    await bob.SendAsync("WORLD1_READY " + localFields).ConfigureAwait(false);
                    await alice.WaitAsync("WORLD1_READY " + localFields, 0).ConfigureAwait(false);
                    await test.ProcessAsync(true, "WORLD1 READY " + wireFields).ConfigureAwait(false);
                    await alice.SendAsync("WORLD1_PROBE " + ticket + " " + Ticket(1303) + " " + destination + " 20 56").ConfigureAwait(false);
                    await alice.WaitAsync("WORLD1_NO " + ticket + " " + Ticket(1303), 0).ConfigureAwait(false);
                    Check(alice.Count("WORLD1_READY ") == 1 && bob.Count("WORLD1_PROBE ") == 1,
                        "Exactly one attempt and one authenticated response can complete for a live accepted ticket");

                    ticket = await AcceptWorldInviteAsync(alice, bob, 1).ConfigureAwait(false);
                    nonce = Ticket(1304);
                    localFields = ticket + " " + nonce;
                    wireFields = ticket + " " + hostEpoch + " " + guestEpoch + " " + nonce;
                    await alice.SendAsync("WORLD1_PROBE " + localFields + " " + destination + " 20 56").ConfigureAwait(false);
                    await bob.WaitAsync("WORLD1_PROBE " + localFields, 0).ConfigureAwait(false);
                    TaskCompletionSource<bool> release = new TaskCompletionSource<bool>(), entered = new TaskCompletionSource<bool>();
                    Task hold = test.A.HoldNativeWritesForTest(release.Task, entered);
                    await entered.Task.ConfigureAwait(false);
                    try {
                        await bob.SendAsync("WORLD1_READY " + localFields).ConfigureAwait(false);
                        await UntilAsync(delegate { return test.Controls(true, "WORLD1 READY " + wireFields) > 0; },
                            "The protected readiness result reaches the host while its native writer is held").ConfigureAwait(false);
                        Interlocked.Exchange(ref test.Now, 10000);
                    } finally { release.TrySetResult(true); }
                    await hold.ConfigureAwait(false);
                    await test.A.DrainControlsForTest().ConfigureAwait(false);
                    Check(alice.Count("WORLD1_READY " + localFields) == 0 && test.A.AcceptedIntentForTest && test.Host.IsPaired,
                        "The probe deadline expires independently of the invitation while a native send is queued");

                    ticket = await AcceptWorldInviteAsync(alice, bob, 2).ConfigureAwait(false);
                    localFields = ticket + " " + Ticket(1305);
                    int receivedFromGuest = test.Controls(true, "WORLD1 PROBE ");
                    await bob.SendAsync("WORLD1_PROBE " + localFields + " " + destination + " 20 56").ConfigureAwait(false);
                    await bob.WaitAsync("WORLD1_NO " + localFields, 0).ConfigureAwait(false);
                    Check(test.Controls(true, "WORLD1 PROBE ") == receivedFromGuest,
                        "The guest's native runtime cannot start an exchange");

                    localFields = ticket + " " + Ticket(1306);
                    await alice.SendAsync("WORLD1_PROBE " + localFields + " " + destination + " 20 56").ConfigureAwait(false);
                    await bob.WaitAsync("WORLD1_PROBE " + localFields, 0).ConfigureAwait(false);
                    await bob.SendAsync("WORLD1_NO " + localFields).ConfigureAwait(false);
                    await alice.WaitAsync("WORLD1_NO " + localFields, 0).ConfigureAwait(false);
                    Check(test.Host.IsPaired && test.A.AcceptedIntentForTest,
                        "The guest's native refusal reaches the exact host request and preserves pairing and the invitation");
                }
            }
        }

        private static async Task NoDowngradeAsync()
        {
            using (Fixture test = new Fixture()) {
                await test.StartAsync().ConfigureAwait(false);
                using (FakeNative alice = await FakeNative.OpenAsync(test.A, 1, Alice, Bob).ConfigureAwait(false))
                using (FakeNative bob = await FakeNative.OpenAsync(test.B, 2, Bob, Alice).ConfigureAwait(false)) {
                    await UntilAsync(delegate { return test.A.PeerProtocolForTest == 2 && test.B.PeerProtocolForTest == 1; }, "Mixed native protocols are announced without pretending v2 capability").ConfigureAwait(false);
                    string connect = RuntimeBridge.Hex("blocked-legacy-invitation");
                    await test.ProcessAsync(false, "SOCIAL1 INVITE " + Number(Alice) + " " + connect).ConfigureAwait(false);
                    await Task.Delay(100).ConfigureAwait(false);
                    Check(bob.Count("INVITEFROM ") == 0 && bob.Count("INVITEFROM2 ") == 0 && test.Host.IsPaired && test.B.NativeConnected,
                        "A legacy remote invitation cannot bypass a v2 native consumer's ticketed acceptance path");
                    await bob.SendAsync("INVITE " + Number(Alice) + " " + connect).ConfigureAwait(false);
                    await UntilAsync(delegate { return !test.B.NativeConnected; }, "A v2 native invitation to a legacy peer fails closed").ConfigureAwait(false);
                    Check(test.Controls(true, "SOCIAL1 INVITE ") == 0 && test.Controls(true, "SOCIAL2 OFFER ") == 0 && test.Host.IsPaired,
                        "A v2 sender never downgrades to a legacy remote invitation");
                }
            }
            // Simulate an older launcher that publishes SOCIAL1 presence but no runtime capabilities.
            using (PairSession host = new PairSession())
            using (PairSession guest = new PairSession()) {
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                await guest.JoinAsync(host.Code).ConfigureAwait(false);
                int invites = 0;
                guest.ControlReceived += delegate(string message) { if (message.StartsWith("SOCIAL1 INVITE ", StringComparison.Ordinal) || message.StartsWith("SOCIAL2 OFFER ", StringComparison.Ordinal)) Interlocked.Increment(ref invites); };
                using (RuntimeBridge bridge = new RuntimeBridge(host, Alice, "Alice")) {
                    await guest.SendControlAsync("SOCIAL1 PROFILE " + Number(Bob) + " " + RuntimeBridge.Hex("Bob") + " 1").ConfigureAwait(false);
                    await UntilAsync(delegate { return bridge.PeerSteamId == Bob; }, "Legacy-only launcher presence supplies identity without v2 capability").ConfigureAwait(false);
                    using (FakeNative alice = await FakeNative.OpenAsync(bridge, 2, Alice, Bob).ConfigureAwait(false)) {
                        Check(bridge.PeerProtocolForTest == 0, "An unannounced peer protocol remains unknown");
                        await alice.SendAsync("INVITE " + Number(Bob) + " " + RuntimeBridge.Hex("blocked-unknown-capability")).ConfigureAwait(false);
                        await UntilAsync(delegate { return !bridge.NativeConnected; }, "A v2 invitation with unknown peer capability fails closed").ConfigureAwait(false);
                        Check(Thread.VolatileRead(ref invites) == 0 && host.IsPaired, "Unknown capability never produces a legacy invitation or ticketed offer");
                    }
                }
            }
        }
        private static async Task UntilAsync(Func<bool> condition, string label)
        { for (int step = 0; step < 200 && !condition(); ++step) await Task.Delay(25).ConfigureAwait(false); Check(condition(), label); }
    }
}
