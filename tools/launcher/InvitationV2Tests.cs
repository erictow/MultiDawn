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
        internal static string Run() { report.Clear(); Ledger(); NetworkAsync().GetAwaiter().GetResult(); LegacyAsync().GetAwaiter().GetResult(); NoDowngradeAsync().GetAwaiter().GetResult(); return report.ToString(); }

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
            Check(ledger.AcceptOutgoing(Ticket(1), SecondEpoch, FirstEpoch) == null && !outgoing.Accepted, "Acceptance cannot swap the host and guest runtime epochs");
            Check(ledger.AcceptOutgoing(Ticket(1), FirstEpoch, SecondEpoch) == outgoing && outgoing.Accepted, "Only the exact current outgoing offer records accepted intent");
            Check(ledger.AcceptOutgoing(Ticket(1), FirstEpoch, SecondEpoch) == null, "A duplicate acceptance cannot create a second accepted intent");
            InviteRecord incoming = ledger.Receive(Ticket(2), Alice, SecondEpoch, FirstEpoch, "4142", out replaced);
            Check(incoming != null && ledger.Receive(Ticket(2), Alice, SecondEpoch, FirstEpoch, "4142", out replaced) == null, "A repeated incoming offer cannot extend or replace its original lifetime");
            Check(ledger.Receive(Ticket(3), Other, SecondEpoch, FirstEpoch, "4142", out replaced) == null && ledger.Incoming == incoming, "An offer for another Steam identity cannot replace an incoming ticket");
            Check(ledger.AcceptIncoming(Other, Ticket(2)) == null && ledger.AcceptIncoming(Bob, Ticket(3)) == null, "Native acceptance checks both sender and exact incoming ticket");
            Check(ledger.AcceptIncoming(Bob, Ticket(2)) == incoming && ledger.AcceptIncoming(Bob, Ticket(2)) == null, "An incoming invitation can be accepted only once");
            now += 59999;
            Check(ledger.Remaining(outgoing) == 1 && ledger.Expire().Count == 0, "An accepted intent remains valid only through its original deadline");
            ++now;
            Check(ledger.Remaining(outgoing) == 0 && ledger.AcceptOutgoing(Ticket(1), FirstEpoch, SecondEpoch) == null, "An expired acceptance cannot revive its intent");
            Check(ledger.Expire().Count == 2 && ledger.Expire().Count == 0 && ledger.Outgoing == null && ledger.Incoming == null, "Expiry revokes both bounded records once without persisting credentials");
            Check(ledger.Receive(Ticket(2), Alice, SecondEpoch, FirstEpoch, "4142", out replaced) == null, "A recently expired incoming ticket cannot be replayed");
            outgoing = ledger.Offer(Ticket(4), "4142", out replaced);
            InviteRecord next = ledger.Offer(Ticket(5), "4142", out replaced);
            Check(next != null && replaced == outgoing && !outgoing.Active, "Replacing an offer revokes the former outgoing record");
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
