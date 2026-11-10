using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MultiDawn.Launcher
{
    internal static class RuntimeBridgeSelfTests
    {
        private static readonly StringBuilder report = new StringBuilder();
        private const ulong Alice = 0x0110000100001011UL, Bob = 0x0110000100002022UL, Other = 0x0110000100003033UL;
        internal static string Run() { report.Clear(); RunAsync().GetAwaiter().GetResult(); return report.ToString(); }

        private static async Task RunAsync()
        {
            Require(RuntimeBridge.ValidSteamId(Alice) && !RuntimeBridge.ValidSteamId(0) && !RuntimeBridge.ValidSteamId(0x0110000100000000UL), "Companion IDs require nonzero individual Steam accounts");
            string connect = new string('X', 255);
            Require(RuntimeBridge.Unhex(RuntimeBridge.Hex(connect), 255, false) == connect, "Maximum native invitation text round trip");
            Reject(delegate { RuntimeBridge.Unhex("00", 255, false); }, "Hex text cannot inject NUL");
            Reject(delegate { RuntimeBridge.Unhex("6a", 255, false); }, "Hex encoding is canonical uppercase");
            Reject(delegate { RuntimeBridge.Unhex("-", 255, false); }, "Empty invitation is rejected");
            using (FragmentedStream fragments = new FragmentedStream(Frame("HELLO 1 fragment")))
                Require(await RuntimeBridge.ReadFrameAsync(fragments, CancellationToken.None, 5000).ConfigureAwait(false) == "HELLO 1 fragment", "Native framing handles fragmented headers and bodies");
            await RejectFrameAsync(new byte[] { 1, 4, 0, 0 }, "Oversized native frame is rejected before allocation").ConfigureAwait(false);
            await RejectFrameAsync(new byte[] { 0, 0, 0, 0 }, "Zero-length native frame is rejected").ConfigureAwait(false);
            await RejectFrameAsync(new byte[] { 1, 0, 0, 0, 0 }, "Native frame rejects nonprintable bytes").ConfigureAwait(false);
            await RejectFrameAsync(new byte[] { 5, 0, 0, 0, 65 }, "Truncated native frame fails closed").ConfigureAwait(false);
            using (PairSession host = new PairSession())
            using (PairSession guest = new PairSession())
            {
                bool rejected = false;
                try { await host.SendControlAsync("test").ConfigureAwait(false); } catch (IOException) { rejected = true; }
                Require(rejected, "Control messages require an authenticated partner");
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                await guest.JoinAsync(host.Code).ConfigureAwait(false);
                string received = null;
                Action<string> capture = delegate(string message) { received = message; };
                guest.ControlReceived += capture;
                string maximumControl = new string('Z', 1024);
                await host.SendControlAsync(maximumControl).ConfigureAwait(false);
                await UntilAsync(delegate { return received == maximumControl; }, "Authenticated control framing supports its full 1024-byte bound").ConfigureAwait(false);
                guest.ControlReceived -= capture;
                rejected = false;
                try { await host.SendControlAsync(new string('Z', 1025)).ConfigureAwait(false); } catch (ArgumentException) { rejected = true; }
                Require(rejected && host.IsPaired, "Oversized outbound controls are rejected without corrupting the channel");
                rejected = false;
                try { await host.SendControlAsync("bad\nmessage").ConfigureAwait(false); } catch (ArgumentException) { rejected = true; }
                Require(rejected && host.IsPaired, "Control messages cannot inject protocol delimiters");
                using (RuntimeBridge hostBridge = new RuntimeBridge(host, Alice, "Alice"))
                using (RuntimeBridge guestBridge = new RuntimeBridge(guest, Bob, "Bob"))
                {
                    await UntilAsync(delegate { return hostBridge.PeerSteamId == Bob && guestBridge.PeerSteamId == Alice; }, "Paired launchers negotiate distinct native identities").ConfigureAwait(false);
                    ProcessStartInfo environment = GameLaunch.CreateStartInfo(Path.GetTempPath());
                    environment.EnvironmentVariables["DAWN_SESSION_TOKEN"] = "stale-token";
                    hostBridge.ApplyEnvironment(environment);
                    Require(environment.EnvironmentVariables["DAWN_COMPANION_ID"] == hostBridge.PipeId && environment.EnvironmentVariables["DAWN_COMPANION_NONCE"] == hostBridge.Nonce
                        && environment.EnvironmentVariables["DAWN_SESSION_MODE"] == "solo", "Native companion credentials stay in an explicit solo child environment");
                    Require(!environment.EnvironmentVariables.ContainsKey("DAWN_SESSION_TOKEN"), "Explicit companion setup removes inherited session credentials");
                    using (NamedPipeClientStream wrong = await ConnectAsync(hostBridge).ConfigureAwait(false))
                    {
                        await SendAsync(wrong, "HELLO 1 " + new string('0', 32)).ConfigureAwait(false);
                        bool closed = false;
                        try { await RuntimeBridge.ReadFrameAsync(wrong, CancellationToken.None, 5000).ConfigureAwait(false); } catch (IOException) { closed = true; }
                        Require(closed && !hostBridge.NativeConnected && host.IsPaired, "Incorrect native nonce is rejected without disconnecting paired launchers");
                    }
                    using (NamedPipeClientStream alice = await AuthenticateAsync(hostBridge, Alice, Bob, "Bob").ConfigureAwait(false))
                    using (NamedPipeClientStream bob = await AuthenticateAsync(guestBridge, Bob, Alice, "Alice").ConfigureAwait(false))
                    {
                        await ReadUntilAsync(alice, "PEER " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("Bob") + " 1").ConfigureAwait(false);
                        Require(hostBridge.NativeConnected && guestBridge.NativeConnected, "Only nonce-authenticated native consumers publish game-running presence");
                        string invitation = "dawn-test:86657:invitation";
                        await SendAsync(alice, "INVITE " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(invitation)).ConfigureAwait(false);
                        await ReadUntilAsync(bob, "INVITEFROM " + Alice.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(invitation)).ConfigureAwait(false);
                        Require(true, "Native invitation crosses the authenticated pair to the correct remote native consumer");
                        await SendAsync(bob, "INVITE " + Alice.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(connect)).ConfigureAwait(false);
                        await ReadUntilAsync(alice, "INVITEFROM " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(connect)).ConfigureAwait(false);
                        Require(true, "Maximum invitation forwards in the reverse direction without heartbeat interleaving");
                        await SendAsync(alice, "INVITE " + Other.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(invitation)).ConfigureAwait(false);
                        await UntilAsync(delegate { return !hostBridge.NativeConnected; }, "Native consumer cannot invite an unrelated identity").ConfigureAwait(false);
                        Require(host.IsPaired && guest.IsPaired, "Rejected native recipient does not terminate the launcher pairing");
                        await host.SendControlAsync("SOCIAL1 INVITE " + Other.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(invitation)).ConfigureAwait(false);
                        await UntilAsync(delegate { return !guest.IsPaired && !host.IsPaired; }, "Peer cannot forge another player's invitation source").ConfigureAwait(false);
                        await UntilAsync(delegate { return !guestBridge.NativeConnected; }, "Pair disconnect closes the native consumer connection").ConfigureAwait(false);
                    }
                }
            }
            await ReconnectAsync().ConfigureAwait(false);
        }

        private static async Task ReconnectAsync()
        {
            using (PairSession host = new PairSession())
            using (PairSession guest = new PairSession())
            {
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                string code = host.Code;
                await guest.JoinAsync(code).ConfigureAwait(false);
                long oldGeneration = host.ConnectionGeneration;
                string oldPeer = host.PeerId;
                using (RuntimeBridge bridge = new RuntimeBridge(host, Alice, "Alice"))
                {
                    await guest.SendControlAsync("SOCIAL1 PROFILE " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("Bob") + " 1").ConfigureAwait(false);
                    await UntilAsync(delegate { return bridge.PeerSteamId == Bob; }, "Reconnect fixture receives the original profile").ConfigureAwait(false);
                    using (NamedPipeClientStream original = await AuthenticateAsync(bridge, Alice, Bob, "Bob").ConfigureAwait(false))
                    {
                        TaskCompletionSource<bool> release = new TaskCompletionSource<bool>();
                        bridge.HoldControlsForTest(release.Task);
                        int observed = 0;
                        Action<string> capture = delegate(string message) { if (message.StartsWith("SOCIAL1 ", StringComparison.Ordinal)) Interlocked.Increment(ref observed); };
                        host.ControlReceived += capture;
                        try
                        {
                            // The old profile conflicts with Bob on purpose. Replaying it must neither
                            // repopulate the new session nor disconnect it when fresh Bob arrives.
                            await guest.SendControlAsync("SOCIAL1 PROFILE " + Other.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("Stale") + " 1").ConfigureAwait(false);
                            await guest.SendControlAsync("SOCIAL1 INVITE " + Other.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("stale-invitation")).ConfigureAwait(false);
                            await UntilAsync(delegate { return Thread.VolatileRead(ref observed) == 2; }, "Old profile and invite are queued from the authenticated TCP connection").ConfigureAwait(false);
                            guest.Disconnect();
                            await UntilAsync(delegate { return !host.IsPaired && !bridge.NativeConnected; }, "Disconnect clears the old native consumer before queued controls run").ConfigureAwait(false);
                            await guest.JoinAsync(code).ConfigureAwait(false);
                            await UntilAsync(delegate { return host.IsPaired && guest.IsPaired; }, "The same launcher objects reconnect").ConfigureAwait(false);
                            Require(host.PeerId == oldPeer && host.ConnectionGeneration > oldGeneration, "Reconnecting the same peer identity creates a new connection generation");
                            bool rejected = false;
                            try { await host.SendControlAsync("stale outbound invitation", oldGeneration).ConfigureAwait(false); } catch (IOException) { rejected = true; }
                            Require(rejected && host.IsPaired, "An outbound message from an old connection cannot use the replacement socket");
                            host.Disconnect(oldGeneration);
                            Require(host.IsPaired, "A delayed old connection error cannot disconnect the replacement socket");
                        }
                        finally
                        {
                            host.ControlReceived -= capture;
                            release.TrySetResult(true);
                        }
                        Task drained = bridge.DrainControlsForTest();
                        Require(await Task.WhenAny(drained, Task.Delay(5000)).ConfigureAwait(false) == drained, "Queued old controls drain after reconnect");
                        await drained.ConfigureAwait(false);
                        Require(bridge.PeerSteamId == 0 && host.IsPaired && guest.IsPaired, "Old queued profile and invite cannot republish identity or break the new pair");
                    }
                    await guest.SendControlAsync("SOCIAL1 PROFILE " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("Bob") + " 1").ConfigureAwait(false);
                    await UntilAsync(delegate { return bridge.PeerSteamId == Bob; }, "The replacement connection accepts a fresh peer profile").ConfigureAwait(false);
                    using (NamedPipeClientStream replacement = await AuthenticateAsync(bridge, Alice, Bob, "Bob").ConfigureAwait(false))
                    {
                        await guest.SendControlAsync("SOCIAL1 INVITE " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("fresh-invitation")).ConfigureAwait(false);
                        await ReadUntilAsync(replacement, "INVITEFROM " + Bob.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex("fresh-invitation")).ConfigureAwait(false);
                        Require(host.IsPaired && guest.IsPaired, "Fresh invitations reach the replacement native consumer without stale delivery");
                    }
                }
            }
        }
        private sealed class FragmentedStream : MemoryStream
        {
            internal FragmentedStream(byte[] bytes) : base(bytes) { }
            public override Task<int> ReadAsync(byte[] bytes, int offset, int count, CancellationToken cancellation) { return base.ReadAsync(bytes, offset, Math.Min(count, 1), cancellation); }
        }
        private static byte[] Frame(string text)
        {
            byte[] body = Encoding.ASCII.GetBytes(text), frame = new byte[text.Length + 4];
            Array.Copy(BitConverter.GetBytes(body.Length), frame, 4); Array.Copy(body, 0, frame, 4, body.Length); return frame;
        }
        private static async Task RejectFrameAsync(byte[] frame, string name)
        {
            bool rejected = false;
            using (MemoryStream stream = new MemoryStream(frame))
                try { await RuntimeBridge.ReadFrameAsync(stream, CancellationToken.None, 5000).ConfigureAwait(false); } catch (IOException) { rejected = true; }
            Require(rejected, name);
        }
        private static async Task<NamedPipeClientStream> ConnectAsync(RuntimeBridge bridge)
        {
            NamedPipeClientStream pipe = new NamedPipeClientStream(".", "MultiDawn-" + bridge.PipeId, PipeDirection.InOut, PipeOptions.Asynchronous);
            try { await Task.Run(delegate { pipe.Connect(5000); }).ConfigureAwait(false); return pipe; }
            catch { pipe.Dispose(); throw; }
        }
        private static async Task<NamedPipeClientStream> AuthenticateAsync(RuntimeBridge bridge, ulong localId, ulong peerId, string name)
        {
            NamedPipeClientStream pipe = await ConnectAsync(bridge).ConfigureAwait(false);
            try
            {
                await SendAsync(pipe, "HELLO 1 " + bridge.Nonce).ConfigureAwait(false);
                string response = await RuntimeBridge.ReadFrameAsync(pipe, CancellationToken.None, 5000).ConfigureAwait(false);
                Require(response.StartsWith("WELCOME 1 " + localId.ToString(CultureInfo.InvariantCulture) + " " + peerId.ToString(CultureInfo.InvariantCulture) + " " + RuntimeBridge.Hex(name) + " ", StringComparison.Ordinal), "Native handshake returns the authenticated peer identity");
                await UntilAsync(delegate { return bridge.NativeConnected; }, "Native pipe handshake completes").ConfigureAwait(false);
                return pipe;
            }
            catch { pipe.Dispose(); throw; }
        }
        private static async Task SendAsync(Stream stream, string message)
        {
            using (SemaphoreSlim gate = new SemaphoreSlim(1, 1))
                await RuntimeBridge.WriteFrameAsync(stream, gate, message, CancellationToken.None).ConfigureAwait(false);
        }
        private static async Task ReadUntilAsync(Stream stream, string expected)
        {
            for (int i = 0; i < 12; i++)
            {
                string message = await RuntimeBridge.ReadFrameAsync(stream, CancellationToken.None, 5000).ConfigureAwait(false);
                if (message == expected) return;
                if (message != "PING" && !message.StartsWith("PEER ", StringComparison.Ordinal)) throw new IOException("Unexpected native test message: " + message);
            }
            throw new IOException("Expected native test message was not received.");
        }
        private static async Task UntilAsync(Func<bool> condition, string name)
        {
            for (int i = 0; i < 170 && !condition(); i++) await Task.Delay(30).ConfigureAwait(false);
            Require(condition(), name);
        }
        private static void Reject(Action action, string name)
        {
            bool rejected = false;
            try { action(); } catch (IOException) { rejected = true; } catch (ArgumentException) { rejected = true; }
            Require(rejected, name);
        }
        private static void Require(bool value, string name)
        {
            report.AppendLine((value ? "PASS: " : "FAIL: ") + name);
            if (!value) throw new Exception("Runtime bridge test failed: " + name);
        }
    }
}
