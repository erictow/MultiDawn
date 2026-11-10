using System;
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
    /** Social IPC for the native runtime. It does not carry account or gameplay packets. */
    internal sealed class RuntimeBridge : IDisposable
    {
        private sealed class NativeConnection
        {
            internal readonly NamedPipeServerStream Pipe;
            internal readonly SemaphoreSlim Writes = new SemaphoreSlim(1, 1);
            internal bool Authenticated;
            internal long Generation;
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

        private readonly object sync = new object(), queueLock = new object();
        private readonly PairSession session;
        private readonly CancellationTokenSource lifetime = new CancellationTokenSource();
        private readonly CancellationToken cancellation;
        private readonly ulong localId;
        private readonly string localName;
        private readonly Task listenerWorker, presenceWorker;
        private Task queued = Task.FromResult(0);
        private int queuedCount;
        private NativeConnection native;
        private string boundPeer = "", remoteName = "Paired player";
        private ulong remoteId;
        private long boundGeneration;
        private bool remoteRunning, disposed;
        internal readonly string PipeId = Guid.NewGuid().ToString("N");
        internal readonly string Nonce = Guid.NewGuid().ToString("N");

        internal RuntimeBridge(PairSession paired, string persona) : this(paired, DeviceIdentity.Load(), persona) { }
        internal RuntimeBridge(PairSession paired, ulong identity, string persona)
        {
            if (paired == null || !ValidSteamId(identity)) throw new ArgumentException("Invalid native session identity.");
            ValidateText(persona, 127, false);
            session = paired; localId = identity; localName = persona;
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
                close = native; native = null;
            }
            // Close synchronously on the pairing transition. A queued old invitation cannot
            // keep a previous native consumer connected after its partner has disconnected.
            if (close != null) close.Pipe.Dispose();
            if (paired) Enqueue(PublishProfileAsync, generation);
        }

        private async Task ReceiveControlAsync(long generation, string source, string message)
        {
            lock (sync) if (!CurrentControl(generation, source)) return;
            if (!message.StartsWith("SOCIAL1 ", StringComparison.Ordinal)) return;
            try
            {
                string[] fields = Split(message);
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
                        remoteId = id; remoteName = name; remoteRunning = fields[4] == "1";
                        destination = native != null && native.Authenticated ? native : null;
                    }
                    if (destination != null) await TrySendNativeAsync(destination, "PEER " + fields[2] + " " + fields[3] + " " + fields[4]).ConfigureAwait(false);
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

        private async Task PublishLoopAsync()
        {
            try
            {
                while (true)
                {
                    await PublishProfileAsync().ConfigureAwait(false);
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
            bool running; long generation;
            lock (sync) { generation = boundGeneration; running = native != null && native.Authenticated && native.Generation == generation; }
            try { await session.SendControlAsync("SOCIAL1 PROFILE " + localId.ToString(CultureInfo.InvariantCulture) + " " + Hex(localName) + " " + (running ? "1" : "0"), generation).ConfigureAwait(false); }
            catch (IOException) { }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
        }

        private async Task ListenAsync()
        {
            while (!cancellation.IsCancellationRequested)
            {
                NativeConnection connection = null;
                try
                {
                    connection = new NativeConnection("MultiDawn-" + PipeId);
                    lock (sync) { if (disposed) { connection.Pipe.Dispose(); break; } native = connection; }
                    using (cancellation.Register(delegate { connection.Pipe.Dispose(); }))
                    {
                        await Task.Factory.FromAsync(connection.Pipe.BeginWaitForConnection, connection.Pipe.EndWaitForConnection, null).ConfigureAwait(false);
                        string hello = await ReadFrameAsync(connection.Pipe, cancellation, 5000).ConfigureAwait(false);
                        if (!FixedEquals(hello, "HELLO 1 " + Nonce)) throw new IOException("Native companion authentication failed.");
                        DateTime deadline = DateTime.UtcNow.AddSeconds(5);
                        ulong peerId;
                        string name;
                        bool running;
                        do
                        {
                            lock (sync)
                            {
                                if (native != connection || disposed) throw new IOException("Native connection was superseded.");
                                peerId = remoteId; name = remoteName; running = remoteRunning;
                                connection.Generation = boundGeneration;
                            }
                            if (peerId != 0) break;
                            await Task.Delay(30, cancellation).ConfigureAwait(false);
                        } while (DateTime.UtcNow < deadline);
                        if (peerId == 0) throw new IOException("The native companion has no authenticated peer profile.");
                        await SendNativeAsync(connection, "WELCOME 1 " + localId.ToString(CultureInfo.InvariantCulture) + " " + peerId.ToString(CultureInfo.InvariantCulture) + " " + Hex(name) + " " + (running ? "1" : "0")).ConfigureAwait(false);
                        lock (sync) { if (native != connection || connection.Generation != boundGeneration) throw new IOException("Native connection was superseded."); connection.Authenticated = true; }
                        await PublishProfileAsync().ConfigureAwait(false);
                        while (true)
                        {
                            string[] fields = Split(await ReadFrameAsync(connection.Pipe, cancellation, 0).ConfigureAwait(false));
                            if (fields.Length != 3 || fields[0] != "INVITE") throw new IOException("Unexpected native message.");
                            ulong target = Identity(fields[1]);
                            Unhex(fields[2], 255, false);
                            lock (sync) if (target != remoteId || !remoteRunning || native != connection || connection.Generation != boundGeneration) throw new IOException("Invitation recipient is unavailable.");
                            await session.SendControlAsync("SOCIAL1 INVITE " + localId.ToString(CultureInfo.InvariantCulture) + " " + fields[2], connection.Generation).ConfigureAwait(false);
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
                        lock (sync) if (native == connection) native = null;
                        connection.Pipe.Dispose();
                    }
                }
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

        internal static async Task WriteFrameAsync(Stream stream, SemaphoreSlim writes, string message, CancellationToken cancellation)
        {
            ValidateText(message, 1024, false);
            byte[] text = Encoding.ASCII.GetBytes(message), frame = new byte[message.Length + 4];
            byte[] length = BitConverter.GetBytes(text.Length);
            if (!BitConverter.IsLittleEndian) Array.Reverse(length);
            Array.Copy(length, frame, 4); Array.Copy(text, 0, frame, 4, text.Length);
            await writes.WaitAsync(cancellation).ConfigureAwait(false);
            try
            {
                using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                {
                    timeout.CancelAfter(5000);
                    using (timeout.Token.Register(delegate { stream.Dispose(); }))
                        await stream.WriteAsync(frame, 0, frame.Length, timeout.Token).ConfigureAwait(false);
                }
            }
            finally { writes.Release(); }
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
            NativeConnection close;
            lock (sync) { if (disposed) return; disposed = true; close = native; native = null; remoteId = 0; remoteRunning = false; }
            session.ConnectionControlReceived -= ControlReceived; session.PeerChanged -= PeerChanged;
            lifetime.Cancel();
            if (close != null) close.Pipe.Dispose();
        }
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
