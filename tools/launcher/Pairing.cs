using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MultiDawn.Launcher
{
    // Pair codes identify a reachable endpoint. They are not a rendezvous or NAT relay.
    public sealed class PairCode
    {
        public IPAddress Address { get; private set; }
        public int Port { get; private set; }
        public string Token { get; private set; }

        public static string Create(IPAddress host, int port, string token)
        {
            ValidateAddress(host);
            if (port < 1 || port > 65535) throw new ArgumentException("Port must be between 1 and 65535.");
            byte[] secret;
            try { secret = Decode(token); }
            catch (FormatException) { throw new ArgumentException("Invalid pairing token."); }
            if (secret.Length != 16 || Encode(secret) != token) throw new ArgumentException("Invalid pairing token.");
            byte[] payload = new byte[26];
            Array.Copy(host.GetAddressBytes(), 0, payload, 0, 4);
            payload[4] = (byte)(port >> 8);
            payload[5] = (byte)port;
            Array.Copy(secret, 0, payload, 6, 16);
            using (SHA256 hash = SHA256.Create()) Array.Copy(hash.ComputeHash(payload, 0, 22), 0, payload, 22, 4);
            return "MD2-" + Encode(payload);
        }

        public static PairCode Parse(string value)
        {
            value = (value ?? "").Trim();
            if (value.Length != 39 || !value.StartsWith("MD2-", StringComparison.Ordinal))
                throw new FormatException("Enter the complete MD2 pair code from the host.");
            byte[] payload;
            try { payload = Decode(value.Substring(4)); }
            catch (FormatException) { throw new FormatException("The pair code contains invalid characters."); }
            if (payload.Length != 26 || Encode(payload) != value.Substring(4)) throw new FormatException("Invalid pair code.");
            using (SHA256 hash = SHA256.Create())
            {
                byte[] checksum = hash.ComputeHash(payload, 0, 22);
                int different = 0;
                for (int i = 0; i < 4; i++) different |= checksum[i] ^ payload[22 + i];
                if (different != 0) throw new FormatException("The pair code is mistyped or incomplete.");
            }
            byte[] ip = new byte[4];
            byte[] secret = new byte[16];
            Array.Copy(payload, 0, ip, 0, 4);
            Array.Copy(payload, 6, secret, 0, 16);
            IPAddress address = new IPAddress(ip);
            try { ValidateAddress(address); }
            catch (ArgumentException) { throw new FormatException("The pair code has an invalid host address."); }
            int port = (payload[4] << 8) | payload[5];
            if (port == 0) throw new FormatException("The pair code has an invalid port.");
            return new PairCode { Address = address, Port = port, Token = Encode(secret) };
        }

        internal static void ValidateAddress(IPAddress address)
        {
            if (address == null || address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Select an IPv4 address on your LAN or VPN.");
            byte[] bytes = address.GetAddressBytes();
            if (bytes[0] == 0 || bytes[0] >= 224 || (bytes[0] == 169 && bytes[1] == 254))
                throw new ArgumentException("Select a unicast IPv4 address on your LAN or VPN.");
        }

        internal static string RandomToken()
        {
            byte[] value = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(value);
            return Encode(value);
        }

        internal static string Encode(byte[] value) { return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
        internal static byte[] Decode(string value)
        {
            if (String.IsNullOrEmpty(value)) throw new FormatException();
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_')
                    throw new FormatException();
            }
            string text = value.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(text.PadRight((text.Length + 3) / 4 * 4, '='));
        }
    }

    public sealed class PairSession : IDisposable
    {
        private sealed class SessionLifetime : IDisposable
        {
            private readonly CancellationTokenSource source = new CancellationTokenSource();
            private int references = 1;
            private int cancelled;
            public readonly CancellationToken Token;
            public SessionLifetime() { Token = source.Token; }
            public bool IsCancellationRequested { get { return Token.IsCancellationRequested; } }
            public void AddWorker() { Interlocked.Increment(ref references); }
            public void WorkerDone() { if (Interlocked.Decrement(ref references) == 0) source.Dispose(); }
            public void Cancel()
            {
                if (Interlocked.Exchange(ref cancelled, 1) != 0) return;
                try { source.Cancel(); }
                finally { WorkerDone(); }
            }
            public void Dispose() { Cancel(); }
        }

        private readonly object sync = new object();
        private readonly string localPeerId;
        private readonly int preferredHostPort;
        private SessionLifetime lifetime;
        private TcpListener listener;
        private TcpClient peer;
        // WaitAsync does not create an unmanaged wait handle. Retain one gate across reconnects
        // so a concurrent control send can never wait on a disposed semaphore.
        private readonly SemaphoreSlim controlWrites = new SemaphoreSlim(1, 1);
        private SemaphoreSlim peerWrites;
        private PairProtection peerProtection;
        private CancellationToken peerCancellation;
        private long connectionGeneration;
        private readonly HashSet<TcpClient> pending = new HashSet<TcpClient>();
        private bool isHost;
        private string code = "", token = "", peerId = "";
        private IPAddress address;
        private int port;
        private int peerHostPort;

        public PairSession() : this(NewPeerId(), 30979) { }
        public PairSession(string persistentPeerId, int preferredListenPort)
        {
            if (!ValidIdentity(persistentPeerId)) throw new ArgumentException("Invalid persistent launcher identity.");
            if (preferredListenPort < 1 || preferredListenPort > 65535) throw new ArgumentException("Invalid preferred hosting port.");
            localPeerId = persistentPeerId; preferredHostPort = preferredListenPort;
        }

        public event Action<string> StatusChanged;
        public event Action<bool> PeerChanged;
        public event Action PeerEndpointChanged;
        /** Post-authenticated bounded launcher control messages. They are not gameplay packets. */
        public event Action<string> ControlReceived;
        internal event Action<long, string, string> ConnectionControlReceived;
        public long ConnectionGeneration { get { lock (sync) return connectionGeneration; } }
        internal void ConnectionSnapshot(out long generation, out string identity)
        { lock (sync) { generation = connectionGeneration; identity = peer == null ? "" : peerId; } }
        public bool IsHost { get { lock (sync) return isHost; } }
        public bool IsPaired { get { lock (sync) return peer != null; } }
        public string Code { get { lock (sync) return code; } }
        public string Token { get { lock (sync) return token; } }
        public string PeerId { get { lock (sync) return peerId; } }
        public string LocalPeerId { get { return localPeerId; } }
        public IPAddress Address { get { lock (sync) return address; } }
        public int Port { get { lock (sync) return port; } }
        public static string NewPeerId() { return PairCode.RandomToken(); }
        public bool TryPeerEndpoint(out string identity, out IPEndPoint endpoint)
        {
            lock (sync)
            {
                identity = ""; endpoint = null;
                if (peer == null || peerHostPort == 0) return false;
                IPEndPoint remote;
                try { Socket socket = peer.Client; if (socket == null) return false; remote = socket.RemoteEndPoint as IPEndPoint; }
                catch (SocketException) { return false; }
                catch (ObjectDisposedException) { return false; }
                if (remote == null) return false;
                identity = peerId; endpoint = new IPEndPoint(remote.Address, peerHostPort); return true;
            }
        }

        public Task SendControlAsync(string message) { return SendControlAsync(message, ConnectionGeneration); }

        public async Task SendControlAsync(string message, long expectedGeneration)
        {
            if (String.IsNullOrEmpty(message) || message.Length > 1024) throw new ArgumentException("Invalid control message size.");
            foreach (char value in message) if (value < 32 || value > 126) throw new ArgumentException("Control messages must be printable ASCII.");
            TcpClient client; SemaphoreSlim gate; PairProtection protection; SessionLifetime current; CancellationToken cancellation;
            lock (sync)
            {
                client = peer; gate = peerWrites; protection = peerProtection; current = lifetime;
                if (client == null || gate == null || protection == null || current == null || connectionGeneration != expectedGeneration)
                    throw new IOException("The authenticated partner connection is no longer current.");
                current.AddWorker();
                cancellation = peerCancellation;
            }
            try
            {
                await SerializedWriteAsync(client.GetStream(), gate, protection, "CONTROL " + message, cancellation).ConfigureAwait(false);
            }
            finally { current.WorkerDone(); }
        }

        public Task HostAsync(IPAddress host, int requestedPort)
        {
            PairCode.ValidateAddress(host);
            if (requestedPort < 0 || requestedPort > 65535) throw new ArgumentException("Invalid listen port.");
            Disconnect();
            SessionLifetime current = new SessionLifetime();
            TcpListener acceptor = new TcpListener(host, requestedPort);
            try { acceptor.Start(4); }
            catch { current.Dispose(); throw; }
            lock (sync)
            {
                lifetime = current;
                listener = acceptor;
                isHost = true;
                address = host;
                port = ((IPEndPoint)acceptor.LocalEndpoint).Port;
                token = PairCode.RandomToken();
                code = PairCode.Create(host, port, token);
            }
            // Each async worker handles its own errors and closes its sockets on cancellation.
            AcceptLoopAsync(acceptor, current);
            Publish(current, null, "Hosting: waiting for one player on your LAN or VPN.");
            return Task.FromResult(0);
        }

        public Task JoinAsync(string pairCode) { return JoinAsync(pairCode, null, null, null); }

        public async Task JoinAsync(string pairCode, IPAddress destinationAddress, int? destinationPort, string expectedHostPeerId)
        {
            PairCode parsed = PairCode.Parse(pairCode);
            IPAddress targetAddress = destinationAddress ?? parsed.Address;
            int targetPort = destinationPort ?? parsed.Port;
            PairCode.ValidateAddress(targetAddress);
            if (targetPort < 1 || targetPort > 65535) throw new ArgumentException("Join port must be between 1 and 65535.");
            if (expectedHostPeerId != null && !ValidIdentity(expectedHostPeerId)) throw new ArgumentException("Invalid saved friend identity.");
            Disconnect();
            SessionLifetime current = new SessionLifetime();
            current.AddWorker();
            TcpClient client = new TcpClient(AddressFamily.InterNetwork);
            lock (sync)
            {
                lifetime = current;
                address = targetAddress;
                port = targetPort;
                token = parsed.Token;
                code = pairCode.Trim();
                pending.Add(client);
            }
            Publish(current, null, "Connecting to host...");
            PairProtection protection = null;
            try
            {
                using (current.Token.Register(delegate { client.Close(); }))
                {
                    Task connect = client.ConnectAsync(targetAddress, targetPort);
                    if (await Task.WhenAny(connect, Task.Delay(5000, current.Token)).ConfigureAwait(false) != connect)
                    {
                        current.Token.ThrowIfCancellationRequested();
                        client.Close();
                        Observe(connect);
                        throw new IOException("Host could not be reached. Check the code, LAN/VPN connection, and host firewall.");
                    }
                    await connect.ConfigureAwait(false);
                    current.Token.ThrowIfCancellationRequested();
                    client.NoDelay = true;
                    NetworkStream stream = client.GetStream();
                    string clientNonce = PairCode.RandomToken();
                    await WriteLineAsync(stream, "MD3 HELLO " + clientNonce + " " + localPeerId, current.Token).ConfigureAwait(false);
                    string response = await ReadLineAsync(stream, 5000, current.Token).ConfigureAwait(false);
                    string[] words = response.Split(' ');
                    if (words.Length != 5 || words[0] != "MD3" || words[1] != "CHALLENGE" || !ValidIdentity(words[2]) || !ValidIdentity(words[3])
                        || !SameProof(words[4], Proof(parsed.Token, "host", clientNonce, words[2], localPeerId, words[3])))
                        throw new IOException("The host rejected the pair code or uses a different launcher protocol.");
                    string hostIdentity = words[3];
                    if (expectedHostPeerId != null && !String.Equals(hostIdentity, expectedHostPeerId, StringComparison.Ordinal))
                        throw new IOException("The authenticated host does not match the selected saved friend. Check their current code and address.");
                    await WriteLineAsync(stream, "MD3 PROOF " + Proof(parsed.Token, "join", clientNonce, words[2], localPeerId, hostIdentity), current.Token).ConfigureAwait(false);
                    response = await ReadLineAsync(stream, 5000, current.Token).ConfigureAwait(false);
                    if (response == "MD3 BUSY") throw new IOException("The host already has a paired player.");
                    if (!SameProof(response, "MD3 WELCOME " + hostIdentity + " " + Proof(parsed.Token, "welcome", clientNonce, words[2], localPeerId, hostIdentity)))
                        throw new IOException("The host rejected the pair code or did not confirm this protected connection.");
                    protection = new PairProtection(parsed.Token, clientNonce, words[2], localPeerId, hostIdentity, false);
                    lock (sync)
                    {
                        if (lifetime != current) throw new OperationCanceledException();
                        pending.Remove(client);
                        peer = client;
                        peerHostPort = targetPort;
                        peerProtection = protection;
                        connectionGeneration++;
                        peerId = hostIdentity;
                    }
                    MonitorAsync(client, current, protection);
                    Publish(current, true, "Paired with host. Gameplay multiplayer is not available in this build.");
                }
            }
            catch
            {
                if (protection != null) protection.Dispose();
                client.Close();
                lock (sync)
                {
                    pending.Remove(client);
                    if (lifetime == current)
                    {
                        lifetime = null;
                        if (peer != null) connectionGeneration++;
                        peer = null;
                        peerHostPort = 0;
                        peerWrites = null;
                        peerProtection = null;
                        code = token = peerId = "";
                        address = null;
                        port = 0;
                    }
                }
                current.Cancel();
                throw;
            }
            finally { current.WorkerDone(); }
        }

        private async void AcceptLoopAsync(TcpListener acceptor, SessionLifetime current)
        {
            current.AddWorker();
            try
            {
                while (!current.IsCancellationRequested)
                {
                    TcpClient client = await acceptor.AcceptTcpClientAsync().ConfigureAwait(false);
                    lock (sync)
                    {
                        if (lifetime != current) { client.Close(); break; }
                        pending.Add(client);
                    }
                    await AuthenticateAsync(client, current).ConfigureAwait(false);
                }
            }
            catch (Exception)
            {
                if (!current.IsCancellationRequested)
                {
                    Publish(current, null, "The pairing listener stopped. Disconnect and host again.");
                    Disconnect();
                }
            }
            finally { current.WorkerDone(); }
        }

        private async Task AuthenticateAsync(TcpClient client, SessionLifetime current)
        {
            bool accepted = false;
            PairProtection protection = null;
            try
            {
                using (CancellationTokenSource handshake = CancellationTokenSource.CreateLinkedTokenSource(current.Token))
                {
                    handshake.CancelAfter(5000);
                    using (handshake.Token.Register(delegate { client.Close(); }))
                    {
                    client.NoDelay = true;
                    NetworkStream stream = client.GetStream();
                    string line = await ReadLineAsync(stream, 5000, handshake.Token).ConfigureAwait(false);
                    string[] words = line.Split(' ');
                    string expected;
                    lock (sync) expected = token;
                    if (words.Length != 4 || words[0] != "MD3" || words[1] != "HELLO" || !ValidIdentity(words[2]) || !ValidIdentity(words[3]))
                    {
                        await WriteLineAsync(stream, "MD3 REJECT", handshake.Token).ConfigureAwait(false);
                        return;
                    }
                    string hostNonce = PairCode.RandomToken();
                    await WriteLineAsync(stream, "MD3 CHALLENGE " + hostNonce + " " + localPeerId + " " + Proof(expected, "host", words[2], hostNonce, words[3], localPeerId), handshake.Token).ConfigureAwait(false);
                    string proofLine = await ReadLineAsync(stream, 5000, handshake.Token).ConfigureAwait(false);
                    string expectedProof = "MD3 PROOF " + Proof(expected, "join", words[2], hostNonce, words[3], localPeerId);
                    if (!SameProof(proofLine, expectedProof))
                    {
                        await WriteLineAsync(stream, "MD3 REJECT", handshake.Token).ConfigureAwait(false);
                        return;
                    }
                    bool busy;
                    lock (sync) busy = peer != null;
                    if (busy)
                    {
                        await WriteLineAsync(stream, "MD3 BUSY", handshake.Token).ConfigureAwait(false);
                        return;
                    }
                    protection = new PairProtection(expected, words[2], hostNonce, words[3], localPeerId, true);
                    await WriteLineAsync(stream, "MD3 WELCOME " + localPeerId + " " + Proof(expected, "welcome", words[2], hostNonce, words[3], localPeerId), handshake.Token).ConfigureAwait(false);
                    lock (sync)
                    {
                        if (lifetime != current) return;
                        peer = client;
                        peerHostPort = 0;
                        peerProtection = protection;
                        connectionGeneration++;
                        peerId = words[3];
                        accepted = true;
                    }
                    MonitorAsync(client, current, protection);
                    Publish(current, true, "One player paired. Gameplay multiplayer is not available in this build.");
                    }
                }
            }
            catch (Exception) { /* Malformed, stale, and unreachable peers do not stop the host. */ }
            finally
            {
                lock (sync) pending.Remove(client);
                if (!accepted) { if (protection != null) protection.Dispose(); client.Close(); }
            }
        }

        private async void MonitorAsync(TcpClient client, SessionLifetime current, PairProtection protection)
        {
            current.AddWorker();
            try
            {
            using (CancellationTokenSource monitor = CancellationTokenSource.CreateLinkedTokenSource(current.Token))
            using (monitor.Token.Register(delegate { client.Close(); }))
            {
                lock (sync) { if (lifetime != current || peer != client) return; }
                SemaphoreSlim writes = controlWrites;
                lock (sync) { if (lifetime == current && peer == client) { peerWrites = writes; peerCancellation = monitor.Token; } }
                int advertisedPort;
                lock (sync) advertisedPort = isHost ? port : preferredHostPort;
                Task heartbeat = HeartbeatAsync(client, writes, protection, monitor.Token, advertisedPort);
                Task reader = ReadPeerAsync(client, writes, protection, current, monitor.Token);
                try { await Task.WhenAny(heartbeat, reader).ConfigureAwait(false); }
                catch (Exception) { }
                monitor.Cancel();
                try { await Task.WhenAll(heartbeat, reader).ConfigureAwait(false); }
                catch (Exception) { }
            }
            bool changed = false, hosting = false;
            lock (sync)
            {
                if (lifetime == current && peer == client)
                {
                    peer = null;
                    peerHostPort = 0;
                    connectionGeneration++;
                    peerWrites = null;
                    peerProtection = null;
                    peerId = "";
                    changed = true;
                    hosting = isHost;
                    if (!hosting)
                    {
                        code = token = "";
                        address = null;
                        port = 0;
                    }
                }
            }
            client.Close();
            if (changed)
            {
                Publish(current, false, hosting ? "Player disconnected. Waiting for another player." : "Host disconnected. Choose Disconnect, then enter a current code to reconnect.");
            }
            }
            finally { if (protection != null) protection.Dispose(); current.WorkerDone(); }
        }

        private static async Task HeartbeatAsync(TcpClient client, SemaphoreSlim writes, PairProtection protection, CancellationToken cancellation, int advertisedPort)
        {
            await SerializedWriteAsync(client.GetStream(), writes, protection, "CONTROL FRIEND1 PORT " + advertisedPort.ToString(System.Globalization.CultureInfo.InvariantCulture), cancellation).ConfigureAwait(false);
            while (true)
            {
                await Task.Delay(2000, cancellation).ConfigureAwait(false);
                await SerializedWriteAsync(client.GetStream(), writes, protection, "PING", cancellation).ConfigureAwait(false);
            }
        }

        private async Task ReadPeerAsync(TcpClient client, SemaphoreSlim writes, PairProtection protection, SessionLifetime current, CancellationToken cancellation)
        {
            NetworkStream stream = client.GetStream();
            while (true)
            {
                string line = protection.Open(await ReadLineAsync(stream, 10000, cancellation, PairProtection.MaximumWireLength).ConfigureAwait(false));
                if (line == "PING") await SerializedWriteAsync(stream, writes, protection, "PONG", cancellation).ConfigureAwait(false);
                else if (line.StartsWith("CONTROL ", StringComparison.Ordinal))
                {
                    string message = line.Substring(8);
                    if (message.Length == 0 || message.Length > 1024) throw new IOException("Invalid control message size.");
                    lock (sync)
                    {
                        if (lifetime != current || peer != client) return;
                        if (message.StartsWith("FRIEND1 PORT ", StringComparison.Ordinal))
                        {
                            int advertised;
                            string value = message.Substring(13);
                            if (!Int32.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out advertised)
                                || advertised < 1 || advertised > 65535 || value != advertised.ToString(System.Globalization.CultureInfo.InvariantCulture))
                                throw new IOException("Invalid authenticated friend endpoint.");
                            peerHostPort = advertised;
                            Action endpointChanged = PeerEndpointChanged;
                            if (endpointChanged != null) endpointChanged();
                            continue;
                        }
                        Action<long, string, string> boundReceiver = ConnectionControlReceived;
                        if (boundReceiver != null) boundReceiver(connectionGeneration, peerId, message);
                        Action<string> receiver = ControlReceived;
                        if (receiver != null) receiver(message);
                    }
                }
                else if (line != "PONG") throw new IOException("Unexpected pairing message.");
            }
        }

        private static async Task SerializedWriteAsync(NetworkStream stream, SemaphoreSlim gate, PairProtection protection, string line, CancellationToken cancellation)
        {
            await gate.WaitAsync(cancellation).ConfigureAwait(false);
            try
            {
                cancellation.ThrowIfCancellationRequested();
                await WriteLineAsync(stream, protection.Seal(line), cancellation).ConfigureAwait(false);
            }
            catch { stream.Close(); throw; } // A failed write consumes its sequence; this stream cannot continue.
            finally { gate.Release(); }
        }

        internal static async Task WriteLineAsync(NetworkStream stream, string line, CancellationToken cancellation)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(line + "\n");
            using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                timeout.CancelAfter(5000);
                using (timeout.Token.Register(delegate { stream.Close(); }))
                    await stream.WriteAsync(bytes, 0, bytes.Length, timeout.Token).ConfigureAwait(false);
            }
        }

        internal static async Task<string> ReadLineAsync(NetworkStream stream, int milliseconds, CancellationToken cancellation, int maximum = 512)
        {
            byte[] one = new byte[1];
            StringBuilder line = new StringBuilder();
            using (CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                timeout.CancelAfter(milliseconds);
                using (timeout.Token.Register(delegate { stream.Close(); }))
                {
                    while (line.Length <= maximum)
                    {
                        int read = await stream.ReadAsync(one, 0, 1, timeout.Token).ConfigureAwait(false);
                        if (read == 0) throw new IOException("Peer disconnected.");
                        if (one[0] == 10) return line.ToString().TrimEnd('\r');
                        if (one[0] < 32 || one[0] > 126) throw new IOException("Invalid pairing message.");
                        line.Append((char)one[0]);
                    }
                }
            }
            throw new IOException("Pairing message exceeds the size limit.");
        }

        private static string Proof(string secret, string role, string clientNonce, string hostNonce, string clientIdentity, string hostIdentity)
        {
            using (HMACSHA256 hmac = new HMACSHA256(PairCode.Decode(secret)))
                return PairCode.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes("MD3|" + role + "|" + clientNonce + "|" + hostNonce + "|" + clientIdentity + "|" + hostIdentity)));
        }
        private static bool SameProof(string actual, string expected)
        {
            if (actual.Length != expected.Length) return false;
            int different = 0;
            for (int i = 0; i < actual.Length; i++) different |= actual[i] ^ expected[i];
            return different == 0;
        }
        internal static bool ValidIdentity(string value)
        {
            try { return value != null && value.Length == 22 && PairCode.Decode(value).Length == 16 && PairCode.Encode(PairCode.Decode(value)) == value; }
            catch (FormatException) { return false; }
        }
        private static async void Observe(Task task) { try { await task.ConfigureAwait(false); } catch (Exception) { } }
        // Publish in the same lock as state transitions. A superseded worker cannot enqueue
        // a connected event after Disconnect or a new session has already changed the state.
        // UI subscribers should queue work to their UI thread and read current properties.
        private void Publish(SessionLifetime current, bool? paired, string status)
        {
            lock (sync)
            {
                if (lifetime != current || (paired.HasValue && paired.Value != (peer != null))) return;
                if (paired.HasValue) NotifyPeer(paired.Value);
                if (lifetime != current) return;
                Action<string> handler = StatusChanged;
                if (handler != null) handler(status);
            }
        }
        private void NotifyPeer(bool value) { Action<bool> handler = PeerChanged; if (handler != null) handler(value); }

        public void Disconnect() { DisconnectCore(null); }
        internal void Disconnect(long expectedGeneration) { DisconnectCore(expectedGeneration); }

        private void DisconnectCore(long? expectedGeneration)
        {
            SessionLifetime old;
            TcpListener acceptor;
            TcpClient active;
            TcpClient[] waiting;
            bool changed;
            lock (sync)
            {
                if (expectedGeneration.HasValue && connectionGeneration != expectedGeneration.Value) return;
                old = lifetime;
                lifetime = null;
                acceptor = listener;
                listener = null;
                active = peer;
                if (active != null) connectionGeneration++;
                peer = null;
                peerHostPort = 0;
                peerWrites = null;
                peerProtection = null;
                waiting = new TcpClient[pending.Count];
                pending.CopyTo(waiting);
                pending.Clear();
                changed = active != null;
                isHost = false;
                code = token = peerId = "";
                address = null;
                port = 0;
                if (changed) NotifyPeer(false);
            }
            if (old != null) old.Cancel();
            if (acceptor != null) acceptor.Stop();
            if (active != null) active.Close();
            foreach (TcpClient client in waiting) client.Close();
        }
        public void Dispose() { Disconnect(); }
    }

    public static class PairingSelfTests
    {
        public static string LastError { get; private set; }
        public static string Report { get; private set; }
        public static int Run()
        {
            LastError = "";
            Report = "";
            try { RunAsync().GetAwaiter().GetResult(); Console.WriteLine("Pairing self-tests passed."); return 0; }
            catch (Exception error) { LastError = error.ToString(); Report += "FAIL: " + error.Message + Environment.NewLine; Console.Error.WriteLine("Pairing self-tests failed: " + error.Message); return 1; }
        }

        private static async Task RunAsync()
        {
            string token = PairCode.RandomToken();
            string code = PairCode.Create(IPAddress.Parse("192.168.1.50"), 31871, token);
            PairCode parsed = PairCode.Parse(code);
            Require(parsed.Address.ToString() == "192.168.1.50" && parsed.Port == 31871 && parsed.Token == token, "Code round trip");
            MustReject(delegate { PairCode.Parse("MD1-" + code.Substring(4)); }, "Legacy MD1 pair codes are rejected before connecting");
            MustReject(delegate { PairCode.Parse(code.Substring(0, 38)); }, "Truncated code");
            MustReject(delegate { PairCode.Parse(code.Substring(0, 10) + (code[10] == 'A' ? "B" : "A") + code.Substring(11)); }, "Checksum");
            MustReject(delegate { PairCode.Create(IPAddress.Any, 1, token); }, "Wildcard address");
            MustReject(delegate { PairCode.Create(IPAddress.Parse("239.1.2.3"), 1, token); }, "Multicast address");
            MustReject(delegate { PairCode.Create(IPAddress.Loopback, 0, token); }, "Zero port");
            using (PairSession host = new PairSession())
            using (PairSession joiner = new PairSession())
            using (PairSession third = new PairSession())
            {
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                int actualPort = host.Port;
                await RejectedHandshakeAsync(actualPort, "MD1 HELLO " + token + " " + PairSession.NewPeerId()).ConfigureAwait(false);
                await RejectedHandshakeAsync(actualPort, "MD2 HELLO " + PairSession.NewPeerId() + " " + PairSession.NewPeerId()).ConfigureAwait(false);
                await RejectedHandshakeAsync(actualPort, "MD3 HELLO malformed " + PairSession.NewPeerId()).ConfigureAwait(false);
                await RejectedGuestProofAsync(host).ConfigureAwait(false);
                await RejectedReplayAsync(host).ConfigureAwait(false);
                await RejectedPostHandshakeAsync(host, false).ConfigureAwait(false);
                await RejectedPostHandshakeAsync(host, true).ConfigureAwait(false);
                await MalformedFrameAsync(actualPort, Encoding.ASCII.GetBytes(new string('x', 513) + "\n")).ConfigureAwait(false);
                await MalformedFrameAsync(actualPort, new byte[] { 255, 10 }).ConfigureAwait(false);
                string stale = PairCode.Create(IPAddress.Loopback, actualPort, token);
                bool rejected = false;
                try { await third.JoinAsync(stale).ConfigureAwait(false); }
                catch (IOException) { rejected = true; }
                Require(rejected && !third.IsPaired, "Invalid token rejected");
                await joiner.JoinAsync(host.Code).ConfigureAwait(false);
                await UntilAsync(delegate { return host.IsPaired; }, "Host paired").ConfigureAwait(false);
                Require(joiner.IsPaired && host.PeerId == joiner.LocalPeerId && joiner.PeerId == host.LocalPeerId, "Authenticated peer identities");
                await ConcurrentControlsAsync(host, joiner).ConfigureAwait(false);
                long oldGeneration = host.ConnectionGeneration;
                rejected = false;
                try { await third.JoinAsync(host.Code).ConfigureAwait(false); }
                catch (IOException) { rejected = true; }
                Require(rejected && host.IsPaired && joiner.IsPaired, "Third player rejected");
                await Task.Delay(2300).ConfigureAwait(false);
                Require(host.IsPaired && joiner.IsPaired, "Heartbeat keeps pair connected");
                joiner.Disconnect();
                await UntilAsync(delegate { return !host.IsPaired; }, "Host detects disconnect").ConfigureAwait(false);
                await third.JoinAsync(host.Code).ConfigureAwait(false);
                await UntilAsync(delegate { return host.IsPaired; }, "Host accepts replacement peer").ConfigureAwait(false);
                rejected = false;
                try { await host.SendControlAsync("stale connection", oldGeneration).ConfigureAwait(false); }
                catch (IOException) { rejected = true; }
                Require(rejected && host.IsPaired && third.IsPaired, "Stale send generation cannot write onto a replacement protected connection");
                await ConcurrentControlsAsync(host, third).ConfigureAwait(false);
                host.Disconnect();
                await UntilAsync(delegate { return !third.IsPaired; }, "Joiner detects host shutdown").ConfigureAwait(false);
                TcpListener rebound = new TcpListener(IPAddress.Loopback, actualPort);
                rebound.Start();
                rebound.Stop();
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                using (TcpClient silent = new TcpClient())
                {
                    await silent.ConnectAsync(IPAddress.Loopback, host.Port).ConfigureAwait(false);
                    host.Disconnect();
                    Require(!host.IsPaired && host.Code == "", "Cancellation clears pending handshake");
                }
            }
            await CancelJoinAsync().ConfigureAwait(false);
            await RejectedWelcomeAsync().ConfigureAwait(false);
            PairProtectionSelfTests.Run(Require);
        }

        private static async Task RejectedWelcomeAsync()
        {
            for (int variant = 0; variant < 3; ++variant)
            {
                TcpListener substitute = new TcpListener(IPAddress.Loopback, 0);
                substitute.Start();
                try
                {
                    using (PairSession guest = new PairSession())
                    {
                        string secret = PairCode.RandomToken(), hostIdentity = PairSession.NewPeerId(), hostNonce = PairSession.NewPeerId();
                        bool published = false;
                        guest.PeerChanged += delegate(bool paired) { if (paired) published = true; };
                        Task joining = guest.JoinAsync(PairCode.Create(IPAddress.Loopback, ((IPEndPoint)substitute.LocalEndpoint).Port, secret));
                        using (TcpClient server = await substitute.AcceptTcpClientAsync().ConfigureAwait(false))
                        {
                            NetworkStream stream = server.GetStream();
                            string[] hello = (await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false)).Split(' ');
                            string challengeProof = TestProof(secret, "host", hello[2], hostNonce, hello[3], hostIdentity);
                            await PairSession.WriteLineAsync(stream, "MD3 CHALLENGE " + hostNonce + " " + hostIdentity + " " + challengeProof, CancellationToken.None).ConfigureAwait(false);
                            await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false);
                            string welcome = "MD3 WELCOME " + hostIdentity;
                            if (variant == 1) welcome += " " + PairCode.Encode(new byte[32]);
                            if (variant == 2) welcome += " " + TestProof(secret, "welcome", hello[2], PairSession.NewPeerId(), hello[3], hostIdentity);
                            await PairSession.WriteLineAsync(stream, welcome, CancellationToken.None).ConfigureAwait(false);
                            bool rejected = false;
                            try { await joining.ConfigureAwait(false); } catch (IOException) { rejected = true; }
                            Require(rejected && !guest.IsPaired && !published, variant == 0 ? "Unauthenticated welcome cannot publish a paired connection" : variant == 1 ? "Forged welcome proof cannot publish a paired connection" : "Welcome from another handshake cannot publish a paired connection");
                        }
                    }
                }
                finally { substitute.Stop(); }
            }
        }
        private static string TestProof(string secret, string role, string clientNonce, string hostNonce, string clientIdentity, string hostIdentity)
        {
            using (HMACSHA256 hmac = new HMACSHA256(PairCode.Decode(secret)))
                return PairCode.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes("MD3|" + role + "|" + clientNonce + "|" + hostNonce + "|" + clientIdentity + "|" + hostIdentity)));
        }

        private static async Task ConcurrentControlsAsync(PairSession host, PairSession joiner)
        {
            int hostReceived = 0, guestReceived = 0;
            HashSet<string> hostMessages = new HashSet<string>(), guestMessages = new HashSet<string>();
            Action<string> atHost = delegate(string message) { lock (hostMessages) { if (message.StartsWith("test guest ", StringComparison.Ordinal)) { hostMessages.Add(message); Interlocked.Increment(ref hostReceived); } } };
            Action<string> atGuest = delegate(string message) { lock (guestMessages) { if (message.StartsWith("test host ", StringComparison.Ordinal)) { guestMessages.Add(message); Interlocked.Increment(ref guestReceived); } } };
            host.ControlReceived += atHost; joiner.ControlReceived += atGuest;
            try
            {
                List<Task> sends = new List<Task>();
                for (int index = 0; index < 24; ++index)
                {
                    sends.Add(host.SendControlAsync("test host " + index));
                    sends.Add(joiner.SendControlAsync("test guest " + index));
                }
                await Task.WhenAll(sends).ConfigureAwait(false);
                await UntilAsync(delegate { return Volatile.Read(ref hostReceived) == 24 && Volatile.Read(ref guestReceived) == 24; }, "Concurrent protected controls delivered in both directions").ConfigureAwait(false);
                lock (hostMessages) lock (guestMessages) Require(hostMessages.Count == 24 && guestMessages.Count == 24 && host.IsPaired && joiner.IsPaired, "Protected controls arrive exactly once without disrupting heartbeat");
            }
            finally { host.ControlReceived -= atHost; joiner.ControlReceived -= atGuest; }
        }

        private static async Task RejectedPostHandshakeAsync(PairSession host, bool tamper)
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(IPAddress.Loopback, host.Port).ConfigureAwait(false);
                NetworkStream stream = client.GetStream();
                string nonce = PairSession.NewPeerId(), identity = PairSession.NewPeerId();
                await PairSession.WriteLineAsync(stream, "MD3 HELLO " + nonce + " " + identity, CancellationToken.None).ConfigureAwait(false);
                string[] challenge = (await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false)).Split(' ');
                string proof;
                using (HMACSHA256 hmac = new HMACSHA256(PairCode.Decode(host.Token)))
                    proof = PairCode.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes("MD3|join|" + nonce + "|" + challenge[2] + "|" + identity + "|" + challenge[3])));
                await PairSession.WriteLineAsync(stream, "MD3 PROOF " + proof, CancellationToken.None).ConfigureAwait(false);
                Require((await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false)).StartsWith("MD3 WELCOME ", StringComparison.Ordinal), "Protected rejection setup authenticates");
                await UntilAsync(delegate { return host.IsPaired; }, "Protected rejection setup host paired").ConfigureAwait(false);
                string frame = "MD2 CONTROL dGVzdA==";
                using (PairProtection protection = new PairProtection(host.Token, nonce, challenge[2], identity, challenge[3], false))
                {
                    if (tamper)
                    {
                        byte[] bytes = PairCode.Decode(protection.Seal("CONTROL test").Substring(10));
                        bytes[bytes.Length - 1] ^= 1;
                        frame = "MD3 FRAME " + PairCode.Encode(bytes);
                    }
                }
                await PairSession.WriteLineAsync(stream, frame, CancellationToken.None).ConfigureAwait(false);
                await UntilAsync(delegate { return !host.IsPaired; }, tamper ? "Tampered protected control closes the pair" : "Legacy plaintext control closes the pair").ConfigureAwait(false);
            }
        }

        private static async Task RejectedGuestProofAsync(PairSession host)
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(IPAddress.Loopback, host.Port).ConfigureAwait(false);
                NetworkStream stream = client.GetStream();
                await PairSession.WriteLineAsync(stream, "MD3 HELLO " + PairSession.NewPeerId() + " " + PairSession.NewPeerId(), CancellationToken.None).ConfigureAwait(false);
                string challenge = await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false);
                Require(challenge.StartsWith("MD3 CHALLENGE ", StringComparison.Ordinal), "Host challenges before accepting guest");
                await PairSession.WriteLineAsync(stream, "MD3 PROOF " + PairCode.Encode(new byte[32]), CancellationToken.None).ConfigureAwait(false);
                Require(await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false) == "MD3 REJECT", "Host rejects invalid guest proof");
            }
            Require(!host.IsPaired, "Invalid proof does not occupy player slot");
        }

        private static async Task RejectedReplayAsync(PairSession host)
        {
            string clientNonce = PairSession.NewPeerId(), identity = PairSession.NewPeerId(), proof, originalNonce;
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(IPAddress.Loopback, host.Port).ConfigureAwait(false);
                NetworkStream stream = client.GetStream();
                await PairSession.WriteLineAsync(stream, "MD3 HELLO " + clientNonce + " " + identity, CancellationToken.None).ConfigureAwait(false);
                string[] challenge = (await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false)).Split(' ');
                Require(challenge.Length == 5 && challenge[1] == "CHALLENGE", "Replay setup challenge");
                originalNonce = challenge[2];
                using (HMACSHA256 hmac = new HMACSHA256(PairCode.Decode(host.Token)))
                    proof = PairCode.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes("MD3|join|" + clientNonce + "|" + challenge[2] + "|" + identity + "|" + challenge[3])));
                await PairSession.WriteLineAsync(stream, "MD3 PROOF " + proof, CancellationToken.None).ConfigureAwait(false);
                Require((await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false)).StartsWith("MD3 WELCOME ", StringComparison.Ordinal), "Replay setup accepted once");
                await UntilAsync(delegate { return host.IsPaired; }, "Replay setup host paired").ConfigureAwait(false);
            }
            await UntilAsync(delegate { return !host.IsPaired; }, "Replay setup disconnected").ConfigureAwait(false);
            using (TcpClient replay = new TcpClient())
            {
                await replay.ConnectAsync(IPAddress.Loopback, host.Port).ConfigureAwait(false);
                NetworkStream stream = replay.GetStream();
                await PairSession.WriteLineAsync(stream, "MD3 HELLO " + clientNonce + " " + identity, CancellationToken.None).ConfigureAwait(false);
                string[] challenge = (await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false)).Split(' ');
                Require(challenge[2] != originalNonce, "Fresh host challenge nonce");
                await PairSession.WriteLineAsync(stream, "MD3 PROOF " + proof, CancellationToken.None).ConfigureAwait(false);
                Require(await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false) == "MD3 REJECT", "Captured guest proof cannot be replayed");
            }
        }

        private static async Task MalformedFrameAsync(int port, byte[] frame)
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);
                NetworkStream stream = client.GetStream();
                await stream.WriteAsync(frame, 0, frame.Length).ConfigureAwait(false);
                bool rejected = false;
                try { await PairSession.ReadLineAsync(stream, 5000, CancellationToken.None).ConfigureAwait(false); }
                catch (IOException) { rejected = true; }
                Require(rejected, "Oversized and non-ASCII frames close the peer connection");
            }
        }

        private static async Task CancelJoinAsync()
        {
            TcpListener silent = new TcpListener(IPAddress.Loopback, 0);
            silent.Start();
            try
            {
                using (PairSession joiner = new PairSession())
                {
                    string code = PairCode.Create(IPAddress.Loopback, ((IPEndPoint)silent.LocalEndpoint).Port, PairCode.RandomToken());
                    Task joining = joiner.JoinAsync(code);
                    using (TcpClient accepted = await silent.AcceptTcpClientAsync().ConfigureAwait(false))
                    {
                        joiner.Disconnect();
                        Require(await Task.WhenAny(joining, Task.Delay(2000)).ConfigureAwait(false) == joining, "Pending join cancels promptly");
                        bool rejected = false;
                        try { await joining.ConfigureAwait(false); }
                        catch (IOException) { rejected = true; }
                        catch (OperationCanceledException) { rejected = true; }
                        catch (ObjectDisposedException) { rejected = true; }
                        Require(rejected && !joiner.IsPaired && joiner.Code == "", "Pending join cancellation clears session");
                    }
                }
            }
            finally { silent.Stop(); }
        }

        private static async Task RejectedHandshakeAsync(int port, string request)
        {
            using (TcpClient client = new TcpClient())
            {
                await client.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);
                await PairSession.WriteLineAsync(client.GetStream(), request, CancellationToken.None).ConfigureAwait(false);
                string response = await PairSession.ReadLineAsync(client.GetStream(), 5000, CancellationToken.None).ConfigureAwait(false);
                Require(response == "MD3 REJECT", "Version/token handshake rejected");
            }
        }
        private static async Task UntilAsync(Func<bool> condition, string name)
        {
            for (int i = 0; i < 100 && !condition(); i++) await Task.Delay(30).ConfigureAwait(false);
            Require(condition(), name);
        }
        private static void Require(bool value, string name)
        {
            if (!value) throw new Exception(name);
            Report += "PASS: " + name + Environment.NewLine;
        }
        private static void MustReject(Action action, string name)
        {
            bool rejected = false;
            try { action(); } catch (ArgumentException) { rejected = true; } catch (FormatException) { rejected = true; }
            Require(rejected, name);
        }
    }
}
