using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MultiDawn.Launcher
{
    internal static class FriendsSelfTests
    {
        private static readonly StringBuilder report = new StringBuilder();
        internal static string Run()
        {
            report.Clear(); Persistence(); ConcurrentPersistence(); PairingAsync().GetAwaiter().GetResult(); ReconnectContactsAsync().GetAwaiter().GetResult(); return report.ToString();
        }
        private static void Require(bool passed, string message)
        {
            if (!passed) throw new Exception("Friends test failed: " + message);
            report.AppendLine("PASS: " + message);
        }
        private static void Reject(Action action, string message)
        {
            bool rejected = false;
            try { action(); } catch (IOException) { rejected = true; } catch (InvalidDataException) { rejected = true; } catch (ArgumentException) { rejected = true; }
            Require(rejected, message);
        }
        private static SavedFriend Friend(string identity, string name)
        { return new SavedFriend { PeerId = identity, Nickname = name, Address = "192.168.1.124", Port = 30979 }; }

        private static void Persistence()
        {
            string directory = Path.Combine(Path.GetTempPath(), "MultiDawnFriends-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "friends.json");
            FriendStore store = new FriendStore(path);
            try
            {
                Require(store.Load().Count == 0, "Missing friends file starts empty");
                string identity = FriendStore.LoadOrCreateIdentity(directory);
                Require(identity == FriendStore.LoadOrCreateIdentity(directory) && PairSession.ValidIdentity(identity), "Launcher identity persists across launcher sessions");
                SavedFriend first = Friend(identity, "Zoë");
                store.Upsert(first);
                List<SavedFriend> loaded = new FriendStore(path).Load();
                Require(loaded.Count == 1 && loaded[0].PeerId == identity && loaded[0].Nickname == "Zoë" && loaded[0].Port == 30979,
                    "Friends JSON atomically round-trips stable identity, Unicode nickname and endpoint");
                string text = File.ReadAllText(path);
                Require(!text.Contains("Token") && !text.Contains("PairCode") && !text.Contains("MD2-") && !text.Contains("Nonce"),
                    "Friends JSON contains no pairing tokens, codes or companion credentials");
                first.Nickname = "Renamed"; first.Port = 30980; store.Upsert(first);
                Require(store.Load().Count == 1 && store.Load()[0].Nickname == "Renamed" && store.Load()[0].Port == 30980, "Saving an existing identity updates one friend");
                string original = File.ReadAllText(path);
                using (FileStream snapshot = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
                {
                    first.Nickname = "Updated during read"; store.Upsert(first);
                    using (StreamReader reader = new StreamReader(snapshot, Encoding.UTF8))
                        Require(reader.ReadToEnd() == original && store.Load()[0].Nickname == first.Nickname,
                            "Atomic friend replacement succeeds while an open reader retains its complete previous snapshot");
                }
                original = File.ReadAllText(path);
                using (FileStream locked = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    Reject(delegate { store.Upsert(Friend(PairSession.NewPeerId(), "Blocked")); }, "Atomic replace failure preserves the existing friend file");
                Require(File.ReadAllText(path) == original && Directory.GetFiles(directory, "*.tmp-*").Length == 0,
                    "Failed save leaves no partial file or temporary credentials");
                SavedFriend invalid = Friend(identity, new string('X', 65));
                Reject(delegate { store.Upsert(invalid); }, "Oversized nickname is rejected");
                invalid.Nickname = "Line\nBreak";
                Reject(delegate { store.Upsert(invalid); }, "Control characters in nicknames are rejected");
                invalid.Nickname = "Valid"; invalid.Port = 0;
                Reject(delegate { store.Upsert(invalid); }, "Invalid saved port is rejected");
                invalid.Port = 30979; invalid.Address = "::1";
                Reject(delegate { store.Upsert(invalid); }, "Saved endpoint must be IPv4");
                Require(File.ReadAllText(path) == original, "Invalid friend edits preserve previous data");
                foreach (string corrupt in new[] { "{", "{\"version\":2,\"friends\":[]}", "{\"version\":1,\"friends\":null}",
                    "{\"version\":1,\"friends\":[],\"Token\":\"do-not-save\"}", new string(' ', FriendStore.MaximumBytes + 1) })
                {
                    File.WriteAllText(path, corrupt);
                    Reject(delegate { store.Upsert(first); }, "Corrupt or oversized friends data fails closed");
                    Require(File.ReadAllText(path) == corrupt, "Corrupt friends file is retained for recovery");
                }
                File.Delete(path);
                for (int index = 0; index < FriendStore.MaximumFriends; ++index) store.Upsert(Friend(PairSession.NewPeerId(), "Friend " + index));
                Require(store.Load().Count == FriendStore.MaximumFriends, "Saved friends list accepts its bounded capacity");
                Reject(delegate { store.Upsert(first); }, "Saved friends list rejects a 65th identity");
                SavedFriend existing = store.Load()[0]; existing.Nickname = "Updated at limit"; store.Upsert(existing);
                store.Remove(existing.PeerId);
                Require(store.Load().Count == FriendStore.MaximumFriends - 1, "Existing friends can be updated or removed at capacity");
                string identityPath = Path.Combine(directory, "peer-id.txt");
                File.WriteAllText(identityPath, "corrupt");
                Reject(delegate { FriendStore.LoadOrCreateIdentity(directory); }, "Corrupt local identity is never silently replaced");
                Require(File.ReadAllText(identityPath) == "corrupt", "Invalid local identity remains recoverable");
                Require(FriendStore.ParseAddress("25.12.34.56").ToString() == "25.12.34.56"
                    && FriendStore.ParseAddress("100.64.0.2").ToString() == "100.64.0.2", "VPN IPv4 ranges remain valid endpoints");
                Reject(delegate { FriendStore.ParseAddress("2130706433"); }, "Manual address requires explicit dotted IPv4");
                Reject(delegate { FriendStore.ParseAddress("239.1.2.3"); }, "Manual multicast destination is rejected");
            }
            finally
            {
                // Only the uniquely-created flat fixture directory is cleaned up.
                foreach (string file in Directory.GetFiles(directory)) File.Delete(file);
                Directory.Delete(directory);
            }
        }

        private static async Task UntilAsync(Func<bool> condition, string message)
        {
            Stopwatch watch = Stopwatch.StartNew();
            while (!condition() && watch.ElapsedMilliseconds < 5000) await Task.Delay(20).ConfigureAwait(false);
            Require(condition(), message);
        }

        private sealed class FriendWorker : IDisposable
        {
            internal readonly Process Process;
            private readonly Task<string> errors, output;
            internal FriendWorker(string script, string store, string mode, string identity, string prefix, string start)
            {
                string shell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
                string arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " + Quote(script)
                    + " -AssemblyPath " + Quote(typeof(FriendStore).Assembly.Location) + " -StorePath " + Quote(store)
                    + " -Mode " + mode + " -PeerId " + identity + " -ReadyPath " + Quote(prefix + ".ready")
                    + " -AttemptPath " + Quote(prefix + ".attempt") + " -StartPath " + Quote(start);
                Process = new Process { StartInfo = new ProcessStartInfo(shell, arguments) {
                    UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                    RedirectStandardError = true, RedirectStandardOutput = true } };
                if (!Process.Start()) throw new IOException("Could not start isolated friends test worker.");
                errors = Process.StandardError.ReadToEndAsync(); output = Process.StandardOutput.ReadToEndAsync();
            }
            private static string Quote(string value) { return "\"" + value + "\""; }
            internal void Complete()
            {
                if (!Process.WaitForExit(10000)) throw new Exception("Concurrent friends test worker timed out.");
                string error = errors.GetAwaiter().GetResult(); output.GetAwaiter().GetResult();
                if (Process.ExitCode != 0) throw new Exception("Concurrent friends worker failed: " + error);
            }
            public void Dispose()
            {
                if (!Process.HasExited) { Process.Kill(); Process.WaitForExit(5000); }
                Process.Dispose();
            }
        }

        private static void WaitForFiles(string first, string second)
        {
            Stopwatch timer = Stopwatch.StartNew();
            while ((!File.Exists(first) || !File.Exists(second)) && timer.ElapsedMilliseconds < 7000)
                System.Threading.Thread.Sleep(10);
            if (!File.Exists(first) || !File.Exists(second)) throw new Exception("Concurrent friends worker did not reach its synchronization point.");
        }

        private static void ConcurrentMutation(string directory, string path, string script, string phase,
            string firstMode, string firstIdentity, string secondMode, string secondIdentity)
        {
            string first = Path.Combine(directory, phase + "-first"), second = Path.Combine(directory, phase + "-second");
            string start = Path.Combine(directory, phase + ".start");
            using (FriendWorker a = new FriendWorker(script, path, firstMode, firstIdentity, first, start))
            using (FriendWorker b = new FriendWorker(script, path, secondMode, secondIdentity, second, start))
            {
                WaitForFiles(first + ".ready", second + ".ready");
                string before = File.ReadAllText(path);
                using (FileStream held = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                {
                    File.WriteAllText(start, "start");
                    WaitForFiles(first + ".attempt", second + ".attempt");
                    Require(!a.Process.WaitForExit(150) && !b.Process.WaitForExit(150) && File.ReadAllText(path) == before,
                        "Separate launcher processes wait for the shared mutation lock (" + phase + ")");
                }
                a.Complete(); b.Complete();
            }
        }

        private static void ConcurrentPersistence()
        {
            string directory = Path.Combine(Path.GetTempPath(), "MultiDawnConcurrentFriends-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "friends.json"), script = Path.Combine(directory, "worker.ps1");
            try
            {
                File.WriteAllText(script, @"param([string] $AssemblyPath, [string] $StorePath, [string] $Mode, [string] $PeerId,
    [string] $ReadyPath, [string] $AttemptPath, [string] $StartPath)
$ErrorActionPreference = 'Stop'
try {
    $assembly = [Reflection.Assembly]::LoadFrom($AssemblyPath)
    $storeType = $assembly.GetType('MultiDawn.Launcher.FriendStore', $true)
    $flags = [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic
    $store = [Activator]::CreateInstance($storeType, $flags, $null, [object[]]@($StorePath), [Globalization.CultureInfo]::InvariantCulture)
    [IO.File]::WriteAllText($ReadyPath, 'ready')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not [IO.File]::Exists($StartPath)) {
        if ($timer.ElapsedMilliseconds -gt 10000) { throw 'Worker start barrier timed out' }
        Start-Sleep -Milliseconds 10
    }
    [IO.File]::WriteAllText($AttemptPath, 'attempt')
    if ($Mode -eq 'upsert') {
        $friend = [Activator]::CreateInstance($assembly.GetType('MultiDawn.Launcher.SavedFriend', $true), $true)
        $friend.PeerId = $PeerId
        $friend.Nickname = 'Concurrent friend'
        $friend.Address = '192.168.1.124'
        $friend.Port = 30979
        [void]$storeType.GetMethod('Upsert', $flags).Invoke($store, [object[]]@($friend))
    } elseif ($Mode -eq 'remove') {
        [void]$storeType.GetMethod('Remove', $flags).Invoke($store, [object[]]@($PeerId))
    } else { throw 'Unknown worker mutation' }
    exit 0
} catch { [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }
");
                FriendStore store = new FriendStore(path);
                string original = PairSession.NewPeerId(), first = PairSession.NewPeerId(), second = PairSession.NewPeerId(), third = PairSession.NewPeerId();
                store.Upsert(Friend(original, "Original"));
                ConcurrentMutation(directory, path, script, "two-adds", "upsert", first, "upsert", second);
                List<SavedFriend> rows = store.Load();
                Require(rows.Count == 3 && rows.Exists(delegate(SavedFriend row) { return row.PeerId == first; })
                    && rows.Exists(delegate(SavedFriend row) { return row.PeerId == second; }), "Concurrent processes preserve both friend additions");
                ConcurrentMutation(directory, path, script, "add-remove", "remove", first, "upsert", third);
                rows = store.Load();
                Require(rows.Count == 3 && !rows.Exists(delegate(SavedFriend row) { return row.PeerId == first; })
                    && rows.Exists(delegate(SavedFriend row) { return row.PeerId == third; }), "Concurrent add and remove preserve both mutations");
                string before = File.ReadAllText(path);
                using (FileStream held = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
                {
                    FriendStore bounded = new FriendStore(path, 100);
                    Stopwatch timer = Stopwatch.StartNew(); bool rejected = false;
                    try { bounded.Upsert(Friend(PairSession.NewPeerId(), "Timed out")); }
                    catch (IOException error) { rejected = error.Message.Contains("busy in another launcher"); }
                    Require(rejected && timer.ElapsedMilliseconds < 1500 && File.ReadAllText(path) == before,
                        "Busy friend-store timeout is bounded, clear, and leaves saved data unchanged");
                }
                store.Upsert(Friend(original, "Lock released"));
                Require(store.Load().Exists(delegate(SavedFriend row) { return row.Nickname == "Lock released"; })
                    && new FileInfo(path + ".lock").Length == 0 && Directory.GetFiles(directory, "*.tmp-*").Length == 0,
                    "Mutation lock releases after timeout and stores no credentials");
            }
            finally
            {
                foreach (string file in Directory.GetFiles(directory)) File.Delete(file);
                Directory.Delete(directory);
            }
        }

        private static async Task PairingAsync()
        {
            string hostIdentity = PairSession.NewPeerId();
            using (PairSession host = new PairSession(hostIdentity, 30979))
            using (PairSession guest = new PairSession(PairSession.NewPeerId(), 31817))
            {
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                bool rejected = false;
                try { await guest.JoinAsync(host.Code, IPAddress.Loopback, host.Port, PairSession.NewPeerId()).ConfigureAwait(false); }
                catch (IOException error) { rejected = error.Message.Contains("saved friend"); }
                Require(rejected && !guest.IsPaired && !host.IsPaired, "Authenticated host identity mismatch rejects before either side admits a saved friend");
                string offNetworkCode = PairCode.Create(IPAddress.Parse("192.0.2.1"), 1, host.Token);
                await guest.JoinAsync(offNetworkCode, IPAddress.Loopback, host.Port, hostIdentity).ConfigureAwait(false);
                await UntilAsync(delegate { return host.IsPaired; }, "Manual IPv4 and port override reaches the real authenticated host").ConfigureAwait(false);
                Require(guest.Address.Equals(IPAddress.Loopback) && guest.Port == host.Port && guest.PeerId == hostIdentity,
                    "Manual destination retains the pair-code HMAC and saved identity pin");
                await UntilAsync(delegate { string id; IPEndPoint endpoint; return host.TryPeerEndpoint(out id, out endpoint) && id == guest.LocalPeerId && endpoint.Port == 31817; },
                    "Host saves authenticated guest hosting port rather than its temporary TCP source port").ConfigureAwait(false);
                await UntilAsync(delegate { string id; IPEndPoint endpoint; return guest.TryPeerEndpoint(out id, out endpoint) && endpoint.Port == host.Port; },
                    "Joiner remembers the host's authenticated listening endpoint").ConfigureAwait(false);
                await guest.SendControlAsync("FRIEND1 PORT 0").ConfigureAwait(false);
                await UntilAsync(delegate { return !host.IsPaired && !guest.IsPaired; }, "Malformed authenticated friend port closes the connection").ConfigureAwait(false);
                string unused; IPEndPoint absent;
                Require(!host.TryPeerEndpoint(out unused, out absent), "Disconnected partner cannot be saved as authenticated");
                string staleCode = host.Code;
                host.Disconnect(); await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                rejected = false;
                try { await guest.JoinAsync(staleCode, IPAddress.Loopback, host.Port, hostIdentity).ConfigureAwait(false); }
                catch (IOException) { rejected = true; }
                Require(rejected && !guest.IsPaired, "Saved identity and manual IP cannot reuse a stale host token");
                rejected = false;
                try { await guest.JoinAsync("", IPAddress.Loopback, host.Port, hostIdentity).ConfigureAwait(false); }
                catch (FormatException) { rejected = true; }
                Require(rejected, "IP-only joining cannot bypass the current pair code");
                await guest.JoinAsync(host.Code, IPAddress.Loopback, host.Port, hostIdentity).ConfigureAwait(false);
                Require(guest.IsPaired, "Current code reconnects to the same persistent host identity");
            }
        }

        private static async Task ReconnectContactsAsync()
        {
            using (PairSession host = new PairSession())
            using (PairSession original = new PairSession(PairSession.NewPeerId(), 31001))
            using (PairSession replacement = new PairSession(PairSession.NewPeerId(), 31002))
            {
                List<Action> delayedUi = new List<Action>();
                string observedIdentity = ""; int observedPort = 0;
                // Match the UI pattern: delayed notifications read current state
                // rather than capturing an identity or endpoint from the event.
                host.PeerEndpointChanged += delegate {
                    lock (delayedUi) delayedUi.Add(delegate {
                        string identity; IPEndPoint endpoint;
                        if (host.TryPeerEndpoint(out identity, out endpoint)) { observedIdentity = identity; observedPort = endpoint.Port; }
                    });
                };
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                await original.JoinAsync(host.Code).ConfigureAwait(false);
                await UntilAsync(delegate { lock (delayedUi) return delayedUi.Count != 0; }, "Authenticated friend endpoint notification can be delayed by the UI").ConfigureAwait(false);
                long oldGeneration = original.ConnectionGeneration;
                original.Disconnect();
                await UntilAsync(delegate { return !host.IsPaired; }, "Friend metadata is retired on disconnect").ConfigureAwait(false);
                await replacement.JoinAsync(host.Code).ConfigureAwait(false);
                await UntilAsync(delegate { string id; IPEndPoint endpoint; return host.TryPeerEndpoint(out id, out endpoint) && id == replacement.LocalPeerId && endpoint.Port == 31002; },
                    "Replacement peer identity and endpoint are published together").ConfigureAwait(false);
                Action[] pendingUi;
                lock (delayedUi) pendingUi = delayedUi.ToArray();
                foreach (Action notification in pendingUi) notification();
                Require(observedIdentity == replacement.LocalPeerId && observedPort == 31002,
                    "Delayed old UI notification cannot combine an old friend identity with a new endpoint");
                bool rejected = false;
                try { await original.SendControlAsync("FRIEND1 PORT 31003", oldGeneration).ConfigureAwait(false); }
                catch (IOException) { rejected = true; }
                Require(rejected, "An old connection cannot publish friend endpoint controls to its replacement");
                string finalIdentity; IPEndPoint finalEndpoint;
                Require(host.TryPeerEndpoint(out finalIdentity, out finalEndpoint) && finalIdentity == replacement.LocalPeerId && finalEndpoint.Port == 31002,
                    "Saving a friend uses one locked snapshot of the current authenticated identity and endpoint");
            }
        }
    }
}
