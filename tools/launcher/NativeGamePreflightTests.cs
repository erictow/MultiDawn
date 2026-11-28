using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace MultiDawn.Launcher
{
    internal static class NativeGamePreflightSelfTests
    {
        private static readonly StringBuilder report = new StringBuilder();
        private const ulong Alice = 0x0110000100001011UL, Bob = 0x0110000100002022UL;
        internal static string Run()
        {
            report.Clear(); Files(); PreparedFolder(); PairingAsync().GetAwaiter().GetResult(); return report.ToString();
        }
        private static void Check(bool passed, string message)
        { if (!passed) throw new IOException("Native game preflight test failed: " + message); report.AppendLine("PASS: " + message); }

        private static void Files()
        {
            string temporaryRoot = Path.GetFullPath(Path.GetTempPath());
            string root = Path.GetFullPath(Path.Combine(temporaryRoot, "MultiDawn-NativeGamePreflight-" + Guid.NewGuid().ToString("N")));
            if (!root.StartsWith(temporaryRoot, StringComparison.OrdinalIgnoreCase)) throw new IOException("Invalid temporary fixture path.");
            Directory.CreateDirectory(Path.Combine(root, "bin/x64"));
            string exe = Path.Combine(root, "destiny2.exe"), dll = Path.Combine(root, "bin/x64/steam_api64.dll");
            string rootDll = Path.Combine(root, "steam_api64.dll"), marker = Path.Combine(root, "native-test-install.json");
            string save = Path.Combine(root, "player-state.db");
            try {
                File.WriteAllText(exe, "non-executable test fixture"); File.WriteAllText(dll, "matching runtime fixture");
                File.WriteAllText(save, "preserved local profile fixture");
                string expected = NativeGamePreflight.Hash(dll), exeHash = NativeGamePreflight.Hash(exe);
                Check(NativeGamePreflight.IsSha256(expected) && NativeGamePreflight.IsSha256(expected.ToLowerInvariant())
                    && !NativeGamePreflight.IsSha256(expected + "0") && !NativeGamePreflight.IsSha256(new string('G', 64)),
                    "Native game preflight requires a complete SHA-256 pin");
                Check(NativeGamePreflight.ValidatePins(root, expected) != null, "Missing isolated fixture marker blocks native game testing");
                Dictionary<string, object> record = new Dictionary<string, object> {
                    { "schema", 1 }, { "gameVersion", GameLaunch.GameVersion }, { "runtimeSha256", expected }, { "executableSha256", exeHash }
                };
                Action write = delegate { File.WriteAllText(marker, new JavaScriptSerializer().Serialize(record)); };
                write();
                Check(NativeGamePreflight.ValidatePins(root, expected) == null, "An exact legacy-layout fixture passes read-only hash validation");
                Check(NativeGamePreflight.ValidatePins(root, expected.ToLowerInvariant()) == null, "Fixture hash comparison accepts canonical hexadecimal case variants");
                Check(NativeGamePreflight.ValidatePins(root, new string('0', 64)) != null, "A marker from a different test runtime is refused");
                File.Copy(dll, rootDll);
                Check(NativeGamePreflight.ValidatePins(root, expected) == null, "Both installed Dawn DLL locations must match the selected runtime");
                File.WriteAllText(rootDll, "different root runtime");
                Check(NativeGamePreflight.ValidatePins(root, expected) != null, "A root DLL cannot shadow the pinned bin/x64 runtime with another build");
                File.Delete(rootDll); File.WriteAllText(dll, "different bin runtime");
                Check(NativeGamePreflight.ValidatePins(root, expected) != null, "A changed bin/x64 runtime is refused even when the marker is unchanged");
                File.WriteAllText(dll, "matching runtime fixture"); File.WriteAllText(exe, "changed executable fixture");
                Check(NativeGamePreflight.ValidatePins(root, expected) != null, "Changing the fixture executable invalidates its recorded hash");
                File.WriteAllText(exe, "non-executable test fixture");
                foreach (string key in new[] { "schema", "gameVersion", "runtimeSha256", "executableSha256" }) {
                    object previous = record[key];
                    record[key] = key == "schema" ? (object)2 : "invalid"; write();
                    Check(NativeGamePreflight.ValidatePins(root, expected) != null, "Fixture validation refuses an invalid " + key);
                    record[key] = previous;
                }
                write(); File.WriteAllText(marker, "{broken json");
                Check(NativeGamePreflight.ValidatePins(root, expected) != null, "Malformed fixture JSON fails without modifying the installation");
                File.WriteAllText(marker, new string(' ', 64 * 1024 + 1));
                Check(NativeGamePreflight.ValidatePins(root, expected).Contains("64 KiB"), "Oversized fixture markers are refused before JSON allocation");
                write(); File.Delete(dll);
                Check(NativeGamePreflight.ValidatePins(root, expected) != null, "The bin/x64 runtime remains mandatory for native game fixtures");
                Check(File.ReadAllText(save) == "preserved local profile fixture", "All native fixture validation leaves local profile data unchanged");
            }
            finally {
                foreach (string path in new[] { exe, dll, rootDll, marker, save }) if (File.Exists(path)) File.Delete(path);
                Directory.Delete(Path.Combine(root, "bin/x64")); Directory.Delete(Path.Combine(root, "bin")); Directory.Delete(root);
            }
        }

        private static void PreparedFolder()
        {
            string kit = Path.Combine(Path.GetTempPath(), "MultiDawn-Prefill-" + Guid.NewGuid().ToString("N"));
            string build = Path.Combine(kit, "build");
            string testRoot = Path.Combine(build, "gameplay-tests");
            string fixture = Path.Combine(testRoot, "session-noah's-test & copy");
            string pointer = Path.Combine(build, "latest-native-test-path.txt");
            string marker = Path.Combine(fixture, "native-test-install.json");
            Directory.CreateDirectory(fixture);
            try {
                Check(NativeGamePreflight.ReadLatestPreparedFolder(kit) == null, "An unprepared kit can fall back to the saved game folder");
                File.WriteAllText(pointer, fixture + Environment.NewLine, Encoding.UTF8);
                Check(NativeGamePreflight.ReadLatestPreparedFolder(kit) == null, "A missing fixture marker cannot prefill an incomplete test install");
                File.WriteAllText(marker, "{}");
                Check(NativeGamePreflight.ReadLatestPreparedFolder(kit) == fixture,
                    "Native test startup recovers this kit's exact prepared folder with spaces and punctuation");
                File.WriteAllText(pointer, "build\\gameplay-tests\\session-noah's-test & copy");
                Check(NativeGamePreflight.ReadLatestPreparedFolder(kit) == null, "A relative fixture pointer cannot depend on the launch working directory");
                File.WriteAllText(pointer, kit);
                Check(NativeGamePreflight.ReadLatestPreparedFolder(kit) == null, "A fixture pointer must stay inside this kit's test tree");
            }
            finally {
                if (File.Exists(marker)) File.Delete(marker);
                if (File.Exists(pointer)) File.Delete(pointer);
                Directory.Delete(fixture); Directory.Delete(testRoot); Directory.Delete(build); Directory.Delete(kit);
            }
        }

        private static async Task UntilAsync(Func<bool> ready, string description)
        {
            Stopwatch deadline = Stopwatch.StartNew();
            while (!ready() && deadline.ElapsedMilliseconds < 5000) await Task.Delay(20).ConfigureAwait(false);
            Check(ready(), description);
        }
        private static async Task PairingAsync()
        {
            using (PairSession host = new PairSession())
            using (PairSession guest = new PairSession()) {
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                string code = host.Code;
                await guest.JoinAsync(code).ConfigureAwait(false);
                using (RuntimeBridge first = new RuntimeBridge(host, Alice, "Alice")) {
                    GamePreflightLaunchContext pending;
                    Check(!first.TryCaptureGamePreflight(out pending) && pending == null, "A paired launcher cannot launch a native test before the partner profile arrives");
                    using (RuntimeBridge second = new RuntimeBridge(guest, Bob, "Bob")) {
                        GamePreflightLaunchContext captured = null;
                        await UntilAsync(delegate { return first.TryCaptureGamePreflight(out captured); }, "A live paired partner profile supplies an exact native launch context").ConfigureAwait(false);
                        Check(captured.PairGeneration == host.ConnectionGeneration && captured.PartnerLauncherId == host.PeerId && captured.PeerSteamId == Bob
                            && first.ValidateGamePreflight(captured), "Native launch context binds the current pair generation, partner and native social identity");
                        ProcessStartInfo info = GameLaunch.CreateStartInfo(Path.GetTempPath());
                        Check(!info.EnvironmentVariables.ContainsKey("DAWN_COMPANION_ID") && !info.EnvironmentVariables.ContainsKey("DAWN_COMPANION_PAIR_GENERATION"),
                            "Ordinary solo launch receives no native test credentials or pairing pins");
                        Check(first.ApplyGamePreflightEnvironment(info, captured), "Explicit game preflight can apply a current connection context");
                        Check(info.EnvironmentVariables["DAWN_COMPANION_PROTOCOL"] == "3"
                            && info.EnvironmentVariables["DAWN_COMPANION_PAIR_GENERATION"] == captured.PairGeneration.ToString(CultureInfo.InvariantCulture)
                            && info.EnvironmentVariables["DAWN_COMPANION_PEER_ID"] == Bob.ToString(CultureInfo.InvariantCulture)
                            && info.EnvironmentVariables["DAWN_COMPANION_ID"] == first.PipeId && info.EnvironmentVariables["DAWN_SESSION_MODE"] == "solo",
                            "Native test child uses protocol three with exact expected pair and peer pins while keeping local solo services");
                        Check(info.EnvironmentVariables["DAWN_NATIVE_ADDRESS_RESOLUTION"] == "1" && info.EnvironmentVariables["DAWN_NATIVE_SESSION_TRACE"] == "1"
                            && info.EnvironmentVariables["DAWN_NATIVE_IDENTITY_OBSERVATION"] == "1" && info.EnvironmentVariables["DAWN_ACTIVITY_BINDING_TRACE"] == "1"
                            && info.EnvironmentVariables["DAWN_COMPANION_WORLD_PROBE"] == "1",
                            "Only the explicit native test environment enables the bounded Tower observation and readiness flags");
                        ProcessStartInfo normal = GameLaunch.CreateStartInfo(Path.GetTempPath()); first.ApplyEnvironment(normal);
                        Check(normal.EnvironmentVariables["DAWN_COMPANION_PROTOCOL"] == "2"
                            && !normal.EnvironmentVariables.ContainsKey("DAWN_COMPANION_WORLD_PROBE")
                            && !normal.EnvironmentVariables.ContainsKey("DAWN_COMPANION_PAIR_GENERATION") && !normal.EnvironmentVariables.ContainsKey("DAWN_COMPANION_PEER_ID"),
                            "Existing companion setup remains protocol two without native game pins");
                        foreach (GamePreflightLaunchContext forged in new[] {
                            new GamePreflightLaunchContext(captured.PairGeneration + 1, captured.PartnerLauncherId, Bob),
                            new GamePreflightLaunchContext(captured.PairGeneration, PairSession.NewPeerId(), Bob),
                            new GamePreflightLaunchContext(captured.PairGeneration, captured.PartnerLauncherId, Alice) }) {
                            ProcessStartInfo rejected = GameLaunch.CreateStartInfo(Path.GetTempPath());
                            Check(!first.ApplyGamePreflightEnvironment(rejected, forged) && !rejected.EnvironmentVariables.ContainsKey("DAWN_COMPANION_ID"),
                                "Mismatched native launch context cannot populate a child environment");
                        }
                        Check(first.GamePreflightStatus.Contains("not connected"), "Paired launchers are not reported as connected native game clients");
                        guest.Disconnect();
                        await UntilAsync(delegate { return !host.IsPaired; }, "A lost LAN partner retires the native launch context").ConfigureAwait(false);
                        Check(!first.ValidateGamePreflight(captured) && !first.ApplyGamePreflightEnvironment(GameLaunch.CreateStartInfo(Path.GetTempPath()), captured),
                            "A disconnected or delayed UI launch cannot use captured pairing credentials");
                        await guest.JoinAsync(code).ConfigureAwait(false);
                        GamePreflightLaunchContext replacement = null;
                        await UntilAsync(delegate { return first.TryCaptureGamePreflight(out replacement); }, "The same partner can publish a fresh native launch context after reconnect").ConfigureAwait(false);
                        Check(replacement.PairGeneration > captured.PairGeneration && !first.ValidateGamePreflight(captured)
                            && first.ValidateGamePreflight(replacement), "Reconnecting the same device cannot revive the former launch generation");
                    }
                }
            }
        }
    }
}
