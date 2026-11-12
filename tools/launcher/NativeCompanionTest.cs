using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading.Tasks;

namespace MultiDawn.Launcher
{
    /** Runs the actual native companion implementation in disposable test workers, never a game. */
    internal static class NativeCompanionTest
    {
        internal static string Run(string harness) { return RunAsync(Path.GetFullPath(harness)).GetAwaiter().GetResult(); }
        private static async Task<string> RunAsync(string harness)
        {
            if (!File.Exists(harness)) throw new FileNotFoundException("Build the native companion_bridge_harness project first.", harness);
            return await RunVersionAsync(harness, 2).ConfigureAwait(false)
                + await RunVersionAsync(harness, 1).ConfigureAwait(false);
        }
        private static async Task<string> RunVersionAsync(string harness, int protocol)
        {
            using (PairSession host = new PairSession())
            using (PairSession guest = new PairSession())
            {
                await host.HostAsync(IPAddress.Loopback, 0).ConfigureAwait(false);
                await guest.JoinAsync(host.Code).ConfigureAwait(false);
                using (RuntimeBridge firstBridge = new RuntimeBridge(host, 0x0110000100001011UL, "Native test A"))
                using (RuntimeBridge secondBridge = new RuntimeBridge(guest, 0x0110000100002022UL, "Native test B"))
                {
                    for (int i = 0; i < 170 && (firstBridge.PeerSteamId == 0 || secondBridge.PeerSteamId == 0); ++i)
                        await Task.Delay(30).ConfigureAwait(false);
                    if (firstBridge.PeerSteamId == 0 || secondBridge.PeerSteamId == 0) throw new IOException("Native test launchers failed to exchange identities.");
                    Process first = null, second = null;
                    try
                    {
                        first = Start(harness, "side-a", firstBridge, protocol);
                        second = Start(harness, "side-b", secondBridge, protocol);
                        Task<string> firstOut = first.StandardOutput.ReadToEndAsync(), firstError = first.StandardError.ReadToEndAsync();
                        Task<string> secondOut = second.StandardOutput.ReadToEndAsync(), secondError = second.StandardError.ReadToEndAsync();
                        bool[] completed = await Task.WhenAll(Task.Run(delegate { return first.WaitForExit(25000); }), Task.Run(delegate { return second.WaitForExit(25000); })).ConfigureAwait(false);
                        if (!completed[0] || !completed[1]) throw new TimeoutException("Native companion test workers exceeded 25 seconds.");
                        string output = "Companion protocol " + protocol + Environment.NewLine + "Native side A:" + Environment.NewLine + await firstOut.ConfigureAwait(false) + await firstError.ConfigureAwait(false)
                            + "Native side B:" + Environment.NewLine + await secondOut.ConfigureAwait(false) + await secondError.ConfigureAwait(false);
                        if (first.ExitCode != 0 || second.ExitCode != 0)
                            throw new IOException("Native companion test worker failed (" + first.ExitCode + ", " + second.ExitCode + ")." + Environment.NewLine + output);
                        Stopwatch cleanup = Stopwatch.StartNew();
                        while (!Clean(firstBridge, secondBridge) && cleanup.ElapsedMilliseconds < 5000)
                            await Task.Delay(25).ConfigureAwait(false);
                        if (!Clean(firstBridge, secondBridge)) throw new IOException("Native exit did not retire both runtime epochs and invitation contexts.");
                        if (!host.IsPaired || !guest.IsPaired) throw new IOException("Native worker exit incorrectly terminated launcher pairing.");
                        return output + "PASS: actual C++ companion framing, nonce authentication, identity publication, bidirectional invitations, and native exit cleanup."
                            + (protocol == 2 ? " Invitation acceptance reached the host as intent only; no gameplay grant." : " Legacy protocol 1 remains compatible.") + Environment.NewLine
                            + "No Destiny process or game DLL was started. No account or save was opened." + Environment.NewLine;
                    }
                    finally { Stop(first); Stop(second); }
                }
            }
        }
        private static bool Clean(RuntimeBridge first, RuntimeBridge second)
        {
            return !first.NativeConnected && !second.NativeConnected
                && first.PeerProtocolForTest == 0 && second.PeerProtocolForTest == 0
                && first.PeerEpochForTest == "-" && second.PeerEpochForTest == "-"
                && !first.AcceptedIntentForTest && !second.AcceptedIntentForTest
                && first.IncomingTicketForTest.Length == 0 && second.IncomingTicketForTest.Length == 0;
        }
        private static Process Start(string harness, string side, RuntimeBridge bridge, int protocol)
        {
            ProcessStartInfo start = new ProcessStartInfo(harness, side);
            start.WorkingDirectory = Path.GetDirectoryName(harness);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = start.RedirectStandardError = true;
            bridge.ApplyEnvironment(start);
            start.EnvironmentVariables["DAWN_COMPANION_PROTOCOL"] = protocol.ToString(System.Globalization.CultureInfo.InvariantCulture);
            Process process = Process.Start(start);
            if (process == null) throw new IOException("Native companion test worker did not start.");
            return process;
        }
        private static void Stop(Process worker)
        {
            if (worker == null) return;
            try { if (!worker.HasExited) { worker.Kill(); worker.WaitForExit(5000); } }
            finally { worker.Dispose(); }
        }
    }
}
