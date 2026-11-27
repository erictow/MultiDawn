using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Web.Script.Serialization;

namespace MultiDawn.Launcher
{
    /** Explicit developer fixture checks only. This never installs, patches or writes game data. */
    internal static class NativeGamePreflight
    {
        internal static bool IsSha256(string value)
        {
            if (value == null || value.Length != 64) return false;
            foreach (char digit in value)
                if (!((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') || (digit >= 'A' && digit <= 'F'))) return false;
            return true;
        }

        internal static string Hash(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            using (SHA256 algorithm = SHA256.Create())
                return BitConverter.ToString(algorithm.ComputeHash(stream)).Replace("-", "");
        }

        internal static string ReadLatestPreparedFolder(string kitRoot)
        {
            try
            {
                string build = Path.Combine(kitRoot, "build");
                string pointer = Path.Combine(build, "latest-native-test-path.txt");
                string folder;
                using (FileStream input = File.Open(pointer, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete)) {
                    if (input.Length > 64 * 1024) return null;
                    using (StreamReader reader = new StreamReader(input)) folder = reader.ReadToEnd().Trim();
                }
                if (!Path.IsPathRooted(folder)) return null;
                folder = Path.GetFullPath(folder);
                string testRoot = Path.GetFullPath(Path.Combine(build, "gameplay-tests")) + Path.DirectorySeparatorChar;
                if (!folder.StartsWith(testRoot, StringComparison.OrdinalIgnoreCase)
                    || !File.Exists(Path.Combine(folder, "native-test-install.json"))) return null;
                return folder;
            }
            catch (Exception error)
            {
                if (error is IOException || error is UnauthorizedAccessException || error is ArgumentException
                    || error is NotSupportedException) return null;
                throw;
            }
        }

        /** Metadata validation is performed by GameLaunch.Validate separately before these pins. */
        internal static string ValidatePins(string gameRoot, string expectedRuntimeSha256)
        {
            if (!IsSha256(expectedRuntimeSha256)) return "The native test needs an exact runtime SHA-256.";
            try
            {
                string root = Path.GetFullPath(gameRoot);
                string marker = Path.Combine(root, "native-test-install.json");
                if (!File.Exists(marker)) return "Native tests require an isolated fixture with native-test-install.json.";
                if ((File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0)
                    return "The native fixture marker must be a regular file.";
                Dictionary<string, object> document;
                using (FileStream input = File.Open(marker, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                    if (input.Length > 64 * 1024) return "The native fixture marker exceeds the 64 KiB limit.";
                    using (StreamReader reader = new StreamReader(input))
                        document = new JavaScriptSerializer().DeserializeObject(reader.ReadToEnd()) as Dictionary<string, object>;
                }
                object schema, version, runtime, executable;
                if (document == null || !document.TryGetValue("schema", out schema) || !(schema is int) || (int)schema != 1
                    || !document.TryGetValue("gameVersion", out version) || !(version is string) || (string)version != GameLaunch.GameVersion
                    || !document.TryGetValue("runtimeSha256", out runtime) || !(runtime is string) || !IsSha256((string)runtime)
                    || !document.TryGetValue("executableSha256", out executable) || !(executable is string) || !IsSha256((string)executable))
                    return "The native fixture marker has an unsupported schema, build or hash.";
                if (!String.Equals((string)runtime, expectedRuntimeSha256, StringComparison.OrdinalIgnoreCase))
                    return "The fixture marker does not match the selected native test runtime.";
                string exe = Path.Combine(root, "destiny2.exe");
                if (!File.Exists(exe) || !String.Equals(Hash(exe), (string)executable, StringComparison.OrdinalIgnoreCase))
                    return "The fixture executable does not match its recorded SHA-256.";
                foreach (string relative in new[] { "", "bin/x64" })
                {
                    string dll = Path.Combine(Path.Combine(root, relative), "steam_api64.dll");
                    if (relative == "" && !File.Exists(dll)) continue;
                    if (!File.Exists(dll) || !String.Equals(Hash(dll), expectedRuntimeSha256, StringComparison.OrdinalIgnoreCase))
                        return "The installed " + (relative == "" ? "steam_api64.dll" : "bin/x64/steam_api64.dll") + " does not match the selected native test runtime.";
                }
                return null;
            }
            catch (Exception error)
            {
                if (error is IOException || error is UnauthorizedAccessException || error is ArgumentException || error is InvalidOperationException)
                    return "Could not validate the isolated native fixture: " + error.Message;
                throw;
            }
        }
    }

    /** Copied pairing observation; each use must check the actual session again. */
    internal sealed class GamePreflightLaunchContext
    {
        internal readonly long PairGeneration;
        internal readonly string PartnerLauncherId;
        internal readonly ulong PeerSteamId;
        internal GamePreflightLaunchContext(long generation, string partner, ulong peer)
        { PairGeneration = generation; PartnerLauncherId = partner; PeerSteamId = peer; }
    }
}
