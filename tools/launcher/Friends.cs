using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace MultiDawn.Launcher
{
    internal sealed class SavedFriend
    {
        public string PeerId { get; set; }
        public string Nickname { get; set; }
        public string Address { get; set; }
        public int Port { get; set; }
        public override string ToString() { return Nickname + " (" + Address + ":" + Port + ")"; }
    }

    internal sealed class FriendStore
    {
        internal const int MaximumFriends = 64, MaximumBytes = 65536;
        private readonly string path;
        private readonly int lockTimeoutMilliseconds;
        private static readonly UTF8Encoding utf8 = new UTF8Encoding(false, true);
        internal FriendStore(string file) : this(file, 5000) { }
        internal FriendStore(string file, int lockTimeout)
        {
            if (lockTimeout < 1 || lockTimeout > 5000) throw new ArgumentOutOfRangeException("lockTimeout");
            path = Path.GetFullPath(file); lockTimeoutMilliseconds = lockTimeout;
        }

        internal static IPAddress ParseAddress(string text)
        {
            IPAddress address;
            text = (text ?? "").Trim();
            if (!IPAddress.TryParse(text, out address) || address.ToString() != text)
                throw new ArgumentException("Enter a full IPv4 address, such as 192.168.1.124 or your partner's VPN address.");
            PairCode.ValidateAddress(address); return address;
        }

        private static void Validate(SavedFriend value)
        {
            if (value == null || !PairSession.ValidIdentity(value.PeerId)) throw new InvalidDataException("Invalid saved friend identity.");
            if (String.IsNullOrWhiteSpace(value.Nickname) || value.Nickname.Length > 64 || value.Nickname.Trim() != value.Nickname)
                throw new InvalidDataException("Use a friend nickname between 1 and 64 characters.");
            foreach (char character in value.Nickname) if (Char.IsControl(character)) throw new InvalidDataException("Friend nicknames cannot contain control characters.");
            try { utf8.GetByteCount(value.Nickname); ParseAddress(value.Address); }
            catch (ArgumentException error) { throw new InvalidDataException("Invalid saved friend name or IPv4 address.", error); }
            if (value.Port < 1 || value.Port > 65535) throw new InvalidDataException("Invalid saved friend port.");
        }

        private static byte[] ReadBounded(string file, int maximum)
        {
            // Atomic replacement leaves this handle on its original snapshot.
            // Allow replacement so an unlocked UI read cannot block a writer.
            using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
            {
                if (stream.Length > maximum) throw new InvalidDataException("Saved friend data exceeds its size limit.");
                byte[] bytes = new byte[(int)stream.Length];
                int position = 0;
                while (position < bytes.Length)
                {
                    int count = stream.Read(bytes, position, bytes.Length - position);
                    if (count == 0) throw new EndOfStreamException("Saved friend data was truncated.");
                    position += count;
                }
                return bytes;
            }
        }

        internal List<SavedFriend> Load()
        {
            if (!File.Exists(path)) return new List<SavedFriend>();
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = MaximumBytes, RecursionLimit = 8 };
                Dictionary<string, object> document = serializer.DeserializeObject(utf8.GetString(ReadBounded(path, MaximumBytes))) as Dictionary<string, object>;
                if (document == null || document.Count != 2 || !document.ContainsKey("version") || !document.ContainsKey("friends")
                    || !(document["version"] is int) || (int)document["version"] != 1)
                    throw new InvalidDataException("Unsupported saved friends file.");
                object[] rows = document["friends"] as object[];
                if (rows == null || rows.Length > MaximumFriends) throw new InvalidDataException("Saved friends file exceeds its entry limit.");
                List<SavedFriend> result = new List<SavedFriend>();
                HashSet<string> identities = new HashSet<string>(StringComparer.Ordinal);
                foreach (object row in rows)
                {
                    Dictionary<string, object> fields = row as Dictionary<string, object>;
                    if (fields == null || fields.Count != 4 || !fields.ContainsKey("PeerId") || !fields.ContainsKey("Nickname")
                        || !fields.ContainsKey("Address") || !fields.ContainsKey("Port") || !(fields["Port"] is int))
                        throw new InvalidDataException("Invalid saved friend entry.");
                    SavedFriend value = new SavedFriend { PeerId = fields["PeerId"] as string, Nickname = fields["Nickname"] as string,
                        Address = fields["Address"] as string, Port = (int)fields["Port"] };
                    Validate(value);
                    if (!identities.Add(value.PeerId)) throw new InvalidDataException("Duplicate saved friend identity.");
                    result.Add(value);
                }
                return result;
            }
            catch (ArgumentException error) { throw new InvalidDataException("Saved friends file is corrupt; it has been preserved.", error); }
        }

        internal void Upsert(SavedFriend value)
        {
            Validate(value);
            using (FileStream held = AcquireMutationLock())
            {
                List<SavedFriend> friends = Load();
                int existing = friends.FindIndex(delegate(SavedFriend row) { return row.PeerId == value.PeerId; });
                if (existing >= 0) friends[existing] = value;
                else
                {
                    if (friends.Count >= MaximumFriends) throw new InvalidDataException("The saved friends limit is 64. Remove a friend before adding another.");
                    friends.Add(value);
                }
                Save(friends);
            }
        }

        internal void Remove(string identity)
        {
            using (FileStream held = AcquireMutationLock())
            {
                List<SavedFriend> friends = Load();
                friends.RemoveAll(delegate(SavedFriend value) { return value.PeerId == identity; });
                Save(friends);
            }
        }

        private FileStream AcquireMutationLock()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            Stopwatch watch = Stopwatch.StartNew();
            while (true)
            {
                try
                {
                    // This persistent empty file is a lock, not a credential or
                    // backup. Never unlink it: another process may already hold
                    // its handle. Closing releases ownership after a crash too.
                    return new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                }
                catch (IOException error)
                {
                    int code = error.HResult & 0xFFFF;
                    if (code != 32 && code != 33) throw;
                    if (watch.ElapsedMilliseconds >= lockTimeoutMilliseconds)
                        throw new IOException("Saved friends are busy in another launcher. Try again in a moment.", error);
                    Thread.Sleep(Math.Min(25, lockTimeoutMilliseconds));
                }
            }
        }

        private void Save(List<SavedFriend> friends)
        {
            string text = new JavaScriptSerializer().Serialize(new { version = 1, friends = friends });
            byte[] data = utf8.GetBytes(text);
            if (data.Length > MaximumBytes) throw new InvalidDataException("Saved friends file exceeds its size limit.");
            AtomicWrite(path, data, true);
        }

        internal static string LoadOrCreateIdentity(string directory)
        {
            string file = Path.Combine(directory, "peer-id.txt");
            if (File.Exists(file)) return ReadIdentity(file);
            string identity = PairSession.NewPeerId();
            try { AtomicWrite(file, utf8.GetBytes(identity + "\n"), false); }
            catch (IOException) { if (!File.Exists(file)) throw; }
            return ReadIdentity(file);
        }

        private static string ReadIdentity(string file)
        {
            string identity = utf8.GetString(ReadBounded(file, 128)).Trim();
            if (!PairSession.ValidIdentity(identity)) throw new InvalidDataException("The launcher identity file is invalid. Restore peer-id.txt to keep existing friend pins.");
            return identity;
        }

        private static void AtomicWrite(string file, byte[] bytes, bool replace)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file));
            string temporary = file + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                using (FileStream stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
                if (replace && File.Exists(file)) File.Replace(temporary, file, null);
                else File.Move(temporary, file);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
