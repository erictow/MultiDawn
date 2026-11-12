using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MultiDawn.Launcher
{
    // One authenticated connection, with independent keys and counters in each direction.
    // Pair codes are bearer secrets. This protects the connection, not a disclosed code.
    internal sealed class PairProtection : IDisposable
    {
        internal const int MaximumPlaintext = 1032; // "CONTROL " plus the existing 1024-byte limit.
        internal const int MaximumWireLength = 1473;
        private const string Prefix = "MD3 FRAME ";
        private const int HeaderLength = 25; // version, uint64 sequence, 16-byte random IV.
        private const int TagLength = 32;
        private readonly object sync = new object();
        private readonly byte[] sendEncryption, sendAuthentication, receiveEncryption, receiveAuthentication;
        private ulong sent, received;
        private bool disposed;

        internal PairProtection(string secret, string clientNonce, string hostNonce,
            string clientIdentity, string hostIdentity, bool host)
        {
            if (!PairSession.ValidIdentity(secret) || !PairSession.ValidIdentity(clientNonce)
                || !PairSession.ValidIdentity(hostNonce) || !PairSession.ValidIdentity(clientIdentity)
                || !PairSession.ValidIdentity(hostIdentity)) throw new ArgumentException("Invalid protected connection transcript.");
            byte[] input = PairCode.Decode(secret);
            byte[] root;
            try
            {
                using (HMACSHA256 hmac = new HMACSHA256(input))
                    root = hmac.ComputeHash(Encoding.ASCII.GetBytes("MultiDawn|MD3|control-root|" + clientNonce + "|" + hostNonce + "|" + clientIdentity + "|" + hostIdentity));
            }
            finally { Array.Clear(input, 0, input.Length); }
            try
            {
                sendEncryption = Derive(root, host ? "host-to-client|encryption" : "client-to-host|encryption");
                sendAuthentication = Derive(root, host ? "host-to-client|authentication" : "client-to-host|authentication");
                receiveEncryption = Derive(root, host ? "client-to-host|encryption" : "host-to-client|encryption");
                receiveAuthentication = Derive(root, host ? "client-to-host|authentication" : "host-to-client|authentication");
            }
            finally { Array.Clear(root, 0, root.Length); }
        }

        private static byte[] Derive(byte[] root, string purpose)
        {
            using (HMACSHA256 hmac = new HMACSHA256(root))
                return hmac.ComputeHash(Encoding.ASCII.GetBytes("MultiDawn|MD3|" + purpose));
        }

        // The caller holds its connection's write gate until the complete frame is written.
        internal string Seal(string message)
        {
            ValidatePlaintext(message);
            lock (sync)
            {
                if (disposed || sent == UInt64.MaxValue) throw new IOException("Protected connection is no longer available.");
                byte[] plaintext = Encoding.ASCII.GetBytes(message), ciphertext, iv = new byte[16];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(iv);
                try
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = sendEncryption; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                        using (ICryptoTransform encryptor = aes.CreateEncryptor())
                            ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                    }
                }
                finally { Array.Clear(plaintext, 0, plaintext.Length); }
                byte[] frame = new byte[HeaderLength + ciphertext.Length + TagLength];
                frame[0] = 3;
                ulong sequence = ++sent;
                for (int index = 8; index >= 1; --index) { frame[index] = (byte)sequence; sequence >>= 8; }
                Array.Copy(iv, 0, frame, 9, iv.Length);
                Array.Copy(ciphertext, 0, frame, HeaderLength, ciphertext.Length);
                using (HMACSHA256 hmac = new HMACSHA256(sendAuthentication))
                    Array.Copy(hmac.ComputeHash(frame, 0, frame.Length - TagLength), 0, frame, frame.Length - TagLength, TagLength);
                return Prefix + PairCode.Encode(frame);
            }
        }

        internal string Open(string line)
        {
            if (line == null || line.Length > MaximumWireLength || !line.StartsWith(Prefix, StringComparison.Ordinal))
                throw InvalidFrame();
            byte[] frame;
            string encoded = line.Substring(Prefix.Length);
            try { frame = PairCode.Decode(encoded); }
            catch (FormatException) { throw InvalidFrame(); }
            if (PairCode.Encode(frame) != encoded || frame.Length < HeaderLength + 16 + TagLength
                || frame[0] != 3 || (frame.Length - HeaderLength - TagLength) % 16 != 0) throw InvalidFrame();
            lock (sync)
            {
                if (disposed || received == UInt64.MaxValue) throw InvalidFrame();
                byte[] tag;
                using (HMACSHA256 hmac = new HMACSHA256(receiveAuthentication))
                    tag = hmac.ComputeHash(frame, 0, frame.Length - TagLength);
                int different = 0;
                for (int index = 0; index < TagLength; ++index) different |= tag[index] ^ frame[frame.Length - TagLength + index];
                if (different != 0) throw InvalidFrame(); // Authenticate before any decryption or padding check.
                ulong sequence = 0;
                for (int index = 1; index <= 8; ++index) sequence = (sequence << 8) | frame[index];
                if (sequence != received + 1) throw InvalidFrame();
                byte[] plaintext = null, iv = new byte[16];
                Array.Copy(frame, 9, iv, 0, iv.Length);
                try
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = receiveEncryption; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                        using (ICryptoTransform decryptor = aes.CreateDecryptor())
                            plaintext = decryptor.TransformFinalBlock(frame, HeaderLength, frame.Length - HeaderLength - TagLength);
                    }
                    if (plaintext.Length == 0 || plaintext.Length > MaximumPlaintext) throw InvalidFrame();
                    foreach (byte value in plaintext) if (value < 32 || value > 126) throw InvalidFrame();
                    string message = Encoding.ASCII.GetString(plaintext);
                    received = sequence;
                    return message;
                }
                catch (CryptographicException) { throw InvalidFrame(); }
                finally { if (plaintext != null) Array.Clear(plaintext, 0, plaintext.Length); }
            }
        }

        private static void ValidatePlaintext(string message)
        {
            if (String.IsNullOrEmpty(message) || message.Length > MaximumPlaintext) throw new ArgumentException("Invalid protected message size.");
            foreach (char value in message) if (value < 32 || value > 126) throw new ArgumentException("Invalid protected message encoding.");
        }
        private static IOException InvalidFrame() { return new IOException("Invalid protected pairing message."); }

        public void Dispose()
        {
            lock (sync)
            {
                if (disposed) return;
                disposed = true;
                Array.Clear(sendEncryption, 0, sendEncryption.Length); Array.Clear(sendAuthentication, 0, sendAuthentication.Length);
                Array.Clear(receiveEncryption, 0, receiveEncryption.Length); Array.Clear(receiveAuthentication, 0, receiveAuthentication.Length);
            }
        }
    }
}
