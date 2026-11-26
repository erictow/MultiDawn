using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MultiDawn.Launcher
{
    internal static class PairProtectionSelfTests
    {
        private static readonly string Secret = PairCode.Encode(new byte[16]);
        private static readonly string ClientNonce = Token(1), HostNonce = Token(2), ClientId = Token(3), HostId = Token(4);

        internal static void Run(Action<bool, string> require)
        {
            using (PairProtection client = Create(false))
            using (PairProtection host = Create(true))
            {
                string first = client.Seal("CONTROL invite ticket"), second = client.Seal("PING");
                require(host.Open(first) == "CONTROL invite ticket", "Protected client-to-host control round trip");
                Reject(delegate { host.Open(first); }, require, "Protected control replay is refused");
                require(host.Open(second) == "PING", "Rejected replay does not advance receive sequence");
                require(client.Open(host.Seal("PONG")) == "PONG", "Protected reverse direction has an independent sequence");
            }
            using (PairProtection client = Create(false))
            using (PairProtection host = Create(true))
            {
                string first = client.Seal("CONTROL one"), second = client.Seal("CONTROL two");
                Reject(delegate { host.Open(second); }, require, "Protected frames cannot skip or reorder sequence numbers");
                require(host.Open(first) == "CONTROL one" && host.Open(second) == "CONTROL two", "Rejected future frame leaves the expected sequence intact");
            }
            using (PairProtection sender = Create(false))
            using (PairProtection receiver = Create(true))
            {
                string wire = sender.Seal("CONTROL test mutation");
                byte[] frame = PairCode.Decode(wire.Substring(10));
                for (int index = 0; index < frame.Length; ++index)
                {
                    frame[index] ^= 1;
                    bool rejected = false;
                    try { receiver.Open("MD3 FRAME " + PairCode.Encode(frame)); } catch (IOException) { rejected = true; }
                    require(rejected, "Protected frame refuses mutation at byte " + index);
                    frame[index] ^= 1;
                }
                require(receiver.Open(wire) == "CONTROL test mutation", "Unauthenticated mutations publish no plaintext or sequence progress");
                Reject(delegate { receiver.Open("MD2 CONTROL dGVzdA=="); }, require, "Plaintext legacy control has no fallback");
                Reject(delegate { receiver.Open("MD3 PING"); }, require, "Plaintext heartbeat has no fallback");
                Reject(delegate { receiver.Open("MD3 FRAME !!!"); }, require, "Protected frame refuses invalid base64");
                Reject(delegate { receiver.Open(wire + "="); }, require, "Protected frame refuses noncanonical base64");
                Reject(delegate { receiver.Open(wire.Substring(0, wire.Length - 1)); }, require, "Protected frame refuses truncation");
                Reject(delegate { receiver.Open(new string('A', PairProtection.MaximumWireLength + 1)); }, require, "Protected frame refuses oversized input");
            }
            using (PairProtection sender = Create(false))
            using (PairProtection wrongDirection = Create(false))
            using (PairProtection wrongNonce = new PairProtection(Secret, ClientNonce, Token(5), ClientId, HostId, true))
            using (PairProtection wrongClientId = new PairProtection(Secret, ClientNonce, HostNonce, Token(5), HostId, true))
            using (PairProtection wrongHostId = new PairProtection(Secret, ClientNonce, HostNonce, ClientId, Token(5), true))
            using (PairProtection wrongClientNonce = new PairProtection(Secret, Token(5), HostNonce, ClientId, HostId, true))
            using (PairProtection wrongSecret = new PairProtection(Token(5), ClientNonce, HostNonce, ClientId, HostId, true))
            {
                string wire = sender.Seal("CONTROL secret connection binding");
                Reject(delegate { wrongDirection.Open(wire); }, require, "Reflected direction is refused");
                Reject(delegate { wrongNonce.Open(wire); }, require, "Captured control is refused by a fresh host nonce");
                Reject(delegate { wrongClientNonce.Open(wire); }, require, "Captured control is refused by a fresh client nonce");
                Reject(delegate { wrongClientId.Open(wire); }, require, "Control is bound to authenticated client identity");
                Reject(delegate { wrongHostId.Open(wire); }, require, "Control is bound to authenticated host identity");
                Reject(delegate { wrongSecret.Open(wire); }, require, "Control is bound to the pairing secret");
            }
            using (PairProtection sender = Create(false))
            using (PairProtection senderAgain = Create(false))
            using (PairProtection receiver = Create(true))
            {
                string maximum = new string('X', PairProtection.MaximumPlaintext);
                string wire = sender.Seal(maximum);
                require(wire.Length == PairProtection.MaximumWireLength && receiver.Open(wire) == maximum, "Maximum protected control fits the bounded wire frame");
                require(wire != senderAgain.Seal(maximum), "Equal sequence and plaintext receive fresh random IVs");
                RejectArgument(delegate { sender.Seal(maximum + "X"); }, require, "Protected sender refuses oversized plaintext");
                RejectArgument(delegate { sender.Seal("\u0100"); }, require, "Protected sender refuses non-ASCII plaintext");
                RejectArgument(delegate { sender.Seal(""); }, require, "Protected sender refuses empty plaintext");
                sender.Dispose();
                Reject(delegate { sender.Seal("PING"); }, require, "Disposed connection cannot seal another frame");
                receiver.Dispose();
                Reject(delegate { receiver.Open(wire); }, require, "Disposed connection cannot open another frame");
            }
            // A valid MAC with invalid CBC padding exercises the authenticated failure path.
            using (PairProtection sender = Create(false))
            using (PairProtection receiver = Create(true))
            {
                byte[] frame = PairCode.Decode(sender.Seal("PING").Substring(10));
                frame[24] ^= 12; // last IV byte changes the final padding byte 0x0C to invalid 0x00.
                SignClientFrame(frame);
                Reject(delegate { receiver.Open("MD3 FRAME " + PairCode.Encode(frame)); }, require, "Authenticated invalid padding is refused with no plaintext");
            }
            // Authenticated bodies still must obey text limits before their sequence is committed.
            using (PairProtection sender = Create(false))
            using (PairProtection receiver = Create(true))
            {
                byte[] frame = PairCode.Decode(sender.Seal("PING").Substring(10));
                frame[9] ^= (byte)('P' ^ 0); // first plaintext byte becomes NUL without changing padding.
                SignClientFrame(frame);
                Reject(delegate { receiver.Open("MD3 FRAME " + PairCode.Encode(frame)); }, require, "Authenticated invalid plaintext encoding is refused");
            }
        }

        private static PairProtection Create(bool host) { return new PairProtection(Secret, ClientNonce, HostNonce, ClientId, HostId, host); }
        private static string Token(byte value) { byte[] bytes = new byte[16]; bytes[0] = value; return PairCode.Encode(bytes); }
        private static void Reject(Action action, Action<bool, string> require, string name)
        {
            bool rejected = false; try { action(); } catch (IOException) { rejected = true; } require(rejected, name);
        }
        private static void RejectArgument(Action action, Action<bool, string> require, string name)
        {
            bool rejected = false; try { action(); } catch (ArgumentException) { rejected = true; } require(rejected, name);
        }
        private static void SignClientFrame(byte[] frame)
        {
            byte[] root, mac;
            using (HMACSHA256 hmac = new HMACSHA256(PairCode.Decode(Secret)))
                root = hmac.ComputeHash(Encoding.ASCII.GetBytes("MultiDawn|MD3|control-root|" + ClientNonce + "|" + HostNonce + "|" + ClientId + "|" + HostId));
            using (HMACSHA256 hmac = new HMACSHA256(root))
                mac = hmac.ComputeHash(Encoding.ASCII.GetBytes("MultiDawn|MD3|client-to-host|authentication"));
            using (HMACSHA256 hmac = new HMACSHA256(mac))
                Array.Copy(hmac.ComputeHash(frame, 0, frame.Length - 32), 0, frame, frame.Length - 32, 32);
            Array.Clear(root, 0, root.Length); Array.Clear(mac, 0, mac.Length);
        }
    }
}
