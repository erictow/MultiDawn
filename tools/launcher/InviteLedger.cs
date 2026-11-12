using System;
using System.Collections.Generic;

namespace MultiDawn.Launcher
{
    /** In-memory invitation intent only. No record authorizes gameplay or stores account data. */
    internal sealed class InviteContext
    {
        internal readonly long Generation;
        internal readonly string Launcher, LocalEpoch, PeerEpoch;
        internal readonly ulong LocalId, PeerId;
        internal InviteContext(long generation, string launcher, ulong local, ulong peer, string localEpoch, string peerEpoch)
        { Generation = generation; Launcher = launcher; LocalId = local; PeerId = peer; LocalEpoch = localEpoch; PeerEpoch = peerEpoch; }
        internal bool Same(InviteContext other)
        {
            return other != null && Generation == other.Generation && Launcher == other.Launcher && LocalId == other.LocalId
                && PeerId == other.PeerId && LocalEpoch == other.LocalEpoch && PeerEpoch == other.PeerEpoch;
        }
    }

    internal sealed class InviteRecord
    {
        internal readonly InviteContext Context;
        internal readonly string Ticket, ConnectHex, HostEpoch, GuestEpoch;
        internal readonly long Started;
        internal readonly bool Outgoing;
        internal bool Active = true, Accepted;
        internal InviteRecord(InviteContext context, string ticket, string connect, long now, bool outgoing)
        {
            Context = context; Ticket = ticket; ConnectHex = connect; Started = now; Outgoing = outgoing;
            HostEpoch = outgoing ? context.LocalEpoch : context.PeerEpoch;
            GuestEpoch = outgoing ? context.PeerEpoch : context.LocalEpoch;
        }
    }

    /** Caller serializes access. A monotonic local clock supplies every deadline. */
    internal sealed class InviteLedger
    {
        internal const int LifetimeMilliseconds = 60000;
        private readonly Func<long> clock;
        private InviteContext context;
        private InviteRecord outgoing, incoming;
        private readonly Queue<string> recent = new Queue<string>();
        private readonly HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
        internal InviteLedger(Func<long> monotonicClock) { if (monotonicClock == null) throw new ArgumentNullException("monotonicClock"); clock = monotonicClock; }
        internal InviteRecord Outgoing { get { return outgoing != null && outgoing.Active ? outgoing : null; } }
        internal InviteRecord Incoming { get { return incoming != null && incoming.Active ? incoming : null; } }

        internal static bool Token(string value)
        {
            if (value == null || value.Length != 32) return false;
            foreach (char item in value) if (!((item >= '0' && item <= '9') || (item >= 'A' && item <= 'F'))) return false;
            return true;
        }
        private bool Live(InviteRecord record)
        {
            long now = clock();
            return record != null && record.Active && record.Context.Same(context) && now >= record.Started
                && now - record.Started < LifetimeMilliseconds;
        }
        internal int Remaining(InviteRecord record)
        {
            long now = clock();
            if (record == null || !record.Active || !record.Context.Same(context) || now < record.Started || now - record.Started >= LifetimeMilliseconds) return 0;
            return (int)(LifetimeMilliseconds - (now - record.Started));
        }
        internal List<InviteRecord> SetContext(InviteContext next)
        {
            if (context == null ? next == null : context.Same(next)) return new List<InviteRecord>();
            List<InviteRecord> revoked = Invalidate(); context = next; return revoked;
        }
        internal List<InviteRecord> Invalidate()
        {
            List<InviteRecord> records = new List<InviteRecord>();
            if (outgoing != null && outgoing.Active) { outgoing.Active = false; records.Add(outgoing); }
            if (incoming != null && incoming.Active) { incoming.Active = false; records.Add(incoming); }
            return records;
        }
        internal List<InviteRecord> Expire()
        {
            List<InviteRecord> records = new List<InviteRecord>();
            if (outgoing != null && outgoing.Active && !Live(outgoing)) { outgoing.Active = false; records.Add(outgoing); }
            if (incoming != null && incoming.Active && !Live(incoming)) { incoming.Active = false; records.Add(incoming); }
            return records;
        }
        private void Remember(string ticket)
        {
            seen.Add(ticket); recent.Enqueue(ticket);
            while (recent.Count > 64) seen.Remove(recent.Dequeue());
        }
        internal InviteRecord Offer(string ticket, string connect, out InviteRecord replaced)
        {
            replaced = null;
            if (context == null || !Token(ticket) || seen.Contains(ticket)) return null;
            if (outgoing != null && outgoing.Active) { outgoing.Active = false; replaced = outgoing; }
            outgoing = new InviteRecord(context, ticket, connect, clock(), true); Remember(ticket); return outgoing;
        }
        internal InviteRecord Receive(string ticket, ulong target, string hostEpoch, string guestEpoch, string connect, out InviteRecord replaced)
        {
            replaced = null;
            if (context == null || target != context.LocalId || !Token(ticket) || seen.Contains(ticket)
                || hostEpoch != context.PeerEpoch || guestEpoch != context.LocalEpoch) return null;
            if (incoming != null && incoming.Active) { incoming.Active = false; replaced = incoming; }
            incoming = new InviteRecord(context, ticket, connect, clock(), false); Remember(ticket); return incoming;
        }
        internal InviteRecord AcceptIncoming(ulong from, string ticket)
        {
            if (!Live(incoming) || incoming.Accepted || from != context.PeerId || ticket != incoming.Ticket) return null;
            incoming.Accepted = true; return incoming;
        }
        internal InviteRecord AcceptOutgoing(string ticket, string hostEpoch, string guestEpoch)
        {
            if (!Live(outgoing) || outgoing.Accepted || ticket != outgoing.Ticket
                || hostEpoch != outgoing.HostEpoch || guestEpoch != outgoing.GuestEpoch) return null;
            outgoing.Accepted = true; return outgoing;
        }
        internal InviteRecord Revoke(string ticket, string hostEpoch, string guestEpoch)
        {
            foreach (InviteRecord record in new[] { outgoing, incoming })
                if (record != null && record.Active && record.Ticket == ticket && record.HostEpoch == hostEpoch && record.GuestEpoch == guestEpoch)
                { record.Active = false; return record; }
            return null;
        }
    }
}
