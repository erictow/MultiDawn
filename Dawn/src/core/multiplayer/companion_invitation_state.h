#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "companion.h"
#include "companion_protocol.h"

namespace dawn::core::multiplayer {

/** Value-only mailbox. Caller owns synchronization and authenticated peer identity. */
class InvitationIntentState final {
public:
    [[nodiscard]] bool runtime(std::string_view epoch, std::uint64_t version,
                               bool& changed) noexcept {
        changed = false;
        if (version > 2 || (version == 0 ? epoch != "-" : !protocol::ticket(epoch))) return false;
        const bool same = version == version_ && (version == 0 || epoch == epoch_.data());
        if (same) return true;
        *this = {};
        version_ = version;
        if (version != 0) std::memcpy(epoch_.data(), epoch.data(), epoch.size());
        changed = true;
        return true;
    }

    [[nodiscard]] bool ready() const noexcept { return version_ == 2; }

    /** Duplicates do not extend the deadline or recreate an already consumed intent. */
    [[nodiscard]] bool accepted(std::uint64_t peer, std::string_view ticket,
                                std::uint64_t ttl, std::uint64_t now) noexcept {
        if (!ready() || !protocol::steam_identity(peer) || !protocol::ticket(ticket)
            || ttl == 0 || ttl > 60'000 || now > UINT64_MAX - ttl) return false;
        if (ticket == lastTicket_.data()) return true;
        lastTicket_ = {};
        std::memcpy(lastTicket_.data(), ticket.data(), ticket.size());
        current_ = {};
        current_.peerSteamId = peer;
        current_.ticket = lastTicket_;
        current_.deadline = now + ttl;
        available_ = true;
        return true;
    }

    void revoke(std::string_view ticket) noexcept {
        if (ticket == current_.ticket.data()) { current_ = {}; available_ = false; }
    }

    void expire(std::uint64_t now) noexcept {
        if (current_.deadline != 0 && now >= current_.deadline) { current_ = {}; available_ = false; }
    }

    [[nodiscard]] bool take(std::uint64_t now, AcceptedInvitationIntent& output) noexcept {
        output = {};
        expire(now);
        if (!available_) return false;
        output = current_;
        available_ = false;
        return true;
    }

private:
    std::array<char, 33> epoch_{}, lastTicket_{};
    AcceptedInvitationIntent current_{};
    std::uint64_t version_{};
    bool available_{};
};

} // namespace dawn::core::multiplayer
