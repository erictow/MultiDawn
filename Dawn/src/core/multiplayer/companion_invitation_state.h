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
    [[nodiscard]] std::string_view epoch() const noexcept { return epoch_.data(); }

    /** Duplicates do not extend the deadline or recreate an already consumed intent. */
    [[nodiscard]] bool accepted(std::uint64_t peer, std::string_view ticket,
                                std::uint64_t ttl, std::uint64_t now,
                                bool* fresh = nullptr) noexcept {
        if (fresh != nullptr) *fresh = false;
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
        if (fresh != nullptr) *fresh = true;
        return true;
    }

    /** The current ticket's lifetime is independent of whether the mailbox was taken. */
    [[nodiscard]] bool current(std::uint64_t peer, std::string_view ticket,
                               std::uint64_t now) const noexcept {
        return current_.deadline > now && current_.peerSteamId == peer && ticket == current_.ticket.data();
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

/** Bounded request/reply state. Caller authenticates the pipe and serializes every operation. */
class InvitationPreflightState final {
public:
    static constexpr std::uint64_t kRequestTimeout = 5'000;

    [[nodiscard]] bool begin(std::string_view nonce, std::uint64_t peer,
                              std::string_view ticket, std::string_view localEpoch,
                              std::string_view peerEpoch, std::uint64_t pairGeneration,
                              std::uint64_t companionGeneration, std::uint64_t requestGeneration,
                              std::uint64_t now) noexcept {
        expire(now);
        if (pending_ || !protocol::ticket(nonce) || !protocol::ticket(ticket)
            || !protocol::ticket(localEpoch) || !protocol::ticket(peerEpoch)
            || !protocol::steam_identity(peer) || pairGeneration == 0
            || companionGeneration == 0 || requestGeneration == 0) return false;
        *this = {};
        std::memcpy(nonce_.data(), nonce.data(), nonce.size());
        std::memcpy(observation_.ticket.data(), ticket.data(), ticket.size());
        std::memcpy(observation_.localEpoch.data(), localEpoch.data(), localEpoch.size());
        std::memcpy(observation_.peerEpoch.data(), peerEpoch.data(), peerEpoch.size());
        observation_.peerSteamId = peer;
        observation_.pairGeneration = pairGeneration;
        observation_.companionGeneration = companionGeneration;
        observation_.requestGeneration = requestGeneration;
        started_ = now;
        pending_ = true;
        return true;
    }

    /** Well-formed stale nonces are ignored; matching malformed/mismatched replies are refused. */
    [[nodiscard]] bool response(const protocol::Fields& fields, std::uint64_t now) noexcept {
        expire(now);
        if (fields.count == 2 && fields.values[0] == "PREFLIGHT_NO" && protocol::ticket(fields.values[1])) {
            if (pending_ && fields.values[1] == nonce_.data()) *this = {};
            return true;
        }
        std::uint64_t peer{}, generation{}, ttl{};
        if (fields.count != 8 || fields.values[0] != "PREFLIGHT_OK"
            || !protocol::ticket(fields.values[1]) || !protocol::decimal(fields.values[2], peer)
            || !protocol::steam_identity(peer) || !protocol::ticket(fields.values[3])
            || !protocol::decimal(fields.values[4], generation) || generation == 0
            || !protocol::ticket(fields.values[5]) || !protocol::ticket(fields.values[6])
            || !protocol::decimal(fields.values[7], ttl) || ttl == 0 || ttl > 60'000) return false;
        if (!pending_ || fields.values[1] != nonce_.data()) return true;
        if (peer != observation_.peerSteamId || fields.values[3] != observation_.ticket.data()
            || generation != observation_.pairGeneration
            || fields.values[5] != observation_.localEpoch.data()
            || fields.values[6] != observation_.peerEpoch.data()) return false;
        // Charge all local queuing/response time against the authoritative remaining TTL.
        if (now < started_ || now - started_ >= ttl || started_ > UINT64_MAX - ttl) {
            *this = {};
            return true;
        }
        observation_.deadline = started_ + ttl;
        pending_ = false;
        available_ = true;
        return true;
    }

    void revoke(std::string_view ticket) noexcept {
        if (ticket == observation_.ticket.data()) *this = {};
    }
    /** Conservatively retire an older observation when another invitation replaces it locally. */
    void replace(std::string_view ticket) noexcept {
        if (observation_.ticket[0] != '\0' && ticket != observation_.ticket.data()) *this = {};
    }
    void expire(std::uint64_t now) noexcept {
        if (((pending_ || observation_.deadline != 0) && now < started_)
            || (pending_ && now - started_ >= kRequestTimeout)
            || (observation_.deadline != 0 && now >= observation_.deadline)) *this = {};
    }
    [[nodiscard]] bool pending() const noexcept { return pending_; }
    [[nodiscard]] bool take(std::uint64_t now, InvitationPreflightObservation& output) noexcept {
        output = {};
        expire(now);
        if (!available_) return false;
        output = observation_;
        available_ = false;
        return true;
    }
    [[nodiscard]] bool validate(std::uint64_t now, const InvitationPreflightObservation& observed) noexcept {
        expire(now);
        return observation_.deadline != 0 && now < observation_.deadline && observed == observation_;
    }

private:
    std::array<char, 33> nonce_{};
    InvitationPreflightObservation observation_{};
    std::uint64_t started_{};
    bool pending_{}, available_{};
};

} // namespace dawn::core::multiplayer
