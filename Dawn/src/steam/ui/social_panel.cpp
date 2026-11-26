#include "social_panel.h"

#include <array>
#include <imgui.h>

#include "../../core/ui/modules/registry/ui_module_registry.h"
#include "../../core/ui/scaling/dpi/ui_dpi_scaling.h"
#include "../runtime/social.h"

namespace dawn::steam::ui {
namespace {

core::ui::modules::registry::PageRegistration g_page;
const char* g_result{};
std::uint64_t g_displayedPeer{};

void draw_page() noexcept {
    social::PeerProfile peer{};
    if (!social::peer_profile(peer)) {
        g_result = nullptr; g_displayedPeer = 0;
        ImGui::TextDisabled("No partner is connected.");
        ImGui::TextWrapped("Use Host or Join in the MultiDawn launcher to pair with your partner.");
        return;
    }
    if (g_displayedPeer != peer.steamId) { g_result = nullptr; g_displayedPeer = peer.steamId; }
    ImGui::TextUnformatted(peer.name.data());
    ImGui::SameLine();
    ImGui::TextDisabled(peer.gameRunning ? "In game" : "Online");
    ImGui::Spacing();
    if (peer.status[0] != '\0') { ImGui::TextWrapped("%s", peer.status.data()); }
    std::array<char, social::kConnectCapacity> connect{};
    const bool canInvite = social::local_presence("connect", connect) && connect[0] != '\0';
    ImGui::BeginDisabled(!canInvite);
    if (ImGui::Button("Invite to party")) {
        g_result = social::send_invitation(peer.steamId, connect.data())
                       ? "Invitation sent." : "The invitation could not be sent. Check your connection.";
    }
    ImGui::EndDisabled();
    if (!canInvite) { ImGui::TextWrapped("A party invitation is available when the game publishes a joinable session."); }
    if (g_result != nullptr) { ImGui::TextWrapped("%s", g_result); }
    social::PendingInvitation pending{};
    if (social::pending_invitation(pending)) {
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
        ImGui::Text("Party invitation from %s", peer.name.data());
        if (pending.waitingForAuthorization) { ImGui::TextDisabled("Waiting for host authorization"); }
        ImGui::BeginDisabled(pending.waitingForAuthorization);
        if (ImGui::Button("Accept invitation")) {
            g_result = social::accept_invitation(pending.id)
                           ? (pending.ticket[0] != '\0' ? nullptr : "Join request delivered to the game.")
                           : "The acceptance request could not be sent. Try again.";
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Decline")) { (void)social::dismiss_invitation(pending.id); g_result = "Invitation declined."; }
    }
}

void reset_page() noexcept { g_result = nullptr; g_displayedPeer = 0; }

} // namespace

bool initialize() noexcept {
    return g_page.acquire(core::ui::modules::Owner::core, "steam.friends", "Friends", &draw_page, &reset_page);
}

void shutdown() noexcept { g_page.release(&reset_page); }

bool draw_invitation_notice() noexcept {
    social::PendingInvitation invitation{};
    social::PeerProfile peer{};
    if (!social::pending_invitation(invitation) || !social::peer_profile(peer)
        || peer.steamId != invitation.from || ImGui::GetCurrentContext() == nullptr) { return false; }
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    if (viewport == nullptr) { return false; }
    const float margin = core::ui::scaling::dpi::pixels(24.0F);
    ImGui::SetNextWindowPos({viewport->WorkPos.x + viewport->WorkSize.x - margin,
                              viewport->WorkPos.y + margin}, ImGuiCond_Always, {1.0F, 0.0F});
    constexpr auto flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs
                           | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize
                           | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoMove;
    if (ImGui::Begin("##dawn_party_invitation", nullptr, flags)) {
        ImGui::Text("Party invitation from %s", peer.name.data());
        ImGui::TextUnformatted(invitation.waitingForAuthorization
            ? "Waiting for host authorization" : "Open Dawn > Friends to accept or decline.");
    }
    ImGui::End();
    return true;
}

} // namespace dawn::steam::ui
