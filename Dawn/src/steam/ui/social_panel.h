#pragma once

namespace dawn::steam::ui {

/** Register the Dawn Friends page in the existing game overlay. */
[[nodiscard]] bool initialize() noexcept;
void shutdown() noexcept;
/** Draw a non-interactive incoming-invitation notice in the caller's active ImGui frame. */
[[nodiscard]] bool draw_invitation_notice() noexcept;

} // namespace dawn::steam::ui
