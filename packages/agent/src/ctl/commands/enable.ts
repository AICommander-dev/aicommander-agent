import { systemctlStart, systemctlRestart, systemctlEnable, systemctlActiveState } from "../systemctl.js";
import { ui, requireRoot } from "../ui.js";

export function cmdEnable(): void {
  requireRoot();
  if (systemctlActiveState() === "active") {
    // Already running: restart (not no-op) so a just-installed binary is loaded
    // instead of leaving the old process in place.
    ui.warn("Service is already running — restarting to load the current binary.");
    systemctlRestart();
  } else {
    systemctlStart();
  }
  systemctlEnable();
  ui.ok("Service started and enabled to run on boot.");
  ui.blank();
}
