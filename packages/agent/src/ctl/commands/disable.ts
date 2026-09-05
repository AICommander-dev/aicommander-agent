import { systemctlStop, systemctlDisable, listJobScopeUnits } from "../systemctl.js";
import { JOB_SCOPE_UNIT_GLOB } from "../../job-scope.js";
import { ui, requireRoot } from "../ui.js";

export function cmdDisable(): void {
  requireRoot();
  systemctlStop();
  systemctlDisable();
  ui.ok("Service stopped and disabled.");

  // …which used to be the whole story, and is not any more. job-scope.ts puts
  // every detached Linux job in its own transient scope OUTSIDE the service's
  // cgroup — deliberately, so an agent restart or upgrade no longer kills a
  // twelve-hour training run. The same property means `systemctl stop` on the
  // service no longer stops the jobs, so this command can leave root processes
  // running that the operator has no reason to expect and, once the agent is
  // down, no way to reach: remote_job_cancel travels through the agent.
  //
  // We report them; we do NOT stop them. `disable` says "do not run the agent",
  // not "destroy what is running" — ending someone's training job because they
  // turned the agent off on boot would be a far worse surprise than a warning
  // they can act on. (uninstall --force makes the opposite call, and says why.)
  const units = listJobScopeUnits();
  if (units === null) {
    ui.warn("Could NOT list AI Commander job scopes, so a still-running job cannot be ruled out.");
    ui.warn(`Check with: systemctl list-units --type=scope '${JOB_SCOPE_UNIT_GLOB}'`);
  } else if (units.length > 0) {
    ui.warn(`${units.length} job(s) are STILL RUNNING as root, in their own systemd scope:`);
    for (const unit of units) ui.warn(`  ${unit}`);
    ui.warn("They outlive the agent by design, but nothing supervises them now: they will not");
    ui.warn("report progress, and they can no longer be cancelled through AI Commander.");
    ui.warn(`Stop them with: systemctl stop '${JOB_SCOPE_UNIT_GLOB}'`);
  }
  ui.blank();
}
