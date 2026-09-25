import chalk from "chalk";
import { maskSessionCode } from "@aicommander/protocol";
import { readState } from "../../state.js";
import { systemctlActiveState, systemctlIsEnabled } from "../systemctl.js";
import { requireRoot, ui } from "../ui.js";

function formatUptime(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export async function cmdStatus(opts: { reveal?: boolean } = {}): Promise<void> {
  ui.header("AI Commander — Agent Status");

  // systemctlActiveState() never throws: a machine with no systemd reports the
  // NO_SYSTEMD sentinel and a failed query reports ACTIVE_STATE_UNKNOWN, both of
  // which are states worth PRINTING here. A try/catch around it could only ever
  // be dead code, and the "systemd is not available, exit 1" it used to hold was
  // wrong twice over — it never ran, and status has plenty to say (the session
  // code, the pid, the uptime) about an agent that is not a systemd unit at all.
  const active = systemctlActiveState();

  const enabled = systemctlIsEnabled();
  const state = await readState();

  ui.info("State", active === "active" ? chalk.green("running") : chalk.red(active));

  if (state) {
    // Masked by default; --reveal prints the full root-exec credential and so
    // requires root (the state file itself is 0600, but be explicit here too).
    if (opts.reveal) {
      requireRoot();
      ui.info("Session code", chalk.bold.cyan(state.sessionCode));
      ui.step(chalk.yellow("  ⚠ Keep this secret — anyone with it can run commands as root here."));
    } else {
      ui.info("Session code", chalk.bold.cyan(maskSessionCode(state.sessionCode)));
      ui.step(chalk.gray("  (run with --reveal to show the full code)"));
    }
    ui.info("PID", String(state.pid));
    const startedAt = new Date(state.startedAt);
    const uptimeSec = Math.floor((Date.now() - startedAt.getTime()) / 1000);
    ui.info("Started", `${state.startedAt}  (${formatUptime(uptimeSec)} ago)`);
    ui.info("Server", state.serverUrl);
  } else if (active === "active") {
    ui.warn("Session code not yet available (agent still starting)");
  }

  ui.info("Enabled", enabled ? chalk.green("yes") : chalk.yellow("no"));
  ui.blank();
}
