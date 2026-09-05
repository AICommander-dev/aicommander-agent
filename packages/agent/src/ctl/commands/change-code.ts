import chalk from "chalk";
import { systemctlRestart } from "../systemctl.js";
import { readState } from "../../state.js";
import { writeRotateMarker, clearSession } from "../../session-store.js";
import { ui, requireRoot, confirm } from "../ui.js";

export async function cmdChangeCode(opts: { yes?: boolean } = {}): Promise<void> {
  requireRoot();

  // Resetting the code rotates the device's credential, which UNLINKS every
  // account currently bound to this machine. Make that explicit before doing it.
  if (!opts.yes) {
    if (!process.stdin.isTTY) {
      ui.error("Refusing to reset the code non-interactively.");
      ui.info("To proceed", "re-run with --yes (this unlinks ALL linked accounts)");
      process.exitCode = 1;
      return;
    }
    const ok = await confirm("Resetting the access code will UNLINK ALL linked accounts. Continue?");
    if (!ok) {
      ui.info("Cancelled", "no changes made");
      return;
    }
  }

  ui.step("Restarting agent to get a new session code…");
  // Force a brand-new code on the next startup: a one-shot rotate marker tells
  // run.ts to register with forceNew, and clearing the stored session ensures we
  // don't re-assert the old code. (Only change-code rotates; reboot/restart
  // re-asserts the same code.)
  writeRotateMarker();
  clearSession();
  systemctlRestart();

  const deadline = Date.now() + 10_000;
  let state = null;
  while (Date.now() < deadline) {
    await new Promise<void>((r) => setTimeout(r, 500));
    state = await readState();
    if (state) break;
  }

  if (state) {
    ui.ok(`New session code:  ${chalk.bold.greenBright(state.sessionCode)}`);
  } else {
    ui.warn("Service restarted. Session code not yet available.");
    ui.info("Check", "aicommander-agent status");
  }
  ui.blank();
}
