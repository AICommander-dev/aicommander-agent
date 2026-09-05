#!/usr/bin/env node
import { program } from "commander";
import { AGENT_VERSION } from "../src/version.js";
import { startAgent } from "../src/run.js";
import { maybeRunSecureExecDrop } from "../src/secure-exec-drop.js";
import { unknownCliCommand, unknownCliCommandMessage } from "../src/cli-guard.js";
import { cmdSelfUpdate } from "../src/self-update.js";
import {
  cmdInstall,
  cmdStatus,
  cmdEnable,
  cmdDisable,
  cmdChangeCode,
  cmdUninstall,
  cmdListAdmins,
  cmdBlockAdmin,
  cmdUnblockAdmin,
  cmdDoctor,
} from "../src/ctl/index.js";

// Secure-exec re-execs this runtime with a sentinel sub-command to drop privilege
// in-process (no external setpriv). When that sentinel is present we become the
// sandboxed command and must NOT run the normal CLI. Checked first, before commander.
if (maybeRunSecureExecDrop(process.argv)) {
  // The drop handler has taken over (it execs the target and process.exit()s with
  // the child's code). Nothing else in this file should run.
} else {

program
  .name("aicommander-agent")
  .description("AI Commander remote agent + service controller")
  .version(AGENT_VERSION);

// Default command — what the systemd service runs (no arguments).
program
  .command("run", { isDefault: true })
  .description("Run the agent: register with the relay and listen for commands")
  // Refuses to start when another agent is (or may be) already running — a second
  // one silently takes this machine's relay session from the first. --force is the
  // operator's override once they have looked; see src/single-instance.ts.
  .option("-f, --force", "Start even if another agent may already be running on this machine")
  .action(async (opts: { force?: boolean }) => {
    await startAgent({ force: opts.force === true });
  });

// `version` as a real sub-command, not only the `--version` flag. Bare `version`
// is what everyone reaches for first, and before the guard below it was the exact
// spelling that fell through to `run` and stole a machine's relay session.
program
  .command("version")
  .description("Print the agent version and exit")
  .action(() => {
    console.log(AGENT_VERSION);
  });

// The upgrade as code rather than as a recipe — it detaches, verifies the signed
// installer against a compiled-in key, and rolls back unless the VERSION actually
// changed and the service stayed up. See src/self-update.ts for why each of those
// is load-bearing.
program
  .command("self-update")
  .description("Upgrade this agent to the latest release (Linux service; detaches, verifies, rolls back)")
  .option("-f, --force", "Reinstall even when already on the published version")
  .action(async (opts: { force?: boolean }) => {
    await cmdSelfUpdate({
      force: opts.force === true,
      // Pass the override THROUGH, undefined and all. Defaulting it here would
      // silently disable the unit lookup inside cmdSelfUpdate — which is the whole
      // point of that lookup, because `sudo` strips AICOMMANDER_SERVER from this
      // process's environment and a staging box would then fetch the production
      // installer, whose install rewrites the unit and moves it onto production.
      // (Verified the hard way: with a default here, the "relay (from the unit)"
      // line never appeared in a real self-update run.)
      serverUrl: process.env["AICOMMANDER_SERVER"],
    });
  });

program
  .command("install")
  .description("Install and start the agent as a systemd service (Linux, root)")
  .option("--server <url>", "Relay server URL baked into the service unit")
  .action(async (opts: { server?: string }) => {
    await cmdInstall(opts);
  });

program
  .command("status")
  .description("Show agent status, session code, and uptime")
  .option("--reveal", "Show the full session code (otherwise masked)")
  .action(async (opts: { reveal?: boolean }) => {
    await cmdStatus(opts);
  });

// One command that answers "why can I not start / why is this machine offline".
// Read-only by design: it consumes no credential, rotates nothing, leaves no
// file behind, and never disturbs a running agent — see src/doctor/types.ts.
// Deliberately NOT root-gated: the person running it is already having a bad
// day, and almost none of the checks needs privilege (the one that does says so
// in its own answer).
program
  .command("doctor")
  .description("Diagnose this installation: files, antivirus interference, connectivity, autostart, helper")
  .option("--json", "Emit the (redacted) report as JSON instead of text")
  .option("--report <path>", "Also write a redacted report file to attach to a support case")
  .option("--offline", "Skip every check that touches the network")
  .option("-v, --verbose", "Show each check's structured facts")
  .action(async (opts: { json?: boolean; report?: string; offline?: boolean; verbose?: boolean }) => {
    await cmdDoctor(opts);
  });

program
  .command("enable")
  .description("Start and enable the agent service")
  .action(() => {
    cmdEnable();
  });

program
  .command("disable")
  .description("Stop and disable the agent service")
  .action(() => {
    cmdDisable();
  });

program
  .command("change-code")
  .aliases(["reset-code"])
  .description("Reset the access code — mint a new code and remove ALL access (unlinks every linked account)")
  .option("-y, --yes", "Skip the confirmation prompt")
  .action(async (opts: { yes?: boolean }) => {
    await cmdChangeCode(opts);
  });

program
  .command("list-admins")
  .description("List the accounts (admins) linked to this device")
  .action(async () => {
    await cmdListAdmins();
  });

program
  .command("block-admin <account>")
  .aliases(["revoke-admin"])
  .description("Block one account on this device (by list number or id) — refuses access; unblock anytime")
  .action(async (account: string) => {
    await cmdBlockAdmin(account);
  });

program
  .command("unblock-admin <account>")
  .description("Restore a blocked account's access (by list number or id)")
  .action(async (account: string) => {
    await cmdUnblockAdmin(account);
  });

program
  .command("uninstall")
  .description("Fully remove the agent (stop, disable, delete files)")
  .option("-f, --force", "Skip confirmation requirement")
  .action((opts: { force: boolean }) => {
    cmdUninstall(opts);
  });

// Fail closed on an unrecognised bare word BEFORE commander can route it to the
// default `run` command — see cli-guard.ts for why that default is a footgun.
// `help` is commander's own implicit command, so it is added by hand.
{
  const known = [
    "help",
    ...program.commands.flatMap((c) => [c.name(), ...c.aliases()]),
  ];
  const offending = unknownCliCommand(process.argv, known);
  if (offending !== null) {
    console.error(unknownCliCommandMessage(offending));
    process.exit(1);
  }
}

program.parseAsync().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

}
