import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import chalk from "chalk";
import { isGpuLockFileName, JOB_ID_PATTERN } from "@aicommander/protocol";
import {
  systemctlStop,
  systemctlDisable,
  systemctlKill,
  systemctlActiveState,
  listJobScopeUnits,
  systemctlStopUnit,
  systemctlKillUnit,
  daemonReload,
  NO_SYSTEMD,
  ACTIVE_STATE_UNKNOWN,
  SCOPE_STOP_TIMEOUT_MS,
} from "../systemctl.js";
import { JOB_SCOPE_UNIT_GLOB } from "../../job-scope.js";
import { ui, requireRoot } from "../ui.js";
import { envConfigDir } from "../../config-dir.js";
import { resolveJobsRoot } from "../../job-manager.js";
import { findRunningAgents } from "../../live-agent.js";

const SERVICE_FILE = "/etc/systemd/system/aicommander-agent.service";
const BIN = "/usr/local/bin/aicommander-agent";
const CTL_SYMLINK = "/usr/local/bin/aicommander-ctl";
const STATE_DIR = "/var/run/aicommander-agent";
const DEVICE_DIR = "/etc/aicommander-agent";
const SESSION_FILE = "/etc/aicommander-agent/session.json";
const ROTATE_MARKER = "/etc/aicommander-agent/.rotate";

/**
 * The non-root default identity directory, derived exactly as device.ts and
 * session-store.ts derive it (`os.homedir()`), so we purge the path THEY would
 * use — see the HOME caveat where this is consumed.
 */
const FALLBACK_DIR = path.join(os.homedir(), ".config", "aicommander-agent");

/** Everything device.ts + session-store.ts persist inside a config directory. */
const IDENTITY_FILES = ["device.json", "session.json", "session.token", ".rotate"];

/** FHS jobs root of a Linux service (job-manager.ts), kept once the override moved it. */
const SERVICE_DATA_DIR = "/var/lib/aicommander";

/**
 * The fallback HOME job-manager.ts creates for root-run jobs — the one entry in a
 * jobs root that is neither a job directory nor a GPU lock.
 */
const SHARED_HOME_DIR = "home";

/** Returns false when the target is still on disk after we tried to remove it. */
function removeIfExists(target: string, label: string): boolean {
  try {
    if (fs.existsSync(target) || fs.lstatSync(target)) {
      fs.rmSync(target, { recursive: true, force: true });
      ui.ok(`${label} removed.`);
      return true;
    }
  } catch (err) {
    // lstatSync throws for a path that is simply missing — nothing to do. A
    // failing rmSync is different: it leaves a live credential behind, which we
    // must never fold into the "fully removed" summary.
    if (fs.existsSync(target)) {
      const detail = err instanceof Error ? err.message : String(err);
      ui.error(`${label} could NOT be removed: ${detail}`);
      return false;
    }
  }
  ui.warn(`${label} not found (already removed?).`);
  return true;
}

/** Delete a directory only if it is empty; anything else stays. */
function removeIfEmpty(dir: string): void {
  try {
    fs.rmdirSync(dir);
    ui.ok(`${dir} removed.`);
  } catch {
    // Not empty, missing, or not ours to delete — nothing more to do here.
  }
}

/**
 * Is `root` a jobs root this software created, i.e. safe to delete RECURSIVELY?
 *
 * The recursive delete is justified for a jobs root and NOT for the config dir
 * around it: a jobs root is ours end to end, with a layout we own (job-manager.ts),
 * whereas the config dir is a path the operator chose and may share with other
 * things. Do not collapse the two into one `rm -rf`. A path that fails any check
 * below is left alone and reported rather than deleted on a guess.
 *
 * What makes the recursive delete defensible is the readdir test: EVERY name in the
 * root must be one job-manager.ts could have written — a job directory, a GPU lock,
 * or the shared home. So both recognisers are the protocol package's own, the same
 * ones job-manager uses to MINT those names (JOB_ID_PATTERN, isGpuLockFileName),
 * never a local copy that could drift away from them and start calling a stranger's
 * file ours. Anything else in the root — one unexpected name is enough — makes the
 * whole root "foreign" and it is left on disk.
 */
function classifyJobsRoot(root: string): "absent" | "ours" | "foreign" {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(root);
  } catch {
    return "absent";
  }
  try {
    // lstat, not stat: a symlink would take the recursive delete somewhere we
    // never created.
    if (stat.isSymbolicLink() || !stat.isDirectory()) return "foreign";
    return fs
      .readdirSync(root)
      .every((e) => JOB_ID_PATTERN.test(e) || isGpuLockFileName(e) || e === SHARED_HOME_DIR)
      ? "ours"
      : "foreign";
  } catch {
    // Unreadable: refuse to recursively delete what we could not inspect.
    return "foreign";
  }
}

/**
 * Bounded synchronous pause. `systemctl kill` only SENDS the signal, so the
 * re-check below has to give the cgroup a moment to empty, and cmdUninstall is
 * synchronous (the CLI action calls it without awaiting).
 */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * The `is-active` answers that PROVE the unit is not running, plus systemctl.ts's
 * "there is no systemd here" sentinel — on macOS, in a container or on QTS there
 * is no unit at all, so there is nothing to stop and the uninstall may proceed.
 *
 * Deliberately a whitelist. `active` and `reloading` are obviously still up, but
 * so are the transitional `activating`/`deactivating` (the process is alive and
 * still holds its credentials), and ACTIVE_STATE_UNKNOWN means we never got an
 * answer. Anything not listed here is treated as "still running" — the fail-closed
 * side, because the alternative is deleting a live root agent's files.
 */
const STOPPED_STATES = new Set([
  "inactive",
  // `failed` is safe HERE because of how OUR unit is written (install.ts, and
  // the web/install it mirrors): Type=simple with the default
  // KillMode=control-group, so systemd tears the whole cgroup down before the
  // unit may reach `failed` — an empty cgroup is part of what the word means.
  // A hand-edited unit with KillMode=process would break that inference: only
  // the main process is killed, and children survive into a `failed` unit. That
  // is one of the holes the process check below closes, so the whitelist stands
  // as it is.
  "failed",
  "unknown", // old systemd's "no such unit"
  NO_SYSTEMD,
]);

/** Operator-facing wording for the state that blocked the uninstall. */
function describeState(state: string): string {
  if (state === ACTIVE_STATE_UNKNOWN) return "in an unknown state (systemd could not be queried)";
  if (state === "deactivating") return "still shutting down";
  if (state === "activating") return "starting up";
  return `${state}`;
}

/**
 * Stop the unit and PROVE it stopped. Returns the state that blocked us when it
 * could not be proven.
 *
 * A `systemctl stop` error on its own proves nothing: it looks identical for a
 * unit that was never installed, a machine with no systemd at all, and a stop
 * that genuinely failed to kill anything — so only `is-active` may decide. It
 * has to: everything after this point deletes the workspaces, logs, binary and
 * credentials that a surviving agent is still using and still serving from. And
 * "not `active`" is not the same question as "stopped" (see STOPPED_STATES): a
 * unit that is still deactivating, or one systemd would not tell us about, must
 * not buy the uninstall its go-ahead.
 */
function stopServiceVerified(): { ok: true; state: string } | { ok: false; state: string } {
  try { systemctlStop(); } catch { /* not installed, not running, or failed — is-active tells which */ }
  let state = systemctlActiveState();
  if (STOPPED_STATES.has(state)) return { ok: true, state };

  // The same escalation install.ts uses for a hung unit, for the same reason —
  // and, like the QNAP skill's stop block, verified afterwards: an unchecked kill is
  // not a guarantee. The bounded re-check that follows also gives a unit that was
  // merely mid-`deactivating`, or a query that failed on a transient bus hiccup,
  // its chance to settle into a real answer.
  ui.warn(`Service is ${describeState(state)} — sending SIGKILL…`);
  try { systemctlKill(); } catch { /* nothing to kill, or nothing to kill it with */ }
  for (let attempt = 0; attempt < 4; attempt++) {
    sleepSync(250);
    state = systemctlActiveState();
    if (STOPPED_STATES.has(state)) return { ok: true, state };
  }
  return { ok: false, state };
}

/**
 * The total wall-clock this command will spend waiting on GRACEFUL scope stops
 * before it starts going straight to SIGKILL.
 *
 * SCOPE_STOP_TIMEOUT_MS bounds ONE unit; this bounds the loop, which is the
 * number the operator actually experiences. Without it, "15 s each" is still
 * unbounded in the only variable that matters here — a box that legitimately
 * runs twenty jobs would sit for five minutes mid-uninstall. 60 s lets the first
 * four stuck scopes each have their full graceful window (a cooperative job
 * needs a fraction of it, so a healthy machine never approaches this) and
 * converts the rest into kills, which cost ~nothing. Worst case for the whole
 * teardown is therefore roughly this budget plus one settle-and-verify pass,
 * not N × 90 s.
 */
const SCOPE_STOP_BUDGET_MS = 60_000;

/**
 * The same bound for the SIGKILL phase, for the same reason: SCOPE_KILL_TIMEOUT_MS
 * bounds ONE `systemctl kill`, and the kills run serially, so without this the
 * teardown's worst case is still N × 5 s.
 *
 * N is normally small — a machine cannot exceed JOB_MAX_CONCURRENT (32) running
 * jobs — but "normally" is not what this command must survive: the listing is
 * parsed systemd output, and a stale, duplicated or simply unexpected one must
 * not be able to hold an uninstall open for minutes with nothing on screen. 30 s
 * gives six wedged kills their full round trip, and a kill that has anything to
 * signal returns in ~0.01 s (measured, see SCOPE_KILL_TIMEOUT_MS), so a healthy
 * machine never comes near it. Spending the budget is not a verdict: a unit we
 * never got to signal goes to the verification pass below like any other, and
 * the fresh listing — not the missed kill — decides whether it is gone.
 */
const SCOPE_KILL_BUDGET_MS = 30_000;

/** Outcome of the scope teardown; `failed`/`enumerationFailed` gate the deletes. */
interface ScopeTeardown {
  /** Down without us having to end it: a plain `systemctl stop`, or a job that finished by itself. */
  stopped: string[];
  /** Would not stop, was SIGKILLed, and is VERIFIED gone. A destroyed job. */
  killed: string[];
  /** Still there, or we could not confirm it went. A job that may still be alive. */
  failed: string[];
  /** We never got a usable listing, so we do not know what is running. */
  enumerationFailed: boolean;
}

/**
 * Stop the transient job scopes the agent left behind, and report what would not
 * go. Called AFTER the unit is proven stopped and after the service file, the
 * ctl symlink, the binary and the state dir are already gone — but BEFORE the
 * job workspaces and logs, which are the files a surviving job is still writing
 * to and the only deletion this result gates.
 *
 * This exists because job-scope.ts moved running jobs OUT of the service's
 * control group, and that changed an assumption this command was built on.
 * `systemctl stop aicommander-agent` used to be the whole story — the unit is
 * `KillMode=control-group` (see STOPPED_STATES, where the same fact is what
 * makes `failed` safe to accept), so stopping it took every job with it. A job
 * in its own scope is no longer in that cgroup and keeps running, as a root
 * process, while the code below deletes its output.log and its workspace out
 * from under it. Deleting a live job's files is exactly the harm the rest of
 * this command refuses to do to a live agent.
 *
 * Anything that cannot be stopped — or a machine whose scopes we could not even
 * list — is handed back so it can disqualify the "fully removed" claim AND
 * suppress the jobs-root deletion. There is no abort here, unlike the live-agent
 * check: by this point the unit is stopped and the service file is gone, so
 * stopping would leave a HALF-uninstalled machine, which is worse than a named
 * leftover.
 *
 * WHY A TIMED-OUT STOP ESCALATES TO SIGKILL — the one deliberately destructive
 * decision in this command. `uninstall --force` is an explicit "remove
 * everything from this machine", and the two ways out of a scope that will not
 * stop are both bad: kill the job, or leave a root process running with its
 * workspace and output.log deleted around it (it keeps writing to unlinked fds,
 * the job never reports, and nothing on the machine can stop it any more, since
 * the agent and its CLI are gone). Between destroying a job the operator asked
 * to have removed and leaking an unkillable-by-any-remaining-tool root process,
 * the kill is the lesser harm — but ONLY because it is loud: every escalation is
 * printed as it happens and every killed scope is named in the summary. Note
 * that `disable` faces the same situation and makes the OPPOSITE call, because
 * "stop the agent on boot" is not consent to end a running job.
 *
 * WHY NO EXIT CODE HERE IS A VERDICT. The asymmetry this whole file is built on
 * runs both ways: never delete a live job's data, but never withhold cleanup
 * from a job that has demonstrably finished either — an operator who is told
 * "a job may still be running as root, even with SIGKILL" about a job that
 * simply ended is being handed a false alarm and a directory they must delete by
 * hand. And a job CAN end between the listing and the stop; systemd then answers
 * `Failed to stop …: Unit … not loaded.` with a NON-ZERO exit, which is exactly
 * what a stop that failed to kill anything looks like. job-scope.ts's
 * killJobScope documents that same answer as the normal case, so the two must
 * not disagree.
 *
 * The way out is NOT to read systemd's message — that text is localised and
 * version-dependent, and this decision gates an `rm -rf` over a live root
 * process's data. It is to decide by EVIDENCE, as stopServiceVerified already
 * does with `is-active`: every unit whose stop OR kill reported failure goes to
 * the verification pass, and absence from a FRESH listing is what settles it as
 * gone. A listing we cannot get settles nothing and keeps the data.
 */
function stopJobScopes(): ScopeTeardown {
  const units = listJobScopeUnits();
  if (units === null) return { stopped: [], killed: [], failed: [], enumerationFailed: true };
  const stopped: string[] = [];
  const killed: string[] = [];
  const failed: string[] = [];
  // Units the commands did NOT settle, with how each is to be REPORTED if the
  // listing proves it gone. `killed`: our SIGKILL was accepted, so the cgroup was
  // there and we ended it — say so. `vanished`: nothing we ran got a grip on it,
  // so a unit that is no longer listed ended on its own and must not be reported
  // as a job we destroyed. Neither value is evidence by itself; the listing is.
  const pending = new Map<string, "killed" | "vanished">();
  const gracefulUntil = Date.now() + SCOPE_STOP_BUDGET_MS;
  let killBudgetLeft = SCOPE_KILL_BUDGET_MS;

  for (const [index, unit] of units.entries()) {
    // Progress, because a teardown that takes tens of seconds must not look like
    // a hung CLI — the whole point of bounding the calls above.
    ui.step(`  [${index + 1}/${units.length}] stopping ${unit}…`);
    if (Date.now() < gracefulUntil) {
      try {
        systemctlStopUnit(unit);
        stopped.push(unit);
        continue;
      } catch (err) {
        // execFileSync marks a timeout kill with `code === "ETIMEDOUT"`;
        // anything else is a stop that genuinely failed — or a unit that is
        // simply no longer there, which is indistinguishable from it by exit
        // code. So the timeout case, where the unit demonstrably still exists,
        // keeps its blunt wording and the ambiguous one does not promise
        // something it cannot know.
        //
        // NOT `killed` — that is the ASYNC execFile callback's shape. A
        // synchronous timeout (measured, and pinned by uninstall.test.ts) leaves
        // `killed` undefined and reports `code: "ETIMEDOUT"`, `status: null`,
        // `signal: "SIGTERM"`. Nothing else that can reach this catch carries
        // that code: the unit-name guard in systemctlStopUnit throws a plain
        // Error with no `code`, a spawn failure carries its own errno string
        // (ENOENT, EACCES), and a non-zero exit carries a NUMERIC `status` and
        // no string `code` at all. Testing `signal === "SIGTERM"` on top would
        // add no certainty — it is merely the default killSignal restating the
        // same event — and would silently switch this branch off if that default
        // ever changed.
        const timedOut = (err as NodeJS.ErrnoException).code === "ETIMEDOUT";
        ui.warn(
          timedOut
            ? `${unit} did not stop within ${SCOPE_STOP_TIMEOUT_MS / 1000}s — sending SIGKILL (this ENDS the job).`
            : `${unit} could not be stopped — escalating to SIGKILL (this ENDS the job if it is still running).`,
        );
      }
    } else {
      ui.warn(`${unit}: the ${SCOPE_STOP_BUDGET_MS / 1000}s graceful-stop budget is spent — sending SIGKILL (this ENDS the job).`);
    }
    if (killBudgetLeft <= 0) {
      ui.warn(`${unit}: the ${SCOPE_KILL_BUDGET_MS / 1000}s SIGKILL budget is spent — not signalling it; the verification listing decides whether it is gone.`);
      pending.set(unit, "vanished");
      continue;
    }
    const killStarted = Date.now();
    try {
      systemctlKillUnit(unit);
      pending.set(unit, "killed");
    } catch {
      // Nothing left to try — but "nothing worked" is not "it is still there".
      // This is where a job that ended between the listing and the stop lands,
      // and it is the verification pass, not this catch, that tells the two
      // apart. Held, not written off.
      pending.set(unit, "vanished");
    }
    killBudgetLeft -= Date.now() - killStarted;
  }

  // The only evidence in this function. A kill only SENDS the signal — the same
  // reason stopServiceVerified re-checks `is-active` after its own SIGKILL — and
  // a stop or kill that ERRORED says nothing either way, so both classes of
  // unsettled unit are re-listed here. Absent from a fresh listing = gone,
  // whatever the exit codes said; still listed after the cgroup has had a moment
  // to empty, or a listing we could not get at all, keeps the job data.
  let remaining = [...pending.keys()];
  for (let attempt = 0; attempt < 4 && remaining.length > 0; attempt++) {
    sleepSync(250);
    const still = listJobScopeUnits();
    if (still === null) {
      // We cannot confirm. Fail closed: treat every unconfirmed unit as possibly
      // alive rather than deleting its workspace on an assumption.
      failed.push(...remaining);
      return { stopped, killed, failed, enumerationFailed: false };
    }
    for (const unit of remaining) {
      if (still.includes(unit)) continue;
      if (pending.get(unit) === "killed") killed.push(unit);
      else stopped.push(unit);
    }
    remaining = remaining.filter((u) => still.includes(u));
  }
  failed.push(...remaining);
  return { stopped, killed, failed, enumerationFailed: false };
}

export function cmdUninstall(opts: { force: boolean }): void {
  requireRoot();

  if (!opts.force) {
    ui.warn("This will fully remove the AI Commander agent.");
    ui.error("Add --force to confirm: sudo aicommander-agent uninstall --force");
    process.exit(1);
  }

  const leftBehind: string[] = [];
  // Locations we did NOT find a remnant in because we could not look at all.
  // Kept apart from leftBehind so a real failure keeps its own signal, but they
  // equally disqualify the "fully removed" claim at the end.
  const unverified: string[] = [];
  const remove = (target: string): void => {
    if (!removeIfExists(target, target)) leftBehind.push(target);
  };

  ui.step("Stopping and disabling service…");
  // ABORT rather than proceed loudly. Nothing has been deleted yet, so stopping
  // here leaves a consistent machine the operator can retry on — the binary and
  // this very command are still installed. Proceeding would be the worst of both
  // worlds: a root-privileged agent still connected to the relay, holding its
  // credentials in memory, while the files that could stop it and the record of
  // what it is are deleted around it. (A remover embedded in a package manager's
  // removal flow cannot afford this abort — the retired QNAP QPKG's pre-remove
  // hook had to proceed, because a refusal inside App Center's flow leaves a
  // package the user can never remove; this CLI has no such trap.)
  const stopped = stopServiceVerified();
  if (!stopped.ok) {
    if (stopped.state === ACTIVE_STATE_UNKNOWN) {
      // Not knowing is not the same as knowing it is down, and it gets the same
      // answer: systemd is installed here, so there may well be a unit, and we
      // could not rule out that it is STILL running.
      ui.error("Could NOT determine whether the aicommander-agent service is still running.");
      ui.error("systemd is present but `systemctl is-active` gave no usable answer.");
    } else {
      ui.error(`The aicommander-agent service is STILL running (${stopped.state}) after stop and SIGKILL.`);
    }
    ui.error("Nothing was removed — a live root-exec agent must not be left without its");
    ui.error("service file, binary and credentials.");
    ui.warn("Inspect it with: systemctl status aicommander-agent");
    ui.warn("Then (rebooting if necessary) re-run: sudo aicommander-agent uninstall --force");
    process.exit(1);
    return; // unreachable in production; keeps "nothing removed" true under a stubbed exit
  }
  // Everything above is a statement about a UNIT, and the agent need not be in
  // one: started by hand (`aicommander-agent run`), started by a NAS-style
  // cron/init wrapper on a box that also has systemd, left over from a botched install, or
  // outliving a unit that was deleted around it. In every one of those cases
  // `is-active` truthfully answers `inactive`, STOPPED_STATES accepts it, and the
  // removals below would take the binary, the session credential and the device
  // identity away from a live root-exec agent — the same harm the abort above
  // exists to prevent, reached through a TRUE negative, which no amount of
  // tightening the systemd mapping could ever catch. So ask about PROCESSES too,
  // and abort on the same terms: before the first delete, having changed nothing.
  const live = findRunningAgents();
  if (live.running.length > 0 || live.unverified.length > 0 || live.scanFailed) {
    if (live.running.length > 0) {
      ui.error(`An AI Commander agent is STILL running outside the service unit (pid ${live.running.join(", ")}).`);
    }
    if (live.unverified.length > 0) {
      // Not knowing is not knowing it is down, exactly as for ACTIVE_STATE_UNKNOWN
      // above: something is alive under a pid the agent recorded as its own, and
      // we could not read what it is.
      ui.error(`Could NOT determine what is running as the recorded agent process (pid ${live.unverified.join(", ")}).`);
    }
    if (live.scanFailed) {
      // The /proc walk is the only thing that finds an agent nobody wrote down,
      // so a walk that could not run leaves a live root-exec agent unruled-out —
      // the same unanswered question as an unverified pid, without a pid to name.
      ui.error("Could NOT scan this machine's processes (/proc was unreadable), so a running agent cannot be ruled out.");
    }
    ui.error("Nothing was removed — a live root-exec agent must not be left without its");
    ui.error("service file, binary and credentials.");
    const pids = [...live.running, ...live.unverified];
    // A remedy, because failing closed on an unanswered question is only
    // acceptable while the operator has a way through it. Every pid is a number
    // we derived ourselves, so none of this is a shell line built from input.
    // A failed scan has no pid to point at, so its remedy is only the re-run.
    if (pids.length > 0) {
      ui.warn(`Inspect it with: ps -o pid,ppid,user,lstart,args -p ${pids.join(",")}`);
      ui.warn(`Stop it with: kill ${pids.join(" ")}   (add -9 if it will not go)`);
    }
    ui.warn("Then (rebooting if necessary) re-run: sudo aicommander-agent uninstall --force");
    process.exit(1);
    return; // unreachable in production; keeps "nothing removed" true under a stubbed exit
  }
  try { systemctlDisable(); } catch { /* already disabled */ }
  ui.ok("Service stopped.");

  ui.step("Removing service file…");
  remove(SERVICE_FILE);

  ui.step("Reloading systemd…");
  try {
    daemonReload();
    ui.ok("daemon-reload complete.");
  } catch {
    ui.warn("daemon-reload failed (non-critical).");
  }

  ui.step("Removing agent binary…");
  // Remove the ctl symlink first so it doesn't dangle, then the binary itself.
  remove(CTL_SYMLINK);
  remove(BIN);
  remove(STATE_DIR);

  // The identity may live outside /etc. Resolve WHERE with the same helper the
  // stores use (device.ts, session-store.ts) so uninstall can never disagree
  // with them; an unusable value is reported and skipped rather than aborting,
  // since bailing out here would leave the /etc copy on disk.
  let overrideDir: string | undefined;
  let overrideBroken = false;
  try {
    overrideDir = envConfigDir();
  } catch (err) {
    overrideBroken = true;
    const detail = err instanceof Error ? err.message : String(err);
    ui.error(`AICOMMANDER_CONFIG_DIR is unusable, so its contents were left in place: ${detail}`);
    leftBehind.push(process.env["AICOMMANDER_CONFIG_DIR"] ?? "AICOMMANDER_CONFIG_DIR");
  }

  // Job workspaces and logs are user data (job output), so a full uninstall must
  // take them too. Before the identity purge: a jobs root sits INSIDE the config
  // dir, which can then be left empty and dropped below.
  // Only where scopes can exist. A machine with no systemd never had one, and
  // must not pay for a systemctl call — or be told about a failure — over a
  // mechanism it does not use. `stopped.state` is the answer `is-active` already
  // gave us, so this costs nothing extra.
  //
  // The result also GATES the deletion below. Deleting a live job's output.log
  // and workspace is precisely the harm the live-agent abort above exists to
  // prevent, and doing it while this teardown has just told us a root job may
  // still be running would be doing it KNOWINGLY.
  let jobDataSafeToDelete = true;
  if (stopped.state !== NO_SYSTEMD) {
    ui.step("Stopping leftover job scopes…");
    const scopes = stopJobScopes();
    if (scopes.stopped.length > 0) {
      ui.ok(`Stopped ${scopes.stopped.length} running job scope(s): ${scopes.stopped.join(", ")}`);
    }
    if (scopes.killed.length > 0) {
      // Said plainly, not buried: this ended somebody's running job.
      ui.warn(`SIGKILLed ${scopes.killed.length} job scope(s) that would not stop — those jobs were ENDED: ${scopes.killed.join(", ")}`);
    }
    for (const unit of scopes.failed) {
      ui.error(`${unit} could NOT be stopped, even with SIGKILL — a job may still be running as root.`);
      leftBehind.push(unit);
    }
    if (scopes.enumerationFailed) {
      // Same standard as the /proc scan above: we did not get to look, so we
      // cannot assert there is nothing running. It is not a leftover we FOUND,
      // hence unverified rather than leftBehind.
      ui.warn("Could NOT list AI Commander job scopes, so a still-running job cannot be ruled out.");
      unverified.push(`${JOB_SCOPE_UNIT_GLOB} units (systemctl list-units gave no usable answer)`);
    }
    if (scopes.failed.length === 0 && !scopes.enumerationFailed && scopes.stopped.length === 0 && scopes.killed.length === 0) {
      ui.ok("No job scopes were running.");
    }
    jobDataSafeToDelete = scopes.failed.length === 0 && !scopes.enumerationFailed;
  }

  ui.step("Removing job workspaces and logs…");
  const jobsRoots = new Set<string>([
    // The two branches resolveJobsRoot() cannot return for us here: the service
    // root (unreachable once the override is set, yet a pre-override service
    // filled it) and the per-user root a non-root run used — same HOME caveat as
    // FALLBACK_DIR below.
    path.join(SERVICE_DATA_DIR, "jobs"),
    path.join(os.homedir(), ".local", "share", "aicommander", "jobs"),
  ]);
  // job-manager.ts is the authority on where jobs live; hand it the directory we
  // already resolved so a broken override cannot throw here a second time.
  if (!overrideBroken) jobsRoots.add(resolveJobsRoot(overrideDir));
  if (!jobDataSafeToDelete) {
    // The teardown above either could not stop a scope or could not even list
    // them, so a root-owned job may be writing into these roots right now. Keep
    // them: a leftover directory the operator can delete in one command is a far
    // smaller harm than pulling a running job's log and workspace out from under
    // it, which is the exact failure the whole abort-before-deleting design of
    // this file exists to prevent. Recorded so the "fully removed" claim stays
    // true, with the remedy — the scopes themselves are already named above.
    //
    // Classify BEFORE saying anything. A machine that never ran a job has no
    // jobs root at all, and announcing that "workspaces and logs were KEPT",
    // naming nothing, is a false alarm about data that does not exist — it sends
    // the operator looking for a directory we never found. The failed teardown
    // is still worth reporting (a scope we could not stop is named above, and
    // the scope remedy below still applies), but only what is true gets printed.
    const kept: string[] = [];
    const foreign: string[] = [];
    for (const root of jobsRoots) {
      const verdict = classifyJobsRoot(root);
      if (verdict === "absent") continue;
      if (verdict === "foreign") {
        // The SAME classification the delete branch applies, and it has to be:
        // this is the directory that branch refuses to touch because it does not
        // look like ours. Naming it here as a kept job workspace would claim it
        // IS ours, and — worse — put it in the `rm -rf` below, handing the
        // operator a command to delete by hand exactly what we declined to
        // delete ourselves. Reported in the delete branch's own words instead,
        // and kept out of `kept`, which is what the remedy is built from.
        foreign.push(root);
        leftBehind.push(root);
        continue;
      }
      leftBehind.push(root);
      kept.push(root);
    }
    if (kept.length > 0) {
      ui.error("Job workspaces and logs were KEPT — a job may still be running as root and still writing to them.");
      for (const root of kept) ui.error(`  ${root}`);
    }
    for (const root of foreign) {
      ui.error(`  ${root} does not look like a jobs directory, so it was left in place.`);
    }
    ui.warn(
      kept.length > 0
        ? "Once nothing is running there, finish by hand with:"
        // Nothing was kept, so there is no directory to point at — but the scope
        // that would not stop (or the listing we never got) is still the
        // operator's problem, and this is the command for it.
        : "Finish the teardown by hand with:",
    );
    ui.warn(`  systemctl stop '${JOB_SCOPE_UNIT_GLOB}'`);
    // Same rule as the SUDO_USER remedy below: a path we OFFER AS A COMMAND LINE
    // must not have come from an environment string that could carry shell
    // metacharacters (AICOMMANDER_CONFIG_DIR feeds resolveJobsRoot). An excluded
    // path is still named above, just not pasted into an `rm -rf`.
    const pasteable = kept.filter((root) => /^[A-Za-z0-9._/@+-]+$/.test(root));
    if (pasteable.length > 0) ui.warn(`  rm -rf ${pasteable.join(" ")}`);
  } else {
    for (const root of jobsRoots) {
      const verdict = classifyJobsRoot(root);
      if (verdict === "absent") continue;
      if (verdict === "foreign") {
        ui.error(`${root} does not look like a jobs directory, so it was left in place.`);
        leftBehind.push(root);
        continue;
      }
      remove(root);
    }
    removeIfEmpty(SERVICE_DATA_DIR);
  }

  // Purge the identity from the active directory AND from both defaults: a
  // pre-override (or non-root) install left copies there and session-store.ts
  // still adopts them (inheritedDirs), so they stay live.
  const identityDirs = new Set<string>([DEVICE_DIR, FALLBACK_DIR]);
  if (overrideDir) identityDirs.add(overrideDir);
  for (const dir of identityDirs) {
    for (const name of IDENTITY_FILES) remove(path.join(dir, name));
    // Take the directory itself only when nothing else is in it: an override dir
    // is a path the operator chose and may hold more than our credentials.
    if (dir !== DEVICE_DIR) removeIfEmpty(dir);
  }
  // /etc/aicommander-agent is ours alone, so it goes wholesale.
  remove(DEVICE_DIR);

  // Under `sudo`, HOME is root's or the invoking user's depending on how sudo was
  // configured and invoked; we purged whichever one os.homedir() resolves to,
  // exactly as the stores would. The other one we cannot resolve without guessing
  // at a path inside someone else's home, so we report it instead of deleting it.
  const sudoUser = process.env["SUDO_USER"];
  let unverifiedRemedy: string | undefined;
  if (sudoUser && path.basename(os.homedir()) !== sudoUser) {
    ui.warn(`Checked ${FALLBACK_DIR}; ${sudoUser}'s own home was NOT checked.`);
    // "Fully removed" is a claim about fact, not about effort: we did not look
    // here, so we cannot assert this machine is clean. It is NOT a leftover
    // either — we found nothing — hence its own list rather than leftBehind.
    //
    // BOTH per-user roots, not just the identity: a non-root run of this agent
    // puts job workspaces (and every job's output.log) under ~/.local/share,
    // which is user data by the same standard as the credential — see the jobs
    // roots above, where the HOME-derived one has the identical caveat.
    unverified.push(`${sudoUser}'s ~/.config/aicommander-agent (device identity + session credential)`);
    unverified.push(`${sudoUser}'s ~/.local/share/aicommander/jobs (job workspaces and output.log files)`);
    // The remedy has to work while STAYING root: cmdUninstall opens with
    // requireRoot(), so "re-run as that user" would only ever print "must be run
    // as root". `~user/` is expanded by the operator's shell (POSIX tilde-prefix),
    // which resolves the home directory we deliberately do not resolve ourselves.
    // Only offered for a plain username: SUDO_USER reaches us as an environment
    // string, and we will not print a shell command line built from anything that
    // could carry metacharacters.
    unverifiedRemedy = /^[A-Za-z0-9._-]+$/.test(sudoUser)
      ? `sudo rm -rf ~${sudoUser}/.config/aicommander-agent ~${sudoUser}/.local/share/aicommander/jobs`
      : undefined;
  }

  ui.blank();
  if (leftBehind.length > 0) {
    ui.error(chalk.bold("AI Commander agent removed, but some paths remain:"));
    for (const target of leftBehind) ui.error(`  ${target}`);
    ui.warn("Delete them by hand — they may still hold a usable root-exec credential or job output.");
  } else if (unverified.length > 0) {
    ui.warn(chalk.bold("AI Commander agent removed from every location that could be checked."));
  }
  if (unverified.length > 0) {
    ui.warn("These could NOT be checked:");
    for (const target of unverified) ui.warn(`  ${target}`);
    if (unverifiedRemedy) {
      ui.warn("Clear them as root with:");
      ui.warn(`  ${unverifiedRemedy}`);
    }
  }
  if (leftBehind.length === 0 && unverified.length === 0) {
    ui.ok(chalk.bold("AI Commander agent fully removed."));
  }
  ui.blank();
}
