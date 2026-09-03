import { execFileSync } from "node:child_process";
import { isJobScopeUnitName, JOB_SCOPE_UNIT_GLOB } from "../job-scope.js";

const SERVICE = "aicommander-agent";

function run(args: string[]): void {
  execFileSync("systemctl", args, { stdio: "inherit" });
}

/**
 * There is no systemd on this machine (macOS, a plain container, QTS), so there
 * is no unit and nothing to stop. Distinct from ACTIVE_STATE_UNKNOWN: this is a
 * definite answer, not a failed query.
 */
export const NO_SYSTEMD = "no-systemd";

/**
 * systemd is installed but `is-active` produced nothing we may act on — the bus
 * was unreachable, the output was empty, or it was a word we do not know. Never
 * a state systemd itself prints, so callers can test for it unambiguously.
 */
export const ACTIVE_STATE_UNKNOWN = "query-failed";

/**
 * Whether a live systemd manager is reachable on this Linux host. The presence
 * of the `systemctl` binary is not enough: minimal containers and non-systemd
 * distributions often ship it even though PID 1 is another init and there is no
 * manager bus to reload. A manager-level property query succeeds only when
 * systemctl can actually talk to systemd; an empty answer is not evidence of a
 * usable manager. Never throws so install can fail before making any changes.
 */
export function systemdManagerAvailable(): boolean {
  try {
    const out = execFileSync(
      "systemctl",
      ["show", "--property=Version", "--value"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Every word `systemctl is-active` prints (systemd's unit active-state names).
 * `unknown` is the one older systemd emits for a unit that is not loaded at all;
 * newer versions print `inactive` for that case — both mean "not running".
 */
const IS_ACTIVE_WORDS = new Set([
  "active",
  "reloading",
  "inactive",
  "failed",
  "activating",
  "deactivating",
  "maintenance",
  "unknown",
]);

/**
 * The errno names that PROVE there is no `systemctl` to run, i.e. no systemd and
 * therefore no unit. ENOENT is the binary not existing (or, for a bare name, no
 * PATH entry holding it) — macOS, a plain container, QTS. ENOTDIR is a
 * non-directory somewhere in the path prefix, so no file can exist there either.
 *
 * Deliberately NOT here: EACCES. It means the binary EXISTS and we could not
 * execute it — a noexec mount, a PATH directory we may not traverse, a hardened
 * container — and systemd may be running the agent at that very moment. The same
 * goes for EPERM, ENOEXEC and resource exhaustion (EMFILE/ENFILE/ENOMEM/EAGAIN):
 * none of them is evidence of ABSENCE, only evidence that we never got to ask.
 * Everything outside this set is reported as ACTIVE_STATE_UNKNOWN so that
 * ctl/commands/uninstall.ts aborts rather than deleting a live root agent's
 * unit file, binary and credentials out from under it.
 */
const NO_SUCH_BINARY_ERRNOS = new Set(["ENOENT", "ENOTDIR"]);

/**
 * The unit's active state, or one of the two sentinels above. Never throws, so
 * cmdStatus can render it on a machine without systemd.
 *
 * The exit code deliberately decides nothing: `is-active` exits non-zero for the
 * perfectly ordinary `inactive` and `failed` answers, printing the state word on
 * stdout either way. Only the word decides — and its absence is reported as such
 * rather than being folded into "inactive", because callers that delete a live
 * root agent's files on the strength of this answer (ctl/commands/uninstall.ts)
 * must be able to tell "it is stopped" from "we could not find out".
 */
export function systemctlActiveState(): string {
  let out: unknown;
  try {
    out = execFileSync("systemctl", ["is-active", SERVICE], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch (err) {
    // Two different failures land here, and Node distinguishes them by `err.code`:
    // a STRING errno means the spawn never got off the ground (`status` is null,
    // `stdout` undefined), whereas a command that RAN and exited non-zero carries
    // no `code` at all — just `status` and the state word on `stdout`. So only a
    // string `code` may be read as a statement about the binary; anything else
    // ran, and its stdout is read back below instead of being discarded.
    const code = (err as NodeJS.ErrnoException).code;
    if (typeof code === "string") {
      return NO_SUCH_BINARY_ERRNOS.has(code) ? NO_SYSTEMD : ACTIVE_STATE_UNKNOWN;
    }
    out = (err as { stdout?: unknown }).stdout;
  }
  const state =
    typeof out === "string" ? out.trim()
    : Buffer.isBuffer(out) ? out.toString("utf8").trim()
    : "";
  return IS_ACTIVE_WORDS.has(state) ? state : ACTIVE_STATE_UNKNOWN;
}

export function systemctlIsEnabled(): boolean {
  try {
    const out = execFileSync("systemctl", ["is-enabled", SERVICE], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out === "enabled";
  } catch {
    return false;
  }
}

/**
 * How long ONE systemctl call about a job scope may take before we stop waiting
 * on it. Both bounds exist because uninstall reaches these calls with the
 * service file, the ctl symlink, the binary and the state dir ALREADY deleted:
 * an unbounded wait there is a root CLI sitting mute in the middle of a
 * half-finished uninstall, with nothing on screen to say what it is waiting for.
 *
 * The number that forces the issue is systemd's DefaultTimeoutStopSec — 90 s on
 * a stock Ubuntu 24.04 / systemd 255. `systemctl stop` on a scope whose job
 * ignores SIGTERM blocks for the whole of it, PER UNIT, so a handful of stuck
 * jobs is minutes of silence. Against that, a scope whose job is cooperative
 * collapses in well under a second (measured: the unit is collected the instant
 * the process tree exits), so 15 s is many times the honest case and a sixth of
 * the pathological one — long enough that we never SIGKILL a job that was merely
 * slow to finish flushing, short enough that the operator gets an answer.
 *
 * Listing is a plain bus query that normally answers in milliseconds; 10 s is
 * there only for a wedged or heavily loaded manager. And SIGKILL delivery does
 * not wait for anything (measured at 0.01 s), so 5 s covers only the round trip.
 *
 * NOTE what a timeout does and does not do: it kills the systemctl CLIENT, not
 * the stop job systemd has already queued — the unit keeps going down on its own
 * schedule. So a timed-out stop is not a stopped unit, and callers must treat it
 * as a failure (ctl/commands/uninstall.ts does, and escalates).
 */
export const SCOPE_STOP_TIMEOUT_MS = 15_000;
export const SCOPE_LIST_TIMEOUT_MS = 10_000;
export const SCOPE_KILL_TIMEOUT_MS = 5_000;

/**
 * The transient job scopes still on this machine (job-scope.ts), or null when we
 * could not find out.
 *
 * The distinction matters to the caller and is why this does not simply return
 * `[]` on failure: an uninstall that cannot enumerate the scopes is about to
 * delete the workspaces and output.log files of jobs it cannot see, and must say
 * so rather than claim the machine is clean. A machine with no systemd has no
 * scopes and never asks — cmdUninstall gates on that before calling.
 *
 * There is no stale-unit duty here: a scope disappears the instant its process
 * tree ends, so this listing only ever contains LIVE jobs (measured on Ubuntu
 * 24.04 / systemd 255, along with the fact that `systemctl stop <unit>` on a job
 * scope kills the whole tree and leaves the unit collected).
 *
 * The glob goes to `list-units`, which expands it itself; nothing built from
 * that output is ever passed back to systemctl without isJobScopeUnitName
 * agreeing it is one of ours. `--plain` gives bare unit names one per line;
 * without it every line is indented and carries the LOAD/ACTIVE/SUB/DESCRIPTION
 * columns, with the unit name still first — so the parse below survives a
 * systemd that ignores the flag, which is why it is written that way rather than
 * trusting the flag to have worked.
 */
export function listJobScopeUnits(): string[] | null {
  let out: string;
  try {
    out = execFileSync(
      "systemctl",
      ["list-units", "--type=scope", "--all", "--no-legend", "--plain", JOB_SCOPE_UNIT_GLOB],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: SCOPE_LIST_TIMEOUT_MS },
    );
  } catch {
    // Includes the perfectly ordinary "no such binary" — but the caller only
    // reaches this on a machine where systemd answered, so a failure here is a
    // question we could not get answered, not an answer. A listing that hit
    // SCOPE_LIST_TIMEOUT_MS lands here too, and is the same non-answer: we have
    // no idea what is running, and must not pretend the machine is clean.
    return null;
  }
  const units: string[] = [];
  for (const line of out.split("\n")) {
    // `--plain` drops the leading bullet, but a systemd that ignores it would
    // put one in the first column; the trim + filter below survives both, and
    // isJobScopeUnitName is what makes the result safe to act on either way.
    const first = line.trim().replace(/^[^\w]+\s+/, "").split(/\s+/)[0];
    if (first && isJobScopeUnitName(first) && !units.includes(first)) units.push(first);
  }
  return units;
}

/**
 * Stop one unit BY NAME, gracefully (SIGTERM, then systemd's own escalation).
 * Separate from systemctlStop (which owns the service and takes no argument)
 * precisely so that no caller can hand a glob to a `stop`: the enumeration above
 * expands the pattern, this stops exactly what it found. Throws, so the caller
 * can account for a scope that would not go — INCLUDING one that merely ran past
 * SCOPE_STOP_TIMEOUT_MS, which is not a stopped unit either (see the constant).
 */
export function systemctlStopUnit(unit: string): void {
  if (!isJobScopeUnitName(unit)) throw new Error(`refusing to stop ${unit}: not an AI Commander job scope`);
  execFileSync("systemctl", ["stop", unit], {
    stdio: ["ignore", "ignore", "ignore"],
    timeout: SCOPE_STOP_TIMEOUT_MS,
  });
}

/**
 * SIGKILL everything in one job scope's cgroup. The last resort of the uninstall
 * path, for a scope that would not stop within SCOPE_STOP_TIMEOUT_MS.
 *
 * `--kill-who=all` and not the default `main`: a scope's "main" process is the
 * job's `/bin/sh`, and killing only that would leave the real work — the trainer,
 * the compiler — running in a cgroup whose workspace and output.log the uninstall
 * is about to delete. The whole cgroup is what has to go.
 *
 * Guarded by the same isJobScopeUnitName check as the stop, for the same reason:
 * this is a root `systemctl kill` and the name it aims at came out of parsed text
 * output. And like the stop it throws — but note that a kill SUCCEEDING only
 * means the signal was sent; the caller (ctl/commands/uninstall.ts) re-lists the
 * scopes afterwards rather than believing it.
 */
export function systemctlKillUnit(unit: string): void {
  if (!isJobScopeUnitName(unit)) throw new Error(`refusing to kill ${unit}: not an AI Commander job scope`);
  execFileSync("systemctl", ["kill", "--kill-who=all", "--signal=SIGKILL", unit], {
    stdio: ["ignore", "ignore", "ignore"],
    timeout: SCOPE_KILL_TIMEOUT_MS,
  });
}

export function systemctlStart(): void   { run(["start",   SERVICE]); }
export function systemctlStop(): void    { run(["stop",    SERVICE]); }
export function systemctlEnable(): void  { run(["enable",  SERVICE]); }
export function systemctlDisable(): void { run(["disable", SERVICE]); }
export function systemctlRestart(): void { run(["restart", SERVICE]); }
export function daemonReload(): void     { run(["daemon-reload"]);    }

// Force-kill a hung unit (mirrors web/install's `systemctl kill --signal=SIGKILL`).
// Used in the restart-failure fallback to guarantee the old process is gone
// before a fresh start.
export function systemctlKill(): void    { run(["kill", "--signal=SIGKILL", SERVICE]); }
