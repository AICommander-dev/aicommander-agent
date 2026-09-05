import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

/**
 * "Is an agent PROCESS running on this machine right now?" — the question
 * systemd cannot answer.
 *
 * `systemctl is-active` describes a UNIT. Every way of running this agent that
 * is not that unit — `aicommander-agent run` started by hand, a NAS-style
 * cron/init wrapper on a box that also has systemd, a process that survived a botched
 * install, a unit deleted out from under its still-running process — makes the
 * unit truthfully answer `inactive` while a root-exec agent is very much alive.
 * ctl/commands/uninstall.ts then deletes the binary, the session credential and
 * the device identity from underneath it: the exact harm its abort path exists
 * to prevent, reached through a TRUE negative rather than a false one.
 *
 * So this module asks the kernel about processes instead, and answers in three
 * parts — proved running, proved absent, and could-not-tell — because the caller
 * (a command whose next step is an irreversible delete) must be able to tell the
 * last one from the second.
 */

/** Hard cap on an identity probe, mirroring proc-identity.ts: a wedged `ps` is "we do not know". */
const PROBE_TIMEOUT_MS = 5_000;

/**
 * Where run.ts records the running agent. state.ts hardcodes this path, and
 * DELIBERATELY does not consult AICOMMANDER_CONFIG_DIR the way the identity and
 * jobs directories do — the override exists for DURABLE storage, and runtime
 * state must not be durable. The systemd unit's RuntimeDirectory=aicommander-agent
 * resolves to the same place (/var/run is /run on every systemd distro). Reading
 * the literal path state.ts writes is therefore the only correct thing to do:
 * a second opinion here could only ever disagree with the writer.
 */
const STATE_FILE = "/var/run/aicommander-agent/state.json";

/** The name both installers give the binary (ctl/commands/install.ts, web/install). */
const AGENT_BIN_NAME = "aicommander-agent";

/** The npm install's entrypoint script (package.json `bin`), for the `node <script> run` shape. */
const AGENT_SCRIPT_NAME = "agent.js";

/**
 * Runtimes the agent can be `exec`ed as. In the npm/`cmdInstall` shape the
 * process's exe is the RUNTIME, not the agent, so the runtime alone proves
 * nothing — an entrypoint token is then required as well (see identifiesAgent).
 */
const JS_RUNTIMES = new Set(["node", "node.exe", "bun", "bun.exe", "deno", "deno.exe"]);

/** What a probe could learn about a process: the binary behind it and its argv. */
interface ProcInfo {
  exe: string;
  argv: string[];
}

export interface LiveAgentScan {
  /** pids we PROVED are running this agent right now. */
  running: number[];
  /**
   * pids that are alive but whose identity we could not read. Never folded into
   * `running` — "we could not look" is not "we saw an agent" — and never dropped
   * either, so the caller can fail closed on it deliberately.
   */
  unverified: number[];
  /**
   * True when this platform HAS a process table to walk and the walk itself
   * could not run (a /proc readdir failure). The walk is the only thing that
   * finds an agent nobody wrote down — the very scenario the detector exists
   * for — so "we could not look at the table" must stay distinguishable from
   * "we looked and it was empty": the same could-not-tell channel as an
   * unverified pid, minus the pid we do not have. The caller fails closed on it
   * on the same terms. Platforms with no table to walk (macOS) report false —
   * there was nothing to fail at, and the recorded pid is their only source by
   * design.
   */
  scanFailed: boolean;
}

/**
 * Every agent process on this machine that is not US.
 *
 * Two sources, because neither alone is enough:
 *  - the pid run.ts recorded in state.json, which is the only handle we have on
 *    a platform without /proc, and which is VERIFIED rather than trusted (see
 *    classify): the file outlives its process — clearState() runs only from the
 *    SIGINT/SIGTERM handler, so a worker killed by SIGKILL or an unhandled throw
 *    leaves it behind for the rest of the boot — and a pid recorded an hour ago
 *    may belong to something else entirely by now;
 *  - on Linux, a walk of /proc, which is what finds the processes state.json
 *    knows NOTHING about: the hand-started run whose state write failed, an
 *    agent installed somewhere this command does not manage (a NAS data
 *    volume), the survivor of a previous botched install. It also makes the
 *    supervisor/worker pair (supervisor.ts) fall out for free — they share an exe
 *    and an argv — where state.json records only the worker.
 */
export function findRunningAgents(): LiveAgentScan {
  const running = new Set<number>();
  const unverified = new Set<number>();

  const recorded = readRecordedPid();
  if (recorded !== null) {
    const verdict = classify(recorded);
    if (verdict === "agent") running.add(recorded);
    else if (verdict === "unknown") unverified.add(recorded);
    // The supervisor is the worker's PARENT (supervisor.ts spawns it), and
    // state.json carries the worker's pid only — so on the platforms with no
    // /proc to walk, the parent is the only way the pair is seen as a pair. It
    // gets the same identity test as everything else, so a shell or an init that
    // happens to be the parent is not reported as an agent.
    const parent = parentPid(recorded);
    if (parent !== null && classify(parent) === "agent") running.add(parent);
  }

  const walked = scanProcFs();
  if (walked !== null) for (const pid of walked) running.add(pid);

  // Belt and braces. Both sources already skip us — classify() by pid and
  // isAgentRole() by the `uninstall` in our own argv — but this command deletes
  // things, and detecting ITSELF would make every uninstall abort forever, which
  // is a worse failure than the one being prevented.
  running.delete(process.pid);
  unverified.delete(process.pid);
  return { running: sorted(running), unverified: sorted(unverified), scanFailed: walked === null };
}

function sorted(pids: Set<number>): number[] {
  return [...pids].sort((a, b) => a - b);
}

/**
 * The pid state.json claims is running, or null when there is no usable claim.
 *
 * A missing, truncated or unparseable file is "no evidence", never an error:
 * the ordinary uninstall runs on a machine where the agent was stopped minutes
 * ago and nothing here is expected to exist. Refusing to uninstall over a
 * corrupt JSON file would be the failure mode the whole check is meant to avoid.
 *
 * pids ≤ 1 are rejected on their way in rather than at the call site: 0 means
 * "my whole process group" to process.kill and -1 means "every process I may
 * signal", so a hand-edited or zeroed record must never reach a signal-shaped
 * call, and 1 is init, which is nothing of ours.
 */
function readRecordedPid(): number | null {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    const pid = (parsed as { pid?: unknown } | null)?.pid;
    return typeof pid === "number" && Number.isInteger(pid) && pid > 1 ? pid : null;
  } catch {
    return null;
  }
}

/**
 * What is behind `pid` right now: our agent, something else (or nothing), or an
 * unanswered question.
 *
 * The liveness call is deliberately not the answer, only the gate. `kill(pid, 0)`
 * says "SOMETHING holds this number", which after a crash-and-reboot-less week
 * is a different statement from "the agent is running" — pid counters wrap, and
 * aborting an uninstall because an unrelated process inherited the number would
 * be a bad failure with no obvious remedy. So the identity question is answered
 * from the process's OWN executable and argv (see identifiesAgent), which is the
 * same evidence the QNAP install skill's agent_pids() uses (web/skill/qnap/
 * SKILL.md, Rule 3 — /proc exe symlink plus cmdline, proven the only reliable
 * discovery where BusyBox ps truncates its command column) and a
 * strictly stronger one than proc-identity.ts's start-time token: a start time
 * only tells apart two processes we already recorded something about, whereas
 * here we must also recognise an agent nobody wrote down.
 *
 * The liveness re-check after a failed probe closes the obvious race: a process
 * that exits between the gate and the probe is GONE, not unverifiable.
 *
 * A live pid the probe cannot describe gets one corroboration before it is
 * allowed to abort an uninstall: is it even a REAL userspace process? The
 * question matters because a stale state.json is routine, not rare — clearState
 * runs from the signal handler and used to race process.exit — and a recorded
 * pid recycled onto a kernel thread or left as a zombie passes `kill(pid, 0)`
 * while readProcFs fails (no exe to readlink), which used to read as
 * "unknown" and abort with a `kill <pid>` remedy that cannot work on either.
 * Neither can possibly be an agent: an agent is a live userspace process with
 * an executable. What remains "unknown" — and still aborts — is a live REAL
 * process we merely may not read (hidepid, a hardened container), because for
 * the recorded pid we have positive prior reason to believe it was an agent.
 * This is also what keeps the two Linux sources in agreement: the /proc walk
 * below already skips kernel threads and zombies as noise, and the recorded-pid
 * path must not turn the very same condition into a refusal.
 */
function classify(pid: number): "agent" | "other" | "unknown" {
  if (pid === process.pid) return "other"; // never our own uninstall
  if (!isAlive(pid)) return "other";
  const info = probeProcess(pid);
  if (info === null) {
    if (!isAlive(pid)) return "other";
    if (isKernelThreadOrZombie(pid)) return "other";
    return "unknown";
  }
  return isAgentProcess(info) ? "agent" : "other";
}

/** The kernel's PF_KTHREAD flag in /proc/<pid>/stat field 9. */
const PF_KTHREAD = 0x00200000;

/**
 * Is `pid` provably not a userspace process at all — a kernel thread or a
 * zombie? Linux-only, from the process's own /proc stat line: the state field
 * ('Z' zombie, 'X'/'x' dead) and the PF_KTHREAD flag are the kernel's word, not
 * text the process chose. Anything unreadable or unparseable is false — "we
 * still do not know" — so this can only ever DOWNGRADE an abort into a proceed
 * on positive evidence, never invent certainty from a read failure.
 */
function isKernelThreadOrZombie(pid: number): boolean {
  if (process.platform !== "linux") return false;
  try {
    const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    // Counted from the last ')' for the same reason as proc-identity.ts: comm
    // may itself contain spaces and parentheses.
    const fields = raw.slice(raw.lastIndexOf(")") + 1).trim().split(/\s+/);
    const state = fields[0];
    if (state === "Z" || state === "X" || state === "x") return true;
    const flags = Number(fields[6]);
    return Number.isFinite(flags) && (flags & PF_KTHREAD) !== 0;
  } catch {
    return false;
  }
}

/**
 * EPERM means a process we may not signal is alive under that number, which is
 * still alive; only ESRCH ("no such process") proves absence.
 */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Does this process run our program, in the role that serves the relay? */
function isAgentProcess(info: ProcInfo): boolean {
  return identifiesAgent(info) && isAgentRole(info.argv);
}

/**
 * Is the BINARY behind this process our agent?
 *
 * Two install shapes have to be recognised, and only these two:
 *  - the signed standalone binary (web/install): the exe IS the
 *    agent, so its name decides. Matched on the name rather than a fixed path
 *    because an install can keep its copy anywhere — a NAS data volume, say —
 *    and this command must still not delete files from under a live process it
 *    does not manage.
 *  - the npm install (ctl/commands/install.ts writes `<node> <script> run`): the
 *    exe is the RUNTIME, so it proves nothing on its own and an agent ENTRYPOINT
 *    in the argv is required as well. Without that second condition every node
 *    process on the machine would look like an agent.
 *
 * The argv is only ever read as corroboration, never as the anchor: argv is text
 * any process may write, so `vim /usr/local/bin/aicommander-agent` must not be
 * able to block an uninstall.
 */
function identifiesAgent(info: ProcInfo): boolean {
  const exe = path.basename(stripDeletedSuffix(info.exe));
  if (exe === AGENT_BIN_NAME) return true;
  return JS_RUNTIMES.has(exe) && info.argv.some(isEntrypointToken);
}

/**
 * An upgrade in flight leaves the replaced inode running as "<path> (deleted)" —
 * still an agent, and the one most likely to be forgotten.
 */
function stripDeletedSuffix(exe: string): string {
  return exe.endsWith(" (deleted)") ? exe.slice(0, -" (deleted)".length) : exe;
}

/** A token that names the program itself rather than one of its arguments. */
function isEntrypointToken(token: string): boolean {
  const name = path.basename(token);
  // The running CLI's own entrypoint is included because uninstall is the SAME
  // installation as the agent it is looking for: whatever this process was
  // started from, the service was started from it too. It also covers the
  // compiled binary's re-exec, which inserts its embedded "/$bunfs/…" entry
  // before the arguments.
  const self = process.argv[1];
  return (
    name === AGENT_BIN_NAME ||
    name === AGENT_SCRIPT_NAME ||
    (self !== undefined && name === path.basename(self))
  );
}

/**
 * Is this argv the agent, as opposed to one of the CLI subcommands that share
 * the very same binary?
 *
 * Decided the way commander decides it (bin/agent.ts), so it cannot drift as
 * subcommands are added: the first non-flag argument that is not the program
 * itself is the subcommand, and `run` is also the DEFAULT — `sudo
 * aicommander-agent` with no arguments is a running agent, which is exactly how
 * the operator is told to start one by hand. That is the one place this test has
 * to be more permissive than the QNAP skill's agent_pids(), which may require a
 * literal `run` because it always passes one itself.
 *
 * This is also what excludes THIS process without relying on the pid: an
 * uninstall carries `uninstall` in its argv, a `status` carries `status`, and
 * the secure-exec privilege dropper (secure-exec-drop.ts) re-execs this same
 * binary with its `__secure-exec-drop` sentinel — a sandboxed user command that
 * must never be mistaken for the service.
 *
 * A bare `aicommander-agent --version` is classified as an agent here. It is a
 * process that lives for milliseconds, and the direction of the error is the
 * safe one: a spurious abort deletes nothing and says which pid it saw.
 */
function isAgentRole(argv: string[]): boolean {
  // argv[0] is the program; a subcommand can only be at a later position.
  for (const token of argv.slice(1)) {
    if (token.startsWith("-")) continue;
    if (isEntrypointToken(token)) continue;
    return token === "run";
  }
  return true;
}

/** Ask the platform what is behind a pid. Null means "we could not find out". */
function probeProcess(pid: number): ProcInfo | null {
  if (process.platform === "linux") return readProcFs(pid);
  if (process.platform === "darwin") return readBsdPs(pid);
  return null;
}

/**
 * Linux: the kernel's own answers. /proc/<pid>/exe is a symlink to the binary
 * being executed — not a string the process chose — and cmdline is NUL-separated
 * argv. Reading them costs two syscalls and no fork, which is what makes the
 * whole-/proc walk below affordable.
 */
function readProcFs(pid: number): ProcInfo | null {
  try {
    const exe = fs.readlinkSync(`/proc/${pid}/exe`);
    const raw = fs.readFileSync(`/proc/${pid}/cmdline`, "utf8");
    return { exe, argv: raw.split("\0").filter((token) => token !== "") };
  } catch {
    return null;
  }
}

/**
 * macOS has no /proc, so `ps` is the only answer available — and this platform
 * matters MORE than Linux here, not less: with no systemd there is no unit at
 * all, so every macOS agent is by definition one this check is the only guard
 * for. `comm` is the executable path and `args` the argv, read in two calls
 * because one line carrying both cannot be split unambiguously.
 */
function readBsdPs(pid: number): ProcInfo | null {
  const exe = runPs(["-o", "comm=", "-p", String(pid)]);
  const args = runPs(["-o", "args=", "-p", String(pid)]);
  if (exe === null || args === null) return null;
  const trimmed = exe.trim();
  if (trimmed === "") return null;
  return { exe: trimmed, argv: args.trim().split(/\s+/).filter((token) => token !== "") };
}

/** The parent of `pid`, or null when this platform cannot cheaply say. */
function parentPid(pid: number): number | null {
  // Linux needs no special case: the /proc walk sees the supervisor in its own
  // right, so asking for a parent here would only duplicate it.
  if (process.platform !== "darwin") return null;
  const out = runPs(["-o", "ppid=", "-p", String(pid)]);
  const parsed = Number(out?.trim());
  return Number.isInteger(parsed) && parsed > 1 ? parsed : null;
}

function runPs(args: string[]): string | null {
  try {
    return execFileSync("/bin/ps", args, {
      encoding: "utf8",
      timeout: PROBE_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    // A `ps` that could not run, or a pid that vanished before it did.
    return null;
  }
}

/**
 * Every agent process on a Linux box, found the way the QNAP install skill's
 * agent_pids() finds them (web/skill/qnap/SKILL.md, Rule 3): one readlink and
 * one small read per pid, compared against the kernel's answers.
 *
 * This IS a full walk of the process table, and it is deliberate. The targeted
 * check above can only see a process something wrote down, and the entire defect
 * is processes nobody wrote down — a hand-started run whose state write failed,
 * an agent living on a NAS data volume, a survivor of a previous install. The
 * cost is bounded by the number
 * of live processes (a few hundred readlinks, single-digit milliseconds, no
 * forks) and it is paid ONCE, by an interactive command whose next step is
 * deleting a root credential. Nothing here runs on a hot path.
 *
 * A pid we cannot read is skipped rather than reported as unverified: /proc is
 * full of kernel threads with no exe at all, and a pid that vanishes mid-walk is
 * the normal case. Only the RECORDED pid — the one we have positive reason to
 * believe was an agent — can make the caller fail closed.
 *
 * The walk NOT RUNNING is a different statement entirely, and gets the null
 * return: a /proc we could not enumerate has told us nothing about the machine,
 * and folding that into "found nothing" would wave through the uninstall in
 * exactly the cases this walk is the only guard for — the hand-started agent,
 * the NAS survivor — with a root credential deleted from under a live process.
 * The caller turns null into scanFailed, the same fail-closed channel as an
 * unverified pid.
 */
function scanProcFs(): number[] | null {
  if (process.platform !== "linux") return [];
  let entries: string[];
  try {
    entries = fs.readdirSync("/proc");
  } catch {
    return null;
  }
  const found: number[] = [];
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === process.pid) continue;
    const info = readProcFs(pid);
    if (info !== null && isAgentProcess(info)) found.push(pid);
  }
  return found;
}
