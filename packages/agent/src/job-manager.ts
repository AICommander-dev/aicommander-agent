import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  gpuLockFileName,
  isGpuLockFileName,
  JOB_ID_PATTERN,
  JOB_LIST_DEFAULT_ENTRIES,
  JOB_LOGS_DEFAULT_TAIL_LINES,
  JOB_LOGS_MAX_SLICE_BYTES,
  JOB_MAX_CONCURRENT,
  JOB_MAX_GPU_INDEX,
  JOB_MAX_LOG_BYTES,
  JOB_RETENTION_MS,
  JOB_WIRE_MAX_COMMAND_CHARS,
  JOB_WIRE_MAX_LIST_ENTRIES,
  JOB_WIRE_MAX_NAME_CHARS,
  KILL_ESCALATION_MS,
  MAX_EPOCH_MS,
} from "@aicommander/protocol";
import type { GpuDevice, JobRefusal, JobRpcResult, JobStatus, JobSummary } from "@aicommander/protocol";
import { atomicWriteUtf8, ensurePrivateDir, PRIVATE_FILE_MODE } from "./atomic-file.js";
import { envConfigDir } from "./config-dir.js";
import { decideGpuIndex, type KnownGpus } from "./job-gpu-index.js";
import {
  applyLoginShellLocale,
  applyLoginShellPath,
  applyNonInteractiveTerm,
  pendingLoginShellPath,
} from "./login-shell-path.js";
import {
  buildJobScopeArgv,
  jobScopeDescription,
  jobScopeLauncher,
  jobScopeUnitName,
  killJobScope,
  reapLeftoverJobScope,
  pendingJobScope,
  type JobScopeLauncher,
} from "./job-scope.js";
import { compareProcIdentity, readProcIdentity } from "./proc-identity.js";

/**
 * Detached jobs — long-running commands whose state lives on THIS machine's disk.
 *
 * The point of the whole mechanism is that a job outlives everything around it:
 * the request that started it, the relay connection, the agent process, and a
 * reboot of the caller's machine. Its stdout/stderr go straight to a file — the
 * wrapper's own redirect, plus an inherited fd on POSIX — and never through the
 * agent, so nothing is lost while the agent is down and nothing is capped at
 * MAX_OUTPUT_TOTAL_BYTES on the way. That is what
 * makes a 6-hour, chatty training run possible where `do:exec` kills it.
 *
 * Two invariants run through every method below:
 *  - DISK IS THE TRUTH. No status is cached in memory; every one we report is
 *    recomputed from `exit` / pid liveness at the moment it is asked for, so an
 *    agent restart changes nothing about what we say. There are exactly two
 *    in-memory notes, both of which only ever make us claim LESS: settledJobs
 *    records that a job has already REACHED a terminal state (a fact that cannot
 *    change, and one no caller is ever answered from), and retiringJobs records
 *    that a process this process started is still being stopped — until it is
 *    gone, no disk state could describe it honestly. The second one is only the
 *    fast half of a fact that is also WRITTEN DOWN (`retiring` in meta.json), so
 *    that a restart mid-stop does not lose it; nothing here survives only in RAM.
 *  - A JOB ENDS ONLY ON EVIDENCE. An `exit` file, or a pid that is provably not
 *    alive, ends a job. "Something is alive under that pid but we cannot prove it
 *    is ours" is not evidence of an ending — it is an unanswered question — and
 *    it therefore keeps the job running, holding its GPU lock and its concurrency
 *    slot, until the question is answered. See refresh().
 *  - RELAY INPUT IS UNTRUSTED. `jobId` is validated against a 16-hex pattern
 *    before it can reach a path join, and a value that fails is `not_found` — the
 *    same answer as a jobId that simply does not exist, so probing learns nothing.
 *    No uid, privilege, or path outside the jobs root is ever derived from a
 *    message: a job runs as the agent's own user, exactly like `do:exec`.
 */

// ── On-disk layout ───────────────────────────────────────────────────────────
// <jobsRoot>/<jobId>/meta.json   — JobMeta, atomically replaced (atomic-file.ts)
// <jobsRoot>/<jobId>/output.log  — stdout+stderr interleaved, as a terminal sees it
// <jobsRoot>/<jobId>/exit        — the exit code as text, written by the wrapper
// <jobsRoot>/<jobId>/wrapper.cmd — Windows only: the wrapper itself (see spawnJob)
// <jobsRoot>/<jobId>/command.cmd — Windows only: the command's own line (see spawnJob)
// <jobsRoot>/<jobId>/workspace/  — default cwd, so each job starts somewhere clean
// <jobsRoot>/gpu-<index>.lock    — exclusive GPU reservation, holder's jobId inside
// <jobsRoot>/home/               — fallback HOME for root-run jobs (see resolveJobHome)
const META_FILE = "meta.json";
const LOG_FILE = "output.log";
const EXIT_FILE = "exit";
const WORKSPACE_DIR = "workspace";
const SHARED_HOME_DIR = "home";
/** Windows only: the wrapper the detached launcher runs. See WINDOWS_JOB_WRAPPER. */
const WRAPPER_FILE = "wrapper.cmd";
/** Windows only: the batch the wrapper runs, holding the command's own line. */
const COMMAND_FILE = "command.cmd";

/**
 * Ceiling on the command string we accept. A command is user payload we store on
 * disk and hand to a shell; nothing legitimate is anywhere near this, and it
 * bounds both `meta.json` and the wrapper's argv.
 */
const MAX_COMMAND_BYTES = 65_536;

/**
 * Longest job name we keep; longer is truncated rather than rejected.
 *
 * Deliberately LOCAL and unshared: this is job_start INPUT policy, a judgement about
 * how long a name a caller may usefully give a job, not a wire bound. The wire
 * ceiling is JOB_WIRE_MAX_NAME_CHARS in the protocol package, and it is looser on
 * purpose (see the wire normalisers below).
 */
const MAX_JOB_NAME_LENGTH = 64;

/**
 * How often the retention prune may run while the agent is up.
 *
 * The target machines are a 24/7 GPU box and a NAS that stays up for months, so
 * pruning only in `recover()` (once per process) reclaims nothing on exactly the
 * deployments the feature exists for. We deliberately do NOT add a timer: the
 * agent already unref()s several, and a timer would wake a mostly idle process
 * for housekeeping nobody asked for. Instead the sweep is amortised onto the
 * RPCs that are cheap enough to carry it (start/list — see maybePrune), so its
 * cost is one directory scan per hour of ACTIVITY rather than per call.
 */
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Where the wrapper writes the exit code. Passed in the ENVIRONMENT rather than
 * quoted into the script so the path never has to survive two rounds of shell
 * quoting (a jobs root can legitimately contain a quote or a space), and set
 * AFTER the caller's env in buildEnv so a relay message can never redirect where
 * a root job writes.
 */
export const JOB_EXIT_PATH_ENV = "AIC_JOB_EXIT";

/**
 * Where the wrapper redirects the job's own stdout/stderr.
 *
 * The wrapper redirects INSIDE the shell rather than relying only on the log fd
 * handed to spawn(). On POSIX both are used and both work: `exec >>` cannot be
 * lost, and the fd additionally covers whatever the shell writes before the
 * redirect takes effect.
 *
 * On Windows the two are mutually exclusive, and the redirect needs a shell that
 * is not the detached process itself. Measured on 10.0.26200 / Node 24.18, one
 * spawn per row, `cmd /d /s /c "echo X" >> log` unless noted:
 *
 *   attached, parent opens the log + passes it as stdio -> "…used by another process"
 *   attached, parent opens the log, stdio "ignore"      -> "" (redirect failed, silently)
 *   attached, parent never opens the log                -> "X"
 *   DETACHED, parent never opens the log                -> ""
 *   DETACHED, `echo AFTER >> log` in the wrapper itself -> "AFTER" lands
 *   DETACHED, fd passed, no redirect at all             -> "" (and node/ping children too)
 *   DETACHED, wrapper.cmd run BY the detached shell     -> "" for a child process
 *   DETACHED, wrapper.cmd run one level down            -> the child's output lands
 *
 * Two independent facts. First, a handle of OURS held across the spawn is enough
 * to make `cmd`'s redirect fail — passing it as stdio is not required — and the
 * log then holds the sharing violation instead of the job's output, exit code
 * and all; so spawnJob does not keep the fd open on Windows. Second, a
 * DETACHED_PROCESS shell has no console, and such a shell hands neither a
 * redirected stdout nor an inherited fd to the processes it STARTS — its own
 * builtins still write, which is why the failure looks like an empty log rather
 * than an error, and why a probe that only echoed looked fine. Detaching is not
 * optional (libuv puts every non-detached child in a KILL_ON_JOB_CLOSE job
 * object, i.e. the job would die with the agent — measured: the child was gone
 * the moment its parent exited). So the detached shell only LAUNCHES the wrapper
 * (WINDOWS_JOB_WRAPPER), and the wrapper — a child, with a console — is what
 * redirects.
 *
 * Travels in the environment for the same reasons JOB_EXIT_PATH_ENV does, and on
 * Windows for one more: a value substituted from the environment is not rescanned
 * by the shell that substituted it, so a jobs root containing a literal `%…%`
 * pair survives. Nothing of ours is on a command line there — see spawnJob.
 */
export const JOB_LOG_PATH_ENV = "AIC_JOB_LOG";

/**
 * The job's command and working directory, for the Windows wrapper only.
 *
 * The wrapper is a FILE, so the only thing it can be told at spawn time is its
 * environment — and that is the point: `%VAR%` is substituted once, by the shell
 * that reaches the line, and cmd does not rescan what a variable expanded to. So
 * a jobs root or working directory holding a literal `%…%` pair cannot be
 * re-expanded on the way, and the command's own percent references get exactly
 * ONE expansion round: the one `call` re-parses the line for.
 *
 * One round is FEWER than the command line this replaced, which expanded twice
 * — the launcher's own `/c` parse and then the inner `cmd` — and that is a
 * deliberate, user-visible change, not an accident: a command whose percent
 * escaping was tuned to the old two-round chain (`%%VAR%%` reaching the program
 * as `%VAR%`) now means something else. One round is the behaviour that can
 * actually be explained to a caller, and it is pinned by an executing test.
 *
 * One round means ONE, and it is the batch parser's own: the command is a line
 * of the command file, so reaching it expands the whole line once, before any
 * pipeline child exists. That leaves exactly one caller-visible difference from
 * a POSIX job:
 *
 *  - a literal percent needs `%%`, the ordinary batch rule — where `$` needs no
 *    doubling on the POSIX side.
 *
 * Two behaviours that USED to be documented here as accepted warts are gone, and
 * both were consequences of reaching the command with `call`, whose re-parse ran
 * batch's escaping over the command's text a second time:
 *
 *  - a caret is no longer doubled. `"a^b"` reached the program as `a^^b` under
 *    `call`, and the note here said it could not be removed "without giving up
 *    the expansion round the `env` parameter depends on". That premise was
 *    wrong — writing the command into the file keeps the round and drops the
 *    doubling, because there is one parse rather than a parse plus a re-parse.
 *    Measured on the real box; pinned by an executing Windows test;
 *  - a pipeline no longer expands a second time. `cmd` still starts a fresh
 *    `cmd /S /D /c` per pipeline side, but by then the line has already been
 *    expanded once and there is nothing left for that child's percent phase to
 *    find. The old test for this pinned the opposite and said in as many words
 *    that its disappearance should prompt this correction; this is it.
 *
 * Three more caller-visible properties of running a command through cmd:
 *
 *  - a pipeline reports the RIGHT-hand stage's exit code, exactly as `sh` does
 *    without `pipefail`; a failing left stage feeding a succeeding `findstr` is
 *    a job that exited 0;
 *  - a `.bat`/`.cmd` invoked without `call` TRANSFERS control instead of
 *    returning, so in a chain (`prep.py && activate.bat && train.py`) the tail
 *    after it never runs — a property of batch, not something this wrapper can
 *    fix from outside. It costs nothing when the batch is the whole command:
 *    that is the last line anyway, and the nested cmd exits with that batch's
 *    ERRORLEVEL, which is the same answer;
 *  - MAX_COMMAND_BYTES is 65536, but cmd's own command-line ceiling is 8191
 *    characters, so a very large Windows command can fail inside cmd rather than
 *    at our validation.
 *
 * On Windows only, start() refuses a command containing `\r` or `\n`: the batch
 * parser would read the tail of such a command as further LINES of our script,
 * which is a different program from the one the caller wrote. POSIX keeps
 * accepting multi-line commands — buildJobScript embeds the command in a script
 * where a newline is an ordinary statement separator — so this asymmetry is
 * deliberate and lives here where a caller writing a command will meet it.
 *
 * NOTE: the command no longer travels in this variable — it is written into the
 * job's command file, which is what gives it the single whole-line expansion
 * round described above (see buildWindowsJobCommandScript). The name is kept as
 * the anchor these caller-facing rules are referenced by, and so a test can
 * assert the command is not passed through the environment any more. JOB_CWD_ENV
 * IS still set, AFTER the caller's env in buildEnv, like every other decision of
 * ours: a relay message must not be able to say where a root job runs.
 */
export const JOB_COMMAND_ENV = "AIC_JOB_COMMAND";
export const JOB_CWD_ENV = "AIC_JOB_CWD";

/**
 * The Windows wrapper, written into the job's own directory and run by the
 * launcher spawnJob starts. The POSIX counterpart is buildJobScript.
 *
 * It is a FILE and not a command line, and it is the SAME text for every job:
 * everything that varies travels in the environment. Nothing job-specific and
 * no path of ours is on any command line here, so a jobs root or working
 * directory containing a literal `%…%` pair cannot be re-expanded into
 * something else, and nothing needs caret-escaping.
 *
 * The wrapper only sets the redirect up and records the outcome; the command
 * itself lives one file down, in WINDOWS_JOB_COMMAND_SCRIPT, and that split is
 * load-bearing — see there. The redirect binds to the nested `cmd`, which is
 * also what makes `exit` and `exit /b` in the command's own text end THAT shell
 * rather than this one, so the `echo %ERRORLEVEL%` line always runs. A batch
 * line is expanded when it is REACHED, not when the file is read, so that
 * `%ERRORLEVEL%` needs no `call`: it is the value the nested shell just exited
 * with, which — because the command script ends ON the command, and falling off
 * the end of a batch carries the last errorlevel out of `cmd /c` — is the
 * command's own.
 *
 * `.\command.cmd` resolves because the launcher's cwd is the JOB directory; the
 * `cd` into the job's real working directory happens down there, after the
 * redirect is already in place, so a cwd that has gone missing between start()'s
 * check and here can say so IN THE LOG.
 */
export const WINDOWS_JOB_WRAPPER =
  "@echo off\r\n" +
  `cmd /d /s /c .\\${COMMAND_FILE} >> "%${JOB_LOG_PATH_ENV}%" 2>&1\r\n` +
  `echo %ERRORLEVEL% > "%${JOB_EXIT_PATH_ENV}%"\r\n`;

/**
 * The command's own line, in a file of its own — the second half of the Windows
 * wrapper, run by the nested `cmd` in WINDOWS_JOB_WRAPPER. Same text for every
 * job, for the same reasons.
 *
 * It is a separate FILE because the command must be alone on its line, and a
 * line that also carries our redirect cannot give it that. Measured on the real
 * box (agent 1.0.40, Windows 10.0.26200): a command whose own quotes wrap a `|`
 * or `&` — `python.exe -c "print('a', '| b')"` — died as
 * `'b')""' is not recognized as an internal or external command`, while the same
 * text through `do:exec` ran fine. The doubled quote in that message is the whole
 * story: the line the batch parser saw was
 *
 *   cmd /d /s /c "python.exe -c "print('a', '| b')"" >> "…\output.log" 2>&1
 *
 * and cmd scans a line for operators BEFORE it starts anything, tracking quote
 * state as it goes. Our opening quote turns quoting ON, the command's own first
 * quote turns it back OFF, and the `|` after it is therefore read as a PIPE — the
 * line is split, and the right-hand half (`b')"" >> …`) is looked up as a program.
 * `/s` cannot save it: `/s` is a rule about how the cmd being STARTED treats its
 * own `/c` string, and that cmd is never started — the parent split the line
 * first. Any fix that keeps the command inside our quotes on a line carrying an
 * operator has the same hole, whatever the quoting looks like by inspection.
 *
 * Here the command is the entire line, unquoted, with nothing of ours on it:
 * quote state is whatever the command itself says, so its `|` and `&` stay inside
 * its quotes, and a pipeline it MEANS still works and still lands in the log
 * (every stage inherits the redirected handle from the nested cmd above).
 *
 * The command's TEXT is written into this file. It used to be reached with
 * `call %AIC_JOB_COMMAND%` instead, and that indirection quietly broke the
 * expansion contract it was added to provide.
 *
 * The mechanics: reaching a `call %VAR%` line substitutes the variable once, and
 * cmd does not rescan what a substitution produced — so `call` was doing the one
 * extra round that resolves the command's own `%FOO%`. But `call` re-parses only
 * the command it INVOKES, which ends at the first `&` or `|`. Measured on the
 * real box (2026-08-10, agent 1.0.43):
 *
 *   echo A=[%AIC_TEST%] & echo B=[%AIC_TEST%] & echo PCT=50%%
 *   → A=[wartosc-z-env]   B=[%AIC_TEST%]   PCT=50%%
 *
 * so the documented "`%VAR%` behaves like `$VAR` in sh" held for the first
 * command of a line and silently failed for every one after it — the literal
 * text reaching the program, which is the worst way to be wrong.
 *
 * Written here, the batch parser expands the whole line once when it reaches it:
 * every `%FOO%` on it, defined or not, exactly as `sh` treats `$FOO`. Verified
 * side by side on the same box: the same command through this shape prints
 * `A=[wartosc-z-env] B=[wartosc-z-env] PCT=50%`.
 *
 * It costs nothing the indirection was protecting. Quote state still comes from
 * the command alone, because nothing of ours shares its line, so its `|` and `&`
 * stay inside its quotes. OUR paths keep travelling in the environment, which is
 * what stops a jobs root containing a literal `%…%` from being re-expanded — the
 * command is the one text on this line that is SUPPOSED to expand. And the
 * command string no longer sits in the job's environment, where every child
 * process could read it.
 *
 * One caller-facing rule survives from batch itself: a literal percent needs
 * `%%`. It is written down where a caller looks, in JOB_COMMAND_ENV.
 *
 * `cd /d` rather than spawn's own cwd, so a working directory that disappeared
 * between start()'s check and now is recorded as a failed job with a line in the
 * log rather than silently run somewhere else. The missing-cwd branch is written
 * BEFORE the command and jumped over, so the command reference is the LAST line
 * of the file — the same rule buildJobScript states for POSIX, and for the same
 * reason: a trailing continuation in the command's own text must have nothing of
 * ours left to swallow. Measured on the real box (agent 1.0.40, Windows
 * 10.0.26200): with a command ending in an unquoted `^`, the `exit /b
 * %ERRORLEVEL%` line that used to follow it was eaten as the continuation,
 * execution fell through into the missing-cwd label, and a job that had just run
 * fine reported a working directory it could not enter. The two scripts now
 * agree about that hazard instead of only one of them respecting it.
 *
 * That ordering is what makes the branch's own `exit /b 1` load-bearing rather
 * than decorative. Under the old layout the branch sat at the END of the file and
 * was terminal by position; now it is followed by `:aic_run`, so that one line is
 * the ONLY thing between a cwd that could not be entered and the command running
 * in the JOB directory instead — logging the failure and then reporting the
 * command's own exit code as the job's. Measured on the real box (Windows
 * 10.0.26200) with this pair against a missing cwd: as shipped the exit file
 * holds 1 and the command does not run; with the line deleted the log carries the
 * SAME notice, the command RUNS, and the exit file holds 0. The notice alone
 * therefore does not distinguish the two, and delete or reorder that line and
 * nothing about the file reads wrong. The invariant is held by an executing
 * Windows test ("does not run the command when the cwd vanished before the
 * spawn") and by a structural one that pins the branch's shape. NEITHER covers
 * the other's platform: the executing test runs only on windows-latest, the
 * structural one lives in describeOnPosix. Deleting either leaves this invariant
 * unasserted where that half actually runs.
 *
 * Nothing replaces that `exit /b`: falling off the END of a batch already
 * propagates the last command's errorlevel out of `cmd /c` (measured: a file
 * whose last line exits 7 makes `cmd /d /s /c file.cmd` return 7), which is
 * exactly what the wrapper's `echo %ERRORLEVEL%` reads. A command that transfers
 * control to a batch of its own never returns here in either shape, and the
 * nested cmd then exits with that batch's ERRORLEVEL, which is the same answer.
 */
export function buildWindowsJobCommandScript(command: string): string {
  return (
    "@echo off\r\n" +
    `cd /d "%${JOB_CWD_ENV}%"\r\n` +
    "if not errorlevel 1 goto aic_run\r\n" +
    "echo [aicommander] the job's working directory could not be entered\r\n" +
    "exit /b 1\r\n" +
    ":aic_run\r\n" +
    // The command's own text, as the whole last line. See the block above for why
    // it is written here rather than reached through `call %AIC_JOB_COMMAND%`.
    `${command}\r\n`
  );
}

/**
 * Default environment applied BEFORE the caller's, so an explicit `env` still
 * wins. Python block-buffers stdout in ~4-8 KiB chunks whenever it is not a
 * terminal — and a job's stdout is always a file — so without this the "how is
 * it going?" call on a training run returns nothing for minutes and then a
 * burst, which is indistinguishable from a job producing no output at all.
 */
const JOB_ENV_DEFAULTS: Readonly<Record<string, string>> = { PYTHONUNBUFFERED: "1" };

/**
 * Appended once when a log reaches the cap; see checkLogCap. Worded for BOTH
 * cases it covers — a running job and one that exited before anyone looked — and
 * it does not claim the writing stopped, because it does not: only what we SERVE
 * ends here.
 */
const TRUNCATION_NOTICE =
  "\n[aicommander] output.log reached its size limit; nothing past this point is served. The job itself was not stopped.\n";

/**
 * Everything we persist about a job. `command` and `cwd` are payload: they live
 * here because a restarted agent must still be able to describe the job, but
 * they leave the machine ONLY when the caller explicitly asked for the command
 * (`includeCommand`) — see toSummary.
 */
interface JobMeta {
  /** Schema marker, so a future field change can be detected rather than guessed. */
  v: 1;
  jobId: string;
  name: string;
  command: string;
  cwd: string;
  status: JobStatus;
  exitCode: number | null;
  startedAt: number;
  endedAt: number | null;
  /**
   * True when `endedAt` was ESTIMATED rather than observed — the `unknown` branch
   * of refresh, where no exit marker exists and the ending has to be inferred
   * from the log's last write. Absent on every `exited` record (its timestamp is
   * the exit file's mtime, i.e. the real instant) and on every record written
   * before this field existed. See estimateVanishedEndedAt.
   */
  endedAtApproximate?: boolean;
  gpuIndex: number | null;
  /** Wrapper pid; on POSIX also the process-GROUP id, since we spawn detached. */
  pid: number | null;
  /**
   * An opaque, platform-specific token identifying the PROCESS behind `pid`,
   * captured at spawn and compared on every liveness check so a recycled pid can
   * never be mistaken for our job (see readProcIdentity). Null is never a match.
   * Compared only through compareProcIdentity: a record written by an older
   * agent may hold a pre-canonical rendering, and that legacy token must read
   * as "cannot verify" — a hold — never as a mismatch that ends a live job.
   *
   * On POSIX a job we started successfully always has one: a start that cannot
   * capture it does not become a job at all (see start), precisely so that a
   * null here can only mean a hand-edited, truncated or pre-upgrade record — the
   * cases where refusing to vouch for the pid is the right answer. Windows may
   * legitimately hold null, because the probe there depends on a wmic/PowerShell
   * that a hardened box may not have; see verifyJobProcess for what refusing to
   * vouch then costs (a hold, never a fabricated ending).
   */
  procIdentity: string | null;
  /**
   * Set while a process this agent STARTED is being stopped because its start
   * could not be completed (see retireStartedProcess). Absent on every ordinary
   * job, and never bumps `v`: a record written before this field existed simply
   * is not retiring.
   *
   * Purely agent-local — it describes what THIS machine is doing about a process,
   * not what the job is, and it is not projected onto the wire by toSummary. The
   * wire has nothing to say here: the honest external answer for "we cannot yet
   * prove this ended" is the `running` the record already carries.
   *
   * It exists because retiringJobs is memory: an agent that restarts between the
   * SIGTERM and the child's exit would otherwise read a record it cannot account
   * for and settle it, releasing a GPU lock the still-living child needs.
   */
  retiring?: boolean;
  /**
   * The transient systemd scope this job was LAUNCHED INTO
   * (`aic-job-<id>.scope`), or absent when it was not — see job-scope.ts for
   * when that happens and why.
   *
   * "Launched into", not "confirmed in", and the distinction is deliberate: the
   * field records the systemd-run command we ran, not a verified cgroup
   * membership (see the assignment in start() for the window that leaves open
   * and why closing it would cost more than it buys).
   *
   * Follows `retiring`'s precedent exactly: agent-local, absent on every record
   * written before this field existed, does not bump `v`, and is NOT projected
   * onto the wire by toSummary. The caller has nothing to do with it; the wire
   * describes what the job IS, not which cgroup this machine put it in.
   *
   * It is written down because nothing else on disk can answer the question it
   * answers. "Will this job survive the next agent upgrade?" is invisible from
   * the outside — a scoped and an unscoped job look identical until the restart
   * that ends one of them — and by the time an operator asks, the process that
   * made the decision may be long gone. This is also the name the uninstall path
   * stops, so a record and a unit can be matched up by hand if they ever disagree.
   */
  scope?: string;
  /**
   * Byte length of output.log at the moment the cap was hit (including the
   * truncation notice), or null while the log is intact. Reads never go past it,
   * so offsets stay inside the cap even though the still-running job's own writes
   * do not (we cannot revoke an fd we already handed it — see checkLogCap).
   */
  truncatedAt: number | null;
}

/** Fields a start request may carry, already extracted from the relay frame. */
export interface JobStartRequest {
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  name?: string;
  gpuIndex?: number;
}

export interface JobListRequest {
  status?: JobStatus;
  /** Newest-first page size; defaults to JOB_LIST_DEFAULT_ENTRIES, capped at the wire page cap. */
  limit?: number;
  includeCommand?: boolean;
}

export interface JobStatusRequest {
  jobId: string;
  includeCommand?: boolean;
}

export interface JobLogsRequest {
  jobId: string;
  tailLines?: number;
  offsetBytes?: number;
  maxBytes?: number;
}

export interface JobCancelRequest {
  jobId: string;
}

/**
 * A genuinely unexpected failure OF THIS MACHINE (unwritable jobs root, spawn
 * rejection, a directory we cannot read). The connection layer turns this into
 * `agent:job_error`, which — unlike a JobRefusal — is NOT an expected outcome the
 * caller branches on, and which the relay can only report as "the machine failed"
 * (502). Messages are authored here and never interpolate job output or a command.
 *
 * A fault in the REQUEST is deliberately NOT this: it goes back as a
 * `invalid_request` JobRefusal instead (see {@link invalidRequest}), because the
 * caller must change the request, not retry it or blame the machine.
 */
export class JobError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JobError";
  }
}

const isWindows = process.platform === "win32";

/**
 * Where job directories live.
 *
 * Deliberately NOT the /etc credential directory the device identity and session
 * use: a jobs root holds hundreds of megabytes of logs and whole workspaces, i.e.
 * variable DATA, not configuration. Order of preference:
 *  1. an explicit `configDir` — the desktop app's per-user data dir;
 *  2. AICOMMANDER_CONFIG_DIR (see config-dir.ts) — durable storage the operator
 *     chose precisely because the default paths are volatile (QNAP QTS);
 *  3. /var/lib/aicommander for a root service, the FHS location for exactly this;
 *  4. otherwise a per-user data dir, so a non-root dev/user agent still works.
 */
export function resolveJobsRoot(configDir?: string): string {
  const base = configDir ?? envConfigDir();
  if (base) return path.join(base, "jobs");
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  if (!isWindows && isRoot) return "/var/lib/aicommander/jobs";
  if (isWindows) {
    const localAppData = process.env["LOCALAPPDATA"];
    const winBase = localAppData && path.isAbsolute(localAppData)
      ? localAppData
      : path.join(os.homedir(), "AppData", "Local");
    return path.join(winBase, "aicommander", "jobs");
  }
  return path.join(os.homedir(), ".local", "share", "aicommander", "jobs");
}

export class JobManager {
  readonly jobsRoot: string;

  /**
   * When the retention sweep last ran, so a long-lived agent prunes on activity
   * instead of only at startup. 0 means "never in this process", which makes the
   * first RPC prune — the same reclaim a restart would have done.
   */
  private lastPruneAt = 0;

  /**
   * jobIds this process has already OBSERVED in a terminal state on disk.
   *
   * A terminal status is final — nothing ever moves a job back to `running` —
   * so remembering it is not caching a status we might report wrongly. Two
   * users, both of them work-avoidance: the concurrency count in start(), which
   * skips re-reading a week of finished meta.json on every job_start, and
   * refresh's terminal branch, which weighs an already-finished log against the
   * cap once instead of stat-ing it on every list. Every reported status is
   * still recomputed from disk by refresh().
   */
  private readonly settledJobs = new Set<string>();

  /**
   * jobIds whose START failed AFTER the process was already running, and whose
   * process this agent has not yet SEEN exit (see retireStartedProcess).
   *
   * The mirror image of settledJobs, and the only other in-memory note here: it
   * records that a process exists which disk cannot describe — either because
   * its pid never landed there, or because we could not identify it well enough
   * to vouch for it later. Like settledJobs it can only ever make us report
   * less, never more: while an id is in here refresh() leaves the record
   * `running`, so the job keeps its GPU lock and its concurrency slot until the
   * process is confirmed gone. Nothing is invented — a process really is (or may
   * still be) running — and the set is emptied by the exit that proves it is not.
   *
   * This half is only an OPTIMISATION over the `retiring` flag written to
   * meta.json (see retireStartedProcess): it is what lets the process holding the
   * child handle skip the pid probe entirely, and — because it needs no disk — it
   * is also the only cover left when the very write that failed is why we are
   * retiring at all. The durable flag is what a RESTARTED agent reads.
   */
  private readonly retiringJobs = new Set<string>();

  /**
   * Jobs THIS agent has signalled a cancel for.
   *
   * The exit-watcher below records an observed exit code only when the child was
   * not killed by a signal — `signal === null` was meant to be that test. It is
   * not sufficient, and the gap is platform-shaped: on Linux `/bin/sh` is dash,
   * which dies OF the SIGTERM, so Node reports `signal: "SIGTERM"` and nothing is
   * recorded (outcome `unknown`, which is correct). On macOS `/bin/sh` is bash,
   * which runs the wrapper's EXIT trap and then leaves NORMALLY — Node reports
   * `code: 0, signal: null`, and a job we killed at tick 45 of 300 was being
   * recorded, and reported, as **exit code 0**. Indistinguishable from success.
   * Windows reaches the same place by another road: `taskkill /F` gives the
   * terminated process an ordinary exit code (1), also with no signal.
   *
   * So the observation cannot be trusted to describe a death we caused. What the
   * agent KNOWS — "I cancelled this" — has to outrank what it saw, and that is
   * what this set is: consulted before recording, so a cancelled job keeps no
   * exit marker and settles as `unknown`, the same answer Linux already gave and
   * the one every caller-facing description promises ("cancelled, never
   * succeeded").
   *
   * It never blocks a REAL outcome: a job whose wrapper already wrote the exit
   * file keeps that value (recordExitCode is create-or-fail), and the wrapper is
   * the process that actually ran the command.
   */
  private readonly cancelledJobs = new Set<string>();

  /**
   * The cards this machine is KNOWN to have, or null for "we do not know".
   *
   * Pushed in from connection.ts, which owns the probe (gpu.ts) and its polling
   * policy — nothing here ever probes. That direction is forced by two things:
   * start() is synchronous and runs on the thread that must answer `do:ping`
   * inside AGENT_TIMEOUT_MS, so it cannot wait on `nvidia-smi`; and a second
   * probe here would be a second copy of the "undefined means unknown, so never
   * publish a failed re-probe" policy that connection.ts already implements.
   *
   * Null is the honest default, and it is what a JobManager reached through
   * getJobManager() has until a connection hands it a list: the manager's
   * lifecycle is independent of the socket, so it must be USABLE with no list at
   * all. Null is permissive — the only refusals come from a list we actually
   * have.
   */
  private knownGpus: KnownGpus = null;

  /**
   * How spawnJob asks whether this machine can put a job in its own systemd
   * scope. Defaults to the module-level settled memo (job-scope.ts) and is
   * overridable ONLY as a test seam: the scope path needs root, systemd and a
   * reachable system bus, none of which a test box has, so the alternative would
   * be a whole platform's behaviour that nothing ever executes. Internal — it is
   * not on the wire and not reachable from the CLI.
   */
  private readonly scopeLauncher: () => JobScopeLauncher | null;

  constructor(opts?: {
    jobsRoot?: string;
    configDir?: string;
    scopeLauncher?: () => JobScopeLauncher | null;
  }) {
    this.jobsRoot = opts?.jobsRoot ?? resolveJobsRoot(opts?.configDir);
    this.scopeLauncher = opts?.scopeLauncher ?? jobScopeLauncher;
  }

  /**
   * Tell the manager which GPUs this machine has, for validating `gpuIndex` at
   * job_start. Called with the registration probe and again after every
   * CONFIDENT re-probe — including a confident EMPTY one, which is how removed
   * hardware stops being accepted. `undefined` means "we could not tell" (the
   * probe failed, timed out, or only partly parsed) and resets us to permissive
   * rather than claiming the cards went away; `[]` is the confident "there are
   * none". See gpu.ts probeGpuState for which observation produces which.
   *
   * Copied rather than kept by reference: the caller's array is the live
   * telemetry value it also puts on the wire, and a validation input must not
   * change under a start() that is already reading it.
   */
  setKnownGpus(gpus: readonly GpuDevice[] | undefined): void {
    this.knownGpus = gpus === undefined ? null : gpus.slice();
  }

  /**
   * Startup hook: reconcile everything a previous agent process left behind, then
   * reclaim disk. Never throws — a machine with an unusable jobs root must still
   * come online and serve exec/screenshot; job calls will fail individually.
   *
   * Order matters. Jobs are settled FIRST (which releases the GPU lock of any job
   * that ended while we were down), then expired directories are deleted, then
   * lockfiles whose holder no longer exists at all are reaped. Doing the reap
   * first would race with a job we are about to adopt as still running.
   */
  recover(): void {
    // Kick the macOS login-shell PATH probe off HERE, at agent startup, rather
    // than on the first job: buildEnv cannot wait for it (see there), so the only
    // way a job gets the user's real PATH is for the answer to be cached before
    // one is ever started. Memoized process-wide and fail-open, so this costs one
    // bounded shell spawn per process and nothing on any other platform.
    //
    // NOT the only warm-up, and deliberately not load-bearing on its own:
    // recover() runs at startup on the controller/CLI path, but the desktop path
    // reaches this manager lazily (getJobManager() inside connection.ts's jobs()),
    // i.e. only when the first do:job_* frame lands. runConnectionLoop therefore
    // starts the same probe on its own, and do:job_start waits for it. Both call
    // the same memoized probe, so whichever runs first pays for it.
    void pendingLoginShellPath();
    // And the systemd-scope capability probe, for exactly the same reasons and
    // with exactly the same wiring (runConnectionLoop starts it too, and
    // do:job_start awaits it). It is HERE rather than in spawnJob because it was
    // a synchronous execFileSync there: on a box with a wedged system bus — the
    // very shape the probe exists to detect — the first job start blocked the
    // frame handler for the probe's whole timeout. Bounded, fail-open, and a
    // no-op anywhere but Linux-as-root-under-systemd.
    void pendingJobScope();
    try {
      ensurePrivateDir(this.jobsRoot);
    } catch {
      // Unwritable root: nothing to recover and nothing we can do about it here.
      return;
    }

    for (const jobId of this.listJobIds()) {
      try {
        const meta = this.readMeta(jobId);
        // A settling pass first: it is what turns a week-old "running" record
        // into the terminal state the prune below can then age out.
        if (meta) this.refresh(meta);
      } catch {
        // One bad directory must never abort recovery of the rest.
      }
    }

    this.pruneExpired(Date.now());
    this.reapGpuLocks();
  }

  /**
   * Delete every job directory whose retention window has passed.
   *
   * Reads only the STORED state — deliberately no refresh() here. A prune that
   * re-checked liveness would be a full pid/-proc sweep of every surviving job,
   * and it would buy nothing: a job that ended without being settled still has
   * `endedAt === null`, so it is kept, and the next reader settles it.
   */
  private pruneExpired(now: number): void {
    this.lastPruneAt = now;
    for (const jobId of this.listJobIds()) {
      try {
        const meta = this.readMeta(jobId);
        if (!meta) {
          // No readable meta.json: either a half-created directory or one written
          // by a version we cannot parse. Only reclaim it once it is older than
          // the retention window, so a live job is never destroyed on a guess.
          this.pruneUnreadable(jobId, now);
          continue;
        }
        if (meta.endedAt !== null && now - meta.endedAt > JOB_RETENTION_MS) {
          this.removeJobDir(jobId);
        }
      } catch {
        // One bad directory must never abort the prune of the rest.
      }
    }
  }

  /**
   * Run the retention sweep if it is due. Called from the RPCs that already walk
   * the jobs root (start, list) and never from the polling paths (status, logs,
   * cancel), which must stay at one job's worth of syscalls: they are what a
   * caller tailing a training run hits every few seconds, on the same thread
   * that has to answer `do:ping` inside AGENT_TIMEOUT_MS.
   */
  private maybePrune(): void {
    const now = Date.now();
    if (now - this.lastPruneAt < PRUNE_INTERVAL_MS) return;
    this.pruneExpired(now);
  }

  // ── RPC surface ────────────────────────────────────────────────────────────

  /**
   * Start a detached job. Refuses (rather than throws) for the two expected
   * capacity conditions — too many running jobs, GPU already reserved — because
   * the caller is meant to branch on those: poll and retry. It also refuses, with
   * `invalid_request`, anything decidable from the REQUEST alone; only a fault of
   * this machine leaves here as a JobError.
   */
  start(req: JobStartRequest): JobRpcResult {
    const command = req.command;
    if (typeof command !== "string" || command.trim() === "") {
      return invalidRequest("A job requires a non-empty command.");
    }
    if (Buffer.byteLength(command, "utf8") > MAX_COMMAND_BYTES) {
      return invalidRequest("The command is too long to run as a job.");
    }
    // Windows ONLY, deliberately. There the command becomes the last LINE of a
    // batch file (WINDOWS_JOB_COMMAND_SCRIPT), so an embedded newline does not
    // separate two statements — it ends our line early and turns the rest into
    // further lines of our script, run outside everything that line arranges.
    // That is a different program from the one the caller wrote, and no escaping
    // fixes it, so it is refused as a property of the REQUEST. POSIX keeps
    // accepting multi-line commands: buildJobScript embeds the command in a
    // script where a newline is an ordinary statement separator, callers already
    // send small here-scripts that way, and taking that away would break them.
    // The asymmetry is documented in JOB_COMMAND_ENV, where a caller looks.
    if (isWindows && /[\r\n]/.test(command)) {
      return invalidRequest(
        "A job command cannot contain a line break on Windows: it would be read as further lines of the wrapper script. Join the steps with `&&` instead.",
      );
    }
    // Validated against THIS machine's cards when we know them (setKnownGpus),
    // not only against the lockfile namespace: `gpuIndex: 7` on a one-card box
    // used to start happily, run with CUDA_VISIBLE_DEVICES=7, find nothing and
    // either die hours later or fall back to CPU without saying so. An unknown
    // list stays permissive — see job-gpu-index.ts for why that asymmetry is
    // deliberate.
    const gpu = decideGpuIndex(req.gpuIndex, this.knownGpus);
    if ("invalid" in gpu) return invalidRequest(gpu.invalid);
    const gpuIndex = gpu.gpuIndex;

    try {
      ensurePrivateDir(this.jobsRoot);
    } catch (err) {
      throw new JobError(`The jobs directory is not usable: ${errText(err)}`);
    }

    // Starting a job is the moment the jobs root GROWS, so it is where the
    // retention sweep belongs. Throttled to PRUNE_INTERVAL_MS, so back-to-back
    // starts pay for it once.
    this.maybePrune();

    const running = this.countRunningJobs();
    if (running >= JOB_MAX_CONCURRENT) {
      return {
        ok: false,
        reason: "too_many_jobs",
        message: `This machine already has ${running} jobs running (limit ${JOB_MAX_CONCURRENT}).`,
      };
    }

    const jobId = randomBytes(8).toString("hex");
    const dir = path.join(this.jobsRoot, jobId);
    const workspace = path.join(dir, WORKSPACE_DIR);
    try {
      ensurePrivateDir(dir);
      ensurePrivateDir(workspace);
    } catch (err) {
      throw new JobError(`Could not create the job directory: ${errText(err)}`);
    }

    // A caller-supplied cwd is checked BEFORE the spawn: with a shell wrapper an
    // invalid cwd surfaces asynchronously, which would leave a job recorded as
    // "running" behind a pid that never existed.
    //
    // The two checks are NOT the same kind of fault, and are answered differently:
    //  - not absolute is a property of the REQUEST — no machine anywhere accepts
    //    it, so it is `invalid_request` (400: fix the path you sent);
    //  - not a directory is a property of THIS MACHINE at this moment. isDirectory
    //    also returns false for a path that exists but the agent's user may not
    //    stat, and for a network/USB volume that failed to mount — machine
    //    conditions under which the identical request succeeds later. Calling that
    //    a caller fault would tell the operator to fix a path that is already
    //    correct, so it stays a JobError (502: the machine answered, it failed
    //    there, do not retry unchanged).
    let cwd = workspace;
    if (req.cwd !== undefined) {
      if (typeof req.cwd !== "string" || !path.isAbsolute(req.cwd)) {
        this.removeJobDir(jobId);
        return invalidRequest("cwd must be an absolute path.");
      }
      if (!isDirectory(req.cwd)) {
        this.removeJobDir(jobId);
        throw new JobError("cwd does not exist on this machine.");
      }
      cwd = req.cwd;
    }

    if (gpuIndex !== null) {
      const heldBy = this.acquireGpuLock(gpuIndex, jobId);
      if (heldBy !== null) {
        this.removeJobDir(jobId);
        return {
          ok: false,
          reason: "gpu_busy",
          heldBy,
          message: `GPU ${gpuIndex} is reserved by job ${heldBy}.`,
        };
      }
    }

    const meta: JobMeta = {
      v: 1,
      jobId,
      name: normalizeName(req.name, jobId),
      command,
      cwd,
      status: "running",
      exitCode: null,
      startedAt: Date.now(),
      endedAt: null,
      gpuIndex,
      pid: null,
      procIdentity: null,
      truncatedAt: null,
    };

    // Record BEFORE spawning. The two failure modes are not symmetric: a record
    // whose process never started is RECOVERABLE (refresh settles a pid that is
    // not alive as `unknown`, releasing its GPU lock), while a process with no
    // record is not — it is invisible to status and list, nothing can cancel it,
    // and the GPU lock it holds looks stale enough to be reaped, which puts a
    // second job on the same card and causes the exact OOM the lock prevents.
    // So an unwritable record fails the start instead of being suppressed.
    if (!this.writeMeta(meta)) {
      this.abandonStart(jobId, gpuIndex);
      throw new JobError("Could not record the job on disk.");
    }

    let child: ChildProcess;
    let pid: number;
    let scope: string | undefined;
    try {
      ({ child, pid, scope } = this.spawnJob(meta, req.env));
    } catch (err) {
      // Nothing was started, so nothing has to be stopped: this is the only
      // failure past the lock that may drop it immediately.
      this.abandonStart(jobId, gpuIndex);
      throw new JobError(`Could not start the job: ${errText(err)}`);
    }

    // From here on a REAL process exists on this machine, and every remaining
    // branch has to answer for it.
    meta.pid = pid;
    meta.procIdentity = captureProcIdentity(pid);
    // Only when there IS one: the field's absence is what says "this job is in
    // the agent's own cgroup", and an empty string would say nothing.
    //
    // This records the LAUNCH, not a confirmed cgroup membership. systemd-run
    // registers the transient unit and only then execs the wrapper in its place,
    // so for the few milliseconds between spawn() returning and that
    // registration completing the child is still in the AGENT's cgroup while
    // this field already names a scope. A `systemctl restart` landing inside
    // that window kills it. We deliberately do not verify: reading
    // /proc/<pid>/cgroup right after the spawn cannot tell "did not make it"
    // from "not yet", and any wait for it belongs to the start path we keep
    // clear on purpose (start() is synchronous — see buildEnv and
    // connection.ts's do:job_start). The observable outcome of losing that race
    // is a job whose wrapper never wrote an exit marker, which refresh() reports
    // as `unknown` — already the honest answer — so what is left wrong is only
    // an agent-local diagnostic field.
    if (scope !== undefined) meta.scope = scope;
    // Write BEFORE judging the identity, so that even a job we are about to
    // retire has its pid on disk while we do it: that is what makes the process
    // visible to an operator (and to a recovery pass) during the seconds it
    // takes to stop.
    const recorded = this.writeMeta(meta);
    const verdict = this.verifyJobProcess(meta);

    // Two ways a start can fail with the process already running, and they are
    // the same failure: we cannot durably own what we just started.
    //  - the pid is not on disk, so nothing could later find or cancel it;
    //  - the platform would not tell us WHICH process the pid is, so nothing
    //    could later PROVE it is ours. That is no longer a job that gets settled
    //    out from under its card — refresh() holds an unprovable-but-live pid
    //    rather than releasing what it holds — but the write end is unforgiving:
    //    signalJob refuses to signal a pid it cannot confirm, so the caller
    //    would be handed a running job it can never cancel, on a card only that
    //    process's own death can free. Right here we still hold the child
    //    handle, the one thing that can stop it WITHOUT an identity, so this is
    //    the last moment the machine can clean up after itself. An identity is
    //    therefore part of what makes a start succeed, exactly as the record is.
    // `gone` is deliberately NOT one of them: a process that ended before we
    // finished writing it down leaves nothing running, and refresh settles it
    // from the exit file (or as `unknown`) with no orphan and no held card.
    // Windows is exempt from the identity requirement because a missing identity
    // is a STANDING condition there, not an accident: the probe needs a
    // wmic/PowerShell a hardened box may not have, so demanding one would refuse
    // every job that machine ever starts. It pays for the exemption in the same
    // coin as everything else here — its jobs are held on bare liveness and are
    // not signalled — which costs precision, not ownership.
    const unidentified = verdict === "unverifiable" && !isWindows;
    if (!recorded || unidentified) {
      this.retireStartedProcess(meta, child);
      throw new JobError(
        recorded
          ? "Could not identify the job's process; it is being stopped."
          : "Could not record the job on disk; the process is being stopped.",
      );
    }
    return { ok: true, kind: "job", job: this.toSummary(meta, false) };
  }

  /** Undo a start that cannot be completed: no lock, no directory, no trace. */
  private abandonStart(jobId: string, gpuIndex: number | null): void {
    if (gpuIndex !== null) this.releaseGpuLock(gpuIndex, jobId);
    this.removeJobDir(jobId);
  }

  /**
   * Abandon a start whose process is ALREADY RUNNING: stop it, and surrender
   * what it holds only once it is gone.
   *
   * Signalling is not instantaneous — a process that ignores SIGTERM lives until
   * the KILL_ESCALATION_MS escalation — so releasing the lock and deleting the
   * directory at signal time would open a window in which a live process has
   * neither a record nor a reservation, and a concurrent job_start could take the
   * same card. So the job stays fully recorded and fully locked (retiringJobs
   * keeps refresh from settling it) until the process EXITS, which is the only
   * event that proves the card is free.
   *
   * The waiting happens on the child's own `exit` event, never on this thread:
   * start() returns immediately, so the agent keeps answering `do:ping` inside
   * AGENT_TIMEOUT_MS while a stubborn process is being escalated — the same
   * reasoning that keeps signalJob's escalation on a timer.
   *
   * A process that survives even SIGKILL (an uninterruptible wait) therefore
   * keeps its GPU reserved indefinitely. That is the intended fail-closed
   * answer: we would rather strand a card than put a second training run on one
   * we cannot prove is idle.
   *
   * And the wait can outlive US: an agent restarted between the SIGTERM and the
   * exit has no child handle and no retiringJobs, so the fact is written down
   * first, together with the pid that makes it checkable. Without that, recovery
   * reads a record that says `running` with nothing to ask about, settles it
   * `unknown` and frees the card while the child is still being escalated — the
   * same double-booked GPU by a second route.
   */
  private retireStartedProcess(meta: JobMeta, child: ChildProcess): void {
    const { jobId, gpuIndex, pid } = meta;
    this.retiringJobs.add(jobId);
    // Before the first signal, so a crash a millisecond later still finds it.
    // Best-effort by necessity: a failed write is one of the two things that got
    // us here, and if the disk still refuses there is nothing durable to be had —
    // the in-memory note then covers the process for as long as we live, and a
    // restart is back to settling a pid-less record as `unknown`. We do not hold
    // a record with no pid instead: that is a state no later observation could
    // ever get out of (see refresh).
    this.writeMeta({ ...meta, retiring: true });
    child.once("exit", () => {
      // The process is gone for certain — this is the handle we spawned it with,
      // not a pid we looked up — so the lock and the record can go with it.
      this.retiringJobs.delete(jobId);
      this.abandonStart(jobId, gpuIndex);
    });
    if (pid === null) return;
    this.signalSpawned(child, pid, "SIGTERM");
    const escalation = setTimeout(() => {
      this.signalSpawned(child, pid, "SIGKILL");
      // And empty the scope's cgroup, exactly as signalJob's escalation does and
      // for the same reason: the process-group signal above does not reach a
      // descendant that called setsid, and inside its own scope that descendant
      // no longer dies at the next service restart either. Here the exit handler
      // above has already released the card (abandonStart) or is about to, so a
      // survivor would sit on a GPU nothing knows is occupied.
      //
      // Unconditional on the scope's presence and not on the child's state: the
      // timer fires whether or not the child has exited, and a scope that went
      // with it is already collected — killJobScope then answers `Unit not
      // loaded`, does not throw, and reports nothing.
      if (meta.scope !== undefined) killJobScope(meta.scope);
    }, KILL_ESCALATION_MS);
    // Never keep the process alive just to escalate a kill.
    escalation.unref?.();
  }

  /**
   * Signal the process tree of a child we spawned ourselves and still hold the
   * handle for.
   *
   * The identity re-check signalJob performs is both unnecessary and impossible
   * here: while Node has not observed the exit the child cannot have been
   * reaped, so its pid still names our process and no stranger can have
   * inherited it — and the identity is exactly what we may be missing. Once the
   * exit HAS been observed we stop signalling, for the reason signalJob does.
   */
  private signalSpawned(child: ChildProcess, pid: number, signal: "SIGTERM" | "SIGKILL"): void {
    if (child.exitCode !== null || child.signalCode !== null) return;
    try {
      if (isWindows) {
        spawn("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
      } else {
        // Negative pid = the process group led by the detached wrapper.
        process.kill(-pid, signal);
      }
    } catch {
      // Process group already gone — nothing to signal.
    }
  }

  /**
   * Concurrency rail input. Counted from disk (the truth) rather than a counter
   * an agent restart would reset — and RECOMPUTED, not read off the stored
   * status: a job adopted across a restart has no child handle here, so its
   * meta.json still says "running" long after the process died. Counting the
   * stored value would wedge job_start on a machine with nothing running until
   * some unrelated job_list happened to refresh it.
   *
   * Jobs already seen in a terminal state are skipped without re-reading them,
   * so the cost of a start tracks the number of LIVE jobs (bounded by
   * JOB_MAX_CONCURRENT) instead of a whole retention window of finished ones.
   */
  private countRunningJobs(): number {
    let running = 0;
    for (const jobId of this.listJobIds()) {
      if (this.settledJobs.has(jobId)) continue;
      const meta = this.readMeta(jobId);
      if (!meta) continue;
      if (this.refresh(meta).status === "running") running++;
    }
    return running;
  }

  list(req: JobListRequest): JobRpcResult {
    this.maybePrune();
    // Newest first, so what we drop is the least interesting. The refresh — the
    // part that costs syscalls per job — happens INSIDE the walk, so a machine
    // holding a week of jobs pays it for the page it returns, not for all of
    // them (a stored-terminal meta short-circuits in refresh anyway).
    const stored = this.listMetas().sort((a, b) => b.startedAt - a.startedAt);
    const limit = clampListLimit(req.limit);
    const jobs: JobSummary[] = [];
    let walked = 0;
    for (const entry of stored) {
      if (jobs.length >= limit) break;
      walked++;
      const meta = this.refresh(entry);
      if (req.status && meta.status !== req.status) continue;
      jobs.push(this.toSummary(meta, req.includeCommand === true));
    }
    // Records we never looked at, so the caller learns there IS more history
    // rather than mistaking a page for the whole machine. RECORDS, not matches:
    // under a `status` filter we stop at the first N matches and cannot know how
    // many of the rest would have matched without refreshing them all — which is
    // the syscall cost the limit exists to avoid. Documented as an upper bound on
    // the wire (JobRpcResult).
    const omitted = stored.length - walked;
    return { ok: true, kind: "jobs", jobs, ...(omitted > 0 ? { omitted } : {}) };
  }

  status(req: JobStatusRequest): JobRpcResult {
    const meta = this.loadForRequest(req.jobId);
    if (!meta) return notFound();
    return { ok: true, kind: "job", job: this.toSummary(meta, req.includeCommand === true) };
  }

  /**
   * Read a bounded slice of a job's log.
   *
   * Two modes, both stateless:
   *  - `offsetBytes` — read forward from an offset (feed a previous reply's
   *    `nextOffsetBytes` back in to follow a growing log);
   *  - otherwise — the last `tailLines` lines, the "how is it going?" call.
   * Either way the decoded slice is hard-clamped to JOB_LOGS_MAX_SLICE_BYTES:
   * the caller's `maxBytes` can only ever make it smaller.
   */
  logs(req: JobLogsRequest): JobRpcResult {
    const meta = this.loadForRequest(req.jobId);
    if (!meta) return notFound();

    const logPath = path.join(this.jobsRoot, meta.jobId, LOG_FILE);
    // Never serve past the truncation point: beyond it the file may still be
    // growing (the running job holds the fd) but those bytes are outside the cap
    // we promised, and paging into them would never reach eof.
    const size = Math.min(fileSize(logPath), meta.truncatedAt ?? Number.MAX_SAFE_INTEGER);
    const maxBytes = clampSliceBytes(req.maxBytes);

    let start: number;
    if (isNonNegativeNumber(req.offsetBytes)) {
      start = Math.min(Math.floor(req.offsetBytes), size);
    } else {
      // Tail mode: look at most one slice back from the end and find where the
      // requested number of lines begins inside that window. A single huge line
      // therefore still returns a slice-sized tail rather than nothing.
      const tailLines = clampTailLines(req.tailLines);
      const windowStart = Math.max(0, size - maxBytes);
      const window = readRange(logPath, windowStart, size - windowStart);
      start = windowStart + offsetOfLastLines(window, tailLines);
    }

    const chunk = readRange(logPath, start, Math.min(maxBytes, Math.max(0, size - start)));
    const nextOffsetBytes = start + chunk.length;
    return {
      ok: true,
      kind: "logs",
      logs: {
        jobId: meta.jobId,
        chunk: chunk.toString("base64"),
        offsetBytes: start,
        nextOffsetBytes,
        // "You have read up to the current end" — NOT "the job ended".
        eof: nextOffsetBytes >= size,
        truncated: meta.truncatedAt !== null,
      },
    };
  }

  /**
   * Terminate a running job's whole process tree. Cancelling a job that already
   * finished is not an error — the reply is simply its current state.
   */
  cancel(req: JobCancelRequest): JobRpcResult {
    const meta = this.loadForRequest(req.jobId);
    if (!meta) return notFound();
    if (meta.status === "running" && meta.pid !== null) {
      this.signalJob(meta);
    }
    return { ok: true, kind: "job", job: this.toSummary(meta, false) };
  }

  // ── Spawning ───────────────────────────────────────────────────────────────

  /**
   * Launch the wrapper, detached, with the job's output going straight to
   * output.log. Returns the wrapper's pid AND its handle: the handle is the only
   * thing that can say, without a procIdentity, whether the process we just
   * started has exited (see retireStartedProcess).
   *
   * The wrapper writes the exit code to disk itself, so the outcome is recorded
   * whether or not the agent is alive when the job ends — that is the entire
   * restart-survival mechanism; buildJobScript (POSIX) and WINDOWS_JOB_WRAPPER
   * are where it is made robust against the ways a command can end its own shell.
   *
   * The two platforms hand the wrapper over differently, for the reasons set out
   * at JOB_LOG_PATH_ENV:
   *
   *  - POSIX: the script IS the command line (`/bin/sh -c`), and the log fd goes
   *    to the child as stdout/stderr alongside the script's own `exec >>`.
   *  - Windows: the script is a pair of FILES in the job's directory, and the
   *    detached `cmd.exe` only launches a second one that runs the first of them
   *    — a detached shell cannot give its redirected stdout to a process it
   *    starts. Nothing of ours is on that command line: both files are named
   *    relative to the launcher's cwd (the job directory) and everything else
   *    travels in the environment, so no path and no command text is parsed by a
   *    shell it is not meant for.
   *    The log fd is not passed and not even held: while we hold one, the
   *    wrapper's `>>` cannot open the same file.
   *
   * On Linux the POSIX wrapper is launched THROUGH `systemd-run --scope`, which
   * execs itself away and leaves the job's `/bin/sh` in a cgroup of its own, so
   * that `systemctl restart aicommander-agent` no longer kills every running job
   * — see job-scope.ts for why that is safe and what it does not disturb. The
   * returned `scope` is the unit name when that happened.
   */
  private spawnJob(
    meta: JobMeta,
    callerEnv: Record<string, string> | undefined,
  ): { child: ChildProcess; pid: number; scope?: string } {
    const dir = path.join(this.jobsRoot, meta.jobId);
    // Rewritten before every spawn — the content of both files is the same for
    // every job, so a stale one cannot exist, and the atomic write means a
    // half-written one cannot either. A failure here fails the start, which is
    // the honest outcome: there would be nothing to run.
    if (isWindows) {
      atomicWriteUtf8(dir, WRAPPER_FILE, WINDOWS_JOB_WRAPPER);
      atomicWriteUtf8(dir, COMMAND_FILE, buildWindowsJobCommandScript(meta.command));
    }
    // What actually gets executed, as a file plus argv.
    //
    // Windows keeps `shell: true` and a single command STRING, byte for byte as
    // it was: that path is delicately measured (see JOB_LOG_PATH_ENV and
    // WINDOWS_JOB_WRAPPER) and nothing here has anything to offer it.
    //
    // POSIX no longer uses `shell: true`. Node implements it as exactly
    // `spawn("/bin/sh", ["-c", script])`, so writing that out changes nothing
    // about how the job runs — but it makes the argv a LIST, which is what lets
    // the scope wrapper be put in front of it without a second round of quoting.
    // The command text still reaches exactly ONE shell, the wrapper's own
    // `/bin/sh -c`: systemd-run passes argv elements to `execvp` untouched, so
    // nothing between us and that shell parses the job's command.
    const launch: { file: string; args: string[] } =
      isWindows
        ? { file: `cmd /d /s /c .\\${WRAPPER_FILE}`, args: [] }
        : { file: "/bin/sh", args: ["-c", buildJobScript(meta.command)] };

    // Null everywhere but Linux-as-root-under-systemd; see job-scope.ts. This is
    // a SYNCHRONOUS read of an already-settled memo — the probe behind it runs on
    // the agent's startup path and do:job_start awaits it — so start() stays
    // synchronous and nothing here can block the frame handler. When the
    // launcher says no we fall back to today's plain detached spawn SILENTLY —
    // the alternative is refusing to run jobs on every machine without systemd,
    // which would be a far larger regression than the one this fixes, and the
    // launcher has already logged the reason once.
    const scopeLauncher = isWindows ? null : this.scopeLauncher();
    let scope: string | undefined;
    if (scopeLauncher) {
      scope = jobScopeUnitName(meta.jobId);
      const wrapped = buildJobScopeArgv({
        systemdRun: scopeLauncher.systemdRun,
        unit: scope,
        description: jobScopeDescription(meta.jobId),
        file: launch.file,
        args: launch.args,
      });
      launch.file = wrapped.file;
      launch.args = wrapped.args;
    }

    // Append mode: a job restarted-into (recovery) or a re-opened log must never
    // truncate output another process still holds an offset into. On Windows the
    // handle is closed again right here, BEFORE the spawn — opening is only how
    // the file comes into existence with our mode on it.
    let logFd: number | null = fs.openSync(path.join(dir, LOG_FILE), "a", PRIVATE_FILE_MODE);
    if (isWindows) {
      fs.closeSync(logFd);
      logFd = null;
    }
    try {
      const child = spawn(launch.file, launch.args, {
        // Windows only: the command is one string for cmd.exe to parse. POSIX
        // spells the same shell out in argv above, so there is nothing left for
        // Node to wrap — and no scope wrapper could survive it if there were.
        shell: isWindows,
        // Windows: the job directory, so `.\wrapper.cmd` and the `.\command.cmd`
        // it runs both resolve; the latter `cd`s to meta.cwd itself. POSIX: the
        // job's cwd directly.
        cwd: isWindows ? dir : meta.cwd,
        env: this.buildEnv(meta, callerEnv),
        // POSIX: stdout and stderr share one fd so the log reads exactly as a
        // terminal would show it, and it covers whatever the shell writes before
        // its own redirect takes effect. Windows: the redirect is the only
        // writer, for the reason above. stdin is closed on both so a job can
        // never block on input.
        stdio: logFd === null ? ["ignore", "ignore", "ignore"] : ["ignore", logFd, logFd],
        // POSIX: own process group, so cancel signals the whole tree (a training
        // run is never a single process). Windows: keep it out of our console so
        // it survives us, and never flash a window.
        detached: true,
        windowsHide: true,
      });
      if (child.pid === undefined) throw new Error("the shell did not start");

      // Prompt bookkeeping while we happen to be alive: releases the GPU lock as
      // soon as the job ends instead of waiting for someone to ask. Purely an
      // optimisation — recovery and refresh reach the same state from disk.
      child.on("exit", (code, signal) => {
        try {
          // Backstop for the two ways a command can outlive the wrapper's own
          // EXIT trap: replacing the shell with `exec`, or installing an EXIT
          // trap of its own over ours. We watched this process exit, so the code
          // is not a guess — but only a real exit is recorded.
          //
          // `signal === null` alone does NOT mean "not killed": a shell that
          // handles SIGTERM (macOS bash) leaves normally with 0, and Windows
          // taskkill hands the terminated process an ordinary code. A cancel we
          // issued therefore has to be excluded by what we KNOW, not by what we
          // observed — see cancelledJobs, and the mac box that reported a job
          // killed at 15% as "exit code 0".
          if (code !== null && signal === null && !this.cancelledJobs.has(meta.jobId)) {
            this.recordExitCode(meta.jobId, code);
          }
          const current = this.readMeta(meta.jobId);
          if (current) this.refresh(current);
        } catch {
          // Best-effort only.
        }
      });
      // A detached job must not be reported as a spawn failure of ours later on;
      // swallow the async error event and let the recovery logic classify it.
      child.on("error", () => undefined);
      // Do not hold the event loop open for a job that outlives this process.
      child.unref();
      // Deliberately NO runtime retry or fallback ladder for a scope launch that
      // fails despite a successful probe. systemd-run's own error message is
      // already the first thing in the job's output.log (it inherited the log
      // fd) — one clear line, measured: `Failed to start transient scope unit:
      // Unit aic-job-….scope was already loaded or has a fragment file.` for the
      // (near-impossible) name collision, `… Interactive authentication
      // required.` if the agent somehow is not root after all. The job records
      // the exit code it died with and the caller sees a stated reason.
      // Re-running the command unscoped
      // after that would mean starting a SECOND process for a job whose first
      // one we cannot prove is gone, on a GPU that is already locked to it.
      return { child, pid: child.pid, scope };
    } finally {
      if (logFd !== null) fs.closeSync(logFd);
    }
  }

  /**
   * Environment for the job: our own, then JOB_ENV_DEFAULTS, then the caller's
   * overrides, then the things we decide ourselves.
   *
   * The defaults go BEFORE the caller's, so they are suggestions an explicit
   * `env` overrides. The last block is applied AFTER the caller's and
   * deliberately overrides it: CUDA_VISIBLE_DEVICES because the lock is what
   * makes exclusive GPU use meaningful, so the reserved card is the one the
   * workload gets; the exit-file and log paths because they are paths a root
   * process writes to and therefore must never come from a relay message. The
   * Windows pair is there for the same reason: the wrapper reads what to run and
   * where from the environment, so a caller must not be able to set either.
   *
   * ERRORLEVEL is a decision of ours too, and the way it is enforced is
   * different from the rest: the job's environment must contain NO variable of
   * that name at all, whatever put it there. The wrapper's `echo %ERRORLEVEL%`
   * is how a job's outcome is recorded, and cmd resolves `%ERRORLEVEL%` from the
   * ENVIRONMENT when a variable of that name exists there, in preference to the
   * real exit status. Measured on the real box (agent 1.0.40, Windows
   * 10.0.26200): the identical job whose child exits 5 recorded 5 normally and 0
   * with `ERRORLEVEL=0` in `env` — a relay message forging a job's exit code.
   *
   * `env` is only the loudest source, not the only one. The line below starts
   * from `process.env`, so an agent that inherited an ERRORLEVEL of its own —
   * from the service wrapper, a parent shell, an operator's `set` — would pass it
   * to EVERY job on the machine and record that one constant as every outcome. So
   * this is not a filter on the caller's block but a sweep of the finished
   * environment: there is no value we want to write there and none we want to
   * preserve, from any source. It runs before the block below only for tidiness —
   * nothing we set ourselves is spelled that way.
   */
  private buildEnv(meta: JobMeta, callerEnv: Record<string, string> | undefined): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env, ...JOB_ENV_DEFAULTS };
    // macOS: the same launchd PATH problem `do:exec` has. The desktop app — and
    // this in-process agent with it — is started by launchd with no
    // EnvironmentVariables, so `process.env.PATH` is /usr/bin:/bin:/usr/sbin:/sbin
    // and homebrew, nvm, conda and docker are simply absent. A training job that
    // runs `python` from a terminal fine then dies with "command not found".
    //
    // Applied BEFORE the caller's block, so an explicit `env.PATH` still wins,
    // exactly like JOB_ENV_DEFAULTS.
    //
    // Unlike the executor, this does NOT wait for the probe. start() is
    // synchronous by contract — its caller is the WS handler that must answer
    // `do:ping` inside AGENT_TIMEOUT_MS, and its reply carries the jobId — and
    // deferring the spawn behind a promise would break the other invariant this
    // file is built on: the record is written before the process exists, so a
    // status poll landing in the gap would read a `running` job with no pid, and
    // refresh would have to either settle it wrongly or invent a fourth state.
    // So we use whatever the memoized probe has resolved SO FAR (applyLoginShellPath
    // is a no-op until then) and start it if nobody has. It has: the probe is
    // started on the agent's startup path (runConnectionLoop, and recover() here)
    // and connection.ts's do:job_start handler AWAITS it before calling start(),
    // so by the time we get here it has resolved or timed out — which is how the
    // synchronous contract above and "the first job also gets the real PATH" hold
    // at the same time.
    void pendingLoginShellPath();
    applyLoginShellPath(env);
    // The other half of the same launchd hole, and for the same reason: a job
    // spawned on macOS inherited an EMPTY LANG, i.e. the C locale, while a
    // `do:exec` command on the very same machine got a real one. A multi-hour
    // training run that writes Polish or Japanese text is exactly the job that
    // cannot afford ASCII-mangled output, so the inconsistency mattered more
    // here than for a short command. Same precedence as PATH — applied BEFORE
    // the caller's block, so an explicit `env.LANG` still wins — and it fails
    // open: with nothing resolved it sets a sane default and never throws, so
    // the synchronous contract above is untouched.
    applyLoginShellLocale(env);
    // TERM, same precedence and the same reason it exists for `do:exec` — see
    // applyNonInteractiveTerm. It matters MORE for a job than for a command: a
    // multi-hour build or training run writes the longest logs on the machine,
    // and remote_job_logs pages them back to a model that has to read every
    // escape sequence a colour-capable TERM would have invited. An inherited or
    // caller-supplied TERM still wins.
    applyNonInteractiveTerm(env);
    if (callerEnv && typeof callerEnv === "object") {
      for (const [key, value] of Object.entries(callerEnv)) {
        // Silently skip non-string values instead of coercing them: a frame that
        // is not shaped as we expect must not turn into a surprising env var.
        if (typeof key === "string" && key !== "" && typeof value === "string") {
          env[key] = value;
        }
      }
    }
    // Case-INSENSITIVELY, and on every platform: Windows looks environment
    // variables up without regard to case, so a lowercase `errorlevel` would
    // forge the exit code just as well, and Node's env object here is a plain
    // object that would happily hold both spellings side by side. Dropping it off
    // Windows too costs nothing — no POSIX shell reads it — and keeps the same
    // request from meaning two different things per platform.
    for (const key of Object.keys(env)) {
      if (key.toUpperCase() === "ERRORLEVEL") delete env[key];
    }
    const home = this.resolveJobHome(meta.cwd, typeof callerEnv?.["HOME"] === "string");
    if (home) env["HOME"] = home;
    if (meta.gpuIndex !== null) env["CUDA_VISIBLE_DEVICES"] = String(meta.gpuIndex);
    env[JOB_EXIT_PATH_ENV] = path.join(this.jobsRoot, meta.jobId, EXIT_FILE);
    env[JOB_LOG_PATH_ENV] = path.join(this.jobsRoot, meta.jobId, LOG_FILE);
    // Windows only: where WINDOWS_JOB_WRAPPER runs. The command itself is NOT
    // passed here any more — it is written into the command file, which is what
    // gives it the one whole-line expansion round the contract promises (see
    // buildWindowsJobCommandScript). Keeping it out of the environment also keeps
    // the command string away from every child process that inherits it. The
    // POSIX script carries both itself, and its environment stays as it was.
    if (isWindows) {
      env[JOB_CWD_ENV] = meta.cwd;
    }
    return env;
  }

  /**
   * Decide the job's HOME.
   *
   * On Linux the agent runs as root under systemd, so ML tooling would put
   * ~/.cache/huggingface, ~/.cache/torch and ~/.triton into /root: invisible to
   * the user who owns the machine and able to fill the system partition with tens
   * of gigabytes of model weights nobody can find. So:
   *  1. a caller-supplied HOME always wins (explicit intent, never second-guessed);
   *  2. non-root, or Windows, keeps the inherited HOME — it is already the right
   *     user's, and the Windows service model is different enough not to guess;
   *  3. as root we take the home of the user who OWNS the job's cwd, which is the
   *     user whose workspace this is;
   *  4. failing that, a shared directory inside the jobs root — still wrong-ish,
   *     but predictable, on the volume the operator chose for job data, and
   *     shared across jobs so a model cache is downloaded once.
   *
   * This picks a PATH only. It never changes the uid a job runs as (that is
   * always the agent's own, exactly as for `do:exec`), so no privilege decision
   * is being taken from a relay message — and a caller who wanted a specific HOME
   * could simply have passed one.
   *
   * What a relay message DOES influence, through `cwd`, is whose on-disk
   * configuration the root job then reads and writes: that user's dotfiles,
   * ~/.config, ~/.cache, and anything a tool auto-loads from HOME. We keep it,
   * for two reasons. It is not a new capability — the same caller already chose
   * the COMMAND this root process runs, so it can read or write any of those
   * paths directly, with or without HOME. And constraining it to a cwd we own
   * would delete the behaviour rather than tighten it: everything under the jobs
   * root is created by us as root, so rule 3 would never fire and every job
   * would land on the shared cache — the "/root fills up with model weights"
   * problem this exists to solve. HOME therefore follows the workspace the
   * caller explicitly pointed at, which is also the least surprising answer.
   */
  private resolveJobHome(cwd: string, callerSetHome: boolean): string | undefined {
    if (callerSetHome) return undefined;
    if (isWindows) return undefined;
    if (typeof process.getuid !== "function" || process.getuid() !== 0) return undefined;

    const ownerHome = homeOfPathOwner(cwd);
    if (ownerHome) return ownerHome;

    const shared = path.join(this.jobsRoot, SHARED_HOME_DIR);
    try {
      ensurePrivateDir(shared);
      return shared;
    } catch {
      // Fall back to the inherited HOME rather than failing the job over a cache
      // directory.
      return undefined;
    }
  }

  /**
   * Signal a job's whole process tree, SIGTERM first and SIGKILL after a grace
   * window, mirroring executor.ts: a job that ignores SIGTERM must still reach a
   * terminal state rather than hang around forever holding a GPU.
   */
  private signalJob(meta: JobMeta): void {
    const pid = meta.pid;
    if (pid === null) return;
    // Remember BEFORE signalling, not after: the child can be gone and its exit
    // watcher run before this function returns, and a cancel recorded too late is
    // a cancel that still reports "exit code 0". See cancelledJobs.
    this.cancelledJobs.add(meta.jobId);
    const send = (signal: "SIGTERM" | "SIGKILL") => {
      // Re-check identity before EVERY signal: the escalation fires seconds later,
      // by which time the job may have exited and the pid been recycled. Signalling
      // a recycled pid would kill an unrelated process — and we signal a whole
      // process GROUP, as root, so that is a foreign process TREE. This is the one
      // path that must fail closed even where a read is allowed to guess: an
      // identity we cannot confirm is not signalled at all.
      if (this.verifyJobProcess(meta) !== "ours") return;
      try {
        if (isWindows) {
          // taskkill /T kills the descendants too; /F forces it.
          spawn("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
        } else {
          // Negative pid = the process group led by the detached wrapper.
          process.kill(-pid, signal);
        }
      } catch {
        // Process group already gone — nothing to signal.
      }
    };

    send("SIGTERM");
    const escalation = setTimeout(() => {
      send("SIGKILL");
      // And, on a scoped job, empty the scope's cgroup as well.
      //
      // SIGKILL to the process GROUP does not reach a descendant that called
      // setsid, and with scopes that descendant no longer dies at the next
      // service restart either — it lives in the job's own unit. Measured on
      // Ubuntu 24.04.4 / systemd 255: a runaway kept running and kept writing to
      // the job's log after the wrapper was killed, while refresh() saw the pid
      // gone, settled the job and released its GPU lock. See killJobScope, which
      // is fire-and-forget and never throws, so a cancel cannot fail on it.
      //
      // Unconditional, unlike `send`: the unit name is derived from the job id
      // and belongs to this job alone, so it stays safe to kill even once the
      // wrapper's pid can no longer be confirmed as ours — which is exactly the
      // escaped-descendant case.
      if (meta.scope !== undefined) killJobScope(meta.scope);
    }, KILL_ESCALATION_MS);
    // Never keep the process alive just to escalate a kill.
    escalation.unref?.();
  }

  // ── State reconciliation ───────────────────────────────────────────────────

  /**
   * Bring a job's recorded state in line with what is on disk right now. This is
   * the single place a status can change, and it is called from every read path,
   * so an agent that has been down for a week reports the truth on the first call.
   *
   * Three branches, exactly as specified:
   *  1. `exit` exists           ⇒ exited, with the code the wrapper wrote;
   *  2. a process is alive under the pid ⇒ still running (adopted across our
   *     restart), whether or not we can prove WHICH process it is — see below;
   *  3. nothing is alive there  ⇒ `unknown`. NOT "exited": we have no exit code
   *     and no way to obtain one, and reporting a success we cannot prove is the
   *     worse failure. A job killed with SIGKILL (including by our own cancel
   *     escalation) lands here too — its wrapper never got to write the file.
   *
   * With one job this cannot answer for: one whose process we started but never
   * managed to write down (retiringJobs). Every branch above needs a pid it can
   * trust, and that is exactly what is missing there — so classifying it would
   * mean settling a job whose process may still be running, releasing a GPU lock
   * that is still needed. It therefore stays `running` until the exit that
   * retireStartedProcess is waiting for, which is the only fact that can end it.
   */
  private refresh(meta: JobMeta): JobMeta {
    if (this.retiringJobs.has(meta.jobId)) return meta;
    if (meta.status !== "running") {
      // Terminal on disk, and possibly terminal since long before this agent
      // started — in which case no read path has ever weighed its log against
      // the cap. Do it once, the first time we see the record: after that the
      // job cannot write another byte, so the answer can never change (and a
      // capped record short-circuits inside checkLogCap anyway).
      if (!this.settledJobs.has(meta.jobId)) this.checkLogCap(meta);
      this.markSettled(meta, false);
      return meta;
    }

    const dir = path.join(this.jobsRoot, meta.jobId);
    const exitPath = path.join(dir, EXIT_FILE);
    const observed = readExitFile(exitPath);
    if (observed) {
      // A job WE cancelled does not get to claim an exit code, whoever wrote it.
      // Blocking the agent's own observation was not enough: the wrapper's EXIT
      // trap also runs when the shell leaves in response to the signal, and it
      // writes `$?` — which is 0 for a shell that handled SIGTERM and left
      // cleanly. That is how a Mac reported a job killed at tick 45 of 300 as
      // "exit code 0".
      //
      // And the code would be worthless even when written honestly: it describes
      // how the SHELL departed, never whether the work finished. A cancelled job
      // is `unknown` — "cancelled, outcome unknown" — which is what every
      // description of this tool promises and what Linux already answered.
      //
      // Only a job that was RUNNING when the cancel was issued is in this set
      // (signalJob is not reached otherwise), so a job that had already finished
      // keeps its real exit code, as its own test requires.
      if (this.cancelledJobs.has(meta.jobId)) return this.settle(meta, "unknown", null, observed.at);
      return this.settle(meta, "exited", observed.code, observed.at);
    }

    // Anything except a pid we can prove is GONE holds the job here. An
    // `unverifiable` verdict is not absence: kill(pid, 0) has just succeeded, so
    // SOMETHING is alive under our number and all we failed at is reading its
    // start time — a /proc that would not open, a `ps` that could not fork,
    // exactly what a loaded GPU box produces. Settling on that releases the card
    // (see settle) under a training run that is still on it, so the next
    // job_start is granted the same GPU and two runs collide in the OOM the lock
    // exists to prevent — triggered by nothing more than a routine job_status
    // poll. It also makes the job terminal, and cancel will not signal a
    // terminal job, so the surviving run becomes unkillable through the API too.
    //
    // Holding instead costs a card stranded until that pid dies, which is the
    // trade this file makes everywhere else, and it is not a state nothing can
    // leave: a pid that genuinely ends reads as `gone` on the very next poll —
    // no timer, no bookkeeping — and until then the job is simply `running`,
    // which is what it looks like to every caller anyway.
    if (this.verifyJobProcess(meta) !== "gone") {
      this.checkLogCap(meta);
      return meta;
    }

    // Close the race: the wrapper writes `exit` and only THEN exits, so a process
    // that has just disappeared may have completed the write between our two
    // checks. Re-read before we condemn the job to `unknown`.
    const late = readExitFile(exitPath);
    if (late) {
      return this.settle(meta, "exited", late.code, late.at);
    }
    return this.settle(meta, "unknown", null, this.estimateVanishedEndedAt(meta), true);
  }

  /**
   * When a job whose process vanished WITHOUT an exit marker probably ended.
   *
   * This is the agent-restart / hard-kill branch, and the only one with nothing
   * authoritative to read: `exited` jobs get the exit file's mtime, which is the
   * real instant. Here the honest upper bound is "now" — but now is when WE
   * noticed, and nobody looks at a job the moment it dies: measured skew of the
   * old `Date.now()` was ~14 s on Linux and 1 m 52 s on Windows (an agent that
   * had been down over a reboot would report the restart, hours late).
   *
   * The log's last write is a better lower bound, and it is already at hand
   * (checkLogCap stats the same path). Two guards, both about not trading one
   * wrong direction for the other:
   *  - a job that never wrote a byte has a log mtime equal to its SPAWN, so
   *    reporting it would say "ended ≈ started" about a run that may have worked
   *    silently for hours. An empty log therefore falls back to `now`.
   *  - the mtime is floored at `startedAt` and capped at `now`, so a clock step
   *    or a copied job directory cannot produce an ending before the beginning
   *    or in the future.
   *
   * WINDOWS CAVEAT, unfixed: NTFS defers last-write-time updates while a handle
   * is open, and the wrapper holds its `>>` redirect for the job's whole life, so
   * the mtime there may itself be minutes stale — this may not move the 1 m 52 s
   * number at all. That is precisely why the estimate is also MARKED as one
   * (`endedAtApproximate` on the wire) instead of being presented as a fact: an
   * estimate that quietly improves is still a claim of precision we do not have.
   *
   * Retention footnote: `endedAt` is what pruneExpired ages against, so an
   * earlier estimate shortens a vanished job's retention by exactly the skew it
   * removes — seconds to minutes off seven days, which is not worth a second
   * timestamp to preserve.
   */
  private estimateVanishedEndedAt(meta: JobMeta): number {
    const now = Date.now();
    const logPath = path.join(this.jobsRoot, meta.jobId, LOG_FILE);
    let mtimeMs: number;
    try {
      const stat = fs.statSync(logPath);
      // A silent job proves nothing about when it stopped.
      if (stat.size === 0) return now;
      mtimeMs = stat.mtimeMs;
    } catch {
      // No log to ask (a pruned or unreadable directory) — "when we noticed" is
      // then genuinely all we have.
      return now;
    }
    if (!Number.isFinite(mtimeMs)) return now;
    // Rounded here rather than at the wire so meta.json holds an integer too;
    // wireEpochMs still re-checks it before the value leaves the machine.
    const ended = Math.round(mtimeMs);
    if (!Number.isSafeInteger(ended)) return now;
    const floor = Number.isSafeInteger(meta.startedAt) ? meta.startedAt : 0;
    return Math.min(Math.max(ended, floor), now);
  }

  /**
   * Persist a terminal status and release whatever the job was holding. The
   * single door out of `running`, which is why the retirement case is checked
   * HERE rather than at each of refresh's three exits.
   *
   * `approximate` says the caller ESTIMATED `endedAt` (the vanished-process
   * branch) rather than read it off an exit marker. It is recorded on the record
   * itself so the claim survives a restart — a later reader of the settled
   * meta.json has no way to tell where the number came from otherwise — and it is
   * written as an explicit `false` for the observed cases rather than left off,
   * so `{...meta}` cannot carry a stale `true` from some earlier state.
   */
  private settle(
    meta: JobMeta,
    status: JobStatus,
    exitCode: number | null,
    endedAt: number,
    approximate = false,
  ): JobMeta {
    if (meta.retiring === true) return this.discardRetired(meta, endedAt);
    const settled: JobMeta = { ...meta, status, exitCode, endedAt, endedAtApproximate: approximate };
    // The job's LAST bytes land between the previous poll and this one, so this
    // is the last chance to weigh the finished log against the cap — and for a
    // job that ran and exited without ever being polled, the only one. Written
    // with the settled record below rather than on its own.
    this.checkLogCap(settled, false);
    if (settled.gpuIndex !== null) this.releaseGpuLock(settled.gpuIndex, settled.jobId);
    this.writeMeta(settled);
    this.markSettled(settled, true);
    // The cancel note has done its work once the job is terminal: the status is
    // now on disk, and keeping the id would only grow a set for the life of the
    // process.
    this.cancelledJobs.delete(settled.jobId);
    return settled;
  }

  /**
   * Note that a job has reached a terminal state — and, on a scoped job, empty
   * what is left of its cgroup.
   *
   * WHY THE REAP HANGS OFF THE TERMINAL TRANSITION. Cancel is the rarer half of
   * the escaped-descendant problem; the likelier one is a job that ENDS ON ITS
   * OWN while a descendant that called `setsid` keeps running. The wrapper is
   * then gone, so refresh() settles the job and releases its GPU lock in the
   * same breath — handing the card and the concurrency slot to the next job
   * while a live root process is still on it, which is the exact OOM the lock
   * exists to prevent. Before scopes, `KillMode=control-group` reaped that
   * descendant at the next agent restart; inside its own scope it no longer
   * dies with the service, so nothing would ever end it (measured on Ubuntu
   * 24.04.4 / systemd 255 — see killJobScope).
   *
   * THE TRADE-OFF, stated because it IS a behaviour change: such a descendant
   * survives on macOS and Windows (nothing reparents it into anything we own),
   * and it survived on Linux too until the next agent restart. We end it at the
   * settle instead, because that is the instant its card is given away. macOS
   * and Windows are untouched: they never record a `scope`, so the branch below
   * is never taken there.
   *
   * EXACTLY ONCE, by construction: settledJobs is the record of "this job has
   * reached a terminal state", and the kill hangs off ADDING to it. Every read
   * path calls refresh() constantly (status, list, countRunningJobs), so killing
   * on each of those would be a root `systemctl kill` per poll. The one place
   * the id is removed again (removeJobDir) deletes the record with it, so there
   * is nothing left to refresh and re-add. Retired starts do not come through
   * here at all — settle() hands them to discardRetired, and their scope is
   * reaped by retireStartedProcess's escalation.
   *
   * killJobScope is fire-and-forget and never throws, so this can never turn a
   * successful status or list into an error, and an already-collected scope (the
   * overwhelmingly common case — the job ended and took its scope with it)
   * answers `Unit not loaded` and stays a silent no-op.
   *
   * WHY `transition` DECIDES WHICH REAP. settledJobs has two entrances. This one
   * — settle(), the running→terminal transition — is the moment the GPU lock is
   * released, so the survivor has to be ended right there and gets the immediate
   * kill. The other is refresh()'s "already terminal on disk" branch, i.e.
   * records left by a PREVIOUS agent, and killing per record there fired one
   * root `systemctl kill` per retained job at startup — a spawn burst on the
   * frame handler's thread, introduced and removed once already. Those go to
   * reapLeftoverJobScope, which coalesces the whole recovery pass into a single
   * deferred `systemctl list-units` and kills only the scopes that answer it.
   * See job-scope.ts, where the failure and the fix are written down.
   */
  private markSettled(meta: JobMeta, transition: boolean): void {
    if (this.settledJobs.has(meta.jobId)) return;
    this.settledJobs.add(meta.jobId);
    if (meta.scope === undefined) return;
    if (transition) killJobScope(meta.scope);
    else reapLeftoverJobScope(meta.scope);
  }

  /**
   * The end of a retired start, once its process is provably gone.
   *
   * There is no job here to report: start() already answered its caller with a
   * failure, and the record survived only to keep the process visible and its
   * card reserved while it was being stopped. So we finish exactly what the
   * in-process exit handler in retireStartedProcess would have done — release
   * the card, delete the record — rather than leave behind a phantom `unknown`
   * job nobody ever started, sitting on the machine for a retention window.
   *
   * The returned value is never written back: its directory is gone. It exists
   * only so the caller that triggered this refresh stops being told "running".
   */
  private discardRetired(meta: JobMeta, endedAt: number): JobMeta {
    this.abandonStart(meta.jobId, meta.gpuIndex);
    return { ...meta, status: "unknown", exitCode: null, endedAt };
  }

  /**
   * "Is the process behind meta.pid the one we started?", with the third answer
   * — we could not tell — kept distinct so each caller can decide how to fail.
   *
   * `kill(pid, 0)` alone answers "does some process have this pid", which after
   * an agent restart (or simply a long-lived job on a busy box) is not the same
   * question. So the process START TIME captured at spawn is compared as well:
   * Linux reads it from /proc, macOS from `ps -o lstart=` and Windows from the
   * process CreationDate (see readProcIdentity). A recycled pid therefore reads
   * as `gone` rather than as somebody else's process wearing our job's name.
   *
   * `unverifiable` means a live pid we could not put a name to: the probe came
   * back empty. On Windows that is a standing condition — the creation time
   * needs a wmic/PowerShell a hardened box may not have — and on POSIX a
   * transient one, a /proc or `ps` that could not answer this instant. Both
   * callers treat it as the open question it is, in the direction that claims
   * least: a READ holds the job as running rather than inventing an ending it
   * cannot see (refresh), and the write path — signalling a process GROUP, often
   * as root — refuses to act at all (signalJob). Neither ever concludes "gone"
   * from it, which is the whole point of keeping it distinct from `gone`.
   *
   * One deliberate omission: no retry. A second probe of a pid whose first probe
   * just failed costs another fork on a machine that is already out of them, on
   * the thread that must answer `do:ping` — and it would only shorten a hold
   * that is harmless while it lasts. captureProcIdentity retries because a miss
   * THERE costs the whole start; a miss here costs nothing but precision.
   */
  private verifyJobProcess(meta: JobMeta): "ours" | "gone" | "unverifiable" {
    if (meta.pid === null) return "gone";
    try {
      process.kill(meta.pid, 0);
    } catch (err) {
      // This kill is only the LIVENESS gate — the identity comparison below is
      // the authority on WHOSE process the pid names — so an errno may end the
      // job here only when it proves ABSENCE. Node surfaces the raw errno as
      // `code` on the thrown Error (verified: "kill ESRCH" / "kill EPERM",
      // syscall "kill"), and the errnos do not agree with each other:
      //  - ESRCH: no process has this pid. The one confident "gone" the gate
      //    may give on its own.
      //  - EPERM: a process EXISTS under this pid — we merely may not signal
      //    it. That is a fact about OUR privileges, not about the job: an
      //    agent started as a lesser user against a root service's jobs root
      //    (a hand start, a QNAP-style manual run) draws EPERM for every live
      //    root-owned job it adopted. An early "gone" here settled those jobs
      //    and released their GPU locks under still-running training runs, so
      //    EPERM falls THROUGH to the identity check exactly as a successful
      //    kill does. That check keeps every answer honest: /proc (and ps)
      //    can read a foreign process's start time, so a recycled pid still
      //    reads `gone`, and where the probe cannot see the process (Windows
      //    without query rights) it degrades to the `unverifiable` hold this
      //    file takes everywhere else.
      //  - anything else, or an error carrying no code, proves neither
      //    presence nor absence: `unverifiable`, never a guess at either
      //    extreme.
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ESRCH") return "gone";
      if (code !== "EPERM") return "unverifiable";
    }
    const identity = readProcIdentity(meta.pid);
    if (identity === null || meta.procIdentity === null) return "unverifiable";
    // Never raw string equality: the probe's raw rendering is not stable for a
    // fixed process (Windows answers via wmic OR PowerShell in different
    // formats; macOS used to render a zone-dependent wall time and now probes
    // zone-free), and a format-only difference must read as the open question
    // it is, not as the confident `gone` that releases a GPU lock under a live
    // job. The comparator also owns both legacy cases: a pre-canonical token
    // still on disk does not parse, and a macOS `epoch:` token minted by the
    // old local-time inversion is a different KIND from the zone-free `utc:`
    // probe — either way `unverifiable`, held, never settled.
    switch (compareProcIdentity(meta.procIdentity, identity)) {
      case "match":
        return "ours";
      case "mismatch":
        return "gone";
      default:
        return "unverifiable";
    }
  }

  /**
   * Enforce JOB_MAX_LOG_BYTES on a job's log.
   *
   * Deliberately does NOT kill the job — killing a 5-hour training run because it
   * was chatty is precisely the `do:exec` behaviour jobs exist to remove. We
   * append one notice, record the cut-off point, and stop SERVING beyond it.
   *
   * The cut-off is the CAP, never "wherever the file happened to be when we first
   * looked". Recording the observed size meant a job that wrote a gigabyte
   * between two polls got a gigabyte cut-off, and every reply about it — its
   * `logBytes`, and the paging that follows — then served far past the 256 MiB
   * this agent advertises. Clamping is what makes the promise below true rather
   * than usually true. Its one cost: when the file had ALREADY overshot when we
   * noticed, the notice sits at the physical end, past the cut-off, so it is
   * visible to someone reading the file on the machine but not to a caller paging
   * to eof — who is told by `truncated` on every reply either way.
   *
   * We cannot stop the WRITING: the wrapper holds its own append redirect onto
   * the path (`>>`, on both platforms) and POSIX jobs additionally hold the
   * output fd handed to them at spawn. There is no way to take either back
   * without killing the process or breaking its stdout mid-run. So be precise
   * about what is and is not bounded here. What we SERVE is bounded: never more
   * than JOB_MAX_LOG_BYTES of the job's output plus the one notice, and on
   * Windows a RUNNING job's log cannot be appended to at all — the wrapper's
   * handle denies our write, and the notice is then simply absent rather than
   * accounted for (see below). What is on
   * DISK is not: it is bounded only by what the job writes before it ends, and is
   * reclaimed when its directory ages out of JOB_RETENTION_MS — which, since the
   * prune also runs on activity and not just at startup (maybePrune), is a promise
   * the agent actually keeps on a box that stays up for months. A job that outruns
   * the cap by hundreds of gigabytes before it ends will still fill the volume,
   * and that is accepted: see above for why it is not killed, and truncating a
   * file another process appends to corrupts every offset a reader holds.
   *
   * Called from the read paths only — no timer — but from ALL of them, including
   * the two terminal ones in refresh/settle. Checking only the "still running"
   * branch meant a job that exited before it was ever polled never had the cap
   * evaluated at all: its record went straight to terminal, `truncated` stayed
   * false however large the file was, and every later read served the whole thing.
   * That is not the "cap noticed late" case this comment shrugs at — the cap never
   * engaged.
   *
   * The cut-off counts the notice ONLY when the notice was actually appended.
   * Counting it unconditionally meant that wherever the append fails — Windows,
   * for every job still running, which is precisely the case the cap exists for —
   * the extra bytes were served as if they were the notice, so a reader paging to
   * the boundary got that many bytes of raw output presented as our sentence, and
   * the notice itself never appeared. The cap still engages either way; only the
   * claim about the notice is dropped.
   *
   * `persist` is false for the one caller that is about to write `meta` itself
   * (settle), so a settling job costs one meta.json write rather than two.
   */
  private checkLogCap(meta: JobMeta, persist = true): void {
    if (meta.truncatedAt !== null) return;
    const logPath = path.join(this.jobsRoot, meta.jobId, LOG_FILE);
    const size = fileSize(logPath);
    if (size < JOB_MAX_LOG_BYTES) return;
    let noticeBytes = 0;
    try {
      fs.appendFileSync(logPath, TRUNCATION_NOTICE);
      noticeBytes = Buffer.byteLength(TRUNCATION_NOTICE, "utf8");
    } catch {
      // The cap still applies; we just do not pretend a notice is there.
    }
    meta.truncatedAt = Math.min(size, JOB_MAX_LOG_BYTES) + noticeBytes;
    if (persist) this.writeMeta(meta);
  }

  // ── GPU locks ──────────────────────────────────────────────────────────────

  private gpuLockPath(index: number): string {
    return path.join(this.jobsRoot, gpuLockFileName(index));
  }

  /**
   * Reserve a card. Returns null on success, or the jobId currently holding it.
   *
   * `O_EXCL` (`wx`) makes the create-or-fail atomic, so two starts racing for the
   * same card cannot both win. On contention we check the recorded holder: a job
   * that is gone or finished must not wedge a GPU forever (an agent crash used to
   * be enough), so its lock is reaped and the acquisition retried exactly once —
   * bounded, so two agents cannot ping-pong stealing from each other.
   */
  private acquireGpuLock(index: number, jobId: string, retried = false): string | null {
    const lockPath = this.gpuLockPath(index);
    try {
      const fd = fs.openSync(lockPath, "wx", PRIVATE_FILE_MODE);
      try {
        fs.writeFileSync(fd, jobId);
      } finally {
        fs.closeSync(fd);
      }
      return null;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
        throw new JobError(`Could not reserve GPU ${index}: ${errText(err)}`);
      }
    }

    const lock = readLockHolder(lockPath);
    // A lock file that exists but could not be READ may be a live job's
    // reservation — EMFILE/EIO on a loaded box is precisely when this races a
    // running training run — so it is answered "busy", never stolen. Reaping
    // needs proof, and "we could not look" is the opposite of proof.
    if (lock.kind === "unreadable") return "unknown";
    if (lock.kind === "holder" && this.gpuHolderState(lock.jobId) !== "gone") {
      // `running` is plainly busy; `unknown` (the holder's record exists but
      // would not read) fails closed the same way, because the alternative is
      // putting a second job on a card whose first job we merely failed to see.
      return lock.jobId;
    }
    if (retried) {
      // Someone re-took the lock in the microscopic window between our reap and
      // our retry. Report it as busy rather than looping.
      return lock.kind === "holder" ? lock.jobId : "unknown";
    }
    try {
      fs.rmSync(lockPath, { force: true });
    } catch {
      return lock.kind === "holder" ? lock.jobId : "unknown";
    }
    return this.acquireGpuLock(index, jobId, true);
  }

  /** Release a card, but only if WE hold it — never steal another job's lock. */
  private releaseGpuLock(index: number, jobId: string): void {
    const lockPath = this.gpuLockPath(index);
    const lock = readLockHolder(lockPath);
    if (lock.kind !== "holder" || lock.jobId !== jobId) return;
    try {
      fs.rmSync(lockPath, { force: true });
    } catch {
      // Best-effort; a leftover lock is reaped on the next start or recovery.
    }
  }

  /**
   * Startup stale-lock reaping: drop every lockfile whose holder is PROVABLY
   * not a running job — a terminal record, a directory that was pruned, or
   * content that was never a job id (a truncated write, a manually created
   * file). A lock or record that merely could not be read is left alone: the
   * next recovery re-asks, and until then a held card is recoverable while a
   * double-booked one is not.
   */
  private reapGpuLocks(): void {
    let entries: string[];
    try {
      entries = fs.readdirSync(this.jobsRoot);
    } catch {
      return;
    }
    for (const entry of entries) {
      // Recognised by the same helper that BUILDS the name, so a lockfile we can
      // create can never be one this sweep skips over.
      if (!isGpuLockFileName(entry)) continue;
      const lockPath = path.join(this.jobsRoot, entry);
      const lock = readLockHolder(lockPath);
      if (lock.kind === "absent" || lock.kind === "unreadable") continue;
      if (lock.kind === "holder" && this.gpuHolderState(lock.jobId) !== "gone") continue;
      try {
        fs.rmSync(lockPath, { force: true });
      } catch {
        // Best-effort.
      }
    }
  }

  /**
   * Whether the job a GPU lock names still owns its reservation — the reaping
   * question, with the load-bearing third answer the reapers act on.
   *
   * This path never goes through settle(), so none of the guards there cover
   * it: folding "could not read the holder's record" into "the holder is not
   * running" made an EMFILE or EIO on a loaded box free a live job's card and
   * double-book it — the same defect the settle path was cured of, reached
   * around the side. Hence:
   *  - `gone` ONLY on evidence: a record that reads and is terminal, or a
   *    record that provably is not there (pruned, or a crash before it was
   *    written). Absence must keep reaping, or one crash strands a card until
   *    a human notices — the failure the reap exists to prevent.
   *  - `unknown` when the record exists but would not read or validate. The
   *    holder may be mid-training; the reapers hold the lock and re-ask later.
   * The refresh inside is itself fail-closed (an unverifiable pid stays
   * `running`), so a live-but-unprovable holder also lands on the held side.
   */
  private gpuHolderState(jobId: string): "running" | "gone" | "unknown" {
    const read = this.readMetaState(jobId);
    if (read.kind === "absent") return "gone";
    if (read.kind === "unreadable") return "unknown";
    return this.refresh(read.meta).status === "running" ? "running" : "gone";
  }

  /**
   * Project on-disk state onto the wire shape.
   *
   * `command` is included ONLY when the caller explicitly asked for it — a
   * command line is user payload, and the payload-safety invariant keeps it out
   * of every reply that did not request it. `logBytes` is the size a caller may
   * actually page through (capped at the truncation point), so it can size its
   * `job_logs` calls without a probe read.
   *
   * This is the ONE place a JobSummary is built, which makes it the one place
   * that can guarantee every summary MATCHES THE PROTOCOL. The relay validates
   * each record and rejects the whole reply when a single field is off, so a
   * value that is merely plausible on disk — a fractional epoch-ms from a file
   * mtime, a `undefined` where the schema demands a literal `null` (which
   * JSON.stringify then drops entirely), a NaN out of an unreadable stat — costs
   * the caller the entire answer. So nothing is copied straight through: every
   * field either goes through a normaliser that can only ever emit a value the
   * schema accepts — including the LENGTH bounds, since the relay rejects an
   * over-long `name` or `command` exactly as hard as a malformed number — or is
   * already constrained at its source in a way the relay's check cannot fail
   * (`jobId` against JOB_ID_PATTERN and `status` against the three literals, both
   * in isJobMeta). The record therefore cannot be built invalid, rather than
   * being checked for validity afterwards.
   */
  private toSummary(meta: JobMeta, includeCommand: boolean): JobSummary {
    const size = fileSize(path.join(this.jobsRoot, meta.jobId, LOG_FILE));
    const truncatedAt = wireByteCount(meta.truncatedAt);
    return {
      jobId: meta.jobId,
      name: wireBoundedString(meta.name, JOB_WIRE_MAX_NAME_CHARS),
      status: meta.status,
      exitCode: wireInteger(meta.exitCode),
      // The one field with no `null` alternative in the schema. A record whose
      // startedAt is unusable is a broken record, but answering "epoch" about
      // it is still better than an unparseable reply that hides every OTHER job
      // in the same list.
      startedAt: wireEpochMs(meta.startedAt) ?? 0,
      endedAt: wireEpochMs(meta.endedAt),
      // Only ever sent as `true`, and only alongside an endedAt that survived
      // wireEpochMs: the field's whole job is to stop a rendered timestamp
      // claiming a precision it does not have, and an explicit `false` would
      // just be bytes saying "as usual". Optional on the wire (see JobSummary),
      // so an older relay drops it and renders exactly what it renders today.
      ...(meta.endedAtApproximate === true && wireEpochMs(meta.endedAt) !== null
        ? { endedAtApproximate: true }
        : {}),
      gpuIndex: wireGpuIndex(meta.gpuIndex),
      logBytes: truncatedAt !== null ? Math.min(wireByteCount(size) ?? 0, truncatedAt) : wireByteCount(size) ?? 0,
      truncated: meta.truncatedAt !== null,
      ...(includeCommand ? { command: wireBoundedString(meta.command, JOB_WIRE_MAX_COMMAND_CHARS) } : {}),
    };
  }

  // ── Disk helpers ───────────────────────────────────────────────────────────

  /**
   * Resolve a CALLER-SUPPLIED jobId to fresh state, or null.
   *
   * This is the only door relay input has into a path join, so validation happens
   * here and nowhere else. A malformed id (`../../etc`, an empty string, a
   * different case) is indistinguishable from an unknown one in the reply, so a
   * caller cannot use the difference to probe the filesystem.
   */
  private loadForRequest(jobId: unknown): JobMeta | null {
    if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) return null;
    const meta = this.readMeta(jobId);
    if (!meta) return null;
    return this.refresh(meta);
  }

  private listJobIds(): string[] {
    try {
      return fs.readdirSync(this.jobsRoot).filter((entry) => JOB_ID_PATTERN.test(entry));
    } catch {
      return [];
    }
  }

  private listMetas(): JobMeta[] {
    const metas: JobMeta[] = [];
    for (const jobId of this.listJobIds()) {
      const meta = this.readMeta(jobId);
      if (meta) metas.push(meta);
    }
    return metas;
  }

  /** Read + validate meta.json. Anything unreadable or unrecognised is null. */
  private readMeta(jobId: string): JobMeta | null {
    const read = this.readMetaState(jobId);
    return read.kind === "ok" ? read.meta : null;
  }

  /**
   * readMeta with the reason for a miss kept distinct, because one caller —
   * lock reaping via gpuHolderState — must act OPPOSITELY on the two reasons:
   *  - `absent`: the record provably is not there (ENOENT/ENOTDIR — the job
   *    directory was pruned, or never finished being created). Evidence.
   *  - `unreadable`: something IS there but could not be read or believed —
   *    EMFILE/EIO under load, a permissions change, a half-corrupted JSON.
   *    Not evidence of anything about the job, least of all that it ended.
   * Every other caller flattens both to null: for status/list/prune, "cannot
   * read the record" and "no record" already lead to the same held/skipped
   * outcome, so only the reaping path pays for the distinction.
   */
  private readMetaState(
    jobId: string,
  ): { kind: "ok"; meta: JobMeta } | { kind: "absent" } | { kind: "unreadable" } {
    if (!JOB_ID_PATTERN.test(jobId)) return { kind: "absent" };
    try {
      const raw = fs.readFileSync(path.join(this.jobsRoot, jobId, META_FILE), "utf8");
      const parsed: unknown = JSON.parse(raw);
      // A record that exists but does not validate is UNREADABLE, not absent:
      // corruption or a future schema is not proof its process ended, and the
      // directory itself ages out via pruneUnreadable, after which the record
      // really is absent and a held lock becomes reapable.
      return isJobMeta(parsed) && parsed.jobId === jobId
        ? { kind: "ok", meta: parsed }
        : { kind: "unreadable" };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
      // JSON.parse throws SyntaxError (no code): the file was read, so it
      // exists — unreadable, same as an EMFILE/EIO that never got that far.
      return { kind: "unreadable" };
    }
  }

  /**
   * Persist meta.json atomically (temp file + rename), so a reader — including a
   * recovery pass after a power cut mid-write — never sees a half-written record
   * and mistakes a running job for a corrupt one.
   *
   * Returns whether the record actually landed. Every caller but start() ignores
   * that: a failed STATUS write is not worth failing an RPC over, because the
   * next refresh recomputes the same answer from `exit` / pid liveness anyway.
   * start() is the exception — see the ordering argument there.
   */
  private writeMeta(meta: JobMeta): boolean {
    try {
      atomicWriteUtf8(path.join(this.jobsRoot, meta.jobId), META_FILE, JSON.stringify(meta, null, 2));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Write the exit marker if the wrapper did not. `wx` makes it create-or-fail,
   * so the value written by the process that actually RAN the command always
   * wins and can never be overwritten by our observation of it.
   */
  private recordExitCode(jobId: string, code: number): void {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    try {
      fs.writeFileSync(path.join(this.jobsRoot, jobId, EXIT_FILE), String(code), {
        flag: "wx",
        mode: PRIVATE_FILE_MODE,
      });
    } catch {
      // Already recorded, or the directory is gone — either way what is on disk
      // stands.
    }
  }

  private removeJobDir(jobId: string): void {
    if (!JOB_ID_PATTERN.test(jobId)) return;
    this.settledJobs.delete(jobId);
    try {
      // Retries because a job we just signalled can still be writing into this
      // directory (its wrapper records an exit code on the way out), which lands
      // as ENOTEMPTY between the removal's own readdir and rmdir. Losing that
      // race would leave a directory with no meta.json behind for a week.
      fs.rmSync(path.join(this.jobsRoot, jobId), {
        recursive: true,
        force: true,
        maxRetries: 3,
        retryDelay: 50,
      });
    } catch {
      // Best-effort; retried on the next recovery.
    }
  }

  /**
   * A directory with no readable meta.json cannot be classified, so it is removed
   * only once its own mtime is older than the retention window — long past any
   * plausible in-flight creation.
   */
  private pruneUnreadable(jobId: string, now: number): void {
    try {
      const stat = fs.statSync(path.join(this.jobsRoot, jobId));
      if (now - stat.mtimeMs > JOB_RETENTION_MS) this.removeJobDir(jobId);
    } catch {
      // Vanished under us — nothing to do.
    }
  }
}

// ── Process-wide instance ────────────────────────────────────────────────────

let cached: { root: string; manager: JobManager } | null = null;

/**
 * The shared JobManager for this process, created (and recovered) on first use.
 *
 * There is exactly one jobs root per machine, and recovery must run exactly once
 * per process — reconciling twice would be harmless but pointless. The desktop
 * controller creates it explicitly with its own configDir at startup; the
 * headless CLI path reaches it lazily through here.
 */
export function getJobManager(configDir?: string): JobManager {
  const root = resolveJobsRoot(configDir);
  if (cached && cached.root === root) return cached.manager;
  const manager = new JobManager({ jobsRoot: root });
  manager.recover();
  cached = { root, manager };
  return manager;
}

/** Test seam: forget the process-wide instance. */
export function resetJobManagerForTests(): void {
  cached = null;
}

// ── Free functions ───────────────────────────────────────────────────────────

/**
 * The reply for every jobId we will not resolve — unknown, malformed, or outside
 * the jobs root. The caller's id is never echoed back (it is untrusted text on
 * its way into an LLM's context) and the three cases are deliberately
 * indistinguishable, so a caller cannot probe the filesystem with the difference.
 */
function notFound(): JobRpcResult {
  return { ok: false, reason: "not_found", message: "No such job on this machine." };
}

/**
 * The reply for a request that cannot succeed here or anywhere — it is malformed,
 * not unlucky. Deliberately a REFUSAL and not a JobError: an error frame is
 * free-text the relay can only render as "the machine failed" (502, "do not retry
 * unchanged"), while this arrives structured, is validated at the relay's trust
 * boundary like any other refusal, and becomes a 400 the caller can act on.
 *
 * `message` is authored by us and names the offending FIELD only — never the
 * value, which is caller payload on its way into an LLM's context.
 */
function invalidRequest(message: string): JobRefusal {
  return { ok: false, reason: "invalid_request", message };
}

function isJobMeta(value: unknown): value is JobMeta {
  if (typeof value !== "object" || value === null) return false;
  const meta = value as Partial<JobMeta>;
  return (
    meta.v === 1 &&
    typeof meta.jobId === "string" &&
    JOB_ID_PATTERN.test(meta.jobId) &&
    typeof meta.name === "string" &&
    typeof meta.command === "string" &&
    typeof meta.cwd === "string" &&
    (meta.status === "running" || meta.status === "exited" || meta.status === "unknown") &&
    (meta.exitCode === null || typeof meta.exitCode === "number") &&
    typeof meta.startedAt === "number" &&
    (meta.endedAt === null || typeof meta.endedAt === "number") &&
    // Absent on every record written before this field existed, and on every
    // record whose endedAt was OBSERVED — absent simply means "not an estimate".
    (meta.endedAtApproximate === undefined || typeof meta.endedAtApproximate === "boolean") &&
    (meta.gpuIndex === null || typeof meta.gpuIndex === "number") &&
    (meta.pid === null || typeof meta.pid === "number") &&
    (meta.procIdentity === null || typeof meta.procIdentity === "string") &&
    // Absent on every record written before this field existed, and on every
    // ordinary job since — absent simply means "not being retired".
    (meta.retiring === undefined || typeof meta.retiring === "boolean") &&
    // Absent on every record written before this field existed, and on every job
    // that got no scope — absent simply means "in the agent's own cgroup".
    (meta.scope === undefined || typeof meta.scope === "string") &&
    (meta.truncatedAt === null || typeof meta.truncatedAt === "number")
  );
}

/**
 * The spawn-time process identity, with one immediate retry.
 *
 * A probe can come back empty for reasons that have nothing to do with the
 * process — a momentarily unreadable /proc, a `ps` that could not fork under
 * load. Since a miss now costs the whole start (see start), it is worth a second
 * look before concluding that this platform will not tell us. Bounded at two
 * attempts on purpose: this runs on the thread that must answer `do:ping` inside
 * AGENT_TIMEOUT_MS, and a probe that fails twice in a row is not transient.
 */
function captureProcIdentity(pid: number): string | null {
  return readProcIdentity(pid) ?? readProcIdentity(pid);
}

/** The exit code the wrapper wrote, plus when it landed, or null. */
function readExitFile(exitPath: string): { code: number; at: number } | null {
  try {
    const stat = fs.statSync(exitPath);
    const raw = fs.readFileSync(exitPath, "utf8").trim();
    if (!/^-?\d{1,5}$/.test(raw)) return null;
    const code = Number(raw);
    if (!Number.isInteger(code)) return null;
    // Rounded, never raw: mtimeMs carries the filesystem's sub-millisecond
    // precision (NTFS 100 ns, APFS/ext4 nanoseconds), so it is almost always
    // fractional — and epoch-ms on the wire is an INTEGER. A fractional
    // `endedAt` is what made every reply describing an exited job fail the
    // relay's protocol check. toSummary normalises this again at the wire
    // boundary; it is fixed here as well so meta.json itself stays honest.
    return { code, at: Math.round(stat.mtimeMs) };
  } catch {
    return null;
  }
}

/**
 * What a GPU lock file holds, with the misses kept apart for the same reason as
 * readMetaState: `garbage` (exists, content is not a job id) and `absent` are
 * facts a reaper may act on, while `unreadable` (EMFILE/EIO/permissions) says
 * nothing about the reservation and must therefore hold it.
 */
function readLockHolder(
  lockPath: string,
): { kind: "holder"; jobId: string } | { kind: "garbage" } | { kind: "absent" } | { kind: "unreadable" } {
  try {
    const raw = fs.readFileSync(lockPath, "utf8").trim();
    return JOB_ID_PATTERN.test(raw) ? { kind: "holder", jobId: raw } : { kind: "garbage" };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
    return { kind: "unreadable" };
  }
}

/**
 * The POSIX wrapper script that runs the command and records its exit code. The
 * Windows counterpart is a pair of FILES rather than a command line built here —
 * WINDOWS_JOB_WRAPPER, which owns the redirect and the exit marker, and
 * WINDOWS_JOB_COMMAND_SCRIPT, which owns the command's own line. The split is
 * load-bearing there, for reasons written down at the second one.
 *
 * The exit marker is what makes an outcome survive the agent, so it must not
 * depend on the command REACHING the end of the script. Appending
 * `; printf %s "$?"` after arbitrary user text does depend on exactly that, and
 * ordinary training scripts break it: `exit`, `set -e` plus a failing step, and
 * a trailing `\` continuation or comment all skip whatever we appended. So the
 * script uses an EXIT trap, installed BEFORE the command and therefore
 * unreachable by anything the command's own text does. It fires on a normal end,
 * on `exit N` (with `$?` = N) and on a `set -e` abort. The exit path travels in
 * the environment, so no path of ours is quoted into user-controlled text.
 *
 * Two cases no in-shell mechanism can catch — the command replacing the shell
 * with `exec`, or installing an EXIT trap over ours — are covered while the
 * agent is alive by the child `exit` handler in spawnJob. A job that does one of
 * those AND ends while the agent is down still reports `unknown`, which is the
 * honest answer: nothing observed its exit code.
 *
 * One consequence worth naming: shells differ on whether an EXIT trap runs when
 * the shell is killed by a signal. bash (macOS `/bin/sh`) runs it, so a
 * CANCELLED job records the 143 the shell died with; dash (Debian `/bin/sh`)
 * does not, so the same job stays `unknown`. Both are true statements about what
 * was observed, neither can invent a success, and SIGKILL — where the process
 * gets no chance to record anything — is `unknown` everywhere.
 *
 * Exported for tests, which run the script through a real shell rather than
 * asserting on its text.
 */
export function buildJobScript(command: string): string {
  // The trap is installed FIRST so that even a redirect we cannot open (a full
  // or read-only volume) still records an outcome rather than killing the shell
  // silently. `exec` then rebinds the shell's own stdout/stderr, so the command
  // and every child it forks land in the log without depending on which handles
  // survived the spawn. The command stays LAST, so a trailing continuation or
  // comment has nothing of ours left to swallow — WINDOWS_JOB_COMMAND_SCRIPT
  // keeps the same rule, after a measured failure from breaking it.
  return (
    `trap 'printf %s "$?" > "$${JOB_EXIT_PATH_ENV}"' EXIT\n` +
    `exec >> "$${JOB_LOG_PATH_ENV}" 2>&1\n` +
    `${command}\n`
  );
}

/** The home directory of the user owning `target`, when it is a real directory. */
function homeOfPathOwner(target: string): string | undefined {
  try {
    const uid = fs.statSync(target).uid;
    if (uid === 0) return undefined;
    const passwd = fs.readFileSync("/etc/passwd", "utf8");
    for (const line of passwd.split("\n")) {
      const fields = line.split(":");
      if (fields.length < 6) continue;
      if (Number(fields[2]) !== uid) continue;
      const home = fields[5];
      // The home must belong to the SAME user the cwd does. A passwd entry
      // pointing at someone else's directory (or at a shared one) would have us
      // scatter root-owned caches through a third party's home, which is neither
      // what the owner-derived rule promises nor recoverable by that user.
      if (home && path.isAbsolute(home) && isDirectory(home) && ownerUid(home) === uid) return home;
      return undefined;
    }
  } catch {
    // No /etc/passwd (containers, Windows), unreadable cwd — fall through.
  }
  return undefined;
}

/** Owning uid of `target`, or null when it cannot be stat'ed. */
function ownerUid(target: string): number | null {
  try {
    return fs.statSync(target).uid;
  } catch {
    return null;
  }
}

function isDirectory(target: string): boolean {
  try {
    return fs.statSync(target).isDirectory();
  } catch {
    return false;
  }
}

// ── Wire normalisers ─────────────────────────────────────────────────────────
//
// The relay revalidates every JobSummary field and drops the record (or the
// whole reply) on the first one that does not match, so these mirror its checks
// exactly — Number.isSafeInteger rather than `typeof x === "number"` (which
// admits NaN and Infinity), the same epoch and GPU bounds — and each returns the
// literal `null` the schema names for "no value". Never `undefined`: that is not
// a JSON value at all, JSON.stringify DELETES the key, and an absent key is not
// the `null` the validator demands.
//
// Those two bounds are the SHARED MAX_EPOCH_MS / JOB_MAX_GPU_INDEX, imported from
// protocol/constants.ts rather than restated here, because they are the kind both
// sides must agree on exactly — a local copy is the two-definitions shape that cost
// us the 502 in the first place.

// The bounds this file truncates `name`/`command` to on the way out are
// JOB_WIRE_MAX_NAME_CHARS / JOB_WIRE_MAX_COMMAND_CHARS in protocol/constants.ts,
// which is also where the reason they are looser than MAX_JOB_NAME_LENGTH /
// MAX_COMMAND_BYTES is written down. They are the PRODUCING half of a contract
// whose accepting half — the relay's own, separately declared bounds in
// worker/src/jobs-relay.ts — must COVER them (relay >= agent); emitting more than
// the relay accepts costs the caller not a truncated field but the whole answer —
// for a `kind:"job"` reply, a 502 with no job in it at all. The bounds are kept
// separate so the relay MAY be widened independently, but today the two pairs are
// EQUAL (256 / 131072): the tolerance the split exists to allow currently has zero
// headroom in practice.
//
// That relationship is asserted by worker/src/__tests__/jobs-wire-contract.test.ts
// rather than left to two comments agreeing with each other. RAISING either value
// is a two-step DEPLOY, not a one-line edit — the order is spelled out where the
// constants themselves are declared.

/**
 * A string the relay will accept: never longer than `maxChars`, never anything
 * but a string.
 *
 * The cut is made on code units to match the relay's `length` check exactly, so
 * it can land between the halves of a surrogate pair; the orphaned high half is
 * dropped rather than shipped, since a lone surrogate is not text and only ever
 * confuses whatever renders it.
 */
function wireBoundedString(value: unknown, maxChars: number): string {
  if (typeof value !== "string") return "";
  if (value.length <= maxChars) return value;
  const cut = value.slice(0, maxChars);
  const last = cut.charCodeAt(cut.length - 1);
  return last >= 0xd800 && last <= 0xdbff ? cut.slice(0, -1) : cut;
}

function wireInteger(value: number | null): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) ? value : null;
}

function wireEpochMs(value: number | null): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  // Rounded rather than rejected: a filesystem mtime is a real instant that
  // simply carries sub-millisecond precision, and the millisecond it falls in is
  // the honest answer.
  const ms = Math.round(value);
  return Number.isSafeInteger(ms) && Math.abs(ms) <= MAX_EPOCH_MS ? ms : null;
}

function wireGpuIndex(value: number | null): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= JOB_MAX_GPU_INDEX
    ? value
    : null;
}

/** A byte count, or null when the value could not be one (callers pick a floor). */
function wireByteCount(value: number | null): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function fileSize(target: string): number {
  try {
    return fs.statSync(target).size;
  } catch {
    return 0;
  }
}

/** Read `length` bytes at `position`; a short/failed read yields what we got. */
function readRange(target: string, position: number, length: number): Buffer {
  if (length <= 0) return Buffer.alloc(0);
  let fd: number | null = null;
  try {
    fd = fs.openSync(target, "r");
    const buffer = Buffer.alloc(length);
    const read = fs.readSync(fd, buffer, 0, length, position);
    return buffer.subarray(0, read);
  } catch {
    return Buffer.alloc(0);
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // Nothing useful to do about a failed close.
      }
    }
  }
}

/**
 * Offset inside `window` where its last `lines` lines start. A trailing newline
 * is not treated as starting an empty final line, so "a\nb\n" with lines=1 is
 * "b\n". Falls back to the start of the window when it holds fewer lines.
 */
function offsetOfLastLines(window: Buffer, lines: number): number {
  let end = window.length;
  if (end > 0 && window[end - 1] === 0x0a) end--;
  let seen = 0;
  for (let i = end - 1; i >= 0; i--) {
    if (window[i] !== 0x0a) continue;
    seen++;
    if (seen === lines) return i + 1;
  }
  return 0;
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

/** A caller may only ever shrink the slice; the protocol cap is absolute. */
function clampSliceBytes(requested: unknown): number {
  if (!isNonNegativeNumber(requested) || requested < 1) return JOB_LOGS_MAX_SLICE_BYTES;
  return Math.min(Math.floor(requested), JOB_LOGS_MAX_SLICE_BYTES);
}

/**
 * A caller's job_list page size. Like clampSliceBytes: the caller may shrink the
 * reply, never grow it past the wire page cap — an oversized `limit` is clamped
 * rather than refused, because it asks for something harmless (more of a list
 * that is bounded anyway), unlike a gpuIndex that cannot name a card.
 */
function clampListLimit(requested: unknown): number {
  if (!isNonNegativeNumber(requested) || requested < 1) return JOB_LIST_DEFAULT_ENTRIES;
  return Math.min(Math.floor(requested), JOB_WIRE_MAX_LIST_ENTRIES);
}

function clampTailLines(requested: unknown): number {
  if (!isNonNegativeNumber(requested) || requested < 1) return JOB_LOGS_DEFAULT_TAIL_LINES;
  // No upper clamp is needed: the slice cap already bounds how much a tail can
  // return, so an absurd line count just means "as much as fits".
  return Math.floor(requested);
}

/**
 * A job name is echoed back to callers (and thence to an LLM), so it is stripped
 * to printable characters and bounded. An absent or unusable name becomes a
 * stable, recognisable default rather than an error.
 */
function normalizeName(value: unknown, jobId: string): string {
  const fallback = `job-${jobId.slice(0, 8)}`;
  if (typeof value !== "string") return fallback;
  // eslint-disable-next-line no-control-regex
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, MAX_JOB_NAME_LENGTH);
  return cleaned === "" ? fallback : cleaned;
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
