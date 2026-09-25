import fs from "node:fs";
import path from "node:path";

import { JOB_SCRIPT_REMOVED_ERROR } from "@aicommander/protocol";
import { atomicWriteUtf8Async, type AsyncWriteAbandoned } from "./atomic-file.js";
import { JOB_NOTICE_ID_ENV, JOB_NOTICE_OPERATOR_ENV, JOB_NOTICE_STARTED_ENV } from "./job-notice.js";

/**
 * The scripts a job actually runs, and nothing else.
 *
 * job-manager.ts owns lifecycle decisions, GPU locks, and retention;
 * job-process.ts launches the process using the scripts defined here.
 * What lives here is the text handed to a shell — the POSIX wrapper script, the
 * Windows wrapper/command pair, the launcher plumbing that starts them — plus
 * the check that the Windows pair is still on disk at the moment we spawn.
 *
 * The comments below are not preference. They are measurements taken on a real
 * Windows box (agent 1.0.40 / 1.1.0, Windows 10.0.26200) and on macOS/Linux
 * shells, and they record failure modes that each looked like "an empty log"
 * rather than an error. They travel WITH the code they explain.
 *
 * STANDING DECISION (PLAN-av-hardening.md §2 W4): the shape, content and
 * execution model of the Windows pair are FROZEN. The console identification
 * banner only adds display lines before execution; they do not enter the job
 * log. Four properties are
 * load-bearing and each was arrived at by measurement — process-tree capture
 * under DETACHED_PROCESS, exit-code propagation through the nested `cmd`,
 * quoting correctness for a command carrying `|` or `&` inside its own quotes,
 * and keeping every path of OURS off any command line so a `%…%` in a path
 * cannot be re-expanded. A regression in any of them is silent and lands on
 * every Windows job. Changing this file's scripts is its own project with its
 * own review, gated on the conditions written down in that plan.
 */

/** Windows only: the wrapper the detached launcher runs. See WINDOWS_JOB_WRAPPER. */
export const WRAPPER_FILE = "wrapper.cmd";
/** Windows only: the batch the wrapper runs, holding the command's own line. */
export const COMMAND_FILE = "command.cmd";

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
  "title AI Commander - running job\r\n" +
  "echo AI Commander is running a remotely started job. > CON\r\n" +
  `echo Job: %${JOB_NOTICE_ID_ENV}% > CON\r\n` +
  `echo Started by: %${JOB_NOTICE_OPERATOR_ENV}% > CON\r\n` +
  `echo Started at: %${JOB_NOTICE_STARTED_ENV}% > CON\r\n` +
  "echo Closing this window may stop the job. > CON\r\n" +
  "echo View job output and status in AI Commander. > CON\r\n" +
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

/**
 * How the detached launcher reaches the Windows wrapper: a single command STRING
 * for `cmd.exe` to parse, byte for byte as it has always been.
 *
 * `.\wrapper.cmd` is RELATIVE on purpose — the spawn's cwd is the job directory —
 * so no path of ours appears on this command line and a jobs root containing a
 * literal `%…%` pair cannot be re-expanded into something else. Frozen; see the
 * standing decision at the top of this file.
 */
export function windowsJobLaunch(): { file: string; args: string[] } {
  return { file: `cmd /d /s /c .\\${WRAPPER_FILE}`, args: [] };
}

/**
 * Errno codes that mean "something took this file away from us" rather than
 * "this disk is broken".
 *
 * EACCES/EPERM is the shape an on-access scanner produces when it holds or
 * denies the file, ENOENT is the shape it produces when it has already moved the
 * file to quarantine, and EBUSY is the shape of a handle it still holds. Anything
 * else (ENOSPC, EIO, EROFS) is a storage fault and keeps the generic start
 * failure, because calling a full disk an antivirus incident would send the
 * operator to the wrong page.
 */
const SCRIPT_FAULT_CODES = new Set(["EACCES", "EPERM", "ENOENT", "EBUSY"]);

function faultCode(err: unknown): string | null {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" && SCRIPT_FAULT_CODES.has(code) ? code : null;
}

/**
 * How long the whole write — or the whole read-back — of the job's two script
 * files gets before it is called a fault.
 *
 * A REFUSED filesystem call answers immediately and is already classified
 * (SCRIPT_FAULT_CODES). This bound is for the other half of the same story: a
 * filter driver that answers NOTHING because it is still deciding, holding a
 * handle on a file we are trying to open. That call can hang for as long as the
 * scanner likes, and there is no errno for it.
 *
 * Unbounded, that hang is worse than the synchronous code it replaced. The old
 * synchronous write blocked the event loop, so the machine went visibly offline
 * and somebody noticed within a minute. This one does not: the heartbeat keeps
 * answering, the machine looks healthy, and the job stays wedged inside
 * JobManager's record→pid window holding its GPU lock and its JOB_MAX_CONCURRENT
 * slot forever — after which every later start is refused `too_many_jobs` or
 * `gpu_busy` with nothing anywhere saying why.
 *
 * Eight seconds, chosen against both ends:
 *  - the floor is what a HEALTHY call costs. Two files of roughly a kilobyte
 *    each, written and read back in the job's own directory; even where an
 *    on-access scanner inspects each freshly created `.cmd` synchronously that
 *    is milliseconds to low hundreds of milliseconds. 8 s is orders of magnitude
 *    of headroom, so this can never fire on a machine that is merely slow.
 *  - the ceiling is the relay's JOB_RPC_TIMEOUT_MS (30 s). A start pays this
 *    bound at most TWICE (the write, then the read-back), so a doubly-hung
 *    filesystem still fails at ~16 s and leaves the rest of the budget for the
 *    do:job_start handler's own probe waits and for the reply to travel. That is
 *    the whole point: the caller must be told `job_script_removed`, naming
 *    security software, rather than being handed the relay's generic timeout.
 *
 * A timeout is reported as the same family of fault as a refusal, because it is
 * the same event seen a moment earlier: an on-access scanner holding our file
 * open and an on-access scanner deleting it are one story, and they have one
 * answer (jobScriptRemovedMessage). Nothing is retried — the retry would sit
 * behind the same handle.
 */
export const JOB_SCRIPT_IO_TIMEOUT_MS = 8_000;

/** Resolution of a filesystem call that never came back in time. */
const TIMED_OUT = Symbol("job-script-io-timed-out");

/**
 * Await `work`, giving up at `deadline`.
 *
 * Giving up does NOT cancel the call — no fs API can revoke a request a filter
 * driver is sitting on, and `AbortSignal` only helps between chunks, which a
 * one-shot read of a kilobyte never reaches. What it does is free the JOB: the
 * start fails with a named cause and surrenders its lock and its slot, while the
 * orphaned promise resolves or rejects into nothing whenever the scanner
 * releases it. A late rejection is swallowed here so it can never surface as an
 * unhandled rejection long after the job it belonged to is gone.
 */
async function withinDeadline<T>(work: Promise<T>, deadline: number): Promise<T | typeof TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<typeof TIMED_OUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMED_OUT), Math.max(0, deadline - Date.now()));
    // Never hold the process open for a bound nobody is waiting on any more.
    if (typeof timer.unref === "function") timer.unref();
  });
  try {
    const settled = await Promise.race([work, guard]);
    if (settled === TIMED_OUT) void work.catch(() => undefined);
    return settled;
  } finally {
    clearTimeout(timer);
  }
}

/** How a timed-out call names itself in the caller-visible detail. */
function timeoutDetail(file: string, verb: string, timeoutMs: number): string {
  return `${file} timed out being ${verb} (${Math.round(timeoutMs / 1000)}s)`;
}

/**
 * Write the Windows pair into the job's directory.
 *
 * Returns a short DETAIL string when the write was refused in a way that looks
 * like interference (see SCRIPT_FAULT_CODES), `null` when both files landed, and
 * THROWS for any other error — a full or broken volume is a different failure and
 * gets the generic "could not start the job" answer it always had.
 *
 * The detail never contains the command: it is caller payload, it travels to the
 * relay inside the error text, and no diagnostic here is worth putting it there.
 *
 * ASYNCHRONOUS, like the read-back below and for the same reason: this runs
 * inside the WebSocket frame handler, and the desktop host is Electron's main
 * loop. See atomicWriteUtf8Async.
 *
 * BOUNDED, because asynchronous is not the same as harmless — see
 * JOB_SCRIPT_IO_TIMEOUT_MS. The bound covers the whole pair, not each file: what
 * the caller is buying is a start that either has both scripts or has failed.
 *
 * And a bound is not the same as a stop. Giving up leaves the write RUNNING
 * inside whatever is holding it; the caller meanwhile fails its start and
 * deletes the job's directory. The abandoned call is told so — that is the latch
 * below — so that when the scanner finally lets go it removes what it created
 * instead of re-creating an id-shaped directory around a stray wrapper.cmd,
 * hours after the job it belonged to stopped existing (see atomicWriteUtf8Async).
 */
export async function writeWindowsJobScripts(
  dir: string,
  command: string,
  timeoutMs: number = JOB_SCRIPT_IO_TIMEOUT_MS,
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  for (const [file, contents] of windowsJobScripts(command)) {
    const giveUp: AsyncWriteAbandoned = { abandoned: false };
    try {
      const written = await withinDeadline(atomicWriteUtf8Async(dir, file, contents, giveUp), deadline);
      if (written === TIMED_OUT) {
        giveUp.abandoned = true;
        return timeoutDetail(file, "written", timeoutMs);
      }
    } catch (err) {
      const code = faultCode(err);
      if (code === null) throw err;
      return `${file} could not be written (${code})`;
    }
  }
  return null;
}

/**
 * Read the Windows pair back and check it still holds what we just wrote.
 *
 * This is the whole point of W3.1 (PLAN-av-hardening.md): on 2026-09-02 a
 * behavioural engine quarantined exactly these two files — six of them across
 * several jobs — and the product said NOTHING. The operator saw a job that failed
 * with an empty log, which is indistinguishable from a command that printed
 * nothing and died. The moment the scanner acts is the one moment we can name the
 * cause precisely, and it is HERE: between our write and our spawn.
 *
 * Observation only. Nothing about the scripts changes, and a clean read is not
 * reported anywhere — a job whose files survived costs two small reads and
 * carries on exactly as before.
 *
 * Those two reads are ASYNCHRONOUS, and that is not a style choice. This is the
 * one check that must sit immediately before the spawn, i.e. inside the
 * WebSocket frame handler, which on the desktop host is Electron's main loop —
 * and the filesystem it reads is by hypothesis one an on-access scanner is busy
 * with. A synchronous read there would block the loop exactly as the modal in
 * tray.ts once did, starving the heartbeat into the "Reconnecting…" state this
 * work exists to prevent. The adjacency to the spawn is preserved: the caller
 * awaits this and then spawns, with nothing in between (see spawnJob).
 *
 * Returns a detail string describing what is wrong, or `null` when both files are
 * present and byte-identical to what was written. A read refused or a file gone
 * is a fault; anything else (an EIO on a dying disk) is NOT claimed as one — it
 * throws, and the generic start failure describes it. A read that never comes
 * back is a fault too, on the same bound as the write (JOB_SCRIPT_IO_TIMEOUT_MS):
 * this is the call most likely to meet a handle a scanner is still holding.
 */
export async function verifyWindowsJobScripts(
  dir: string,
  command: string,
  timeoutMs: number = JOB_SCRIPT_IO_TIMEOUT_MS,
): Promise<string | null> {
  const deadline = Date.now() + timeoutMs;
  for (const [file, expected] of windowsJobScripts(command)) {
    let actual: string;
    try {
      const read = await withinDeadline(fs.promises.readFile(path.join(dir, file), "utf8"), deadline);
      if (read === TIMED_OUT) return timeoutDetail(file, "read back", timeoutMs);
      actual = read;
    } catch (err) {
      const code = faultCode(err);
      if (code === null) throw err;
      return code === "ENOENT" ? `${file} is gone` : `${file} could not be read back (${code})`;
    }
    // Byte-for-byte, not "starts with" or "is non-empty": a scanner that empties
    // or rewrites a file leaves something readable behind, and a wrapper missing
    // its redirect is the same empty log by another route.
    //
    // Compared against what UTF-8 CAN HOLD, not against the JavaScript string we
    // started from. A command arriving over JSON may contain a lone surrogate
    // (`"\ud800"` is valid JSON and an unpaired half of a code point); writing it
    // as UTF-8 substitutes U+FFFD, so the file on disk is byte-perfect and yet
    // differs from `expected`. Read literally, that told a HEALTHY machine its
    // scripts had been quarantined and sent its operator to antivirus support —
    // for a job that, before this check existed, simply ran. The round trip is
    // exactly the transformation the write performed, so what is left is a real
    // difference: something else edited the file.
    if (actual !== utf8RoundTrip(expected)) {
      return actual === "" ? `${file} was emptied` : `${file} no longer holds what was written`;
    }
  }
  return null;
}

/**
 * What a string becomes once it has been through a UTF-8 file — the encode the
 * write did, and the decode the read back did. Lossless for everything a text
 * file can represent; the one thing it changes is an unpaired surrogate, which
 * becomes U+FFFD in both directions and can therefore never be read back as
 * itself. See the comparison in verifyWindowsJobScripts.
 */
function utf8RoundTrip(text: string): string {
  return Buffer.from(text, "utf8").toString("utf8");
}

/** The pair, in the order they are written and read back. */
function windowsJobScripts(command: string): ReadonlyArray<readonly [string, string]> {
  return [
    [WRAPPER_FILE, WINDOWS_JOB_WRAPPER],
    [COMMAND_FILE, buildWindowsJobCommandScript(command)],
  ];
}

/**
 * What the operator — or the AI agent driving their machine — is told when a
 * job's scripts did not survive to the spawn.
 *
 * Leads with the shared token, then the detail, then a semicolon, then prose —
 * the shape JOB_SCRIPT_REMOVED_ERROR documents, which is what lets the relay
 * lift the detail out and write the rest itself for an AI caller. The prose is
 * still said in full here because plenty of readers have nothing to map the
 * token with: an agent talking to an older Worker, a log line, and the CLI on the
 * box itself all get this same string.
 *
 * `detail` is ours, never the command: it names a file of ours and what happened
 * to it, and it crosses the relay into caller-visible text.
 *
 * The URL is the short one on purpose — it is what goes into vendor reports and
 * support replies, and it redirects to /troubleshooting/#antivirus.
 */
export function jobScriptRemovedMessage(detail: string): string {
  return (
    `${JOB_SCRIPT_REMOVED_ERROR}: ${detail}; the job's scripts were removed or blocked between being written ` +
    "and being run, so the job never started. On Windows this is almost always security software quarantining " +
    "the per-job .cmd files, which look like a dropper to a behavioural engine; excluding the AI Commander jobs " +
    "directory and restoring anything already quarantined fixes it. https://aicommander.dev/antivirus"
  );
}
