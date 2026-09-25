import { existsSync } from "node:fs";
import { isExecShell, unsupportedExecShellMessage } from "@aicommander/protocol";

/**
 * Turn a requested `shell` (see protocol/exec-shell.ts) into something this
 * machine can actually spawn — or into a refusal.
 *
 * THE AGENT IS THE AUTHORITY. The relay refuses obviously-wrong values before
 * they leave it, but it only knows the platform the agent LAST reported and it
 * cannot know whether bash is installed or where PowerShell lives. So every
 * value is re-checked here, on the box, and anything that cannot be honoured
 * EXACTLY is answered with agent:error. There is no fallback to the default
 * interpreter anywhere in this file: a caller that asked for PowerShell and got
 * cmd.exe has been told the command ran in a language it did not.
 *
 * The Windows half is written around one hard constraint: exec on Windows does
 * NOT spawn a shell directly. It spawns the signed launcher
 * (aicommander-win-exec-x64.exe), whose whole trust model is that the command
 * travels only over a bounded stdin protocol — never a command line, never a
 * file on disk — and that cmd.exe is resolved from GetSystemDirectoryW() rather
 * than %COMSPEC%. Selecting an interpreter must therefore change only the TEXT
 * handed to that launcher, never the launcher itself. See wrapForPowerShell for
 * why the wrapping is injection-proof rather than merely careful, and
 * WINDOWS_POWERSHELL_PATH for why the second interpreter this file can name is a
 * fixed literal instead of an environment lookup.
 */

/** Where a POSIX bash lives, in the order we are willing to accept it. */
const BASH_CANDIDATES = [
  "/bin/bash",
  "/usr/bin/bash",
  "/usr/local/bin/bash",
  "/opt/homebrew/bin/bash",
];

/**
 * cmd.exe's own command-line ceiling. The launcher runs
 * `cmd.exe /d /s /c "<text>"`, so everything we produce has to fit inside it
 * with the wrapper's 19 characters of `cmd.exe /d /s /c "` + `"` to spare.
 * The margin keeps us clear of the exact boundary, which behaves differently
 * across Windows builds and is not worth discovering in production.
 */
const WINDOWS_COMMAND_LINE_LIMIT = 8191;
const WINDOWS_LAUNCHER_WRAPPER_CHARS = 19;
const WINDOWS_COMMAND_LINE_MARGIN = 64;

/** PowerShell arguments that make a remote, non-interactive run deterministic. */
const POWERSHELL_ARGS = "-NoProfile -NonInteractive -EncodedCommand";

/**
 * The ONE path we are willing to run as Windows PowerShell — a fixed literal
 * baked into this file, not assembled from anything a caller or an environment
 * can influence.
 *
 * WHY A LITERAL AND NOT %SystemRoot%. The signed launcher resolves cmd.exe from
 * GetSystemDirectoryW() specifically BECAUSE an environment-derived interpreter
 * path is redirectable: anyone who can seed the agent's environment (a service
 * unit, a launchd plist, a parent process, a compromised installer) would then
 * choose the binary that every `shell: "powershell"` command executes. Building
 * the PowerShell path out of `process.env.SystemRoot` would reintroduce exactly
 * that property one layer up, so it is not built out of it. Node exposes no
 * GetSystemDirectoryW and no other non-environment source for the system
 * directory (os.homedir, process.env.windir and friends are all environment or
 * registry lookups the same attacker reaches), so the honest remaining option is
 * a constant.
 *
 * WHAT THIS ACTUALLY BUYS, precisely — no more, no less: the string is chosen at
 * build time by us, so no environment can point it elsewhere, and reaching the
 * directory it names requires Administrator on a stock Windows. It is NOT a
 * proof that the file there is Microsoft's: an attacker who is already
 * Administrator can replace anything under System32, and this check does not
 * pretend otherwise.
 *
 * WHAT IT COSTS. Windows can legally be installed somewhere other than
 * C:\Windows (an alternate drive, an alternate directory). On such a machine
 * `shell: "powershell"` REFUSES — see missingPowerShellMessage — because the
 * only way to find the real one would be to trust the environment, which is the
 * thing we just refused to do. cmd (the default) is unaffected: the launcher
 * resolves it through the API.
 */
const WINDOWS_POWERSHELL_PATH =
  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

export interface ExecShellPlanOptions {
  /**
   * Injected in tests; defaults to the real filesystem. This is the only
   * injection point on the Windows path — the interpreter PATH itself is a
   * constant (WINDOWS_POWERSHELL_PATH) and deliberately cannot be overridden,
   * by a test or by anything else.
   */
  exists?: (candidate: string) => boolean;
}

/**
 * The result of planning.
 *
 * `posixShell` is what to hand Node's spawn `shell` option on POSIX (`true` =
 * /bin/sh, a path = that interpreter). It is always `true` and always IGNORED on
 * Windows, where nothing is spawned through a shell at all: the command goes to
 * the signed launcher, which runs cmd.exe itself.
 *
 * `command` is the text to run. Only the Windows PowerShell path rewrites it;
 * every other path hands back exactly what it was given.
 *
 * `clixmlStderr` says the stderr of the resulting process needs the PowerShell
 * CLIXML decoder (powershell-clixml.ts) in front of it. It is set on exactly ONE
 * path — the -EncodedCommand wrapping below — because the CLIXML is a side effect
 * of that wrapping and of nothing else. It travels on the plan rather than being
 * re-derived from `shell` in executor.ts so that the decision stays where the
 * wrapping decision is: change the wrapping here and the flag changes with it,
 * instead of a second file quietly disagreeing about which commands were
 * wrapped. cmd, sh and bash never carry it and their stderr is byte-identical to
 * what it was before this existed.
 */
export type ExecShellPlan =
  | { ok: true; command: string; posixShell: true | string; clixmlStderr?: true }
  | { ok: false; message: string };

/**
 * Refusal for `bash` on a machine that has none.
 *
 * Says which paths were looked at, so the user can see it is not a PATH problem,
 * and offers the only two real moves. It never suggests "we ran it in sh
 * instead", because we did not.
 */
function noBashMessage(): string {
  return (
    '`shell: "bash"` was requested, but this machine has no bash: none of ' +
    `${BASH_CANDIDATES.join(", ")} exists. The command was NOT run — it is never quietly ` +
    "handed to a different shell. Retrying this call unchanged will fail the same way. Either " +
    "re-send it without `shell`, writing POSIX-portable syntax for /bin/sh (no arrays, no `[[ ]]`, " +
    "no `pipefail`), or install bash on that machine."
  );
}

/**
 * Refusal for a PowerShell script too long to reach the interpreter.
 *
 * The ceiling is cmd.exe's, not ours, and it is reached sooner than a caller
 * expects because base64-of-UTF-16 is ~2.67× the source. Spelling out both
 * numbers is what lets a model decide how much to cut instead of bisecting.
 */
function powerShellTooLongMessage(sourceChars: number, budgetChars: number): string {
  return (
    `This PowerShell command is too long to run on Windows: ${sourceChars} characters of script, and the ` +
    `practical ceiling here is about ${budgetChars}. The agent passes the script to powershell.exe as a ` +
    "single `-EncodedCommand` argument, base64 of UTF-16 makes it roughly 2.7× its original size, and " +
    "cmd.exe cannot parse a command line longer than 8191 characters. The command was NOT run and " +
    "nothing was truncated. Retrying unchanged will fail the same way. Split the work across several " +
    "remote_exec calls, or write the script to a .ps1 file on the machine in pieces and run it with " +
    "`powershell -NoProfile -File <path>`."
  );
}

/**
 * Refusal for `powershell` when nothing is present at the one path we accept.
 *
 * Two different machines land here and the message has to serve both: a Windows
 * without PowerShell 5.1 (rare — it ships with every supported version), and a
 * Windows installed outside C:\Windows, where the interpreter exists but we
 * decline to go looking for it through the environment. Saying so plainly is
 * what stops a reader concluding the feature is broken, and the workaround for
 * the second case is exact: name the path in the command itself, where it is the
 * caller's own choice rather than a value we inherited.
 */
function missingPowerShellMessage(): string {
  return (
    '`shell: "powershell"` was requested, but this agent found no Windows PowerShell at ' +
    `${WINDOWS_POWERSHELL_PATH}. That path is a FIXED one: the agent will not locate the interpreter ` +
    "through %SystemRoot%, %PATH% or any other environment value, because whoever can set those would " +
    "then choose which binary every `shell: \"powershell\"` command runs. So this also happens on a " +
    "Windows installed outside C:\\Windows, where PowerShell is present but not where we are willing to " +
    "look for it. The command was NOT run in cmd.exe instead, and retrying unchanged will fail the same " +
    "way. Either re-send without `shell` and write the command for cmd.exe (chain steps with `&&` on " +
    "one line), or re-send without `shell` and invoke the interpreter yourself by full path, e.g. " +
    '`"D:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -Command "…"` — run ' +
    "`echo %SystemRoot%` there first to see where Windows actually lives."
  );
}

/**
 * Build the cmd.exe line that runs `command` under Windows PowerShell.
 *
 * WHY -EncodedCommand AND NOT QUOTING. The obvious wrapping —
 * `powershell -NoProfile -Command "<command>"` — has to survive TWO parsers in a
 * row: cmd.exe's (which treats `&`, `|`, `<`, `>`, `^`, `%` as syntax and has no
 * general escape that works inside quotes) and then PowerShell's own. Any script
 * containing a double quote, an ampersand or a percent sign either breaks or —
 * far worse — reparses into a different command than the caller wrote. That is
 * an injection hazard, not a quoting inconvenience, and it would be
 * user-triggerable by ordinary scripts.
 *
 * base64 removes the problem instead of managing it: the encoded text is only
 * `A-Za-z0-9+/=`, none of which is special to cmd.exe, so there is nothing to
 * escape and nothing that can reparse. It also PRESERVES the interior-line-break
 * guarantee this platform depends on — a newline inside the script becomes
 * base64, so the line the launcher hands cmd.exe is still exactly one line, and
 * cmd.exe cannot silently run "only the first line" of anything. That is why
 * multi-line scripts are ALLOWED here while they remain rejected for cmd.
 *
 * THE PRICE, and where it is paid. -EncodedCommand also makes PowerShell 5.1
 * serialize its own error/warning/verbose/debug/progress streams to stderr as
 * CLIXML instead of writing them as text, so a plain `Write-Error` reaches the
 * caller shredded across `<S S="Error">` elements with `_x000D_` escapes. That is
 * a presentation artifact of THIS wrapping, so it is undone on the transport by
 * powershell-clixml.ts — see that file for the measured payloads and for why
 * -OutputFormat Text is not the answer (it was tested against this exact
 * invocation and changed nothing). The plan carries `clixmlStderr: true` to say
 * so. Nothing about the wrapping itself is relaxed for it.
 *
 * The interpreter is addressed by the fixed absolute path in
 * WINDOWS_POWERSHELL_PATH — never `powershell` bare, which cmd.exe would resolve
 * against the child's PATH (caller-settable), and never a path assembled from
 * %SystemRoot% (environment-settable). See that constant for exactly what the
 * literal does and does not guarantee, and for why a Windows installed elsewhere
 * is refused rather than searched for.
 */
function wrapForPowerShell(
  command: string,
  options: ExecShellPlanOptions,
): { ok: true; command: string } | { ok: false; message: string } {
  const pathExists = options.exists ?? existsSync;
  const exe = WINDOWS_POWERSHELL_PATH;
  if (!pathExists(exe)) {
    return { ok: false, message: missingPowerShellMessage() };
  }
  // A NUL cannot survive the launcher's stdin protocol and has no meaning inside
  // a script; base64 would hide it from that check, so it is refused here with
  // the same wording the unwrapped path uses.
  if (command.includes("\0")) {
    return { ok: false, message: "Windows command contains an unsupported NUL character" };
  }

  const encoded = Buffer.from(command, "utf16le").toString("base64");
  const line = `"${exe}" ${POWERSHELL_ARGS} ${encoded}`;
  const limit =
    WINDOWS_COMMAND_LINE_LIMIT - WINDOWS_LAUNCHER_WRAPPER_CHARS - WINDOWS_COMMAND_LINE_MARGIN;
  if (line.length > limit) {
    // Report the budget in the caller's own units (script characters), derived
    // from the same arithmetic rather than a second hard-coded number: 4 base64
    // characters per 3 bytes, 2 bytes per UTF-16 code unit.
    const overhead = line.length - encoded.length;
    const budgetChars = Math.floor(((limit - overhead) * 3) / 4 / 2);
    return { ok: false, message: powerShellTooLongMessage(command.length, budgetChars) };
  }
  return { ok: true, command: line };
}

/**
 * Resolve a requested shell for THIS machine.
 *
 * `shell` arrives off a relay frame, so it is treated as untrusted input: an
 * unknown string, or one belonging to the other platform family, is refused
 * with the same message the relay would have produced. `undefined` is the
 * documented "machine default" and is the only value that changes nothing.
 */
export function planExecShell(
  platform: NodeJS.Platform | string,
  shell: string | undefined,
  command: string,
  options: ExecShellPlanOptions = {},
): ExecShellPlan {
  const isWindows = platform === "win32";
  if (shell === undefined) {
    return { ok: true, command, posixShell: true };
  }
  if (!isExecShell(shell)) {
    return { ok: false, message: unsupportedExecShellMessage(shell, platform) };
  }

  if (isWindows) {
    if (shell === "cmd") return { ok: true, command, posixShell: true };
    if (shell === "powershell") {
      const wrapped = wrapForPowerShell(command, options);
      return wrapped.ok
        ? { ok: true, command: wrapped.command, posixShell: true, clixmlStderr: true }
        : { ok: false, message: wrapped.message };
    }
    return { ok: false, message: unsupportedExecShellMessage(shell, platform) };
  }

  if (shell === "sh") return { ok: true, command, posixShell: true };
  if (shell === "bash") {
    const pathExists = options.exists ?? existsSync;
    const found = BASH_CANDIDATES.find((candidate) => pathExists(candidate));
    return found === undefined
      ? { ok: false, message: noBashMessage() }
      : { ok: true, command, posixShell: found };
  }
  return { ok: false, message: unsupportedExecShellMessage(shell, platform) };
}
