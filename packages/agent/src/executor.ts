import { spawn } from "node:child_process";
import { statSync } from "node:fs";
import path from "node:path";
import { KILL_ESCALATION_MS } from "@aicommander/protocol";
import { planExecShell } from "./exec-shell.js";
import {
  applyLoginShellLocale,
  applyLoginShellPath,
  applyNonInteractiveTerm,
  pendingLoginShellPath,
} from "./login-shell-path.js";
import { PowerShellClixmlDecoder } from "./powershell-clixml.js";
import {
  encodeWindowsLauncherRequest,
  resolveWindowsLauncherPath,
  WindowsLauncherHandshakeDecoder,
  WINDOWS_LAUNCHER_HANDSHAKE_TIMEOUT_MS,
} from "./windows-exec-launcher.js";

export interface CommandHandlers {
  onOutput: (chunk: string, stream: "stdout" | "stderr") => void;
  onDone: (exitCode: number, durationMs: number) => void;
  onError: (error: string) => void;
}

export interface RunningCommand {
  kill: () => void;
}

export interface CommandExecutionOptions {
  /**
   * Desktop-only path to the signed launcher in Electron extraResources. npm
   * and source runs resolve their package-relative dist-native copy.
   */
  windowsExecLauncherPath?: string;
  /**
   * Absolute epoch-ms instant at which the CALLER will declare this command
   * timed out (connection.ts arms its own timer). The executor cannot see that
   * deadline otherwise, and the post-exit drain below would happily push a
   * command that exited just under the wire past it — the caller would then
   * report "Command timed out" for work that actually finished in time. Given
   * the deadline we clamp the drain to end before it. Optional because callers
   * without a deadline (tests, library embedders) simply get the unclamped
   * drain; when it IS supplied it is honoured, never merely recorded.
   */
  deadlineMs?: number;
  /**
   * Which interpreter to run the command in (protocol ExecShell: "sh" | "bash" |
   * "cmd" | "powershell"). Omitted = this machine's historical default, which is
   * what every caller predating the field gets.
   *
   * Typed as a plain string because it arrives off a relay frame: planExecShell
   * validates it against what THIS machine can actually run and refuses anything
   * else through onError. It is never coerced to the default — running a command
   * in a language the caller did not ask for is the failure this field exists to
   * prevent.
   */
  shell?: string | undefined;
  /**
   * The filesystem probe planExecShell uses to decide whether the requested
   * interpreter exists here (`/bin/bash`, `powershell.exe`). Defaults to the real
   * one; a caller that supplies it is choosing a different answer to "is this
   * interpreter present", nothing more.
   *
   * It exists because it is the ONLY way the PowerShell half of this file can be
   * exercised off Windows. `plan.clixmlStderr` — which decides whether stderr
   * goes through the CLIXML decoder at all — can only be true when planning says
   * powershell.exe is present, so without this seam the decoder wiring here (the
   * emitStderr funnel, the pre-handshake replay, the flush before settle) was
   * asserted by comments alone and CI would have passed with any of it deleted.
   * It changes no decision on a real machine: nobody in the product passes it.
   */
  shellExists?: (candidate: string) => boolean;
}

const MAX_PRE_HANDSHAKE_STDERR_BYTES = 64 * 1024;

/**
 * How long we keep reading the pipes after the child has EXITED.
 *
 * We used to settle on 'close', which needs the child to exit AND every stdio
 * pipe to reach EOF. A backgrounded grandchild (`sleep 20 &`) inherits our
 * stdout/stderr write ends, so EOF never arrives and a command that finished in
 * milliseconds blocked until the caller's timeout. Settling on 'exit' instead
 * fixes that, but 'exit' can beat the last 'data' events, so we drain first.
 *
 * The drain is QUIET-BASED, not a flat wait, and the difference matters at both
 * ends. Waiting a fixed 250 ms after every such exit adds 250 ms of pure
 * latency to a command that had nothing left to say — and the caller's deadline
 * (connection.ts) keeps running through it, so a command that exits just under
 * its timeout could be reported as timed out AFTER it had already succeeded.
 * Waiting only for quiet cuts that exposure to one poll interval, and the
 * deadline clamp in scheduleDrainCheck (options.deadlineMs) removes even that.
 * In the other
 * direction, a burst still arriving when the window would have expired keeps
 * extending it instead of being truncated — the flat window was both too long
 * for the common case and, for a multi-megabyte burst on a slow reader, too
 * short for the rare one. The absolute cap bounds a grandchild that just keeps
 * talking; a command that ended is not entitled to hold the slot forever.
 *
 * Note this whole path is the UNCOMMON one: with no surviving grandchild the
 * pipes reach EOF within a turn or two and 'close' settles immediately, so the
 * normal command pays nothing at all.
 */
const EXIT_DRAIN_QUIET_MS = 25;
const EXIT_DRAIN_MAX_MS = 250;

/**
 * The Windows launcher's "I cannot tell you what happened" signal — BOTH halves.
 *
 * MUST match `kUnknownOutcomeExitCode` / `kUnknownOutcomeMarker` in
 * native/win-exec-launcher/main.cpp; windows-exec-launcher.test.ts pins the pair.
 *
 * Why two halves. Past the ready handshake every path here ends in onDone, and a
 * number there reads as a finished command, so a vanished console stage must not
 * arrive as an exit status. The launcher therefore returns a value no ordinary
 * program picks — but 0xa1c0ffff is a perfectly legal 32-bit Windows status, and
 * keying off it alone did the mirror-image damage: a command that genuinely
 * returned it was reported as an unknown outcome. The launcher also writes a
 * marker-led notice to the command's stderr on that path and on no other, so we
 * require both. A real `exit /b` of this value has no marker and stays a result;
 * a real vanish has both and stays an error.
 *
 * The marker rides the command's own stderr because the launcher has no private
 * channel left after the handshake, so this is corroboration, not proof: a
 * command would have to print this leader AND exit with exactly this status to
 * be misread. That is two independent coincidences instead of one.
 */
const WINDOWS_LAUNCHER_UNKNOWN_OUTCOME_EXIT_CODE = 0xa1c0ffff;
const WINDOWS_LAUNCHER_UNKNOWN_OUTCOME_MARKER = "aicommander-launcher-unknown-outcome:";

/**
 * Headroom kept between the end of the drain and the caller's deadline.
 *
 * Settling is not instantaneous from the caller's point of view: onDone runs a
 * few statements and a WebSocket send, and the caller's timer is armed slightly
 * BEFORE the executor starts (connection.ts arms it, then spawns). Landing the
 * drain exactly on the deadline would therefore still race it. A handful of
 * milliseconds costs nothing — the drain is already a sub-second window — and
 * turns the race into an ordering guarantee.
 */
const EXIT_DRAIN_DEADLINE_GUARD_MS = 5;

/**
 * Stop reading a post-exit pipe WITHOUT closing our end of it.
 *
 * The obvious move here — `stream.destroy()` — is the ONE thing this must not
 * do, and it was here once. Destroying our READ end closes the last reader of
 * that pipe, so the surviving grandchild's next write gets EPIPE, and with it
 * SIGPIPE (fatal by default: libuv restores default signal dispositions in the
 * child, so nothing catches it) — on Windows, ERROR_BROKEN_PIPE, which the CRT
 * turns into a write failure most runtimes treat as fatal too. `mydaemon &`
 * with no redirect was therefore KILLED ~250 ms after the foreground command
 * returned, while we reported success: the caller is told the daemon started,
 * and it is already dead. That is exactly the failure this file is written to
 * avoid, and it contradicts the promise made in the 'exit' handler below —
 * starting a daemon with `... &` is a legitimate thing to ask for.
 *
 * "Stop WAITING on the pipe" was the only thing the drain ever needed. So:
 *  - drop OUR data listener: nothing that arrives now can reach the caller
 *    anyway (settle() has run), and the drain must not be re-armed by it;
 *  - `resume()`, so the stream keeps consuming and discarding rather than
 *    back-pressuring the writer. A daemon that filled the 64 KiB pipe buffer
 *    would otherwise block forever in write() — a subtler version of the same
 *    bug. With no 'data' listener attached, flowing mode simply drops the bytes;
 *  - `unref()`, so an open pipe held by a daemon for weeks cannot keep this
 *    process's event loop alive. unref only affects loop-alive accounting; the
 *    stream still reads whenever the loop turns for anything else, which on the
 *    agent is constantly (the relay socket).
 *
 * Resume rather than pause is what makes this leak-free, and is the part a
 * future "simplification" is most likely to get wrong: a PAUSED stream never
 * observes EOF, so its fd would stay open for the agent's whole life — over
 * thousands of commands, that is fd exhaustion, an outage of its own. A flowing
 * stream sees EOF the moment the survivor finally exits, and Node then ends,
 * closes and frees it with no further help from us. Nothing per-command
 * outlives that: our listener is gone and the only reference left is the
 * ChildProcess's own.
 *
 * The no-op 'error' listener is not decoration. These streams now outlive the
 * command, and an 'error' on a stream with no listener is an uncaught exception
 * that would take the agent down — a pipe whose peer dies mid-write is precisely
 * the case we are here for.
 */
function detachPipe(
  stream: NodeJS.ReadableStream | null,
  onData: (chunk: Buffer) => void,
): void {
  if (!stream) return;
  stream.removeListener("data", onData);
  stream.on("error", () => {});
  stream.resume();
  (stream as { unref?: () => void }).unref?.();
}

function isDirectory(target: string): boolean {
  try {
    return statSync(target).isDirectory();
  } catch {
    return false;
  }
}

function setWindowsEnvDefault(env: NodeJS.ProcessEnv, key: string, value: string): void {
  const upper = key.toUpperCase();
  if (Object.keys(env).some((candidate) => candidate.toUpperCase() === upper)) return;
  env[key] = value;
}

function buildChildEnv(
  isWindows: boolean,
  overlay: Record<string, string> | undefined,
): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = { ...process.env };
  // macOS: launchd hands the app its own minimal PATH, so merge in the user's
  // login-shell PATH (see login-shell-path.ts). A no-op on every other platform
  // and while the probe is unresolved. It runs BEFORE the overlay below, so an
  // explicit PATH from the caller still wins — the precedence never changes.
  applyLoginShellPath(result);
  // Same story, same precedence, one line later: launchd gives the app no LANG
  // either, so a macOS command ran in the C locale and mangled non-ASCII output
  // that the identical Linux command handled fine. macOS-only and never
  // overrides an inherited value; the overlay below still wins.
  applyLoginShellLocale(result);
  // And the third hole of the same kind, on every POSIX platform: a service
  // manager hands the agent no TERM either, and software that finds none guesses
  // — often into ANSI colour and cursor control, straight through the output an
  // AI agent has to read. Fills only when absent; overlay still wins.
  applyNonInteractiveTerm(result);
  if (!isWindows) return { ...result, ...(overlay ?? {}) };

  // Windows environment names are case-insensitive, while JavaScript objects
  // are not. Remove inherited casing aliases before applying the caller's key,
  // otherwise Node sorts duplicates and may forward the inherited value.
  for (const [key, value] of Object.entries(overlay ?? {})) {
    const upper = key.toUpperCase();
    for (const inherited of Object.keys(result)) {
      if (inherited.toUpperCase() === upper) delete result[inherited];
    }
    result[key] = value;
  }
  return result;
}

export function executeCommand(
  command: string,
  cwd: string | undefined,
  env: Record<string, string> | undefined,
  handlers: CommandHandlers,
  options: CommandExecutionOptions = {},
): RunningCommand {
  // A caller-supplied cwd is checked BEFORE the spawn. Left to libuv the failure
  // arrives as `spawn ... ENOENT` naming `/bin/sh` — the PROGRAM, never the
  // directory — which reads as "that command does not exist" and sends the
  // caller looking in the wrong place entirely. Both checks use the job path's
  // wording so the two tools answer an identical mistake identically: not
  // absolute is a property of the REQUEST (no machine anywhere accepts it),
  // not a directory is a property of THIS MACHINE right now (an unmounted
  // volume, or a path the agent's user may not stat).
  if (cwd !== undefined) {
    const invalid = !path.isAbsolute(cwd)
      ? "cwd must be an absolute path."
      : !isDirectory(cwd)
        ? "cwd does not exist on this machine."
        : null;
    if (invalid !== null) {
      queueMicrotask(() => handlers.onError(invalid));
      return { kill() {} };
    }
  }

  // macOS only, and at most once per process: wait for the login-shell PATH
  // probe rather than run with launchd's minimal PATH. The probe is
  // timeout-bounded and fails open, so this delays a spawn but cannot block it.
  const pendingPath = pendingLoginShellPath();
  if (pendingPath) {
    let running: RunningCommand | null = null;
    let killRequested = false;
    let settled = false;
    const fail = (message: string) => {
      if (settled) return;
      settled = true;
      handlers.onError(message);
    };
    void pendingPath
      .then(() => {
        // A kill that arrived while we were waiting is already terminal for the
        // caller — a timeout or a dropped connection sent its response before
        // calling us. Spawning the command now and killing it again would run
        // the command's side effects AFTER the caller was told it did not run:
        // the deletion happens, the report says it did not. So we never start
        // it, and answer the kill ourselves.
        if (killRequested) {
          fail("Command was cancelled before it started.");
          return;
        }
        running = startCommand(command, cwd, env, handlers, options);
        settled = true;
      })
      .catch((err: unknown) => {
        // The direct path below throws synchronously into the caller's try; on
        // this deferred path there is no caller left on the stack, so without
        // this an argument or launcher-resolution error would be an unhandled
        // rejection and the command would simply hang until the relay's
        // timeout — silent, on the ONE platform this branch exists for.
        fail(err instanceof Error ? err.message : String(err));
      });
    return {
      kill: () => {
        killRequested = true;
        running?.kill();
      },
    };
  }

  return startCommand(command, cwd, env, handlers, options);
}

function startCommand(
  command: string,
  cwd: string | undefined,
  env: Record<string, string> | undefined,
  handlers: CommandHandlers,
  options: CommandExecutionOptions,
): RunningCommand {
  const startMs = Date.now();
  const isWindows = process.platform === "win32";
  const childEnv = buildChildEnv(isWindows, env);

  // Resolve the requested interpreter BEFORE anything is spawned. A value this
  // machine cannot honour is a property of the REQUEST plus this machine, so it
  // is answered exactly like a bad cwd: one clear error, no process, and never a
  // quiet fallback to the default shell.
  const plan = planExecShell(
    process.platform,
    options.shell,
    command,
    options.shellExists === undefined ? {} : { exists: options.shellExists },
  );
  if (!plan.ok) {
    queueMicrotask(() => handlers.onError(plan.message));
    return { kill() {} };
  }
  // On Windows with shell:"powershell" this is the base64-wrapped launcher line,
  // not the caller's script; everywhere else it is the caller's command verbatim.
  const effectiveCommand = plan.command;

  if (isWindows) {
    // Python can ignore the console code page for redirected stdio. These are
    // its documented UTF-8 switches; explicit command environment values win.
    setWindowsEnvDefault(childEnv, "PYTHONUTF8", "1");
    setWindowsEnvDefault(childEnv, "PYTHONIOENCODING", "utf-8");
  }

  let launcherRequest: Buffer | null = null;
  let program = effectiveCommand;
  if (isWindows) {
    try {
      program = resolveWindowsLauncherPath({
        explicitPath: options.windowsExecLauncherPath,
      });
      // The WRAPPED text is what the launcher (and therefore cmd.exe) sees, so
      // it is what has to satisfy the protocol's bounds — including the interior
      // line-break rejection. base64 has no line breaks, so a multi-line
      // PowerShell script passes here while a multi-line cmd command still does
      // not: in the first case the newline provably cannot reach cmd.exe, in the
      // second it provably would.
      launcherRequest = encodeWindowsLauncherRequest(effectiveCommand);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Windows command launcher is unavailable";
      queueMicrotask(() => handlers.onError(message));
      return { kill() {} };
    }
  }

  let proc: ReturnType<typeof spawn>;
  try {
    proc = isWindows
      ? spawn(program, [], {
          shell: false,
          cwd: cwd ?? process.env["USERPROFILE"] ?? process.env["HOME"],
          env: childEnv,
          stdio: ["pipe", "pipe", "pipe"],
          detached: false,
          windowsHide: true,
        })
      : spawn(program, [], {
          // `true` = /bin/sh, the historical default; a path when the caller
          // asked for a specific interpreter (see planExecShell).
          shell: plan.posixShell,
          cwd: cwd ?? process.env["HOME"],
          env: childEnv,
          stdio: ["ignore", "pipe", "pipe"],
          // Own process group so kill can signal the shell and all descendants.
          detached: true,
        });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    queueMicrotask(() => handlers.onError(message));
    return { kill() {} };
  }

  let closed = false;
  let settled = false;
  let pendingError: string | null = null;
  let terminationRequested = false;
  let launcherReady = !isWindows;
  let escalationTimer: ReturnType<typeof setTimeout> | null = null;
  let handshakeTimer: ReturnType<typeof setTimeout> | null = null;
  let drainTimer: ReturnType<typeof setTimeout> | null = null;
  const pendingStderr: Buffer[] = [];
  let pendingStderrBytes = 0;
  const handshake = isWindows ? new WindowsLauncherHandshakeDecoder() : null;

  const clearEscalation = () => {
    if (escalationTimer) {
      clearTimeout(escalationTimer);
      escalationTimer = null;
    }
  };
  const clearHandshakeTimer = () => {
    if (handshakeTimer) {
      clearTimeout(handshakeTimer);
      handshakeTimer = null;
    }
  };
  const clearDrainTimer = () => {
    if (drainTimer) {
      clearTimeout(drainTimer);
      drainTimer = null;
    }
  };
  const emitOutput = (chunk: Buffer, stream: "stdout" | "stderr") => {
    if (settled || pendingError !== null || chunk.length === 0) return;
    handlers.onOutput(chunk.toString("base64"), stream);
  };

  /**
   * The ONE transform this executor applies to a stream's bytes, and only on the
   * one path that created the thing it undoes: `shell: "powershell"`, where our
   * own -EncodedCommand wrapping makes PowerShell serialize its streams to stderr
   * as CLIXML (see powershell-clixml.ts, and exec-shell.ts for the wrapping).
   * `plan.clixmlStderr` is set there and nowhere else, so cmd, sh and bash get
   * `null` here and their stderr stays byte-for-byte what the process wrote.
   *
   * Every stderr byte goes through this single funnel — including the
   * pre-handshake bytes replayed after the Windows launcher becomes ready — so
   * the decoder sees the stream once, in order, exactly as the child wrote it.
   */
  const clixml = plan.clixmlStderr === true ? new PowerShellClixmlDecoder() : null;
  const emitStderr = (chunk: Buffer) => {
    emitOutput(clixml === null ? chunk : clixml.push(chunk), "stderr");
  };

  // Post-exit drain state (see EXIT_DRAIN_QUIET_MS). `drainExitCode` doubles as
  // "the drain is running": `undefined` = not draining, anything else = the exit
  // code we owe the caller once the pipes go quiet.
  let drainExitCode: number | null | undefined;
  let drainUntilMs = 0;
  let lastDataAtMs = 0;
  const finishDrain = () => {
    drainTimer = null;
    detachPipe(proc.stdout, onStdoutData);
    detachPipe(proc.stderr, onStderrData);
    settle(drainExitCode ?? null);
  };
  const scheduleDrainCheck = () => {
    const now = Date.now();
    // The caller's deadline outranks both drain constants. Whatever budget is
    // left (minus the guard) caps the absolute window AND the quiet poll: a
    // 250 ms cap is useless if the caller gives up in 40 ms, and a 25 ms poll
    // is still 25 ms of exposure if only 10 ms remain. With no deadline both
    // stay at their unclamped values.
    const budgetMs = options.deadlineMs === undefined
      ? Number.POSITIVE_INFINITY
      : options.deadlineMs - EXIT_DRAIN_DEADLINE_GUARD_MS - now;
    const maxMs = Math.min(EXIT_DRAIN_MAX_MS, budgetMs);
    if (maxMs <= 0) {
      // Already at (or past) the deadline: reporting the exit we have is the
      // whole point — a command that finished must not be called timed out.
      finishDrain();
      return;
    }
    const quietMs = Math.min(EXIT_DRAIN_QUIET_MS, maxMs);
    drainUntilMs = now + maxMs;
    const check = () => {
      drainTimer = null;
      const quietForMs = Date.now() - lastDataAtMs;
      const remainingMs = drainUntilMs - Date.now();
      if (quietForMs >= quietMs || remainingMs <= 0) {
        finishDrain();
        return;
      }
      drainTimer = setTimeout(check, Math.max(1, Math.min(quietMs - quietForMs, remainingMs)));
      drainTimer.unref?.();
    };
    drainTimer = setTimeout(check, quietMs);
    drainTimer.unref?.();
  };

  const signalTree = (signal: "SIGTERM" | "SIGKILL") => {
    if (closed || proc.pid == null) return;
    try {
      if (isWindows) {
        const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
        const killer = spawn(
          path.win32.join(systemRoot, "System32", "taskkill.exe"),
          ["/pid", String(proc.pid), "/T", "/F"],
          { shell: false, stdio: "ignore", windowsHide: true },
        );
        killer.on("error", () => {});
        killer.unref?.();
      } else {
        process.kill(-proc.pid, signal);
      }
    } catch {
      // The process tree is already gone.
    }
  };

  const requestTermination = (signal: "SIGTERM" | "SIGKILL") => {
    if (closed || terminationRequested) return;
    terminationRequested = true;
    signalTree(signal);
  };

  const recordSetupFailure = (message: string) => {
    if (settled || pendingError !== null) return;
    pendingError = message;
    clearHandshakeTimer();
    requestTermination("SIGKILL");
  };

  // Second half of the unknown-outcome signal (see the constants). Watched on
  // stderr only, because that is the one stream the launcher writes its notice
  // to, and carried across chunk boundaries by a tail of marker-length-1 bytes —
  // a pipe may split the notice anywhere. Scanning stops for good once found.
  const unknownOutcomeMarker = Buffer.from(WINDOWS_LAUNCHER_UNKNOWN_OUTCOME_MARKER, "ascii");
  let unknownOutcomeTail = Buffer.alloc(0);
  let unknownOutcomeSeen = false;
  const scanForUnknownOutcome = (chunk: Buffer) => {
    if (!isWindows || unknownOutcomeSeen || chunk.length === 0) return;
    const window = unknownOutcomeTail.length === 0
      ? chunk
      : Buffer.concat([unknownOutcomeTail, chunk]);
    if (window.includes(unknownOutcomeMarker)) {
      unknownOutcomeSeen = true;
      unknownOutcomeTail = Buffer.alloc(0);
      return;
    }
    const keep = unknownOutcomeMarker.length - 1;
    // Copied, never a subarray view: a view would pin the whole chunk in memory
    // for the rest of the command.
    unknownOutcomeTail = window.length <= keep
      ? Buffer.from(window)
      : Buffer.from(window.subarray(window.length - keep));
  };

  // Named rather than inline so the post-exit drain can take them off again
  // (detachPipe) — removing OUR listener is how we stop waiting on a pipe a
  // surviving grandchild still writes to.
  const onStdoutData = (chunk: Buffer) => {
    // Any traffic — including bytes we end up discarding — keeps the post-exit
    // drain open: what matters there is whether the pipes are still moving.
    lastDataAtMs = Date.now();
    if (pendingError !== null) return;
    if (!isWindows || launcherReady) {
      emitOutput(chunk, "stdout");
      return;
    }
    try {
      const result = handshake!.push(chunk);
      if (!result) return;
      if (result.kind === "error") {
        recordSetupFailure(result.message);
        return;
      }
      launcherReady = true;
      clearHandshakeTimer();
      for (const pending of pendingStderr) emitStderr(pending);
      pendingStderr.length = 0;
      emitOutput(result.trailingOutput, "stdout");
    } catch (err) {
      recordSetupFailure(
        err instanceof Error ? err.message : "Windows command launcher handshake failed",
      );
    }
  };
  proc.stdout?.on("data", onStdoutData);

  const onStderrData = (chunk: Buffer) => {
    lastDataAtMs = Date.now();
    scanForUnknownOutcome(chunk);
    if (pendingError !== null) return;
    if (!isWindows || launcherReady) {
      emitStderr(chunk);
      return;
    }
    pendingStderrBytes += chunk.length;
    if (pendingStderrBytes > MAX_PRE_HANDSHAKE_STDERR_BYTES) {
      recordSetupFailure("Windows command launcher produced output before it was ready");
      return;
    }
    pendingStderr.push(Buffer.from(chunk));
  };
  proc.stderr?.on("data", onStderrData);

  const settle = (code: number | null) => {
    if (settled) return;
    // BEFORE `settled` is set, because emitOutput refuses to run afterwards. A
    // CLIXML block can be cut off mid-record — PowerShell killed, output
    // truncated at the relay's cap — and the decoder is holding those bytes
    // waiting for a closing tag that will never come. Flushing them here is what
    // makes "nothing the command wrote is ever lost" true rather than
    // approximately true; they come out verbatim, which is the honest rendering
    // of a fragment. A no-op on every non-PowerShell path (clixml === null).
    if (clixml !== null) emitOutput(clixml.flush(), "stderr");
    const error = pendingError ?? (isWindows && !launcherReady
      ? "Windows command launcher exited before it was ready"
      : isWindows && code === WINDOWS_LAUNCHER_UNKNOWN_OUTCOME_EXIT_CODE && unknownOutcomeSeen
        // The launcher's console stage vanished AFTER the ready handshake, so it
        // never reported the shell's exit code and nothing here knows what the
        // command did. BOTH halves of its signal are present — the sentinel
        // status and the marker it wrote to stderr on that path only — so this is
        // not a command that happened to return the sentinel itself, which is
        // reported as the ordinary result it is. Past the handshake every other
        // path in this function ends in onDone, and onDone(some number) is
        // indistinguishable from a real result; the one thing we must never do
        // with an unknown outcome is dress it as known.
        ? "The Windows command launcher's console stage exited without reporting the command's result. " +
          "The command's outcome is UNKNOWN — it may have finished, failed, or still be running — so do not " +
          "treat this as a completed run. Any side effects it had have already happened; check the machine " +
          "before re-running anything that is not safe to repeat."
        : null);
    settled = true;
    clearEscalation();
    clearHandshakeTimer();
    clearDrainTimer();
    if (error !== null) {
      handlers.onError(error);
      return;
    }
    handlers.onDone(code ?? -1, Date.now() - startMs);
  };

  proc.on("exit", (code) => {
    // The COMMAND is over here. 'close' additionally waits for every inherited
    // pipe write end to be gone, and a backgrounded grandchild (`sleep 20 &`)
    // holds ours open for as long as it likes — which used to stall a
    // millisecond-long command until the caller's timeout. So drain what the
    // pipes still hold, then report, and leave the survivor alone: starting a
    // daemon with `... &` is a legitimate thing to ask for. "Leave alone" is
    // enforced by detachPipe, which stops us WAITING on those pipes without
    // closing them under a live writer — see the rationale there.
    if (settled || drainExitCode !== undefined) return;
    drainExitCode = code;
    // ORDER MATTERS, and this is the part two reviewers landed on independently:
    // signalling stops the INSTANT the child is reaped, before the drain, not
    // after it. Node has already waitpid()ed this pid by the time 'exit' fires,
    // so the kernel may hand the number to somebody else's process — and we
    // signal the process GROUP, `-pid`, which is a much bigger blast radius
    // than one stray pid. A pending SIGKILL escalation from an earlier kill()
    // must therefore be cancelled here rather than being allowed to fire during
    // the drain window, and `closed` must be set here so a kill() arriving
    // during the window cannot arm a new one. The command is over; the only
    // thing left to do is read the pipes.
    closed = true;
    clearEscalation();
    scheduleDrainCheck();
  });

  proc.on("close", (code) => {
    closed = true;
    clearEscalation();
    clearHandshakeTimer();
    clearDrainTimer();
    settle(code);
  });

  proc.on("error", (err) => {
    if (settled) return;
    // A spawn failure has no live process and is not guaranteed to produce a
    // useful close lifecycle. Deliver it immediately. Errors from a process
    // that did start are terminalized only after close, like setup failures.
    if (proc.pid == null) {
      closed = true;
      settled = true;
      clearEscalation();
      clearHandshakeTimer();
      handlers.onError(pendingError ?? err.message);
      return;
    }
    recordSetupFailure(err.message);
  });

  if (isWindows) {
    handshakeTimer = setTimeout(() => {
      handshakeTimer = null;
      recordSetupFailure("Windows command launcher did not become ready");
    }, WINDOWS_LAUNCHER_HANDSHAKE_TIMEOUT_MS);
    handshakeTimer.unref?.();

    proc.stdin?.on("error", (err) => {
      if (!launcherReady) {
        recordSetupFailure(`Windows command launcher input failed: ${err.message}`);
      }
    });
    proc.stdin?.end(launcherRequest!);
  }

  return {
    kill: () => {
      if (closed || terminationRequested) return;
      requestTermination("SIGTERM");
      clearEscalation();
      escalationTimer = setTimeout(() => {
        escalationTimer = null;
        signalTree("SIGKILL");
      }, KILL_ESCALATION_MS);
      escalationTimer.unref?.();
    },
  };
}
