// Hardened privileged spawn: pinned shell, minimal locked env, locked PATH, a
// local monotonic timeout backstop, and output caps. Runs the (already-verified)
// command as root / LocalSystem.

import { spawn, execFileSync } from "node:child_process";
import { isAbsolute } from "node:path";
import { KILL_ESCALATION_MS } from "@aicommander/protocol";
import {
  encodeWindowsLauncherRequest,
  resolvePrivilegedWindowsLauncher,
  WindowsLauncherHandshakeDecoder,
  WINDOWS_LAUNCHER_HANDSHAKE_TIMEOUT_MS,
} from "./windows-exec-launcher.js";
import type {
  ExecHandlers,
  PrivilegedExecutor,
  RunningPrivilegedCommand,
} from "./types.js";
import type { ElevatedCapabilityClaims } from "@aicommander/protocol";

const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_TIMEOUT_MS = 60 * 60_000;
const MIN_TIMEOUT_MS = 1000;

/** Well-known, locale-independent SID for the Windows LocalSystem account. */
const LOCAL_SYSTEM_SID = "S-1-5-18";

/** Short SIGTERM→SIGKILL grace used on shutdown ({ hard: true }) so a
 *  TERM-ignoring detached child is reaped before process.exit, not left to
 *  survive a restart/upgrade/uninstall. */
const HARD_KILL_GRACE_MS = 400;
const MAX_PRE_HANDSHAKE_STDERR_BYTES = 64 * 1024;

/**
 * Caller-supplied env keys that can hijack a child via dynamic-linker /
 * interpreter hooks. Any LD_ / DYLD_ prefixed var is stripped by pattern; the rest are
 * exact (case-insensitive) key matches. This list covers keys the locked base
 * does NOT set (and keys it only sets on the OTHER platform — HOME/USER on
 * Windows, SystemRoot/windir on POSIX, which must stay stripped everywhere).
 * Everything the base DOES set is stripped as well, derived from the base itself
 * by `lockedEnvKeys()` — see there for why that is not a hand-maintained list.
 */
const ENV_DANGER_KEYS = new Set([
  "NODE_OPTIONS", "BASH_ENV", "ENV", "IFS", "PYTHONSTARTUP", "PYTHONPATH",
  "PERL5OPT", "RUBYOPT", "GIT_EXTERNAL_DIFF", "COMSPEC",
  "PATH", "HOME", "USER", "LOGNAME", "SYSTEMROOT", "WINDIR",
]);

/**
 * Upper-cased key set of the locked base env. The overlay (`{ ...caller, ...base }`)
 * is a case-SENSITIVE object merge, while Windows and libuv resolve env names
 * case-INSENSITIVELY — so a caller spelling of `PROGRAMDATA` next to the base's
 * `ProgramData` would land in the same block as two distinct keys and let the
 * platform, not this code, pick the winner. Deriving the filter from the base's
 * own keys makes that class of bug structurally impossible: any variable added to
 * `lockedBaseEnv()` is automatically unshadowable in every casing, with no second
 * list to keep in sync.
 */
const lockedEnvKeys = (base: Record<string, string>): Set<string> =>
  new Set(Object.keys(base).map((k) => k.toUpperCase()));

const isDangerEnvKey = (k: string, locked: Set<string>): boolean => {
  const up = k.toUpperCase();
  return /^LD_/.test(up) || /^DYLD_/.test(up) || ENV_DANGER_KEYS.has(up) || locked.has(up);
};

function lockedBaseEnv(): Record<string, string> {
  if (process.platform === "win32") {
    const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
    const systemDrive = process.env["SystemDrive"] ?? "C:";
    const programData = process.env["ProgramData"] ?? `${systemDrive}\\ProgramData`;
    return {
      SystemRoot: systemRoot,
      windir: systemRoot,
      // %ProgramData% (and its long-standing ALLUSERSPROFILE alias — scripts read
      // one or the other) is where practically every machine-wide admin script
      // keeps its state, so leaving it out silently breaks them. It is NOT a
      // caller-controlled value despite being a directory a privileged script
      // writes to (win-updater.ps1 stages the installer, purges and re-DACLs a
      // tree, and writes its SYSTEM log under it): the filter above strips every
      // caller spelling of a locked-base key, so the value here always wins. The
      // value comes from the helper's own env — the helper runs as LocalSystem,
      // so that env is machine-level and not settable by an unprivileged user.
      ProgramData: programData,
      ALLUSERSPROFILE: programData,
      // WindowsPowerShell\v1.0 lives INSIDE System32 (already trusted, already
      // first on this PATH), so adding it changes nothing about the security
      // model — a locked PATH must not be a substitution vector, hence it goes
      // LAST. Without it `powershell` is simply not found, and on Windows
      // practically all administration is PowerShell. PowerShell 7
      // (C:\Program Files\PowerShell) is deliberately NOT added: user-installed,
      // outside the trusted tree.
      PATH: `${systemRoot}\\System32;${systemRoot};${systemRoot}\\System32\\Wbem;${systemRoot}\\System32\\WindowsPowerShell\\v1.0`,
    };
  }
  return {
    // No user/group-writable dirs (e.g. /usr/local/{s}bin, admin-writable on
    // macOS): a locked PATH must not be a root-planting vector.
    PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/var/root",
    USER: "root",
    LOGNAME: "root",
  };
}

function defaultCwd(): string {
  if (process.platform === "win32") return process.env["SystemRoot"] ?? "C:\\Windows";
  return "/";
}

export interface PrivilegedExecutorOptions {
  /** Cap on total base64-decoded output bytes across both streams. */
  maxOutputBytes?: number;
  /** Upper clamp on the caller's timeoutMs. */
  maxTimeoutMs?: number;
  /**
   * Escape hatch for tests: run even when the helper is NOT actually privileged.
   * In production this MUST stay false — a non-privileged launch while the client
   * believes it's elevated is fail-OPEN, so `run()` refuses by default.
   */
  allowUnprivileged?: boolean;
}

function setWindowsEnvDefault(env: Record<string, string>, key: string, value: string): void {
  const upper = key.toUpperCase();
  if (Object.keys(env).some((candidate) => candidate.toUpperCase() === upper)) return;
  env[key] = value;
}

/**
 * Resolve the REAL identity the helper process runs under.
 *  - darwin/linux: "root" (uid 0) or "uid=N".
 *  - win32: the `whoami` display name (e.g. "nt authority\\system"), resolved
 *    ONCE via %SystemRoot%\System32\whoami.exe. Display only — NOT used for the
 *    privilege decision (whoami localizes the authority name). Returns null if it
 *    can't run.
 */
function resolveWin32Identity(): string | null {
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  try {
    const out = execFileSync(`${systemRoot}\\System32\\whoami.exe`, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.trim().toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Locale-independent LocalSystem check: `whoami /user` prints the account SID,
 * which is the same on every localized Windows (unlike the display name, which is
 * translated). The helper is treated as privileged IFF the output contains the
 * well-known LocalSystem SID S-1-5-18. Best-effort + fail closed: any failure to
 * resolve ⇒ NOT privileged.
 */
function resolveWin32IsLocalSystem(): boolean {
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  try {
    const out = execFileSync(
      `${systemRoot}\\System32\\whoami.exe`,
      ["/user", "/fo", "list"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    return out.includes(LOCAL_SYSTEM_SID);
  } catch {
    return false;
  }
}

/** Create the platform privileged executor (root on macOS, LocalSystem on Windows). */
export function createPrivilegedExecutor(
  opts?: PrivilegedExecutorOptions,
): PrivilegedExecutor {
  const maxOutputBytes = opts?.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const maxTimeoutMs = opts?.maxTimeoutMs ?? DEFAULT_MAX_TIMEOUT_MS;
  const allowUnprivileged = opts?.allowUnprivileged ?? false;

  // win32 state is resolved once (whoami is not free). `win32Identity` is the
  // display name (handshake/audit only); `win32IsLocalSystem` is the go/no-go
  // privilege decision, based on the locale-independent SID.
  const win32Identity =
    process.platform === "win32" ? resolveWin32Identity() : null;
  const win32IsLocalSystem =
    process.platform === "win32" ? resolveWin32IsLocalSystem() : false;

  const effectiveIdentity = (): string => {
    if (process.platform === "win32") {
      return win32Identity ?? "unknown";
    }
    return process.getuid?.() === 0 ? "root" : `uid=${String(process.getuid?.())}`;
  };

  // True only when the helper is REALLY running elevated.
  const isActuallyPrivileged = (): boolean => {
    if (process.platform === "win32") {
      // SID-based, locale-independent: the display name is translated on
      // localized Windows and must NOT gate execution.
      return win32IsLocalSystem;
    }
    return process.getuid?.() === 0;
  };

  return {
    effectiveIdentity,

    run(claims: ElevatedCapabilityClaims, handlers: ExecHandlers): RunningPrivilegedCommand {
      const start = Date.now();

      // Fired exactly once when the command is terminally gone (real 'close', or
      // a no-spawn failure). Lets the caller keep the lease until the process
      // actually exits, so a failed-but-still-alive child stays reapable.
      let closedFired = false;
      const notifyClosed = () => {
        if (closedFired) return;
        closedFired = true;
        handlers.onClosed?.();
      };

      // Fail CLOSED: never run a command unprivileged while the client believes
      // it's elevated. Tests opt out via { allowUnprivileged: true }.
      if (!isActuallyPrivileged() && !allowUnprivileged) {
        queueMicrotask(() => {
          handlers.onError(
            "privileged helper is not running with elevated privileges — refusing to execute",
          );
          notifyClosed();
        });
        return { kill() {} };
      }

      // cwd: absolute required. Relative fails closed WITHOUT spawning.
      let cwd: string;
      if (claims.cwd != null) {
        if (!isAbsolute(claims.cwd)) {
          queueMicrotask(() => {
            handlers.onError("cwd must be absolute");
            notifyClosed();
          });
          return { kill() {} };
        }
        cwd = claims.cwd;
      } else {
        cwd = defaultCwd();
      }

      // env: minimal LOCKED base, overlay filtered caller env, base always wins.
      const base = lockedBaseEnv();
      const locked = lockedEnvKeys(base);
      const filteredCallerEnv: Record<string, string> = {};
      for (const [k, v] of Object.entries(claims.env ?? {})) {
        if (!isDangerEnvKey(k, locked)) filteredCallerEnv[k] = v;
      }
      const childEnv = { ...filteredCallerEnv, ...base };
      if (process.platform === "win32") {
        // Redirected Python stdio can ignore the console code page. Preserve an
        // explicit signed override, otherwise request Python's documented UTF-8
        // mode just like the ordinary agent executor.
        setWindowsEnvDefault(childEnv, "PYTHONUTF8", "1");
        setWindowsEnvDefault(childEnv, "PYTHONIOENCODING", "utf-8");
      }

      // Pinned invocation (shell:false, argv explicit). Windows uses the exact
      // signed native launcher shared with ordinary exec: it creates a hidden
      // console, pins both code pages to UTF-8, and then starts system cmd.exe.
      // The command itself travels only over the bounded stdin protocol.
      let cmd: string;
      let args: string[];
      let launcherRequest: Buffer | null = null;
      if (process.platform === "win32") {
        try {
          cmd = resolvePrivilegedWindowsLauncher();
          launcherRequest = encodeWindowsLauncherRequest(claims.command);
        } catch (err) {
          queueMicrotask(() => {
            handlers.onError(err instanceof Error ? err.message : String(err));
            notifyClosed();
          });
          return { kill() {} };
        }
        args = [];
      } else {
        cmd = "/bin/sh";
        args = ["-c", claims.command];
      }

      let settled = false;
      let outputBytes = 0;
      let escalationTimer: ReturnType<typeof setTimeout> | null = null;
      let timeoutTimer: ReturnType<typeof setTimeout> | null = null;
      let handshakeTimer: ReturnType<typeof setTimeout> | null = null;
      let proc: ReturnType<typeof spawn> | null = null;
      let launcherReady = process.platform !== "win32";
      const pendingStderr: Buffer[] = [];
      let pendingStderrBytes = 0;
      const handshake = process.platform === "win32"
        ? new WindowsLauncherHandshakeDecoder()
        : null;

      const clearTimeoutTimer = () => {
        if (timeoutTimer) { clearTimeout(timeoutTimer); timeoutTimer = null; }
      };
      const clearEscalationTimer = () => {
        if (escalationTimer) { clearTimeout(escalationTimer); escalationTimer = null; }
      };
      const clearHandshakeTimer = () => {
        if (handshakeTimer) { clearTimeout(handshakeTimer); handshakeTimer = null; }
      };

      const signalTree = (signal: "SIGTERM" | "SIGKILL") => {
        if (proc?.pid == null) return;
        try {
          if (process.platform === "win32") {
            spawn("taskkill", ["/pid", String(proc.pid), "/T", "/F"], { stdio: "ignore" });
          } else {
            process.kill(-proc.pid, signal);
          }
        } catch {
          // Process group already gone — nothing to signal.
        }
      };

      const killTree = (hard = false) => {
        signalTree("SIGTERM");
        const grace = hard ? HARD_KILL_GRACE_MS : KILL_ESCALATION_MS;
        if (escalationTimer) {
          // Already escalating (soft). A hard kill (shutdown) must reap FAST, so
          // shorten the pending grace; a soft re-kill leaves it as-is.
          if (!hard) return;
          clearTimeout(escalationTimer);
          escalationTimer = null;
        }
        escalationTimer = setTimeout(() => {
          escalationTimer = null;
          signalTree("SIGKILL");
        }, grace);
        escalationTimer.unref?.();
      };

      const fail = (message: string) => {
        if (settled) return;
        settled = true;
        // Clear ONLY the timeout backstop. The escalation timer (SIGTERM→SIGKILL)
        // MUST be left armed so a SIGTERM-ignoring child is still force-killed
        // even after this terminal error is reported — otherwise it's orphaned.
        clearTimeoutTimer();
        clearHandshakeTimer();
        handlers.onError(message);
      };

      try {
        proc = spawn(cmd, args, {
          cwd,
          env: childEnv,
          stdio: process.platform === "win32"
            ? ["pipe", "pipe", "pipe"]
            : ["ignore", "pipe", "pipe"],
          detached: process.platform !== "win32",
          shell: false,
          ...(process.platform === "win32" ? { windowsHide: true } : {}),
        });
      } catch (err) {
        queueMicrotask(() => {
          fail(err instanceof Error ? err.message : String(err));
          notifyClosed();
        });
        return { kill() {} };
      }

      const onChunk = (chunk: Buffer, stream: "stdout" | "stderr") => {
        if (settled || chunk.length === 0) return;
        outputBytes += chunk.length;
        if (outputBytes > maxOutputBytes) {
          killTree();
          fail("elevated command exceeded output limit");
          return;
        }
        handlers.onOutput(chunk.toString("base64"), stream);
      };
      proc.stdout?.on("data", (chunk: Buffer) => {
        if (settled) return;
        if (launcherReady) {
          onChunk(chunk, "stdout");
          return;
        }
        try {
          const result = handshake!.push(chunk);
          if (!result) return;
          if (result.kind === "error") {
            killTree();
            fail(result.message);
            return;
          }
          launcherReady = true;
          clearHandshakeTimer();
          for (const pending of pendingStderr) onChunk(pending, "stderr");
          pendingStderr.length = 0;
          onChunk(result.trailingOutput, "stdout");
        } catch (err) {
          killTree();
          fail(err instanceof Error ? err.message : "Windows command launcher handshake failed");
        }
      });
      proc.stderr?.on("data", (chunk: Buffer) => {
        if (settled) return;
        if (launcherReady) {
          onChunk(chunk, "stderr");
          return;
        }
        pendingStderrBytes += chunk.length;
        if (pendingStderrBytes > MAX_PRE_HANDSHAKE_STDERR_BYTES) {
          killTree();
          fail("Windows command launcher produced output before it was ready");
          return;
        }
        pendingStderr.push(Buffer.from(chunk));
      });

      proc.on("close", (code) => {
        // The process (group) is GONE. Always clear BOTH timers FIRST — there is
        // nothing left to escalate to, and a pending SIGKILL would otherwise fire
        // later against a possibly-RECYCLED process-group id. Only THEN gate the
        // onDone reporting on `settled` (a timeout/output-cap may already have
        // reported a terminal error for this command).
        clearTimeoutTimer();
        clearEscalationTimer();
        clearHandshakeTimer();
        // The process is truly gone: release the lease (terminal, always fires),
        // even if a prior fail() already reported a terminal error to the client.
        notifyClosed();
        if (settled) return;
        if (!launcherReady) {
          settled = true;
          handlers.onError("Windows command launcher exited before it was ready");
          return;
        }
        settled = true;
        handlers.onDone(code ?? -1, Date.now() - start);
      });
      proc.on("error", (err) => {
        // A spawn/kill 'error' may NOT be followed by 'close' (e.g. the child was
        // never created), so this handler must ALSO release the lease + clear
        // timers — `notifyClosed` is the SOLE lease-removal path, and leaving it
        // unfired here would leak the lease in the boot-persistent root daemon.
        clearTimeoutTimer();
        clearEscalationTimer();
        clearHandshakeTimer();
        fail(err.message);
        notifyClosed();
      });

      if (process.platform === "win32") {
        handshakeTimer = setTimeout(() => {
          handshakeTimer = null;
          killTree();
          fail("Windows command launcher did not become ready");
        }, WINDOWS_LAUNCHER_HANDSHAKE_TIMEOUT_MS);
        handshakeTimer.unref?.();
        proc.stdin?.on("error", (err) => {
          if (!launcherReady) {
            killTree();
            fail(`Windows command launcher input failed: ${err.message}`);
          }
        });
        proc.stdin?.end(launcherRequest!);
      }

      // Local monotonic timeout backstop, clamped.
      const timeoutMs = Math.min(Math.max(claims.timeoutMs, MIN_TIMEOUT_MS), maxTimeoutMs);
      timeoutTimer = setTimeout(() => {
        timeoutTimer = null;
        killTree();
        fail(`elevated command timed out after ${timeoutMs}ms`);
      }, timeoutMs);
      timeoutTimer.unref?.();

      return {
        kill(killOpts) {
          // Gate on the process being truly GONE, not on `settled`: a command
          // that already reported a terminal error (timeout/output-cap) may still
          // be alive (TERM-ignoring child), and a HARD kill on shutdown must still
          // be able to shorten its escalation and reap it.
          if (closedFired) return;
          killTree(killOpts?.hard ?? false);
          clearTimeoutTimer();
          clearHandshakeTimer();
        },
      };
    },
  };
}
