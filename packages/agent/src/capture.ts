import { spawn } from "node:child_process";

/**
 * "The OS said no" and "I could not ask the OS" are DIFFERENT answers, and this
 * module exists so no caller has to remember that on its own. It is the command
 * half of what doctor/checks/presence.ts is for the filesystem, and it exists for
 * the same reason: the single-valued shape underneath both is a machine for
 * rounding "could not check" down to whichever neighbour happens to be
 * convenient.
 *
 * The shape it replaces is `installed-version.ts`'s `runCapture`, which returns
 * `""` for a spawn failure, a non-zero exit, a timeout, an AppLocker or
 * ConstrainedLanguage block, an access error, AND for a command that ran fine
 * and printed nothing. Every wrong direction has already been shipped on the
 * strength of that one value:
 *
 *   - `reg.exe` that never ran was reported as "no AI Commander value under
 *     HKCU\…\Run, which is normal";
 *   - `launchctl print system/<label>` that exited non-zero UNDER ROOT — i.e.
 *     the daemon is not loaded — was reported as "not readable from here, it
 *     needs root", on the one check whose job is to separate "registered" from
 *     "running".
 *
 * `queryScheduledTask` (windows-scheduled-task.ts) had to grow a `QUERIED=1`
 * sentinel inside its PowerShell script to escape the same trap. This is that
 * sentinel, for every command, from outside the command.
 *
 * ── WHY IT LIVES AT src/ AND NOT UNDER doctor/ ───────────────────────────────
 * It started in `doctor/checks/`, where all of its first callers were. But
 * `windows-scheduled-task.ts` — asked on every reconcile by the fail-closed
 * `elevated-availability.ts` — needs exactly this tri-state, and that module may
 * not import from the diagnostics subtree: runtime logic that depends on a
 * report the user asks for cannot be moved, removed or reasoned about on its
 * own. Re-exporting it from `doctor/` would have been the same edge with an
 * extra hop. So the primitive sits beside `installed-version.ts`, the other
 * "shell out and read the answer" module, and `doctor/` imports UP like everyone
 * else.
 *
 * A caller reads `kind` BEFORE it says anything about the machine:
 *   `output`      — it ran, exited 0, and here is its stdout (possibly empty:
 *                   "it ran and printed nothing" is itself a measurement);
 *   `failed`      — it ran and exited non-zero. A statement about the machine
 *                   for a command whose non-zero exit MEANS something (`launchctl
 *                   print` on a service launchd does not have), and nothing more
 *                   than "it did not work" for one where it does not;
 *   `unavailable` — it never ran, or was killed: a statement about the
 *                   DIAGNOSTIC, never about the machine.
 */
export type Captured =
  | { kind: "output"; stdout: string }
  | { kind: "failed"; stdout: string; code: number | null; signal: string | null }
  /**
   * `partialStdout` is whatever reached us before the command was killed —
   * usually "", and never a measurement in its own right, which is why it is not
   * called `stdout` and cannot be read without narrowing to this branch.
   *
   * It is kept for ONE shape, and that shape is not an optimisation: a script
   * that flushes a sentinel of ours FIRST and then does the slow thing has
   * already answered by the time the deadline kills it. `Get-ScheduledTask`
   * cold-loading the ScheduledTasks CIM module under a behavioural AV scan is
   * precisely that case — the `QUERIED=1` bytes are on the pipe, and discarding
   * them turns "Windows answered, and did not name the task" (a verdict) into
   * "we never asked" (an unknown, published as `endpoint_unreachable` ten
   * TTL-minutes at a time). Read it only through `capturedStdout`, which
   * documents the rule.
   */
  | { kind: "unavailable"; reason: string; partialStdout: string };

/**
 * Mirrors installed-version.ts's own budget. Duplicated rather than imported so
 * these probes cannot be re-tuned by a change made for the version probe: they
 * run while a user waits at a prompt, and the tray runs them on Electron's main
 * loop. A caller with a genuinely slower question passes its own `timeoutMs`
 * (see SCHEDULED_TASK_QUERY_TIMEOUT_MS).
 */
export const CAPTURE_TIMEOUT_MS = 5_000;
const MAX_CAPTURE_BYTES = 8 * 1024;

/** How a caller may bend the defaults. */
export interface CaptureOptions {
  /** Override CAPTURE_TIMEOUT_MS for a question known to be slower. */
  timeoutMs?: number;
}

/**
 * Run a command and report WHAT HAPPENED, not just what it printed.
 *
 * Never throws, never uses a shell, and never inherits stdin. stderr is
 * discarded: callers parse stdout and a command's error text is not something
 * the redacted report bundle may carry (doctor/types.ts).
 */
export function runCaptured(command: string, args: string[], opts?: CaptureOptions): Promise<Captured> {
  const timeoutMs = opts?.timeoutMs ?? CAPTURE_TIMEOUT_MS;
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const captured = (): string => Buffer.concat(chunks).toString("utf8");
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, { stdio: ["ignore", "pipe", "ignore"] });
    } catch (err) {
      resolve({
        kind: "unavailable",
        reason: `${command} could not be started: ${message(err)}`,
        partialStdout: "",
      });
      return;
    }
    const finish = (value: Captured) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
      finish({
        kind: "unavailable",
        reason: `${command} did not answer within ${timeoutMs} ms and was stopped`,
        // Whatever it had already said. See the `unavailable` variant's comment:
        // a sentinel flushed before the deadline is an answer, and throwing it
        // away is how a slow box loses the only verdict it can produce.
        partialStdout: captured(),
      });
    }, timeoutMs);
    timer.unref?.();
    child.stdout?.on("data", (chunk: Buffer) => {
      if (bytes > MAX_CAPTURE_BYTES) return;
      bytes += chunk.length;
      chunks.push(Buffer.from(chunk));
    });
    child.on("error", (err) => {
      finish({
        kind: "unavailable",
        reason: `${command} could not be run: ${message(err)}`,
        partialStdout: captured(),
      });
    });
    child.on("close", (code, signal) => {
      const stdout = captured();
      finish(
        code === 0
          ? { kind: "output", stdout }
          : { kind: "failed", stdout, code: code ?? null, signal: signal ?? null },
      );
    });
  });
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * The one-line reason a `Captured` did not produce an answer — for the `detail`
 * of a `skipped` check, which has to say WHY it was skipped.
 */
export function unavailableReason(captured: Captured): string {
  if (captured.kind === "unavailable") return captured.reason;
  if (captured.kind === "failed") {
    return `it exited ${captured.signal ? `on ${captured.signal}` : `with status ${captured.code ?? "unknown"}`}`;
  }
  return "";
}

/**
 * The stdout of a command that SAID SOMETHING — whether or not it exited 0, and
 * whether or not it was still running when the deadline killed it.
 *
 * For the sentinel shape ONLY — a script that prints a token of ours on the path
 * we care about (`echo VERIFIED`, `Write-Output 'QUERIED=1'`), where the token's
 * PRESENCE is the measurement and neither the exit status nor a later timeout
 * can unsay it. Anywhere else this is the very collapse capture.ts exists to
 * prevent: read `kind`.
 */
export function capturedStdout(captured: Captured): string {
  return captured.kind === "unavailable" ? captured.partialStdout : captured.stdout;
}
