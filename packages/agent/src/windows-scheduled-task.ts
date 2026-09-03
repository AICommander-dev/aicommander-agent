import path from "node:path";
import { capturedStdout, runCaptured, unavailableReason } from "./capture.js";
import { powerShellSingleQuote } from "./installed-version.js";

/**
 * "Has Windows been told to run this?" — asked of Task Scheduler, by name.
 *
 * A RUNTIME question, not a diagnostic one. `elevated-availability.ts` asks it
 * on every reconcile to decide which word a machine with no reachable helper
 * publishes to the relay (`not_registered` vs `endpoint_unreachable`), and the
 * doctor asks the same question when it prints a report. It lives here, on its
 * own, because the dependency may only run in that direction: fail-closed
 * runtime logic must not import from the diagnostics subtree, or removing or
 * moving `doctor/` breaks the agent and the availability rule can no longer be
 * reasoned about by itself. The tri-state capture primitive it is built on
 * (capture.ts) was moved out of `doctor/checks/` for exactly that reason.
 *
 * THERE IS ONE OF THESE. There were briefly two — the doctor's and the
 * runtime's — and they diverged on the case that matters most, which is how the
 * `queried` sentinel came to be computed by one copy and thrown away by the
 * other. `doctor/checks/windows.ts` re-exports this module; it does not have its
 * own.
 *
 * FULL PATHS, NEVER BARE NAMES. `powershell.exe` is spelled out under
 * `%SystemRoot%\System32`: this runs from the tray, from a service and from the
 * SYSTEM-owned helper, and in none of those is `PATH` ours to trust.
 *
 * NOTHING READ HERE EVER BECOMES SOMETHING WE RUN. The only value interpolated
 * into the script is a compile-time constant of ours, quoted as a PowerShell
 * literal; everything Windows answers is parsed and reported.
 */

/** `C:\Windows`, or whatever this machine calls it. */
export function systemRoot(): string {
  return process.env["SystemRoot"] ?? process.env["windir"] ?? "C:\\Windows";
}

export function powerShellPath(): string {
  return path.join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/**
 * How long the scheduled-task query may take before we give up on it.
 *
 * Far above `capture.ts`'s 5 s default, and deliberately: `Get-ScheduledTask`
 * cold-loads the ScheduledTasks CIM module on first use, and on a box under
 * behavioural AV scanning — the machine this whole effort is aimed at — that
 * alone regularly runs past five seconds. A timeout there is not a cheap "we
 * could not tell": it is the reason the incident machine could never produce
 * `not_registered`, the one verdict worth producing. Still bounded, because
 * nothing that can hang may sit on the reconcile path.
 */
export const SCHEDULED_TASK_QUERY_TIMEOUT_MS = 25_000;

/** What Windows said about a task it DOES know about, or does not. */
interface ScheduledTaskAnswer {
  /**
   * Whether the QUESTION was actually answered — i.e. PowerShell ran and told us
   * something, as opposed to not running at all.
   *
   * This is the discriminant of the union, and that is the point: `registered`
   * exists ONLY on this branch, so a caller cannot obtain "is it registered"
   * without having first established that the question was answered. Reading a
   * bare boolean was possible for one release and produced three separate bugs,
   * all of the same shape — "we could not ask" published as "it was never
   * registered", which is the 2026-09-02 incident's own signature invented on a
   * machine that may be perfectly healthy.
   */
  queried: true;
  /** Windows named the task (`false` = Windows answered and did not name it). */
  registered: boolean;
  state: string | null;
  /** The action's own program (`powershell.exe`, the tray exe, …). */
  execute: string | null;
  /** The action's argument string, as registered. */
  args: string | null;
  /**
   * Whether the process that ASKED is a member of Administrators — `null` when
   * even the identity call was refused.
   *
   * It changes what an absent task means. Task Scheduler enforces a per-task
   * ACL, and the installer registers the Relaunch task with SDDL
   * `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)` — SYSTEM and Administrators only, no
   * Users grant (desktop/build/win-update-task.ps1, `$relaunchSddl`). A
   * standard-user tray asking about it is told there is no such task, which is
   * indistinguishable from its never having been registered. Without this, "the
   * task is missing" would fire on every packaged install running as a normal
   * user — the false alarm that costs a diagnostic its credibility.
   */
  elevated: boolean | null;
}

/** The query itself did not run. A statement about US, never about the machine. */
interface ScheduledTaskUnanswered {
  queried: false;
  /** Why, in one line, for the `detail` of a check that reports itself skipped. */
  reason: string;
}

/**
 * Windows' answer, or the absence of one.
 *
 * Three states, not two: registered, answered-and-absent, and never-asked. The
 * third has no `registered` field at all — see `queried`.
 */
export type ScheduledTaskInfo = ScheduledTaskAnswer | ScheduledTaskUnanswered;

/**
 * Ask Windows about ONE scheduled task by its constant name.
 *
 * `queried: true` means Windows answered — INCLUDING the case where the answer
 * arrived as partial output before the deadline killed the process, but NOT the
 * case where the process was killed while the lookup was still running. Starting
 * to ask is not being answered. `queried: false` means we could not ask, and no
 * caller may read it as "the task is absent".
 */
export async function queryScheduledTask(
  name: string,
  opts?: { timeoutMs?: number },
): Promise<ScheduledTaskInfo> {
  // TWO MARKERS, AND THEY MEAN DIFFERENT THINGS.
  //
  // `QUERIED=1` is printed before anything is looked up, so an empty stdout means
  // the query never ran (no PowerShell, a timeout before the shell said anything,
  // a policy block) rather than "no such task" — the distinction the original
  // script could not make. But it proves only that PowerShell STARTED. A run
  // killed at its deadline while `Get-ScheduledTask` cold-loads the CIM module
  // has flushed `QUERIED=1` and nothing else, and reading that as "Windows
  // answered and did not name the task" invents the very verdict this module
  // exists to withhold — a definite answer to a question nobody answered. That
  // was shipped once, on the reasoning that "the sentinel survives the timeout";
  // the sentinel survives, the ANSWER does not.
  //
  // `ANSWERED=1` is printed once the lookup has RETURNED, and it is what
  // `registered: false` now rests on. It comes after the STATE line and before
  // the action lines, so every partial output still says as much as it honestly
  // can: killed before the lookup returns → `QUERIED=1` alone → "we could not
  // ask"; killed while printing the actions → STATE and ANSWERED are already on
  // the pipe → "registered, state known".
  //
  // The lookup itself is wrapped so a missing task is an ABSENCE we report, not a
  // nonzero exit that swallows the markers with it.
  const script =
    "$ErrorActionPreference='Stop';" +
    "Write-Output 'QUERIED=1';" +
    // Printed from the same process that does the lookup, so it describes the
    // rights the lookup actually had. Wrapped, because a locked-down host can
    // refuse the identity call without refusing the query.
    "try { Write-Output ('ADMIN=' + [int](New-Object Security.Principal.WindowsPrincipal(" +
    "[Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(" +
    "[Security.Principal.WindowsBuiltInRole]::Administrator)) } catch { };" +
    "$t = $null;" +
    `try { $t = Get-ScheduledTask -TaskName ${powerShellSingleQuote(name)} -ErrorAction Stop } catch { $t = $null };` +
    "if ($t) { Write-Output ('STATE=' + $t.State) };" +
    // The lookup has returned. Everything after this line is detail.
    "Write-Output 'ANSWERED=1';" +
    "if ($t) {" +
    " foreach ($a in $t.Actions) {" +
    "  Write-Output ('EXECUTE=' + $a.Execute);" +
    "  Write-Output ('ARGS=' + $a.Arguments) } }";
  const captured = await runCaptured(
    powerShellPath(),
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    { timeoutMs: opts?.timeoutMs ?? SCHEDULED_TASK_QUERY_TIMEOUT_MS },
  );
  // THE ANSWER SURVIVES THE TIMEOUT, and this reads like an optimisation and is
  // not. `capturedStdout` hands back what the process said even when it exited
  // non-zero or was killed at the deadline. A lookup that RETURNED before the CIM
  // cold-load pushed the rest of the script past the clock has already put
  // `STATE=` and/or `ANSWERED=1` on the pipe, and those bytes are the verdict the
  // machine needed. Discarding them left `queried: false` and, ten TTL-minutes at
  // a time, a permanent `endpoint_unreachable` on the one box this whole effort
  // exists for.
  const out = capturedStdout(captured);
  const read = (key: string): string | null => {
    const match = new RegExp(`^${key}=(.*)$`, "m").exec(out);
    return match ? match[1]!.trim() : null;
  };
  const state = read("STATE");
  const started = /^QUERIED=1$/m.test(out);
  // WHAT MAKES AN ABSENCE AN ANSWER. Any ONE of:
  //   - `ANSWERED=1`: the lookup returned, whatever happened to the process
  //     afterwards. No STATE line alongside it is Windows saying the task is not
  //     there — the only route to `registered: false` for a killed run.
  //   - a STATE line: Windows named the task. Older output shapes carried no
  //     marker at all, which is what keeps a stubbed PowerShell honest in tests.
  //   - the script RAN TO COMPLETION (`kind: "output"` — it exited 0) with the
  //     start sentinel on the pipe. A process that reached its own exit cannot be
  //     mid-lookup, so here the sentinel really does bound the whole script.
  // What is deliberately NOT enough is `QUERIED=1` from a process that was killed
  // or died: that is "we got as far as starting and no further".
  const answered = /^ANSWERED=1$/m.test(out) || state !== null || (captured.kind === "output" && started);
  if (!answered) {
    // `unavailableReason` is empty exactly when the command ran and exited 0,
    // which here means PowerShell started and printed nothing recognisable —
    // ConstrainedLanguage, a wedged profile, a script host that swallowed the
    // output. Still "we could not ask", never "no such task".
    const reason = unavailableReason(captured) || `${powerShellPath()} ran but printed no answer`;
    return {
      queried: false,
      reason: started ? `${reason} (the scheduled-task lookup never returned)` : reason,
    };
  }
  const admin = read("ADMIN");
  return {
    queried: true,
    registered: state !== null,
    elevated: admin === null ? null : admin === "1",
    state,
    execute: read("EXECUTE"),
    args: read("ARGS"),
  };
}
