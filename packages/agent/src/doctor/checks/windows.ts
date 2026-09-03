import path from "node:path";
import { powerShellSingleQuote } from "../../installed-version.js";
import { powerShellPath, systemRoot } from "../../windows-scheduled-task.js";
import { runCaptured, unavailableReason, type Captured } from "../../capture.js";

/**
 * The small Windows questions the doctor has to ask the OS, and the rules for
 * asking them safely.
 *
 * FULL PATHS, NEVER BARE NAMES. Every helper below spells out
 * `%SystemRoot%\System32\…`. The doctor can run from the tray, from a service,
 * and (W2.3) from the SYSTEM-owned privileged helper, and in none of those is
 * `PATH` ours to trust — a `reg.exe` earlier on the path is somebody else's
 * program. This mirrors the rule win-watchdog-probe.ts states for the same
 * reason.
 *
 * NOTHING READ HERE EVER BECOMES SOMETHING WE RUN. Every value that reaches a
 * PowerShell script is a compile-time constant of ours, quoted as a literal
 * (`powerShellSingleQuote`); everything the OS answers is parsed, compared
 * against the filesystem and REPORTED. The doctor's whole remedy for a broken
 * autostart entry is "re-run the installer" precisely because re-pointing an
 * admin-owned task at a path discovered from a user-writable location is the
 * privilege escalation the current design exists to prevent (PLAN-av-hardening
 * §2 W7).
 *
 * ── THE SCHEDULED-TASK QUERY IS NOT HERE ─────────────────────────────────────
 * `queryScheduledTask`, `ScheduledTaskInfo`, `systemRoot` and `powerShellPath`
 * live in `../../windows-scheduled-task.ts` and are re-exported below. The
 * runtime's fail-closed availability rule (elevated-availability.ts) asks the
 * same question, and it may not import from the diagnostics subtree — so the
 * shared module owns it and this one borrows it, rather than each keeping a
 * copy. Two implementations of one question is how the `queried` sentinel came
 * to be computed and then ignored in the first place, and the copies had already
 * diverged on the case that matters most: a `Get-ScheduledTask` that runs past
 * its deadline has still flushed `QUERIED=1`, and the shared module keeps those
 * bytes, so the machine reports "Windows did not name the task" — a real verdict
 * — instead of "we never asked". The doctor's copy threw them away and answered
 * `skipped` on exactly the slow, AV-scanned box this whole command exists for.
 * The merged one is built on the same `../../capture.ts` tri-state everything
 * below uses, which is why that primitive sits at `src/` and not here.
 */

export {
  powerShellPath,
  queryScheduledTask,
  SCHEDULED_TASK_QUERY_TIMEOUT_MS,
  systemRoot,
  type ScheduledTaskInfo,
} from "../../windows-scheduled-task.js";

export function regExePath(): string {
  return path.join(systemRoot(), "System32", "reg.exe");
}

/**
 * Run a fixed PowerShell script and report what happened — capture.ts's
 * tri-state, deliberately, so a caller cannot mistake "PowerShell is blocked
 * here" for "Windows says no".
 *
 * For the SHORT diagnostic scripts only (the Authenticode read). The
 * scheduled-task query does not come through here: it needs a far longer
 * deadline and it needs its partial output kept, and both of those live with it
 * in windows-scheduled-task.ts.
 *
 * `-EncodedCommand` would be safer still, but every
 * script here is a constant with at most a constant of ours interpolated through
 * `powerShellSingleQuote`, and plain text keeps these readable in a diagnostic
 * that people will read.
 */
export function runPowerShell(script: string): Promise<Captured> {
  return runCaptured(powerShellPath(), [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script,
  ]);
}

export { powerShellSingleQuote };

export interface RegistryValue {
  name: string;
  type: string;
  data: string;
}

/**
 * Parse `reg.exe query` output. Values are indented and separated from their
 * type and data by runs of whitespace; a value NAME may itself contain single
 * spaces (`electron.app.AI Commander` does), which is why the split is on runs
 * of four or more and not on whitespace generally.
 */
export function parseRegValues(output: string): RegistryValue[] {
  const values: RegistryValue[] = [];
  for (const line of output.split(/\r?\n/)) {
    const match = /^\s{4,}(\S.*?)\s{4,}(REG_[A-Z_]+)\s{4,}(.*)$/.exec(line);
    if (!match) continue;
    values.push({ name: match[1]!.trim(), type: match[2]!, data: match[3]!.trim() });
  }
  return values;
}

/**
 * Read one registry key's values.
 *
 * Tri-state for the same reason `ScheduledTaskInfo.queried` is: `reg.exe` that
 * never ran (no `reg.exe`, an AppLocker block, a timeout) and a key holding no
 * values of ours produce the SAME empty list, and a caller that cannot tell them
 * apart ends up publishing "there is no autostart entry here, which is normal"
 * about a machine it never managed to ask. `reg.exe query` on a key that exists
 * prints the key's own header and exits 0 even when the key is empty, so an
 * `output` answer really is evidence about the registry.
 */
export type RegistryQuery =
  | { queried: true; values: RegistryValue[] }
  | { queried: false; reason: string };

export async function regQuery(key: string): Promise<RegistryQuery> {
  const captured = await runCaptured(regExePath(), ["query", key]);
  if (captured.kind !== "output") {
    return { queried: false, reason: `${regExePath()} ${unavailableReason(captured)}` };
  }
  return { queried: true, values: parseRegValues(captured.stdout) };
}

/**
 * The executable out of a Windows command line: the quoted first token, or
 * everything up to the first space when it is unquoted.
 *
 * Best-effort by nature — an unquoted path containing spaces is ambiguous to
 * everyone including Windows — and it only ever feeds an existence check and a
 * printed line. Never a spawn.
 */
export function extractExecutablePath(commandLine: string): string | null {
  const trimmed = commandLine.trim();
  if (trimmed === "") return null;
  if (trimmed.startsWith('"')) {
    const end = trimmed.indexOf('"', 1);
    return end > 1 ? trimmed.slice(1, end) : null;
  }
  const space = trimmed.indexOf(" ");
  return space === -1 ? trimmed : trimmed.slice(0, space);
}

/**
 * The path a scheduled task's action was PINNED to.
 *
 * `desktop/build/win-update-task.ps1` registers two tasks and they bake their
 * path in two different ways, which is why both shapes are read here:
 *
 *   Relaunch — `Start-Process -FilePath '<path>'`, a PowerShell single-quoted
 *              literal inside the double-quoted `-Command` argument;
 *   Update   — `-NoProfile -ExecutionPolicy Bypass -File "<win-updater.ps1>"`,
 *              the script the silent updater runs.
 *
 * Reading only the first shape meant the Update task's pinned path was never
 * checked at all — the task registered by the same script, baking in the same
 * install directory, subject to the same staleness this whole check exists for
 * (PLAN-av-hardening §2 W7).
 *
 * `-File` is matched only when a separator follows it, so `-FilePath` cannot be
 * mistaken for it. The LAST occurrence wins, exactly as win-watchdog-probe.ts
 * does it — an argument string can legitimately mention the switch more than
 * once, and the one that starts the app is the final one. `null` means "no shape
 * this function recognises", which the caller must report as UNCHECKED rather
 * than as healthy.
 *
 * Parsing lives HERE and not in windows-scheduled-task.ts on purpose: the shared
 * module answers "is Windows told to run this", which the runtime needs; what
 * the action's argument string points AT is a diagnostic question and nothing
 * fail-closed reads it.
 */
export function parsePinnedFilePath(taskArguments: string): string | null {
  for (const pattern of [/-FilePath\s+'([^']+)'/g, /-File\s+(?:"([^"]+)"|'([^']+)')/g]) {
    const matches = [...taskArguments.matchAll(pattern)];
    const last = matches[matches.length - 1];
    const value = last ? (last[1] ?? last[2]) : undefined;
    if (value) return value;
  }
  return null;
}
