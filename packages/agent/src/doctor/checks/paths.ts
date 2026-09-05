import os from "node:os";
import path from "node:path";
import { resolveJobsRoot } from "../../job-manager.js";

/**
 * Where the doctor looks, resolved WITHOUT bringing anything into existence.
 *
 * The agent's own resolution runs through `envConfigDir()` (config-dir.ts),
 * which validates AICOMMANDER_CONFIG_DIR by CREATING the directory and asserting
 * write access, and throws when it cannot. That is right for the agent at
 * startup and wrong for a diagnostic three times over:
 *
 *   - a doctor run must not bring a directory into existence, least of all one
 *     an operator mistyped (types.ts: "nothing is left behind on disk");
 *   - a check whose verdict depends on whether an EARLIER check happened to
 *     create the directory first is not a measurement of anything;
 *   - a throw from the resolution turns a reportable finding — "the override
 *     points somewhere unusable" — into a group that failed to run at all.
 *
 * So the doctor asks the same three questions read-only, and every check under
 * `doctor/checks/` resolves its paths through here rather than through
 * `envConfigDir()` or anything that calls it.
 *
 * ── WHY EVERY DIRECTORY, NOT JUST THE INTERESTING ONES ───────────────────────
 * That rule was stated as a rule and then broken by the check that needed it
 * least: `checkDiagLog` resolved through `diag-log.ts`'s `resolveDiagLogDir`,
 * which falls back to `envConfigDir()` — so running `doctor` on a machine with
 * an absolute-but-nonexistent AICOMMANDER_CONFIG_DIR CREATED that directory,
 * synchronously, on Electron's main loop, while the file above it claimed
 * nothing under `doctor/checks/` does that. A rule each check has to remember is
 * a rule that gets forgotten, so every directory the doctor names is resolved
 * here instead, and `doctor-paths.test.ts` pins each one against the agent's own
 * resolver wherever the two can be compared without mutating anything.
 *
 * The ladders below are MIRRORED from job-manager.ts and diag-log.ts rather than
 * shared, for the reason session-read.ts mirrors session-store.ts: the shared
 * thing would have to be the function that creates.
 */

/** The per-user data root both mirrored ladders end at. */
function platformDataDir(): string {
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  if (process.platform !== "win32" && isRoot) return "/var/lib/aicommander";
  if (process.platform === "win32") {
    const localAppData = process.env["LOCALAPPDATA"];
    const winBase =
      localAppData && path.isAbsolute(localAppData)
        ? localAppData
        : path.join(os.homedir(), "AppData", "Local");
    return path.join(winBase, "aicommander");
  }
  return path.join(os.homedir(), ".local", "share", "aicommander");
}

/**
 * The AICOMMANDER_CONFIG_DIR override, if it is one the agent would accept.
 *
 * `null` covers both "not set" and "set to something the agent refuses to start
 * with" (a relative path) — the latter is not silently substituted, it is
 * REPORTED by storage.ts's `config.override` check, which is the one place that
 * verdict belongs.
 */
export function doctorConfigDirOverride(): string | null {
  const raw = process.env["AICOMMANDER_CONFIG_DIR"]?.trim();
  if (!raw || !path.isAbsolute(raw)) return null;
  return raw;
}

/**
 * The jobs root, resolved as job-manager.ts's `resolveJobsRoot` resolves it —
 * with the env override read read-only, and the rest delegated so the ladder
 * below it (a root service's /var/lib, the per-user data dir, the Windows
 * LOCALAPPDATA shape) has exactly one implementation. `doctor-paths.test.ts`
 * pins the two against each other.
 *
 * `null` when AICOMMANDER_CONFIG_DIR is set to something the agent refuses to
 * start with: there is then no jobs directory on this machine to measure, and
 * the checks that wanted one report themselves `skipped` pointing at the
 * `config.override` check, rather than probing a path nothing would ever use.
 */
export function doctorJobsRoot(configDir?: string): string | null {
  const base = configDir ?? doctorConfigDirOverride();
  if (base) return path.join(base, "jobs");
  const raw = process.env["AICOMMANDER_CONFIG_DIR"]?.trim();
  // Set, but not absolute — `doctorConfigDirOverride` already refused it, and
  // delegating now would reach envConfigDir's create-and-assert path (which
  // would throw here and create a directory in the case where it does not).
  if (raw) return null;
  return resolveJobsRoot();
}

/** The reason a check has no jobs root to look at, in one sentence. */
export const NO_JOBS_ROOT_REASON =
  "AICOMMANDER_CONFIG_DIR is set to a path the agent refuses to start with, so this machine has no jobs " +
  "directory to measure — see the AICOMMANDER_CONFIG_DIR check.";

/**
 * The diagnostic log directory, resolved as diag-log.ts's `resolveDiagLogDir`
 * resolves it — and, unlike it, without `envConfigDir()` underneath.
 *
 * The one behaviour deliberately reproduced rather than "fixed" is the fallback
 * for an override the agent refuses: `resolveDiagLogDir` catches the throw and
 * lands on the platform default, so that IS where the logs of such a machine
 * are, and a doctor that pointed somewhere else would send the user to an empty
 * directory. (`doctorJobsRoot` answers `null` in the same case because there the
 * agent genuinely never gets that far — it will not start at all.)
 */
export function doctorDiagLogDir(configDir?: string): string {
  const base = configDir ?? doctorConfigDirOverride();
  if (base) return path.join(base, "logs");
  return path.join(platformDataDir(), "logs");
}
