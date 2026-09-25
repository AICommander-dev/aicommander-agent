import fs from "node:fs";
import path from "node:path";
import { doctorReportBundle, doctorReportJson, renderDoctorReport, runDoctor } from "../../doctor/index.js";
import { ui } from "../ui.js";

/**
 * `aicommander-agent doctor` — one command that answers "which of these is it?"
 *
 * The user this is for cannot start the app, or their machine went offline for
 * no visible reason. Before this existed, telling those two apart took an hour
 * of hands-on forensics WITH administrative access: counting files in the
 * install directory, testing whether a path was writable, reading a quarantine
 * ledger, watching for a ticket exchange that never completed. Every one of
 * those steps is mechanical, and every one of them is a check in `doctor/`.
 *
 * ── NO requireRoot ───────────────────────────────────────────────────────────
 * Deliberately. Almost none of these checks needs root, and the person running
 * this is already having a bad day; making them find `sudo` before the product
 * will describe itself would be a poor trade. Where privilege genuinely changes
 * the answer, the check SAYS so instead of demanding it — the install-path write
 * probe reports a refusal as a warning when it does not know it is elevated, and
 * as a failure when it does, because the whole point of that check is that on
 * 2026-09-02 an elevated administrator was refused anyway.
 *
 * ── EXIT CODE ────────────────────────────────────────────────────────────────
 * 1 when any check FAILED, 0 otherwise. Warnings and skips do not fail the
 * command: a skipped check is a check we honestly did not run, and exiting
 * non-zero for "you have no privileged helper on Linux" would make the exit code
 * useless for the scripts that will end up wrapping this.
 */
export interface DoctorCommandOptions {
  json?: boolean;
  report?: string;
  offline?: boolean;
  verbose?: boolean;
  /** Test seam / tray: where the packaged resources are. */
  resourcesPath?: string;
  /** Test seam / tray: the host's per-user data dir. */
  configDir?: string;
}

/**
 * Write the bundle to a path the CALLER chose, without following a symlink and
 * without inheriting an existing file's mode.
 *
 * `writeFileSync(target, …, { mode: 0o600 })` does neither. `mode` applies only
 * when the file is CREATED, so re-running over a world-readable file leaves it
 * world-readable; and the default `w` flag follows a symlink at the target and
 * truncates whatever it points at — which, with `sudo doctor --report
 * /tmp/anything`, is a way to clobber a file the caller could not otherwise
 * touch. `wx` (the flag storage.ts's probe uses) is not an option here, because
 * re-running `--report` over yesterday's file has to work.
 *
 * So: O_NOFOLLOW where the platform has it, a regular file or nothing, and the
 * mode re-asserted on the DESCRIPTOR after opening rather than trusted from
 * creation. The bundle is redacted, but it is still a description of somebody's
 * machine written wherever they asked for it, often /tmp.
 *
 * ON WINDOWS THE REFUSAL IS NOT AVAILABLE, AND IS NOT CLAIMED. Windows has the
 * mechanism — `CreateFileW`'s FILE_FLAG_OPEN_REPARSE_POINT opens the reparse
 * point itself instead of traversing it — but nothing in Node's `fs` surface
 * passes that flag and `fs.constants.O_NOFOLLOW` is undefined there, so the open
 * CANNOT be made to fail on a link. This function does not rest on "Windows has
 * no /tmp" either, which is the argument that used to sit here: it is a
 * mitigation and a weak one, because creating a FILE symlink needs
 * SeCreateSymbolicLinkPrivilege (an administrator, or Developer Mode) while
 * junctions and hard links need no privilege at all — and here the path is
 * CALLER-SUPPLIED (`--report`), so the exposure is larger than the desktop
 * save-dialog's. What it does instead is make the write NON-DESTRUCTIVE where it
 * cannot make the open refusing (the same shape as desktop/src/diagnostics.ts):
 *   * open WITHOUT O_TRUNC, so nothing is destroyed by the open itself;
 *   * `lstat` the path and bail when it is a link (Node reports file symlinks
 *     AND directory junctions as symbolic links on Windows);
 *   * only then truncate the descriptor and write.
 * It is a check, not the atomic guarantee O_NOFOLLOW gives: a swap landing
 * between the open and the lstat is not detectable, and a DANGLING link will
 * already have had its target created (empty) by O_CREAT. What it does deliver
 * is that no existing file we were pointed at through a link is truncated or
 * written.
 *
 * @param openRefusesLinks whether this platform's `open` can be asked to refuse
 * a link. Defaults to what the platform actually has; a test passes `false` to
 * exercise the Windows path on a platform that has O_NOFOLLOW.
 */
export function writeReportFile(
  target: string,
  contents: string,
  openRefusesLinks: boolean = typeof fs.constants.O_NOFOLLOW === "number",
): void {
  const { O_WRONLY, O_CREAT, O_NOFOLLOW } = fs.constants;
  const noFollow = openRefusesLinks ? O_NOFOLLOW : 0;
  const fd = fs.openSync(target, O_WRONLY | O_CREAT | noFollow, 0o600);
  try {
    if (!fs.fstatSync(fd).isFile()) {
      throw new Error("the report target is not a regular file");
    }
    if (!openRefusesLinks && fs.lstatSync(target).isSymbolicLink()) {
      throw new Error("the report target is a link, and this platform cannot refuse to follow one");
    }
    // Re-assert, because the file may have existed with a looser mode.
    if (process.platform !== "win32") fs.fchmodSync(fd, 0o600);
    // Truncation is the destructive step, so it happens AFTER both refusals
    // above rather than in the open's flags.
    fs.ftruncateSync(fd, 0);
    fs.writeFileSync(fd, contents);
  } finally {
    fs.closeSync(fd);
  }
}

export async function cmdDoctor(opts: DoctorCommandOptions = {}): Promise<void> {
  const report = await runDoctor({
    ...(opts.offline ? { offline: true } : {}),
    ...(opts.resourcesPath ? { resourcesPath: opts.resourcesPath } : {}),
    ...(opts.configDir ? { configDir: opts.configDir } : {}),
  });

  if (opts.json) {
    // The JSON is redacted, because it is the shape support tooling forwards.
    // The human view below is not — a remedy that says "exclude ~" is a remedy
    // nobody can follow. See doctor/report.ts.
    process.stdout.write(doctorReportJson(report));
  } else {
    process.stdout.write(
      renderDoctorReport(report, {
        color: process.stdout.isTTY === true,
        verbose: opts.verbose === true,
      }),
    );
  }

  if (opts.report) {
    const target = path.resolve(opts.report);
    try {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      writeReportFile(target, doctorReportBundle(report));
      if (!opts.json) {
        ui.blank();
        ui.ok(`Report written to ${target}`);
        ui.step("  It carries no access code, no token and no command text — safe to attach to a ticket.");
      }
    } catch (err) {
      ui.error(`Could not write the report to ${target}: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
      return;
    }
  }

  if (report.summary.fail > 0) process.exitCode = 1;
}
