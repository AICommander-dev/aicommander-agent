import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { doctorJobsRoot, NO_JOBS_ROOT_REASON } from "./paths.js";
import {
  COMMAND_FILE,
  WRAPPER_FILE,
  verifyWindowsJobScripts,
  writeWindowsJobScripts,
} from "../../job-scripts.js";
import {
  errnoOf,
  errorText,
  fail,
  HELP_URL,
  ok,
  skipped,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorFacts,
} from "../types.js";

/**
 * The live antivirus-interference probe: does this machine's security software
 * take our job scripts away?
 *
 * ── WHY THIS IS THE MOST VALUABLE CHECK IN THE COMMAND ───────────────────────
 * Everything else here diagnoses damage that has already happened. This one
 * fires BEFORE the user loses their installation: it stages exactly the event a
 * behavioural engine scores — a process writing a `.cmd` into a user-writable
 * directory — and then asks whether the file is still there a moment later. It
 * is vendor-agnostic by construction: it never asks what is installed, never
 * reads a vendor's ledger, and cannot be defeated by a product we have not heard
 * of. Vanished, emptied, rewritten or refused → something on this machine is
 * interfering with us.
 *
 * ── WHY THE REAL MACHINERY, NOT A LOOKALIKE ──────────────────────────────────
 * `writeWindowsJobScripts` / `verifyWindowsJobScripts` (job-scripts.ts) are what
 * a real job start uses, including their bounded timeout — the one that exists
 * because a filter driver can answer NOTHING at all and there is no errno for
 * that. A second, hand-rolled implementation here would drift from the one under
 * test, and the drift would be exactly in the bytes a scanner scores. So the
 * probe writes the real `wrapper.cmd` and a real `command.cmd`; only the command
 * inside it is inert.
 *
 * Nothing about those scripts is CHANGED by this file — the shape is frozen (see
 * PLAN-av-hardening.md W4 and the job-scripts.ts header). This only writes them.
 *
 * ── WHAT IT LEAVES BEHIND: NOTHING ───────────────────────────────────────────
 * The scratch directory is removed in a `finally`, on every path including the
 * failure ones, and a cleanup that itself failed is reported rather than
 * swallowed — an undeletable file is the same story seen from the other end. The
 * directory is dot-prefixed and does not match JOB_ID_PATTERN, so a job manager
 * running in another process cannot mistake it for a job even while it exists.
 *
 * "Nothing" is meant literally, and two things make it harder than one `rm`:
 *
 *   - the JOBS ROOT itself. `atomicWriteUtf8Async` opens with
 *     `mkdir({recursive:true})`, so on a machine that has never run a job the
 *     probe brings the whole jobs directory into existence. Whether it existed
 *     BEFORE is therefore recorded first, and one we created is removed after —
 *     with `rmdir`, which refuses a directory that has anything in it, so a real
 *     job that appeared meanwhile is never touched.
 *   - a write we GAVE UP on. `withinDeadline` (job-scripts.ts) cannot cancel a
 *     filesystem call a filter driver is sitting on; it abandons the promise, and
 *     that promise still ends in a `mkdir` and a write. A single removal can
 *     therefore be followed, a moment later, by the directory reappearing. So
 *     removal is verified, retried after a short grace, and — if the directory is
 *     still (or again) there — REPORTED, because a scratch directory that will
 *     not stay deleted is itself the finding.
 *
 * NOTHING IS EXECUTED. The scripts are written and read; no shell is started.
 * A diagnostic that ran `cmd /d /s /c` to prove that `cmd /d /s /c` works would
 * be the very behaviour we are being scored on.
 */

/**
 * The command written into `command.cmd`. Inert on purpose, and unmistakably
 * ours if anybody ever sees it in a quarantine ledger — which is the other half
 * of the point: a vendor looking at the quarantined file should be able to tell
 * at a glance that it is a self-test.
 */
const PROBE_COMMAND = "echo aicommander-doctor-probe";

/** Read at import time, exactly like job-manager.ts's own `isWindows`, so tests pin it the same way. */
const isWindows = process.platform === "win32";

/**
 * The pause between writing and reading back. Its timer is deliberately NOT
 * unref'd: for those few hundred milliseconds this is the only handle keeping
 * the process alive, and an unref'd one lets Node decide the event loop is empty
 * and exit — silently, mid-diagnosis, with a zero status. (Measured: it did.)
 */
async function sleep(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });
}

const PROBE_ID = "av.probe";
const PROBE_TITLE = "Antivirus interference probe";

/** How long a removal waits before looking again, and how many times it looks. */
const RESURRECTION_GRACE_MS = 50;
const REMOVAL_ATTEMPTS = 3;

type PathState = "absent" | "present" | "unknown";

/**
 * Is it there? ENOENT is a real "no"; ANY other stat failure is "we could not
 * find out", and must never be reported as "gone, as intended" — an EACCES from
 * the very filter driver this check is looking for would otherwise read as a
 * successful cleanup.
 */
async function pathState(target: string): Promise<PathState> {
  try {
    await fs.promises.stat(target);
    return "present";
  } catch (err) {
    return errnoOf(err) === "ENOENT" ? "absent" : "unknown";
  }
}

interface RemovalOutcome {
  state: PathState;
  /** The last error a removal attempt produced, if any. */
  error: string | null;
  /**
   * True when the directory came BACK after a removal that had already
   * succeeded — reported even if a later attempt removed it again, because
   * something recreating our scratch directory is the finding, not the tidiness.
   */
  reappeared: boolean;
  /**
   * How long the directory was watched, and seen still gone, after the removal
   * that finally took.
   *
   * This is the honest bound on the claim. The window is tens of milliseconds
   * because a diagnostic cannot sit on the machine waiting for a filter driver
   * to release a write, and a resurrection later than that WILL NOT BE SEEN by
   * this run — so the number is reported rather than the claim being made
   * unqualified. The header promises the probe leaves nothing behind; this is
   * the part of that promise the probe can actually establish.
   */
  observedForMs: number;
}

/** Remove the scratch directory and prove it stayed removed. Never throws. */
async function removeScratch(dir: string): Promise<RemovalOutcome> {
  let error: string | null = null;
  let reappeared = false;
  let state: PathState = "unknown";
  let observedForMs = 0;
  for (let attempt = 0; attempt < REMOVAL_ATTEMPTS; attempt++) {
    try {
      await fs.promises.rm(dir, { recursive: true, force: true });
      error = null;
    } catch (err) {
      error = errorText(err);
    }
    state = await pathState(dir);
    const removed = state === "absent";
    if (!removed && attempt + 1 >= REMOVAL_ATTEMPTS) break;
    // Look again after the grace: an abandoned write releasing now would
    // recreate exactly what we just removed.
    await sleep(RESURRECTION_GRACE_MS);
    state = await pathState(dir);
    if (state === "absent") {
      observedForMs += RESURRECTION_GRACE_MS;
      break;
    }
    if (removed) {
      // It was gone and is back. Start the clock over for the next attempt.
      reappeared = true;
      observedForMs = 0;
    }
  }
  return { state, error, reappeared, observedForMs };
}

/**
 * What happened to a jobs root this probe brought into existence.
 *
 * `rmdir` refuses a non-empty directory, which is the whole reason it is used:
 * a real job that started while we were probing must survive us. So ENOTEMPTY is
 * a SUCCESS of that rule, not a failure — and every other error is a directory
 * we created and could not remove, which is exactly the thing the header
 * promises does not happen. Swallowing it (`.catch(() => undefined)`) meant the
 * one-sided verification the second reviewer objected to: the scratch directory
 * was verified and the directory above it, which we had also created, was not.
 */
type JobsRootCleanup =
  | { kind: "not-ours" }
  | { kind: "removed" }
  | { kind: "kept"; reason: string }
  | { kind: "failed"; error: string; code: string | null; state: PathState };

async function removeJobsRoot(jobsRoot: string): Promise<JobsRootCleanup> {
  try {
    await fs.promises.rmdir(jobsRoot);
  } catch (err) {
    const code = errnoOf(err);
    if (code === "ENOENT") return { kind: "removed" };
    if (code === "ENOTEMPTY" || code === "EEXIST") {
      return { kind: "kept", reason: "it is no longer empty, so something else is using it now" };
    }
    return { kind: "failed", error: errorText(err), code, state: await pathState(jobsRoot) };
  }
  const state = await pathState(jobsRoot);
  if (state === "absent") return { kind: "removed" };
  return {
    kind: "failed",
    error:
      state === "unknown"
        ? "whether it is gone could not be confirmed"
        : "it is there again although rmdir reported success",
    code: null,
    state,
  };
}

async function probe(ctx: DoctorContext, dir: string): Promise<CheckResult> {
  const id = PROBE_ID;
  const title = PROBE_TITLE;

  const facts: DoctorFacts = {
    dir,
    scripts: `${WRAPPER_FILE}, ${COMMAND_FILE}`,
    delayMs: ctx.probeDelayMs,
  };
  const remedy =
    "Restore anything already quarantined and exclude the AI Commander jobs directory in your security " +
    `software, then re-run this command. ${HELP_URL}`;

  {
    let writeFault: string | null;
    try {
      writeFault = await writeWindowsJobScripts(dir, PROBE_COMMAND);
    } catch (err) {
      // job-scripts.ts classifies EACCES/EPERM/ENOENT/EBUSY as interference and
      // returns a detail; anything else it THROWS, because a full or broken
      // volume is a different failure and telling that operator about antivirus
      // would send them to the wrong page.
      return fail(
        id,
        title,
        `the job scripts could not be written: ${errorText(err)}`,
        "This looks like a storage fault (a full disk, a read-only or broken volume) rather than security " +
          "software. Check the free space and the health of the volume holding the jobs directory.",
        { ...facts, ...(errnoOf(err) ? { code: errnoOf(err)! } : {}) },
      );
    }
    if (writeFault !== null) {
      return fail(id, title, `the job scripts were refused: ${writeFault}.`, remedy, {
        ...facts,
        stage: "write",
        fault: writeFault,
      });
    }

    // An on-access engine acts asynchronously — quarantine is not part of our
    // write() returning — so a read-back with no pause measures our own page
    // cache and proves nothing.
    await sleep(ctx.probeDelayMs);

    let readFault: string | null;
    try {
      readFault = await verifyWindowsJobScripts(dir, PROBE_COMMAND);
    } catch (err) {
      return fail(
        id,
        title,
        `the job scripts could not be read back: ${errorText(err)}`,
        "This looks like a storage fault rather than security software. Check the volume holding the jobs directory.",
        { ...facts, ...(errnoOf(err) ? { code: errnoOf(err)! } : {}) },
      );
    }
    if (readFault !== null) {
      return fail(
        id,
        title,
        `a job script did not survive being written: ${readFault}. Security software on this machine is ` +
          "removing or altering the files every job needs.",
        remedy,
        { ...facts, stage: "read-back", fault: readFault },
      );
    }

    return ok(
      id,
      title,
      isWindows
        ? "wrote the two job scripts, read them back unchanged, and removed them — nothing is interfering."
        : "wrote the two job scripts, read them back unchanged, and removed them. (The `.cmd` shape is only " +
          "scored by Windows engines; here this proves the jobs directory accepts a script write and read-back.)",
      facts,
    );
  }
}

/**
 * Report on the cleanup — always, and with the bound on what was verified.
 *
 * This used to return `null` on the happy path, which made "nothing was left
 * behind" a claim the report never had to support. It is a check now, for the
 * reason the rest of this directory grew its third verdict: the promise in the
 * header is either established, established with a stated limit, or not
 * established, and the report should say which.
 */
function checkCleanup(
  dir: string,
  removal: RemovalOutcome,
  jobsRoot: string,
  rootCleanup: JobsRootCleanup,
): CheckResult {
  const id = "av.probe_cleanup";
  const title = "Antivirus probe cleanup";
  const facts: DoctorFacts = {
    dir,
    reappeared: removal.reappeared,
    observedForMs: removal.observedForMs,
    jobsRoot: rootCleanup.kind === "not-ours" ? null : jobsRoot,
    jobsRootCleanup: rootCleanup.kind,
    ...(removal.error ? { error: removal.error } : {}),
    ...(rootCleanup.kind === "failed" ? { jobsRootError: rootCleanup.error } : {}),
  };

  if (rootCleanup.kind === "failed") {
    return warn(
      id,
      title,
      `the probe brought the jobs directory into existence and could not remove it again: ${jobsRoot} ` +
        `(${rootCleanup.error})`,
      `Delete ${jobsRoot} by hand if this machine has never run a job. A directory we created and cannot ` +
        "remove is the same interference this check looks for, one level up from the files it writes.",
      facts,
    );
  }
  if (removal.state === "unknown") {
    return warn(
      id,
      title,
      `the probe's scratch directory was removed, but whether it is gone could not be confirmed: ` +
        `${removal.error ?? "the directory could not be read"}`,
      `Check ${dir} by hand and delete it if it is there. A path that answers neither "present" nor "absent" ` +
        "is usually one a scanner is holding.",
      facts,
    );
  }
  if (removal.reappeared) {
    const gone = removal.state === "absent";
    return warn(
      id,
      title,
      `the probe's scratch directory was removed and came BACK${gone ? ", and had to be removed again" : ""}: ${dir}`,
      gone
        ? "Nothing was left behind, but something on this machine recreated a directory we had just deleted — " +
          "a write we had given up on, completed by whatever was holding it. That is the same interference " +
          "this check looks for, seen from the other end."
        : `Delete ${dir} by hand. Something is recreating it faster than it can be removed.`,
      facts,
    );
  }
  if (removal.state !== "absent") {
    return warn(
      id,
      title,
      `the probe's scratch directory could not be removed and is still on disk: ${dir}`,
      `Delete ${dir} by hand. A directory that refuses to be removed is usually held open by a scanner that is ` +
        "still working on the files we wrote.",
      facts,
    );
  }
  const rootNote =
    rootCleanup.kind === "not-ours"
      ? ""
      : rootCleanup.kind === "removed"
        ? ` The jobs directory this probe created was removed too.`
        : ` The jobs directory this probe created was left in place because ${rootCleanup.reason}.`;
  return ok(
    id,
    title,
    `the probe's scratch directory was removed and was still gone ${removal.observedForMs}ms later.` +
      rootNote +
      ` Nothing looks again after that, so a recreation later than ${removal.observedForMs}ms is outside what ` +
      "this run can see.",
    facts,
  );
}

export const antivirusProbeChecks: DoctorCheckGroup = {
  id: "av",
  title: "Antivirus interference",
  async run(ctx) {
    const jobsRoot = doctorJobsRoot(ctx.configDir);
    if (!jobsRoot) return [skipped(PROBE_ID, PROBE_TITLE, NO_JOBS_ROOT_REASON)];

    // Asked BEFORE anything is written, because the write is what would create
    // it. "unknown" counts as existing: removing a directory we are not certain
    // we made is the one mistake this check must not make.
    const jobsRootExisted = (await pathState(jobsRoot)) !== "absent";
    const dir = path.join(jobsRoot, `.doctor-probe-${randomBytes(6).toString("hex")}`);

    let result: CheckResult;
    let removal: RemovalOutcome;
    let rootCleanup: JobsRootCleanup = { kind: "not-ours" };
    try {
      result = await probe(ctx, dir);
    } finally {
      // Unconditional, and last: a diagnostic may not leave a `.cmd` behind for
      // the next scan to find.
      removal = await removeScratch(dir);
      // rmdir, never rm -r: it refuses a directory with anything in it, so a
      // real job that started while we were probing is safe from us. Its outcome
      // is now VERIFIED and reported rather than swallowed.
      if (!jobsRootExisted) rootCleanup = await removeJobsRoot(jobsRoot);
    }
    return [result, checkCleanup(dir, removal, jobsRoot, rootCleanup)];
  },
};
