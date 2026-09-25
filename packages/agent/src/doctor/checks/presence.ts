import fs from "node:fs";
import { errnoOf, errorText } from "../types.js";

/**
 * "It is not there" and "I could not find out" are DIFFERENT answers, and this
 * module exists so no check has to remember that on its own.
 *
 * Every wrong direction has now been shipped by this directory at least once:
 * a creatable override reported as unusable, and then — in the fix for it — an
 * override nobody could stat reported as "does not exist yet, the agent will
 * create it". Both came from the same one-line shape, `stat().catch(() => null)`,
 * which folds EACCES, EPERM, EIO, ELOOP and a mount that is hanging into the
 * single word "absent".
 *
 * So absence is defined once, the way desktop/src/integrity.ts's `isAbsence`
 * defines it and the Windows installer's `Get-PathPresence` mirrors it: ENOENT
 * is the file's absence, ENOTDIR is the absence of a directory on the way to it,
 * and EVERYTHING else means the answer is unknown. An unknown is never counted
 * towards a fault and never towards health — it gets its own verdict at the call
 * site, which is the only place that knows what "unknown" costs.
 */
export type Presence =
  | { kind: "present"; stats: fs.Stats }
  | { kind: "absent" }
  | { kind: "unknown"; error: string; code: string | null };

/** ENOENT / ENOTDIR is a real "no"; every other errno is "we could not tell". */
export function isAbsence(err: unknown): boolean {
  const code = errnoOf(err);
  return code === "ENOENT" || code === "ENOTDIR";
}

/** Tri-state `stat`. Never throws, and never invents an absence. */
export async function pathPresence(target: string): Promise<Presence> {
  try {
    return { kind: "present", stats: await fs.promises.stat(target) };
  } catch (err) {
    if (isAbsence(err)) return { kind: "absent" };
    return { kind: "unknown", error: errorText(err), code: errnoOf(err) };
  }
}

/**
 * Did the OS REFUSE, or did it fail to answer?
 *
 * `access(…, W_OK)` denying a write is a measurement; an EIO or an ELOOP out of
 * the same call is not, and reporting it as "this directory will not accept a
 * write" is the same mistake as reporting an unreadable path as missing.
 */
export function isRefusal(code: string | null): boolean {
  return code === "EACCES" || code === "EPERM" || code === "EROFS";
}
