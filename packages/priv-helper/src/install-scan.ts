// Count the installed app's shipped files FROM OUTSIDE the app, WITHOUT asking
// Windows anything that needs administrative rights.
//
// WHY IT EXISTS. `doctor`'s central question is the incident question — "how
// many files are left in your AI Commander folder?" — and it used to be answered
// only through the watchdog's probe. That probe derives the install directory
// from the "AI Commander Relaunch" scheduled task, whose SDDL grants access to
// SYSTEM and Administrators and to nobody else (desktop/build/win-update-task.ps1
// registers it that way on purpose). The Start Menu entry the installer creates
// for this verb launches UNELEVATED, and the helper's own ACL grants Users only
// (RX). So on the primary user-facing path — a normal user clicking "AI Commander
// Diagnostics" after their app stopped starting — the one check that answers the
// incident question degraded to "Windows could not be queried", which is the
// least useful sentence this binary could produce at that moment.
//
// WHY IT MAY GUESS WHERE THE PROBE MAY NOT. The watchdog refuses to guess
// because it ACTS: a directory it discovered becomes a task it triggers, so a
// wrong directory becomes a program somebody else chose. Nothing here acts. This
// module opens no process, executes nothing, deletes nothing and writes nothing;
// it lstats a list of relative paths and returns integers. A candidate root that
// is wrong yields "no manifest here" and the next candidate is tried — the cost
// of being wrong is a sentence, not a privilege.
//
// The candidates are derived from THIS binary's own location rather than from an
// environment variable: the installer copies the helper into
// `<ProgramFiles>\AI Commander Privileged Helper`, a SIBLING of the app's own
// directory (installer.nsh customInstall), so the container is simply this
// executable's grandparent. Both spellings of the app directory are tried
// because both exist in the field: electron-builder 26 derives the NSIS
// `APP_FILENAME` from win.executableName for a perMachine install, which has
// been `AICommander` since the Trusted Signing rename, while installs from
// before it sit in `AI Commander`.
//
// AND ONLY INSIDE THE ROOT IT IS COUNTING. The manifest chooses the paths this
// module lstats, so the entry path is vetted as a string (isManifestEntryPath),
// proved to spell itself inside the candidate root (entryTarget), and then
// proved to REFER to something inside it (entryRealTarget) — because `lstat`
// follows every component but the last, so a link inside the tree used to be
// enough to have this scan counting somebody else's directory.
//
// ABSENCE VERSUS DENIAL, as everywhere else in this workstream: only ENOENT and
// ENOTDIR count as a missing file. A read a security product's filter driver
// denied is not evidence that anything was removed — and this module exists for
// machines that have such a driver.
//
// ── AND THE INVENTORY ITSELF MAY BE GONE ─────────────────────────────────────
// The manifest is a file in the directory it describes, so the sweep that took
// 80 of 81 files took it too. Read only from in-tree, this scan then reports
// `no-manifest-found` — "we could not locate the install" — on the exact machine
// it exists to describe, which reads to the user as "nothing to see here".
//
// So the installer places a byte-identical copy of the manifest BESIDE THIS
// BINARY (installer.nsh customInstall), in the admin-owned sibling directory the
// sweep did not touch, and this scan falls back to it. Two rules keep the
// fallback honest:
//
//   * The in-tree copy always wins where it exists. It is the inventory OF the
//     directory being counted; the sibling copy is only a copy of what SOME
//     install shipped, so a half-applied update can never make the two disagree
//     in a way that matters — the fresher, local one is read first.
//   * The sibling copy is counted ONLY against a candidate root that exists as a
//     directory. Without that rule, a machine whose app is installed somewhere
//     this module cannot derive (NSIS `/D=`) would lstat every entry against a
//     directory that is not there, get ENOENT for all of them, and report a
//     perfectly healthy install as gutted. A root that does not exist is not
//     evidence; it is the absence of a place to look.

import fs from "node:fs/promises";
import path from "node:path";

import {
  MANIFEST_FILENAME,
  MANIFEST_REL_POSIX,
  MANIFEST_SCHEMA,
  MAX_MANIFEST_BYTES,
  MAX_MANIFEST_FILES,
  type ManifestSource,
} from "./win-watchdog-install.js";

/**
 * Directory names the app has been installed under, most recent first. See the
 * header for where each comes from; the sibling helper directory is the one
 * with spaces, and it is not in this list.
 */
export const APP_INSTALL_DIR_NAMES = ["AICommander", "AI Commander"] as const;

export interface InstallScan {
  /** The directory the counts describe. */
  root: string;
  /** Manifest entries actually examined. */
  totalFiles: number;
  /** Of those, entries proved absent (ENOENT/ENOTDIR). */
  missingFiles: number;
  /** Of the absent ones, entries the manifest flags `critical`. */
  missingCritical: number;
  /** Entries we could not get an answer about. Never counted as damage. */
  unreadableFiles: number;
  /** The manifest's `version`, or "" when it was not a plausible version. */
  version: string;
  /**
   * WHICH copy of the manifest was counted — `install` for the one inside the
   * root, `helper` for the copy beside this binary, which is the only one left
   * once a sweep has emptied the install. Never `unknown` here: this module
   * reads the file itself and always knows which it opened.
   */
  source: Exclude<ManifestSource, "unknown">;
}

/**
 * Why nothing was counted.
 *  - `not-windows`      — this scan is a Windows answer only.
 *  - `no-manifest-found`— no candidate root held a manifest we recognise. Says
 *                         nothing about whether files are missing.
 *  - `manifest-unusable`— a manifest WAS found and it cannot be counted: `files`
 *                         is empty, or ANY entry is not a path we will follow —
 *                         because of what it says (isManifestEntryPath) or
 *                         because of where it leads (entryRealTarget: a link
 *                         inside the root pointing out of it). That is a damaged
 *                         manifest, and
 *                         it must never be reported as "0 of 0 files missing" —
 *                         nor as "1 of 1 present" with the other eighty entries
 *                         quietly dropped — on a surface built to answer "are 80
 *                         of my 81 files gone?". The rejected path itself never
 *                         reaches the result: the caller is told the manifest is
 *                         unusable, not what it said.
 */
export type InstallScanFailure = "not-windows" | "no-manifest-found" | "manifest-unusable";

export type InstallScanResult =
  | { ok: true; scan: InstallScan }
  | {
      ok: false;
      reason: InstallScanFailure;
      /** The roots that were tried, so the report can say what was NOT looked at. */
      triedRoots?: readonly string[];
    };

/** Same shape check the watchdog applies before a version reaches a log. */
const VERSION_RE = /^[0-9]{1,5}(\.[0-9]{1,5}){0,3}(-[A-Za-z0-9.]{1,16})?$/;

/**
 * The roots to try, in order. `execPath` is a seam for the tests; in production
 * it is this SEA binary's own path.
 */
export function candidateInstallRoots(execPath: string): string[] {
  const container = path.dirname(path.dirname(execPath));
  return APP_INSTALL_DIR_NAMES.map((name) => path.join(container, name));
}

/** ENOENT/ENOTDIR is an absence; everything else means we did not find out. */
function isAbsence(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/**
 * What a manifest ENTRY's path is allowed to be.
 *
 * MIRROR of `isManifestEntryPath` in
 * desktop/src/install-manifest-contract.mjs — see that file for the rule, for
 * why `%` is an ordinary character here, and for the trace that settled it. It
 * is copied rather than imported for the reason everything in this package is:
 * the helper is a standalone SEA binary and `@aicommander/desktop` is not (and
 * must not become) a dependency of it. What keeps the copy honest is
 * __tests__/install-scan.test.ts, which runs THIS function and the declaration
 * over the one shared table of cases.
 *
 * This function had a rule of its own until 2026-09-03, and it disagreed with
 * the other four in both directions: it rejected `%`, which nothing else did,
 * and it accepted control characters and `<>"|?*`, which everything else
 * refused. Two readers of one file, disagreeing about what the file says.
 */
export function isManifestEntryPath(relative: unknown): relative is string {
  if (typeof relative !== "string" || relative.trim() === "") return false;
  // A backslash is a separator on Windows and a legal file name character on
  // POSIX; a colon is a drive letter or an NTFS alternate data stream.
  if (/[\\:]/.test(relative)) return false;
  if (relative.startsWith("/")) return false;
  // Control characters (NUL..US and DEL) and the characters Windows forbids in
  // a file name. Nothing electron-builder packs contains one, and a control
  // character is how a hostile string hides what it actually says.
  if (Array.from(relative).some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) {
    return false;
  }
  if (/["<>|?*]/.test(relative)) return false;
  return relative
    .split("/")
    .every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

/**
 * The absolute path an entry names, or `null` when the manifest may not steer us
 * there. The string rule above is a necessary condition and never a sufficient
 * one, so the path we are about to lstat PROVES it resolves under the root
 * instead of the string being trusted to imply it — the same two-step the
 * agent's `manifestEntryTarget` and win-install-check.ps1's root-prefix test
 * make, and for the same reason: only the reader knows the root.
 *
 * LEXICAL, and therefore only half the proof: a path can spell itself inside the
 * root and refer to something outside it, so nothing may be lstat'd on the
 * strength of this result alone. `entryRealTarget` supplies the other half.
 */
function entryTarget(root: string, relative: unknown): string | null {
  if (!isManifestEntryPath(relative)) return null;
  const resolvedRoot = path.resolve(root);
  const absolute = path.resolve(resolvedRoot, ...relative.split("/"));
  return isInside(resolvedRoot, absolute) ? absolute : null;
}

/**
 * Is `candidate` strictly under `resolvedRoot`? `path.relative` compares the way
 * the platform does — case-insensitively on win32, as win-install-check.ps1's
 * `OrdinalIgnoreCase` does. The root itself is not a valid target: the manifest
 * lists FILES.
 */
function isInside(resolvedRoot: string, candidate: string): boolean {
  const inside = path.relative(resolvedRoot, candidate);
  if (inside === "" || path.isAbsolute(inside)) return false;
  return inside !== ".." && !inside.startsWith(`..${path.sep}`);
}

/**
 * What an entry's path REFERS TO, once the links on the way to it are resolved.
 *
 * WHY. `lstat` declines to follow only the LAST component of a path and follows
 * every one before it, so a link `link` inside the install tree and the entry
 * `link/gone.dat` spelled itself inside the root, passed the lexical test above,
 * and got lstat'd somewhere else on the machine entirely — an absence outside
 * the installation counted as one of the shipped files this binary exists to
 * count, on the surface a user reaches precisely because their app will not
 * start. Nothing here opens or hashes anything, so that is the whole cost; it is
 * still a count of the wrong directory.
 *
 * MIRROR of `manifestEntryRealTarget` in the agent doctor's
 * checks/manifest-entry.ts (which carries the full argument), copied rather than
 * imported for the reason everything in this package is: the helper is a
 * standalone SEA binary. What keeps the copy honest is
 * __tests__/install-scan.test.ts, which runs THIS resolver and the desktop one
 * over the same shared table of filesystem cases.
 *
 * `inside` is the only path that may be lstat'd; `escapes` is the manifest
 * steering us out by way of a link, which condemns it exactly as a `..` entry
 * does; `absent` is the entry's directory not being there, which is the file
 * being gone; `unresolvable` is "we did not find out", which is neither.
 */
export type EntryRealTarget =
  | { kind: "inside"; absolute: string }
  | { kind: "escapes" }
  | { kind: "absent" }
  | { kind: "unresolvable"; code: string };

/**
 * Per-scan `realpath` memo, keyed by lexical directory: a manifest lists
 * hundreds of files across a few dozen directories, and one resolve per
 * directory is what keeps this from doubling the scan's syscalls. It lives for a
 * single scan, so it cannot go stale in any way that matters.
 */
export type EntryDirCache = Map<string, EntryRealTarget>;

/**
 * Resolve the directory chain of a lexically-contained entry path and re-prove
 * containment on what comes back.
 *
 * Only the PARENT is resolved: the final component is deliberately left alone so
 * a symlink there is still reported as a link by `lstat` rather than followed.
 * `realRoot` must already be resolved by the caller — an install under a
 * symlinked prefix would otherwise fail containment for every entry it has.
 */
export async function entryRealTarget(
  realRoot: string,
  absolute: string,
  cache: EntryDirCache,
): Promise<EntryRealTarget> {
  const dir = path.dirname(absolute);
  let resolved = cache.get(dir);
  if (!resolved) {
    resolved = await resolveDir(realRoot, dir);
    cache.set(dir, resolved);
  }
  if (resolved.kind !== "inside") return resolved;
  const target = path.join(resolved.absolute, path.basename(absolute));
  // The basename is one segment of a string the rule above already vetted, so it
  // cannot climb; the check is here because containment is never assumed.
  return isInside(realRoot, target) ? { kind: "inside", absolute: target } : { kind: "escapes" };
}

async function resolveDir(realRoot: string, dir: string): Promise<EntryRealTarget> {
  let real: string;
  try {
    real = path.resolve(await fs.realpath(dir));
  } catch (err) {
    // The same split `isAbsence` makes, and for the same reason: only ENOENT and
    // ENOTDIR are a missing file. A filter driver's EACCES, a link cycle's
    // ELOOP — those are answers we did not get.
    return isAbsence(err)
      ? { kind: "absent" }
      : { kind: "unresolvable", code: errnoOf(err) };
  }
  // The root's own real path is a valid parent: the manifest lists files
  // directly in the install root as well as in its subdirectories.
  if (real !== realRoot && !isInside(realRoot, real)) return { kind: "escapes" };
  return { kind: "inside", absolute: real };
}

function errnoOf(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" ? code : "unknown";
}

interface ManifestEntry {
  path?: unknown;
  critical?: unknown;
}

/**
 * Parse one manifest file. `file` is a full path — the in-tree copy or the
 * sibling one — and nothing here knows or cares which: the two are byte
 * identical, including `manifestPath`, which states where the manifest belongs
 * INSIDE THE INSTALL ROOT and is therefore the same sentence in both copies.
 * That check stays exactly as strict as it was; what it establishes is "this is
 * one of our inventories", not "this file is where it says it is".
 */
async function readManifestFile(
  file: string,
): Promise<{ files: ManifestEntry[]; version: string } | null> {
  try {
    const info = await fs.stat(file);
    if (!info.isFile() || info.size > MAX_MANIFEST_BYTES) return null;
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as {
      schema?: unknown;
      manifestPath?: unknown;
      version?: unknown;
      files?: unknown;
    };
    if (parsed?.schema !== MANIFEST_SCHEMA) return null;
    // The manifest states where it belongs inside an install root. Anything else
    // is not one of ours, whichever of the two copies we opened.
    if (parsed.manifestPath !== MANIFEST_REL_POSIX) return null;
    if (!Array.isArray(parsed.files)) return null;
    const version = typeof parsed.version === "string" && VERSION_RE.test(parsed.version) ? parsed.version : "";
    return { files: parsed.files as ManifestEntry[], version };
  } catch {
    // Absent, unreadable, or not JSON: all "no manifest here", which is the
    // quiet direction — never an accusation.
    return null;
  }
}

/** One root paired with the inventory to count it against. */
interface CandidateScan {
  root: string;
  manifest: { files: ManifestEntry[]; version: string };
  source: Exclude<ManifestSource, "unknown">;
}

/** Does this path exist AND is it a directory? Anything else is "no". */
async function isDirectory(target: string): Promise<boolean> {
  try {
    return (await fs.stat(target)).isDirectory();
  } catch {
    return false;
  }
}

/**
 * The (root, inventory) pairs worth counting, in the order they should be tried:
 * every candidate root that carries its own manifest first, then — only if none
 * did — the sibling copy beside this binary, paired with the first candidate
 * root that actually EXISTS.
 *
 * The two rules in the header are both here. In-tree wins because it comes
 * first, and the sibling copy is only ever paired with a directory we have seen,
 * so an install placed somewhere this module cannot derive yields no pair at all
 * rather than a fabricated "everything is missing".
 */
async function candidateScans(roots: readonly string[], execPath: string): Promise<CandidateScan[]> {
  const pairs: CandidateScan[] = [];
  for (const root of roots) {
    const manifest = await readManifestFile(path.join(root, ...MANIFEST_REL_POSIX.split("/")));
    if (manifest !== null) pairs.push({ root, manifest, source: "install" });
  }
  if (pairs.length > 0) return pairs;
  const sibling = await readManifestFile(path.join(path.dirname(execPath), MANIFEST_FILENAME));
  if (sibling === null) return pairs;
  for (const root of roots) {
    if (await isDirectory(root)) return [{ root, manifest: sibling, source: "helper" }];
  }
  return pairs;
}

/**
 * Scan the first candidate root that holds a manifest we recognise.
 *
 * Never throws. `ok: false` means we found nothing to count, which is
 * deliberately indistinguishable from an older build that shipped no manifest.
 */
export async function scanInstall(
  options: { execPath?: string; platform?: NodeJS.Platform } = {},
): Promise<InstallScanResult> {
  const platform = options.platform ?? process.platform;
  if (platform !== "win32") return { ok: false, reason: "not-windows" };

  const execPath = options.execPath ?? process.execPath;
  const triedRoots = candidateInstallRoots(execPath);
  // Set when a manifest was found but described nothing examinable, so the
  // caller is told "the manifest is damaged" rather than "no manifest here" —
  // two very different sentences for the person reading the report.
  let sawUnusableManifest = false;
  for (const { root, manifest, source } of await candidateScans(triedRoots, execPath)) {
    let totalFiles = 0;
    let missingFiles = 0;
    let missingCritical = 0;
    let unreadableFiles = 0;
    // A REJECTED ENTRY CONDEMNS THE MANIFEST, it is not skipped. Skipping it
    // was this module's worst bug: eighty malformed entries and one good one
    // reported `totalFiles=1, missing=0` — a clean bill of health derived from a
    // file every other reader refuses outright, on the UNELEVATED Start Menu
    // path, i.e. the surface a user reaches precisely because their app will not
    // start. Same shape as the empty-manifest branch below, and the same verdict.
    // EVERY entry is checked, including the ones past MAX_MANIFEST_FILES: that
    // cap bounds the lstat work, and validating a string costs nothing on an
    // array the manifest's byte limit has already bounded. Stopping the loop at
    // the cap would put a malformed entry back out of sight — behind a number
    // that reads as a measurement.
    let rejectedEntry = false;
    // The root is resolved ONCE and every entry is re-proved against the
    // resolved one, so no link the manifest picked can point an lstat outside
    // the directory being counted (see `entryRealTarget`). A root we cannot
    // resolve is not a root we can prove anything about: the candidate is
    // skipped, without accusing the manifest of anything.
    let realRoot: string;
    try {
      realRoot = path.resolve(await fs.realpath(root));
    } catch {
      continue;
    }
    const dirs: EntryDirCache = new Map();
    for (const entry of manifest.files) {
      const target = entryTarget(root, entry.path);
      if (target === null) {
        rejectedEntry = true;
        break;
      }
      // Past the cap the entry is validated and not probed. The string rule is
      // free on an array the manifest's byte limit already bounds; resolving a
      // directory is a syscall, and the cap is what bounds those.
      if (totalFiles >= MAX_MANIFEST_FILES) continue;
      const resolved = await entryRealTarget(realRoot, target, dirs);
      // A link that leads out of the installation is the manifest naming a file
      // outside it by another route — the same finding as a `..` entry, and the
      // same verdict, with nothing outside stat'd to reach it.
      if (resolved.kind === "escapes") {
        rejectedEntry = true;
        break;
      }
      totalFiles++;
      if (resolved.kind === "absent") {
        // The entry's own directory is not there. That is the file being gone.
        missingFiles++;
        if (entry.critical === true) missingCritical++;
        continue;
      }
      if (resolved.kind === "unresolvable") {
        unreadableFiles++;
        continue;
      }
      try {
        await fs.lstat(resolved.absolute);
      } catch (err) {
        if (isAbsence(err)) {
          missingFiles++;
          if (entry.critical === true) missingCritical++;
        } else {
          unreadableFiles++;
        }
      }
    }
    // AN EMPTY INVENTORY IS NOT A COMPLETE INSTALL. `ok: true` with zero files
    // rendered as "the installation is complete — all 0 shipped files are
    // present", i.e. a corrupted or truncated manifest read as a healthy
    // machine, on the one check this binary exists for. Nothing counted is a
    // failure to count, so the next candidate is tried and, failing that, the
    // caller is told the manifest itself is the problem.
    if (rejectedEntry || totalFiles === 0) {
      sawUnusableManifest = true;
      continue;
    }
    return {
      ok: true,
      scan: {
        root,
        totalFiles,
        missingFiles,
        missingCritical,
        unreadableFiles,
        version: manifest.version,
        source,
      },
    };
  }
  return { ok: false, reason: sawUnusableManifest ? "manifest-unusable" : "no-manifest-found", triedRoots };
}
