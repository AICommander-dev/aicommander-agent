import fs from "node:fs";
import path from "node:path";

/**
 * Where a manifest entry is allowed to point, and the proof that it does.
 *
 * ── THE RULE IS DECLARED ELSEWHERE ───────────────────────────────────────────
 * `isManifestEntryPath` MIRRORS `isManifestEntryPath` in
 * packages/desktop/src/install-manifest-contract.mjs, for the reason
 * MANIFEST_FILENAME and MANIFEST_SCHEMA are mirrored in install.ts: the agent
 * ships to npm on its own and `@aicommander/desktop` is not (and must not
 * become) a dependency of it. `doctor-manifest-parity.test.ts` runs BOTH
 * implementations over one table of cases, so a mirror that drifts fails a test
 * here rather than quietly disagreeing about what the manifest means.
 *
 * ── WHY IT EXISTS ────────────────────────────────────────────────────────────
 * Both TypeScript readers of the manifest used to do `path.join(root,
 * ...entry.path.split("/"))` and then `stat` the result, and the agent's doctor
 * additionally streamed it through sha256. So a corrupted or hostile manifest
 * could point either component at any path on the machine: `..` walks out of the
 * installation, an absolute entry replaces the root outright. The consequences
 * are worse than a wrong verdict — a FIFO makes the doctor hang, `/dev/zero`
 * streams forever into the hash, and file metadata from outside the installation
 * reaches a report we tell users to send to antivirus vendors. The two
 * PowerShell readers already refused such an entry before probing it; these two
 * did not.
 *
 * ── STRING RULE, THEN CONTAINMENT ────────────────────────────────────────────
 * The string rule is a necessary condition and never a sufficient one, so the
 * derived absolute path must additionally PROVE it resolves under the root
 * rather than the string being trusted to imply it. `manifestEntryTarget` is the
 * only way either check turns an entry into a path.
 *
 * And a LEXICAL proof of containment is itself only necessary, never sufficient:
 * a path can spell itself inside the root and refer to something outside it. A
 * symlink anywhere on the way to the file is followed by every syscall that
 * takes a path — `lstat` included, which declines to follow only the LAST
 * component — so with a link `link` inside the install tree the entry
 * `link/file` used to pass the string rule, pass the lexical test, and get
 * stat'd and streamed through sha256 from outside the installation.
 * `manifestEntryRealTarget` closes that by resolving the entry's parent
 * directory with `realpath` and re-proving containment on the result, so the
 * path handed to `lstat` has no unresolved link left in it. The final component
 * is deliberately NOT resolved: a symlink there must be reported as a symlink
 * (install.ts's regular-file gate), never followed.
 *
 * A rejected entry is NOT damage. It makes the manifest unusable — a verdict
 * both readers already have (a `warn` here, `unavailable` in integrity.ts) — and
 * reporting it as missing or altered files would accuse a user's antivirus on
 * the strength of a file we could not trust in the first place.
 */

/**
 * Is this a relative POSIX path inside the install root, and nothing else?
 * MIRROR — see the header before changing a character of it.
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
 * there.
 *
 * The containment test is done on the RESOLVED path, not on the string: the
 * string rule above is what a well-formed entry looks like, and this is the
 * proof that the thing we are about to `lstat` is inside the installation the
 * manifest describes. `path.relative` does that comparison the way the platform
 * does — case-insensitively on win32, as win-install-check.ps1's
 * `OrdinalIgnoreCase` does — and the root is our own string on both sides, so
 * no case difference can arise from anything the manifest supplied.
 *
 * The test here is LEXICAL, and that is only half the proof: it is a statement
 * about the path we were asked to look at, not about what the filesystem
 * redirects it to. A symlink inside the root that points outside it passes this
 * function — see the header — so nothing may be stat'd, opened or hashed on the
 * strength of this result alone. `manifestEntryRealTarget` supplies the other
 * half and returns the path that is actually safe to probe.
 *
 * The root itself is not a valid target: the manifest lists FILES in the
 * installation, never the directory containing them.
 */
export function manifestEntryTarget(root: string, relative: unknown): string | null {
  if (!isManifestEntryPath(relative)) return null;
  const resolvedRoot = path.resolve(root);
  const absolute = path.resolve(resolvedRoot, ...relative.split("/"));
  if (!isInside(resolvedRoot, absolute)) return null;
  return absolute;
}

/**
 * Is `candidate` a path strictly under `resolvedRoot`?
 *
 * `path.relative` does the comparison the way the platform does — case
 * insensitively on win32, as win-install-check.ps1's `OrdinalIgnoreCase` does —
 * and the root is our own string on both sides, so no case difference can arise
 * from anything the manifest supplied.
 */
function isInside(resolvedRoot: string, candidate: string): boolean {
  const inside = path.relative(resolvedRoot, candidate);
  if (inside === "" || path.isAbsolute(inside)) return false;
  return inside !== ".." && !inside.startsWith(`..${path.sep}`);
}

/**
 * What an entry's path REFERS TO, once the links on the way to it are resolved.
 *
 * `inside` carries the only path install.ts may probe: its directory chain is
 * fully resolved, so no `lstat`, `open` or read through it can be redirected out
 * of the installation by a link the manifest chose. `escapes` is the manifest
 * steering us outside by way of a link and is treated exactly like a `..` entry
 * — the manifest is unusable, never evidence of damaged files. `absent` is the
 * entry's directory not being there (its own kind of missing file), and
 * `unresolvable` is "we could not find out", which is neither.
 */
export type ManifestEntryRealTarget =
  | { kind: "inside"; absolute: string }
  | { kind: "escapes" }
  | { kind: "absent" }
  | { kind: "unresolvable"; code: string };

/** Per-run `realpath` memo, keyed by lexical directory — see `manifestEntryRealTarget`. */
export type ManifestDirCache = Map<string, ManifestEntryRealTarget>;

/**
 * Resolve the directory chain of a lexically-contained entry path and re-prove
 * containment on what comes back.
 *
 * Only the PARENT is resolved, and the resolved parent is memoised per lexical
 * directory: a manifest lists hundreds of files across a few dozen directories,
 * and one `realpath` per directory is what keeps this pass from doubling its
 * syscalls. The memo lives for a single run, so it cannot go stale in any way
 * that matters — and it is per-directory rather than per-entry precisely so a
 * hostile manifest cannot make the doctor do more work than the tree it
 * describes.
 *
 * `realRoot` must already be `realpath`-resolved by the caller (an install under
 * a symlinked prefix — `/var` on macOS is `/private/var` — would otherwise fail
 * containment for every entry it has).
 */
export async function manifestEntryRealTarget(
  realRoot: string,
  absolute: string,
  cache: ManifestDirCache,
): Promise<ManifestEntryRealTarget> {
  const dir = path.dirname(absolute);
  let resolved = cache.get(dir);
  if (!resolved) {
    resolved = await resolveDir(realRoot, dir);
    cache.set(dir, resolved);
  }
  if (resolved.kind !== "inside") return resolved;
  const target = path.join(resolved.absolute, path.basename(absolute));
  // The basename is one segment of a string the rule above already vetted, so
  // this cannot climb; the check is here because containment is never assumed.
  return isInside(realRoot, target) ? { kind: "inside", absolute: target } : { kind: "escapes" };
}

async function resolveDir(realRoot: string, dir: string): Promise<ManifestEntryRealTarget> {
  let real: string;
  try {
    real = await fs.promises.realpath(dir);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    // ENOENT is the directory not being there; ENOTDIR is a file where one of
    // its parents should be — both are absences, and everything else (EACCES
    // from a filter driver, ELOOP from a link cycle, EBUSY) is an answer we did
    // not get. Only the first kind may ever be counted as a missing file.
    if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
    return { kind: "unresolvable", code: typeof code === "string" ? code : "unknown" };
  }
  // The root's own real path is a valid parent: the manifest lists files
  // directly in the install root as well as in its subdirectories.
  if (path.resolve(real) !== realRoot && !isInside(realRoot, path.resolve(real))) {
    return { kind: "escapes" };
  }
  return { kind: "inside", absolute: path.resolve(real) };
}
