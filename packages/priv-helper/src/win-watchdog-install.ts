// The out-of-process half of the install-integrity check: everything the
// watchdog needs to tell "this install has been gutted" from "the tray simply is
// not running", plus the one condition that says the watchdog is measuring the
// WRONG DIRECTORY and therefore cannot tell anything at all.
//
// WHY THIS LIVES OUTSIDE THE APP. On 2026-09-02 an antivirus removed 80 of the
// 81 files in `C:\Program Files\AICommander\`. The running `AICommander.exe`
// survived (Windows locks a running image) and then died with `Invalid file
// descriptor to ICU data received`. `icudtl.dat` and `resources\app.asar` are
// consumed by ELECTRON'S OWN STARTUP, before a single line of our JavaScript
// runs, so the in-process check (desktop/src/integrity.ts) structurally cannot
// observe that case: the process is dead before it could look. The watchdog can,
// because it is a different binary in a sibling directory the sweep did not
// touch. What it saw instead, all night, was a healthy-looking machine — the exe
// was present, so nothing blocked — and it kept triggering the Relaunch task
// into an app that could not start.
//
// (The directory is spelled `AICommander`, no space: that is what the sweep
// emptied, re-measured across three machines when win-watchdog-probe.ts was
// written. `AI Commander` is the pre-1.0.15 spelling and survives only on
// installs from before the Trusted Signing rename — see APP_INSTALL_DIR_NAMES in
// install-scan.ts, which tries both.)
//
// ── AND WHERE THE MANIFEST IS READ FROM, WHICH IS THE WHOLE POINT ───────────
// The obvious place to read the inventory is inside the directory it describes,
// and for a year that was the only place. It does not survive the case this
// module exists for: the sweep took 80 of 81 files, and
// `resources\install-manifest.json` was one of them. `Test-Path` then answered
// $false, the verdict degraded to "no manifest, nothing to say", and the
// watchdog went on triggering the Relaunch task into an install that could not
// start — the pre-change behaviour, exactly. desktop/scripts/generate-manifest.mjs
// says it outright: the manifest cannot attest to itself, and "only a check
// outside this directory can cover that case".
//
// So the installer places a SECOND, byte-identical copy of the manifest beside
// this binary, in `%ProgramFiles%\AI Commander Privileged Helper` — the
// admin-owned sibling directory that survived the incident and that the app's
// uninstaller does not wipe (installer.nsh customInstall). The probe reads the
// in-tree copy FIRST and falls back to the sibling one, and the reply says which
// (`source`). Preferring the in-tree copy is what makes a partial update a
// non-event: the copy inside the directory is by definition the inventory OF
// that directory, so a sibling copy left behind by an older install is only ever
// consulted when there is no in-tree copy to disagree with.
//
// WHAT THE FALLBACK STILL CANNOT DO, stated rather than glossed: the entries are
// relative paths, so they are still statted under $installDir, which is derived
// from the Relaunch task. A machine that has lost the Relaunch task as well has
// no confirmed directory to count in and the check says nothing — "no evidence",
// never damage. The 2026-09-02 machine had the task (it is registered with Task
// Scheduler, not stored in $INSTDIR), which is why the fallback answers there.
// And a sibling copy with NO copy in the install directory is, by construction,
// possibly a build behind: it can only be wrong about files that were RENAMED
// between builds, and `critical` names Electron's own startup data and the exe,
// which do not get renamed. The alarm is gated on `critical` alone, so a stale
// sibling copy cannot raise one over a shuffled locale pack.
//
// WHAT THIS MODULE MAY AND MAY NOT DO — the constraint that shapes all of it.
// win-watchdog.ts's guarantee is that no observation is ever turned into a
// program name, a path we execute, or an argument we pass; the only action the
// watchdog can cause is `Run` on ONE fixed, admin-owned task. Nothing here
// changes that. Both manifests are read from admin-owned directories — the one
// DERIVED from that task's pinned action, and the one this SYSTEM process is
// itself executing out of — the relative paths in them are only ever STATTED
// (never executed, never joined into a command), and the two conditions below
// can only SUPPRESS a relaunch or add a log line. In particular the stale-path
// condition below deliberately does NOT repair the task: re-pointing a
// SYSTEM-triggered task at a directory discovered from a running process would
// turn it into a user-chosen program, which is the privilege escalation the
// current design exists to prevent. The repair path is re-running the installer,
// which re-registers from its own elevated context.
//
// THE SECOND PATH INTERPOLATED INTO THE PROBE SCRIPT. win-watchdog.ts's header
// used to say a terminal-services session id was the only value ever spliced
// into a script; it is now that plus this one directory, and the difference is
// stated here rather than left to be discovered. It is `process.execPath`'s own
// directory — not an environment variable (as LocalSystem the environment is
// stripped to 12 variables with no %ProgramFiles%, which is why the probe reads
// none) and not a guess. Its provenance is the strongest available: it is where
// Task Scheduler loaded THIS running image from, and win-privhelper-task.ps1
// refused to register that task at all unless that exact copy passed an
// exact-signer Authenticode check and the ACL guard. It is validated to a rooted
// drive path with no `%` and no control characters before it is quoted as a
// PowerShell literal, it is only ever an argument to `Test-Path`/`Get-Content`,
// and a value that fails validation simply removes the fallback candidate.
//
// The pure predicates here are consumed by win-watchdog.ts (the decision half)
// and the PowerShell fragment by win-watchdog-probe.ts (the impure half). It is
// a separate module because both of those are already at the size where adding
// to them is how they got that way.
//
// AND THE ONE RULE THAT RUNS THROUGH ALL OF IT: "the file is not there" and "I
// could not find out" are different answers, and only the first is evidence of
// damage. A denial from a security product's filter driver read as an absence
// would let that driver suppress crash recovery machine-wide on a perfectly
// intact install — the exact machine-wide-denial shape this module's neighbours
// have had removed twice. See `unreadableFiles` and the probe fragment.

import type { InstallSignals, WatchdogSnapshot } from "./win-watchdog.js";

/**
 * THE MANIFEST CONTRACT, MIRRORED. The producer is
 * `packages/desktop/scripts/generate-manifest.mjs` and it declares these two
 * values in `packages/desktop/src/install-manifest-contract.mjs`, which this
 * package cannot import: the helper is a standalone SEA binary with no
 * dependency on the desktop package, and adding one to reach two constants would
 * be a far larger commitment than mirroring them.
 *
 * A mirror that drifts is the silent-death shape this whole module is written
 * against: a renamed file, or a bumped schema, reads here as "no manifest
 * shipped" — which is deliberately indistinguishable from an older build and
 * therefore blocks nothing, logs nothing and looks exactly like health. So
 * win-watchdog-install.test.ts reads the desktop contract file and fails if
 * either value stops matching, the same way QUIT_MARKER_REL is pinned against
 * its two other derivations.
 */
export const MANIFEST_FILENAME = "install-manifest.json";
/** Manifests that do not carry THIS number are treated as absent, never as damage. */
export const MANIFEST_SCHEMA = 1;

/**
 * Where the manifest sits relative to the install root, in the manifest's own
 * spelling (forward slashes, as `manifestPath` records it on every platform).
 * On Windows the root is $INSTDIR and this is `process.resourcesPath`.
 */
export const MANIFEST_REL_POSIX = `resources/${MANIFEST_FILENAME}`;
/** The same path as Windows spells it, for Join-Path. */
export const MANIFEST_REL_WIN = MANIFEST_REL_POSIX.replace("/", "\\");

/**
 * WHICH of the two copies produced the counts — see the header.
 *  - `install` — `<installDir>\resources\install-manifest.json`, the inventory
 *    that shipped inside the directory being counted. Always preferred.
 *  - `helper`  — the copy the installer placed beside this binary. Consulted
 *    ONLY when there is no in-tree copy, which is itself the incident's shape.
 *  - `unknown` — a reply from a build that did not report the field. Never a
 *    reason to say less; the counts stand either way.
 */
export type ManifestSource = "install" | "helper" | "unknown";

/**
 * A directory this module is willing to quote into the probe script: a rooted
 * drive path, no unexpanded environment reference, no control characters, no
 * UNC (a `\\server\share` root would make the read a network call inside the
 * tick budget), and short enough to be a real Windows path. See the header for
 * where the value comes from and why it is admitted at all.
 */
const HELPER_DIR_RE = /^[A-Za-z]:\\[^%\u0000-\u001f]{0,240}$/;

/**
 * The sibling copy's full path, derived from THIS binary's own location.
 * `execPath` is a seam for the tests; in production it is the SEA binary Task
 * Scheduler started. Returns null when the location is not a shape we will
 * quote — which simply removes the fallback candidate, the quiet direction.
 */
export function helperManifestPath(execPath: string = process.execPath): string | null {
  const at = Math.max(execPath.lastIndexOf("\\"), execPath.lastIndexOf("/"));
  if (at < 0) return null;
  const dir = execPath.slice(0, at);
  if (!HELPER_DIR_RE.test(dir)) return null;
  return `${dir.replace(/[\\/]+$/, "")}\\${MANIFEST_FILENAME}`;
}

/** A PowerShell single-quoted literal: only the quote itself is special inside. */
function psLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * Most entries the probe will stat in one tick.
 *
 * NOT a security boundary — the manifest lives in %ProgramFiles%, which no
 * non-admin can write, so its length is not attacker-chosen. It is a cost
 * bound: the tick budget is shared with a process enumeration and a handful of
 * CIM calls (see WATCHDOG_INTERVAL_MS), and a `[System.IO.File]::GetAttributes`
 * on a local NTFS path is cheap but not free. A packaged Electron app on Windows is ~80-120 files
 * including `locales\`, so this leaves an order of magnitude of headroom.
 *
 * Over the cap the scan STOPS and the counts are a LOWER BOUND — the permissive
 * direction: fewer missing files can only mean "we said nothing", never a false
 * alarm.
 */
export const MAX_MANIFEST_FILES = 4096;

/**
 * Largest manifest we will read into memory. ~120 entries is ~15 KB; a megabyte
 * is four orders of magnitude of slack and still cannot wedge a tick.
 */
export const MAX_MANIFEST_BYTES = 1_048_576;

/**
 * What the shipped manifest says about the install RIGHT NOW. Presence and
 * counts only — never hashes: hashing app.asar every 60 seconds would cost more
 * than the rest of the tick put together, and an antivirus sweep DELETES files
 * rather than altering them, so presence is what catches the case this exists
 * for. (`doctor` is where a hash check belongs; it runs on demand.)
 */
export interface InstallManifestSignals {
  /**
   * Entries actually examined — the manifest's `files` array, minus entries the
   * probe refused to look at (see the path validation in the script) and minus
   * anything past MAX_MANIFEST_FILES. Reported rather than `manifest.totalFiles`
   * so the log's denominator is what was really counted.
   */
  totalFiles: number;
  /** Examined entries that are not on disk. */
  missingFiles: number;
  /**
   * Of those, entries the manifest flags `critical` — files whose absence alone
   * means the app cannot start (Electron's own startup data, the exe, the DLLs
   * next to it). Deliberately NOT the per-locale `.pak` packs: a build that
   * ships one language legitimately has the rest pruned, and treating those as
   * damage put a dialog on screen at every launch for one quarantined
   * translation. This is the number that justifies an alarm.
   */
  missingCritical: number;
  /**
   * Examined entries the probe could not get an answer about: the file may be
   * there and may not, because the attempt failed with something other than
   * "not found" — an access denial from a security product's filter driver
   * (the 2026-09-02 record has path-scoped denials even to an elevated
   * administrator), a lock, an I/O error.
   *
   * IT IS NOT DAMAGE, AND IT IS NOT COUNTED AS SUCH. `Test-Path` returning
   * $false was previously the whole test, and it answers $false for a denied
   * `GetFileAttributes` exactly as it does for a missing file — so one denying
   * filter driver reported a healthy install as gutted, `installIncompleteVerdict`
   * turned that into the machine-wide `install-incomplete` block, and crash
   * recovery was suppressed for EVERY user on the box for as long as the driver
   * was there, with one throttled log line an hour as the only signal. Reported
   * here so the log can say "we could not read N files" instead, which is a
   * different sentence and a different support case.
   */
  unreadableFiles: number;
  /**
   * The manifest's `version` — the build that wrote it. Diagnostic only: a
   * support engineer needs to know WHICH install was gutted. It comes from a
   * file in %ProgramFiles% (no non-admin can write it) and is re-validated
   * against a strict shape before it reaches the log, because the log is
   * world-readable and written as SYSTEM. Empty when the field was unusable.
   */
  version: string;
  /**
   * WHICH copy of the manifest these counts came from. Diagnostic only — it
   * gates nothing and changes no verdict — but it is the difference between "the
   * inventory that shipped inside the directory we counted" and "the copy beside
   * this binary, read because the in-tree one is gone with everything else", and
   * an operator reading `missing=80` is owed that distinction. See
   * ManifestSource.
   */
  source: ManifestSource;
}

/**
 * The settle window `installIncompleteVerdict` honours. It is INSTALL_SETTLE_MS,
 * restated rather than imported: win-watchdog.ts owns that constant and importing
 * it here at runtime would close the type-only cycle between the two modules.
 * win-watchdog-install.test.ts pins the two numbers together, so a change to one
 * fails on the other.
 */
const INSTALL_SETTLE_GRACE_MS = 120_000;

/**
 * Whether the manifest verdict is a CONFIDENT statement about damage.
 *
 * Three gates, and the first two are the existing in-flight signals rather than
 * a new mechanism: an install genuinely in progress has files missing for a
 * moment, and both windows are already measured — the Update task is RUNNING for
 * the whole silent download+install, and $INSTDIR's mtime is fresh for
 * INSTALL_SETTLE_MS after anything writes there (an unpacking installer, a
 * hand-extracted `app-64.7z`). Neither is re-derived here; `installBlockReason`
 * evaluates them first and this predicate is only consulted once they are clear.
 *
 * The third gate is `missingCritical > 0`, not `missingFiles > 0`. A user who
 * deletes a README, an antivirus that takes one locale pack, an installer that
 * pruned a translation — none of those stop the app starting, and a watchdog that
 * refuses to recover a healthy machine over one non-essential file is a worse
 * outage than the one it is guarding against. `critical` is exactly the flag the
 * manifest carries for this question.
 *
 * Returns the verdict (for the log) or null when there is nothing confident to
 * say — which is the same answer for "no manifest shipped", "manifest quarantined
 * too", "unreadable" and "an older build". All four must be indistinguishable
 * from health here: a missing manifest is never evidence of damage.
 *
 * `missingCritical` counts only files the probe proved ABSENT — never files it
 * could not read (`unreadableFiles`). Without that distinction a security
 * product denying reads of %ProgramFiles% would block crash recovery for every
 * user on an intact machine; see the probe fragment below.
 */
export function installIncompleteVerdict(install: InstallSignals): InstallManifestSignals | null {
  const manifest = install.manifest;
  if (manifest === null) return null;
  if (install.updateTaskRunning) return null;
  if (
    install.msSinceInstallDirChange !== null &&
    install.msSinceInstallDirChange < INSTALL_SETTLE_GRACE_MS
  ) {
    return null;
  }
  if (manifest.missingCritical <= 0) return null;
  return manifest;
}

/**
 * The W7 condition: the directory the watchdog MEASURES holds no tray exe, while
 * a process named like the tray is running from somewhere else.
 *
 * WHY THAT IS ITS OWN CONDITION. `win-watchdog-probe.ts` does not have an idea
 * of where the app lives — it extracts $installDir from the "AI Commander
 * Relaunch" task's pinned action (deliberately: it refuses to guess), and
 * `desktop/build/win-update-task.ps1` bakes that path in ONCE, at registration,
 * from where the script itself sat. Only the NSIS installer re-registers it. So
 * a recovery that does not run the installer — hand-extracting `app-64.7z`, which
 * is exactly what the 2026-09-02 incident required — leaves the task pointing at
 * an executable that no longer exists, and THREE symptoms follow from one stale
 * string: the task launches a path that is not there, the watchdog measures the
 * old directory and reports `tray-exe-missing` forever, and a perfectly healthy
 * tray running from the new directory fails the `$imagePath.StartsWith(
 * $installDirPrefix)` test and is counted as an impostor
 * (`unverifiedTrayProcesses`) instead of as ours.
 *
 * The last of those is what makes this detectable at all: on a stale path the
 * healthy tray shows up in precisely the counter that means "not the installed
 * exe". `tray-lookalikes` is the wrong thing to tell an operator then — it reads
 * as "somebody is running a renamed binary", when the truth is "we are looking in
 * the wrong place".
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It authorises nothing. `unverifiedTray-
 * Processes` is a count any unprivileged user can raise (start a renamed
 * `AICommander.exe`), so it may never gate an action — and it does not: the
 * machine is ALREADY blocked by `tray-exe-missing` whenever this is true, so the
 * only thing this changes is which sentence goes in the log. It especially does
 * not hand anyone a way to re-point the Relaunch task; see the module header.
 */
export function looksLikeStaleInstallPath(snapshot: WatchdogSnapshot): boolean {
  return !snapshot.install.trayExeInstalled && snapshot.unverifiedTrayProcesses > 0;
}

// --- the probe's half -------------------------------------------------------

/**
 * The PowerShell lines that measure the manifest, spliced into the probe script
 * by win-watchdog-probe.ts. It expects two variables already in scope there:
 * `$installDir` (derived from the Relaunch task's pinned action, and $null when
 * that derivation failed) and `$ordinal` (see the ORDINAL note in that file —
 * every string comparison in the probe binds the culture-insensitive overload
 * explicitly, because the search strings are punctuation).
 *
 * IT CATCHES ITS OWN FAILURES AND ADDS NOTHING TO $queryErrors — the one query in
 * the script that does. Everything else there fails closed by rejecting the whole
 * snapshot, because a failed process or task query reads as "nothing is running",
 * which AUTHORIZES a relaunch. This one is the opposite: it can only ever ADD a
 * block, so an unreadable manifest that rejected the snapshot would let a
 * diagnostic file deny recovery to every user on the machine — the exact
 * machine-wide-denial shape this module's neighbours have had removed twice.
 * Unreadable therefore degrades to `$null` = "nothing to say", i.e. exactly the
 * behaviour of the build before this check existed.
 *
 * THE RELATIVE PATHS ARE STATTED, NEVER EXECUTED, and they are validated before
 * even that, against the ONE rule every reader of this manifest applies — see
 * desktop/src/install-manifest-contract.mjs, which declares it and records why
 * `%` is an ordinary character in it. So an entry cannot escape the install
 * root. The root itself is the admin-owned directory already derived from the
 * pinned task. A rejected entry is simply not counted here (it cannot be
 * "missing" either), which is the quiet direction — note that this is the one
 * reader that does so: the in-process and doctor readers condemn the whole
 * manifest instead, because they have a verdict to report and this probe has
 * only a block it may add to a log.
 *
 * `helperManifest` is the sibling copy's full path — the fallback candidate, and
 * the one value this module quotes into the script. Defaulted from
 * `helperManifestPath()` so the probe's splice site does not have to know about
 * it; passed explicitly by the tests, which run off Windows where
 * `process.execPath` is not a shape we would ever quote. Null means one
 * candidate instead of two, and therefore the pre-fallback behaviour.
 */
export function manifestProbeLines(
  helperManifest: string | null = helperManifestPath(),
): string[] {
  return [
    "$installManifest = $null",
    // TWO CANDIDATES, IN-TREE FIRST. The order is the design (see the header):
    // the copy inside the directory is the inventory OF that directory, so it
    // wins whenever it exists and a sibling copy a build behind can never
    // contradict it. The sibling copy is reached only when the first is gone —
    // which, on the machine this feature exists for, is the whole point.
    //
    // The candidate list is built with a plain array of two-element arrays
    // rather than hashtables: PowerShell 5.1's `@{}` in a `foreach` is fine, but
    // an ordered pair keeps the generated script small and needs no property
    // access. [0] is the source code, [1] the path.
    "$manifestCandidates = New-Object System.Collections.ArrayList",
    "if ($installDir) {",
    `  [void]$manifestCandidates.Add(@('install', (Join-Path $installDir '${MANIFEST_REL_WIN}')))`,
    "}",
    // The sibling path is the ONE directory this module quotes into the script,
    // and it is quoted only after helperManifestPath() has validated its shape.
    // Absent (an unusual exec location, or a non-Windows test build) simply
    // means one candidate instead of two.
    ...(helperManifest === null
      ? []
      : [`[void]$manifestCandidates.Add(@('helper', ${psLiteral(helperManifest)}))`]),
    // STILL GATED ON $installDir. The manifest's entries are relative paths;
    // without a confirmed root there is nothing to stat them under, and guessing
    // a root is exactly what the watchdog may not do. No root = no evidence.
    "if ($installDir) {",
    "  foreach ($cand in $manifestCandidates) {",
    // First usable candidate wins; the rest are not even opened.
    "    if ($installManifest -ne $null) { continue }",
    "    try {",
    "      $manifestFile = $cand[1]",
    "      if (Test-Path -LiteralPath $manifestFile -PathType Leaf) {",
    "        $manifestItem = Get-Item -LiteralPath $manifestFile -Force",
    `        if ($manifestItem.Length -le ${MAX_MANIFEST_BYTES}) {`,
    "          $manifest = (Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8) | ConvertFrom-Json",
    // A schema we do not know is not damage and not a guess: say nothing. The
    // `manifestPath` check is what makes this file recognisably ONE OF OURS
    // rather than any JSON that happens to sit at the path — it is the manifest's
    // own statement of where it belongs INSIDE THE INSTALL ROOT, so it reads the
    // same in both copies (the sibling one is a byte copy) and a file that says
    // anything else is not an inventory of an AI Commander install.
    `          if (([int]$manifest.schema -eq ${MANIFEST_SCHEMA}) -and ([string]$manifest.manifestPath -eq '${MANIFEST_REL_POSIX}')) {`,
    "            $seen = 0",
    "            $missing = 0",
    "            $missingCritical = 0",
    "            $unreadable = 0",
    "            foreach ($f in @($manifest.files)) {",
    `              if ($seen -ge ${MAX_MANIFEST_FILES}) { break }`,
    "              $rel = [string]$f.path",
    // THE SHARED ENTRY-PATH RULE, in PowerShell. Character for character the one
    // desktop/src/install-manifest-contract.mjs declares and win-install-check.ps1
    // states as `Test-ManifestRelativePath`: not blank, no `\` and no `:`, not
    // rooted, no empty and no `.`/`..` segment, no control character and none of
    // `<>"|?*`. It rejected `%` until 2026-09-03 and nothing else did; the
    // contract's rule carries the trace that settled it — the entry is DATA read
    // out of the manifest at run time, never spliced into this script's text, and
    // it reaches the filesystem as an argument to a .NET call, so there is no
    // point at which cmd.exe could expand it. The `..` check is now segment-wise
    // rather than a substring, so a file legitimately named `a..b` is counted.
    "              if ([string]::IsNullOrWhiteSpace($rel)) { continue }",
    "              if ($rel -match '[\\\\:]') { continue }",
    "              if ($rel.StartsWith('/', $ordinal)) { continue }",
    "              if ($rel -match '(^|/)(/|$)') { continue }",
    "              if ($rel -match '(^|/)\\.{1,2}(/|$)') { continue }",
    "              if ($rel -match '[\\u0000-\\u001F\\u007F<>\"|?*]') { continue }",
    "              $seen++",
    "              $full = Join-Path $installDir ($rel.Replace('/', '\\'))",
    // ABSENCE, NOT "NOT FOUND BY Test-Path". GetFileAttributes fails with a
    // TYPED exception, so the two answers this feature depends on telling apart
    // stay apart: FileNotFoundException / DirectoryNotFoundException are the file
    // (or a directory on the way to it) genuinely not being there; anything else
    // — UnauthorizedAccessException from a filter driver or a DACL, IOException
    // from a lock — means we did not find out. Only the first may increment
    // $missing. Same ENOENT/ENOTDIR-versus-the-rest split `isAbsence` makes in
    // desktop/src/integrity.ts, against the same incident.
    //
    // The exception CHAIN is walked rather than the exception itself: a .NET
    // method that raises inside PowerShell surfaces as a MethodInvocationException
    // wrapping the real one, and an absence misread as an unknown would quietly
    // switch this check off. Only the two specific types count — IOException is
    // their base class and must never be tested for here.
    "              $absent = $false",
    "              $answered = $true",
    "              try {",
    "                [void][System.IO.File]::GetAttributes($full)",
    "              } catch {",
    "                $answered = $false",
    "                $ex = $_.Exception",
    "                while ($ex -ne $null) {",
    "                  if (($ex -is [System.IO.FileNotFoundException]) -or ($ex -is [System.IO.DirectoryNotFoundException])) { $absent = $true; break }",
    "                  $ex = $ex.InnerException",
    "                }",
    "              }",
    "              if ($answered) { continue }",
    "              if (-not $absent) { $unreadable++; continue }",
    "              $missing++",
    "              if ($f.critical -eq $true) { $missingCritical++ }",
    "            }",
    "            $installManifest = [ordered]@{",
    "              version = [string]$manifest.version",
    "              totalFiles = $seen",
    "              missingFiles = $missing",
    "              missingCritical = $missingCritical",
    "              unreadableFiles = $unreadable",
    "              source = [string]$cand[0]",
    "            }",
    "          }",
    "        }",
    "      }",
    // See the header: this query, alone in the script, degrades instead of
    // rejecting. $null here means "nothing to say", which is what an install
    // with no manifest at all (any build before this shipped) also means. It is
    // INSIDE the loop, so a candidate that throws leaves the next one to try.
    "    } catch { $installManifest = $null }",
    "  }",
    "}",
  ];
}

/**
 * Version strings we are willing to repeat. The value comes from an admin-owned
 * file, but it is the only string this feature adds to a SYSTEM-written,
 * world-readable log, so it is re-validated here rather than trusted: dotted
 * digits with an optional pre-release tail, nothing else. `win-watchdog-log.ts`
 * re-checks it a second time on the way out (that module's gate 2) and filters
 * the finished line (gate 3); this is the first of the three.
 */
const VERSION_RE = /^[0-9]{1,5}(\.[0-9]{1,5}){0,3}(-[A-Za-z0-9.]{1,16})?$/;

function asCount(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : null;
}

/**
 * Parse the probe's `installManifest` field.
 *
 * EVERY FAILURE MODE RETURNS null, INCLUDING AN ABSENT FIELD — and that is a
 * deliberate exception to this parser's house rule ("a missing field is treated
 * exactly like a failed query, not as a default"). The rule exists because every
 * other field's absence reads permissively, i.e. as "nothing is running", which
 * authorizes a relaunch. This field's absence reads as "no manifest", which
 * authorizes nothing and blocks nothing: it restores exactly the behaviour of
 * the watchdog before the check existed. Rejecting the snapshot over it would
 * instead skip the tick, and a skipped tick recovers NOBODY on the machine — a
 * diagnostic field with a machine-wide kill switch attached, which is the shape
 * that has already had to be removed from this module twice.
 *
 * The regression the house rule would have caught (a script that stopped
 * emitting the key) is caught instead by win-watchdog-install.test.ts, which
 * pins the field's presence in the generated script text.
 */
export function parseInstallManifestSignals(v: unknown): InstallManifestSignals | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const r = v as Record<string, unknown>;
  const totalFiles = asCount(r["totalFiles"]);
  const missingFiles = asCount(r["missingFiles"]);
  const missingCritical = asCount(r["missingCritical"]);
  if (totalFiles === null || missingFiles === null || missingCritical === null) return null;
  // `unreadableFiles` is diagnostic only — it can neither raise an alarm nor
  // suppress one — so an absent or unusable value degrades to 0 rather than
  // rejecting a reply whose three load-bearing counts are all present.
  const unreadableFiles = asCount(r["unreadableFiles"]) ?? 0;
  const rawVersion = typeof r["version"] === "string" ? r["version"] : "";
  // The source is a CODE, not a path, and it is validated against the two names
  // this module emits rather than passed through: it reaches a world-readable,
  // SYSTEM-written log, so an unrecognised value becomes "unknown" instead of
  // becoming text in that file. A reply from a build that predates the field is
  // "unknown" too, and that costs nothing — the field gates no verdict.
  const rawSource = r["source"];
  const source: ManifestSource =
    rawSource === "install" || rawSource === "helper" ? rawSource : "unknown";
  // Counts that cannot all be true of one directory describe no install at
  // all: say nothing rather than alarm on a reply we do not understand.
  if (missingFiles > totalFiles || missingCritical > missingFiles) return null;
  if (unreadableFiles > totalFiles || missingFiles + unreadableFiles > totalFiles) return null;
  return {
    totalFiles,
    missingFiles,
    missingCritical,
    unreadableFiles,
    version: VERSION_RE.test(rawVersion) ? rawVersion : "",
    source,
  };
}
