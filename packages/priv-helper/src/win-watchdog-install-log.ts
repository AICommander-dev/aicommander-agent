// What the watchdog SAYS about the install manifest — the third verdict
// included.
//
// WHY IT IS ITS OWN MODULE. The tick loop in win-watchdog.ts used to hold this,
// and it held only two of the three states the probe can report. That file is
// over the 1000-line limit and may not grow, so the branch moved here whole
// rather than gaining a third arm in place; the loop is now four lines that ask
// this function what, if anything, there is to say.
//
// ── THE THREE STATES, AND WHY THE MIDDLE ONE HAD TO BE ADDED ────────────────
// `unreadableFiles` has been measured, parsed and carried through the snapshot
// since the check shipped, and it reached NOTHING. `install-incomplete` logged
// `files/missing/critical/version`, and a manifest that was read cleanly while N
// entries could not be stat'd produced no line at all. So the two states the
// distinction exists to separate were both rounded to "fine" in the only
// diagnostic an operator has:
//
//   * a partially denied machine printed `files=81 missing=40 critical=7` with
//     34 files silently unaccounted for — the reader has no way to know the
//     denominator is not the whole story;
//   * a filter driver denying every read of %ProgramFiles% on an INTACT install
//     printed nothing whatsoever, which is exactly what a healthy machine
//     prints.
//
// The second is the one that matters. Refusing to count a denial as damage is
// what keeps a security product from suppressing crash recovery machine-wide
// (see `unreadableFiles` in win-watchdog-install.ts) — but "we did not find out"
// is only a third verdict if somebody can HEAR it. Silence is not the third
// verdict; it is the first one, spelled differently.
//
// NEITHER LINE CHANGES WHAT THE WATCHDOG DOES. `install-unreadable` blocks
// nothing, suppresses nothing and gates nothing: `installIncompleteVerdict` is
// the only consumer of these counts that decides anything, and it counts files
// proved ABSENT and never files we could not read. This module is diagnostics
// in the strict sense.

import type { WatchdogLogEvent } from "./win-watchdog-log.js";
import { installIncompleteVerdict } from "./win-watchdog-install.js";
import type { InstallSignals } from "./win-watchdog.js";

/**
 * The one line the manifest has to contribute this tick, or null for silence.
 *
 * At most one, deliberately: the damage verdict's line already carries the
 * unreadable count, so a machine that is both gutted and partly denied gets one
 * sentence with every number in it rather than two lines to correlate. That also
 * lets the caller keep a single throttle for the whole condition — see the
 * throttle note in win-watchdog.ts for why the rate bound, not the value, is
 * what has to be bounded.
 *
 * Pure and total: it reads counts and returns a value.
 */
export function installManifestEvent(install: InstallSignals): WatchdogLogEvent | null {
  const damaged = installIncompleteVerdict(install);
  if (damaged !== null) {
    return {
      kind: "install-incomplete",
      files: damaged.totalFiles,
      missing: damaged.missingFiles,
      critical: damaged.missingCritical,
      unreadable: damaged.unreadableFiles,
      version: damaged.version,
      source: damaged.source,
    };
  }
  const manifest = install.manifest;
  // NOTHING TO SAY IS NOT THE SAME AS NOTHING WRONG, but it is the same as
  // silence here: with no usable manifest there is no denominator, no count and
  // no fact — an older build, a quarantined manifest and a machine we could not
  // read all arrive as null and all mean "no evidence". The check that DOES
  // notice a vanished manifest is the doctor's, which can say so in prose.
  if (manifest === null || manifest.unreadableFiles <= 0) return null;
  return {
    kind: "install-unreadable",
    files: manifest.totalFiles,
    unreadable: manifest.unreadableFiles,
    missing: manifest.missingFiles,
    version: manifest.version,
    source: manifest.source,
  };
}
