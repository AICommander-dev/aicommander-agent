// Log lines for the Windows crash watchdog, and NOTHING ELSE may produce them.
//
// WHY THIS IS A MODULE AND NOT A TEMPLATE STRING AT THE CALL SITE. The watchdog
// runs as LocalSystem and its log is written into %ProgramData%, a machine-wide
// location that every local user can read. The things it observes, meanwhile,
// are user-controlled: process command lines, HKCU registry value data, profile
// paths, PowerShell error text quoting any of the above. A single
// `log(err.message)` would therefore publish one user's command line — and the
// connection keys and tokens that appear on command lines — to every other user
// on the machine, from a SYSTEM-owned file nobody thinks of as sensitive.
//
// THE RULE, from the owner and non-negotiable: a watchdog log line may contain
// ONLY a timestamp, a session id, a user SID, a coded outcome/reason, counts, an
// attempt number, a next-due tick, the installed product VERSION, and FIXED
// message text from this file. No command lines, no registry value contents, no
// file paths, no file NAMES, no exception messages, no tokens or keys — not
// "sanitised" versions of them, none at all.
//
// The version is the one addition that list has taken, and it did not loosen the
// rule: it is admitted on the same terms as the SID — an admin-owned value
// (%ProgramFiles%\...\install-manifest.json) re-validated to a shape that cannot
// carry a path or a token, and filtered again by gate 3 on the way out. It is
// there because "files are missing from the install" is not actionable without
// knowing which build is installed.
//
// The manifest SOURCE (`install` / `helper`) is admitted on stricter terms
// still: it is not an observed string at all but one of two codes this process
// chose, re-validated here against the coded-identifier shape. It is there
// because the counts now come from one of two files and a report that does not
// say which is a report an operator cannot check.
//
// It is enforced three ways, deliberately overlapping:
//   1. the event type below has no free-text field, so a caller CANNOT pass one;
//   2. every value is re-validated here (a SID that is not shaped like a SID is
//      replaced, a non-integer number becomes '?'), so a mistyped or hostile
//      value cannot ride in through a field that is nominally numeric;
//   3. the finished line is filtered to a small character set, so nothing with
//      structure (a path, a quoted string, a base64 blob) can survive intact.
//
// win-watchdog-log.test.ts pins all three: gates 1 and 2 against a snapshot
// deliberately stuffed with a command line and a token-shaped string, and gate 3
// against a value that PASSES the earlier gates and still carries a character
// outside the allowlist — so deleting the filter is observable. That last pin
// was missing while this comment claimed it existed, which is the same mistake
// the comment was written to stop: an enforcement claim nothing enforces.

import type { ProbeFailureReason } from "./win-watchdog.js";

/**
 * Everything the watchdog is allowed to say. Adding a variant is fine; adding a
 * `string` field that carries an observed value to a call site is not.
 *
 * EVERY VARIANT MUST HAVE A PRODUCTION EMITTER. `tray-list-overflow` sat here
 * with a message, a formatter branch, a test and a paragraph in OPERATIONS.md
 * telling operators to look for it — and nothing in startWindowsWatchdog ever
 * produced it, so the condition it named ("nothing was recovered this tick")
 * looked exactly like an idle machine, which is the failure mode this whole
 * module exists to remove. The suite stayed green because the test drove the
 * formatter directly. win-watchdog-log.test.ts now cross-checks these kinds
 * against the `formatWatchdogLine` call sites in win-watchdog.ts and against the
 * list in OPERATIONS.md, so a kind nothing emits fails the build.
 */
export type WatchdogLogEvent =
  /**
   * A tick produced no usable snapshot. `consecutive` = how many in a row,
   * `reason` = the one observed on THIS tick (the throttle bounds the rate, so a
   * reason that changed mid-run is reported by the next line rather than by an
   * extra one — see createLogThrottle).
   */
  | { kind: "probe-failed"; reason: ProbeFailureReason; consecutive: number }
  /** Sessions dropped by the probe because they could not be read (fail-closed). */
  | { kind: "sessions-skipped"; count: number }
  /** Processes named like the tray but not running from the install dir. */
  | { kind: "tray-lookalikes"; count: number }
  /** Processes named like the shell but not the one in the Windows directory. */
  | { kind: "shell-lookalikes"; count: number }
  /**
   * The shipped install manifest says files that must be there are not — the
   * antivirus-sweep verdict. `files` is what was counted, `missing` how many of
   * them are gone, `critical` how many of THOSE the app cannot start without,
   * `unreadable` how many the probe could not get an answer about at all, and
   * `version` the build the manifest describes. Numbers, a validated version
   * string and a coded source only: no path, and above all no FILE NAME, which
   * would be the first thing to smuggle text into a world-readable file.
   *
   * `unreadable` is here because without it the counts do not add up and nothing
   * says so: `files=81 missing=40 critical=7` leaves 34 entries the reader will
   * assume were found. `source` says WHICH copy of the manifest was counted —
   * `install` for the one inside the directory, `helper` for the copy beside the
   * privileged helper, which is the only one left once a sweep has emptied the
   * install (win-watchdog-install.ts).
   */
  | {
      kind: "install-incomplete";
      files: number;
      missing: number;
      critical: number;
      unreadable: number;
      version: string;
      source: string;
    }
  /**
   * THE THIRD VERDICT, which used to be silence. The manifest was read and N of
   * its entries could not be stat'd — a filter driver denying reads, a DACL, a
   * lock — while nothing was proved absent. It is NOT damage and it blocks
   * NOTHING; refusing to count a denial as damage is what keeps a security
   * product from suppressing crash recovery for every user on an intact machine.
   * But a machine-wide denial that produces no line at all is indistinguishable
   * from health in the only file an operator has, which is how it went unnoticed
   * for the life of the check. See win-watchdog-install-log.ts.
   */
  | {
      kind: "install-unreadable";
      files: number;
      missing: number;
      unreadable: number;
      version: string;
      source: string;
    }
  /**
   * The directory the watchdog measures holds no tray exe while `count`
   * processes named like the tray run from somewhere else — i.e. the Relaunch
   * task's pinned path is stale and every measurement downstream of it is being
   * taken in the wrong place. Its own kind because the alternative is an
   * indefinite `tray-exe-missing`, which sends an operator looking for a missing
   * install that is in fact sitting one directory over.
   */
  | { kind: "install-path-stale"; count: number }
  /** A relaunch was triggered for this user, in this session. */
  | {
      kind: "relaunch";
      sessionId: number;
      userSid: string;
      attempt: number;
      flaps: number;
      nextDueTick: number;
      atBackoffCeiling: boolean;
    }
  /** Previous relaunches for this user have not stuck. */
  | {
      kind: "relaunch-escalating";
      sessionId: number;
      userSid: string;
      attempt: number;
      flaps: number;
      atBackoffCeiling: boolean;
    }
  /** The Relaunch task could not be started. */
  | { kind: "relaunch-failed"; sessionId: number; userSid: string; attempt: number };

/** Fixed message text, by event kind. The ONLY prose that reaches the log. */
const MESSAGES = {
  "probe-failed": "no usable snapshot, tick skipped",
  "sessions-skipped": "session(s) not read this tick (unreadable or over budget), no recovery",
  "tray-lookalikes": "process(es) named like the tray ignored, not the installed exe",
  "shell-lookalikes": "process(es) named like the shell ignored, not the Windows shell",
  // No URL in either of these, however much a support engineer would want one:
  // '/' is not in ALLOWED_CHARS, so a link would arrive silently mangled. The
  // codes are what OPERATIONS.md is indexed by.
  "install-incomplete": "installed files are missing, the app cannot start, relaunch suppressed",
  // Says what it is NOT, because the count next to it looks like the one above.
  "install-unreadable":
    "some installed files could not be read (access denied or locked); this is not evidence of damage and nothing is suppressed",
  "install-path-stale":
    "no tray exe where the relaunch task points, but a tray runs elsewhere; reinstall to re-register it",
  relaunch: "no tray for this user, relaunch triggered",
  "relaunch-escalating": "previous relaunch(es) did not stick, backing off",
  "relaunch-failed": "relaunch task could not be started",
} as const;

/**
 * A SID and nothing else. Anything that is not shaped like one is replaced
 * rather than logged: with the version below, these are the only two observed
 * STRINGS that reach the log, so they are the only places where a bad value
 * could smuggle text in.
 */
const SID_RE = /^S-1-\d{1,10}(-\d{1,10}){0,15}$/i;

/** Coded reasons are lower-case identifiers; anything else is not one of ours. */
const CODE_RE = /^[a-z][a-z0-9-]{0,31}$/;

/**
 * A product version and nothing else. This is the SECOND string ever admitted
 * to a watchdog line, and the rule at the top of this file did not change to let
 * it in: it is admitted because it is re-validated here to a shape that cannot
 * carry a path, a quoted string or a token, exactly as the SID is. It reaches
 * the caller from the install manifest — a file in %ProgramFiles%, which no
 * non-admin can write — and it is there because "80 of 81 files are gone" is a
 * report nobody can act on without knowing WHICH build was gutted.
 */
const VERSION_RE = /^[0-9]{1,5}(\.[0-9]{1,5}){0,3}(-[A-Za-z0-9.]{1,16})?$/;

/**
 * Final gate: letters, digits, and the punctuation the format itself uses. A
 * path (`\`, `:`, `/`), a quoted string, an `=`-heavy blob or anything non-ASCII
 * cannot pass through intact, so even a future bug that put an observed value in
 * a numeric field cannot publish it verbatim.
 */
const ALLOWED_CHARS = /[^A-Za-z0-9 ()\-_.,;=?[\]:]/g;

function sid(value: string): string {
  return SID_RE.test(value) ? value : "invalid-sid";
}

function code(value: string): string {
  return CODE_RE.test(value) ? value : "unknown";
}

function version(value: string): string {
  return VERSION_RE.test(value) ? value : "unknown";
}

function num(value: number): string {
  return Number.isInteger(value) ? String(value) : "?";
}

/**
 * LOCAL machine time, second resolution: `yyyy-MM-dd HH:mm:ss`.
 *
 * The same clock and the same format as update.log, which is written next to
 * this file by win-updater.ps1's Write-Log (`Get-Date -Format 'yyyy-MM-dd
 * HH:mm:ss'`, i.e. local). OPERATIONS.md tells operators to read the two
 * together — an update in one explains a relaunch in the other — and this used
 * to stamp UTC while claiming to "match the shape of update.log's stamps",
 * which is true of the shape and false of the instant: on any machine not set to
 * UTC the two files disagreed by the local offset with nothing in either saying
 * so, so the correlation the doc asks for silently lined up the wrong events.
 *
 * Local time inherits local time's one ambiguity — under a DST fall-back an hour
 * repeats — but it inherits it IDENTICALLY in both files, which is what makes
 * them comparable line for line. That is the property being bought here.
 */
function stamp(now: Date): string {
  const pad = (n: number): string => String(n).padStart(2, "0");
  const date = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  return `${date} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

/**
 * Render one event as a log line. Pure, total (never throws) and the ONLY way a
 * line is produced — see the header for the rule it enforces.
 */
export function formatWatchdogLine(event: WatchdogLogEvent, now: Date = new Date()): string {
  const fields: string[] = [];
  switch (event.kind) {
    case "probe-failed":
      fields.push(`reason=${code(event.reason)}`, `consecutive=${num(event.consecutive)}`);
      break;
    case "sessions-skipped":
    case "tray-lookalikes":
    case "shell-lookalikes":
      fields.push(`count=${num(event.count)}`);
      break;
    case "install-incomplete":
      fields.push(
        `files=${num(event.files)}`,
        `missing=${num(event.missing)}`,
        `critical=${num(event.critical)}`,
        `unreadable=${num(event.unreadable)}`,
        `version=${version(event.version)}`,
        `source=${code(event.source)}`,
      );
      break;
    case "install-unreadable":
      fields.push(
        `files=${num(event.files)}`,
        `missing=${num(event.missing)}`,
        `unreadable=${num(event.unreadable)}`,
        `version=${version(event.version)}`,
        `source=${code(event.source)}`,
      );
      break;
    case "install-path-stale":
      fields.push(`count=${num(event.count)}`);
      break;
    case "relaunch":
      fields.push(
        `session=${num(event.sessionId)}`,
        `sid=${sid(event.userSid)}`,
        `attempt=${num(event.attempt)}`,
        `flaps=${num(event.flaps)}`,
        `next-due-tick=${num(event.nextDueTick)}`,
        `ceiling=${event.atBackoffCeiling ? "yes" : "no"}`,
      );
      break;
    case "relaunch-escalating":
      fields.push(
        `session=${num(event.sessionId)}`,
        `sid=${sid(event.userSid)}`,
        `attempt=${num(event.attempt)}`,
        `flaps=${num(event.flaps)}`,
        `ceiling=${event.atBackoffCeiling ? "yes" : "no"}`,
      );
      break;
    case "relaunch-failed":
      fields.push(
        `session=${num(event.sessionId)}`,
        `sid=${sid(event.userSid)}`,
        `attempt=${num(event.attempt)}`,
      );
      break;
  }
  const line = `[${stamp(now)}] watchdog ${code(event.kind)} ${fields.join(" ")} - ${
    MESSAGES[event.kind]
  }`;
  // Third gate (see header). Also collapses any stray control character, so one
  // line in the file is always one event.
  return line.replace(ALLOWED_CHARS, "");
}
