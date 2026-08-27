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
// ONLY a timestamp, a session id, a user SID, a coded outcome/reason, an attempt
// number, a next-due tick, and FIXED message text from this file. No command
// lines, no registry value contents, no file paths, no exception messages, no
// tokens or keys — not "sanitised" versions of them, none at all.
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
  relaunch: "no tray for this user, relaunch triggered",
  "relaunch-escalating": "previous relaunch(es) did not stick, backing off",
  "relaunch-failed": "relaunch task could not be started",
} as const;

/**
 * A SID and nothing else. Anything that is not shaped like one is replaced
 * rather than logged: the SID is the only observed STRING that reaches the log,
 * so it is the only place where a bad value could smuggle text in.
 */
const SID_RE = /^S-1-\d{1,10}(-\d{1,10}){0,15}$/i;

/** Coded reasons are lower-case identifiers; anything else is not one of ours. */
const CODE_RE = /^[a-z][a-z0-9-]{0,31}$/;

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
