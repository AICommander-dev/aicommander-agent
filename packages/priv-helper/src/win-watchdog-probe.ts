// The impure half of the Windows crash watchdog: everything that has to ask
// Windows a question, plus the one action the watchdog can take. The decision
// logic lives in win-watchdog.ts and is unit-tested against this module's output
// shape; nothing here decides anything.
//
// Both entry points shell out to the FULL path of the in-box powershell.exe
// (never a bare name — this process is LocalSystem and PATH is not ours to
// trust) with a fixed -EncodedCommand script. EncodedCommand, not -Command:
// the script is handed over as one opaque base64 token, so no amount of quoting
// in the script body can be re-interpreted by the Windows command line. The only
// value ever interpolated into a script is a session id, and it is validated as a
// non-negative integer first. Nothing read from anywhere is ever turned into a
// path we execute or a program name.
//
// The scripts run in session 0 under SYSTEM, which has no desktop — so unlike a
// launcher hosted in the user's own session, this can never flash a console
// window at anybody.

import { execFile, type ExecFileException } from "node:child_process";
import { manifestProbeLines, parseInstallManifestSignals } from "./win-watchdog-install.js";
import {
  TRAY_IMAGE_NAME,
  RELAUNCH_TASK_NAME,
  UPDATE_TASK_NAME,
  type InstallSignals,
  type ProbeFailureReason,
  type ProbeQueryName,
  type ProbeResult,
  type UserSession,
  type WatchdogSnapshot,
} from "./win-watchdog.js";

// ANYTHING THIS MODULE MIRRORS FROM THE DESKTOP APP — paths, directory names,
// registry keys, value names — MUST be verified against a PACKAGED, INSTALLED
// build, never inferred from the dev `packages/desktop/package.json`. The two
// disagree, and the disagreement is invisible from here: every mismatch shows up
// as a field that reads "false" / "absent", which is exactly what a healthy
// machine with nothing to do looks like. Two silent deaths came from this in one
// day (a stripped SYSTEM environment, and the Run value name below). Measure on
// the box, then write the measurement into the comment — and where a value can
// be DERIVED from admin-owned state instead of mirrored, derive it (the install
// directory below is derived; the quit-marker path is mirrored, and is pinned to
// the other two derivations by win-watchdog-probe.test.ts).
//
// MEASURED on a real installation. The 2026-08-08 reading recorded the install
// directory WITH a space (`C:\Program Files\AI Commander\`); re-measured on
// 2026-09-03 across three Windows machines (aic-pc, aic-wfs-pc, aic-wfs-pc2) it is
// consistently WITHOUT one, and aic-pc's uninstall entry agrees
// (`InstallLocation=C:\Program Files\AICommander`). The August reading was a
// pre-rename build; the directory name follows `executableName: AICommander` in
// electron-builder.yml through app-builder-lib's `productFilename`.
//
//   Run value:  electron.app.AI Commander = "C:\Program Files\AICommander\AICommander.exe"
//   user data:  --user-data-dir="C:\Users\<u>\AppData\Roaming\@aicommander/desktop"
//
// Note the three DIFFERENT names in play: the Run VALUE NAME is electron-builder's
// `productName` ("AI Commander", with a space), the install DIRECTORY is
// `executableName` ("AICommander", without), and the user-data directory is
// package.json's `name` ("@aicommander/desktop"). The privileged helper's own
// sibling directory keeps the spaced spelling too (`AI Commander Privileged
// Helper`). There is NO single "app name" constant that is right for all of them
// — do not introduce one, and do not assume a spelling: derive it.

/**
 * The tray's per-user data dir, relative to roaming AppData: Electron's
 * app.getPath('userData'), where quit-marker.ts writes '.user-quit'.
 * MEASURED (see above) as the package.json name, with the '/' kept as a literal
 * path segment separator on disk. Do NOT re-derive this from productName.
 *
 * This is the ONE string here that is still mirrored rather than derived, and it
 * is the fail-OPEN direction (a wrong path reads as "the user never asked to
 * stay down"), so win-watchdog-probe.test.ts pins it against BOTH other
 * derivations of the same path: desktop/src/quit-marker.ts and the launcher
 * command built by desktop/build/win-update-task.ps1.
 */
export const QUIT_MARKER_REL = "@aicommander\\desktop\\.user-quit";

/**
 * Sanity caps on what one probe may report. They are not tuning knobs: the
 * process list is attacker-influenced (anybody can start processes), so a reply
 * whose size follows the process list is a reply whose size an attacker chooses
 * — and the failure that produced, an output buffer overflow, was
 * indistinguishable from "nothing to report", i.e. it suppressed recovery for
 * every user on the box for as long as the attacker kept the processes alive.
 *
 * THE ANSWER IS AGGREGATION, NOT A BIGGER CAP. The decision half needs exactly
 * one bit per USER — does this SID own a verified MAIN tray? — so the script
 * groups by owner SID and emits the SET of owning SIDs, never a record per
 * process. The reply is therefore sized by USERS, and starting the installed exe
 * a thousand times cannot grow it at all.
 *
 * That shape matters because the previous one's over-cap HANDLING was itself the
 * vulnerability, twice over. A per-process list has to be capped; the first
 * version made exceeding the cap a query error, which rejects the whole snapshot
 * — a per-list bound turned into a machine-wide kill switch. The second replaced
 * that with a `trayProcessesOverflow` flag, which the decision half turned into
 * a machine-wide BLOCK: same outcome, one indirection further in. An Electron
 * tray is 4-6 AICommander.exe processes, so an unprivileged user reached even a
 * 512-process cap by launching the installed exe ~100 times, and recovery then
 * stopped for every other user on the machine with one hourly log line as the
 * only symptom. The flag, the block and the per-process list are all gone
 * together.
 *
 * WHAT THAT ACTUALLY BUYS, stated as a mechanism rather than as an absolute — a
 * security comment that overstates its guarantee is worse than none, because the
 * next author reasons from it and stops looking. Two properties, each with its
 * own mechanism:
 *   * NO MACHINE-WIDE SUPPRESSING FLAG. Nothing this script reports is applied
 *     machine-wide except the three install signals, and all three are rooted in
 *     admin-owned state (see the TRUSTWORTHINESS block below). There is no
 *     remaining per-list "the cap was hit" that the decision half turns into a
 *     block; every cap degrades its own signal, listed below.
 *   * NO ATTACKER-SIZED REPLY. The reply is sized by USERS, not processes, so it
 *     cannot be pushed past PROBE_MAX_OUTPUT_BYTES.
 *   * BOUNDED WORK, AND NOW PRICED. Every loop that costs a CIM method call per
 *     candidate is bounded per SESSION and again GLOBALLY, and the budgets are
 *     sized from a measured per-call cost so the worst case demonstrably fits
 *     inside PROBE_TIMEOUT_MS — see MEASURED_OWNER_SID_LOOKUP_MS and the two
 *     MAX_*_OWNER_LOOKUPS pairs below for the arithmetic, and
 *     win-watchdog-probe.test.ts for the assertion that keeps it true.
 *     The previous budgets (512 global tray lookups + 16 per session) were
 *     chosen without measurement and did NOT fit: at the measured 73.68 ms per
 *     call the tray budget alone was 37.7 s against a 30 s timeout, so one
 *     unprivileged user could make every tick time out — and a timed-out probe
 *     recovers NOBODY on the machine. That is the machine-wide denial of
 *     recovery this whole rework exists to remove, re-entering through the
 *     clock instead of through the reply size, and it was real and reachable.
 * Neither property says a user cannot suppress their OWN recovery: they can, by
 * opting out of autostart, by writing the quit marker, or by exhausting their own
 * session's lookup budget. That direction is theirs to choose.
 *
 * What is left is a backstop on the AGGREGATE, plus the two caps that were
 * always about bounding per-user work, each degrading its OWN signal:
 *
 *   * tray owner SIDs — distinct owners of a verified MAIN tray. The space it
 *     bounds is "accounts simultaneously running the installed exe", which is
 *     the same space MAX_SESSIONS already bounds, so it reuses that number
 *     rather than inventing a second one. Processes cannot reach it: a 257th
 *     entry needs credentials for a 257th account. If it were reached, the
 *     dropped owners read as "that user has no tray" — the bounded direction,
 *     and the same one an unresolved owner SID already takes. Bounded is not
 *     free: see MAX_TRAY_OWNER_LOOKUPS for what a dropped tray owner actually
 *     costs that user.
 *   * sessions — over-cap sessions are counted into `skippedSessions`, the
 *     existing fail-closed drop counter. A dropped session gets no recovery this
 *     tick; every other session is still evaluated normally. The GetOwnerSid
 *     budget that bounds the scan's WORK is charged the same way — per SESSION
 *     ID, which is not per user: overrunning one bucket drops candidates in that
 *     session only, but the GLOBAL pool the buckets draw on is first-come, so a
 *     user holding several sessions can exhaust it and starve later ones for
 *     that tick. See MAX_SHELL_OWNER_LOOKUPS_PER_SESSION for the numbers and for
 *     why keying by owner SID is not available here.
 *   * Run values per user — over-cap stops the scan. Missing the value that
 *     points at the tray exe reads as "autostart off" for THAT user, which
 *     suppresses their own recovery and nobody else's.
 *
 * The intermediate list of verified tray processes is held IN MEMORY ONLY. It is
 * a subset of the Win32_Process enumeration this script already performs, so it
 * allocates nothing the tick had not already allocated, and it is never
 * serialised — which is exactly what makes the reply's size independent of it.
 */
export const MAX_SESSIONS = 256;
/** Distinct tray owners reported. Deliberately the same number — see above. */
const MAX_TRAY_OWNERS = MAX_SESSIONS;

/**
 * THE PRICE OF ONE Win32_Process::GetOwnerSid CALL, in milliseconds.
 *
 * MEASURED 2026-08-09 on aic-pc (Windows x64, 281 live processes) under the
 * identity the watchdog really runs as — LocalSystem, via the privileged helper —
 * over 100 Invoke-CimMethod calls, 99 of which succeeded: 73.68 ms each. The two
 * enumerations the tick also performs were measured at the same time and are not
 * the problem: Get-CimInstance Win32_Process over 281 processes is 163 ms and
 * Win32_UserProfile over 7 profiles is 28 ms, ~200 ms together.
 *
 * This constant exists so the lookup budgets below are ARITHMETIC rather than
 * intuition. Their adequacy used to live in a comment, which is exactly how they
 * came to be an order of magnitude too loose; win-watchdog-probe.test.ts now
 * multiplies the worst-case lookup count by this number and fails if the product
 * exceeds PROBE_TIMEOUT_MS * OWNER_LOOKUP_BUDGET_FRACTION (there is no
 * OWNER_LOOKUP_BUDGET_MS constant — an earlier version of this line named one
 * that was never written). Raising any cap, or adding a third lookup site,
 * therefore fails a test instead of silently re-opening a measured hole.
 *
 * Re-measure it if the shape of the call changes. A slower box moves it the wrong
 * way, so if it is ever re-measured higher, the caps have to come down.
 */
export const MEASURED_OWNER_SID_LOOKUP_MS = 73.68;

/**
 * The share of PROBE_TIMEOUT_MS the owner lookups are allowed to consume in the
 * worst case. A THIRD, not "most of it": the same 30 s has to cover the
 * powershell.exe cold start (seconds, on a box under load), the two CIM
 * enumerations (~200 ms measured), the Task Scheduler COM calls, the per-session
 * registry and file work, and a margin wide enough that a machine slower than the
 * one this was measured on still finishes.
 */
export const OWNER_LOOKUP_BUDGET_FRACTION = 1 / 3;

/**
 * GetOwnerSid calls the tray aggregation will make in one tick, PER SESSION ID,
 * and GLOBALLY across all sessions.
 *
 * Distinct OWNERS cannot be driven up by starting processes, but the LOOKUPS
 * can: one CIM method call per candidate main process, and a user may start as
 * many verified copies of the installed exe as they like (admin ownership
 * protects the binary, not the right to run it).
 *
 * WHY THERE ARE TWO NUMBERS, and why lowering the global one alone would have
 * been the wrong fix. The global budget is FIRST-COME, and the loop walks one
 * process list, so a user who starts many verified trays can consume it before
 * ANOTHER user's live tray is reached. That user then reads as tray-less: they
 * get a relaunch their own single-instance lock discards, and the discarded
 * relaunch counts as a flap. `flaps` is a COUNT OF FLAPS, not a tick count:
 * backoffTicks doubles the wait behind each one (2, 4, 8, 16, 32 ticks) until
 * the SIXTH reaches WATCHDOG_MAX_BACKOFF_TICKS = 60 — so the retries are not
 * every tick, and sustained crowd-out arrives there after ~69 ticks (measured
 * by driving evaluateTick; win-watchdog.test.ts pins the doubling and the
 * ceiling, not that total). Once there, the victim's next GENUINE crash waits up
 * to 60 ticks, ~60 minutes at the 60 s WATCHDOG_INTERVAL_MS. A SMALLER global number makes that crowd-out
 * CHEAPER to inflict
 * — it would have traded a machine-wide timeout for a cross-user recovery delay,
 * which is not a fix.
 *
 * So the tray loop gets per-session-id buckets, exactly as the session loop
 * already has. Win32_Process.SessionId is already on the objects from the single
 * enumeration, so grouping by it costs no extra CIM call; and a process's session
 * id comes from its token, which an unprivileged user cannot forge for somebody
 * else's session (that needs SeTcbPrivilege).
 *
 * WHAT THE BUCKET DOES AND DOES NOT CONFINE — stated exactly, because a previous
 * version of this comment claimed cross-user isolation the code does not have.
 * A bucket confines lookups charged to ONE SESSION ID to 8. It does NOT confine
 * a USER: one account may hold several concurrent interactive sessions (console
 * + RDP, a reconnected disconnected session — see OPERATIONS.md), and each of
 * them draws from the FIRST-COME global pool below. So ~6 sessions
 * (MAX_TRAY_OWNER_LOOKUPS / MAX_TRAY_OWNER_LOOKUPS_PER_SESSION = 48 / 8) held by
 * one user exhaust the tray pool for everybody, and ~10 (80 / 8) exhaust the
 * session pool; later users are then starved for that tick, in the directions
 * described above and under MAX_SHELL_OWNER_LOOKUPS. What the pair DOES buy is
 * the timeout property — the whole script's lookups are priced at 128 calls,
 * ~9.4 s of the 30 s PROBE_TIMEOUT_MS — plus a per-session ceiling low enough
 * that no single session can reach it.
 *
 * KEYING BY OWNER SID INSTEAD would give real per-user isolation and is not
 * available here: the bucket has to be chosen BEFORE the call, and the owner SID
 * is what the call returns. The session id is the only per-user proxy that is
 * free at that point.
 *
 * THE NUMBERS, from the measurement above. A real tray is 3 AICommander.exe in
 * one session (1 main + 2 children), i.e. ONE candidate after the child filter;
 * 8 per session is an 8x margin over that. The global 48 is the backstop that
 * actually delivers the timeout property — per-session buckets alone would allow
 * 8 x MAX_SESSIONS = 2048 lookups = 151 s — and 48 distinct main trays is far
 * above any real machine (measured: 1).
 *
 * EXCEEDING EITHER IS NOT HARMLESS — an earlier version of this line said it was,
 * two paragraphs after describing what it costs. A dropped tray owner reads as
 * "that user has no tray": they get a relaunch their single-instance lock
 * discards, that counts as a flap, and six such flaps put `backoffTicks` on its
 * WATCHDOG_MAX_BACKOFF_TICKS ceiling (see MAX_TRAY_OWNER_LOOKUPS above for the
 * measured escalation), so their next GENUINE crash can go unrecovered for up to
 * 60 ticks, ~60 minutes. It is merely the LESSER of the two starvations — the victim
 * is still evaluated every tick and recovers as soon as the flood stops, whereas
 * a starved SESSION lookup means a user who is never considered at all — which
 * is why the tray loop gets the SMALLER share of the global budget (see
 * MAX_SHELL_OWNER_LOOKUPS).
 */
export const MAX_TRAY_OWNER_LOOKUPS_PER_SESSION = 8;
export const MAX_TRAY_OWNER_LOOKUPS = 48;
/**
 * GetOwnerSid calls the SESSION scan will make, GLOBALLY across all sessions.
 *
 * The larger half of the budget (80 of the 128 total) on purpose, because the two
 * loops starve in opposite directions: starving the TRAY loop costs a redundant
 * relaunch, while starving SESSION discovery is the suppression itself — an
 * undiscovered session is a user never considered for recovery at all.
 *
 * WHAT IT COSTS A GENUINELY LARGE HOST, stated rather than hidden: a session is
 * discovered on its FIRST SUCCESSFUL lookup and the dedupe now runs BEFORE the
 * call (see the session loop), so a discovered session never pays a second one
 * however many explorer.exe processes it holds. 80 therefore covers 80 sessions
 * that answer first time; a session whose lookups FAIL still costs up to
 * MAX_SHELL_OWNER_LOOKUPS_PER_SESSION of the pool, so on a host where lookups
 * fail the reach is lower. Beyond that, later sessions are dropped into
 * `skippedSessions` — a real ceiling on a large host, documented in
 * OPERATIONS.md so an operator does not read it as a fault.
 *
 * IT IS STILL BETTER THAN NO BOUND, but not for the reason this comment used to
 * give. 256 sessions x 73.68 ms is 18 862 ms, which does NOT by itself exceed
 * the 30 s PROBE_TIMEOUT_MS — the old line said it did, and that arithmetic was
 * simply wrong. What it does is spend 63% of the timeout on lookups alone,
 * leaving ~11 s for the powershell.exe cold start, the two CIM enumerations
 * (~200 ms measured), the Task Scheduler COM calls and the per-session registry
 * and file work — of which only the enumerations have been measured. A budget
 * whose adequacy rests on unmeasured remainder is not one to bet machine-wide
 * recovery on, and a timed-out probe recovers NOBODY. Serving 80 sessions
 * deterministically and reporting the rest beats risking that.
 */
export const MAX_SHELL_OWNER_LOOKUPS = 80;
/**
 * GetOwnerSid calls the SESSION scan will make, PER SESSION ID.
 *
 * The session loop had the same unbounded exposure as the tray loop above and a
 * CHEAPER one: the tray loop pays for a lookup only after verifying the process
 * runs from the admin-owned install dir, while the session loop matched on the
 * image NAME alone, so any unprivileged user could copy any binary to
 * `explorer.exe`, start many copies and push the probe past PROBE_TIMEOUT_MS on
 * every tick. A timed-out probe recovers NOBODY on the machine — the same
 * machine-wide outage the caps block above exists to remove.
 *
 * THE TWO LOOPS ARE NOT SYMMETRIC, so they do not share a budget. Starving tray
 * lookups drops owners from `trayOwnerSids`, which reads as "that user has no
 * tray" and costs a discarded relaunch plus the backoff it drives (see
 * MAX_TRAY_OWNER_LOOKUPS — not free, but always retried).
 * Starving SESSION lookups makes a session undiscoverable, and an undiscovered
 * session is a user who is never considered for recovery at all — the
 * suppression itself. A single shared pool consumed first-come-first-served
 * would let a flood of tray candidates (the loop that runs first) drain it and
 * leave session discovery with nothing, which only moves the outage. That is why
 * the 128-call whole-script budget is SPLIT (80 here, 48 for the tray) rather
 * than pooled, and why the larger share is on this side.
 *
 * TWO INDEPENDENT MECHANISMS, in this order:
 *   1. the path filter below — a genuine interactive shell is the explorer.exe
 *      inside the Windows directory, which no unprivileged user can write to, so
 *      the candidates that reach a lookup are bounded by the number of GENUINE
 *      shells rather than by attacker behaviour. It rejects only a path that is
 *      present and WRONG; one that reads back empty is admitted (see the filter
 *      itself for why), which is one of the cases this budget pays for;
 *   2. this budget, as a backstop, charged PER SESSION ID. A process's session
 *      id comes from its token and an unprivileged user cannot start a process in
 *      somebody else's session, so the work provoked from ONE session is confined
 *      to that session's bucket: overrunning it drops candidates in THAT session
 *      only (counted into `skippedSessions`).
 *
 * THE BUCKET IS NOT PER USER, and this comment used to say it was — that "the
 * worst an attacker achieves is suppressing their own recovery" is false. The key
 * is the session id, and one account can hold SEVERAL concurrent interactive
 * sessions (OPERATIONS.md's "per user, not per session" note is about exactly
 * that), each with a full bucket drawing on the first-come global pool. About 10
 * such sessions (MAX_SHELL_OWNER_LOOKUPS / MAX_SHELL_OWNER_LOOKUPS_PER_SESSION =
 * 80 / 8) exhaust session discovery for the rest of that tick, and about 6
 * (48 / 8) exhaust the tray pool — so the reach of one user IS cross-user, in the
 * starvation direction, bounded by how many sessions they can hold and reset
 * every tick. Keying by owner SID would fix that and is not possible here: the
 * bucket is chosen before the call whose result is the owner SID. What the pair
 * guarantees is the timeout property, which is the machine-wide one.
 *
 * The bucket table can only grow when a lookup is actually charged, so
 * MAX_SHELL_OWNER_LOOKUPS bounds the number of buckets as well; the explicit
 * MAX_SESSIONS guard on it is kept as a belt-and-braces second bound.
 *
 * 8 rather than 1 because a session legitimately holds several genuine
 * explorer.exe processes ("launch folder windows in a separate process"), and the
 * shell need not come first in the enumeration. Since the dedupe moved ahead of
 * the call, a session that answers pays exactly ONE lookup, so this budget pays
 * only for repeated FAILURES within one session. 16, its previous value, bought
 * nothing that 8 does not and doubled the aggregate the timeout has to absorb.
 */
export const MAX_SHELL_OWNER_LOOKUPS_PER_SESSION = 8;
/** Run values scanned per user before we give up looking for the tray exe. */
const MAX_RUN_VALUES = 64;

export const PROBE_TIMEOUT_MS = 30_000;
/**
 * Output cap. The script no longer serialises anything unbounded (see
 * the tray block below — command lines never cross this boundary) and every
 * list above is bounded AS IT IS BUILT, so even a worst-case snapshot (every cap
 * reached at once) is well under a hundred kilobytes and a normal one is a few.
 * This is the backstop, and hitting it is reported as `output-too-large` rather
 * than as a bare failure.
 */
const PROBE_MAX_OUTPUT_BYTES = 256 * 1024;

function powershellPath(): string {
  const root = process.env["SystemRoot"] ?? "C:\\Windows";
  return `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
}

/** stdout of a successful run, or a CODED reason it produced nothing usable. */
type ShellResult = { ok: true; stdout: string } | { ok: false; reason: ProbeFailureReason };

/**
 * Classify a child-process failure. Every case here used to collapse into a bare
 * null, which the loop then skipped in silence — so a probe that timed out on
 * every single tick looked exactly like a machine with nothing to do.
 *
 * Pure and exported for tests (`__` prefix): there is no Windows here to produce
 * the real errors, but the shapes Node gives us are stable and testable.
 */
export function __classifyExecError(err: ExecFileException | null): ProbeFailureReason | null {
  if (err === null) return null;
  // execFile kills the child on timeout; `killed` is the only reliable marker.
  if (err.killed === true || err.signal === "SIGTERM") return "timeout";
  if (err.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") return "output-too-large";
  if (typeof err.code === "string") return "spawn-failed";
  return "exit-nonzero";
}

/** Run a PowerShell script and resolve its stdout, or a coded failure. */
function runPowerShell(script: string, timeoutMs: number): Promise<ShellResult> {
  // UTF-16LE base64 is what -EncodedCommand expects.
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  return new Promise((resolve) => {
    execFile(
      powershellPath(),
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
      { windowsHide: true, timeout: timeoutMs, maxBuffer: PROBE_MAX_OUTPUT_BYTES },
      (err, stdout) => {
        const reason = __classifyExecError(err);
        resolve(reason === null ? { ok: true, stdout } : { ok: false, reason });
      },
    );
  });
}

// --- the probe script -------------------------------------------------------
//
// ONE powershell.exe start and ONE Win32_Process enumeration answer every
// question a tick needs (there used to be three enumerations; they are filtered
// client-side now — see the cost note on WATCHDOG_INTERVAL_MS):
//
//  * trayOwnerSids — the SET of owner SIDs of the live MAIN trays, aggregated
//    HERE rather than shipped as a process list. A process counts only if it is
//    named like the tray AND runs from the admin-owned install dir AND is not
//    one of Electron's GPU/utility/renderer children (which share the image
//    name); the owner then comes from that process's own token. That set is what
//    "does this user have a tray" is answered from — never the session list
//    below, which cannot see a session without a conventional shell. Grouping in
//    the script is what makes the reply's size a function of USERS instead of
//    processes; see the caps block for why that is a security property and not
//    an optimisation.
//  * sessions — one entry per interactive desktop, discovered through the
//    explorer.exe INSIDE THE WINDOWS DIRECTORY: a session running the normal
//    shell has one, and its process token is the authoritative owner SID
//    (Win32_Process::GetOwnerSid). A user could of course run a process of their
//    own named explorer.exe, but the SID still comes from THEIR token, so the
//    worst they can invent is a session that is already theirs — and the only
//    consequence is that we may ask the Relaunch task to start the app they are
//    entitled to run anyway. The path filter is not about that: it is about
//    COST, because each candidate costs a CIM method call and the candidate
//    count would otherwise be attacker-chosen. See
//    MAX_SHELL_OWNER_LOOKUPS_PER_SESSION.
//    This list is DELIBERATELY not a liveness input: it exists to pick a session
//    to aim a relaunch at and to carry that user's consent signals. A session it
//    misses (RemoteApp, a replaced shell) is a desktop we could not have started
//    a tray in anyway.
//  * per session: autostart consent — read from the user's loaded HKU hive by
//    scanning their Run key for a value whose TARGET is the installed tray exe
//    (never by guessing the value's name; see the Run block below) — and the
//    quit marker under their profile directory.
//  * the install-in-flight signals — the Update task's state, $INSTDIR's mtime
//    and whether the tray exe is there (see installBlockReason in
//    win-watchdog.ts).
//
// NO ENVIRONMENT, ANYWHERE, AND NO ENVIRONMENT EXPANSION EITHER. Measured on a
// real box: as SYSTEM under the helper this script sees 12 environment variables
// against a desktop session's 60, and ProgramFiles is not among them, so
// `Join-Path $env:ProgramFiles` threw on line 4 and every tick died before
// producing anything. The contract held (a failed probe recovers nothing), which
// is exactly why it would have shipped silent. But `$env:` was only the visible
// form of the bug: `[Environment]::ExpandEnvironmentVariables` and the registry
// provider's automatic REG_EXPAND_SZ expansion read the SAME stripped
// environment, and both were in this script. The profile path came from
// ProfileImagePath (REG_EXPAND_SZ, typically `%SystemDrive%\Users\x`), expanded
// against an environment with no SystemDrive, giving a path that exists nowhere
// — so Test-Path on the quit marker returned $false and every user's explicit
// tray Exit was reported as "they never asked to stay down". Fail OPEN, on the
// module's headline consent property.
//
// So: profile paths come from Win32_UserProfile.LocalPath, which the CIM
// provider returns already resolved, and are then VALIDATED (rooted, no leftover
// %, directory actually exists) before they are used; registry values are read
// with expansion explicitly disabled and a value that still contains '%' is
// skipped; and the install directory is derived from the Relaunch task (below)
// rather than from %ProgramFiles%. Any future `$env:`,
// `ExpandEnvironmentVariables`, or default-expanding registry read in this script
// is the same bug waiting to happen, and win-watchdog-probe.test.ts fails on all three.
//
// WHERE THE INSTALL DIRECTORY COMES FROM. Not `%ProgramFiles%\AI Commander`: a
// hardcoded product name drifts (every peer script in this repo carries an
// explicit "never hardcode C:\Program Files" rule and derives the directory from
// its own location instead), and GetFolderPath('ProgramFiles') silently means
// `Program Files (x86)` the day this helper is built 32-bit. Either drift makes
// trayExeInstalled false on every tick, which blocks recovery forever with no
// symptom other than a log line.
//
// Instead the tray exe path is taken from the ONE thing that is authoritative
// about what a recovery would actually start: the action of the "AI Commander
// Relaunch" task, pinned at registration by desktop/build/win-update-task.ps1,
// in a task whose SDDL grants no non-admin any access. The launcher command ends
// in `Start-Process -FilePath '<path>'`, so the path is extracted from there and
// then validated (rooted, no '%', ends in the tray image name). If the task is
// missing or its action does not parse, that is a query error: the snapshot is
// rejected and nothing is recovered — which is right, because without that task
// there is no recovery to be had anyway.
//
// FAIL CLOSED, FOR REAL: $ErrorActionPreference is 'Stop' and every query is
// wrapped, so a query that FAILS is reported in `queryErrors` instead of
// returning an empty list. That distinction is the whole point — a failed
// process query that silently returns "no processes" reads as "no tray running,
// no installer running", which AUTHORIZES a relaunch. Any entry in queryErrors
// makes the parser reject the entire snapshot and the tick is skipped.
//
// TRUSTWORTHINESS OF THE SUPPRESSING SIGNALS. `installBlockReason` is applied
// MACHINE-WIDE and tray liveness suppresses ONE user's recovery, so an
// unprivileged user must not be able to fabricate either and thereby stop
// somebody else being recovered. Nothing this script reports is machine-wide
// except the install signals — the tray-overflow flag that used to be was
// removed with the per-process list it described. Only signals rooted in
// admin-owned state qualify:
//   * the "AI Commander Update" task's own RUNNING state — unforgeable, and it
//     spans the entire silent download+install;
//   * a process whose image path is inside the admin-owned install dir — this is
//     what makes `trayOwnerSids` trustworthy: liveness used to be decided on
//     image NAME alone, so any process a user could name AICommander.exe read as
//     a healthy tray and suppressed that session's recovery. The owner comes
//     from the process's own token, so one user cannot claim a tray on another's
//     behalf;
//   * the install dir's mtime and the presence of the tray exe — both in
//     %ProgramFiles%, which no non-admin can write.
//
// WHY THERE IS NO "AN INSTALLER PROCESS IS RUNNING" SIGNAL ANY MORE. There was
// one: a list of live processes named `Uninstall *` whose image path was inside
// the install dir, and it blocked recovery machine-wide while non-empty. Its
// premise was that running from an admin-owned directory makes the process
// trustworthy. IT DOES NOT. Admin ownership protects the BINARY from
// modification, not the right to RUN it: Users have read+execute on
// %ProgramFiles%\AI Commander, so any local user can start the uninstaller
// unelevated (`__COMPAT_LAYER=RunAsInvoker`) and simply leave it sitting there.
// The block has no time limit, so that unprivileged act suppressed crash
// recovery for EVERY user on the machine, indefinitely — the same class of bug
// as the name-only match it replaced (a downloaded `AICommander-Setup-*.exe`,
// NSIS's `~nsu*.tmp\Un_*.exe` copy), just one directory further in.
//
// Bounding it in time would only shorten the attack (restart the process on a
// timer); requiring an elevated OWNER would restore the property but adds a
// second Windows-only mechanism nothing here can verify — for coverage that is
// now redundant. VERIFIED against the templates we actually build with,
// app-builder-lib@26.15.3 (`templates/nsis/uninstaller.nsh`,
// `include/allowOnlyOneInstallerInstance.nsh`) and this app's
// `desktop/build/installer.nsh` + `electron-builder.yml` (`oneClick: false`):
//
//   * SILENT uninstall — the `/S` run an upgrade performs — kills the app in
//     `un.onInit` (`${If} ${Silent}` → `un.checkAppRunning` → our
//     `customCheckAppRunning`, a `taskkill /F /IM AICommander.exe /T`), and the
//     whole upgrade is spanned by the Update task's RUNNING state anyway.
//   * MANUAL uninstall — the case the Update task does NOT span — kills the app
//     at the TOP of `Section "un.Uninstall"`, after the user confirms and before
//     any file operation. `customUnInstall` then stops and DELETES the helper's
//     own scheduled task and kills the helper exe, so the watchdog is not even
//     running for the rest of it; it also deletes the "AI Commander Relaunch"
//     task, which makes the install-dir derivation above fail closed
//     (`queryErrors += 'relaunch-task'` → snapshot rejected → nothing started).
//     Then `RMDir /r $INSTDIR` moves the directory's mtime, and when it finishes
//     the tray exe is gone (`trayExeInstalled` false). Every step of that is
//     inside the two-tick debounce, which cannot fire earlier than 60 s after
//     the tray dies.
//   * A HAND-DRIVEN install is covered by `customCheckAppRunning` (immediately
//     before the file operations, not before the wizard), plus $INSTDIR's mtime
//     and the two-tick debounce. There is no in-flight marker: an earlier design
//     wrote one into $INSTDIR and it has been removed on the desktop side, so
//     nothing here may read it.
//   * An install driven by something that is NOT our NSIS installer (a repair
//     tool, an MSI wrapper, someone unzipping over $INSTDIR) is caught only once
//     the tray exe disappears or $INSTDIR's mtime moves — unchanged, the deleted
//     signal never covered that either.
//
// So the signal was deleted outright rather than left in weakened form. A signal
// whose stated security property does not hold is worse than no signal: the
// reasoning around it — including win-watchdog.ts's SECURITY header — leans on
// that property. Do not reintroduce it without an owner check that proves
// elevation, and do not reintroduce a name-only match at all.
function probeScript(): string {
  return [
    // 'Stop', so a failing cmdlet raises instead of quietly yielding nothing.
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "$queryErrors = @()",
    // Every string comparison in this script passes this explicitly — see the
    // ORDINAL note in the install-directory block below.
    "$ordinal = [System.StringComparison]::Ordinal",
    "",
    // --- where the tray lives: derived, never guessed (see the header) -------
    "$svc = $null",
    "try {",
    "  $svc = New-Object -ComObject 'Schedule.Service'",
    "  $svc.Connect()",
    "} catch { $queryErrors += 'scheduler' }",
    "",
    "$trayExe = $null",
    "$installDir = $null",
    "if ($svc) {",
    "  try {",
    `    $relaunchTask = $svc.GetFolder('\\').GetTask('${RELAUNCH_TASK_NAME}')`,
    "    $relaunchArgs = [string]$relaunchTask.Definition.Actions.Item(1).Arguments",
    // The launcher command ends in: Start-Process -FilePath '<path>' — a
    // single-quoted PowerShell literal with any apostrophes doubled, built by
    // win-update-task.ps1. Take the LAST such marker and the LAST quote, then
    // undouble. Anything unexpected raises: a wrong install dir is worse than no
    // install dir, because it reads as "the app is not installed" forever.
    //
    // ORDINAL, EXPLICITLY, HERE AND EVERYWHERE BELOW. String.IndexOf(String),
    // LastIndexOf(String), StartsWith(String) and EndsWith(String) all bind to
    // the CULTURE-SENSITIVE overload in .NET / PowerShell 5.1, and the search
    // strings here are made of punctuation ('-', '"', '\'', '.') — exactly the
    // characters a collation may give reduced weight, which shifts the offsets.
    // The extraction would then fail IsPathRooted/EndsWith and report
    // queryErrors += 'relaunch-task' on every tick: the same silent-death shape
    // as the stripped-environment bugs above, on a machine nothing here can
    // reproduce. `Contains(String)` is ordinal already; every other comparison
    // says so out loud, and win-watchdog-probe.test.ts fails if one stops.
    // ($ordinal is defined at the top of the script, so every block below has it
    // whether or not this one ran.)
    "    $flag = \"-FilePath '\"",
    "    $at = $relaunchArgs.LastIndexOf($flag, $ordinal)",
    "    if ($at -lt 0) { throw 'no -FilePath in the relaunch action' }",
    "    $rest = $relaunchArgs.Substring($at + $flag.Length)",
    "    $end = $rest.LastIndexOf(\"'\", $ordinal)",
    "    if ($end -lt 1) { throw 'unterminated tray exe literal' }",
    "    $candidate = $rest.Substring(0, $end).Replace(\"''\", \"'\")",
    // No environment, ever: an unexpanded variable must fail, not be resolved.
    "    if ($candidate.Contains('%')) { throw 'unexpanded variable in tray exe path' }",
    "    if (-not [System.IO.Path]::IsPathRooted($candidate)) { throw 'tray exe path not rooted' }",
    `    if (-not $candidate.ToLowerInvariant().EndsWith('\\${TRAY_IMAGE_NAME.toLowerCase()}', $ordinal)) { throw 'unexpected tray exe name' }`,
    "    $trayExe = $candidate",
    "    $installDir = [System.IO.Path]::GetDirectoryName($trayExe)",
    "  } catch { $queryErrors += 'relaunch-task' }",
    "}",
    "",
    // --- one process enumeration for all three consumers --------------------
    "$allProcs = @()",
    "try {",
    "  $allProcs = @(Get-CimInstance Win32_Process)",
    "} catch { $queryErrors += 'processes' }",
    "",
    "$installDirPrefix = $null",
    "if ($installDir) { $installDirPrefix = ($installDir.TrimEnd('\\') + '\\').ToLowerInvariant() }",
    "",
    // A tray process is one running FROM the install dir — not merely one named
    // like the tray. Anything else is counted and ignored: it is either a stale
    // install or somebody trying to fake a living tray to suppress recovery.
    // An unreadable ExecutablePath cannot be verified, so it does not count
    // either (that direction at worst starts a tray the single-instance lock
    // then discards; the other direction silently disables recovery).
    //
    // PASS 1 builds the verified set IN MEMORY. Nothing here is serialised: it
    // is the input to the aggregation below, whose output is one entry per USER.
    // An ArrayList rather than `+=`, because `+=` on a PowerShell array copies
    // the whole array every time and this loop's length is attacker-influenced.
    "$trayProcs = [System.Collections.ArrayList]::new()",
    "$unverifiedTrayProcesses = 0",
    "if ($installDirPrefix) {",
    "  foreach ($p in $allProcs) {",
    `    if ($p.Name -ne '${TRAY_IMAGE_NAME}') { continue }`,
    "    $imagePath = [string]$p.ExecutablePath",
    "    if (-not $imagePath -or -not $imagePath.ToLowerInvariant().StartsWith($installDirPrefix, $ordinal)) {",
    "      $unverifiedTrayProcesses++",
    "      continue",
    "    }",
    // Only the ONE bit of the command line the decision needs is kept — never
    // the text itself, which is unbounded user-controlled data.
    "    $cmd = [string]$p.CommandLine",
    "    $hasType = [bool]($cmd.Contains('--type='))",
    // SessionId comes off the object this enumeration already returned, so the
    // per-session bucket below costs no extra CIM call. It comes from the
    // process's token: a user cannot start a process in somebody else's session.
    "    $null = $trayProcs.Add([pscustomobject]@{",
    "      proc = $p",
    "      processId = [int]$p.ProcessId",
    "      parentProcessId = [int]$p.ParentProcessId",
    "      sessionId = [int]$p.SessionId",
    "      hasType = $hasType",
    "    })",
    "  }",
    "}",
    "",
    // PASS 2 aggregates: MAIN trays only, grouped by owner SID.
    //
    // MAIN vs CHILD, the same two OR'd signals the decision half used to apply
    // (they moved here with the grouping, they were not dropped): Electron's
    // GPU/utility/renderer children share the AICommander.exe image name, so "an
    // AICommander.exe exists" proves nothing. A child is anything carrying
    // `--type=` OR anything parented by another verified tray process. Either
    // one alone disqualifies it, because mistaking a lingering CHILD for the
    // main process suppresses recovery for as long as it lives, while mistaking
    // the main process for a child at worst starts a second tray that the app's
    // own single-instance lock discards at once.
    //
    // WHOSE tray this is comes from the process's OWN token. It used to be
    // inferred from the session the process ran in, matched against the sessions
    // discovered below through explorer.exe; a RemoteApp or shell-replaced
    // session has no explorer.exe, so a perfectly healthy tray there read as
    // "this user has no tray" and the watchdog relaunched into another session
    // forever.
    //
    // GetOwnerSid is an Invoke-CimMethod PER PROCESS, so it is asked only for
    // the processes that survive the child test — children are 3-5 of the 4-6
    // processes a tray consists of. A failed lookup yields no SID at all, which
    // proves liveness for nobody: the bounded direction (a redundant relaunch
    // dies on the single-instance lock; a tray attributed to the wrong user
    // would suppress a real recovery).
    "$trayPids = @{}",
    "foreach ($t in $trayProcs) { $trayPids[$t.processId] = $true }",
    "$trayOwnerSids = @()",
    "$trayOwnerSeen = @{}",
    "$ownerLookups = 0",
    "$trayLookups = @{}",
    "foreach ($t in $trayProcs) {",
    "  if ($t.hasType) { continue }",
    "  if ($t.parentProcessId -ne $t.processId -and $trayPids.ContainsKey($t.parentProcessId)) { continue }",
    // Bounded WORK, not just a bounded reply: one CIM method call per candidate,
    // and the candidate count is attacker-influenced. Two bounds, in this order:
    // the GLOBAL backstop that prices the whole loop against PROBE_TIMEOUT_MS,
    // then a PER-SESSION-ID bucket so a flood in one session can neither do the
    // machine's worth of work nor crowd another user's live tray out of the set.
    // Charging the bucket only when a lookup is actually made keeps the table's
    // size bounded by the global budget as well. See MAX_TRAY_OWNER_LOOKUPS.
    `  if ($ownerLookups -ge ${MAX_TRAY_OWNER_LOOKUPS}) { break }`,
    "  $trayKey = $t.sessionId.ToString()",
    "  $trayLookupsUsed = [int]$trayLookups[$trayKey]",
    `  if ($trayLookupsUsed -ge ${MAX_TRAY_OWNER_LOOKUPS_PER_SESSION}) { continue }`,
    "  $trayLookups[$trayKey] = $trayLookupsUsed + 1",
    "  $ownerLookups++",
    "  $ownerSid = ''",
    "  try { $ownerSid = [string](Invoke-CimMethod -InputObject $t.proc -MethodName GetOwnerSid).Sid } catch { $ownerSid = '' }",
    "  if (-not $ownerSid) { continue }",
    "  $ownerKey = $ownerSid.ToLowerInvariant()",
    "  if ($trayOwnerSeen.ContainsKey($ownerKey)) { continue }",
    // Bounded AS THE SET IS BUILT. Unreachable by starting processes — a further
    // entry needs a further ACCOUNT — see the caps block for what happens if it
    // is ever reached anyway.
    `  if ($trayOwnerSids.Count -ge ${MAX_TRAY_OWNERS}) { break }`,
    "  $trayOwnerSeen[$ownerKey] = $true",
    "  $trayOwnerSids += $ownerSid",
    "}",
    "",
    // --- profile directories, resolved by the CIM provider ------------------
    // Win32_UserProfile.LocalPath is already resolved; ProfileImagePath (which
    // this used to read) is REG_EXPAND_SZ and would be expanded against the
    // stripped SYSTEM environment. See the header.
    "$profilePaths = @{}",
    "try {",
    "  foreach ($u in @(Get-CimInstance Win32_UserProfile)) {",
    "    $psid = [string]$u.SID",
    "    if ($psid) { $profilePaths[$psid] = [string]$u.LocalPath }",
    "  }",
    "} catch { $queryErrors += 'user-profiles' }",
    "",
    // WHERE THE REAL SHELL LIVES. An interactive desktop's explorer.exe is the
    // one inside the Windows directory, which no unprivileged user can write to;
    // a copy of any binary under that name anywhere else is not a shell and must
    // not buy a CIM method call (see MAX_SHELL_OWNER_LOOKUPS_PER_SESSION).
    //
    // Through the API, NOT the environment: %WINDIR% would be read from the
    // stripped SYSTEM environment, which is the bug the header block above is
    // about. GetFolderPath is not environment-backed and is not subject to the
    // WOW64 redirection that makes GetFolderPath('ProgramFiles') unusable here.
    //
    // FAIL OPEN, DELIBERATELY: if the API cannot answer, the filter is not
    // applied at all and every explorer.exe stays a candidate. Refusing them
    // instead would leave the machine with no sessions and therefore no
    // recovery for anybody — exactly the suppression this filter exists to
    // prevent. The per-session budget still bounds the work in that case.
    "$shellExe = $null",
    "try {",
    "  $windowsDir = [string][System.Environment]::GetFolderPath('Windows')",
    "  if ($windowsDir) { $shellExe = (Join-Path $windowsDir 'explorer.exe').ToLowerInvariant() }",
    "} catch { $shellExe = $null }",
    "",
    // A per-session failure drops only THAT session (it can then never be
    // recovered this tick — the fail-closed direction) instead of rejecting the
    // whole machine's snapshot, which one unreadable hive would otherwise do
    // forever. Failing to enumerate sessions at all IS a snapshot-level error.
    "$sessions = @()",
    // COUNTED BY SESSION ID, NOT BY PROCESS. Each drop site used to do a bare
    // `$skippedSessions++`, which fires per candidate PROCESS — and an
    // over-budget session never reaches `$seenSessions`, so every one of its
    // explorer.exe processes incremented it. A session legitimately holds
    // several ("launch folder windows in a separate process"), so the number an
    // operator read was the session count times an unknown multiplier, while
    // its NAME (`sessions-skipped`) and OPERATIONS.md both promise sessions. A
    // SET of session ids makes the reported number mean what it is called; the
    // key is removed again if a later candidate in the same session succeeds,
    // so what is finally reported is "sessions this tick did not deliver".
    //
    // Bounded by LOGONS, not by processes: the key is Win32_Process.SessionId,
    // which comes from the process's token, so a further entry needs a further
    // interactive session rather than a further process — the same argument
    // `$trayOwnerSids` is bounded by, and the reason this table carries no
    // explicit cap (`$seenSessions` and `$profilePaths` carry none either).
    "$skippedSessionIds = @{}",
    "$unverifiedSessionShells = 0",
    "$seenSessions = @{}",
    "$shellLookups = @{}",
    "$shellOwnerLookups = 0",
    "try {",
    // WHY THE CANDIDATES ARE COLLECTED AND ROTATED INSTEAD OF WALKED IN PLACE.
    //
    // The budgets below are per-tick and reset every tick, and this loop used to
    // walk `$allProcs` in whatever order CIM returned — which is stable across
    // ticks in practice. On a host with more than MAX_SHELL_OWNER_LOOKUPS logons
    // that made the starvation PERMANENT rather than temporary: the same first
    // ~80 sessions were served on every tick and the tail was never discovered
    // at all, i.e. never recovered, ever. OPERATIONS.md promised the opposite
    // ("slower and partial"); this is what makes that true.
    //
    // A uniformly random start offset, applied to the candidate list and then
    // wrapped, is enough: every session is reachable from some offset, so
    // permanent starvation becomes a bounded EXPECTED delay. It costs no extra
    // CIM call — the candidates are already-materialised objects from the one
    // `Get-CimInstance Win32_Process` above, so the list holds references to
    // things already in memory — and it needs no cross-tick state, which the
    // probe (a fresh powershell.exe per tick) has nowhere to keep.
    //
    // WHAT AN UNREACHED TICK COSTS a user is deliberately NOT narrated here:
    // that is evaluateTick's behaviour, this prose has been wrong about it
    // repeatedly, and it is pinned by the pair of tests "keeps the backoff for a
    // user missing from an INCOMPLETE tick" and "keeps a PART-WAY miss debounce
    // for a user missing from an INCOMPLETE tick" (win-watchdog.test.ts), which
    // compare the user's WHOLE cross-tick entry across such ticks — the second
    // with a non-zero `misses`, so the debounce is covered and not just the
    // backoff the first one carries. Below ~80 logons
    // nothing changes: every session is served on every tick whatever the
    // offset.
    //
    // FALLS BACK, NEVER FAILS: if the rotation itself throws, the unrotated
    // order is used. Rotation is an availability improvement, so its failure
    // must not become a snapshot-level 'sessions' error, which recovers nobody.
    "  $shellCandidates = [System.Collections.ArrayList]::new()",
    "  foreach ($e in $allProcs) {",
    // EVERY property read in this loop is guarded, this one included. The loop
    // body sits inside the outer try, so under $ErrorActionPreference='Stop' an
    // unguarded read here would reject the WHOLE MACHINE's snapshot ('sessions')
    // and recover nobody that tick — while the ExecutablePath read two lines
    // down, in the same iteration and against the same failure mode, is guarded.
    // Unreachable in practice (Name is always present on Win32_Process, and the
    // object is already materialised by the single enumeration above, so the
    // read does no IO), but the asymmetry is not defensible on its own terms.
    //
    // Fail-OPEN, the same direction as the path read below: a name that cannot
    // be read KEEPS the candidate, never drops it, because dropping is the
    // silent suppression this module exists to avoid. A survivor still has to
    // pass the path filter here and again in the walk, and still costs at most
    // the per-session budget.
    "    $procName = 'explorer.exe'",
    "    try { $procName = [string]$e.Name } catch { $procName = 'explorer.exe' }",
    "    if ($procName -ne 'explorer.exe') { continue }",
    // THE PATH FILTER RUNS HERE, WHERE THE ROTATION DOMAIN IS BUILT, not only in
    // the walk below. Filtering on the NAME alone leaves the candidate list —
    // and therefore the offset drawn over it — inflatable by anyone who can
    // start processes called explorer.exe: a large contiguous block of fakes
    // biases the draw toward one real starting candidate and re-creates the
    // near-fixed served set rotation exists to break. The list is what the
    // offset is drawn over, so it is the list that has to be verified.
    //
    // A read that THROWS keeps the candidate: the reject is fail-open in exactly
    // the direction the walk's copy of this filter is (see there), and a
    // candidate that survives on a throw is filtered — and counted — there
    // instead, so nothing is counted twice. $shellExe = $null keeps everything,
    // for the reason the lookup above states.
    "    $verifiedShell = $true",
    "    if ($shellExe) {",
    "      try {",
    "        $candidatePath = [string]$e.ExecutablePath",
    "        if ($candidatePath -and" +
      " -not $candidatePath.ToLowerInvariant().Equals($shellExe, $ordinal)) { $verifiedShell = $false }",
    "      } catch { $verifiedShell = $true }",
    "    }",
    "    if (-not $verifiedShell) { $unverifiedSessionShells++; continue }",
    "    $null = $shellCandidates.Add($e)",
    "  }",
    "  $shellOrder = @($shellCandidates)",
    // MEASURED ON WINDOWS — aic-pc, PowerShell 5.1, as LocalSystem, 2026-08-09 —
    // by running these exact expressions, because nothing off Windows executes
    // them:
    //   - `Get-Random -Minimum 0 -Maximum 7`, 20 000 draws: observed range 0..6.
    //     -Maximum is exclusive, so the offset can never index past the end.
    //   - the two-slice concatenation below, for every offset 0..6: always
    //     exactly 7 elements, nothing dropped and nothing duplicated.
    //   - control, with the `$rotateAt -gt 0` guard removed and rotateAt = 0:
    //     `$src[0..(-1)]` yields `1,7` — element 0 plus the LAST element,
    //     corrupting the list. The guard is load-bearing, by execution.
    "  try {",
    // `-ge 2`, not `.Count -gt 1`: the latter is the shape a test forbids
    // outright, because it is how a cap evaluated against a FINISHED list reads.
    // This is not a cap — it is "there is something to rotate".
    "    if ($shellOrder.Count -ge 2) {",
    "      $rotateAt = Get-Random -Minimum 0 -Maximum $shellOrder.Count",
    "      if ($rotateAt -gt 0) {",
    "        $shellOrder = @($shellOrder[$rotateAt..($shellOrder.Count - 1)]) +" +
      " @($shellOrder[0..($rotateAt - 1)])",
    "      }",
    "    }",
    "  } catch { $shellOrder = @($shellCandidates) }",
    "  foreach ($e in $shellOrder) {",
    // The session id is read FIRST, so that every drop below — including the
    // per-candidate catch — can name the session it dropped. Reading a property
    // off an already-materialised CIM object does no IO, so the $null case is a
    // formality: a candidate whose session we cannot even name is dropped
    // uncounted rather than charged to somebody else's id.
    "    $lookupKey = $null",
    "    try {",
    "      $sessionId = [int]$e.SessionId",
    "      $lookupKey = $sessionId.ToString()",
    // The filter again, for the candidates the collection loop admitted on a
    // THROWN path read — INSIDE the per-session try, so a read that throws again
    // under $ErrorActionPreference='Stop' drops this one candidate (named, and
    // counted as a skipped session) instead of escaping to the outer catch and
    // rejecting the whole machine's snapshot. A candidate the collection loop
    // already rejected never reaches here, so the two sites cannot both charge
    // $unverifiedSessionShells for one process.
    // Counted, never silent: an empty session list is
    // otherwise indistinguishable from an idle machine, which is the failure
    // mode this whole module is built to keep visible.
    //
    // AN UNREADABLE PATH IS NOT A LOOKALIKE. A path that is present and is not
    // the Windows shell is a copy somebody made, and it is rejected; a path that
    // reads back EMPTY says nothing either way, and it stays a candidate. That
    // is the same fail-OPEN the $shellExe lookup itself takes, for the same
    // reason: the filter exists to bound COST, not to authorize anything, and an
    // admitted candidate still costs at most the per-session budget below. The
    // closed direction would be the dangerous one — if ExecutablePath ever read
    // back empty for the genuine shell (it should not: SYSTEM can query any user
    // process), every session on the box would go undiscovered and nobody would
    // ever be recovered. Nothing is gained by admitting a fake: its SessionId
    // and owner SID both come from the attacker's own token, so the most they
    // can invent is a session that is already theirs.
    "      if ($shellExe) {",
    "        $shellPath = [string]$e.ExecutablePath",
    "        if ($shellPath -and -not $shellPath.ToLowerInvariant().Equals($shellExe, $ordinal)) {",
    "          $unverifiedSessionShells++",
    "          continue",
    "        }",
    "      }",
    // THE DEDUPE COMES BEFORE THE LOOKUP, not after it. It used to key on
    // sessionId|sid, which can only be computed once the CIM call has been paid
    // for — so every further genuine explorer.exe in an ALREADY-DISCOVERED
    // session spent one of MAX_SHELL_OWNER_LOOKUPS to produce a duplicate that
    // was then dropped. That made "80 covers 80 logons" untrue by whatever the
    // shells-per-session multiplier happens to be, and it is not always 1:
    // "launch folder windows in a separate process" gives a session one
    // explorer.exe per open window.
    //
    // Keying on the session id ALONE is what makes the skip legitimate, and it
    // is a deliberate narrowing, not an equivalence: a second lookup in the same
    // session can only ever add a SECOND ACCOUNT's shell in one desktop (a
    // secondary logon — `runas` — which needs that account's credentials, so no
    // unprivileged attacker can provoke it), and such a user is no longer
    // discovered through that session. They are still discovered through any
    // session of their own. This is the suppressing direction for that one case,
    // taken because a relaunch is aimed at a SESSION id and the tick's budget is
    // the resource being defended.
    "      if ($seenSessions.ContainsKey($lookupKey)) { continue }",
    // The backstop, charged per session id so one user's flood cannot consume
    // another session's budget, and again GLOBALLY so the loop is priced against
    // PROBE_TIMEOUT_MS (see MAX_SHELL_OWNER_LOOKUPS). All over-budget cases are
    // fail-closed drops: that session may go undiscovered this tick, and the
    // count is reported.
    `      if ($shellOwnerLookups -ge ${MAX_SHELL_OWNER_LOOKUPS}) { $skippedSessionIds[$lookupKey] = $true; continue }`,
    `      if (-not $shellLookups.ContainsKey($lookupKey) -and $shellLookups.Count -ge ${MAX_SESSIONS}) { $skippedSessionIds[$lookupKey] = $true; continue }`,
    "      $shellLookupsUsed = [int]$shellLookups[$lookupKey]",
    `      if ($shellLookupsUsed -ge ${MAX_SHELL_OWNER_LOOKUPS_PER_SESSION}) { $skippedSessionIds[$lookupKey] = $true; continue }`,
    "      $shellLookups[$lookupKey] = $shellLookupsUsed + 1",
    "      $shellOwnerLookups++",
    "      $sid = [string](Invoke-CimMethod -InputObject $e -MethodName GetOwnerSid).Sid",
    "      if (-not $sid) { $skippedSessionIds[$lookupKey] = $true; continue }",
    // Marked ANSWERED here, before the validations below: a session dropped for
    // an unresolvable profile is dropped for this whole tick, not retried once
    // per shell process. (The table grows only on a successful lookup, so
    // MAX_SHELL_OWNER_LOOKUPS bounds its size too.)
    "      $seenSessions[$lookupKey] = $true",
    // Over-cap sessions join the fail-closed drops (they get no recovery this
    // tick and the count is logged) instead of rejecting everybody's snapshot.
    `      if ($sessions.Count -ge ${MAX_SESSIONS}) { $skippedSessionIds[$lookupKey] = $true; continue }`,
    // The quit marker is the user's explicit "stay down", so a profile path we
    // cannot resolve must never read as "no marker". Three validations, all of
    // which drop the session (suppressing) rather than guessing: known to CIM,
    // fully resolved (no leftover %), and actually present on disk.
    "      $localPath = [string]$profilePaths[$sid]",
    "      if (-not $localPath -or $localPath.Contains('%')) { $skippedSessionIds[$lookupKey] = $true; continue }",
    "      if (-not (Test-Path -LiteralPath $localPath -PathType Container)) { $skippedSessionIds[$lookupKey] = $true; continue }",
    // Autostart is detected by TARGET, not by value NAME. Electron names the Run
    // value after the app user model id (`electron.app.<name>`), and which name
    // that is differs between the dev package and the packaged app — guessing it
    // wrong makes every session read "opted out" and silently switches the whole
    // watchdog off, which is precisely what happened. So: scan every value in the
    // key and accept the session as autostart-enabled when any value's DATA
    // points at the installed, admin-owned tray exe. That survives a productName
    // change, an appUserModelId change and a value rename; a user who DELETES the
    // entry is still respected, because then nothing points at the exe.
    //
    // DoNotExpandEnvironmentNames: the registry provider would otherwise expand a
    // REG_EXPAND_SZ value against this process's stripped environment (the same
    // bug as the profile path above). Measured data is a literal REG_SZ path, so
    // a value that still contains '%' is one we cannot resolve without an
    // environment — skip it, which reads as "not autostarted" and suppresses.
    //
    // A MISSING Run key is the normal opted-out case, not a failure; only a key
    // we cannot read is, and that throws out to the per-session catch.
    //
    // The scan is BOUNDED: a user can create arbitrarily many values under their
    // own Run key, and this loop runs per session on every tick. Stopping early
    // can only fail to FIND the tray exe, which reads as "autostart off" and
    // suppresses that one user's recovery — their own key, their own outcome.
    "      $autoStart = $false",
    "      $runValuesScanned = 0",
    "      $runKeyPath = 'Registry::HKEY_USERS\\' + $sid + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    "      if ($trayExe -and (Test-Path -LiteralPath $runKeyPath)) {",
    "        $runKey = Get-Item -LiteralPath $runKeyPath",
    "        $trayExeTarget = $trayExe.ToLowerInvariant()",
    "        $noExpand = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames",
    "        foreach ($valueName in @($runKey.GetValueNames())) {",
    `          if ($runValuesScanned -ge ${MAX_RUN_VALUES}) { break }`,
    "          $runValuesScanned++",
    "          $data = [string]$runKey.GetValue($valueName, '', $noExpand)",
    "          if (-not $data) { continue }",
    "          $data = $data.Trim()",
    "          if ($data.Contains('%')) { continue }",
    // Same extraction as desktop/src/autolaunch.ts launchCommandProgram: the
    // program is the first QUOTED token, or (Electron writes the bare path with
    // no args) the string up to and including the first '.exe'.
    "          if ($data.StartsWith('\"', $ordinal)) {",
    "            $closing = $data.IndexOf('\"', 1, $ordinal)",
    "            if ($closing -lt 1) { continue }",
    "            $program = $data.Substring(1, $closing - 1)",
    "          } else {",
    "            $exeAt = $data.ToLowerInvariant().IndexOf('.exe', $ordinal)",
    "            if ($exeAt -ge 0) { $program = $data.Substring(0, $exeAt + 4) } else { $program = $data }",
    "          }",
    "          if ($program.ToLowerInvariant() -eq $trayExeTarget) { $autoStart = $true; break }",
    "        }",
    "      }",
    `      $markerPath = Join-Path $localPath 'AppData\\Roaming\\${QUIT_MARKER_REL}'`,
    "      $quitMarker = [bool](Test-Path -LiteralPath $markerPath)",
    "      $sessions += [ordered]@{",
    "        sessionId = $sessionId",
    "        userSid = $sid",
    "        autoStartEnabled = $autoStart",
    "        quitMarkerPresent = $quitMarker",
    "      }",
    // Delivered after all: an earlier candidate in this session may have been
    // recorded as skipped (a lookup that returned no SID, say) before a later
    // one succeeded, and a session that IS in the reply was not skipped.
    "      $skippedSessionIds.Remove($lookupKey)",
    "    } catch { if ($lookupKey) { $skippedSessionIds[$lookupKey] = $true } }",
    "  }",
    "} catch { $queryErrors += 'sessions' }",
    "",
    // Fail-closed default: if we cannot answer "is an install running?", the
    // answer must read as YES until proven otherwise. The ONE exception is a
    // definitively ABSENT task (HRESULT 0x80070002 / ERROR_FILE_NOT_FOUND, signed
    // -2147024894) — the same fail-closed re-check idiom win-update-task.ps1
    // uses. Any other failure is a query error and rejects the snapshot.
    "$updateTaskRunning = $true",
    "if ($svc) {",
    "  try {",
    `    $updateTask = $svc.GetFolder('\\').GetTask('${UPDATE_TASK_NAME}')`,
    // 4 = TASK_STATE_RUNNING. win-updater.ps1 runs AS this task and -Waits on the
    // silent installer, so RUNNING spans the whole download + install.
    "    $updateTaskRunning = ([int]$updateTask.State -eq 4)",
    "  } catch {",
    "    $hr = $_.Exception.HResult",
    "    $innerHr = $null",
    "    if ($_.Exception.InnerException) { $innerHr = $_.Exception.InnerException.HResult }",
    "    if ($hr -eq -2147024894 -or $innerHr -eq -2147024894) { $updateTaskRunning = $false }",
    "    else { $queryErrors += 'update-task' }",
    "  }",
    "}",
    "",
    // NO "AN INSTALLER PROCESS IS RUNNING" SIGNAL — deliberately, see the header.
    //
    // An ABSENT install dir is an answer (null age + no exe → 'tray-exe-missing'
    // blocks anyway); an unreadable one is a query error.
    "$msSinceInstallDirChange = $null",
    "$trayExeInstalled = $false",
    "if ($installDir) {",
    "  try {",
    "    if (Test-Path -LiteralPath $installDir) {",
    "      $installDirItem = Get-Item -LiteralPath $installDir -Force",
    "      $msSinceInstallDirChange = [int64]((Get-Date) - $installDirItem.LastWriteTime).TotalMilliseconds",
    "    }",
    "    $trayExeInstalled = [bool](Test-Path -LiteralPath $trayExe)",
    "  } catch { $queryErrors += 'install-dir' }",
    "}",
    "",
    // The out-of-process integrity check: presence and counts against the
    // manifest shipped inside $INSTDIR. It lives in win-watchdog-install.ts with
    // the predicates that consume it, and it is the ONE query here that reports
    // a failure as "nothing to say" instead of as a query error — see the note
    // on manifestProbeLines for why a diagnostic field may not reject a snapshot.
    ...manifestProbeLines(),
    "",
    "$result = [ordered]@{",
    "  trayOwnerSids = @($trayOwnerSids)",
    "  unverifiedTrayProcesses = $unverifiedTrayProcesses",
    "  sessions = @($sessions)",
    // Distinct SESSION IDS, not drop events — see $skippedSessionIds. The wire
    // name is unchanged, so nothing downstream of the parser moves.
    "  skippedSessions = $skippedSessionIds.Count",
    "  unverifiedSessionShells = $unverifiedSessionShells",
    "  updateTaskRunning = $updateTaskRunning",
    "  msSinceInstallDirChange = $msSinceInstallDirChange",
    "  trayExeInstalled = $trayExeInstalled",
    "  installManifest = $installManifest",
    "  queryErrors = @($queryErrors)",
    "}",
    "ConvertTo-Json -InputObject $result -Depth 4 -Compress",
  ].join("\n");
}

// --- defensive parsing ------------------------------------------------------
//
// The probe output is machine-generated, but PowerShell's JSON has enough
// well-known quirks (a one-element array collapsing to a bare object, $null
// fields, numbers arriving as strings) that every field is re-validated here.
// Anything that doesn't parse makes the WHOLE snapshot fail → the tick is
// skipped. Never recover on a partial picture.
//
// A MISSING field is treated exactly like a failed query, not as a default: the
// script always emits every key, so an absent one means the script did not get
// that far, and "no data" must never read as "nothing is running".
//
// The rule applies ONE LEVEL DOWN too, and there the fields are NOT symmetric —
// each one has to be judged by which way its default leans:
//   * autoStartEnabled → false means "opted out" → no recovery. Suppressing, so
//     defaulting it would be SAFE — but it still rejects the session rather than
//     defaulting, because a session we cannot read cleanly is not one to reason
//     about, and one rule is easier to keep true than two.
//   * quitMarkerPresent → false means "the user did NOT ask to stay down" →
//     RELAUNCH. Permissive, so a missing or mistyped value must NOT default; it
//     rejects the session, or a garbled field would silently override an
//     explicit user Exit.
//   * an entry of trayOwnerSids → "this user has a tray" → suppresses recovery.
//     Suppressing, but it still has to be a real, non-empty string: a value we
//     cannot read cleanly rejects the snapshot rather than being dropped, since
//     dropping one reads as "that user has no tray" and starts an app.
//   * a null/absent list → "nothing running" → permissive, so it rejects.
//   * an unreadable install-dir age → "nothing in flight" → permissive, so it
//     resolves to 0 ("just changed", blocks) instead of null ("unknown").
// Only an EXPLICIT null age is a real "unknown", and that happens solely when
// the install dir is absent — in which case trayExeInstalled is false and
// installBlockReason blocks on that instead.

/** Query names the script emits. Anything else is reported as `query-failed`. */
const QUERY_NAMES: readonly ProbeQueryName[] = [
  "scheduler",
  "relaunch-task",
  "update-task",
  "processes",
  "user-profiles",
  "sessions",
  "install-dir",
];

/** A JSON list, tolerating PowerShell collapsing one element to a bare object. */
function asList(v: unknown): unknown[] | null {
  if (Array.isArray(v)) return v;
  // null/undefined is NOT an empty list: "no data" must never read as "nothing
  // is running", which is the direction that authorizes a relaunch.
  if (v === null || v === undefined) return null;
  return [v];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function asInt(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/**
 * An "ms since <event>" field: explicit null stays null (the event's own
 * "absent"), anything else clamps to a non-negative number and falls back to 0 —
 * "just happened" — because 0 is the blocking direction.
 */
function parseAgeMs(v: unknown): number | null {
  if (v === null) return null;
  const raw = asInt(v);
  return raw === null ? 0 : Math.max(0, raw);
}

function parseSession(v: unknown): UserSession | null {
  const r = asRecord(v);
  if (!r) return null;
  const sessionId = asInt(r["sessionId"]);
  const userSid = typeof r["userSid"] === "string" ? r["userSid"] : "";
  if (sessionId === null || userSid === "") return null;
  // Session 0 is the non-interactive services session: never a user desktop, and
  // never somewhere a tray should be started.
  if (sessionId === 0) return null;
  // quitMarkerPresent is the user's explicit "stay down". A missing or mistyped
  // value would default to false = "they never asked" = relaunch, which is
  // exactly the fail-OPEN this module must not have. Drop the session instead:
  // it then gets no recovery this tick, which is the suppressing direction.
  if (typeof r["quitMarkerPresent"] !== "boolean") return null;
  // autoStartEnabled leans the other way (false = opted out = no recovery), but
  // require a real boolean anyway — a session we cannot read cleanly is not one
  // to reason about.
  if (typeof r["autoStartEnabled"] !== "boolean") return null;
  return {
    sessionId,
    userSid,
    autoStartEnabled: r["autoStartEnabled"],
    quitMarkerPresent: r["quitMarkerPresent"],
  };
}

/**
 * Parse one probe stdout into a snapshot, or a CODED reason it is unusable.
 *
 * The reason matters: every one of these used to be a bare null that the loop
 * skipped in silence, so a machine whose probe failed on every tick — a broken
 * CIM service, an unreadable registry, a persistent timeout — was
 * indistinguishable from a healthy machine with nothing to do.
 */
export function parseProbeResult(stdout: string | null): ProbeResult {
  if (stdout === null) return { ok: false, reason: "unparsable-output" };
  let raw: unknown;
  try {
    raw = JSON.parse(stdout);
  } catch {
    return { ok: false, reason: "unparsable-output" };
  }
  const r = asRecord(raw);
  if (!r) return { ok: false, reason: "unparsable-output" };

  // Any query that FAILED (as opposed to answering "nothing") invalidates the
  // whole tick: a failed process query returns an empty list, which would
  // otherwise read as "no tray running, no installer running" and authorize a
  // relaunch. This is the check that makes the documented fail-closed behaviour
  // real rather than aspirational.
  if (!Array.isArray(r["queryErrors"])) return { ok: false, reason: "unusable-fields" };
  if (r["queryErrors"].length > 0) {
    const first = r["queryErrors"][0];
    const known = QUERY_NAMES.find((n) => n === first);
    return { ok: false, reason: known ? (`query-${known}` as ProbeFailureReason) : "query-failed" };
  }

  // Every remaining field must be PRESENT and of the right type.
  if (typeof r["updateTaskRunning"] !== "boolean") return { ok: false, reason: "unusable-fields" };
  if (typeof r["trayExeInstalled"] !== "boolean") return { ok: false, reason: "unusable-fields" };
  if (!("trayOwnerSids" in r) || !("sessions" in r)) {
    return { ok: false, reason: "unusable-fields" };
  }
  if (!("msSinceInstallDirChange" in r)) return { ok: false, reason: "unusable-fields" };
  // Diagnostics, but required: they are the difference between "nothing to do"
  // and "nothing can ever be done here", and the loop logs them.
  const skippedSessions = asInt(r["skippedSessions"]);
  const unverifiedTrayProcesses = asInt(r["unverifiedTrayProcesses"]);
  const unverifiedSessionShells = asInt(r["unverifiedSessionShells"]);
  if (
    skippedSessions === null ||
    unverifiedTrayProcesses === null ||
    unverifiedSessionShells === null
  ) {
    return { ok: false, reason: "unusable-fields" };
  }
  // A null/absent list reads as "nothing running" — permissive — so it rejects
  // the snapshot rather than becoming an empty array.
  const rawTrayOwners = asList(r["trayOwnerSids"]);
  const rawSessions = asList(r["sessions"]);
  if (rawTrayOwners === null || rawSessions === null) {
    return { ok: false, reason: "unusable-fields" };
  }

  // A tray owner we cannot read must REJECT the snapshot, never be dropped:
  // dropping one reads as "that user has no tray", which is the direction that
  // authorizes a relaunch. (Dropping a malformed SESSION is the opposite
  // direction — that session simply gets no recovery — so those are filtered.)
  // The script never emits an empty entry: a process whose owner it could not
  // resolve contributes nothing at all rather than an empty string.
  const trayOwnerSids: string[] = [];
  for (const entry of rawTrayOwners) {
    if (typeof entry !== "string" || entry === "") return { ok: false, reason: "unusable-fields" };
    trayOwnerSids.push(entry);
  }

  const sessions: UserSession[] = [];
  for (const entry of rawSessions) {
    const s = parseSession(entry);
    if (s) sessions.push(s);
  }

  // Only an EXPLICIT null is "unknown"/"absent". Anything present but unreadable
  // resolves to 0, i.e. "it happened just now" → blocks; treating it as null
  // would mean "nothing in flight", the permissive direction. A negative age is a
  // FUTURE mtime (clock change mid-install) and blocks too.
  // msSinceInstallDirChange is null only when the install dir is absent — and
  // then trayExeInstalled is false, which blocks anyway.
  const msSinceInstallDirChange = parseAgeMs(r["msSinceInstallDirChange"]);

  const install: InstallSignals = {
    updateTaskRunning: r["updateTaskRunning"],
    msSinceInstallDirChange,
    trayExeInstalled: r["trayExeInstalled"],
    // THE ONE FIELD WHOSE ABSENCE DOES NOT REJECT. Every other field above is
    // load-bearing for the decision and reads permissively when missing, so a
    // missing one must skip the tick. This one can only ever ADD a block, so a
    // missing, null or malformed value degrades to null — "no usable manifest",
    // which is exactly what an older build with no manifest at all reports, and
    // exactly the behaviour of the watchdog before this check existed. Rejecting
    // instead would let an unreadable diagnostic file deny recovery to every
    // user on the machine. See parseInstallManifestSignals.
    manifest: parseInstallManifestSignals(r["installManifest"]),
  };

  return {
    ok: true,
    snapshot: {
      sessions,
      trayOwnerSids,
      install,
      skippedSessions: Math.max(0, skippedSessions),
      unverifiedTrayProcesses: Math.max(0, unverifiedTrayProcesses),
      unverifiedSessionShells: Math.max(0, unverifiedSessionShells),
    },
  };
}

/** parseProbeResult, reduced to "a snapshot or nothing". Convenience for tests. */
export function parseProbeOutput(stdout: string | null): WatchdogSnapshot | null {
  const result = parseProbeResult(stdout);
  return result.ok ? result.snapshot : null;
}

/** One snapshot. Never throws; `timeoutMs` bounds the shell run (see doctor.ts). */
export async function probeWindows(timeoutMs: number = PROBE_TIMEOUT_MS): Promise<ProbeResult> {
  const shell = await runPowerShell(probeScript(), timeoutMs);
  if (!shell.ok) return { ok: false, reason: shell.reason };
  return parseProbeResult(shell.stdout);
}

/**
 * Test-only (`__` prefix): the probe script source.
 *
 * WHAT THE TESTS DO AND DO NOT ESTABLISH — stated exactly, because a green suite
 * over this function is easy to mistake for a working probe. Nothing off Windows
 * EXECUTES this script, and nothing PARSES it either: there is no PowerShell
 * host here, so the assertions are substring and structural checks over the
 * generated TEXT. They pin the properties that are properties of the text — the
 * machine-wide install signals rooted in admin-owned paths, no silently failing
 * query, no environment read or expansion in any of its three disguises, ordinal
 * string comparisons, bounded lists — plus balanced braces/parentheses as a
 * crude syntax smoke test.
 *
 * They CANNOT catch: a genuine PowerShell syntax or binding error, a wrong
 * overload resolution, the actual shape of the JSON emitted, CIM / registry /
 * Task-Scheduler behaviour, or RunEx session targeting. A syntax error here does
 * not fail loudly — it presents as `probe-failed reason=exit-nonzero` on every
 * tick, i.e. a watchdog that never recovers anybody. So any change to this
 * script must be run on a real Windows box before it ships; OPERATIONS.md lists
 * what that run has to check.
 */
export function __probeScript(): string {
  return probeScript();
}

/**
 * Start the existing "AI Commander Relaunch" task on demand, in one specific
 * terminal-services session.
 *
 * RunEx + TASK_RUN_USE_SESSION_ID (0x4) is what makes the trigger session-aware
 * without touching the task itself: the task keeps its Users-group principal, its
 * admin-owned action and its SDDL, and we merely say WHICH interactive session to
 * land in. The task's action path is pinned by win-update-task.ps1 and is not
 * derived from anything observed here.
 *
 * THERE IS DELIBERATELY NO FALLBACK TO A PLAIN `Run`. There used to be one, and
 * it quietly threw away the identity the decision was made about: a plain Run
 * lets Task Scheduler pick the session, so after the targeted session logged off
 * (or targeting failed for any other reason) the launcher could fire in a
 * DIFFERENT user's session — one that may have turned "Start at Login" off. A
 * per-session consent decision that is executed against an arbitrary session is
 * not the decision that was made. If RunEx will not target the session we chose,
 * we do nothing and let the backoff retry; a missed recovery is recoverable, an
 * override of somebody's explicit opt-out is not.
 */
export async function triggerRelaunchTask(sessionId: number): Promise<void> {
  // The ONLY value interpolated into a script anywhere in this module.
  if (!Number.isInteger(sessionId) || sessionId < 0) {
    throw new Error(`refusing to trigger relaunch for invalid session id ${String(sessionId)}`);
  }
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$svc = New-Object -ComObject 'Schedule.Service'",
    "$svc.Connect()",
    `$task = $svc.GetFolder('\\').GetTask('${RELAUNCH_TASK_NAME}')`,
    // 4 = TASK_RUN_USE_SESSION_ID.
    `$task.RunEx($null, 4, ${sessionId}, $null) | Out-Null`,
  ].join("\n");
  const out = await runPowerShell(script, PROBE_TIMEOUT_MS);
  if (!out.ok) throw new Error(`could not start the '${RELAUNCH_TASK_NAME}' task: ${out.reason}`);
}
