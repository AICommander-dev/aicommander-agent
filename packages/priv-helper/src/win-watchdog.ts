// Windows crash watchdog. The tray has no supervisor on Windows: the HKCU Run
// entry fires at LOGON only, so a crashed tray leaves the machine unreachable
// until somebody starts it by hand. Linux has systemd `Restart=always`; macOS
// has its own answer in the desktop package (a LaunchAgent that relaunches the
// tray), which is a separate mechanism reviewed separately — nothing here knows
// or needs to know about it. This is the Windows answer.
//
// THE SPLIT: the helper decides WHEN, the existing per-user "AI Commander
// Relaunch" scheduled task remains HOW. The helper is the only component that is
// always armed (SYSTEM, AtStartup, RestartCount 3, no execution time limit) and
// can see every session; but it lives in session 0, has no desktop and no
// %APPDATA%, so it can never start a tray itself. The Relaunch task already owns
// exactly that half — a Users-group principal that lands a detached tray in a
// real interactive desktop — so the watchdog only TRIGGERS it on demand. The task
// keeps NO trigger of its own: an earlier attempt gave it a logon trigger with a
// 5-minute repetition, which (a) never armed in the session that installed it,
// (b) could fire mid-install while NSIS was replacing $INSTDIR, (c) overrode the
// user's "Start at Login" opt-out and (d) flashed a console window every 5
// minutes forever. All four are properties of the trigger, not of the launcher.
//
// ---------------------------------------------------------------------------
// SECURITY — stated as what is actually true, because this runs as LocalSystem.
//
// An earlier version of this comment claimed that everything read from a
// user-writable location "can only ever SUPPRESS a recovery, never redirect
// one". That was FALSE in at least two places (the HKCU Run value is a POSITIVE
// gate, and the quit marker's absence authorises a relaunch), and a security
// comment that overstates its guarantee is worse than none, because the next
// author reasons from it. What holds is narrower and mechanical:
//
//   THE GUARANTEE. The only action this watchdog can cause is `Run` on ONE
//   fixed, admin-owned scheduled task ("AI Commander Relaunch"), whose action
//   path is pinned at registration by desktop/build/win-update-task.ps1 and
//   whose SDDL grants no non-admin any access at all. No observation — from a
//   user-writable location or otherwise — is ever turned into a program name, a
//   path we execute, or an argument we pass. Exactly TWO values are interpolated
//   into the scripts in this module's impure half: a terminal-services session
//   id, validated as a non-negative integer, and the directory THIS running image
//   was loaded from, validated to a rooted drive path with no `%` and no control
//   characters and used only as an argument to `Test-Path`/`Get-Content`
//   (win-watchdog-install.ts owns it and says why). Neither reaches anything that
//   executes; that is the property to keep, and nothing must ever be added that
//   turns a read value into something executed.
//
//   WHAT IS *NOT* GUARANTEED, and why it is nevertheless acceptable:
//     * autoStartEnabled is a POSITIVE gate read from the user's own HKCU Run
//       key. A user who writes a Run value pointing at the installed tray exe
//       causes this SYSTEM process to invoke the task in their session. Safe not
//       because the input is trusted, but because the outcome is self-limited:
//       it starts the admin-owned, pinned tray exe, unelevated, as themselves,
//       in their own session — exactly what double-clicking the exe would do.
//     * quitMarkerPresent = false is likewise permissive ("the user never asked
//       to stay down"). It is only ever reported for a session whose profile
//       directory was positively resolved; anything the probe cannot resolve
//       drops the session instead, which suppresses. See win-watchdog-probe.ts.
//     * MACHINE-WIDE signals are the ones that actually need trust, because one
//       user could otherwise suppress every other user's recovery. There are
//       exactly FOUR, they are the whole of installBlockReason, and all four are
//       admin-owned state: the "AI Commander Update" task's RUNNING state,
//       $INSTDIR's mtime, whether the tray exe is present, and the verdict of
//       the shipped install manifest (win-watchdog-install.ts) — read from that
//       same admin-owned directory, or, when a sweep took that copy too, from the
//       admin-owned directory this SYSTEM process itself runs out of. Either way
//       the files are COUNTED in the directory derived from the Relaunch task's
//       pinned action: the fallback moves the inventory, never the measurement.
//       The manifest verdict is the newest of the four and the one to read
//       carefully: it counts only files proved ABSENT, never files that could
//       not be read, because a security product denying reads would otherwise
//       block every user's recovery on an intact machine — a machine-wide
//       suppression produced by something that is not admin-owned state at all. Nothing else in this module is
//       applied machine-wide — evaluateTick has one `blockedBy`, and it is that
//       function's return value.
//       This list is SHORTER than it was, twice over, and both deletions were of
//       signals an unprivileged user could produce: an "installer running from
//       the install dir" signal, once it turned out that admin ownership of a
//       binary says nothing about who may RUN it (see installBlockReason); and a
//       tray-list overflow flag, which any user reached by launching the
//       installed exe ~100 times (an Electron tray is 4-6 processes). The probe
//       now aggregates trays by owner SID, so the size of what it reports
//       follows the number of USERS and no such flag exists to raise. Anything
//       added here must be state an unprivileged user cannot produce — not
//       merely state they cannot write.
//       A MACHINE-WIDE SUPPRESSION DOES NOT HAVE TO BE A REPORTED SIGNAL: a
//       probe that never finishes suppresses everybody just as effectively as a
//       block, because a timed-out probe recovers nobody. So the property to
//       keep is narrower than "no forgeable signal" — every loop in the probe
//       whose candidate count an unprivileged user can raise must also be
//       BOUNDED, per loop, and where the bound's cost is a lost recovery it must
//       be charged to the session that provoked it. See
//       MAX_TRAY_OWNER_LOOKUPS and MAX_SHELL_OWNER_LOOKUPS_PER_SESSION; the
//       latter closed a session scan that paid a CIM call for every process
//       merely NAMED explorer.exe.
//       BOUNDED IS NOT THE SAME AS PRICED, and this comment used to blur the
//       two. It is priced now: GetOwnerSid was MEASURED at 73.68 ms per call on
//       a real box (2026-08-09, aic-pc, as LocalSystem), which showed the old
//       budgets did NOT fit — 512 tray lookups alone were 37.7 s against a 30 s
//       PROBE_TIMEOUT_MS, i.e. one unprivileged user could time out every tick
//       and recover nobody. Both loops are now bucketed per session id and
//       capped globally at 128 calls between them (~9.4 s), and no single
//       SESSION can charge more than 16 of those calls (~1.2 s).
//       PER SESSION IS NOT PER USER, and an earlier version of this paragraph
//       said "one user's own reachable ceiling is 16 calls", which is false: one
//       account can hold several concurrent interactive sessions (see "per user,
//       not per session" below), so ~6 sessions drain the 48-call tray pool and
//       ~10 drain the 80-call session pool, first-come, starving later users for
//       that tick. That starvation is the bounded direction (a redundant
//       relaunch, or a session undiscovered until the next tick); the property
//       the budgets actually guarantee machine-wide is the TIMEOUT. Keying the
//       buckets by owner SID would give per-user isolation and cannot be done:
//       the bucket must be picked before the call that returns the SID.
//       The two Get-CimInstance enumerations that feed them are still not
//       bounded — they are the size of the process table — but were measured at
//       ~200 ms together. The numbers, the arithmetic and the test that pins it
//       live with the constants in win-watchdog-probe.ts — read them before
//       adding a loop.
//     * PER-USER liveness needs the same kind of trust, one user at a time: a
//       fake tray attributed to somebody else would suppress THEIR recovery. A
//       process merely NAMED AICommander.exe is not a tray — it must run from
//       the admin-owned install directory — and which user a verified tray
//       belongs to comes from that process's own token (GetOwnerSid), so to fake
//       liveness for somebody else you would have to run the installed exe AS
//       them.
// ---------------------------------------------------------------------------
//
// This file is the PURE decision half (fully unit-tested); win-watchdog-probe.ts
// is the impure half that queries Windows and triggers the task, and
// win-watchdog-log.ts turns decisions into log lines under a strict field
// allowlist.

import {
  installIncompleteVerdict,
  looksLikeStaleInstallPath,
  type InstallManifestSignals,
} from "./win-watchdog-install.js";
import { formatWatchdogLine } from "./win-watchdog-log.js";
import { installManifestEvent } from "./win-watchdog-install-log.js";

/**
 * Tick interval.
 *
 * COST, counted honestly (an earlier version of this comment claimed "one CIM
 * query plus a few registry reads, ~0.1 s of CPU" and counted neither the
 * process start nor two thirds of the queries). One tick spawns ONE
 * powershell.exe — a cold start is the dominant cost, and on Windows that is
 * several hundred milliseconds of CPU, not tens — which then performs:
 *   * one Get-CimInstance Win32_Process enumeration (both consumers — tray
 *     processes and explorer sessions — filter that one result client-side);
 *   * one Get-CimInstance Win32_UserProfile enumeration;
 *   * one GetOwnerSid call per candidate shell process — the explorer.exe inside
 *     the Windows directory, typically 1 per interactive session. Processes
 *     merely NAMED explorer.exe are filtered out before the call and the calls
 *     are budgeted per session id (MAX_SHELL_OWNER_LOOKUPS_PER_SESSION), so this
 *     count is not attacker-chosen;
 *   * one GetOwnerSid call per tray process that could be a MAIN process, i.e.
 *     per verified AICommander.exe that is neither `--type=` nor parented by
 *     another tray process — typically 1 per logged-on user, because an Electron
 *     tray is one main process and 3-5 children and the children are skipped.
 *     This is what liveness is read from (see hasLiveTrayMainForUser); the
 *     alternative, deriving the owner from the session the process runs in, is
 *     exactly the false negative that was removed. The count is attacker-
 *     influenced (a user may start verified copies of the installed exe), so the
 *     probe bounds the lookups explicitly, per session id and globally — see
 *     MAX_TRAY_OWNER_LOOKUPS and MAX_TRAY_OWNER_LOOKUPS_PER_SESSION; the
 *     snapshot itself does not grow either way, because what crosses the
 *     boundary is owner SIDs, not processes.
 *   * one Schedule.Service COM connect + two task lookups;
 *   * a handful of registry and file existence checks.
 * WHAT OF THAT IS MEASURED, exactly — three of the items above, on aic-pc
 * (Windows x64, 281 live processes) on 2026-08-09 as LocalSystem, via the
 * privileged helper:
 *   * Get-CimInstance Win32_Process over 281 processes: 163 ms;
 *   * Get-CimInstance Win32_UserProfile over 7 profiles: 28 ms;
 *   * Invoke-CimMethod GetOwnerSid: 73.68 ms per call, over 100 calls — the
 *     number the probe's lookup budgets are derived from
 *     (MEASURED_OWNER_SID_LOOKUP_MS).
 * NOT measured: the powershell.exe cold start, the Schedule.Service COM connect
 * and task lookups, the per-session registry and file work, and therefore the
 * whole tick. So the interval is still chosen to be safe under a pessimistic
 * estimate rather than fitted to a measured total: even at a full second of CPU
 * per tick, 60 s between ticks keeps the watchdog under ~2% of one core, and
 * still restores a crashed tray inside ~2 minutes (see
 * WATCHDOG_MISSES_BEFORE_RECOVERY). Measuring the remainder on a real box would
 * let that estimate be replaced by a figure; measuring the whole tick is the
 * useful measurement, not any one of the parts.
 */
export const WATCHDOG_INTERVAL_MS = 60_000;

/**
 * Consecutive ticks a user must look "tray missing but wanted" before we act.
 * Defense in depth behind the explicit install detection below: an install or
 * uninstall we somehow failed to observe still has to keep the tray down for two
 * whole ticks to fool us, and the cost of the delay is bounded by the interval.
 */
export const WATCHDOG_MISSES_BEFORE_RECOVERY = 2;

/**
 * How long after the last change to the install directory we keep treating an
 * install as "possibly still in flight". NSIS writes $INSTDIR right up to the end
 * of the install and the app's own first start rewrites nothing there, so a fresh
 * mtime means an install/upgrade just touched it.
 */
export const INSTALL_SETTLE_MS = 120_000;

/**
 * Ceiling on the retry backoff, in ticks (60 = ~1 hour at the default interval).
 *
 * A trigger is not a guarantee: the launcher can still decline (a quit marker
 * under a REDIRECTED AppData that the probe's profile-path derivation missed), or
 * the tray can start and immediately crash again. Without a backoff the decision
 * would re-fire every WATCHDOG_MISSES_BEFORE_RECOVERY ticks forever — a console
 * flash in that user's session every couple of minutes, unbounded task history
 * and unbounded log spam. That is the very symptom the 5-minute repetition was
 * rejected for, arriving through a different door.
 *
 * So each consecutive attempt that does not take doubles the wait, and so does
 * each relaunch that "works" only until the tray dies again (see `flaps`).
 */
export const WATCHDOG_MAX_BACKOFF_TICKS = 60;

/**
 * How long a user's tray has to stay up before we forget that we ever had to
 * relaunch it (60 ticks = ~1 hour).
 *
 * The counter this clears (`flaps`) is what stops a CRASH LOOP from looking like
 * a series of successful recoveries. The consecutive-attempt counter cannot see
 * that case at all: a tray that starts, lives for one tick and dies again clears
 * `attempts` on every cycle, so the watchdog would relaunch it every ~2 minutes
 * forever, at full speed, with no escalation and no signal that anything is
 * wrong. `flaps` counts relaunches instead of failures, and only an
 * UNINTERRUPTED healthy hour clears it — one hour because that is the backoff
 * ceiling too, i.e. "we have gone a whole slowest-cadence period without needing
 * to do anything", which is as close to "this is fixed" as the watchdog can see.
 */
export const WATCHDOG_FLAP_QUIET_TICKS = 60;

/**
 * Ticks to wait after the Nth escalation: 2, 4, 8, 16, 32, then the cap. Never
 * zero — attempt 1 already waits a full debounce window, which is long enough
 * for a started tray to show up in the next snapshot.
 */
export function backoffTicks(attempts: number): number {
  if (attempts < 1) return WATCHDOG_MISSES_BEFORE_RECOVERY;
  return Math.min(2 ** attempts, WATCHDOG_MAX_BACKOFF_TICKS);
}

/** On-disk name of the tray executable (electron-builder `executableName`). */
export const TRAY_IMAGE_NAME = "AICommander.exe";
/** The task the watchdog triggers; registered by desktop/build/win-update-task.ps1. */
export const RELAUNCH_TASK_NAME = "AI Commander Relaunch";
/** The SYSTEM updater task; its RUNNING state is our "an install is in flight" signal. */
export const UPDATE_TASK_NAME = "AI Commander Update";

/** One interactive user session and the two consent signals that belong to it. */
export interface UserSession {
  sessionId: number;
  /** The session owner's SID — the key for their HKU hive and their profile dir. */
  userSid: string;
  /**
   * The user's HKCU Run key holds a value whose TARGET is the installed tray exe
   * (autolaunch.ts writes it; the probe matches on the target, never the value
   * name). Missing = the user turned "Start at Login" off, which is an explicit
   * opt-out we must not override. This is a POSITIVE, user-writable gate — see
   * the SECURITY block at the top of this file for why that is accepted.
   */
  autoStartEnabled: boolean;
  /**
   * `<userData>\.user-quit` exists — the user chose tray Exit/Uninstall and means
   * it (desktop/src/quit-marker.ts). The Relaunch task's launcher checks this too;
   * checking it here as well keeps us from triggering a task that would only
   * no-op, which is what would otherwise re-create a periodic console flash in
   * the user's session.
   */
  quitMarkerPresent: boolean;
}

/** Machine-wide signals that say "do not start anything right now". */
export interface InstallSignals {
  /** The SYSTEM "AI Commander Update" task is in state RUNNING (4). */
  updateTaskRunning: boolean;
  /** Age of the install dir's mtime, or null when it could not be determined. */
  msSinceInstallDirChange: number | null;
  /** The installed tray exe is present on disk. */
  trayExeInstalled: boolean;
  /**
   * What the install manifest shipped inside $INSTDIR says about the files that
   * are supposed to be there — or null when there is no usable manifest, which
   * is deliberately the same answer for "an older build shipped none", "the
   * sweep took the manifest too" and "we could not read it". A missing manifest
   * is never evidence of damage.
   *
   * ADMIN-OWNED, like the other three: the file lives in %ProgramFiles% under
   * the install directory derived from the Relaunch task's pinned action, so no
   * non-admin can write it. That is what lets it join a MACHINE-WIDE block
   * without handing an unprivileged user a way to suppress everybody's recovery
   * — the standard this list is held to (see the SECURITY block at the top).
   */
  manifest: InstallManifestSignals | null;
}

export interface WatchdogSnapshot {
  sessions: UserSession[];
  /**
   * The SET of user SIDs that own a live MAIN tray, aggregated BY THE PROBE.
   *
   * One entry per user, never per process — and that is a security property, not
   * a convenience. A per-process list made the reply's size an attacker-chosen
   * quantity (an Electron tray is 4-6 `AICommander.exe` processes, so launching
   * the installed exe ~100 times reached even a 512-entry cap), and every shape
   * of "the list was too long" the probe could report ended up denying recovery
   * to every user on the machine. Sized by USERS, the cap is bounded by the
   * number of accounts logged on and no amount of process-starting reaches it.
   *
   * A user whose tray the probe could not attribute — an unresolved owner token
   * — is simply absent, which reads as "no tray" and authorises a redundant
   * relaunch their single-instance lock discards. That is the bounded direction;
   * attributing a tray to the wrong user would suppress a real recovery.
   *
   * What the probe verified before an entry got here: the process runs from the
   * admin-owned install directory (a process a user merely NAMED
   * `AICommander.exe` never counts), it is not one of Electron's
   * GPU/utility/renderer children (`--type=`, or parented by another tray
   * process — they share the image name, so a lingering child must not read as a
   * living tray), and the SID comes from the process's own token.
   */
  trayOwnerSids: string[];
  install: InstallSignals;
  /**
   * Interactive sessions this tick did not deliver — dropped because they could
   * not be read cleanly, or because the scan's lookup budget ran out (fail-
   * closed: they get no recovery). Counted as distinct session ids by the probe.
   * They are the difference between "this machine has nothing to do" and "this
   * machine can never recover anybody", so they are logged.
   *
   * NOT diagnostics only, which this comment used to claim: a non-zero count is
   * what tells evaluateTick that `sessions` is PARTIAL, and therefore that a
   * user's absence from it is not evidence they logged off. See the prune at the
   * end of evaluateTick.
   *
   * Still exactly that, now that liveness no longer reads sessions: a dropped
   * session cannot make a user look tray-LESS either. If it was their only
   * session the user is not evaluated at all (no target, no trigger); if they
   * have another, that one carries the same per-profile consent signals. Both
   * directions suppress, which is the property this counter names.
   */
  skippedSessions: number;
  /**
   * Processes named like the tray but NOT running from the install directory.
   * Never counted as a live tray; reported because a persistent non-zero count
   * is either a stale install or somebody probing at the check.
   */
  unverifiedTrayProcesses: number;
  /**
   * Processes named `explorer.exe` but NOT the shell inside the Windows
   * directory. Never bought a GetOwnerSid call, so they cannot slow a tick down;
   * reported because a persistent non-zero count means somebody is running
   * copies of a binary under the shell's name, which is what the filter that
   * counts them exists to make cheap.
   */
  unverifiedSessionShells: number;
}

/** Why a user did (or did not) get a recovery this tick. */
export type SessionOutcome =
  | "recover"
  | "waiting"
  | "backoff"
  | "tray-running"
  | "autostart-opt-out"
  | "user-quit";

export interface SessionVerdict {
  /**
   * The session a recovery would be aimed at (see pickTargetSession). The
   * decision itself is per USER, not per session.
   */
  sessionId: number;
  userSid: string;
  outcome: SessionOutcome;
  /** Consecutive ticks this user has looked recoverable, including this one. */
  misses: number;
  /** Consecutive relaunch attempts that have not taken (0 = healthy). */
  attempts: number;
  /** Relaunches not yet followed by a healthy hour — the flap counter. */
  flaps: number;
}

/** One user to relaunch, with the observability the loop logs. */
export interface RecoveryTarget {
  /** Session to aim at; RunEx needs one, even though the decision is per user. */
  sessionId: number;
  userSid: string;
  /** 1 for the first attempt, N for the Nth consecutive one that hasn't taken. */
  attempt: number;
  /** Relaunches for this user inside the current flap window (>= attempt). */
  flaps: number;
  /** Ticks until this user is eligible again if this attempt does not take. */
  retryInTicks: number;
  /** Absolute tick this user becomes eligible again (what the log reports). */
  nextDueTick: number;
  /** This attempt is at the backoff ceiling — the watchdog is being vetoed. */
  atBackoffCeiling: boolean;
}

export interface TickResult {
  /** Users to trigger the Relaunch task for, this tick. */
  trigger: RecoveryTarget[];
  /** Machine-wide reason nothing was done, or null when the tick was evaluated. */
  blockedBy: string | null;
  verdicts: SessionVerdict[];
}

interface UserWatchdogState {
  /** Consecutive ticks this user has looked recoverable. */
  misses: number;
  /** Consecutive attempts that did not take. */
  attempts: number;
  /** Relaunches inside the current flap window (cleared by a healthy hour). */
  flaps: number;
  /** Tick of the most recent relaunch, 0 when there has never been one. */
  lastTriggerTick: number;
  /** Tick number before which this user is not eligible again. */
  retryAtTick: number;
  /**
   * CONSECUTIVE ticks this user's tray has been observed alive — reset by any
   * other outcome. This is what clears `flaps`, and it has to be consecutive
   * observations rather than elapsed time: measuring "ticks since the last
   * trigger" let a crash loop clear the counter on a single live observation
   * that happened to land at the hour boundary, which is precisely the case
   * `flaps` exists to catch.
   */
  healthyTicks: number;
}

/**
 * Cross-tick state, keyed by USER (not by session — see evaluateTick). A
 * boot-persistent SYSTEM process must not grow it over months of logons, so
 * evaluateTick prunes keys for users that are gone — but only on a tick whose
 * session enumeration was complete (`skippedSessions === 0`), because on a host
 * past the probe's session budget an absence means "not looked at", not "logged
 * off". On such a host the map is bounded by the accounts that have held an
 * interactive session since boot AND are mid-escalation, each of which costs a
 * handful of numbers; see the prune for why that is not capped.
 */
export interface WatchdogState {
  users: Map<string, UserWatchdogState>;
  /** Monotonic tick counter — the clock the backoff is measured in. */
  tick: number;
}

export function createWatchdogState(): WatchdogState {
  return { users: new Map(), tick: 0 };
}

/** SIDs are case-insensitive strings; normalise so one user is one key. */
function userKey(userSid: string): string {
  return userSid.toLowerCase();
}

/**
 * True when a MAIN tray OWNED BY THIS USER is alive — in whichever session it
 * happens to be running. A set membership test, because the probe has already
 * done the work: see WatchdogSnapshot.trayOwnerSids.
 *
 * DECIDED FROM THE PROCESS LIST, NOT FROM SESSION DISCOVERY. This used to ask
 * "is there a main tray in one of the sessions we discovered for this user?",
 * and the sessions were discovered by enumerating `explorer.exe` and taking its
 * owner. A tray running in a session with no conventional shell — RemoteApp, or
 * a machine whose shell has been replaced — was therefore invisible, and the
 * consequence was not a missing log line: the user read as tray-less, the
 * watchdog relaunched into a DIFFERENT session, the per-user single-instance
 * lock killed the new process at once, and the cycle escalated to the backoff
 * ceiling and stayed there — one console flash an hour, forever, on a machine
 * whose tray was perfectly healthy.
 *
 * The owner SID comes from the process's own token (Win32_Process::GetOwnerSid),
 * so it no longer depends on the user having an enumerable session, and one user
 * cannot claim a tray on another's behalf. What the probe could not attribute is
 * not in the set, and therefore counts for nobody.
 *
 * WHY THE MAIN-vs-CHILD TEST IS NOT HERE ANY MORE. It has not been dropped — it
 * moved into the probe script, next to the process list it needs, because that
 * is what lets the reply carry one entry per USER instead of one per process.
 * Sizing the reply by processes was the whole DoS: an unprivileged user could
 * make it overflow any cap and every over-cap shape the probe could report ended
 * up denying recovery machine-wide. Both signals survive verbatim (`--type=`, or
 * parented by another verified tray process), and win-watchdog-probe.test.ts
 * pins them in the script's text.
 */
export function hasLiveTrayMainForUser(
  trayOwnerSids: readonly string[],
  userSid: string,
): boolean {
  if (userSid === "") return false;
  const key = userKey(userSid);
  return trayOwnerSids.some((sid) => sid !== "" && userKey(sid) === key);
}

/**
 * Machine-wide "an install or uninstall is in flight" check — the reason the
 * watchdog must not be a blind timer. Relaunching the tray while NSIS is
 * replacing $INSTDIR makes the new process lock its own exe/DLLs and turns the
 * watchdog into a cause of failed silent updates and half-finished uninstalls.
 *
 * What each signal keys on, and why it is reliable from SYSTEM:
 *  - updateTaskRunning: win-updater.ps1 runs AS the "AI Commander Update" task
 *    and `Start-Process -Wait`s the silent installer, so the task instance is
 *    RUNNING for the whole download+install. This covers every automatic update —
 *    the dominant install path — with an admin-owned signal a user cannot forge.
 *  - trayExeInstalled: mid-install the exe is simply absent. Nothing to start,
 *    and its absence IS the window we must not act in.
 *  - msSinceInstallDirChange: NSIS writes $INSTDIR until the very end of the
 *    install; the running app never does. A fresh mtime therefore means an
 *    install just touched the directory, which closes the gap between "installer
 *    process exited" and "install actually settled".
 *
 * WHAT DELIBERATELY IS NOT HERE — two signals, both DELETED rather than left in
 * weakened form, because a guard that nothing feeds (or whose premise is false)
 * reads as "no install in flight" forever, which is the permissive direction,
 * and the next reader takes it for a live one:
 *
 *  - an `.install-in-flight` marker the installer used to write into $INSTDIR.
 *    A hand-driven install once opened a window nothing here could see: the NSIS
 *    `.onInit` killed the tray before the wizard drew its first page, so for as
 *    long as the user sat on that page the machine looked like "healthy box,
 *    tray crashed". The installer now kills the app in `customCheckAppRunning`
 *    instead — immediately before the file operations rather than before the
 *    wizard — so the window is bounded by the install itself and the two-tick
 *    debounce covers it. The marker was then removed on the desktop side.
 *
 *  - `installerProcesses`: live processes running from inside the admin-owned
 *    install dir. Its premise was that an admin-owned directory makes the
 *    process trustworthy, and that is FALSE — admin ownership protects the
 *    binary from modification, not the right to run it, and Users have
 *    read+execute there. Any local user could start the uninstaller unelevated
 *    and leave it sitting, and since this block has no time limit that
 *    suppressed crash recovery for every user on the machine indefinitely. The
 *    coverage it claimed is provided by the three signals above (the Update task
 *    spans every silent update; a manual uninstall kills the tray, deletes this
 *    helper's own task and the Relaunch task, and moves $INSTDIR's mtime, all
 *    inside the debounce). win-watchdog-probe.ts records the template reading
 *    that verified this. Do not reintroduce it without a check that proves the
 *    process is elevated, and never as a name-only match.
 *
 * Order is log ergonomics, not logic — any one of them blocks, and the first
 * match is the reason we report. The update task comes first because it names a
 * CAUSE ("an install is running"), while the other two are consequences ("the
 * exe is gone", "the directory changed") that are far more confusing to read in
 * a log when the real story is an install.
 *
 * Returns a short reason string (for logs/tests) or null when nothing blocks.
 */
export function installBlockReason(install: InstallSignals): string | null {
  if (install.updateTaskRunning) return "update-task-running";
  if (!install.trayExeInstalled) return "tray-exe-missing";
  if (
    install.msSinceInstallDirChange !== null &&
    install.msSinceInstallDirChange < INSTALL_SETTLE_MS
  ) {
    return "install-dir-just-changed";
  }
  // LAST, and that position is the whole of its in-progress handling. A gutted
  // install and an install in flight look identical from a file listing, so this
  // signal is only consulted once the two windows above are clear — the Update
  // task is not running, and nothing has written $INSTDIR for INSTALL_SETTLE_MS.
  // Reusing them was the requirement; a second in-flight mechanism would be one
  // more thing that can be wrong about the same question.
  //
  // WHY IT MAY BLOCK MACHINE-WIDE. The manifest is a file in %ProgramFiles%
  // inside the directory derived from the admin-owned Relaunch task, so it meets
  // the bar the other three signals meet: an unprivileged user cannot produce
  // it, and therefore cannot use it to deny anybody else recovery. What it buys
  // is the 2026-09-02 case, which every other signal reports as health: the exe
  // survived the sweep (Windows locks a running image) while the data files
  // Electron loads before our JavaScript runs did not, so the watchdog kept
  // triggering the Relaunch task, once every couple of minutes, into an app that
  // could not start — for as long as the machine stayed on.
  // AND IT BUYS IT EVEN THOUGH THE SWEEP TOOK THE MANIFEST — which it did, the
  // manifest being one of the 80, so reading only the in-tree copy left this
  // signal saying "nothing to say" on the very machine it was written for. The
  // installer now puts a second copy beside the privileged helper and the probe
  // falls back to it; win-watchdog-install.ts owns the rest of that argument.
  if (installIncompleteVerdict(install) !== null) return "install-incomplete";
  return null;
}

/** One logged-on user, with every interactive session they currently own. */
interface UserView {
  userSid: string;
  sessions: UserSession[];
  /** Session a relaunch is aimed at (see pickTargetSession). */
  targetSessionId: number;
  /** Every session agrees (they read the same HKCU key) — `every` fails closed. */
  autoStartEnabled: boolean;
  /** Any session seeing the marker suppresses — the marker is per profile. */
  quitMarkerPresent: boolean;
}

/**
 * Which session a per-user recovery is aimed at: the LOWEST session id.
 *
 * The decision is per user, but Task Scheduler's RunEx needs a concrete session,
 * and there is no signal available from SYSTEM that reliably says which of a
 * user's sessions is the connected one (that would need WTS APIs we do not
 * P/Invoke). Session ids increase with logon order, so the lowest is the console
 * session on a workstation — the overwhelmingly common case, and the one where a
 * tray is actually useful. When the guess is wrong the cost is bounded and
 * self-correcting: the tray starts in the user's other session, the app's
 * per-user single-instance lock means it is the only one either way, and the
 * next tick sees it alive.
 */
function pickTargetSession(sessions: readonly UserSession[]): number {
  return sessions.reduce((lowest, s) => Math.min(lowest, s.sessionId), Number.MAX_SAFE_INTEGER);
}

function groupByUser(sessions: readonly UserSession[]): UserView[] {
  const byUser = new Map<string, UserSession[]>();
  for (const s of sessions) {
    const key = userKey(s.userSid);
    const list = byUser.get(key);
    if (list) list.push(s);
    else byUser.set(key, [s]);
  }
  return [...byUser.values()].map((list) => ({
    userSid: list[0]!.userSid,
    sessions: list,
    targetSessionId: pickTargetSession(list),
    // Both consent signals come from ONE per-user source (the HKCU hive and the
    // profile directory), so every session of a user carries the same value.
    // They are still combined in the SUPPRESSING direction, so a disagreement —
    // which would mean one of the reads was wrong — cannot authorize anything.
    autoStartEnabled: list.every((s) => s.autoStartEnabled),
    quitMarkerPresent: list.some((s) => s.quitMarkerPresent),
  }));
}

/**
 * One tick of the decision. Pure: all OS knowledge arrives in `snapshot`, all
 * cross-tick memory lives in `state`.
 *
 * KEYED PER USER, NOT PER SESSION. A tray is a per-USER thing: Electron's
 * requestSingleInstanceLock is scoped to the shared per-user `userData`
 * directory, so one user has AT MOST ONE tray no matter how many desktops they
 * are logged into (console + RDP, or a reconnected disconnected session), and it
 * lives in whichever session started it. Keying this per session therefore made
 * the second session's liveness check permanently false: the watchdog triggered
 * there forever, climbed to the backoff ceiling and never converged — one
 * console flash an hour, indefinitely.
 *
 * WHAT "ALIVE" IS READ FROM. The owner of a verified tray PROCESS, not the
 * sessions we managed to discover for that user (see hasLiveTrayMainForUser):
 * session discovery goes through `explorer.exe`, which a RemoteApp or
 * shell-replaced session does not have, and deciding liveness from it hid a
 * healthy tray in exactly that case. Session discovery still runs, but its only
 * job now is to pick a TARGET for the relaunch — RunEx needs a session id — and
 * to carry the two consent signals. A user with no discoverable session is
 * simply not evaluated: there is no desktop to start a tray in, so there is
 * nothing to aim at and nothing to do. The quit marker, which is per profile,
 * then naturally suppresses recovery across all of that user's sessions —
 * something the per-session model could not express at all.
 *
 * Per user, a recovery needs all of: no main tray OWNED BY THEM anywhere on the
 * machine, autostart not opted out, no quit marker, nothing installing, and
 * WATCHDOG_MISSES_BEFORE_RECOVERY consecutive ticks. Another user's live tray
 * never suppresses anything here — each interactive user runs their own tray
 * against their own userData.
 */
export function evaluateTick(state: WatchdogState, snapshot: WatchdogSnapshot): TickResult {
  state.tick += 1;
  // The ONLY machine-wide block, and deliberately so: every signal behind it is
  // admin-owned state (see installBlockReason). There used to be a second one —
  // a tray-list overflow flag — and it was reachable by any unprivileged user
  // simply starting the installed exe often enough, which denied recovery to
  // everybody on the box. It is gone with the per-process list that produced it;
  // do not add a machine-wide block for anything a user can cause.
  const blockedBy = installBlockReason(snapshot.install);
  const verdicts: SessionVerdict[] = [];
  const trigger: RecoveryTarget[] = [];
  const seen = new Set<string>();

  for (const user of groupByUser(snapshot.sessions)) {
    const key = userKey(user.userSid);
    seen.add(key);
    const prev = state.users.get(key);
    let misses = prev?.misses ?? 0;
    let attempts = prev?.attempts ?? 0;
    let flaps = prev?.flaps ?? 0;
    let lastTriggerTick = prev?.lastTriggerTick ?? 0;
    let retryAtTick = prev?.retryAtTick ?? 0;
    let healthyTicks = prev?.healthyTicks ?? 0;

    // From the PROCESS LIST, by owner — never from the sessions we discovered
    // for this user. See hasLiveTrayMainForUser.
    const trayAlive = hasLiveTrayMainForUser(snapshot.trayOwnerSids, user.userSid);

    let outcome: SessionOutcome;
    if (trayAlive) {
      outcome = "tray-running";
    } else if (!user.autoStartEnabled) {
      outcome = "autostart-opt-out";
    } else if (user.quitMarkerPresent) {
      outcome = "user-quit";
    } else if (blockedBy !== null) {
      outcome = "waiting";
    } else if (state.tick < retryAtTick) {
      // A previous attempt has not taken yet and we are still backing off.
      outcome = "backoff";
    } else {
      outcome = "recover";
    }

    // Consecutive health, counted before anything else reads it: every outcome
    // other than a live tray breaks the streak, including a blocked or backing-
    // off tick. Only an unbroken run of WATCHDOG_FLAP_QUIET_TICKS clears `flaps`.
    healthyTicks = outcome === "tray-running" ? healthyTicks + 1 : 0;

    if (outcome !== "recover") {
      // The miss counter only advances on a clean "should be running and isn't";
      // every other outcome (block, backoff, consent) resets it to zero.
      misses = 0;
      if (outcome === "tray-running") {
        // A tray we can see means this round of attempts worked, so the
        // CONSECUTIVE-failure counter is done.
        attempts = 0;
        // The FLAP counter is not: it is cleared only by an uninterrupted
        // healthy stretch, because a tray that comes up and dies again on any
        // period longer than one tick would otherwise look like a series of
        // successful recoveries and be relaunched forever at full speed.
        //
        // "Uninterrupted" means CONSECUTIVE healthy observations, not elapsed
        // ticks since the last trigger: with elapsed ticks, a crash loop whose
        // one live moment happened to fall on the hour boundary reset the whole
        // escalation, and then did it again every hour, forever.
        if (lastTriggerTick !== 0 && healthyTicks >= WATCHDOG_FLAP_QUIET_TICKS) {
          flaps = 0;
          lastTriggerTick = 0;
          retryAtTick = 0;
          healthyTicks = 0;
        }
      } else if (outcome === "autostart-opt-out" || outcome === "user-quit") {
        // Consent withdrawn: escalating against a user we are not going to
        // recover is meaningless, so the failure counter goes. `flaps` and
        // `retryAtTick` deliberately do NOT — otherwise touching `.user-quit`
        // for a single tick would reset an escalating backoff, which is a
        // user-writable way to restore the once-every-two-minutes behaviour.
        attempts = 0;
      }
      // "waiting" / "backoff" keep every counter: an install passing through
      // must not hand a wedged user a free reset either.
    } else {
      misses += 1;
      if (misses < WATCHDOG_MISSES_BEFORE_RECOVERY) {
        outcome = "waiting";
      } else {
        misses = 0;
        attempts += 1;
        flaps += 1;
        lastTriggerTick = state.tick;
        // Whichever escalation is further along wins: `attempts` catches a
        // relaunch that never takes, `flaps` catches one that takes and then
        // dies again. (`flaps` is >= `attempts` by construction; the max is
        // written out so the rule survives a change to either clearing rule.)
        const retryInTicks = backoffTicks(Math.max(attempts, flaps));
        retryAtTick = state.tick + retryInTicks;
        trigger.push({
          sessionId: user.targetSessionId,
          userSid: user.userSid,
          attempt: attempts,
          flaps,
          retryInTicks,
          nextDueTick: retryAtTick,
          atBackoffCeiling: retryInTicks >= WATCHDOG_MAX_BACKOFF_TICKS,
        });
      }
    }

    // Drop state for a user with nothing to remember, so the map stays small.
    // (`healthyTicks` is only ever read to clear `flaps`, so a user with no
    // flaps has nothing to lose by forgetting it.)
    if (misses === 0 && attempts === 0 && flaps === 0) state.users.delete(key);
    else {
      state.users.set(key, { misses, attempts, flaps, lastTriggerTick, retryAtTick, healthyTicks });
    }

    verdicts.push({
      sessionId: user.targetSessionId,
      userSid: user.userSid,
      outcome,
      misses,
      attempts,
      flaps,
    });
  }

  // PRUNE ONLY ON EVIDENCE. This state lives for the machine's uptime, so users
  // who logged off have to be dropped — but absence from `snapshot.sessions` is
  // evidence of a logoff only when the enumeration was COMPLETE. The probe's
  // session scan is budgeted (MAX_SHELL_OWNER_LOOKUPS) and, past that budget,
  // starts at a random offset each tick so the starved tail rotates instead of
  // being the same users forever; on such a host a user is missing from most
  // ticks simply because the scan never reached them. `skippedSessions` is
  // exactly "sessions this tick did not deliver" (over budget, unreadable hive,
  // unresolvable profile — the probe counts distinct session ids), so a non-zero
  // count means the list is partial and an absence proves nothing.
  //
  // What the prune deletes is the BACKOFF (`flaps`, `attempts`, `retryAtTick`),
  // not just the miss debounce. Pruning on a partial list therefore relaunched a
  // crash-looping tray at full speed forever on exactly the large hosts the
  // rotation was added for — the respawn storm WATCHDOG_MAX_BACKOFF_TICKS exists
  // to prevent.
  //
  // THE COST, stated rather than hidden: a user who really does log off and back
  // on while ticks are partial keeps stale `flaps`, so their next genuine crash
  // can wait up to the ceiling (~1 h) instead of ~2 min, and one uninterrupted
  // healthy hour clears it. That is bounded and self-correcting; the other
  // direction is not — a backoff that can be reset by a tick that simply did not
  // look never stops. NOT BOUNDED BY A CAP, deliberately: an entry needs a user
  // the probe positively OBSERVED in an interactive session and still carrying a
  // non-zero counter (the block above deletes anyone with nothing to remember),
  // so growth follows distinct interactive logons, not anything a process can
  // multiply. A cap would have to evict somebody, and an evicted user is one
  // whose backoff — or whose recovery — an unprivileged user could then discard
  // by logging on enough times. That failure mode has already been removed from
  // this module twice; do not add it back here.
  if (snapshot.skippedSessions === 0) {
    for (const key of [...state.users.keys()]) {
      if (!seen.has(key)) state.users.delete(key);
    }
  }

  return { trigger, blockedBy, verdicts };
}

// --- the loop ---------------------------------------------------------------

/**
 * Why a probe produced nothing usable. A FIXED set of codes, never free text:
 * these end up in a SYSTEM-written log file, and an error message from a child
 * process can quote arbitrary user-controlled text (see win-watchdog-log.ts).
 */
export type ProbeFailureReason =
  | "spawn-failed"
  | "timeout"
  | "output-too-large"
  | "exit-nonzero"
  | "unparsable-output"
  | "query-failed"
  | `query-${ProbeQueryName}`
  | "unusable-fields"
  | "threw";

/**
 * The individual queries the probe script can report as failed. Named here (a
 * closed set) rather than passed through as text, because these codes end up in
 * a machine-wide log file — see win-watchdog-log.ts.
 */
export type ProbeQueryName =
  | "scheduler"
  | "relaunch-task"
  | "update-task"
  | "processes"
  | "user-profiles"
  | "sessions"
  | "install-dir";

export type ProbeResult =
  | { ok: true; snapshot: WatchdogSnapshot }
  | { ok: false; reason: ProbeFailureReason };

export interface WatchdogDeps {
  /**
   * Query Windows. A failure carries a REASON: every expected production failure
   * (a CIM hiccup, an unreadable hive, a timeout, an output overflow) used to
   * return a bare null and be skipped silently, which meant a permanently broken
   * watchdog was indistinguishable from a healthy idle machine.
   */
  probe(): Promise<ProbeResult>;
  /** Trigger the Relaunch task on demand in the given session. */
  trigger(sessionId: number): Promise<void>;
  intervalMs?: number;
  /** Diagnostics sink; defaults to no output. Never trusted to not throw. */
  log?(line: string): void;
}

export interface RunningWatchdog {
  stop(): void;
  /** Test-only (`__` prefix): run one tick synchronously-awaitable. */
  __tick(): Promise<TickResult | null>;
}

/**
 * Minimum ticks between two log lines about the same standing condition (60 =
 * ~1 hour at the default interval).
 *
 * Every condition the watchdog reports is a STANDING one, not an edge: a broken
 * probe stays broken, unreadable sessions stay unreadable, and a machine
 * migrated from a per-user (<= 1.0.14) install autostarts its %LOCALAPPDATA%
 * copy, whose processes are permanent `tray-lookalikes`. Logged once a tick,
 * that is ~1440 lines a day and a 1 MiB rotation every few days — which
 * contradicts both the "a handful of lines a day" sizing in
 * win-watchdog-logfile.ts and the "silence is normal" contract operators are
 * told to rely on.
 */
const REPEATED_OBSERVATION_LOG_EVERY = 60;

/**
 * The throttle above, as a small piece of state per condition. `hit` returns how
 * many consecutive ticks the condition has now been observed for when this one
 * should be logged, or null to stay silent; `clear` is called on a tick where
 * the condition does not hold.
 *
 * IT BOUNDS THE RATE, NOT REPEATS OF AN IDENTICAL VALUE — that distinction is
 * the whole point. The first version keyed on the observed value and logged
 * immediately whenever the key differed from the last one, which reads as "a
 * change is never delayed" and IS that, right up until the key is something an
 * unprivileged user picks. `unverifiedTrayProcesses` is exactly that: anybody
 * can run a renamed `AICommander.exe`, so a count oscillating 3 → 4 → 3 → 4
 * differed on every tick and logged on every tick — the once-a-minute spam the
 * throttle was added to stop, undiminished, and one line a minute into a
 * SYSTEM-written file every local user can read. Clearing had the same hole from
 * the other side: a condition that alternates present/absent cleared the state
 * and logged again every second tick, so an attacker only had to stop and start.
 *
 * So: at most ONE line per condition per REPEATED_OBSERVATION_LOG_EVERY ticks,
 * counting the ticks where the condition was absent too. What that costs is
 * latency, not information — the line carries the CURRENT count or reason, not
 * the one that was first seen — and what it buys is a bound nothing outside this
 * process can raise. A condition that has been quiet for the whole window is
 * still reported at once when it comes back, which is what makes an incident
 * visible while it is happening.
 */
function createLogThrottle(): {
  hit(): number | null;
  clear(): void;
} {
  /** Consecutive ticks the condition has held; reset by `clear`. */
  let observations = 0;
  /**
   * Ticks since the last line, capped so it cannot grow without bound. Starts AT
   * the limit so the very first observation is logged.
   */
  let sinceLog = REPEATED_OBSERVATION_LOG_EVERY;
  return {
    hit(): number | null {
      observations += 1;
      sinceLog += 1;
      if (sinceLog < REPEATED_OBSERVATION_LOG_EVERY) return null;
      sinceLog = 0;
      return observations;
    },
    clear(): void {
      observations = 0;
      // Quiet ticks still count toward the budget: without this, a condition an
      // unprivileged user toggles on and off would be "new" on every second tick.
      if (sinceLog < REPEATED_OBSERVATION_LOG_EVERY) sinceLog += 1;
    },
  };
}

/**
 * Start the watchdog loop. Ticks are chained with setTimeout (never setInterval)
 * so a slow probe can't stack overlapping ticks, and the timer is unref'd so the
 * watchdog alone never keeps the process alive.
 *
 * NOTHING in here may take the process down. The helper's other half is the
 * elevated-exec IPC endpoint, the task that hosts it has a finite RestartCount 3,
 * and an unhandled rejection terminates Node under its default policy — so a
 * supervisor that dies on a logging failure is strictly worse than one that skips
 * a tick. Hence: the whole tick body is guarded, the caller's `log` is called
 * through a swallowing wrapper, and the scheduling chain cannot reject.
 */
export function startWindowsWatchdog(deps: WatchdogDeps): RunningWatchdog {
  const state = createWatchdogState();
  const intervalMs = deps.intervalMs ?? WATCHDOG_INTERVAL_MS;
  const rawLog = deps.log ?? ((): void => {});
  const log = (line: string): void => {
    try {
      rawLog(line);
    } catch {
      // A log sink is a disk write; disks fill up, and a full disk must not stop
      // the watchdog (nor kill the IPC endpoint sharing this process).
    }
  };
  let stopped = false;
  let timer: NodeJS.Timeout | null = null;
  // One throttle per standing condition, so a change in any of them is still
  // reported at once while none of them can write a line a minute forever.
  const probeFailures = createLogThrottle();
  const skippedSessions = createLogThrottle();
  const trayLookalikes = createLogThrottle();
  const shellLookalikes = createLogThrottle();
  const installManifest = createLogThrottle();
  const staleInstallPath = createLogThrottle();

  async function tick(): Promise<TickResult | null> {
    let probed: ProbeResult;
    try {
      probed = await deps.probe();
    } catch {
      // A failed probe is NOT evidence that anything needs recovering: skip the
      // tick entirely rather than act on a partial picture. The reason is coded,
      // never the thrown message — see ProbeFailureReason.
      probed = { ok: false, reason: "threw" };
    }
    if (!probed.ok) {
      const consecutive = probeFailures.hit();
      if (consecutive !== null) {
        log(formatWatchdogLine({ kind: "probe-failed", reason: probed.reason, consecutive }));
      }
      return null;
    }
    probeFailures.clear();
    const snapshot = probed.snapshot;

    // Fail-closed drops are invisible by construction — a session that cannot be
    // read simply is not there — so they are the one thing that must be said out
    // loud, or "nobody is ever recovered on this machine" looks like health.
    // Both are STANDING conditions, hence the same hourly throttle the probe
    // failures get. The throttle bounds the RATE and does not key on the count:
    // `unverifiedTrayProcesses` is picked by whoever runs a renamed exe, so a
    // count-keyed throttle logged on every tick as soon as the count oscillated.
    // The line always carries the count observed NOW.
    if (snapshot.skippedSessions > 0) {
      if (skippedSessions.hit() !== null) {
        log(formatWatchdogLine({ kind: "sessions-skipped", count: snapshot.skippedSessions }));
      }
    } else {
      skippedSessions.clear();
    }
    // The SAME COUNT, two different stories, and telling them apart is the whole
    // point of the branch. `unverifiedTrayProcesses` means "named like the tray,
    // not running from the directory we measure". Usually that is a stale
    // per-user (<= 1.0.14) install or somebody running a renamed binary — a
    // lookalike. But when the directory we measure holds no tray exe AT ALL, the
    // likelier reading is the opposite one: the Relaunch task's pinned path is
    // stale (a recovery that hand-extracted the app instead of re-running the
    // installer), we are measuring a directory that no longer exists, and those
    // "impostors" are the real, healthy tray. Reporting that as
    // `tray-lookalikes` sends an operator hunting for a rogue binary; reporting
    // it as `tray-exe-missing` (which is what blocks, unchanged) sends them
    // hunting for an install that is sitting one directory over.
    //
    // NEITHER BRANCH CHANGES WHAT THE WATCHDOG DOES. The machine is already
    // blocked by `tray-exe-missing` whenever the stale branch is taken, so this
    // count — which any unprivileged user can raise — still gates nothing. See
    // looksLikeStaleInstallPath for why the repair is deliberately not here.
    const stalePath = looksLikeStaleInstallPath(snapshot);
    if (stalePath) {
      trayLookalikes.clear();
      if (staleInstallPath.hit() !== null) {
        log(
          formatWatchdogLine({
            kind: "install-path-stale",
            count: snapshot.unverifiedTrayProcesses,
          }),
        );
      }
    } else if (snapshot.unverifiedTrayProcesses > 0) {
      staleInstallPath.clear();
      if (trayLookalikes.hit() !== null) {
        log(
          formatWatchdogLine({ kind: "tray-lookalikes", count: snapshot.unverifiedTrayProcesses }),
        );
      }
    } else {
      staleInstallPath.clear();
      trayLookalikes.clear();
    }

    // What the install manifest has to say this tick — the 2026-09-02 damage
    // verdict, or the "N entries could not be read" that used to be silence, or
    // nothing. Taken from the SNAPSHOT, not `blockedBy`: that reports the FIRST
    // matching reason, so a sweep that also took the exe would be logged as
    // `tray-exe-missing`, the less informative half of the same story. One
    // throttle for both — one condition; the branch is win-watchdog-install-log.ts.
    const manifestLine = installManifestEvent(snapshot.install);
    if (manifestLine !== null) {
      if (installManifest.hit() !== null) log(formatWatchdogLine(manifestLine));
    } else {
      installManifest.clear();
    }
    // Same shape, for the shell candidates the probe declined to pay a
    // GetOwnerSid for. A standing non-zero count is somebody running binaries
    // named explorer.exe from outside the Windows directory — harmless now that
    // they buy no work, but it must not be silent: an empty session list looks
    // exactly like an idle machine.
    if (snapshot.unverifiedSessionShells > 0) {
      if (shellLookalikes.hit() !== null) {
        log(
          formatWatchdogLine({
            kind: "shell-lookalikes",
            count: snapshot.unverifiedSessionShells,
          }),
        );
      }
    } else {
      shellLookalikes.clear();
    }

    const result = evaluateTick(state, snapshot);
    for (const target of result.trigger) {
      // Every attempt says how many have not taken and when the next one is due —
      // a watchdog that has quietly given up is its own failure mode, so the
      // backoff must be visible in the log, not just in the state map.
      log(
        formatWatchdogLine({
          kind: "relaunch",
          sessionId: target.sessionId,
          userSid: target.userSid,
          attempt: target.attempt,
          flaps: target.flaps,
          nextDueTick: target.nextDueTick,
          atBackoffCeiling: target.atBackoffCeiling,
        }),
      );
      if (target.attempt > 1 || target.flaps > 1) {
        log(
          formatWatchdogLine({
            kind: "relaunch-escalating",
            sessionId: target.sessionId,
            userSid: target.userSid,
            attempt: target.attempt,
            flaps: target.flaps,
            atBackoffCeiling: target.atBackoffCeiling,
          }),
        );
      }
      try {
        await deps.trigger(target.sessionId);
      } catch {
        // Coded, never quoted: the thrown text comes from a child process and can
        // quote anything it read.
        log(
          formatWatchdogLine({
            kind: "relaunch-failed",
            sessionId: target.sessionId,
            userSid: target.userSid,
            attempt: target.attempt,
          }),
        );
      }
    }
    return result;
  }

  /** Never rejects, whatever the probe, the decision or the log sink do. */
  async function guardedTick(): Promise<TickResult | null> {
    try {
      return await tick();
    } catch {
      return null;
    }
  }

  function schedule(): void {
    if (stopped) return;
    timer = setTimeout(() => {
      // guardedTick never rejects, and `then(schedule, schedule)` re-arms in both
      // directions; the trailing catch exists so that even a throwing schedule()
      // cannot become an unhandled rejection and kill the helper process.
      void guardedTick()
        .then(schedule, schedule)
        .catch(() => undefined);
    }, intervalMs);
    timer.unref?.();
  }

  schedule();

  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
    },
    __tick: guardedTick,
  };
}
