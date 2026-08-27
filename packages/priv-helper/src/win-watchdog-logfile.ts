// The watchdog's log FILE — the impure half of win-watchdog-log.ts.
//
// WHY IT EXISTS. The watchdog's whole diagnostic channel used to be
// process.stdout.write, and the helper is hosted by a scheduled task with no
// redirection, so every line went straight to the bit bucket. That is worse than
// no logging, because the design leans on it: a watchdog that has quietly
// stopped trying looks exactly like a machine with nothing to do, and on a real
// box there was no way to tell a working watchdog from one that had been blocked
// on `tray-exe-missing` since installation.
//
// WHERE. %ProgramData%\AICommander\watchdog.log — next to the updater's
// update.log (desktop/build/win-updater.ps1), which is where anyone debugging
// this app already looks. Written as SYSTEM, world-readable: hence the absolute
// rule in win-watchdog-log.ts that nothing user-controlled is ever put in it.
//
// HARDENING. Any user can pre-create %ProgramData%\AICommander — or any part of
// the path above it — before we ever run, so both the FILE and the DIRECTORY
// CHAIN are hostile input to an elevated writer.
//
//   * The file. A pre-existing watchdog.log may be a symlink or a hardlink
//     planted so that our appends land in a file of somebody else's choosing, so
//     anything that is not a plain, single-linked regular file is removed first.
//     Opening then re-checks the object we actually hold against the one we
//     looked at (same device + inode), which closes the lstat→open swap race.
//     `fstat` alone cannot: it describes the file we opened, and says nothing
//     about the DIRECTORIES we walked to reach it.
//   * The chain. That is why every component of the path is validated, not just
//     the leaf: a junction planted at `%ProgramData%\AICommander` (or higher)
//     redirects an unimpeachable-looking open into a directory the planter owns.
//     Each component must already be a real directory that is not a link, or not
//     exist at all — in which case we create it ourselves, non-recursively, so
//     it inherits its parent's admin-owned ACL and cannot be a pre-planted
//     object. A component we did not create and cannot vouch for turns logging
//     off.
//
// OWNERSHIP. node:fs answers this on POSIX only (uid/mode), and on Windows it
// synthesises both — so the Windows side asks Windows instead: ONE powershell.exe
// at startup reads the owner SID of every existing component of the chain, and a
// component owned by anything other than SYSTEM (S-1-5-18), Administrators
// (S-1-5-32-544) or TrustedInstaller (the OS servicing identity, which owns the
// drive root on a stock install — see TRUSTED_OWNER_SIDS for the measurement)
// turns file logging off. VERIFICATION, NOT REPAIR: taking
// ownership or rewriting a DACL is a privileged write we do not need, and
// repairing a directory somebody else controls is a harder problem than declining
// it. Losing diagnostics is safe — the watchdog keeps recovering, and stdout
// still carries every line for anyone running the helper by hand.
//
// Compared by SID, never by name: `(Get-Acl $p).Owner` is a LOCALISED string
// ("Administratorzy" on a Polish install), so the check is
// `.GetOwner([System.Security.Principal.SecurityIdentifier]).Value`.
//
// WHAT THIS STILL DOES NOT DO: it reads the OWNER, not the DACL, so a directory
// owned by Administrators but with a loosened ACL is accepted. Do not read the
// paragraph above as more than it says. %ProgramData%\AICommander is also
// re-secured by the updater's Initialize-SecureDirectory — but that runs on each
// RUN of the Update task, whose only trigger is daily at 12:00 with a random
// spread (desktop/build/win-update-task.ps1), so the first run can land up to
// ~24 h after install. Between install and that first run, the owner check here
// is the only thing standing between an elevated appender and a directory an
// unprivileged user pre-created.
//
// When any check cannot be satisfied, logging turns itself off permanently
// rather than writing somewhere unknown — a lost log is an inconvenience, an
// elevated arbitrary-file-append is a vulnerability.
//
// AND IT SAYS SO WHERE SOMEBODY CAN HEAR IT. The refusal used to be announced on
// stdout alone, which a scheduled task with no redirection discards, so "logging
// refused" and "the helper never started" looked identical — the very confusion
// this file exists to remove, reproduced one level up. Every refusal therefore
// also writes ONE Windows Application-log event (in-box eventcreate.exe; see
// WATCHDOG_EVENT_SOURCE and __eventCommandScript). That log is world-readable
// too, so it carries the same payload as watchdog.log and no more: fixed text
// plus a coded reason from a fixed set — never a path, never an owner name,
// never an exception message.
//
// Never throws. A logger that can take the helper down is a worse failure than
// no log at all (see startWindowsWatchdog).

import { spawn, spawnSync } from "node:child_process";
import {
  closeSync,
  type Stats,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join, parse, resolve, sep } from "node:path";

/** Rotate at ~1 MiB, keeping one previous generation. */
export const WATCHDOG_LOG_MAX_BYTES = 1024 * 1024;
export const WATCHDOG_LOG_NAME = "watchdog.log";
/** Rotated generation. One is enough: this file gets a handful of lines a day. */
export const WATCHDOG_LOG_ROTATED_NAME = "watchdog.log.1";

/**
 * %ProgramData%, without trusting the environment more than we have to. The
 * helper's own environment as a SYSTEM scheduled task is minimal (measured: 12
 * variables), so the literal fallback is not theoretical — it is the same
 * belt-and-braces pattern as powershellPath() in win-watchdog-probe.ts.
 */
function programDataDir(): string {
  return process.env["ProgramData"] ?? "C:\\ProgramData";
}

/** Where the log goes; its ownership is verified before anything is written. */
export function watchdogLogDir(): string {
  return join(programDataDir(), "AICommander");
}

/** `lstat`, or null when the name does not exist / cannot be read. */
function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

/**
 * POSIX ownership we are willing to write under. `uid`/`mode` are real there,
 * and the tests that exercise this run on macOS. Windows has its own answer
 * below, because node:fs synthesises both fields there (uid 0, mode 0o666).
 */
function posixOwnershipAcceptable(st: Stats): boolean {
  const us = process.getuid?.();
  if (st.uid !== 0 && us !== undefined && st.uid !== us) return false;
  // Group- or world-writable without the sticky bit means somebody else can
  // replace what is inside it, which defeats everything below.
  return (st.mode & 0o022) === 0 || (st.mode & 0o1000) !== 0;
}

/**
 * The only owners an elevated appender may inherit a directory from. SIDs, never
 * names: `(Get-Acl $p).Owner` is localised (a Polish install says
 * "Administratorzy"), and a name comparison there fails open on every
 * non-English machine.
 */
const TRUSTED_OWNER_SIDS = new Set([
  // ZARZĄDZANIE NT\SYSTEM — LocalSystem, the identity the helper itself runs as.
  "s-1-5-18",
  // BUILTIN\Administratorzy.
  "s-1-5-32-544",
  // NT SERVICE\TrustedInstaller — see the measurement below.
  "s-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
]);

// MEASURED on aic-pc (Windows x64, Polish locale, stock install) on 2026-08-09,
// under the identity this code actually runs as — `ZARZĄDZANIE NT\SYSTEM`, via
// the privileged helper. Owner SIDs of the paths this module can walk:
//
//   C:\                        s-1-5-80-956008885-...-2271478464  TrustedInstaller
//   C:\ProgramData             s-1-5-18                           SYSTEM
//   C:\ProgramData\AICommander s-1-5-32-544                       Administrators
//   C:\Program Files           s-1-5-80-956008885-...-2271478464  TrustedInstaller
//
// The list above USED to be {SYSTEM, Administrators} with a note saying to
// measure it before shipping. The measurement says that set is wrong: the DRIVE
// ROOT of a normal Windows machine is owned by TrustedInstaller, so prepareLogDir
// returned `chain-owner` and file logging was off on every stock box — invisibly,
// because the refusal goes to stdout and the scheduled task that hosts the helper
// discards stdout, which is the exact failure this whole file exists to remove.
//
// HARDCODING THE SERVICE SID IS SAFE. An `S-1-5-80-…` service SID is derived by
// hash from the UPPERCASED service name, not issued per machine, so this value is
// identical on every Windows installation. Verified on the box:
//   (New-Object System.Security.Principal.NTAccount('NT SERVICE\TrustedInstaller'))
//     .Translate([System.Security.Principal.SecurityIdentifier]).Value
// returned exactly the SID above — i.e. name-derived, not machine-specific.
//
// WHY TrustedInstaller QUALIFIES: it is the OS servicing identity, it is
// admin-equivalent for the paths it owns (only it and Administrators can write
// there), and a chain component it owns is one no unprivileged user planted. NOT
// because it is "well known". Do NOT widen this to "any well-known SID" — most of
// them (Users, Everyone, Authenticated Users, INTERACTIVE) are exactly the
// identities the check exists to reject — and do NOT take ownership of anything:
// verification, not repair (see the header).
//
// If a future box shows `reason=chain-owner`, the fix is the same one applied
// here: measure the owner, establish that it is admin-equivalent and that its SID
// is constant across installations, and add THAT SID.

/**
 * Owner SID per path, in the order asked, or null if the question could not be
 * put at all. An entry is null when THAT path's owner could not be read.
 */
export type OwnerSidLookup = (paths: string[]) => (string | null)[] | null;

/**
 * powershell.exe by FULL path — this process is LocalSystem and PATH is not ours
 * to trust. Same reasoning, and the same literal fallback, as
 * win-watchdog-probe.ts's powershellPath().
 */
function powershellPath(): string {
  const root = process.env["SystemRoot"] ?? "C:\\Windows";
  return `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
}

/**
 * Ask Windows who owns each path, in ONE process. This runs once at helper
 * startup, not per tick, so a single spawn is the whole cost.
 *
 * The paths are handed over as UTF-16 base64 and decoded inside the script, so
 * nothing about a path — quotes, `$`, a newline — can be re-read as script. (The
 * script itself is then base64'd again by -EncodedCommand, for the same reason
 * the probe does it: the Windows command line cannot re-interpret one opaque
 * token.)
 */
function windowsOwnerSids(paths: string[]): (string | null)[] | null {
  const literals = paths
    .map((p) => `'${Buffer.from(p, "utf16le").toString("base64")}'`)
    .join(",");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    `$encoded = @(${literals})`,
    "foreach ($e in $encoded) {",
    "  $sid = ''",
    "  try {",
    "    $p = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($e))",
    "    $acl = Get-Acl -LiteralPath $p",
    "    $sid = [string]$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
    "  } catch { $sid = '' }",
    "  [Console]::Out.WriteLine($sid)",
    "}",
  ].join("\n");
  try {
    const run = spawnSync(
      powershellPath(),
      [
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        Buffer.from(script, "utf16le").toString("base64"),
      ],
      { encoding: "utf8", timeout: 30_000, windowsHide: true, maxBuffer: 256 * 1024 },
    );
    if (run.error || run.status !== 0 || typeof run.stdout !== "string") return null;
    const lines = run.stdout.split(/\r?\n/);
    // One trailing newline is the writer's, not an answer.
    if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    // A short or long reply is an answer we cannot line up with the paths, and
    // guessing which is which is exactly the mistake this check exists to avoid.
    if (lines.length !== paths.length) return null;
    return lines.map((l) => (l.trim() === "" ? null : l.trim()));
  } catch {
    return null;
  }
}

/**
 * Every component of `dir`, root first: "C:\\", "C:\\ProgramData",
 * "C:\\ProgramData\\AICommander". The chain is what has to be validated — see
 * the header — so it has to be enumerated.
 */
function pathChain(dir: string): string[] {
  const absolute = resolve(dir);
  const root = parse(absolute).root;
  const chain: string[] = [root];
  let current = root;
  for (const part of absolute.slice(root.length).split(sep)) {
    if (part === "") continue;
    current = join(current, part);
    chain.push(current);
  }
  return chain;
}

/** Why file logging refused. Coded, and the only thing ever reported about it. */
export type LogDirRefusal =
  /** A component is a symlink or junction — the redirection this all exists for. */
  | "chain-link"
  /** A component exists and is not a directory. */
  | "chain-not-directory"
  /** A component is owned by somebody we will not inherit a directory from. */
  | "chain-owner"
  /** The owner could not be established at all, so nothing vouches for the chain. */
  | "owner-unknown"
  /** A missing component could not be created (or something raced us to it). */
  | "create-failed";

/**
 * Every reason file logging can end up OFF — the refusals above plus the two
 * failures of the file itself. This is the complete input domain of disable(),
 * and it is an explicit SET (below) rather than a regex, because it is what
 * reaches a world-readable Windows event log.
 */
export type WatchdogLogDisableReason =
  | LogDirRefusal
  /** The leaf could not be opened (or re-opened after a rotation). */
  | "open-failed"
  /** An append failed — a full disk, a revoked handle. */
  | "write-failed";

/**
 * THE allowlist. Anything not in it is reported as `unknown`, so a future
 * caller cannot widen what leaves this process by inventing a code — the same
 * discipline as win-watchdog-log.ts, one notch stricter (a fixed set, not a
 * shape). Nothing observed — no path, no owner name, no exception text — is
 * ever a member, and members are the ONLY variable part of an event.
 *
 * Exported so the tests can DERIVE their coverage from it instead of restating
 * it: win-watchdog-log.test.ts fails until every member is provoked end to end,
 * so a reason added here without a test fails immediately rather than sitting
 * uncovered (which is how `write-failed` came to have no test at all).
 */
export const DISABLE_REASONS: ReadonlySet<WatchdogLogDisableReason> =
  new Set<WatchdogLogDisableReason>([
    "chain-link",
    "chain-not-directory",
    "chain-owner",
    "owner-unknown",
    "create-failed",
    "open-failed",
    "write-failed",
  ]);

/**
 * The Application-log event this module emits when file logging turns off.
 *
 * MEASURED on aic-pc (Windows x64, Polish locale) on 2026-08-09 as LocalSystem,
 * the identity the helper really runs as: the invocation below exited 0 and the
 * source was created by eventcreate.exe itself on first use, so there is nothing
 * to register at install time.
 *
 *   eventcreate.exe /L APPLICATION /SO AICommanderWatchdog /T WARNING /ID 900
 *                   /D 'reason=chain-owner'
 *
 * The values are inside eventcreate's contract: /L takes APPLICATION or SYSTEM,
 * /T takes SUCCESS|ERROR|WARNING|INFORMATION, and /ID must be 1-1000 — 900 is in
 * range. WARNING rather than ERROR because nothing is broken for the USER: the
 * watchdog goes on supervising and recovering, only its diagnostics are off.
 *
 * The level's DISPLAY name is localised ("Ostrzeżenia" on the measured box), so
 * anything reading these back must filter on ProviderName + Id, never on the
 * level text. See OPERATIONS.md for the Get-WinEvent recipe.
 */
export const WATCHDOG_EVENT_SOURCE = "AICommanderWatchdog";
export const WATCHDOG_EVENT_ID = 900;
export const WATCHDOG_EVENT_LEVEL = "WARNING";

/**
 * How long the reporter's powershell.exe may live once it has started. It is a
 * failure path at startup, so the event is worth a cold start (seconds on a
 * loaded box) and nothing more.
 *
 * NOT spawn's own `timeout` option, and that is the entire point of the code
 * below. MEASURED on this machine (macOS, node v24.5.0): a child spawned with
 * `{ stdio: "ignore", timeout: 3000 }` running `sh -c "sleep 30"`, with
 * `child.on("error")` attached and `child.unref()` called, kept the PARENT
 * process alive for 3006 ms after its last work — the option arms a REF'd timer
 * that `unref()` does not cover. At 15 s that is a helper that cannot exit or
 * restart for 15 s while one powershell.exe is stuck, under a task with
 * RestartCount 3. Re-measured with the timer kept by hand (`setTimeout(...)`,
 * `.unref()`, explicit `child.kill()`): the parent exits 2 ms after its last
 * work. win-watchdog-event-lifetime.test.ts re-runs BOTH measurements — the
 * subject and, as its control, the `spawn({ timeout })` form. Not
 * win-watchdog-event.test.ts, which mocks node:child_process wholesale and
 * therefore spawns nothing and times nothing.
 *
 * What the hand-kept deadline does NOT do, stated so nobody reads more into it:
 * an unref'd timer does not keep the process alive to fire, so a stuck child
 * outlives a helper that exits first and is left to the OS. That is the trade
 * being made — bounding OUR lifetime matters, bounding a lost event's does not.
 */
const EVENT_REPORT_TIMEOUT_MS = 15_000;

/**
 * The script that writes the event. Pure and exported for tests (`__` prefix,
 * as in win-watchdog-probe.ts): there is no Windows here, but WHAT would be run
 * is exactly what has to be pinned — a fixed literal command plus one coded
 * reason, and no environment anywhere.
 *
 * WHY POWERSHELL AND NOT eventcreate.exe DIRECTLY. eventcreate must be invoked
 * by full path (this process is LocalSystem; PATH is not ours to trust), and the
 * only trustworthy source for that path is the API — %SystemRoot% out of the
 * environment is exactly the bug the header's ProfileImagePath note is about,
 * and the SYSTEM environment is stripped (measured: 12 variables). Node exposes
 * no binding for the system directory, so the one process that can ask
 * [System.Environment]::GetFolderPath('System') asks it and invokes what it
 * finds. GetFolderPath('System'), not ('Windows') + 'system32': the former IS
 * the system directory (measured: C:\WINDOWS\system32), the latter would make us
 * guess a subdirectory name.
 */
export function __eventCommandScript(reason: WatchdogLogDisableReason): string {
  // The allowlist, applied at the boundary: a code we do not know becomes a
  // fixed literal, so the script text is always fixed text plus a known token.
  const code = DISABLE_REASONS.has(reason) ? reason : "unknown";
  return [
    "$ErrorActionPreference = 'Stop'",
    "try {",
    "  $sys = [string][System.Environment]::GetFolderPath('System')",
    "  if ($sys) {",
    "    $exe = Join-Path $sys 'eventcreate.exe'",
    `    & $exe /L APPLICATION /SO ${WATCHDOG_EVENT_SOURCE} /T ${WATCHDOG_EVENT_LEVEL}` +
      ` /ID ${WATCHDOG_EVENT_ID} /D 'watchdog log-file disabled reason=${code}' | Out-Null`,
    "  }",
    "} catch { }",
  ].join("\n");
}

/**
 * Start a child nothing ever waits for, and that cannot keep this process alive
 * — not while it runs, and not through the deadline that bounds it.
 *
 * Exported (`__` prefix) so win-watchdog-event-lifetime.test.ts can prove that
 * property by RUNNING it in a child node process and timing the exit — that file
 * exists separately from win-watchdog-event.test.ts for exactly this reason. A mocked
 * child_process cannot observe an event-loop handle at all, which is precisely
 * how `spawn({ timeout })` held the helper open under a green suite — see
 * EVENT_REPORT_TIMEOUT_MS for both measurements. It takes program and args so
 * the proof can use a portable long-lived command instead of powershell.exe.
 */
export function __spawnUnheldChild(program: string, args: string[]): void {
  try {
    const child = spawn(program, args, { stdio: "ignore", windowsHide: true });
    // Without this an ENOENT is thrown at the process, asynchronously, where no
    // try/catch of ours can see it.
    child.on("error", () => {});
    // The deadline, kept by hand rather than by spawn's `timeout` option, which
    // arms a REF'd timer (measured — see EVENT_REPORT_TIMEOUT_MS).
    const deadline = setTimeout(() => {
      try {
        child.kill();
      } catch {
        // A child that has already gone needs no killing.
      }
    }, EVENT_REPORT_TIMEOUT_MS);
    deadline.unref();
    child.on("exit", () => clearTimeout(deadline));
    child.unref();
  } catch {
    // A spawn that fails synchronously is one lost event, nothing more.
  }
}

/**
 * Say — through a channel a scheduled task with no redirection cannot swallow —
 * that file logging is off, and why. Windows only; a no-op everywhere else.
 *
 * IT MUST NOT BE ABLE TO HURT THE HELPER. This runs on a failure path while the
 * watchdog is trying to log something: the child is asynchronous (nothing
 * blocks), unref'd along with its own deadline (measured: the helper exits 2 ms
 * after its last work with a stuck child still running), stdio-less, and every
 * error — a failed spawn, a non-zero exit, a missing eventcreate — is swallowed.
 * A failure to report a failure is not worth an outage.
 *
 * The production default of WatchdogLogFileOptions.eventReport; exported only so
 * win-watchdog-event.test.ts can inspect WHAT it would run (the `__` prefix, as
 * in win-watchdog-probe.ts, marks an export that exists for tests).
 */
export function __windowsEventReport(reason: WatchdogLogDisableReason): void {
  // Impossible to execute off Windows, whatever a caller passes: the platform
  // seam below decides whether to CALL this, and this decides whether to run.
  if (process.platform !== "win32") return;
  __spawnUnheldChild(powershellPath(), [
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    Buffer.from(__eventCommandScript(reason), "utf16le").toString("base64"),
  ]);
}

/** Reports a refusal out of band. Injectable exactly like the owner lookup. */
export type DisableEventReporter = (reason: WatchdogLogDisableReason) => void;

interface LogDirChecks {
  platform: NodeJS.Platform;
  ownerSids: OwnerSidLookup;
}

/**
 * Make `dir` safe to write into, or say why it is not: no component may be a
 * link or a non-directory, every EXISTING component must be owned by somebody we
 * trust, and a missing one is created by us rather than accepted from whoever
 * got there first. Returns null on success.
 *
 * Order matters. Structure is checked first, because a link must never be handed
 * to the owner lookup — Get-Acl would resolve it and answer about the target,
 * i.e. about a directory we are refusing to write into anyway. Ownership is then
 * asked for every existing component in ONE call, before any of them is used or
 * anything is created below them.
 */
function prepareLogDir(dir: string, checks: LogDirChecks): LogDirRefusal | null {
  try {
    const chain = pathChain(dir);
    const stats = chain.map((step) => lstatOrNull(step));

    for (const st of stats) {
      if (st === null) continue;
      // isDirectory() is false for a symlink, but say both: a junction to a
      // directory is the case this exists for, and the intent should be legible.
      if (st.isSymbolicLink()) return "chain-link";
      if (!st.isDirectory()) return "chain-not-directory";
    }

    if (checks.platform === "win32") {
      const existing = chain.filter((_, i) => stats[i] !== null);
      const owners = existing.length === 0 ? [] : checks.ownerSids(existing);
      // No answer is not "acceptable": an unverifiable chain turns logging off,
      // which costs diagnostics and nothing else.
      if (owners === null || owners.length !== existing.length) return "owner-unknown";
      for (const owner of owners) {
        if (owner === null) return "owner-unknown";
        if (!TRUSTED_OWNER_SIDS.has(owner.toLowerCase())) return "chain-owner";
      }
    } else {
      for (const st of stats) {
        if (st !== null && !posixOwnershipAcceptable(st)) return "chain-owner";
      }
    }

    for (let i = 0; i < chain.length; i++) {
      if (stats[i] !== null) continue;
      // Non-recursive on purpose: it throws (→ create-failed) if something
      // appeared in the meantime, so we never adopt a directory we did not
      // create — including one planted between the checks above and this line.
      mkdirSync(chain[i]!);
    }
    return null;
  } catch {
    return "create-failed";
  }
}

/**
 * Open the log for appending, refusing anything that is not a plain file we
 * exclusively own. Returns null when logging must stay off.
 *
 * Assumes prepareLogDir() has vouched for the directory chain: this function
 * only guards the leaf, and `fstat` on the leaf cannot see a redirection that
 * happened in a parent.
 */
function openLogFile(path: string): number | null {
  try {
    // A symlink/junction, a directory, or extra hardlinks: all mean our writes
    // could land somewhere else. Remove the name and start clean — we own the
    // file name, not whatever a user planted under it.
    let existing = lstatOrNull(path);
    if (existing && (!existing.isFile() || existing.isSymbolicLink() || existing.nlink > 1)) {
      unlinkSync(path);
      existing = null;
    }
    if (existing === null) {
      // Exclusive create: if anything raced us to the name after the check
      // above, this throws instead of appending into whatever they left.
      return openSync(path, "ax");
    }
    const fd = openSync(path, "a");
    // Re-check the object we actually hold, not the name we looked at: between
    // the lstat and the open, the name could have been replaced. Comparing
    // device+inode is what makes this a check rather than a formality — the
    // replacement would also be a plain single-linked file.
    const held = fstatSync(fd);
    const sameObject = held.dev === existing.dev && held.ino === existing.ino;
    if (!held.isFile() || held.nlink > 1 || !sameObject) {
      closeSync(fd);
      return null;
    }
    return fd;
  } catch {
    return null;
  }
}

/**
 * Test seams. Production passes none of these: the platform is this one, the
 * owner lookup is the real Windows one, the notice goes to stdout and the event
 * goes to the Windows Application log.
 *
 * HOW A REFUSAL IS OBSERVED — two channels, because the first one only exists
 * for half the audience. `notice` is stdout, which is a real channel ONLY for
 * somebody running the helper by hand: in production the helper is hosted by a
 * scheduled task with no redirection, so every stdout line is discarded. That
 * made a refusal — the thing that turns file logging off machine-wide —
 * indistinguishable from "the helper never started", which is precisely the
 * confusion this module exists to remove. So on Windows the refusal ALSO goes to
 * the Application event log, as source WATCHDOG_EVENT_SOURCE, id
 * WATCHDOG_EVENT_ID, carrying the coded reason and fixed text only; the log is
 * world-readable, exactly like watchdog.log, and the same rule applies to both.
 * OPERATIONS.md has the Get-WinEvent recipe for reading it back.
 *
 * At most ONE event per helper process: disable() latches, so a wedged machine
 * produces one event per START of the helper, not one per tick.
 */
export interface WatchdogLogFileOptions {
  platform?: NodeJS.Platform;
  ownerSids?: OwnerSidLookup;
  notice?: (message: string) => void;
  eventReport?: DisableEventReporter;
}

/**
 * A line sink that appends to %ProgramData%\AICommander\watchdog.log, rotating
 * at WATCHDOG_LOG_MAX_BYTES. The returned function never throws; after an
 * unrecoverable failure it becomes a no-op for the life of the process — having
 * first said, ONCE, why. Silence there would be the same bug the whole module is
 * about: "no log file" and "nothing to log" must not look alike.
 *
 * `dir` is injectable for tests only — production always uses watchdogLogDir().
 */
export function createWatchdogLogFile(
  dir: string = watchdogLogDir(),
  options: WatchdogLogFileOptions = {},
): (line: string) => void {
  const path = join(dir, WATCHDOG_LOG_NAME);
  const rotated = join(dir, WATCHDOG_LOG_ROTATED_NAME);
  const checks: LogDirChecks = {
    platform: options.platform ?? process.platform,
    ownerSids: options.ownerSids ?? windowsOwnerSids,
  };
  const notice =
    options.notice ??
    ((message: string): void => {
      try {
        process.stdout.write(`${message}\n`);
      } catch {
        // A closed stdout must not take the helper down either.
      }
    });
  const eventReport = options.eventReport ?? __windowsEventReport;
  let fd: number | null = null;
  let disabled = false;

  /**
   * Turn logging off for good, saying why — a coded reason and nothing else, on
   * both channels. Called at most once: it latches `disabled`, and every path
   * into it checks that first, so the event log gets one event per helper
   * process however long the machine stays wedged.
   */
  function disable(reason: WatchdogLogDisableReason): false {
    disabled = true;
    try {
      notice(`watchdog log-file disabled reason=${reason}`);
    } catch {
      // A sink that throws is not a reason to stop watching the machine.
    }
    // Windows only, decided here rather than inside the reporter so the seam is
    // the same one the owner lookup uses (and so an injected reporter is held to
    // the same rule).
    if (checks.platform === "win32") {
      try {
        eventReport(reason);
      } catch {
        // Reporting the failure must never become a second failure.
      }
    }
    return false;
  }

  function ensureOpen(): boolean {
    if (disabled) return false;
    if (fd !== null) return true;
    // The chain first, then the leaf: a validated file inside a redirected
    // directory is not a validated file.
    const refused = prepareLogDir(dir, checks);
    if (refused !== null) return disable(refused);
    fd = openLogFile(path);
    if (fd === null) return disable("open-failed");
    return true;
  }

  function rotateIfNeeded(): void {
    if (fd === null) return;
    try {
      if (fstatSync(fd).size < WATCHDOG_LOG_MAX_BYTES) return;
      closeSync(fd);
      fd = null;
      // renameSync replaces the previous generation atomically, so the cap is on
      // the pair — the watchdog can never grow ProgramData without bound, and
      // the previous run's evidence survives one rotation.
      renameSync(path, rotated);
      fd = openLogFile(path);
      if (fd === null) disable("open-failed");
    } catch {
      disable("open-failed");
      fd = null;
    }
  }

  return (line: string): void => {
    if (!ensureOpen()) return;
    rotateIfNeeded();
    if (fd === null) return;
    try {
      writeSync(fd, `${line}\n`);
    } catch {
      // A full disk or a revoked handle must not stop the watchdog; stop
      // logging — and SAY SO. This used to set the flag silently, which is the
      // same "the log is off and the log cannot tell you why" state as every
      // refusal above, reached from the other end.
      disable("write-failed");
      try {
        closeSync(fd);
      } catch {
        // Nothing left to do about a descriptor we cannot close.
      }
      fd = null;
    }
  };
}
