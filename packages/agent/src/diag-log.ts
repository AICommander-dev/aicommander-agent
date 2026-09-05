import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { JOB_ID_PATTERN, maskSessionCode } from "@aicommander/protocol";
import { ensurePrivateDir, PRIVATE_FILE_MODE } from "./atomic-file.js";
import { envConfigDir } from "./config-dir.js";

/**
 * The agent's diagnostic log — the one place the product can describe its own
 * failure.
 *
 * Written by BOTH hosts of the agent runtime (the headless CLI and the Electron
 * tray app) so a support case gets the same record either way. It exists because
 * of the 2026-09-02 Bitdefender event: an agent that was running, disconnected
 * and completely silent — no log file anywhere, `--enable-logging --v=1` on the
 * desktop app produced nothing but Chromium's own noise — so "was the ws-ticket
 * exchange failing, and with what status?" cost an hour of black-box observation
 * to answer. Every event in DiagEvent below is one question we could not answer
 * that day.
 *
 * ── REDACTION RULE (a correctness requirement, not hygiene) ───────────────────
 * These files get pasted into support tickets and attached to antivirus-vendor
 * submissions. They must NEVER contain:
 *   - the session code (it is a root-exec credential — masked here on sight),
 *   - agent tokens, ws tickets, device secrets, API keys, elevated capability JWS,
 *   - command text, job output, or file paths that came from a caller's payload.
 * Job IDENTIFIERS are the approved way to talk about a job.
 *
 * The API is shaped so violating that is hard by accident rather than by
 * discipline: `diag()` takes an event name from a fixed catalogue plus SCALAR
 * fields only (no objects, no error instances), and every string value is run
 * through `redactDiagText` — which masks session codes, blanks JWS triples and
 * blanks any 32+ char opaque blob (tickets, tokens, secrets) — then truncated.
 * For errors, `errorFields()` extracts the errno `code`/`syscall` and nothing
 * else, because an fs error's MESSAGE embeds the path it failed on.
 *
 * ── NEVER BLOCK, NEVER THROW ─────────────────────────────────────────────────
 * `diag()` only appends a formatted line to an in-memory queue and arms a timer;
 * all I/O happens later, serialized, off the hot path. Nothing here is sync
 * except `initDiagLog`, which runs once at startup. This is not a style
 * preference: a synchronous modal on the desktop main loop once starved the
 * WebSocket heartbeat and wedged the app in "Reconnecting…" (see tray.ts), and a
 * logger on the message path would be the same bug with a wider blast radius. A
 * logging failure degrades to SILENCE — a dropped line is always better than a
 * broken agent, so every failure path here swallows.
 *
 * ── TWO PROCESSES, TWO FILES ─────────────────────────────────────────────────
 * The headless agent is a supervisor that re-execs itself as a worker
 * (AIC_ROLE=worker; see run.ts / supervisor.ts), so two live processes want to
 * log at once. They get SEPARATE files, one per role. The alternative — one
 * shared file — buys a single merged timeline and pays for it twice: O_APPEND
 * atomicity for a whole line is a POSIX-only property that Windows does not
 * promise (and Windows is the platform this whole effort exists for), and
 * rotation is unsynchronized, so one process renames the file the other is
 * appending to and a generation is silently lost. Interleaved half-lines and
 * vanished generations are strictly worse than two files with a shared clock:
 * both stamp UTC ISO timestamps and their own pid, so `sort` merges them
 * whenever a merged view is actually wanted.
 *
 * We deliberately open/close per flush (`fs.promises.appendFile`) rather than
 * holding a write stream: an open handle is exactly what makes a rotation rename
 * fail with EPERM/EBUSY on Windows.
 *
 * ── ADDITIVE ─────────────────────────────────────────────────────────────────
 * This changes no existing console output. In particular the systemd service
 * keeps inheriting stdout into the journal with the session code masked there
 * (see the `inSystemdService` logic in run.ts) — this log is a second, quieter
 * record, never a replacement.
 */

/**
 * Rotate at 512 KiB; keep the live file plus 2 older generations (1.5 MiB cap).
 * One documented exception, at the end of rotate(): a machine that refuses every
 * way of preserving the history lets the live file overshoot rather than delete
 * the only copy of it.
 */
const MAX_FILE_BYTES = 512 * 1024;
const MAX_GENERATIONS = 2;

/**
 * How far past the cap the live file may grow when it holds the ONLY copy of the
 * history — a machine that refuses the rename, the copy AND the truncation all
 * at once. Past this the bound wins and the file is truncated anyway. See the
 * fallback at the end of rotate() for why the overshoot is allowed at all.
 */
const OVERFLOW_MULTIPLE = 4;

/**
 * Lines held in memory awaiting a flush. A queue is only ever this deep when the
 * disk is gone or wedged — precisely when we must not grow without bound — so
 * past it we drop and count, and say so in the log once writing recovers.
 */
const MAX_QUEUE_LINES = 500;

/** Per-value ceiling; a diagnostic field is a fact, never a payload. */
const MAX_VALUE_CHARS = 200;

/** Fields past this on one event are dropped — a guard against accidental dumps. */
const MAX_FIELDS = 12;

/** Which host wrote the line; also the file name (`<role>.log`). */
export type DiagRole = "worker" | "supervisor" | "main";

/**
 * The catalogue of things worth recording. A closed union rather than a free
 * string so that adding an event is a deliberate edit in THIS file, next to the
 * redaction rule above — the moment to ask "what exactly am I about to write?".
 */
export type DiagEvent =
  // Process lifecycle
  | "startup"
  | "shutdown"
  // Registration + connection (the incident's unanswered questions)
  | "conn.register_ok"
  | "conn.register_failed"
  | "conn.device_reset"
  | "conn.ticket_failed"
  | "conn.ticket_error"
  | "conn.ticket_invalid"
  | "conn.ws_open"
  | "conn.ws_close"
  | "conn.ws_error"
  | "conn.ws_upgrade_failed"
  | "conn.retry"
  | "conn.status"
  | "conn.token_rotated"
  | "conn.token_rotate_failed"
  // Jobs — by id only, never command text or output
  | "job.start"
  | "job.refused"
  // A start that THREW rather than returning a refusal: the scripts were taken
  // between our write and the spawn (job_script_removed), an unwritable record,
  // a shell that would not start. The remote caller is told; without this the
  // file that goes into the ticket is not.
  | "job.start_failed"
  | "job.cancel"
  | "job.exit"
  // Our own paths refusing us (EACCES / EPERM / ENOENT)
  | "path.error"
  // Housekeeping the user never sees
  | "autostart.repaired"
  | "autostart.repair_failed"
  | "update.available"
  | "update.none"
  | "update.check_failed"
  // Supervisor ↔ worker
  | "supervisor.worker_spawned"
  | "supervisor.worker_exit"
  | "supervisor.worker_stalled"
  // Startup integrity — does the install still contain the files it shipped
  // with? (desktop/src/integrity.ts against the packaged install-manifest.json).
  // Paths recorded here are our own packaged resource names, never a caller's.
  | "integrity.ok"
  | "integrity.damaged"
  | "integrity.check_failed"
  // Desktop host
  | "desktop.watchdog_restart"
  | "desktop.uncaught"
  | "desktop.unhandled_rejection"
  // The logger talking about itself
  | "diag.dropped";

/**
 * Scalars only. Objects and Error instances are rejected by the type system
 * because that is how command text, env maps and fs error messages (which carry
 * the path they failed on) would otherwise arrive here by accident.
 */
export type DiagValue = string | number | boolean | null | undefined;
export type DiagFields = Record<string, DiagValue>;

interface DiagState {
  role: DiagRole;
  filePath: string;
  maxFileBytes: number;
  size: number;
  queue: string[];
  dropped: number;
  /** The write in flight, so a caller can await it instead of polling. */
  pending: Promise<void> | null;
  timer: ReturnType<typeof setTimeout> | null;
}

let state: DiagState | null = null;

const SESSION_CODE_RE = /\bAIC-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}\b/gi;
// A JWS/JWT triple — the elevated capability's shape. Matched BEFORE the opaque
// blob rule, which would otherwise eat the segments one at a time and hide what
// it was.
const JWS_RE = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
// Any long opaque run: the 64-hex ws ticket, base64url agent tokens and device
// secrets, API keys. 32 is comfortably above every identifier we legitimately
// log (a jobId is 16 hex chars) and below every credential we mint.
const OPAQUE_BLOB_RE = /\b[A-Za-z0-9_-]{32,}\b/g;
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/g;

/**
 * The OS account name, and only that, taken out of every path we write.
 *
 * Paths are worth keeping: "where is this installed", "which data directory did
 * it resolve to" and "which of our own files was refused" are the questions a
 * vendor submission is FOR, and a redaction that dropped paths would take the
 * diagnosis with it. The account name is worth nothing to any of them — and
 * `C:\Users\<name>\…` in the first line of a file we tell people to attach to a
 * third-party ticket is the user's identity leaving the machine.
 *
 * Two rules, in order. First this process's real home directory, replaced with
 * `~`, which covers every layout an OS invents (a relocated Windows profile, a
 * QNAP share, `/var/root`). Then the generic shapes, so that a path belonging to
 * ANOTHER account — an operator's config-dir override, a second user's install —
 * is redacted too, which the first rule alone cannot do.
 *
 * This is not a licence to log a caller's paths: the header's rule stands, and a
 * payload path is still forbidden whatever it looks like. This is what makes OUR
 * paths safe to write down.
 */
const HOME_SEGMENT_RE = /(^|[\s"'=(:,])((?:[A-Za-z]:)?[\\/](?:Users|home)[\\/])([^\\/\s"',)]+)/g;

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * What has to follow a directory prefix for the text to be that directory.
 *
 * Without it `/Users/lukasz` matches inside `/Users/lukaszek/x`, which produces
 * `~ek/x`: the tail of ANOTHER account's name reaches the file, and the path is
 * relabelled as sitting inside our own home — the exact opposite of what the
 * rule above promises. A directory ends at a separator or at the end of the
 * value; anything a filename can continue with means this is a different
 * directory that merely starts with the same letters.
 *
 * UNICODE, NOT ASCII. The first version of this listed `[A-Za-z0-9._~-]`, and a
 * character class is only ever as wide as the alphabets it was written against:
 * with `/Users/lukasz` as home, `/Users/lukaszż/customer` still redacted to
 * `~ż/customer` — the same leak, one character out of reach. Windows and macOS
 * both allow non-ASCII account names, and this codebase has been bitten by an
 * ASCII assumption twice already (a Polish Windows returns localised ACL owner
 * names, which is why owners are compared by SID). So the class is every
 * character a path segment can CONTINUE with — any letter, digit, mark or
 * connector in any script — which is what the sentence above always meant. The
 * matchers built from it carry the `u` flag; they must, or `\p{…}` is read as a
 * literal `p`.
 */
const DIR_BOUNDARY = "(?![\\p{L}\\p{N}\\p{M}\\p{Pc}._~-])";
/** …and the flags every matcher using it needs. See DIR_BOUNDARY. */
const DIR_FLAGS = process.platform === "win32" ? "giu" : "gu";

/** The home directory as a matcher, built once — `os.homedir()` can throw. */
const HOME_DIR_RE: RegExp | null = (() => {
  let home: string;
  try {
    home = os.homedir();
  } catch {
    return null;
  }
  // "/" or a one-segment root is not a home directory worth substituting;
  // doing it anyway would rewrite every absolute path into a bare `~`.
  if (!home || home.length < 4) return null;
  const trimmed = home.replace(/[\\/]+$/, "");
  // Windows paths are case-insensitive, and the case a path reaches us in is
  // not necessarily the case the OS stored it under.
  return new RegExp(escapeRegExp(trimmed) + DIR_BOUNDARY, DIR_FLAGS);
})();

/**
 * The operator's config-dir override, as a matcher — the one path of ours that
 * the two rules above cannot reason about.
 *
 * AICOMMANDER_CONFIG_DIR points the identity and session stores at durable
 * storage (see config-dir.ts), and it is set on exactly the machines whose
 * layout we cannot predict: a QNAP data volume, a container mount, a NAS share
 * an operator named after their company, their customer, or themselves. It is
 * neither inside `os.homedir()` nor shaped like `/home/<x>`, so it reaches the
 * file verbatim — and the file's whole purpose is to be attached to a
 * third-party antivirus ticket.
 *
 * Replaced whole, with a name that keeps the diagnostic value of the line ("the
 * override is in force, and this file was under it") while surrendering none of
 * the operator's own words. Read ONCE, at module load, exactly like the home
 * directory: this is a redactor, so it must never depend on what the environment
 * looks like at the moment somebody logs something.
 *
 * BOTH SPELLINGS ARE MATCHED, because the value we are given and the value we
 * write down are not the same string. Every path built from the override goes
 * through `path.join`, which NORMALISES — `/share/DATA//aic` becomes
 * `/share/DATA/aic/logs`, and on Windows `D:/aic` becomes `D:\aic\logs`. An
 * override written with a doubled or forward slash therefore never matched the
 * raw value, and the operator's own path went verbatim into the first line of
 * the file (logStartup's `logDir`). So the raw form AND its normalised form are
 * both alternatives here; longest first, so the placeholder replaces as much of
 * the path as any of them can.
 */
const CONFIG_DIR_RE: RegExp | null = (() => {
  const raw = process.env["AICOMMANDER_CONFIG_DIR"]?.trim();
  // Same floor as the home rule, and for the same reason: a one-segment root
  // would rewrite every absolute path on the machine into the placeholder.
  if (!raw || raw.length < 4) return null;
  const variants = new Set<string>();
  for (const candidate of [raw, normalizeQuietly(raw)]) {
    const trimmed = candidate.replace(/[\\/]+$/, "");
    // The floor applies per spelling: normalising can only ever shorten.
    if (trimmed.length >= 4) variants.add(trimmed);
  }
  if (variants.size === 0) return null;
  const alternation = [...variants]
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp)
    .join("|");
  return new RegExp(`(?:${alternation})${DIR_BOUNDARY}`, DIR_FLAGS);
})();

/** `path.normalize`, which can throw on a value we did not choose. */
function normalizeQuietly(target: string): string {
  try {
    return path.normalize(target);
  } catch {
    return target;
  }
}

export function redactHomePaths(text: string): string {
  // The override first: it may itself sit under a home directory, and
  // `~/aic-data` says less about what happened than `<config-dir>` does.
  const withoutConfig = CONFIG_DIR_RE ? text.replace(CONFIG_DIR_RE, "<config-dir>") : text;
  const out = HOME_DIR_RE ? withoutConfig.replace(HOME_DIR_RE, "~") : withoutConfig;
  return out.replace(HOME_SEGMENT_RE, (_m, lead: string, root: string, name: string) =>
    // A path that is already anonymous stays as it is, so redacting a line
    // twice does not turn `/home/<user>` into `/home/<<user>>`.
    name === "<user>" ? `${lead}${root}${name}` : `${lead}${root}<user>`,
  );
}

/**
 * The last line of defence for every string that reaches the file. Callers are
 * expected not to hand us secrets in the first place; this is what makes a
 * mistake harmless instead of a credential in a vendor's inbox.
 */
export function redactDiagText(text: string): string {
  return redactHomePaths(text)
    .replace(SESSION_CODE_RE, (match) => maskSessionCode(match.toUpperCase()))
    .replace(JWS_RE, "[redacted-jws]")
    .replace(OPAQUE_BLOB_RE, "[redacted]")
    .replace(CONTROL_CHARS_RE, " ");
}

function formatValue(value: Exclude<DiagValue, undefined>): string {
  if (value === null) return "null";
  if (typeof value !== "string") return String(value);
  let out = redactDiagText(value);
  if (out.length > MAX_VALUE_CHARS) out = `${out.slice(0, MAX_VALUE_CHARS)}…`;
  if (out === "") return '""';
  return /[\s"]/.test(out) ? `"${out.replace(/["\\]/g, "\\$&")}"` : out;
}

function formatKey(key: string): string {
  return key.replace(/[^A-Za-z0-9_]/g, "_");
}

/**
 * One event, one line: `<iso> <role> <pid> <event> key=value …`. Line-oriented
 * and greppable on purpose — the audience is a support engineer with a text
 * editor, not a log pipeline.
 */
function formatLine(role: DiagRole, event: DiagEvent, fields: DiagFields): string {
  const parts = [new Date().toISOString(), role, String(process.pid), event];
  let n = 0;
  for (const key of Object.keys(fields)) {
    if (n >= MAX_FIELDS) break;
    const value = fields[key];
    if (value === undefined) continue;
    n++;
    parts.push(`${formatKey(key)}=${formatValue(value)}`);
  }
  return `${parts.join(" ")}\n`;
}

/**
 * Where the log lives when the host does not name a directory.
 *
 * Deliberately mirrors `resolveJobsRoot`'s ladder (job-manager.ts) — same
 * reasoning, same answer, so an operator finds jobs and logs side by side — and
 * deliberately NOT the /etc credential directory: this is variable data.
 *   1. an explicit `configDir` (the desktop's per-user data dir);
 *   2. AICOMMANDER_CONFIG_DIR, for machines whose defaults are volatile (QNAP);
 *   3. /var/lib/aicommander for a root service (FHS);
 *   4. otherwise a per-user data dir.
 */
export function resolveDiagLogDir(configDir?: string): string {
  let base = configDir;
  if (!base) {
    try {
      base = envConfigDir();
    } catch {
      // An unusable override is reported loudly by the stores that need it;
      // logging must not be the thing that turns it into a crash.
      base = undefined;
    }
  }
  if (base) return path.join(base, "logs");
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  if (process.platform !== "win32" && isRoot) return "/var/lib/aicommander/logs";
  if (process.platform === "win32") {
    const localAppData = process.env["LOCALAPPDATA"];
    const winBase =
      localAppData && path.isAbsolute(localAppData)
        ? localAppData
        : path.join(os.homedir(), "AppData", "Local");
    return path.join(winBase, "aicommander", "logs");
  }
  return path.join(os.homedir(), ".local", "share", "aicommander", "logs");
}

export interface DiagLogOptions {
  /** Directory to write into; created 0700 if missing. */
  dir: string;
  /** Names the file (`<role>.log`) and every line. One file per process role. */
  role: DiagRole;
  /** Test seam: rotate sooner than 512 KiB. */
  maxFileBytes?: number;
}

/**
 * Point the logger at a file. Idempotent-ish: a second call replaces the target
 * (the tests rely on that), and a failure here simply leaves the logger inert —
 * `diag()` then costs a null check.
 *
 * This is the ONLY synchronous I/O in the module and it runs once, at startup,
 * before anything is connected.
 */
export function initDiagLog(opts: DiagLogOptions): void {
  try {
    ensurePrivateDir(opts.dir);
    const filePath = path.join(opts.dir, `${opts.role}.log`);
    let size = 0;
    try {
      size = fs.statSync(filePath).size;
    } catch {
      // Missing file — starts at zero, which is exactly right.
    }
    state = {
      role: opts.role,
      filePath,
      maxFileBytes: opts.maxFileBytes ?? MAX_FILE_BYTES,
      size,
      queue: [],
      dropped: 0,
      pending: null,
      timer: null,
    };
  } catch {
    // No writable log directory (read-only volume, AV-quarantined path, a
    // sandboxed userData). Stay silent rather than fail the host.
    state = null;
  }
}

/** Absolute path of the live log file, or null when logging is inert. */
export function diagLogPath(): string | null {
  return state?.filePath ?? null;
}

/**
 * Record one event. Never throws, never blocks, never touches the disk on the
 * calling turn. Inert until a host calls `initDiagLog`.
 */
export function diag(event: DiagEvent, fields: DiagFields = {}): void {
  const s = state;
  if (!s) return;
  try {
    if (s.queue.length >= MAX_QUEUE_LINES) {
      s.dropped++;
      return;
    }
    s.queue.push(formatLine(s.role, event, fields));
    schedule(s);
  } catch {
    // Formatting cannot realistically throw, but a logger that can take the
    // process down is worse than no logger at all.
  }
}

function schedule(s: DiagState): void {
  if (s.timer || s.pending) return;
  // 0 ms rather than a coalescing delay: the interesting lines are the ones
  // written just before a process dies, and a timer is already enough to keep
  // the I/O off the caller's turn.
  s.timer = setTimeout(() => {
    s.timer = null;
    void flush(s);
  }, 0);
  s.timer.unref?.();
}

function flush(s: DiagState): Promise<void> {
  if (s.pending || state !== s || s.queue.length === 0) return Promise.resolve();
  const run = writeBatch(s).finally(() => {
    s.pending = null;
    if (s.queue.length > 0) schedule(s);
  });
  s.pending = run;
  return run;
}

async function writeBatch(s: DiagState): Promise<void> {
  try {
    const batch = s.queue.join("");
    // Cleared BEFORE the await: a failed write drops its batch instead of
    // retrying it forever against a disk that is not coming back.
    s.queue.length = 0;
    const bytes = Buffer.byteLength(batch);
    if (s.size + bytes > s.maxFileBytes) await rotate(s);
    await fs.promises.appendFile(s.filePath, batch, { mode: PRIVATE_FILE_MODE });
    s.size += bytes;
    // Confess overflow only once a write has actually SUCCEEDED — queued with the
    // failed batch it would be discarded along with it, and a silent logger that
    // silently lost lines is the worst of both worlds.
    if (s.dropped > 0) {
      const dropped = s.dropped;
      s.dropped = 0;
      s.queue.push(formatLine(s.role, "diag.dropped", { lines: dropped }));
    }
  } catch {
    // Silence is the contract. Losing lines is acceptable; anything else is not.
  }
}

/**
 * `<role>.log` → `<role>.log.1` → … → `<role>.log.<MAX_GENERATIONS>`, oldest
 * discarded. Best-effort at every step: on Windows a rename can lose to an
 * antivirus scanner holding the file open, and the correct response to that is
 * to keep appending, not to stop logging.
 */
async function rotate(s: DiagState): Promise<void> {
  let movedAside = false;
  for (let i = MAX_GENERATIONS; i >= 1; i--) {
    const from = i === 1 ? s.filePath : `${s.filePath}.${i - 1}`;
    const to = `${s.filePath}.${i}`;
    try {
      // The rename REPLACES the destination — that is what rename does on every
      // platform this runs on (POSIX by definition; Node's Windows rename asks
      // for MOVEFILE_REPLACE_EXISTING) — so nothing is removed first.
      //
      // Removing first is what this used to do, and it destroyed a generation
      // BEFORE the rename that would have refilled it. The live file's rename is
      // also the likeliest to fail, on exactly the machines this history is kept
      // for: a scanner holding worker.log open on Windows refuses it. Two such
      // rotations left an empty log and no history at all — no bytes to attach
      // to the vendor report, on the box the report is about.
      await fs.promises.rename(from, to);
      // Only the LIVE file moving decides whether the counter may restart; the
      // older generations are housekeeping.
      if (i === 1) movedAside = true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | null)?.code;
      // Nothing to shift (that generation does not exist yet), or a rename the
      // OS refused — in both cases both files stay exactly as they are.
      if (code !== "EEXIST" && code !== "ENOTEMPTY" && code !== "EISDIR") continue;
      // The one shape rename cannot replace: the destination is not a plain
      // file. Only then is removing it first justified, and only because we
      // already know the source is there to take its place.
      try {
        await fs.promises.rm(to, { recursive: true, force: true });
        await fs.promises.rename(from, to);
        if (i === 1) movedAside = true;
      } catch {
        // Carry on; the live-file fallback below is what keeps the bound.
      }
    }
  }
  if (movedAside) {
    s.size = 0;
    return;
  }

  // The live file is still there with all of its bytes, and this is the case the
  // whole feature is aimed at: a scanner holding our log open makes exactly this
  // rename fail on Windows. Zeroing the counter here — which is what this used
  // to do unconditionally — turns the documented 512 KiB/1.5 MiB ceiling into no
  // ceiling at all: the file keeps every byte it had, the counter starts over,
  // and the next attempt is another maxFileBytes away. Forever.
  //
  // So: truncate in place instead. It needs no rename — a handle held open for
  // READING does not stop it on Windows the way it stops a rename — and it costs
  // one generation of history, which is the price of a bound that holds.
  //
  // ONE generation, though, and not the only one. On the FIRST rotation there is
  // nothing else on disk, so truncating there does not cost a generation, it
  // costs the whole record: every byte accumulated since the agent started,
  // deleted on the machine whose antivirus event we are asking the user to send
  // to a vendor, at the moment the file grew big enough to be interesting. That
  // is a worse outcome than any bound violation this module could commit.
  //
  // So before truncating, COPY the history aside. A copy only READS the live
  // file — the one operation the scanner's own handle does not refuse — and it
  // goes to `<file>.1` only while that slot is EMPTY: an existing generation is
  // somebody's support case too and must not be overwritten (the loop above is
  // the only thing allowed to age generations), and while one exists the record
  // survives a truncation anyway. The bound is untouched: at most the live file
  // plus MAX_GENERATIONS copies, exactly as documented.
  const firstGeneration = `${s.filePath}.1`;
  let history = await fileExists(firstGeneration);
  if (!history) {
    try {
      await fs.promises.copyFile(s.filePath, firstGeneration);
      history = true;
    } catch {
      // A scanner that refuses a read as well, or a full disk. An OLDER
      // generation may still be there (the loop above can shift generations even
      // when it cannot move the live file), and while one is, a truncation costs
      // a generation rather than the record.
      history = await anyGenerationExists(s);
    }
  }
  if (history) {
    try {
      await fs.promises.truncate(s.filePath, 0);
      s.size = 0;
      return;
    } catch {
      // Both refused. Re-derive the counter from the file itself so it stays a
      // true statement about the bytes on disk: the next batch then trips the
      // ceiling again immediately and retries the rotation, rather than waiting
      // out another maxFileBytes of growth.
    }
  } else {
    // NOTHING could be saved: no rename, no copy, no older generation — the live
    // file holds the only copy of the evidence. THE TRADE, made explicit: we let
    // it grow past the documented cap rather than delete it, up to a hard
    // ceiling of OVERFLOW_MULTIPLE × the cap, and only there truncate as the
    // last resort. Overshooting a support log's size is a nuisance; being asked
    // for the log and having nothing to send is the failure this whole module
    // was written for. The ceiling keeps it a nuisance: a wedged machine cannot
    // fill a disk with diagnostics either.
    await recountLiveFile(s);
    if (s.size >= s.maxFileBytes * OVERFLOW_MULTIPLE) {
      try {
        await fs.promises.truncate(s.filePath, 0);
        s.size = 0;
        return;
      } catch {
        // Still refused; the recount below keeps the counter honest.
      }
    }
  }
  await recountLiveFile(s);
}

/** Is any older generation on disk — i.e. would a truncation still leave history? */
async function anyGenerationExists(s: DiagState): Promise<boolean> {
  for (let i = 1; i <= MAX_GENERATIONS; i++) {
    if (await fileExists(`${s.filePath}.${i}`)) return true;
  }
  return false;
}

/** Best-effort presence check; a file we cannot stat is not history we can count on. */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.promises.stat(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Re-derive the counter from the file itself, so it stays a true statement about
 * the bytes on disk: the next batch then trips the ceiling again immediately and
 * retries the rotation, rather than waiting out another maxFileBytes of growth.
 */
async function recountLiveFile(s: DiagState): Promise<void> {
  try {
    s.size = (await fs.promises.stat(s.filePath)).size;
  } catch (err) {
    // Gone entirely (quarantined, or an operator deleted it): the append below
    // creates a fresh file, so zero is the honest count.
    if ((err as NodeJS.ErrnoException | null)?.code === "ENOENT") s.size = 0;
    // Anything else: keep the counter as it stands. Over-counting only costs a
    // rotation attempt per batch, which is the safe direction.
  }
}

/**
 * Wait for queued lines to reach the disk. For tests and for the rare shutdown
 * path that can afford one await; nothing on a hot path may call it.
 */
export async function flushDiagLog(): Promise<void> {
  const s = state;
  if (!s) return;
  if (s.timer) {
    clearTimeout(s.timer);
    s.timer = null;
  }
  // A flush already in flight owns the batch it took; awaiting it and then
  // flushing again drains whatever arrived meanwhile. Bounded so a caller can
  // never be held by a process that keeps logging.
  for (let i = 0; i < 8 && (s.pending || s.queue.length > 0); i++) {
    if (s.pending) await s.pending.catch(() => undefined);
    else await flush(s);
  }
}

/**
 * How long a dying process will wait for its last lines. Long enough for a
 * healthy disk by orders of magnitude, short enough that a wedged one cannot
 * turn an exit into a hang.
 */
const EXIT_FLUSH_TIMEOUT_MS = 2_000;

/**
 * Exit, but not before the lines that explain WHY are on disk.
 *
 * `diag()` deliberately defers its I/O to a timer, and `process.exit` never lets
 * that timer fire — so every fatal path that logged its cause and then exited
 * wrote that cause to memory and threw it away. The events lost this way were
 * precisely the ones this log exists for: `conn.register_failed` and the
 * `path.error`s on our own credential, state and jobs paths, i.e. the antivirus
 * signature. Every `process.exit` in this package that follows a `diag()` goes
 * through here instead, and a test asserts there are no others.
 *
 * Bounded: a flush that cannot complete (a disk that is gone, an AV holding the
 * file) must not hold the process open, so the wait is raced against a timer and
 * the exit happens either way. Silence stays the contract.
 */
export async function exitAfterDiagFlush(code: number): Promise<never> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      flushDiagLog(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, EXIT_FLUSH_TIMEOUT_MS);
        timer.unref?.();
      }),
    ]);
  } catch {
    // A logger may not be the reason a process fails to die.
  } finally {
    if (timer) clearTimeout(timer);
  }
  return process.exit(code);
}

/** Stop logging and drop any pending lines. Tests and teardown only. */
export function closeDiagLog(): void {
  const s = state;
  state = null;
  if (s?.timer) clearTimeout(s.timer);
}

/**
 * The safe half of an unknown error: for an errno failure (`EACCES`, `EPERM`,
 * `ENOENT` on our own paths — the antivirus signature) the `code` and `syscall`,
 * which is the whole diagnosis, and never `err.message`, which embeds the path.
 * Anything else degrades to the error's class name.
 */
export function errorFields(err: unknown): DiagFields {
  if (err && typeof err === "object") {
    const e = err as NodeJS.ErrnoException;
    if (typeof e.code === "string") {
      return { code: e.code, ...(typeof e.syscall === "string" ? { syscall: e.syscall } : {}) };
    }
    if (err instanceof Error) return { error: err.name };
  }
  return { error: "unknown" };
}

/**
 * Errors that have already been recorded under a MORE PRECISE name.
 *
 * A fault raised deep in a local call — our own credential store refusing us,
 * the antivirus signature this log exists to name — is diagnosed where it
 * happens (`path.error path_role=sessionStore`) and then travels up through
 * `catch`es that know only that "the thing they were doing failed". Each of
 * those would give the same event a second, vaguer name, and a support engineer
 * reading the file sees one machine telling two stories about one fault.
 *
 * So the raiser marks the error and the outer handler asks before naming it. A
 * WeakSet rather than a flag on the error: nothing of ours is attached to an
 * object we did not create. It lives HERE, next to the catalogue, because both
 * ends of the rule are diag() callers and neither owns the other — the session
 * store is written from agent-controller.ts and the rotation failure is named in
 * connection.ts.
 */
const diagnosedLocally = new WeakSet<object>();

/** Mark an error as already recorded under its own name. */
export function noteDiagnosed(err: unknown): void {
  if (err !== null && typeof err === "object") diagnosedLocally.add(err);
}

/** Has this error already been recorded? Outer handlers must not rename it. */
export function alreadyDiagnosed(err: unknown): boolean {
  return err !== null && typeof err === "object" && diagnosedLocally.has(err);
}

/**
 * The only shape a job id may reach the log in.
 *
 * A job id is the APPROVED way to talk about a job here (the header's rule), and
 * that permission rests entirely on a job id being a 16-hex token of OUR OWN
 * making. Several of these lines are written from a relay frame whose fields are
 * untrusted and, on the cancel path, not yet validated by the job manager — so a
 * malformed or hostile frame could otherwise put command text or a user's path
 * into a vendor-bound file through the nominal `jobId` field. Anything that is
 * not a job id is recorded AS not being one: `invalid` says the frame was
 * malformed, which is itself the diagnostic, and quoting the value back would be
 * the vulnerability.
 *
 * The pattern is the shared one job-manager.ts validates against before a jobId
 * can reach a path join — the log must not accept anything weaker.
 */
export function diagJobId(jobId: unknown): string {
  return typeof jobId === "string" && JOB_ID_PATTERN.test(jobId) ? jobId : "invalid";
}

/**
 * Facts about this process that a support ticket always needs and that nobody
 * can read off a running machine: what is installed where, and with what
 * privileges. Emitted by each host right after `initDiagLog`.
 */
export function logStartup(fields: DiagFields = {}): void {
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  diag("startup", {
    platform: process.platform,
    arch: process.arch,
    node: process.versions.node,
    // Windows has no cheap, non-blocking elevation query, so we report what we
    // know rather than guessing: "unknown" is an honest answer, a wrong one is not.
    elevated: uid === undefined ? "unknown" : uid === 0,
    execPath: process.execPath,
    ...fields,
  });
}
