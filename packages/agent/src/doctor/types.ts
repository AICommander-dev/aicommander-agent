/**
 * The shapes every doctor check speaks in.
 *
 * `doctor` is a LIBRARY of checks plus a renderer, deliberately split that way:
 * the same checks run from the CLI (ctl/commands/doctor.ts), from the Electron
 * tray's "Run diagnostics…" window, and — on a Windows install that has been
 * gutted, where nothing inside $INSTDIR can run any more — from the privileged
 * helper's own binary (PLAN-av-hardening.md W2.2/W2.3). None of those three may
 * have to reimplement a verdict, so no check is allowed to print anything: it
 * returns a CheckResult and the renderer decides how it looks.
 *
 * ── WHAT A DIAGNOSTIC MAY DO ─────────────────────────────────────────────────
 * A diagnostic must never make the machine worse than it found it. Concretely,
 * across every check in this directory:
 *   - nothing is left behind on disk (every probe file is removed, including on
 *     the failure paths, and a cleanup that itself failed is REPORTED);
 *   - no one-shot credential is consumed, no session code rotated, no device
 *     identity created — in particular `register()` is never called, because on
 *     a machine with no stored session it would MINT one;
 *   - the live agent is never disturbed: the WebSocket-upgrade probe carries no
 *     credential and a ticket that cannot exist, precisely so it can never
 *     displace the machine's real relay session.
 * Where a check cannot be run safely, it returns `skipped` with the reason.
 * "Not checked" is an honest answer; a guess is not.
 */

/**
 * `ok`      — checked, and healthy.
 * `warn`    — checked, and worth telling somebody about; not itself a breakage.
 * `fail`    — checked, and broken.
 * `skipped` — NOT checked, with `detail` saying why. Never a verdict on the
 *             machine: an npm agent has no install manifest and a Linux box has
 *             no privileged helper, and neither is a fault.
 */
export type CheckVerdict = "ok" | "warn" | "fail" | "skipped";

/**
 * Scalars only — same rule as diag-log.ts, and for the same reason.
 *
 * ── WHAT A FACT MAY CONTAIN ──────────────────────────────────────────────────
 * Facts are the part of a check that ends up in the `--json` output and in the
 * `--report` bundle, i.e. in an antivirus vendor's inbox. `redactDiagText` is
 * the last line of defence and it has never claimed to remove ordinary text: it
 * masks credentials and de-identifies home directories, and a Run-key value or a
 * systemd `ExecStart` line passes through it verbatim. So the rule is enforced
 * HERE, where facts are built, and not hoped for downstream:
 *
 *   ALLOWED   — paths of OURS (an install root, a store directory, an executable
 *               an autostart entry names), status codes, errnos, counts, sizes,
 *               protocol and version numbers, booleans, closed vocabularies.
 *   FORBIDDEN — command lines and their arguments (a Run value's data, a task's
 *               argument string, an `ExecStart=` line), any command's OUTPUT, the
 *               caller's working directory or environment values that are not
 *               ours to publish, and every credential shape.
 *
 * When a check reads a command line to find a path in it, the PATH is the fact
 * and the line it came from is not. `pathFact` is the one-line reminder of that
 * at each such site.
 */
export type DoctorFactValue = string | number | boolean | null;
export type DoctorFacts = Record<string, DoctorFactValue>;

/**
 * The one thing a fact may carry out of an OS-registered command line: the path
 * we extracted from it. Exists so the rule above has a name at every call site
 * where the temptation is to record "and here is the whole line for context" —
 * the whole line is exactly what the bundle may not carry.
 */
export function pathFact(extracted: string | null | undefined): DoctorFactValue {
  return extracted ?? null;
}

export interface CheckResult {
  /** Stable, dotted, machine-readable (`install.manifest`). Support tooling keys off it. */
  id: string;
  /** One short human phrase. */
  title: string;
  verdict: CheckVerdict;
  /** One line a human can act on, or the reason a `skipped` check was skipped. */
  detail: string;
  /** Structured evidence: status codes, errnos, counts, paths. */
  facts?: DoctorFacts;
  /** What to DO about it. Present on `warn`/`fail` wherever we know the answer. */
  remedy?: string;
}

/**
 * The read half of session-store.ts's `TokenVault`. Structurally identical, and
 * declared here rather than imported so the doctor's option surface says exactly
 * what it uses: it decrypts, and it never encrypts.
 */
export interface DoctorTokenVault {
  isAvailable(): boolean;
  decrypt(ciphertext: Buffer): string;
}

/** What a caller may configure. Every field has a safe default. */
export interface DoctorOptions {
  /**
   * Where the packaged install manifest lives. The tray passes Electron's
   * `process.resourcesPath`; the headless CLI has none, and the manifest check
   * then reports itself skipped rather than inventing a location.
   */
  resourcesPath?: string;
  /** The desktop's per-user data dir. Headless leaves it undefined (see config-dir.ts). */
  configDir?: string;
  /**
   * Relay base URL. Whatever is passed goes through the SAME host-lock the agent
   * itself uses (relay-url.ts) before any check sees it — see resolveDoctorContext.
   */
  serverUrl?: string;
  /**
   * OS-protected storage for the stored agent token (the desktop's safeStorage).
   *
   * A registered desktop install keeps its token encrypted in `session.token`,
   * so without this the ticket check can only report that it could not read the
   * credential — which is honest but useless on exactly the machines the tray
   * runs on. Read-only: the doctor decrypts to present a Bearer header and never
   * writes anything back.
   */
  tokenVault?: DoctorTokenVault;
  /** Skip every check that touches the network. */
  offline?: boolean;
  /** Budget for one network leg. */
  networkTimeoutMs?: number;
  /**
   * How long the antivirus probe waits between writing its scripts and reading
   * them back. An on-access engine acts asynchronously — quarantining is not
   * part of our `write()` returning — so a read-back with no pause at all
   * measures our own page cache and nothing else.
   */
  probeDelayMs?: number;
}

/** Options with the defaults applied. What every check actually receives. */
export interface DoctorContext {
  resourcesPath?: string;
  configDir?: string;
  serverUrl: string;
  offline: boolean;
  networkTimeoutMs: number;
  probeDelayMs: number;
  tokenVault?: DoctorTokenVault;
}

/**
 * One group of related checks. A group exists because some checks share an
 * expensive lookup (the install manifest is loaded once and answers both the
 * manifest check and "where is the install root" for the writability probe).
 * A group that THROWS is caught by the runner and reported as a single failed
 * check, so a bug in one group can never suppress the others.
 */
export interface DoctorCheckGroup {
  id: string;
  title: string;
  run(ctx: DoctorContext): Promise<CheckResult[]>;
}

export interface DoctorSummary {
  ok: number;
  warn: number;
  fail: number;
  skipped: number;
}

export interface DoctorReport {
  /** Bumped only on an incompatible change; support tooling reads it first. */
  schema: 1;
  generatedAt: string;
  agentVersion: string;
  platform: string;
  arch: string;
  node: string;
  /**
   * `"unknown"` on Windows, where there is no cheap non-blocking elevation
   * query — the same honest answer diag-log.ts's `logStartup` gives.
   */
  elevated: boolean | "unknown";
  /** Whether the JSON has been through `redactDoctorReport`. */
  redacted: boolean;
  checks: CheckResult[];
  summary: DoctorSummary;
}

/** Convenience constructors — every check builds its result through these. */
export function ok(id: string, title: string, detail: string, facts?: DoctorFacts): CheckResult {
  return { id, title, verdict: "ok", detail, ...(facts ? { facts } : {}) };
}

export function warn(
  id: string,
  title: string,
  detail: string,
  remedy?: string,
  facts?: DoctorFacts,
): CheckResult {
  return {
    id,
    title,
    verdict: "warn",
    detail,
    ...(facts ? { facts } : {}),
    ...(remedy ? { remedy } : {}),
  };
}

export function fail(
  id: string,
  title: string,
  detail: string,
  remedy?: string,
  facts?: DoctorFacts,
): CheckResult {
  return {
    id,
    title,
    verdict: "fail",
    detail,
    ...(facts ? { facts } : {}),
    ...(remedy ? { remedy } : {}),
  };
}

export function skipped(id: string, title: string, why: string, facts?: DoctorFacts): CheckResult {
  return { id, title, verdict: "skipped", detail: why, ...(facts ? { facts } : {}) };
}

/**
 * The message of an unknown error, unwrapped.
 *
 * Unlike diag-log.ts's `errorFields`, the doctor DOES keep `err.message` — the
 * whole point of the install-path check is the OS error verbatim, embedded path
 * and all, because on 2026-09-02 an elevated administrator got "Access denied"
 * on a directory whose ACL granted `BUILTIN\Administrators: FullControl` with no
 * deny ACEs, and that exact string is what identified a filter driver rather
 * than a permissions problem. The report boundary (report.ts) is where paths are
 * de-identified; throwing the evidence away here would leave nothing to redact.
 */
export function errorText(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** The errno of a failed syscall, or `null` when it was not an errno failure. */
export function errnoOf(err: unknown): string | null {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return typeof code === "string" ? code : null;
}

/** Short URL of record; redirects to /troubleshooting/#antivirus. */
export const HELP_URL = "https://aicommander.dev/antivirus";
