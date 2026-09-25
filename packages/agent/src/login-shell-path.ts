import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";

/**
 * macOS only, and deliberately so.
 *
 * The desktop app — and with it this in-process agent — is started by launchd
 * (SMAppService, dev.aicommander.tray.plist), which declares no
 * EnvironmentVariables, so the process inherits launchd's minimal
 * /usr/bin:/bin:/usr/sbin:/sbin. Commands then run through `/bin/sh -c`, a
 * NON-login, NON-interactive shell that reads no profile, so homebrew, nvm/fnm,
 * docker and everything else the user installed is simply not on PATH — while
 * the very same command typed into the user's own terminal works. Asking the
 * user's login shell once what its PATH is, and merging that in, is what makes
 * the two agree.
 *
 * The probe is best-effort BY CONSTRUCTION: a login+interactive shell runs the
 * user's rc files, which may be slow, broken, or block waiting for input. Every
 * failure mode — timeout, non-zero exit, empty or implausible output, spawn
 * error — collapses to "keep the inherited PATH", because a broken .zshrc must
 * never be able to wedge command execution. It runs at most once per process.
 *
 * Elevated exec deliberately does NOT use this: priv-helper keeps a locked PATH
 * of system directories only, because /usr/local/bin and /opt/homebrew/bin are
 * admin-writable on macOS and would be a root-planting vector.
 *
 * The probe carries a SECOND value for the same reason and at no extra cost:
 * $LANG. launchd hands the app no locale at all, so a remote command on macOS
 * ran with LANG empty while the identical command on Linux saw en_US.UTF-8 —
 * and a Python or Node tool that assumes a UTF-8 locale then mangles or crashes
 * on non-ASCII output, which this fleet produces daily (Polish, Japanese). One
 * shell invocation answers both questions; see applyLoginShellLocale.
 */
export const LOGIN_SHELL_PATH_TIMEOUT_MS = 2_000;

/** A PATH longer than this is not a PATH — it is a shell that printed garbage. */
const MAX_LOGIN_SHELL_PATH_BYTES = 8 * 1024;

/**
 * How much of the probe's stdout we are willing to hold. This is NOT a bound on
 * the PATH (that is the constant above) — an interactive login shell prints the
 * user's motd, nvm/p10k/asdf notices and whatever a stray `echo` in .zshrc
 * produces down the SAME pipe, and the value we want may be at the far end of
 * it. Capturing generously costs nothing and keeps the sentinel reachable.
 */
const MAX_PROBE_OUTPUT_BYTES = 256 * 1024;

/** A shell reporting more entries than this is not describing a real machine. */
const MAX_PATH_ENTRIES = 256;

/**
 * The locale the child gets when the login shell reports none of its own.
 *
 * A hard-coded value is the LAST resort, deliberately: the shell's own $LANG is
 * what the user's terminal uses, and matching it is the whole point. But most
 * macOS users never set LANG in an rc file — Terminal.app injects it — so a
 * launchd-started agent's probe legitimately comes back empty, and the choice is
 * then between this and the C locale's ASCII-only behaviour. en_US.UTF-8 is
 * present on every macOS install, so it cannot produce the "Setting locale
 * failed" warnings an invented name would; and only the ENCODING half matters
 * for the failure being fixed (mangled non-ASCII output), not the language.
 */
const FALLBACK_MACOS_LANG = "en_US.UTF-8";

/**
 * A locale name is short and drawn from a tiny alphabet (`pl_PL.UTF-8`,
 * `en_US.ISO8859-1`, `C`). Anything else came from a shell that was not printing
 * $LANG, and putting it in a child's environment could only confuse the tools
 * that read it — so it is dropped rather than repaired.
 */
const LANG_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;

/** What one probe learned. Either field may be null: they fail open separately. */
interface ProbeResult {
  path: string | null;
  lang: string | null;
}

/** "The probe told us nothing" — every failure path resolves to exactly this. */
const EMPTY_PROBE_RESULT: ProbeResult = { path: null, lang: null };

let probe: Promise<ProbeResult> | null = null;
/** `undefined` = not resolved yet; otherwise the (possibly all-null) result. */
let resolved: ProbeResult | undefined;

/**
 * The probe's stdout is a SHARED channel: rc-file chatter arrives on it and we
 * cannot tell chatter from value by looking. So the shell brackets the value
 * with two markers carrying a per-probe random nonce, and we read only what is
 * between them. The nonce matters — fixed markers could in principle be echoed
 * by an rc file (or by `set -x`-style tracing of our own command line), while a
 * value freshly drawn from the CSPRNG cannot be predicted by anything that was
 * written to disk before the probe ran.
 */
function makeProbeMarkers(): {
  begin: string;
  end: string;
  langBegin: string;
  langEnd: string;
  script: string;
} {
  const nonce = randomBytes(9).toString("hex");
  const begin = `--aic-path-begin-${nonce}--`;
  const end = `--aic-path-end-${nonce}--`;
  // A SEPARATE marker pair per value, sharing the one nonce: the two are read
  // independently, so a shell that garbles one still yields the other, and
  // neither can be mistaken for the other's content.
  const langBegin = `--aic-lang-begin-${nonce}--`;
  const langEnd = `--aic-lang-end-${nonce}--`;
  // Single-quoted markers (hex + dashes only, so nothing to quote around) and
  // `printf %s` rather than `echo`, which mangles backslashes in some shells.
  return {
    begin,
    end,
    langBegin,
    langEnd,
    script:
      `printf %s '${begin}'; printf %s "$PATH"; printf %s '${end}'; ` +
      `printf %s '${langBegin}'; printf %s "$LANG"; printf %s '${langEnd}'`,
  };
}

/** Pull the bracketed value out of everything else the shell decided to say. */
function extractSentinelValue(raw: string, begin: string, end: string): string | null {
  // LAST begin, then the FIRST end after it: if the command line itself was
  // echoed back (xtrace with a redirected stderr, an rc file that prints $-),
  // the real value is the last one printed, and its own terminator ends it.
  const start = raw.lastIndexOf(begin);
  if (start === -1) return null;
  const from = start + begin.length;
  const stop = raw.indexOf(end, from);
  return stop === -1 ? null : raw.slice(from, stop);
}

/**
 * Every entry is validated, not just the value as a whole, because this becomes
 * the FRONT of the PATH of every command the agent runs afterwards. A relative
 * entry there — including the empty entry a trailing or doubled colon produces,
 * which every shell reads as "the current directory" — turns any directory a
 * command happens to run in into a place someone can drop `git` or `python`.
 * Unusable entries are dropped rather than failing the whole probe; a PATH with
 * nothing absolute left in it is not worth prepending, so that fails open.
 */
function sanitizeProbedPath(value: string): string | null {
  if (value.length > MAX_LOGIN_SHELL_PATH_BYTES) return null;
  const seen = new Set<string>();
  const entries: string[] = [];
  for (const entry of value.split(":")) {
    if (!entry.startsWith("/")) continue;
    // NUL, newline, ESC and friends: a directory name never needs them, and a
    // shell that emitted them was not printing a PATH.
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(entry)) continue;
    if (seen.has(entry)) continue;
    seen.add(entry);
    entries.push(entry);
    if (entries.length >= MAX_PATH_ENTRIES) break;
  }
  return entries.length === 0 ? null : entries.join(":");
}

/** Accept a locale name, or nothing at all — never a repaired guess. */
function sanitizeProbedLang(value: string): string | null {
  const trimmed = value.trim();
  return LANG_PATTERN.test(trimmed) ? trimmed : null;
}

function runProbe(): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const { begin, end, langBegin, langEnd, script } = makeProbeMarkers();
    let child: ReturnType<typeof spawn>;
    try {
      // `-l -i` because that is the shell the USER sees: many PATH mutations
      // (homebrew shellenv, nvm, fnm, asdf) live in an interactive rc file, not
      // only in the login profile. That is also why the value needs the
      // sentinel above — interactive rc files are exactly the ones that talk.
      // stdin is /dev/null so an rc file that reads input gets EOF instead of
      // hanging until the timeout.
      child = spawn(process.env["SHELL"] ?? "/bin/zsh", ["-l", "-i", "-c", script], {
        stdio: ["ignore", "pipe", "ignore"],
        // Own process group: an rc file may start children, and the timeout
        // below must be able to take the whole tree down with it.
        detached: true,
      });
    } catch {
      resolve(EMPTY_PROBE_RESULT);
      return;
    }

    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const finish = (value: ProbeResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try {
        if (child.pid != null) process.kill(-child.pid, "SIGKILL");
      } catch {
        // Already gone.
      }
      finish(EMPTY_PROBE_RESULT);
    }, LOGIN_SHELL_PATH_TIMEOUT_MS);
    timer.unref?.();

    child.stdout?.on("data", (chunk: Buffer) => {
      if (bytes > MAX_PROBE_OUTPUT_BYTES) return;
      bytes += chunk.length;
      chunks.push(Buffer.from(chunk));
    });
    child.on("error", () => finish(EMPTY_PROBE_RESULT));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(EMPTY_PROBE_RESULT);
        return;
      }
      const raw = Buffer.concat(chunks).toString("utf8");
      // No sentinel pair = we never saw the value, only noise (or a truncated
      // firehose). Guessing which line was the PATH is exactly the mistake this
      // protocol exists to avoid, so this fails open like every other miss.
      // Each value is extracted on its own: a shell that mangles one still
      // yields the other, which is strictly better than discarding both.
      const path = extractSentinelValue(raw, begin, end);
      const lang = extractSentinelValue(raw, langBegin, langEnd);
      finish({
        path: path === null ? null : sanitizeProbedPath(path),
        lang: lang === null ? null : sanitizeProbedLang(lang),
      });
    });
  });
}

/**
 * Resolve the user's login-shell PATH (and $LANG) once per process. Memoized:
 * every caller shares the single probe, and the result is cached for
 * synchronous reuse.
 */
export function startLoginShellPathProbe(): Promise<ProbeResult> {
  if (probe) return probe;
  if (process.platform !== "darwin") {
    resolved = EMPTY_PROBE_RESULT;
    probe = Promise.resolve(EMPTY_PROBE_RESULT);
    return probe;
  }
  probe = runProbe().then((value) => {
    resolved = value;
    return value;
  });
  return probe;
}

/**
 * The promise a caller must await before building a child environment, or null
 * when there is nothing to wait for (not macOS, or already resolved). Starting
 * the probe is a side effect of asking — the first command pays for it, every
 * later one reads the cache.
 */
export function pendingLoginShellPath(): Promise<unknown> | null {
  if (process.platform !== "darwin" || resolved !== undefined) return null;
  return startLoginShellPathProbe();
}

/**
 * Merge the resolved login-shell PATH into an environment block, in place.
 * A no-op until the probe has resolved to a usable value, so it is always safe
 * to call synchronously. Inherited entries the login shell does not know about
 * are KEPT (appended): this adds directories, it never takes any away.
 */
export function applyLoginShellPath(env: NodeJS.ProcessEnv): void {
  const resolvedPath = resolved?.path;
  if (typeof resolvedPath !== "string") return;
  const seen = new Set(resolvedPath.split(":").filter((entry) => entry !== ""));
  const extra = (env["PATH"] ?? "")
    .split(":")
    .filter((entry) => entry !== "" && !seen.has(entry));
  env["PATH"] = extra.length === 0 ? resolvedPath : `${resolvedPath}:${extra.join(":")}`;
}

/**
 * Give a macOS child a usable locale, in place. macOS only — Linux agents
 * already inherit a LANG from systemd/the login session, and Windows does not
 * use the variable at all.
 *
 * WHAT WAS WRONG. launchd declares no environment, so a remote command on macOS
 * ran with `LANG=[]` where the same command on Linux saw `LANG=en_US.UTF-8`.
 * An empty LANG means the C locale: Python (pre-3.7 defaults and any
 * locale-aware library), Perl, sort, and a long tail of CLI tools then treat
 * output as ASCII and mangle or refuse non-ASCII text. This fleet handles Polish
 * and Japanese daily, so macOS being the odd one out was a live source of
 * corrupted output.
 *
 * PRECEDENCE, unchanged from PATH: an inherited non-empty LANG is left alone,
 * and because this runs BEFORE the caller's overlay is merged, an explicit LANG
 * in `env` still wins. We only fill a hole.
 *
 * TERM is filled in by applyNonInteractiveTerm, one call later and on every
 * POSIX platform — same "fill a hole, never overwrite" rule, different variable.
 */
export function applyLoginShellLocale(env: NodeJS.ProcessEnv): void {
  if (process.platform !== "darwin") return;
  const inherited = env["LANG"];
  if (typeof inherited === "string" && inherited.trim() !== "") return;
  // The user's own answer first; the fallback only when the probe found none
  // (unresolved, timed out, or a shell that simply has no LANG set — the common
  // case on macOS, where Terminal.app injects it rather than an rc file).
  env["LANG"] = resolved?.lang ?? FALLBACK_MACOS_LANG;
}

/**
 * What TERM a child gets when nothing gave it one. POSIX-shaped value, and the
 * one every terminfo database has: `dumb` is the documented "no cursor
 * addressing, no colour" terminal.
 */
const NON_INTERACTIVE_TERM = "dumb";

/**
 * Give a POSIX child a TERM, in place. Fills a HOLE only — an inherited TERM is
 * left exactly as it is, and because this runs before the caller's overlay is
 * merged, an explicit TERM in `env` still wins. Same precedence as PATH and
 * LANG, deliberately.
 *
 * WHAT WAS WRONG. This used to be a comment claiming "a remote command inherits
 * TERM=dumb, so ANSI sequences are suppressed" — a guarantee nobody provided.
 * Nothing in the agent set TERM: under launchd/systemd (the same situation the
 * LANG fix above exists for) the agent has NO TERM at all, and started from a
 * terminal it has a full xterm-256color. So the value the reasoning rested on
 * was whatever happened to be there. A comment asserting a security- or
 * correctness-relevant property the code does not have is worse than no comment,
 * because the next reader stops checking; so the code now does the thing.
 *
 * WHY `dumb` AND NOT NOTHING. A remote command is non-interactive by
 * construction — its output is read by a model, never rendered by a terminal —
 * and with TERM unset a good deal of software guesses. `dumb` is what tells ls,
 * git, pytest, npm and friends to emit no colour and no cursor control, which
 * would otherwise arrive as escape noise interleaved with the text the caller
 * actually asked for. Filling the hole is also strictly closer to a real
 * terminal session than leaving it empty: a login shell always has one.
 *
 * THE HONEST LIMIT. Because an inherited value wins, an agent started FROM a
 * terminal still passes that terminal's TERM down, and its children may still
 * colour their output. That is the same precedence trade PATH and LANG make (the
 * machine's own configuration outranks our default) and it costs nothing where
 * it matters: the shipped agent runs under launchd, systemd or the Windows
 * service, none of which hand it a TERM. So the guarantee here is "the child is
 * never left with TERM unset", not "output is never coloured".
 *
 * Windows is skipped: cmd.exe and PowerShell take no notice of TERM, and the
 * few ported tools that do would be reading a POSIX terminal name off a machine
 * that has no terminfo to look it up in.
 */
export function applyNonInteractiveTerm(env: NodeJS.ProcessEnv): void {
  if (process.platform === "win32") return;
  const inherited = env["TERM"];
  if (typeof inherited === "string" && inherited.trim() !== "") return;
  env["TERM"] = NON_INTERACTIVE_TERM;
}

/** Test helper: forget the memoized probe so a new platform/spawn can be set up. */
export function resetLoginShellPathForTest(): void {
  probe = null;
  resolved = undefined;
}
