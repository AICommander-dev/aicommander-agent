import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  errnoOf,
  errorText,
  fail,
  ok,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorFacts,
} from "../types.js";
import { doctorDiagLogDir } from "./paths.js";
import { isRefusal, pathPresence, type Presence } from "./presence.js";
import { readSessionShape, type SessionShape } from "./session-read.js";

/**
 * Where the agent keeps the two things it cannot regenerate — its device
 * identity and its session — and where it keeps the file we ask people to send
 * us.
 *
 * ── WHAT IS AND IS NOT READ ──────────────────────────────────────────────────
 * The stores hold a root-exec credential. This check STATS them; the single
 * value it ever opens one for is `session.json`'s `tokenProtected` boolean
 * (`readSessionShape`), because whether a missing `session.token` is damage or
 * normal is decided by a flag that lives inside the file and nowhere else. That
 * boolean is all that comes back — no token, no session code, nothing that could
 * reach a fact, a detail or a remedy, and so nothing that could reach a vendor's
 * inbox. Presence, size, mode and writability answer every other question a
 * support case asks. The diagnostic log's path and SIZE are reported — still
 * never its contents.
 *
 * ── ABSENCE IS PROVED, NEVER ASSUMED ─────────────────────────────────────────
 * Every `stat` here goes through `presence.ts`, which answers present / absent /
 * unknown. This file has now shipped the mistake in both directions — a creatable
 * override called unusable, and then, in the fix for that, an unstattable
 * override called "does not exist yet, the agent will create it" — and both came
 * out of collapsing a failed `stat` into "not there". A path we could not
 * inspect gets a `warn` that says so, which is neither of the two lies.
 *
 * ── EVERY CALL HERE IS ASYNCHRONOUS ──────────────────────────────────────────
 * Not a style choice. The tray runs this same library on Electron's MAIN LOOP
 * (desktop/src/diagnostics.ts), and these are the probes most likely to meet a
 * filesystem an on-access scanner is holding: a stat, an access check and an
 * actual file creation, in the directories a security product watches. A
 * synchronous call there blocks the loop for as long as the filter driver takes
 * to answer, starving the relay WebSocket's heartbeat and dropping the link —
 * the "Reconnecting…" state the user opened diagnostics to investigate. The
 * banned pattern (tray.ts's `showMessageBoxSync` note) on the one code path
 * where it is most likely to fire.
 *
 * ── DURABILITY, NOT JUST WRITABILITY ─────────────────────────────────────────
 * A store that is writable but volatile is the failure config-dir.ts exists for:
 * QNAP QTS rebuilds /etc from a ramdisk on every boot, so an agent persisting
 * its identity there comes back from a reboot with a NEW session code and no
 * linked accounts — and nothing reports it, because every write SUCCEEDED. So
 * this check names the resolved directory and whether the AICOMMANDER_CONFIG_DIR
 * override is in force, which is the only thing that distinguishes the two.
 */

/** Mirrors device.ts / session-store.ts. */
const PRIMARY_DIR = "/etc/aicommander-agent";
const DEVICE_FILE = "device.json";
const SESSION_FILE = "session.json";
/** Only written where a token vault is in use (the desktop's safeStorage). */
const SESSION_TOKEN_FILE = "session.token";

function fallbackDir(): string {
  return path.join(os.homedir(), ".config", "aicommander-agent");
}

/**
 * The override, checked WITHOUT calling `envConfigDir()`.
 *
 * `envConfigDir` validates by creating the directory and asserting write access,
 * which is right for the agent at startup and wrong for a diagnostic: a doctor
 * run must not bring a directory into existence, least of all one an operator
 * mistyped. So the same three questions are asked read-only here, and the
 * answers are reported rather than thrown.
 */
async function checkConfigOverride(): Promise<{ result: CheckResult; overrideDir: string | null }> {
  const id = "config.override";
  const title = "AICOMMANDER_CONFIG_DIR";
  const raw = process.env["AICOMMANDER_CONFIG_DIR"]?.trim();
  if (!raw) {
    return {
      overrideDir: null,
      result: ok(id, title, "not set; the default identity and session locations apply."),
    };
  }
  const facts: DoctorFacts = { value: raw };
  if (!path.isAbsolute(raw)) {
    return {
      overrideDir: null,
      result: fail(
        id,
        title,
        `set to "${raw}", which is not an absolute path — the agent refuses to start with it.`,
        "Point AICOMMANDER_CONFIG_DIR at an absolute path on durable storage. A relative path resolves against " +
          "a working directory the operator does not control.",
        facts,
      ),
    };
  }
  const status = await probeStoreDir(raw);
  const left = leftoversOf([status]);
  if (status.kind === "creatable") {
    // NOT a fault, and reporting it as one was: `envConfigDir()` creates the
    // directory at startup (mkdir recursive, 0700), so an absolute path whose
    // chain accepts a `mkdir -p` is a configuration the agent starts with
    // perfectly well. The old verdict also changed depending on whether another
    // check had happened to create the directory first, which is not a
    // measurement. This branch now requires the absence to have been PROVED —
    // see the `unknown` branch below for the state the first fix folded in here.
    return {
      overrideDir: raw,
      result: withLeftovers(
        ok(
          id,
          title,
          `in force, pointing at ${raw}, which does not exist yet — the agent creates it at startup and ` +
            `${status.ancestor} accepts writes.`,
          { ...facts, exists: false },
        ),
        left,
      ),
    };
  }
  if (status.kind === "unknown") {
    // Neither "usable" nor "unusable": something on the path would not answer,
    // so nothing has been established about it. Both other verdicts would be a
    // claim about this machine that this run did not measure.
    return {
      overrideDir: raw,
      result: withLeftovers(
        warn(
          id,
          title,
          `set to "${raw}", and whether the agent can store there could not be determined: ${status.error}`,
          "This is not a diagnosis of a fault — the path could not be inspected from this process at all, " +
            "which is itself worth knowing: an unreadable or non-traversable store directory is how a mount " +
            "that is gone, and a scanner holding a directory open, both look. Check the path by hand.",
          { ...facts, ...(status.code ? { code: status.code } : {}) },
        ),
        left,
      ),
    };
  }
  if (status.kind === "refused") {
    return {
      overrideDir: raw,
      result: withLeftovers(
        fail(
          id,
          title,
          `set to "${raw}", which is not usable: ${status.error}`,
          "The device identity and the session code live there. Until it is writable the agent refuses to " +
            "start, which is deliberate — silently falling back would mean a new session code on every restart.",
          { ...facts, ...(status.code ? { code: status.code } : {}) },
        ),
        left,
      ),
    };
  }
  return {
    overrideDir: raw,
    result: withLeftovers(
      ok(id, title, `in force, pointing at ${raw}, which is writable.`, { ...facts, exists: true }),
      left,
    ),
  };
}

/**
 * A probe file this run WROTE and could not remove. The write itself succeeded —
 * so the directory is writable, which is what the check was asking — but a
 * diagnostic that leaves a file behind has to say so, by name, wherever it ends
 * up reporting (types.ts: "nothing is left behind on disk … and a cleanup that
 * itself failed is REPORTED"). Reporting this as `refused` did both wrong things
 * at once: it said no store directory accepted a write, which is false, and
 * nothing named the file still sitting there.
 */
interface Leftover {
  file: string;
  error: string;
  code: string | null;
}

type DirStatus =
  | { kind: "writable"; leftover: Leftover | null }
  /** PROVABLY not there yet, and an existing ancestor would let the agent create it. */
  | { kind: "creatable"; ancestor: string }
  | { kind: "refused"; error: string; code: string | null }
  /** Neither established: something on the path would not answer. */
  | { kind: "unknown"; error: string; code: string | null };

/**
 * Could the agent create this directory? Asked of the whole chain, not one link.
 *
 * `envConfigDir()` and the stores create with `mkdir({recursive:true})`, so the
 * question is not "does the immediate parent accept a write" — on a fresh
 * `/srv/data/aicommander/store` the immediate parent does not exist either, and
 * testing only it answered "refused" for a path the agent creates without
 * complaint. So we walk UP to the nearest ancestor that exists and ask that one,
 * which is exactly what `mkdir -p` will do.
 *
 * A link in the chain that will not answer stops the walk as `unknown`: the
 * ancestor above it might be writable, but that would not make the unreadable
 * one traversable, and guessing either way is the thing this file is done doing.
 */
async function probeCreatable(dir: string): Promise<DirStatus> {
  let current = path.dirname(dir);
  for (;;) {
    const presence = await pathPresence(current);
    if (presence.kind === "unknown") {
      return { kind: "unknown", error: `${current} could not be inspected: ${presence.error}`, code: presence.code };
    }
    if (presence.kind === "present") {
      if (!presence.stats.isDirectory()) {
        return { kind: "refused", error: `${current} is not a directory`, code: "ENOTDIR" };
      }
      try {
        await fs.promises.access(current, fs.constants.W_OK);
        return { kind: "creatable", ancestor: current };
      } catch (err) {
        const code = errnoOf(err);
        return isRefusal(code)
          ? { kind: "refused", error: errorText(err), code }
          : { kind: "unknown", error: errorText(err), code };
      }
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return { kind: "refused", error: `nothing on the path to ${dir} exists`, code: "ENOENT" };
    }
    current = parent;
  }
}

/**
 * Can the agent store into this directory? Answered WITHOUT creating anything.
 *
 * The distinction between "refused" and "not there yet" is the whole point. The
 * stores walk a ladder — /etc first, then the per-user config dir — and create
 * whichever one they land on (device.ts, session-store.ts). A non-root agent has
 * no `/etc/aicommander-agent` and never will, and reporting that as a fault
 * would fire on every user install on every platform. So a directory PROVED
 * missing whose chain accepts a `mkdir -p` is `creatable`, which is exactly what
 * the agent will do with it.
 *
 * The third state is the one the first fix for this lost. A directory whose
 * `stat` fails with anything other than ENOENT/ENOTDIR — an unreadable mount, a
 * non-traversable parent, an EIO — has not been shown to be absent, and calling
 * it "creatable" reports a machine that may well be broken as healthy. It is
 * `unknown`, and the callers say so out loud.
 *
 * An existing directory gets a real write probe, and the probe file is removed —
 * a diagnostic leaves nothing behind, including here.
 */
async function probeStoreDir(dir: string): Promise<DirStatus> {
  const presence = await pathPresence(dir);
  if (presence.kind === "unknown") {
    return { kind: "unknown", error: `${dir} could not be inspected: ${presence.error}`, code: presence.code };
  }
  if (presence.kind === "absent") return probeCreatable(dir);
  if (!presence.stats.isDirectory()) {
    return { kind: "refused", error: `${dir} exists but is not a directory`, code: "ENOTDIR" };
  }
  const file = path.join(dir, `.aicommander-doctor-${process.pid}-${Date.now().toString(36)}.tmp`);
  try {
    await fs.promises.writeFile(file, "probe\n", { flag: "wx", mode: 0o600 });
  } catch (err) {
    return { kind: "refused", error: errorText(err), code: errnoOf(err) };
  }
  try {
    await fs.promises.rm(file, { force: true });
  } catch (err) {
    // Written, so the directory IS writable; not removed, so this run has left a
    // file in it and the caller has to name that file. install.ts's twin probe
    // has always reported this case honestly — see `Leftover` above.
    return { kind: "writable", leftover: { file, error: errorText(err), code: errnoOf(err) } };
  }
  return { kind: "writable", leftover: null };
}

/**
 * Fold every probe file this run could not remove into whatever the check was
 * going to say, so that no verdict — pass, warn or fail — can be published while
 * a `.aicommander-doctor-*.tmp` of ours is still sitting in somebody's store
 * directory with nothing naming it.
 *
 * Applied at the RETURN rather than in one branch on purpose: which branch wins
 * depends on the machine (a loose mode, a half-written store, an indeterminate
 * path all outrank it), and the leftover has to be said out loud in all of them.
 * A leftover never improves a verdict and never downgrades a `fail`.
 */
function withLeftovers(result: CheckResult, leftovers: Leftover[]): CheckResult {
  if (leftovers.length === 0) return result;
  const named = leftovers.map((l) => `${l.file} (${l.error})`).join("; ");
  return {
    ...result,
    verdict: result.verdict === "fail" ? "fail" : "warn",
    detail: `${result.detail} This run also LEFT a probe file behind that it could not remove: ${named}.`,
    remedy:
      `${result.remedy ? `${result.remedy} ` : ""}Delete ${leftovers.map((l) => l.file).join(", ")} by hand — ` +
      "the diagnostic could not, and it does not belong there. A file that cannot be deleted right after being " +
      "created is usually held open by a scanner.",
    facts: { ...(result.facts ?? {}), leftover: named },
  };
}

/** The probe files a set of directory probes failed to clean up. */
function leftoversOf(statuses: DirStatus[]): Leftover[] {
  return statuses.flatMap((status) =>
    status.kind === "writable" && status.leftover ? [status.leftover] : [],
  );
}

/**
 * The identity and session store: is it there, is it complete, is it private,
 * and can the agent still write to it?
 *
 * ── WHY "SOME OF THE FILES" IS NOT AUTOMATICALLY DAMAGE ──────────────────────
 * The agent needs both halves to stay the same machine across a restart, and a
 * store that has LOST one is exactly what a scanner's quarantine leaves behind.
 * But the two halves are not written at the same moment, and the rule that
 * ignored that told the truth about a quarantined store by lying about the most
 * common machine there is:
 *
 *   `loadOrCreateDevice()` persists `device.json` BEFORE `register()` is ever
 *   attempted (device.ts), and `session.json` only exists once the relay has
 *   answered. So a machine that has never reached the relay — never registered,
 *   first start, or simply offline — legitimately has `device.json` and no
 *   `session.json`. That is the state `doctor` is most often run in, and telling
 *   that user their store bears "the signature of a scanner having quarantined
 *   it" is both wrong and alarming.
 *
 * The order the files appear in is therefore what separates the two states:
 *
 *   device.json only ................ never registered. Normal. Not damage.
 *   session.json without device.json . damage: the identity the session belongs
 *                                     to is gone, so the next start registers
 *                                     again and every linked account follows the
 *                                     old device.
 *   session.token without session.json  damage: a sidecar for a session that is
 *                                     not there.
 *   session.json says tokenProtected,
 *     and session.token is missing ... damage: the token itself is gone, and the
 *                                     agent cannot present a credential it can
 *                                     no longer decrypt. This is the one that
 *                                     needs the file OPENED (readSessionShape) —
 *                                     an unprotected session has no sidecar to
 *                                     lose, and a stat cannot tell them apart.
 *
 * Anything we could not stat is neither, and gets its own verdict.
 */
async function checkCredentialStore(
  ctx: DoctorContext,
  overrideDir: string | null,
): Promise<CheckResult> {
  const id = "config.store";
  const title = "Identity and session store";

  // The same ladder device.ts and session-store.ts walk: an explicit configDir
  // (the desktop's per-user data dir) wins, then the override, then /etc with a
  // per-user fallback.
  const readDirs = ctx.configDir
    ? [ctx.configDir]
    : overrideDir
      ? [overrideDir, PRIMARY_DIR, fallbackDir()]
      : [PRIMARY_DIR, fallbackDir()];
  // Where a WRITE would go. With an explicit dir or the override in force there
  // is exactly one candidate and it is authoritative; otherwise the store tries
  // /etc and falls back to the per-user config dir, so both are candidates and
  // ONE of them being usable is success.
  const writeDirs = ctx.configDir ? [ctx.configDir] : overrideDir ? [overrideDir] : [PRIMARY_DIR, fallbackDir()];

  const found: string[] = [];
  /** Files whose presence we could not establish either way — never counted as absent. */
  const indeterminate: string[] = [];
  const seenNames = new Set<string>();
  const unknownNames = new Set<string>();
  let looseMode: { detail: string; dir: string } | null = null;
  /** The directory that actually holds session.json — where its sidecar would be. */
  let sessionDir: string | null = null;
  for (const dir of readDirs) {
    for (const name of [DEVICE_FILE, SESSION_FILE, SESSION_TOKEN_FILE]) {
      const target = path.join(dir, name);
      const presence: Presence = await pathPresence(target);
      if (presence.kind === "unknown") {
        unknownNames.add(name);
        indeterminate.push(`${target} (${presence.error})`);
        continue;
      }
      if (presence.kind === "absent") continue;
      found.push(target);
      seenNames.add(name);
      if (name === SESSION_FILE && sessionDir === null) sessionDir = dir;
      // 0600 is what atomic-file.ts writes. Anything group- or world-readable
      // means a local unprivileged user can read a root-exec credential.
      if (process.platform !== "win32" && (presence.stats.mode & 0o077) !== 0) {
        looseMode = { detail: `${target} is mode ${(presence.stats.mode & 0o777).toString(8)}`, dir };
      }
    }
  }

  // Opened only when there is a session to ask about, and only for the flag.
  const shape: SessionShape | null = sessionDir ? await readSessionShape(sessionDir) : null;
  if (shape?.kind === "unreadable") indeterminate.push(`${path.join(sessionDir!, SESSION_FILE)} (${shape.error})`);

  /** A name is MISSING only when its absence was proved. */
  const absent = (name: string): boolean => !seenNames.has(name) && !unknownNames.has(name);
  const damage: string[] = [];
  if (seenNames.has(SESSION_FILE) && absent(DEVICE_FILE)) {
    damage.push(`${DEVICE_FILE} is gone while ${SESSION_FILE} is still there`);
  }
  if (seenNames.has(SESSION_TOKEN_FILE) && absent(SESSION_FILE)) {
    damage.push(`${SESSION_TOKEN_FILE} is there without the ${SESSION_FILE} that names it`);
  }
  if (shape?.kind === "present" && shape.tokenProtected && absent(SESSION_TOKEN_FILE)) {
    damage.push(
      `${SESSION_FILE} says its token is held in OS-protected storage, but the ${SESSION_TOKEN_FILE} ` +
        "holding it is gone",
    );
  }

  const probes: Array<{ dir: string; status: DirStatus }> = [];
  for (const dir of writeDirs) probes.push({ dir, status: await probeStoreDir(dir) });
  // Named in EVERY branch below, not just the one that noticed — see withLeftovers.
  const left = leftoversOf(probes.map((p) => p.status));
  const usable = probes.find((p) => p.status.kind === "writable" || p.status.kind === "creatable");
  const undetermined = probes.filter((p) => p.status.kind === "unknown");
  const facts: DoctorFacts = {
    writeDir: usable?.dir ?? writeDirs.join(", "),
    searched: readDirs.join(", "),
    found: found.length > 0 ? found.join(", ") : null,
    registered: unknownNames.has(SESSION_FILE) ? null : seenNames.has(SESSION_FILE),
    damaged: damage.length > 0 ? damage.join("; ") : null,
    indeterminate: indeterminate.length > 0 ? indeterminate.join("; ") : null,
    override: overrideDir,
  };

  // Every branch below is a VERDICT; the probe files this run could not remove
  // are a statement about the run itself, and withLeftovers folds them into
  // whichever verdict wins so a leftover can never go unnamed.
  const verdict = ((): CheckResult => {
    if (!usable && undetermined.length === 0) {
      const refusals = probes
        .map((p) => `${p.dir}: ${p.status.kind === "refused" ? p.status.error : ""}`)
        .join("; ");
      return fail(
        id,
        title,
        `no store directory accepted a write (${refusals})`,
        "The agent cannot persist its identity or its session code there, so it will come back from every " +
          "restart as a different machine. Fix the permissions, or set AICOMMANDER_CONFIG_DIR to durable, " +
          "writable storage.",
        facts,
      );
    }
    if (looseMode) {
      return warn(
        id,
        title,
        `${looseMode.detail} — a local user can read a credential that runs commands here.`,
        `Run: chmod 600 on the files in ${looseMode.dir}.`,
        facts,
      );
    }
    if (!usable) {
      // Every write candidate was indeterminate. Not a fault and not a pass.
      return warn(
        id,
        title,
        `whether the store directory accepts writes could not be determined ` +
          `(${undetermined.map((p) => `${p.dir}: ${p.status.kind === "unknown" ? p.status.error : ""}`).join("; ")})`,
        "Inspect the path by hand. A store directory that answers neither way is how a vanished mount and a " +
          "scanner holding a directory open both look.",
        facts,
      );
    }
    if (indeterminate.length > 0) {
      return warn(
        id,
        title,
        `the store could not be inspected in full, so whether it is complete is unknown: ${indeterminate.join("; ")}`,
        "The files below the store directory could not all be read. Until they can, neither 'this machine is " +
          "registered' nor 'a file has gone missing' can be said about it — check the directory by hand.",
        facts,
      );
    }
    if (damage.length > 0) {
      return warn(
        id,
        title,
        `the store has lost a file: ${damage.join("; ")}.`,
        "The agent writes its identity before it registers and its session after, so this order cannot happen " +
          "on its own — a file that has gone missing by itself is the signature of a scanner having quarantined " +
          "it. Restore it from quarantine if so; otherwise start the agent once to rebuild the store, and expect " +
          "a new session code that linked accounts will have to be pointed at again.",
        facts,
      );
    }
    if (!seenNames.has(SESSION_FILE)) {
      // Never registered — the ordinary state of a machine somebody is running
      // diagnostics on. `device.json` alone is part of it, not evidence against it.
      return warn(
        id,
        title,
        found.length === 0
          ? `no identity or session file exists yet under ${readDirs.join(" or ")}; the directory does accept writes.`
          : `${DEVICE_FILE} is there and ${SESSION_FILE} is not: this machine has a device identity but has ` +
            "never completed a registration with the relay.",
        "Nothing here is damaged — the identity is written at startup and the session only once the relay has " +
          "answered. Start the agent and let it reach the relay once; if it has been running, the connectivity " +
          "checks say why registration is not completing.",
        facts,
      );
    }
    return ok(
      id,
      title,
      `${found.length} store file(s) present, and ${usable.dir} ` +
        `${usable.status.kind === "writable" ? "accepts writes" : "can be created by the agent"}.`,
      facts,
    );
  })();
  return withLeftovers(verdict, left);
}

/**
 * The diagnostic log: where it is and how big, so the user can find the file we
 * ask them to attach. Its contents are already redacted at the point of writing
 * (see diag-log.ts) — they are still not read here.
 */
async function checkDiagLog(ctx: DoctorContext): Promise<CheckResult> {
  const id = "diag.log";
  const title = "Diagnostic log";
  // paths.ts, never diag-log.ts's own resolver: that one falls back to
  // `envConfigDir()`, which CREATES the configured directory (synchronously,
  // on Electron's main loop) — so simply naming the log directory used to be a
  // mutation, on exactly the machine whose override was mistyped.
  const dir = doctorDiagLogDir(ctx.configDir);

  let entries: string[];
  try {
    entries = await fs.promises.readdir(dir);
  } catch (err) {
    return warn(
      id,
      title,
      `no diagnostic log directory at ${dir} (${errorText(err)}).`,
      "Nothing has written a log here yet. Run the agent (or the desktop app) once, reproduce the problem, " +
        "then re-run this command.",
      { dir },
    );
  }
  const logs = entries.filter((name) => /\.log(\.\d+)?$/.test(name));
  if (logs.length === 0) {
    return warn(id, title, `the log directory ${dir} exists but holds no log files.`, "Run the agent once and reproduce the problem.", { dir });
  }
  const sizes: string[] = [];
  for (const name of logs) {
    const presence = await pathPresence(path.join(dir, name));
    sizes.push(
      `${name} (${presence.kind === "present" ? Math.round(presence.stats.size / 1024) : "?"} KiB)`,
    );
  }
  return ok(id, title, `${logs.length} log file(s) in ${dir}: ${sizes.join(", ")}.`, {
    dir,
    files: sizes.join(", "),
  });
}

export const storageChecks: DoctorCheckGroup = {
  id: "config",
  title: "Configuration and credentials",
  async run(ctx) {
    const override = await checkConfigOverride();
    return [
      override.result,
      await checkCredentialStore(ctx, override.overrideDir),
      await checkDiagLog(ctx),
    ];
  },
};
