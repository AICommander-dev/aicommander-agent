/**
 * `aicommander-agent self-update` — the upgrade procedure as CODE, because as
 * prose it is reliably got wrong.
 *
 * The documented Linux upgrade is not hard, it is just unforgiving, and every
 * one of its traps is invisible until it fires. All three of these happened in
 * one sitting on 2026-08-10, to a caller that had the README open:
 *
 *  - `sh install` instead of `bash install` — Ubuntu's /bin/sh is dash, which
 *    has no `set -o pipefail`, so the installer dies on line 2;
 *  - `curl /install | bash` — that path is a MUTABLE TEMPLATE which refuses to
 *    run (its version placeholder is unsubstituted); the real one is the signed
 *    `/dist/v/<ver>/install`, and the difference is invisible until you read the
 *    error;
 *  - running any of it in the FOREGROUND of a remote_exec — the installer
 *    restarts the service, which kills the agent, which kills the command that
 *    was mid-install.
 *
 * And the subtlest one: a health check that asks "is the agent running?" answers
 * YES after a failed upgrade, because the OLD agent is running perfectly well.
 * The only question worth asking afterwards is "is it running the version I
 * asked for?".
 *
 * So this command does the whole thing itself: detaches from its caller, fetches
 * the versioned installer, verifies it against a signing key COMPILED IN (not
 * fetched — a key you download from the same host as the payload proves nothing),
 * backs up the current binary, installs, then verifies the VERSION and that the
 * service stayed up — and restores the backup if either fails.
 *
 * Scope is deliberately narrow. It refuses anything it cannot make safe rather
 * than improvising: see `selfUpdatePreflight`.
 */

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AGENT_VERSION } from "./version.js";
import { isNewerVersion, compareVersions } from "./update-check.js";

/**
 * The release signing key, embedded rather than fetched.
 *
 * `web/install` downloads `/install.pub` and checks its fingerprint, because a
 * shell script cannot carry a key. We can, and doing so removes a whole class of
 * problem: a key served from the same origin as the payload is only as
 * trustworthy as that origin, so fetching it and then verifying the payload with
 * it proves the payload matches whatever the origin wanted. Compiled in, the key
 * arrives through the signed release the operator already trusted.
 *
 * Identical to `web/install.pub`; its SHA-256 (DER/SPKI) is the fingerprint
 * README publishes for independent confirmation, and `signingKeyFingerprint()`
 * below recomputes it so a bad edit here fails a test rather than a machine.
 */
const RELEASE_SIGNING_KEY_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAcqNx01NvglpKTsF60Yij5LuoIHgXJ/SUoQysfU2eyRw=\n" +
  "-----END PUBLIC KEY-----\n";

/** The value README publishes, and the one an operator confirms out of band. */
export const RELEASE_SIGNING_KEY_SHA256 =
  "2d76d381fc8ed38e7dfb53882e14b2980ee105e0b49ff31cf55403e19e648407";

/** Set on the detached child so it knows to do the work instead of re-detaching. */
const WORKER_ENV = "AIC_SELF_UPDATE_WORKER";

/** Transient unit name for the detached worker. `--collect` reaps it when it exits. */
const TRANSIENT_UNIT = "aicommander-self-update";

/**
 * How the worker is launched so the upgrade cannot kill its own supervision.
 *
 * `detached: true` is NOT enough, and the difference is invisible until it costs
 * you: it starts a new session and process group, but the child stays in the
 * agent service's CGROUP — and the unit runs with systemd's default
 * `KillMode=control-group`, so `systemctl restart aicommander-agent` (which the
 * installer performs) kills every process in that group. The updater would be
 * killed by the restart it just triggered, half-way through, with the binary
 * already swapped and nothing left to verify or roll back.
 *
 * This is not a theoretical concern — it happened on 2026-08-10, to a hand-written
 * setsid script whose log simply stops after "backup ok". The upgrade landed by
 * luck; the verification and rollback never ran and nobody noticed until the cgroup
 * was checked.
 *
 * `systemd-run` puts the worker in a transient unit of ITS OWN, outside the agent's
 * control group, which is the whole point. It is also why preflight insists on
 * systemd: without it there is no way to escape, and the honest answer is to refuse.
 */
export function selfUpdateLaunchArgv(
  binary: string,
  forwardedArgs: readonly string[],
  env: Readonly<Record<string, string | undefined>> = {},
): string[] {
  const argv = [
    "--collect",
    `--unit=${TRANSIENT_UNIT}`,
    "--property=KillMode=process",
    `--setenv=${WORKER_ENV}=1`,
  ];
  // Carry the relay override so a dev/staging agent updates from the same origin
  // it talks to, rather than silently from production.
  if (env["AICOMMANDER_SERVER"]) argv.push(`--setenv=AICOMMANDER_SERVER=${env["AICOMMANDER_SERVER"]}`);
  argv.push(binary, ...forwardedArgs);
  return argv;
}

/** Durable, root-owned home for the backup binary and the log. */
const WORK_DIR = "/var/lib/aicommander";
const LOG_PATH = path.join(WORK_DIR, "self-update.log");
const BACKUP_PATH = path.join(WORK_DIR, "agent.bak");
const LOCK_PATH = path.join(WORK_DIR, "self-update.lock");

/** How long the new agent gets to come up, and the gap proving it stayed up. */
const SETTLE_MS = 25_000;
const STABILITY_MS = 15_000;

/** Runtimes that mean "this is the npm install shape", where the exe is not us. */
const JS_RUNTIMES = new Set(["node", "bun", "deno"]);

export interface PreflightEnv {
  platform: NodeJS.Platform;
  /** process.getuid(), or undefined on a platform without one. */
  uid: number | undefined;
  /** Basename of process.execPath — the agent binary, or a JS runtime. */
  execName: string;
  /** Whether this machine is running systemd (i.e. /run/systemd/system exists). */
  hasSystemd: boolean;
}

/**
 * Why this machine may not self-update, or null when it may.
 *
 * Each refusal names the supported alternative, because "no" without a next step
 * is what pushes a caller back into improvising — which is the thing this whole
 * command exists to stop.
 */
export function selfUpdatePreflight(env: PreflightEnv): string | null {
  if (env.platform !== "linux") {
    return (
      "self-update is for the headless Linux agent only.\n" +
      "macOS and Windows update through the desktop app: Windows installs silently via the\n" +
      "'AI Commander Update' scheduled task (schtasks /Run /TN \"AI Commander Update\"), and\n" +
      "macOS stages the update and applies it when you pick 'Restart to install' in the tray."
    );
  }
  if (env.uid !== 0) {
    return "self-update must run as root — it replaces /usr/local/bin and restarts the service.\nTry: sudo aicommander-agent self-update";
  }
  if (JS_RUNTIMES.has(env.execName.replace(/\.exe$/, ""))) {
    return (
      "This is the npm install shape (the agent runs under a JS runtime), which self-update\n" +
      "does not manage: its upgrade replaces a package and rewrites the unit's ExecStart, so a\n" +
      "binary backup could not roll it back. Upgrade it the documented way, both steps:\n" +
      "  sudo npm i -g @aicommander/agent@latest && sudo aicommander-agent install"
    );
  }
  if (!env.hasSystemd) {
    // Name the steps, do not just cite a document. The refusal used to point at
    // "the documented swap procedure" in a file that had no such section, using a
    // repo path the operator does not have on their NAS — a "no" whose way forward
    // did not exist, which is the exact thing that sends a caller back to
    // improvising. The section exists now; the summary below stands on its own
    // even for someone who cannot reach the page.
    return (
      "No systemd on this machine, so nothing here can promise the agent comes back after the\n" +
      "binary is replaced — and an agent that does not come back takes remote access with it.\n" +
      "Refusing rather than guessing: on a box like this the restart authority is your own\n" +
      "keepalive/cron entry, not an init system.\n" +
      "Upgrade it by hand instead, in this order: stage and verify the new binary beside the\n" +
      "old one (never over it), keep a copy of the current one, stop the agent and confirm it\n" +
      "is stopped, rename the new binary into place, then start it and check --version.\n" +
      "Full procedure for QNAP/QTS: https://aicommander.dev/skill/qnap/SKILL.md (see\n" +
      "\"Upgrading an existing install\")."
    );
  }
  return null;
}

/** Fingerprint of the compiled-in key, in the form README publishes. */
export function signingKeyFingerprint(): string {
  const der = crypto.createPublicKey(RELEASE_SIGNING_KEY_PEM).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

/**
 * Is `installer` genuinely the release we published? Ed25519 over the raw bytes,
 * matching the detached `.sig` the release job uploads next to it.
 *
 * Returns false rather than throwing for a malformed signature: a corrupt or
 * truncated download is an ordinary outcome here, not an exceptional one, and it
 * must land in the same "do not install" branch as a wrong one.
 */
export function verifyInstallerSignature(installer: Buffer, signature: Buffer): boolean {
  try {
    return crypto.verify(null, installer, crypto.createPublicKey(RELEASE_SIGNING_KEY_PEM), signature);
  } catch {
    return false;
  }
}

export interface OutcomeInput {
  /** `systemctl is-active` at the end, verbatim. */
  activeState: string;
  /** MainPID read BEFORE the installer ran — the process we are replacing. */
  pidBeforeInstall: string;
  /** MainPID sampled twice after the install, STABILITY_MS apart. */
  pidBefore: string;
  pidAfter: string;
  /** What the on-disk binary reports now, and what we asked for. */
  installedVersion: string;
  targetVersion: string;
}

export type Outcome = { ok: true } | { ok: false; reason: string };

/**
 * Did the upgrade actually take? Three conditions, and the VERSION one is the
 * point: "the service is running" is true after a failed install too, because the
 * old agent never stopped. A check that cannot tell those apart reports success
 * for an upgrade that did not happen — which is exactly what happened here on the
 * first attempt.
 *
 * The pid pair catches the other shape of failure: a new binary that starts,
 * crashes, and gets restarted forever by `Restart=always`. Sampled across a gap,
 * a flapping unit shows two different MainPIDs while `is-active` still says
 * `active` at both ends.
 */
export function updateOutcome(input: OutcomeInput): Outcome {
  if (input.activeState !== "active") {
    return { ok: false, reason: `service is ${input.activeState}, not active` };
  }
  if (input.pidBefore === "0" || input.pidBefore === "" || input.pidBefore !== input.pidAfter) {
    return { ok: false, reason: `service is restarting (MainPID ${input.pidBefore} → ${input.pidAfter})` };
  }
  // The service must actually have been REPLACED. Without this, an installer that
  // swaps the binary and then dies before restarting systemd passes every other
  // check: the old process is still active with a rock-steady pid, while
  // `installedVersion` — which executes the file on disk, not the running
  // process — cheerfully reports the new version. Success would be logged for a
  // machine still serving the old release. A pid that never changed means the
  // restart never happened, whatever the disk says.
  if (input.pidAfter === input.pidBeforeInstall) {
    return {
      ok: false,
      reason: `service never restarted (MainPID still ${input.pidAfter}); the binary may be swapped but the running agent is not`,
    };
  }
  if (input.installedVersion !== input.targetVersion) {
    return {
      ok: false,
      reason: `still running ${input.installedVersion || "an unknown version"}, expected ${input.targetVersion}`,
    };
  }
  return { ok: true };
}

/**
 * Is the lock file a live claim, or the corpse of a worker that was killed?
 *
 * The lock lives in a DURABLE directory and its holder can die without unlinking
 * it — OOM, `systemctl kill`, a host reboot mid-update, or the very cgroup kill
 * this module exists to escape. Honouring it blindly turns one dead process into
 * a machine that refuses to update FOREVER, and refuses it quietly: the refusal
 * only reaches the log, while the parent has already told the caller the update
 * started. That is a worse failure than a rare double-run.
 *
 * `maxAgeMs` is a backstop for the case pid checks cannot cover — after a reboot,
 * the recorded pid may well be alive again as something else entirely.
 */
export function lockVerdict(
  content: string,
  ageMs: number,
  isAlive: (pid: number) => boolean,
  maxAgeMs = 2 * 60 * 60_000,
): "held" | "stale" {
  if (ageMs > maxAgeMs) return "stale";
  const pid = Number.parseInt(content.trim(), 10);
  if (!Number.isInteger(pid) || pid <= 1) return "stale";
  return isAlive(pid) ? "held" : "stale";
}

/**
 * The relay this agent actually talks to, read from its systemd unit.
 *
 * `web/install` bakes the override into the unit as
 * `Environment="AICOMMANDER_SERVER=…"`, and that is the only durable record of it.
 * Taking it from the CLI's own environment instead is wrong in the exact case it
 * matters: run as documented (`sudo aicommander-agent self-update`), sudo's
 * `env_reset` strips the variable, self-update falls back to production, fetches
 * the production installer — and that installer REWRITES the unit's Environment
 * line, moving a staging box onto the production relay as a side effect of
 * upgrading it.
 *
 * Input is the raw `systemctl show -p Environment aicommander-agent` line.
 */
export function serverUrlFromUnitEnvironment(showOutput: string): string | null {
  // The boundary must admit `=` as well as whitespace and a quote: systemd prints
  // `Environment=AICOMMANDER_SERVER=…` for the first variable and
  // `Environment="AICOMMANDER_SERVER=…"` when it quotes. Requiring whitespace found
  // neither, which a test caught before this ever reached a machine.
  const match = /(?:^|[\s"=])AICOMMANDER_SERVER=("?)([^"\s]+)\1/.exec(showOutput);
  const value = match?.[2];
  return value && /^https?:\/\//.test(value) ? value : null;
}

export type TargetVerdict =
  | { proceed: true; warning?: string }
  | { proceed: false; reason: string };

/**
 * Should we install `target` over `current`?
 *
 * The interesting case is DOWNWARDS. An old release carries a perfectly valid
 * signature — signing proves provenance, never freshness — so the signature check
 * cannot tell a genuine upgrade from a replayed older one. A `/dist/latest` that
 * is stale, misdeployed, or attacker-controlled would otherwise walk a whole fleet
 * back onto a version whose bugs are public knowledge, one machine at a time, with
 * every cryptographic check passing.
 *
 * So the version pointer may only ever move an agent FORWARD on its own authority.
 * Going back is a decision a person makes, with --force, and it is logged as what
 * it is.
 */
export function evaluateTarget(target: string, current: string, force: boolean): TargetVerdict {
  if (isNewerVersion(target, current)) return { proceed: true };
  const goingBack = compareVersions(target, current) < 0;
  if (!force) {
    return {
      proceed: false,
      reason: goingBack
        ? `REFUSING TO DOWNGRADE to ${target} (running ${current}) — the version pointer may only move forward; use --force if this is deliberate`
        : `already on ${target} — nothing to do (use --force to reinstall)`,
    };
  }
  return goingBack
    ? { proceed: true, warning: `WARNING: --force is taking this agent DOWN from ${current} to ${target}` }
    : { proceed: true };
}

/**
 * Put `source` at `target` even when `target` is a RUNNING executable.
 *
 * `copyFileSync` opens the destination for writing, which Linux refuses with
 * ETXTBSY while the file is being executed — and that is precisely the state
 * during a rollback: the failed new agent is running from that path. The throw
 * would escape before the restart, so the one code path whose entire job is to
 * rescue an unreachable machine would be the one that fails on it.
 *
 * Writing beside it and renaming over it is atomic, permitted while the old
 * inode is still executing (the running process keeps it), and leaves no window
 * in which the path holds a half-written binary.
 */
export function replaceExecutable(source: string, target: string): void {
  const staged = `${target}.staged-${process.pid}`;
  try {
    fs.copyFileSync(source, staged);
    fs.chmodSync(staged, 0o755);
    fs.renameSync(staged, target);
  } catch (err) {
    try {
      fs.unlinkSync(staged);
    } catch {
      // Nothing useful to do; the rename either happened or it did not.
    }
    throw err;
  }
}

// ── Orchestration ───────────────────────────────────────────────────────────

function log(line: string): void {
  const stamp = new Date().toISOString().replace("T", " ").slice(0, 19);
  try {
    fs.appendFileSync(LOG_PATH, `[${stamp}] ${line}\n`);
  } catch {
    // A log we cannot write must never be the reason an upgrade stops.
  }
}

function systemctl(...args: string[]): string {
  try {
    return execFileSync("systemctl", args, { encoding: "utf8", timeout: 15_000 }).trim();
  } catch {
    return "";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** What the binary on disk says it is — the only honest answer to "did it swap?". */
function installedVersion(binary: string): string {
  try {
    return execFileSync(binary, ["--version"], { encoding: "utf8", timeout: 15_000 }).trim();
  } catch {
    return "";
  }
}

export interface SelfUpdateOptions {
  /** Update even when the published version equals the running one. */
  force?: boolean;
  /**
   * Explicit relay origin. Undefined means "ask the unit, then fall back to
   * production" — see serverUrlFromUnitEnvironment for why the caller's own
   * environment is the wrong source.
   */
  serverUrl?: string | undefined;
}

/**
 * CLI entry. On the first call this DETACHES and returns immediately; the child
 * does the work.
 *
 * The detach is not a nicety. The installer restarts the service, which kills the
 * agent — and with it any remote_exec session that started this command. A
 * foreground upgrade therefore dies at its most dangerous moment: binary swapped,
 * service restarting, nothing left to verify or roll back. Detached, the caller
 * losing its connection is expected and harmless; the child finishes alone and
 * writes its verdict to the log.
 */
export async function cmdSelfUpdate(opts: SelfUpdateOptions): Promise<void> {
  const refusal = selfUpdatePreflight({
    platform: process.platform,
    uid: typeof process.getuid === "function" ? process.getuid() : undefined,
    execName: path.basename(process.execPath),
    hasSystemd: fs.existsSync("/run/systemd/system"),
  });
  if (refusal !== null) {
    console.error(refusal);
    process.exitCode = 1;
    return;
  }

  if (process.env[WORKER_ENV] !== "1") {
    try {
      fs.mkdirSync(WORK_DIR, { recursive: true, mode: 0o700 });
    } catch {
      console.error(`Cannot create ${WORK_DIR} — self-update needs a durable place for its backup.`);
      process.exitCode = 1;
      return;
    }
    // Escape the agent's control group — see selfUpdateLaunchArgv. A plain
    // detached spawn would be killed by the very restart this update performs.
    // slice(2), not slice(1): process.argv is [execPath, entry, ...realArgs] on
    // BOTH shapes, and the entry is the runtime's business, not ours. Forwarding it
    // would hand the worker `<binary> /$bunfs/root/… self-update`, whose argv[2] is
    // that path — the worker would exit on an unknown command while this parent
    // cheerfully reported the update as started, and nothing would ever be written
    // to the log. Passing only the real arguments keeps both shapes identical.
    const argv = selfUpdateLaunchArgv(process.execPath, process.argv.slice(2), process.env);
    try {
      execFileSync("systemd-run", argv, { stdio: "pipe", timeout: 30_000 });
    } catch (err) {
      console.error(
        `Could not start the update in its own systemd unit: ${String(err)}\n` +
          `Refusing to fall back to a plain background process: it would live in this agent's\n` +
          `control group and be killed by the service restart the update itself triggers —\n` +
          `leaving the binary swapped with nothing left to verify or roll back.`,
      );
      process.exitCode = 1;
      return;
    }
    console.log(
      `Self-update started as the transient unit '${TRANSIENT_UNIT}'.\n` +
        `It runs outside this agent's control group on purpose: installing restarts the agent,\n` +
        `which would otherwise kill the updater mid-swap.\n` +
        `Follow it:  tail -f ${LOG_PATH}   (or: journalctl -u ${TRANSIENT_UNIT} -f)\n` +
        `Verify:     aicommander-agent --version   (or session_status from your client)`,
    );
    return;
  }

  await runSelfUpdate(opts);
}

/** The detached worker: fetch, verify, install, prove, roll back on doubt. */
async function runSelfUpdate(opts: SelfUpdateOptions): Promise<void> {
  const binary = process.execPath;

  // One at a time. Two concurrent swaps of the same file is the one way to end up
  // with a binary that is neither the old nor the new one.
  let lockFd: number;
  try {
    lockFd = fs.openSync(LOCK_PATH, "wx");
  } catch {
    // Someone holds it — or something died holding it. See lockVerdict: a corpse
    // in a durable directory would otherwise disable updates on this machine
    // permanently, and quietly, because the refusal reaches only the log.
    const alive = (pid: number): boolean => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    let verdict: "held" | "stale";
    try {
      verdict = lockVerdict(
        fs.readFileSync(LOCK_PATH, "utf8"),
        Date.now() - fs.statSync(LOCK_PATH).mtimeMs,
        alive,
      );
    } catch {
      verdict = "stale"; // unreadable lock tells us nothing, and blocks forever
    }
    if (verdict === "held") {
      log("another self-update is already running — refusing");
      return;
    }
    log("found a stale self-update lock (its holder is gone) — clearing it");
    try {
      fs.unlinkSync(LOCK_PATH);
      lockFd = fs.openSync(LOCK_PATH, "wx");
    } catch {
      log("could not clear the stale lock — refusing");
      return;
    }
  }
  try {
    fs.writeSync(lockFd, String(process.pid));
    log(`=== self-update start (running ${AGENT_VERSION}, binary ${binary}) ===`);

    // Precedence: an explicit override from the caller, then the relay baked into
    // this agent's own unit, then production. The middle step is the one that
    // matters — see serverUrlFromUnitEnvironment: without it, `sudo` strips the
    // variable and a staging box quietly re-points itself at production.
    const fromUnit = serverUrlFromUnitEnvironment(
      systemctl("show", "-p", "Environment", "aicommander-agent"),
    );
    const resolved = opts.serverUrl ?? fromUnit ?? "https://aicommander.dev";
    if (opts.serverUrl === undefined && fromUnit !== null) log(`relay (from the unit): ${fromUnit}`);
    const base = resolved.replace(/\/+$/, "");
    const meta = (await (await fetch(`${base}/dist/latest`, { headers: { Accept: "application/json" } })).json()) as {
      version?: unknown;
    };
    const target = typeof meta.version === "string" ? meta.version : "";
    if (!/^\d+\.\d+\.\d+$/.test(target)) {
      log(`published version is not usable (${JSON.stringify(meta.version)}) — stopping`);
      return;
    }
    const verdict = evaluateTarget(target, AGENT_VERSION, opts.force === true);
    if (!verdict.proceed) {
      log(verdict.reason);
      return;
    }
    if (verdict.warning) log(verdict.warning);
    log(`target: ${target}`);

    const [installerRes, sigRes] = await Promise.all([
      fetch(`${base}/dist/v/${target}/install`),
      fetch(`${base}/dist/v/${target}/install.sig`),
    ]);
    if (!installerRes.ok || !sigRes.ok) {
      log(`download failed (installer ${installerRes.status}, signature ${sigRes.status}) — stopping`);
      return;
    }
    const installer = Buffer.from(await installerRes.arrayBuffer());
    const signature = Buffer.from(await sigRes.arrayBuffer());

    if (!verifyInstallerSignature(installer, signature)) {
      // Nothing has been touched yet, and nothing will be.
      log("INSTALLER SIGNATURE INVALID — refusing to install anything");
      return;
    }
    log("installer signature ok");

    fs.copyFileSync(binary, BACKUP_PATH);
    fs.chmodSync(BACKUP_PATH, 0o755);
    log(`backup ok: ${fs.statSync(BACKUP_PATH).size} B → ${BACKUP_PATH}`);

    // Read BEFORE the installer runs: the pid we are replacing. Comparing against
    // it afterwards is the only way to know the service actually restarted rather
    // than the binary merely having been swapped underneath a live old process.
    const pidBeforeInstall = systemctl("show", "-p", "MainPID", "--value", "aicommander-agent");
    log(`service MainPID before install: ${pidBeforeInstall || "(none)"}`);

    const installerPath = path.join(WORK_DIR, "install");
    fs.writeFileSync(installerPath, installer, { mode: 0o700 });
    // bash, NOT sh: the installer uses `set -o pipefail`, which dash rejects.
    let installFailed = false;
    const installLog = (() => {
      try {
        return execFileSync("bash", [installerPath], { encoding: "utf8", timeout: 15 * 60_000 });
      } catch (err) {
        installFailed = true;
        return `INSTALLER FAILED: ${String(err)}`;
      }
    })();
    log(`installer output:\n${installLog.trim()}`);

    // An installer that failed WITHOUT touching the binary has changed nothing, so
    // there is nothing to roll back — and rolling back anyway would restart the
    // agent, dropping every live remote_exec and relay session on this machine to
    // undo an install that never happened. Only a binary that actually moved earns
    // the restart. (Checked by version rather than by trusting the exit code: the
    // installer can fail AFTER replacing the file, and that case does need rescue.)
    if (installFailed && installedVersion(binary) === AGENT_VERSION) {
      log(`=== INSTALLER FAILED, binary untouched — still on ${AGENT_VERSION}, nothing to roll back ===`);
      return;
    }

    await sleep(SETTLE_MS);
    const pidBefore = systemctl("show", "-p", "MainPID", "--value", "aicommander-agent");
    await sleep(STABILITY_MS);
    const outcome = updateOutcome({
      activeState: systemctl("is-active", "aicommander-agent") || "unknown",
      pidBeforeInstall,
      pidBefore,
      pidAfter: systemctl("show", "-p", "MainPID", "--value", "aicommander-agent"),
      installedVersion: installedVersion(binary),
      targetVersion: target,
    });

    if (outcome.ok) {
      log(`=== OK: running ${target} ===`);
      return;
    }

    log(`upgrade did not take (${outcome.reason}) → ROLLBACK`);
    // Atomic, because the path we are restoring is very likely being executed
    // right now by the failed new agent — see replaceExecutable.
    replaceExecutable(BACKUP_PATH, binary);
    systemctl("restart", "aicommander-agent");
    await sleep(STABILITY_MS);
    const back = installedVersion(binary);
    if (systemctl("is-active", "aicommander-agent") === "active") {
      log(`=== ROLLBACK OK: back on ${back || "the previous binary"} ===`);
    } else {
      log("=== ROLLBACK FAILED — this machine needs local access ===");
    }
  } finally {
    fs.closeSync(lockFd);
    try {
      fs.unlinkSync(LOCK_PATH);
    } catch {
      // Best effort; a stale lock only blocks the next self-update, which is the
      // safe direction to fail in.
    }
  }
}
