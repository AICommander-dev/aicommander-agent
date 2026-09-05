import { register, RegistrationError } from "./register.js";
import { runConnectionLoop, AGENT_TOKEN_ROTATE_MS } from "./connection.js";
import { showCode } from "./display.js";
import { writeState, clearState } from "./state.js";
import { loadOrCreateDevice } from "./device.js";
import { loadSession, saveSession, consumeRotateMarker } from "./session-store.js";
import { runSupervisor } from "./supervisor.js";
import { findRunningAgents } from "./live-agent.js";
import { singleInstanceVerdict, singleInstanceMessage } from "./single-instance.js";
import { startHeartbeat, stopHeartbeat, defaultHeartbeatPath } from "./heartbeat.js";
import { fetchLatestDist, isNewerVersion } from "./update-check.js";
import { AGENT_VERSION } from "./version.js";
import { resolveTrustedServerUrl } from "./relay-url.js";
import {
  diag,
  errorFields,
  exitAfterDiagFlush,
  flushDiagLog,
  initDiagLog,
  logStartup,
  resolveDiagLogDir,
} from "./diag-log.js";

// Host-locked to the canonical relay: an AICOMMANDER_SERVER override to a
// non-canonical origin is honored only under the explicit dev escape hatch
// (AICOMMANDER_DEV=1) or for loopback — otherwise it's ignored. The agent runs as
// root and executes whatever the relay sends, so the relay is its trust anchor.
const SERVER_URL = resolveTrustedServerUrl(process.env["AICOMMANDER_SERVER"]);

// How often a long-running headless agent re-checks for a newer release.
const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

/**
 * Headless agents have no UI, so a newer release is surfaced as a one-line log
 * with the exact update command. Best-effort: never blocks startup, never throws
 * (an unreachable relay just means "assume up to date").
 */
async function checkForAgentUpdate(): Promise<void> {
  const dist = await fetchLatestDist(SERVER_URL);
  if (!dist?.version) {
    diag("update.check_failed");
    return;
  }
  if (!isNewerVersion(dist.version, AGENT_VERSION)) {
    diag("update.none", { running: AGENT_VERSION });
    return;
  }
  diag("update.available", { latest: dist.version, running: AGENT_VERSION });
  console.warn(
    `\n  ⬆  A newer AI Commander agent is available (v${dist.version}; you have v${AGENT_VERSION}).\n` +
    `     Update safely (verify before sudo):  ${SERVER_URL}/howto/#install-agent\n`,
  );
}

/**
 * Entry point for the `run` command. Splits into two roles for self-healing:
 *
 *  - SUPERVISOR (default): a thin parent that spawns the real agent as a worker
 *    and force-restarts it if its event loop wedges (see supervisor.ts).
 *  - WORKER (AIC_ROLE=worker): the actual agent — registers, connects, executes,
 *    and stamps a heartbeat the supervisor watches.
 *
 * The supervisor sets AIC_ROLE=worker when spawning, so re-execing the binary
 * lands in the worker branch.
 */
export async function startAgent(opts: { force?: boolean } = {}): Promise<void> {
  if (process.env["AIC_ROLE"] === "worker") {
    await runAgent();
    return;
  }

  // The supervisor logs to its OWN file: it and the worker it re-execs are two
  // live processes, and one shared file would interleave half-lines and race the
  // rotation rename (see diag-log.ts).
  initDiagLog({ dir: resolveDiagLogDir(), role: "supervisor" });
  logStartup({ role: "supervisor", version: AGENT_VERSION });

  // Single-instance gate — SUPERVISOR BRANCH ONLY, and that placement is the
  // whole trick. A worker is spawned by our own supervisor, which findRunningAgents
  // correctly reports as a live agent; running the check there would make every
  // supervised start refuse itself. The supervisor, by contrast, is the process
  // that is about to claim this machine's relay session, so it is exactly the one
  // that must ask whether the session is already claimed. See single-instance.ts.
  if (opts.force !== true) {
    const verdict = singleInstanceVerdict(findRunningAgents());
    if (verdict.kind !== "clear") {
      console.error(singleInstanceMessage(verdict));
      process.exitCode = 1;
      // Nothing exits here — the process simply runs out of work — and diag's
      // flush timer is unref'd, so without this the supervisor's startup line
      // (the one that says which install this was) never reaches the file.
      await flushDiagLog();
      return;
    }
  }

  await runSupervisor();
  // Same reason: the supervisor's last lines (`shutdown`, a final worker exit)
  // are queued behind an unref'd timer that a draining event loop never runs.
  await flushDiagLog();
}

/** Run the agent: register with the relay, show the session code, and listen for commands. */
export async function runAgent(): Promise<void> {
  // Heartbeat proves this worker's event loop is alive; the supervisor restarts
  // us if it stalls. Only meaningful when launched as a supervised worker.
  initDiagLog({ dir: resolveDiagLogDir(), role: "worker" });
  logStartup({
    role: "worker",
    version: AGENT_VERSION,
    supervised: process.env["AIC_ROLE"] === "worker",
    logDir: resolveDiagLogDir(),
  });

  const heartbeatActive = process.env["AIC_ROLE"] === "worker";
  if (heartbeatActive) {
    startHeartbeat(process.env["AIC_HEARTBEAT"] || defaultHeartbeatPath());
  }

  const shutdown = () => {
    diag("shutdown");
    if (heartbeatActive) stopHeartbeat();
    // Exit only AFTER the state file is actually gone. An un-awaited clearState
    // raced process.exit and routinely lost, so every clean stop left a stale
    // state.json whose pid the uninstaller then had to disprove — turning a
    // rare condition every consumer must tolerate into the NORMAL one.
    // clearState never rejects, and rm of one file cannot hang, so this does
    // not meaningfully delay the exit; finally() guarantees we still exit even
    // if that contract ever changes.
    void clearState().finally(() => exitAfterDiagFlush(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  // Root check — privileged commands (apt, systemctl, etc.) require root
  if (typeof process.getuid === "function" && process.getuid() !== 0) {
    console.warn(
      "\n  ⚠  Warning: not running as root.\n" +
      "  Commands requiring sudo (apt, systemctl, brew cask…) will fail.\n" +
      "  Recommended: sudo aicommander-agent\n",
    );
  }

  // Stable device identity — survives reboots and session-code rotation so the
  // relay can map a re-registering agent back to the same saved machine.
  const device = loadOrCreateDevice();

  // The session code is STABLE: generated once and reused across reboots,
  // restarts, and reconnects. It changes ONLY when `change-code` writes the
  // one-shot rotate marker (which also clears the stored session). On a normal
  // start we pass the stored code as `currentCode` so the relay can restore the
  // exact code even if its KV record was evicted; on a change-code start we set
  // `forceNew` and send no `currentCode`.
  const forceNew = consumeRotateMarker();
  const stored = forceNew ? null : loadSession();

  let sessionCode: string;
  let agentToken: string;

  try {
    const result = await register(SERVER_URL, device, {
      forceNew,
      ...(stored ? { currentCode: stored.sessionCode } : {}),
    });
    sessionCode = result.sessionCode;
    agentToken = result.agentToken;
    diag("conn.register_ok");
  } catch (err) {
    // The relay's own refusal, in the relay's own vocabulary — the HTTP status
    // and the machine-readable code from the body. `errorFields` cannot carry
    // either: it reads `err.code` as an ERRNO, so a relay code went into the log
    // labelled as a filesystem fault and the status — the one number that says
    // whether this machine was refused, rate-limited or met a broken relay —
    // went nowhere at all. The desktop host records exactly these two fields for
    // the same failure (agent-controller.ts); the headless log has to agree with
    // it, or the two hosts describe one event differently.
    diag(
      "conn.register_failed",
      err instanceof RegistrationError ? { status: err.status, relay_code: err.code } : errorFields(err),
    );
    console.error(`  Failed to register: ${String(err)}`);
    // The line above is the whole reason this file exists; process.exit would
    // kill the process before its flush timer ever fired (see diag-log.ts).
    await exitAfterDiagFlush(1);
    return;
  }

  try {
    saveSession({ sessionCode, agentToken });
  } catch (err) {
    diag("path.error", { path_role: "sessionStore", ...errorFields(err) });
    console.error(`  Failed to persist session credentials: ${String(err)}`);
    await exitAfterDiagFlush(1);
    return;
  }

  // Reveal the FULL code on a real interactive terminal, OR on any foreground run
  // that is NOT the systemd service (piped `| tee`, `nohup`, CI). `run` is the
  // foreground flow (npx / `aicommander-agent run` in a shell) where the user
  // launched it to obtain the code — revealing is the whole point. The one place
  // it MUST stay masked is under the systemd service, where this same `run` is
  // supervised and its stdout is inherited into journald (StandardOutput=journal,
  // see ctl/commands/install.ts): persisting the root-exec credential in the
  // journal (readable by root and by systemd-journal/adm-group users, prone to
  // leaking into exported logs / screen-shares) would defeat the masking applied
  // everywhere else. We detect that context via systemd's own env markers
  // (INVOCATION_ID is set for every service unit; JOURNAL_STREAM is set precisely
  // because our unit routes stdout to the journal) rather than TTY-ness alone,
  // which masked *every* non-TTY foreground run. `stdio:"inherit"` + `...process.env`
  // propagate both the fds and these markers across the supervisor→worker re-exec,
  // so the gate is accurate in both roles: service → masked, everything else → full.
  const inSystemdService = !!(process.env["INVOCATION_ID"] || process.env["JOURNAL_STREAM"]);
  showCode(sessionCode, SERVER_URL, process.stdout.isTTY === true || !inSystemdService);
  try {
    await writeState({
      sessionCode,
      pid: process.pid,
      startedAt: new Date().toISOString(),
      serverUrl: SERVER_URL,
    });
  } catch (err) {
    diag("path.error", { path_role: "state", ...errorFields(err) });
    console.error(`  Failed to persist runtime state: ${String(err)}`);
    await exitAfterDiagFlush(1);
    return;
  }

  // Nudge about newer releases: once now, then daily for long-lived services.
  void checkForAgentUpdate();
  const updateTimer = setInterval(() => void checkForAgentUpdate(), UPDATE_CHECK_INTERVAL_MS);
  updateTimer.unref?.();

  await runConnectionLoop({
    serverUrl: SERVER_URL,
    sessionCode,
    agentToken,
    // Periodically rotate the agent token (re-assert the SAME code, fresh token).
    reauthIntervalMs: AGENT_TOKEN_ROTATE_MS,
    reauth: async () => {
      const r = await register(SERVER_URL, device, { currentCode: sessionCode });
      try {
        saveSession({ sessionCode: r.sessionCode, agentToken: r.agentToken });
      } catch (err) {
        diag("path.error", { path_role: "sessionStore", ...errorFields(err) });
        console.error(`  Failed to persist rotated session credentials: ${String(err)}`);
        await exitAfterDiagFlush(1);
      }
      return r.agentToken;
    },
  });
}
