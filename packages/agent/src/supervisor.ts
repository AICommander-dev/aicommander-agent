import { spawn, type ChildProcess } from "child_process";
import {
  WATCHDOG_CHECK_INTERVAL_MS,
  WATCHDOG_STALL_MS,
  WATCHDOG_MAX_RESTARTS,
  WATCHDOG_RESTART_WINDOW_MS,
  WATCHDOG_BACKOFF_MS,
} from "@aicommander/protocol";
import { defaultHeartbeatPath, readHeartbeat } from "./heartbeat.js";

export interface SupervisorOptions {
  /** Override the heartbeat file location (defaults to the RuntimeDirectory). */
  heartbeatPath?: string;
  /** Override the data dir used to derive the default heartbeat path. */
  configDir?: string;
  /** Test seam: spawn a worker child. Defaults to re-execing this binary. */
  spawnWorker?: (env: NodeJS.ProcessEnv) => ChildProcess;
  /** Test seam: stop after the worker has been (re)spawned this many times. */
  maxSpawns?: number;
}

/**
 * Thin, long-lived parent that runs the real agent as a WORKER child and
 * force-restarts it when its heartbeat goes stale (a wedged event loop) or it
 * exits unexpectedly. The supervisor itself does no WebSocket or command work,
 * so it virtually cannot wedge; systemd's `Restart=always` covers the rare case
 * where the supervisor itself dies.
 */
export async function runSupervisor(opts: SupervisorOptions = {}): Promise<void> {
  const heartbeatPath = opts.heartbeatPath ?? defaultHeartbeatPath(opts.configDir);

  const spawnWorker =
    opts.spawnWorker ??
    ((env: NodeJS.ProcessEnv) =>
      spawn(process.execPath, process.argv.slice(1), { env, stdio: "inherit" }));

  let child: ChildProcess | null = null;
  let lastSpawnAt = 0;
  let shuttingDown = false;
  let spawnCount = 0;
  let restartTimes: number[] = [];
  let watchdog: ReturnType<typeof setInterval> | null = null;
  let respawnTimer: ReturnType<typeof setTimeout> | null = null;

  await new Promise<void>((resolve) => {
    let sigintHandler: (() => void) | null = null;
    let sigtermHandler: (() => void) | null = null;

    const stopAll = () => {
      if (watchdog) { clearInterval(watchdog); watchdog = null; }
      if (respawnTimer) { clearTimeout(respawnTimer); respawnTimer = null; }
      if (sigintHandler) { process.removeListener("SIGINT", sigintHandler); sigintHandler = null; }
      if (sigtermHandler) { process.removeListener("SIGTERM", sigtermHandler); sigtermHandler = null; }
    };

    const finish = () => {
      stopAll();
      resolve();
    };

    const start = () => {
      lastSpawnAt = Date.now();
      spawnCount++;
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        AIC_ROLE: "worker",
        AIC_HEARTBEAT: heartbeatPath,
      };
      child = spawnWorker(env);

      child.on("exit", (code, signal) => {
        child = null;
        if (shuttingDown) {
          finish();
          return;
        }
        if (opts.maxSpawns != null && spawnCount >= opts.maxSpawns) {
          finish();
          return;
        }
        scheduleRespawn(`worker exited (code=${code ?? "null"} signal=${signal ?? "null"})`);
      });

      child.on("error", () => {
        // Spawn failure — treat like an exit; the exit handler schedules respawn.
      });
    };

    const scheduleRespawn = (_reason: string) => {
      const now = Date.now();
      restartTimes = restartTimes.filter((t) => now - t < WATCHDOG_RESTART_WINDOW_MS);
      restartTimes.push(now);

      // Crash-loop guard: back off so self-healing never hammers the
      // rate-limited /api/register endpoint.
      const delay = restartTimes.length > WATCHDOG_MAX_RESTARTS ? WATCHDOG_BACKOFF_MS : 0;
      if (respawnTimer) clearTimeout(respawnTimer);
      respawnTimer = setTimeout(() => {
        respawnTimer = null;
        if (!shuttingDown) start();
      }, delay);
      respawnTimer.unref?.();
    };

    const forceRestart = () => {
      if (!child) return;
      // SIGKILL — the worker is wedged and won't honor a graceful signal. Its
      // "exit" handler drives the respawn.
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
    };

    watchdog = setInterval(() => {
      if (shuttingDown || !child) return;
      // Grace window after each spawn so a fresh worker has time to stamp before
      // we judge it — otherwise we'd kill it on the previous worker's stale stamp.
      if (Date.now() - lastSpawnAt < WATCHDOG_STALL_MS) return;
      const last = readHeartbeat(heartbeatPath);
      if (last == null) return; // no stamp yet — give it more time, don't false-trip
      if (Date.now() - last > WATCHDOG_STALL_MS) forceRestart();
    }, WATCHDOG_CHECK_INTERVAL_MS);
    watchdog.unref?.();

    const onSignal = (sig: NodeJS.Signals) => {
      shuttingDown = true;
      if (watchdog) { clearInterval(watchdog); watchdog = null; }
      if (respawnTimer) { clearTimeout(respawnTimer); respawnTimer = null; }
      if (child) {
        // Forward the signal for a graceful worker shutdown; its "exit" handler
        // calls finish(). If it never exits, the unit's TimeoutStopSec applies.
        try { child.kill(sig); } catch { /* already gone */ }
      } else {
        finish();
      }
    };
    sigintHandler = () => onSignal("SIGINT");
    sigtermHandler = () => onSignal("SIGTERM");
    process.on("SIGINT", sigintHandler);
    process.on("SIGTERM", sigtermHandler);

    start();
  });
}
