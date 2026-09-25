import fs from "fs";
import path from "path";
import os from "os";
import { HEARTBEAT_INTERVAL_MS } from "@aicommander/protocol";

/**
 * The worker stamps a heartbeat file from a steady timer. The stamp proves only
 * that the event loop is turning — it is INTENTIONALLY independent of command
 * workload, so a long or quiet command never looks "stuck". The supervisor reads
 * this file and force-restarts the worker only when the stamp goes stale, which
 * means a genuinely wedged loop (no benign explanation) → zero false positives.
 */

/** Default heartbeat path. Prefers the systemd RuntimeDirectory (tmpfs). */
export function defaultHeartbeatPath(configDir?: string): string {
  if (configDir) return path.join(configDir, "heartbeat");
  // /run/aicommander-agent is provisioned by the systemd unit (RuntimeDirectory).
  if (process.platform === "linux") {
    try {
      fs.mkdirSync("/run/aicommander-agent", { recursive: true });
      return "/run/aicommander-agent/heartbeat";
    } catch {
      // fall through to tmp
    }
  }
  return path.join(os.tmpdir(), "aicommander-agent-heartbeat");
}

function stamp(file: string): void {
  try {
    // Atomic replace so a reader never sees a half-written value.
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, String(Date.now()));
    fs.renameSync(tmp, file);
  } catch {
    // Best-effort: a transient FS error must not crash the worker.
  }
}

let timer: ReturnType<typeof setInterval> | null = null;

/** Begin stamping `file` every `intervalMs`. Idempotent. */
export function startHeartbeat(
  file: string,
  intervalMs: number = HEARTBEAT_INTERVAL_MS,
): void {
  stopHeartbeat();
  stamp(file);
  timer = setInterval(() => stamp(file), intervalMs);
  // Never keep the process alive just for the heartbeat.
  timer.unref?.();
}

export function stopHeartbeat(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

/** Read the last heartbeat epoch-ms, or null if missing/unreadable. */
export function readHeartbeat(file: string): number | null {
  try {
    const raw = fs.readFileSync(file, "utf8").trim();
    const value = Number(raw);
    return Number.isFinite(value) ? value : null;
  } catch {
    return null;
  }
}
