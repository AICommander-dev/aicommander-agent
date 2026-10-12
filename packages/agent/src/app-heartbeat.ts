import { APP_PING_FRAME, APP_PING_INTERVAL_MS, APP_PONG_FRAME, APP_PONG_TIMEOUT_MS } from "@aicommander/protocol";
import type { AgentToDoMsg, DoToAgentMsg } from "@aicommander/protocol";

/**
 * Agent-driven relay heartbeat (AgentRegisterMsg.appPing).
 *
 * The legacy heartbeat is server-driven: the relay's Durable Object wakes every
 * 20s to send do:ping and wakes again for our agent:pong — the bulk of the relay's
 * Durable Object bill for an idle fleet. Once the relay acknowledges our `appPing`
 * advertisement (a do:ping carrying `heartbeat: "app"`), we send APP_PING_FRAME on
 * our own timer instead, and the relay's runtime answers APP_PONG_FRAME through a
 * WebSocket auto-response without waking the object at all.
 *
 * Liveness on our side is unchanged in shape: createRelayLiveness (below) resets
 * the link-dead timer (APP_PONG_TIMEOUT_MS, three missed pings) on every pong, exactly
 * as it does on every do:ping, and terminates + reconnects when it lapses. A relay
 * that never acknowledges (one predating this) keeps sending do:ping, and this
 * timer is simply never started.
 */
export interface AppHeartbeat {
  /** Begin pinging. Idempotent: a repeated acknowledgement does not stack timers. */
  start(): void;
  stop(): void;
  readonly active: boolean;
}

export function createAppHeartbeat(
  send: (frame: string) => void,
  intervalMs: number = APP_PING_INTERVAL_MS,
): AppHeartbeat {
  let timer: ReturnType<typeof setInterval> | null = null;
  return {
    start() {
      if (timer) return;
      timer = setInterval(() => {
        try { send(APP_PING_FRAME); } catch { /* socket gone; close handler stops us */ }
      }, intervalMs);
      timer.unref?.();
    },
    stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
    get active() {
      return timer !== null;
    },
  };
}

/** True for the relay's auto-response pong (exact string, never JSON). */
export function isAppPong(raw: unknown): boolean {
  return String(raw) === APP_PONG_FRAME;
}

/**
 * The agent side of the relay heartbeat for one socket, both protocols: the
 * link-dead timer, the legacy do:ping → agent:pong answer, and the app heartbeat
 * started when that do:ping acknowledges `appPing`.
 */
export interface RelayLiveness {
  /** (Re-)arm the link-dead timer; called on open and on every sign of life. */
  reset(): void;
  /**
   * Consume the relay's auto-response pong. Must run BEFORE the JSON parse — the
   * pong is not JSON. Returns true when `raw` was the pong.
   */
  handleAppPong(raw: unknown): boolean;
  /** Answer a do:ping, and start our own pings when it acknowledges `appPing`. */
  handlePing(msg: Extract<DoToAgentMsg, { type: "do:ping" }>): void;
  /** Stop the link-dead timer and our pings. Idempotent. */
  stop(): void;
}

export function createRelayLiveness(deps: {
  /** Raw socket send; may throw on a dead socket, exactly like ws.send. */
  send: (frame: string) => void;
  /** Every sign of life (the desktop watchdog's input). Must not throw. */
  onBeat: () => void;
  /** Nothing heard for APP_PONG_TIMEOUT_MS: the link is dead. */
  onDead: () => void;
  timeoutMs?: number;
  intervalMs?: number;
}): RelayLiveness {
  let deadTimer: ReturnType<typeof setTimeout> | null = null;
  const appHeartbeat = createAppHeartbeat(deps.send, deps.intervalMs);
  const reset = () => {
    deps.onBeat();
    if (deadTimer) clearTimeout(deadTimer);
    // If no ping (legacy) or app pong received in 90s (APP_PONG_TIMEOUT_MS: three
    // missed app pings), consider connection dead
    deadTimer = setTimeout(deps.onDead, deps.timeoutMs ?? APP_PONG_TIMEOUT_MS);
  };
  return {
    reset,
    handleAppPong(raw) {
      if (!isAppPong(raw)) return false;
      reset();
      return true;
    },
    handlePing(msg) {
      reset();
      const pong: AgentToDoMsg = { type: "agent:pong", ts: msg.ts };
      deps.send(JSON.stringify(pong));
      // The relay understood our `appPing`: from now on WE ping, it stops.
      if (msg.heartbeat === "app") appHeartbeat.start();
    },
    stop() {
      if (deadTimer) {
        clearTimeout(deadTimer);
        deadTimer = null;
      }
      appHeartbeat.stop();
    },
  };
}
