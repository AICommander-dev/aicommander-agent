// Frozen internal interfaces wiring the helper together: the local IPC transport
// (server) and the privileged executor. Implementations live in transport.ts and
// executor.ts; helper.ts composes them. Kept in one file so the seams can't drift.

import type { HelperToClientMsg } from "./protocol.js";
import type { ElevatedCapabilityClaims } from "@aicommander/protocol";

// --- Transport (server side) ------------------------------------------------

/** One accepted client connection. Framing/JSON is handled inside the transport. */
export interface ServerConnection {
  /** Stable per-process id for this connection (leases, audit correlation). */
  readonly id: number;
  /** Decoded inbound frames (already parsed JSON objects; validate the shape yourself). */
  onMessage(cb: (msg: Record<string, unknown>) => void): void;
  /**
   * Register a callback fired when the connection is gone (client close, error,
   * or local close()). ADDITIVE: multiple owners may register; each callback runs
   * exactly once. (A single-slot setter would let one owner silently clobber
   * another — e.g. the transport's own liveConnections cleanup vs. helper wiring.)
   */
  onClose(cb: () => void): void;
  /** Serialize + frame + write one typed message. No-op after close. */
  send(msg: HelperToClientMsg): void;
  /** Tear down this connection. Idempotent; triggers onClose once. */
  close(): void;
}

/** The helper's local IPC listener (unix socket on macOS, loopback TCP on Windows). */
export interface TransportServer {
  /** Register the accept handler BEFORE listen(). */
  onConnection(cb: (conn: ServerConnection) => void): void;
  /**
   * Bind the helper endpoint(s) (endpoint.ts). On Windows, binds EVERY free port in
   * the candidate pool — a live helper must own the whole pool so a local squatter
   * can't answer discovery from an earlier candidate. Rejects only if NO candidate
   * can be owned exclusively.
   */
  listen(): Promise<void>;
  /** Stop accepting + drop the endpoint(s). Idempotent. */
  close(): Promise<void>;
  /**
   * Test-only (`__` prefix): the FIRST OS-assigned bound TCP address (so a test
   * binding port 0 can discover the real port). Returns null for a unix socket,
   * an unbound server, or an unsupported (null) endpoint.
   */
  __boundAddress(): { port: number } | null;
  /** Test-only (`__` prefix): ALL bound TCP addresses, in candidate order. */
  __boundAddresses(): Array<{ port: number }>;
  /** Test-only (`__` prefix): number of connections currently live (asserts the set doesn't leak). */
  __liveConnectionCount(): number;
}

// --- Privileged executor ----------------------------------------------------

/** Streaming callbacks for one privileged command; mirrors the agent's CommandHandlers. */
export interface ExecHandlers {
  /** `chunk` is base64 (binary-safe), matching the agent's output framing. */
  onOutput(chunk: string, stream: "stdout" | "stderr"): void;
  onDone(exitCode: number, durationMs: number): void;
  onError(message: string): void;
  /**
   * Terminal "the process is truly GONE" notification, fired EXACTLY once after
   * the child (and its escalation timers) are finished — on real 'close', and on
   * every no-spawn failure path too. Fires regardless of a prior onDone/onError,
   * so lease cleanup can hold the lease until the process actually exits (a
   * failed-but-still-alive command stays reapable on shutdown). Not a client
   * frame: onDone/onError remain the one-and-only terminal report to the client.
   */
  onClosed?(): void;
}

export interface RunningPrivilegedCommand {
  /**
   * Terminate the whole process tree (SIGTERM→SIGKILL / taskkill /T /F). Idempotent.
   * `{ hard: true }` (shutdown) uses a SHORT SIGKILL grace (HARD_KILL_GRACE_MS)
   * instead of the normal KILL_ESCALATION_MS, so a TERM-ignoring detached child is
   * reaped before process.exit rather than surviving a restart/upgrade/uninstall.
   */
  kill(opts?: { hard?: boolean }): void;
}

/**
 * Runs a command as root (macOS) / LocalSystem (Windows). The executor trusts
 * that `claims` was ALREADY signature-verified and binding-checked by the helper;
 * its own job is a hardened spawn: pinned shell, minimal locked env, locked PATH,
 * a local monotonic timeout backstop, and output caps.
 */
export interface PrivilegedExecutor {
  /** Identity commands run as, for the handshake + done frames ("root" / "nt authority\\system"). */
  effectiveIdentity(): string;
  /** Spawn one verified command. Never falls back to a less-privileged path on error. */
  run(claims: ElevatedCapabilityClaims, handlers: ExecHandlers): RunningPrivilegedCommand;
}
