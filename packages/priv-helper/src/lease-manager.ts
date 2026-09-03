// Process leases: every running command belongs to the IPC connection that
// started it. When that connection drops (client close, tray crash, helper
// shutdown) all of its commands are killed — a privileged process must never
// outlive the authorized session that spawned it.

import type { RunningPrivilegedCommand } from "./types.js";

export class LeaseManager {
  // connId → requestId → running command.
  private readonly byConn = new Map<number, Map<string, RunningPrivilegedCommand>>();

  /** Register a running command under a connection id, keyed by requestId. */
  register(connId: number, requestId: string, running: RunningPrivilegedCommand): void {
    let inner = this.byConn.get(connId);
    if (!inner) {
      inner = new Map<string, RunningPrivilegedCommand>();
      this.byConn.set(connId, inner);
    }
    inner.set(requestId, running);
  }

  /** Is a command currently leased under (connId, requestId)? */
  has(connId: number, requestId: string): boolean {
    return this.byConn.get(connId)?.has(requestId) ?? false;
  }

  /**
   * SIGNAL a kill for one command by (connId, requestId) but LEAVE the lease in
   * place. No-op if unknown/already gone (its process closed and `release` already
   * dropped it). Removal happens ONLY from the `onClosed` lifecycle hook via
   * `release()` — so a TERM-ignoring child stays leased (and reapable by a later
   * hard `killAll` on shutdown) until its process is ACTUALLY gone.
   */
  kill(connId: number, requestId: string, opts?: { hard?: boolean }): void {
    const running = this.byConn.get(connId)?.get(requestId);
    if (!running) return;
    running.kill(opts);
  }

  /**
   * Drop a settled command from the lease table WITHOUT killing it. This is the
   * one and only removal path — driven by the executor's `onClosed` hook once the
   * process has truly exited. Idempotent: a second call (or one for an already-gone
   * command) is a harmless no-op, so there are no double-remove issues.
   */
  release(connId: number, requestId: string): void {
    const inner = this.byConn.get(connId);
    if (!inner) return;
    inner.delete(requestId);
    if (inner.size === 0) this.byConn.delete(connId);
  }

  /**
   * SIGNAL a kill for EVERY command across ALL connections (called on helper
   * shutdown). Forwards `{ hard: true }` so TERM-ignoring children are reaped on
   * the SHORT grace before process.exit. Leases are NOT dropped here — removal is
   * left to each command's `onClosed`-driven `release()`.
   */
  killAll(opts?: { hard?: boolean }): void {
    for (const connId of [...this.byConn.keys()]) {
      this.releaseAll(connId, opts);
    }
  }

  /**
   * SIGNAL a kill for EVERY command owned by a connection (called on disconnect).
   * The disconnect path passes `{ hard: true }`: the authorizing connection is
   * gone, so the command must die decisively (short SIGKILL grace), not linger on
   * the 5s soft escalation. Leases are NOT dropped here — removal is left to each
   * command's `onClosed`-driven `release()`, so a still-alive child remains covered
   * by a subsequent shutdown `killAll`.
   */
  releaseAll(connId: number, opts?: { hard?: boolean }): void {
    const inner = this.byConn.get(connId);
    if (!inner) return;
    for (const running of inner.values()) {
      try {
        running.kill(opts);
      } catch {
        // One command's kill throwing must not skip the rest.
      }
    }
  }

  /** Test-only: total number of leases currently tracked across all connections. */
  size(): number {
    let n = 0;
    for (const inner of this.byConn.values()) n += inner.size;
    return n;
  }
}
