// Composition root: wire transport + capability verification + executor + leases
// into the running helper. This is the security-critical glue; every inbound
// frame is validated for shape before use, every capability is verified
// (signature + expiry + boot + anti-replay) before a single process is spawned,
// and every privileged process is leased to its connection so it can never
// outlive the authorized session.

import { ReplayGuard, verifyCapabilityForExec } from "./capability-verify.js";
import { generateBootId } from "./boot-challenge.js";
import { LeaseManager } from "./lease-manager.js";
import { HELPER_VERSION } from "./version.js";
import { IPC_PROTOCOL_VERSION } from "./protocol.js";
import type { ServerConnection, TransportServer, PrivilegedExecutor } from "./types.js";

/**
 * How long stop() waits for the HARD (short) SIGKILL escalation to land before
 * closing the transport. killAll({ hard: true }) schedules SIGKILL after
 * HARD_KILL_GRACE_MS (~400ms); this gives that + a buffer so even a
 * SIGTERM-ignoring child is dead before process.exit.
 */
const SHUTDOWN_DRAIN_MS = 700;

export interface HelperDeps {
  transport: TransportServer;
  executor: PrivilegedExecutor;
}

export interface RunningHelper {
  readonly bootId: string;
  stop(): Promise<void>;
  /** Test-only: number of leases currently tracked (asserts no lease leak). */
  __leaseCount(): number;
}

// --- inbound frame shape guards (never trust a decoded object) ---------------

function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

// Test-only: per-live-connection sizes of the cancellation-tracking sets, so a
// test can assert they stay bounded to in-flight requests (no unbounded growth
// from a client spamming `kill` frames). Entries are added on serveConnection and
// removed on close, so this map is itself bounded to live connections.
const __connTracking = new Map<
  number,
  { pendingVerify: Set<string>; cancelled: Set<string> }
>();

/** Test-only: sizes of the tracking sets for every currently-live connection. */
export function __connTrackingSizes(): Array<{
  pendingVerify: number;
  cancelled: number;
}> {
  return [...__connTracking.values()].map((t) => ({
    pendingVerify: t.pendingVerify.size,
    cancelled: t.cancelled.size,
  }));
}

/**
 * Serve one tray connection. Enforces: a `hello` handshake (with matching IPC
 * protocol version) BEFORE any exec; per-command capability verification; leases
 * tied to this connection id; and fail-closed handling of every malformed or
 * unknown frame.
 */
function serveConnection(
  conn: ServerConnection,
  deps: HelperDeps,
  bootId: string,
  replay: ReplayGuard,
  leases: LeaseManager,
  isStopping: () => boolean,
): void {
  let handshakeDone = false;

  // Per-connection cancellation state. `closed` flips on disconnect. `cancelled`
  // records requestIds that were killed while their exec was still awaiting
  // capability verification — so the async handler can bail BEFORE it spawns.
  // `pendingVerify` holds requestIds whose exec is currently in flight (from the
  // `exec` frame until handleExec settles). Both sets are pruned to in-flight
  // requests so a client spamming `kill` frames for never-exec'd ids can't grow
  // them without bound in the boot-persistent root daemon.
  let closed = false;
  const cancelled = new Set<string>();
  const pendingVerify = new Set<string>();
  __connTracking.set(conn.id, { pendingVerify, cancelled });

  conn.onClose(() => {
    closed = true;
    __connTracking.delete(conn.id);
    // A privileged process must never outlive the connection that authorized it.
    // HARD kill: the authorizing connection is gone, so the command must die
    // decisively (short SIGKILL grace) rather than linger on the 5s soft
    // escalation — that's what closes the disconnect-then-shutdown race. The lease
    // itself is dropped only by the command's onClosed hook (real 'close'), so a
    // still-alive TERM-ignoring child stays covered by a subsequent stop().
    leases.releaseAll(conn.id, { hard: true });
  });

  conn.onMessage((msg) => {
    const t = asString(msg["t"]);

    if (t === "hello") {
      if (handshakeDone) {
        conn.send({ t: "error", message: "duplicate handshake" });
        conn.close();
        return;
      }
      const clientProto = msg["protocolVersion"];
      if (typeof clientProto !== "number" || clientProto !== IPC_PROTOCOL_VERSION) {
        // Version skew fails closed: refuse to serve a client we can't speak to.
        conn.send({
          t: "error",
          message: `unsupported IPC protocol version ${String(clientProto)} (helper speaks ${IPC_PROTOCOL_VERSION})`,
        });
        conn.close();
        return;
      }
      handshakeDone = true;
      conn.send({
        t: "hello-ok",
        protocolVersion: IPC_PROTOCOL_VERSION,
        helperVersion: HELPER_VERSION,
        bootId,
        effectiveIdentity: deps.executor.effectiveIdentity(),
      });
      return;
    }

    // Every non-handshake frame requires a completed handshake first.
    if (!handshakeDone) {
      conn.send({ t: "error", message: "handshake required before any command" });
      conn.close();
      return;
    }

    if (t === "exec") {
      const requestId = asString(msg["requestId"]);
      const capability = asString(msg["capability"]);
      if (!requestId || !capability) {
        conn.send({ t: "error", message: "exec requires requestId and capability" });
        return;
      }
      // Shutdown drain: the transport is still listening while killAll() reaps
      // in-flight commands, but a NEW exec arriving now must never spawn a process
      // that could outlive process.exit. Reject it and don't lease/spawn.
      if (isStopping()) {
        conn.send({ t: "error", requestId, message: "helper is shutting down" });
        return;
      }
      // Track this requestId as in flight BEFORE the await; prune both sets when
      // handleExec settles (spawned or bailed) so they stay bounded.
      pendingVerify.add(requestId);
      void handleExec(conn, deps, bootId, replay, leases, requestId, capability, {
        isCancelled: () => closed || cancelled.has(requestId),
        isStopping,
      }).finally(() => {
        pendingVerify.delete(requestId);
        cancelled.delete(requestId);
      });
      return;
    }

    if (t === "kill") {
      const requestId = asString(msg["requestId"]);
      if (requestId) {
        // Only add a `cancelled` marker for an exec still AWAITING verification
        // (pendingVerify) — that's the only race the marker guards: the async
        // handler re-checks it after the verify await and bails before spawning.
        // A LIVE lease is SIGNALLED via leases.kill and needs no marker; a marker
        // there would leak, since handleExec's finally (which prunes `cancelled`)
        // already ran when the verify settled. Anything else has nothing to cancel.
        // This keeps `cancelled` bounded to in-flight verifies.
        if (pendingVerify.has(requestId)) {
          cancelled.add(requestId);
        }
        // SOFT (user-initiated, be gentle): leases.kill signals SIGTERM→SIGKILL on
        // the normal escalation. The lease is NOT dropped here — it persists until
        // the process's real 'close' fires onClosed → release, so a stop() during
        // that window can still hard-upgrade the still-alive child via killAll.
        leases.kill(conn.id, requestId);
      }
      return;
    }

    // helper removal is a normal relay-signed elevated command (verified), not an
    // unauthenticated IPC op.

    // Unknown frame type: fail closed (report, don't act).
    conn.send({ t: "error", message: `unknown message type: ${String(t)}` });
  });
}

async function handleExec(
  conn: ServerConnection,
  deps: HelperDeps,
  bootId: string,
  replay: ReplayGuard,
  leases: LeaseManager,
  requestId: string,
  capability: string,
  lifecycle: { isCancelled: () => boolean; isStopping: () => boolean },
): Promise<void> {
  let claims;
  try {
    claims = await verifyCapabilityForExec(capability, { replay, bootId });
  } catch (err) {
    // Verification failure is terminal for this request. No process is spawned.
    conn.send({
      t: "error",
      requestId,
      message: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  // verifyCapabilityForExec was awaited: if the connection closed or a `kill` for
  // this requestId arrived during the await, bail WITHOUT spawning or leasing.
  if (lifecycle.isCancelled()) {
    conn.send({ t: "error", requestId, message: "exec cancelled before start" });
    return;
  }

  // stop() may have begun WHILE this exec was mid-verify; bail before spawning so
  // a command authorized just before shutdown can't outlive the drain.
  if (lifecycle.isStopping()) {
    conn.send({ t: "error", requestId, message: "helper is shutting down" });
    return;
  }

  // Defense in depth: the wire requestId MUST equal the signed requestId, so a
  // caller can't stream a verified command's output under a different id.
  if (claims.requestId !== requestId) {
    conn.send({ t: "error", requestId, message: "requestId does not match the signed capability" });
    return;
  }

  const running = deps.executor.run(claims, {
    onOutput: (chunk, stream) => conn.send({ t: "output", requestId, chunk, stream }),
    onDone: (exitCode, durationMs) => {
      conn.send({
        t: "done",
        requestId,
        exitCode,
        durationMs,
        effectiveIdentity: deps.executor.effectiveIdentity(),
      });
    },
    onError: (message) => {
      conn.send({ t: "error", requestId, message });
    },
    // Release the lease ONLY when the process is truly gone — not on onError.
    // A command that failed (timeout/output-cap) but is still alive (its
    // SIGTERM→SIGKILL escalation is armed) must stay leased so a helper shutdown
    // within that window can still reap it via killAll; dropping the lease on
    // the error report would orphan a TERM-ignoring child.
    onClosed: () => leases.release(conn.id, requestId),
  });
  leases.register(conn.id, requestId, running);
}

/** Start the helper: listen for tray connections and serve verified elevated execs. */
export async function startHelper(deps: HelperDeps): Promise<RunningHelper> {
  const bootId = generateBootId();
  const replay = new ReplayGuard();
  const leases = new LeaseManager();

  // Flips true at the very start of stop(). While set, no NEW exec is accepted —
  // the transport is still listening during the kill drain, so without this a
  // hello+exec arriving mid-drain could spawn a command that survives exit.
  let stopping = false;

  deps.transport.onConnection((conn) => {
    serveConnection(conn, deps, bootId, replay, leases, () => stopping);
  });

  await deps.transport.listen();

  return {
    bootId,
    __leaseCount: () => leases.size(),
    async stop() {
      stopping = true;
      // Never leave privileged children behind on shutdown: HARD force-kill every
      // leased command (SIGTERM→short-grace SIGKILL), give that grace to land,
      // THEN close the transport. Hard is required — the normal escalation
      // (KILL_ESCALATION_MS) outlasts this drain, so a TERM-ignoring child would
      // survive process.exit.
      leases.killAll({ hard: true });
      await new Promise<void>((resolve) => setTimeout(resolve, SHUTDOWN_DRAIN_MS));
      await deps.transport.close();
    },
  };
}
