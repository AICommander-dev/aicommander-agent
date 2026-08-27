import net from "node:net";
import fs from "node:fs";
import {
  elevatedEndpoint,
  elevatedEndpoints,
  helperVersionMarkerPath,
  encodeFrame,
  FrameDecoder,
  IPC_PROTOCOL_VERSION,
  type ElevatedEndpoint,
} from "@aicommander/priv-helper";
import type { CommandHandlers, RunningCommand } from "./executor.js";
import { AGENT_VERSION } from "./version.js";

/**
 * Open a socket to the privileged-helper IPC endpoint, transport-agnostic:
 *  - unix → connect the root-owned socket path (mac)
 *  - tcp  → connect loopback host:port (Windows)
 * Pure connect; the caller wires up the handshake and event handlers.
 */
function connectEndpoint(ep: ElevatedEndpoint): net.Socket {
  return ep.transport === "unix" ? net.connect(ep.path) : net.connect(ep.port, ep.host);
}

/**
 * Whether this machine can run relay-signed elevated commands right now — i.e. a
 * per-machine privileged helper (mac LaunchDaemon / Windows Service) is installed
 * and reachable.
 *
 * Synchronous, fail-closed probe: true ONLY when the platform HAS an elevated IPC
 * endpoint (mac/Windows) AND the helper's on-disk VERSION marker exists. Any error
 * or other platform → false. Reported at register time as
 * AgentRegisterMsg.elevatedExec so the relay refuses elevated remote_exec against
 * a machine that can't actually honor it — the advertisement stays honest.
 */
export function isElevatedHelperAvailable(): boolean {
  try {
    if (elevatedEndpoint() === null) return false;
    const marker = helperVersionMarkerPath();
    if (marker === null) return false;
    return fs.existsSync(marker);
  } catch {
    return false;
  }
}

/**
 * Run ONE relay-signed elevated command via the privileged helper. This is a pure
 * local-IPC RELAY: it NEVER runs anything itself and NEVER falls back to
 * unprivileged exec on any error path. It opens the helper endpoint, hands over
 * the opaque signed capability, and streams the helper's result back through the
 * same CommandHandlers contract as executeCommand so connection.ts routes it
 * identically.
 *
 * `commandId` MUST equal the signed capability.requestId — the helper cross-checks
 * them and rejects a mismatch. `opts.endpoint` exists SOLELY so tests can point at
 * a temp socket; production callers omit it (default = elevatedEndpoint()).
 *
 * `opts.onBootId` (optional) fires once with the helper's live per-boot nonce as
 * soon as `hello-ok` arrives — BEFORE `exec` is sent. connection.ts uses it to
 * detect a helper restart (a bootId that differs from the one last advertised to
 * the relay) and re-register with the fresh nonce, so elevated exec self-heals
 * instead of staying dead until the next reconnect/reauth.
 *
 * Fail-closed everywhere: a null endpoint, a connection failure (no helper
 * listening), a version-skew handshake, a decode error, or a premature close all
 * surface as a terminal onError and never spawn a process.
 */
export function executeElevatedCommand(
  capability: string,
  commandId: string,
  handlers: CommandHandlers,
  opts?: { endpoint?: ElevatedEndpoint | null; onBootId?: (bootId: string) => void },
): RunningCommand {
  const endpoint = opts?.endpoint === undefined ? elevatedEndpoint() : opts.endpoint;

  if (endpoint === null) {
    // No helper endpoint on this platform — fail closed, spawn nothing.
    queueMicrotask(() => {
      handlers.onError(
        "elevated execution is not available on this machine — the AI Commander privileged helper is not installed or running.",
      );
    });
    return { kill: () => {} };
  }

  const decoder = new FrameDecoder();
  // onDone/onError fire at most once; `settled` is the single arbiter.
  let settled = false;
  let connected = false;
  // Set by kill(). If it flips before we've sent `exec`, we CANCEL: no command
  // is ever started — we destroy the socket and settle with an error instead.
  let cancelled = false;
  let execSent = false;

  const socket = connectEndpoint(endpoint);

  const settle = (): void => {
    settled = true;
  };

  socket.on("connect", () => {
    connected = true;
    socket.write(
      encodeFrame({
        t: "hello",
        protocolVersion: IPC_PROTOCOL_VERSION,
        clientVersion: AGENT_VERSION,
      }),
    );
  });

  socket.on("data", (chunk: Buffer) => {
    let frames: Array<Record<string, unknown>>;
    try {
      frames = decoder.push(chunk);
    } catch (err) {
      if (!settled) {
        handlers.onError(
          `elevated helper protocol error: ${err instanceof Error ? err.message : String(err)}`,
        );
        settle();
      }
      socket.destroy();
      return;
    }

    for (const frame of frames) {
      if (settled) break;
      const t = frame["t"];

      if (t === "hello-ok") {
        if (frame["protocolVersion"] !== IPC_PROTOCOL_VERSION) {
          handlers.onError(
            `elevated helper protocol version mismatch (helper ${String(frame["protocolVersion"])}, agent ${IPC_PROTOCOL_VERSION})`,
          );
          settle();
          socket.destroy();
          return;
        }
        // Surface the helper's live per-boot nonce to the caller (restart
        // detection). Fires regardless of cancellation; listener errors here
        // must never derail the relay.
        if (opts?.onBootId) {
          const bootId = frame["bootId"];
          if (typeof bootId === "string" && bootId.length > 0) {
            try {
              opts.onBootId(bootId);
            } catch {
              /* listener errors must not propagate */
            }
          }
        }
        if (cancelled) {
          // Cancelled before we handed the helper anything to run — never send
          // `exec`, so no root command starts. Tear down and settle.
          handlers.onError("elevated execution cancelled before it started");
          settle();
          socket.destroy();
          return;
        }
        execSent = true;
        socket.write(encodeFrame({ t: "exec", requestId: commandId, capability }));
        continue;
      }

      if (t === "output") {
        // `chunk` is already base64; pass it straight through.
        handlers.onOutput(String(frame["chunk"]), frame["stream"] as "stdout" | "stderr");
        continue;
      }

      if (t === "done") {
        handlers.onDone(Number(frame["exitCode"]), Number(frame["durationMs"]));
        settle();
        socket.destroy();
        return;
      }

      if (t === "error") {
        handlers.onError(String(frame["message"]));
        settle();
        socket.destroy();
        return;
      }
      // Unknown frame types are ignored — a terminal frame always settles us.
    }
  });

  socket.on("error", (err: Error) => {
    if (settled) return;
    // Includes ENOENT/ECONNREFUSED when no helper is listening: fail closed.
    handlers.onError(`elevated helper connection failed: ${err.message}`);
    settle();
  });

  socket.on("close", () => {
    if (settled) return;
    handlers.onError("elevated helper closed the connection before completing");
    settle();
  });

  return {
    kill: () => {
      if (settled) return;
      cancelled = true;
      if (execSent && connected && socket.writable) {
        // Command already handed to the helper: ask it to kill the process tree
        // and send the terminal done/error, which settles us via 'data'.
        try {
          socket.write(encodeFrame({ t: "kill", requestId: commandId }));
        } catch {
          socket.destroy();
        }
      } else {
        // Cancelled before `exec` was sent (not yet connected, or connected but
        // still pre-hello-ok): no command ever starts. Settle now and tear down.
        // If hello-ok is still in flight, its handler also sees `cancelled` and
        // won't send exec; the `settled` guard keeps this to one terminal call.
        handlers.onError("elevated execution cancelled before it started");
        settle();
        socket.destroy();
      }
    },
  };
}

/**
 * Probe the privileged helper's current per-boot nonce (`bootId`) by performing
 * ONLY the handshake: connect → send `hello` → await `hello-ok` → resolve its
 * bootId. Used at register time so the agent can advertise the nonce the relay
 * must bind into every capability (machine + boot binding) AND so it can confirm
 * the helper is actually reachable before advertising elevatedExec.
 *
 * Fail-closed: resolves `null` on ANY failure — no endpoint on this platform, a
 * connect error (ECONNREFUSED / ENOENT / EPERM when the helper isn't listening or
 * the pipe is unreachable), a ~2s timeout, a version-skew or otherwise malformed
 * handshake, or a premature close. The socket is ALWAYS destroyed before we
 * resolve. A null result means "don't advertise elevatedExec".
 */
export async function probeHelperBootId(opts?: {
  endpoint?: ElevatedEndpoint | null;
  timeoutMs?: number;
}): Promise<string | null> {
  const endpoint = opts?.endpoint === undefined ? elevatedEndpoint() : opts.endpoint;
  if (endpoint === null) return null;
  const timeoutMs = opts?.timeoutMs ?? 2000;

  return new Promise<string | null>((resolve) => {
    const decoder = new FrameDecoder();
    let done = false;

    const socket = connectEndpoint(endpoint);

    const finish = (bootId: string | null): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(bootId);
    };

    const timer = setTimeout(() => finish(null), timeoutMs);

    socket.on("connect", () => {
      socket.write(
        encodeFrame({
          t: "hello",
          protocolVersion: IPC_PROTOCOL_VERSION,
          clientVersion: AGENT_VERSION,
        }),
      );
    });

    socket.on("data", (chunk: Buffer) => {
      let frames: Array<Record<string, unknown>>;
      try {
        frames = decoder.push(chunk);
      } catch {
        finish(null);
        return;
      }
      for (const frame of frames) {
        if (frame["t"] !== "hello-ok") continue;
        if (frame["protocolVersion"] !== IPC_PROTOCOL_VERSION) {
          finish(null);
          return;
        }
        const bootId = frame["bootId"];
        finish(typeof bootId === "string" && bootId.length > 0 ? bootId : null);
        return;
      }
    });

    socket.on("error", () => finish(null));
    socket.on("close", () => finish(null));
  });
}

/**
 * Locate the reachable privileged helper among this platform's candidate endpoints
 * (Windows has a POOL of loopback ports; the helper binds EVERY free one). Probes
 * ALL candidates via probeHelperBootId, then:
 *
 *  - every answer carries the SAME bootId (the genuine helper on its bound ports)
 *    → return that bootId + the first answering endpoint; the caller pins the
 *    endpoint for subsequent execs so it doesn't re-scan the pool every command;
 *  - answers DISAGREE on bootId → resolve null (fail closed). Since a live helper
 *    owns every pool port it could bind, a second distinct bootId means an
 *    endpoint the helper does NOT own is answering the handshake — a local
 *    squatter posing as the helper (it grabbed a port while the helper was down).
 *    Refusing here downgrades that squat to a DoS (elevated unavailable) instead
 *    of handing the squatter a signed capability. The 60s reconciler retries, so
 *    a transient disagreement (helper restarting mid-scan) self-corrects.
 *
 * `attempts` retries the WHOLE list a few times with a short fixed delay: at
 * register time a single transient probe failure (I/O storm right after boot,
 * helper still finishing its bind) would otherwise wrongly advertise
 * elevatedExec:false and disable elevated exec until the next reconnect.
 * Fail-closed: resolves null when no candidate answers after every attempt (or
 * the platform has no endpoints).
 */
export async function discoverHelper(opts?: {
  endpoints?: ElevatedEndpoint[];
  timeoutMs?: number;
  attempts?: number;
  retryDelayMs?: number;
}): Promise<{ bootId: string; endpoint: ElevatedEndpoint } | null> {
  const endpoints = opts?.endpoints ?? elevatedEndpoints();
  if (endpoints.length === 0) return null;
  const attempts = Math.max(1, opts?.attempts ?? 3);
  const retryDelayMs = opts?.retryDelayMs ?? 300;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const answers: Array<{ bootId: string; endpoint: ElevatedEndpoint }> = [];
    for (const endpoint of endpoints) {
      const bootId = await probeHelperBootId({ endpoint, timeoutMs: opts?.timeoutMs });
      if (bootId !== null) answers.push({ bootId, endpoint });
    }
    if (answers.length > 0) {
      const bootIds = new Set(answers.map((a) => a.bootId));
      // Conflicting bootIds ⇒ someone besides the helper is answering. Fail
      // closed NOW (no retry — a squatter won't go away in 300ms; the periodic
      // reconciler is the retry path).
      if (bootIds.size > 1) return null;
      return answers[0]!;
    }
    // Short fixed delay before rescanning the full list after a no-answer pass
    // (not after the last attempt — nothing would come after it).
    if (attempt + 1 < attempts) {
      await new Promise((r) => setTimeout(r, retryDelayMs));
    }
  }
  return null;
}
