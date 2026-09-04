import net from "node:net";
import {
  elevatedEndpoint,
  elevatedEndpoints,
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

// WHERE THE "IS A HELPER AVAILABLE?" ANSWER LIVES. There used to be a second,
// synchronous version of it here — `isElevatedHelperAvailable()`, an endpoint
// check plus an existsSync on the VERSION marker — and by the end it had no
// production caller: the agent asks resolveElevatedAvailability()
// (elevated-availability.ts), which applies the SAME on-disk gate before it
// probes and then says WHY when the answer is no. Two shapes of one fail-closed
// rule, only one of which the running agent exercised, is exactly the drift that
// makes a security gate wrong later, so the unused one is gone. Its on-disk gate
// is quoted in elevated-availability.ts, where the live one is.

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
 * What ONE handshake attempt saw. Everything except `ok` is still a refusal —
 * this type exists so the caller can EXPLAIN the refusal, never to soften it.
 *
 *  - `ok`                — `hello-ok` with a usable bootId.
 *  - `protocol_mismatch` — it answered, speaking a version we will not speak.
 *                          Distinguished because the remedy is "finish the
 *                          half-applied upgrade and reboot", not "install".
 *  - `unreachable`       — nothing answered: no endpoint, a connect error, a
 *                          timeout, a malformed or nonsensical handshake, a close.
 *                          Collapsed on purpose: they are all "not running here".
 */
export type HelperProbeOutcome =
  | { kind: "ok"; bootId: string }
  | { kind: "protocol_mismatch" }
  | { kind: "unreachable" };

/**
 * Probe the privileged helper's current per-boot nonce (`bootId`) by performing
 * ONLY the handshake: connect → send `hello` → await `hello-ok` → resolve its
 * bootId. Used at register time so the agent can advertise the nonce the relay
 * must bind into every capability (machine + boot binding) AND so it can confirm
 * the helper is actually reachable before advertising elevatedExec.
 *
 * Fail-closed: every failure resolves a NON-`ok` outcome — no endpoint on this
 * platform, a connect error (ECONNREFUSED / ENOENT / EPERM when the helper isn't
 * listening or the pipe is unreachable), a ~2s timeout, a version-skew or
 * otherwise malformed handshake, or a premature close. The socket is ALWAYS
 * destroyed before we resolve. Anything but `ok` means "don't advertise
 * elevatedExec".
 */
export async function probeHelperHello(opts?: {
  endpoint?: ElevatedEndpoint | null;
  timeoutMs?: number;
}): Promise<HelperProbeOutcome> {
  const endpoint = opts?.endpoint === undefined ? elevatedEndpoint() : opts.endpoint;
  if (endpoint === null) return { kind: "unreachable" };
  const timeoutMs = opts?.timeoutMs ?? 2000;

  return new Promise<HelperProbeOutcome>((resolve) => {
    const decoder = new FrameDecoder();
    let done = false;

    const socket = connectEndpoint(endpoint);

    const finish = (outcome: HelperProbeOutcome): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(outcome);
    };

    const timer = setTimeout(() => finish({ kind: "unreachable" }), timeoutMs);

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
        finish({ kind: "unreachable" });
        return;
      }
      for (const frame of frames) {
        if (frame["t"] !== "hello-ok") continue;
        if (frame["protocolVersion"] !== IPC_PROTOCOL_VERSION) {
          finish({ kind: "protocol_mismatch" });
          return;
        }
        const bootId = frame["bootId"];
        finish(
          typeof bootId === "string" && bootId.length > 0
            ? { kind: "ok", bootId }
            : { kind: "unreachable" },
        );
        return;
      }
    });

    socket.on("error", () => finish({ kind: "unreachable" }));
    socket.on("close", () => finish({ kind: "unreachable" }));
  });
}

/**
 * Why discovery could not produce a helper. Every one of these is a REFUSAL that
 * behaves exactly as a bare `null` did — the value is only ever read to say
 * something true about the machine (see elevated-availability.ts).
 *
 *  - `unreachable`       — no candidate answered after every attempt.
 *  - `protocol_mismatch` — the only answer(s) came back on a version we will not
 *                          speak, and nothing usable answered anywhere.
 *  - `conflict`          — endpoints answered with DIFFERENT bootIds, so at least
 *                          one answer is not the helper.
 */
export type HelperDiscoveryFailure = "unreachable" | "protocol_mismatch" | "conflict";

/**
 * Locate the reachable privileged helper among this platform's candidate endpoints
 * (Windows has a POOL of loopback ports; the helper binds EVERY free one). Probes
 * ALL candidates via probeHelperHello, then:
 *
 *  - every answer carries the SAME bootId (the genuine helper on its bound ports)
 *    → return that bootId + the first answering endpoint; the caller pins the
 *    endpoint for subsequent execs so it doesn't re-scan the pool every command;
 *  - answers DISAGREE on bootId → fail closed (`conflict`). Since a live helper
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
 * Fail-closed: refuses when no candidate answers after every attempt (or the
 * platform has no endpoints).
 *
 * THE ONLY DISCOVERY THERE IS. It used to have a `discoverHelper()` twin that
 * threw the cause away and returned `bootId | null`; nothing but its own test
 * called it once availability reasons existed, and a fail-closed rule with two
 * implementations is one that can start disagreeing with itself. The cause is
 * carried, and every caller that does not want it ignores it.
 */
export async function discoverHelperDetailed(opts?: {
  endpoints?: ElevatedEndpoint[];
  timeoutMs?: number;
  attempts?: number;
  retryDelayMs?: number;
}): Promise<
  | { ok: true; bootId: string; endpoint: ElevatedEndpoint }
  | { ok: false; cause: HelperDiscoveryFailure }
> {
  const endpoints = opts?.endpoints ?? elevatedEndpoints();
  if (endpoints.length === 0) return { ok: false, cause: "unreachable" };
  const attempts = Math.max(1, opts?.attempts ?? 3);
  const retryDelayMs = opts?.retryDelayMs ?? 300;

  // Remembered ACROSS attempts: a helper answering with the wrong protocol
  // version is stable (a half-applied upgrade does not resolve itself in 300ms),
  // and the last attempt's silence must not erase what the earlier ones saw.
  let sawProtocolMismatch = false;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const answers: Array<{ bootId: string; endpoint: ElevatedEndpoint }> = [];
    for (const endpoint of endpoints) {
      const outcome = await probeHelperHello({ endpoint, timeoutMs: opts?.timeoutMs });
      if (outcome.kind === "ok") answers.push({ bootId: outcome.bootId, endpoint });
      else if (outcome.kind === "protocol_mismatch") sawProtocolMismatch = true;
    }
    if (answers.length > 0) {
      const bootIds = new Set(answers.map((a) => a.bootId));
      // Conflicting bootIds ⇒ someone besides the helper is answering. Fail
      // closed NOW (no retry — a squatter won't go away in 300ms; the periodic
      // reconciler is the retry path).
      if (bootIds.size > 1) return { ok: false, cause: "conflict" };
      const first = answers[0]!;
      return { ok: true, bootId: first.bootId, endpoint: first.endpoint };
    }
    // Short fixed delay before rescanning the full list after a no-answer pass
    // (not after the last attempt — nothing would come after it).
    if (attempt + 1 < attempts) {
      await new Promise((r) => setTimeout(r, retryDelayMs));
    }
  }
  return { ok: false, cause: sawProtocolMismatch ? "protocol_mismatch" : "unreachable" };
}
