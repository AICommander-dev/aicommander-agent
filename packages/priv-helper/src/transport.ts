// Local IPC listener: a Node-native `net` server on the fixed endpoint (unix
// socket on macOS, loopback TCP on Windows). Handles framing so ServerConnection
// deals in decoded messages / typed sends.

import net from "node:net";
import fs from "node:fs";
import path from "node:path";

import { encodeFrame, FrameDecoder } from "./protocol.js";
import { elevatedEndpoints } from "./endpoint.js";
import type { ElevatedEndpoint } from "./endpoint.js";
import type { HelperToClientMsg } from "./protocol.js";
import type { ServerConnection, TransportServer } from "./types.js";

/**
 * macOS `staff` group id. Every locally-created interactive user has staff as its
 * primary group, so group-owning the socket to staff (mode 0660) lets the non-root
 * tray connect while excluding daemon/service accounts and `nobody`.
 */
const MAC_STAFF_GID = 20;

/** Monotonic per-process connection id source (starts at 1). */
let nextConnectionId = 1;

/** Wrap one accepted socket as a framed ServerConnection. */
function makeConnection(socket: net.Socket): ServerConnection {
  const id = nextConnectionId++;
  const decoder = new FrameDecoder();

  let closed = false;
  let onMessageCb: ((msg: Record<string, unknown>) => void) | undefined;
  // onClose is ADDITIVE: multiple owners (helper wiring + the transport's own
  // liveConnections cleanup) each register a callback; a single-slot setter would
  // let one overwrite the other and leak connections. Every callback fires once.
  const onCloseCbs: Array<() => void> = [];

  // onClose callbacks must each fire EXACTLY once, on the first of socket
  // 'close'/'error' or a local close(). This guard is the single arbiter.
  let closeFired = false;
  const fireClose = (): void => {
    if (closeFired) return;
    closeFired = true;
    closed = true;
    for (const cb of onCloseCbs) cb();
  };

  const conn: ServerConnection = {
    id,
    onMessage(cb) {
      onMessageCb = cb;
    },
    onClose(cb) {
      onCloseCbs.push(cb);
    },
    send(msg: HelperToClientMsg) {
      if (closed) return; // no-op after close
      socket.write(encodeFrame(msg));
    },
    close() {
      if (closed) return; // idempotent
      closed = true;
      socket.destroy();
      // 'close' will still fire fireClose(); belt-and-suspenders in case the
      // socket was already detached.
      fireClose();
    },
  };

  socket.on("data", (chunk: Buffer) => {
    let messages: Array<Record<string, unknown>>;
    try {
      messages = decoder.push(chunk);
    } catch (err) {
      // Oversized/invalid frame: best-effort error frame, then close the peer.
      const message = err instanceof Error ? err.message : String(err);
      try {
        socket.write(encodeFrame({ t: "error", message }));
      } catch {
        // best-effort only
      }
      socket.destroy();
      return;
    }
    for (const msg of messages) {
      onMessageCb?.(msg);
    }
  });

  // An ECONNRESET (or any socket error) must never throw uncaught; it just ends
  // the connection.
  socket.on("error", () => {
    fireClose();
  });
  socket.on("close", () => {
    fireClose();
  });

  return conn;
}

/**
 * Create the helper's IPC transport server. `endpoint` may be a single endpoint, an
 * ORDERED LIST of candidates (Windows loopback ports — bind EVERY free one), or
 * null (unsupported platform → fail closed). Defaults to elevatedEndpoints().
 *
 * Binding every free candidate (not just the first) is deliberate: a live helper
 * must OWN the whole pool, so a local squatter cannot sit on an earlier candidate
 * and answer the agent's discovery scan ahead of the genuine helper. A port a
 * squatter grabbed while the helper was down then coexists with the helper's own
 * ports — the agent's discovery detects the conflicting bootIds and fails closed
 * (see discoverHelper in the agent).
 */
export function createTransportServer(
  endpoint: ElevatedEndpoint | ElevatedEndpoint[] | null = elevatedEndpoints(),
): TransportServer {
  const candidates =
    endpoint === null ? [] : Array.isArray(endpoint) ? endpoint : [endpoint];
  // One net.Server per successfully bound candidate; all feed the same handler.
  const bound: Array<{ server: net.Server; ep: ElevatedEndpoint }> = [];
  const liveConnections = new Set<ServerConnection>();
  let onConnectionCb: ((conn: ServerConnection) => void) | undefined;
  let closePromise: Promise<void> | undefined;

  const handleConnection = (socket: net.Socket): void => {
    const conn = makeConnection(socket);
    liveConnections.add(conn);
    conn.onClose(() => {
      liveConnections.delete(conn);
    });
    onConnectionCb?.(conn);
  };

  // Bind ONE candidate; rejects on a bind error (EADDRINUSE from a squatter or
  // another instance, a Hyper-V/WSL excluded-port reservation, …).
  const bindCandidate = (ep: ElevatedEndpoint): Promise<net.Server> =>
    new Promise<net.Server>((resolve, reject) => {
      const server = net.createServer();
      server.on("connection", handleConnection);
      const onPreListenError = (err: Error): void => {
        reject(err);
      };
      server.once("error", onPreListenError);

      if (ep.transport === "unix") {
        const sock = ep.path;
        // Unix socket: ensure parent dir exists and clear any stale socket
        // file before binding (both best-effort).
        try {
          fs.mkdirSync(path.dirname(sock), { recursive: true });
        } catch {
          // best-effort
        }
        try {
          fs.rmSync(sock, { force: true });
        } catch {
          // best-effort
        }

        server.listen(sock, () => {
          server.removeListener("error", onPreListenError);
          // The helper runs as root, so the socket is root-owned. The tray agent
          // runs as the NON-root console user, which on macOS is in group `staff`
          // (gid 20) — so the socket is root:staff mode 0660: owner (root) + the
          // staff group can read/write, everyone else is shut out. 0600 would
          // lock the agent out entirely (elevated exec dead on macOS). This
          // widening is safe because authorization is the relay-signed capability
          // (a staff process that connects still can't run anything without a
          // valid capability); restricting the socket to the specific console
          // user via peer-cred (getpeereid) is the documented hardening follow-up.
          // Both calls are best-effort (a non-root test owner can't chown to root).
          try {
            const uid = typeof process.getuid === "function" ? process.getuid() : 0;
            fs.chownSync(sock, uid, MAC_STAFF_GID);
          } catch {
            // best-effort — production root sets root:staff; a non-root test
            // owner keeps its own uid, which is fine (owner can still connect).
          }
          try {
            fs.chmodSync(sock, 0o660);
          } catch {
            // best-effort
          }
          resolve(server);
        });
        return;
      }

      // TCP: Windows binds loopback 127.0.0.1:<port>. Loopback TCP is local-only
      // (no SMB / remote reach, unlike a named pipe) and needs no fs prep or
      // chmod; access control is the relay-signed, machine-bound capability —
      // loopback grants local reach, the signature grants authority.
      server.listen(ep.port, ep.host, () => {
        server.removeListener("error", onPreListenError);
        resolve(server);
      });
    });

  const boundAddresses = (): Array<{ port: number }> => {
    const out: Array<{ port: number }> = [];
    for (const { server, ep } of bound) {
      if (ep.transport !== "tcp") continue;
      const addr = server.address();
      if (addr === null || typeof addr === "string") continue;
      out.push({ port: addr.port });
    }
    return out;
  };

  return {
    onConnection(cb) {
      onConnectionCb = cb;
    },

    async listen() {
      if (candidates.length === 0) {
        // Unsupported platform (or empty list) — fail closed.
        throw new Error(
          "elevated IPC endpoint is unavailable on this platform (fail closed)",
        );
      }
      // Bind EVERY candidate that's free; a per-candidate bind error is recorded
      // and skipped. Only when NO candidate could be bound do we fail (closed,
      // never share) with the last error.
      let lastError: Error | null = null;
      for (const ep of candidates) {
        try {
          bound.push({ server: await bindCandidate(ep), ep });
        } catch (err) {
          lastError = err instanceof Error ? err : new Error(String(err));
        }
      }
      if (bound.length === 0) {
        throw lastError ?? new Error("no elevated IPC candidate could be bound");
      }
    },

    __boundAddress() {
      // Test-only: the FIRST bound TCP address (so a test binding port 0 can
      // discover it). Unix sockets have no port → null.
      return boundAddresses()[0] ?? null;
    },

    __boundAddresses() {
      return boundAddresses();
    },

    __liveConnectionCount() {
      return liveConnections.size;
    },

    close() {
      if (closePromise) return closePromise; // idempotent
      closePromise = new Promise<void>((resolve) => {
        // Destroy all live connections first so nothing keeps the servers open.
        for (const conn of [...liveConnections]) {
          conn.close();
        }
        if (bound.length === 0) {
          resolve();
          return;
        }
        let remaining = bound.length;
        for (const { server } of bound) {
          server.close(() => {
            if (--remaining === 0) resolve();
          });
        }
      });
      return closePromise;
    },
  };
}
