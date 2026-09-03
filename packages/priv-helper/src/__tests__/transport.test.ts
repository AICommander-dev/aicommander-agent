// Transport tests: bind a REAL unix socket at a temp path and exercise framing,
// round-trip, reassembly, oversized-frame rejection, single onClose, and close().

import { afterEach, describe, expect, it } from "vitest";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { createTransportServer } from "../transport.js";
import { encodeFrame, FrameDecoder, MAX_FRAME_BYTES } from "../protocol.js";
import type { TransportServer } from "../types.js";
import type { HelloMsg, HelloOkMsg } from "../protocol.js";

// Deterministic unique temp socket path: pid + counter (no Math.random flake).
let sockCounter = 0;
function tmpSocketPath(): string {
  return path.join(
    os.tmpdir(),
    `aic-priv-helper-test-${process.pid}-${sockCounter++}.sock`,
  );
}

let server: TransportServer | undefined;
let endpoint: string | undefined;
const clients: net.Socket[] = [];

afterEach(async () => {
  for (const c of clients.splice(0)) c.destroy();
  if (server) {
    await server.close();
    server = undefined;
  }
  if (endpoint) {
    try {
      fs.rmSync(endpoint, { force: true });
    } catch {
      // best-effort
    }
    endpoint = undefined;
  }
});

/** Bind a fresh server at a temp unix socket and return it (with onConnection set). */
async function startServer(
  onConn: Parameters<TransportServer["onConnection"]>[0],
): Promise<void> {
  endpoint = tmpSocketPath();
  server = createTransportServer({ transport: "unix", path: endpoint });
  server.onConnection(onConn);
  await server.listen();
}

function connect(): net.Socket {
  const c = net.connect(endpoint!);
  clients.push(c);
  return c;
}

const HELLO: HelloMsg = { t: "hello", protocolVersion: 1, clientVersion: "test" };

describe("createTransportServer", () => {
  it("round-trips a framed hello and replies with hello-ok", async () => {
    const received: Array<Record<string, unknown>> = [];
    await startServer((conn) => {
      conn.onMessage((msg) => {
        received.push(msg);
        const ok: HelloOkMsg = {
          t: "hello-ok",
          protocolVersion: 1,
          helperVersion: "test",
          bootId: "boot",
          effectiveIdentity: "root",
        };
        conn.send(ok);
      });
    });

    const client = connect();
    const clientDecoder = new FrameDecoder();
    const reply = new Promise<Record<string, unknown>>((resolve) => {
      client.on("data", (chunk: Buffer) => {
        const msgs = clientDecoder.push(chunk);
        if (msgs[0]) resolve(msgs[0]);
      });
    });
    client.write(encodeFrame(HELLO));

    const got = await reply;
    expect(got).toMatchObject({ t: "hello-ok", effectiveIdentity: "root" });
    expect(received.at(-1)).toMatchObject({ t: "hello", clientVersion: "test" });
  });

  it("splits multiple frames arriving in one chunk", async () => {
    const received: Array<Record<string, unknown>> = [];
    let resolveTwo!: () => void;
    const gotTwo = new Promise<void>((r) => {
      resolveTwo = r;
    });
    await startServer((conn) => {
      conn.onMessage((msg) => {
        received.push(msg);
        if (received.length === 2) resolveTwo();
      });
    });

    const client = connect();
    const a = encodeFrame({ ...HELLO, clientVersion: "a" });
    const b = encodeFrame({ ...HELLO, clientVersion: "b" });
    client.write(Buffer.concat([a, b]));

    await gotTwo;
    expect(received.map((m) => m["clientVersion"])).toEqual(["a", "b"]);
  });

  it("reassembles a frame split across two writes", async () => {
    const received: Array<Record<string, unknown>> = [];
    let resolveOne!: () => void;
    const gotOne = new Promise<void>((r) => {
      resolveOne = r;
    });
    await startServer((conn) => {
      conn.onMessage((msg) => {
        received.push(msg);
        resolveOne();
      });
    });

    const client = connect();
    const frame = encodeFrame(HELLO);
    const split = 3; // mid-header split is fine
    client.write(frame.subarray(0, split));
    await new Promise((r) => setTimeout(r, 20));
    client.write(frame.subarray(split));

    await gotOne;
    expect(received[0]).toMatchObject({ t: "hello", clientVersion: "test" });
  });

  it("fires onClose exactly once when the client disconnects", async () => {
    let closeCount = 0;
    let resolveClosed!: () => void;
    const closed = new Promise<void>((r) => {
      resolveClosed = r;
    });
    await startServer((conn) => {
      conn.onClose(() => {
        closeCount++;
        resolveClosed();
      });
    });

    const client = connect();
    await new Promise((r) => client.on("connect", r));
    client.destroy();

    await closed;
    // Give any duplicate close/error a chance to (wrongly) fire.
    await new Promise((r) => setTimeout(r, 30));
    expect(closeCount).toBe(1);
  });

  it("does not leak live connections after they open and close", async () => {
    const closes: Array<() => void> = [];
    await startServer((conn) => {
      // A second onClose owner (like helper.ts) must not clobber the transport's
      // own liveConnections cleanup — both fire because onClose is additive.
      conn.onClose(() => {
        const next = closes.shift();
        next?.();
      });
    });

    const N = 4;
    for (let i = 0; i < N; i++) {
      const client = connect();
      await new Promise((r) => client.on("connect", r));
    }
    // Wait until the server has accepted all N.
    const accepted = Date.now() + 1000;
    while (server!.__liveConnectionCount() < N && Date.now() < accepted) {
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(server!.__liveConnectionCount()).toBe(N);

    const allClosed = new Promise<void>((resolve) => {
      let remaining = N;
      for (let i = 0; i < N; i++) closes.push(() => { if (--remaining === 0) resolve(); });
    });
    for (const c of clients.splice(0)) c.destroy();
    await allClosed;
    // Give the transport's own onClose cleanup a beat to run.
    await new Promise((r) => setTimeout(r, 30));
    expect(server!.__liveConnectionCount()).toBe(0);
  });

  it("rejects an oversized frame with an error frame then closes", async () => {
    let closeCount = 0;
    let resolveClosed!: () => void;
    const closed = new Promise<void>((r) => {
      resolveClosed = r;
    });
    await startServer((conn) => {
      conn.onClose(() => {
        closeCount++;
        resolveClosed();
      });
    });

    const client = connect();
    const clientDecoder = new FrameDecoder();
    const errFrame = new Promise<Record<string, unknown>>((resolve) => {
      client.on("data", (chunk: Buffer) => {
        const msgs = clientDecoder.push(chunk);
        if (msgs[0]) resolve(msgs[0]);
      });
    });

    // 4-byte header declaring MAX_FRAME_BYTES + 1.
    const header = Buffer.allocUnsafe(4);
    header.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    client.write(header);

    const err = await errFrame;
    expect(err["t"]).toBe("error");
    await closed;
    expect(closeCount).toBe(1);
  });

  it("close() resolves and rejects further connections", async () => {
    await startServer(() => {
      // no-op
    });
    await server!.close();
    // Idempotent: a second close still resolves.
    await server!.close();

    // A new connection to the (now unlinked) socket must fail.
    const failed = new Promise<Error>((resolve) => {
      const c = net.connect(endpoint!);
      clients.push(c);
      c.on("error", (e) => resolve(e));
    });
    const e = await failed;
    expect(e).toBeInstanceOf(Error);
  });

  it("listen() rejects on an unsupported (null) endpoint", async () => {
    const s = createTransportServer(null);
    await expect(s.listen()).rejects.toThrow(/fail closed|unavailable/i);
  });
});

describe("createTransportServer (tcp)", () => {
  it("round-trips a framed hello over loopback TCP (port 0 → boundAddress)", async () => {
    // Windows uses loopback TCP (no named pipe). Bind port 0 so the OS assigns a
    // free port, discover it via boundAddress(), then do a real framed round-trip.
    const received: Array<Record<string, unknown>> = [];
    server = createTransportServer({ transport: "tcp", host: "127.0.0.1", port: 0 });
    server.onConnection((conn) => {
      conn.onMessage((msg) => {
        received.push(msg);
        const ok: HelloOkMsg = {
          t: "hello-ok",
          protocolVersion: 1,
          helperVersion: "test",
          bootId: "boot",
          effectiveIdentity: "root",
        };
        conn.send(ok);
      });
    });
    await server.listen();

    const bound = server.__boundAddress();
    expect(bound).not.toBeNull();
    expect(bound!.port).toBeGreaterThan(0);

    const client = net.connect(bound!.port, "127.0.0.1");
    clients.push(client);
    const clientDecoder = new FrameDecoder();
    const reply = new Promise<Record<string, unknown>>((resolve) => {
      client.on("data", (chunk: Buffer) => {
        const msgs = clientDecoder.push(chunk);
        if (msgs[0]) resolve(msgs[0]);
      });
    });
    client.write(encodeFrame(HELLO));

    const got = await reply;
    expect(got).toMatchObject({ t: "hello-ok", effectiveIdentity: "root" });
    expect(received.at(-1)).toMatchObject({ t: "hello", clientVersion: "test" });
  });

  it("listen() rejects (fail closed) when the TCP port is already owned", async () => {
    // First server takes an OS-assigned loopback port. A second server aimed at the
    // SAME port must REJECT on the pre-listen 'error' (EADDRINUSE) — the helper must
    // never silently share the endpoint with a squatter.
    const server1 = createTransportServer({ transport: "tcp", host: "127.0.0.1", port: 0 });
    server1.onConnection(() => {
      // no-op
    });
    await server1.listen();

    const bound = server1.__boundAddress();
    expect(bound).not.toBeNull();
    const port = bound!.port;

    const server2 = createTransportServer({ transport: "tcp", host: "127.0.0.1", port });
    server2.onConnection(() => {
      // no-op
    });
    try {
      await expect(server2.listen()).rejects.toThrow();
    } finally {
      await server2.close();
      await server1.close();
    }
  });

  it("boundAddress() is null for a unix endpoint", () => {
    const s = createTransportServer({ transport: "unix", path: "/tmp/whatever.sock" });
    expect(s.__boundAddress()).toBeNull();
  });

  it("binds EVERY free candidate and accepts connections on each", async () => {
    // A live helper must own the WHOLE pool so a squatter can't sit on one of the
    // candidates. Two port-0 candidates → two distinct bound ports, both serving.
    server = createTransportServer([
      { transport: "tcp", host: "127.0.0.1", port: 0 },
      { transport: "tcp", host: "127.0.0.1", port: 0 },
    ]);
    server.onConnection(() => {});
    await server.listen();

    const bound = server.__boundAddresses();
    expect(bound).toHaveLength(2);
    expect(bound[0]!.port).not.toBe(bound[1]!.port);

    for (const { port } of bound) {
      const c = net.connect(port, "127.0.0.1");
      clients.push(c);
      await new Promise<void>((resolve, reject) => {
        c.on("connect", () => resolve());
        c.on("error", reject);
      });
    }
    // Wait for the server side to see both accepted connections.
    const deadline = Date.now() + 1000;
    while (server.__liveConnectionCount() < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    expect(server.__liveConnectionCount()).toBe(2);
  });

  it("skips a candidate already owned and binds the remaining free ones", async () => {
    // Occupy a port, then hand a two-candidate list whose first entry is that
    // occupied port. listen() must skip it (EADDRINUSE) and bind the second.
    const occupier = createTransportServer({ transport: "tcp", host: "127.0.0.1", port: 0 });
    occupier.onConnection(() => {});
    await occupier.listen();
    const takenPort = occupier.__boundAddress()!.port;

    server = createTransportServer([
      { transport: "tcp", host: "127.0.0.1", port: takenPort },
      { transport: "tcp", host: "127.0.0.1", port: 0 },
    ]);
    server.onConnection(() => {});
    try {
      await server.listen();
      const bound = server.__boundAddresses();
      expect(bound).toHaveLength(1);
      expect(bound[0]!.port).toBeGreaterThan(0);
      expect(bound[0]!.port).not.toBe(takenPort);
    } finally {
      await occupier.close();
    }
  });

  it("rejects (fail closed) only when EVERY candidate is already owned", async () => {
    const occ1 = createTransportServer({ transport: "tcp", host: "127.0.0.1", port: 0 });
    const occ2 = createTransportServer({ transport: "tcp", host: "127.0.0.1", port: 0 });
    occ1.onConnection(() => {});
    occ2.onConnection(() => {});
    await occ1.listen();
    await occ2.listen();
    const p1 = occ1.__boundAddress()!.port;
    const p2 = occ2.__boundAddress()!.port;

    const s = createTransportServer([
      { transport: "tcp", host: "127.0.0.1", port: p1 },
      { transport: "tcp", host: "127.0.0.1", port: p2 },
    ]);
    s.onConnection(() => {});
    try {
      await expect(s.listen()).rejects.toThrow();
    } finally {
      await s.close();
      await occ1.close();
      await occ2.close();
    }
  });
});
