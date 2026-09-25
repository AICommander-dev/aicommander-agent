// Integration test for the composition root: a real unix-socket transport + real
// executor, driven by a real IPC client over the wire. Capabilities are minted
// with a throwaway signer pinned via AIC_ELEVATED_PUBKEY. Commands run as the
// current (non-root) test user — we exercise the protocol/verify/lease plumbing,
// not real privilege.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateCapabilityKeypair,
  signElevatedCapability,
  type ElevatedCapabilityClaims,
} from "@aicommander/protocol";
import { createTransportServer } from "../transport.js";
import { createPrivilegedExecutor } from "../executor.js";
import { startHelper, __connTrackingSizes, type RunningHelper } from "../helper.js";
import { encodeFrame, FrameDecoder, IPC_PROTOCOL_VERSION } from "../protocol.js";
import { HELPER_VERSION } from "../version.js";

let signer: { privateKeyPkcs8: string; publicKeyRaw: string };
let socketCounter = 0;
// The running helper's per-boot nonce, set by start(). Every happy-path mint binds
// its capability to this bootId (helperInstanceId) so verifyCapabilityForExec's
// REQUIRED boot binding passes.
let currentBootId: string | undefined;

beforeAll(async () => {
  signer = await generateCapabilityKeypair();
  process.env["AIC_ELEVATED_PUBKEY"] = signer.publicKeyRaw;
});

afterAll(() => {
  delete process.env["AIC_ELEVATED_PUBKEY"];
});

function tempSocketPath(): string {
  return join(tmpdir(), `aic-helper-test-${process.pid}-${socketCounter++}.sock`);
}

async function mint(overrides: Partial<ElevatedCapabilityClaims> = {}): Promise<{
  capability: string;
  requestId: string;
}> {
  const now = Date.now();
  const requestId = overrides.requestId ?? `req-${socketCounter}-${now}`;
  const claims: ElevatedCapabilityClaims = {
    protocolVersion: 1,
    accountId: "acct",
    requestId,
    command: "printf hi",
    timeoutMs: 5000,
    issuedAt: now,
    expiresAt: now + 60_000,
    ...(currentBootId !== undefined ? { helperInstanceId: currentBootId } : {}),
    ...overrides,
  };
  return { capability: await signElevatedCapability(claims, signer.privateKeyPkcs8), requestId };
}

/** A connected client that decodes helper frames into a growing list. */
class Client {
  readonly socket: net.Socket;
  readonly messages: Array<Record<string, unknown>> = [];
  private readonly decoder = new FrameDecoder();
  private waiters: Array<{ pred: (m: Record<string, unknown>) => boolean; resolve: (m: Record<string, unknown>) => void }> = [];

  constructor(path: string) {
    this.socket = net.connect(path);
    this.socket.on("data", (chunk: Buffer) => {
      for (const m of this.decoder.push(chunk)) {
        this.messages.push(m);
        this.waiters = this.waiters.filter((w) => {
          if (w.pred(m)) {
            w.resolve(m);
            return false;
          }
          return true;
        });
      }
    });
    this.socket.on("error", () => {});
  }

  send(msg: Record<string, unknown>): void {
    this.socket.write(encodeFrame(msg as never));
  }

  waitFor(pred: (m: Record<string, unknown>) => boolean, timeoutMs = 4000): Promise<Record<string, unknown>> {
    const existing = this.messages.find(pred);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out waiting for message")), timeoutMs);
      this.waiters.push({
        pred,
        resolve: (m) => {
          clearTimeout(timer);
          resolve(m);
        },
      });
    });
  }

  async handshake(protocolVersion = IPC_PROTOCOL_VERSION): Promise<Record<string, unknown>> {
    await new Promise<void>((r) => this.socket.on("connect", () => r()));
    this.send({ t: "hello", protocolVersion, clientVersion: "test" });
    return this.waitFor((m) => m["t"] === "hello-ok" || m["t"] === "error");
  }

  close(): void {
    this.socket.destroy();
  }
}

describe("startHelper (integration)", () => {
  let helper: RunningHelper;
  let path: string;
  const clients: Client[] = [];

  async function start(execOpts?: { maxTimeoutMs?: number }): Promise<void> {
    path = tempSocketPath();
    helper = await startHelper({
      transport: createTransportServer({ transport: "unix", path }),
      // The test user is not root; allow the unprivileged launch so we exercise
      // the protocol/verify/lease plumbing rather than the fail-closed refusal.
      executor: createPrivilegedExecutor({ allowUnprivileged: true, ...execOpts }),
    });
    currentBootId = helper.bootId;
  }

  afterEach(async () => {
    for (const c of clients.splice(0)) c.close();
    if (helper) await helper.stop();
  });

  function connect(): Client {
    const c = new Client(path);
    clients.push(c);
    return c;
  }

  it("completes a handshake with matching identity fields", async () => {
    await start();
    const c = connect();
    const ok = await c.handshake();
    expect(ok["t"]).toBe("hello-ok");
    expect(ok["protocolVersion"]).toBe(IPC_PROTOCOL_VERSION);
    expect(ok["helperVersion"]).toBe(HELPER_VERSION);
    expect(ok["bootId"]).toBe(helper.bootId);
    expect(typeof ok["effectiveIdentity"]).toBe("string");
  });

  it("runs a verified command and streams output + done", async () => {
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({ command: "printf hi" });
    c.send({ t: "exec", requestId, capability });
    const out = await c.waitFor((m) => m["t"] === "output" && m["requestId"] === requestId);
    expect(Buffer.from(out["chunk"] as string, "base64").toString()).toBe("hi");
    const done = await c.waitFor((m) => m["t"] === "done" && m["requestId"] === requestId);
    expect(done["exitCode"]).toBe(0);
  });

  it("rejects an exec before the handshake and closes", async () => {
    await start();
    const c = connect();
    await new Promise<void>((r) => c.socket.on("connect", () => r()));
    const { capability, requestId } = await mint();
    c.send({ t: "exec", requestId, capability });
    const err = await c.waitFor((m) => m["t"] === "error");
    expect(String(err["message"])).toMatch(/handshake required/);
  });

  it("rejects a replayed capability the second time", async () => {
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({ command: "printf hi" });
    c.send({ t: "exec", requestId, capability });
    await c.waitFor((m) => m["t"] === "done" && m["requestId"] === requestId);
    // Replay the exact same capability → verify layer rejects it.
    c.send({ t: "exec", requestId, capability });
    const err = await c.waitFor(
      (m) => m["t"] === "error" && m["requestId"] === requestId && /replay/.test(String(m["message"])),
    );
    expect(err).toBeTruthy();
  });

  it("rejects an expired capability without spawning", async () => {
    await start();
    const c = connect();
    await c.handshake();
    const past = Date.now() - 120_000;
    const { capability, requestId } = await mint({ issuedAt: past, expiresAt: past + 1000 });
    c.send({ t: "exec", requestId, capability });
    const err = await c.waitFor((m) => m["t"] === "error" && m["requestId"] === requestId);
    expect(String(err["message"])).toMatch(/expired/);
  });

  it("rejects a wire requestId that does not match the signed capability", async () => {
    await start();
    const c = connect();
    await c.handshake();
    const { capability } = await mint({ requestId: "signed-id" });
    c.send({ t: "exec", requestId: "different-id", capability });
    const err = await c.waitFor((m) => m["t"] === "error" && m["requestId"] === "different-id");
    expect(String(err["message"])).toMatch(/does not match/);
  });

  it("reports an unknown message type as an error", async () => {
    await start();
    const c = connect();
    await c.handshake();
    c.send({ t: "bogus" });
    const err = await c.waitFor((m) => m["t"] === "error" && /unknown message type/.test(String(m["message"])));
    expect(err).toBeTruthy();
  });

  it("does not spawn if the connection closes during capability verification", async () => {
    await start();
    const c = connect();
    await c.handshake();
    // A long-running command; begin the exec then immediately drop the wire.
    const { capability, requestId } = await mint({ command: "sleep 5", timeoutMs: 10_000 });
    c.send({ t: "exec", requestId, capability });
    c.close();

    // Give verification + any (wrongly) scheduled spawn a chance to happen.
    await new Promise((r) => setTimeout(r, 400));
    // Nothing for this requestId may have been delivered, and nothing runs.
    const forThis = c.messages.filter((m) => m["requestId"] === requestId);
    expect(forThis.filter((m) => m["t"] === "output" || m["t"] === "done")).toHaveLength(0);
  });

  it("cancels a pending exec when a kill for it arrives during verification", async () => {
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({ command: "sleep 5", timeoutMs: 10_000 });
    c.send({ t: "exec", requestId, capability });
    // Kill the SAME requestId before verification resolves.
    c.send({ t: "kill", requestId });
    const err = await c.waitFor(
      (m) => m["t"] === "error" && m["requestId"] === requestId && /cancelled/.test(String(m["message"])),
    );
    expect(err).toBeTruthy();
    // No output/done was produced for it.
    const forThis = c.messages.filter(
      (m) => m["requestId"] === requestId && (m["t"] === "output" || m["t"] === "done"),
    );
    expect(forThis).toHaveLength(0);
  });

  it("reaps even a SIGTERM-ignoring child when the helper stops", async () => {
    await start();
    const c = connect();
    await c.handshake();
    // #7: the child IGNORES SIGTERM, so only the HARD (short-grace) SIGKILL
    // escalation from killAll({ hard: true }) can reap it before process.exit.
    const { capability, requestId } = await mint({
      command: "echo $$; trap '' TERM; sleep 10",
      timeoutMs: 30_000,
    });
    c.send({ t: "exec", requestId, capability });
    const out = await c.waitFor((m) => m["t"] === "output" && m["requestId"] === requestId);
    const pid = Number(Buffer.from(out["chunk"] as string, "base64").toString().trim());
    expect(Number.isInteger(pid)).toBe(true);

    // stop() hard-kills every leased command and drains before closing.
    await helper.stop();

    const gone = (): boolean => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    };
    // SIGKILL delivery is async; poll briefly for the TERM-ignoring child to die.
    const deadline = Date.now() + 1500;
    while (Date.now() < deadline && !gone()) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(gone()).toBe(true);
  }, 8000);

  it("does not grow cancellation tracking for kills of never-exec'd requestIds", async () => {
    await start();
    const c = connect();
    await c.handshake();
    // R2: a client spamming `kill` frames for requestIds that were never exec'd
    // (no pendingVerify entry, no live lease) must NOT accumulate in the tracking
    // sets — otherwise the boot-persistent root daemon grows without bound.
    for (let i = 0; i < 300; i++) c.send({ t: "kill", requestId: `ghost-${i}` });
    await new Promise((r) => setTimeout(r, 200));
    const sizes = __connTrackingSizes();
    const total = sizes.reduce((acc, s) => acc + s.pendingVerify + s.cancelled, 0);
    expect(total).toBe(0);
  });

  it("rejects a new exec that arrives during the shutdown drain (no spawn)", async () => {
    // Gap 1: the transport is still listening while stop() drains the kill, so an
    // exec arriving mid-drain must be refused — never spawn a command that could
    // outlive process.exit.
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({ command: "sleep 5", timeoutMs: 10_000 });
    // stop() flips `stopping` synchronously before it returns its promise.
    const stopping = helper.stop();
    c.send({ t: "exec", requestId, capability });
    const err = await c.waitFor(
      (m) => m["t"] === "error" && m["requestId"] === requestId && /shutting down/.test(String(m["message"])),
    );
    expect(err).toBeTruthy();
    const forThis = c.messages.filter(
      (m) => m["requestId"] === requestId && (m["t"] === "output" || m["t"] === "done"),
    );
    expect(forThis).toHaveLength(0);
    await stopping;
  });

  it("reaps a TERM-ignoring command that already FAILED (timeout) when the helper stops", async () => {
    // Gap 2: the timeout reports onError, but the child ignores SIGTERM and is
    // still alive with its SIGKILL escalation armed. The lease must be held past
    // the error (released only on real close) so helper.stop()'s HARD killAll can
    // still reap it — otherwise it's orphaned past process.exit.
    await start({ maxTimeoutMs: 500 });
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({
      command: "echo $$; trap '' TERM; sleep 10",
      timeoutMs: 500,
    });
    c.send({ t: "exec", requestId, capability });
    const out = await c.waitFor((m) => m["t"] === "output" && m["requestId"] === requestId);
    const pid = Number(Buffer.from(out["chunk"] as string, "base64").toString().trim());
    expect(Number.isInteger(pid)).toBe(true);
    // The (clamped) timeout fires → terminal error, but the child is still alive.
    await c.waitFor(
      (m) => m["t"] === "error" && m["requestId"] === requestId && /timed out/.test(String(m["message"])),
    );

    // stop() HARD-kills every STILL-LEASED command (short grace) and drains.
    await helper.stop();

    const gone = (): boolean => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    };
    // Poll well under KILL_ESCALATION_MS (5s): passing requires the HARD kill on
    // the held lease, not the original soft escalation.
    const deadline = Date.now() + 1500;
    while (Date.now() < deadline && !gone()) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(gone()).toBe(true);
  }, 8000);

  it("does not leak cancellation tracking across many start+kill cycles on one connection", async () => {
    // Gap 3: killing a LIVE (post-verify) lease must not add a `cancelled` entry
    // (its handleExec finally already ran) — so a long-lived connection that
    // starts+kills many commands keeps its tracking sets bounded.
    await start();
    const c = connect();
    await c.handshake();
    for (let i = 0; i < 20; i++) {
      const { capability, requestId } = await mint({
        command: "sleep 5",
        timeoutMs: 10_000,
        requestId: `live-${i}`,
      });
      c.send({ t: "exec", requestId, capability });
      // Let it settle into a live post-verify lease, then kill it directly.
      await new Promise((r) => setTimeout(r, 120));
      c.send({ t: "kill", requestId });
      await c.waitFor(
        (m) => (m["t"] === "done" || m["t"] === "error") && m["requestId"] === requestId,
      );
    }
    // Let any in-flight finally/onClosed settle, then assert nothing accumulated.
    await new Promise((r) => setTimeout(r, 100));
    const sizes = __connTrackingSizes();
    const total = sizes.reduce((acc, s) => acc + s.pendingVerify + s.cancelled, 0);
    expect(total).toBe(0);
  }, 15000);

  it("reaps a TERM-ignoring child killed via an explicit kill FRAME when the helper then stops", async () => {
    // #7 residual: a soft `kill` frame arms only the 5s escalation, but the lease
    // now persists until the child's real close. So a helper.stop() within that
    // window still hard-upgrades the still-alive child via killAll({ hard: true })
    // and reaps it before stop() resolves — no orphaned root process.
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({
      command: "echo $$; trap '' TERM; sleep 10",
      timeoutMs: 30_000,
    });
    c.send({ t: "exec", requestId, capability });
    const out = await c.waitFor((m) => m["t"] === "output" && m["requestId"] === requestId);
    const pid = Number(Buffer.from(out["chunk"] as string, "base64").toString().trim());
    expect(Number.isInteger(pid)).toBe(true);

    // Soft kill frame (5s escalation) then shutdown INSIDE that window.
    c.send({ t: "kill", requestId });
    await helper.stop();

    const gone = (): boolean => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    };
    // Passing well under KILL_ESCALATION_MS (5s) requires the HARD upgrade on the
    // still-leased child, not the soft escalation the kill frame armed.
    const deadline = Date.now() + 1500;
    while (Date.now() < deadline && !gone()) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(gone()).toBe(true);
  }, 8000);

  it("hard-kills a TERM-ignoring child promptly when its CONNECTION drops", async () => {
    // A spontaneous client disconnect must kill the command DECISIVELY (short
    // SIGKILL grace), not leave it lingering on the 5s soft escalation — the
    // authorizing connection is gone.
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({
      command: "echo $$; trap '' TERM; sleep 10",
      timeoutMs: 30_000,
    });
    c.send({ t: "exec", requestId, capability });
    const out = await c.waitFor((m) => m["t"] === "output" && m["requestId"] === requestId);
    const pid = Number(Buffer.from(out["chunk"] as string, "base64").toString().trim());
    expect(Number.isInteger(pid)).toBe(true);

    // Drop the wire: onClose → releaseAll({ hard: true }).
    c.close();

    const gone = (): boolean => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    };
    // Reaped within ~HARD grace (400ms + async SIGKILL), far under the 5s soft path.
    const deadline = Date.now() + 1500;
    while (Date.now() < deadline && !gone()) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(gone()).toBe(true);
  }, 8000);

  it("does not leak leases: the table is empty after N normal completions", async () => {
    await start();
    const c = connect();
    await c.handshake();
    for (let i = 0; i < 8; i++) {
      const { capability, requestId } = await mint({
        command: "printf hi",
        requestId: `done-${i}`,
      });
      c.send({ t: "exec", requestId, capability });
      await c.waitFor((m) => m["t"] === "done" && m["requestId"] === requestId);
    }
    // onClosed fires on the real 'close' just after onDone; give it a tick to run.
    await new Promise((r) => setTimeout(r, 100));
    expect(helper.__leaseCount()).toBe(0);
  }, 8000);

  it("kills a running command on request", async () => {
    await start();
    const c = connect();
    await c.handshake();
    const { capability, requestId } = await mint({ command: "sleep 5", timeoutMs: 10_000 });
    c.send({ t: "exec", requestId, capability });
    // Give the process a moment to start, then kill.
    await new Promise((r) => setTimeout(r, 150));
    c.send({ t: "kill", requestId });
    const terminal = await c.waitFor(
      (m) => (m["t"] === "done" || m["t"] === "error") && m["requestId"] === requestId,
    );
    expect(terminal).toBeTruthy();
  });
});
