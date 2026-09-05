// Tests for the agent-side elevated-execution IPC client. Fail-closed paths use
// no helper at all; the round-trip + kill tests stand up a REAL priv-helper over
// a temp unix socket, minting throwaway-signed capabilities pinned via
// AIC_ELEVATED_PUBKEY. Commands run as the (non-root) test user — we exercise the
// wire protocol, not real privilege.

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  generateCapabilityKeypair,
  signElevatedCapability,
  type ElevatedCapabilityClaims,
} from "@aicommander/protocol";
import {
  startHelper,
  createTransportServer,
  createPrivilegedExecutor,
  encodeFrame,
  FrameDecoder,
  type RunningHelper,
  type TransportServer,
} from "@aicommander/priv-helper";
import type { ElevatedEndpoint } from "@aicommander/priv-helper";
import { executeElevatedCommand, probeHelperHello, discoverHelperDetailed } from "../elevated-executor.js";
import type { CommandHandlers } from "../executor.js";

let signer: { privateKeyPkcs8: string; publicKeyRaw: string };
let socketCounter = 0;

beforeAll(async () => {
  signer = await generateCapabilityKeypair();
  process.env["AIC_ELEVATED_PUBKEY"] = signer.publicKeyRaw;
});

afterAll(() => {
  delete process.env["AIC_ELEVATED_PUBKEY"];
});

function tempSocketPath(): string {
  return join(tmpdir(), `aic-agent-elev-test-${process.pid}-${socketCounter++}.sock`);
}

/** Fake endpoints stood up by a test; closed after each one. */
const fakeServers: net.Server[] = [];

afterEach(async () => {
  for (const server of fakeServers.splice(0)) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

/**
 * A responder that answers `hello` with an `error` frame and hangs up — what
 * the live helper does when it will not speak our IPC protocol version, and
 * equally what any local process holding the endpoint could do. Not a real
 * helper on purpose: the point is the SHAPE of the answer, which is all the
 * probe is allowed to conclude from.
 */
async function refusingEndpoint(message: string): Promise<ElevatedEndpoint> {
  const path = tempSocketPath();
  const server = net.createServer((socket) => {
    const decoder = new FrameDecoder();
    socket.on("data", (chunk: Buffer) => {
      for (const frame of decoder.push(chunk)) {
        if (frame["t"] !== "hello") continue;
        socket.write(encodeFrame({ t: "error", message }));
        socket.end();
      }
    });
    socket.on("error", () => undefined);
  });
  fakeServers.push(server);
  await new Promise<void>((resolve) => server.listen(path, resolve));
  return { transport: "unix", path };
}

async function mint(overrides: Partial<ElevatedCapabilityClaims> = {}): Promise<string> {
  const now = Date.now();
  const claims: ElevatedCapabilityClaims = {
    protocolVersion: 1,
    accountId: "acct",
    requestId: "id1",
    command: "printf hi",
    timeoutMs: 10_000,
    issuedAt: now,
    expiresAt: now + 60_000,
    ...overrides,
  };
  return signElevatedCapability(claims, signer.privateKeyPkcs8);
}

function spyHandlers(): {
  handlers: CommandHandlers;
  output: Array<{ chunk: string; stream: string }>;
  done: Array<{ exitCode: number; durationMs: number }>;
  errors: string[];
} {
  const output: Array<{ chunk: string; stream: string }> = [];
  const done: Array<{ exitCode: number; durationMs: number }> = [];
  const errors: string[] = [];
  return {
    output,
    done,
    errors,
    handlers: {
      onOutput: (chunk, stream) => output.push({ chunk, stream }),
      onDone: (exitCode, durationMs) => done.push({ exitCode, durationMs }),
      onError: (error) => errors.push(error),
    },
  };
}

describe("executeElevatedCommand — fail-closed", () => {
  it("reports a terminal error and a safe no-op kill when endpoint is null", async () => {
    const { handlers, output, done, errors } = spyHandlers();
    const running = executeElevatedCommand("cap", "id1", handlers, { endpoint: null });

    expect(() => running.kill()).not.toThrow();
    await new Promise((r) => setTimeout(r, 0));

    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/not available on this machine/);
    expect(output).toHaveLength(0);
    expect(done).toHaveLength(0);
  });

  it("fails closed (connection failed) when nothing is listening, never onDone", async () => {
    const { handlers, done, errors } = spyHandlers();
    // A temp path with no server bound → ENOENT on connect.
    executeElevatedCommand("cap", "id1", handlers, {
      endpoint: { transport: "unix", path: tempSocketPath() },
    });

    await new Promise((r) => setTimeout(r, 100));

    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/connection failed/);
    expect(done).toHaveLength(0);
  });
});

describe("executeElevatedCommand — real helper", () => {
  let helper: RunningHelper;
  let socketPath: string;
  let endpoint: ElevatedEndpoint;

  afterEach(async () => {
    if (helper) await helper.stop();
    try {
      fs.rmSync(socketPath, { force: true });
    } catch {
      // best-effort
    }
  });

  async function startAt(): Promise<void> {
    socketPath = tempSocketPath();
    endpoint = { transport: "unix", path: socketPath };
    helper = await startHelper({
      transport: createTransportServer(endpoint),
      // The test runs as a non-root user; allow the unprivileged launch so we
      // exercise the client↔helper wire, not the fail-closed privilege refusal.
      executor: createPrivilegedExecutor({ allowUnprivileged: true }),
    });
  }

  it("completes a full round-trip: streams output and a done exit code 0", async () => {
    await startAt();
    const { handlers, output, done, errors } = spyHandlers();
    // The helper now REQUIRES a machine-bound capability: helperInstanceId must
    // equal its live bootId, else verify rejects it before exec.
    const capability = await mint({
      command: "printf hi",
      requestId: "id1",
      helperInstanceId: helper.bootId,
    });

    executeElevatedCommand(capability, "id1", handlers, { endpoint });

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out")), 4000);
      const poll = setInterval(() => {
        if (done.length > 0 || errors.length > 0) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve();
        }
      }, 20);
    });

    expect(errors).toHaveLength(0);
    expect(output.length).toBeGreaterThan(0);
    const decoded = output.map((o) => Buffer.from(o.chunk, "base64").toString()).join("");
    expect(decoded).toBe("hi");
    expect(done).toHaveLength(1);
    expect(done[0]!.exitCode).toBe(0);
  });

  it("kill() terminates a long-running command with a terminal frame", async () => {
    await startAt();
    const { handlers, done, errors } = spyHandlers();
    const capability = await mint({
      command: "sleep 5",
      requestId: "id1",
      timeoutMs: 30_000,
      helperInstanceId: helper.bootId,
    });

    const running = executeElevatedCommand(capability, "id1", handlers, { endpoint });

    // Let the exec start on the helper, then request a kill.
    await new Promise((r) => setTimeout(r, 200));
    running.kill();

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no terminal frame after kill")), 4000);
      const poll = setInterval(() => {
        if (done.length > 0 || errors.length > 0) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve();
        }
      }, 20);
    });

    expect(done.length + errors.length).toBeGreaterThan(0);
  });

  it("kill() before hello-ok cancels: no command ever runs, no onDone success", async () => {
    await startAt();
    const { handlers, output, done, errors } = spyHandlers();
    // A command that would leave an observable side effect (a temp file) IF it ran.
    const marker = join(tmpdir(), `aic-elev-cancel-${process.pid}-${socketCounter++}.marker`);
    const capability = await mint({
      command: `printf x > ${marker}`,
      requestId: "id1",
      timeoutMs: 30_000,
      helperInstanceId: helper.bootId,
    });

    const running = executeElevatedCommand(capability, "id1", handlers, { endpoint });
    // Cancel immediately — before the connect/hello-ok round-trip completes, so
    // `exec` is never sent to the helper.
    running.kill();

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no terminal after cancel")), 4000);
      const poll = setInterval(() => {
        if (done.length > 0 || errors.length > 0) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve();
        }
      }, 20);
    });

    // Give the helper a beat to (mistakenly) run anything, then assert it didn't.
    await new Promise((r) => setTimeout(r, 200));

    // The command must never have executed: no side effect on disk, no output,
    // and no successful done — only a terminal onError (the cancellation).
    expect(fs.existsSync(marker)).toBe(false);
    expect(output).toHaveLength(0);
    expect(done).toHaveLength(0);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/cancel/i);

    fs.rmSync(marker, { force: true });
  });
});

describe("executeElevatedCommand — TCP transport (Windows client branch)", () => {
  let helper: RunningHelper | undefined;
  let server: TransportServer;

  afterEach(async () => {
    if (helper) await helper.stop();
    helper = undefined;
  });

  // Stand up a real helper on loopback TCP with an OS-assigned port (port 0),
  // then discover the bound port so the client connects the same net.connect
  // branch Windows uses in production.
  async function startTcp(): Promise<ElevatedEndpoint> {
    server = createTransportServer({ transport: "tcp", host: "127.0.0.1", port: 0 });
    helper = await startHelper({
      transport: server,
      executor: createPrivilegedExecutor({ allowUnprivileged: true }),
    });
    const bound = server.__boundAddress();
    if (bound === null) throw new Error("TCP server did not bind a port");
    return { transport: "tcp", host: "127.0.0.1", port: bound.port };
  }

  it("completes a full round-trip over TCP: output 'hi' and done exit 0", async () => {
    const endpoint = await startTcp();
    const { handlers, output, done, errors } = spyHandlers();
    const capability = await mint({
      command: "printf hi",
      requestId: "id1",
      helperInstanceId: helper!.bootId,
    });

    executeElevatedCommand(capability, "id1", handlers, { endpoint });

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out")), 4000);
      const poll = setInterval(() => {
        if (done.length > 0 || errors.length > 0) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve();
        }
      }, 20);
    });

    expect(errors).toHaveLength(0);
    expect(output.length).toBeGreaterThan(0);
    const decoded = output.map((o) => Buffer.from(o.chunk, "base64").toString()).join("");
    expect(decoded).toBe("hi");
    expect(done).toHaveLength(1);
    expect(done[0]!.exitCode).toBe(0);
  });

  it("onBootId fires with the helper's live bootId when hello-ok arrives", async () => {
    const endpoint = await startTcp();
    const { handlers, done, errors } = spyHandlers();
    const observed: string[] = [];
    const capability = await mint({
      command: "printf hi",
      requestId: "id1",
      helperInstanceId: helper!.bootId,
    });

    executeElevatedCommand(capability, "id1", handlers, {
      endpoint,
      onBootId: (bootId) => observed.push(bootId),
    });

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("timed out")), 4000);
      const poll = setInterval(() => {
        if (done.length > 0 || errors.length > 0) {
          clearInterval(poll);
          clearTimeout(timer);
          resolve();
        }
      }, 20);
    });

    expect(errors).toHaveLength(0);
    expect(observed).toEqual([helper!.bootId]);
  });

  it("the handshake probe returns the helper's bootId over TCP", async () => {
    const endpoint = await startTcp();
    expect(await probeHelperHello({ endpoint })).toEqual({ kind: "ok", bootId: helper!.bootId });
  });
});

describe("probeHelperHello", () => {
  let helper: RunningHelper | undefined;
  let socketPath: string;

  afterEach(async () => {
    if (helper) await helper.stop();
    helper = undefined;
    try {
      fs.rmSync(socketPath, { force: true });
    } catch {
      // best-effort
    }
  });


  it("returns the helper's live bootId against a real helper", async () => {
    socketPath = tempSocketPath();
    const endpoint: ElevatedEndpoint = { transport: "unix", path: socketPath };
    helper = await startHelper({
      transport: createTransportServer(endpoint),
      executor: createPrivilegedExecutor({ allowUnprivileged: true }),
    });

    expect(await probeHelperHello({ endpoint })).toEqual({ kind: "ok", bootId: helper.bootId });
  });

  it("refuses when nothing is listening (dead endpoint)", async () => {
    const endpoint: ElevatedEndpoint = { transport: "unix", path: tempSocketPath() };
    expect(await probeHelperHello({ endpoint, timeoutMs: 500 })).toEqual({ kind: "unreachable" });
  });

  it("refuses when there is no endpoint on this platform", async () => {
    expect(await probeHelperHello({ endpoint: null })).toEqual({ kind: "unreachable" });
  });

  it("calls an `error` frame a refusal, not silence — the close behind it must not win", async () => {
    // A helper too old to speak our version answers exactly this and hangs up.
    // Read as `unreachable` it becomes "nothing is there, reboot"; the true
    // remedy is finishing an interrupted upgrade, so the shape must survive.
    const endpoint = await refusingEndpoint("unsupported IPC protocol version 7");
    expect(await probeHelperHello({ endpoint, timeoutMs: 1000 })).toEqual({ kind: "refused" });
  });

  it("never carries the responder's message into the outcome", async () => {
    // The text comes from whatever holds the endpoint and ends up in reports
    // users forward, so the outcome records a shape and nothing else.
    const endpoint = await refusingEndpoint("<script>DO NOT FORWARD ME</script>");
    const outcome = await probeHelperHello({ endpoint, timeoutMs: 1000 });
    expect(outcome).toEqual({ kind: "refused" });
    expect(JSON.stringify(outcome)).not.toContain("DO NOT FORWARD");
  });
});

describe("discoverHelperDetailed — pool scan + bootId conflict detection", () => {
  const helpers: RunningHelper[] = [];

  afterEach(async () => {
    for (const h of helpers.splice(0)) await h.stop();
  });

  // One real helper listening on N loopback TCP ports (the production Windows
  // shape: the helper binds every free pool port). Returns its endpoints.
  async function startPoolHelper(ports: number): Promise<{
    helper: RunningHelper;
    endpoints: ElevatedEndpoint[];
  }> {
    const server = createTransportServer(
      Array.from({ length: ports }, () => ({
        transport: "tcp" as const,
        host: "127.0.0.1",
        port: 0,
      })),
    );
    const helper = await startHelper({
      transport: server,
      executor: createPrivilegedExecutor({ allowUnprivileged: true }),
    });
    helpers.push(helper);
    const endpoints = server.__boundAddresses().map(({ port }) => ({
      transport: "tcp" as const,
      host: "127.0.0.1",
      port,
    }));
    return { helper, endpoints };
  }

  it("returns the shared bootId + the FIRST answering endpoint when all answers agree", async () => {
    const { helper, endpoints } = await startPoolHelper(2);
    const found = await discoverHelperDetailed({ endpoints, attempts: 1 });
    expect(found).toEqual({ ok: true, bootId: helper.bootId, endpoint: endpoints[0] });
  });

  it("skips a dead candidate and pins the answering one", async () => {
    const { helper, endpoints } = await startPoolHelper(1);
    const dead: ElevatedEndpoint = { transport: "tcp", host: "127.0.0.1", port: 1 };
    const found = await discoverHelperDetailed({
      endpoints: [dead, endpoints[0]!],
      attempts: 1,
      timeoutMs: 500,
    });
    expect(found).toEqual({ ok: true, bootId: helper.bootId, endpoint: endpoints[0] });
  });

  it("fails closed when candidates answer with CONFLICTING bootIds", async () => {
    // Two distinct helpers = two distinct per-boot nonces on two pool ports. That
    // is exactly what a squatter-next-to-the-live-helper looks like on the wire —
    // discovery must refuse rather than pick either.
    const a = await startPoolHelper(1);
    const b = await startPoolHelper(1);
    expect(a.helper.bootId).not.toBe(b.helper.bootId);

    const found = await discoverHelperDetailed({
      endpoints: [a.endpoints[0]!, b.endpoints[0]!],
      attempts: 1,
    });
    expect(found).toEqual({ ok: false, cause: "conflict" });
  });

  it("reports a REFUSED candidate as protocol_mismatch, not unreachable", async () => {
    // The consumer side of the probe's `refused`: one skew, two shapes on the
    // wire depending on which side is older, and the same cause — the word the
    // agent puts on the relay as an ELEVATED_UNAVAILABLE_REASON, whose remedy is
    // "finish the upgrade" rather than "nothing is listening, reboot".
    const endpoint = await refusingEndpoint("unsupported IPC protocol version 7");
    const found = await discoverHelperDetailed({ endpoints: [endpoint], attempts: 1, timeoutMs: 1000 });
    expect(found).toEqual({ ok: false, cause: "protocol_mismatch" });
  });

  it("remembers a refusal across a later attempt that sees nothing", async () => {
    const refusing = await refusingEndpoint("unsupported IPC protocol version 7");
    const dead: ElevatedEndpoint = { transport: "unix", path: tempSocketPath() };
    const found = await discoverHelperDetailed({
      endpoints: [refusing, dead],
      attempts: 2,
      retryDelayMs: 0,
      timeoutMs: 1000,
    });
    expect(found).toEqual({ ok: false, cause: "protocol_mismatch" });
  });

  it("refuses when nothing answers on any candidate after every attempt", async () => {
    const found = await discoverHelperDetailed({
      endpoints: [{ transport: "tcp", host: "127.0.0.1", port: 1 }],
      attempts: 2,
      retryDelayMs: 10,
      timeoutMs: 300,
    });
    expect(found).toEqual({ ok: false, cause: "unreachable" });
  });
});
