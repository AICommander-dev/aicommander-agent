import { describe, it, expect, vi, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import fs from "fs";
import os from "os";
import path from "path";
import { runSupervisor } from "../supervisor.js";

// A stand-in for a spawned worker child: an EventEmitter with pid + kill.
interface FakeChild extends EventEmitter {
  pid: number;
  kill: ReturnType<typeof vi.fn>;
}

function makeChild(onKillEmitExit = false): FakeChild {
  const c = new EventEmitter() as FakeChild;
  c.pid = 4242;
  c.kill = vi.fn((sig?: NodeJS.Signals) => {
    if (onKillEmitExit) queueMicrotask(() => c.emit("exit", null, sig ?? "SIGTERM"));
    return true;
  });
  return c;
}

function tmpHeartbeat(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aic-sup-")), "heartbeat");
}

afterEach(() => {
  vi.useRealTimers();
});

describe("supervisor", () => {
  it("respawns the worker after it exits, up to maxSpawns", async () => {
    const children: FakeChild[] = [];
    const spawnWorker = () => {
      const c = makeChild();
      children.push(c);
      return c as never;
    };

    const p = runSupervisor({ heartbeatPath: tmpHeartbeat(), spawnWorker, maxSpawns: 3 });

    // First worker spawned synchronously on start.
    expect(children).toHaveLength(1);

    children[0]!.emit("exit", 1, null);
    await new Promise((r) => setTimeout(r, 5));
    expect(children).toHaveLength(2);

    children[1]!.emit("exit", 1, null);
    await new Promise((r) => setTimeout(r, 5));
    expect(children).toHaveLength(3);

    // Third exit hits maxSpawns → supervisor stops.
    children[2]!.emit("exit", 0, null);
    await p;
    expect(children).toHaveLength(3);
  });

  it("passes AIC_ROLE=worker and the heartbeat path to the worker env", async () => {
    const hb = tmpHeartbeat();
    let seenEnv: NodeJS.ProcessEnv | null = null;
    const spawnWorker = (env: NodeJS.ProcessEnv) => {
      seenEnv = env;
      const c = makeChild();
      // Exit immediately so maxSpawns=1 resolves the supervisor.
      queueMicrotask(() => c.emit("exit", 0, null));
      return c as never;
    };
    await runSupervisor({ heartbeatPath: hb, spawnWorker, maxSpawns: 1 });
    expect(seenEnv).not.toBeNull();
    expect(seenEnv!["AIC_ROLE"]).toBe("worker");
    expect(seenEnv!["AIC_HEARTBEAT"]).toBe(hb);
  });

  it("force-restarts (SIGKILL) the worker when the heartbeat goes stale", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    const hb = tmpHeartbeat();
    // A stamp at t=0; we never advance it → it goes stale as fake time moves.
    fs.writeFileSync(hb, String(Date.now()));

    const children: FakeChild[] = [];
    const spawnWorker = () => {
      const c = makeChild();
      children.push(c);
      return c as never;
    };

    const p = runSupervisor({ heartbeatPath: hb, spawnWorker });

    // Within the post-spawn grace window: no kill yet (no false positive).
    await vi.advanceTimersByTimeAsync(25_000);
    expect(children[0]!.kill).not.toHaveBeenCalled();

    // Past the stall budget: the supervisor SIGKILLs the wedged worker.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(children[0]!.kill).toHaveBeenCalledWith("SIGKILL");

    // Clean up the still-pending supervisor.
    const sigint = process.listeners("SIGINT").at(-1) as () => void;
    sigint();
    children.at(-1)!.emit("exit", null, "SIGINT");
    await p;
  });

  it("does not force-restart a worker whose heartbeat is fresh", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);

    const hb = tmpHeartbeat();
    const children: FakeChild[] = [];
    const spawnWorker = () => {
      const c = makeChild();
      children.push(c);
      return c as never;
    };

    const p = runSupervisor({ heartbeatPath: hb, spawnWorker });

    // Keep stamping a fresh heartbeat as time advances (a busy-but-alive worker).
    for (let i = 0; i < 6; i++) {
      fs.writeFileSync(hb, String(Date.now()));
      await vi.advanceTimersByTimeAsync(10_000);
    }
    expect(children[0]!.kill).not.toHaveBeenCalled();

    const sigint = process.listeners("SIGINT").at(-1) as () => void;
    sigint();
    children.at(-1)!.emit("exit", null, "SIGINT");
    await p;
  });

  it("forwards SIGTERM to the worker and shuts down", async () => {
    const children: FakeChild[] = [];
    const spawnWorker = () => {
      const c = makeChild(true); // kill → emits exit
      children.push(c);
      return c as never;
    };

    const p = runSupervisor({ heartbeatPath: tmpHeartbeat(), spawnWorker });
    const sigterm = process.listeners("SIGTERM").at(-1) as () => void;
    sigterm();
    await p;
    expect(children[0]!.kill).toHaveBeenCalledWith("SIGTERM");
  });
});
