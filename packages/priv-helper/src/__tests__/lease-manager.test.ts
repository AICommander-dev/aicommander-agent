import { describe, it, expect, vi } from "vitest";
import { LeaseManager } from "../lease-manager.js";
import type { RunningPrivilegedCommand } from "../types.js";

function fakeRunning(): RunningPrivilegedCommand & { kill: ReturnType<typeof vi.fn> } {
  return { kill: vi.fn() };
}

describe("LeaseManager", () => {
  it("kill SIGNALS but keeps the lease; release (onClosed) removes it", () => {
    const lm = new LeaseManager();
    const r = fakeRunning();
    lm.register(1, "a", r);
    lm.kill(1, "a");
    expect(r.kill).toHaveBeenCalledTimes(1);
    // Lease PERSISTS until the process's real close drives release() — so a later
    // hard kill (e.g. shutdown) can still reach a TERM-ignoring child.
    expect(lm.size()).toBe(1);
    // Removal happens only via release (the onClosed hook), not via kill.
    lm.release(1, "a");
    expect(lm.size()).toBe(0);
    // Now absent: kill is a no-op (no double-remove issues).
    lm.kill(1, "a");
    expect(r.kill).toHaveBeenCalledTimes(1);
  });

  it("kill forwards the hard option to the running command", () => {
    const lm = new LeaseManager();
    const r = fakeRunning();
    lm.register(1, "a", r);
    lm.kill(1, "a", { hard: true });
    expect(r.kill).toHaveBeenCalledWith({ hard: true });
  });

  it("releaseAll signals all for a conn and not others; leases persist until release", () => {
    const lm = new LeaseManager();
    const a1 = fakeRunning();
    const a2 = fakeRunning();
    const b1 = fakeRunning();
    lm.register(1, "a", a1);
    lm.register(1, "b", a2);
    lm.register(2, "a", b1);
    lm.releaseAll(1, { hard: true });
    expect(a1.kill).toHaveBeenCalledTimes(1);
    expect(a1.kill).toHaveBeenCalledWith({ hard: true });
    expect(a2.kill).toHaveBeenCalledTimes(1);
    expect(b1.kill).not.toHaveBeenCalled();
    // Signalled but NOT dropped: removal awaits each command's onClosed→release.
    // conn 1 keeps its 2 leases, conn 2 its 1 → all 3 persist.
    expect(lm.size()).toBe(3);
    // conn 2 still live: signalling it works.
    lm.kill(2, "a");
    expect(b1.kill).toHaveBeenCalledTimes(1);
  });

  it("release removes without killing", () => {
    const lm = new LeaseManager();
    const r = fakeRunning();
    lm.register(1, "a", r);
    lm.release(1, "a");
    expect(r.kill).not.toHaveBeenCalled();
    // Now unknown: kill is a no-op.
    lm.kill(1, "a");
    expect(r.kill).not.toHaveBeenCalled();
  });

  it("unknown ids are no-ops", () => {
    const lm = new LeaseManager();
    expect(() => lm.kill(99, "x")).not.toThrow();
    expect(() => lm.release(99, "x")).not.toThrow();
    expect(() => lm.releaseAll(99)).not.toThrow();
  });

  it("a throwing kill in releaseAll does not stop the others", () => {
    const lm = new LeaseManager();
    const bad = { kill: vi.fn(() => { throw new Error("boom"); }) };
    const good = fakeRunning();
    lm.register(1, "a", bad);
    lm.register(1, "b", good);
    expect(() => lm.releaseAll(1)).not.toThrow();
    expect(bad.kill).toHaveBeenCalledTimes(1);
    expect(good.kill).toHaveBeenCalledTimes(1);
  });
});
