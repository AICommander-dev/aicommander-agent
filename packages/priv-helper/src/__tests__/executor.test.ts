import { describe, it, expect, vi } from "vitest";
import { createPrivilegedExecutor } from "../executor.js";
import type { ExecHandlers } from "../types.js";
import type { ElevatedCapabilityClaims } from "@aicommander/protocol";

function claims(partial: Partial<ElevatedCapabilityClaims> & { command: string }): ElevatedCapabilityClaims {
  return {
    protocolVersion: 1,
    accountId: "a",
    requestId: "r1",
    timeoutMs: 5000,
    issuedAt: 0,
    expiresAt: 0,
    ...partial,
  };
}

interface Collected {
  out: { chunk: string; stream: "stdout" | "stderr" }[];
  done?: { exitCode: number; durationMs: number };
  error?: string;
}

function run(
  exec: ReturnType<typeof createPrivilegedExecutor>,
  c: ElevatedCapabilityClaims,
): { collected: Collected; running: ReturnType<typeof exec.run>; settled: Promise<void> } {
  const collected: Collected = { out: [] };
  let resolveSettled!: () => void;
  const settled = new Promise<void>((res) => { resolveSettled = res; });
  const handlers: ExecHandlers = {
    onOutput(chunk, stream) { collected.out.push({ chunk, stream }); },
    onDone(exitCode, durationMs) { collected.done = { exitCode, durationMs }; resolveSettled(); },
    onError(message) { collected.error = message; resolveSettled(); },
  };
  const running = exec.run(c, handlers);
  return { collected, running, settled };
}

const decode = (out: Collected["out"]) =>
  out.map((o) => Buffer.from(o.chunk, "base64").toString("utf8")).join("");

describe("createPrivilegedExecutor", () => {
  it("streams output and exits 0", async () => {
    const exec = createPrivilegedExecutor({ allowUnprivileged: true });
    const { collected, settled } = run(exec, claims({ command: "printf hi" }));
    await settled;
    expect(decode(collected.out)).toBe("hi");
    expect(collected.done?.exitCode).toBe(0);
    expect(collected.error).toBeUndefined();
  });

  it("reports non-zero exit code", async () => {
    const exec = createPrivilegedExecutor({ allowUnprivileged: true });
    const { collected, settled } = run(exec, claims({ command: "exit 3" }));
    await settled;
    expect(collected.done?.exitCode).toBe(3);
  });

  it("times out and reports an error", async () => {
    const exec = createPrivilegedExecutor({ maxTimeoutMs: 60 * 60_000, allowUnprivileged: true });
    const { collected, settled } = run(exec, claims({ command: "sleep 5", timeoutMs: 1000 }));
    await settled;
    expect(collected.error).toContain("timed out");
    expect(collected.done).toBeUndefined();
  }, 3000);

  it("enforces the output cap", async () => {
    const exec = createPrivilegedExecutor({ maxOutputBytes: 16, allowUnprivileged: true });
    const { collected, settled } = run(exec, claims({ command: "printf abcdefghijklmnopqrstuvwxyz" }));
    await settled;
    expect(collected.error).toContain("output limit");
  });

  it("rejects a relative cwd without spawning", async () => {
    const exec = createPrivilegedExecutor({ allowUnprivileged: true });
    const { collected, settled } = run(exec, claims({ command: "printf hi", cwd: "relative/path" }));
    await settled;
    expect(collected.error).toBe("cwd must be absolute");
    expect(collected.out).toHaveLength(0);
    expect(collected.done).toBeUndefined();
  });

  it("kill() drives the command to a terminal state", async () => {
    const exec = createPrivilegedExecutor({ allowUnprivileged: true });
    const { collected, running, settled } = run(exec, claims({ command: "sleep 5" }));
    running.kill();
    await settled;
    expect(collected.done ?? collected.error).toBeDefined();
  }, 8000);

  it("force-kills a SIGTERM-ignoring child after a timeout", async () => {
    // maxTimeoutMs clamps the effective timeout down to ~300ms so the backstop
    // fires fast. The child traps SIGTERM, so the escalation SIGKILL is what
    // must actually reap it — the terminal onError must NOT cancel that.
    const exec = createPrivilegedExecutor({ maxTimeoutMs: 300, allowUnprivileged: true });
    const { collected, settled } = run(
      exec,
      // Print the (group-leader) pid first so we can watch it disappear.
      claims({ command: "echo $$; trap '' TERM; sleep 10", timeoutMs: 300 }),
    );
    await settled;
    expect(collected.error).toContain("timed out");

    const pid = Number(decode(collected.out).trim());
    expect(Number.isInteger(pid)).toBe(true);

    // Poll until the process group is gone (kill(pid,0) throws ESRCH). The
    // SIGKILL escalation must still fire despite the terminal error above.
    const gone = async (): Promise<boolean> => {
      try {
        process.kill(pid, 0);
        return false;
      } catch {
        return true;
      }
    };
    // The child ignores SIGTERM, so it survives until the SIGKILL escalation
    // (KILL_ESCALATION_MS) fires — which the terminal onError must NOT cancel.
    const deadline = Date.now() + 6500;
    while (Date.now() < deadline && !(await gone())) {
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(await gone()).toBe(true);
  }, 8000);

  it("clears the SIGKILL escalation once the process exits on its own after a timeout", async () => {
    // R3: a TERM-ignoring child hits the timeout (onError fires, SIGTERM sent,
    // SIGKILL escalation armed for KILL_ESCALATION_MS), then exits ON ITS OWN
    // before the escalation would fire. The 'close' handler MUST clear the armed
    // escalation so no SIGKILL is later sent against a (possibly recycled) pgid.
    const killSpy = vi.spyOn(process, "kill");
    try {
      const exec = createPrivilegedExecutor({ maxTimeoutMs: 300, allowUnprivileged: true });
      const { collected, settled } = run(
        // Ignores SIGTERM, but the process exits on its own ~500ms in — long
        // before the 5s escalation, so the escalation must be cancelled by close.
        exec,
        claims({ command: "echo $$; trap '' TERM; sleep 0.5", timeoutMs: 300 }),
      );
      await settled;
      expect(collected.error).toContain("timed out");
      const pid = Number(decode(collected.out).trim());
      expect(Number.isInteger(pid)).toBe(true);

      // Wait past KILL_ESCALATION_MS (5000): if close() failed to clear the timer,
      // a SIGKILL would fire ~5.3s after the timeout. With the fix it never does.
      await new Promise((r) => setTimeout(r, 5400));
      const sigkills = killSpy.mock.calls.filter(([, sig]) => sig === "SIGKILL");
      expect(sigkills).toHaveLength(0);
    } finally {
      killSpy.mockRestore();
    }
  }, 8000);

  it("refuses to run when not actually privileged (fail closed)", async () => {
    // The test process is not root/SYSTEM; the default (allowUnprivileged=false)
    // must refuse rather than run the command unprivileged. On win32 the go/no-go
    // decision is the locale-independent LocalSystem SID (S-1-5-18) via
    // `whoami /user`, not the (localized) display name — but SYSTEM can't be faked
    // in a unit test, so here we assert the non-privileged refusal still holds.
    const exec = createPrivilegedExecutor();
    const { collected, settled } = run(exec, claims({ command: "printf hi" }));
    await settled;
    expect(collected.error).toContain("not running with elevated privileges");
    expect(collected.out).toHaveLength(0);
    expect(collected.done).toBeUndefined();
  });

  it("effectiveIdentity returns a string", () => {
    const exec = createPrivilegedExecutor({ allowUnprivileged: true });
    expect(typeof exec.effectiveIdentity()).toBe("string");
  });
});
