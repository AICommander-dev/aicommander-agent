import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { EventEmitter } from "node:events";

// node:child_process is mocked so the drop path never actually spawns the target;
// the posix privilege-drop syscalls and process.exit are stubbed per-test so we can
// drive the drop without ever dropping this test runner's privileges.
vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}));

import { spawn } from "node:child_process";
import {
  SECURE_EXEC_DROP_SENTINEL,
  buildDropReexec,
  maybeRunSecureExecDrop,
} from "../secure-exec-drop.js";

const LOCKED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

const origArgv1 = process.argv[1];
afterEach(() => {
  process.argv[1] = origArgv1;
});

describe("buildDropReexec", () => {
  it("re-passes the script when launched as `node agent.js …` (npm install)", () => {
    process.argv[1] = "/opt/aic/dist/bin/agent.js";
    const { cmd, args } = buildDropReexec(["999", "999", "aicommander-exec", "wrangler"]);
    expect(cmd).toBe(process.execPath);
    expect(args).toEqual([
      "/opt/aic/dist/bin/agent.js",
      SECURE_EXEC_DROP_SENTINEL,
      "999", "999", "aicommander-exec", "wrangler",
    ]);
  });

  it("re-passes an EXTENSIONLESS script shim (global/npm bin) — not just *.js", () => {
    // The old `.js/.mjs/.cjs` regex would mis-detect this as a SEA and omit the
    // script, breaking the re-exec. We are not a SEA here, so the script is re-passed.
    process.argv[1] = "/usr/local/bin/aicommander-agent";
    const { args } = buildDropReexec(["999", "999", "aicommander-exec", "wrangler"]);
    expect(args).toEqual([
      "/usr/local/bin/aicommander-agent",
      SECURE_EXEC_DROP_SENTINEL,
      "999", "999", "aicommander-exec", "wrangler",
    ]);
  });
});

/**
 * Stub the POSIX privilege-drop syscalls + process.exit on `process`, recording
 * call order, and restore them after. `exit` throws a tagged error so the caller
 * can capture the intended exit code without actually exiting the test runner.
 */
class ExitCalled extends Error {
  constructor(public code: number) {
    super(`exit ${code}`);
  }
}

interface PosixStubs {
  initgroups?: ((user: unknown, group: unknown) => void) | undefined;
  setgid?: (id: unknown) => void;
  setuid?: (id: unknown) => void;
  getuid?: () => number;
  getgid?: () => number;
  getgroups?: () => number[];
}

function installPosix(stubs: PosixStubs, order: string[]) {
  const proc = process as unknown as Record<string, unknown>;
  const saved: Record<string, unknown> = {};
  const keys = ["initgroups", "setgid", "setuid", "getuid", "getgid", "getgroups", "exit"] as const;
  for (const k of keys) saved[k] = proc[k];

  const wrap = (name: keyof PosixStubs, fn?: (...a: unknown[]) => unknown) =>
    fn
      ? (...a: unknown[]) => {
          order.push(name);
          return fn(...a);
        }
      : undefined;

  proc.initgroups = wrap("initgroups", stubs.initgroups as never);
  proc.setgid = wrap("setgid", stubs.setgid as never);
  proc.setuid = wrap("setuid", stubs.setuid as never);
  proc.getuid = stubs.getuid;
  proc.getgid = stubs.getgid;
  proc.getgroups = stubs.getgroups;
  proc.exit = (code?: number) => {
    throw new ExitCalled(code ?? 0);
  };

  // If a stub is explicitly undefined (to simulate a missing syscall) delete it so
  // `typeof process.initgroups !== "function"` is observed by the dropper.
  if (stubs.initgroups === undefined) delete proc.initgroups;
  if (stubs.setgid === undefined) delete proc.setgid;
  if (stubs.setuid === undefined) delete proc.setuid;

  return () => {
    for (const k of keys) {
      if (saved[k] === undefined) delete proc[k];
      else proc[k] = saved[k];
    }
  };
}

describe("maybeRunSecureExecDrop", () => {
  let restore: (() => void) | null = null;
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    restore?.();
    restore = null;
  });

  it("returns false (no-op) for a normal launch without the sentinel", () => {
    expect(maybeRunSecureExecDrop(["node", "agent.js", "run"])).toBe(false);
    expect(maybeRunSecureExecDrop(["node", "agent.js", "status", "--reveal"])).toBe(false);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("ignores the sentinel when it is NOT in the exact re-exec position (FIX 1)", () => {
    // A stray sentinel token deeper in argv (e.g. a status arg) must NOT dispatch
    // the drop parser — only argv[1] (binary) or argv[2] (node+script) count.
    const order: string[] = [];
    restore = installPosix(
      { initgroups: () => {}, setgid: () => {}, setuid: () => {}, getuid: () => 0, getgid: () => 0 },
      order,
    );
    const result = maybeRunSecureExecDrop([
      "node", "agent.js", "status", SECURE_EXEC_DROP_SENTINEL, "999", "999", "u", "wrangler",
    ]);
    expect(result).toBe(false);
    expect(order).toEqual([]);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("is shape-gated: a sentinel at the OTHER index for the launch shape is ignored (FIX 1)", () => {
    // The test runner is `node <script>` (not a SEA), so the sentinel is honoured
    // ONLY at argv[2]. A token at argv[1] (the single-binary position) must NOT
    // dispatch — proving the gate keys off the launch shape, not "either index".
    const order: string[] = [];
    restore = installPosix(
      { initgroups: () => {}, setgid: () => {}, setuid: () => {}, getuid: () => 0, getgid: () => 0 },
      order,
    );
    const result = maybeRunSecureExecDrop([
      "node", SECURE_EXEC_DROP_SENTINEL, "999", "999", "u", "wrangler",
    ]);
    expect(result).toBe(false);
    expect(order).toEqual([]);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("drops privilege in syscall ORDER initgroups→setgid→setuid then spawns with a LOCKED PATH (FIX 1 self-contained)", () => {
    const order: string[] = [];
    const initgroups = vi.fn();
    const setgid = vi.fn();
    const setuid = vi.fn();
    const child = new EventEmitter();
    vi.mocked(spawn).mockReturnValue(child as never);
    restore = installPosix(
      {
        initgroups,
        setgid,
        setuid,
        getuid: () => 999,
        getgid: () => 888,
        getgroups: () => [999],
      },
      order,
    );

    // node + script shape → sentinel at argv[2].
    const result = maybeRunSecureExecDrop([
      "node", "agent.js", SECURE_EXEC_DROP_SENTINEL, "999", "888", "aicommander-exec", "wrangler", "deploy",
    ]);
    expect(result).toBe(true);

    // Order assertion: the whole point of the in-process drop.
    expect(order).toEqual(["initgroups", "setgid", "setuid"]);
    expect(initgroups).toHaveBeenCalledWith("aicommander-exec", 888);
    expect(setgid).toHaveBeenCalledWith(888);
    expect(setuid).toHaveBeenCalledWith(999);

    // Target spawned with no shell and a locked PATH the dropper sets itself.
    expect(spawn).toHaveBeenCalledOnce();
    const [bin, args, opts] = vi.mocked(spawn).mock.calls[0]!;
    expect(bin).toBe("wrangler");
    expect(args).toEqual(["deploy"]);
    expect((opts as { shell?: boolean }).shell).toBe(false);
    expect((opts as { stdio?: string }).stdio).toBe("inherit");
    expect((opts as { env: Record<string, string> }).env.PATH).toBe(LOCKED_PATH);

    // Child exit code propagates.
    expect(() => child.emit("exit", 17, null)).toThrow(ExitCalled);
    try {
      child.emit("exit", 17, null);
    } catch (e) {
      expect((e as ExitCalled).code).toBe(17);
    }
  });

  it("propagates a signal death as 128+signum (FIX 6)", () => {
    const order: string[] = [];
    const child = new EventEmitter();
    vi.mocked(spawn).mockReturnValue(child as never);
    restore = installPosix(
      {
        initgroups: () => {},
        setgid: () => {},
        setuid: () => {},
        getuid: () => 999,
        getgid: () => 999,
        getgroups: () => [999],
      },
      order,
    );
    maybeRunSecureExecDrop([
      "node", "agent.js", SECURE_EXEC_DROP_SENTINEL, "999", "999", "aicommander-exec", "wrangler",
    ]);
    // SIGKILL → 137.
    let captured = -1;
    try {
      child.emit("exit", null, "SIGKILL");
    } catch (e) {
      captured = (e as ExitCalled).code;
    }
    expect(captured).toBe(137);
  });

  it("guards against a double process.exit when error+exit both fire (FIX 7)", () => {
    const order: string[] = [];
    const child = new EventEmitter();
    vi.mocked(spawn).mockReturnValue(child as never);
    restore = installPosix(
      {
        initgroups: () => {},
        setgid: () => {},
        setuid: () => {},
        getuid: () => 999,
        getgid: () => 999,
        getgroups: () => [999],
      },
      order,
    );
    maybeRunSecureExecDrop([
      "node", "agent.js", SECURE_EXEC_DROP_SENTINEL,
      "999", "999", "aicommander-exec", "wrangler",
    ]);
    // First handler exits.
    expect(() => child.emit("error", new Error("boom"))).toThrow(ExitCalled);
    // Second handler is a no-op (settled) — does NOT throw a second exit.
    expect(() => child.emit("exit", 0, null)).not.toThrow();
  });

  it("fails closed (exit 127, NO spawn) on an invalid payload — uid 0 (FIX 9)", () => {
    const order: string[] = [];
    restore = installPosix(
      { initgroups: () => {}, setgid: () => {}, setuid: () => {}, getuid: () => 0, getgid: () => 0 },
      order,
    );
    let code = -1;
    try {
      maybeRunSecureExecDrop(["node", "agent.js", SECURE_EXEC_DROP_SENTINEL, "0", "0", "root", "wrangler"]);
    } catch (e) {
      code = (e as ExitCalled).code;
    }
    expect(code).toBe(127);
    expect(order).toEqual([]); // never even attempted the drop
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed (exit 127, NO spawn) when a syscall is missing — initgroups undefined", () => {
    const order: string[] = [];
    restore = installPosix(
      { initgroups: undefined, setgid: () => {}, setuid: () => {}, getuid: () => 999, getgid: () => 999 },
      order,
    );
    let code = -1;
    try {
      maybeRunSecureExecDrop([
        "node", "agent.js", SECURE_EXEC_DROP_SENTINEL,
        "999", "999", "aicommander-exec", "wrangler",
      ]);
    } catch (e) {
      code = (e as ExitCalled).code;
    }
    expect(code).toBe(127);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed (exit 127, NO spawn) when post-drop groups cannot be read", () => {
    const order: string[] = [];
    restore = installPosix(
      {
        initgroups: () => {},
        setgid: () => {},
        setuid: () => {},
        getuid: () => 999,
        getgid: () => 999,
        getgroups: undefined,
      },
      order,
    );
    let code = -1;
    try {
      maybeRunSecureExecDrop([
        "node", "agent.js", SECURE_EXEC_DROP_SENTINEL,
        "999", "999", "aicommander-exec", "wrangler",
      ]);
    } catch (e) {
      code = (e as ExitCalled).code;
    }
    expect(code).toBe(127);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed (exit 127, NO spawn) when post-drop getgroups still contains 0 (FIX 2)", () => {
    const order: string[] = [];
    restore = installPosix(
      {
        initgroups: () => {},
        setgid: () => {},
        setuid: () => {},
        getuid: () => 999,
        getgid: () => 999,
        getgroups: () => [999, 0], // root supplementary group survived → reject
      },
      order,
    );
    let code = -1;
    try {
      maybeRunSecureExecDrop([
        "node", "agent.js", SECURE_EXEC_DROP_SENTINEL,
        "999", "999", "aicommander-exec", "wrangler",
      ]);
    } catch (e) {
      code = (e as ExitCalled).code;
    }
    expect(code).toBe(127);
    // The syscalls ran, but the verification rejected → target never spawned.
    expect(order).toEqual(["initgroups", "setgid", "setuid"]);
    expect(spawn).not.toHaveBeenCalled();
  });
});
