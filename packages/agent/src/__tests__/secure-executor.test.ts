import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { EventEmitter } from "node:events";

// secure exec is the long-lived service-token path: it MUST run non-root (via
// an in-process drop that also clears root's supplementary groups), no shell, and
// only bare commands on the token's allowlist. These guards are the whole
// security boundary, so we lock each one. node:child_process and node:fs are
// mocked so nothing spawns or touches the real system.
vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}));
vi.mock("node:fs", () => ({
  readFileSync: vi.fn(),
}));

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { executeSecureCommand } from "../secure-executor.js";
import {
  SECURE_EXEC_DENIED_COMMANDS,
  SECURE_EXEC_MAX_INPUT_BYTES,
  SECURE_EXEC_PRIVILEGED_GROUPS,
} from "@aicommander/protocol";
import { SECURE_EXEC_DROP_SENTINEL } from "../secure-exec-drop.js";

const noopHandlers = { onOutput: vi.fn(), onDone: vi.fn(), onError: vi.fn() };
const SAFE_PASSWD =
  "root:x:0:0::/root:/bin/bash\n" +
  "aicommander-exec:x:999:999::/home/aicommander-exec:/usr/sbin/nologin\n";
const SAFE_GROUP =
  "root:x:0:\n" +
  "aicommander-exec:x:999:\n";

function mockIdentityFiles(passwd: string, group: string): void {
  vi.mocked(readFileSync).mockImplementation(((path: string) => {
    if (path === "/etc/passwd") return passwd;
    if (path === "/etc/group") return group;
    throw new Error("unexpected file");
  }) as never);
}

/** A fake child process exposing the streams secure-executor wires up. */
function fakeProc(): EventEmitter & { pid: number; stdout: EventEmitter; stderr: EventEmitter; stdin: { on: () => void; end: () => void } } {
  const proc = new EventEmitter() as never;
  // @ts-expect-error test shim
  proc.pid = 4242;
  // @ts-expect-error test shim
  proc.stdout = new EventEmitter();
  // @ts-expect-error test shim
  proc.stderr = new EventEmitter();
  // @ts-expect-error test shim
  proc.stdin = { on: vi.fn(), end: vi.fn() };
  return proc;
}

let platformSpy: { mockRestore: () => void };
const origGetuid = process.getuid;

beforeEach(() => {
  vi.clearAllMocks();
  platformSpy = vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  process.getuid = () => 0;
  // Default: local identity files resolve a non-root user with only its safe
  // private primary group.
  mockIdentityFiles(SAFE_PASSWD, SAFE_GROUP);
  vi.mocked(spawn).mockReturnValue(fakeProc() as never);
});

afterEach(() => {
  platformSpy.mockRestore();
  process.getuid = origGetuid;
});

describe("executeSecureCommand — pre-flight guards (fail closed)", () => {
  it("rejects non-Linux platforms", () => {
    platformSpy.mockRestore();
    vi.spyOn(process, "platform", "get").mockReturnValue("darwin");
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/Linux/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("refuses to run when the agent is not root (cannot drop privilege)", () => {
    process.getuid = () => 1000;
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/root/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed when the runtime cannot determine its uid", () => {
    delete (process as unknown as Record<string, unknown>).getuid;
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/requires the agent to run as root/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects an empty argv", () => {
    expect(() =>
      executeSecureCommand({ argv: [], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/non-empty argv/);
  });

  it("rejects a command outside the token allowlist", () => {
    expect(() =>
      executeSecureCommand({ argv: ["rm", "-rf", "/"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/allowlist/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it.each(SECURE_EXEC_DENIED_COMMANDS)(
    "rejects denied command %s even when a hostile relay allowlists it",
    (command) => {
      expect(() =>
        executeSecureCommand(
          { argv: [command], allowedCommands: [command] },
          noopHandlers,
        ),
      ).toThrow(/denied for secure exec/);
      expect(spawn).not.toHaveBeenCalled();
    },
  );

  it.each(["python3.13", "perl5.40.0", "ruby3.4", "php8.4", "lua5.4"])(
    "rejects version-suffixed runtime %s before spawn",
    (command) => {
      expect(() =>
        executeSecureCommand(
          { argv: [command], allowedCommands: [command] },
          noopHandlers,
        ),
      ).toThrow(/denied for secure exec/);
      expect(spawn).not.toHaveBeenCalled();
    },
  );

  it("rejects argv[0] that contains a path separator (must be a bare name)", () => {
    expect(() =>
      executeSecureCommand(
        { argv: ["/usr/local/bin/wrangler", "deploy"], allowedCommands: ["wrangler"] },
        noopHandlers,
      ),
    ).toThrow(/bare command name/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed when the sandbox user is absent from /etc/passwd", () => {
    vi.mocked(readFileSync).mockReturnValue("root:x:0:0::/root:/bin/bash\n" as never);
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/not found in \/etc\/passwd/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("does not match a different user that merely shares a name prefix", () => {
    // The `:` anchor must prevent `aicommander-exec-evil` from being picked for
    // `aicommander-exec` — otherwise a lookalike account could capture the drop.
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec-evil:x:999:999::/home/evil:/bin/sh\n" as never,
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/not found in \/etc\/passwd/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects a relative cwd", () => {
    expect(() =>
      executeSecureCommand(
        { argv: ["wrangler"], allowedCommands: ["wrangler"], cwd: "relative/dir" },
        noopHandlers,
      ),
    ).toThrow(/absolute path/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects an oversized stdin payload", () => {
    const tooBig = Buffer.alloc(SECURE_EXEC_MAX_INPUT_BYTES + 1).toString("base64");
    expect(() =>
      executeSecureCommand(
        { argv: ["wrangler"], allowedCommands: ["wrangler"], input: tooBig },
        noopHandlers,
      ),
    ).toThrow(/exceeds limit/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("refuses if /etc/passwd resolves the sandbox user to uid 0", () => {
    // Correct name, but a record that maps it to uid 0 — must still fail closed.
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec:x:0:0::/root:/bin/bash\n" as never,
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/uid 0/);
  });

  it("refuses if /etc/passwd resolves the sandbox user to gid 0 (FIX 4)", () => {
    // Non-root uid, but gid 0 — a root-group sandbox user must fail closed at the
    // primary resolution boundary, not just downstream in the dropper.
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec:x:999:0::/home/aicommander-exec:/usr/sbin/nologin\n" as never,
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/gid 0/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects a malformed passwd line — too few fields (FIX 5)", () => {
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec:x:999:999:/home/aicommander-exec\n" as never, // 5 fields
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/malformed passwd entry/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects a malformed passwd line — too many fields (FIX 5)", () => {
    // An 8-field line (e.g. a stray trailing colon/field) must fail closed too —
    // exactly 7 fields are required, not ">= 7".
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec:x:999:999::/home/aicommander-exec:/usr/sbin/nologin:extra\n" as never,
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/malformed passwd entry/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects a non-decimal uid field (FIX 5)", () => {
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec:x:0x10:999::/home/aicommander-exec:/usr/sbin/nologin\n" as never,
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/could not resolve uid\/gid/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("refuses two matching passwd entries — poisoned/duplicate (FIX 5)", () => {
    vi.mocked(readFileSync).mockReturnValue(
      "aicommander-exec:x:999:999::/home/aicommander-exec:/usr/sbin/nologin\n" +
        "aicommander-exec:x:0:0::/root:/bin/bash\n" as never,
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/multiple \/etc\/passwd entries/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("rejects a privileged primary group before spawn", () => {
    mockIdentityFiles(
      "aicommander-exec:x:999:27::/home/aicommander-exec:/usr/sbin/nologin\n",
      "root:x:0:\nsudo:x:27:\n",
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/privileged group "sudo"/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it.each(SECURE_EXEC_PRIVILEGED_GROUPS)(
    "rejects supplementary privileged group %s before spawn",
    (group) => {
      const gid = group === "root" ? 0 : 800;
      mockIdentityFiles(
        SAFE_PASSWD,
        `aicommander-exec:x:999:\n${group}:x:${gid}:aicommander-exec\n`,
      );
      expect(() =>
        executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
      ).toThrow(/privileged group/);
      expect(spawn).not.toHaveBeenCalled();
    },
  );

  it("rejects supplementary gid 0 even when the group has an unprivileged name", () => {
    mockIdentityFiles(
      SAFE_PASSWD,
      "aicommander-exec:x:999:\nzero:x:0:aicommander-exec\n",
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/privileged group "zero".*gid 0/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed on a malformed /etc/group entry", () => {
    mockIdentityFiles(
      SAFE_PASSWD,
      "aicommander-exec:x:999:\ndocker:x:not-a-gid:aicommander-exec\n",
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/invalid numeric id in \/etc\/group/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed on duplicate /etc/group entries", () => {
    mockIdentityFiles(
      SAFE_PASSWD,
      "aicommander-exec:x:999:\nusers:x:1000:\nusers:x:1001:\n",
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/duplicate \/etc\/group/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed on duplicate /etc/group gids", () => {
    mockIdentityFiles(
      SAFE_PASSWD,
      "aicommander-exec:x:999:\nusers:x:1000:\noperators:x:1000:\n",
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/duplicate \/etc\/group/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed on duplicate members in a /etc/group entry", () => {
    mockIdentityFiles(
      SAFE_PASSWD,
      "aicommander-exec:x:999:\nusers:x:1000:aicommander-exec,aicommander-exec\n",
    );
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/malformed \/etc\/group member list/);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("fails closed when /etc/group cannot be read", () => {
    vi.mocked(readFileSync).mockImplementation(((path: string) => {
      if (path === "/etc/passwd") return SAFE_PASSWD;
      throw new Error("denied");
    }) as never);
    expect(() =>
      executeSecureCommand({ argv: ["wrangler"], allowedCommands: ["wrangler"] }, noopHandlers),
    ).toThrow(/cannot read \/etc\/group/);
    expect(spawn).not.toHaveBeenCalled();
  });
});

describe("executeSecureCommand — spawn shape (the security contract)", () => {
  it("spawns a self-reexec drop (NO shell), not the target directly, with no uid/gid on spawn", () => {
    executeSecureCommand(
      { argv: ["wrangler", "deploy", "&&", "rm -rf /"], allowedCommands: ["wrangler"] },
      noopHandlers,
    );
    expect(spawn).toHaveBeenCalledOnce();
    const [cmd, args, opts] = vi.mocked(spawn).mock.calls[0]!;
    // Re-exec THIS runtime; the drop sub-command does the uid/gid + supplementary
    // group transition in-process before exec'ing the target (no external setpriv).
    expect(cmd).toBe(process.execPath);
    const si = (args as string[]).indexOf(SECURE_EXEC_DROP_SENTINEL);
    expect(si).toBeGreaterThanOrEqual(0);
    // Sentinel payload: uid gid username bin …args. `&&` and `rm -rf /` are inert
    // literal argv — never shell-interpreted.
    expect((args as string[]).slice(si + 1)).toEqual([
      "999", "999", "aicommander-exec", "wrangler", "deploy", "&&", "rm -rf /",
    ]);
    expect((opts as { shell?: boolean }).shell).toBe(false);
    // uid/gid are NOT passed to spawn() — the in-process drop does the transition.
    expect((opts as { uid?: number }).uid).toBeUndefined();
    expect((opts as { gid?: number }).gid).toBeUndefined();
  });

  it("strips PATH and LD_PRELOAD from relay env but keeps benign vars + locked PATH", () => {
    executeSecureCommand(
      {
        argv: ["wrangler"],
        allowedCommands: ["wrangler"],
        env: {
          PATH: "/tmp/evil",
          LD_PRELOAD: "/tmp/evil.so",
          NODE_OPTIONS: "--require /tmp/x",
          CLAUDE_CONFIG_DIR: "/home/aicommander-exec/.claude",
        },
      },
      noopHandlers,
    );
    const [, , opts] = vi.mocked(spawn).mock.calls[0]!;
    const env = (opts as { env: Record<string, string> }).env;
    // Protected PATH wins (locked), the relay's /tmp/evil never reaches the child.
    expect(env.PATH).toBe("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    expect(env.LD_PRELOAD).toBeUndefined();
    expect(env.NODE_OPTIONS).toBeUndefined();
    // Benign caller var survives.
    expect(env.CLAUDE_CONFIG_DIR).toBe("/home/aicommander-exec/.claude");
    // HOME/USER are forced from the resolved sandbox user.
    expect(env.HOME).toBe("/home/aicommander-exec");
    expect(env.USER).toBe("aicommander-exec");
  });

  it("feeds base64 input to the child's stdin", () => {
    const proc = fakeProc();
    vi.mocked(spawn).mockReturnValue(proc as never);
    executeSecureCommand(
      {
        argv: ["wrangler"],
        allowedCommands: ["wrangler"],
        input: Buffer.from("hello").toString("base64"),
      },
      noopHandlers,
    );
    expect(proc.stdin.end).toHaveBeenCalledWith(Buffer.from("hello"));
  });
});
