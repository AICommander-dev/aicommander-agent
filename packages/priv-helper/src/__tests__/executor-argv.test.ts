// Regression tests for the win32 launcher boundary + locked PATH. These mock
// spawn (the real launcher is covered by the Windows runtime suite) and inspect
// the exact process options, private stdin frame, and handshake/output relay.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

const spawnMock = vi.fn();
const execFileSyncMock = vi.fn();

vi.mock("../windows-exec-launcher.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../windows-exec-launcher.js")>();
  return {
    ...actual,
    resolvePrivilegedWindowsLauncher: () =>
      "C:\\Program Files\\AI Commander Privileged Helper\\aicommander-win-exec-x64.exe",
  };
});

vi.mock("node:child_process", () => ({
  spawn: (...a: unknown[]) => spawnMock(...a),
  execFileSync: (...a: unknown[]) => execFileSyncMock(...a),
}));

const { createPrivilegedExecutor } = await import("../executor.js");
const { encodeWindowsLauncherResponseForTest } = await import("../windows-exec-launcher.js");
import type { ExecHandlers } from "../types.js";
import type { ElevatedCapabilityClaims } from "@aicommander/protocol";

function fakeChild() {
  const proc = new EventEmitter() as EventEmitter & {
    pid: number;
    stdout: EventEmitter;
    stderr: EventEmitter;
    stdin: EventEmitter & { end: ReturnType<typeof vi.fn> };
  };
  proc.pid = 4242;
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.stdin = Object.assign(new EventEmitter(), { end: vi.fn() });
  return proc;
}

function claims(command: string): ElevatedCapabilityClaims {
  return {
    protocolVersion: 1,
    accountId: "a",
    requestId: "r1",
    timeoutMs: 5000,
    issuedAt: 0,
    expiresAt: 0,
    command,
  };
}

const handlers: ExecHandlers = {
  onOutput() {},
  onDone() {},
  onError() {},
};

const originalPlatform = process.platform;
function setPlatform(p: NodeJS.Platform) {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

beforeEach(() => {
  spawnMock.mockReset();
  spawnMock.mockImplementation(() => fakeChild());
  execFileSyncMock.mockReset();
  execFileSyncMock.mockReturnValue("");
});

afterEach(() => {
  setPlatform(originalPlatform);
  vi.unstubAllEnvs();
});

const lastSpawn = () => {
  const call = spawnMock.mock.calls[0] as [string, string[], Record<string, unknown>];
  return { cmd: call[0], args: call[1], opts: call[2] };
};

describe("win32 shell invocation", () => {
  it("passes the command only in the launcher's bounded UTF-16LE stdin frame", () => {
    setPlatform("win32");
    const command = 'dir "C:\\Program Files\\X"';
    createPrivilegedExecutor({ allowUnprivileged: true }).run(claims(command), handlers);

    const { cmd, args, opts } = lastSpawn();
    expect(cmd).toMatch(/aicommander-win-exec-x64\.exe$/);
    expect(args).toEqual([]);
    expect(opts["stdio"]).toEqual(["pipe", "pipe", "pipe"]);
    expect(opts["windowsHide"]).toBe(true);
    expect(opts["windowsVerbatimArguments"]).toBeUndefined();
    expect(opts["shell"]).toBe(false);

    const child = spawnMock.mock.results[0]!.value as ReturnType<typeof fakeChild>;
    expect(child.stdin.end).toHaveBeenCalledOnce();
    const frame = child.stdin.end.mock.calls[0]![0] as Buffer;
    expect(frame.subarray(0, 8).toString("ascii")).toBe("AICEXE01");
    expect(frame.subarray(16).toString("utf16le")).toBe(command);
    expect(JSON.stringify(opts)).not.toContain(command);
  });

  it("locks PATH to System32/Windows/Wbem/WindowsPowerShell v1.0", () => {
    setPlatform("win32");
    createPrivilegedExecutor({ allowUnprivileged: true }).run(claims("whoami"), handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    const entries = env["PATH"]!.split(";");
    expect(entries).toHaveLength(4);
    // Last, not first: the locked PATH must not become a substitution vector.
    expect(entries[3]).toMatch(/System32\\WindowsPowerShell\\v1\.0$/);
    expect(entries[0]).toMatch(/System32$/);
    expect(env["PYTHONUTF8"]).toBe("1");
    expect(env["PYTHONIOENCODING"]).toBe("utf-8");
  });

  it("carries ProgramData and its ALLUSERSPROFILE alias from the helper's own env", () => {
    setPlatform("win32");
    vi.stubEnv("ProgramData", "D:\\ProgramData");
    createPrivilegedExecutor({ allowUnprivileged: true }).run(claims("whoami"), handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    expect(env["ProgramData"]).toBe("D:\\ProgramData");
    // Aliases must agree — scripts read one or the other.
    expect(env["ALLUSERSPROFILE"]).toBe(env["ProgramData"]);
  });

  it("falls back to %SystemDrive%\\ProgramData when the helper's env lacks it", () => {
    setPlatform("win32");
    vi.stubEnv("ProgramData", undefined);
    vi.stubEnv("SystemDrive", "E:");
    createPrivilegedExecutor({ allowUnprivileged: true }).run(claims("whoami"), handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    expect(env["ProgramData"]).toBe("E:\\ProgramData");
    expect(env["ALLUSERSPROFILE"]).toBe("E:\\ProgramData");
  });

  it("falls back to C:\\ProgramData when SystemDrive is absent too", () => {
    setPlatform("win32");
    vi.stubEnv("ProgramData", undefined);
    vi.stubEnv("SystemDrive", undefined);
    createPrivilegedExecutor({ allowUnprivileged: true }).run(claims("whoami"), handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    expect(env["ProgramData"]).toBe("C:\\ProgramData");
    expect(env["ALLUSERSPROFILE"]).toBe("C:\\ProgramData");
  });

  it("keeps PATH and SystemRoot locked while ProgramData comes along", () => {
    setPlatform("win32");
    vi.stubEnv("SystemRoot", "C:\\Windows");
    const commandClaims = claims("whoami");
    // A caller cannot shadow the locked keys, ProgramData or not.
    commandClaims.env = { PATH: "C:\\evil", SystemRoot: "C:\\evil", ProgramData: "C:\\evil" };
    createPrivilegedExecutor({ allowUnprivileged: true }).run(commandClaims, handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    expect(env["PATH"]!.split(";")).toHaveLength(4);
    expect(env["PATH"]).not.toContain("evil");
    expect(env["SystemRoot"]).toBe("C:\\Windows");
    expect(env["windir"]).toBe("C:\\Windows");
    expect(env["ProgramData"]).not.toBe("C:\\evil");
  });

  it("strips every caller casing of a locked base key from the child block", () => {
    setPlatform("win32");
    vi.stubEnv("SystemRoot", "C:\\Windows");
    vi.stubEnv("ProgramData", "C:\\ProgramData");
    const commandClaims = claims("whoami");
    // The overlay is a case-SENSITIVE merge but Windows resolves env names
    // case-INSENSITIVELY — a surviving alternate spelling would let the platform
    // pick the winner, so none may reach the child at all.
    commandClaims.env = {
      PROGRAMDATA: "C:\\evil",
      programdata: "C:\\evil",
      ProgramData: "C:\\evil",
      AllUsersProfile: "C:\\evil",
      allusersprofile: "C:\\evil",
      systemroot: "C:\\evil",
      Path: "C:\\evil",
      WinDir: "C:\\evil",
    };
    createPrivilegedExecutor({ allowUnprivileged: true }).run(commandClaims, handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    expect(Object.values(env)).not.toContain("C:\\evil");
    const locked = new Set(["PROGRAMDATA", "ALLUSERSPROFILE", "SYSTEMROOT", "WINDIR", "PATH"]);
    for (const key of Object.keys(env)) {
      if (!locked.has(key.toUpperCase())) continue;
      // Exactly one spelling per locked name survives: the base's own.
      expect(["ProgramData", "ALLUSERSPROFILE", "SystemRoot", "windir", "PATH"]).toContain(key);
    }
    expect(env["ProgramData"]).toBe("C:\\ProgramData");
    expect(env["ALLUSERSPROFILE"]).toBe("C:\\ProgramData");
    expect(env["SystemRoot"]).toBe("C:\\Windows");
  });

  it("still strips the danger keys the locked base never sets", () => {
    setPlatform("win32");
    const commandClaims = claims("whoami");
    commandClaims.env = {
      NODE_OPTIONS: "--require=C:\\evil.js",
      node_options: "--require=C:\\evil.js",
      PYTHONPATH: "C:\\evil",
      PYTHONSTARTUP: "C:\\evil.py",
      COMSPEC: "C:\\evil.exe",
      BASH_ENV: "C:\\evil.sh",
      GIT_EXTERNAL_DIFF: "C:\\evil.exe",
      // Locked only on the OTHER platform — must stay stripped here too.
      HOME: "C:\\evil",
      USER: "evil",
      LD_PRELOAD: "C:\\evil",
      DYLD_INSERT_LIBRARIES: "C:\\evil",
      KEPT: "fine",
    };
    createPrivilegedExecutor({ allowUnprivileged: true }).run(commandClaims, handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    for (const key of [
      "NODE_OPTIONS", "node_options", "PYTHONPATH", "PYTHONSTARTUP", "COMSPEC",
      "BASH_ENV", "GIT_EXTERNAL_DIFF", "HOME", "USER", "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
    ]) {
      expect(env[key]).toBeUndefined();
    }
    expect(env["KEPT"]).toBe("fine");
  });

  it("preserves signed, case-insensitive Python UTF-8 overrides", () => {
    setPlatform("win32");
    const commandClaims = claims("python -c pass");
    commandClaims.env = { pythonutf8: "0", PythonIoEncoding: "utf-8:strict" };
    createPrivilegedExecutor({ allowUnprivileged: true }).run(commandClaims, handlers);

    const env = lastSpawn().opts["env"] as Record<string, string>;
    expect(env["pythonutf8"]).toBe("0");
    expect(env["PythonIoEncoding"]).toBe("utf-8:strict");
    expect(env["PYTHONUTF8"]).toBeUndefined();
    expect(env["PYTHONIOENCODING"]).toBeUndefined();
  });

  it("strips a fragmented READY frame and then relays exact buffered bytes", () => {
    setPlatform("win32");
    const outputs: Array<{ bytes: Buffer; stream: "stdout" | "stderr" }> = [];
    const executor = createPrivilegedExecutor({ allowUnprivileged: true });
    executor.run(claims("echo ok"), {
      onOutput(data, stream) { outputs.push({ bytes: Buffer.from(data, "base64"), stream }); },
      onDone() {},
      onError() {},
    });
    const child = spawnMock.mock.results[0]!.value as ReturnType<typeof fakeChild>;
    const ready = encodeWindowsLauncherResponseForTest(
      "ready", "", Buffer.from([0x7a, 0x61, 0xc5, 0xbc]),
    );

    child.stderr.emit("data", Buffer.from([0xff, 0x00]));
    child.stdout.emit("data", ready.subarray(0, 9));
    expect(outputs).toEqual([]);
    child.stdout.emit("data", ready.subarray(9));
    child.stdout.emit("data", Buffer.from([0xe6, 0xbc, 0xa2]));

    expect(outputs).toEqual([
      { bytes: Buffer.from([0xff, 0x00]), stream: "stderr" },
      { bytes: Buffer.from([0x7a, 0x61, 0xc5, 0xbc]), stream: "stdout" },
      { bytes: Buffer.from([0xe6, 0xbc, 0xa2]), stream: "stdout" },
    ]);
  });
});

describe("posix shell invocation", () => {
  for (const platform of ["darwin", "linux"] as const) {
    it(`${platform}: /bin/sh -c with an unquoted command and no verbatim argv`, () => {
      setPlatform(platform);
      const command = 'ls "/tmp/a b"';
      createPrivilegedExecutor({ allowUnprivileged: true }).run(claims(command), handlers);

      const { cmd, args, opts } = lastSpawn();
      expect(cmd).toBe("/bin/sh");
      expect(args).toEqual(["-c", command]);
      expect(opts["windowsVerbatimArguments"]).toBeFalsy();

      const env = lastSpawn().opts["env"] as Record<string, string>;
      expect(env["PATH"]).toBe("/usr/sbin:/usr/bin:/sbin:/bin");
    });

    it(`${platform}: no caller casing of a locked base key reaches the child`, () => {
      setPlatform(platform);
      const commandClaims = claims("id");
      commandClaims.env = {
        Path: "/evil", path: "/evil", home: "/evil", Logname: "evil", user: "evil",
      };
      createPrivilegedExecutor({ allowUnprivileged: true }).run(commandClaims, handlers);

      const env = lastSpawn().opts["env"] as Record<string, string>;
      expect(Object.values(env)).not.toContain("/evil");
      expect(env["PATH"]).toBe("/usr/sbin:/usr/bin:/sbin:/bin");
      expect(env["HOME"]).toBe("/var/root");
      expect(env["USER"]).toBe("root");
      expect(env["LOGNAME"]).toBe("root");
    });
  }
});
