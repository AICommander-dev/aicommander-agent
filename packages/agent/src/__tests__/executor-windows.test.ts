import { EventEmitter } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

import { spawn } from "node:child_process";
import { KILL_ESCALATION_MS } from "@aicommander/protocol";
import { executeCommand } from "../executor.js";
import { encodeWindowsLauncherResponseForTest } from "../windows-exec-launcher.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
const originalArch = Object.getOwnPropertyDescriptor(process, "arch");
const originalPythonUtf8 = process.env["PYTHONUTF8"];

/**
 * A child pipe as the executor touches it. `destroy` is watched because it must
 * NEVER be called on a post-exit pipe — that closes the last reader and EPIPEs a
 * surviving daemon — while `resume`/`unref` are how we detach from one instead.
 */
type FakeStream = EventEmitter & {
  destroy: ReturnType<typeof vi.fn>;
  resume: ReturnType<typeof vi.fn>;
  unref: ReturnType<typeof vi.fn>;
};

function fakeStream(): FakeStream {
  return Object.assign(new EventEmitter(), {
    destroy: vi.fn(),
    resume: vi.fn(),
    unref: vi.fn(),
  });
}

function fakeChild(): EventEmitter & {
  stdin: EventEmitter & { end: ReturnType<typeof vi.fn> };
  stdout: FakeStream;
  stderr: FakeStream;
  pid?: number;
} {
  return Object.assign(new EventEmitter(), {
    stdin: Object.assign(new EventEmitter(), { end: vi.fn() }),
    stdout: fakeStream(),
    stderr: fakeStream(),
    pid: 1234,
  });
}

function setPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

beforeEach(() => {
  Object.defineProperty(process, "arch", { value: "x64", configurable: true });
  vi.mocked(spawn).mockReset();
  vi.mocked(spawn).mockReturnValue(fakeChild() as never);
});

afterEach(() => {
  vi.useRealTimers();
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  if (originalArch) Object.defineProperty(process, "arch", originalArch);
  if (originalPythonUtf8 === undefined) delete process.env["PYTHONUTF8"];
  else process.env["PYTHONUTF8"] = originalPythonUtf8;
});

describe("executeCommand Windows native launcher", () => {
  it("uses the unprivileged launcher without putting the command in argv/env", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);

    // A real directory: an explicit cwd is validated before the spawn, and this
    // suite runs on the CI host's filesystem, not on Windows.
    executeCommand("echo %USERNAME% | findstr .", process.cwd(), undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    }, { windowsExecLauncherPath: process.execPath });

    const [program, args, options] = vi.mocked(spawn).mock.calls[0]!;
    expect(program).toBe(process.execPath);
    expect(args).toEqual([]);
    expect(options).toMatchObject({
      shell: false,
      cwd: process.cwd(),
      detached: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    expect(JSON.stringify(options?.env)).not.toContain("echo %USERNAME%");
    const request = child.stdin.end.mock.calls[0]![0] as Buffer;
    expect(request.subarray(0, 8).toString("ascii")).toBe("AICEXE01");
    expect(request.subarray(16).toString("utf16le")).toBe("echo %USERNAME% | findstr .");
    expect(options?.env).toMatchObject({ PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" });
  });

  // Past the ready handshake every path in settle() ends in onDone, so a number
  // there reads as a finished command. The launcher signals a console stage that
  // vanished without reporting the shell's code with BOTH a sentinel status and a
  // marker-led stderr notice — an outcome nobody knows must not arrive dressed as
  // a result.
  const UNKNOWN_OUTCOME_NOTICE =
    "aicommander-launcher-unknown-outcome: the Windows command launcher's console " +
    "stage exited unexpectedly (exit 3221225477). The command's outcome is unknown " +
    "and it may still be running.\r\n";

  it("reports the launcher's unknown-outcome signal as an error, not an exit code", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = { onOutput: vi.fn(), onDone: vi.fn(), onError: vi.fn() };

    executeCommand("echo hi", undefined, undefined, h, {
      windowsExecLauncherPath: process.execPath,
    });
    child.stdout.emit("data", encodeWindowsLauncherResponseForTest("ready", "", Buffer.from("hi")));
    child.stderr.emit("data", Buffer.from(UNKNOWN_OUTCOME_NOTICE, "utf8"));
    child.emit("exit", 0xa1c0ffff);
    child.emit("close", 0xa1c0ffff);

    expect(h.onDone).not.toHaveBeenCalled();
    expect(h.onError).toHaveBeenCalledTimes(1);
    const message = String(h.onError.mock.calls[0]![0]);
    expect(message).toMatch(/outcome is UNKNOWN/);
    expect(message).toMatch(/do not\s+treat this as a completed run|do not treat this as a completed run/);
  });

  // The marker may be split anywhere by the pipe; the scanner carries a tail
  // across chunks precisely so a torn notice is still recognised.
  it("recognises the unknown-outcome marker split across stderr chunks", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = { onOutput: vi.fn(), onDone: vi.fn(), onError: vi.fn() };

    executeCommand("echo hi", undefined, undefined, h, {
      windowsExecLauncherPath: process.execPath,
    });
    child.stdout.emit("data", encodeWindowsLauncherResponseForTest("ready", "", Buffer.from("")));
    const notice = Buffer.from(UNKNOWN_OUTCOME_NOTICE, "utf8");
    child.stderr.emit("data", notice.subarray(0, 9));
    child.stderr.emit("data", notice.subarray(9, 20));
    child.stderr.emit("data", notice.subarray(20));
    child.emit("exit", 0xa1c0ffff);
    child.emit("close", 0xa1c0ffff);

    expect(h.onDone).not.toHaveBeenCalled();
    expect(h.onError).toHaveBeenCalledTimes(1);
    expect(String(h.onError.mock.calls[0]![0])).toMatch(/outcome is UNKNOWN/);
  });

  // The sentinel is a LEGAL Windows exit status. Without the launcher's marker it
  // is somebody's real result, and reporting it as an unknown outcome would be
  // the same lie in the other direction.
  it("treats the sentinel value alone as a real exit code", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = { onOutput: vi.fn(), onDone: vi.fn(), onError: vi.fn() };

    executeCommand("exit /b -1581187073", undefined, undefined, h, {
      windowsExecLauncherPath: process.execPath,
    });
    child.stdout.emit("data", encodeWindowsLauncherResponseForTest("ready", "", Buffer.from("")));
    child.stderr.emit("data", Buffer.from("done\r\n", "utf8"));
    child.emit("exit", 0xa1c0ffff);
    child.emit("close", 0xa1c0ffff);

    expect(h.onError).not.toHaveBeenCalled();
    expect(h.onDone).toHaveBeenCalledWith(0xa1c0ffff, expect.any(Number));
  });

  it("still reports an ordinary exit code as a result", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = { onOutput: vi.fn(), onDone: vi.fn(), onError: vi.fn() };

    executeCommand("exit /b 3", undefined, undefined, h, {
      windowsExecLauncherPath: process.execPath,
    });
    child.stdout.emit("data", encodeWindowsLauncherResponseForTest("ready", "", Buffer.from("")));
    child.emit("exit", 3);
    child.emit("close", 3);

    expect(h.onError).not.toHaveBeenCalled();
    expect(h.onDone).toHaveBeenCalledWith(3, expect.any(Number));
  });

  it("removes a fragmented handshake and streams trailing stdout separately from stderr", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const output: Array<[string, string]> = [];

    executeCommand("echo hello", undefined, undefined, {
      onOutput: (chunk, stream) => output.push([stream, Buffer.from(chunk, "base64").toString()]),
      onDone: () => {}, onError: () => {},
    }, { windowsExecLauncherPath: process.execPath });

    child.stderr.emit("data", Buffer.from("early-error"));
    const response = encodeWindowsLauncherResponseForTest("ready", "", Buffer.from("hello"));
    child.stdout.emit("data", response.subarray(0, 7));
    child.stdout.emit("data", response.subarray(7));
    child.stderr.emit("data", Buffer.from("later-error"));
    expect(output).toEqual([
      ["stderr", "early-error"],
      ["stdout", "hello"],
      ["stderr", "later-error"],
    ]);
  });

  it.each([
    ["an explicit launcher error", (child: ReturnType<typeof fakeChild>) => {
      child.stdout.emit("data", encodeWindowsLauncherResponseForTest("error", "native setup failed"));
    }, "native setup failed"],
    ["a malformed handshake", (child: ReturnType<typeof fakeChild>) => {
      child.stdout.emit("data", Buffer.alloc(20));
    }, "Windows command launcher returned an invalid handshake"],
    ["pre-ready stderr overflow", (child: ReturnType<typeof fakeChild>) => {
      child.stderr.emit("data", Buffer.alloc(64 * 1024 + 1));
    }, "Windows command launcher produced output before it was ready"],
    ["a launcher stdin error", (child: ReturnType<typeof fakeChild>) => {
      child.stdin.emit("error", new Error("broken pipe"));
    }, "Windows command launcher input failed: broken pipe"],
  ])("defers %s until process close and settles once", (_name, trigger, expectedError) => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const onError = vi.fn();
    const onDone = vi.fn();
    executeCommand("whoami", undefined, undefined, {
      onOutput: () => {}, onDone, onError,
    }, { windowsExecLauncherPath: process.execPath });

    trigger(child);
    expect(onError).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(2);
    child.emit("close", 1);
    child.emit("close", 1);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledWith(expectedError);
    expect(onDone).not.toHaveBeenCalled();
  });

  it("preserves every command exit code without reserving launcher statuses", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const onError = vi.fn();
    const onDone = vi.fn();
    executeCommand("exit /b -1581252607", undefined, undefined, {
      onOutput: () => {}, onDone, onError,
    }, { windowsExecLauncherPath: process.execPath });
    child.stdout.emit("data", encodeWindowsLauncherResponseForTest("ready"));
    child.emit("close", 0xa1c00001);
    child.emit("error", new Error("late duplicate"));
    expect(onDone).toHaveBeenCalledTimes(1);
    expect(onDone).toHaveBeenCalledWith(0xa1c00001, expect.any(Number));
    expect(onError).not.toHaveBeenCalled();
  });

  it("times out the bounded handshake and settles only once", async () => {
    vi.useFakeTimers();
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const onError = vi.fn();
    const onDone = vi.fn();
    executeCommand("echo never-started", undefined, undefined, {
      onOutput: () => {}, onDone, onError,
    }, { windowsExecLauncherPath: process.execPath });
    await vi.advanceTimersByTimeAsync(10_001);
    expect(onError).not.toHaveBeenCalled();
    expect(onDone).not.toHaveBeenCalled();
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(2);
    child.emit("close", 1);
    child.emit("close", 1);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError).toHaveBeenCalledWith("Windows command launcher did not become ready");
    expect(onDone).not.toHaveBeenCalled();
  });

  it("settles a true spawn error without waiting for a close that may never arrive", () => {
    setPlatform("win32");
    const child = fakeChild();
    delete child.pid;
    vi.mocked(spawn).mockReturnValue(child as never);
    const onError = vi.fn();
    const onDone = vi.fn();
    executeCommand("echo never-spawned", undefined, undefined, {
      onOutput: () => {}, onDone, onError,
    }, { windowsExecLauncherPath: process.execPath });

    child.emit("error", new Error("spawn EACCES"));
    child.emit("close", -1);
    expect(onError).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledWith("spawn EACCES");
    expect(onDone).not.toHaveBeenCalled();
  });

  it("keeps kill idempotent while termination is pending", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const running = executeCommand("echo running", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    }, { windowsExecLauncherPath: process.execPath });

    running.kill();
    running.kill();
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(2);
    child.emit("close", 1);
  });

  it("fails closed when the configured launcher is missing", async () => {
    setPlatform("win32");
    const onError = vi.fn();
    executeCommand("echo must-not-run", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError,
    }, { windowsExecLauncherPath: "Z:\\missing\\aic.exe" });
    await Promise.resolve();
    expect(spawn).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith("Windows command launcher is unavailable");
  });

  it("refuses a multi-line command instead of silently running its first line", async () => {
    setPlatform("win32");
    const onError = vi.fn();
    executeCommand("echo one\r\necho two", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError,
    }, { windowsExecLauncherPath: process.execPath });
    await Promise.resolve();
    expect(spawn).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith(expect.stringContaining("line break on Windows"));
  });

  it("keeps sending a command with a trailing newline", () => {
    setPlatform("win32");
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    executeCommand("echo one\r\n", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    }, { windowsExecLauncherPath: process.execPath });
    const request = child.stdin.end.mock.calls[0]![0] as Buffer;
    expect(request.subarray(16).toString("utf16le")).toBe("echo one\r\n");
  });

  it("names the cwd when it is missing, instead of letting libuv name the shell", async () => {
    setPlatform("win32");
    const onError = vi.fn();
    executeCommand("whoami", join(tmpdir(), `aic-missing-${Date.now()}`), undefined, {
      onOutput: () => {}, onDone: () => {}, onError,
    }, { windowsExecLauncherPath: process.execPath });
    await Promise.resolve();
    expect(spawn).not.toHaveBeenCalled();
    expect(onError).toHaveBeenCalledWith("cwd does not exist on this machine.");
  });

  it("preserves explicit Python encoding overrides", () => {
    setPlatform("win32");
    process.env["PYTHONUTF8"] = "inherited-must-lose";
    executeCommand("python script.py", undefined, {
      pythonutf8: "0", PythonIoEncoding: "cp1250",
    }, { onOutput: () => {}, onDone: () => {}, onError: () => {} }, {
      windowsExecLauncherPath: process.execPath,
    });
    expect(vi.mocked(spawn).mock.calls[0]![2]?.env).toMatchObject({
      pythonutf8: "0", PythonIoEncoding: "cp1250",
    });
    expect(vi.mocked(spawn).mock.calls[0]![2]?.env?.["PYTHONUTF8"]).toBeUndefined();
    expect(vi.mocked(spawn).mock.calls[0]![2]?.env?.["PYTHONIOENCODING"]).toBeUndefined();
  });

  it("leaves POSIX shell behavior unchanged", () => {
    setPlatform("linux");
    // cwd is validated against the REAL filesystem before the spawn, so a
    // hard-coded POSIX path never spawns on the Windows CI runner and the
    // assertion below reads an undefined call. Use a directory that exists
    // wherever this test runs.
    const cwd = process.cwd();
    executeCommand("printf 'zażółć'", cwd, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    expect(vi.mocked(spawn).mock.calls[0]).toMatchObject([
      "printf 'zażółć'", [], { shell: true, cwd, detached: true },
    ]);
  });
});

/**
 * The window between 'exit' (the child is reaped) and 'close' (every inherited
 * pipe reached EOF), which a backgrounded grandchild can stretch indefinitely.
 * Linux here purely to stay off the macOS login-shell probe — the code is the
 * same on both.
 */
describe("executeCommand post-exit drain", () => {
  const handlers = () => ({ onOutput: vi.fn(), onDone: vi.fn(), onError: vi.fn() });
  const decode = (onOutput: ReturnType<typeof vi.fn>) =>
    onOutput.mock.calls.map(([chunk]) => Buffer.from(String(chunk), "base64").toString()).join("");

  beforeEach(() => {
    vi.useFakeTimers();
    setPlatform("linux");
  });

  it("reports the exit as soon as the pipes go quiet, not after a flat grace window", async () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    executeCommand("sleep 30 & echo done", undefined, undefined, h);

    child.stdout.emit("data", Buffer.from("done\n"));
    child.emit("exit", 0);
    // 'close' never comes: the grandchild still holds the write ends. The
    // caller's deadline keeps running while we wait, so the wait is short.
    await vi.advanceTimersByTimeAsync(20);
    expect(h.onDone).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(20);
    expect(h.onDone).toHaveBeenCalledTimes(1);
    expect(h.onDone).toHaveBeenCalledWith(0, expect.any(Number));
    expect(decode(h.onOutput)).toBe("done\n");
  });

  it("detaches from the pipes without closing them under a live writer", async () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    executeCommand("mydaemon & echo started", undefined, undefined, h);

    child.stdout.emit("data", Buffer.from("started\n"));
    child.emit("exit", 0);
    await vi.advanceTimersByTimeAsync(40);
    expect(h.onDone).toHaveBeenCalledTimes(1);

    for (const stream of [child.stdout, child.stderr]) {
      // destroy() closes OUR read end, and the surviving daemon's next write
      // would then take EPIPE/SIGPIPE — killing a daemon we just reported as
      // started. It must never be called here.
      expect(stream.destroy).not.toHaveBeenCalled();
      // Flowing-and-discarding instead: no back-pressure on the writer, and the
      // fd is still released the moment the survivor finally exits (EOF).
      expect(stream.resume).toHaveBeenCalled();
      // ...and it may not hold the agent's event loop open meanwhile.
      expect(stream.unref).toHaveBeenCalled();
      expect(stream.listenerCount("data")).toBe(0);
    }

    // Late output cannot reach the caller (nor re-arm anything): we are detached.
    child.stdout.emit("data", Buffer.from("late\n"));
    expect(decode(h.onOutput)).toBe("started\n");
    expect(h.onDone).toHaveBeenCalledTimes(1);
  });

  it("keeps draining while a burst is still arriving, and caps how long it will", async () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    executeCommand("cat huge & true", undefined, undefined, h);

    child.emit("exit", 0);
    // A reader that keeps handing us chunks past the old flat window must never
    // be cut off mid-burst — that would be output silently lost from a
    // successful command.
    for (let i = 0; i < 20; i += 1) {
      await vi.advanceTimersByTimeAsync(10);
      child.stdout.emit("data", Buffer.from("x"));
    }
    expect(h.onDone).not.toHaveBeenCalled();
    expect(decode(h.onOutput)).toBe("x".repeat(20));
    // ...but a grandchild that simply never stops talking cannot hold the
    // caller's slot open forever either: the absolute cap ends the drain even
    // while data is still flowing.
    for (let i = 0; i < 20; i += 1) {
      await vi.advanceTimersByTimeAsync(10);
      child.stdout.emit("data", Buffer.from("x"));
    }
    expect(h.onDone).toHaveBeenCalledTimes(1);
  });

  it("ends the drain before the caller's deadline instead of being declared timed out", async () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    // A command that exits 10 ms before its deadline. An unclamped drain would
    // wait one full quiet interval (25 ms) and settle AFTER connection.ts had
    // already sent "Command timed out after Nms" — a completed command silently
    // reported as a failure. The clamp must beat the deadline.
    const deadlineMs = Date.now() + 10;
    executeCommand("sleep 30 & echo done", undefined, undefined, h, { deadlineMs });

    child.stdout.emit("data", Buffer.from("done\n"));
    child.emit("exit", 0);
    await vi.advanceTimersByTimeAsync(10);
    expect(h.onDone).toHaveBeenCalledTimes(1);
    expect(h.onDone).toHaveBeenCalledWith(0, expect.any(Number));
    expect(h.onError).not.toHaveBeenCalled();
    expect(decode(h.onOutput)).toBe("done\n");
  });

  it("settles at once when the deadline has already passed at exit", () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    executeCommand("sleep 30 & echo late", undefined, undefined, h, {
      deadlineMs: Date.now() - 1,
    });

    child.stdout.emit("data", Buffer.from("late\n"));
    child.emit("exit", 0);
    // No budget left to wait for quiet: report the exit we already have rather
    // than let the caller call a finished command timed out.
    expect(h.onDone).toHaveBeenCalledTimes(1);
    expect(decode(h.onOutput)).toBe("late\n");
  });

  it("does not truncate a burst when there is ample time before the deadline", async () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    // Deadline far away: the clamp must be inert and leave the quiet-based
    // drain free to keep extending while the burst is still arriving.
    executeCommand("cat huge & true", undefined, undefined, h, {
      deadlineMs: Date.now() + 60_000,
    });

    child.emit("exit", 0);
    for (let i = 0; i < 20; i += 1) {
      await vi.advanceTimersByTimeAsync(10);
      child.stdout.emit("data", Buffer.from("x"));
    }
    expect(h.onDone).not.toHaveBeenCalled();
    expect(decode(h.onOutput)).toBe("x".repeat(20));
    // Quiet at last (no more chunks): the drain settles on its own terms, not
    // because the clamp cut it off.
    await vi.advanceTimersByTimeAsync(30);
    expect(h.onDone).toHaveBeenCalledTimes(1);
  });

  it("settles immediately when the pipes do reach EOF", () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const h = handlers();
    executeCommand("echo hi", undefined, undefined, h);
    child.emit("exit", 7);
    child.emit("close", 7);
    // The ordinary command pays nothing for the drain at all.
    expect(h.onDone).toHaveBeenCalledTimes(1);
    expect(h.onDone).toHaveBeenCalledWith(7, expect.any(Number));
  });

  it("stops signalling the process group the moment the child is reaped", async () => {
    const child = fakeChild();
    vi.mocked(spawn).mockReturnValue(child as never);
    const killSpy = vi.spyOn(process, "kill").mockImplementation(() => true);
    const h = handlers();
    const running = executeCommand("sleep 30 & sleep 1", undefined, undefined, h);

    running.kill();
    expect(killSpy).toHaveBeenCalledWith(-1234, "SIGTERM");
    child.emit("exit", 143);
    killSpy.mockClear();
    // Node has already waitpid()ed 1234, so the number may belong to someone
    // else now — and `-1234` is a whole process GROUP. Neither the pending
    // SIGKILL escalation nor a kill() arriving during the drain may fire.
    running.kill();
    await vi.advanceTimersByTimeAsync(KILL_ESCALATION_MS + 1_000);
    expect(killSpy).not.toHaveBeenCalled();
    expect(h.onDone).toHaveBeenCalledWith(143, expect.any(Number));
    killSpy.mockRestore();
  });
});
