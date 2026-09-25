import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

import { spawn } from "node:child_process";
import { executeCommand } from "../executor.js";
import { pendingLoginShellPath, resetLoginShellPathForTest } from "../login-shell-path.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
const originalPath = process.env["PATH"];
const originalShell = process.env["SHELL"];
const originalLang = process.env["LANG"];
const originalTerm = process.env["TERM"];

type FakeChild = EventEmitter & {
  stdin: EventEmitter & { end: ReturnType<typeof vi.fn> };
  stdout: EventEmitter & { destroy: ReturnType<typeof vi.fn> };
  stderr: EventEmitter & { destroy: ReturnType<typeof vi.fn> };
  pid?: number;
};

const children: FakeChild[] = [];

function fakeChild(): FakeChild {
  return Object.assign(new EventEmitter(), {
    stdin: Object.assign(new EventEmitter(), { end: vi.fn() }),
    stdout: Object.assign(new EventEmitter(), { destroy: vi.fn() }),
    stderr: Object.assign(new EventEmitter(), { destroy: vi.fn() }),
    pid: undefined as number | undefined,
  });
}

function setPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

/** The nonce'd sentinel pairs the probe told its shell to print around each value. */
function probeMarkers(): { begin: string; end: string; langBegin: string; langEnd: string } {
  const script = String(vi.mocked(spawn).mock.calls[0]![1]![3]);
  const begin = /'(--aic-path-begin-[0-9a-f]+--)'/.exec(script)?.[1];
  const end = /'(--aic-path-end-[0-9a-f]+--)'/.exec(script)?.[1];
  const langBegin = /'(--aic-lang-begin-[0-9a-f]+--)'/.exec(script)?.[1];
  const langEnd = /'(--aic-lang-end-[0-9a-f]+--)'/.exec(script)?.[1];
  expect(begin).toBeTruthy();
  expect(end).toBeTruthy();
  expect(langBegin).toBeTruthy();
  expect(langEnd).toBeTruthy();
  return { begin: begin!, end: end!, langBegin: langBegin!, langEnd: langEnd! };
}

/**
 * Answer the one-shot probe the way the real shell does — value bracketed by
 * the sentinel — then let the deferred command spawn happen.
 */
async function answerProbe(
  value: string | null,
  exitCode = 0,
  lang: string | null = null,
): Promise<void> {
  const probeChild = children[0]!;
  if (value !== null || lang !== null) {
    const { begin, end, langBegin, langEnd } = probeMarkers();
    const path = value === null ? "" : `${begin}${value}${end}`;
    const locale = lang === null ? "" : `${langBegin}${lang}${langEnd}`;
    probeChild.stdout.emit("data", Buffer.from(`${path}${locale}`));
  }
  probeChild.emit("close", exitCode);
  await new Promise((resolve) => setImmediate(resolve));
}

/** Answer with RAW stdout, sentinel and all — for the noisy-rc-file cases. */
async function answerProbeRaw(stdout: string, exitCode = 0): Promise<void> {
  const probeChild = children[0]!;
  probeChild.stdout.emit("data", Buffer.from(stdout));
  probeChild.emit("close", exitCode);
  await new Promise((resolve) => setImmediate(resolve));
}

/** PATH of the environment the executor handed to the actual command spawn. */
function commandPath(): string | undefined {
  return commandEnv()?.["PATH"];
}

/** The whole environment the executor handed to the actual command spawn. */
function commandEnv(): NodeJS.ProcessEnv | undefined {
  const call = vi.mocked(spawn).mock.calls[1];
  return call?.[2]?.env as NodeJS.ProcessEnv | undefined;
}

beforeEach(() => {
  resetLoginShellPathForTest();
  children.length = 0;
  process.env["PATH"] = "/usr/bin:/bin";
  process.env["SHELL"] = "/bin/zsh";
  // launchd hands the app no locale, which is the situation under test; the test
  // runner's own LANG must not stand in for one.
  delete process.env["LANG"];
  // Same reasoning for TERM, and it matters MORE here: the test runner is
  // usually started from a terminal, so it has a real TERM the agent under
  // launchd/systemd never has. Leaving it in place is exactly what made the old
  // TERM test vacuous — it asserted a value the test itself supplied.
  delete process.env["TERM"];
  setPlatform("darwin");
  vi.mocked(spawn).mockReset();
  vi.mocked(spawn).mockImplementation(() => {
    const child = fakeChild();
    children.push(child);
    return child as never;
  });
});

afterEach(() => {
  vi.useRealTimers();
  resetLoginShellPathForTest();
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  if (originalPath === undefined) delete process.env["PATH"];
  else process.env["PATH"] = originalPath;
  if (originalShell === undefined) delete process.env["SHELL"];
  else process.env["SHELL"] = originalShell;
  if (originalLang === undefined) delete process.env["LANG"];
  else process.env["LANG"] = originalLang;
  if (originalTerm === undefined) delete process.env["TERM"];
  else process.env["TERM"] = originalTerm;
});

describe("macOS login-shell PATH", () => {
  it("asks the user's login shell once and merges its PATH ahead of the inherited one", async () => {
    const running = executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    // The command waits for the probe instead of running with launchd's PATH.
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(spawn).mock.calls[0]![0]).toBe("/bin/zsh");
    const args = vi.mocked(spawn).mock.calls[0]![1]!;
    expect(args.slice(0, 3)).toEqual(["-l", "-i", "-c"]);
    const { begin, end, langBegin, langEnd } = probeMarkers();
    // One shell invocation carries BOTH values: PATH and LANG are the two things
    // launchd fails to give the agent, and a second probe would double the cost
    // of the first command for no benefit.
    expect(String(args[3])).toBe(
      `printf %s '${begin}'; printf %s "$PATH"; printf %s '${end}'; ` +
        `printf %s '${langBegin}'; printf %s "$LANG"; printf %s '${langEnd}'`,
    );

    await answerProbe("/opt/homebrew/bin:/usr/bin");
    // Inherited entries the login shell does not list are kept, not dropped.
    expect(commandPath()).toBe("/opt/homebrew/bin:/usr/bin:/bin");
    running.kill();

    // The second command reuses the cache: no second probe, no waiting.
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(3);
    expect(vi.mocked(spawn).mock.calls[2]![0]).toBe("brew --version");
  });

  it("never overrides a PATH the caller sent with the command", async () => {
    executeCommand("brew --version", undefined, { PATH: "/caller/only" }, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin:/usr/bin");
    expect(commandPath()).toBe("/caller/only");
  });

  it.each([
    ["a non-zero exit", "/opt/homebrew/bin", 1],
    ["empty output", "   \n", 0],
    ["output with no absolute entry", "not-a-path", 0],
    ["output with a NUL byte", "/opt/homebrew/bin\0/x", 0],
    ["no output at all", null, 0],
  ])("keeps the inherited PATH when the probe fails with %s", async (_name, stdout, code) => {
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe(stdout, code);
    expect(commandPath()).toBe("/usr/bin:/bin");
  });

  it("takes only what is between the sentinels, never the rc file's chatter", async () => {
    // The realistic failure: a login+interactive shell prints a motd and an nvm
    // notice down the SAME pipe as the value. Without the sentinel, "Welcome"
    // became the first PATH entry of every command — a RELATIVE entry, i.e. the
    // command's own cwd, in front of everything.
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    const { begin, end } = probeMarkers();
    await answerProbeRaw(
      `Welcome to Darwin!\nnvm: using v20\n${begin}/opt/homebrew/bin:/usr/bin${end}\nbye\n`,
    );
    expect(commandPath()).toBe("/opt/homebrew/bin:/usr/bin:/bin");
  });

  it("drops entries that are not absolute directories, keeping the rest", async () => {
    // "" is what a trailing or doubled colon leaves behind, and every shell
    // reads it as the current directory — the same code-execution hazard as an
    // explicitly relative entry, just harder to see.
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe(":/opt/homebrew/bin:.:relative/bin:/opt/homebrew/bin:/usr/bin:");
    expect(commandPath()).toBe("/opt/homebrew/bin:/usr/bin:/bin");
  });

  it("keeps the inherited PATH when the value never made it through the noise", async () => {
    // Truncated/garbled output with no sentinel pair: guessing which line was
    // the PATH is exactly what this protocol exists to avoid.
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbeRaw("Welcome to Darwin!\n/opt/homebrew/bin:/usr/bin\n");
    expect(commandPath()).toBe("/usr/bin:/bin");
  });

  it("gives up on a shell that never answers, and still runs the command", async () => {
    vi.useFakeTimers();
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2_000);
    await vi.advanceTimersByTimeAsync(0);
    expect(commandPath()).toBe("/usr/bin:/bin");
  });

  it("keeps the inherited PATH when the shell cannot even be spawned", async () => {
    vi.mocked(spawn).mockImplementationOnce(() => {
      throw new Error("spawn ENOENT");
    });
    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect((vi.mocked(spawn).mock.calls[1]?.[2]?.env as NodeJS.ProcessEnv)["PATH"])
      .toBe("/usr/bin:/bin");
  });

  it("never runs a command that was killed while the probe was still pending", async () => {
    // The caller has already been told this command failed — a timeout or a
    // dropped connection sent its terminal response before killing us. Starting
    // it now would run its side effects AFTER that report: the deletion
    // happens, the answer says it did not.
    const events: string[] = [];
    const running = executeCommand("rm -rf /tmp/aic-must-not-run", undefined, undefined, {
      onOutput: () => {},
      onDone: (code) => events.push(`done:${code}`),
      onError: (error) => events.push(`error:${error}`),
    });
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(1); // the probe only

    running.kill();
    await answerProbe("/opt/homebrew/bin");
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(1); // still only the probe
    expect(events).toEqual(["error:Command was cancelled before it started."]);
  });

  it("reports a deferred start failure instead of leaving the caller hanging", async () => {
    // Nothing awaits the deferred start, so a throw from it used to be an
    // unhandled rejection: no onDone, no onError, and a command that hangs
    // until the relay's timeout — on the one platform that takes this branch.
    const events: string[] = [];
    vi.mocked(spawn)
      .mockImplementationOnce(() => {
        const child = fakeChild();
        children.push(child);
        return child as never;
      })
      .mockImplementationOnce(() => ({
        on() { throw new Error("child wiring failed"); },
      }) as never);

    executeCommand("brew --version", undefined, undefined, {
      onOutput: () => {},
      onDone: (code) => events.push(`done:${code}`),
      onError: (error) => events.push(`error:${error}`),
    });
    await answerProbe("/opt/homebrew/bin");
    expect(events).toEqual(["error:child wiring failed"]);
  });

  it("gives the command the login shell's own LANG when it reports one", async () => {
    executeCommand("python3 -c 'print(1)'", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "pl_PL.UTF-8");
    expect(commandEnv()?.["LANG"]).toBe("pl_PL.UTF-8");
  });

  it("falls back to a UTF-8 locale when the shell reports no LANG at all", async () => {
    // The common macOS case: Terminal.app injects LANG, no rc file sets it, so a
    // launchd-started agent probes an empty value. Empty means the C locale, which
    // is what mangled non-ASCII output — en_US.UTF-8 exists on every macOS.
    executeCommand("python3 -c 'print(1)'", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "");
    expect(commandEnv()?.["LANG"]).toBe("en_US.UTF-8");
  });

  it("still sets a locale when the probe fails open entirely", async () => {
    executeCommand("python3 -c 'print(1)'", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe(null, 1);
    // PATH failed open (unchanged), and the locale still got filled in: the two
    // values are independent, and neither failure may take the other down.
    expect(commandPath()).toBe("/usr/bin:/bin");
    expect(commandEnv()?.["LANG"]).toBe("en_US.UTF-8");
  });

  it("ignores a shell that printed something that is not a locale", async () => {
    executeCommand("python3 -c 'print(1)'", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "Welcome to Darwin! (no locale here)");
    expect(commandEnv()?.["LANG"]).toBe("en_US.UTF-8");
  });

  it("never overrides a LANG the caller sent with the command", async () => {
    executeCommand("python3 -c 'print(1)'", undefined, { LANG: "C" }, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "pl_PL.UTF-8");
    expect(commandEnv()?.["LANG"]).toBe("C");
  });

  it("never overrides a LANG the agent already inherited", async () => {
    process.env["LANG"] = "ja_JP.UTF-8";
    try {
      executeCommand("python3 -c 'print(1)'", undefined, undefined, {
        onOutput: () => {}, onDone: () => {}, onError: () => {},
      });
      await answerProbe("/opt/homebrew/bin", 0, "pl_PL.UTF-8");
      expect(commandEnv()?.["LANG"]).toBe("ja_JP.UTF-8");
    } finally {
      delete process.env["LANG"];
    }
  });

  it("SETS TERM=dumb when the agent has none — the launchd/systemd case", async () => {
    // The situation the fix is for, and the one the old test could not see: an
    // agent started by a service manager has NO TERM, so software that looks for
    // one guesses — often into ANSI colour and cursor control, straight through
    // the output an AI agent has to read. beforeEach deletes TERM precisely so
    // this assertion is about the code and not about the test runner's terminal.
    expect(process.env["TERM"]).toBeUndefined();
    executeCommand("git status", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "pl_PL.UTF-8");
    expect(commandEnv()?.["TERM"]).toBe("dumb");
  });

  it("sets TERM on Linux too — systemd hands the agent no more than launchd does", async () => {
    setPlatform("linux");
    executeCommand("git status", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    // No probe off macOS: the command spawns immediately, so it is call 0 here.
    const call = vi.mocked(spawn).mock.calls[0];
    expect((call?.[2]?.env as NodeJS.ProcessEnv | undefined)?.["TERM"]).toBe("dumb");
  });

  it("never overrides a TERM the agent already inherited", async () => {
    // Same precedence as PATH and LANG: we fill a hole, we do not overrule the
    // machine's own configuration. An agent started from a terminal keeps it.
    process.env["TERM"] = "xterm-256color";
    executeCommand("git status", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "pl_PL.UTF-8");
    expect(commandEnv()?.["TERM"]).toBe("xterm-256color");
  });

  it("never overrides a TERM the caller sent with the command", async () => {
    executeCommand("git status", undefined, { TERM: "xterm" }, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    await answerProbe("/opt/homebrew/bin", 0, "pl_PL.UTF-8");
    expect(commandEnv()?.["TERM"]).toBe("xterm");
  });

  it("does not touch LANG off macOS", async () => {
    // Linux agents inherit a locale from systemd/the login session, and Windows
    // does not use the variable; inventing one there would be a guess, not a fix.
    setPlatform("linux");
    executeCommand("printf hi", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    const call = vi.mocked(spawn).mock.calls[0];
    expect((call?.[2]?.env as NodeJS.ProcessEnv | undefined)?.["LANG"]).toBeUndefined();
  });

  it("does not probe anything off macOS", () => {
    setPlatform("linux");
    expect(pendingLoginShellPath()).toBeNull();
    executeCommand("printf hi", undefined, undefined, {
      onOutput: () => {}, onDone: () => {}, onError: () => {},
    });
    expect(vi.mocked(spawn)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(spawn).mock.calls[0]![0]).toBe("printf hi");
  });
});
