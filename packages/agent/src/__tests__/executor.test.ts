import { describe, it, expect } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";
import { executeCommand } from "../executor.js";

function run(
  command: string,
  cwd?: string,
  env?: Record<string, string>,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    executeCommand(command, cwd, env, {
      onOutput: (chunk, stream) => {
        const decoded = Buffer.from(chunk, "base64");
        if (stream === "stdout") stdoutChunks.push(decoded);
        else stderrChunks.push(decoded);
      },
      onDone: (exitCode) =>
        resolve({
          stdout: Buffer.concat(stdoutChunks).toString("utf8"),
          stderr: Buffer.concat(stderrChunks).toString("utf8"),
          exitCode,
        }),
      onError: (error) => reject(new Error(error)),
    });
  });
}

describe("executeCommand", () => {
  it("captures stdout", async () => {
    const { stdout, exitCode } = await run("echo hello");
    expect(stdout.trim()).toBe("hello");
    expect(exitCode).toBe(0);
  });

  it("captures stderr", async () => {
    const { stderr, exitCode } = await run("echo error >&2");
    expect(stderr.trim()).toBe("error");
    expect(exitCode).toBe(0);
  });

  it("captures both stdout and stderr", async () => {
    const { stdout, stderr } = await run("echo out && echo err >&2");
    expect(stdout.trim()).toBe("out");
    expect(stderr.trim()).toBe("err");
  });

  it("preserves non-ASCII UTF-8 output bytes", async () => {
    const { stdout, stderr } = await run(
      `${JSON.stringify(process.execPath)} -e "process.stdout.write('zażółć'); process.stderr.write('€')"`,
    );
    expect(stdout).toBe("zażółć");
    expect(stderr).toBe("€");
  });

  it("returns non-zero exit code", async () => {
    const { exitCode } = await run("exit 42");
    expect(exitCode).toBe(42);
  });

  it("output chunks are valid base64", async () => {
    await new Promise<void>((resolve, reject) => {
      executeCommand("echo hello", undefined, undefined, {
        onOutput: (chunk) => {
          expect(() => Buffer.from(chunk, "base64")).not.toThrow();
          expect(Buffer.from(chunk, "base64").toString("utf8")).toContain("hello");
        },
        onDone: () => resolve(),
        onError: (e) => reject(new Error(e)),
      });
    });
  });

  it("passes env variables", async () => {
    const { stdout } = await run("echo $TEST_SENTINEL", undefined, { TEST_SENTINEL: "aic-test-value" });
    expect(stdout.trim()).toBe("aic-test-value");
  });

  it("uses provided cwd", async () => {
    const { stdout } = await run("pwd", "/tmp");
    // macOS resolves /tmp → /private/tmp
    expect(stdout.trim()).toMatch(/\/tmp/);
  });

  it("kill() terminates the process", async () => {
    let exited = false;
    const result = new Promise<void>((resolve) => {
      const { kill } = executeCommand("sleep 60", undefined, undefined, {
        onOutput: () => {},
        onDone: () => { exited = true; resolve(); },
        onError: () => { exited = true; resolve(); },
      });
      setTimeout(kill, 100);
    });
    await result;
    expect(exited).toBe(true);
  });

  it("kill terminates the whole process group, not just the shell", async () => {
    // A background grandchild appends to a file on a loop. If kill only hit the
    // shell, the grandchild would keep writing; killing the whole process group
    // stops it. (We assert no growth rather than probing the pid, because a
    // SIGKILLed leaf lingers as a zombie that still answers signal 0.)
    const file = path.join(os.tmpdir(), `aic-grandkill-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.writeFileSync(file, "");

    await new Promise<void>((resolve) => {
      const running = executeCommand(
        'while true; do echo x >> "$AIC_GK"; sleep 0.05; done & echo started; wait',
        undefined,
        { AIC_GK: file },
        {
          onOutput: (chunk) => {
            if (Buffer.from(chunk, "base64").toString("utf8").includes("started")) {
              setTimeout(running.kill, 150); // let it write a few lines, then kill the tree
            }
          },
          onDone: () => resolve(),
          onError: () => resolve(),
        },
      );
    });

    const sizeAtKill = fs.statSync(file).size;
    expect(sizeAtKill).toBeGreaterThan(0); // the grandchild did run
    await new Promise((r) => setTimeout(r, 400));
    // No further writes → the grandchild was killed with the group.
    expect(fs.statSync(file).size).toBe(sizeAtKill);

    try { fs.unlinkSync(file); } catch { /* ignore */ }
  });

  it("onError fires for non-existent command", async () => {
    await new Promise<void>((resolve) => {
      executeCommand("this-cmd-does-not-exist-aic", undefined, undefined, {
        onOutput: () => {},
        onDone: () => resolve(), // shell exits with non-zero, not an error event
        onError: () => resolve(),
      });
    });
  });

  it("names the cwd, not the shell, when the cwd is unusable", async () => {
    const missing = path.join(os.tmpdir(), `aic-missing-cwd-${Date.now()}`);
    await expect(run("pwd", missing)).rejects.toThrow("cwd does not exist on this machine.");
    await expect(run("pwd", "relative/dir")).rejects.toThrow("cwd must be an absolute path.");
  });

  it("returns when the command exits, not when a backgrounded grandchild lets go", async () => {
    // The grandchild inherits our stdout/stderr pipes, so the pipes never reach
    // EOF. Waiting for that used to stall this command until the caller's
    // timeout, minutes after it had actually finished.
    const started = Date.now();
    const { stdout, exitCode } = await run("sleep 30 & echo done");
    expect(stdout.trim()).toBe("done");
    expect(exitCode).toBe(0);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("leaves a backgrounded daemon alive when it keeps WRITING after we settled", async () => {
    // The regression this guards: the post-exit drain used to destroy() OUR read
    // ends. The survivor still holds the WRITE ends, so its next write got
    // EPIPE/SIGPIPE and it died ~250 ms after the foreground command returned —
    // while we had already reported success. Every earlier test here used a
    // SILENT survivor (`sleep 30 &`), which never notices its pipe is gone; this
    // one writes to stdout throughout, which is the only shape that catches it.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-daemon-"));
    const marker = path.join(dir, "survived");
    const started = Date.now();
    const { stdout, exitCode } = await run(
      '( i=0; while [ $i -lt 12 ]; do echo tick; sleep 0.1; i=$((i+1)); done; ' +
        'echo yes > "$AIC_MARKER" ) & echo started',
      undefined,
      { AIC_MARKER: marker },
    );
    expect(stdout).toContain("started");
    expect(exitCode).toBe(0);
    // The call still returns on the child's exit, not on the daemon's.
    expect(Date.now() - started).toBeLessThan(1_000);

    // The daemon writes for ~1.2s, long past the drain, and only then leaves its
    // marker. No marker ⇒ a legitimate `... &` daemon was killed by our cleanup.
    await new Promise((r) => setTimeout(r, 2_000));
    expect(fs.existsSync(marker)).toBe(true);
    fs.rmSync(dir, { recursive: true, force: true });
  }, 15_000);

  it("does not truncate a large burst written right before the child exits", async () => {
    const size = 4 * 1024 * 1024;
    const { stdout, exitCode } = await run(
      `${JSON.stringify(process.execPath)} -e "process.stdout.write('x'.repeat(${size}))"`,
    );
    expect(stdout.length).toBe(size);
    expect(exitCode).toBe(0);
  });

  it("runs piped commands via shell", async () => {
    const { stdout } = await run("echo 'hello world' | tr ' ' '-'");
    expect(stdout.trim()).toBe("hello-world");
  });
});
