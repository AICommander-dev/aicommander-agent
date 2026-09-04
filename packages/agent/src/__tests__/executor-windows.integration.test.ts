import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { executeCommand } from "../executor.js";

const describeOnWindows = describe.runIf(process.platform === "win32");
const packageRoot = fileURLToPath(new URL("../..", import.meta.url));
const launcher = path.join(packageRoot, "dist-native", "aicommander-win-exec-x64.exe");
const probe = path.join(packageRoot, "dist-native", "test", "aic-console-probe.exe");

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function sizeOf(target: string): number {
  try {
    return fs.statSync(target).size;
  } catch {
    return 0;
  }
}

async function waitForBytes(target: string, timeoutMs: number): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const size = sizeOf(target);
    if (size > 0) return size;
    await sleep(50);
  }
  return 0;
}

function run(command: string, env?: Record<string, string>) {
  return new Promise<{ stdout: string; stderr: string; exitCode: number; chunks: number[] }>((resolve, reject) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const chunks: number[] = [];
    executeCommand(command, undefined, env, {
      onOutput: (chunk, stream) => {
        chunks.push(Date.now());
        (stream === "stdout" ? stdout : stderr).push(Buffer.from(chunk, "base64"));
      },
      onDone: (exitCode) => resolve({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        exitCode,
        chunks,
      }),
      onError: (error) => reject(new Error(error)),
    }, { windowsExecLauncherPath: launcher });
  });
}

describeOnWindows("Windows native UTF-8 executor", () => {
  it("gives a console-native program CP=65001, separate Unicode pipes, and no visible window", async () => {
    const result = await run(JSON.stringify(probe));
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("CP=65001;VISIBLE=0");
    expect(result.stdout).toContain("stdout=zażółć € 漢字");
    expect(result.stderr).toContain("stderr=Łódź Ж");
  });

  it("preserves cmd expansion, piping, Unicode built-ins, and exit codes", async () => {
    const syntax = await run("echo %AIC_UTF8_TEST% | findstr Commander", {
      AIC_UTF8_TEST: "zażółć Commander €",
    });
    expect(syntax.stdout).toContain("zażółć Commander €");
    expect(syntax.exitCode).toBe(0);
    expect((await run("exit /b 37")).exitCode).toBe(37);
    expect((await run("exit /b -1581252607")).exitCode).toBe(0xa1c00001);
  });

  // Also the one runtime check on the launcher's PRE-EXIT poll interval
  // (kRelayPollMs, currently 150 ms): `first` has to reach us during the 500 ms
  // sleep, not with `second` at the end. Buffered output makes that latency
  // invisible to a normal caller, which is why the interval may be raised at
  // all — but not past the point where these two writes arrive as one chunk.
  it("streams before exit rather than buffering the command", async () => {
    const result = await run(
      'echo first & powershell.exe -NoProfile -NonInteractive -Command "Start-Sleep -Milliseconds 500" & echo second',
    );
    expect(result.stdout).toContain("first");
    expect(result.stdout).toContain("second");
    expect(result.chunks.length).toBeGreaterThanOrEqual(2);
    expect(result.chunks.at(-1)! - result.chunks[0]!).toBeGreaterThanOrEqual(300);
  });

  // F-03: the call used to settle on end-of-file rather than on the command's
  // exit, and a `start /b` grandchild inherits the command's stdout write
  // handle — so a command that left anything running in the background burned
  // the caller's whole timeout (measured 8000 ms on agent 1.0.50) and, before
  // the partial-output half of the fix, returned nothing at all. The launcher
  // now settles on the shell's exit with a bounded drain; these two tests pin
  // both halves of that contract, and the second pins what the bound must not
  // cost a normal command.
  it("returns when the command exits, leaving a background writer alive", async () => {
    const tick = path.join(os.tmpdir(), `aic-win-bg-${Date.now()}.txt`);
    const escaped = tick.replace(/'/g, "''");
    // The background process writes to BOTH the inherited stdout pipe and the
    // file: the pipe write is what would fail with ERROR_BROKEN_PIPE if the
    // launcher closed the read end instead of merely stopping to read it, and
    // the file is how a killed or broken writer becomes visible after the fact.
    const started = Date.now();
    const result = await run(
      `start /b "" powershell.exe -NoProfile -NonInteractive -Command "1..50 | ForEach-Object { Write-Output 'background'; [IO.File]::AppendAllText('${escaped}','x'); Start-Sleep -Milliseconds 100 }" & echo foreground-done`,
    );
    const elapsed = Date.now() - started;

    expect(result.stdout).toContain("foreground-done");
    expect(result.exitCode).toBe(0);
    expect(elapsed).toBeLessThan(2500);

    const settled = await waitForBytes(tick, 8000);
    expect(settled).toBeGreaterThan(0);
    await sleep(600);
    expect(sizeOf(tick)).toBeGreaterThan(settled);
    try {
      fs.rmSync(tick, { force: true });
    } catch {
      // The survivor is still appending; leaving a temp file behind is fine.
    }
  }, 30_000);

  it("relays a large burst written immediately before exit", async () => {
    const marker = "BURST-END";
    const bytes = 8192 * 32;
    const result = await run(
      `powershell.exe -NoProfile -NonInteractive -Command "$block = 'x' * 8192; 1..32 | ForEach-Object { [Console]::Out.Write($block) }; [Console]::Out.Write('${marker}')"`,
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout.endsWith(marker)).toBe(true);
    expect(result.stdout.length).toBe(bytes + marker.length);
  }, 30_000);

  it("kill terminates the launcher, shell, and writing grandchild", async () => {
    const tick = path.join(os.tmpdir(), `aic-win-tree-${Date.now()}.txt`);
    const escaped = tick.replace(/'/g, "''");
    await new Promise<void>((resolve, reject) => {
      const running = executeCommand(
        `powershell.exe -NoProfile -NonInteractive -Command "while ($true) {[IO.File]::AppendAllText('${escaped}','x'); Start-Sleep -Milliseconds 50}"`,
        undefined, undefined,
        {
          onOutput: () => {},
          onDone: () => resolve(),
          onError: (error) => reject(new Error(error)),
        },
        { windowsExecLauncherPath: launcher },
      );
      const poll = setInterval(() => {
        if (fs.existsSync(tick) && fs.statSync(tick).size > 0) {
          clearInterval(poll);
          running.kill();
        }
      }, 25);
    });
    const settledSize = fs.statSync(tick).size;
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(fs.statSync(tick).size).toBe(settledSize);
    fs.rmSync(tick, { force: true });
  }, 15_000);
});
