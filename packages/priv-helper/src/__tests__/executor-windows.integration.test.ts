import {
  copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { ElevatedCapabilityClaims } from "@aicommander/protocol";
import { createPrivilegedExecutor } from "../executor.js";
import type { RunningPrivilegedCommand } from "../types.js";

const describeOnWindows = describe.runIf(process.platform === "win32");
const packageRoot = fileURLToPath(new URL("../..", import.meta.url));
const builtLauncher = join(
  packageRoot, "..", "agent", "dist-native", "aicommander-win-exec-x64.exe",
);
const builtHelper = join(packageRoot, "dist-bin", "aicommander-priv-helper.exe");
const registrar = join(
  packageRoot, "..", "desktop", "build", "win-privhelper-task.ps1",
);
const probe = join(
  packageRoot, "..", "agent", "dist-native", "test", "aic-console-probe.exe",
);
let runtimeDir = "";
let launcher = "";
const originalExecPath = process.execPath;
const HARNESS_WATCHDOG_MS = 12_000;

interface ActiveTestCommand {
  running: RunningPrivilegedCommand;
  closed: Promise<void>;
}
const activeCommands = new Set<ActiveTestCommand>();

function claims(command: string, timeoutMs = 10_000): ElevatedCapabilityClaims {
  return {
    protocolVersion: 1,
    accountId: "runtime-test",
    requestId: `runtime-${Date.now()}`,
    timeoutMs,
    issuedAt: 0,
    expiresAt: 0,
    command,
  };
}

function run(command: string, timeoutMs = 10_000) {
  return new Promise<{
    stdout: Buffer;
    stderr: Buffer;
    exitCode?: number;
    errors: string[];
    closed: boolean;
    chunkTimes: number[];
  }>((resolve, reject) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const errors: string[] = [];
    const chunkTimes: number[] = [];
    let exitCode: number | undefined;
    let terminal = false;
    let closed = false;
    let finished = false;
    let harnessError: Error | null = null;
    let resolveClosed!: () => void;
    const closedPromise = new Promise<void>((done) => { resolveClosed = done; });
    let active!: ActiveTestCommand;
    const finish = () => {
      if (!terminal || !closed || finished) return;
      finished = true;
      clearTimeout(harnessWatchdog);
      if (harnessError) {
        reject(harnessError);
        return;
      }
      resolve({
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        ...(exitCode === undefined ? {} : { exitCode }),
        errors,
        closed: true,
        chunkTimes,
      });
    };
    const running = createPrivilegedExecutor({ allowUnprivileged: true }).run(
      claims(command, timeoutMs), {
        onOutput(data, stream) {
          chunkTimes.push(Date.now());
          (stream === "stdout" ? stdout : stderr).push(Buffer.from(data, "base64"));
        },
        onDone(code) { terminal = true; exitCode = code; finish(); },
        onError(error) { terminal = true; errors.push(error); finish(); },
        onClosed() {
          closed = true;
          activeCommands.delete(active);
          resolveClosed();
          finish();
        },
      },
    );
    active = { running, closed: closedPromise };
    activeCommands.add(active);
    // Vitest timing out a test does not cancel its child process. Reap first and
    // reject only after onClosed, so afterAll never races an executable still
    // mapped by Windows (the prior failure surfaced as EPERM during rmSync).
    const harnessWatchdog = setTimeout(() => {
      harnessError = new Error(
        `Windows runtime command did not close within ${HARNESS_WATCHDOG_MS}ms`,
      );
      running.kill({ hard: true });
    }, HARNESS_WATCHDOG_MS);
  });
}

async function reapActiveCommands(): Promise<void> {
  const pending = [...activeCommands];
  for (const command of pending) command.running.kill({ hard: true });
  await Promise.all(pending.map((command) => command.closed));
}

describeOnWindows("privileged helper Windows native UTF-8 executor", () => {
  beforeAll(() => {
    runtimeDir = mkdtempSync(join(tmpdir(), "aic-priv-launcher-runtime-"));
    const installedHelper = join(runtimeDir, "aicommander-priv-helper.exe");
    launcher = join(runtimeDir, "aicommander-win-exec-x64.exe");
    copyFileSync(builtHelper, installedHelper);
    copyFileSync(builtLauncher, launcher);
    const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
    const powershell = join(
      systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe",
    );
    execFileSync(powershell, [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy", "Bypass",
      "-File", registrar,
      "-WriteLauncherHashMarkerOnly",
      "-HelperDir", runtimeDir,
    ], { stdio: ["ignore", "pipe", "pipe"] });

    // Lock the persisted cross-language contract produced by the REAL registrar
    // function: exact suffix, 64 lower-case ASCII hex bytes, and no BOM/newline.
    const markerPath = `${launcher}.sha256`;
    expect(markerPath).toBe(join(
      runtimeDir, "aicommander-win-exec-x64.exe.sha256",
    ));
    const marker = readFileSync(markerPath);
    const markerText = marker.toString("utf8");
    expect(marker).toHaveLength(64);
    expect(markerText).toMatch(/^[0-9a-f]{64}$/);
    expect(marker.equals(Buffer.from(markerText, "ascii"))).toBe(true);
    expect(marker.subarray(0, 3)).not.toEqual(Buffer.from([0xef, 0xbb, 0xbf]));
    expect(marker.subarray(0, 2)).not.toEqual(Buffer.from([0xff, 0xfe]));
    // Match the real installation layout: executor production code derives the
    // launcher exclusively from dirname(process.execPath), with no path override.
    Object.defineProperty(process, "execPath", {
      value: installedHelper,
      configurable: true,
      writable: true,
    });
  });

  afterEach(async () => {
    await reapActiveCommands();
  }, 15_000);

  afterAll(async () => {
    await reapActiveCommands();
    Object.defineProperty(process, "execPath", {
      value: originalExecPath,
      configurable: true,
      writable: true,
    });
    rmSync(runtimeDir, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  });

  it("uses the shared launcher console boundary and preserves Unicode bytes per stream", async () => {
    const result = await run(JSON.stringify(probe));
    expect(result.exitCode).toBe(0);
    expect(result.errors).toEqual([]);
    expect(result.stdout.toString("utf8")).toContain("CP=65001;VISIBLE=0");
    expect(result.stdout.toString("utf8")).toContain("stdout=zażółć € 漢字");
    expect(result.stderr.toString("utf8")).toContain("stderr=Łódź Ж");
    expect(result.stdout.toString("utf8")).not.toContain("�");
    expect(result.stderr.toString("utf8")).not.toContain("�");
  });

  it("keeps cmd semantics, streams before exit, and reports the exact exit code", async () => {
    const result = await run(
      "echo first & ping.exe -n 2 127.0.0.1 >nul & echo zażółć & exit /b 37",
    );
    expect(result.exitCode).toBe(37);
    expect(result.stdout.toString("utf8")).toContain("first");
    expect(result.stdout.toString("utf8")).toContain("zażółć");
    expect(result.chunkTimes.length).toBeGreaterThanOrEqual(2);
    expect(result.chunkTimes.at(-1)! - result.chunkTimes[0]!).toBeGreaterThanOrEqual(300);
  }, 20_000);

  it("reports one timeout, kills the launcher tree, and closes the lease", async () => {
    const result = await run(
      'powershell.exe -NoProfile -NonInteractive -Command "while ($true) { Start-Sleep -Milliseconds 50 }"',
      1_000,
    );
    expect(result.exitCode).toBeUndefined();
    expect(result.errors).toEqual(["elevated command timed out after 1000ms"]);
    expect(result.closed).toBe(true);
  }, 15_000);

  it("kill stops a writing grandchild before releasing the lease", async () => {
    const tick = join(tmpdir(), `aic-priv-win-tree-${Date.now()}.txt`);
    const escaped = tick.replace(/'/g, "''");
    await new Promise<void>((resolve, reject) => {
      const running = createPrivilegedExecutor({ allowUnprivileged: true }).run(claims(
        `powershell.exe -NoProfile -NonInteractive -Command "while ($true) {[IO.File]::AppendAllText('${escaped}','x'); Start-Sleep -Milliseconds 50}"`,
      ), {
        onOutput() {},
        onDone() {},
        onError(error) { reject(new Error(error)); },
        onClosed: resolve,
      });
      const poll = setInterval(() => {
        if (existsSync(tick) && statSync(tick).size > 0) {
          clearInterval(poll);
          running.kill({ hard: true });
        }
      }, 25);
    });
    const settledSize = statSync(tick).size;
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(statSync(tick).size).toBe(settledSize);
    rmSync(tick, { force: true });
  }, 15_000);
});
