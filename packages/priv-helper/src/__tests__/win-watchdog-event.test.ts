// The out-of-band half of win-watchdog-logfile.ts: the Windows Application-log
// event that says file logging refused, when the log file itself cannot.
//
// The SEAM (a refusal reaches the reporter, once, with the right code) is tested
// in win-watchdog-log.test.ts, next to the refusals themselves. What is pinned
// HERE is the thing that seam hides: what would actually be RUN on a Windows box
// — which program, from where, with which arguments, and with what it is allowed
// to do to the helper if it goes wrong. child_process is mocked for exactly that
// reason: this suite runs on macOS, and the point is to inspect the invocation
// rather than to perform it.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import {
  __eventCommandScript,
  __windowsEventReport,
  WATCHDOG_EVENT_ID,
  WATCHDOG_EVENT_LEVEL,
  WATCHDOG_EVENT_SOURCE,
  type WatchdogLogDisableReason,
} from "../win-watchdog-logfile.js";

vi.mock("node:child_process", () => ({
  spawn: vi.fn(() => ({ on: vi.fn(), unref: vi.fn(), kill: vi.fn() })),
  spawnSync: vi.fn(),
}));

/** Every reason disable() can be given — the complete input domain. */
const REASONS: WatchdogLogDisableReason[] = [
  "chain-link",
  "chain-not-directory",
  "chain-owner",
  "owner-unknown",
  "create-failed",
  "open-failed",
  "write-failed",
];

/** The -EncodedCommand argument, back as text. */
function decodeScript(args: readonly string[]): string {
  const at = args.indexOf("-EncodedCommand");
  expect(at).toBeGreaterThanOrEqual(0);
  return Buffer.from(args[at + 1]!, "base64").toString("utf16le");
}

describe("the event this module would write, and only it", () => {
  it("uses eventcreate arguments the tool actually accepts", () => {
    // MEASURED as SYSTEM on aic-pc, 2026-08-09, exit code 0:
    //   eventcreate /L APPLICATION /SO AICommanderWatchdog /T WARNING /ID 900
    //               /D '<coded reason>'
    // /L takes APPLICATION or SYSTEM; /T takes SUCCESS|ERROR|WARNING|INFORMATION;
    // /ID must be 1-1000 — outside that range eventcreate rejects the call and
    // the refusal goes unreported, which is the whole failure being fixed.
    expect(WATCHDOG_EVENT_ID).toBeGreaterThanOrEqual(1);
    expect(WATCHDOG_EVENT_ID).toBeLessThanOrEqual(1000);
    expect(Number.isInteger(WATCHDOG_EVENT_ID)).toBe(true);
    expect(["SUCCESS", "ERROR", "WARNING", "INFORMATION"]).toContain(WATCHDOG_EVENT_LEVEL);
    // The source is created by eventcreate on first use (measured), so it is
    // only ever this literal — nothing derives it from anything observed.
    expect(WATCHDOG_EVENT_SOURCE).toMatch(/^[A-Za-z][A-Za-z0-9]{0,29}$/);

    const script = __eventCommandScript("chain-owner");
    expect(script).toContain("/L APPLICATION");
    expect(script).toContain(`/SO ${WATCHDOG_EVENT_SOURCE}`);
    expect(script).toContain(`/T ${WATCHDOG_EVENT_LEVEL}`);
    expect(script).toContain(`/ID ${WATCHDOG_EVENT_ID}`);
  });

  it("finds eventcreate.exe through the API, never through the environment", () => {
    // The helper's SYSTEM environment is stripped (measured: 12 variables), and
    // this module has been bitten by exactly that before — see the header's
    // ProfileImagePath note. %SystemRoot% read from the environment is therefore
    // not an acceptable source for a program we EXECUTE as LocalSystem.
    // GetFolderPath('System') IS the system directory (measured:
    // C:\WINDOWS\system32); GetFolderPath('Windows') would make us guess the
    // subdirectory name.
    const script = __eventCommandScript("chain-owner");
    expect(script).toContain("[System.Environment]::GetFolderPath('System')");
    expect(script).toContain("Join-Path $sys 'eventcreate.exe'");
    expect(script).not.toContain("$env:");
    expect(script).not.toContain("%SystemRoot%");
    expect(script).not.toContain("ExpandEnvironmentVariables");
    // Never a bare name: PATH is not ours to trust from LocalSystem.
    expect(script).not.toMatch(/[^\\'](eventcreate|EVENTCREATE)(?!\.exe)/);
  });

  it("varies by the coded reason and by nothing else", () => {
    const baseline = __eventCommandScript("chain-owner");
    for (const reason of REASONS) {
      const script = __eventCommandScript(reason);
      expect(script, reason).toContain(`reason=${reason}`);
      // Same fixed text throughout; the code is the only moving part.
      expect(script.replace(`reason=${reason}`, "reason=chain-owner"), reason).toBe(baseline);
    }
  });

  it("cannot be made to carry a path, a command line or a key", () => {
    // The Application log is world-readable, exactly like watchdog.log, so the
    // rule from win-watchdog-log.ts holds here too — and it is enforced by a
    // fixed SET, not by a shape: a code this module does not know becomes
    // 'unknown' rather than being escaped and passed along.
    const smuggled = [
      "C:\\Users\\victim\\AppData\\Roaming\\key.txt",
      "--connection-key=sk-live-0123456789",
      "chain-owner'; & calc.exe; '",
      "chain owner",
      "CHAIN-OWNER",
    ];
    for (const value of smuggled) {
      const script = __eventCommandScript(value as WatchdogLogDisableReason);
      expect(script, value).toContain("reason=unknown");
      expect(script, value).not.toContain(value);
      expect(script, value).toBe(
        __eventCommandScript("chain-owner").replace("reason=chain-owner", "reason=unknown"),
      );
    }
  });
});

describe("reporting a refusal cannot hurt the helper", () => {
  const realPlatform = process.platform;
  function setPlatform(value: NodeJS.Platform): void {
    Object.defineProperty(process, "platform", { value, configurable: true });
  }
  beforeEach(() => {
    vi.mocked(spawn).mockClear();
    vi.mocked(spawnSync).mockClear();
    vi.mocked(spawn).mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (() => ({ on: vi.fn(), unref: vi.fn(), kill: vi.fn() })) as any,
    );
  });
  afterEach(() => {
    setPlatform(realPlatform);
  });

  it("never runs anything off Windows", () => {
    // The reporter is Windows-only twice over: the caller decides at the same
    // seam as the owner lookup (win-watchdog-log.test.ts pins that), and the
    // reporter refuses to run anyway.
    for (const platform of ["darwin", "linux"] as NodeJS.Platform[]) {
      setPlatform(platform);
      __windowsEventReport("chain-owner");
    }
    expect(spawn).not.toHaveBeenCalled();
    expect(spawnSync).not.toHaveBeenCalled();
  });

  it("spawns powershell.exe by full path with the encoded script", () => {
    setPlatform("win32");
    __windowsEventReport("chain-owner");
    expect(spawn).toHaveBeenCalledTimes(1);
    const [program, args] = vi.mocked(spawn).mock.calls[0]!;
    expect(String(program)).toMatch(/\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$/);
    expect(args as string[]).toContain("-NoProfile");
    expect(args as string[]).toContain("-NonInteractive");
    expect(decodeScript(args as string[])).toBe(__eventCommandScript("chain-owner"));
  });

  it("does not BLOCK the tick, and gives the child a deadline it does not wait on", () => {
    // spawnSync here would stop the watchdog's event loop for a PowerShell cold
    // start on a failure path. Losing the event is acceptable; losing the tick
    // is not — so it is async, unref'd, stdio-less and bounded in time.
    //
    // THE DEADLINE IS NOT spawn's `timeout` OPTION, and this test exists because
    // it used to be. MEASURED on this machine (macOS, node v24.5.0):
    //   spawn("sh", ["-c", "sleep 30"], { stdio: "ignore", timeout: 3000 })
    //   with an "error" listener and child.unref() → the PARENT stayed alive
    //   3006 ms after its last work.
    // `unref()` does not cover the REF'd timer that option arms, so at
    // EVENT_REPORT_TIMEOUT_MS a stuck powershell.exe held the helper open for up
    // to 15 s at shutdown or restart. The deadline is therefore kept by hand,
    // unref'd, with an explicit kill; the same measurement re-run against the
    // real function is the last test in this file.
    setPlatform("win32");
    const child = { on: vi.fn(), unref: vi.fn(), kill: vi.fn() };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    vi.mocked(spawn).mockImplementation((() => child) as any);
    // The spy CALLS THROUGH — a faked timer would have neither hasRef() nor a
    // real handle, i.e. it would answer the question with its own mock.
    const timerSpy = vi.spyOn(globalThis, "setTimeout");
    let armed: { callback: () => void; timer: NodeJS.Timeout }[] = [];
    try {
      __windowsEventReport("chain-owner");
      // Read the spy BEFORE restoring it: mockRestore() drops the recorded
      // calls along with the implementation.
      armed = timerSpy.mock.calls.map((call, i) => ({
        callback: call[0] as () => void,
        timer: timerSpy.mock.results[i]!.value as NodeJS.Timeout,
      }));
    } finally {
      timerSpy.mockRestore();
    }
    expect(spawnSync).not.toHaveBeenCalled();
    const options = vi.mocked(spawn).mock.calls[0]![2] as Record<string, unknown>;
    // The option that held us open must not come back.
    expect(options).not.toHaveProperty("timeout");
    expect(options["windowsHide"]).toBe(true);
    expect(options["stdio"]).toBe("ignore");
    expect(child.unref).toHaveBeenCalled();
    // Exactly one hand-kept deadline, and it holds nothing: an unref'd timer is
    // not a reason for the event loop to stay alive.
    expect(armed).toHaveLength(1);
    const { timer: deadline, callback: onDeadline } = armed[0]!;
    expect(deadline.hasRef()).toBe(false);
    clearTimeout(deadline);
    // …and it is a deadline, not decoration: firing it kills the child.
    onDeadline();
    expect(child.kill).toHaveBeenCalled();
    // The child is also released when it exits on its own, so a helper that
    // lives for days does not accumulate one dead timer per refusal.
    expect(child.on).toHaveBeenCalledWith("exit", expect.any(Function));
    // An ENOENT arrives asynchronously, where no try/catch of ours can see it:
    // without a listener it is thrown at the process and kills the helper.
    expect(child.on).toHaveBeenCalledWith("error", expect.any(Function));
    const onError = child.on.mock.calls.find(([event]) => event === "error")![1] as (
      err: Error,
    ) => void;
    expect(() => onError(new Error("spawn ENOENT"))).not.toThrow();
  });

  it("swallows a spawn that fails outright", () => {
    setPlatform("win32");
    vi.mocked(spawn).mockImplementation(() => {
      throw new Error("EMFILE");
    });
    expect(() => __windowsEventReport("chain-owner")).not.toThrow();
  });
});
