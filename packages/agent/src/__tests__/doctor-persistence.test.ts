// Autostart: does the thing that starts us at boot point at something that
// exists?
//
// PLATFORM NOTE. The failure this guards (PLAN-av-hardening §2 W7) is a Windows
// one — a Relaunch task and a Run value with a path baked into them at
// registration time — and the package's Windows CI job is deliberately narrow.
// So the Windows branch is driven on POSIX: `process.platform` is pinned before
// the dynamic import, and the OS queries are answered by a stand-in for
// `runCapture` so the REAL parsers in windows.ts are the code under test.

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Stage a command that NEVER RAN, as opposed to one that ran and printed
 * nothing. `runCapture` could not tell the two apart, which is how "reg.exe is
 * blocked here" came to be published as "no autostart entry, which is normal".
 */
const UNAVAILABLE = "\u0000never-ran";

/**
 * Stage a command KILLED AT ITS DEADLINE having already flushed some bytes —
 * prefix the staged answer with this and the rest is what reached us before the
 * kill. `Get-ScheduledTask` cold-loading its CIM module under an AV scan is that
 * case on every slow box, and the `QUERIED=1` it printed first is an answer.
 */
const TIMED_OUT = "\u0000timed-out:";

/** What the staged OS answers with, keyed by the program we shelled out to. */
const shell = vi.hoisted(() => ({
  reg: "",
  /** Answer for the Relaunch task query (and any other PowerShell script). */
  powershell: "",
  /** Answer for the Update task query, which has its own action shape. */
  updateTask: null as string | null,
  launchctl: "",
  calls: [] as Array<{ command: string; args: string[] }>,
}));

// The doctor's command seam is capture.ts's `runCaptured`, not
// installed-version.ts's `runCapture`: a single string could not separate "the
// command ran and printed nothing" from "the command never ran", and three
// checks rounded the second into a verdict about the machine. Staging the
// tri-state here is what lets those two shapes be tested apart.
vi.mock("../capture.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../capture.js")>();
  return {
    ...actual,
    runCaptured: async (
      command: string,
      args: string[],
    ): Promise<import("../capture.js").Captured> => {
      shell.calls.push({ command, args });
      const ran = (stdout: string): import("../capture.js").Captured => {
        if (stdout === UNAVAILABLE) {
          return { kind: "unavailable", reason: "staged: the command never ran", partialStdout: "" };
        }
        if (stdout.startsWith(TIMED_OUT)) {
          return {
            kind: "unavailable",
            reason: "staged: it was stopped at its deadline",
            partialStdout: stdout.slice(TIMED_OUT.length),
          };
        }
        return { kind: "output", stdout };
      };
      if (/reg\.exe$/i.test(command)) return ran(shell.reg);
      if (/launchctl$/.test(command)) return ran(shell.launchctl);
      if (/powershell\.exe$/i.test(command)) {
        // The task name is a literal in the script, so the two task queries are
        // told apart the same way Windows tells them apart.
        const script = args.join(" ");
        if (shell.updateTask !== null && script.includes("AI Commander Update")) {
          return ran(shell.updateTask);
        }
        return ran(shell.powershell);
      }
      return { kind: "output", stdout: "" };
    },
  };
});

// ONE seam, because there is now ONE query. The scheduled-task question is the
// RUNTIME's (windows-scheduled-task.ts, which elevated-availability.ts also
// calls) and the doctor re-exports it; it takes a 25 s deadline of its own but
// runs on the same capture.ts primitive as everything else the doctor shells out
// to, which is what lets a killed query still report the `QUERIED=1` it flushed.

type PersistenceModule = typeof import("../doctor/checks/persistence.js");
let persistence: PersistenceModule;
let windows: typeof import("../doctor/checks/windows.js");
const realPlatform = process.platform;

beforeAll(async () => {
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  persistence = await import("../doctor/checks/persistence.js");
  windows = await import("../doctor/checks/windows.js");
});

afterAll(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

let tmp: string;
let realExe: string;

beforeEach(() => {
  shell.reg = "";
  shell.powershell = "";
  shell.updateTask = null;
  shell.launchctl = "";
  shell.calls = [];
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-persist-"));
  realExe = path.join(tmp, "AICommander.exe");
  fs.writeFileSync(realExe, "exe");
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

/**
 * The context, with `resourcesPath` deciding whether this is a PACKAGED install.
 * On a packaged install the scheduled tasks are the installer's and their
 * absence is a fault; on the headless agent they are not supposed to exist.
 */
const ctx = (overrides: { resourcesPath?: string } = {}) => ({
  serverUrl: "https://relay.invalid",
  offline: true,
  networkTimeoutMs: 100,
  probeDelayMs: 0,
  ...overrides,
});

function runKeyDump(data: string): string {
  return [
    "",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "    OneDrive    REG_SZ    C:\\Users\\x\\OneDrive.exe /background",
    `    electron.app.AI Commander    REG_SZ    ${data}`,
    "",
  ].join("\r\n");
}

/** The Relaunch task's shape: `Start-Process -FilePath '<exe>'`. */
function taskDump(pinned: string): string {
  return [
    "QUERIED=1",
    "STATE=Ready",
    "EXECUTE=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    `ARGS=-NoProfile -Command "Start-Process -FilePath '${pinned}'"`,
  ].join("\r\n");
}

/** The Update task's shape: `-File "<win-updater.ps1>"`. A DIFFERENT switch. */
function updateTaskDump(pinned: string): string {
  return [
    "QUERIED=1",
    "STATE=Ready",
    "EXECUTE=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    `ARGS=-NoProfile -ExecutionPolicy Bypass -File "${pinned}"`,
  ].join("\r\n");
}

describe("windows autostart parsing", () => {
  it("finds the Run value by its DATA, not by a mirrored value name", () => {
    // The value name comes from Electron's app user model id and the install
    // path from a different source; there is no one constant that is right for
    // both, and mirroring the wrong one has silently killed this check before.
    const values = windows.parseRegValues(runKeyDump('"C:\\Program Files\\AI Commander\\AICommander.exe"'));
    expect(values.map((v) => v.name)).toContain("electron.app.AI Commander");
    expect(windows.extractExecutablePath(values[1]!.data)).toBe(
      "C:\\Program Files\\AI Commander\\AICommander.exe",
    );
  });

  it("takes the LAST -FilePath out of a task's arguments", () => {
    const args = "-Command \"Start-Process -FilePath 'C:\\a.exe'; Start-Process -FilePath 'C:\\b.exe'\"";
    expect(windows.parsePinnedFilePath(args)).toBe("C:\\b.exe");
  });

  it("reads the Update task's -File shape too, which was never being checked", () => {
    // win-update-task.ps1 registers the Relaunch task with `-FilePath '<exe>'`
    // and the Update task with `-File "<script>"`. Reading only the first shape
    // left the Update task's pinned path — baked in at registration time from
    // the same install directory — unverified on every machine.
    const args = '-NoProfile -ExecutionPolicy Bypass -File "C:\\Program Files\\AI Commander\\win-updater.ps1"';
    expect(windows.parsePinnedFilePath(args)).toBe("C:\\Program Files\\AI Commander\\win-updater.ps1");
  });

  it("does not mistake -FilePath for -File", () => {
    expect(windows.parsePinnedFilePath("-FilePath 'C:\\a.exe'")).toBe("C:\\a.exe");
  });
});

describe("one scheduled-task query, not two", () => {
  it("re-exports the RUNTIME's query rather than keeping a doctor copy of it", async () => {
    // Two implementations of one question is how the `queried` sentinel came to
    // be computed and then ignored. The runtime may not import from `doctor/`
    // (elevated-availability.ts's fail-closed rule), so the shared module owns
    // this and the doctor borrows it — identity is the only assertion that
    // cannot be satisfied by a second copy that merely looks the same.
    const shared = await import("../windows-scheduled-task.js");
    expect(windows.queryScheduledTask).toBe(shared.queryScheduledTask);
    expect(windows.powerShellPath).toBe(shared.powerShellPath);
    // And the deadline the doctor inherits is the long one: Get-ScheduledTask
    // cold-loads a CIM module, which on an AV-scanned box outruns 5 s routinely.
    expect(windows.SCHEDULED_TASK_QUERY_TIMEOUT_MS).toBeGreaterThan(20_000);
  });

  it("reads a TRUNCATED answer as 'we asked' when the LOOKUP had returned", async () => {
    // The doctor's old copy discarded stdout whenever the command did not exit
    // 0, so a query killed at its deadline read as "we never asked" and the
    // check went `skipped` — on exactly the slow machine this command exists
    // for. The shared module keeps the partial bytes, so a lookup that returned
    // before the clock ran out still counts as Windows having answered.
    shell.reg = "";
    // Staged as the real failure: KILLED at the deadline, but `ANSWERED=1` was
    // already on the pipe, so Windows had answered and had not named the task.
    // If the merged query ever stops keeping those bytes, `queried` goes false
    // and this check goes back to `skipped`.
    shell.powershell = `${TIMED_OUT}QUERIED=1\r\nADMIN=1\r\nANSWERED=1`;
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    const relaunch = results.find((r) => r.id === "persistence.relaunch_task")!;
    expect(relaunch.verdict).toBe("fail");
    expect(relaunch.verdict).not.toBe("skipped");
  });

  it("SKIPS when the process died with only the start sentinel on the pipe", async () => {
    // The complement, and the bug this pair exists to keep out: `QUERIED=1` is
    // printed before the lookup, so alone it proves PowerShell started and
    // nothing more. Reading it as an answer told the operator the Relaunch task
    // is not registered on the strength of a query that never returned.
    shell.reg = "";
    shell.powershell = `${TIMED_OUT}QUERIED=1\r\nADMIN=1`;
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    const relaunch = results.find((r) => r.id === "persistence.relaunch_task")!;
    expect(relaunch.verdict).toBe("skipped");
    expect(relaunch.verdict).not.toBe("fail");
  });
});

describe("windows autostart checks", () => {
  it("passes when the Run value and the tasks all point at files that exist", async () => {
    shell.reg = runKeyDump(`"${realExe}"`);
    shell.powershell = taskDump(realExe);
    shell.updateTask = updateTaskDump(realExe);
    const results = await persistence.persistenceChecks.run(ctx());
    const verdicts = Object.fromEntries(results.map((r) => [r.id, r.verdict]));
    expect(verdicts["persistence.run_key"]).toBe("ok");
    expect(verdicts["persistence.relaunch_task"]).toBe("ok");
    expect(verdicts["persistence.update_task"]).toBe("ok");
  });

  it("fails on a STALE pinned path — the defect that made a recovery invisible", async () => {
    const gone = path.join(tmp, "old", "AICommander.exe");
    shell.reg = runKeyDump(`"${gone}"`);
    shell.powershell = taskDump(gone);
    const results = await persistence.persistenceChecks.run(ctx());
    const runKey = results.find((r) => r.id === "persistence.run_key")!;
    const task = results.find((r) => r.id === "persistence.relaunch_task")!;

    expect(runKey.verdict).toBe("fail");
    expect(runKey.facts?.["target"]).toBe(gone);
    expect(task.verdict).toBe("fail");
    expect(task.facts?.["pinnedPath"]).toBe(gone);
    // Detect and report. The remedy is the installer, never a self-repair:
    // re-pointing an admin-owned task at a path discovered from user-writable
    // state is the privilege escalation the design exists to prevent.
    expect(task.remedy).toMatch(/Re-run the installer/);
    expect(task.remedy).toMatch(/not edit the entry by hand/i);
  });

  it("checks the UPDATE task's pinned path, which uses a different switch", async () => {
    const gone = path.join(tmp, "old", "win-updater.ps1");
    shell.powershell = taskDump(realExe);
    shell.updateTask = updateTaskDump(gone);
    const results = await persistence.persistenceChecks.run(ctx());
    const update = results.find((r) => r.id === "persistence.update_task")!;
    expect(update.verdict).toBe("fail");
    expect(update.facts?.["pinnedPath"]).toBe(gone);
  });

  it("says the path was NOT verified when a task's action is a shape we do not know", async () => {
    // Registered is good news; "registered, and we could not read what it
    // starts" is not the same statement as "registered and healthy".
    shell.powershell = ["QUERIED=1", "STATE=Ready", "ARGS=-Command Write-Host hi"].join("\r\n");
    const task = (await persistence.persistenceChecks.run(ctx())).find(
      (r) => r.id === "persistence.relaunch_task",
    )!;
    expect(task.verdict).toBe("warn");
    expect(task.detail).toMatch(/NOT verified/);
  });

  it("skips, rather than failing, when there is no entry at all on the headless agent", async () => {
    shell.reg = "";
    shell.powershell = "QUERIED=1"; // Asked, and there is no such task.
    const results = await persistence.persistenceChecks.run(ctx());
    expect(results.every((r) => r.verdict === "skipped")).toBe(true);
    expect(results.find((r) => r.id === "persistence.run_key")!.detail).toMatch(/headless agent/);
  });

  it("does NOT call an unrun reg.exe an absent Run value", async () => {
    // The regression: `regQuery` answered `[]` both for "the Run key holds
    // nothing of ours" and for "reg.exe never ran" (spawn failure, non-zero
    // exit, timeout, AppLocker), and the check then stated as FACT that there
    // is no AI Commander value under HKCU\…\Run and called it normal. The
    // scheduled-task path got the QUERIED sentinel for exactly this; the Run
    // key had no equivalent until capture.ts gave every command one.
    shell.reg = UNAVAILABLE;
    shell.powershell = "QUERIED=1";
    const results = await persistence.persistenceChecks.run(ctx());
    const runKey = results.find((r) => r.id === "persistence.run_key")!;
    expect(runKey.verdict).toBe("skipped");
    expect(runKey.detail).toMatch(/could not be determined/);
    expect(runKey.detail).not.toMatch(/Normal for the headless agent/);
  });

  it("still calls an ANSWERED, empty Run key normal", async () => {
    // The other half of the same distinction: reg.exe ran, printed the key's
    // own header and nothing of ours. That IS evidence, and it is not a fault.
    shell.reg = [
      "",
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "    OneDrive    REG_SZ    C:\\Users\\x\\OneDrive.exe /background",
      "",
    ].join("\r\n");
    shell.powershell = "QUERIED=1";
    const runKey = (await persistence.persistenceChecks.run(ctx())).find(
      (r) => r.id === "persistence.run_key",
    )!;
    expect(runKey.verdict).toBe("skipped");
    expect(runKey.detail).toMatch(/Normal for the headless agent/);
  });

  it("FAILS a missing task on a packaged install, where the installer registers both", async () => {
    // The tray runs the same library. Reporting "normal for a headless agent"
    // there hid the W7 state: nothing starts the app at boot and nothing
    // updates it, silently.
    shell.reg = "";
    shell.powershell = "QUERIED=1\r\nADMIN=1";
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    const relaunch = results.find((r) => r.id === "persistence.relaunch_task")!;
    const update = results.find((r) => r.id === "persistence.update_task")!;
    expect(relaunch.verdict).toBe("fail");
    expect(relaunch.detail).toMatch(/starts the app at boot/);
    expect(update.verdict).toBe("fail");
    expect(update.detail).toMatch(/installs updates/);
  });

  it("does not accuse a NON-ELEVATED run over a task its ACL hides from it", async () => {
    // The Relaunch task's SDDL grants SYSTEM and Administrators only, so a
    // standard-user tray is REFUSED the read — and the refusal now arrives as
    // such (`DENIED=1`, HRESULT 0x80070005 from the Task Scheduler COM API)
    // instead of masquerading as "there is no such task". This is the shape that
    // replaced the old `QUERIED=1/ADMIN=0` pin: the script cannot produce that one
    // for a hidden task any more, so pinning it tested nothing.
    //
    // The verdict is a WARN, deliberately, and not a `skipped`: a refusal is
    // Windows confirming the task EXISTS, and what the check could not do is read
    // the path it starts. Reporting that as "could not be determined" would drop
    // a real shortfall of the report on every unelevated packaged install.
    shell.reg = "";
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    // The Update task grants Users GR/GX, so the same account gets a real answer
    // for it — and its absence IS evidence. The two must not be collapsed.
    shell.updateTask = "QUERIED=1\r\nADMIN=0\r\nABSENT=1\r\nANSWERED=1";
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    const relaunch = results.find((r) => r.id === "persistence.relaunch_task")!;
    expect(relaunch.verdict).toBe("warn");
    expect(relaunch.detail).toMatch(/IS registered/);
    expect(relaunch.detail).not.toMatch(/not registered/);
    expect(relaunch.detail).not.toMatch(/could not be determined/);
    // THE SHARED CLAUSE, verbatim from the module that measures the refusal.
    // priv-helper.ts asserts the same string for the same marker: the two checks
    // once described this one fact in opposite words — "IS registered" here,
    // "could not be determined" there — and pinning the clause in both suites is
    // what fails if either is reworded on its own.
    expect(relaunch.detail).toContain(windows.DENIAL_PROVES_TASK_EXISTS);
    expect(relaunch.remedy).toMatch(/elevated prompt/);
    expect(results.find((r) => r.id === "persistence.update_task")!.verdict).toBe("fail");
  });

  it("says the true thing about EACH task's ACL, which are not the same ACL", async () => {
    // Both tasks got one sentence — "Its ACL grants Administrators only, by
    // design" — which is the Relaunch task's SDDL. The Update task's grants
    // Users GR/GX, so for IT a refusal is not by design at all: it means the ACL
    // has drifted from what the installer set, and telling the reader it was
    // intentional buries exactly that.
    shell.reg = "";
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    shell.updateTask = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    const relaunch = results.find((r) => r.id === "persistence.relaunch_task")!;
    const update = results.find((r) => r.id === "persistence.update_task")!;
    expect(relaunch.verdict).toBe("warn");
    expect(relaunch.remedy).toMatch(/by design/);
    expect(update.verdict).toBe("warn");
    expect(update.remedy).toMatch(/unexpected/);
    expect(update.remedy).toMatch(/no longer matches what was shipped/);
    expect(update.remedy).not.toMatch(/by design/);
  });

  it("does not warn the HEADLESS agent about two tasks it never registers", async () => {
    // A headless npm agent on a machine that also carries the desktop install is
    // refused the read for both of the installer's tasks. The refusal branch used
    // to return before the packaged-install gate, so it warned that "the path it
    // starts at boot was not verified" — about someone else's install. The gate
    // comes first now, as it always did for an absent task.
    shell.reg = "";
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    shell.updateTask = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    const results = await persistence.persistenceChecks.run(ctx());
    for (const id of ["persistence.relaunch_task", "persistence.update_task"]) {
      const task = results.find((r) => r.id === id)!;
      expect(task.verdict).toBe("skipped");
      expect(task.detail).toMatch(/headless agent/);
      expect(task.detail).not.toMatch(/NOT verified/);
      expect(task.remedy).toBeUndefined();
    }
  });

  it("SKIPS — never warns about an ACL — when the lookup broke rather than being refused", async () => {
    // The other half of the same branch, and the reason it branches at all. A
    // blocked `Schedule.Service`, a ConstrainedLanguage host or a killed query
    // learned NOTHING about the task, so neither "it is registered" nor the
    // elevation remedy may be printed for it.
    shell.reg = "";
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nLOOKUPFAIL=ComConnect";
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    for (const id of ["persistence.relaunch_task", "persistence.update_task"]) {
      const task = results.find((r) => r.id === id)!;
      expect(task.verdict).toBe("skipped");
      expect(task.detail).toMatch(/could not be determined/);
      expect(task.detail).not.toMatch(/ACL|elevated/i);
    }
  });

  it("FAILS a task Windows positively says is absent, whichever ACL it would have had", async () => {
    // The Relaunch task used to be exempted from a failure BY NAME, because a
    // refusal was indistinguishable from an absence. `ABSENT=1` is the COM API's
    // 0x80070002 — the task is not in the root folder — and hedging that is how
    // the W7 state stayed hidden in the first place.
    shell.reg = "";
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nABSENT=1\r\nANSWERED=1";
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    const relaunch = results.find((r) => r.id === "persistence.relaunch_task")!;
    expect(relaunch.verdict).toBe("fail");
    expect(relaunch.detail).toMatch(/is not registered on a packaged install/);
  });

  it("does NOT accuse a machine whose PowerShell query never ran", async () => {
    // No sentinel: the query did not run at all (no PowerShell, a policy block,
    // a timeout). Even on a packaged install that is a statement about the
    // diagnostic, not about the machine.
    shell.reg = "";
    shell.powershell = "";
    const results = await persistence.persistenceChecks.run(ctx({ resourcesPath: tmp }));
    for (const id of ["persistence.relaunch_task", "persistence.update_task"]) {
      const task = results.find((r) => r.id === id)!;
      expect(task.verdict).toBe("skipped");
      expect(task.detail).toMatch(/could not be determined/);
    }
  });

  it("gives every matching Run value its OWN id, so a stale leftover is not dropped", async () => {
    const gone = path.join(tmp, "old", "AICommander.exe");
    shell.reg = [
      "",
      "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      `    electron.app.AI Commander    REG_SZ    "${realExe}"`,
      `    AI Commander    REG_SZ    "${gone}"`,
      "",
    ].join("\r\n");
    shell.powershell = "QUERIED=1";
    const results = await persistence.persistenceChecks.run(ctx());
    const runKeys = results.filter((r) => r.id.startsWith("persistence.run_key"));
    expect(runKeys).toHaveLength(2);
    // Two results sharing one id are silently deduplicated by any consumer keyed
    // on the id — and the one that would be dropped is the stale one.
    expect(new Set(runKeys.map((r) => r.id)).size).toBe(2);
    expect(runKeys.some((r) => r.verdict === "fail")).toBe(true);
  });

  it("keeps the Run value's COMMAND LINE out of the report, and the path in", async () => {
    // The bundle promises an antivirus vendor it carries no command text, and
    // redactDiagText does not remove ordinary arguments — so the enforcement is
    // that the fact is never built from them.
    shell.reg = runKeyDump(`"${realExe}" --hidden --profile=finance-team`);
    shell.powershell = "QUERIED=1";
    const runKey = (await persistence.persistenceChecks.run(ctx())).find(
      (r) => r.id === "persistence.run_key",
    )!;
    expect(JSON.stringify(runKey)).not.toContain("--profile=finance-team");
    expect(runKey.facts?.["target"]).toBe(realExe);
  });
});

// The branch is chosen inside run(), not at module load, so switching
// process.platform between calls is enough here — no second import.
describe("linux autostart checks", () => {
  it("reads the unit's ExecStart and reports a path that no longer exists", async () => {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    const gone = path.join(tmp, "missing", "agent.js");
    // Asynchronous, like every filesystem call in these checks: the tray runs
    // them on Electron's main loop.
    const readFile = vi.spyOn(fs.promises, "readFile").mockImplementation((async (target: string) => {
      if (String(target).endsWith("aicommander-agent.service")) {
        return `[Service]\nExecStart="/usr/bin/node" "${gone}"\n`;
      }
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    }) as unknown as typeof fs.promises.readFile);
    try {
      const [result] = await persistence.persistenceChecks.run(ctx());
      expect(result!.id).toBe("persistence.systemd");
      expect(result!.verdict).toBe("fail");
      expect(result!.detail).toContain(gone);
      // The paths are the diagnostic; the ExecStart LINE they came from is
      // command text and never reaches the bundle.
      expect(JSON.stringify(result)).not.toContain("ExecStart=");
    } finally {
      readFile.mockRestore();
      Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    }
  });

  it("skips when no unit is installed", async () => {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    const readFile = vi.spyOn(fs.promises, "readFile").mockImplementation((async () => {
      throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
    }) as unknown as typeof fs.promises.readFile);
    try {
      const [result] = await persistence.persistenceChecks.run(ctx());
      expect(result!.verdict).toBe("skipped");
    } finally {
      readFile.mockRestore();
      Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    }
  });
});
