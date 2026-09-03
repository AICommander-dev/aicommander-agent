// The ONE scheduled-task query, and the two properties it may never lose.
//
// It was briefly two implementations — the runtime's and the doctor's — fenced
// apart from each other, and each ended up holding half of the answer: the
// runtime's kept the partial output a killed `Get-ScheduledTask` had already
// flushed, the doctor's kept the tri-state that tells "the OS said no" from "I
// could not ask the OS". Merging them is only worth anything if BOTH halves
// survive, so both are pinned here, at the seam where losing one is silent.
//
// PLATFORM NOTE. Driven on POSIX: `queryScheduledTask` is exercised through a
// staged `runCaptured`, and the capture primitive itself is exercised against a
// REAL /bin/sh, so the timeout path is measured rather than described.

import { describe, it, expect, beforeEach, vi } from "vitest";

type Captured = import("../capture.js").Captured;

const staged = vi.hoisted(() => ({ captured: { kind: "output", stdout: "" } as Captured }));

vi.mock("../capture.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../capture.js")>();
  return { ...actual, runCaptured: async (): Promise<Captured> => staged.captured };
});

const { queryScheduledTask, SCHEDULED_TASK_QUERY_TIMEOUT_MS } = await import(
  "../windows-scheduled-task.js"
);
// The REAL primitive, not the staged one: the timeout below has to be measured
// against a real child process, which is the only way to know the bytes it
// printed first actually reach us.
const { runCaptured, capturedStdout } = await vi.importActual<typeof import("../capture.js")>(
  "../capture.js",
);

beforeEach(() => {
  staged.captured = { kind: "output", stdout: "" };
});

describe("partial output survives the deadline", () => {
  it("reads a killed run whose LOOKUP RETURNED as answered, on the bytes it had flushed", async () => {
    // THE PIN. The CIM cold-load is what outruns the clock on an AV-scanned box,
    // and a lookup that returned before the rest of the script did has already
    // put `ANSWERED=1` on the pipe. Discard those bytes and this comes back
    // `queried: false` — "we never asked" — and the machine publishes
    // `endpoint_unreachable` forever instead of `not_registered`, the one verdict
    // the 2026-09-02 incident machine could never produce.
    staged.captured = {
      kind: "unavailable",
      reason: "powershell.exe did not answer within 25000 ms and was stopped",
      partialStdout: "QUERIED=1\r\nADMIN=1\r\nANSWERED=1\r\n",
    };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(true);
    if (!info.queried) throw new Error("unreachable");
    expect(info.registered).toBe(false);
    expect(info.elevated).toBe(true);
  });

  it("does NOT read the start sentinel alone as an answer when the process was killed", async () => {
    // The other half, and the reason `ANSWERED=1` exists. `QUERIED=1` is printed
    // BEFORE the lookup, so on its own it proves only that PowerShell started.
    // Reading it as an answer turned "the query never returned" into the
    // definite, alarming "the task is not registered" — a verdict from a question
    // that was never answered, in the module written to keep those apart.
    staged.captured = {
      kind: "unavailable",
      reason: "powershell.exe did not answer within 25000 ms and was stopped",
      partialStdout: "QUERIED=1\r\nADMIN=1\r\n",
    };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/never returned/i);
  });

  it("keeps the bytes a real process printed before it was stopped", async () => {
    // The same property one level down, against a real child: without it the
    // sentinel never reaches the parser in the first place.
    const captured = await runCaptured("/bin/sh", ["-c", "echo QUERIED=1; sleep 30"], {
      timeoutMs: 300,
    });
    expect(captured.kind).toBe("unavailable");
    expect(capturedStdout(captured)).toContain("QUERIED=1");
  });

  it("still says 'we could not ask' when nothing was flushed", async () => {
    // The other side of the same rule: partial output is only an answer when it
    // CONTAINS one. An empty kill is still a statement about the diagnostic.
    staged.captured = {
      kind: "unavailable",
      reason: "powershell.exe could not be started: ENOENT",
      partialStdout: "",
    };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/ENOENT/);
  });

  it("gives the query its own long deadline", async () => {
    // Get-ScheduledTask cold-loads a CIM module; 5 s is capture.ts's budget for
    // a probe a user is waiting on, not for this one.
    expect(SCHEDULED_TASK_QUERY_TIMEOUT_MS).toBeGreaterThan(20_000);
  });
});

describe("the answer is a tri-state, not a boolean", () => {
  it("offers no `registered` at all until `queried` has been established", async () => {
    // THE PIN. Three bugs came out of one flat shape carrying both fields: a
    // caller read `registered: false` and published "the task is absent" about a
    // machine it had never managed to ask. The union makes that unwritable —
    // `registered` does not exist on the unanswered branch — so a collapse back
    // to `{ registered: boolean; queried: boolean }` fails to compile here as
    // well as failing the assertion below.
    staged.captured = { kind: "unavailable", reason: "staged", partialStdout: "" };
    const info = await queryScheduledTask("AI Commander Relaunch");
    // @ts-expect-error — "is it registered" is not readable without narrowing.
    void info.registered;
    expect("registered" in info).toBe(false);
    expect(info).toEqual({ queried: false, reason: "staged" });
  });

  it("separates 'Windows named the task' from 'Windows did not'", async () => {
    staged.captured = {
      kind: "output",
      stdout: "QUERIED=1\r\nADMIN=0\r\nSTATE=Ready\r\nEXECUTE=powershell.exe\r\nARGS=-File x.ps1\r\n",
    };
    const present = await queryScheduledTask("AI Commander Relaunch");
    expect(present).toEqual({
      queried: true,
      registered: true,
      elevated: false,
      state: "Ready",
      execute: "powershell.exe",
      args: "-File x.ps1",
    });

    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=0\r\n" };
    const absent = await queryScheduledTask("AI Commander Relaunch");
    expect(absent.queried).toBe(true);
    if (!absent.queried) throw new Error("unreachable");
    expect(absent.registered).toBe(false);
  });

  it("does not turn a PowerShell that ran and said nothing into 'no such task'", async () => {
    // ConstrainedLanguage, a wedged profile, a script host that swallowed the
    // output: exit 0 and an empty pipe. It is not evidence about the machine.
    staged.captured = { kind: "output", stdout: "" };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/printed no answer/);
  });

  it("reports a non-zero exit that said nothing as unanswered, with the status", async () => {
    staged.captured = { kind: "failed", stdout: "", code: 1, signal: null };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/status 1/);
  });
});
