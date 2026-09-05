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

const staged = vi.hoisted(() => ({
  captured: { kind: "output", stdout: "" } as Captured,
  /**
   * The generated PowerShell, kept rather than dropped on the floor.
   *
   * Staging `runCaptured`'s ANSWER tests the parser and nothing else: the script
   * itself — a single concatenated string with nested `if`/`else` braces — is
   * never looked at, so a misplaced brace or `else` would ship as "PowerShell
   * exits 1, prints nothing", i.e. a permanent `queried: false` on every Windows
   * box, with a green suite. The suite cannot RUN PowerShell here, so it pins the
   * script's structure instead, as packages/desktop's win-updater-script.test.ts
   * does for the updater.
   */
  argv: [] as string[],
}));

vi.mock("../capture.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../capture.js")>();
  return {
    ...actual,
    runCaptured: async (_command: string, args: string[]): Promise<Captured> => {
      staged.argv = args;
      return staged.captured;
    },
  };
});

const { queryScheduledTask, SCHEDULED_TASK_QUERY_TIMEOUT_MS, ROOT_FOLDER_TASKS } = await import(
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
  staged.argv = [];
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
    expect(info).toEqual({ queried: false, cause: "unavailable", reason: "staged" });
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

describe("a refused lookup is not an absence", () => {
  // The 2026-09-03 half of the same bug. `Get-ScheduledTask` throws
  // `ObjectNotFound` BOTH for a task that is not there and for a task whose ACL
  // denies the caller, and the script used to flatten every exception into
  // `$t = $null` and print `ANSWERED=1` anyway — so two of three live Windows
  // boxes reported a definite `registered: false` about a helper task that exists
  // and is RUNNING. The script now disambiguates through the Task Scheduler COM
  // API and prints a different marker for each; these pin what the parser does
  // with them.
  it("reads ABSENT+ANSWERED as Windows saying the task really is not there", async () => {
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=1\r\nABSENT=1\r\nANSWERED=1\r\n" };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    expect(info.queried).toBe(true);
    if (!info.queried) throw new Error("unreachable");
    expect(info.registered).toBe(false);
  });

  it("reads DENIED as 'we could not ask', in words that never suggest absence", async () => {
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=0\r\nDENIED=1\r\n" };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/denied access to "AI Commander Privileged Helper"/);
    expect(info.reason).toMatch(/the task exists/);
    expect(info.reason).not.toMatch(/not registered|no such task|absent/i);
  });

  it("reads a non-ObjectNotFound failure as 'we could not ask', naming the category", async () => {
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=1\r\nLOOKUPFAIL=ConnectionError\r\n" };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/lookup failed: ConnectionError/);
  });

  it("reads an unusable COM discriminator as 'we could not ask', naming the HRESULT", async () => {
    // `Schedule.Service` blocked, or an HRESULT that is neither 0x80070002 nor
    // 0x80070005. Not knowing which of the two it was is exactly the state that
    // may not become an answer.
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nLOOKUPFAIL=80070422\r\n" };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.reason).toMatch(/lookup failed: 80070422/);
  });

  it("lets a refusal marker outrank a clean exit carrying the start sentinel", async () => {
    // THE TRAP, and it is one line of ordering. A denied run exits 0 with
    // `QUERIED=1` on the pipe, which satisfies `answered`'s third clause ("it ran
    // to completion, so the sentinel bounds the whole script") — read in that
    // order, the fix above would be undone by the parser below it and the denial
    // would come back as `registered: false` all over again. DENIED and
    // LOOKUPFAIL must return before that expression is ever evaluated.
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=0\r\nDENIED=1\r\n" };
    const denied = await queryScheduledTask("AI Commander Privileged Helper");
    expect(denied.queried).toBe(false);

    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=0\r\nLOOKUPFAIL=NotSpecified\r\n" };
    const failed = await queryScheduledTask("AI Commander Privileged Helper");
    expect(failed.queried).toBe(false);
  });

  it("still answers 'registered' when the lookup itself succeeded", async () => {
    // The happy path is untouched by any of the above — `Get-ScheduledTask`
    // remains the primary lookup and the COM call only runs where it threw.
    staged.captured = {
      kind: "output",
      stdout: "QUERIED=1\r\nADMIN=1\r\nSTATE=Running\r\nANSWERED=1\r\nEXECUTE=helper.exe\r\nARGS=--serve\r\n",
    };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    expect(info).toEqual({
      queried: true,
      registered: true,
      elevated: true,
      state: "Running",
      execute: "helper.exe",
      args: "--serve",
    });
  });
});

describe("a refusal cannot be forged by the task's own action text", () => {
  // `EXECUTE=`/`ARGS=` echo the action the task was registered with, and
  // `Arguments` may contain CRLF — so for one afternoon anybody who could
  // register a task could put the line `DENIED=1` in its arguments and turn a
  // lookup that SUCCEEDED into "we could not ask", or put `ANSWERED=1` in them
  // and manufacture an answer. The markers are printed before the first
  // `EXECUTE=` line and the parser stops reading them there; these pin the
  // boundary from both sides.
  const forged = (line: string): string =>
    `QUERIED=1\r\nADMIN=1\r\nSTATE=Ready\r\nANSWERED=1\r\nEXECUTE=helper.exe\r\nARGS=--flag\r\n${line}\r\n`;

  it("ignores a DENIED line echoed back out of the task's arguments", async () => {
    staged.captured = { kind: "output", stdout: forged("DENIED=1") };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    expect(info.queried).toBe(true);
    if (!info.queried) throw new Error("unreachable");
    expect(info.registered).toBe(true);
    expect(info.state).toBe("Ready");
  });

  it("ignores LOOKUPFAIL, ABSENT and CONTRADICTION lines from the same place", async () => {
    for (const line of ["LOOKUPFAIL=ConnectionError", "ABSENT=1", "CONTRADICTION=1"]) {
      staged.captured = { kind: "output", stdout: forged(line) };
      const info = await queryScheduledTask("AI Commander Privileged Helper");
      expect(info.queried).toBe(true);
      if (!info.queried) throw new Error("unreachable");
      expect(info.registered).toBe(true);
    }
  });

  it("cannot have an ANSWER manufactured for it out of a killed run", async () => {
    // The other direction: a run stopped mid-lookup that had already echoed an
    // action (it cannot have, but the parser must not depend on that) may not
    // acquire `ANSWERED=1` from the action's own text.
    staged.captured = {
      kind: "unavailable",
      reason: "powershell.exe did not answer within 25000 ms and was stopped",
      partialStdout: "QUERIED=1\r\nEXECUTE=x.exe\r\nARGS=--x\r\nANSWERED=1\r\n",
    };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(false);
  });

  it("still reports the task's real action, which is what those lines are for", async () => {
    staged.captured = {
      kind: "output",
      stdout: "QUERIED=1\r\nADMIN=1\r\nSTATE=Ready\r\nANSWERED=1\r\nEXECUTE=helper.exe\r\nARGS=--serve\r\n",
    };
    const info = await queryScheduledTask("AI Commander Privileged Helper");
    if (!info.queried) throw new Error("unreachable");
    expect(info.execute).toBe("helper.exe");
    expect(info.args).toBe("--serve");
  });
});

describe("what each 'we could not find out' was", () => {
  // `cause` exists because every caller was writing ONE remedy — "re-run
  // elevated" — for a set that includes ENOENT, a timeout, ConstrainedLanguage
  // and a blocked COM, where elevation changes nothing.
  it("calls a refusal a refusal and everything else something weaker", async () => {
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=0\r\nDENIED=1\r\n" };
    const denied = await queryScheduledTask("AI Commander Relaunch");
    if (denied.queried) throw new Error("unreachable");
    expect(denied.cause).toBe("denied");

    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nLOOKUPFAIL=ComConnect\r\n" };
    const broke = await queryScheduledTask("AI Commander Relaunch");
    if (broke.queried) throw new Error("unreachable");
    expect(broke.cause).toBe("lookup_failed");

    staged.captured = { kind: "unavailable", reason: "ENOENT", partialStdout: "" };
    const never = await queryScheduledTask("AI Commander Relaunch");
    if (never.queried) throw new Error("unreachable");
    expect(never.cause).toBe("unavailable");
  });

  it("keeps the fact a contradiction carries instead of flattening it to a failure code", async () => {
    // COM reading a task out of the root folder that `Get-ScheduledTask` said was
    // not there is the strongest fact either call produced — existence — and
    // `LOOKUPFAIL=READABLE` threw it away. It is still not an ANSWER (the two
    // lookups disagree), so it stays `queried: false`, but it says what happened.
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=0\r\nCONTRADICTION=1\r\n" };
    const info = await queryScheduledTask("AI Commander Relaunch");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    // And it gets its OWN cause. Collapsing it into `lookup_failed` — documented
    // as "nothing was learned about the task either way" — left every caller
    // pairing that code with this reason, i.e. printing one sentence that says
    // the service read the task AND that nothing was learned.
    expect(info.cause).toBe("contradiction");
    expect(info.reason).toMatch(/Task Scheduler service read it/);
    expect(info.reason).not.toMatch(/READABLE/);
  });
});

describe("the root-folder contract", () => {
  // The COM discriminator asks `GetFolder('\')` and therefore only searches the
  // ROOT folder, while `Get-ScheduledTask -TaskName` searches every TaskPath. For
  // a task registered elsewhere the two disagree by construction and 0x80070002
  // would mean "not in this folder", not "not registered".
  it("covers exactly the tasks measured to live at the root", () => {
    expect([...ROOT_FOLDER_TASKS].sort()).toEqual([
      "AI Commander Privileged Helper",
      "AI Commander Relaunch",
      "AI Commander Update",
    ]);
  });

  it("refuses to turn a root-folder miss into an absence for a name outside it", async () => {
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=1\r\nABSENT=1\r\nANSWERED=1\r\n" };
    const info = await queryScheduledTask("Microsoft\\Windows\\Something Else");
    expect(info.queried).toBe(false);
    if (info.queried) throw new Error("unreachable");
    expect(info.cause).toBe("lookup_failed");
    expect(info.reason).toMatch(/only the root folder/);
  });

  it("accepts it for a name the contract covers", async () => {
    staged.captured = { kind: "output", stdout: "QUERIED=1\r\nADMIN=1\r\nABSENT=1\r\nANSWERED=1\r\n" };
    const info = await queryScheduledTask("AI Commander Update");
    expect(info.queried).toBe(true);
    if (!info.queried) throw new Error("unreachable");
    expect(info.registered).toBe(false);
  });
});

describe("the generated PowerShell", () => {
  // THE GAP THAT WOULD HAVE LET THIS SHIP BROKEN. Every other test in this file
  // stages the script's OUTPUT; none of them looks at the script, so a misplaced
  // brace or `else` — in a nested conditional built by string concatenation —
  // would produce a parse error on the real machine, an empty stdout, and a
  // permanent `queried: false` everywhere, with all of the above still green.
  // Pinned the way packages/desktop/src/__tests__/win-updater-script.test.ts pins
  // win-updater.ps1.
  const scriptFor = async (name: string): Promise<string> => {
    staged.captured = { kind: "output", stdout: "" };
    await queryScheduledTask(name);
    const at = staged.argv.indexOf("-Command");
    expect(at).toBeGreaterThan(-1);
    return staged.argv[at + 1]!;
  };

  /** Brace/paren depth, counting only what is OUTSIDE PowerShell string literals. */
  const balance = (script: string): { braces: number; parens: number; quotes: number } => {
    let braces = 0;
    let parens = 0;
    let inQuote = false;
    for (let i = 0; i < script.length; i += 1) {
      const c = script[i];
      if (c === "'") {
        // '' inside a single-quoted string is an escaped quote, not a close.
        if (inQuote && script[i + 1] === "'") {
          i += 1;
          continue;
        }
        inQuote = !inQuote;
        continue;
      }
      if (inQuote) continue;
      if (c === "{") braces += 1;
      else if (c === "}") braces -= 1;
      else if (c === "(") parens += 1;
      else if (c === ")") parens -= 1;
      expect(braces).toBeGreaterThanOrEqual(0);
      expect(parens).toBeGreaterThanOrEqual(0);
    }
    return { braces, parens, quotes: inQuote ? 1 : 0 };
  };

  it("closes every brace, paren and quote it opens", async () => {
    expect(balance(await scriptFor("AI Commander Relaunch"))).toEqual({
      braces: 0,
      parens: 0,
      quotes: 0,
    });
  });

  it("puts the start sentinel before the lookup and ANSWERED after it", async () => {
    const script = await scriptFor("AI Commander Relaunch");
    const sentinel = script.indexOf("Write-Output 'QUERIED=1'");
    const lookup = script.indexOf("Get-ScheduledTask -TaskName");
    const state = script.indexOf("Write-Output ('STATE=");
    // Two ANSWERED lines: the absence branch's (which rides on ABSENT=1) and the
    // success branch's. The one that matters here is the second.
    const answered = script.lastIndexOf("Write-Output 'ANSWERED=1'");
    expect(sentinel).toBeGreaterThan(-1);
    expect(sentinel).toBeLessThan(lookup);
    // `QUERIED=1` proving only that PowerShell STARTED, and `ANSWERED=1` proving
    // the lookup RETURNED, is the whole tri-state — and it rests on this order.
    expect(lookup).toBeLessThan(state);
    expect(state).toBeLessThan(answered);
    // A killed run must never carry ANSWERED without the ABSENT it belongs to.
    expect(script.indexOf("Write-Output 'ABSENT=1'")).toBeLessThan(
      script.indexOf("Write-Output 'ANSWERED=1'"),
    );
  });

  it("emits every marker BEFORE the first line that echoes the task's own action", async () => {
    // The parser stops reading markers at the first `EXECUTE=`; if the script
    // ever printed one after that line, the marker would be unreachable.
    const script = await scriptFor("AI Commander Relaunch");
    const firstEcho = script.indexOf("Write-Output ('EXECUTE=");
    expect(firstEcho).toBeGreaterThan(-1);
    for (const marker of ["QUERIED=1", "ANSWERED=1", "ABSENT=1", "DENIED=1", "CONTRADICTION=1", "LOOKUPFAIL="]) {
      expect(script.indexOf(marker)).toBeLessThan(firstEcho);
    }
    // ARGS is the one line allowed after it, being the other half of the action.
    expect(script.indexOf("Write-Output ('ARGS=")).toBeGreaterThan(firstEcho);
  });

  it("asks COM in three separate stages, so only GetTask may claim the task exists", async () => {
    // A denial from `New-Object Schedule.Service`, `Connect()` or `GetFolder('\')`
    // is about the HOST — none of those calls has seen the name — and reporting
    // it as "the task exists but you may not read it" is the bug being fixed,
    // one layer up. Each stage gets its own `try`, and only the third can print
    // DENIED.
    const script = await scriptFor("AI Commander Relaunch");
    const connect = script.indexOf("New-Object -ComObject Schedule.Service");
    const folder = script.indexOf("$svc.GetFolder(");
    const getTask = script.indexOf("$folder.GetTask(");
    expect(connect).toBeGreaterThan(-1);
    expect(folder).toBeGreaterThan(connect);
    expect(getTask).toBeGreaterThan(folder);
    // A failed stage 1 or 2 claims nothing.
    expect(script).toContain("Write-Output 'LOOKUPFAIL=ComConnect'");
    expect(script).toContain("Write-Output 'LOOKUPFAIL=ComRootFolder'");
    // …and the branch that CAN claim it comes only after GetTask.
    expect(script.indexOf("Write-Output 'DENIED=1'")).toBeGreaterThan(getTask);
    expect(script.indexOf("Write-Output 'ABSENT=1'")).toBeGreaterThan(getTask);
    // Guarded so a stage-1/2 failure never reaches the stages after it.
    expect(script).toContain("if ($null -eq $svc)");
    expect(script).toContain("if ($null -eq $folder)");
  });

  it("compares the HRESULT as a formatted string, never numerically", async () => {
    // `-eq` between the literal 0x80070005 (a positive Int64 to PowerShell) and
    // `Exception.HResult` (a negative Int32) is quietly always false, which would
    // send every denial down the LOOKUPFAIL branch.
    const script = await scriptFor("AI Commander Relaunch");
    expect(script).toContain("'{0:X8}' -f $_.Exception.HResult");
    expect(script).toContain("$h -eq '80070002'");
    expect(script).toContain("$h -eq '80070005'");
    expect(script).not.toMatch(/0x8007000[25]/);
  });

  it("only consults COM for ObjectNotFound, and only after Get-ScheduledTask threw", async () => {
    const script = await scriptFor("AI Commander Relaunch");
    // Anything else never reached the question of existence.
    expect(script).toContain("$e.CategoryInfo.Category -ne 'ObjectNotFound'");
    expect(script.indexOf("Get-ScheduledTask -TaskName")).toBeLessThan(
      script.indexOf("New-Object -ComObject Schedule.Service"),
    );
  });

  it("interpolates the task name ONLY as a quoted literal, in both lookups", async () => {
    // The only value that ever enters the script, and it must reach both calls
    // asking about the same task — a name that reached one of them only would
    // make the discriminator answer about something else.
    const script = await scriptFor("AI Commander Relaunch");
    expect(script).toContain("Get-ScheduledTask -TaskName 'AI Commander Relaunch'");
    expect(script).toContain("$folder.GetTask('AI Commander Relaunch')");
    // A quote in a name is escaped, not closed: the script must stay balanced.
    const quoted = await scriptFor("AI Commander's Task");
    expect(quoted).toContain("'AI Commander''s Task'");
    expect(balance(quoted)).toEqual({ braces: 0, parens: 0, quotes: 0 });
  });

  it("runs the whole thing with -NoProfile -NonInteractive and a bypassed policy", async () => {
    await scriptFor("AI Commander Relaunch");
    expect(staged.argv.slice(0, 5)).toEqual([
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-Command",
    ]);
  });
});
