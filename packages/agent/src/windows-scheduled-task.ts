import path from "node:path";
import { capturedStdout, runCaptured, unavailableReason } from "./capture.js";
import { powerShellSingleQuote } from "./installed-version.js";

/**
 * "Has Windows been told to run this?" — asked of Task Scheduler, by name.
 *
 * A RUNTIME question, not a diagnostic one. `elevated-availability.ts` asks it
 * on every reconcile to decide which word a machine with no reachable helper
 * publishes to the relay (`not_registered` vs `endpoint_unreachable`), and the
 * doctor asks the same question when it prints a report. It lives here, on its
 * own, because the dependency may only run in that direction: fail-closed
 * runtime logic must not import from the diagnostics subtree, or removing or
 * moving `doctor/` breaks the agent and the availability rule can no longer be
 * reasoned about by itself. The tri-state capture primitive it is built on
 * (capture.ts) was moved out of `doctor/checks/` for exactly that reason.
 *
 * THERE IS ONE OF THESE. There were briefly two — the doctor's and the
 * runtime's — and they diverged on the case that matters most, which is how the
 * `queried` sentinel came to be computed by one copy and thrown away by the
 * other. `doctor/checks/windows.ts` re-exports this module; it does not have its
 * own.
 *
 * FULL PATHS, NEVER BARE NAMES. `powershell.exe` is spelled out under
 * `%SystemRoot%\System32`: this runs from the tray, from a service and from the
 * SYSTEM-owned helper, and in none of those is `PATH` ours to trust.
 *
 * NOTHING READ HERE EVER BECOMES SOMETHING WE RUN. The only value interpolated
 * into the script is a compile-time constant of ours, quoted as a PowerShell
 * literal; everything Windows answers is parsed and reported.
 */

/** `C:\Windows`, or whatever this machine calls it. */
export function systemRoot(): string {
  return process.env["SystemRoot"] ?? process.env["windir"] ?? "C:\\Windows";
}

export function powerShellPath(): string {
  return path.join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/**
 * How long the scheduled-task query may take before we give up on it.
 *
 * Far above `capture.ts`'s 5 s default, and deliberately: `Get-ScheduledTask`
 * cold-loads the ScheduledTasks CIM module on first use, and on a box under
 * behavioural AV scanning — the machine this whole effort is aimed at — that
 * alone regularly runs past five seconds. A timeout there is not a cheap "we
 * could not tell": it is the reason the incident machine could never produce
 * `not_registered`, the one verdict worth producing. Still bounded, because
 * nothing that can hang may sit on the reconcile path.
 */
export const SCHEDULED_TASK_QUERY_TIMEOUT_MS = 25_000;

/** What Windows said about a task it DOES know about, or does not. */
interface ScheduledTaskAnswer {
  /**
   * Whether the QUESTION was actually answered — i.e. PowerShell ran and told us
   * something, as opposed to not running at all.
   *
   * This is the discriminant of the union, and that is the point: `registered`
   * exists ONLY on this branch, so a caller cannot obtain "is it registered"
   * without having first established that the question was answered. Reading a
   * bare boolean was possible for one release and produced three separate bugs,
   * all of the same shape — "we could not ask" published as "it was never
   * registered", which is the 2026-09-02 incident's own signature invented on a
   * machine that may be perfectly healthy.
   */
  queried: true;
  /** Windows named the task (`false` = Windows answered and did not name it). */
  registered: boolean;
  state: string | null;
  /** The action's own program (`powershell.exe`, the tray exe, …). */
  execute: string | null;
  /** The action's argument string, as registered. */
  args: string | null;
  /**
   * Whether the process that ASKED is a member of Administrators — `null` when
   * even the identity call was refused.
   *
   * It changes what an absent task means. Task Scheduler enforces a per-task
   * ACL, and the installer registers the Relaunch task with SDDL
   * `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)` — SYSTEM and Administrators only, no
   * Users grant (desktop/build/win-update-task.ps1, `$relaunchSddl`). A
   * standard-user tray asking about it is told there is no such task, which is
   * indistinguishable from its never having been registered. Without this, "the
   * task is missing" would fire on every packaged install running as a normal
   * user — the false alarm that costs a diagnostic its credibility.
   *
   * It is now the SECOND line of defence, not the first: a denied lookup is
   * caught below by the COM HRESULT and comes back `queried: false`, never as an
   * answer. What is left for this field is the case COM cannot discriminate —
   * `Get-ScheduledTask` returning the task but with an action the caller may not
   * read, or a future ACL shape neither call resolves — plus the plain reporting
   * value of "who was asking" beside an absence. It is deliberately NOT justified
   * by the blocked-COM case: a host that blocks `Schedule.Service` returns the
   * unanswered branch, which has no `elevated` field at all.
   */
  elevated: boolean | null;
}

/**
 * WHICH KIND of "we could not find out" this was.
 *
 * It exists because callers were writing ONE remedy for all of them — "re-run
 * elevated" — which is right for exactly one and misleading for the rest: no
 * amount of elevation fixes a missing `powershell.exe`, a killed query or a
 * ConstrainedLanguage host. A caller that wants to say something about the cause
 * must branch on this rather than on the prose of `reason`.
 *
 *  - `denied`      — Task Scheduler refused to let this account read the task.
 *                    The task EXISTS (that is what 0x80070005 means, as opposed
 *                    to 0x80070002), and elevation is what would answer it.
 *  - `contradiction` — the two lookups disagree: `Get-ScheduledTask` did not find
 *                    the task, the Task Scheduler service read it out of the root
 *                    folder. SOMETHING was learned — the service saw it — but two
 *                    lookups disagreeing is not a positive answer, so it is not a
 *                    registration. It has its own value precisely so a caller does
 *                    not have to say "nothing was learned either way", which is the
 *                    one thing that is NOT true here.
 *  - `lookup_failed` — the lookup broke. Nothing was learned about the task,
 *                    including whether it exists.
 *  - `unavailable` — the query never ran, or ran and printed no answer.
 */
export type ScheduledTaskUnansweredCause = "denied" | "contradiction" | "lookup_failed" | "unavailable";

/**
 * THE ONE SENTENCE ABOUT A REFUSAL, exported so there can only be one of it.
 *
 * `cause: "denied"` is 0x80070005 raised by `$folder.GetTask(<name>)` itself —
 * the only stage of the COM probe that has SEEN the name (the three-stage note
 * in the script below is what makes that true) — so a denial proves the named
 * task EXISTS. Every caller that reports one says so with this clause instead of
 * wording it again: for one release the two doctor checks described this single
 * measured fact in opposite words, `persistence.ts` opening `"…" IS registered`
 * while `priv-helper.ts` opened "whether … is registered could not be
 * determined" and then asserted existence two clauses later.
 *
 * WHAT IT DOES NOT SAY, and no caller may add: what the task points at, or that
 * it runs. The refusal withheld the DEFINITION — the action, the state, the
 * path — which is exactly the half a registration check exists to read. That is
 * why a denial still comes back `queried: false` with no `registered` field:
 * "exists, definition unreadable" is a weaker fact than "registered", and
 * promoting it would let an ACL refusal alone stand in for a working helper.
 */
export const DENIAL_PROVES_TASK_EXISTS =
  "Task Scheduler refused this process the right to read it, which it only does for a task that exists";

/**
 * No answer came back — the query did not run, broke, or was refused. A statement
 * about the DIAGNOSTIC, never about whether the task is registered.
 */
interface ScheduledTaskUnanswered {
  queried: false;
  cause: ScheduledTaskUnansweredCause;
  /** Why, in one line, for the `detail` of a check that reports itself skipped. */
  reason: string;
}

/**
 * THE ROOT-FOLDER CONTRACT, and it is load-bearing rather than decorative.
 *
 * `Get-ScheduledTask -TaskName x` searches EVERY TaskPath; the COM discriminator
 * below asks `GetFolder('\')` and therefore searches only the root. For a task
 * registered under, say, `\Microsoft\Windows\…`, the two disagree by
 * construction: COM would answer 0x80070002 ("not in this folder") and we would
 * publish a confident absence about a task that is merely somewhere else.
 *
 * The contract is that everything this module is asked about is registered at
 * `\`. MEASURED, not deduced: `Get-ScheduledTask | ? TaskName -like 'AI
 * Commander*'` reports `TaskPath=\` for all three of ours on three live boxes,
 * and our installer registers all three there. A recursive folder walk would
 * remove the assumption but costs a COM round trip per folder inside a 25 s
 * budget that already loses to a CIM cold-load, so the assumption is kept and
 * ENFORCED instead: an `ABSENT` for a name outside this set degrades to
 * `lookup_failed`.
 *
 * WHAT THIS SET DOES NOT DO, because it reads like it does: it constrains NAMES,
 * not LOCATIONS. Membership asserts a measurement about where the installer puts
 * a task; it cannot make a task be there. If one of these three were ever
 * registered somewhere other than `\` AND its ACL denied us — so that
 * `Get-ScheduledTask` throws ObjectNotFound and the root-folder COM call misses
 * it — this module would publish a confident `registered: false` about a task
 * that exists. The absence verdict is only as sound as that measurement. Move a
 * task out of `\` and this needs the folder walk; add a name here only after
 * checking its TaskPath.
 */
export const ROOT_FOLDER_TASKS: ReadonlySet<string> = new Set([
  "AI Commander Privileged Helper",
  "AI Commander Relaunch",
  "AI Commander Update",
]);

/**
 * Windows' answer, or the absence of one.
 *
 * Three states, not two: registered, answered-and-absent, and never-asked. The
 * third has no `registered` field at all — see `queried`.
 */
export type ScheduledTaskInfo = ScheduledTaskAnswer | ScheduledTaskUnanswered;

/**
 * Ask Windows about ONE scheduled task by its constant name.
 *
 * `queried: true` means Windows answered — INCLUDING the case where the answer
 * arrived as partial output before the deadline killed the process, but NOT the
 * case where the process was killed while the lookup was still running. Starting
 * to ask is not being answered.
 *
 * `queried: false` covers BOTH "we could not ask" and "Windows refused to answer"
 * — the second being the denial that started all this, where the task provably
 * exists — and no caller may read either as "the task is absent". Which of them
 * happened is on `cause`; a caller writing a remedy must branch on it rather than
 * assume the ACL case (see ScheduledTaskUnansweredCause).
 */
export async function queryScheduledTask(
  name: string,
  opts?: { timeoutMs?: number },
): Promise<ScheduledTaskInfo> {
  // TWO MARKERS, AND THEY MEAN DIFFERENT THINGS.
  //
  // `QUERIED=1` is printed before anything is looked up, so an empty stdout means
  // the query never ran (no PowerShell, a timeout before the shell said anything,
  // a policy block) rather than "no such task" — the distinction the original
  // script could not make. But it proves only that PowerShell STARTED. A run
  // killed at its deadline while `Get-ScheduledTask` cold-loads the CIM module
  // has flushed `QUERIED=1` and nothing else, and reading that as "Windows
  // answered and did not name the task" invents the very verdict this module
  // exists to withhold — a definite answer to a question nobody answered. That
  // was shipped once, on the reasoning that "the sentinel survives the timeout";
  // the sentinel survives, the ANSWER does not.
  //
  // `ANSWERED=1` is printed once the lookup has RETURNED, and it is what
  // `registered: false` now rests on. It comes after the STATE line and before
  // the action lines, so every partial output still says as much as it honestly
  // can: killed before the lookup returns → `QUERIED=1` alone → "we could not
  // ask"; killed while printing the actions → STATE and ANSWERED are already on
  // the pipe → "registered, state known".
  //
  // The lookup itself is wrapped so a missing task is an ABSENCE we report, not a
  // nonzero exit that swallows the markers with it.
  //
  // BUT A FAILED LOOKUP IS NOT AN ABSENCE, and for one release the script said it
  // was: `catch { $t = $null }` flattened every exception into "no such task" and
  // then printed `ANSWERED=1` regardless, so the TS tri-state above — correct in
  // itself — was handed a definite "Windows answered: not registered" for a
  // question Windows had refused. Three markers now come out of the failure path
  // instead, and only one of them is an answer:
  //
  //   `ABSENT=1` + `ANSWERED=1` — the task really is not there.
  //   `DENIED=1`               — the task IS there and this account may not read it.
  //   `CONTRADICTION=1`        — the two lookups disagree; see below.
  //   `LOOKUPFAIL=<why>`       — the lookup broke; we learned nothing either way.
  //
  // Telling those apart takes TWO calls, because `Get-ScheduledTask` cannot do it:
  // a task whose ACL denies the caller throws `ObjectNotFound`, the same category
  // and the same CimJobException type as a task that does not exist. Measured on
  // aic-wfs-pc and aic-wfs-pc2, where "AI Commander Privileged Helper" is
  // registered and RUNNING and a standard-user query is told it is not there —
  // two of three Windows boxes publishing a false `registered: false`.
  //
  // The discriminator is the Task Scheduler COM API, whose HRESULTs separate the
  // two: 0x80070002 (not found) from 0x80070005 (access denied). It is matched on
  // the HRESULT and never on the message, because these machines are Polish and
  // print "Nie można odnaleźć określonego pliku" / "Odmowa dostępu"; `schtasks.exe`
  // was no use either, exiting 1 for both. `Get-ScheduledTask` stays the PRIMARY
  // lookup so the path that works keeps working byte for byte, and the COM call
  // only ever runs on the path that was previously wrong. All of it is wrapped:
  // a host where `Schedule.Service` is blocked degrades to LOOKUPFAIL rather than
  // throwing the markers away with the script.
  //
  // THE COM CALL IS THREE STAGES, AND ONLY THE LAST ONE KNOWS THE TASK. Creating
  // `Schedule.Service`, `Connect()`ing to the service and opening the root folder
  // can each fail with 0x80070005 of their own — a locked-down host, a service
  // the account may not talk to — and none of those refusals is about the NAME we
  // asked about. Wrapping all three in one `try` (which is what the first cut of
  // this did) republishes the bug being fixed one layer up: "access denied" from
  // a stage that never saw the name, reported as "the task exists but you may not
  // read it". So the stages are separate and only `GetTask(<name>)`'s own HRESULT
  // may claim anything about the task; a stage failure before it is LOOKUPFAIL,
  // which claims nothing at all.
  const script =
    "$ErrorActionPreference='Stop';" +
    "Write-Output 'QUERIED=1';" +
    // Printed from the same process that does the lookup, so it describes the
    // rights the lookup actually had. Wrapped, because a locked-down host can
    // refuse the identity call without refusing the query.
    "try { Write-Output ('ADMIN=' + [int](New-Object Security.Principal.WindowsPrincipal(" +
    "[Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(" +
    "[Security.Principal.WindowsBuiltInRole]::Administrator)) } catch { };" +
    "$t = $null; $e = $null;" +
    `try { $t = Get-ScheduledTask -TaskName ${powerShellSingleQuote(name)} -ErrorAction Stop } catch { $e = $_ };` +
    "if ($e) {" +
    // Anything but ObjectNotFound never even reached the question of existence.
    " if ($e.CategoryInfo.Category -ne 'ObjectNotFound') {" +
    "  Write-Output ('LOOKUPFAIL=' + $e.CategoryInfo.Category) } else {" +
    //  ObjectNotFound is ambiguous — ask COM which of the two it was. The HRESULT
    //  is formatted rather than compared numerically: PowerShell reads the literal
    //  0x80070005 as a positive Int64 while `Exception.HResult` is a negative
    //  Int32, so `-eq` between them is quietly always false. The OUTER exception
    //  carries it; `InnerException.HResult` was empty when measured.
    //  Stage 1 and 2 — get to the root folder. A refusal here is about the HOST,
    //  not about the task, so it may only ever be a LOOKUPFAIL.
    "  $svc = $null; $folder = $null;" +
    "  try { $svc = New-Object -ComObject Schedule.Service; $svc.Connect() } catch { $svc = $null };" +
    "  if ($null -eq $svc) { Write-Output 'LOOKUPFAIL=ComConnect' } else {" +
    "   try { $folder = $svc.GetFolder('\\') } catch { $folder = $null };" +
    "   if ($null -eq $folder) { Write-Output 'LOOKUPFAIL=ComRootFolder' } else {" +
    //   Stage 3 — the only call that has seen the name, and so the only HRESULT
    //   allowed to say anything about it.
    "    $h = $null;" +
    `    try { $null = $folder.GetTask(${powerShellSingleQuote(name)}); $h = 'READABLE' }` +
    "    catch { $h = '{0:X8}' -f $_.Exception.HResult };" +
    "    if ($h -eq '80070002') { Write-Output 'ABSENT=1'; Write-Output 'ANSWERED=1' }" +
    "    elseif ($h -eq '80070005') { Write-Output 'DENIED=1' }" +
    //   COM handing back a task that Get-ScheduledTask said was not there is a
    //   contradiction, and a contradiction is not an absence. Its own marker,
    //   because "LOOKUPFAIL=READABLE" threw away the one fact it carries.
    "    elseif ($h -eq 'READABLE') { Write-Output 'CONTRADICTION=1' }" +
    "    else { Write-Output ('LOOKUPFAIL=' + $h) } } } } } else {" +
    " if ($t) { Write-Output ('STATE=' + $t.State) };" +
    // The lookup has returned. Everything after this line is detail — and the
    // ORDER is a parsing contract, not tidiness: EXECUTE/ARGS echo the task's own
    // registered action, whose text we do not control, so every marker is printed
    // BEFORE the first EXECUTE line and the parser stops reading markers there.
    " Write-Output 'ANSWERED=1';" +
    " if ($t) {" +
    "  foreach ($a in $t.Actions) {" +
    "   Write-Output ('EXECUTE=' + $a.Execute);" +
    "   Write-Output ('ARGS=' + $a.Arguments) } } }";
  const captured = await runCaptured(
    powerShellPath(),
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    { timeoutMs: opts?.timeoutMs ?? SCHEDULED_TASK_QUERY_TIMEOUT_MS },
  );
  // THE ANSWER SURVIVES THE TIMEOUT, and this reads like an optimisation and is
  // not. `capturedStdout` hands back what the process said even when it exited
  // non-zero or was killed at the deadline. A lookup that RETURNED before the CIM
  // cold-load pushed the rest of the script past the clock has already put
  // `STATE=` and/or `ANSWERED=1` on the pipe, and those bytes are the verdict the
  // machine needed. Discarding them left `queried: false` and, ten TTL-minutes at
  // a time, a permanent `endpoint_unreachable` on the one box this whole effort
  // exists for.
  const out = capturedStdout(captured);
  // MARKERS ARE READ FROM THE HEADER ONLY, and this is a boundary, not a
  // micro-optimisation. `EXECUTE=`/`ARGS=` echo the task's OWN registered action,
  // which anyone able to register a task controls, and `Arguments` may contain
  // CRLF — so a task registered with an argument containing the line `DENIED=1`
  // could otherwise overturn a lookup that succeeded, and one carrying `ANSWERED=1`
  // could manufacture an answer out of a killed run. The script prints every
  // marker before the first `EXECUTE=` line (see the script's ordering comment);
  // the cut here is what makes that ordering enforceable rather than hopeful.
  const executeAt = out.search(/^EXECUTE=/m);
  const header = executeAt === -1 ? out : out.slice(0, executeAt);
  const read = (key: string, from: string = header): string | null => {
    const match = new RegExp(`^${key}=(.*)$`, "m").exec(from);
    return match ? match[1]!.trim() : null;
  };
  const state = read("STATE");
  const started = /^QUERIED=1$/m.test(header);
  // A REFUSAL OUTRANKS EVERY OTHER MARKER ON THE PIPE, and this ordering is the
  // whole fix, not a detail of it. A denied or broken lookup exits 0 with
  // `QUERIED=1` printed, which is precisely the third clause of `answered` below
  // ("it ran to completion, so the sentinel bounds the whole script") — leave
  // these two after that expression and the script's new honesty is thrown away
  // one line later, reinventing the bug as "Windows answered and did not name the
  // task". So they return FIRST, and neither reason may read as an absence: the
  // task in the denied case is, as measured, right there and running.
  if (/^DENIED=1$/m.test(header)) {
    return {
      queried: false,
      cause: "denied",
      reason:
        `the scheduled-task lookup was denied access to "${name}" ` +
        "(the task exists but this account may not read it)",
    };
  }
  if (/^CONTRADICTION=1$/m.test(header)) {
    // The strongest fact obtained is EXISTENCE, and it is kept — in words, not as
    // a verdict. Turning it into `registered: true` would be a claim of the kind
    // this module exists to withhold: the two lookups disagree, so what the task
    // is and whether it is still there a moment later is precisely what we do not
    // know. Naming both halves is what a reader needs to act on it.
    //
    // ITS OWN `cause`, and that is the other half of keeping the fact. Collapsing
    // it into `lookup_failed` handed callers a code documented as "nothing was
    // learned about the task either way" together with a `reason` saying the
    // service had just read the task — one sentence asserting both, which the
    // helper check duly printed. `contradiction` lets a caller say the weaker true
    // thing instead.
    return {
      queried: false,
      cause: "contradiction",
      reason:
        `the two scheduled-task lookups disagree about "${name}": Get-ScheduledTask did not find it, ` +
        "but the Task Scheduler service read it out of the root folder",
    };
  }
  const lookupFail = read("LOOKUPFAIL");
  if (lookupFail !== null) {
    return { queried: false, cause: "lookup_failed", reason: `the scheduled-task lookup failed: ${lookupFail}` };
  }
  // THE ROOT-FOLDER CONTRACT, ENFORCED (see ROOT_FOLDER_TASKS). `ABSENT=1` means
  // the ROOT folder does not hold the task; only for a name we know is registered
  // there is that the same thing as "the task is not registered".
  if (/^ABSENT=1$/m.test(header) && !ROOT_FOLDER_TASKS.has(name)) {
    return {
      queried: false,
      cause: "lookup_failed",
      reason:
        `the scheduled-task lookup searched only the root folder for "${name}", which is not one of the ` +
        "tasks known to be registered there, so its absence from that folder says nothing",
    };
  }
  // WHAT MAKES AN ABSENCE AN ANSWER. Any ONE of:
  //   - `ANSWERED=1`: the lookup returned, whatever happened to the process
  //     afterwards. No STATE line alongside it is Windows saying the task is not
  //     there — the only route to `registered: false` for a killed run.
  //   - a STATE line: Windows named the task. Older output shapes carried no
  //     marker at all, which is what keeps a stubbed PowerShell honest in tests.
  //   - the script RAN TO COMPLETION (`kind: "output"` — it exited 0) with the
  //     start sentinel on the pipe. A process that reached its own exit cannot be
  //     mid-lookup, so here the sentinel really does bound the whole script.
  // What is deliberately NOT enough is `QUERIED=1` from a process that was killed
  // or died: that is "we got as far as starting and no further". Nor is it reached
  // at all once a refusal marker is on the pipe — those returned above, and the
  // only absence that gets this far is the one the script vouched for (`ABSENT=1`,
  // which rides on the `ANSWERED=1` printed with it).
  const answered = /^ANSWERED=1$/m.test(header) || state !== null || (captured.kind === "output" && started);
  if (!answered) {
    // `unavailableReason` is empty exactly when the command ran and exited 0,
    // which here means PowerShell started and printed nothing recognisable —
    // ConstrainedLanguage, a wedged profile, a script host that swallowed the
    // output. Still "we could not ask", never "no such task".
    const reason = unavailableReason(captured) || `${powerShellPath()} ran but printed no answer`;
    return {
      queried: false,
      cause: "unavailable",
      reason: started ? `${reason} (the scheduled-task lookup never returned)` : reason,
    };
  }
  const admin = read("ADMIN");
  return {
    queried: true,
    registered: state !== null,
    elevated: admin === null ? null : admin === "1",
    state,
    // The detail lines, and the ONLY two read from outside the header. A task
    // whose action text contains a `ARGS=` line can shift what these two report —
    // but only between two fields of its OWN action, which whoever registered the
    // task wrote in the first place. Nothing there can reach a marker, which is
    // the boundary that matters.
    execute: read("EXECUTE", out),
    args: read("ARGS", out),
  };
}
