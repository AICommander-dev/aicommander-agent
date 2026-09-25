// `skippedSessions` counts SESSIONS THE TICK DID NOT DELIVER — and nothing else
// in the suite made that bite. Deleting `$skippedSessionIds.Remove($lookupKey)`
// from the probe left the whole priv-helper suite green, and that one line is
// the difference between "a count of drop events" and "a count of sessions":
// a session whose first candidate fails and whose second succeeds IS delivered,
// so it must not be counted. The number gates evaluateTick's prune, so a
// spuriously non-zero count means no user is ever pruned again for the
// machine's uptime.
//
// WHAT THIS FILE CAN AND CANNOT PROVE. There is no PowerShell host on this
// platform (see the header of win-watchdog-probe.test.ts), so nothing here
// EXECUTES the probe. Instead the per-candidate loop's bookkeeping is EXTRACTED
// from the shipped script — the drops, the dedupe, the delivery and the clear,
// in the order they appear — and that extracted program is then RUN over
// candidate sequences. So the model cannot drift from the script: it is built
// out of it. What it does not model is PowerShell's own semantics, and it reads
// only statements at the loop body's own indentation, so a step buried in a
// nested block is not seen (which fails the scenarios rather than passing them).

import { describe, it, expect } from "vitest";
import { __probeScript } from "../win-watchdog-probe.js";

const script = __probeScript();

// --- the extractor ----------------------------------------------------------

type Step =
  | { kind: "drop"; cond: string }
  | { kind: "dedupe" }
  | { kind: "seen" }
  | { kind: "deliver" }
  | { kind: "clear" };

/**
 * The bookkeeping of the per-candidate walk, in source order. Every pattern is
 * anchored at the loop body's exact indentation: a statement pushed into a
 * nested block (`if ($false) { … }`, an extra `if`) is NOT extracted, which is
 * how a mutation that leaves the text present but unreachable still fails.
 */
function extractProgram(): Step[] {
  const body = script.slice(
    script.indexOf("  foreach ($e in $shellOrder) {"),
    script.indexOf("} catch { $queryErrors += 'sessions' }"),
  );
  expect(body.length).toBeGreaterThan(500);
  const steps: Step[] = [];
  for (const line of body.split("\n")) {
    let m = /^ {6}if \((.+?)\) \{ \$skippedSessionIds\[\$lookupKey\] = \$true; continue \}$/.exec(line);
    if (m) {
      steps.push({ kind: "drop", cond: m[1]! });
      continue;
    }
    if (/^ {6}if \(\$seenSessions\.ContainsKey\(\$lookupKey\)\) \{ continue \}$/.test(line)) {
      steps.push({ kind: "dedupe" });
      continue;
    }
    if (/^ {6}\$seenSessions\[\$lookupKey\] = \$true$/.test(line)) {
      steps.push({ kind: "seen" });
      continue;
    }
    if (/^ {6}\$sessions \+= \[ordered\]@\{$/.test(line)) {
      steps.push({ kind: "deliver" });
      continue;
    }
    if (/^ {6}\$skippedSessionIds\.Remove\(\$lookupKey\)$/.test(line)) {
      steps.push({ kind: "clear" });
      continue;
    }
  }
  return steps;
}

const PROGRAM = extractProgram();

/** One explorer.exe the walk visits: its session, and the guard it trips (if any). */
type Candidate = { session: string; trips?: string };

/**
 * Runs the extracted program over a tick's candidates and reports what the
 * probe would report: `skippedSessions` (the SET's size) and the sessions that
 * made it into the reply.
 */
function runTick(candidates: readonly Candidate[]): { skipped: number; delivered: string[] } {
  const skippedSessionIds = new Set<string>();
  const seenSessions = new Set<string>();
  const delivered: string[] = [];
  for (const candidate of candidates) {
    const key = candidate.session;
    for (const step of PROGRAM) {
      if (step.kind === "drop") {
        if (candidate.trips && step.cond.includes(candidate.trips)) {
          skippedSessionIds.add(key);
          break;
        }
      } else if (step.kind === "dedupe") {
        if (seenSessions.has(key)) break;
      } else if (step.kind === "seen") {
        seenSessions.add(key);
      } else if (step.kind === "deliver") {
        delivered.push(key);
      } else {
        skippedSessionIds.delete(key);
      }
    }
  }
  return { skipped: skippedSessionIds.size, delivered };
}

describe("skippedSessions counts sessions the tick did not deliver", () => {
  it("(sanity) the walk's bookkeeping was extracted, not assumed", () => {
    // Anti-vacuity for the extractor only — deliberately says nothing about the
    // clear, so that removing it fails on BEHAVIOUR below and not here.
    expect(PROGRAM.filter((s) => s.kind === "drop").length).toBeGreaterThanOrEqual(3);
    expect(PROGRAM.filter((s) => s.kind === "deliver")).toHaveLength(1);
    expect(PROGRAM.filter((s) => s.kind === "dedupe")).toHaveLength(1);
    expect(PROGRAM.filter((s) => s.kind === "seen")).toHaveLength(1);
  });

  it("does not count a session whose first candidate failed and whose second succeeded", () => {
    // THE PROPERTY. A session legitimately holds several explorer.exe processes
    // ("launch folder windows in a separate process"), and the early guards run
    // before the session is marked discovered — so an earlier candidate can be
    // recorded as skipped and a later one still deliver. The session IS in the
    // reply, therefore it was not skipped, therefore the count must be 0 and the
    // prune in evaluateTick must still run.
    const tick = runTick([
      { session: "3", trips: "-not $sid" },
      { session: "3" },
    ]);
    expect(tick.delivered).toEqual(["3"]);
    expect(tick.skipped).toBe(0);
  });

  it("does count a session that never delivered", () => {
    // The other direction: the set is not simply always empty. A silent 0 would
    // make an outage look like an idle machine.
    const tick = runTick([{ session: "4", trips: "-not $sid" }]);
    expect(tick.delivered).toEqual([]);
    expect(tick.skipped).toBe(1);
  });

  it("counts one session once, however many of its processes were dropped", () => {
    // SESSIONS, NOT DROP EVENTS. Each drop site used to be a bare counter bump,
    // which fires per candidate PROCESS — so the number an operator read was the
    // session count times the shells-per-session multiplier, while its name and
    // OPERATIONS.md both promise sessions.
    const tick = runTick([
      { session: "5", trips: "$shellOwnerLookups -ge" },
      { session: "5", trips: "$shellOwnerLookups -ge" },
      { session: "5", trips: "$shellOwnerLookups -ge" },
    ]);
    expect(tick.skipped).toBe(1);
    // …and distinct sessions are still counted distinctly.
    const two = runTick([
      { session: "5", trips: "$shellOwnerLookups -ge" },
      { session: "6", trips: "$shellOwnerLookups -ge" },
    ]);
    expect(two.skipped).toBe(2);
  });
});
