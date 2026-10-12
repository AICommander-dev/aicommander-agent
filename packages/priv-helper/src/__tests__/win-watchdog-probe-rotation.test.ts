// The one property of the session scan that a substring check cannot state: that
// a host with more logons than MAX_SHELL_OWNER_LOOKUPS eventually serves ALL of
// them, instead of serving the same prefix forever.
//
// WHAT THIS FILE CAN AND CANNOT PROVE, said first so a green run is not read as
// more than it is. There is no PowerShell host on this platform (see the header
// of win-watchdog-probe.test.ts), so nothing here EXECUTES the probe. The proof
// is therefore in two halves, and it is only as strong as the join between them:
//
//   1. a MODEL of the scan — collect the explorer.exe candidates in enumeration
//      order, rotate by an offset, walk, and stop after the budget's worth of
//      DISTINCT sessions — which really does run, over a real 200-logon host
//      shape, and which reproduces the old behaviour as its control;
//   2. a TEXT PIN tying that model to the shipped script: the rotation block
//      compared WHOLE and exactly, and the fact that the loop holding the
//      GetOwnerSid call iterates the rotated list rather than $allProcs. Whole,
//      because line-by-line `toContain` checks were the first attempt and a
//      mutation that made the rotation unreachable passed all of them.
//
// A change that rotates differently fails (2); a rotation that does not actually
// reach the tail fails (1). What neither half covers is PowerShell's own
// semantics for `Get-Random` and the range operator — that needs the Windows run
// OPERATIONS.md already asks for.

import { describe, it, expect } from "vitest";
import { MAX_SHELL_OWNER_LOOKUPS, __probeScript } from "../win-watchdog-probe.js";

const script = __probeScript();

// --- the model --------------------------------------------------------------

/**
 * A host as the scan sees it: one entry per explorer.exe process, in the order
 * `Get-CimInstance Win32_Process` returns it, carrying the session it belongs
 * to. Deliberately NOT one entry per session — a session legitimately holds
 * several shells ("launch folder windows in a separate process"), and the
 * rotation offset is drawn over PROCESSES, so a model with one process per
 * session would hide whatever that multiplier does to the reach.
 */
function host(sessions: number, shellsPerSession: (id: number) => number): number[] {
  const order: number[] = [];
  for (let id = 0; id < sessions; id++) {
    for (let n = 0; n < shellsPerSession(id); n++) order.push(id);
  }
  return order;
}

/** The rotation itself, exactly as the script's two lines express it. */
function rotate(order: readonly number[], at: number): number[] {
  if (order.length < 2 || at <= 0) return [...order];
  return [...order.slice(at), ...order.slice(0, at)];
}

/**
 * The session ids one tick discovers. The budget is spent on DISTINCT sessions
 * because the dedupe precedes the lookup (see the script's `$seenSessions`
 * block), so a repeat visit to a discovered session costs nothing.
 */
function served(order: readonly number[]): Set<number> {
  const out = new Set<number>();
  for (const id of order) {
    if (out.has(id)) continue;
    if (out.size >= MAX_SHELL_OWNER_LOOKUPS) break;
    out.add(id);
  }
  return out;
}

/** Deterministic uniform offsets, so "eventually" is a number and never a flake. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// A host well past the budget, with a realistic mix of one-shell and
// several-shell sessions. 200 logons against a pool of 80.
const SESSIONS = 200;
const ORDER = host(SESSIONS, (id) => (id % 5 === 0 ? 3 : 1));
const ALL = new Set([...Array(SESSIONS).keys()]);

describe("the session scan rotates, so a large host's tail is not starved forever", () => {
  it("(control) an unrotated scan serves the same prefix every tick, forever", () => {
    // THE BUG, reproduced. This is what the loop did before: it walked
    // $allProcs, whose order CIM returns stably, so the served set was a pure
    // function of the process list and identical on every tick. The tail was not
    // "slower and partial" as OPERATIONS.md promised — it was never discovered
    // at all, which means never recovered, ever.
    const first = served(ORDER);
    for (let tick = 0; tick < 50; tick++) {
      expect([...served(ORDER)]).toEqual([...first]);
    }
    expect(first.size).toBe(MAX_SHELL_OWNER_LOOKUPS);
    // …and the sessions it never reaches, which is the whole complaint.
    const starved = [...ALL].filter((id) => !first.has(id));
    expect(starved.length).toBeGreaterThan(0);
    expect(starved).toContain(SESSIONS - 1);
  });

  it("reaches EVERY session from some offset — no permanently unreachable tail", () => {
    // The completeness statement, checked exhaustively rather than sampled:
    // sweeping every offset the script can draw, the union of the served sets is
    // the whole host. That is what turns permanent starvation into a delay.
    const union = new Set<number>();
    for (let at = 0; at < ORDER.length; at++) {
      for (const id of served(rotate(ORDER, at))) union.add(id);
    }
    expect(union.size).toBe(SESSIONS);
    // Anti-vacuity: an empty or single-session host would satisfy the above.
    expect(SESSIONS).toBeGreaterThan(MAX_SHELL_OWNER_LOOKUPS);
    expect(union).toEqual(ALL);
  });

  it("serves every session within a bounded number of ticks, at a drawn offset", () => {
    // Completeness over offsets does not by itself bound the WAIT, so this runs
    // the thing: uniform offsets from a fixed seed, and the worst session's
    // first service is recorded. MEASURED with this seed and this host shape —
    // 200 logons against a pool of 80 — the last session to be reached is
    // reached on tick 5; the assertion below carries headroom so an incidental
    // change to the model shape reports rather than breaks. The seed is fixed so
    // this is a measurement and not a coin toss, and it illustrates the expected
    // delay on ONE host shape — it is not a guarantee for every host.
    const draw = mulberry32(0x5eed);
    const firstServedAt = new Map<number, number>();
    const TICKS = 100;
    for (let tick = 1; tick <= TICKS; tick++) {
      const at = Math.floor(draw() * ORDER.length);
      for (const id of served(rotate(ORDER, at))) {
        if (!firstServedAt.has(id)) firstServedAt.set(id, tick);
      }
    }
    expect(firstServedAt.size).toBe(SESSIONS);
    const worst = Math.max(...firstServedAt.values());
    expect(worst).toBeLessThanOrEqual(10);
    // The control above is the anti-vacuity for this one: with a fixed offset
    // the same loop leaves `starved` sessions with no entry at all.
  });
});

describe("the shipped script implements the rotation the model above measures", () => {
  it("collects the candidates, then rotates them by a random start offset", () => {
    // The join between the model and the script, pinned as ONE EXACT BLOCK
    // rather than as a handful of `toContain` lines.
    //
    // WHY THE WHOLE BLOCK. It was written as separate substring checks first, and
    // a mutation walked straight through them: turning the guard into
    // `if ($false) {` left every pinned line present in the text but unreachable,
    // and all five tests in this file stayed green. A rotation is a property of a
    // block, not of the lines in it — a neutered guard, a reordered slice or a
    // dropped `+` is a different rotation, and each has to fail here.
    const block = script.slice(
      script.indexOf("  $shellCandidates = "),
      script.indexOf("  foreach ($e in $shellOrder) {"),
    );
    expect(block).toBe(
      [
        "  $shellCandidates = [System.Collections.ArrayList]::new()",
        "  foreach ($e in $allProcs) {",
        // The name read is guarded like the path read below, and fails OPEN:
        // the loop body is inside the outer try, so an unguarded read that
        // threw would reject the whole machine's snapshot.
        "    $procName = 'explorer.exe'",
        "    try { $procName = [string]$e.Name } catch { $procName = 'explorer.exe' }",
        "    if ($procName -ne 'explorer.exe') { continue }",
        // The domain the offset is drawn over is the PATH-VERIFIED candidates.
        // Filtering on the name alone let any user inflate the list with
        // processes called explorer.exe and so bias the draw — the served set
        // goes back to being near-fixed, which is what rotation exists to break.
        "    $verifiedShell = $true",
        "    if ($shellExe) {",
        "      try {",
        "        $candidatePath = [string]$e.ExecutablePath",
        "        if ($candidatePath -and -not $candidatePath.ToLowerInvariant()" +
          ".Equals($shellExe, $ordinal)) { $verifiedShell = $false }",
        "      } catch { $verifiedShell = $true }",
        "    }",
        "    if (-not $verifiedShell) { $unverifiedSessionShells++; continue }",
        "    $null = $shellCandidates.Add($e)",
        "  }",
        "  $shellOrder = @($shellCandidates)",
        "  try {",
        "    if ($shellOrder.Count -ge 2) {",
        "      $rotateAt = Get-Random -Minimum 0 -Maximum $shellOrder.Count",
        "      if ($rotateAt -gt 0) {",
        "        $shellOrder = @($shellOrder[$rotateAt..($shellOrder.Count - 1)])" +
          " + @($shellOrder[0..($rotateAt - 1)])",
        "      }",
        "    }",
        // A rotation that fails must not become a snapshot-level 'sessions'
        // error — that would recover nobody, which is worse than the starvation
        // it fixes.
        "  } catch { $shellOrder = @($shellCandidates) }",
        "",
      ].join("\n"),
    );
  });

  it("walks the ROTATED list for the lookup, never the raw enumeration", () => {
    // The pin that actually carries the property: rotating a list nothing reads
    // proves nothing. The loop containing the session GetOwnerSid call must be
    // the one over $shellOrder.
    const lines = script.split("\n");
    const site = lines.findIndex((line) => /getownersid/i.test(line) && line.includes("$e"));
    expect(site).toBeGreaterThan(0);
    const loopAbove = lines
      .slice(0, site)
      .map((line, i) => [i, line] as const)
      .filter(([, line]) => /^\s*foreach \(/.test(line))
      .at(-1);
    expect(loopAbove?.[1]).toContain("foreach ($e in $shellOrder)");
    // …and the surviving $allProcs pass over the same variable does no lookup:
    // it only collects, so the budget is spent in rotated order and nowhere else.
    const collect = script.slice(
      script.indexOf("foreach ($e in $allProcs)"),
      script.indexOf("foreach ($e in $shellOrder)"),
    );
    expect(collect.length).toBeGreaterThan(0);
    expect(collect.toLowerCase()).not.toContain("getownersid");
  });
});
