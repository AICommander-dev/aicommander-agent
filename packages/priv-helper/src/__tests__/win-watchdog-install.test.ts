import { describe, it, expect, vi } from "vitest";
import {
  createWatchdogState,
  evaluateTick,
  installBlockReason,
  startWindowsWatchdog,
  INSTALL_SETTLE_MS,
  WATCHDOG_MISSES_BEFORE_RECOVERY,
  type InstallSignals,
  type WatchdogSnapshot,
} from "../win-watchdog.js";
import {
  installIncompleteVerdict,
  looksLikeStaleInstallPath,
  helperManifestPath,
  manifestProbeLines,
  parseInstallManifestSignals,
  type InstallManifestSignals,
  MANIFEST_REL_POSIX,
  MANIFEST_SCHEMA,
  MAX_MANIFEST_FILES,
} from "../win-watchdog-install.js";
import { parseProbeOutput, __probeScript } from "../win-watchdog-probe.js";

// The 2026-09-02 case, in one line: an antivirus took 80 of the 81 files in
// `C:\Program Files\AI Commander\` and left the running exe, so every signal the
// watchdog had reported health while the app could not start — and it went on
// triggering the Relaunch task into it, once every couple of minutes, all night.
//
// WHAT THIS SUITE CANNOT ESTABLISH, said before anything else so a green run is
// not mistaken for a working check: no PowerShell runs here (this suite runs on
// macOS in CI), so the probe fragment is asserted as TEXT — substring and
// structural checks over generated source. Whether `Test-Path` really answers
// for a quarantined file, whether `ConvertFrom-Json` accepts the shipped
// manifest, and whether the counts come back the way the parser expects are all
// unverified until it is run on a real Windows box; OPERATIONS.md lists what
// that run has to check. What IS verified: the decision logic, the parser
// against the JSON shapes PowerShell produces, and the log lines an operator
// will actually read. The contract with the desktop package that PRODUCES the
// manifest is pinned in install-manifest-desktop-parity.test.ts — it reads a
// sibling package, and this suite has to load in the public agent mirror, which
// stages none.

const SID = "S-1-5-21-1-1-1-1001";

/** A machine where nothing blocks: settled install, exe present, no manifest. */
const CLEAN_INSTALL: InstallSignals = {
  updateTaskRunning: false,
  msSinceInstallDirChange: 24 * 60 * 60 * 1000,
  trayExeInstalled: true,
  manifest: null,
};

function manifest(over: Partial<InstallManifestSignals> = {}): InstallManifestSignals {
  return {
    totalFiles: 81,
    missingFiles: 0,
    missingCritical: 0,
    unreadableFiles: 0,
    version: "1.1.0",
    source: "install",
    ...over,
  };
}

/** The incident: 80 of 81 gone, 7 of them files the app cannot start without. */
const GUTTED = manifest({ missingFiles: 80, missingCritical: 7 });

function snapshot(over: Partial<WatchdogSnapshot> = {}): WatchdogSnapshot {
  return {
    sessions: [{ sessionId: 1, userSid: SID, autoStartEnabled: true, quitMarkerPresent: false }],
    trayOwnerSids: [],
    install: { ...CLEAN_INSTALL },
    skippedSessions: 0,
    unverifiedTrayProcesses: 0,
    unverifiedSessionShells: 0,
    ...over,
  };
}

/** Run one watchdog over a fixed snapshot for n ticks, collecting the log. */
async function runTicks(
  s: WatchdogSnapshot,
  n = WATCHDOG_MISSES_BEFORE_RECOVERY + 1,
): Promise<{ lines: string[]; triggered: number }> {
  const lines: string[] = [];
  const trigger = vi.fn(async () => undefined);
  const wd = startWindowsWatchdog({
    probe: async () => ({ ok: true as const, snapshot: s }),
    trigger,
    intervalMs: 60_000,
    log: (l) => lines.push(l),
  });
  for (let i = 0; i < n; i++) await wd.__tick();
  wd.stop();
  return { lines, triggered: trigger.mock.calls.length };
}

// --- the contract with the desktop package ----------------------------------
//
// The values this module copies from packages/desktop — MANIFEST_FILENAME,
// MANIFEST_SCHEMA, MANIFEST_REL_POSIX — are pinned to that declaration in
// install-manifest-desktop-parity.test.ts, not here. Reading a sibling package
// at collection time made this WHOLE suite unloadable in the public agent
// mirror, which stages only agent, protocol and priv-helper; the pins therefore
// sit in the one file mirror-agent.mjs's MONOREPO_ONLY excludes, and everything
// below runs on both sides.

// --- W1.3: a gutted install is not a machine to relaunch into ---------------

describe("installBlockReason — the install-incomplete verdict", () => {
  it("blocks when critical files are missing from a settled install", () => {
    expect(installBlockReason({ ...CLEAN_INSTALL, manifest: GUTTED })).toBe("install-incomplete");
  });

  it("does NOT block a healthy install", () => {
    expect(installBlockReason({ ...CLEAN_INSTALL, manifest: manifest() })).toBeNull();
  });

  it("does NOT block on missing files that are not critical", () => {
    // One quarantined per-locale .pak, or a README somebody deleted. The app
    // starts; refusing to recover it would be a worse outage than the damage.
    expect(
      installBlockReason({
        ...CLEAN_INSTALL,
        manifest: manifest({ missingFiles: 12, missingCritical: 0 }),
      }),
    ).toBeNull();
  });

  it("a machine that DENIES reads is not a gutted machine — nothing blocks", () => {
    // The defect this replaces: `Test-Path` answers $false for a denied
    // GetFileAttributes exactly as it does for a missing file, so a security
    // product's filter driver (the 2026-09-02 record has path-scoped denials
    // even to an elevated administrator) reported an INTACT install as gutted —
    // and `install-incomplete` is applied MACHINE-WIDE, so that one driver
    // suppressed crash recovery for every user on the box, indefinitely, with a
    // throttled log line an hour as the only sign. Denial is not absence.
    expect(
      installBlockReason({
        ...CLEAN_INSTALL,
        manifest: manifest({ missingFiles: 0, missingCritical: 0, unreadableFiles: 81 }),
      }),
    ).toBeNull();
  });

  it("still blocks when files are genuinely gone on a machine that also denies some", () => {
    // The other direction: unreadable entries must not become a get-out-of-jail
    // card for a real sweep. Absent is still absent.
    expect(
      installBlockReason({
        ...CLEAN_INSTALL,
        manifest: manifest({ missingFiles: 40, missingCritical: 7, unreadableFiles: 30 }),
      }),
    ).not.toBeNull();
  });

  it("a missing manifest changes NOTHING — it is never evidence of damage", () => {
    // An older build shipped none; a sweep may have taken the manifest too. Both
    // must be indistinguishable from health, or every pre-manifest install would
    // stop being recovered the day this shipped.
    expect(installBlockReason(CLEAN_INSTALL)).toBeNull();
    expect(installBlockReason({ ...CLEAN_INSTALL, manifest: null })).toBeNull();
  });

  it("does not trip on an install in progress — the Update task is running", () => {
    // Mid-install the files ARE missing. The existing in-flight signal covers
    // it; no second mechanism was invented for the same question.
    const s = { ...CLEAN_INSTALL, manifest: GUTTED, updateTaskRunning: true };
    expect(installIncompleteVerdict(s)).toBeNull();
    expect(installBlockReason(s)).toBe("update-task-running");
  });

  it("does not trip while $INSTDIR is still being written", () => {
    // A hand-extracted app-64.7z, or NSIS writing the directory: fresh mtime.
    const s = {
      ...CLEAN_INSTALL,
      manifest: GUTTED,
      msSinceInstallDirChange: INSTALL_SETTLE_MS - 1,
    };
    expect(installIncompleteVerdict(s)).toBeNull();
    expect(installBlockReason(s)).toBe("install-dir-just-changed");
    // …and it DOES trip the moment that window closes, so the settle window is
    // the only thing separating the two answers.
    expect(
      installIncompleteVerdict({ ...s, msSinceInstallDirChange: INSTALL_SETTLE_MS }),
    ).not.toBeNull();
  });

  it("honours the same settle window the rest of the module uses", () => {
    // The constant is restated in win-watchdog-install.ts to avoid a runtime
    // import cycle; this is what keeps the two numbers equal.
    const at = (age: number): boolean =>
      installIncompleteVerdict({
        ...CLEAN_INSTALL,
        manifest: GUTTED,
        msSinceInstallDirChange: age,
      }) !== null;
    expect(at(INSTALL_SETTLE_MS - 1)).toBe(false);
    expect(at(INSTALL_SETTLE_MS)).toBe(true);
  });

  it("an unknown install-dir age does not suppress the verdict", () => {
    // A null age means the directory is absent, which already blocks on
    // tray-exe-missing; it must not also make the manifest verdict unsayable.
    expect(
      installIncompleteVerdict({
        ...CLEAN_INSTALL,
        manifest: GUTTED,
        msSinceInstallDirChange: null,
      }),
    ).not.toBeNull();
  });
});

describe("evaluateTick — a gutted install stops the relaunches", () => {
  it("never triggers, however many ticks pass", () => {
    const state = createWatchdogState();
    const s = snapshot({ install: { ...CLEAN_INSTALL, manifest: GUTTED } });
    let last = evaluateTick(state, s);
    for (let i = 0; i < 20; i++) last = evaluateTick(state, s);
    expect(last.trigger).toEqual([]);
    expect(last.blockedBy).toBe("install-incomplete");
    expect(last.verdicts[0]?.outcome).toBe("waiting");
  });

  it("still recovers a healthy install with the same manifest shipped", () => {
    // The watchdog must keep doing its job: a manifest that reports no damage is
    // not a new reason to sit still.
    const state = createWatchdogState();
    const s = snapshot({ install: { ...CLEAN_INSTALL, manifest: manifest() } });
    evaluateTick(state, s);
    expect(evaluateTick(state, s).trigger).toMatchObject([{ sessionId: 1, userSid: SID }]);
  });
});

describe("the log line a support engineer actually reads", () => {
  it("names the counts and the build for a gutted install", async () => {
    const { lines, triggered } = await runTicks(
      snapshot({ install: { ...CLEAN_INSTALL, manifest: GUTTED } }),
    );
    const line = lines.find((l) => l.includes("install-incomplete"));
    expect(line).toBeDefined();
    expect(line).toContain("files=81 missing=80 critical=7 unreadable=0 version=1.1.0 source=install");
    expect(line).toContain("installed files are missing");
    // The whole point: it stopped relaunching into it.
    expect(triggered).toBe(0);
  });

  it("says how many files it could NOT read — the third verdict, in the log", async () => {
    // THE REGRESSION: `unreadableFiles` was measured by the probe, parsed by the
    // wire, carried through the snapshot — and dropped. `install-incomplete`
    // printed `files=81 missing=40 critical=7` with 34 entries unaccounted for,
    // and a machine where a filter driver denied every read of %ProgramFiles%
    // printed nothing at all, which is precisely what a healthy machine prints.
    // Refusing to count a denial as damage is only a third verdict if somebody
    // can hear it.
    const { lines } = await runTicks(
      snapshot({
        install: {
          ...CLEAN_INSTALL,
          manifest: manifest({ missingFiles: 40, missingCritical: 7, unreadableFiles: 34 }),
        },
      }),
    );
    const line = lines.find((l) => l.includes("install-incomplete"));
    expect(line).toContain("missing=40 critical=7 unreadable=34");
  });

  it("says so when the ONLY thing wrong is that N files could not be read", async () => {
    const { lines, triggered } = await runTicks(
      snapshot({
        install: { ...CLEAN_INSTALL, manifest: manifest({ unreadableFiles: 34, source: "helper" }) },
      }),
    );
    const line = lines.find((l) => l.includes("install-unreadable"));
    expect(line).toBeDefined();
    expect(line).toContain("files=81 missing=0 unreadable=34");
    expect(line).toContain("source=helper");
    expect(line).toContain("not evidence of damage");
    // AND IT CHANGES NOTHING. A denial may never suppress recovery: that is the
    // machine-wide denial this counter exists to keep out of the decision.
    expect(lines.some((l) => l.includes("install-incomplete"))).toBe(false);
    expect(triggered).toBeGreaterThan(0);
  });

  it("says nothing at all on a healthy install, or when no manifest shipped", async () => {
    for (const m of [manifest(), null]) {
      const { lines } = await runTicks(snapshot({ install: { ...CLEAN_INSTALL, manifest: m } }));
      expect(lines.some((l) => l.includes("install-incomplete"))).toBe(false);
      // Anti-vacuity: the run really did tick and really did act.
      expect(lines.some((l) => l.includes("watchdog relaunch "))).toBe(true);
    }
  });

  it("stays silent while an install is in flight", async () => {
    const { lines } = await runTicks(
      snapshot({ install: { ...CLEAN_INSTALL, manifest: GUTTED, updateTaskRunning: true } }),
      10,
    );
    expect(lines).toEqual([]);
  });

  it("is logged once an hour, not once a minute", async () => {
    // A standing condition: the install stays gutted until somebody repairs it.
    // One line a minute into a world-readable SYSTEM file is the spam the
    // throttle exists to prevent.
    const { lines } = await runTicks(
      snapshot({ install: { ...CLEAN_INSTALL, manifest: GUTTED } }),
      30,
    );
    expect(lines.filter((l) => l.includes("install-incomplete"))).toHaveLength(1);
  });

  it("never repeats a version string it does not recognise", async () => {
    // The version is the only new observed STRING on a watchdog line. It comes
    // from %ProgramFiles% (admin-owned), and it is still re-validated: anything
    // that is not a plain dotted version is replaced rather than printed.
    const { lines } = await runTicks(
      snapshot({
        install: {
          ...CLEAN_INSTALL,
          manifest: manifest({
            missingCritical: 1,
            missingFiles: 1,
            version: '"C:\\Program Files\\x.exe" --key=hunter2',
          }),
        },
      }),
    );
    const line = lines.find((l) => l.includes("install-incomplete"))!;
    expect(line).toContain("version=unknown");
    expect(line).not.toContain("hunter2");
    expect(line).not.toMatch(/[\\"'$%]/);
  });
});

// --- W7: a stale relaunch path, told apart from an absent tray --------------

describe("looksLikeStaleInstallPath", () => {
  it("is the measured dir having no exe WHILE a tray runs elsewhere", () => {
    expect(
      looksLikeStaleInstallPath(
        snapshot({
          install: { ...CLEAN_INSTALL, trayExeInstalled: false },
          unverifiedTrayProcesses: 5,
        }),
      ),
    ).toBe(true);
  });

  it("is NOT a genuinely absent tray", () => {
    // Uninstalled, or mid-install: no exe, and nothing running anywhere either.
    expect(
      looksLikeStaleInstallPath(
        snapshot({ install: { ...CLEAN_INSTALL, trayExeInstalled: false } }),
      ),
    ).toBe(false);
  });

  it("is NOT a lookalike next to a healthy install", () => {
    // The <= 1.0.14 per-user install autostarting its own copy: the exe IS where
    // we measure, so those processes really are the impostors we say they are.
    expect(looksLikeStaleInstallPath(snapshot({ unverifiedTrayProcesses: 5 }))).toBe(false);
  });
});

describe("the stale-path line replaces the misleading one", () => {
  it("reports install-path-stale, not tray-lookalikes", async () => {
    const { lines, triggered } = await runTicks(
      snapshot({
        install: { ...CLEAN_INSTALL, trayExeInstalled: false },
        unverifiedTrayProcesses: 5,
      }),
      10,
    );
    const line = lines.find((l) => l.includes("install-path-stale"));
    expect(line).toBeDefined();
    expect(line).toContain("count=5");
    expect(line).toContain("no tray exe where the relaunch task points");
    expect(lines.some((l) => l.includes("tray-lookalikes"))).toBe(false);
    // It changes the diagnosis, never the action: tray-exe-missing still blocks.
    expect(triggered).toBe(0);
  });

  it("still reports tray-lookalikes when the install is where we think it is", async () => {
    const { lines } = await runTicks(snapshot({ unverifiedTrayProcesses: 5 }), 3);
    expect(lines.some((l) => l.includes("tray-lookalikes"))).toBe(true);
    expect(lines.some((l) => l.includes("install-path-stale"))).toBe(false);
  });

  it("a tray that is simply not running produces neither line", async () => {
    const { lines, triggered } = await runTicks(
      snapshot({ install: { ...CLEAN_INSTALL, trayExeInstalled: false } }),
      3,
    );
    expect(lines.some((l) => l.includes("install-path-stale"))).toBe(false);
    expect(lines.some((l) => l.includes("tray-lookalikes"))).toBe(false);
    expect(triggered).toBe(0);
  });
});

// --- the wire ---------------------------------------------------------------

describe("parseInstallManifestSignals", () => {
  const good = {
    version: "1.1.0",
    totalFiles: 81,
    missingFiles: 80,
    missingCritical: 7,
    unreadableFiles: 0,
    source: "install",
  };

  it("parses the shape the script emits", () => {
    expect(parseInstallManifestSignals(good)).toEqual(good);
  });

  it("tolerates PowerShell's numbers-as-strings", () => {
    expect(
      parseInstallManifestSignals({ ...good, totalFiles: "81", missingCritical: "7" }),
    ).toEqual(good);
  });

  it("defaults unreadableFiles to 0 — a diagnostic count may not reject a reply", () => {
    // It can neither raise an alarm nor suppress one, so an older or partial
    // reply that omits it must still produce a usable verdict.
    const { unreadableFiles: _drop, ...without } = good;
    expect(parseInstallManifestSignals(without)?.unreadableFiles).toBe(0);
    expect(parseInstallManifestSignals({ ...good, unreadableFiles: "x" })?.unreadableFiles).toBe(0);
    expect(parseInstallManifestSignals({ ...good, missingFiles: 10, unreadableFiles: "4" })?.unreadableFiles).toBe(4);
  });

  it("rejects counts that cannot all be true of one directory", () => {
    // 81 files cannot be 80 missing AND 30 unreadable: that is not an install we
    // understand, and an unread reply is never an alarm.
    expect(parseInstallManifestSignals({ ...good, unreadableFiles: 30 })).toBeNull();
    expect(parseInstallManifestSignals({ ...good, missingFiles: 0, unreadableFiles: 99 })).toBeNull();
  });

  it("degrades to null — never to damage — on anything it cannot read", () => {
    for (const bad of [
      null,
      undefined,
      "install-manifest.json",
      [],
      {},
      { ...good, totalFiles: "many" },
      { ...good, missingFiles: undefined },
      // Counts that cannot all be true of one directory.
      { ...good, missingFiles: 999 },
      { ...good, missingCritical: 999 },
    ]) {
      expect(parseInstallManifestSignals(bad)).toBeNull();
    }
  });

  it("drops a version it does not recognise but keeps the counts", () => {
    const parsed = parseInstallManifestSignals({ ...good, version: "../../etc/passwd" });
    expect(parsed?.version).toBe("");
    expect(parsed?.missingCritical).toBe(7);
  });
});

describe("parseProbeOutput — the manifest field may never reject a snapshot", () => {
  const wellFormed = {
    trayOwnerSids: [SID],
    unverifiedTrayProcesses: 0,
    sessions: [{ sessionId: 1, userSid: SID, autoStartEnabled: true, quitMarkerPresent: false }],
    skippedSessions: 0,
    unverifiedSessionShells: 0,
    updateTaskRunning: false,
    msSinceInstallDirChange: 900000,
    trayExeInstalled: true,
    installManifest: {
      version: "1.1.0",
      totalFiles: 81,
      missingFiles: 80,
      missingCritical: 7,
      unreadableFiles: 0,
      source: "install",
    },
    queryErrors: [],
  };

  it("carries the verdict through", () => {
    const snap = parseProbeOutput(JSON.stringify(wellFormed));
    expect(snap?.install.manifest).toEqual(wellFormed.installManifest);
    expect(installBlockReason(snap!.install)).toBe("install-incomplete");
  });

  it("an absent, null or malformed field leaves a usable snapshot", () => {
    // THE EXCEPTION TO THE PARSER'S HOUSE RULE, and the reason for it: every
    // other field reads permissively when missing ("nothing is running"), so a
    // missing one must skip the tick. This one can only ADD a block, so
    // rejecting over it would let a diagnostic file deny recovery to every user
    // on the machine — a machine-wide kill switch on a field that decides
    // nothing.
    const { installManifest: _drop, ...absent } = wellFormed;
    for (const raw of [
      absent,
      { ...wellFormed, installManifest: null },
      { ...wellFormed, installManifest: "no" },
      { ...wellFormed, installManifest: { totalFiles: 81 } },
    ]) {
      const snap = parseProbeOutput(JSON.stringify(raw));
      expect(snap).not.toBeNull();
      expect(snap?.install.manifest).toBeNull();
      expect(installBlockReason(snap!.install)).toBeNull();
    }
  });
});

// --- the probe fragment, as far as macOS can go -----------------------------

describe("manifestProbeLines (text only — no PowerShell runs here)", () => {
  const script = manifestProbeLines().join("\n");

  it("is spliced into the probe and emits the field the parser reads", () => {
    const full = __probeScript();
    expect(full).toContain(script);
    expect(full).toContain("installManifest = $installManifest");
  });

  it("reads the manifest from the DERIVED install dir, never from an env var", () => {
    // The same rule as the rest of the probe: as SYSTEM the environment is
    // stripped (12 variables, no ProgramFiles), so any $env: read, any
    // ExpandEnvironmentVariables and any expanding registry read is a silent
    // death on every tick.
    expect(script).toContain("Join-Path $installDir 'resources\\install-manifest.json'");
    expect(script).not.toContain("$env:");
    expect(script).not.toContain("ExpandEnvironmentVariables");
  });

  it("counts a file as missing ONLY for the two exception types that mean absence", () => {
    // The bug this pins was invisible to a substring assertion, so this reads the
    // DATA out of the generated script instead: the set of exception types whose
    // presence in the chain marks an entry absent. It must be exactly
    // FileNotFoundException and DirectoryNotFoundException.
    //
    // Anything else — UnauthorizedAccessException from a filter driver or a DACL,
    // IOException from a lock — means we did not find out, and IOException in
    // particular is the BASE class of both of the above, so testing for it would
    // silently re-admit every denial as damage.
    const tested = [...script.matchAll(/\$ex -is \[System\.IO\.([A-Za-z]+)\]/g)].map((m) => m[1]);
    expect(new Set(tested)).toEqual(new Set(["FileNotFoundException", "DirectoryNotFoundException"]));

    // ...and the counters are reached only through that decision: an entry we
    // could not read increments `$unreadable` and jumps, and `$missing++` is
    // guarded by `$absent`. `Test-Path`, whose $false answer conflates the two,
    // must not have come back.
    expect(script).not.toContain("Test-Path -LiteralPath $full");
    expect(script).toMatch(/if \(\$answered\) \{ continue \}\s*\n\s*if \(-not \$absent\) \{ \$unreadable\+\+; continue \}\s*\n\s*\$missing\+\+/);
  });

  it("only STATS the paths it reads, and refuses any that could escape the root", () => {
    // The module's guarantee: no observed value becomes a path we execute. These
    // become an argument to a .NET call, inside the admin-owned install dir, and
    // only after the entry has passed the shared entry-path rule.
    expect(script).toContain("[void][System.IO.File]::GetAttributes($full)");
    expect(script).toContain("$rel.StartsWith('/', $ordinal)");
    expect(script).toContain("$rel -match '(^|/)\\.{1,2}(/|$)'");
    expect(script).toContain("$rel -match '[\\\\:]'");
    // Nothing is invoked, started or dot-sourced with a value from the file.
    expect(script).not.toMatch(/Start-Process|Invoke-Expression|&\s*\$/);
  });

  // ── the rule itself ────────────────────────────────────────────────────────
  //
  // This fragment is one of five statements of one rule (declared in
  // desktop/src/install-manifest-contract.mjs). It is PowerShell, and no
  // PowerShell host runs this suite, so it is TRANSLITERATED — worthless unless
  // the generated lines still say what the transliteration claims, which is what
  // the pin below asserts. Until 2026-09-03 this copy rejected `%` while the
  // installer's copy allowed it: two readers of one manifest, disagreeing about
  // what the manifest says.
  //
  // The transliteration and its run over the SHARED table read the declaration
  // in packages/desktop, which the public agent mirror does not stage, so they
  // live in install-manifest-desktop-parity.test.ts. What stays here is the pin
  // itself — the half that needs nothing outside this package, and the half
  // without which the transliteration means nothing. Change one, change both.

  /** The rule's lines out of the generated script, in order. */
  function probeRuleLines(): string[] {
    return script
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.startsWith("if ([string]::IsNullOrWhiteSpace($rel))") || (line.startsWith("if ($rel") && line.endsWith("{ continue }")));
  }

  it("states the rule in exactly the lines the transliteration mirrors", () => {
    expect(probeRuleLines()).toEqual([
      "if ([string]::IsNullOrWhiteSpace($rel)) { continue }",
      "if ($rel -match '[\\\\:]') { continue }",
      "if ($rel.StartsWith('/', $ordinal)) { continue }",
      "if ($rel -match '(^|/)(/|$)') { continue }",
      "if ($rel -match '(^|/)\\.{1,2}(/|$)') { continue }",
      "if ($rel -match '[\\u0000-\\u001F\\u007F<>\"|?*]') { continue }",
    ]);
  });

  it("checks the schema and the manifest's own idea of where it lives", () => {
    expect(script).toContain(`[int]$manifest.schema -eq ${MANIFEST_SCHEMA}`);
    expect(script).toContain(`[string]$manifest.manifestPath -eq '${MANIFEST_REL_POSIX}'`);
  });

  it("bounds the work it does in one tick", () => {
    expect(script).toContain(`if ($seen -ge ${MAX_MANIFEST_FILES}) { break }`);
    expect(script).toContain("$manifestItem.Length -le");
  });

  it("degrades instead of failing the whole snapshot", () => {
    // The one query in the probe that does NOT add to $queryErrors: an
    // unreadable manifest must not skip the tick, because a skipped tick
    // recovers nobody on the machine.
    expect(script).toContain("catch { $installManifest = $null }");
    expect(script).not.toContain("$queryErrors");
  });

  it("counts, and never names, the files it finds missing", () => {
    // The log is world-readable and written as SYSTEM. A file NAME is the first
    // thing that would smuggle text into it, so the reply carries three integers
    // and a version and nothing else.
    expect(script).toContain("totalFiles = $seen");
    expect(script).toContain("missingFiles = $missing");
    expect(script).toContain("missingCritical = $missingCritical");
    expect(script).not.toContain("$missingNames");
    expect(script).not.toContain("$rel }");
  });

  it("takes presence, never hashes — this runs every 60 seconds", () => {
    expect(script).not.toMatch(/Get-FileHash|sha256|SHA256/);
  });

  it("(smoke) has balanced braces and parentheses", () => {
    const count = (c: string): number => script.split(c).length - 1;
    expect(count("{")).toBe(count("}"));
    expect(count("(")).toBe(count(")"));
  });
});

describe("the fallback copy — the manifest outlives the directory it describes", () => {
  /**
   * THE REGRESSION THIS PINS, and it is the one that made the whole check a
   * no-op on the machine it was written for. The manifest is a file inside the
   * install directory, so the sweep that removed 80 of 81 files removed it too:
   * `Test-Path` answered $false, `installManifest` stayed $null,
   * `installIncompleteVerdict` produced nothing, and the watchdog went on
   * triggering the Relaunch task into an install that could not start — exactly
   * the behaviour the check was added to replace. Delete the sibling candidate
   * and these fail.
   */
  const HELPER_MANIFEST = "C:\\Program Files\\AI Commander Privileged Helper\\install-manifest.json";
  const script = manifestProbeLines(HELPER_MANIFEST).join("\n");

  it("reads a SECOND candidate, beside this binary, when the in-tree one is gone", () => {
    expect(script).toContain(`[void]$manifestCandidates.Add(@('helper', '${HELPER_MANIFEST}'))`);
    // ...and it is genuinely a fallback: the in-tree copy is added first and the
    // loop stops at the first candidate that produced a reading.
    const inTree = script.indexOf("@('install'");
    const sibling = script.indexOf("@('helper'");
    expect(inTree).toBeGreaterThanOrEqual(0);
    expect(sibling).toBeGreaterThan(inTree);
    expect(script).toContain("if ($installManifest -ne $null) { continue }");
  });

  it("reports WHICH copy it counted, so a count from the fallback is not silently equal", () => {
    expect(script).toContain("source = [string]$cand[0]");
  });

  it("still refuses to guess the directory the files are counted in", () => {
    // The fallback moves the INVENTORY, never the measurement: with no
    // $installDir derived from the admin-owned Relaunch task there is nothing to
    // stat the relative paths under, and the whole block is skipped. "No root"
    // is no evidence — never damage.
    expect(script).toContain("if ($installDir) {");
    expect(script).toContain("$full = Join-Path $installDir");
    expect(script).not.toContain("Join-Path $helper");
  });

  it("omits the candidate entirely rather than quoting a path it does not trust", () => {
    expect(manifestProbeLines(null).join("\n")).not.toContain("@('helper'");
  });

  it("(smoke) still has balanced braces and parentheses with both candidates", () => {
    const count = (c: string): number => script.split(c).length - 1;
    expect(count("{")).toBe(count("}"));
    expect(count("(")).toBe(count(")"));
  });
});

describe("helperManifestPath — the one directory this module quotes into a script", () => {
  it("is this binary's own directory, which is where the installer put the copy", () => {
    expect(helperManifestPath("C:\\Program Files\\AI Commander Privileged Helper\\helper.exe")).toBe(
      "C:\\Program Files\\AI Commander Privileged Helper\\install-manifest.json",
    );
  });

  it.each([
    // Not rooted at a drive: a UNC path would make the read a network call
    // inside the tick budget, and a relative one is not a location at all.
    ["\\\\server\\share\\helper.exe"],
    ["helper.exe"],
    ["/usr/local/bin/aicommander-priv-helper"],
    // An unexpanded environment reference must FAIL, never be resolved — the
    // same rule the tray-exe extraction applies to the Relaunch task's action.
    ["C:\\%ProgramFiles%\\x\\helper.exe"],
  ])("declines a location it will not quote: %j", (execPath) => {
    expect(helperManifestPath(execPath)).toBeNull();
  });

  it("declines a location carrying a control character", () => {
    expect(helperManifestPath("C:\\bad\u0007dir\\helper.exe")).toBeNull();
  });
});
