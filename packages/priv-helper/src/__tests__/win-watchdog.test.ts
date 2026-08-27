import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  backoffTicks,
  createWatchdogState,
  evaluateTick,
  hasLiveTrayMainForUser,
  installBlockReason,
  startWindowsWatchdog,
  INSTALL_SETTLE_MS,
  WATCHDOG_FLAP_QUIET_TICKS,
  WATCHDOG_MAX_BACKOFF_TICKS,
  WATCHDOG_MISSES_BEFORE_RECOVERY,
  type InstallSignals,
  type UserSession,
  type WatchdogSnapshot,
} from "../win-watchdog.js";

// --- builders: a machine where nothing blocks and one user wants the tray -----

const WATCHDOG_SOURCE = fileURLToPath(new URL("../win-watchdog.ts", import.meta.url));

const CLEAN_INSTALL: InstallSignals = {
  updateTaskRunning: false,
  msSinceInstallDirChange: 24 * 60 * 60 * 1000,
  trayExeInstalled: true,
};

const SID_A = "S-1-5-21-1-1-1-1001";
const SID_B = "S-1-5-21-1-1-1-1002";

function session(over: Partial<UserSession> = {}): UserSession {
  return {
    sessionId: 1,
    userSid: SID_A,
    autoStartEnabled: true,
    quitMarkerPresent: false,
    ...over,
  };
}

function snapshot(over: Partial<WatchdogSnapshot> = {}): WatchdogSnapshot {
  return {
    sessions: [session()],
    trayOwnerSids: [],
    install: { ...CLEAN_INSTALL },
    skippedSessions: 0,
    unverifiedTrayProcesses: 0,
    unverifiedSessionShells: 0,
    ...over,
  };
}

/** Run N ticks of the same snapshot and return the last result. */
function ticks(state: ReturnType<typeof createWatchdogState>, s: WatchdogSnapshot, n: number) {
  let last = evaluateTick(state, s);
  for (let i = 1; i < n; i++) last = evaluateTick(state, s);
  return last;
}

// --- liveness, as the ONE bit per user the probe now hands over ---------------

describe("hasLiveTrayMainForUser — one bit per user, not a process list", () => {
  // The probe aggregates: it verifies the install directory, drops Electron's
  // GPU/utility/renderer children (which share the image name) and asks each
  // survivor's own token whose it is, then emits the SET of owning SIDs. Doing
  // that HERE is what made the reply's size follow the process list, which an
  // unprivileged user chooses — see WatchdogSnapshot.trayOwnerSids. The
  // main-vs-child rules themselves are pinned in win-watchdog-probe.test.ts,
  // against the script text that now applies them.
  it("says yes for a user in the set and no for one who is not", () => {
    expect(hasLiveTrayMainForUser([SID_A], SID_A)).toBe(true);
    expect(hasLiveTrayMainForUser([SID_A], SID_B)).toBe(false);
    // Anti-vacuity: an empty set is not what makes the negative above true.
    expect(hasLiveTrayMainForUser([], SID_A)).toBe(false);
  });

  it("matches the owner SID case-insensitively, like every other SID here", () => {
    expect(hasLiveTrayMainForUser([SID_A.toLowerCase()], SID_A)).toBe(true);
    expect(hasLiveTrayMainForUser([SID_A], SID_A.toLowerCase())).toBe(true);
  });

  it("an empty SID matches nothing, from either side", () => {
    // A tray whose owner the probe could not resolve contributes no entry at
    // all; if one ever arrived, it must not suppress anybody — and a user with
    // no SID must not be matched by it either.
    expect(hasLiveTrayMainForUser([""], SID_A)).toBe(false);
    expect(hasLiveTrayMainForUser([""], "")).toBe(false);
    expect(hasLiveTrayMainForUser([SID_A], "")).toBe(false);
    // Control: the same call with real SIDs does match.
    expect(hasLiveTrayMainForUser(["", SID_A], SID_A)).toBe(true);
  });
});

// --- session awareness (review finding #5) -----------------------------------

describe("evaluateTick — per-user, never machine-wide", () => {
  it("recovers a dead user even while ANOTHER user's tray is alive", () => {
    const state = createWatchdogState();
    const s = snapshot({
      sessions: [session({ sessionId: 1, userSid: SID_A }), session({ sessionId: 2, userSid: SID_B })],
      trayOwnerSids: [SID_A],
    });
    const result = ticks(state, s, WATCHDOG_MISSES_BEFORE_RECOVERY);
    expect(result.trigger).toMatchObject([{ sessionId: 2, userSid: SID_B }]);
    expect(result.verdicts.find((v) => v.sessionId === 1)?.outcome).toBe("tray-running");
  });

  it("does not recover a session whose own MAIN tray is alive", () => {
    const state = createWatchdogState();
    const s = snapshot({ trayOwnerSids: [SID_A] });
    expect(ticks(state, s, 5).trigger).toEqual([]);
  });

  it("recovers a session whose user owns no MAIN tray", () => {
    // What a machine with only a leftover Electron child looks like from here:
    // the probe drops children before grouping, so the user simply is not in
    // the set. (That the child is dropped is pinned in the probe's tests.)
    const state = createWatchdogState();
    const s = snapshot({ trayOwnerSids: [] });
    expect(ticks(state, s, WATCHDOG_MISSES_BEFORE_RECOVERY).trigger).toMatchObject([
      { sessionId: 1, userSid: SID_A },
    ]);
  });
});

// --- one user, several sessions ----------------------------------------------

describe("evaluateTick — a tray is per USER, not per session", () => {
  // Electron's requestSingleInstanceLock is scoped to the per-user userData dir,
  // so one user logged on twice (console + RDP, or a reconnected disconnected
  // session) can only ever have ONE live tray. Keyed per session, the second
  // session was permanently "tray missing": it triggered forever, climbed to the
  // ceiling and never converged — a console flash an hour, indefinitely.
  const twoSessions = () =>
    snapshot({
      sessions: [
        session({ sessionId: 1, userSid: SID_A }),
        session({ sessionId: 2, userSid: SID_A }),
      ],
      trayOwnerSids: [SID_A],
    });

  it("counts the user's ONE tray, however many sessions they are logged into", () => {
    const state = createWatchdogState();
    const result = ticks(state, twoSessions(), 10);
    expect(result.trigger).toEqual([]);
    // One verdict for the USER, not one per session.
    expect(result.verdicts).toHaveLength(1);
    expect(result.verdicts[0]).toMatchObject({ userSid: SID_A, outcome: "tray-running" });
    expect(state.users.size).toBe(0);
  });

  it("(control) the same two sessions with NO tray anywhere do get one relaunch", () => {
    // The counterpart that keeps the test above from passing vacuously: the
    // suppression must come from the live tray, not from the grouping.
    const state = createWatchdogState();
    const dead = { ...twoSessions(), trayOwnerSids: [] };
    const result = ticks(state, dead, WATCHDOG_MISSES_BEFORE_RECOVERY);
    expect(result.trigger).toHaveLength(1);
    expect(result.trigger[0]).toMatchObject({ userSid: SID_A, sessionId: 1 });
  });

  it("aims the relaunch at the user's LOWEST session id", () => {
    // RunEx needs one concrete session; the lowest is the console session on a
    // workstation. Whichever it picks, exactly ONE relaunch is triggered.
    const state = createWatchdogState();
    const s = snapshot({
      sessions: [
        session({ sessionId: 7, userSid: SID_A }),
        session({ sessionId: 3, userSid: SID_A }),
      ],
    });
    expect(ticks(state, s, WATCHDOG_MISSES_BEFORE_RECOVERY).trigger).toMatchObject([
      { sessionId: 3, userSid: SID_A },
    ]);
  });

  it("lets the per-user quit marker suppress ALL of that user's sessions", () => {
    // The per-session model could not express this: the marker lives in one
    // profile, so a session whose read missed it would have relaunched anyway.
    const state = createWatchdogState();
    const s = snapshot({
      sessions: [
        session({ sessionId: 1, userSid: SID_A, quitMarkerPresent: true }),
        session({ sessionId: 2, userSid: SID_A, quitMarkerPresent: false }),
      ],
    });
    const result = ticks(state, s, 10);
    expect(result.trigger).toEqual([]);
    expect(result.verdicts[0]?.outcome).toBe("user-quit");
  });

  it("keeps one state entry per user, and drops it when the user logs off", () => {
    const state = createWatchdogState();
    const s = snapshot({
      sessions: [
        session({ sessionId: 1, userSid: SID_A }),
        session({ sessionId: 2, userSid: SID_A }),
      ],
    });
    evaluateTick(state, s);
    expect(state.users.size).toBe(1);
    // A user with no sessions at all has nothing to recover and no state.
    evaluateTick(state, snapshot({ sessions: [] }));
    expect(state.users.size).toBe(0);
  });

  it("treats a SID that differs only in case as the same user", () => {
    const state = createWatchdogState();
    evaluateTick(state, snapshot({ sessions: [session({ userSid: SID_A })] }));
    evaluateTick(
      state,
      snapshot({ sessions: [session({ sessionId: 2, userSid: SID_A.toLowerCase() })] }),
    );
    expect(state.users.size).toBe(1);
  });
});

// --- liveness comes from the owner set, not from session discovery -----------

describe("evaluateTick — a tray in a session discovery cannot see is still alive", () => {
  // THE CASE THAT MOTIVATED THIS. Sessions are discovered by enumerating
  // explorer.exe, so a session without a conventional shell — RemoteApp, or a
  // machine whose shell has been replaced — is not in `sessions` at all. When
  // liveness was decided from those sessions, a tray running in one of them was
  // invisible: the user read as tray-less, the watchdog relaunched into the
  // session it COULD see, the per-user single-instance lock killed the new
  // process at once, and the cycle escalated to the backoff ceiling and stayed
  // there — one console flash an hour, forever, on a healthy machine.
  //
  // It is now structural rather than merely correct: `trayOwnerSids` carries no
  // session at all, so there is no session for a tray to be hidden in.
  const remoteApp = (over: Partial<WatchdogSnapshot> = {}): WatchdogSnapshot =>
    snapshot({
      sessions: [session({ sessionId: 1, userSid: SID_A })],
      trayOwnerSids: [SID_A],
      ...over,
    });

  it("(fixture) liveness carries no session id for the decision to key on", () => {
    // Anti-vacuity, and the structural half of the property: the tests below
    // cannot pass "because the tray sits in a discovered session", since a tray
    // has no session here — and the fixture really does report a live tray.
    const s = remoteApp();
    expect(s.trayOwnerSids).toEqual([SID_A]);
    expect(s.sessions.length).toBeGreaterThan(0);
    expect(JSON.stringify(s.trayOwnerSids)).not.toContain("sessionId");
  });

  it("reports tray-running and relaunches nothing", () => {
    const state = createWatchdogState();
    // Well past the debounce and past the point the old backoff would have
    // started escalating.
    const result = ticks(state, remoteApp(), 10);
    expect(result.verdicts).toHaveLength(1);
    expect(result.verdicts[0]).toMatchObject({ userSid: SID_A, outcome: "tray-running" });
    expect(result.trigger).toEqual([]);
    expect(state.users.size).toBe(0);
  });

  it("(control) the SAME fixture with the tray genuinely gone DOES relaunch", () => {
    // The positive counterpart to the negative assertion above: the suppression
    // must come from the observed tray, not from the user never being evaluated.
    const state = createWatchdogState();
    const result = ticks(state, remoteApp({ trayOwnerSids: [] }), WATCHDOG_MISSES_BEFORE_RECOVERY);
    expect(result.trigger).toMatchObject([{ userSid: SID_A, sessionId: 1 }]);
  });

  it("(control) a tray belonging to ANOTHER user does not suppress", () => {
    // …and the suppression must come from the OWNER, not merely from "some tray
    // exists somewhere".
    const state = createWatchdogState();
    const result = ticks(
      state,
      remoteApp({ trayOwnerSids: [SID_B] }),
      WATCHDOG_MISSES_BEFORE_RECOVERY,
    );
    expect(result.trigger).toMatchObject([{ userSid: SID_A, sessionId: 1 }]);
  });

  it("evaluates nobody for a user with no discoverable session at all", () => {
    // A user whose ONLY session is invisible has no desktop we could aim RunEx
    // at, so there is nothing to do — and, crucially, nothing to relaunch.
    const state = createWatchdogState();
    const result = ticks(state, snapshot({ sessions: [], trayOwnerSids: [SID_A] }), 10);
    expect(result.verdicts).toEqual([]);
    expect(result.trigger).toEqual([]);
  });
});

// --- consent (review finding #4) ---------------------------------------------

describe("evaluateTick — the user's intent wins", () => {
  it("never resurrects a user who turned autostart OFF (no Run entry)", () => {
    const state = createWatchdogState();
    const s = snapshot({ sessions: [session({ autoStartEnabled: false })] });
    const result = ticks(state, s, 10);
    expect(result.trigger).toEqual([]);
    expect(result.verdicts[0]?.outcome).toBe("autostart-opt-out");
  });

  it("never resurrects a user who chose Exit (quit marker present)", () => {
    const state = createWatchdogState();
    const s = snapshot({ sessions: [session({ quitMarkerPresent: true })] });
    const result = ticks(state, s, 10);
    expect(result.trigger).toEqual([]);
    expect(result.verdicts[0]?.outcome).toBe("user-quit");
  });
});

// --- installs (review finding #3) --------------------------------------------

describe("installBlockReason — never act while an install is in flight", () => {
  const cases: Array<[string, Partial<InstallSignals>, string]> = [
    ["the SYSTEM Update task is running", { updateTaskRunning: true }, "update-task-running"],
    ["the tray exe is not on disk", { trayExeInstalled: false }, "tray-exe-missing"],
    [
      "the install dir was just written",
      { msSinceInstallDirChange: INSTALL_SETTLE_MS - 1 },
      "install-dir-just-changed",
    ],
  ];

  for (const [name, over, reason] of cases) {
    it(`blocks when ${name}`, () => {
      expect(installBlockReason({ ...CLEAN_INSTALL, ...over })).toBe(reason);
    });
  }

  it("does not block on a settled install", () => {
    expect(installBlockReason(CLEAN_INSTALL)).toBeNull();
    expect(
      installBlockReason({ ...CLEAN_INSTALL, msSinceInstallDirChange: INSTALL_SETTLE_MS }),
    ).toBeNull();
  });

  it("has NO 'an installer process is running' signal, and cannot grow one back", () => {
    // Deleted, not weakened: it blocked machine-wide on a process running from
    // the install dir, on the premise that an admin-owned directory makes the
    // process trustworthy. Admin ownership protects the BINARY from
    // modification, not the right to RUN it — Users have read+execute on
    // %ProgramFiles%\AI Commander — so any local user could start the
    // uninstaller unelevated, leave it sitting, and suppress crash recovery for
    // everybody on the box indefinitely. Both halves are pinned here so it
    // cannot come back as an inert field either.
    expect(Object.keys(CLEAN_INSTALL).sort()).toEqual([
      "msSinceInstallDirChange",
      "trayExeInstalled",
      "updateTaskRunning",
    ]);
    // An extra process-shaped field cannot change the answer.
    const withGhost = {
      ...CLEAN_INSTALL,
      installerProcesses: ["C:\\Program Files\\AI Commander\\Uninstall AI Commander.exe"],
    } as InstallSignals;
    expect(installBlockReason(withGhost)).toBeNull();
    // …and the reason string is gone from the module, comments included.
    expect(readFileSync(WATCHDOG_SOURCE, "utf8")).not.toContain('"installer-running"');
  });

  it("does not block when the install dir age is unknown", () => {
    // Unknown mtime must not wedge recovery forever — the other two signals
    // (the Update task's state, a missing exe) still cover the window.
    expect(installBlockReason({ ...CLEAN_INSTALL, msSinceInstallDirChange: null })).toBeNull();
  });
});

describe("evaluateTick — install gating", () => {
  it("holds off entirely while an install is in flight", () => {
    const state = createWatchdogState();
    const s = snapshot({ install: { ...CLEAN_INSTALL, updateTaskRunning: true } });
    const result = ticks(state, s, 10);
    expect(result.trigger).toEqual([]);
    expect(result.blockedBy).toBe("update-task-running");
    expect(result.verdicts[0]?.outcome).toBe("waiting");
  });

  it("restarts the debounce after a block clears (no instant relaunch)", () => {
    const state = createWatchdogState();
    const blocked = snapshot({ install: { ...CLEAN_INSTALL, trayExeInstalled: false } });
    ticks(state, blocked, 5);
    const clear = snapshot();
    // First clear tick must still only be counting, not acting.
    expect(evaluateTick(state, clear).trigger).toEqual([]);
    expect(evaluateTick(state, clear).trigger).toMatchObject([{ sessionId: 1, userSid: SID_A }]);
  });

  it("has NO machine-wide block an unprivileged user can cause", () => {
    // The DoS this replaces. A per-process tray list has to be capped, and
    // exceeding the cap was reported as `trayProcessesOverflow`, which
    // evaluateTick turned into a machine-wide block — so any local user could
    // deny recovery to EVERYONE by launching the installed exe ~100 times (an
    // Electron tray is 4-6 processes). Both the flag and the block are gone; the
    // probe reports one entry per USER, so there is nothing to overflow.
    //
    // The rule, pinned mechanically: `blockedBy` is exactly installBlockReason,
    // whose three inputs are all admin-owned state.
    const ownerSets = [[], [SID_A], [SID_A, SID_B], Array.from({ length: 5000 }, () => SID_B)];
    const installs = [CLEAN_INSTALL, { ...CLEAN_INSTALL, updateTaskRunning: true }];
    const seen = new Set<string | null>();
    for (const owners of ownerSets) {
      for (const install of installs) {
        const s = snapshot({ trayOwnerSids: owners, unverifiedTrayProcesses: 5000, install });
        // Whatever a user does to the process list, the answer is the
        // admin-owned one and nothing else.
        const { blockedBy } = evaluateTick(createWatchdogState(), s);
        expect(blockedBy).toBe(installBlockReason(install));
        seen.add(blockedBy);
      }
    }
    // Anti-vacuity: both directions really were exercised, so "always equals
    // installBlockReason" is not quietly "always null".
    expect(seen).toEqual(new Set([null, "update-task-running"]));
    // …and the fixtures above really do reach a recovery decision.
    expect(
      ticks(createWatchdogState(), snapshot(), WATCHDOG_MISSES_BEFORE_RECOVERY).trigger,
    ).toHaveLength(1);
  });

  it("keeps recovering everybody while one user floods the machine with trays", () => {
    // The same DoS from the victim's side: user B starting thousands of verified
    // trays must not stop user A being recovered.
    const state = createWatchdogState();
    const s = snapshot({
      sessions: [session({ sessionId: 1, userSid: SID_A }), session({ sessionId: 2, userSid: SID_B })],
      trayOwnerSids: [SID_B],
      unverifiedTrayProcesses: 100_000,
    });
    const result = ticks(state, s, WATCHDOG_MISSES_BEFORE_RECOVERY);
    expect(result.blockedBy).toBeNull();
    expect(result.trigger).toMatchObject([{ userSid: SID_A, sessionId: 1 }]);
  });
});

// --- debounce + state hygiene -------------------------------------------------

describe("evaluateTick — debounce and state", () => {
  it("needs consecutive misses before triggering", () => {
    const state = createWatchdogState();
    const s = snapshot();
    for (let i = 1; i < WATCHDOG_MISSES_BEFORE_RECOVERY; i++) {
      expect(evaluateTick(state, s).trigger).toEqual([]);
    }
    expect(evaluateTick(state, s).trigger).toMatchObject([{ sessionId: 1, userSid: SID_A }]);
  });

  it("resets the counter when the tray comes back", () => {
    const state = createWatchdogState();
    evaluateTick(state, snapshot());
    evaluateTick(state, snapshot({ trayOwnerSids: [SID_A] }));
    expect(evaluateTick(state, snapshot()).trigger).toEqual([]);
  });

  it("does not re-trigger the same session on every following tick", () => {
    const state = createWatchdogState();
    const s = snapshot();
    ticks(state, s, WATCHDOG_MISSES_BEFORE_RECOVERY);
    expect(evaluateTick(state, s).trigger).toEqual([]);
  });
});

// --- backoff when a relaunch does not take -----------------------------------

describe("evaluateTick — backoff for a relaunch that never takes", () => {
  /** Tick until the next trigger fires; returns [target, ticksWaited]. */
  function untilTrigger(state: ReturnType<typeof createWatchdogState>, s: WatchdogSnapshot) {
    for (let i = 1; i <= WATCHDOG_MAX_BACKOFF_TICKS * 4; i++) {
      const r = evaluateTick(state, s);
      if (r.trigger.length > 0) return [r.trigger[0]!, i] as const;
    }
    throw new Error("no trigger within the backoff ceiling");
  }

  it("escalates the wait on every attempt that does not take", () => {
    // The tray never appears — e.g. the launcher declines (a quit marker under a
    // REDIRECTED AppData the probe's profile-path derivation missed) or the app
    // crashes on start. Without a backoff this re-fires every 2 ticks forever:
    // a console flash in that session every couple of minutes, unbounded task
    // history and log spam — exactly what the 5-minute repetition was rejected
    // for, arriving through a different door.
    const state = createWatchdogState();
    const s = snapshot();
    const waits: number[] = [];
    for (let attempt = 1; attempt <= 5; attempt++) {
      const [target, waited] = untilTrigger(state, s);
      expect(target.attempt).toBe(attempt);
      waits.push(waited);
    }
    // First attempt after the plain debounce, then strictly increasing waits.
    expect(waits[0]).toBe(WATCHDOG_MISSES_BEFORE_RECOVERY);
    for (let i = 1; i < waits.length; i++) expect(waits[i]!).toBeGreaterThan(waits[i - 1]!);
  });

  it("caps the wait and reports that it is at the ceiling", () => {
    const state = createWatchdogState();
    const s = snapshot();
    let target = untilTrigger(state, s)[0];
    while (!target.atBackoffCeiling) {
      expect(target.retryInTicks).toBeLessThanOrEqual(WATCHDOG_MAX_BACKOFF_TICKS);
      target = untilTrigger(state, s)[0];
    }
    // Capped, and still retrying — a watchdog that silently gives up entirely is
    // its own failure mode.
    expect(target.retryInTicks).toBe(WATCHDOG_MAX_BACKOFF_TICKS);
    // Ceiling wait, then the usual debounce before it fires again.
    expect(untilTrigger(state, s)[1]).toBeGreaterThanOrEqual(WATCHDOG_MAX_BACKOFF_TICKS);
  });

  it("reports the backoff in the verdicts while it waits", () => {
    const state = createWatchdogState();
    const s = snapshot();
    untilTrigger(state, s);
    const next = evaluateTick(state, s);
    expect(next.trigger).toEqual([]);
    expect(next.verdicts[0]?.outcome).toBe("backoff");
    expect(next.verdicts[0]?.attempts).toBe(1);
  });

  it("clears the escalation after a tray has stayed up for a healthy stretch", () => {
    const state = createWatchdogState();
    const s = snapshot();
    const healthy = snapshot({ trayOwnerSids: [SID_A] });
    untilTrigger(state, s);
    untilTrigger(state, s); // second attempt: now backing off further
    // A tray that comes back and STAYS back is a real recovery: the next outage
    // starts from a plain debounce again.
    ticks(state, healthy, WATCHDOG_FLAP_QUIET_TICKS);
    expect(state.users.size).toBe(0);
    expect(untilTrigger(state, s)[1]).toBe(WATCHDOG_MISSES_BEFORE_RECOVERY);
  });

  it("clears the escalation only on CONSECUTIVE health, never on elapsed time", () => {
    // The counter used to be cleared by "ticks since the last trigger", which a
    // continuing crash loop satisfies for free: one live observation landing at
    // the hour boundary reset the whole escalation, and then did it again every
    // hour. It has to be an unbroken run of healthy observations.
    const state = createWatchdogState();
    const dead = snapshot();
    const healthy = snapshot({ trayOwnerSids: [SID_A] });
    untilTrigger(state, dead);
    untilTrigger(state, dead);
    expect(state.users.get(SID_A.toLowerCase())?.flaps).toBe(2);

    // An hour passes with the tray NOT up — here an install blocks, which keeps
    // every counter — and then one single tick sees it alive. Under the old
    // "ticks since the last trigger" rule that one observation cleared the whole
    // escalation, and a crash loop could do it again every hour. It must not.
    const blocked = snapshot({ install: { ...CLEAN_INSTALL, updateTaskRunning: true } });
    ticks(state, blocked, WATCHDOG_FLAP_QUIET_TICKS);
    evaluateTick(state, healthy);
    expect(state.users.get(SID_A.toLowerCase())?.flaps).toBe(2);

    // A genuinely uninterrupted healthy hour does clear it — the positive
    // counterpart, or the assertion above would pass on a counter that never
    // clears at all.
    ticks(state, healthy, WATCHDOG_FLAP_QUIET_TICKS);
    expect(state.users.size).toBe(0);
  });

  it("does not let a single healthy tick inside the streak restart the count", () => {
    // Same rule from the other side: the streak must RESET on any non-healthy
    // outcome, not merely fail to advance.
    const state = createWatchdogState();
    const dead = snapshot();
    const healthy = snapshot({ trayOwnerSids: [SID_A] });
    untilTrigger(state, dead);
    ticks(state, healthy, WATCHDOG_FLAP_QUIET_TICKS - 1);
    expect(state.users.get(SID_A.toLowerCase())?.flaps).toBe(1);
    // One interruption, then all-but-one of a fresh hour: still not enough.
    evaluateTick(state, dead);
    ticks(state, healthy, WATCHDOG_FLAP_QUIET_TICKS - 1);
    expect(state.users.get(SID_A.toLowerCase())?.flaps).toBe(1);
    // …and one more healthy tick completes it.
    evaluateTick(state, healthy);
    expect(state.users.size).toBe(0);
  });

  it("escalates a tray that keeps DYING, even though every cycle 'succeeds'", () => {
    // The gap the consecutive-attempt counter cannot see. A tray that crash-loops
    // on any period longer than one tick came back briefly on every cycle, which
    // cleared `attempts`, so it was relaunched every ~2 minutes forever with zero
    // escalation — every cycle looked like a healthy recovery.
    const state = createWatchdogState();
    const dead = snapshot();
    const healthy = snapshot({ trayOwnerSids: [SID_A] });
    const gaps: number[] = [];
    for (let cycle = 0; cycle < 5; cycle++) {
      const [target, waited] = untilTrigger(state, dead);
      gaps.push(waited);
      expect(target.flaps).toBe(cycle + 1);
      // …and it DID come back, for exactly one tick, before dying again.
      expect(evaluateTick(state, healthy).verdicts[0]?.outcome).toBe("tray-running");
    }
    // Never speeds up, and ends far slower than the flat every-two-ticks cadence
    // it used to keep forever. (The first couple of gaps are equal because the
    // brief healthy tick is itself spent inside the wait.)
    for (let i = 1; i < gaps.length; i++) {
      expect(gaps[i]!).toBeGreaterThanOrEqual(gaps[i - 1]!);
    }
    expect(gaps[gaps.length - 1]!).toBeGreaterThan(gaps[0]! * 4);
  });

  it("does not let a one-tick quit marker reset an escalating backoff", () => {
    // `.user-quit` is user-writable, so if withdrawing consent for a single tick
    // cleared the escalation, any user could restore the once-every-two-minutes
    // relaunch (and its console flash) for themselves.
    const state = createWatchdogState();
    const s = snapshot();
    untilTrigger(state, s);
    untilTrigger(state, s);
    const quit = snapshot({ sessions: [session({ quitMarkerPresent: true })] });
    expect(evaluateTick(state, quit).verdicts[0]?.outcome).toBe("user-quit");
    // Still backing off from where it was, not from scratch.
    expect(untilTrigger(state, s)[1]).toBeGreaterThan(WATCHDOG_MISSES_BEFORE_RECOVERY);
    expect(untilTrigger(state, s)[0].flaps).toBeGreaterThan(2);
  });

  it("keeps backing off across an install block (no free reset)", () => {
    const state = createWatchdogState();
    const s = snapshot();
    untilTrigger(state, s);
    untilTrigger(state, s);
    // An install passing through must not clear the attempt counter, or a wedged
    // session would re-fire on every update.
    evaluateTick(state, snapshot({ install: { ...CLEAN_INSTALL, updateTaskRunning: true } }));
    expect(untilTrigger(state, s)[0].attempt).toBe(3);
  });

  it("prunes state for users that logged off (boot-persistent process)", () => {
    const state = createWatchdogState();
    evaluateTick(state, snapshot({ sessions: [session({ sessionId: 3, userSid: SID_B })] }));
    expect(state.users.size).toBe(1);
    evaluateTick(state, snapshot({ sessions: [] }));
    expect(state.users.size).toBe(0);
  });

  it("keeps the backoff for a user missing from an INCOMPLETE tick", () => {
    // The probe's session scan is budgeted and, past the budget, rotates its
    // start offset, so on a large host a user is absent from most ticks simply
    // because the scan never reached them. Pruning on that absence deletes
    // `flaps`/`attempts` — the backoff — and relaunches a crash-looping tray at
    // full speed forever, which is what the backoff exists to prevent.
    const state = createWatchdogState();
    const dead = snapshot();
    untilTrigger(state, dead);
    untilTrigger(state, dead);
    // A COPY of the entry, not the live map value: compared against itself, the
    // assertion below would pass on an in-place mutation. `evaluateTick` always
    // `set`s a fresh object today, so this costs nothing and stops the pin from
    // depending on that.
    const live = state.users.get(SID_A.toLowerCase());
    expect(live).toBeDefined();
    const escalated = { ...live! };
    expect(escalated.flaps).toBe(2);
    expect(escalated.attempts).toBe(2);

    // Ticks that did not enumerate this user, but did not enumerate everybody
    // either: the count of sessions the tick failed to deliver is non-zero.
    for (let i = 0; i < 2; i++) {
      evaluateTick(state, snapshot({ sessions: [], skippedSessions: 3 }));
    }
    expect(state.users.get(SID_A.toLowerCase())).toEqual(escalated);

    // …so when the rotation reaches them again the escalation continues from
    // where it was — still inside the wait it had earned, and firing as the
    // third attempt rather than a fresh first one.
    const [target, waited] = untilTrigger(state, dead);
    expect(target.attempt).toBe(3);
    expect(target.flaps).toBe(3);
    expect(waited).toBeGreaterThan(WATCHDOG_MISSES_BEFORE_RECOVERY);
  });

  it("keeps a PART-WAY miss debounce for a user missing from an INCOMPLETE tick", () => {
    // The sibling above pins the BACKOFF, but by the time its partial ticks
    // arrive the trigger has just reset `misses` to 0, so comparing the whole
    // entry says nothing about the debounce. Here the entry carries a NON-ZERO
    // `misses` when the unreached ticks land, so the same comparison shows what
    // the other half of the prune gate is worth: an absence the tick cannot
    // account for must leave the half-served debounce alone. Otherwise a user on
    // a host large enough to rotate re-serves the debounce from scratch every
    // time the scan skips them, and a tray that is genuinely down is never
    // recovered at all — the suppression this module exists to avoid.
    const state = createWatchdogState();
    const dead = snapshot();
    untilTrigger(state, dead);

    // Tick past the backoff the trigger earned, up to the first tick that counts
    // as a miss again. WATCHDOG_MISSES_BEFORE_RECOVERY is 2, so that tick is not
    // yet a recovery: nothing fires and the entry is left mid-debounce.
    let live = state.users.get(SID_A.toLowerCase());
    for (let i = 1; i <= WATCHDOG_MAX_BACKOFF_TICKS * 4 && !live?.misses; i++) {
      expect(evaluateTick(state, dead).trigger).toEqual([]);
      live = state.users.get(SID_A.toLowerCase());
    }
    expect(live?.misses).toBeGreaterThan(0);
    expect(live?.misses).toBeLessThan(WATCHDOG_MISSES_BEFORE_RECOVERY);
    const pending = { ...live! };

    // The same unreached ticks as above: partial list, this user not in it.
    for (let i = 0; i < 2; i++) {
      evaluateTick(state, snapshot({ sessions: [], skippedSessions: 3 }));
    }
    expect(state.users.get(SID_A.toLowerCase())).toEqual(pending);

    // …so the next tick that DOES reach them completes the debounce and fires,
    // rather than starting it over.
    expect(evaluateTick(state, dead).trigger).toHaveLength(1);
  });

  it("still prunes a user missing from a COMPLETE tick, escalation and all", () => {
    // The other direction, and it matters just as much: a prune that never fires
    // leaks state for the machine's uptime, and a returning user inherits a
    // backoff they did not earn. Nothing skipped ⇒ absence IS a logoff.
    const state = createWatchdogState();
    const dead = snapshot();
    untilTrigger(state, dead);
    untilTrigger(state, dead);
    expect(state.users.get(SID_A.toLowerCase())?.flaps).toBe(2);

    evaluateTick(state, snapshot({ sessions: [], skippedSessions: 0 }));
    expect(state.users.size).toBe(0);
    // A fresh logon is therefore treated as one: the first trigger is due after
    // the plain debounce, at attempt 1.
    const [target, waited] = untilTrigger(state, dead);
    expect(target.attempt).toBe(1);
    expect(target.flaps).toBe(1);
    expect(waited).toBe(WATCHDOG_MISSES_BEFORE_RECOVERY);
  });

  it("still evaluates the users an incomplete tick DID deliver", () => {
    // A partial list is not a blanket "know nothing": it is still evidence about
    // the users it contains. SID_A's live tray clears their attempt counter on a
    // skipped-sessions tick exactly as on a complete one, while SID_B — merely
    // unreached — is left untouched rather than reset.
    const state = createWatchdogState();
    const bothDead = snapshot({
      sessions: [session({ userSid: SID_A }), session({ sessionId: 2, userSid: SID_B })],
    });
    untilTrigger(state, bothDead);
    const before = state.users.get(SID_B.toLowerCase());
    expect(before?.attempts).toBe(1);
    evaluateTick(
      state,
      snapshot({
        sessions: [session({ userSid: SID_A })],
        trayOwnerSids: [SID_A],
        skippedSessions: 1,
      }),
    );
    expect(state.users.get(SID_A.toLowerCase())?.attempts).toBe(0);
    expect(state.users.get(SID_B.toLowerCase())).toEqual(before);
  });

  it("does not carry a miss count across users on a recycled session id", () => {
    const state = createWatchdogState();
    evaluateTick(state, snapshot({ sessions: [session({ sessionId: 1, userSid: SID_A })] }));
    // Same session id, different user: starts counting from scratch.
    expect(
      evaluateTick(state, snapshot({ sessions: [session({ sessionId: 1, userSid: SID_B })] }))
        .trigger,
    ).toEqual([]);
  });
});

// --- the loop -----------------------------------------------------------------

describe("startWindowsWatchdog", () => {
  /** A probe that always yields the same snapshot. */
  const probing = (s: WatchdogSnapshot) => async () => ({ ok: true as const, snapshot: s });

  it("triggers the relaunch task once the decision says so", async () => {
    const trigger = vi.fn().mockResolvedValue(undefined);
    const wd = startWindowsWatchdog({
      probe: probing(snapshot()),
      trigger,
      intervalMs: 60_000,
    });
    for (let i = 0; i < WATCHDOG_MISSES_BEFORE_RECOVERY; i++) await wd.__tick();
    wd.stop();
    expect(trigger).toHaveBeenCalledTimes(1);
    expect(trigger).toHaveBeenCalledWith(1);
  });

  it("makes the backoff observable in the log", async () => {
    // A watchdog that has quietly stopped trying is its own failure mode, so
    // every attempt must say which one it is and when the next is due.
    const lines: string[] = [];
    const wd = startWindowsWatchdog({
      probe: probing(snapshot()),
      trigger: vi.fn().mockResolvedValue(undefined),
      intervalMs: 60_000,
      log: (l) => lines.push(l),
    });
    for (let i = 0; i < WATCHDOG_MAX_BACKOFF_TICKS * 4; i++) await wd.__tick();
    wd.stop();
    expect(lines.some((l) => l.includes("watchdog relaunch ") && l.includes("attempt=1"))).toBe(
      true,
    );
    expect(lines.some((l) => l.includes("relaunch-escalating"))).toBe(true);
    expect(lines.some((l) => l.includes("ceiling=yes"))).toBe(true);
    // Every line says when the next attempt is due — a watchdog that has quietly
    // given up must be distinguishable from one that is waiting.
    expect(lines.some((l) => /next-due-tick=\d+/.test(l))).toBe(true);
    // …and the ceiling is a real cap on the noise, not a formality.
    const attempts = lines.filter((l) => l.includes("watchdog relaunch ")).length;
    expect(attempts).toBeGreaterThan(0);
    expect(attempts).toBeLessThan(10);
  });

  it("says out loud that a probe produced nothing, and does not spam", async () => {
    // Every expected production failure (CIM hiccup, unreadable hive, timeout,
    // overflow) used to return a bare null and be skipped in SILENCE, so a
    // permanently broken watchdog looked exactly like an idle machine.
    const lines: string[] = [];
    const wd = startWindowsWatchdog({
      probe: async () => ({ ok: false as const, reason: "query-processes" as const }),
      trigger: vi.fn(),
      intervalMs: 60_000,
      log: (l) => lines.push(l),
    });
    for (let i = 0; i < 130; i++) await wd.__tick();
    wd.stop();
    const failures = lines.filter((l) => l.includes("probe-failed"));
    expect(failures.length).toBeGreaterThan(0);
    expect(failures[0]).toContain("reason=query-processes");
    // First one immediately, then hourly — not one a minute forever.
    expect(failures.length).toBeLessThanOrEqual(4);
  });

  it("reports fail-closed drops, which are invisible by construction", async () => {
    const lines: string[] = [];
    const wd = startWindowsWatchdog({
      probe: probing(snapshot({ skippedSessions: 2, unverifiedTrayProcesses: 3 })),
      trigger: vi.fn().mockResolvedValue(undefined),
      intervalMs: 60_000,
      log: (l) => lines.push(l),
    });
    await wd.__tick();
    wd.stop();
    expect(lines.some((l) => l.includes("sessions-skipped") && l.includes("count=2"))).toBe(true);
    expect(lines.some((l) => l.includes("tray-lookalikes") && l.includes("count=3"))).toBe(true);
  });

  it("keeps ticking when the LOG throws — a full disk must not kill the helper", async () => {
    // `void tick().finally(schedule)` had no rejection handler and finally
    // re-raises: a throw from log() or the decision became an unhandled
    // rejection, which terminates the process under Node's default policy and
    // takes the elevated-exec IPC endpoint down with it, against a finite
    // RestartCount 3. A supervisor that dies on a logging failure is worse than
    // one that skips a tick.
    const trigger = vi.fn().mockResolvedValue(undefined);
    const wd = startWindowsWatchdog({
      probe: probing(snapshot()),
      trigger,
      intervalMs: 60_000,
      log: () => {
        throw new Error("ENOSPC");
      },
    });
    for (let i = 0; i < WATCHDOG_MISSES_BEFORE_RECOVERY; i++) {
      await expect(wd.__tick()).resolves.not.toBeUndefined();
    }
    wd.stop();
    // The tick did its actual job despite the sink being broken.
    expect(trigger).toHaveBeenCalledWith(1);
  });

  it("re-arms itself after a failing tick", async () => {
    vi.useFakeTimers();
    try {
      const probe = vi.fn(async () => {
        throw new Error("wmi is having a day");
      });
      const wd = startWindowsWatchdog({ probe, trigger: vi.fn(), intervalMs: 1000 });
      await vi.advanceTimersByTimeAsync(3500);
      wd.stop();
      // Three scheduled ticks, none of which stopped the chain.
      expect(probe.mock.calls.length).toBeGreaterThanOrEqual(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("backoffTicks doubles up to the ceiling", () => {
    expect(backoffTicks(1)).toBe(2);
    expect(backoffTicks(2)).toBe(4);
    expect(backoffTicks(3)).toBe(8);
    expect(backoffTicks(99)).toBe(WATCHDOG_MAX_BACKOFF_TICKS);
  });

  it("skips the tick when the machine could not be probed", async () => {
    const trigger = vi.fn();
    const wd = startWindowsWatchdog({
      probe: async () => ({ ok: false as const, reason: "timeout" as const }),
      trigger,
      intervalMs: 60_000,
    });
    for (let i = 0; i < 5; i++) expect(await wd.__tick()).toBeNull();
    wd.stop();
    expect(trigger).not.toHaveBeenCalled();
  });

  it("survives a throwing probe and a throwing trigger", async () => {
    const wd = startWindowsWatchdog({
      probe: async () => {
        throw new Error("wmi is having a day");
      },
      trigger: vi.fn(),
      intervalMs: 60_000,
    });
    expect(await wd.__tick()).toBeNull();
    wd.stop();

    const failing = vi.fn().mockRejectedValue(new Error("task missing"));
    const wd2 = startWindowsWatchdog({
      probe: probing(snapshot()),
      trigger: failing,
      intervalMs: 60_000,
    });
    for (let i = 0; i < WATCHDOG_MISSES_BEFORE_RECOVERY; i++) await wd2.__tick();
    wd2.stop();
    expect(failing).toHaveBeenCalledTimes(1);
  });
});
