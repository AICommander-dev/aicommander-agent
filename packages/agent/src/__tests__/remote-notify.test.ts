import { describe, it, expect } from "vitest";
import {
  REMOTE_NOTIFY_MIN_INTERVAL_MS,
  REMOTE_NOTIFY_MAX_INTERVAL_MS,
  REMOTE_ACTIVITY_GAP_MS,
} from "@aicommander/protocol";
import { shouldNotify, RemoteNotifier } from "../remote-notify.js";

const HOUR = REMOTE_NOTIFY_MIN_INTERVAL_MS;
const GAP = REMOTE_ACTIVITY_GAP_MS;
const CEILING = REMOTE_NOTIFY_MAX_INTERVAL_MS;

describe("shouldNotify (pure rule)", () => {
  it("always notifies on first contact (no prior state)", () => {
    expect(shouldNotify(undefined, 1_000)).toBe(true);
  });

  it("suppresses while idle gap not yet exceeded, even past the hour", () => {
    const prev = { lastActivityAt: 0, lastNotifiedAt: 0 };
    // 2h later but the operator was active 1ms ago → still the same session.
    expect(shouldNotify({ ...prev, lastActivityAt: 2 * HOUR }, 2 * HOUR + 1)).toBe(false);
  });

  it("suppresses within the hour even after a long idle gap", () => {
    // Idle for >gap (so a new session) but only 30m since the last notice.
    const prev = { lastActivityAt: 0, lastNotifiedAt: HOUR / 2 };
    const now = HOUR / 2 + GAP + 1;
    expect(now - prev.lastActivityAt).toBeGreaterThan(GAP); // idle enough
    expect(now - prev.lastNotifiedAt).toBeLessThan(HOUR); // but still cooling down
    expect(shouldNotify(prev, now)).toBe(false);
  });

  it("notifies once both the idle gap AND the hourly cooldown clear", () => {
    const prev = { lastActivityAt: 0, lastNotifiedAt: 0 };
    expect(shouldNotify(prev, HOUR + GAP + 1)).toBe(true);
  });

  it("re-notifies a NON-STOP session once the continuous-session ceiling passes", () => {
    // Operator active 1ms ago (idle gap never opens) but last notice was CEILING ago.
    const prev = { lastActivityAt: CEILING, lastNotifiedAt: 0 };
    expect(CEILING + 1 - prev.lastActivityAt).toBeLessThan(GAP); // idle gap NOT open
    expect(shouldNotify(prev, CEILING + 1)).toBe(true); // ceiling fires anyway
  });

  it("does not fire the ceiling early for a non-stop session", () => {
    // Just shy of the ceiling, continuously active → still suppressed.
    const prev = { lastActivityAt: CEILING - GAP, lastNotifiedAt: 0 };
    expect(shouldNotify(prev, CEILING - 1)).toBe(false);
  });

  it("uses an inclusive (>=) cooldown but a strict (>) idle gap", () => {
    // At exactly an hour since the notice, with the operator long idle, both gates
    // pass (cooldown is inclusive) → notify.
    expect(shouldNotify({ lastActivityAt: 0, lastNotifiedAt: 0 }, HOUR)).toBe(true);
    // Idle of EXACTLY the gap is not yet a new session (gap is exclusive) → suppress,
    // even though the cooldown has long cleared.
    expect(shouldNotify({ lastActivityAt: 0, lastNotifiedAt: -HOUR }, GAP)).toBe(false);
  });
});

describe("RemoteNotifier (stateful, time injected)", () => {
  it("first command for an operator notifies; an immediate second does not", () => {
    const n = new RemoteNotifier();
    expect(n.note("u1", 0)).toBe(true);
    expect(n.note("u1", 60_000)).toBe(false); // 1m later, mid-session
  });

  it("does not re-notify during continuous work, then notifies after a real break", () => {
    const n = new RemoteNotifier();
    expect(n.note("u1", 0)).toBe(true);
    // Steady stream every 5 minutes for well over an hour — one session, no spam.
    let t = 0;
    for (let i = 0; i < 20; i++) {
      t += 5 * 60_000;
      expect(n.note("u1", t)).toBe(false);
    }
    // Now a >10m pause, and it's been >1h since the notice → a fresh connection.
    expect(n.note("u1", t + GAP + 1)).toBe(true);
  });

  it("measures the hourly cap from the last NOTICE, not the last command", () => {
    const n = new RemoteNotifier();
    expect(n.note("u1", 0)).toBe(true); // notice at t=0
    // Idle gap clears repeatedly, but each is < 1h since the notice → all suppressed.
    expect(n.note("u1", GAP + 1)).toBe(false);
    expect(n.note("u1", 2 * GAP + 2)).toBe(false);
    // Only once an hour has elapsed since t=0 (and idle gap holds) does it fire.
    expect(n.note("u1", HOUR + 1)).toBe(true);
  });

  it("re-warns a non-stop operator about once per the ceiling interval", () => {
    const n = new RemoteNotifier();
    expect(n.note("u1", 0)).toBe(true); // first contact
    // Non-stop cadence every 5 min, right up to just before the 8h ceiling.
    let notices = 0;
    for (let t = 5 * 60_000; t <= CEILING - 5 * 60_000; t += 5 * 60_000) {
      if (n.note("u1", t)) notices++;
    }
    expect(notices).toBe(0); // continuous work is never re-announced before the ceiling
    // Crossing the ceiling while still continuous → exactly one re-notice…
    expect(n.note("u1", CEILING + 1)).toBe(true);
    // …then immediately suppressed again (next ceiling is another interval out).
    expect(n.note("u1", CEILING + 6 * 60_000)).toBe(false);
  });

  it("rate-limits each operator independently", () => {
    const n = new RemoteNotifier();
    expect(n.note("u1", 0)).toBe(true);
    expect(n.note("u2", 1_000)).toBe(true); // different operator → its own first notice
    expect(n.note("u1", 2_000)).toBe(false);
    expect(n.note("anon", 3_000)).toBe(true); // anonymous bucket is just another id
  });
});
