import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// The identity token is what stands between a recycled pid and a released GPU
// lock, so these tests simulate the platform BACKENDS (wmic, PowerShell, ps,
// /proc) and the timezone rather than probing whatever process table and zone
// the host happens to have: the regression being pinned is precisely that two
// backends — or two zone renderings — used to mint two different tokens for the
// SAME process, which read as a confident "gone".
vi.mock("node:child_process", () => ({ execFileSync: vi.fn() }));
vi.mock("node:fs", () => ({
  default: {
    readFileSync: vi.fn(() => {
      throw new Error("ENOENT");
    }),
  },
}));

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { compareProcIdentity, readProcIdentity } from "../proc-identity.js";

let realPlatform: PropertyDescriptor | undefined;
let realTz: string | undefined;

function setPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

/** Node re-reads TZ at runtime, so a test can state the zone instead of inheriting it. */
function setTimezone(tz: string): void {
  process.env["TZ"] = tz;
}

/**
 * The deployed reality on macOS: the agent's env carries no TZ at all — the
 * system zone lives in /etc/localtime, which Node caches at startup and `ps`
 * reads fresh. TZ is the only zone knob a test has, so an unset TZ is how the
 * "the runtime cannot know what zone ps used" condition is stated.
 */
function clearTimezone(): void {
  delete process.env["TZ"];
}

beforeEach(() => {
  vi.clearAllMocks();
  realPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  realTz = process.env["TZ"];
});

afterEach(() => {
  vi.restoreAllMocks();
  if (realPlatform) Object.defineProperty(process, "platform", realPlatform);
  if (realTz === undefined) delete process.env["TZ"];
  else process.env["TZ"] = realTz;
});

describe("readProcIdentity — Windows backends agree on one token", () => {
  beforeEach(() => {
    setPlatform("win32");
  });

  /** The same CreationDate instant as each backend renders it. */
  const WMIC_STAMP = "20260805143012.123456+120"; // CIM: local 14:30:12.123456, UTC+120min
  const ISO_STAMP = "2026-08-05T14:30:12.1234560+02:00"; // PowerShell DateTime.ToString("o")
  const INSTANT_MS = Date.UTC(2026, 7, 5, 12, 30, 12) + 123;

  function givenWmic(stamp: string | null): void {
    vi.mocked(execFileSync).mockImplementation(((file: string) => {
      if (String(file) === "wmic") {
        if (stamp === null) throw new Error("'wmic' is not recognized");
        return `\r\nCreationDate=${stamp}\r\n\r\n`;
      }
      throw new Error("no PowerShell in this scenario");
    }) as never);
  }

  function givenPowershell(stamp: string): void {
    vi.mocked(execFileSync).mockImplementation(((file: string) => {
      // wmic is gone — the deprecated-and-removed case, or a transient failure.
      if (String(file) === "wmic") throw new Error("'wmic' is not recognized");
      return `${stamp}\r\n`;
    }) as never);
  }

  it("captures via wmic and re-reads via PowerShell as the SAME token", () => {
    // THE defect-1 regression: spawn-time capture answered by wmic, a later
    // check answered by PowerShell (wmic removed or failing), same process. The
    // raw renderings differ byte for byte, so raw-string comparison called our
    // own live job "gone" and released its GPU lock.
    givenWmic(WMIC_STAMP);
    const captured = readProcIdentity(4242);
    givenPowershell(ISO_STAMP);
    const checked = readProcIdentity(4242);

    expect(captured).not.toBeNull();
    expect(captured).toBe(checked);
    // verifyJobProcess maps "match" to "ours" — never "gone".
    expect(compareProcIdentity(captured as string, checked as string)).toBe("match");
    // And the token is the instant itself, offset applied — not either backend's
    // wall-clock text with the offset dropped.
    expect(captured).toBe(`epoch:${INSTANT_MS}`);
  });

  it("still tells two DIFFERENT processes apart across backends", () => {
    // Canonicalisation must not blur real differences: one second apart is a
    // recycled pid, and stays a mismatch.
    givenWmic(WMIC_STAMP);
    const ours = readProcIdentity(4242);
    givenPowershell("2026-08-05T14:30:13.1234560+02:00");
    const stranger = readProcIdentity(4242);
    expect(compareProcIdentity(ours as string, stranger as string)).toBe("mismatch");
  });

  it("answers null — not a raw token — when neither backend's answer parses", () => {
    // A token that cannot be parsed must never exist: minting one would hand
    // verifyJobProcess a string that can only ever compare as SOMETHING, when
    // the honest answer is "we do not know".
    givenWmic("banana");
    vi.mocked(execFileSync).mockImplementation(((file: string) => {
      if (String(file) === "wmic") return "\r\nCreationDate=banana\r\n\r\n";
      return "not a date\r\n";
    }) as never);
    expect(readProcIdentity(4242)).toBeNull();
  });

  it("refuses an ISO stamp with no UTC offset rather than guessing a zone", () => {
    // DateTimeKind.Unspecified renders offset-less; resolving it with a guessed
    // offset would rebuild the very instability being removed.
    givenPowershell("2026-08-05T14:30:12.1234560");
    expect(readProcIdentity(4242)).toBeNull();
  });
});

describe("readProcIdentity — macOS lstart is zone-free on BOTH sides", () => {
  beforeEach(() => {
    setPlatform("darwin");
  });

  /** One true start instant; what varies below is the zone each SIDE sees. */
  const INSTANT_MS = Date.UTC(2026, 6, 15, 12, 0, 0);

  /** lstart exactly as a C-locale ps renders it, in the given zone. */
  function lstartInZone(instantMs: number, zone: string): string {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: zone,
      weekday: "short",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
      year: "numeric",
    }).formatToParts(new Date(instantMs));
    const get = (type: string): string => parts.find((part) => part.type === type)?.value ?? "";
    return `${get("weekday")} ${get("month")} ${Number(get("day"))} ${get("hour")}:${get("minute")}:${get("second")} ${get("year")}`;
  }

  /**
   * A fake ps that behaves like the real thing: a FRESH process that renders
   * the true start instant in whatever zone it finds — the TZ the probe put in
   * its env if any, otherwise the current SYSTEM zone. Modelling the zone PER
   * SIDE, instead of moving one global TZ under both sides at once, is the
   * point of this harness: the defect lives precisely in ps and the runtime not
   * sharing a zone, which a both-sides shift can never reproduce.
   */
  function givenFreshPs(systemZone: string): void {
    vi.mocked(execFileSync).mockImplementation(((
      _file: string,
      _args: readonly string[],
      opts: { env?: Record<string, string> },
    ) => `${lstartInZone(INSTANT_MS, opts?.env?.["TZ"] ?? systemZone)}\n`) as never);
  }

  function givenLstart(stamp: string): void {
    vi.mocked(execFileSync).mockImplementation((() => `${stamp}\n`) as never);
  }

  it("mints the same token before and after the SYSTEM zone changes under a cached runtime", () => {
    // Defect path 4. The agent's env has no TZ, so Node cached /etc/localtime
    // at startup and never re-reads it; ps is fresh and reads the current zone.
    // The system zone changing mid-job therefore moves ps's rendering while the
    // runtime's parse stays put — the previous local-time round trip then read
    // a shifted epoch, a confident MISMATCH, and verifyJobProcess said "gone"
    // for our own live job: its GPU lock was released and the run became
    // uncancellable. With the probe pinned to TZ=UTC and parsed as UTC, no side
    // owns a zone, so the verdict may be "match" (or at worst "unverifiable"),
    // never the mismatch that settles a live job.
    clearTimezone();
    givenFreshPs("Europe/Warsaw"); // the zone at capture time
    const captured = readProcIdentity(4242);

    givenFreshPs("Pacific/Auckland"); // ten hours away — the box was moved/reconfigured
    const checked = readProcIdentity(4242);

    expect(captured).not.toBeNull();
    expect(checked).not.toBeNull();
    expect(compareProcIdentity(captured as string, checked as string)).not.toBe("mismatch");
    expect(compareProcIdentity(captured as string, checked as string)).toBe("match");
    // And the token is the instant itself, in the zone-free kind.
    expect(captured).toBe(`utc:${INSTANT_MS}`);
    expect(checked).toBe(captured);
  });

  it("parses the stamp as the UTC fields it literally is, whatever zone the runtime holds", () => {
    // The other half of the fix, which the two-sided test above cannot see: if
    // the parser slid back to local-time construction while the probe still
    // pinned TZ=UTC, both probes would mint the SAME wrong token and match.
    // Pinning the token's VALUE catches that mutation. UTC+14 so no host or
    // season can make the wrong parse accidentally right — and note no seasonal
    // offset is ever applied to either stamp: under UTC there is no DST, so the
    // fall-back hour in which one wall time names two instants cannot exist.
    setTimezone("Pacific/Kiritimati");
    givenLstart("Thu Jan 15 13:00:00 2026");
    expect(readProcIdentity(4242)).toBe(`utc:${Date.UTC(2026, 0, 15, 13, 0, 0)}`);
    givenLstart("Wed Jul 15 14:00:00 2026");
    expect(readProcIdentity(4242)).toBe(`utc:${Date.UTC(2026, 6, 15, 14, 0, 0)}`);
  });

  it("collapses ps's column padding around single-digit days", () => {
    setTimezone("Europe/Warsaw");
    givenLstart("Tue Aug  4 22:36:20 2026"); // ps pads the day: two spaces
    expect(readProcIdentity(4242)).toBe(`utc:${Date.UTC(2026, 7, 4, 22, 36, 20)}`);
  });

  it("pins the probe to the C locale AND to UTC, so the stamp is parseable and zone-free", () => {
    givenLstart("Tue Aug  4 22:36:20 2026");
    readProcIdentity(4242);
    const [, , opts] = vi.mocked(execFileSync).mock.calls[0] as unknown as [
      string,
      string[],
      { env?: Record<string, string> },
    ];
    expect(opts.env?.["LC_ALL"]).toBe("C");
    // The zone pin is load-bearing: without it ps renders the system zone the
    // runtime cannot see, and the parse below reads the wrong instant.
    expect(opts.env?.["TZ"]).toBe("UTC");
  });

  it("answers null for an lstart it cannot parse, never the raw string", () => {
    givenLstart("STARTED"); // a ps that echoed a header, or a localised rendering
    expect(readProcIdentity(4242)).toBeNull();
  });
});

describe("readProcIdentity — Linux ticks stay byte-compatible with old records", () => {
  it("still returns bare start ticks, the pre-canonical on-disk format", () => {
    // Linux never rendered a wall clock, so its token was already stable — and
    // every meta.json on disk holds it as bare digits. Changing its shape would
    // turn every running job's record into a legacy hold for no benefit.
    setPlatform("linux");
    vi.mocked(fs.readFileSync).mockReturnValue(
      "4242 (a (weird) name) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 1000 2 1 0 0 0 0 0 0 0 0 0 0 0 0 0",
    );
    const token = readProcIdentity(4242);
    expect(token).toBe("987654");
    expect(compareProcIdentity("987654", token as string)).toBe("match");
    expect(compareProcIdentity("987653", token as string)).toBe("mismatch");
  });
});

describe("compareProcIdentity — anything unparseable is unverifiable, never a verdict", () => {
  it("holds legacy on-disk tokens as unverifiable instead of mismatching them", () => {
    // Records written by the pre-canonical agent are still on disk under live
    // jobs. Reading them as a mismatch IS the defect — a confident "gone" that
    // releases the GPU lock — so they must land in the third answer.
    const current = `utc:${Date.UTC(2026, 7, 4, 20, 36, 20)}`;
    for (const legacy of [
      "Tue Aug 4 22:36:20 2026", // macOS lstart, collapsed as the old code stored it
      "20260805143012.123456+120", // raw wmic
      "2026-08-05T14:30:12.1234560+02:00", // raw PowerShell ISO
      "not-a-token",
      "",
    ]) {
      expect(compareProcIdentity(legacy, current)).toBe("unverifiable");
      expect(compareProcIdentity(current, legacy)).toBe("unverifiable");
    }
  });

  it("holds a locally-inverted macOS epoch token against a zone-free probe", () => {
    // The compatibility hazard of the zone fix, and the exact shape of the four
    // previous misses: every macOS record on disk holds `epoch:<ms>` minted by
    // parsing a LOCAL rendering with the runtime's cached zone. If the zone was
    // skewed at mint (or the start fell in a DST fall-back hour) that value is
    // shifted from the truth a fresh `utc:` probe reports — so agreement proves
    // nothing and disagreement proves nothing. Both directions must hold, EVEN
    // when the milliseconds happen to be equal: a kind is a trust claim, not a
    // formatting detail.
    const ms = Date.UTC(2026, 6, 15, 12, 0, 0);
    expect(compareProcIdentity(`epoch:${ms}`, `utc:${ms}`)).toBe("unverifiable");
    expect(compareProcIdentity(`utc:${ms}`, `epoch:${ms}`)).toBe("unverifiable");
    expect(compareProcIdentity(`epoch:${ms - 3_600_000}`, `utc:${ms}`)).toBe("unverifiable");
  });

  it("never compares tokens of different kinds", () => {
    // Ticks and instants can only meet through corruption or a moved disk;
    // neither is evidence that a process ended.
    expect(compareProcIdentity("987654", "epoch:987654")).toBe("unverifiable");
    expect(compareProcIdentity("987654", "utc:987654")).toBe("unverifiable");
  });

  it("compares equal canonical tokens as a match, unequal as a mismatch", () => {
    expect(compareProcIdentity("epoch:1000", "epoch:1000")).toBe("match");
    expect(compareProcIdentity("epoch:1000", "epoch:1001")).toBe("mismatch");
    expect(compareProcIdentity("utc:1000", "utc:1000")).toBe("match");
    expect(compareProcIdentity("utc:1000", "utc:1001")).toBe("mismatch");
  });
});
