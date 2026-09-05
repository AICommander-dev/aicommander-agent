import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { EventEmitter } from "node:events";
import { promises as fs } from "node:fs";

/**
 * Every capture path is "spawn an OS tool, then read the file it wrote", so the
 * spawn is mocked and the handler writes a REAL file to the REAL path the code
 * chose. That keeps the file-reading half (size cap, PNG header parsing, cleanup)
 * genuinely exercised while nothing touches the screen.
 */
interface SpawnOutcome {
  code?: number;
  stdout?: string;
  stderr?: string;
  /** Never emit "close" — the macOS-TCC-prompt case the timeout exists for. */
  hang?: boolean;
}

const spawnCalls: { cmd: string; args: string[] }[] = [];
let handler: (cmd: string, args: string[]) => Promise<SpawnOutcome>;

vi.mock("child_process", () => ({
  spawn: (cmd: string, args: string[]) => {
    spawnCalls.push({ cmd, args });
    const proc = Object.assign(new EventEmitter(), {
      stdout: new EventEmitter(),
      stderr: new EventEmitter(),
      kill: vi.fn(),
    });
    void handler(cmd, args).then((outcome) => {
      if (outcome.stdout) proc.stdout.emit("data", Buffer.from(outcome.stdout));
      if (outcome.stderr) proc.stderr.emit("data", Buffer.from(outcome.stderr));
      if (!outcome.hang) proc.emit("close", outcome.code ?? 0);
    });
    return proc;
  },
}));

import {
  canCaptureScreenshot,
  captureScreenshot,
  listDisplays,
  pngSize,
  resetDisplayCache,
} from "../screenshot.js";

/** A buffer with a valid PNG signature + IHDR — everything pngSize() reads. */
function fakePng(width: number, height: number, totalBytes = 64): Buffer {
  const b = Buffer.alloc(Math.max(24, totalBytes));
  b.writeUInt32BE(0x89504e47, 0);
  b.writeUInt32BE(0x0d0a1a0a, 4);
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  return b;
}

/** macOS: the destination is the last argv entry. Windows: it is inside the script. */
function outputPath(cmd: string, args: string[]): string | null {
  if (cmd === "screencapture") return args[args.length - 1] ?? null;
  const m = /\$bmp\.Save\('([^']+)'/.exec(args.join(" "));
  return m ? m[1]! : null;
}

async function writeCapture(cmd: string, args: string[], png: Buffer): Promise<void> {
  const file = outputPath(cmd, args);
  if (file) await fs.writeFile(file, png);
}

let originalPlatform: PropertyDescriptor | undefined;
function setPlatform(p: string) {
  originalPlatform ??= Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: p, writable: true, configurable: true });
}

/** system_profiler's shape, trimmed to the keys listDisplaysMac reads. */
const MAC_PROFILE = JSON.stringify({
  SPDisplaysDataType: [
    {
      spdisplays_ndrvs: [
        { _spdisplays_pixels: "2808 x 4992" },
        { _spdisplays_pixels: "5760 x 3240", spdisplays_main: "spdisplays_yes" },
        { _spdisplays_pixels: "2808 x 4992" },
      ],
    },
  ],
});

/** The same machine, but with no display flagged `spdisplays_main`. */
const MAC_PROFILE_NO_MAIN = JSON.stringify({
  SPDisplaysDataType: [
    {
      spdisplays_ndrvs: [
        { _spdisplays_pixels: "2808 x 4992" },
        { _spdisplays_pixels: "5760 x 3240" },
      ],
    },
  ],
});

/** Two displays of DIFFERENT sizes, so a returned PNG can identify one. */
const MAC_PROFILE_DISTINCT = JSON.stringify({
  SPDisplaysDataType: [
    {
      spdisplays_ndrvs: [
        { _spdisplays_pixels: "5760 x 3240", spdisplays_main: "spdisplays_yes" },
        { _spdisplays_pixels: "1920 x 1080" },
      ],
    },
  ],
});

const WIN_DISPLAYS = [
  { index: 0, width: 3840, height: 2160, primary: true },
  { index: 1, width: 1920, height: 1080, primary: false },
];

beforeEach(() => {
  spawnCalls.length = 0;
  resetDisplayCache();
  handler = async () => ({ code: 0 });
});

afterEach(() => {
  vi.useRealTimers();
  if (originalPlatform) {
    Object.defineProperty(process, "platform", originalPlatform);
    originalPlatform = undefined;
  }
});

describe("canCaptureScreenshot", () => {
  it("is true on macOS and Windows, false elsewhere", () => {
    setPlatform("darwin");
    expect(canCaptureScreenshot()).toBe(true);
    setPlatform("win32");
    expect(canCaptureScreenshot()).toBe(true);
    setPlatform("linux");
    expect(canCaptureScreenshot()).toBe(false);
  });
});

describe("captureScreenshot", () => {
  it("rejects on unsupported platforms (headless Linux)", async () => {
    setPlatform("linux");
    await expect(captureScreenshot()).rejects.toThrow(/only supported on the macOS and Windows/);
  });
});

describe("pngSize", () => {
  it("reads the size out of the IHDR chunk", () => {
    expect(pngSize(fakePng(1234, 567))).toEqual({ width: 1234, height: 567 });
  });

  it("returns null (rather than a guess) for anything that isn't a PNG", () => {
    expect(pngSize(Buffer.from("not a png at all, but long enough to index"))).toBeNull();
    expect(pngSize(Buffer.alloc(4))).toBeNull();
  });
});

describe("listDisplays — enumeration", () => {
  it("parses macOS system_profiler and puts the MAIN display at index 0", async () => {
    setPlatform("darwin");
    handler = async () => ({ code: 0, stdout: MAC_PROFILE });
    const displays = await listDisplays();
    expect(displays).toEqual([
      { index: 0, width: 5760, height: 3240, primary: true },
      { index: 1, width: 2808, height: 4992, primary: false },
      { index: 2, width: 2808, height: 4992, primary: false },
    ]);
  });

  it("does NOT elect a primary when macOS flags none", async () => {
    // The old code rewrote `primary: index === 0` unconditionally, so whichever
    // display system_profiler happened to list first was captioned "the primary
    // screen" — a fact nobody established. Now the order is left alone and every
    // entry says primary: false, i.e. "this machine did not tell us".
    setPlatform("darwin");
    handler = async () => ({ code: 0, stdout: MAC_PROFILE_NO_MAIN });
    expect(await listDisplays()).toEqual([
      { index: 0, width: 2808, height: 4992, primary: false },
      { index: 1, width: 5760, height: 3240, primary: false },
    ]);
  });

  it("parses the Windows AllScreens enumeration", async () => {
    setPlatform("win32");
    handler = async () => ({ code: 0, stdout: JSON.stringify(WIN_DISPLAYS) });
    expect(await listDisplays()).toEqual(WIN_DISPLAYS);
  });

  it("moves a Windows primary listed second to index 0", async () => {
    setPlatform("win32");
    handler = async () => ({
      code: 0,
      stdout: JSON.stringify([
        { index: 0, width: 1920, height: 1080, primary: false },
        { index: 1, width: 3840, height: 2160, primary: true },
      ]),
    });
    expect(await listDisplays()).toEqual([
      { index: 0, width: 3840, height: 2160, primary: true },
      { index: 1, width: 1920, height: 1080, primary: false },
    ]);
  });

  it("marks nothing primary when the report names two of them", async () => {
    // A list with two primaries has not identified one, so it is treated exactly
    // like a list with none: no reordering, no invented flag.
    setPlatform("win32");
    handler = async () => ({
      code: 0,
      stdout: JSON.stringify([
        { index: 0, width: 1920, height: 1080, primary: true },
        { index: 1, width: 3840, height: 2160, primary: true },
      ]),
    });
    expect(await listDisplays()).toEqual([
      { index: 0, width: 1920, height: 1080, primary: false },
      { index: 1, width: 3840, height: 2160, primary: false },
    ]);
  });

  it("returns [] rather than throwing when the OS tooling fails", async () => {
    // Counting displays must never be able to prevent capturing one; an empty
    // list surfaces as "display count unknown", not as a claim of one screen.
    setPlatform("darwin");
    handler = async () => ({ code: 1, stderr: "boom" });
    expect(await listDisplays()).toEqual([]);
  });

  it("caches the enumeration so a burst of screenshots forks it once", async () => {
    setPlatform("darwin");
    handler = async () => ({ code: 0, stdout: MAC_PROFILE });
    await listDisplays();
    await listDisplays();
    expect(spawnCalls.filter((c) => c.cmd === "system_profiler")).toHaveLength(1);
  });
});

describe("captureScreenshot — macOS", () => {
  beforeEach(() => setPlatform("darwin"));

  it("defaults to the primary display with the original, unchanged argv", async () => {
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE };
      await writeCapture(cmd, args, fakePng(5760, 3240));
      return { code: 0 };
    };
    const shot = await captureScreenshot();
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    // No -D at all: the default capture must stay byte-for-byte what it was.
    expect(capture.args).not.toContain("-D");
    expect(capture.args.slice(0, 3)).toEqual(["-x", "-t", "png"]);
    expect(shot.meta.display).toBe(0);
    expect(shot.meta.displayCount).toBe(3);
    expect(shot.meta.width).toBe(5760);
    expect(shot.meta.height).toBe(3240);
    expect(shot.meta.scaled).toBe(false);
    expect(shot.meta.capturedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(shot.meta.displays).toHaveLength(3);
  });

  it("does not claim which display it got when the enumeration cannot say", async () => {
    // The machine from the audit: one wide panel and TWO identical portraits.
    // `-D 3` returns 2808x4992 — which is the size of BOTH portraits, so the
    // bytes cannot tell index 1 from index 2, and the enumeration's order is not
    // settled against screencapture's numbering. Reporting `display: 2` here
    // would hand the caller its own assumption back as a machine-verified fact.
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE };
      await writeCapture(cmd, args, fakePng(2808, 4992));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 2 });
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    expect(capture.args).toContain("-D");
    expect(capture.args[capture.args.indexOf("-D") + 1]).toBe("3");
    expect(shot.meta.display).toBeUndefined();
    // The topology and the true resolution are still reported — only the claim
    // about WHICH display is withheld.
    expect(shot.meta.displayCount).toBe(3);
    // The reported resolution comes from the PNG, not from the enumeration.
    expect(shot.meta.width).toBe(2808);
    expect(shot.meta.height).toBe(4992);
  });

  it("claims the index when the returned PNG matches exactly one display", async () => {
    // Here the -D mapping is not assumed but CHECKED: 1920x1080 is a size only
    // display 1 has, so these pixels can only be display 1.
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE_DISTINCT };
      await writeCapture(cmd, args, fakePng(1920, 1080));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 1 });
    expect(spawnCalls.find((c) => c.cmd === "screencapture")!.args).toContain("-D");
    expect(shot.meta.display).toBe(1);
  });

  it("withholds the index when the PNG does not match the display asked for", async () => {
    // A display running a scaled resolution reports its native panel size to
    // system_profiler while screencapture returns the framebuffer. Unknown is
    // the honest answer; "display 1" would not be.
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE_DISTINCT };
      await writeCapture(cmd, args, fakePng(1680, 1050));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 1 });
    expect(shot.meta.display).toBeUndefined();
    expect(shot.meta.width).toBe(1680);
  });

  it("claims display 0 without a size check — -D 1 is the main display", async () => {
    // This one rests on screencapture's man page, not on list order, so it holds
    // even when the returned size disagrees with what was enumerated.
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE };
      await writeCapture(cmd, args, fakePng(3024, 1964));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 0 });
    expect(spawnCalls.find((c) => c.cmd === "screencapture")!.args).toContain("-D");
    expect(shot.meta.display).toBe(0);
  });

  it("reports no display index at all when no primary was identified", async () => {
    // Default capture = the main display, but with nothing flagged primary we do
    // not know WHICH INDEX that is, so we say nothing rather than say "0".
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE_NO_MAIN };
      await writeCapture(cmd, args, fakePng(5760, 3240));
      return { code: 0 };
    };
    const shot = await captureScreenshot();
    expect(shot.meta.display).toBeUndefined();
    expect(shot.meta.displayCount).toBe(2);
    expect(shot.meta.displays!.every((d) => !d.primary)).toBe(true);
  });

  it("says the primary is unknown in the out-of-range refusal too", async () => {
    handler = async () => ({ code: 0, stdout: MAC_PROFILE_NO_MAIN });
    await expect(captureScreenshot({ display: 5 })).rejects.toThrow(
      /did not report which of its displays is the primary one/,
    );
  });

  it("refuses an out-of-range index and names the valid range", async () => {
    handler = async () => ({ code: 0, stdout: MAC_PROFILE });
    await expect(captureScreenshot({ display: 7 })).rejects.toThrow(
      /has 3 displays, so display 7 does not exist.*between 0 and 2/s,
    );
  });

  it('refuses display "all" and lists what to ask for instead', async () => {
    handler = async () => ({ code: 0, stdout: MAC_PROFILE });
    await expect(captureScreenshot({ display: "all" })).rejects.toThrow(
      /macOS cannot capture every display in one image.*display 0 \(5760x3240, primary\).*display 2 \(2808x4992\)/s,
    );
  });

  it("uses the caller-supplied display list instead of forking system_profiler", async () => {
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(1440, 900));
      return { code: 0 };
    };
    const shot = await captureScreenshot({
      display: 0,
      displays: [{ index: 0, width: 1440, height: 900, primary: true }],
    });
    expect(spawnCalls.some((c) => c.cmd === "system_profiler")).toBe(false);
    expect(shot.meta.displayCount).toBe(1);
    expect(shot.meta.display).toBe(0);
  });

  it("normalises a caller-supplied list that is NOT primary-first", async () => {
    // Issue 6: the caller's list used to be taken verbatim for both the range
    // check and the metadata while every other list was reordered, so on a Mac
    // where Electron lists the external panel first, `-D index+1` selected one
    // screen and the metadata described another.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(5120, 2880));
      return { code: 0 };
    };
    const shot = await captureScreenshot({
      display: 0,
      displays: [
        { index: 0, width: 1920, height: 1080, primary: false },
        { index: 1, width: 5120, height: 2880, primary: true },
      ],
    });
    // -D 1 (the main display) is what index 0 must mean...
    expect(spawnCalls[0]!.args[spawnCalls[0]!.args.indexOf("-D") + 1]).toBe("1");
    // ...and the list handed back must agree that index 0 is that display.
    expect(shot.meta.displays).toEqual([
      { index: 0, width: 5120, height: 2880, primary: true },
      { index: 1, width: 1920, height: 1080, primary: false },
    ]);
    expect(shot.meta.display).toBe(0);
    expect(shot.meta.width).toBe(5120);
  });
});

describe("captureScreenshot — Windows", () => {
  beforeEach(() => setPlatform("win32"));

  const REPORT = JSON.stringify({
    count: 2,
    display: 0,
    sourceWidth: 3840,
    sourceHeight: 2160,
    scaled: false,
    displays: WIN_DISPLAYS,
  });

  it("captures the primary display by default and reports the topology", async () => {
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(3840, 2160));
      return { code: 0, stdout: REPORT };
    };
    const shot = await captureScreenshot();
    const script = spawnCalls[0]!.args.join(" ");
    expect(script).toContain("$sel = 0;");
    // The primary-screen-only bounds of the old implementation are gone; the
    // script now selects out of an explicit, primary-first ordering.
    expect(script).toContain("AllScreens");
    expect(shot.meta.display).toBe(0);
    expect(shot.meta.displayCount).toBe(2);
    expect(shot.meta.width).toBe(3840);
    expect(shot.meta.scaled).toBe(false);
  });

  it("passes an explicit index through to the capture script", async () => {
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(1920, 1080));
      return {
        code: 0,
        stdout: JSON.stringify({
          count: 2,
          display: 1,
          sourceWidth: 1920,
          sourceHeight: 1080,
          scaled: false,
          displays: WIN_DISPLAYS,
        }),
      };
    };
    const shot = await captureScreenshot({ display: 1 });
    expect(spawnCalls[0]!.args.join(" ")).toContain("$sel = 1;");
    expect(shot.meta.display).toBe(1);
  });

  it('captures the whole virtual desktop for "all", and reports the downscale', async () => {
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(3840, 1687));
      return {
        code: 0,
        stdout: JSON.stringify({
          count: 2,
          display: "all",
          sourceWidth: 11376,
          sourceHeight: 4992,
          scaled: true,
          displays: WIN_DISPLAYS,
        }),
      };
    };
    const shot = await captureScreenshot({ display: "all" });
    const script = spawnCalls[0]!.args.join(" ");
    expect(script).toContain("$sel = 'all';");
    expect(script).toContain("VirtualScreen");
    expect(shot.meta.display).toBe("all");
    expect(shot.meta.scaled).toBe(true);
    expect(shot.meta.sourceWidth).toBe(11376);
    expect(shot.meta.width).toBe(3840);
  });

  it("passes the script's controlled refusal through verbatim (no PowerShell noise)", async () => {
    handler = async () => ({
      code: 3,
      stderr: "AIC: This machine has 2 display(s), so display 9 does not exist.",
    });
    await expect(captureScreenshot({ display: 9 })).rejects.toThrow(
      /^This machine has 2 display\(s\), so display 9 does not exist\.$/,
    );
  });
});

describe("captureScreenshot — the 10 MB ceiling", () => {
  it("tells a multi-display caller to ask for a single screen instead", async () => {
    setPlatform("win32");
    handler = async (cmd, args) => {
      // 11 MB — over SCREENSHOT_MAX_BYTES even after the script's downscale.
      await writeCapture(cmd, args, fakePng(9000, 4000, 11 * 1024 * 1024));
      return { code: 0, stdout: JSON.stringify({ count: 3, display: "all", scaled: true }) };
    };
    await expect(captureScreenshot({ display: "all" })).rejects.toThrow(
      /exceeds the 10 MB limit.*ALL displays.*single screen.*display index/s,
    );
  });

  it("keeps the plain over-limit message for a single display", async () => {
    setPlatform("darwin");
    handler = async (cmd, args) => {
      if (cmd === "system_profiler") return { code: 0, stdout: MAC_PROFILE };
      await writeCapture(cmd, args, fakePng(9000, 4000, 11 * 1024 * 1024));
      return { code: 0 };
    };
    const err = await captureScreenshot().catch((e: Error) => e);
    expect((err as Error).message).toMatch(/exceeds the 10 MB limit\.$/);
  });
});

describe("captureScreenshot — the spawn timeout", () => {
  it("fails fast with permission guidance when the capture never returns", async () => {
    // Without this the ONLY backstop was the relay's 30s timer, whose message
    // ("Timed out waiting for the screenshot") says nothing about permissions —
    // which is exactly the situation a TCC-blocked screencapture is in.
    setPlatform("darwin");
    vi.useFakeTimers();
    handler = async (cmd) => (cmd === "system_profiler" ? { code: 0, stdout: MAC_PROFILE } : { hang: true });
    const promise = captureScreenshot();
    const assertion = expect(promise).rejects.toThrow(
      /did not finish within 20s.*Screen Recording/s,
    );
    await vi.advanceTimersByTimeAsync(25_000);
    await assertion;
  });
});
