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
  WINDOWS_NO_BACKEND_REFUSAL,
  type ScreenCaptureBackend,
  type ScreenCaptureDisplay,
  type ScreenCaptureRequest,
} from "../screenshot.js";
import type { RawImage } from "../png-encode.js";
import { SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE } from "@aicommander/protocol";
import zlib from "node:zlib";

/** A buffer with a valid PNG signature + IHDR — everything pngSize() reads. */
function fakePng(width: number, height: number, totalBytes = 64): Buffer {
  const b = Buffer.alloc(Math.max(24, totalBytes));
  b.writeUInt32BE(0x89504e47, 0);
  b.writeUInt32BE(0x0d0a1a0a, 4);
  b.writeUInt32BE(width, 16);
  b.writeUInt32BE(height, 20);
  return b;
}

/** macOS: the destination is the last argv entry. */
function outputPath(cmd: string, args: string[]): string | null {
  if (cmd === "screencapture") return args[args.length - 1] ?? null;
  return null;
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

/** A solid BGRA frame of one colour. */
function solid(width: number, height: number, [b, g, r]: [number, number, number]): RawImage {
  const data = Buffer.alloc(width * height * 4);
  for (let i = 0; i < data.length; i += 4) {
    data[i] = b;
    data[i + 1] = g;
    data[i + 2] = r;
    data[i + 3] = 255;
  }
  return { width, height, data };
}

/** Incompressible BGRA pixels (deterministic per seed). */
function noise(width: number, height: number, seed = 0x12345678): RawImage {
  const data = Buffer.alloc(width * height * 4);
  let x = seed | 1;
  for (let i = 0; i < data.length; i++) {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    data[i] = x & 0xff;
  }
  return { width, height, data };
}

/** A backend over fixed displays; records every capture request. */
function fakeBackend(
  displays: ScreenCaptureDisplay[],
  frame: (req: ScreenCaptureRequest) => RawImage = (req) => solid(req.width, req.height, [0, 0, 255]),
): ScreenCaptureBackend & { requests: ScreenCaptureRequest[][] } {
  const requests: ScreenCaptureRequest[][] = [];
  return {
    requests,
    listDisplays: () => displays,
    capture: async (reqs) => {
      requests.push(reqs);
      return reqs.map(frame);
    },
  };
}

function paethPredict(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/**
 * A synthetic 2560x1440 "desktop": a smooth gradient wallpaper, flat window
 * chrome, and rows of text-like glyph noise — the mix a real screenshot is.
 */
function desktopLike(width: number, height: number): RawImage {
  const data = Buffer.alloc(width * height * 4);
  let x = 0x2545f491;
  for (let py = 0; py < height; py++) {
    for (let px = 0; px < width; px++) {
      const i = (py * width + px) * 4;
      let r = (px * 255) / width;
      let g = (py * 255) / height;
      let b = 128;
      const inWindow = px > width * 0.1 && px < width * 0.7 && py > height * 0.1 && py < height * 0.8;
      if (inWindow) {
        r = g = b = 250;
        // "text": short random runs on every other 18px line band
        if (py % 18 < 12 && px % 9 < 6) {
          x ^= x << 13;
          x ^= x >>> 17;
          x ^= x << 5;
          if ((x & 3) === 0) r = g = b = 20;
        }
      }
      data[i] = b;
      data[i + 1] = g;
      data[i + 2] = r;
      data[i + 3] = 255;
    }
  }
  return { width, height, data };
}

/** Decode an RGB PNG (as encodePng writes it) back to rows of [r,g,b] for assertions. */
function decodeRgb(png: Buffer): { width: number; height: number; pixel: (x: number, y: number) => number[] } {
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  expect(png[25]).toBe(2); // colour type: RGB
  const idat: Buffer[] = [];
  let off = 8;
  while (off < png.length) {
    const len = png.readUInt32BE(off);
    const type = png.toString("ascii", off + 4, off + 8);
    if (type === "IDAT") idat.push(png.subarray(off + 8, off + 8 + len));
    off += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const stride = width * 3;
  const out = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y++) {
    const f = raw[y * (stride + 1)]!;
    for (let i = 0; i < stride; i++) {
      const v = raw[y * (stride + 1) + 1 + i]!;
      const a = i >= 3 ? out[y * stride + i - 3]! : 0;
      const up = y > 0 ? out[(y - 1) * stride + i]! : 0;
      const c = y > 0 && i >= 3 ? out[(y - 1) * stride + i - 3]! : 0;
      out[y * stride + i] = (v + (f === 1 ? a : f === 2 ? up : f === 4 ? paethPredict(a, up, c) : 0)) & 0xff;
    }
  }
  return { width, height, pixel: (x, y) => [...out.subarray(y * stride + x * 3, y * stride + x * 3 + 3)] };
}

/** Two side-by-side panels of different sizes, primary listed SECOND, with a gap below the small one. */
const WIN_BACKEND_DISPLAYS: ScreenCaptureDisplay[] = [
  { id: "side", bounds: { x: 3840, y: 0, width: 1920, height: 1080 }, primary: false },
  { id: "main", bounds: { x: 0, y: 0, width: 3840, height: 2160 }, primary: true },
];

/**
 * The audit machine as ELECTRON sees it: one wide primary and two portraits of
 * IDENTICAL pixel size, each with its own global DIP rectangle. The sizes cannot
 * tell display 1 from display 2; the bounds can.
 */
const MAC_DISPLAYS_WITH_BOUNDS = [
  {
    index: 0,
    width: 5760,
    height: 3240,
    primary: true,
    bounds: { x: 0, y: 0, width: 2880, height: 1620 },
  },
  {
    index: 1,
    width: 2808,
    height: 4992,
    primary: false,
    bounds: { x: 2880, y: 0, width: 1404, height: 2496 },
  },
  {
    index: 2,
    width: 2808,
    height: 4992,
    primary: false,
    bounds: { x: 4284, y: 0, width: 1404, height: 2496 },
  },
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

  it("does not spawn anything to enumerate on Windows (no PowerShell)", async () => {
    setPlatform("win32");
    expect(await listDisplays()).toEqual([]);
    expect(spawnCalls).toHaveLength(0);
  });

  it("returns [] rather than throwing when the OS tooling fails", async () => {
    // Counting displays must never be able to prevent capturing one; an empty
    // list surfaces as "display count unknown", not as a claim of one screen.
    setPlatform("darwin");
    handler = async () => ({ code: 1, stderr: "boom" });
    expect(await listDisplays()).toEqual([]);
  });

  it("keeps the macOS probe at 6s so probe + capture stays under the relay's 30s", async () => {
    // macOS probes and then captures, sequentially: 6s + the 20s capture budget
    // is 26s worst case.
    setPlatform("darwin");
    vi.useFakeTimers();
    handler = async () => ({ hang: true });
    let settled = false;
    const promise = listDisplays().then((d) => {
      settled = true;
      return d;
    });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(promise).resolves.toEqual([]);
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

describe("captureScreenshot — macOS, selecting a display by its bounds", () => {
  beforeEach(() => setPlatform("darwin"));

  it("captures a non-primary display with -R and REPORTS the index, duplicate sizes and all", async () => {
    // The bug: on this machine (two identical 2808x4992 portraits) the returned
    // PNG's size matched two displays, so the index could not be confirmed and
    // the caller was told "the machine did not report WHICH display". With
    // bounds there is nothing left to confirm — the pixels ARE that rectangle.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(2808, 4992));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 2, displays: MAC_DISPLAYS_WITH_BOUNDS });
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    expect(capture.args).not.toContain("-D");
    expect(capture.args).toContain("-R");
    // The rect is display 2's bounds in POINTS, not its pixel size.
    expect(capture.args[capture.args.indexOf("-R") + 1]).toBe("4284,0,1404,2496");
    expect(shot.meta.display).toBe(2);
    expect(shot.meta.displayCount).toBe(3);
    // Resolution still comes from the PNG the caller receives, never the rect.
    expect(shot.meta.width).toBe(2808);
    expect(shot.meta.height).toBe(4992);
    // And no system_profiler fork: the caller's list already had everything.
    expect(spawnCalls.some((c) => c.cmd === "system_profiler")).toBe(false);
  });

  it("still states the index when the PNG's SIZE disagrees with the enumeration", async () => {
    // A scaled resolution or a non-integral backing scale makes the PNG's pixel
    // size differ from the enumerated one while keeping the rect's SHAPE. The
    // rect is what decides WHICH display — live-verified against the matching
    // -D capture on a three-display Mac, including panels at negative x and
    // negative y — so the index stands; the size reported is the PNG's, so
    // nothing is overstated either.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(2800, 4980));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 1, displays: MAC_DISPLAYS_WITH_BOUNDS });
    expect(spawnCalls[0]!.args[spawnCalls[0]!.args.indexOf("-R") + 1]).toBe("2880,0,1404,2496");
    expect(shot.meta.display).toBe(1);
    expect(shot.meta.width).toBe(2800);
  });

  it("withholds the index when the PNG's SHAPE is not the rect's", async () => {
    // The plausibility guard. Whatever backing scale a rect capture comes back
    // at applies to both axes, so the aspect ratio survives it; a PNG shaped
    // differently from the rect means something else happened (a rect clipped
    // at the desktop edge, bounds describing a layout the machine no longer
    // has), and then the rect has not established which display these pixels
    // are. Falls through to confirmMacDisplay, which cannot prove index 1 here
    // because two displays share that size — so `display` is omitted.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(1404, 900));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 1, displays: MAC_DISPLAYS_WITH_BOUNDS });
    expect(spawnCalls[0]!.args).toContain("-R");
    expect(shot.meta.display).toBeUndefined();
    // The pixels are still returned, and still described by the PNG itself.
    expect(shot.meta.width).toBe(1404);
    expect(shot.meta.height).toBe(900);
  });

  it("accepts a rect capture whose aspect ratio is off only by rounding", async () => {
    // 1404x2496 points at 1.5x rounds to 2106x3744 exactly, but a machine that
    // rounds the other way (2105x3745) is still the display we asked for: the
    // tolerance is a couple of percent, not exactness.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(2105, 3745));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 2, displays: MAC_DISPLAYS_WITH_BOUNDS });
    expect(shot.meta.display).toBe(2);
  });

  it("falls back to the SIZE proof, not to nothing, when the shape is wrong", async () => {
    // Same guard, on a desk where the enumeration can still identify the
    // display: a mis-shaped rect capture is demoted to the old dimension check
    // rather than discarded, so a provable index is still stated.
    const distinct = [
      {
        index: 0,
        width: 5760,
        height: 3240,
        primary: true,
        bounds: { x: 0, y: 0, width: 2880, height: 1620 },
      },
      {
        index: 1,
        width: 1920,
        height: 1080,
        primary: false,
        // 16:10 bounds against a 16:9 panel — whatever the cause, the shape of
        // the returned PNG will not be the rect's.
        bounds: { x: 2880, y: 0, width: 1920, height: 1200 },
      },
    ];
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(1920, 1080));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 1, displays: distinct });
    expect(spawnCalls[0]!.args).toContain("-R");
    // 1920x1080 matches exactly one enumerated display, so the index is proven
    // the pre-rect way and stated.
    expect(shot.meta.display).toBe(1);
  });

  it("keeps -D for the identified PRIMARY display even when bounds exist", async () => {
    // `-D 1` is the main display per the man page — documented, so there is no
    // reason to swap a proven path for a computed rect.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(5760, 3240));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 0, displays: MAC_DISPLAYS_WITH_BOUNDS });
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    expect(capture.args).toContain("-D");
    expect(capture.args).not.toContain("-R");
    expect(shot.meta.display).toBe(0);
  });

  it("leaves the default (no display argument) argv byte-identical", async () => {
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(5760, 3240));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ displays: MAC_DISPLAYS_WITH_BOUNDS });
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    expect(capture.args.slice(0, 3)).toEqual(["-x", "-t", "png"]);
    expect(capture.args).toHaveLength(4);
    expect(shot.meta.display).toBe(0);
  });

  it("falls back to -D, and to withholding the index, when the list carries no bounds", async () => {
    // Every older desktop build and the system_profiler probe: unchanged
    // behaviour, which is what keeps those agents working as they always did.
    const noBounds = MAC_DISPLAYS_WITH_BOUNDS.map(({ bounds: _bounds, ...d }) => d);
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(2808, 4992));
      return { code: 0 };
    };
    const shot = await captureScreenshot({ display: 2, displays: noBounds });
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    expect(capture.args).not.toContain("-R");
    expect(capture.args[capture.args.indexOf("-D") + 1]).toBe("3");
    expect(shot.meta.display).toBeUndefined();
  });

  it("ignores a degenerate rect rather than capturing nothing", async () => {
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(1920, 1080));
      return { code: 0 };
    };
    const shot = await captureScreenshot({
      display: 1,
      displays: [
        { index: 0, width: 5760, height: 3240, primary: true },
        {
          index: 1,
          width: 1920,
          height: 1080,
          primary: false,
          bounds: { x: 0, y: 0, width: 0, height: 1080 },
        },
      ],
    });
    const capture = spawnCalls.find((c) => c.cmd === "screencapture")!;
    expect(capture.args).not.toContain("-R");
    expect(capture.args).toContain("-D");
    // Nothing proved the index, but the size happens to be unique here, so the
    // old dimension check answers it — exactly as before this change.
    expect(shot.meta.display).toBe(1);
  });

  it("uses a rect for index 0 when NO display was flagged primary", async () => {
    // With no primary identified, index 0 is just the first display the OS
    // listed — `-D 1` would grab the main display, which may be another one.
    // The rect makes index 0 mean the display at index 0.
    handler = async (cmd, args) => {
      await writeCapture(cmd, args, fakePng(2808, 4992));
      return { code: 0 };
    };
    const shot = await captureScreenshot({
      display: 0,
      displays: [
        {
          index: 0,
          width: 2808,
          height: 4992,
          primary: false,
          bounds: { x: -1404, y: 0, width: 1404, height: 2496 },
        },
        { index: 1, width: 2808, height: 4992, primary: false },
      ],
    });
    // Negative origins are legitimate: a panel placed left of the main display.
    expect(spawnCalls[0]!.args[spawnCalls[0]!.args.indexOf("-R") + 1]).toBe("-1404,0,1404,2496");
    expect(shot.meta.display).toBe(0);
  });
});

describe("captureScreenshot — Windows without a capture backend", () => {
  it("fails fast with a clear sentence and never spawns PowerShell", async () => {
    // 1.4.1 ran an inline System.Drawing CopyFromScreen script here, which
    // Microsoft Defender blocks as HackTool:PowerShell/EmpireGetScreenshot.B.
    setPlatform("win32");
    await expect(captureScreenshot()).rejects.toThrow(WINDOWS_NO_BACKEND_REFUSAL);
    await expect(captureScreenshot({ display: "all" })).rejects.toThrow(/only available from the AI Commander desktop app/);
    expect(spawnCalls).toHaveLength(0);
  });
});

describe("captureScreenshot — the 10 MB ceiling", () => {
  it("tells a multi-display caller to ask for a single screen instead", async () => {
    // Random noise does not compress: two 3840x2400 panels side by side are
    // downscaled to 3840x1200, which still encodes to ~13 MB of RGB — over
    // SCREENSHOT_MAX_BYTES. (Different seeds, so deflate cannot match one
    // panel's rows against the other's.)
    const backend = fakeBackend(
      [
        { id: "a", bounds: { x: 0, y: 0, width: 3840, height: 2400 }, primary: true },
        { id: "b", bounds: { x: 3840, y: 0, width: 3840, height: 2400 }, primary: false },
      ],
      (req) => noise(req.width, req.height, req.id === "a" ? 1 : 2),
    );
    await expect(captureScreenshot({ display: "all", backend })).rejects.toThrow(
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

describe("captureScreenshot — injected capture backend (Windows desktop app)", () => {
  // The backend path is platform-independent by design; pin win32 because that
  // is where it runs, and to prove no PowerShell is spawned there.
  beforeEach(() => setPlatform("win32"));

  it("captures the primary display by default, at native size, and reports the topology", async () => {
    const backend = fakeBackend(WIN_BACKEND_DISPLAYS);
    const shot = await captureScreenshot({ backend });
    expect(backend.requests).toEqual([[{ id: "main", width: 3840, height: 2160 }]]);
    expect(spawnCalls).toHaveLength(0);
    expect(shot.mimeType).toBe("image/png");
    expect(pngSize(shot.data)).toEqual({ width: 3840, height: 2160 });
    expect(shot.meta).toMatchObject({
      display: 0,
      displayCount: 2,
      width: 3840,
      height: 2160,
      sourceWidth: 3840,
      sourceHeight: 2160,
      scaled: false,
    });
    // Primary first, even though the backend listed it second — and no
    // backend-internal fields leak into the protocol metadata.
    expect(shot.meta.displays).toEqual([
      { index: 0, width: 3840, height: 2160, primary: true },
      { index: 1, width: 1920, height: 1080, primary: false },
    ]);
  });

  it("captures an explicit index by the id of the display at that index", async () => {
    const backend = fakeBackend(WIN_BACKEND_DISPLAYS, (req) => solid(req.width, req.height, [255, 0, 0]));
    const shot = await captureScreenshot({ display: 1, backend });
    expect(backend.requests).toEqual([[{ id: "side", width: 1920, height: 1080 }]]);
    expect(shot.meta.display).toBe(1);
    const img = decodeRgb(shot.data);
    expect(img.width).toBe(1920);
    expect(img.pixel(10, 10)).toEqual([0, 0, 255]); // BGRA blue → RGB blue
  });

  it("ignores a caller display list in favour of the backend's own enumeration", async () => {
    const backend = fakeBackend(WIN_BACKEND_DISPLAYS);
    const shot = await captureScreenshot({
      backend,
      displays: [{ index: 0, width: 800, height: 600, primary: true }],
    });
    expect(shot.meta.displayCount).toBe(2);
  });

  it("refuses an out-of-range index with the shared wording, before capturing", async () => {
    const backend = fakeBackend(WIN_BACKEND_DISPLAYS);
    await expect(captureScreenshot({ display: 5, backend })).rejects.toThrow(
      /^This machine has 2 displays, so display 5 does not exist\. Retrying will not help — ask for a display between 0 and 1 instead \(0 is the primary screen\)\.$/,
    );
    expect(backend.requests).toHaveLength(0);
  });

  it('composites "all" in the real layout, gaps black, downscaled and reported as scaled', async () => {
    const colours: Record<string, [number, number, number]> = { main: [0, 0, 255], side: [0, 255, 0] };
    const backend = fakeBackend(WIN_BACKEND_DISPLAYS, (req) => solid(req.width, req.height, colours[req.id]!));
    const shot = await captureScreenshot({ display: "all", backend });
    // Virtual desktop 5760x2160 → longest edge 3840 → r = 2/3.
    expect(shot.meta).toMatchObject({
      display: "all",
      scaled: true,
      sourceWidth: 5760,
      sourceHeight: 2160,
      width: 3840,
      height: 1440,
    });
    expect(backend.requests).toEqual([
      [
        { id: "main", width: 2560, height: 1440 },
        { id: "side", width: 1280, height: 720 },
      ],
    ]);
    const img = decodeRgb(shot.data);
    expect(img.pixel(100, 100)).toEqual([255, 0, 0]); // main (red)
    expect(img.pixel(3000, 100)).toEqual([0, 255, 0]); // side (green)
    expect(img.pixel(3000, 1000)).toEqual([0, 0, 0]); // the gap under the smaller panel
  });

  it('does not scale an "all" capture that already fits', async () => {
    const backend = fakeBackend([
      { id: "l", bounds: { x: -1280, y: 0, width: 1280, height: 1024 }, primary: false },
      { id: "r", bounds: { x: 0, y: 0, width: 1920, height: 1080 }, primary: true },
    ]);
    const shot = await captureScreenshot({ display: "all", backend });
    expect(shot.meta).toMatchObject({ scaled: false, width: 3200, height: 1080, sourceWidth: 3200 });
  });

  it("downscales a single display whose PNG is over the cap instead of refusing", async () => {
    // Noise at 3840x1200 encodes to ~13 MB; the retry asks the backend for a
    // smaller frame and returns that, flagged as scaled, with the native size
    // still reported as the source.
    const backend = fakeBackend(
      [{ id: "x", bounds: { x: 0, y: 0, width: 3840, height: 1200 }, primary: true }],
      (req) => noise(req.width, req.height),
    );
    const shot = await captureScreenshot({ backend });
    expect(shot.data.length).toBeLessThanOrEqual(10 * 1024 * 1024);
    expect(shot.meta).toMatchObject({ display: 0, scaled: true, sourceWidth: 3840, sourceHeight: 1200 });
    expect(shot.meta.width).toBeLessThan(3840);
    expect(backend.requests.length).toBeGreaterThan(1);
    expect(backend.requests[0]).toEqual([{ id: "x", width: 3840, height: 1200 }]);
  });

  it("refuses with the pixel size once every downscale attempt is still over the cap", async () => {
    // An encoder that always returns 11 MB: three attempts, then the refusal.
    const backend = {
      ...fakeBackend([{ id: "x", bounds: { x: 0, y: 0, width: 2560, height: 1440 }, primary: true }]),
      encodePng: (img: RawImage) => {
        const b = Buffer.alloc(11 * 1024 * 1024);
        b.writeUInt32BE(0x89504e47, 0);
        b.writeUInt32BE(0x0d0a1a0a, 4);
        b.writeUInt32BE(img.width, 16);
        b.writeUInt32BE(img.height, 20);
        return b;
      },
    };
    const err = await captureScreenshot({ backend }).catch((e: Error) => e);
    expect((err as Error).message).toMatch(/^Screenshot is 11\.0 MB \(\d+x\d+ pixels\), which exceeds the 10 MB limit\.$/);
    expect(backend.requests).toHaveLength(3);
  });

  it("prefers the backend's native PNG encoder over the pure-JS one", async () => {
    const encoded = fakePng(3840, 2160, 1000);
    const encodePngNative = vi.fn(() => encoded);
    const backend = { ...fakeBackend(WIN_BACKEND_DISPLAYS), encodePng: encodePngNative };
    const shot = await captureScreenshot({ backend });
    expect(encodePngNative).toHaveBeenCalledTimes(1);
    expect(shot.data).toBe(encoded);
  });

  it("encodes a desktop-like 2560x1440 frame well under the cap with the pure-JS fallback", async () => {
    const backend = fakeBackend(
      [{ id: "x", bounds: { x: 0, y: 0, width: 2560, height: 1440 }, primary: true }],
      (req) => desktopLike(req.width, req.height),
    );
    const shot = await captureScreenshot({ backend });
    expect(shot.meta.scaled).toBe(false);
    expect(shot.data.length).toBeLessThan(3 * 1024 * 1024);
  });

  it("refuses to encode a frame of the wrong size instead of mislabelling it", async () => {
    const backend = fakeBackend(WIN_BACKEND_DISPLAYS, () => solid(10, 10, [0, 0, 0]));
    await expect(captureScreenshot({ backend })).rejects.toThrow(/returned a 10x10 image where 3840x2160 was requested/);
  });

  it("says so when the machine reports no displays", async () => {
    const backend = fakeBackend([]);
    await expect(captureScreenshot({ backend })).rejects.toThrow(/reported no displays/);
  });

  it("passes the backend's own error through", async () => {
    const backend: ScreenCaptureBackend = {
      listDisplays: () => WIN_BACKEND_DISPLAYS,
      capture: async () => {
        throw new Error("Windows did not return an image for display 0.");
      },
    };
    await expect(captureScreenshot({ backend })).rejects.toThrow("Windows did not return an image for display 0.");
  });
});

describe("captureScreenshot — antivirus (AMSI) blocks", () => {
  it("replaces PowerShell's 'blocked by your antivirus' stderr with the caller-ready sentence", async () => {
    // Nothing spawns PowerShell for a capture any more, but the mapping lives in
    // the shared spawn helper so no child process can leak that text again.
    setPlatform("darwin");
    handler = async (cmd) =>
      cmd === "system_profiler"
        ? { code: 0, stdout: MAC_PROFILE }
        : {
            code: 1,
            stderr:
              "This script contains malicious content and has been blocked by your antivirus software.\n" +
              "    + FullyQualifiedErrorId : ScriptContainedMaliciousContent",
          };
    await expect(captureScreenshot()).rejects.toThrow(SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE);
  });
});

describe("captureScreenshot — backend timeout", () => {
  it("fails with a sentence when the backend never answers", async () => {
    setPlatform("win32");
    vi.useFakeTimers();
    const backend: ScreenCaptureBackend = {
      listDisplays: () => WIN_BACKEND_DISPLAYS,
      capture: () => new Promise(() => {}),
    };
    const promise = captureScreenshot({ backend });
    const assertion = expect(promise).rejects.toThrow(/did not finish within 20s/);
    await vi.advanceTimersByTimeAsync(25_000);
    await assertion;
  });
});
