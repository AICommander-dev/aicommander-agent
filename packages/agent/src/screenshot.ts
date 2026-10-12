import { spawn } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import { blackCanvas, blit, encodePng, type RawImage } from "./png-encode.js";
import {
  SCREENSHOT_MAX_BYTES,
  SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE,
  isAntivirusScriptBlock,
  type ScreenshotCaptureMeta,
  type ScreenshotDisplayInfo,
  type ScreenshotDisplaySelector,
} from "@aicommander/protocol";

export interface CapturedScreenshot {
  /** Raw image bytes. */
  data: Buffer;
  /** MIME type of `data` (always image/png today). */
  mimeType: string;
  /**
   * What was ACTUALLY captured — echoed to the relay so the caller is told which
   * display it is looking at rather than which one it asked for. Never inferred
   * from the request: `width`/`height` are read out of the returned PNG itself,
   * and `display` is OMITTED whenever the machine could not establish which
   * display the returned pixels belong to (see macRectCapture, which removes the
   * question where it can, and confirmMacDisplay, which answers what is left).
   * An absent `display` means "unknown", never "display 0".
   */
  meta: ScreenshotCaptureMeta;
}

export interface ScreenshotOptions {
  /**
   * 0-based display index, or "all" for the whole virtual desktop. Omitted means
   * the primary display — and, deliberately, the byte-for-byte SAME capture
   * command this module has always run, so the default path cannot regress.
   */
  display?: ScreenshotDisplaySelector;
  /**
   * Displays the caller already knows about. The desktop app passes Electron's
   * `screen.getAllDisplays()`, which is instant; without it macOS falls back to
   * a `system_profiler` probe that costs a second or two (see listDisplays).
   * Ignored when `backend` is given: the backend's own enumeration is the one
   * its pixels are matched against.
   */
  displays?: ScreenshotDisplayInfo[];
  /**
   * Where the pixels come from. The Windows desktop app passes one built on
   * Electron's `desktopCapturer` (see ScreenCaptureBackend); with it, this module
   * does the selection, compositing, scaling, encoding and size cap itself and
   * spawns nothing. Without it, macOS uses `screencapture` and Windows refuses —
   * see captureScreenshot for why there is no Windows fallback any more.
   */
  backend?: ScreenCaptureBackend;
}

/** One display as a capture backend enumerates it. */
export interface ScreenCaptureDisplay {
  /** The backend's own identifier, handed back in `capture` requests. Opaque here. */
  id: string;
  /**
   * The display's rectangle in the virtual desktop, in PHYSICAL pixels — the
   * same coordinate space for every display, so "all" can be composited in the
   * real layout (gaps included) from these alone.
   */
  bounds: { x: number; y: number; width: number; height: number };
  /** True only for the display the OS itself names primary. */
  primary: boolean;
}

/** One capture request: a display, and the exact pixel size wanted back. */
export interface ScreenCaptureRequest {
  id: string;
  width: number;
  height: number;
}

/**
 * A source of screen pixels the agent library can drive without knowing how
 * they are obtained. The desktop app implements it with Electron's
 * `desktopCapturer` + `screen` modules; tests implement it with fixtures.
 *
 * Contract:
 *  • `listDisplays` returns every display with bounds in one physical-pixel
 *    space. Order does not matter — the agent orders primary-first itself.
 *  • `capture` returns one BGRA frame per request, in request order, at EXACTLY
 *    the requested size (the backend scales; it knows its native resampler). It
 *    throws, with a caller-ready message, when a display cannot be captured —
 *    never returns a frame of some other display in its place.
 */
export interface ScreenCaptureBackend {
  listDisplays(): ScreenCaptureDisplay[] | Promise<ScreenCaptureDisplay[]>;
  capture(requests: ScreenCaptureRequest[]): Promise<RawImage[]>;
  /**
   * Optional native PNG encoder for a BGRA frame (the desktop app passes
   * Electron's `nativeImage` encoder). Preferred over this library's pure-JS
   * encoder, which is only the fallback.
   */
  encodePng?(image: RawImage): Buffer | Promise<Buffer>;
}

/**
 * How many times a single-display capture that encodes over SCREENSHOT_MAX_BYTES
 * is re-requested at a smaller size before giving up. A busy photo wallpaper on
 * a 4K/5K panel can exceed the cap at native size; one or two steps down always
 * fit, and an image of the screen beats a refusal.
 */
const SINGLE_DISPLAY_SHRINK_ATTEMPTS = 3;

/**
 * How long a capture may take before we give up on it.
 *
 * This exists because of macOS TCC: without the Screen Recording grant the
 * documented behaviour is a black image, but we have NOT measured what happens
 * on every macOS version — a non-zero exit and a process that sits waiting on a
 * consent dialog are both plausible. A hung `screencapture` used to be caught
 * only by the relay's 30s timer, which reports "Timed out waiting for the
 * screenshot" — a message that tells the caller nothing about permissions. This
 * timeout sits comfortably under that 30s so the specific, actionable error is
 * the one that wins the race.
 */
const CAPTURE_TIMEOUT_MS = 20_000;

/**
 * Display enumeration is advisory; never let it eat the capture's budget.
 *
 * macOS runs the probe (when the desktop app did not hand a list down) and THEN
 * the capture, sequentially, under the relay's 30s timer. 6s + the 20s
 * CAPTURE_TIMEOUT_MS keeps the worst case at 26s; anything larger would let a
 * slow probe followed by a slow capture finish after the relay gave up.
 */
const ENUMERATE_TIMEOUT_MS_MAC = 6_000;

/**
 * Display topology changes rarely (plugging a monitor), and the macOS probe is a
 * `system_profiler` fork that costs ~1-2s. Cache it briefly so a burst of
 * screenshots pays for it once. Deliberately short: a caller who just plugged in
 * a display should not be told for long that it does not exist.
 */
const DISPLAY_CACHE_TTL_MS = 60_000;

/**
 * Longest edge a MULTI-display capture may have before it is downscaled.
 *
 * A virtual desktop spanning a 5760x3240 panel and two 2808x4992 portraits is
 * ~11400x5000 — a PNG far over SCREENSHOT_MAX_BYTES, which would have failed as
 * a bare "too big" with no way for the caller to know what to do instead. Single
 * displays are never scaled by THIS geometry cap; on Windows the capture
 * backend path can still reduce one, but only when the full-size PNG would
 * exceed SCREENSHOT_MAX_BYTES (then the reply is labelled `scaled`).
 */
const MULTI_DISPLAY_MAX_DIMENSION = 3840;

/**
 * True on platforms where the desktop app can grab the screen (mac/win). On
 * Windows that takes the desktop app's capture backend — see captureScreenshot.
 */
export function canCaptureScreenshot(): boolean {
  return process.platform === "darwin" || process.platform === "win32";
}

/**
 * Capture a display as a PNG. With `options.backend` (the Windows desktop app)
 * the backend supplies the pixels; otherwise macOS uses `screencapture`. Throws
 * on any other platform (headless Linux), on a Windows machine without a
 * backend, on capture failure, on an out-of-range display index, or if the
 * result exceeds SCREENSHOT_MAX_BYTES.
 *
 * WHY WINDOWS HAS NO BACKEND-LESS PATH. Up to 1.4.1 Windows captured through an
 * inline PowerShell script (System.Drawing `CopyFromScreen` + `Bitmap.Save`).
 * That script is, line for line, the shape of PowerShell Empire's
 * Get-Screenshot, and Microsoft Defender's AMSI scanning blocks it as
 * `HackTool:PowerShell/EmpireGetScreenshot.B` — on a stock Windows install,
 * with no exclusion that could help, because AMSI scans script content rather
 * than files. A headless (npm) Windows agent has no Electron to capture with
 * and never answered screenshots anyway (it registers no ScreenShareProvider),
 * so it fails fast here with a sentence instead of running the flagged script.
 *
 * On macOS the capture requires the app to hold the "Screen Recording" (TCC)
 * permission; without it the system is documented to yield a black image rather
 * than an error, so the desktop app is responsible for prompting the user to
 * grant it — and the connection layer refuses to even call here when it knows
 * the grant is missing (a black rectangle is a worse answer than a sentence
 * saying why).
 */
export async function captureScreenshot(
  options: ScreenshotOptions = {},
): Promise<CapturedScreenshot> {
  if (options.backend) return captureWithBackend(options, options.backend);
  if (process.platform === "darwin") return captureMac(options);
  if (process.platform === "win32") throw new Error(WINDOWS_NO_BACKEND_REFUSAL);
  throw new Error(
    "Screen capture is only supported on the macOS and Windows desktop apps.",
  );
}

// ── Display enumeration ────────────────────────────────────────────────────

let displayCache: { at: number; displays: ScreenshotDisplayInfo[] } | null = null;

/** Drop the cached enumeration (tests, and any caller that knows it moved). */
export function resetDisplayCache(): void {
  displayCache = null;
}

/**
 * Enumerate the machine's displays (macOS only — [] elsewhere), primary first
 * WHEN the OS said which one is primary (see normalizeDisplays — we never elect
 * one ourselves).
 *
 * Best-effort by design: it returns [] rather than throwing when the OS tooling
 * is unavailable or unparseable, because a failure to COUNT displays must never
 * prevent CAPTURING one. An empty list surfaces as "display count unknown" in
 * the reply — an honest gap, not a claim of one screen.
 */
export async function listDisplays(): Promise<ScreenshotDisplayInfo[]> {
  if (displayCache && Date.now() - displayCache.at < DISPLAY_CACHE_TTL_MS) {
    return displayCache.displays;
  }
  let displays: ScreenshotDisplayInfo[] = [];
  try {
    if (process.platform === "darwin") displays = await listDisplaysMac();
    // Windows: no backend-less enumeration. The only Windows capture path is the
    // desktop app's backend, which enumerates through Electron; spawning
    // PowerShell just to count screens is not worth a process (or an AV scan).
  } catch {
    displays = [];
  }
  displayCache = { at: Date.now(), displays };
  return displays;
}

/**
 * macOS has no small CLI that lists displays, so we parse `system_profiler`.
 *
 * NOT SETTLED BY MEASUREMENT: whether this list's order matches `screencapture
 * -D <n>`'s order. The ONLY index this module treats as known is the one the
 * `screencapture` man page settles — no `-D` (and `-D 1`) capture the MAIN
 * display — plus any index whose enumerated size the returned PNG confirms
 * uniquely (see confirmMacDisplay) — this probe reports no layout, so the
 * bounds-based `-R` capture is not available from it. Everything else is
 * reported as "unknown"
 * rather than guessed, and the reply's resolution is always read from the
 * returned PNG rather than from this list: the pixels are ground truth.
 *
 * `spdisplays_main` is likewise not guaranteed present (we have seen reports
 * without it), which is why normalizeDisplays refuses to invent a primary.
 */
async function listDisplaysMac(): Promise<ScreenshotDisplayInfo[]> {
  const { stdout } = await runToCompletion(
    "system_profiler",
    ["SPDisplaysDataType", "-json"],
    { timeoutMs: ENUMERATE_TIMEOUT_MS_MAC, captureStdout: true },
  );
  const parsed = JSON.parse(stdout) as {
    SPDisplaysDataType?: { spdisplays_ndrvs?: Record<string, unknown>[] }[];
  };
  const out: ScreenshotDisplayInfo[] = [];
  for (const card of parsed.SPDisplaysDataType ?? []) {
    for (const screen of card.spdisplays_ndrvs ?? []) {
      // "5120 x 2880" (native pixels) — or, on older builds, a resolution string
      // like "2560 x 1440 @ 60.00Hz". Both start with "<w> x <h>".
      const raw =
        (screen["_spdisplays_pixels"] as string | undefined) ??
        (screen["_spdisplays_resolution"] as string | undefined) ??
        "";
      const m = /^\s*(\d+)\s*x\s*(\d+)/.exec(raw);
      if (!m) continue;
      out.push({
        index: out.length,
        width: Number(m[1]),
        height: Number(m[2]),
        primary: screen["spdisplays_main"] === "spdisplays_yes",
      });
    }
  }
  return normalizeDisplays(out);
}

/**
 * The ONE funnel every display list passes through — the macOS probe, the
 * Windows capture backend's enumeration, and the list the desktop app hands down. A list that skipped
 * this would be range-checked and described under different rules than the ones
 * the reply's indices mean, which is precisely the bug this replaces.
 *
 * Two rules, and note what the second one deliberately does NOT do:
 *
 *  1. If EXACTLY ONE entry is flagged primary, it moves to index 0 and the rest
 *     keep their relative order. Index 0 then really is the display a caller
 *     gets when it passes no `display` at all.
 *  2. If NO entry is flagged primary (macOS without `spdisplays_main`, an empty
 *     or unparseable report, a caller list that never knew), the order is left
 *     alone and EVERY entry is flagged `primary: false`. We do not elect index 0.
 *     `primary: false` on every display therefore means "this machine did not say
 *     which display is primary" — not "this machine has no primary display" —
 *     and the reply must be worded that way rather than captioning whichever
 *     display happened to sort first as "the primary screen".
 *
 * More than one entry flagged primary is treated as case 2: a list that names two
 * primaries has not identified one.
 */
function normalizeDisplays<T extends ScreenshotDisplayInfo>(displays: T[]): T[] {
  const primary = displays.filter((d) => d.primary === true);
  const ordered =
    primary.length === 1 ? [primary[0]!, ...displays.filter((d) => d !== primary[0])] : displays;
  return ordered.map((d, index) => ({
    ...d,
    index,
    primary: primary.length === 1 && index === 0,
  }));
}

/**
 * Index of the display the machine identified as primary, or null when it did
 * not identify one. After normalizeDisplays this is always 0 or null; callers go
 * through here so the "we do not know" case cannot be read as index 0.
 */
function primaryIndex(displays: ScreenshotDisplayInfo[]): number | null {
  const at = displays.findIndex((d) => d.primary);
  return at === -1 ? null : at;
}

// ── Capture ────────────────────────────────────────────────────────────────

function tmpFile(ext: string): string {
  return path.join(os.tmpdir(), `aic-shot-${crypto.randomUUID()}.${ext}`);
}

async function captureMac(options: ScreenshotOptions): Promise<CapturedScreenshot> {
  // normalizeDisplays applies to the CALLER's list too: the range check, the
  // indices in `meta.displays` and the index we report must all mean the same
  // thing, and only one funnel can guarantee that.
  const displays = normalizeDisplays(options.displays ?? (await listDisplays()));

  // macOS deliberately has NO "all displays" mode here. `screencapture` writes one
  // file per display and offers no whole-desktop composite, and there is no
  // dependency-free way to stitch PNGs on macOS (sips resizes, it does not
  // compose). Returning the primary display and calling it "all" would be exactly
  // the silent mislabelling this whole path exists to remove, so we refuse and say
  // precisely what to ask for instead.
  if (options.display === "all") throw new Error(macAllDisplaysRefusal(displays));

  const index = validateIndex(options.display, displays);
  // The rect path, when it is available: a specific display selected BY ITS
  // GEOMETRY rather than by an index screencapture has to interpret. See
  // macRectCapture for exactly when it applies and why.
  const rect = macRectCapture(options.display, index, displays);
  const file = tmpFile("png");
  try {
    // -x: silent (no shutter sound). -t png: PNG output.
    // With no explicit display we run the ORIGINAL argv (no -D) so the default
    // capture is bit-identical to what every previous version produced.
    const args =
      options.display === undefined
        ? ["-x", "-t", "png", file]
        : rect
          ? // -R takes a rect in POINTS on the global desktop and returns it at
            // the backing scale factor, so this is the asked-for display's own
            // pixels — no index mapping involved.
            ["-x", "-t", "png", "-R", rect, file]
          : // screencapture numbers displays from 1. Beyond `-D 1` (the main
            // display, per the man page) the mapping from OUR index to that
            // numbering is an assumption — confirmMacDisplay decides whether the
            // reply is allowed to state which display came back.
            ["-x", "-t", "png", "-D", String(index + 1), file];
    await runToCompletion("screencapture", args, { timeoutMs: CAPTURE_TIMEOUT_MS });
    const shot = await readCapped(file, "image/png", false);
    const size = pngSize(shot.data);
    const captured =
      // A rect capture normally needs no confirmation: the pixels ARE that
      // display's rectangle, which is what makes two identically-sized monitors
      // distinguishable at last. LIVE-VERIFIED on a three-display Mac with
      // panels at both negative x and negative y: `-R` with Electron/NSScreen
      // bounds returns the same pixels as the matching `-D` capture. The PNG's
      // size legitimately differs from the enumerated pixel size (a scaled
      // resolution, a non-integral backing scale), so a size match is NOT
      // required — but a rect that screencapture clipped, or a bounds list that
      // does not describe this desktop, would change the SHAPE. Hence the cheap
      // aspect-ratio plausibility check below: same shape, state the index;
      // different shape, fall back to proving it from the enumeration (and omit
      // `display` when that cannot).
      rect !== null && rectAspectMatches(rect, size)
        ? index
        : confirmMacDisplay(options.display, index, displays, size);
    return {
      ...shot,
      meta: {
        ...(displays.length ? { displayCount: displays.length, displays } : {}),
        // Omitted, not guessed, when we cannot tell which display these pixels
        // are: an absent `display` reads as "the machine could not confirm it",
        // which is the truth, whereas echoing the request back would be the
        // caller's own assumption handed back as a machine-verified fact.
        ...(captured === null ? {} : { display: captured }),
        ...(size ? { width: size.width, height: size.height, sourceWidth: size.width, sourceHeight: size.height } : {}),
        scaled: false,
        capturedAt: new Date().toISOString(),
      },
    };
  } finally {
    await safeUnlink(file);
  }
}

/**
 * WHICH DISPLAY the returned pixels are — or null when this machine cannot
 * establish it. This is the whole honesty budget of the macOS `-D` path.
 *
 * Only consulted when the capture went through `-D <n>`. A capture made with
 * `-R` needs no inference at all (see macRectCapture), which is what finally
 * makes a non-primary display nameable on a desk with two identical monitors.
 *
 * What we are allowed to claim, and why:
 *
 *  • No `display` argument at all, or the index the machine itself flagged as
 *    primary: `screencapture` with no -D captures the main display, and -D 1 is
 *    documented as that same main display. So once the enumeration has told us
 *    WHICH INDEX the main display sits at, the claim rests on the man page, not
 *    on any assumption about list order.
 *  • A single-display machine asked for display 0: there is nothing else the
 *    pixels could be, given the list we have.
 *  • Any other index: the -D ↔ enumeration mapping is NOT SETTLED BY
 *    MEASUREMENT, so we demand evidence from the bytes — the returned PNG's own
 *    size must equal that display's enumerated size, AND no other display may
 *    share that size (a match against a size two monitors share proves nothing
 *    about which of the two came back).
 *
 * Everything else returns null, including the case where the enumeration failed
 * entirely: with no list, an index is not merely unproven, it has nothing to
 * index into. A macOS display running a SCALED resolution reports its native
 * panel size to `system_profiler` while `screencapture` returns the framebuffer,
 * so an honest "unknown" here is expected on such a machine rather than a fault.
 */
function confirmMacDisplay(
  requested: ScreenshotDisplaySelector | undefined,
  index: number,
  displays: ScreenshotDisplayInfo[],
  size: { width: number; height: number } | null,
): number | null {
  const primary = primaryIndex(displays);
  if (requested === undefined) return primary;
  if (primary !== null && index === primary) return index;
  if (displays.length === 1 && index === 0) return 0;
  const target = displays[index];
  if (!target || !size) return null;
  const sameSize = displays.filter((d) => d.width === size.width && d.height === size.height);
  return sameSize.length === 1 && sameSize[0] === target ? index : null;
}

/**
 * The `-R x,y,w,h` argument for capturing the requested display by GEOMETRY, or
 * null when this capture must fall back to the historical `-D <n>` path.
 *
 * Why this exists: `confirmMacDisplay` can only vouch for a non-primary index
 * when the returned PNG's size matches exactly ONE enumerated display, so a Mac
 * with two identically-sized portrait panels got correct pixels back with no way
 * to say WHICH panel they were — the caller was told "the machine did not report
 * which display" on every non-primary capture. `screencapture -R` removes the
 * question instead of answering it: the rect is in global points with the origin
 * at the top-left of the main display, exactly what Electron's `Display.bounds`
 * reports, and the file comes back at that display's backing scale.
 *
 * Returns null — i.e. keeps the old behaviour — when:
 *  • no display was requested (the default argv must stay byte-identical);
 *  • the requested index IS the machine's identified primary (`-D 1` is the main
 *    display per the man page: documented, so no reason to change it);
 *  • the enumeration carries no `bounds` for that display, which is every older
 *    desktop build and the macOS `system_profiler` fallback.
 */
function macRectCapture(
  requested: ScreenshotDisplaySelector | undefined,
  index: number,
  displays: ScreenshotDisplayInfo[],
): string | null {
  if (requested === undefined) return null;
  if (primaryIndex(displays) === index) return null;
  const b = displays[index]?.bounds;
  if (!b) return null;
  const parts = [b.x, b.y, b.width, b.height];
  // Guard the same way the desktop side does: a rect screencapture would reject
  // (or silently clip to nothing) is worse than the index path we already have.
  if (!parts.every((n) => typeof n === "number" && Number.isFinite(n))) return null;
  if (b.width <= 0 || b.height <= 0) return null;
  return parts.map((n) => String(Math.round(n))).join(",");
}

/** How far a rect capture's aspect ratio may drift from the rect's own. */
const RECT_ASPECT_TOLERANCE = 0.02;

/**
 * Does the returned PNG have the SHAPE the `-R` rect asked for?
 *
 * A rect capture comes back at the display's backing scale, so its pixel size is
 * the rect's point size times some scale factor we do not know — but whatever
 * that factor is, it applies to both axes, so the ASPECT RATIO must survive it.
 * Rounding at non-integral scales (1.5x, 2.25x) moves it by well under a
 * percent, so a 2% band separates "scaled as expected" from "this is not the
 * rectangle I asked for" (screencapture clipped it at the desktop edge, or the
 * bounds we were handed describe a layout the machine no longer has).
 *
 * Returns true when the size is unknown: an unparseable PNG is a reason to omit
 * the resolution, not a reason to doubt the rect that produced it.
 */
function rectAspectMatches(
  rect: string,
  size: { width: number; height: number } | null,
): boolean {
  if (!size) return true;
  const [, , w, h] = rect.split(",").map(Number);
  if (!w || !h || !Number.isFinite(w) || !Number.isFinite(h)) return true;
  const want = w / h;
  const got = size.width / size.height;
  return Math.abs(got - want) / want <= RECT_ASPECT_TOLERANCE;
}

function macAllDisplaysRefusal(displays: ScreenshotDisplayInfo[]): string {
  const list = displays.length
    ? `Ask for one display at a time instead: ` +
      displays
        .map((d) => `display ${d.index} (${d.width}x${d.height}${d.primary ? ", primary" : ""})`)
        .join(", ") +
      `.`
    : // No enumeration means we do not know how many there are, and index 0 is
      // not knowably the primary one — so say what to try, not what is true.
      `This machine could not enumerate its displays, so there is no list to choose from: ` +
      `ask for display 0, then 1, and so on until the index is refused.`;
  const count = displays.length ? `${displays.length} display${displays.length === 1 ? "" : "s"}` : "an unknown number of displays";
  return (
    `macOS cannot capture every display in one image, so display: "all" is not available on this machine ` +
    `(it has ${count}). Retrying will not help. ${list} ` +
    `The "all" mode works on Windows machines only.`
  );
}

/**
 * Resolve + range-check the requested index. Rejecting out-of-range HERE (rather
 * than letting `screencapture` fail with "invalid display specified") is what
 * lets the error name the valid range, which is the whole point of the reply.
 */
function validateIndex(
  display: ScreenshotDisplaySelector | undefined,
  displays: ScreenshotDisplayInfo[],
): number {
  if (display === undefined || display === "all") return 0;
  // Only say "0 is the primary screen" when the machine actually said so — see
  // normalizeDisplays. With no primary identified, index 0 is just the first
  // display the OS listed, and calling it primary would be the same invented
  // fact everywhere else in this file refuses to state.
  const zeroIsPrimary = primaryIndex(displays) === 0;
  const zeroNote = zeroIsPrimary
    ? "0 is the primary screen"
    : "this machine did not report which of its displays is the primary one";
  if (!Number.isInteger(display) || display < 0) {
    throw new Error(
      `Invalid display ${JSON.stringify(display)}. Pass a whole number from 0 upwards, or "all" (${zeroNote}).`,
    );
  }
  if (displays.length && display >= displays.length) {
    throw new Error(
      `This machine has ${displays.length} display${displays.length === 1 ? "" : "s"}, so display ${display} does not exist. ` +
        `Retrying will not help — ask for a display between 0 and ${displays.length - 1} instead ` +
        `(${zeroNote}).`,
    );
  }
  return display;
}

/**
 * The refusal a Windows machine gives when nobody supplied a capture backend —
 * i.e. the headless/npm agent. Worded for the caller: it names the build that
 * CAN take screenshots, and does not invite a retry.
 */
export const WINDOWS_NO_BACKEND_REFUSAL =
  "Screenshots on Windows are only available from the AI Commander desktop app; this headless agent has no " +
  "screen capture. Retrying will not help — install the desktop app on that machine if screenshots are needed. " +
  "Remote commands are not affected.";

/**
 * Capture through an injected backend — the Windows desktop app's path.
 *
 * The selection, layout, scaling and size rules are the ones the old PowerShell
 * script implemented, so callers see the same contract:
 *  • a 0-based index into the primary-first list (no index = index 0, which is
 *    the primary display whenever the OS named one), range-checked with the same
 *    refusal as everywhere else;
 *  • "all" = the virtual desktop, every display in its real position with the
 *    gaps between mismatched panels left black, downscaled to
 *    MULTI_DISPLAY_MAX_DIMENSION on its longest edge (`scaled: true`);
 *  • single displays are captured at native physical resolution, and retried
 *    smaller (`scaled: true`) only when that PNG exceeds SCREENSHOT_MAX_BYTES;
 *  • SCREENSHOT_MAX_BYTES with the same refusal wording.
 *
 * Like the old script — and unlike macOS — this path may state the index
 * outright: the frame for index N is requested by the backend id of the display
 * at index N of the very list reported in `meta.displays`, so index ↔ pixels is
 * established by construction, not assumed.
 */
async function captureWithBackend(
  options: ScreenshotOptions,
  backend: ScreenCaptureBackend,
): Promise<CapturedScreenshot> {
  const enumerated = (await backend.listDisplays()).filter(
    (d) => d.bounds.width > 0 && d.bounds.height > 0,
  );
  if (!enumerated.length) {
    throw new Error(
      "This machine reported no displays to capture — the desktop session may be locked, disconnected or " +
        "running without a monitor. Try again once someone is signed in at the machine with a display attached.",
    );
  }
  const ordered = normalizeDisplays(
    enumerated.map((d) => ({
      index: 0,
      width: d.bounds.width,
      height: d.bounds.height,
      primary: d.primary,
      source: d,
    })),
  );
  const displays: ScreenshotDisplayInfo[] = ordered.map(({ index, width, height, primary }) => ({
    index,
    width,
    height,
    primary,
  }));
  const selector = options.display ?? 0;
  const multi = selector === "all";

  const encode = async (img: RawImage): Promise<Buffer> =>
    backend.encodePng ? await backend.encodePng(img) : await encodePng(img);

  let png: Buffer;
  let sourceWidth: number;
  let sourceHeight: number;
  let scaled = false;
  if (!multi) {
    const index = validateIndex(selector, displays);
    const target = ordered[index]!.source;
    sourceWidth = target.bounds.width;
    sourceHeight = target.bounds.height;
    // Native size first; only an over-the-cap result is retried smaller, each
    // step sized from how far over the last attempt was (PNG size scales with
    // pixel count, so the square root of the ratio, with 10% headroom).
    let r = 1;
    for (let attempt = 0; ; attempt++) {
      const width = Math.max(1, Math.round(sourceWidth * r));
      const height = Math.max(1, Math.round(sourceHeight * r));
      const [frame] = await withCaptureTimeout(backend.capture([{ id: target.id, width, height }]));
      png = await encode(checkFrame(frame, width, height));
      if (png.length <= SCREENSHOT_MAX_BYTES || attempt + 1 >= SINGLE_DISPLAY_SHRINK_ATTEMPTS) break;
      r *= Math.min(0.9, Math.sqrt(SCREENSHOT_MAX_BYTES / png.length) * 0.9);
    }
    scaled = r < 1;
  } else {
    const minX = Math.min(...enumerated.map((d) => d.bounds.x));
    const minY = Math.min(...enumerated.map((d) => d.bounds.y));
    const maxX = Math.max(...enumerated.map((d) => d.bounds.x + d.bounds.width));
    const maxY = Math.max(...enumerated.map((d) => d.bounds.y + d.bounds.height));
    sourceWidth = maxX - minX;
    sourceHeight = maxY - minY;
    const longest = Math.max(sourceWidth, sourceHeight);
    const r = longest > MULTI_DISPLAY_MAX_DIMENSION ? MULTI_DISPLAY_MAX_DIMENSION / longest : 1;
    scaled = r < 1;
    const canvas = blackCanvas(
      Math.max(1, Math.round(sourceWidth * r)),
      Math.max(1, Math.round(sourceHeight * r)),
    );
    // Each display's destination rectangle is derived from its SCALED edges, so
    // adjacent panels meet exactly instead of leaving a one-pixel rounding seam.
    const placed = ordered.map(({ source: d }) => {
      const x = Math.round((d.bounds.x - minX) * r);
      const y = Math.round((d.bounds.y - minY) * r);
      const width = Math.max(1, Math.round((d.bounds.x + d.bounds.width - minX) * r) - x);
      const height = Math.max(1, Math.round((d.bounds.y + d.bounds.height - minY) * r) - y);
      return { id: d.id, x, y, width, height };
    });
    const frames = await withCaptureTimeout(
      backend.capture(placed.map(({ id, width, height }) => ({ id, width, height }))),
    );
    placed.forEach((p, i) => blit(canvas, checkFrame(frames[i], p.width, p.height), p.x, p.y));
    png = await encode(canvas);
  }

  const size = pngSize(png);
  if (png.length > SCREENSHOT_MAX_BYTES) throw new Error(sizeRefusal(png.length, multi, size));
  return {
    data: png,
    mimeType: "image/png",
    meta: {
      displayCount: displays.length,
      displays,
      display: multi ? "all" : (selector as number),
      ...(size ? { width: size.width, height: size.height } : {}),
      sourceWidth,
      sourceHeight,
      scaled,
      capturedAt: new Date().toISOString(),
    },
  };
}

/**
 * Same budget as a spawned capture (CAPTURE_TIMEOUT_MS), so a backend that never
 * answers fails with a sentence before the relay's generic 30s timeout does.
 */
function withCaptureTimeout<T>(work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () =>
        reject(
          new Error(
            `The screen capture did not finish within ${Math.round(CAPTURE_TIMEOUT_MS / 1000)}s. Try again; if it ` +
              "keeps happening, the machine's desktop session may be locked or unresponsive.",
          ),
        ),
      CAPTURE_TIMEOUT_MS,
    );
    timer.unref?.();
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

/** A backend frame that is missing or the wrong size is a backend bug — say so, never encode it. */
function checkFrame(frame: RawImage | undefined, width: number, height: number): RawImage {
  if (!frame) throw new Error("The screen capture returned no image for the requested display.");
  if (frame.width !== width || frame.height !== height) {
    throw new Error(
      `The screen capture returned a ${frame.width}x${frame.height} image where ${width}x${height} was requested.`,
    );
  }
  return frame;
}

/**
 * Read the captured file, enforcing the hard size cap before loading it.
 *
 * `multiDisplay` only changes the ADVICE in the refusal: a whole-desktop capture
 * that is still too big after downscaling has an obvious next move (ask for one
 * screen), and saying so is the difference between a dead end and a retry.
 */
async function readCapped(
  file: string,
  mimeType: string,
  multiDisplay: boolean,
): Promise<{ data: Buffer; mimeType: string }> {
  const stat = await fs.stat(file);
  if (stat.size > SCREENSHOT_MAX_BYTES) throw new Error(sizeRefusal(stat.size, multiDisplay, null));
  const data = await fs.readFile(file);
  return { data, mimeType };
}

/** The over-the-cap refusal, shared by the file-based and backend paths. */
function sizeRefusal(
  bytes: number,
  multiDisplay: boolean,
  size: { width: number; height: number } | null,
): string {
  const mb = (bytes / (1024 * 1024)).toFixed(1);
  // The pixel size makes a field report diagnosable from the message alone.
  const px = size ? ` (${size.width}x${size.height} pixels)` : "";
  return (
    `Screenshot is ${mb} MB${px}, which exceeds the ${SCREENSHOT_MAX_BYTES / (1024 * 1024)} MB limit.` +
    (multiDisplay
      ? " This was a capture of ALL displays at once, which is the expensive case. Retrying will not help — ask for a single screen instead by passing a display index (0 is the primary screen)."
      : "")
  );
}

/**
 * Pixel size straight out of the PNG's IHDR chunk (bytes 16..24 of a valid PNG).
 * Cheap, dependency-free, and — unlike anything computed from the request — it
 * describes the bytes the caller actually receives. Returns null if the buffer
 * is not a PNG we recognise, so metadata degrades instead of lying.
 */
export function pngSize(data: Buffer): { width: number; height: number } | null {
  if (data.length < 24) return null;
  if (data.readUInt32BE(0) !== 0x89504e47 || data.readUInt32BE(4) !== 0x0d0a1a0a) return null;
  const width = data.readUInt32BE(16);
  const height = data.readUInt32BE(20);
  if (!width || !height) return null;
  return { width, height };
}

async function safeUnlink(file: string): Promise<void> {
  try {
    await fs.unlink(file);
  } catch {
    // best-effort cleanup
  }
}

interface RunOptions {
  /** Kill the child and reject once this many ms have passed (see CAPTURE_TIMEOUT_MS). */
  timeoutMs: number;
  /** Buffer stdout for the caller; off by default so captures stream nothing. */
  captureStdout?: boolean;
}

/**
 * Spawn a command, capturing stderr (and optionally stdout), and resolve only on
 * a clean (exit 0) finish within `timeoutMs`.
 *
 * The timeout is the important part: a `screencapture` blocked behind a macOS
 * consent dialog never exits, and without a deadline here the only backstop was
 * the relay's generic 30s "Timed out waiting for the screenshot". A child that
 * an antivirus engine blocked (AMSI) is reported with a caller-ready sentence
 * rather than the engine's raw stderr.
 */
function runToCompletion(
  cmd: string,
  args: string[],
  options: RunOptions,
): Promise<{ stdout: string }> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, {
      stdio: ["ignore", options.captureStdout ? "pipe" : "ignore", "pipe"],
    });
    let stderr = "";
    let stdout = "";
    let timedOut = false;
    proc.stderr?.on("data", (c: Buffer) => {
      stderr += c.toString();
    });
    proc.stdout?.on("data", (c: Buffer) => {
      stdout += c.toString();
    });

    const timer = setTimeout(() => {
      timedOut = true;
      // SIGKILL, not SIGTERM: the case we are timing out on is a process parked
      // on a modal OS prompt, which is not reliably interruptible politely.
      try { proc.kill("SIGKILL"); } catch { /* already gone */ }
      reject(
        new Error(
          `${cmd} did not finish within ${Math.round(options.timeoutMs / 1000)}s and was stopped. ` +
            (process.platform === "darwin"
              ? "On macOS this usually means the screen capture is waiting on a system permission prompt that nobody is there to answer: grant Screen Recording to AI Commander on that machine, in System Settings ▸ Privacy & Security ▸ Screen Recording, then try again."
              : "Try again; if it keeps happening, the machine's desktop session may be locked or unresponsive."),
        ),
      );
    }, options.timeoutMs);
    timer.unref?.();

    const done = () => clearTimeout(timer);

    proc.on("error", (err) => {
      if (timedOut) return;
      done();
      reject(err);
    });
    proc.on("close", (code) => {
      if (timedOut) return;
      done();
      if (code === 0) resolve({ stdout });
      else if (isAntivirusScriptBlock(stderr)) {
        // An AMSI refusal is a finished verdict, not a crash: PowerShell's own
        // text ("…blocked by your antivirus software", plus a parser stack) tells
        // a caller neither that retrying is futile nor that exclusions are the
        // wrong remedy. Nothing in this module spawns PowerShell any more; this
        // stays so that no future capture helper can leak that text again.
        reject(new Error(SCREENSHOT_ANTIVIRUS_BLOCK_MESSAGE));
      } else {
        reject(new Error(`${cmd} exited with code ${code}${stderr ? `: ${stderr.trim()}` : ""}`));
      }
    });
  });
}
