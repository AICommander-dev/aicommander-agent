import { spawn } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import {
  SCREENSHOT_MAX_BYTES,
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
   * display the returned pixels belong to (see confirmMacDisplay). An absent
   * `display` means "unknown", never "display 0".
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
   * Windows ignores this — its capture script enumerates authoritatively itself.
   */
  displays?: ScreenshotDisplayInfo[];
}

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

/** Display enumeration is advisory; never let it eat the capture's budget. */
const ENUMERATE_TIMEOUT_MS = 6_000;

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
 * displays are never scaled: that path's fidelity is what it has always been.
 */
const MULTI_DISPLAY_MAX_DIMENSION = 3840;

/** True on platforms where we know how to grab the screen (desktop mac/win). */
export function canCaptureScreenshot(): boolean {
  return process.platform === "darwin" || process.platform === "win32";
}

/**
 * Capture a display as a PNG using the OS's built-in tooling — no native
 * dependencies. macOS uses `screencapture`; Windows shells out to PowerShell +
 * System.Drawing. Throws on any other platform (headless Linux), on capture
 * failure, on an out-of-range display index, or if the result exceeds
 * SCREENSHOT_MAX_BYTES.
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
  if (process.platform === "darwin") return captureMac(options);
  if (process.platform === "win32") return captureWindows(options);
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
 * Enumerate the machine's displays, primary first WHEN the OS said which one is
 * primary (see normalizeDisplays — we never elect one ourselves).
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
    else if (process.platform === "win32") displays = await listDisplaysWindows();
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
 * uniquely (see confirmMacDisplay). Everything else is reported as "unknown"
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
    { timeoutMs: ENUMERATE_TIMEOUT_MS, captureStdout: true },
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

/** Windows enumerates through the same System.Windows.Forms API the capture uses. */
async function listDisplaysWindows(): Promise<ScreenshotDisplayInfo[]> {
  const { stdout } = await runToCompletion("powershell", psArgs(ENUMERATE_SCRIPT), {
    timeoutMs: ENUMERATE_TIMEOUT_MS,
    captureStdout: true,
  });
  const rows = asArray(JSON.parse(stdout)) as ScreenshotDisplayInfo[];
  return normalizeDisplays(rows);
}

/**
 * The ONE funnel every display list passes through — the macOS probe, the
 * Windows probe, and the list the desktop app hands down. A list that skipped
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
function normalizeDisplays(displays: ScreenshotDisplayInfo[]): ScreenshotDisplayInfo[] {
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

/** PowerShell's ConvertTo-Json emits a bare object (not an array) for one item. */
function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value == null ? [] : [value];
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
  const file = tmpFile("png");
  try {
    // -x: silent (no shutter sound). -t png: PNG output.
    // With no explicit display we run the ORIGINAL argv (no -D) so the default
    // capture is bit-identical to what every previous version produced.
    const args =
      options.display === undefined
        ? ["-x", "-t", "png", file]
        : // screencapture numbers displays from 1. Beyond `-D 1` (the main
          // display, per the man page) the mapping from OUR index to that
          // numbering is an assumption — confirmMacDisplay decides whether the
          // reply is allowed to state which display came back.
          ["-x", "-t", "png", "-D", String(index + 1), file];
    await runToCompletion("screencapture", args, { timeoutMs: CAPTURE_TIMEOUT_MS });
    const shot = await readCapped(file, "image/png", false);
    const size = pngSize(shot.data);
    const captured = confirmMacDisplay(options.display, index, displays, size);
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
 * establish it. This is the whole honesty budget of the macOS path.
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
 * Windows does the whole job — enumerate, select, capture, scale — in ONE
 * PowerShell invocation. Splitting it would let the display list drift from the
 * bounds actually captured between two forks; here the script reports exactly
 * the topology it used.
 *
 * That is also why Windows, unlike macOS, may state the index outright: the
 * script does not ask an OS tool to interpret an index for it, it captures
 * `$ordered[$sel].Bounds` and reports the very same `$ordered` as the display
 * list. Index ↔ pixels is established by construction, not assumed.
 */
async function captureWindows(options: ScreenshotOptions): Promise<CapturedScreenshot> {
  const file = tmpFile("png");
  const selector = options.display === undefined ? 0 : options.display;
  // Same funnel as everywhere else — the caller's list only decides the RANGE
  // here (the script re-enumerates authoritatively), but a list that skipped
  // normalisation would range-check under different rules than it is described.
  if (selector !== "all") validateIndex(selector, normalizeDisplays(options.displays ?? []));
  try {
    const { stdout } = await runToCompletion(
      "powershell",
      psArgs(captureScript(file, selector)),
      { timeoutMs: CAPTURE_TIMEOUT_MS, captureStdout: true },
    );
    const report = JSON.parse(stdout) as {
      count?: number;
      display?: number | "all";
      sourceWidth?: number;
      sourceHeight?: number;
      scaled?: boolean;
      displays?: ScreenshotDisplayInfo[];
    };
    const multi = selector === "all";
    const shot = await readCapped(file, "image/png", multi);
    // Prefer the PNG's own header over the script's arithmetic: it is the size of
    // the bytes the caller will actually receive.
    const size = pngSize(shot.data);
    const displays = normalizeDisplays(asArray(report.displays) as ScreenshotDisplayInfo[]);
    return {
      ...shot,
      meta: {
        ...(displays.length ? { displayCount: displays.length, displays } : {}),
        display: report.display ?? (selector as ScreenshotDisplaySelector),
        ...(size ? { width: size.width, height: size.height } : {}),
        ...(report.sourceWidth && report.sourceHeight
          ? { sourceWidth: report.sourceWidth, sourceHeight: report.sourceHeight }
          : size
            ? { sourceWidth: size.width, sourceHeight: size.height }
            : {}),
        scaled: report.scaled === true,
        capturedAt: new Date().toISOString(),
      },
    };
  } finally {
    await safeUnlink(file);
  }
}

function psArgs(script: string): string[] {
  return ["-NoProfile", "-NonInteractive", "-Command", script];
}

/** Escape a path for a PowerShell single-quoted string literal. */
function psPath(file: string): string {
  return file.replace(/'/g, "''");
}

/**
 * The display list, primary marked. `AllScreens` order is whatever Windows says;
 * normalizeDisplays renumbers it on the Node side, putting the display this
 * script flagged primary at index 0. `PrimaryScreen` always exists on Windows,
 * so this path always identifies one.
 */
const ENUMERATE_SCRIPT = [
  "$ErrorActionPreference='Stop';",
  "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;",
  "$p = [System.Windows.Forms.Screen]::PrimaryScreen;",
  "$out = @();",
  "$i = 0;",
  "foreach ($s in [System.Windows.Forms.Screen]::AllScreens) {",
  "  $out += [pscustomobject]@{ index = $i; width = $s.Bounds.Width; height = $s.Bounds.Height; primary = ($s.DeviceName -eq $p.DeviceName) };",
  "  $i = $i + 1;",
  "}",
  "$out | ConvertTo-Json -Compress",
].join(" ");

/**
 * Capture script. `$sel` is either a 0-based index into the primary-first
 * ordering or the string 'all' (the virtual screen, i.e. every monitor in its
 * real desktop layout — including the gaps between mismatched panels).
 *
 * Note the bounds are the same logical pixels the previous implementation used;
 * on a per-monitor-DPI-aware process they would differ, but this process is not
 * one, so nothing here changes existing behaviour.
 */
function captureScript(file: string, selector: ScreenshotDisplaySelector): string {
  const sel = selector === "all" ? "'all'" : String(Math.trunc(selector));
  return [
    "$ErrorActionPreference='Stop';",
    "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;",
    `$sel = ${sel};`,
    "$p = [System.Windows.Forms.Screen]::PrimaryScreen;",
    "$ordered = @($p) + @([System.Windows.Forms.Screen]::AllScreens | Where-Object { $_.DeviceName -ne $p.DeviceName });",
    "$list = @();",
    "for ($n = 0; $n -lt $ordered.Count; $n++) {",
    "  $list += [pscustomobject]@{ index = $n; width = $ordered[$n].Bounds.Width; height = $ordered[$n].Bounds.Height; primary = ($n -eq 0) };",
    "}",
    "if ($sel -is [string]) { $b = [System.Windows.Forms.SystemInformation]::VirtualScreen; $all = $true }",
    "else {",
    "  $all = $false;",
    "  if ($sel -lt 0 -or $sel -ge $ordered.Count) {",
    // Controlled refusal: the AIC: prefix tells the Node side this stderr line is
    // a finished, caller-ready sentence and not a PowerShell stack trace.
    "    [Console]::Error.WriteLine('AIC: This machine has ' + $ordered.Count + ' display(s), so display ' + $sel + ' does not exist. Retrying will not help — ask for a display between 0 and ' + ($ordered.Count - 1) + ' instead (0 is the primary screen).');",
    "    exit 3;",
    "  }",
    "  $b = $ordered[$sel].Bounds;",
    "}",
    "$sw = $b.Width; $sh = $b.Height;",
    "$bmp = New-Object System.Drawing.Bitmap($sw, $sh);",
    "$g = [System.Drawing.Graphics]::FromImage($bmp);",
    "$g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size);",
    "$g.Dispose();",
    "$scaled = $false;",
    `$max = ${MULTI_DISPLAY_MAX_DIMENSION};`,
    "if ($all -and ([Math]::Max($sw, $sh) -gt $max)) {",
    "  $r = $max / [Math]::Max($sw, $sh);",
    "  $ow = [int][Math]::Max(1, [Math]::Round($sw * $r));",
    "  $oh = [int][Math]::Max(1, [Math]::Round($sh * $r));",
    "  $dst = New-Object System.Drawing.Bitmap($ow, $oh);",
    "  $dg = [System.Drawing.Graphics]::FromImage($dst);",
    "  $dg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic;",
    "  $dg.DrawImage($bmp, 0, 0, $ow, $oh);",
    "  $dg.Dispose(); $bmp.Dispose(); $bmp = $dst; $scaled = $true;",
    "}",
    `$bmp.Save('${psPath(file)}', [System.Drawing.Imaging.ImageFormat]::Png);`,
    "$bmp.Dispose();",
    "$report = [pscustomobject]@{ count = $ordered.Count; display = $(if ($all) { 'all' } else { $sel }); sourceWidth = $sw; sourceHeight = $sh; scaled = $scaled; displays = $list };",
    "$report | ConvertTo-Json -Compress -Depth 4",
  ].join(" ");
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
  if (stat.size > SCREENSHOT_MAX_BYTES) {
    const mb = (stat.size / (1024 * 1024)).toFixed(1);
    throw new Error(
      `Screenshot is ${mb} MB, which exceeds the ${SCREENSHOT_MAX_BYTES / (1024 * 1024)} MB limit.` +
        (multiDisplay
          ? " This was a capture of ALL displays at once, which is the expensive case. Retrying will not help — ask for a single screen instead by passing a display index (0 is the primary screen)."
          : ""),
    );
  }
  const data = await fs.readFile(file);
  return { data, mimeType };
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
 * the relay's generic 30s "Timed out waiting for the screenshot". Exit code 3 is
 * our own scripts' controlled-refusal code — its stderr is already a finished
 * sentence, so it is passed through verbatim instead of being wrapped.
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
      else if (code === 3 && stderr.trim().startsWith("AIC:")) {
        reject(new Error(stderr.trim().slice("AIC:".length).trim()));
      } else {
        reject(new Error(`${cmd} exited with code ${code}${stderr ? `: ${stderr.trim()}` : ""}`));
      }
    });
  });
}
