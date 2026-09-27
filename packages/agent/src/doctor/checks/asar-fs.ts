import fs from "node:fs";
import { createRequire } from "node:module";

/**
 * An `fs` that sees the files the desktop app SHIPPED, not the ones Electron
 * pretends it has.
 *
 * ── WHY A DOCTOR CHECK CARES ─────────────────────────────────────────────────
 * The doctor runs headless from npm, and it ALSO runs inside the desktop app's
 * main process (desktop/src/diagnostics.ts calls `runDoctor()` in-process). In
 * the second case Electron has patched `fs` so an asar archive can be traversed
 * like a directory, and the archive FILE stops looking like a file. Measured on
 * a healthy 1.2.0 macOS install:
 *
 *   fs.lstatSync(".../Contents/Resources/app.asar")
 *     -> { isFile: false, isDirectory: true, size: 0 }
 *   // and, with the patch stood down:
 *     -> { isFile: true,  isDirectory: false, size: 10355446 }
 *
 * `Contents/Resources/app.asar` is a manifest entry with a recorded size and
 * hash, so the manifest check's regular-file gate rejected it and a completely
 * healthy Mac was told "all 276 shipped files are present, but 1 could not be
 * read (not-a-regular-file)" under the remedy that names the user's antivirus.
 * Under plain Node the same code hashed the archive happily, which is why the
 * whole suite passed over it.
 *
 * ── WHY `original-fs` AND NOT `process.noAsar` ───────────────────────────────
 * `process.noAsar = true` is a GLOBAL flag on a shared process. Setting and
 * restoring it around this pass — dozens of awaits long, and concurrent with
 * everything else the main process does — is a window in which any other read
 * of a packaged resource, or a lazy `import()` from inside app.asar, also loses
 * asar support, and in which a second run restores the flag out from under the
 * first. `original-fs` is Electron's own unpatched copy of `fs`: no global
 * state, no window, nothing to restore. Deliberate; please do not "simplify" it
 * back to the flag.
 *
 * ── AND IT MUST DEGRADE, NOT THROW, OUTSIDE ELECTRON ──────────────────────────
 * `original-fs` is an Electron builtin and does not exist under plain Node,
 * which is where this package normally runs (headless agent, npm, this suite).
 * So the choice is made by asking whether this is Electron at all
 * (`process.versions.electron`), never by attempting the load and catching the
 * failure — a `try/catch` there would swallow a real load error too and put the
 * bug silently back.
 *
 * MIRROR of packages/desktop/src/asar-fs.ts. The two are separate because the
 * agent ships to npm on its own and `@aicommander/desktop` is not (and must not
 * become) a dependency of it — the same reason MANIFEST_FILENAME and
 * `isManifestEntryPath` are mirrored (see install.ts and manifest-entry.ts).
 */

/** Only what the install check asks of a stat. */
export interface AsarBlindStats {
  size: number;
  isFile(): boolean;
}

/** An open descriptor, narrowed to what `sha256File` does with one. */
export interface AsarBlindFileHandle {
  stat(): Promise<AsarBlindStats>;
  createReadStream(options: { autoClose: boolean }): AsyncIterable<unknown>;
  close(): Promise<void>;
}

/**
 * The slice of `fs.promises` the install check uses. Narrow on purpose: it is
 * what makes a test double a couple of lines rather than a filesystem.
 */
export interface AsarBlindFs {
  lstat(path: string): Promise<AsarBlindStats>;
  realpath(path: string): Promise<string>;
  readFile(path: string, encoding: "utf8"): Promise<string>;
  open(path: string, flags: number): Promise<AsarBlindFileHandle>;
}

/**
 * Everything the choice depends on, so a test can BE Electron.
 *
 * The bug was invisible to the suite precisely because plain Node's `fs` is
 * honest about app.asar: a test that only ever runs the real thing reproduces
 * nothing. Injecting this env lets a test present a patched `fs` (asar as a
 * zero-byte directory) as `plain` and the true one as what `load` returns, so a
 * check that reaches for the wrong one fails the test.
 */
export interface AsarFsEnv {
  /** `process.versions.electron` — absent under plain Node. */
  electron?: string | undefined;
  /** `require`, as Electron's loader provides it. */
  load(id: string): unknown;
  /** The answer when this is not Electron. */
  plain: AsarBlindFs;
}

/** `fs.promises` satisfies the narrow interface — pinned at compile time. */
const plainFs: AsarBlindFs = fs.promises;

const loadModule = createRequire(import.meta.url);

export function selectAsarBlindFs(env: AsarFsEnv): AsarBlindFs {
  if (!env.electron) return env.plain;
  const original = env.load("original-fs") as { promises: AsarBlindFs };
  return original.promises;
}

let cached: AsarBlindFs | null = null;

/**
 * The real one, resolved once on first use — lazily, so a load failure surfaces
 * inside a check (which the runner reports as one failed check) rather than at
 * import time, where it would take the whole doctor with it.
 */
export function asarBlindFs(): AsarBlindFs {
  if (!cached) {
    cached = selectAsarBlindFs({
      electron: process.versions.electron,
      load: loadModule,
      plain: plainFs,
    });
  }
  return cached;
}
