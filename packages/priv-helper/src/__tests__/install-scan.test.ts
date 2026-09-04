// The unelevated half of the incident question — see src/install-scan.ts.
//
// Unlike the watchdog's probe, this one is ordinary file-system code, so it can
// be exercised for real on macOS: a temporary directory laid out the way an
// install is, with the platform forced to win32. What CANNOT be reproduced here
// is a Windows ACL denial, so the "denial is not absence" property is asserted
// through an injected lstat failure with the errno Windows produces (EPERM), the
// same seam integrity.test.ts uses on the desktop side.

import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import fsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  candidateInstallRoots,
  entryRealTarget,
  isManifestEntryPath,
  scanInstall,
  APP_INSTALL_DIR_NAMES,
} from "../install-scan.js";

/** One row of the shared filesystem table — see manifest-real-target-cases.mjs. */
interface RealTargetCase {
  name: string;
  entry: string;
  kind: string;
  symlink?: boolean;
  code?: string;
  resolvesToEntryItself?: boolean;
  build: (root: string, outside: string) => void;
}
import {
  MANIFEST_FILENAME,
  MANIFEST_REL_POSIX,
  MANIFEST_SCHEMA,
  MAX_MANIFEST_FILES,
} from "../win-watchdog-install.js";

let container = "";

/** `<container>/AI Commander Privileged Helper/aicommander-priv-helper.exe`. */
const execPathIn = (root: string) =>
  path.join(root, "AI Commander Privileged Helper", "aicommander-priv-helper.exe");

interface Entry {
  path: string;
  critical?: boolean;
}

function install(dirName: string, entries: Entry[], overrides: Record<string, unknown> = {}): string {
  const root = path.join(container, dirName);
  for (const entry of entries) {
    const absolute = path.join(root, ...entry.path.split("/"));
    mkdirSync(path.dirname(absolute), { recursive: true });
    writeFileSync(absolute, entry.path);
  }
  const manifest = path.join(root, ...MANIFEST_REL_POSIX.split("/"));
  mkdirSync(path.dirname(manifest), { recursive: true });
  writeFileSync(
    manifest,
    JSON.stringify({
      schema: MANIFEST_SCHEMA,
      manifestPath: MANIFEST_REL_POSIX,
      version: "1.1.0",
      files: entries,
      ...overrides,
    }),
  );
  return root;
}

/**
 * A manifest written into an existing root WITHOUT creating the files it lists —
 * the only way to describe an entry we would refuse, since `install()` would try
 * to create it on this machine.
 */
function manifestOnly(root: string, entries: Entry[], overrides: Record<string, unknown> = {}): void {
  const manifest = path.join(root, ...MANIFEST_REL_POSIX.split("/"));
  mkdirSync(path.dirname(manifest), { recursive: true });
  writeFileSync(
    manifest,
    JSON.stringify({
      schema: MANIFEST_SCHEMA,
      manifestPath: MANIFEST_REL_POSIX,
      version: "1.1.0",
      files: entries,
      ...overrides,
    }),
  );
}

const FILES: Entry[] = [
  { path: "AICommander.exe", critical: true },
  { path: "icudtl.dat", critical: true },
  { path: "resources/app.asar", critical: true },
  { path: "locales/am.pak" },
  { path: "locales/en-US.pak" },
];

const scan = () => scanInstall({ execPath: execPathIn(container), platform: "win32" });

beforeEach(() => {
  container = mkdtempSync(path.join(tmpdir(), "aic-install-scan-"));
});

afterEach(() => {
  vi.restoreAllMocks();
  rmSync(container, { recursive: true, force: true });
});

describe("where it looks", () => {
  it("derives the candidates from this binary's own directory, not from the environment", () => {
    // The helper is installed as a SIBLING of the app; the container is simply
    // its grandparent. No %ProgramFiles% read — this binary may run as SYSTEM,
    // whose environment block is stripped.
    const pf = path.join(path.sep, "pf");
    expect(candidateInstallRoots(execPathIn(pf))).toEqual(APP_INSTALL_DIR_NAMES.map((n) => path.join(pf, n)));
  });

  it("finds the current spelling of the install directory", async () => {
    const root = install("AICommander", FILES);
    const result = await scan();
    expect(result.ok && result.scan.root).toBe(root);
  });

  it("still finds an install from before the executable was renamed", async () => {
    const root = install("AI Commander", FILES);
    const result = await scan();
    expect(result.ok && result.scan.root).toBe(root);
  });

  it("says so plainly when there is nothing to count, rather than reporting damage", async () => {
    expect(await scan()).toMatchObject({ ok: false, reason: "no-manifest-found" });
  });

  it("is Windows-only", async () => {
    install("AICommander", FILES);
    expect(await scanInstall({ execPath: execPathIn(container), platform: "darwin" })).toEqual({
      ok: false,
      reason: "not-windows",
    });
  });
});

describe("what it counts", () => {
  it("reports an intact install as intact", async () => {
    install("AICommander", FILES);
    const result = await scan();
    expect(result.ok && result.scan).toMatchObject({
      totalFiles: 5,
      missingFiles: 0,
      missingCritical: 0,
      unreadableFiles: 0,
      version: "1.1.0",
    });
  });

  it("counts the 2026-09-02 shape: everything gone but the locked exe", async () => {
    const root = install("AICommander", FILES);
    for (const relative of ["icudtl.dat", "resources/app.asar", "locales/am.pak", "locales/en-US.pak"]) {
      rmSync(path.join(root, ...relative.split("/")), { force: true });
    }
    const result = await scan();
    expect(result.ok && result.scan).toMatchObject({
      totalFiles: 5,
      missingFiles: 4,
      missingCritical: 2,
      unreadableFiles: 0,
    });
  });

  it("NEVER counts a file it could not read as a file that is missing", async () => {
    // The whole point. A filter driver denying reads of %ProgramFiles% must not
    // be able to produce "your installation has been gutted" on a machine where
    // every file is exactly where it was put.
    install("AICommander", FILES);
    vi.spyOn(fsPromises, "lstat").mockRejectedValue(
      Object.assign(new Error("access denied"), { code: "EPERM" }),
    );
    const result = await scan();
    expect(result.ok && result.scan).toMatchObject({
      totalFiles: 5,
      missingFiles: 0,
      missingCritical: 0,
      unreadableFiles: 5,
    });
  });

  it("ignores a manifest whose recorded location disagrees with where it was found", async () => {
    install("AICommander", FILES, { manifestPath: "somewhere/else.json" });
    expect(await scan()).toMatchObject({ ok: false, reason: "no-manifest-found" });
  });

  it("never reports an EMPTY manifest as a complete install", async () => {
    // `ok: true` with zero files rendered as "the installation is complete — all
    // 0 shipped files are present": a corrupted or truncated inventory read as a
    // healthy machine, on the surface built to answer "are 80 of my 81 files
    // gone?". Nothing counted is a failure to count.
    install("AICommander", []);
    const result = await scan();
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("manifest-unusable");
  });

  it("says the same when every entry in the manifest is one we refuse to follow", async () => {
    install("AICommander", [{ path: "..\\..\\Windows\\System32\\cmd.exe" }, { path: "C:/Windows/notepad.exe" }]);
    const result = await scan();
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("manifest-unusable");
  });

  it("checks every entry for the rule, including the ones past the lstat cap", async () => {
    // The cap bounds the FILESYSTEM work, not the reading of the file. An entry
    // we will not follow, sitting at position 5000, is exactly as good a sign
    // that this is not the manifest we wrote as one at position 2 — and hiding
    // behind the cap is how it would have gone unnoticed.
    const root = path.join(container, "AICommander");
    mkdirSync(root, { recursive: true });
    const entries: Entry[] = Array.from({ length: MAX_MANIFEST_FILES + 2 }, (_, i) => ({
      path: `resources/pack-${i}.pak`,
    }));
    manifestOnly(root, [...entries, { path: "../../outside.dat" }]);
    const result = await scan();
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("manifest-unusable");
  });

  it("stops STATTING at the cap, and counts only what it examined", async () => {
    const root = path.join(container, "AICommander");
    mkdirSync(root, { recursive: true });
    manifestOnly(
      root,
      Array.from({ length: MAX_MANIFEST_FILES + 2 }, (_, i) => ({ path: `resources/pack-${i}.pak` })),
    );
    const result = await scan();
    expect(result.ok && result.scan.totalFiles).toBe(MAX_MANIFEST_FILES);
  });

  it("names the roots it looked in, so a custom /D install is not a bare 'not found'", async () => {
    const result = await scan();
    expect(!result.ok && result.triedRoots).toEqual(APP_INSTALL_DIR_NAMES.map((n) => path.join(container, n)));
  });

  it("ignores a schema it does not recognise, rather than guessing", async () => {
    install("AICommander", FILES, { schema: MANIFEST_SCHEMA + 1 });
    expect(await scan()).toMatchObject({ ok: false, reason: "no-manifest-found" });
  });

  it("refuses to even stat a relative path that could leave the root — and says the manifest is unusable", async () => {
    // THE REGRESSION THIS PINS, and it is the worst one this module had. A
    // rejected entry used to be SKIPPED: eighty malformed entries and one good
    // one reported `totalFiles=1, missingFiles=0`, i.e. a clean bill of health
    // derived from a file every other reader refuses outright — on the
    // UNELEVATED Start Menu path, the surface a user reaches precisely because
    // their app will not start. Restore the `continue` and this test fails.
    const root = path.join(container, "AICommander");
    mkdirSync(root, { recursive: true });
    writeFileSync(path.join(root, "AICommander.exe"), "x");
    manifestOnly(root, [
      { path: "AICommander.exe", critical: true },
      { path: "../../Windows/System32/config/SAM", critical: true },
      { path: "C:/Windows/notepad.exe", critical: true },
      { path: "resources/app.asar\u0000.txt", critical: true },
    ]);
    const result = await scan();
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("manifest-unusable");
  });

  it("does not let ONE malformed entry among many turn a gutted install into health", async () => {
    // The same failure in its quietest dress: a manifest that is almost all
    // good. Counting the survivors and dropping the rest is a number that reads
    // as a measurement and is not one.
    const root = path.join(container, "AICommander");
    mkdirSync(root, { recursive: true });
    writeFileSync(path.join(root, "AICommander.exe"), "x");
    manifestOnly(root, [...FILES, { path: "locales/../../evil.pak" }]);
    const result = await scan();
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("manifest-unusable");
  });
});

describe("when the sweep took the manifest as well — the copy beside this binary", () => {
  /**
   * THE REGRESSION THIS PINS. The manifest is a file inside the directory it
   * inventories, so the 2026-09-02 sweep took it with the other 79. Reading only
   * the in-tree copy, this scan then answered `no-manifest-found` — "we could not
   * locate the install" — about a directory that was sitting right there with 80
   * of its files gone. Revert the fallback and this suite says so.
   */

  /** Write the sibling copy the installer places beside the helper. */
  function siblingManifest(entries: Entry[], overrides: Record<string, unknown> = {}): void {
    const dir = path.dirname(execPathIn(container));
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      path.join(dir, MANIFEST_FILENAME),
      JSON.stringify({
        schema: MANIFEST_SCHEMA,
        manifestPath: MANIFEST_REL_POSIX,
        version: "1.1.0",
        files: entries,
        ...overrides,
      }),
    );
  }

  /** An install directory with the files present but NO manifest of its own. */
  function gutted(dirName: string, keep: Entry[]): string {
    const root = path.join(container, dirName);
    mkdirSync(root, { recursive: true });
    for (const entry of keep) {
      const absolute = path.join(root, ...entry.path.split("/"));
      mkdirSync(path.dirname(absolute), { recursive: true });
      writeFileSync(absolute, entry.path);
    }
    return root;
  }

  it("still counts the gutted install after the in-tree manifest is gone", async () => {
    // What the incident actually left behind: the exe (Windows locks a running
    // image) and nothing else — the manifest included.
    const root = gutted("AICommander", [FILES[0]!]);
    siblingManifest(FILES);

    const result = await scan();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.scan.root).toBe(root);
    expect(result.scan.totalFiles).toBe(FILES.length);
    expect(result.scan.missingFiles).toBe(FILES.length - 1);
    expect(result.scan.missingCritical).toBe(2);
    // ...and it SAYS which copy it counted, because a count from an inventory
    // that may be a build behind is worth what the reader knows about it.
    expect(result.scan.source).toBe("helper");
  });

  it("prefers the in-tree copy wherever there is one — a partial update is not damage", async () => {
    // Both copies exist and DISAGREE: the sibling one is a build behind and
    // still lists a file this build no longer ships. The in-tree copy is the
    // inventory OF this directory, so it wins and nothing is reported missing.
    install("AICommander", FILES);
    siblingManifest([...FILES, { path: "gone-in-this-build.dll", critical: true }]);

    const result = await scan();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.scan.source).toBe("install");
    expect(result.scan.totalFiles).toBe(FILES.length);
    expect(result.scan.missingCritical).toBe(0);
  });

  it("never counts the sibling copy against a root that does not exist", async () => {
    // The false-alarm this rule closes: an app installed with NSIS `/D=` is not
    // derivable from this binary's path, so every candidate root is absent. Left
    // unguarded, the fallback would lstat all 81 entries under a directory that
    // is not there, get ENOENT for every one, and report a healthy machine as
    // gutted. No place to look is not evidence — it is the absence of evidence.
    siblingManifest(FILES);

    const result = await scan();
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("no-manifest-found");
  });
});

// ── the shared rule ──────────────────────────────────────────────────────────

describe("the entry-path rule this module mirrors", () => {
  /**
   * This module carries its own copy of the rule because the helper is a
   * standalone SEA binary and may not depend on `@aicommander/desktop`. A copy
   * that drifts is not a loud failure — until 2026-09-03 this one rejected `%`
   * (nothing else did) and accepted control characters and `<>"|?*` (everything
   * else refused). So the copy and the DECLARATION are run over the one shared
   * table, the same table the agent's and the installer's mirrors are run over.
   * See desktop/src/__tests__/manifest-entry-cases.mjs.
   */
  it("agrees with the declared rule, case for case", async () => {
    const { isManifestEntryPath: declared } = (await import(
      new URL("../../../desktop/src/install-manifest-contract.mjs", import.meta.url).href
    )) as { isManifestEntryPath: (value: unknown) => boolean };
    const { MANIFEST_ENTRY_CASES, MANIFEST_ENTRY_NON_STRINGS } = (await import(
      new URL("../../../desktop/src/__tests__/manifest-entry-cases.mjs", import.meta.url).href
    )) as { MANIFEST_ENTRY_CASES: Array<[string, boolean]>; MANIFEST_ENTRY_NON_STRINGS: unknown[] };
    expect(MANIFEST_ENTRY_CASES.length).toBeGreaterThan(20);
    for (const [value, expected] of MANIFEST_ENTRY_CASES) {
      expect(isManifestEntryPath(value), `install-scan: ${JSON.stringify(value)}`).toBe(expected);
      expect(declared(value), `contract: ${JSON.stringify(value)}`).toBe(expected);
    }
    for (const value of MANIFEST_ENTRY_NON_STRINGS) {
      expect(isManifestEntryPath(value)).toBe(false);
      expect(declared(value)).toBe(false);
    }
  });

  it("counts an entry the rule allows, `%` and all", async () => {
    const root = path.join(container, "AICommander");
    mkdirSync(path.join(root, "resources"), { recursive: true });
    writeFileSync(path.join(root, "resources", "100%.pak"), "x");
    manifestOnly(root, [{ path: "resources/100%.pak" }]);
    const result = await scan();
    expect(result.ok && result.scan).toMatchObject({ totalFiles: 1, missingFiles: 0 });
  });
});

// ── and where an entry LEADS, not only how it is spelled ─────────────────────

describe("an entry that leads out of the root through a link", () => {
  it("never lstats a path that resolves outside the directory being counted", async () => {
    // `lstat` declines to follow only the LAST component of a path and follows
    // every one before it, so a link `link` inside the install tree and the
    // entry `link/gone.dat` spelled itself inside the root, passed containment,
    // and had this scan counting the absence of a file in somebody else's
    // directory — on the one check this binary exists for.
    //
    // What is asserted is the SYSCALL, not the verdict: every path handed to
    // `lstat` is recorded and none of them may lead outside the root.
    if (process.platform === "win32") return; // creating a symlink needs a privilege
    const outside = mkdtempSync(path.join(tmpdir(), "aic-install-scan-outside-"));
    try {
      const root = install("AICommander", FILES);
      symlinkSync(outside, path.join(root, "link"), "dir");
      manifestOnly(root, [...FILES, { path: "link/gone.dat", critical: true }]);

      const touched: string[] = [];
      const realLstat = fsPromises.lstat.bind(fsPromises);
      vi.spyOn(fsPromises, "lstat").mockImplementation(async (target) => {
        touched.push(String(target));
        return realLstat(target as string);
      });

      const result = await scan();

      // Compared on where each path LEADS, not on how it is spelled — a path
      // under the root that resolves elsewhere is the whole bug.
      const insideRoot = realpathSync(root);
      const escaped = touched.filter((target) => {
        let dir: string;
        try {
          dir = realpathSync(path.dirname(target));
        } catch {
          return false; // gone by the time we look; it led nowhere
        }
        return dir !== insideRoot && !dir.startsWith(insideRoot + path.sep);
      });
      expect(escaped).toEqual([]);
      expect(touched).not.toContain(path.join(outside, "gone.dat"));
      // A link out of the root is the manifest naming a file outside it by
      // another route: the same verdict a `..` entry gets, and never a count of
      // missing files.
      expect(result.ok).toBe(false);
      expect(!result.ok && result.reason).toBe("manifest-unusable");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("counts a link the manifest lists, rather than following it", async () => {
    // The property the fix must KEEP: only the entry's parent is resolved, so a
    // symlink as the entry's last component is still lstat'd as a link — present
    // where it is present, missing when it is gone.
    if (process.platform === "win32") return;
    const root = install("AICommander", FILES);
    symlinkSync(path.join(root, "AICommander.exe"), path.join(root, "alias.exe"), "file");
    manifestOnly(root, [...FILES, { path: "alias.exe" }]);

    const result = await scan();

    expect(result.ok && result.scan).toMatchObject({ totalFiles: 6, missingFiles: 0 });
  });

  it("agrees with the desktop reader over the shared table of cases", async () => {
    // This module carries its own copy of the resolver because the helper is a
    // standalone SEA binary and may not depend on `@aicommander/desktop`. A copy
    // that drifts is not a loud failure, so the two are run over ONE table — see
    // desktop/src/__tests__/manifest-real-target-cases.mjs.
    const { MANIFEST_REAL_TARGET_CASES } = (await import(
      new URL("../../../desktop/src/__tests__/manifest-real-target-cases.mjs", import.meta.url).href
    )) as { MANIFEST_REAL_TARGET_CASES: RealTargetCase[] };
    expect(MANIFEST_REAL_TARGET_CASES.length).toBeGreaterThan(5);
    for (const scenario of MANIFEST_REAL_TARGET_CASES) {
      if (scenario.symlink && process.platform === "win32") continue;
      const caseRoot = mkdtempSync(path.join(tmpdir(), "aic-real-target-"));
      const outside = mkdtempSync(path.join(tmpdir(), "aic-real-outside-"));
      try {
        scenario.build(caseRoot, outside);
        const realRoot = realpathSync(caseRoot);
        const spelled = path.resolve(realRoot, ...scenario.entry.split("/"));
        const resolved = await entryRealTarget(realRoot, spelled, new Map());
        expect(resolved.kind, scenario.name).toBe(scenario.kind);
        if (resolved.kind === "inside") {
          expect(resolved.absolute.startsWith(realRoot + path.sep), scenario.name).toBe(true);
          if (scenario.resolvesToEntryItself) expect(resolved.absolute).toBe(spelled);
        }
        if (resolved.kind === "unresolvable" && scenario.code) {
          expect(resolved.code, scenario.name).toBe(scenario.code);
        }
      } finally {
        rmSync(caseRoot, { recursive: true, force: true });
        rmSync(outside, { recursive: true, force: true });
      }
    }
  });
});
