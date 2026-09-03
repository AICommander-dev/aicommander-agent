// The install checks: the shipped manifest, and the write probe whose verbatim
// error is the evidence.
//
// Everything here runs against a real temp tree rather than a mocked fs — the
// thing under test IS filesystem behaviour, and a mocked lstat would assert only
// that the mock was called.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { checkManifest, installChecks, MANIFEST_FILENAME, MANIFEST_SCHEMA } from "../doctor/checks/install.js";
import type { AsarBlindFs, AsarFsEnv } from "../doctor/checks/asar-fs.js";
import type { CheckResult, DoctorContext } from "../doctor/types.js";

let root: string;
let resources: string;

function ctx(overrides: Partial<DoctorContext> = {}): DoctorContext {
  return {
    serverUrl: "https://relay.invalid",
    offline: true,
    networkTimeoutMs: 100,
    probeDelayMs: 0,
    ...overrides,
  };
}

function byId(results: CheckResult[], id: string): CheckResult {
  const found = results.find((r) => r.id === id);
  if (!found) throw new Error(`no check ${id} in ${results.map((r) => r.id).join(", ")}`);
  return found;
}

/** A packaged install: `<root>/resources/install-manifest.json` plus the files it lists. */
function writeInstall(files: Array<{ rel: string; body: string; critical?: boolean; hashed?: boolean }>): void {
  const entries = files.map((file) => {
    const absolute = path.join(root, ...file.rel.split("/"));
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, file.body);
    return {
      path: file.rel,
      size: Buffer.byteLength(file.body),
      ...(file.hashed === false ? {} : { sha256: createHash("sha256").update(file.body).digest("hex") }),
      ...(file.critical ? { critical: true } : {}),
    };
  });
  fs.mkdirSync(resources, { recursive: true });
  fs.writeFileSync(
    path.join(resources, MANIFEST_FILENAME),
    JSON.stringify({
      schema: MANIFEST_SCHEMA,
      product: "AI Commander",
      version: "1.1.0",
      platform: "win32",
      generatedAt: new Date().toISOString(),
      hashAlgorithm: "sha256",
      // The manifest's own relative path is what the root is recovered from.
      manifestPath: `resources/${MANIFEST_FILENAME}`,
      totalFiles: entries.length,
      hashedFiles: entries.length,
      files: entries,
    }),
  );
}

/**
 * Replace the manifest's file list, leaving everything else (including the
 * `manifestPath` the root is derived from) exactly as a real one has it. This is
 * how a CORRUPTED-BUT-PARSEABLE manifest is written: the shape is right and only
 * the entries are not ones we would ever ship.
 */
function writeEntries(files: unknown[]): void {
  const file = path.join(resources, MANIFEST_FILENAME);
  const manifest = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
  manifest["files"] = files;
  fs.writeFileSync(file, JSON.stringify(manifest));
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-install-"));
  resources = path.join(root, "resources");
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe("install manifest check", () => {
  it("skips — not fails — when there is no manifest, which is the npm agent's normal state", async () => {
    const results = await installChecks.run(ctx());
    expect(byId(results, "install.manifest").verdict).toBe("skipped");
    expect(byId(results, "install.manifest").detail).toMatch(/headless agent/);
    // And with nothing to derive a root from, the write probe declines to guess.
    expect(byId(results, "install.writable").verdict).toBe("skipped");
  });

  it("passes on an intact install, and says how many files it re-hashed", async () => {
    writeInstall([
      { rel: "app.exe", body: "binary" },
      { rel: "resources/app.asar", body: "asar", critical: true },
      { rel: "locales/am.pak", body: "pak" },
    ]);
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("ok");
    expect(result.facts?.["hashed"]).toBe(3);
    expect(result.facts?.["missing"]).toBe(0);
  });

  it("fails, and counts the criticals separately, when files have been taken", async () => {
    writeInstall([
      { rel: "app.exe", body: "binary" },
      { rel: "resources/app.asar", body: "asar", critical: true },
      { rel: "locales/am.pak", body: "pak" },
    ]);
    fs.rmSync(path.join(root, "resources", "app.asar"));
    fs.rmSync(path.join(root, "locales", "am.pak"));

    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("fail");
    expect(result.facts?.["missing"]).toBe(2);
    // A per-locale pack is deliberately NOT critical; only the asar is.
    expect(result.facts?.["missingCritical"]).toBe(1);
    expect(result.remedy).toMatch(/aicommander\.dev\/antivirus/);
  });

  it("fails on a file whose bytes changed, which the startup check cannot see", async () => {
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    // Same length, different content: only hashing catches this, which is the
    // whole reason the doctor pays for the expensive pass.
    fs.writeFileSync(path.join(root, "app.exe"), "BINARY");
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("fail");
    expect(result.facts?.["mismatched"]).toBe(1);
  });

  it("fails a HASHED file whose size no longer matches, without reading it", async () => {
    // The leniency this replaces was justified by the manifest being written at
    // `afterPack`, before signing — but generate-manifest.mjs records a `sha256`
    // only where `isHashWorthy(...) && isByteStable(...)` holds, and
    // `isByteStable` exists to exclude exactly the files a later step rewrites.
    // An entry WITH a hash is one the generator certified as byte-final, so its
    // size changing is evidence, and treating it as pipeline noise made a
    // truncated or padded shipped file read as a healthy install.
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    fs.writeFileSync(path.join(root, "app.exe"), "binary plus a signature");
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("fail");
    expect(result.facts?.["mismatched"]).toBe(1);
    // Settled by the length alone: no point hashing a file that cannot match.
    expect(result.facts?.["resized"]).toBe(1);
    expect(result.facts?.["hashed"]).toBe(0);
    expect(result.remedy).toMatch(/aicommander\.dev\/antivirus/);
  });

  it("leaves an UNHASHED entry's size alone — the generator never certified it", async () => {
    // The other half of the same rule: a file electron-builder signs after the
    // manifest is written grows by its signature on every healthy machine, which
    // is why the generator records no hash for it. No hash, no size claim.
    writeInstall([{ rel: "app.exe", body: "binary", hashed: false }]);
    fs.writeFileSync(path.join(root, "app.exe"), "binary plus a signature");
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("ok");
    expect(result.facts?.["mismatched"]).toBe(0);
    expect(result.remedy).toBeUndefined();
  });

  it("does not read an EMPTY manifest as a complete installation", async () => {
    // "all 0 shipped files are present" is the answer that reads as health while
    // silently switching this detection off. Every other reader of this manifest
    // already refuses an empty one — install-scan.ts calls it `manifest-unusable`
    // and win-install-check.ps1 says "manifest lists no files" — and four
    // components reading one file must not disagree about what an empty one means.
    writeInstall([]);
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/lists no files/);
    expect(result.detail).not.toMatch(/present/);
  });

  it("refuses a manifest whose entry escapes the install root with `..`", async () => {
    // `path.join(root, "../../…")` left the installation entirely, and whatever
    // it landed on was lstat'd and hashed as though it were a shipped file. One
    // entry we will not follow makes the whole manifest unusable — never
    // "missing files", which would accuse a user's antivirus on the strength of
    // a manifest we have just refused to believe.
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    writeEntries([{ path: "../outside.txt", size: 1 }]);
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/outside the installation/);
    expect(result.facts?.["missing"]).toBeUndefined();
  });

  it("refuses a manifest whose entry is an ABSOLUTE path", async () => {
    // An absolute entry does not escape the root, it REPLACES it: `path.join`
    // was never the guard anyone assumed it was.
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    const outside = path.join(os.tmpdir(), "aic-doctor-outside.txt");
    fs.writeFileSync(outside, "not ours");
    try {
      writeEntries([{ path: outside.split(path.sep).join("/"), size: 8 }]);
      const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
      expect(result.verdict).toBe("warn");
      expect(result.detail).toMatch(/outside the installation/);
    } finally {
      fs.rmSync(outside, { force: true });
    }
  });

  it("never follows a symlink INSIDE the root out of the installation", async () => {
    // The hole a lexical containment test cannot see. `lstat` declines to follow
    // only the LAST component of a path and follows every one before it, so a
    // link `link` inside the install tree and the entry `link/secret.txt` spelled
    // itself inside the root, passed containment, and got stat'd and streamed
    // through sha256 from somewhere else on the machine entirely — and because
    // the manifest also supplies the expected hash, the doctor reported that
    // outside file as a healthy shipped one.
    if (process.platform === "win32") return; // symlink creation needs a privilege
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-outside-"));
    const secret = path.join(outsideDir, "secret.txt");
    fs.writeFileSync(secret, "not ours");
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    fs.symlinkSync(outsideDir, path.join(root, "link"));
    writeEntries([
      {
        path: "link/secret.txt",
        size: Buffer.byteLength("not ours"),
        sha256: createHash("sha256").update("not ours").digest("hex"),
      },
    ]);

    // What is asserted is the READ, not the label: every path the check hands to
    // `lstat` or `open` is recorded, and none of them may lie outside the
    // installation. A fix that only changed the verdict would still have opened
    // the file, which is the part a user cannot take back.
    const touched: string[] = [];
    type OpenFn = typeof fs.promises.open;
    type LstatFn = typeof fs.promises.lstat;
    const realOpen: OpenFn = fs.promises.open;
    const realLstat: LstatFn = fs.promises.lstat;
    const spy =
      (real: unknown) =>
      (target: fs.PathLike, ...rest: unknown[]) => {
        touched.push(String(target));
        return (real as (...args: unknown[]) => unknown)(target, ...rest);
      };
    fs.promises.open = spy(realOpen) as unknown as OpenFn;
    fs.promises.lstat = spy(realLstat) as unknown as LstatFn;
    try {
      const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
      // Compared on where each path LEADS, not on how it is spelled — a path
      // under the root that resolves elsewhere is the whole bug.
      const insideRoot = fs.realpathSync(root);
      const escaped = touched.filter((target) => {
        let dir: string;
        try {
          dir = fs.realpathSync(path.dirname(target));
        } catch {
          return false; // gone by the time we look; it led nowhere
        }
        return dir !== insideRoot && !dir.startsWith(insideRoot + path.sep);
      });
      expect(escaped).toEqual([]);
      expect(touched).not.toContain(secret);
      // A link we will not follow is the manifest naming a file outside the
      // installation, arrived at by another route — the same verdict a `..`
      // entry gets, and never "missing files".
      expect(result.verdict).toBe("warn");
      expect(result.detail).toMatch(/outside the installation/);
      expect(result.facts?.["missing"]).toBeUndefined();
    } finally {
      fs.promises.open = realOpen;
      fs.promises.lstat = realLstat;
      fs.rmSync(outsideDir, { recursive: true, force: true });
    }
  });

  it("never streams something that is not a regular file through the hash", async () => {
    // The one with teeth: `sha256File` streams whatever it is handed, so a FIFO
    // inside the install root blocks the doctor until somebody writes to it and
    // a character device never ends at all. A non-regular file where the
    // manifest recorded a hash is "we could not verify this", never damage.
    if (process.platform === "win32") return;
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    fs.rmSync(path.join(root, "app.exe"));
    const mkfifo = spawnSync("mkfifo", [path.join(root, "app.exe")]);
    if (mkfifo.status !== 0) return; // no mkfifo on this box; nothing to assert
    // A FIFO's size is 0, so the entry records 0 and the hash of nothing: the
    // size check agrees and the ONLY thing standing between the doctor and an
    // open() that blocks until somebody writes to the pipe is the regular-file
    // gate. Without it this test does not fail, it never returns.
    writeEntries([
      { path: "app.exe", size: 0, sha256: createHash("sha256").update("").digest("hex") },
    ]);
    // The check must RETURN — before this it would have hung here forever.
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("warn");
    expect(result.facts?.["unreadable"]).toBe(1);
    expect(result.facts?.["unreadableCode"]).toBe("not-a-regular-file");
    expect(result.facts?.["hashed"]).toBe(0);
  });

  it("refuses a manifestPath that does not lead back to the manifest", async () => {
    // The root is DERIVED by stripping the manifest's own recorded path off
    // where the file sits; with enough segments that derivation lands on `/`,
    // under which every path on the machine is "inside the install root". So the
    // claim is checked against the file system, exactly as integrity.ts checks it.
    fs.mkdirSync(resources, { recursive: true });
    fs.writeFileSync(
      path.join(resources, MANIFEST_FILENAME),
      JSON.stringify({
        schema: MANIFEST_SCHEMA,
        manifestPath: `a/b/c/d/e/f/g/${MANIFEST_FILENAME}`,
        files: [{ path: "etc/passwd", size: 1 }],
      }),
    );
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("skipped");
  });

  it("treats an unparseable manifest as absent, never as damage", async () => {
    fs.mkdirSync(resources, { recursive: true });
    fs.writeFileSync(path.join(resources, MANIFEST_FILENAME), "{not json");
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("skipped");
  });

  it("treats an unrecognised schema as absent", async () => {
    fs.mkdirSync(resources, { recursive: true });
    fs.writeFileSync(
      path.join(resources, MANIFEST_FILENAME),
      JSON.stringify({ schema: MANIFEST_SCHEMA + 99, manifestPath: `resources/${MANIFEST_FILENAME}`, files: [] }),
    );
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.manifest");
    expect(result.verdict).toBe("skipped");
  });
});

describe("install path writability", () => {
  it("writes a probe, removes it, and leaves the directory as it found it", async () => {
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    const before = fs.readdirSync(root).sort();
    const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.writable");
    expect(result.verdict).toBe("ok");
    expect(fs.readdirSync(root).sort()).toEqual(before);
  });

  it("does NOT write a probe file into a signed macOS app bundle", async () => {
    // On macOS the manifest root IS the .app — notarized, code-signed, sealed.
    // Writing into it puts a stray file inside a signed bundle, and the refusal
    // it usually gets on macOS 14+ is App Management, not a security product's
    // filter driver: a false alarm on a healthy Mac, with a file left behind.
    const bundle = path.join(root, "AI Commander.app");
    const bundleResources = path.join(bundle, "Contents", "Resources");
    fs.mkdirSync(bundleResources, { recursive: true });
    fs.writeFileSync(
      path.join(bundleResources, MANIFEST_FILENAME),
      JSON.stringify({
        schema: MANIFEST_SCHEMA,
        manifestPath: `Contents/Resources/${MANIFEST_FILENAME}`,
        files: [],
      }),
    );
    const realPlatform = process.platform;
    Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
    try {
      const result = byId(
        await installChecks.run(ctx({ resourcesPath: bundleResources })),
        "install.writable",
      );
      expect(result.verdict).toBe("skipped");
      expect(result.detail).toMatch(/signed macOS application bundle/);
      expect(fs.readdirSync(bundle)).toEqual(["Contents"]);
    } finally {
      Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
    }
  });

  it("reports the OS error VERBATIM when the write is refused", async () => {
    writeInstall([{ rel: "app.exe", body: "binary" }]);
    // Read+execute only: the owner cannot create a file here. The stand-in for a
    // filter driver saying no; what matters is that the errno reaches the report
    // unsummarised, because on 2026-09-02 the exact string was the diagnosis.
    fs.chmodSync(root, 0o500);
    try {
      const result = byId(await installChecks.run(ctx({ resourcesPath: resources })), "install.writable");
      // Not `fail` unless we know we are elevated: on a healthy machine the
      // install directory is admin-owned and an ordinary user is refused.
      expect(result.verdict).toBe(process.getuid?.() === 0 ? "fail" : "warn");
      expect(result.detail).toMatch(/EACCES|EPERM/);
      expect(result.facts?.["code"]).toMatch(/EACCES|EPERM/);
    } finally {
      fs.chmodSync(root, 0o700);
    }
  });
});

/**
 * ── THE BUG THIS SUITE COULD NOT SEE ─────────────────────────────────────────
 * The doctor runs headless from npm — plain Node, where `lstat` tells the truth
 * about `resources/app.asar` — and it ALSO runs inside the desktop's main
 * process (desktop/src/diagnostics.ts). There Electron patches `fs` so an asar
 * archive can be traversed like a directory, and the archive itself reports
 * `{ isFile: false, isDirectory: true, size: 0 }` (measured on a real 1.2.0
 * macOS install). The regular-file gate then rejected a shipped file and a
 * perfectly healthy Mac was told, in the release that exists to STOP false
 * antivirus alarms, that 1 of its files "could not be read" — remedy: your
 * security product's filter driver is holding it.
 *
 * Nothing in a plain-Node suite reproduces that, which is why it shipped. The
 * double below is Electron's patched `fs`, and the first test is the control
 * that proves the double reproduces the defect.
 */
describe("the manifest check inside Electron, where app.asar is virtualized", () => {
  const realFs: AsarBlindFs = fs.promises;

  /** Any path with an `.asar` component: an empty directory, and unopenable. */
  const patchedFs: AsarBlindFs = {
    async lstat(target) {
      return virtualized(target) ? { size: 0, isFile: () => false } : realFs.lstat(target);
    },
    realpath: (target) => realFs.realpath(target),
    readFile: (target, encoding) => realFs.readFile(target, encoding),
    open: (target, flags) => {
      if (virtualized(target)) {
        return Promise.reject(Object.assign(new Error("EISDIR: illegal operation on a directory"), { code: "EISDIR" }));
      }
      return realFs.open(target, flags);
    },
  };

  function virtualized(target: string): boolean {
    return target.split(path.sep).some((segment) => segment.endsWith(".asar"));
  }

  const fsEnv = (electron: string | undefined): AsarFsEnv => ({
    electron,
    load: (id: string) => {
      if (id !== "original-fs") throw new Error(`unexpected module ${id}`);
      return { promises: realFs };
    },
    plain: patchedFs,
  });

  const install = () =>
    writeInstall([
      { rel: "app.exe", body: "binary" },
      { rel: "resources/app.asar", body: "asar", critical: true },
      { rel: "locales/am.pak", body: "pak" },
    ]);

  it("CONTROL: the patched fs makes a healthy install look like one a scanner is holding", async () => {
    install();
    // The shipped 1.2.0 behaviour: the ordinary, patched `fs`.
    const { result } = await checkManifest(ctx({ resourcesPath: resources }), fsEnv(undefined));

    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/1 could not be read \(not-a-regular-file\)/);
    expect(result.facts?.["unreadable"]).toBe(1);
  });

  it("hashes the archive like any other shipped file, so the install passes", async () => {
    install();
    const { result } = await checkManifest(ctx({ resourcesPath: resources }), fsEnv("39.8.10"));

    expect(result.verdict).toBe("ok");
    expect(result.facts?.["unreadable"]).toBe(0);
    expect(result.facts?.["hashed"]).toBe(3);
  });

  it("still catches a genuinely altered archive — a truthful stat, not an exemption", async () => {
    install();
    fs.writeFileSync(path.join(root, "resources", "app.asar"), "asar-but-different");

    const { result } = await checkManifest(ctx({ resourcesPath: resources }), fsEnv("39.8.10"));

    expect(result.verdict).toBe("fail");
    expect(result.facts?.["mismatchedExamples"]).toBe("resources/app.asar");
  });
});
