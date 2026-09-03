import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { manifestEntryRealTarget, manifestEntryTarget, type ManifestDirCache } from "./manifest-entry.js";
import { isAbsence } from "./presence.js";
import {
  errnoOf,
  errorText,
  fail,
  HELP_URL,
  ok,
  skipped,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorFacts,
} from "../types.js";

/**
 * "80 of your 81 files are gone" — the ten-second diagnosis, automated, plus the
 * write probe whose exact error text is what told us it was a filter driver and
 * not a permissions problem.
 *
 * ── THE MANIFEST ─────────────────────────────────────────────────────────────
 * The desktop app ships `resources/install-manifest.json`, written at pack time
 * by packages/desktop/scripts/generate-manifest.mjs. Two consumers already read
 * it: the in-process startup check (desktop/src/integrity.ts) and the Windows
 * watchdog. This is the third, and it is the EXPENSIVE pass the startup check
 * deliberately defers — the startup check does presence and count only, so that
 * it costs the main loop nothing; the doctor re-hashes every file the manifest
 * recorded a hash for, because a user who ran `doctor` has asked to wait.
 *
 * The name and schema number are duplicated here rather than imported: the
 * declaration lives in `packages/desktop/src/install-manifest-contract.mjs`,
 * and `@aicommander/desktop` is not (and must not become) a dependency of the
 * agent — the agent ships to npm on its own. `install-manifest-parity.test.ts`
 * pins these two literals against that file, so a rename or a schema bump over
 * there fails a test here instead of silently switching this check off.
 *
 * A manifest we do not recognise is treated as ABSENT, never as damage. The
 * manifest cannot attest to itself, and accusing a user's antivirus on the
 * strength of a file we failed to parse is the one mistake that would make this
 * command untrustworthy.
 *
 * ── `critical` ───────────────────────────────────────────────────────────────
 * The generator flags a file `critical` when its ABSENCE alone stops the app
 * starting — the runtime's own files. Per-feature and per-locale resources are
 * deliberately NOT critical: a quarantined `locales/am.pak` is missing, and
 * nothing more. The distinction is what keeps the verdict proportionate.
 */

/** Mirrors packages/desktop/src/install-manifest-contract.mjs — see the header. */
export const MANIFEST_FILENAME = "install-manifest.json";
/** Mirrors packages/desktop/src/install-manifest-contract.mjs — see the header. */
export const MANIFEST_SCHEMA = 1;

interface ManifestEntry {
  path: string;
  size: number;
  sha256?: string;
  critical?: boolean;
  link?: boolean;
}

interface InstallManifest {
  schema: number;
  product?: string;
  version?: string;
  platform?: string;
  generatedAt?: string;
  manifestPath?: string;
  totalFiles?: number;
  files: ManifestEntry[];
}

interface LoadedManifest {
  manifest: InstallManifest;
  /** The install root, recovered by stripping the manifest's own relative path. */
  root: string;
}

/**
 * Load the manifest and recover the install root FROM it, by stripping the
 * manifest's own recorded relative path off where the file actually sits —
 * rather than reimplementing "resources/ on Windows, Contents/Resources on
 * macOS". The layout is the generator's business, and every consumer recovers
 * the root the same way (integrity.ts does exactly this).
 */
export async function loadInstallManifest(resourcesPath: string): Promise<LoadedManifest | null> {
  const file = path.join(resourcesPath, MANIFEST_FILENAME);
  const raw = await fs.promises.readFile(file, "utf8");
  const manifest = JSON.parse(raw) as InstallManifest;
  if (manifest?.schema !== MANIFEST_SCHEMA || !Array.isArray(manifest.files)) return null;
  const segments = String(manifest.manifestPath ?? "")
    .split("/")
    .filter(Boolean);
  if (segments.length === 0) return null;
  let root = file;
  for (let i = 0; i < segments.length; i++) root = path.dirname(root);
  // ...and the claim is CHECKED against where the file actually sits, exactly as
  // integrity.ts checks it. Stripping N components off is a valid derivation
  // only if walking those same N components back down lands on the file we just
  // read. A `manifestPath` with the right number of segments but the wrong names
  // derives a root that is not the installation — and with enough segments it
  // derives `/`, under which every path on the machine is "contained" and the
  // containment test below would wave it through.
  if (path.resolve(path.join(root, ...segments)) !== path.resolve(file)) return null;
  return { manifest, root };
}

/** `O_NOFOLLOW`/`O_NONBLOCK` where the platform has them (win32 has neither). */
function openFlag(name: "O_NOFOLLOW" | "O_NONBLOCK"): number {
  const value = (fs.constants as Record<string, number | undefined>)[name];
  return typeof value === "number" ? value : 0;
}

/**
 * Hash a file, having PROVED what is being hashed rather than trusting the path.
 *
 * The caller has already resolved every directory on the way here and `lstat`ed
 * the last component, but a path is not a file: between that stat and this open
 * the name can be replaced. So the descriptor itself is verified —
 * `O_NOFOLLOW` refuses to open the final component if it is a symlink, and the
 * `fstat` on the OPEN descriptor is what says the bytes about to be streamed
 * belong to a regular file. `O_NONBLOCK` is belt and braces on the same rule:
 * regular files ignore it, and it means an `open` that somehow reached a FIFO
 * returns instead of waiting for a writer forever.
 */
async function sha256File(absolute: string): Promise<string> {
  const handle = await fs.promises.open(
    absolute,
    fs.constants.O_RDONLY | openFlag("O_NOFOLLOW") | openFlag("O_NONBLOCK"),
  );
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) throw new Error("not a regular file");
    const hash = createHash("sha256");
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      hash.update(chunk as Buffer);
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
}

interface ManifestVerdict {
  result: CheckResult;
  root: string | null;
}

/**
 * One entry we will not follow condemns the whole manifest.
 *
 * Raised for a path the string rule rejects, for a lexically escaping one, and
 * for one that a symlink on the way to it puts outside the installation — the
 * three are the same finding, "this file list is not describing this
 * installation", and they get one verdict so no reader has to guess which of
 * them a report meant.
 *
 * The offending string is NOT reported: it is attacker-controlled text on its
 * way to a file a user emails to a vendor, and the count is the whole diagnostic.
 */
function namesOutsideInstall(id: string, title: string, manifestFile: string, root: string, files: number): CheckResult {
  return warn(
    id,
    title,
    "the manifest names a file outside the installation it describes, so nothing about this " +
      "installation could be verified.",
    "The manifest itself is damaged. Re-run the installer; until then this check cannot tell an intact " +
      `install from a gutted one. ${HELP_URL}`,
    { manifest: manifestFile, root, files },
  );
}

async function checkManifest(ctx: DoctorContext): Promise<ManifestVerdict> {
  const id = "install.manifest";
  const title = "Install manifest";

  // In a plain Node process `process.resourcesPath` does not exist; in Electron
  // it does. The headless npm agent therefore lands here with nothing, which is
  // not a fault and must not read like one.
  const resourcesPath =
    ctx.resourcesPath ?? (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  if (!resourcesPath) {
    return {
      root: null,
      result: skipped(
        id,
        title,
        "no packaged install manifest here — this is the headless agent, which is installed by npm and has no shipped file list. Not a fault.",
      ),
    };
  }

  let loaded: LoadedManifest | null;
  try {
    loaded = await loadInstallManifest(resourcesPath);
  } catch (err) {
    return {
      root: null,
      result: skipped(id, title, `the manifest could not be read (${errorText(err)}).`, {
        manifest: path.join(resourcesPath, MANIFEST_FILENAME),
      }),
    };
  }
  if (!loaded) {
    return {
      root: null,
      result: skipped(id, title, "the manifest is missing or of an unrecognised schema.", {
        manifest: path.join(resourcesPath, MANIFEST_FILENAME),
      }),
    };
  }

  const { manifest, root } = loaded;
  if (manifest.files.length === 0) {
    // A manifest that lists nothing cannot answer "are 80 of my 81 files gone?",
    // and "all 0 shipped files present" is the answer that reads as health while
    // silently switching the detection off. The other three readers of this same
    // file already refuse it — priv-helper/src/install-scan.ts calls it
    // `manifest-unusable` and desktop/build/win-install-check.ps1 refuses with
    // "manifest lists no files" — and four components reading one manifest must
    // not disagree about what an empty one means.
    return {
      root,
      result: warn(
        id,
        title,
        "the manifest was read but lists no files, so nothing about this installation could be verified.",
        "The manifest itself is damaged or was generated empty. Re-run the installer; until then this check " +
          `cannot tell an intact install from a gutted one. ${HELP_URL}`,
        { manifest: path.join(resourcesPath, MANIFEST_FILENAME), root, files: 0 },
      ),
    };
  }
  // Every entry's SPELLING is vetted here, before a single syscall — see
  // manifest-entry.ts for what an entry may be and for what a `..`, an absolute
  // path or a device node costs a check that stats and hashes what it is handed.
  // The string rule and the lexical containment test are both necessary and
  // neither is sufficient, so what an entry REFERS TO is proved separately, in
  // the loop below, before anything is probed. One bad entry condemns the whole manifest rather
  // than being quietly dropped: a file list we cannot trust cannot answer "are
  // 80 of my 81 files gone?" either, and dropping the entry would leave the
  // remaining count reading like health. Same verdict as the empty manifest
  // above, and the same one the other three readers give (`manifest-unusable`,
  // "manifest contains a path we will not follow").
  const manifestFile = path.join(resourcesPath, MANIFEST_FILENAME);
  const unusable = () => ({
    root,
    result: namesOutsideInstall(id, title, manifestFile, root, manifest.files.length),
  });
  const targets: Array<{ entry: ManifestEntry; absolute: string }> = [];
  for (const entry of manifest.files) {
    const absolute = manifestEntryTarget(root, entry?.path);
    if (absolute === null) return unusable();
    targets.push({ entry, absolute });
  }

  // The lexical proof above is a statement about the SPELLING of a path; this is
  // where it becomes a statement about the file. The root is resolved once, and
  // each entry's directory chain is resolved and re-proved contained before
  // anything touches it (manifest-entry.ts), so no link the manifest picked can
  // redirect an `lstat` — let alone a read — out of the installation. Without
  // it, a link `link` inside the tree and the entry `link/file` had the doctor
  // hashing a file elsewhere on the machine and calling the install healthy.
  let realRoot: string;
  try {
    realRoot = path.resolve(await fs.promises.realpath(root));
  } catch (err) {
    return {
      root,
      result: skipped(
        id,
        title,
        `the install directory itself could not be resolved (${errorText(err)}), so no entry could be proved ` +
          "to be inside it.",
        { manifest: manifestFile, root },
      ),
    };
  }
  const dirs: ManifestDirCache = new Map();

  const missing: string[] = [];
  const missingCritical: string[] = [];
  const unreadable: string[] = [];
  const unreadableCodes: string[] = [];
  const mismatched: string[] = [];
  let resized = 0;
  let hashed = 0;

  for (const { entry, absolute: spelled } of targets) {
    const resolved = await manifestEntryRealTarget(realRoot, spelled, dirs);
    // A link that leads out of the installation is the manifest naming a file
    // outside it, arrived at by another route — same finding, same verdict, and
    // nothing outside has been stat'd, opened or hashed to reach it.
    if (resolved.kind === "escapes") return unusable();
    if (resolved.kind === "absent") {
      // The entry's own directory is not there. That is the file being gone.
      missing.push(entry.path);
      if (entry.critical) missingCritical.push(entry.path);
      continue;
    }
    if (resolved.kind === "unresolvable") {
      unreadable.push(entry.path);
      unreadableCodes.push(resolved.code);
      continue;
    }
    const absolute = resolved.absolute;

    let stats: fs.Stats;
    try {
      // lstat, not stat: a symlink whose target is gone must be reported as the
      // TARGET being gone (its own entry), not as the link being fine. It is
      // safe to call on this path and not on the one the manifest spelled —
      // `lstat` declines to follow only the LAST component and follows every
      // one before it, which is exactly the hole `manifestEntryRealTarget` shuts.
      stats = await fs.promises.lstat(absolute);
    } catch (err) {
      if (isAbsence(err)) {
        missing.push(entry.path);
        if (entry.critical) missingCritical.push(entry.path);
      } else {
        unreadable.push(entry.path);
        unreadableCodes.push(errnoOf(err) ?? "unknown");
      }
      continue;
    }
    // Size is only comparable where the bytes were final when the manifest was
    // written; everything electron-builder signs AFTERWARDS grows by its
    // signature. A recorded `sha256` IS exactly that guarantee — see the size
    // check below — and an entry without one has no dependable size either, so
    // it is inventoried by presence alone and never measured.
    if (!entry.sha256 || entry.link) continue;
    // ONLY a regular file is ever opened. `sha256File` streams whatever it is
    // given: a FIFO blocks the run until someone writes to it, a character
    // device (`/dev/zero`) never ends, and a directory or a socket throws a
    // confusing errno from inside the hash. The manifest records regular files,
    // so anything else here is the manifest disagreeing with the disk — which is
    // "we could not verify this file", never damage. A symlink is one of those
    // "anything else": the last component is the one thing `lstat` does not
    // follow, so a link lands here as a link and is reported, never opened. The
    // manifest's own `link` entries never get this far (`entry.link` above).
    if (!stats.isFile()) {
      unreadable.push(entry.path);
      unreadableCodes.push("not-a-regular-file");
      continue;
    }
    if (stats.size !== entry.size) {
      // A DIFFERENT SIZE ON A HASHED FILE IS DAMAGE, and there is no need to
      // read the file to know it: a file whose length changed cannot hold the
      // bytes whose hash was recorded, so this is the byte mismatch below,
      // established more cheaply.
      //
      // The pipeline argument for leniency does not apply to these entries and
      // never did. generate-manifest.mjs records a `sha256` only where
      // `isHashWorthy(...) && isByteStable(...)` holds, and `isByteStable`
      // exists precisely to exclude everything a later step rewrites — signed
      // extensions, extensionless Mach-O, `_CodeSignature/`, `Info.plist`. Its
      // own header states the consequence: "`size` is compared at runtime only
      // where a hash exists (i.e. where the size is equally final)". An entry
      // carrying a hash is therefore one the generator has certified as final,
      // so a size that no longer matches is evidence, not pipeline noise.
      // Entries WITHOUT a hash keep the leniency they earn — they are not
      // measured at all (see the `continue` above).
      mismatched.push(entry.path);
      resized++;
      continue;
    }
    try {
      const actual = await sha256File(absolute);
      hashed++;
      if (actual !== entry.sha256) mismatched.push(entry.path);
    } catch {
      // Present a moment ago and unreadable now — a lock, or a scanner holding
      // it. Not something to accuse anyone of.
      unreadable.push(entry.path);
      unreadableCodes.push("read-failed");
    }
  }

  const facts: DoctorFacts = {
    root,
    version: manifest.version ?? null,
    files: manifest.files.length,
    present: manifest.files.length - missing.length,
    hashed,
    missing: missing.length,
    missingCritical: missingCritical.length,
    mismatched: mismatched.length,
    // Of the mismatches, how many were settled by the length alone — worth
    // separating, because "shorter than it shipped" and "same length, different
    // bytes" are different stories about the same file.
    resized,
    unreadable: unreadable.length,
    ...(unreadableCodes.length > 0 ? { unreadableCode: unreadableCodes.sort()[0]! } : {}),
    // Enough of the names to recognise WHAT went, without pasting a thousand
    // paths into a vendor's inbox.
    ...(missing.length > 0 ? { missingExamples: missing.slice(0, 8).join(", ") } : {}),
    ...(mismatched.length > 0 ? { mismatchedExamples: mismatched.slice(0, 8).join(", ") } : {}),
  };

  const remedy =
    "Files are gone from the installation. This is almost always security software quarantining them. " +
    `Restore them from quarantine, add an exclusion for the install directory, and re-run the installer. ${HELP_URL}`;

  if (missing.length > 0) {
    const critical = missingCritical.length > 0 ? ` (${missingCritical.length} of them critical)` : "";
    return {
      root,
      result: fail(
        id,
        title,
        `${missing.length} of ${manifest.files.length} shipped files are missing${critical}.`,
        remedy,
        facts,
      ),
    };
  }
  if (mismatched.length > 0) {
    // Alteration of a file the generator certified as byte-final: either the
    // length changed or the bytes did behind an unchanged length. Only entries
    // carrying a `sha256` can reach this, which is what keeps it off the files
    // the build pipeline legitimately rewrites after the manifest was written.
    return {
      root,
      result: fail(
        id,
        title,
        `${mismatched.length} shipped files no longer hold the bytes they were built with.`,
        remedy,
        facts,
      ),
    };
  }
  if (unreadable.length > 0) {
    return {
      root,
      result: warn(
        id,
        title,
        `all ${manifest.files.length} shipped files are present, but ${unreadable.length} could not be read` +
          `${unreadableCodes.length > 0 ? ` (${unreadableCodes.sort()[0]})` : ""}.`,
        "Nothing is missing. A file that is present but refuses to be read is the signature of a security " +
          `product's filter driver holding it. ${HELP_URL}`,
        facts,
      ),
    };
  }
  return {
    root,
    result: ok(
      id,
      title,
      `all ${manifest.files.length} shipped files present; ${hashed} re-hashed and unchanged.`,
      facts,
    ),
  };
}

/** Probe file name — recognisable, so an operator who ever sees one knows whose it is. */
function probeName(): string {
  return `.aicommander-doctor-${process.pid}-${Date.now().toString(36)}.tmp`;
}

/** Is this install root inside a macOS application bundle? */
function insideAppBundle(root: string): boolean {
  return /\.app(?:$|\/)/.test(root);
}

/**
 * Can we write into the installation directory, and if not, what EXACTLY did the
 * OS say?
 *
 * The verbatim error is the whole point. During the 2026-09-02 incident an
 * ELEVATED administrator got "Access denied" on a directory whose ACL granted
 * `BUILTIN\Administrators: FullControl` with no deny ACEs — the signature of a
 * filter driver, not of permissions, and the two are indistinguishable from any
 * summary of the error. So this reports `err.message` as the OS produced it.
 *
 * A refusal is NOT reported as a failure unless we know we are elevated. On
 * every healthy machine the install directory is admin-owned and an ordinary
 * user cannot write to it; calling that "fail" would fire on everybody. Where
 * `getuid()` says we are root, a refusal is real.
 *
 * ── NOT INSIDE A macOS .app BUNDLE ───────────────────────────────────────────
 * The check is skipped there, and it has to be. On macOS the manifest root IS
 * the bundle — a notarized, code-signed, sealed directory — so writing a probe
 * file into it puts a stray file inside a signed bundle, which is a thing a
 * diagnostic may not do (types.ts: "a diagnostic must never make the machine
 * worse than it found it"), and the "could not remove the probe file" branch
 * would then blame a scanner for a file we ourselves left in a sealed bundle.
 * Worse, the refusal it usually gets is not a filter driver at all: macOS 14+
 * denies writes into another app's bundle under App Management unless the user
 * has granted it, so the check as written reported a security-product refusal on
 * a completely healthy Mac — the false alarm that costs a diagnostic its
 * credibility. The question this probe answers is a Windows question (an
 * elevated administrator refused write access to `%ProgramFiles%`), and the
 * manifest check above already covers macOS damage by re-hashing every shipped
 * file.
 */
async function checkInstallWritable(root: string | null): Promise<CheckResult> {
  const id = "install.writable";
  const title = "Install path writability";
  if (!root) {
    return skipped(
      id,
      title,
      "the install directory is unknown without a manifest, and guessing one would probe the wrong path.",
    );
  }
  if (process.platform === "darwin" && insideAppBundle(root)) {
    return skipped(
      id,
      title,
      `the install root is a signed macOS application bundle (${root}); writing a probe file into it would ` +
        "break its seal, and a refusal there is macOS App Management rather than anything to report. Every " +
        "file in the bundle was re-hashed by the manifest check above.",
      { root },
    );
  }

  const file = path.join(root, probeName());
  const elevated = typeof process.getuid === "function" ? process.getuid() === 0 : null;
  const facts: DoctorFacts = { root, elevated };
  try {
    await fs.promises.writeFile(file, "aicommander doctor write probe\n", { flag: "wx" });
  } catch (err) {
    const code = errnoOf(err);
    const detail = `writing into the install directory was refused: ${errorText(err)}`;
    const withCode: DoctorFacts = { ...facts, ...(code ? { code } : {}) };
    const remedy =
      "If this ran WITHOUT administrative rights, the refusal is expected — the install directory is " +
      "admin-owned. If it ran WITH them, and the directory's ACL grants Administrators full control with " +
      `no deny entries, the refusal is coming from a security product's filter driver, not from Windows. ${HELP_URL}`;
    return elevated === true
      ? fail(id, title, detail, remedy, withCode)
      : warn(id, title, detail, remedy, withCode);
  }

  // A diagnostic leaves nothing behind — and a probe file we could not remove is
  // itself worth saying out loud, because it is the same story from the other end.
  try {
    await fs.promises.rm(file, { force: true });
  } catch (err) {
    return warn(
      id,
      title,
      `the install directory accepted a write, but the probe file could not be removed, so this run has LEFT ` +
        `${file} behind: ${errorText(err)}`,
      `Delete ${file} by hand — the diagnostic could not, and it does not belong there. A file that cannot be ` +
        "deleted right after being created is usually held open by a scanner.",
      { ...facts, ...(errnoOf(err) ? { code: errnoOf(err)! } : {}) },
    );
  }
  return ok(id, title, "the install directory accepted a write and the probe was removed.", facts);
}

export const installChecks: DoctorCheckGroup = {
  id: "install",
  title: "Installation",
  async run(ctx) {
    const manifest = await checkManifest(ctx);
    return [manifest.result, await checkInstallWritable(manifest.root)];
  },
};
