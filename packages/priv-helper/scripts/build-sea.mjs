#!/usr/bin/env node
// Build the AI Commander privileged helper as a Node Single Executable
// Application (SEA): a standalone native binary that runs without a system Node,
// so the macOS LaunchDaemon / Windows boot task can execute it directly.
//
// Pipeline:
//   1. esbuild-bundle bin/priv-helper.ts (+ src/* + @aicommander/protocol) into
//      one CommonJS file (dist-sea/helper.cjs).
//   2. node --experimental-sea-config → dist-sea/sea-prep.blob.
//   3. copy process.execPath → dist-bin/aicommander-priv-helper[.exe].
//   4. Windows: validate the PE and strip the copied Node Authenticode table.
//   5. postject-inject the blob into that binary.
//   6. Windows: validate the unsigned PE for downstream signing; macOS: ad-hoc
//      re-sign for local execution (release CI applies the real signature).
//
// Code cache / snapshot are DISABLED on purpose — they are node-version /
// platform fragile, and this is a long-lived security binary.
//
// ARCH (#12): a SEA base is a real `node` binary with a blob injected, so the
// produced binary's architecture is whatever the BASE node's arch is. To ship
// a mac x64 helper from an arm64 runner (and vice-versa) we can't reuse
// process.execPath — that's the runner's arch. Instead, when AIC_SEA_ARCH
// differs from the runner arch, we download the OFFICIAL Node release for the
// runner's node version (process.version) matching the target platform+arch,
// verify its tarball against that exact release's SHASUMS256.txt, freshly
// extract just its `node` binary, and use THAT as the postject base. Same-arch
// builds keep the fast path (process.execPath) unchanged. On macOS we then run
// `file` on the output and HARD-FAIL if the produced arch doesn't match the
// target. Windows is single-arch (x64) so no download ever happens there.
// AIC_SEA_OUT overrides the output path (defaults to the fixed
// dist-bin/<binName> electron-builder consumes).

import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readFileSync,
  chmodSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { prepareVerifiedNodeBase } from "./node-release-artifact.mjs";
import { assertUnsignedPeForSigning, stripPeAuthenticode } from "./pe-authenticode.mjs";

const SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");
const seaDir = join(pkgRoot, "dist-sea");
const binDir = join(pkgRoot, "dist-bin");
const nodeCacheDir = join(pkgRoot, ".node-cache");

const isWin = process.platform === "win32";
const isMac = process.platform === "darwin";

const bundlePath = join(seaDir, "helper.cjs");
const configPath = join(seaDir, "sea-config.json");
const blobPath = join(seaDir, "sea-prep.blob");
const binName = isWin ? "aicommander-priv-helper.exe" : "aicommander-priv-helper";
// Output path electron-builder consumes; override via AIC_SEA_OUT for per-arch
// or out-of-tree destinations.
const binPath = process.env.AIC_SEA_OUT
  ? resolve(process.env.AIC_SEA_OUT)
  : join(binDir, binName);
const binOutDir = dirname(binPath);
// Arch the caller EXPECTS this build to be for (defaults to the runner's arch).
const targetArch = process.env.AIC_SEA_ARCH || process.arch;

function log(msg) {
  process.stdout.write(`[build-sea] ${msg}\n`);
}

// Resolve the `node` binary to use as the SEA base for `targetArch`.
//   - target arch === runner arch → process.execPath (fast path, no download).
//   - else → verify/cache the official Node tarball for process.version and
//     freshly extract its target-platform/arch `node` into a private temp dir.
// Only macOS cross-arch is supported (Windows is single-arch x64); any other
// cross request fails loudly.
async function resolveSeaBase() {
  if (targetArch === process.arch) {
    return { path: process.execPath, cleanup() {} };
  }

  if (!isMac) {
    throw new Error(
      `cross-arch SEA requested (target=${targetArch}, runner=${process.arch}) on ${process.platform}, which is single-arch — cannot produce a ${targetArch} binary here`,
    );
  }
  if (targetArch !== "x64" && targetArch !== "arm64") {
    throw new Error(`unsupported target arch: ${targetArch}`);
  }

  const version = process.version; // e.g. "v22.19.0"
  log(`verifying official Node ${version} checksums for darwin-${targetArch}`);
  const base = await prepareVerifiedNodeBase({
    cacheDir: nodeCacheDir,
    version,
    platform: "darwin",
    arch: targetArch,
  });
  log(
    `${base.downloaded ? "downloaded" : "reused"} SHA-256-verified Node tarball; ` +
      `fresh cross-arch base ready → ${base.path}`,
  );
  return base;
}

// Assert (macOS only) that the produced binary's arch matches the target.
function assertMachOArch(path) {
  const expected = targetArch === "x64" ? "x86_64" : "arm64";
  const out = execFileSync("file", [path], { encoding: "utf8" });
  if (!out.includes(expected)) {
    throw new Error(
      `arch mismatch: expected ${expected} for target ${targetArch}, but \`file\` reports: ${out.trim()}`,
    );
  }
  log(`arch verified (${expected}): ${out.trim()}`);
}

// A usable SEA base MUST contain the sentinel fuse that postject overwrites.
// Package-manager builds that link node DYNAMICALLY against libnode do not:
// the fuse lives in the shared library, and the executable is only a ~70KB
// launcher (Homebrew's `node` is exactly this). Two things then go wrong, and
// neither reports the real cause:
//   - postject dies inside inject() with "Could not find the sentinel ...",
//     which reads like a postject/version bug rather than a bad base;
//   - if it ever did succeed, the artefact would be a launcher bound to the
//     BUILDER's dylibs — useless as the shipped root helper, which must be a
//     self-contained binary on machines that have no Node at all.
// Fail here, where the diagnosis is still cheap.
function assertUsableSeaBase(binary) {
  if (readFileSync(binary).includes(SENTINEL_FUSE)) return;
  throw new Error(
    `${binary} is not a usable SEA base: it lacks the ${SENTINEL_FUSE} sentinel, ` +
      `which means it is dynamically linked against libnode rather than a self-contained node. ` +
      `Homebrew ships node this way (a ~70KB launcher over libnode.dylib); CI does not, ` +
      `which is why this only fails locally. Build with an official statically-linked node ` +
      `— a nodejs.org tarball/installer, or an fnm/nvm/volta-managed version (those install ` +
      `the official builds) — first on PATH.`,
  );
}

async function main() {
  log(`platform=${process.platform} node=${process.version} runnerArch=${process.arch} targetArch=${targetArch}`);
  log(`output → ${binPath}`);

  // Fresh output dirs.
  rmSync(seaDir, { recursive: true, force: true });
  mkdirSync(seaDir, { recursive: true });
  mkdirSync(binOutDir, { recursive: true });
  rmSync(binPath, { force: true });

  // 1. Bundle to a single CommonJS file. Node builtins are external
  //    automatically for platform:node.
  log("bundling bin/priv-helper.ts → dist-sea/helper.cjs (esbuild)");
  await build({
    entryPoints: [join(pkgRoot, "bin", "priv-helper.ts")],
    outfile: bundlePath,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    logLevel: "info",
  });

  // 2. SEA config → prep blob.
  log("writing dist-sea/sea-config.json");
  const seaConfig = {
    main: bundlePath,
    output: blobPath,
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    useCodeCache: false,
  };
  writeFileSync(configPath, JSON.stringify(seaConfig, null, 2));

  log("generating SEA blob (node --experimental-sea-config)");
  execFileSync(process.execPath, ["--experimental-sea-config", configPath], {
    stdio: "inherit",
  });

  // 3. Copy the (target-arch) node binary to the output path.
  // Resolve immediately before the copy so a freshly extracted cross-arch base
  // can be removed on every success or failure path.
  const seaBase = await resolveSeaBase();
  try {
    assertUsableSeaBase(seaBase.path);
    log(`copying ${seaBase.path} → ${binPath}`);
    copyFileSync(seaBase.path, binPath);
  } finally {
    seaBase.cleanup();
  }
  // copyFileSync PRESERVES the source mode, and postject's inject() opens the
  // target read-write. Homebrew (and Nix) ship `node` as 0555 — no write bit at
  // all — so on the fast path the copy inherits it and injection dies with
  // "Can't read and write to target executable". CI never saw it: setup-node
  // installs 0755. The cross-arch path already chmods its cached base; normalise
  // here so BOTH paths land on the same mode.
  chmodSync(binPath, 0o755);

  // 4. Windows: strip the copied Node binary's existing Authenticode table.
  // Official Windows node.exe builds are already Authenticode-signed. postject
  // changes the PE after that signature was produced; retaining its certificate
  // table leaves a stale security directory that Azure SignTool rejects as
  // ERROR_BAD_EXE_FORMAT instead of replacing. Parse and remove only a valid,
  // EOF certificate table before injection. The final packaged helper is signed
  // later by electron-builder's existing directory/filter signer.
  if (isWin) {
    const stripped = stripPeAuthenticode(readFileSync(binPath));
    if (stripped.removedBytes > 0) {
      writeFileSync(binPath, stripped.image);
      log(`removed pre-injection Authenticode table (${stripped.removedBytes} bytes)`);
    }
  }

  // 5. Inject the blob with postject's PROGRAMMATIC API (not the `npx postject`
  //    CLI). execFileSync cannot spawn `npx` on Windows — npx is `npx.cmd`, and
  //    Node refuses to spawn a .cmd without shell:true (EINVAL), which failed the
  //    Windows build. inject() is cross-platform and needs no child process.
  log("injecting blob (postject.inject)");
  const { inject } = await import("postject");
  await inject(binPath, "NODE_SEA_BLOB", readFileSync(blobPath), {
    sentinelFuse: SENTINEL_FUSE,
    ...(isMac ? { machoSegmentName: "NODE_SEA" } : {}),
  });

  // 6. Validate/re-sign the platform-specific output.
  // A structural, unsigned PE is the exact input contract of the downstream
  // Authenticode signer. Gate the real postject result, not only test fixtures.
  if (isWin) assertUnsignedPeForSigning(readFileSync(binPath));

  // On macOS the injection invalidates the code signature. Do a best-effort
  // ad-hoc re-sign so the binary runs locally; CI performs the real
  // Developer ID signing.
  if (isMac) {
    try {
      log("ad-hoc re-signing (codesign --sign -)");
      execFileSync("codesign", ["--sign", "-", "--force", binPath], {
        stdio: "inherit",
      });
    } catch (err) {
      log(
        `warn: ad-hoc codesign failed (non-fatal): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }

  // Hard-guarantee the produced binary is the target arch (macOS only — `file`
  // reports the Mach-O arch). Turns the previous soft warning into a real gate.
  if (isMac) {
    assertMachOArch(binPath);
  }

  const { size } = statSync(binPath);
  log(`done → ${binPath} (${size} bytes)`);
}

main().catch((err) => {
  process.stderr.write(
    `[build-sea] FAILED: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
  );
  process.exit(1);
});
