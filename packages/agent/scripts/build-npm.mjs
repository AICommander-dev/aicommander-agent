// Build self-contained published entries for `@aicommander/agent`.
//
// esbuild bundles each entry plus all of src AND @aicommander/protocol (inlined
// from SOURCE, so protocol need not be pre-built) into a single ESM file. Only
// the real runtime deps (chalk, commander, ora, ws) stay external.
//
// Two outputs:
//   • dist/bin/agent.js  — the executable CLI (`bin`), gets a shebang + chmod.
//   • dist/index.js      — the library entry (`main`). PUBLISH-CRITICAL: the
//     non-bundled dist/src/*.js all `import "@aicommander/protocol"`, which is
//     only a devDependency, so a consumer doing `import "@aicommander/agent"`
//     against the PUBLISHED tarball would fail with ERR_MODULE_NOT_FOUND. The
//     bundled dist/index.js inlines protocol so `main` resolves with no
//     @aicommander/* dependency. src/index.ts is pure re-exports (no top-level
//     side effects), so it is safe as the library entry.
//
// Keeping ws external avoids bundling its optional native deps
// (bufferutil/utf-8-validate).
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import fs from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(__dirname, "..");
const repoRoot = resolve(pkgRoot, "..", "..");

const protocolSrc = resolve(repoRoot, "packages/protocol/src/index.ts");
const EXTERNAL = ["chalk", "commander", "ora", "ws"];

const binEntry = resolve(pkgRoot, "bin/agent.ts");
const binOut = resolve(pkgRoot, "dist/bin/agent.js");
const libEntry = resolve(pkgRoot, "src/index.ts");
const libOut = resolve(pkgRoot, "dist/index.js");
const libTypesOut = resolve(pkgRoot, "dist/index.d.ts");

async function bundle(entryPoints, outfile) {
  await build({
    entryPoints: [entryPoints],
    outfile,
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node18",
    // NOT minified. This package spawns shells with input received over a
    // network socket — that is its advertised purpose, and it is why an
    // automated scanner classified it as malware (OSV MAL-2026-10708). A
    // single-line minified bundle doing that is the exact shape those
    // heuristics look for, and it stops a human reviewer reading what they
    // install. Minification buys nothing for a CLI installed locally on Node:
    // no download budget, no parse budget that matters at process start.
    minify: false,
    external: EXTERNAL,
    alias: {
      "@aicommander/protocol": protocolSrc,
    },
  });
}

// ── Library entry (`main`) ──────────────────────────────────────────────────
await bundle(libEntry, libOut);
console.log(`✓ Bundled published lib → ${libOut}`);

// Ship a flat `types` entry alongside it. dist/index.d.ts re-exports the type
// surface from the tsc-emitted dist/src/*.d.ts tree (also shipped, type-only —
// their `import type … "@aicommander/protocol"` carries no runtime risk and
// there are no external TS consumers of this CLI package). The WORKSPACE
// consumer (desktop) resolves `@aicommander/agent` types through this file too.
fs.writeFileSync(libTypesOut, `export * from "./src/index.js";\n`);
console.log(`✓ Wrote published types → ${libTypesOut}`);

// ── Executable CLI (`bin`) ──────────────────────────────────────────────────
await bundle(binEntry, binOut);

// Normalise the shebang in a post-build step (NOT via esbuild's `banner`): strip
// any leading shebang line(s) esbuild carried over from bin/agent.ts, then
// prepend exactly one `#!/usr/bin/env node` at line 1. This guarantees the
// output starts with a single, valid shebang regardless of the entry's content,
// and chmod 0755 makes it directly executable.
const SHEBANG = "#!/usr/bin/env node";
let code = fs.readFileSync(binOut, "utf8");
code = code.replace(/^(#![^\n]*\n)+/, "");
fs.writeFileSync(binOut, `${SHEBANG}\n${code}`);

fs.chmodSync(binOut, 0o755);
console.log(`✓ Bundled published bin → ${binOut}`);
