import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import fs from "node:fs";

// Invariants for the PUBLISHED bin produced by scripts/build-npm.mjs. The bin
// runs as ROOT on target machines, so a broken/oversized/dependency-leaking
// bundle is a real hazard. This builds the bundle once (no network, no publish)
// and asserts the properties the published tarball relies on.
const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(__dirname, "..", "..");
const buildScript = resolve(pkgRoot, "scripts/build-npm.mjs");
const outfile = resolve(pkgRoot, "dist/bin/agent.js");
const pkgJsonPath = resolve(pkgRoot, "package.json");
const SHEBANG = "#!/usr/bin/env node";

const PROTOCOL_PATTERNS = [
  'from "@aicommander/protocol"',
  "from '@aicommander/protocol'",
  'require("@aicommander/protocol")',
  "require('@aicommander/protocol')",
];

describe("build-npm bundle invariants", () => {
  let code = "";

  beforeAll(() => {
    // Build the bundle deterministically; ~seconds, no network.
    execFileSync("node", [buildScript], { stdio: "ignore" });
    code = fs.readFileSync(outfile, "utf8");
  }, 60_000);

  it("produces dist/bin/agent.js", () => {
    expect(fs.existsSync(outfile)).toBe(true);
  });

  it("starts with exactly one shebang at line 1", () => {
    expect(code.startsWith(`${SHEBANG}\n`)).toBe(true);
    // No second shebang anywhere later in the file.
    const occurrences = code.split("#!/usr/bin/env node").length - 1;
    expect(occurrences).toBe(1);
  });

  it("is mode 0755", () => {
    const mode = fs.statSync(outfile).mode & 0o777;
    expect(mode).toBe(0o755);
  });

  it("inlines @aicommander/protocol (no import/require of it)", () => {
    for (const p of PROTOCOL_PATTERNS) expect(code).not.toContain(p);
  });

  it("runs: --version prints the package version (no protocol error)", () => {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")) as { version: string };
    const out = execFileSync("node", [outfile, "--version"], { encoding: "utf8" }).trim();
    expect(out).toBe(pkg.version);
  });

  it("the published package declares no @aicommander/* runtime dependency", () => {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")) as {
      dependencies?: Record<string, string>;
    };
    const deps = Object.keys(pkg.dependencies ?? {});
    expect(deps.filter((d) => d.startsWith("@aicommander/"))).toEqual([]);
  });
});

describe("published `main` entry is self-contained", () => {
  // PUBLISH-BLOCKER guard: the file that package.json `main` advertises is what
  // a consumer loads via `import "@aicommander/agent"`. It MUST be the bundled,
  // protocol-inlined dist/index.js — NOT a dist/src/*.js that `import`s the
  // dev-only @aicommander/protocol (which would throw ERR_MODULE_NOT_FOUND off
  // the published tarball). Fast/offline: builds the bundle, no real publish.
  let mainPath = "";
  let mainCode = "";

  beforeAll(() => {
    execFileSync("node", [buildScript], { stdio: "ignore" });
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")) as { main: string };
    mainPath = resolve(pkgRoot, pkg.main);
    mainCode = fs.readFileSync(mainPath, "utf8");
  }, 60_000);

  it("main points to a file that exists after build", () => {
    expect(fs.existsSync(mainPath)).toBe(true);
  });

  it("main is the bundled lib entry (dist/index.js), not dist/src/*", () => {
    // The library entry must not live under dist/src (the non-bundled tree whose
    // .js files import @aicommander/protocol).
    expect(mainPath.replace(/\\/g, "/")).toMatch(/\/dist\/index\.js$/);
  });

  it("main contains no @aicommander/protocol import/require", () => {
    for (const p of PROTOCOL_PATTERNS) expect(mainCode).not.toContain(p);
    // Belt-and-suspenders: no bare specifier mention at all.
    expect(mainCode).not.toContain("@aicommander/protocol");
  });
});
