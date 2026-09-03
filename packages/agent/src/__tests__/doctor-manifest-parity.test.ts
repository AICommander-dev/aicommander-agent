// The install manifest's name and schema are DECLARED in
// packages/desktop/src/install-manifest-contract.mjs and MIRRORED in the agent's
// doctor (see doctor/checks/install.ts for why the agent cannot import them: the
// agent ships to npm on its own and must not depend on the desktop package).
//
// A mirror that drifts fails SILENTLY and in the worst direction: the doctor
// looks for a file that is not there, reports "no manifest", and the single most
// valuable check in the command — "80 of your 81 files are missing" — is simply
// switched off with no signal anywhere. Exactly the failure mode the contract
// module was created to prevent, one level up.
//
// Reading across packages follows web-install.test.ts, which pins the same class
// of cross-tree agreement. The check is skipped, not failed, when the desktop
// package is not present — the agent's own tests must still pass in a checkout
// that only has this package.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { MANIFEST_FILENAME, MANIFEST_SCHEMA } from "../doctor/checks/install.js";
import { isManifestEntryPath } from "../doctor/checks/manifest-entry.js";

const contractPath = fileURLToPath(
  new URL("../../../desktop/src/install-manifest-contract.mjs", import.meta.url),
);

function readContract(): string | null {
  try {
    return readFileSync(contractPath, "utf8");
  } catch {
    return null;
  }
}

interface DesktopSide {
  declared: (relative: unknown) => boolean;
  cases: Array<[string, boolean]>;
  nonStrings: unknown[];
}

/** The declaration and the shared table, or null in a checkout without desktop. */
async function loadDesktop(): Promise<DesktopSide | null> {
  try {
    const contractUrl = new URL("../../../desktop/src/install-manifest-contract.mjs", import.meta.url)
      .href;
    const casesUrl = new URL(
      "../../../desktop/src/__tests__/manifest-entry-cases.mjs",
      import.meta.url,
    ).href;
    const contract = (await import(contractUrl)) as {
      isManifestEntryPath?: (p: unknown) => boolean;
    };
    const table = (await import(casesUrl)) as {
      MANIFEST_ENTRY_CASES?: Array<[string, boolean]>;
      MANIFEST_ENTRY_NON_STRINGS?: unknown[];
    };
    if (!contract.isManifestEntryPath || !table.MANIFEST_ENTRY_CASES) return null;
    return {
      declared: contract.isManifestEntryPath,
      cases: table.MANIFEST_ENTRY_CASES,
      nonStrings: table.MANIFEST_ENTRY_NON_STRINGS ?? [],
    };
  } catch {
    return null;
  }
}

describe("install manifest contract parity", () => {
  it("mirrors the desktop contract's file name and schema number", () => {
    const source = readContract();
    if (source === null) {
      // No desktop package in this checkout; nothing to disagree with.
      expect(MANIFEST_FILENAME).toBe("install-manifest.json");
      return;
    }
    const declaredName = /MANIFEST_FILENAME\s*=\s*"([^"]+)"/.exec(source)?.[1];
    const declaredSchema = /MANIFEST_SCHEMA\s*=\s*(\d+)/.exec(source)?.[1];
    expect(declaredName).toBeDefined();
    expect(declaredSchema).toBeDefined();
    expect(MANIFEST_FILENAME).toBe(declaredName);
    expect(MANIFEST_SCHEMA).toBe(Number(declaredSchema));
  });

  // The entry-path rule is the third mirrored thing, and the one with teeth: the
  // readers join an entry onto the install root and then stat (and, here, hash)
  // the result, so a `..` or an absolute entry steers them out of the
  // installation. Both implementations are RUN over one table rather than
  // compared by eye — a rule that disagrees between two readers of one file is
  // how this manifest has already produced two defects.
  //
  // The table is not this file's. It lives beside the declaration, in
  // desktop/src/__tests__/manifest-entry-cases.mjs, and all five readers are run
  // over THAT — see its header for which suite runs which. A table per reader is
  // how five copies of a rule drift while every suite stays green.
  it("mirrors the desktop contract's entry-path rule, case for case", async () => {
    // Variable specifiers: both modules are .mjs OUTSIDE this package's rootDir,
    // so they are imported at run time rather than type-resolved.
    const shared = await loadDesktop();
    if (shared === null) {
      // No desktop package in this checkout; the agent's own tests must still
      // pass, so all that is left is a smoke check of this copy.
      expect(isManifestEntryPath("resources/app.asar")).toBe(true);
      expect(isManifestEntryPath("../outside")).toBe(false);
      expect(isManifestEntryPath(42)).toBe(false);
      return;
    }
    const { declared, cases, nonStrings } = shared;
    expect(cases.length).toBeGreaterThan(20);
    for (const [value, expected] of cases) {
      expect(isManifestEntryPath(value), `agent: ${JSON.stringify(value)}`).toBe(expected);
      expect(declared(value), `contract: ${JSON.stringify(value)}`).toBe(expected);
    }
    // Not a string at all: a manifest is JSON somebody else wrote.
    for (const value of nonStrings) {
      expect(isManifestEntryPath(value)).toBe(false);
      expect(declared(value)).toBe(false);
    }
  });
});
