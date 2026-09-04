// The README's opening block makes factual claims to anyone deciding whether
// this package is safe to install — and to the automated scanners that classify
// it. They are answers to OSV MAL-2026-10708, so they must be true of the
// ARTIFACT, not just of the prose, and narrower rather than broader: an
// overstated claim in a malware rebuttal is worse than a missing one. This suite
// ships in the public mirror on purpose: the claims are checkable by whoever is
// doing the deciding.
//
// Every assertion here is therefore scoped to the disclosure block itself, or
// made against the code, the manifest, or the built bundle. Grepping the whole
// README for a phrase the disclosure supplies proves only that someone typed it
// — that is exactly how a claim that turned out to be FALSE (see the relay test
// below) stayed green for a release.

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  BOUNDARY_SENTENCE,
  LAST_MIT_VERSION,
  RELICENSE_VERSION,
  expectedLicenseFor,
  publishBlocker,
} from "../../scripts/license-boundary.mjs";

const path = (relative: string) => fileURLToPath(new URL(relative, import.meta.url));
const read = (relative: string) => readFileSync(path(relative), "utf8");

const manifest = JSON.parse(read("../../package.json")) as {
  version: string;
  license: string;
  files?: string[];
  scripts?: Record<string, string>;
};
const readme = read("../../README.md");

/**
 * The dual-use disclosure: the leading blockquote, and nothing else. Assertions
 * made against the whole README are satisfied by prose that predates the
 * disclosure elsewhere in the file, which would let the entire block be deleted
 * with the tests still green.
 */
function disclosureBlock(source: string): string {
  const lines = source.split("\n");
  const start = lines.findIndex((line) => line.startsWith(">"));
  expect(start, "the README has no leading blockquote to hold the disclosure").toBeGreaterThan(-1);
  const end = lines.findIndex((line, index) => index > start && !line.startsWith(">"));
  return lines.slice(start, end === -1 ? undefined : end).join("\n");
}

const disclosure = disclosureBlock(readme);

describe("what the README's dual-use disclosure promises about this package", () => {
  it("runs no code on install, and says so no more broadly than that", () => {
    // npm runs these four without being asked. `prepare` is the one that was
    // missing here: npm runs it for a git or directory install — the very route
    // the disclosure points readers at when it links the public source.
    // `prepublish` is deprecated but npm still runs it in install/CI paths, so a
    // claim about what happens on install has to cover it too.
    for (const hook of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) {
      expect(manifest.scripts?.[hook], `package.json defines a ${hook} script`).toBeUndefined();
    }
    expect(disclosure).toMatch(/Nothing in this package runs on install/);
    for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
      expect(disclosure, `the disclosure does not name the ${hook} hook`).toContain(`\`${hook}\``);
    }
    // The claim proved by the four hooks above is about THIS package only. The
    // absence of lifecycle scripts says nothing about a dependency's install
    // scripts or about the registry fetch itself, and the disclosure may not
    // read as though it did.
    expect(
      disclosure,
      "the install claim must stay scoped to this package",
    ).toMatch(/claim about THIS package and nothing else/);
    expect(disclosure, "the disclosure must not omit dependency install scripts").toMatch(
      /dependency remains\s+>?\s*free to run its own install scripts/,
    );
    expect(disclosure).toContain("--ignore-scripts");
  });

  it("describes the relay host-lock as it actually behaves", () => {
    // This replaces a claim that was WRONG and shipped: the README said the relay
    // was "a default, not a destination" and that AICOMMANDER_SERVER pointed the
    // agent at a relay you host yourself. resolveTrustedServerUrl() host-locks to
    // DEFAULT_SERVER and IGNORES any other origin unless it is loopback or
    // AICOMMANDER_DEV is set — good hardening for a root process, and the
    // opposite of what was written.
    //
    // So this asserts against the CODE, not against the disclosure's own words.
    const relayUrl = read("../relay-url.ts");
    expect(relayUrl).toMatch(/host-lock/i);
    expect(disclosure).toMatch(/host-locked/);
    // Wrapped across lines inside a blockquote, so match on words not bytes.
    expect(disclosure).toMatch(/no\s+>?\s*self-hosted relay deployment today/);
    expect(readme, "the retracted claim must not come back").not.toMatch(
      /relay is a default, not a destination/,
    );
  });

  it("names the session code for what it is, in the disclosure itself", () => {
    // Understating this is what would make the disclosure dishonest. The same
    // words appear in the Security section further down, which is why this is
    // scoped to the block: otherwise deleting the block changes nothing here.
    expect(disclosure).toMatch(/session code is a \*\*root-exec credential\*\*/);

    // ...and the prose is pinned to the behaviour that makes it true, not left
    // to stand on its own. The executor really does hand the received command to
    // a shell; if that ever stopped being so, this wording would be the thing to
    // revisit, and this assertion is what would say so.
    const executor = read("../executor.ts");
    expect(executor, "the executor no longer spawns through a shell").toMatch(
      /shell:\s*plan\.posixShell/,
    );
    expect(executor).toMatch(/spawn\(/);
  });

  it("publishes a reviewable, unminified bundle — checked against the build output", () => {
    // Promised in writing to ossf/malicious-packages and Amazon Inspector. The
    // guard that used to back it grepped the BUILD SCRIPT for `minify: false`
    // and lived in a file the mirror never receives, so the one claim that is
    // about the artifact had no check the readers of the disclosure could run.
    // This one reads what the build actually produced.
    for (const bundle of ["../../dist/index.js", "../../dist/bin/agent.js"]) {
      expect(
        existsSync(path(bundle)),
        `${bundle} has not been built — run \`pnpm build\` before \`pnpm test\``,
      ).toBe(true);
      const code = read(bundle);
      const lines = code.split("\n");
      // A minified esbuild bundle is one or a handful of enormous lines.
      expect(lines.length, `${bundle} is not line-broken`).toBeGreaterThan(1000);
      expect(
        code.length / lines.length,
        `${bundle} averages more than 120 characters per line`,
      ).toBeLessThan(120);
      // Minification strips comments; esbuild keeps the originating path above
      // each inlined section, which is what makes the bundle readable at all.
      expect(code, `${bundle} carries no source-path comments`).toMatch(/\n\/\/ (\.\.\/)?src\//);
      // Identifiers survive: a minifier would have renamed this one.
      expect(code, `${bundle} has renamed identifiers`).toContain("resolveTrustedServerUrl");
    }
    expect(disclosure).toMatch(/The published bundle is unminified/);
  });

  it("discloses the one prebuilt binary in the tarball", () => {
    // `files` ships a Windows executable that is NOT built from the tarball: it
    // is compiled and signed in CI and injected as an artifact. In a document
    // answering a malware classification, an unmentioned opaque executable is
    // the first thing a skeptical reader finds.
    // Ask npm what it would actually pack, not what the allowlist spells: a
    // binary nested under a directory entry like `dist/bin` is inside `files`
    // without appearing in it, and would evade a manifest-string check.
    const packed = JSON.parse(
      execFileSync("npm", ["pack", "--dry-run", "--json"], {
        cwd: fileURLToPath(new URL("../..", import.meta.url)),
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
    ) as [{ files: { path: string }[] }];
    const binaries = packed[0].files
      .map((file) => file.path)
      .filter((path) => /\.(exe|node|dll|dylib|so)$/.test(path))
      .sort();
    // Subset, not equality: the launcher is compiled and signed in CI and
    // injected as an artifact, so it is absent from a local checkout and this
    // list is empty here while it holds exactly that one entry on the release
    // runner. What must hold in BOTH places is that nothing packs a binary the
    // disclosure does not name.
    const disclosed = ["dist-native/aicommander-win-exec-x64.exe"];
    expect(
      binaries.filter((path) => !disclosed.includes(path)),
      "an undisclosed binary is in the published tarball",
    ).toEqual([]);
    // And the allowlist itself must not grow a second one.
    expect(
      (manifest.files ?? []).filter((entry) => /\.(exe|node|dll|dylib|so)$/.test(entry)),
    ).toEqual(disclosed);
    expect(disclosure).toContain("dist-native/aicommander-win-exec-x64.exe");
    expect(disclosure, "the disclosure must say the binary is not built from the tarball").toMatch(
      /NOT built from the tarball/,
    );
    // The verification the disclosure promises has to be the one that exists.
    expect(disclosure).toContain("--require-signature");
    expect(disclosure).toContain("--require-authenticode");
    const verify = read("../../scripts/verify-win-exec.mjs");
    expect(verify).toContain('arg === "--require-authenticode"');
    expect(verify).toContain('arg === "--require-signature"');
    // Its source is public, in this repository, next to everything else.
    expect(existsSync(path("../../native/win-exec-launcher/main.cpp"))).toBe(true);
    expect(disclosure).toContain("packages/agent/native/win-exec-launcher/");
  });
});

describe("the licenses the tarball ships under", () => {
  it("carries the MIT notice for the sources esbuild inlines into the bundle", () => {
    // packages/protocol is MIT and is compiled INTO this Elastic-2.0 tarball, so
    // the tarball is a copy of MIT-licensed code and MIT requires its notice to
    // travel with it. Proven against the build output, not the build script.
    const bundle = read("../../dist/index.js");
    expect(bundle, "the bundle no longer inlines packages/protocol").toMatch(
      /\n\/\/ \.\.\/protocol\/src\//,
    );

    expect(manifest.files).toContain("THIRD-PARTY-NOTICES.txt");
    const notices = read("../../THIRD-PARTY-NOTICES.txt");
    expect(notices).toContain("@aicommander/protocol");
    expect(notices).toContain("MIT License");
    expect(notices).toContain("Permission is hereby granted, free of charge");
    expect(notices).toContain(
      "The above copyright notice and this permission notice shall be included in all",
    );
    // priv-helper is inlined too; it is Elastic-2.0, the same terms as this
    // package, and the notice has to say which component is under which.
    expect(notices).toContain("@aicommander/priv-helper");
    expect(readme).toContain("THIRD-PARTY-NOTICES.txt");
  });

  it("describes the launcher's CRT the way its project file links it", () => {
    // "links only the Microsoft Visual C++ runtime supplied by Windows" was
    // false: /MT compiles Microsoft's CRT INTO the shipped executable. The claim
    // is pinned to the setting that decides it, not to the sentence itself.
    const vcxproj = read("../../native/win-exec-launcher/win-exec-launcher.vcxproj");
    expect(vcxproj).toContain("<RuntimeLibrary>MultiThreaded</RuntimeLibrary>");
    expect(vcxproj).not.toContain("<RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>");
    const notices = read("../../THIRD-PARTY-NOTICES.txt");
    expect(notices).toContain("<RuntimeLibrary>MultiThreaded</RuntimeLibrary>");
    expect(notices).toMatch(/linked STATICALLY into that executable/);
    expect(notices, "the CRT is compiled in, not supplied by the OS").not.toContain(
      "runtime supplied by Windows",
    );
  });

  it("cannot publish a manifest whose license contradicts the stated boundary", () => {
    // The boundary is a version number, and until license-boundary.mjs existed
    // nothing tied it to the `license` FIELD: this tree is 1.0.56 — the last MIT
    // release — with `"license": "Elastic-2.0"`, because the release script
    // bumps the number. Harmless only while that combination cannot be shipped.
    expect(expectedLicenseFor(LAST_MIT_VERSION)).toBe("MIT");
    expect(expectedLicenseFor("1.0.99")).toBe("MIT");
    expect(expectedLicenseFor(RELICENSE_VERSION)).toBe("Elastic-2.0");
    expect(expectedLicenseFor("2.0.0")).toBe("Elastic-2.0");
    expect(readme).toContain(BOUNDARY_SENTENCE);

    const blocker = publishBlocker(manifest);
    if (manifest.version === LAST_MIT_VERSION) {
      // A development tree: publishing is refused outright, and the README says
      // so rather than leaving the reader to notice the contradiction.
      expect(blocker, "1.0.56 is already published under MIT and must not be publishable").toBeTruthy();
      expect(readme).toContain("scripts/license-boundary.mjs");
    } else {
      // A release tree (the mirror at a tag): the manifest itself must agree.
      expect(blocker, blocker ?? "").toBeNull();
      expect(manifest.license).toBe(expectedLicenseFor(manifest.version));
    }
  });
});
