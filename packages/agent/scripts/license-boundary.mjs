#!/usr/bin/env node
/**
 * The relicense boundary, as a rule a machine can apply.
 *
 * `@aicommander/agent` shipped under MIT up to and including 1.0.56 and is
 * Elastic License 2.0 from 1.1.0 on. That sentence is repeated in four READMEs;
 * until this file existed nothing tied it to the `license` field of the manifest
 * that ships beside it. The tree between releases is the proof that it needed
 * tying: `packages/agent/package.json` already declares `Elastic-2.0` while
 * `version` still reads 1.0.56 — the release script bumps the number, so every
 * commit between two releases carries a manifest that, taken literally,
 * contradicts its own README.
 *
 * That combination is harmless as long as it can never be PUBLISHED, so this is
 * the gate that makes it so:
 *
 *   • scripts/release.mjs runs assertPublishable() on the version it is about to
 *     bump to, so `pnpm release patch` (1.0.57, still declaring ELv2) fails
 *     before it writes anything;
 *   • the mirror's publish.yml runs `--check` on the tagged tree, in public,
 *     before `npm publish`;
 *   • scripts/publish-npm.mjs --check asserts both of those stay wired, and that
 *     the READMEs state the same two version numbers this file does.
 *
 * Usage:  node scripts/license-boundary.mjs --check [<manifest path>]
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The last release published under MIT. Its grant is irrevocable. */
export const LAST_MIT_VERSION = "1.0.56";
/** The first release published under the Elastic License 2.0. */
export const RELICENSE_VERSION = "1.1.0";

export const MIT = "MIT";
export const ELASTIC = "Elastic-2.0";

/** The exact sentence every README states the boundary with. */
export const BOUNDARY_SENTENCE =
  `${LAST_MIT_VERSION} and earlier are MIT; ${RELICENSE_VERSION} and later are Elastic License 2.0`;

const AGENT_MANIFEST = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");

/** Plain semver compare; the versions here are always `x.y.z` (release.mjs
 *  refuses anything else), so no prerelease handling is needed. */
export function compareVersions(a, b) {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

/** Which license a tarball carrying `version` must declare. */
export function expectedLicenseFor(version) {
  return compareVersions(version, RELICENSE_VERSION) >= 0 ? ELASTIC : MIT;
}

/**
 * Why `{ version, license }` may not be published, or null if it may be.
 *
 * Two separate refusals. A version at or below the last MIT release is already
 * on the registry under different terms and cannot be republished at all — that
 * is the state of every between-releases tree, and it is why this returns a
 * reason rather than comparing licenses for it. Above that line, the license
 * field has to be the one the boundary assigns to the number.
 */
export function publishBlocker({ version, license }) {
  if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) {
    return `version must be plain semver, got ${JSON.stringify(version)}`;
  }
  if (compareVersions(version, LAST_MIT_VERSION) <= 0) {
    return (
      `${version} is at or below ${LAST_MIT_VERSION}, the last release published under ${MIT}` +
      ` — it is already on the registry under those terms and cannot be published again` +
      (license === ELASTIC
        ? `; this tree declares ${ELASTIC} because it is staged for ${RELICENSE_VERSION}`
        : "")
    );
  }
  const expected = expectedLicenseFor(version);
  if (license !== expected) {
    return (
      `version ${version} must declare "license": "${expected}" (${BOUNDARY_SENTENCE}), got ${JSON.stringify(license)}` +
      (expected === MIT
        ? ` — release ${RELICENSE_VERSION} or later to publish under ${ELASTIC}`
        : "")
    );
  }
  return null;
}

/** Throw unless `{ version, license }` may be published. */
export function assertPublishable(pair) {
  const blocker = publishBlocker(pair);
  if (blocker) throw new Error(`refusing to publish @aicommander/agent: ${blocker}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const manifestPath = process.argv.find((arg, index) => index > 1 && !arg.startsWith("--")) ?? AGENT_MANIFEST;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const blocker = publishBlocker(manifest);
  if (blocker) {
    console.error(`::error::${manifestPath}: ${blocker}`);
    process.exit(1);
  }
  console.log(`license boundary OK: ${manifest.version} declares ${manifest.license}`);
}
