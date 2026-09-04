import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  createReadStream,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";

/**
 * Return the single checksum for an exact Node release filename.
 *
 * Node's SHASUMS256.txt uses the sha256sum text format: 64 hex digits, two
 * spaces, then the filename. Rejecting every malformed non-empty line keeps a
 * damaged or unexpectedly formatted manifest from being partially trusted.
 */
export function parseExactSha256(manifest, filename) {
  if (typeof manifest !== "string") {
    throw new TypeError("checksum manifest must be text");
  }
  if (!filename || filename !== basename(filename)) {
    throw new Error(`checksum filename must be a basename: ${filename}`);
  }

  const matches = [];
  const lines = manifest.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === "") continue;

    const parsed = /^([0-9a-fA-F]{64})  (\S(?:.*\S)?)$/u.exec(line);
    if (!parsed) {
      throw new Error(`malformed checksum manifest line ${index + 1}`);
    }
    if (parsed[2] === filename) matches.push(parsed[1].toLowerCase());
  }

  if (matches.length === 0) {
    throw new Error(`checksum manifest has no entry for ${filename}`);
  }
  if (matches.length !== 1) {
    throw new Error(`checksum manifest has duplicate entries for ${filename}`);
  }
  return matches[0];
}

export function sha256File(path) {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

async function fetchBody(url, fetchImpl) {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`download failed: ${url} → HTTP ${response.status} ${response.statusText}`);
  }
  const body = Buffer.from(await response.arrayBuffer());
  if (body.length === 0) {
    throw new Error(`download returned empty body: ${url}`);
  }
  return body;
}

async function assertFileDigest(path, expectedSha256) {
  const actualSha256 = await sha256File(path);
  if (actualSha256 !== expectedSha256) {
    throw new Error(
      `SHA-256 mismatch for ${basename(path)}: expected ${expectedSha256}, got ${actualSha256}`,
    );
  }
}

/**
 * Return a verified cached tarball, downloading it through an unpublished
 * temporary file when the cache is absent or corrupt.
 */
export async function ensureVerifiedTarball({
  cacheDir,
  filename,
  url,
  expectedSha256,
  fetchImpl = fetch,
}) {
  if (!/^[0-9a-f]{64}$/u.test(expectedSha256)) {
    throw new Error(`invalid expected SHA-256 for ${filename}`);
  }
  if (!filename || filename !== basename(filename)) {
    throw new Error(`tarball filename must be a basename: ${filename}`);
  }

  mkdirSync(cacheDir, { recursive: true });
  const cachedTarball = join(cacheDir, filename);

  if (existsSync(cachedTarball)) {
    const cachedStat = lstatSync(cachedTarball);
    if (!cachedStat.isFile()) {
      throw new Error(`cached tarball is not a regular file: ${cachedTarball}`);
    }
    try {
      await assertFileDigest(cachedTarball, expectedSha256);
      return { path: cachedTarball, downloaded: false };
    } catch (error) {
      // A bad cache entry must not remain eligible for a future cache hit.
      unlinkSync(cachedTarball);
      if (!(error instanceof Error && error.message.startsWith("SHA-256 mismatch"))) {
        throw error;
      }
    }
  }

  const tempDir = mkdtempSync(join(cacheDir, ".download-"));
  const tempTarball = join(tempDir, filename);
  try {
    const body = await fetchBody(url, fetchImpl);
    writeFileSync(tempTarball, body, { flag: "wx", mode: 0o600 });
    await assertFileDigest(tempTarball, expectedSha256);
    renameSync(tempTarball, cachedTarball);
    return { path: cachedTarball, downloaded: true };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

/**
 * Fetch and verify an official Node tarball, then extract its node executable
 * into a fresh private directory. No previously extracted executable is ever
 * treated as a cache hit; callers must invoke cleanup after copying the base.
 *
 * This verifies the artifact against the exact version's SHASUMS256.txt. It
 * deliberately does not claim manifest signature verification: that requires
 * separately maintained, pinned Node release-key trust material and revocation
 * policy. Fetching a key beside the manifest would not add an independent trust
 * anchor. HTTPS plus the official checksum binds cache/download corruption, but
 * authenticating the manifest itself remains a separate supply-chain control.
 */
export async function prepareVerifiedNodeBase({
  cacheDir,
  version,
  platform,
  arch,
  fetchImpl = fetch,
  extractImpl = execFileSync,
}) {
  const dirName = `node-${version}-${platform}-${arch}`;
  const tarballName = `${dirName}.tar.gz`;
  const releaseBaseUrl = `https://nodejs.org/dist/${version}`;
  const manifestUrl = `${releaseBaseUrl}/SHASUMS256.txt`;
  const tarballUrl = `${releaseBaseUrl}/${tarballName}`;

  const manifest = (await fetchBody(manifestUrl, fetchImpl)).toString("utf8");
  const expectedSha256 = parseExactSha256(manifest, tarballName);
  const tarball = await ensureVerifiedTarball({
    cacheDir,
    filename: tarballName,
    url: tarballUrl,
    expectedSha256,
    fetchImpl,
  });

  // Hash again immediately before extraction. Besides making the security gate
  // explicit, this catches modification between cache publication and use.
  await assertFileDigest(tarball.path, expectedSha256);

  const extractionRoot = mkdtempSync(join(cacheDir, ".extract-"));
  const relativeNodePath = join(dirName, "bin", "node");
  const extractedNode = join(extractionRoot, relativeNodePath);
  try {
    extractImpl("tar", ["-xzf", tarball.path, "-C", extractionRoot, relativeNodePath], {
      stdio: "inherit",
    });
    if (!existsSync(extractedNode)) {
      throw new Error(`extraction produced no regular node binary at ${extractedNode}`);
    }
    const extractedStat = lstatSync(extractedNode);
    if (!extractedStat.isFile()) {
      throw new Error(`extraction produced no regular node binary at ${extractedNode}`);
    }
    if (extractedStat.size === 0) {
      throw new Error(`extraction produced an empty node binary at ${extractedNode}`);
    }
    chmodSync(extractedNode, 0o755);
  } catch (error) {
    rmSync(extractionRoot, { recursive: true, force: true });
    throw error;
  }

  return {
    path: extractedNode,
    expectedSha256,
    downloaded: tarball.downloaded,
    cleanup() {
      rmSync(extractionRoot, { recursive: true, force: true });
    },
  };
}
