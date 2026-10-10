import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ensureVerifiedTarball,
  parseExactSha256,
  prepareVerifiedNodeBase,
} from "./node-release-artifact.mjs";

const roots = [];

function tempRoot() {
  const root = mkdtempSync(join(tmpdir(), "aic-node-artifact-test-"));
  roots.push(root);
  return root;
}

function sha256(body) {
  return createHash("sha256").update(body).digest("hex");
}

function response(body, init = {}) {
  const bytes = Buffer.from(body);
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    statusText: init.statusText ?? "OK",
    async arrayBuffer() {
      return Uint8Array.from(bytes).buffer;
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("parseExactSha256", () => {
  const filename = "node-v22.19.0-darwin-x64.tar.gz";
  const wanted = "a".repeat(64);
  const other = "b".repeat(64);

  it("returns the one exact filename entry from an official-format manifest", () => {
    const manifest = `${other}  node-v22.19.0-linux-x64.tar.gz\r\n${wanted.toUpperCase()}  ${filename}\r\n`;
    expect(parseExactSha256(manifest, filename)).toBe(wanted);
  });

  it("does not accept a substring or a missing entry", () => {
    expect(() => parseExactSha256(`${wanted}  ${filename}.sig\n`, filename)).toThrow(
      `checksum manifest has no entry for ${filename}`,
    );
  });

  it("rejects duplicate exact entries even when their hashes agree", () => {
    const manifest = `${wanted}  ${filename}\n${wanted}  ${filename}\n`;
    expect(() => parseExactSha256(manifest, filename)).toThrow(
      `checksum manifest has duplicate entries for ${filename}`,
    );
  });

  it.each([
    [`${"g".repeat(64)}  ${filename}\n`, "non-hex digest"],
    [`${wanted} ${filename}\n`, "wrong separator"],
    [`${wanted}  ${filename} \n`, "trailing filename whitespace"],
    [`${wanted.slice(1)}  ${filename}\n`, "short digest"],
  ])("rejects a malformed manifest (%s)", (manifest) => {
    expect(() => parseExactSha256(manifest, filename)).toThrow(
      "malformed checksum manifest line 1",
    );
  });
});

describe("ensureVerifiedTarball", () => {
  const filename = "node-v22.19.0-darwin-x64.tar.gz";
  const url = `https://nodejs.org/dist/v22.19.0/${filename}`;

  it("hashes and reuses a valid cached tarball without downloading it", async () => {
    const cacheDir = tempRoot();
    const body = Buffer.from("verified cached tarball");
    writeFileSync(join(cacheDir, filename), body);
    const fetchImpl = vi.fn();

    const result = await ensureVerifiedTarball({
      cacheDir,
      filename,
      url,
      expectedSha256: sha256(body),
      fetchImpl,
    });

    expect(result).toEqual({ path: join(cacheDir, filename), downloaded: false });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("does not trust a non-empty corrupt cache entry and replaces it atomically", async () => {
    const cacheDir = tempRoot();
    const goodBody = Buffer.from("official tarball");
    writeFileSync(join(cacheDir, filename), "non-empty but corrupt");
    const fetchImpl = vi.fn(async () => response(goodBody));

    const result = await ensureVerifiedTarball({
      cacheDir,
      filename,
      url,
      expectedSha256: sha256(goodBody),
      fetchImpl,
    });

    expect(result.downloaded).toBe(true);
    expect(readFileSync(result.path)).toEqual(goodBody);
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(readdirSync(cacheDir).some((entry) => entry.startsWith(".download-"))).toBe(false);
  });

  it("fails closed on a downloaded digest mismatch without caching the bad body", async () => {
    const cacheDir = tempRoot();
    writeFileSync(join(cacheDir, filename), "old corrupt cache");

    await expect(
      ensureVerifiedTarball({
        cacheDir,
        filename,
        url,
        expectedSha256: sha256("expected body"),
        fetchImpl: async () => response("different downloaded body"),
      }),
    ).rejects.toThrow("SHA-256 mismatch");

    expect(existsSync(join(cacheDir, filename))).toBe(false);
    expect(readdirSync(cacheDir)).toEqual([]);
  });
});

describe("prepareVerifiedNodeBase", () => {
  it("fetches the exact version manifest and ignores a previously extracted binary", async () => {
    const cacheDir = tempRoot();
    const version = "v22.19.0";
    const dirName = `node-${version}-darwin-x64`;
    const tarballName = `${dirName}.tar.gz`;
    const tarballBody = Buffer.from("synthetic verified tarball");
    const digest = sha256(tarballBody);
    writeFileSync(join(cacheDir, tarballName), tarballBody);

    const legacyNode = join(cacheDir, dirName, "bin", "node");
    mkdirSync(join(cacheDir, dirName, "bin"), { recursive: true });
    writeFileSync(legacyNode, "stale extracted binary");

    const fetchImpl = vi.fn(async (url) => {
      expect(url).toBe(`https://nodejs.org/dist/${version}/SHASUMS256.txt`);
      return response(`${digest}  ${tarballName}\n`);
    });
    const extractImpl = vi.fn((_command, args) => {
      const extractionRoot = args[3];
      const relativeNode = args[4];
      const output = join(extractionRoot, relativeNode);
      mkdirSync(join(extractionRoot, dirName, "bin"), { recursive: true });
      writeFileSync(output, "fresh verified extraction");
    });

    const base = await prepareVerifiedNodeBase({
      cacheDir,
      version,
      platform: "darwin",
      arch: "x64",
      fetchImpl,
      extractImpl,
    });

    expect(base.path).not.toBe(legacyNode);
    expect(base.path).toContain(`${join(cacheDir, ".extract-")}`);
    expect(readFileSync(base.path, "utf8")).toBe("fresh verified extraction");
    expect(readFileSync(legacyNode, "utf8")).toBe("stale extracted binary");
    expect(extractImpl).toHaveBeenCalledOnce();
    base.cleanup();
    expect(existsSync(base.path)).toBe(false);
  });
});
