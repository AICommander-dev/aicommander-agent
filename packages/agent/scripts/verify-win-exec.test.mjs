import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { verifyWindowsExecLauncher } from "./verify-win-exec.mjs";
import { RELEASE_SIGNING_KEY_PEM, RELEASE_SIGNING_KEY_SHA256, keyFingerprint } from "./release-key.mjs";

const SCRIPT = fileURLToPath(new URL("./verify-win-exec.mjs", import.meta.url));
const PE_OFFSET = 0x80;
const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;
const HEADERS_SIZE = 0x200;
const RAW_SIZE = 0x200;
const RAW_OFFSET = HEADERS_SIZE;
const IMAGE_SIZE = 0x2000;
const CERTIFICATE_SIZE = 16;

/** A minimal but structurally valid PE, optionally with an Authenticode table. */
function pe({ machine = 0x8664, certificate = true, filler = 0xcc } = {}) {
  const optionalSize = 0xf0;
  const optionalOffset = PE_OFFSET + 24;
  const securityDirectoryOffset = optionalOffset + 112 + 4 * 8;
  const sectionOffset = optionalOffset + optionalSize;
  const sectionDataEnd = RAW_OFFSET + RAW_SIZE;
  const image = Buffer.alloc(certificate ? sectionDataEnd + CERTIFICATE_SIZE : sectionDataEnd);

  image.writeUInt16LE(0x5a4d, 0);
  image.writeUInt32LE(PE_OFFSET, 0x3c);
  image.writeUInt32LE(0x00004550, PE_OFFSET);
  image.writeUInt16LE(machine, PE_OFFSET + 4);
  image.writeUInt16LE(1, PE_OFFSET + 6);
  image.writeUInt16LE(optionalSize, PE_OFFSET + 20);
  image.writeUInt16LE(0x20b, optionalOffset);
  image.writeUInt32LE(SECTION_ALIGNMENT, optionalOffset + 32);
  image.writeUInt32LE(FILE_ALIGNMENT, optionalOffset + 36);
  image.writeUInt32LE(IMAGE_SIZE, optionalOffset + 56);
  image.writeUInt32LE(HEADERS_SIZE, optionalOffset + 60);
  image.writeUInt32LE(16, optionalOffset + 108);
  image.write(".text\0\0\0", sectionOffset, "ascii");
  image.writeUInt32LE(0x180, sectionOffset + 8);
  image.writeUInt32LE(0x1000, sectionOffset + 12);
  image.writeUInt32LE(RAW_SIZE, sectionOffset + 16);
  image.writeUInt32LE(RAW_OFFSET, sectionOffset + 20);
  image.fill(filler, RAW_OFFSET, sectionDataEnd);

  if (certificate) {
    image.writeUInt32LE(sectionDataEnd, securityDirectoryOffset);
    image.writeUInt32LE(CERTIFICATE_SIZE, securityDirectoryOffset + 4);
    image.writeUInt32LE(12, sectionDataEnd);
    image.writeUInt16LE(0x0200, sectionDataEnd + 4);
    image.writeUInt16LE(0x0002, sectionDataEnd + 6);
    image.writeUInt32LE(0xdecafbad, sectionDataEnd + 8);
  }
  return image;
}

const testKey = generateKeyPairSync("ed25519");
const testKeyPem = testKey.publicKey.export({ type: "spki", format: "pem" });
const signWithTestKey = (bytes) => signEd25519(null, bytes, testKey.privateKey);

const scratch = mkdtempSync(join(tmpdir(), "verify-win-exec-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function runCli(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
}

/** Write a launcher (and optionally a .sig) into a fresh scratch path. */
function stage(name, image, signature) {
  const file = join(scratch, name);
  writeFileSync(file, image);
  if (signature) writeFileSync(`${file}.sig`, signature);
  return file;
}

describe("the pinned release key", () => {
  it("is the key web/install.pub and self-update.ts publish", () => {
    expect(keyFingerprint(RELEASE_SIGNING_KEY_PEM)).toBe(RELEASE_SIGNING_KEY_SHA256);
  });
});

describe("verifyWindowsExecLauncher", () => {
  it("accepts a signed x64 launcher and reports what it proved", () => {
    const image = pe();
    const result = verifyWindowsExecLauncher(image, {
      signature: signWithTestKey(image),
      publicKeyPem: testKeyPem,
      requireAuthenticode: true,
      requireSignature: true,
    });
    expect(result).toMatchObject({ machine: 0x8664, authenticode: true, signed: true });
  });

  // The whole point of the rewrite: a substituted launcher plus a freshly
  // computed .sha256 used to pass. It cannot pass this.
  it("rejects a launcher whose bytes were altered after signing", () => {
    const original = pe();
    const substituted = pe({ filler: 0x90 });
    expect(() =>
      verifyWindowsExecLauncher(substituted, {
        signature: signWithTestKey(original),
        publicKeyPem: testKeyPem,
        requireSignature: true,
      }),
    ).toThrow(/not signed by the pinned release key/);
  });

  it("rejects a signature made with any other key", () => {
    const image = pe();
    const other = generateKeyPairSync("ed25519");
    expect(() =>
      verifyWindowsExecLauncher(image, {
        signature: signEd25519(null, image, other.privateKey),
        publicKeyPem: testKeyPem,
        requireSignature: true,
      }),
    ).toThrow(/not signed by the pinned release key/);
  });

  it("rejects a malformed signature instead of throwing past the caller", () => {
    const image = pe();
    expect(() =>
      verifyWindowsExecLauncher(image, {
        signature: Buffer.from("not a signature"),
        publicKeyPem: testKeyPem,
      }),
    ).toThrow(/not signed by the pinned release key/);
  });

  it("fails closed when no signature is supplied and one is required", () => {
    expect(() => verifyWindowsExecLauncher(pe(), { requireSignature: true })).toThrow(
      /no detached Ed25519 signature/,
    );
  });

  it("fails closed when the Authenticode table is missing and one is required", () => {
    const image = pe({ certificate: false });
    expect(() =>
      verifyWindowsExecLauncher(image, {
        signature: signWithTestKey(image),
        publicKeyPem: testKeyPem,
        requireAuthenticode: true,
      }),
    ).toThrow(/no Authenticode certificate table/);
  });

  it("rejects a non-x64 image", () => {
    expect(() => verifyWindowsExecLauncher(pe({ machine: 0x014c }))).toThrow(/expected x64/);
  });

  it("rejects anything that is not a PE image", () => {
    expect(() => verifyWindowsExecLauncher(Buffer.alloc(4096, 0x41))).toThrow(/not a valid PE image/);
  });
});

describe("verify-win-exec.mjs CLI", () => {
  it("verifies a present .sig against the PINNED key, not a supplied one", () => {
    const image = pe();
    const file = stage("pinned.exe", image, signWithTestKey(image));
    const result = runCli([file]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(RELEASE_SIGNING_KEY_SHA256);
  });

  it("exits non-zero when --require-signature finds no signature", () => {
    const file = stage("unsigned.exe", pe());
    const result = runCli(["--require-signature", file]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/no detached Ed25519 signature/);
  });

  it("exits non-zero when --require-authenticode finds no certificate table", () => {
    const file = stage("nocert.exe", pe({ certificate: false }));
    const result = runCli(["--require-authenticode", file]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/no Authenticode certificate table/);
  });

  it("exits non-zero when an explicitly named signature is absent", () => {
    const file = stage("named.exe", pe());
    const result = runCli(["--signature", join(scratch, "missing.sig"), file]);
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/does not exist/);
  });

  it("still passes the unsigned build-time check the launcher build runs", () => {
    const file = stage("fresh.exe", pe({ certificate: false }));
    const result = runCli([file]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/PE Machine 0x8664/);
    expect(result.stdout).toMatch(/Authenticode certificate table: absent/);
  });

  it("rejects an unknown option rather than ignoring it", () => {
    expect(runCli(["--require-signatures", stage("opt.exe", pe())]).status).toBe(1);
  });
});
