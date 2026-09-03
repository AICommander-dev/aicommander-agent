// Relay-signed elevated capability — compact-JWS (EdDSA) sign/verify round-trip,
// tamper detection, wrong-key rejection, and expiry-window enforcement.

import { describe, it, expect } from "vitest";

import type { ElevatedCapabilityClaims } from "../messages.js";
import {
  signElevatedCapability,
  verifyElevatedCapability,
  generateCapabilityKeypair,
} from "../capability.js";

function makeClaims(overrides: Partial<ElevatedCapabilityClaims> = {}): ElevatedCapabilityClaims {
  const issuedAt = Date.now();
  return {
    protocolVersion: 1,
    accountId: "acct_abc",
    requestId: "req_123",
    command: "echo hello",
    timeoutMs: 30_000,
    issuedAt,
    expiresAt: issuedAt + 60_000,
    deviceId: "dev_xyz",
    helperInstanceId: "boot_nonce_1",
    cwd: "/tmp",
    env: { FOO: "bar" },
    ...overrides,
  };
}

describe("elevated capability", () => {
  it("round-trips sign -> verify and returns the same claims", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const claims = makeClaims();

    const jws = await signElevatedCapability(claims, privateKeyPkcs8);
    expect(jws.split(".")).toHaveLength(3);

    const verified = await verifyElevatedCapability(jws, publicKeyRaw);
    expect(verified).toEqual(claims);
  });

  it("throws when the payload is tampered with", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const jws = await signElevatedCapability(makeClaims(), privateKeyPkcs8);

    const parts = jws.split(".");
    // Flip a byte in the payload segment.
    const payload = parts[1]!;
    const idx = Math.floor(payload.length / 2);
    const flipped = payload[idx] === "A" ? "B" : "A";
    parts[1] = payload.slice(0, idx) + flipped + payload.slice(idx + 1);
    const tampered = parts.join(".");

    await expect(verifyElevatedCapability(tampered, publicKeyRaw)).rejects.toThrow();
  });

  it("throws when verified against the wrong public key", async () => {
    const signer = await generateCapabilityKeypair();
    const other = await generateCapabilityKeypair();

    const jws = await signElevatedCapability(makeClaims(), signer.privateKeyPkcs8);

    await expect(verifyElevatedCapability(jws, other.publicKeyRaw)).rejects.toThrow();
  });

  it("throws on a malformed token", async () => {
    const { publicKeyRaw } = await generateCapabilityKeypair();
    await expect(verifyElevatedCapability("not-a-jws", publicKeyRaw)).rejects.toThrow(
      /malformed compact JWS/,
    );
  });

  it("enforces expiry relative to opts.now", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const claims = makeClaims();
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);

    // Before expiry -> ok.
    await expect(
      verifyElevatedCapability(jws, publicKeyRaw, { now: claims.issuedAt + 1_000 }),
    ).resolves.toEqual(claims);

    // At/after expiry -> throws.
    await expect(
      verifyElevatedCapability(jws, publicKeyRaw, { now: claims.expiresAt }),
    ).rejects.toThrow(/expired/);
    await expect(
      verifyElevatedCapability(jws, publicKeyRaw, { now: claims.expiresAt + 1 }),
    ).rejects.toThrow(/expired/);
  });

  it("rejects a capability presented before issuedAt (beyond skew)", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const claims = makeClaims();
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);

    await expect(
      verifyElevatedCapability(jws, publicKeyRaw, { now: claims.issuedAt - 120_000 }),
    ).rejects.toThrow(/not yet valid/);
  });

  it("accepts a future-dated capability with the default (Date.now) clock", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const claims = makeClaims({ expiresAt: Date.now() + 60_000 });
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);

    // No opts.now -> uses Date.now(); expiresAt is in the future -> OK.
    await expect(verifyElevatedCapability(jws, publicKeyRaw)).resolves.toEqual(claims);
  });

  it("rejects an expired capability with the default (Date.now) clock", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const issuedAt = Date.now() - 120_000;
    const claims = makeClaims({ issuedAt, expiresAt: issuedAt + 60_000 });
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);

    await expect(verifyElevatedCapability(jws, publicKeyRaw)).rejects.toThrow(/expired/);
  });

  it("throws when expiresAt is missing", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const claims = makeClaims();
    delete (claims as Partial<ElevatedCapabilityClaims>).expiresAt;
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);

    await expect(verifyElevatedCapability(jws, publicKeyRaw)).rejects.toThrow(/expiresAt/);
  });

  it("throws when expiresAt is non-numeric / NaN", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const bad = makeClaims({ expiresAt: "soon" as unknown as number });
    const nan = makeClaims({ expiresAt: NaN });

    const jwsBad = await signElevatedCapability(bad, privateKeyPkcs8);
    const jwsNan = await signElevatedCapability(nan, privateKeyPkcs8);

    await expect(verifyElevatedCapability(jwsBad, publicKeyRaw)).rejects.toThrow(/expiresAt/);
    await expect(verifyElevatedCapability(jwsNan, publicKeyRaw)).rejects.toThrow(/expiresAt/);
  });

  it("throws when a required field (accountId) is missing", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const claims = makeClaims({ expiresAt: Date.now() + 60_000 });
    delete (claims as Partial<ElevatedCapabilityClaims>).accountId;
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);

    await expect(verifyElevatedCapability(jws, publicKeyRaw)).rejects.toThrow(/accountId/);
  });

  it("throws when the header typ is wrong", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    const jws = await signElevatedCapability(makeClaims(), privateKeyPkcs8);

    // Re-sign the same payload under a header with a bad `typ`. A valid signature
    // over a mismatched header must still be rejected before the payload is used.
    const parts = jws.split(".");
    const badHeader = { alg: "EdDSA", typ: "not-aic" };
    const b64url = (o: unknown) =>
      btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const forged = `${b64url(badHeader)}.${parts[1]}.${parts[2]}`;

    // Header tampering breaks the signature too, but the typ check fires first.
    await expect(verifyElevatedCapability(forged, publicKeyRaw)).rejects.toThrow(/typ/);
  });

  it("generateCapabilityKeypair produces a working pair", async () => {
    const { privateKeyPkcs8, publicKeyRaw } = await generateCapabilityKeypair();
    expect(privateKeyPkcs8.length).toBeGreaterThan(0);
    expect(publicKeyRaw.length).toBeGreaterThan(0);

    const claims = makeClaims({ requestId: "req_gen" });
    const jws = await signElevatedCapability(claims, privateKeyPkcs8);
    await expect(verifyElevatedCapability(jws, publicKeyRaw)).resolves.toEqual(claims);
  });
});
