// Semantic-layer tests for verifyCapabilityForExec + ReplayGuard: mint real
// signed capabilities with a throwaway Ed25519 keypair (pinned via the
// AIC_ELEVATED_PUBKEY override), and assert the boot/replay/version bindings on
// top of the protocol's crypto verification. All clocks are fixed for determinism.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  generateCapabilityKeypair,
  signElevatedCapability,
} from "@aicommander/protocol";
import type { ElevatedCapabilityClaims } from "@aicommander/protocol";

import {
  MIN_PROTOCOL_VERSION,
  ReplayGuard,
  verifyCapabilityForExec,
} from "../capability-verify.js";
import { resolvePinnedPublicKey } from "../pinned-key.js";

const NOW = 1_700_000_000_000;
const BOOT_ID = "boot-aaaa";

let privateKeyPkcs8: string;
let prevPubkey: string | undefined;

beforeAll(async () => {
  const kp = await generateCapabilityKeypair();
  privateKeyPkcs8 = kp.privateKeyPkcs8;
  prevPubkey = process.env["AIC_ELEVATED_PUBKEY"];
  process.env["AIC_ELEVATED_PUBKEY"] = kp.publicKeyRaw;
});

afterAll(() => {
  if (prevPubkey === undefined) delete process.env["AIC_ELEVATED_PUBKEY"];
  else process.env["AIC_ELEVATED_PUBKEY"] = prevPubkey;
});

function baseClaims(over: Partial<ElevatedCapabilityClaims> = {}): ElevatedCapabilityClaims {
  return {
    protocolVersion: MIN_PROTOCOL_VERSION,
    accountId: "acct-1",
    requestId: "req-1",
    command: "whoami",
    timeoutMs: 5_000,
    issuedAt: NOW - 1_000,
    expiresAt: NOW + 60_000,
    ...over,
  };
}

function mint(over: Partial<ElevatedCapabilityClaims> = {}): Promise<string> {
  return signElevatedCapability(baseClaims(over), privateKeyPkcs8);
}

describe("verifyCapabilityForExec", () => {
  it("resolves to the claims for a valid capability whose helperInstanceId matches", async () => {
    const cap = await mint({ helperInstanceId: BOOT_ID });
    const claims = await verifyCapabilityForExec(cap, {
      replay: new ReplayGuard(),
      bootId: BOOT_ID,
      now: NOW,
    });
    expect(claims.requestId).toBe("req-1");
    expect(claims.command).toBe("whoami");
  });

  it("rejects a replay of the same capability against the same guard", async () => {
    const cap = await mint({ helperInstanceId: BOOT_ID });
    const replay = new ReplayGuard();
    await verifyCapabilityForExec(cap, { replay, bootId: BOOT_ID, now: NOW });
    await expect(
      verifyCapabilityForExec(cap, { replay, bootId: BOOT_ID, now: NOW }),
    ).rejects.toThrow(/replay/);
  });

  it("rejects an expired capability", async () => {
    const cap = await mint({ expiresAt: NOW - 1 });
    await expect(
      verifyCapabilityForExec(cap, { replay: new ReplayGuard(), bootId: BOOT_ID, now: NOW }),
    ).rejects.toThrow(/expired/);
  });

  it("rejects a tampered token (bad signature)", async () => {
    const cap = await mint();
    const [h, p, s] = cap.split(".");
    const flipped = p![0] === "A" ? "B" : "A";
    const tampered = `${h}.${flipped}${p!.slice(1)}.${s}`;
    await expect(
      verifyCapabilityForExec(tampered, { replay: new ReplayGuard(), bootId: BOOT_ID, now: NOW }),
    ).rejects.toThrow();
  });

  it("rejects a capability bound to a different helper boot", async () => {
    const cap = await mint({ helperInstanceId: "boot-other" });
    await expect(
      verifyCapabilityForExec(cap, { replay: new ReplayGuard(), bootId: BOOT_ID, now: NOW }),
    ).rejects.toThrow(/not bound to this helper's current boot/);
  });

  it("rejects a capability with NO helperInstanceId (boot binding is required)", async () => {
    const cap = await mint();
    await expect(
      verifyCapabilityForExec(cap, { replay: new ReplayGuard(), bootId: BOOT_ID, now: NOW }),
    ).rejects.toThrow(/not bound to this helper's current boot/);
  });

  it("accepts a capability whose helperInstanceId equals the current bootId", async () => {
    const cap = await mint({ helperInstanceId: BOOT_ID });
    const claims = await verifyCapabilityForExec(cap, {
      replay: new ReplayGuard(),
      bootId: BOOT_ID,
      now: NOW,
    });
    expect(claims.helperInstanceId).toBe(BOOT_ID);
  });

  it("rejects a capability with protocolVersion below the floor", async () => {
    const cap = await mint({ protocolVersion: 0 });
    await expect(
      verifyCapabilityForExec(cap, { replay: new ReplayGuard(), bootId: BOOT_ID, now: NOW }),
    ).rejects.toThrow(/protocolVersion too low/);
  });

  it("falls back to the build-pinned key when the env override is unset, and rejects a foreign signer", async () => {
    // A real helper build ships a non-empty PINNED_ELEVATED_PUBLIC_KEY. With the
    // test override cleared, resolvePinnedPublicKey() returns that pinned key, so
    // a capability signed by OUR throwaway key (a different signer) must FAIL the
    // signature check — the fail-closed property that matters in production.
    const cap = await mint();
    const saved = process.env["AIC_ELEVATED_PUBKEY"];
    delete process.env["AIC_ELEVATED_PUBKEY"];
    try {
      expect(resolvePinnedPublicKey()).not.toBe("");
      await expect(
        verifyCapabilityForExec(cap, { replay: new ReplayGuard(), bootId: BOOT_ID, now: NOW }),
      ).rejects.toThrow(/signature/i);
    } finally {
      if (saved !== undefined) process.env["AIC_ELEVATED_PUBKEY"] = saved;
    }
  });
});

describe("ReplayGuard", () => {
  it("prunes expired ids so a requestId can be reused after its window", () => {
    const guard = new ReplayGuard();
    const t = NOW + 10_000;
    expect(guard.claim("A", t, NOW)).toBe(true);
    // Same id again before expiry → replay.
    expect(guard.claim("A", t, NOW)).toBe(false);
    // After expiry the entry is pruned → fresh again.
    expect(guard.claim("A", t + 20_000, t + 1)).toBe(true);
  });
});
