// Validity of the build-pinned Ed25519 public key and the resolver's override
// behavior. We assert the shipped key is a well-formed raw 32-byte Ed25519 public
// key; we deliberately do NOT try to match the Worker's private half (a secret not
// in this repo). The AIC_ELEVATED_PUBKEY env var is saved and restored around the
// override test so it never leaks into other suites.

import { afterEach, describe, expect, it } from "vitest";

import { PINNED_ELEVATED_PUBLIC_KEY, resolvePinnedPublicKey } from "../pinned-key.js";

const ENV_KEY = "AIC_ELEVATED_PUBKEY";

describe("pinned elevated public key", () => {
  const saved = process.env[ENV_KEY];

  afterEach(() => {
    if (saved === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = saved;
  });

  it("is a non-empty base64 string that decodes to exactly 32 bytes", () => {
    expect(PINNED_ELEVATED_PUBLIC_KEY).not.toBe("");
    expect(Buffer.from(PINNED_ELEVATED_PUBLIC_KEY, "base64").length).toBe(32);
  });

  it("resolves to the pinned key when AIC_ELEVATED_PUBKEY is unset", () => {
    delete process.env[ENV_KEY];
    expect(resolvePinnedPublicKey()).toBe(PINNED_ELEVATED_PUBLIC_KEY);
  });

  it("resolves to the override when AIC_ELEVATED_PUBKEY is set", () => {
    process.env[ENV_KEY] = "override-key-value";
    expect(resolvePinnedPublicKey()).toBe("override-key-value");
  });
});
