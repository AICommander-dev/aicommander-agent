// The pinned Ed25519 PUBLIC key the helper verifies relay-signed capabilities
// against. The matching PRIVATE key lives ONLY in the Worker secret
// ELEVATED_SIGNING_KEY. Pinning the public key in the helper build is what makes
// trust relay-anchored: a same-user process cannot forge a capability without the
// Worker's private key.
//
// Resolves the base64 raw 32-byte public key from the build-pinned constant below
// (or the AIC_ELEVATED_PUBKEY override used by tests). Throws (fail-closed) if
// neither is set.

/**
 * Build-time pinned key: base64 of the 32-byte raw Ed25519 PUBLIC key whose
 * PRIVATE half is the Worker secret ELEVATED_SIGNING_KEY. Safe to commit (public
 * half). Rotating the signer means regenerating this pair and shipping a helper
 * build with the new value pinned. `AIC_ELEVATED_PUBKEY` overrides it for tests.
 */
export const PINNED_ELEVATED_PUBLIC_KEY = "8oA4hT5uzYQef+yRhBZ1wr4bAW6gT+qNJuYu7pWT8WU=";

export function resolvePinnedPublicKey(): string {
  const key = process.env["AIC_ELEVATED_PUBKEY"] ?? PINNED_ELEVATED_PUBLIC_KEY;
  if (!key) {
    throw new Error(
      "no pinned elevated public key — this helper build cannot verify capabilities",
    );
  }
  return key;
}
