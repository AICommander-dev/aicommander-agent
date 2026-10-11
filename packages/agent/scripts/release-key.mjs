import { createHash, createPublicKey, verify as verifyEd25519 } from "node:crypto";

/**
 * The AI Commander release signing key (Ed25519), pinned in source.
 *
 * Byte-identical to `web/install.pub`, to `AGENT_PUBKEY_PEM` in `web/install`,
 * and to `RELEASE_SIGNING_KEY_PEM` in `packages/agent/src/self-update.ts` — the
 * same key that signs the agent binaries, the install script, and the release
 * installers. Pinning it here is what makes the public mirror's launcher check
 * an origin check rather than a self-referential checksum: the mirror holds no
 * secrets, so it cannot produce a signature, only reject one.
 */
export const RELEASE_SIGNING_KEY_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAcqNx01NvglpKTsF60Yij5LuoIHgXJ/SUoQysfU2eyRw=\n" +
  "-----END PUBLIC KEY-----\n";

/** SHA-256 of the SPKI DER — the fingerprint README publishes out of band. */
export const RELEASE_SIGNING_KEY_SHA256 =
  "2d76d381fc8ed38e7dfb53882e14b2980ee105e0b49ff31cf55403e19e648407";

/** Fingerprint of a public key, in the form README publishes. */
export function keyFingerprint(publicKey) {
  const key = typeof publicKey === "string" ? createPublicKey(publicKey) : publicKey;
  const der = key.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

/**
 * The pinned key as a KeyObject. A typo in the PEM above must fail here, loudly,
 * rather than silently pin a key nobody holds — which would reject every genuine
 * artifact, or (worse, if the typo were adversarial) accept a forged one.
 */
export function releaseSigningKey(pem = RELEASE_SIGNING_KEY_PEM) {
  const key = createPublicKey(pem);
  if (pem === RELEASE_SIGNING_KEY_PEM) {
    const fingerprint = keyFingerprint(key);
    if (fingerprint !== RELEASE_SIGNING_KEY_SHA256) {
      throw new Error(
        `pinned release key fingerprint is ${fingerprint}, expected ${RELEASE_SIGNING_KEY_SHA256}`,
      );
    }
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(`release signing key must be Ed25519, got ${key.asymmetricKeyType}`);
  }
  return key;
}

/**
 * Ed25519 over the raw bytes, matching the detached `.sig` the release job
 * produces (`openssl pkeyutl -sign -rawin`, and `sign-win-exec.mjs`).
 *
 * Returns false rather than throwing for a malformed signature: a corrupt
 * signature and a wrong one mean the same thing to the caller — do not trust
 * these bytes.
 */
export function verifyReleaseSignature(bytes, signature, publicKeyPem) {
  try {
    return verifyEd25519(null, bytes, releaseSigningKey(publicKeyPem), signature);
  } catch {
    return false;
  }
}
