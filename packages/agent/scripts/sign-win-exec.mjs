#!/usr/bin/env node
/**
 * Sign the Windows exec launcher with the Ed25519 release key.
 *
 * Runs in the PRIVATE release workflow only; the key never leaves it. The
 * counterpart is `verify-win-exec.mjs --require-signature`, which the public
 * mirror runs against the key pinned in `release-key.mjs`. This script lives in
 * the mirrored tree on purpose: publishing how the signature is produced costs
 * nothing (the private half is the key, not the procedure) and lets a reader
 * check that the two halves describe the same operation.
 *
 * Usage: AGENT_SIGNING_KEY=<base64 PKCS#8 DER> node sign-win-exec.mjs <file>
 * Writes <file>.sig — a raw detached Ed25519 signature over the file's bytes,
 * identical in form to the `.sig` files the release job publishes to R2 with
 * `openssl pkeyutl -sign -rawin`.
 */
import { createPrivateKey, createPublicKey, sign as signEd25519 } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { keyFingerprint, RELEASE_SIGNING_KEY_SHA256, verifyReleaseSignature } from "./release-key.mjs";

const target = process.argv[2];
if (!target) {
  process.stderr.write("usage: sign-win-exec.mjs <file>\n");
  process.exit(1);
}

const encoded = process.env.AGENT_SIGNING_KEY;
if (!encoded) {
  process.stderr.write("AGENT_SIGNING_KEY is not set\n");
  process.exit(1);
}

const privateKey = createPrivateKey({
  key: Buffer.from(encoded, "base64"),
  format: "der",
  type: "pkcs8",
});
if (privateKey.asymmetricKeyType !== "ed25519") {
  process.stderr.write(`AGENT_SIGNING_KEY must be Ed25519, got ${privateKey.asymmetricKeyType}\n`);
  process.exit(1);
}

// Fail closed on a rotated-but-not-repinned key: a signature nobody can verify
// would sail through here and stop the release in the public mirror instead,
// after the snapshot is already pushed.
const fingerprint = keyFingerprint(createPublicKey(privateKey));
if (fingerprint !== RELEASE_SIGNING_KEY_SHA256) {
  process.stderr.write(
    `AGENT_SIGNING_KEY public half is ${fingerprint}, but release-key.mjs pins ${RELEASE_SIGNING_KEY_SHA256}\n`,
  );
  process.exit(1);
}

const file = resolve(target);
const bytes = readFileSync(file);
const signature = signEd25519(null, bytes, privateKey);
if (!verifyReleaseSignature(bytes, signature, undefined)) {
  process.stderr.write("produced signature does not verify against the pinned key\n");
  process.exit(1);
}
writeFileSync(`${file}.sig`, signature);
process.stdout.write(`signed ${file} with release key ${RELEASE_SIGNING_KEY_SHA256}\n`);
