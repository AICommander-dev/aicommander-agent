#!/usr/bin/env node
/**
 * Provenance gate for the signed Windows exec launcher.
 *
 * This script is the check the PUBLIC mirror runs before publishing
 * `@aicommander/agent`, so it has to be worth the words spent on it in the
 * mirror's README. What it actually proves, and nothing more:
 *
 *   1. The file is a structurally valid x64 PE image. The layout is parsed with
 *      the same strict parser the priv-helper SEA build uses, so a truncated
 *      image, an overlapping section, or an opaque overlay appended after the
 *      certificate table is rejected rather than hashed.
 *   2. If an Authenticode certificate table is present, it is a well-formed
 *      chain of PKCS#7 WIN_CERTIFICATE records ending exactly at EOF.
 *      `--require-authenticode` turns its ABSENCE into a failure. This is a
 *      structural check: the PKCS#7 signature itself is validated by Windows at
 *      load time and by `Get-AuthenticodeSignature` in the private `build-win`
 *      job (which also pins the signer subject and requires an RFC-3161
 *      timestamp). Nothing here re-implements that, and nothing here claims to.
 *   3. The detached `<file>.sig` is a valid Ed25519 signature over the file's
 *      bytes under the release key pinned in `release-key.mjs` — the same key
 *      published at https://aicommander.dev/install.pub and compiled into the
 *      agent's self-update path. THIS is the origin proof: a substituted
 *      launcher cannot be re-signed without the private key, which never leaves
 *      the private release job. A `.sig` that is present is always verified; a
 *      `.sig` that is missing fails under `--require-signature`.
 *
 * A co-committed `.sha256` is not evidence of origin — it travels next to the
 * file it describes and anyone who can replace one can replace the other. It
 * stays in the pipeline as a transport-integrity check only.
 *
 * Everything fails closed: any unmet requirement exits non-zero.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// Cross-package relative import on purpose: the mirror stages packages/agent,
// packages/protocol and packages/priv-helper into the identical layout, and this
// parser has no dependencies of its own.
import { inspectPeAuthenticode } from "../../priv-helper/scripts/pe-authenticode.mjs";
import {
  RELEASE_SIGNING_KEY_PEM,
  RELEASE_SIGNING_KEY_SHA256,
  verifyReleaseSignature,
} from "./release-key.mjs";

const MACHINE_AMD64 = 0x8664;

/**
 * Verify one launcher image. Throws on the first unmet requirement; returns what
 * was proven so a caller can print it.
 */
export function verifyWindowsExecLauncher(bytes, options = {}) {
  const {
    label = "image",
    signature,
    publicKeyPem = RELEASE_SIGNING_KEY_PEM,
    requireAuthenticode = false,
    requireSignature = false,
  } = options;

  if (!Buffer.isBuffer(bytes)) throw new TypeError("launcher image must be a Buffer");

  let layout;
  try {
    layout = inspectPeAuthenticode(bytes);
  } catch (error) {
    throw new Error(`${label} is not a valid PE image: ${error.message}`);
  }

  const peOffset = bytes.readUInt32LE(0x3c);
  const machine = bytes.readUInt16LE(peOffset + 4);
  if (machine !== MACHINE_AMD64) {
    throw new Error(`${label} has PE Machine 0x${machine.toString(16)}, expected x64 0x8664`);
  }

  const authenticode = layout.certificateSize > 0;
  if (requireAuthenticode && !authenticode) {
    throw new Error(`${label} carries no Authenticode certificate table`);
  }

  let signed = false;
  if (signature !== undefined) {
    if (!verifyReleaseSignature(bytes, signature, publicKeyPem)) {
      throw new Error(
        `${label} is not signed by the pinned release key ${RELEASE_SIGNING_KEY_SHA256}`,
      );
    }
    signed = true;
  } else if (requireSignature) {
    throw new Error(`${label} has no detached Ed25519 signature (expected ${label}.sig)`);
  }

  return {
    sha256: createHash("sha256").update(bytes).digest("hex"),
    machine,
    authenticode,
    authenticodeBytes: layout.certificateSize,
    signed,
  };
}

function parseArgs(argv) {
  const options = { requireAuthenticode: false, requireSignature: false };
  let binary;
  let signaturePath;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--require-authenticode") options.requireAuthenticode = true;
    else if (arg === "--require-signature") options.requireSignature = true;
    else if (arg === "--signature") {
      signaturePath = argv[index + 1];
      index += 1;
      if (signaturePath === undefined) throw new Error("--signature needs a path");
    } else if (arg.startsWith("--")) throw new Error(`unknown option ${arg}`);
    else if (binary !== undefined) throw new Error("expected at most one file argument");
    else binary = arg;
  }
  return { options, binary, signaturePath };
}

function main(argv) {
  const here = fileURLToPath(new URL(".", import.meta.url));
  const { options, binary, signaturePath } = parseArgs(argv);
  const target = resolve(binary ?? resolve(here, "../dist-native/aicommander-win-exec-x64.exe"));
  const sigTarget = resolve(signaturePath ?? `${target}.sig`);

  let signature;
  try {
    signature = readFileSync(sigTarget);
  } catch (error) {
    // An unreadable-for-any-other-reason signature must not be mistaken for an
    // absent one; only ENOENT means "there is none".
    if (error.code !== "ENOENT") throw error;
    if (signaturePath !== undefined) {
      throw new Error(`signature ${sigTarget} does not exist`);
    }
  }

  const result = verifyWindowsExecLauncher(readFileSync(target), {
    ...options,
    label: basename(target),
    signature,
  });

  const name = basename(target);
  process.stdout.write(`${result.sha256}  ${name}\n`);
  process.stdout.write(
    `PE Machine 0x${result.machine.toString(16)}; Authenticode certificate table: ` +
      `${result.authenticode ? `present (${result.authenticodeBytes} bytes, validated by Windows at load time)` : "absent"}\n`,
  );
  process.stdout.write(
    result.signed
      ? `Ed25519 release signature: VERIFIED against pinned key ${RELEASE_SIGNING_KEY_SHA256}\n`
      : "Ed25519 release signature: none supplied (not required in this mode)\n",
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
