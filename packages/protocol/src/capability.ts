// Relay-signed elevated capability — compact JWS (EdDSA / Ed25519).
//
// TRUST MODEL
// -----------
// An elevated command is authorized by the relay (the trusted server), which
// signs an `ElevatedCapabilityClaims` object with its Ed25519 private key and
// hands the resulting compact JWS down the wire. The privileged HELPER on the
// target machine is the ONLY party that verifies the signature (with the pinned
// public key) before running the command as root / LocalSystem. Everything in
// between — the Durable Object, the agent, the local IPC hop — treats the JWS as
// an opaque, tamper-evident token and never trusts its contents.
//
// This module implements ONLY the cryptographic and structural half of that
// contract. On the verify side it FAILS CLOSED, checking, in order:
//   - the compact-JWS structure (exactly three segments);
//   - the protected header: `alg` MUST be `EdDSA` AND `typ` MUST be
//     `aic-elevated+jws`;
//   - the Ed25519 signature over `header.payload` with the pinned public key;
//   - the payload SHAPE: every required claim is present and well-typed —
//     `protocolVersion`/`timeoutMs`/`issuedAt`/`expiresAt` are finite numbers
//     (NaN/Infinity/undefined rejected), `timeoutMs` > 0, `accountId`/
//     `requestId`/`command` are strings, and the optional `cwd`/`deviceId`/
//     `helperInstanceId`/`env` fields — when present — are the right type;
//   - the expiry window, ALWAYS (never conditional): `now` defaults to
//     `Date.now()` when `opts.now` is omitted, so a token is rejected once
//     `expiresAt <= now`, or before `issuedAt - CLOCK_SKEW_MS`.
// It deliberately does NOT enforce the SEMANTIC bindings that make a capability
// single-use and machine-bound. The caller (the helper) is responsible for:
//   - anti-replay: rejecting a `requestId` it has already executed;
//   - helper boot challenge: matching `helperInstanceId` against its own
//     current boot nonce;
//   - device binding: matching `deviceId` against its own identity;
//   - account/protocol-version policy as appropriate.
// Local IPC transport security (e.g. a unix socket / named pipe with restricted
// ACLs) is channel hygiene only — it is NOT part of this authorization and does
// not substitute for verifying the signature here.
//
// Runs on pure WebCrypto (`crypto.subtle`) so the same code works in Cloudflare
// Workers and Node 20+. No npm dependencies, no `node:crypto`.

import type { ElevatedCapabilityClaims } from "./messages.js";

const JWS_TYP = "aic-elevated+jws";
const JWS_ALG = "EdDSA";
/** Tolerated forward clock skew (ms) between relay and helper for issuedAt. */
const CLOCK_SKEW_MS = 60_000;

interface JwsProtectedHeader {
  alg: string;
  typ?: string;
}

// --- base64 / base64url helpers (no dependencies) ---------------------------

function bytesToBinary(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return s;
}

function binaryToBytes(binary: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64Encode(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

function base64Decode(b64: string): Uint8Array<ArrayBuffer> {
  return binaryToBytes(atob(b64));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(b64url: string): Uint8Array<ArrayBuffer> {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad === 1) throw new Error("invalid base64url string");
  return base64Decode(b64);
}

function utf8Encode(s: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(s);
  const out = new Uint8Array(encoded.length);
  out.set(encoded);
  return out;
}

function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// --- payload shape validation -----------------------------------------------

/**
 * Validate the decoded JSON payload against `ElevatedCapabilityClaims` and
 * return it typed, or THROW on the first violation (fail-closed). Uses
 * `Number.isFinite` for every numeric field so NaN / Infinity / undefined are
 * all rejected — never trust `typeof x === "number"`, which admits NaN.
 */
function validateClaims(raw: unknown): ElevatedCapabilityClaims {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("elevated capability payload is not an object");
  }
  const c = raw as Record<string, unknown>;

  if (!Number.isFinite(c.protocolVersion)) {
    throw new Error("elevated capability: protocolVersion must be a finite number");
  }
  if (typeof c.accountId !== "string" || c.accountId.length === 0) {
    throw new Error("elevated capability: accountId must be a non-empty string");
  }
  if (typeof c.requestId !== "string" || c.requestId.length === 0) {
    throw new Error("elevated capability: requestId must be a non-empty string");
  }
  if (typeof c.command !== "string") {
    throw new Error("elevated capability: command must be a string");
  }
  if (!Number.isFinite(c.timeoutMs) || (c.timeoutMs as number) <= 0) {
    throw new Error("elevated capability: timeoutMs must be a finite number > 0");
  }
  if (!Number.isFinite(c.issuedAt)) {
    throw new Error("elevated capability: issuedAt must be a finite number");
  }
  if (!Number.isFinite(c.expiresAt)) {
    throw new Error("elevated capability: expiresAt must be a finite number");
  }
  if (c.cwd !== undefined && typeof c.cwd !== "string") {
    throw new Error("elevated capability: cwd must be a string when present");
  }
  if (c.deviceId !== undefined && typeof c.deviceId !== "string") {
    throw new Error("elevated capability: deviceId must be a string when present");
  }
  if (c.helperInstanceId !== undefined && typeof c.helperInstanceId !== "string") {
    throw new Error("elevated capability: helperInstanceId must be a string when present");
  }
  if (c.env !== undefined) {
    if (typeof c.env !== "object" || c.env === null || Array.isArray(c.env)) {
      throw new Error("elevated capability: env must be an object when present");
    }
    for (const v of Object.values(c.env as Record<string, unknown>)) {
      if (typeof v !== "string") {
        throw new Error("elevated capability: env values must be strings");
      }
    }
  }

  return raw as ElevatedCapabilityClaims;
}

// --- key import -------------------------------------------------------------

async function importSigningKey(privateKeyPkcs8: string): Promise<CryptoKey> {
  const pkcs8 = base64Decode(privateKeyPkcs8);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

async function importVerifyingKey(publicKeyRaw: string): Promise<CryptoKey> {
  const raw = base64Decode(publicKeyRaw);
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

// --- public API -------------------------------------------------------------

/**
 * Sign `claims` as a compact JWS with protected header
 * `{"alg":"EdDSA","typ":"aic-elevated+jws"}`.
 *
 * @param privateKeyPkcs8 base64 (standard, not url) of the raw Ed25519 private
 *   key in PKCS8 format.
 * @returns `base64url(header) + "." + base64url(payload) + "." + base64url(sig)`.
 */
export async function signElevatedCapability(
  claims: ElevatedCapabilityClaims,
  privateKeyPkcs8: string,
): Promise<string> {
  const key = await importSigningKey(privateKeyPkcs8);

  const header: JwsProtectedHeader = { alg: JWS_ALG, typ: JWS_TYP };
  const encodedHeader = base64UrlEncode(utf8Encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(utf8Encode(JSON.stringify(claims)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, utf8Encode(signingInput));
  const encodedSig = base64UrlEncode(new Uint8Array(sig));

  return `${signingInput}.${encodedSig}`;
}

/**
 * Verify a compact JWS and return the validated claims, or THROW on a bad
 * signature / malformed token.
 *
 * FAILS CLOSED. It checks the Ed25519 signature, the protected header (`alg`
 * must be `EdDSA` AND `typ` must be `aic-elevated+jws`), the FULL payload shape
 * (all required claims present and well-typed, timestamps finite, `timeoutMs`
 * finite and > 0), and the expiry window ALWAYS — `opts.now` defaults to
 * `Date.now()`, so a token with a past `expiresAt` (or a missing / non-numeric
 * `expiresAt`/`issuedAt`) is rejected, never treated as never-expiring.
 *
 * The SEMANTIC bindings (anti-replay via `requestId`, `helperInstanceId`
 * boot-challenge match, `deviceId` match, account/protocol-version policy) are
 * NOT enforced here; the caller (the privileged helper) MUST enforce them.
 *
 * @param publicKeyRaw base64 (standard) of the 32-byte raw Ed25519 public key.
 * @param opts.now epoch ms to check `expiresAt`/`issuedAt` against; defaults to
 *   `Date.now()` (works in Workers and Node). The time check is never skipped.
 */
export async function verifyElevatedCapability(
  jws: string,
  publicKeyRaw: string,
  opts?: { now?: number },
): Promise<ElevatedCapabilityClaims> {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("malformed compact JWS");
  const encodedHeader = parts[0]!;
  const encodedPayload = parts[1]!;
  const encodedSig = parts[2]!;

  let header: JwsProtectedHeader;
  try {
    header = JSON.parse(utf8Decode(base64UrlDecode(encodedHeader)));
  } catch {
    throw new Error("malformed JWS header");
  }
  if (header.alg !== JWS_ALG) throw new Error(`unsupported JWS alg: ${String(header.alg)}`);
  if (header.typ !== JWS_TYP) throw new Error(`unsupported JWS typ: ${String(header.typ)}`);

  const key = await importVerifyingKey(publicKeyRaw);
  const signingInput = utf8Encode(`${encodedHeader}.${encodedPayload}`);
  const sig = base64UrlDecode(encodedSig);

  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, signingInput);
  if (!ok) throw new Error("invalid elevated capability signature");

  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(base64UrlDecode(encodedPayload)));
  } catch {
    throw new Error("malformed elevated capability payload");
  }

  const claims = validateClaims(parsed);

  // Expiry is enforced ALWAYS — `issuedAt`/`expiresAt` are already validated as
  // finite numbers, so no typeof-guard can skip the check.
  const now = opts?.now ?? Date.now();
  if (claims.expiresAt <= now) {
    throw new Error("elevated capability expired");
  }
  if (now < claims.issuedAt - CLOCK_SKEW_MS) {
    throw new Error("elevated capability not yet valid");
  }

  return claims;
}

/**
 * Dev/test only: generate an Ed25519 keypair as base64 strings —
 * `privateKeyPkcs8` (PKCS8) and `publicKeyRaw` (32-byte raw), matching the
 * formats the sign/verify functions expect.
 */
export async function generateCapabilityKeypair(): Promise<{
  privateKeyPkcs8: string;
  publicKeyRaw: string;
}> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));

  return {
    privateKeyPkcs8: base64Encode(pkcs8),
    publicKeyRaw: base64Encode(raw),
  };
}
