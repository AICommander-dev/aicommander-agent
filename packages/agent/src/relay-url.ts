// Relay-URL trust gate.
//
// The agent runs as ROOT and will execute any `do:exec` frame the relay sends, so
// the relay it connects to is its single trust anchor. Two hardening rules keep a
// malicious override from pointing the root agent at an attacker-controlled relay:
//
//   1. HOST-LOCK. By default only the canonical relay (DEFAULT_SERVER) is allowed.
//      `AICOMMANDER_SERVER` can only redirect the agent to a DIFFERENT origin when
//      a deliberate dev escape hatch is on (AICOMMANDER_DEV=1) or the target is
//      loopback. Otherwise the override is IGNORED (loudly) and we fall back to the
//      canonical relay — so a stray/injected env var can't silently re-home a root
//      agent. (TLS alone does NOT defend this: an attacker's own host has a valid
//      cert for itself; only host-locking does.)
//
//   2. NO PLAINTEXT. The chosen origin must be https:// (→ wss:// for the socket),
//      except for an explicit loopback dev target. This blocks a downgrade to an
//      unencrypted, unauthenticated ws:// link that any on-path attacker could MITM.
//
// We deliberately do NOT pin a leaf/intermediate SPKI: Cloudflare rotates the
// managed cert for aicommander.dev, and a hardcoded key pin would brick the fleet
// on rotation. Host-lock + TLS (PKI) is the right trade-off for a hosted relay.

import { DEFAULT_SERVER } from "@aicommander/protocol";

function isDevMode(): boolean {
  const v = process.env["AICOMMANDER_DEV"];
  return v === "1" || v === "true";
}

function isLoopbackHost(host: string): boolean {
  // host may include a port; URL.hostname strips it, but guard both shapes.
  const h = host.toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]";
}

/** The canonical relay's origin (scheme + host), used for the host-lock compare. */
function canonicalOrigin(): string {
  return new URL(DEFAULT_SERVER).origin;
}

/**
 * Resolve the effective, TRUSTED relay base URL from a raw candidate (typically
 * `process.env.AICOMMANDER_SERVER`). Returns a URL string safe to register and
 * open a root-exec socket against. Never throws — an unparseable or untrusted
 * value falls back to DEFAULT_SERVER (with a loud warning) rather than crashing.
 */
export function resolveTrustedServerUrl(raw?: string | null): string {
  const candidate = (raw ?? "").trim();
  if (!candidate) return DEFAULT_SERVER;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    console.warn(
      `\n  ⚠  Ignoring malformed AICOMMANDER_SERVER (${candidate}); using ${DEFAULT_SERVER}.\n`,
    );
    return DEFAULT_SERVER;
  }

  // The canonical relay is always allowed (and is the only allowed origin in prod).
  if (url.origin === canonicalOrigin()) return DEFAULT_SERVER;

  const loopback = isLoopbackHost(url.hostname);
  // Any non-canonical origin requires the explicit dev escape hatch (or loopback,
  // which is inherently local and can't be an over-the-network MITM target).
  if (!isDevMode() && !loopback) {
    console.warn(
      `\n  ⚠  AICOMMANDER_SERVER override to "${url.origin}" ignored for safety —\n` +
      `     the agent runs as root and is host-locked to ${canonicalOrigin()}.\n` +
      `     Set AICOMMANDER_DEV=1 to allow a custom relay for development.\n`,
    );
    return DEFAULT_SERVER;
  }

  // No plaintext: a non-loopback relay MUST be https (→ wss for the socket).
  if (url.protocol !== "https:" && !loopback) {
    console.warn(
      `\n  ⚠  Refusing plaintext relay "${url.origin}" (https required); using ${DEFAULT_SERVER}.\n`,
    );
    return DEFAULT_SERVER;
  }

  // Trusted dev / loopback override — strip any trailing slash for consistency.
  return candidate.replace(/\/+$/, "");
}

/**
 * Assert the about-to-open agent WebSocket URL is encrypted (wss://) or an explicit
 * loopback dev target (ws://localhost). Belt-and-suspenders on top of
 * resolveTrustedServerUrl, evaluated at the actual connection point. Throws on a
 * plaintext non-loopback URL so a root agent never opens an unauthenticated link.
 */
export function assertSecureWsUrl(wsUrl: string): void {
  let url: URL;
  try {
    url = new URL(wsUrl);
  } catch {
    throw new Error("Refusing to connect: malformed relay WebSocket URL.");
  }
  if (url.protocol === "wss:") return;
  if (url.protocol === "ws:" && isLoopbackHost(url.hostname)) return;
  throw new Error(
    `Refusing to open a plaintext relay socket (${url.protocol}//${url.host}); wss:// required.`,
  );
}
