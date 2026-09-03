// Semantic layer on top of the protocol's cryptographic verifyElevatedCapability:
// after the signature/shape/expiry checks pass, enforce the bindings that make a
// capability single-use and machine/boot-scoped (anti-replay, boot challenge,
// protocol-version floor).
//
// The crypto/shape/expiry checks live in the protocol's verifyElevatedCapability —
// this module never re-implements them; it runs ON TOP of a token that already
// passed them. It FAILS CLOSED: any failure throws.
//
// MACHINE binding is enforced HERE via helperInstanceId (the helper's per-boot
// nonce): the relay learns this helper's bootId (agent handshake → register) and
// binds it into every capability, and verifyCapabilityForExec REQUIRES it to match
// this helper's own bootId. That is what actually ties a capability to THIS machine
// and THIS boot — the fleet-wide signing key does not. (deviceId, a peppered hash
// the helper can't recompute, is still not checked here; helperInstanceId is the
// authoritative local binding and also invalidates every capability on helper
// restart.)

import type { ElevatedCapabilityClaims } from "@aicommander/protocol";
import { verifyElevatedCapability } from "@aicommander/protocol";
import { resolvePinnedPublicKey } from "./pinned-key.js";

/** Minimum claims.protocolVersion this helper build accepts. */
export const MIN_PROTOCOL_VERSION = 1;

/**
 * Anti-replay memory: remembers requestIds already executed until they expire, so
 * a captured live capability can be used at most once. Prunes on its own clock.
 */
export class ReplayGuard {
  /** requestId → expiresAt (epoch ms). */
  private readonly seen = new Map<string, number>();

  /**
   * Record a requestId as used until `expiresAt` (epoch ms). Returns false if it
   * is already recorded (and not yet expired) — i.e. a replay. Prunes expired
   * entries first, so a requestId reused after its window is treated as fresh.
   */
  claim(requestId: string, expiresAt: number, now: number = Date.now()): boolean {
    for (const [id, exp] of this.seen) {
      if (exp <= now) this.seen.delete(id);
    }
    if (this.seen.has(requestId)) return false;
    this.seen.set(requestId, expiresAt);
    return true;
  }
}

export interface VerifyContext {
  replay: ReplayGuard;
  bootId: string;
  now?: number;
}

/**
 * Fully verify a wire capability for execution: signature (pinned key) + shape +
 * expiry (protocol layer), then protocol-version floor, the REQUIRED boot-challenge
 * match (helperInstanceId must be present AND equal this helper's bootId), and
 * anti-replay. Throws on ANY failure (fail-closed); returns the validated claims.
 */
export async function verifyCapabilityForExec(
  capability: string,
  ctx: VerifyContext,
): Promise<ElevatedCapabilityClaims> {
  const claims = await verifyElevatedCapability(
    capability,
    resolvePinnedPublicKey(),
    ctx.now !== undefined ? { now: ctx.now } : undefined,
  );

  if (claims.protocolVersion < MIN_PROTOCOL_VERSION) {
    throw new Error("elevated capability protocolVersion too low");
  }

  // MACHINE + BOOT BINDING (fail-closed, REQUIRED — not optional). The relay binds
  // the target helper's current boot nonce into every capability; the helper here
  // demands it match its OWN bootId. This is what stops a legitimately-signed
  // capability minted for machine A (or a previous boot of THIS machine) from being
  // replayed against a DIFFERENT reachable helper — the fleet-wide signing key alone
  // does NOT bind a capability to a machine, so without this check any local user who
  // can mint a capability for a device they control could escalate to root/SYSTEM on
  // any other reachable helper. A capability with a missing or mismatched
  // helperInstanceId is rejected outright.
  if (claims.helperInstanceId !== ctx.bootId) {
    throw new Error("elevated capability not bound to this helper's current boot");
  }

  // Anti-replay LAST, so an earlier throw never consumes the requestId.
  if (!ctx.replay.claim(claims.requestId, claims.expiresAt, ctx.now)) {
    throw new Error("elevated capability already used (replay)");
  }

  return claims;
}
