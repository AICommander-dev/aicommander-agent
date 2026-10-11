// Owner-facing device-management client: talk to the relay's /api/device/*
// endpoints using THIS device's identity (deviceId + deviceSecret) as proof of
// ownership. Used by the CLI (list-admins / block-admin / unblock-admin) and the
// desktop app.

import type { DeviceIdentity } from "./device.js";

export interface AdminEntry {
  userId: string;
  /** Already masked by the server — a full address never leaves the relay. */
  maskedEmail: string;
  /**
   * The linked machine's hostname (e.g. "aic-studio"), NOT a label for the person.
   * Show it as secondary machine info only — use {@link maskedEmail} to identify
   * the account/operator.
   */
  alias: string;
  linkedAt: string;
  lastSeenAt: string | null;
  /** True when the owner has blocked this account on this device. */
  blocked: boolean;
}

export interface AdminsResult {
  /** True when the current code is still in its 1h no-account-needed window. */
  codeFresh: boolean;
  admins: AdminEntry[];
}

export interface BlockResult {
  ok: boolean;
  blocked?: number;
  unblocked?: number;
  /** Set on refusal/failure: "not_found" | other. */
  error?: string;
  message?: string;
}

function deviceHeaders(device: DeviceIdentity): Record<string, string> {
  return { "X-Device-Id": device.deviceId, "X-Device-Secret": device.deviceSecret };
}

// Bound every device-management request so an unreachable/slow relay can't leave a
// fetch pending forever. This matters most on the desktop "someone connected" path,
// which awaits fetchAdmins to label the operator: without a ceiling a wedged relay
// would pile up in-flight requests (one per connecting operator) and delay the
// notice indefinitely. On timeout the fetch rejects; callers fall back gracefully.
const DEVICE_REQUEST_TIMEOUT_MS = 10_000;

/** List the accounts linked to this device (masked emails). Throws on transport/auth/timeout failure. */
export async function fetchAdmins(serverUrl: string, device: DeviceIdentity): Promise<AdminsResult> {
  let res: Response;
  try {
    res = await fetch(`${serverUrl}/api/device/admins`, {
      headers: deviceHeaders(device),
      signal: AbortSignal.timeout(DEVICE_REQUEST_TIMEOUT_MS),
    });
  } catch {
    // Transport failure or the AbortSignal.timeout firing — surface a descriptive
    // error rather than leaking a raw DOMException ("The operation was aborted") to the CLI.
    throw new Error("Failed to list linked accounts (relay unreachable or timed out).");
  }
  if (!res.ok) {
    throw new Error(`Failed to list linked accounts (HTTP ${res.status}).`);
  }
  return (await res.json()) as AdminsResult;
}

// Never throws: the CLI's block/unblock flow relies on a structured result for EVERY
// outcome. A transport failure or timeout returns { ok: false, error: "unreachable" }
// just like a 4xx, so the caller's graceful `else` branch handles it instead of a raw
// rejection escaping to the top-level "Fatal error" handler.
async function postDeviceAction(
  serverUrl: string,
  device: DeviceIdentity,
  action: "block" | "unblock",
  userId: string,
): Promise<BlockResult> {
  let res: Response;
  try {
    res = await fetch(`${serverUrl}/api/device/${action}`, {
      method: "POST",
      headers: { ...deviceHeaders(device), "Content-Type": "application/json" },
      body: JSON.stringify({ userId }),
      signal: AbortSignal.timeout(DEVICE_REQUEST_TIMEOUT_MS),
    });
  } catch {
    // Transport failure or the AbortSignal.timeout firing — report it as a structured
    // failure so the contract "never throws on a 4xx" also holds for unreachable/timeout.
    return { ok: false, error: "unreachable" };
  }
  let body: BlockResult;
  try {
    body = (await res.json()) as BlockResult;
  } catch {
    body = { ok: false, error: `http_${res.status}` };
  }
  return { ...body, ok: res.ok };
}

/**
 * Block one account by userId. Never throws: returns a structured {@link BlockResult}
 * for ANY outcome, including a 4xx, a transport failure, or a request timeout.
 */
export function blockAdmin(
  serverUrl: string,
  device: DeviceIdentity,
  userId: string,
): Promise<BlockResult> {
  return postDeviceAction(serverUrl, device, "block", userId);
}

/**
 * Unblock one account by userId, restoring its access. Never throws: returns a
 * structured {@link BlockResult} for ANY outcome, including a 4xx, a transport
 * failure, or a request timeout.
 */
export function unblockAdmin(
  serverUrl: string,
  device: DeviceIdentity,
  userId: string,
): Promise<BlockResult> {
  return postDeviceAction(serverUrl, device, "unblock", userId);
}

/**
 * Stable display/resolution order: active accounts first, blocked ones last,
 * each group preserving the server's order. Used so a list index means the same
 * thing in `list-admins`, `block-admin`, and `unblock-admin`.
 */
export function orderAdmins(admins: AdminEntry[]): AdminEntry[] {
  return [...admins.filter((a) => !a.blocked), ...admins.filter((a) => a.blocked)];
}

export type ResolveResult =
  | { kind: "ok"; admin: AdminEntry }
  | { kind: "not_found" }
  | { kind: "ambiguous"; matches: AdminEntry[] };

/**
 * Resolve a user-typed identifier against a listing. Accepts (in order): a 1-based
 * list index, an exact userId, or an unambiguous userId prefix. Pure — unit tested.
 */
export function resolveAdminIdentifier(admins: AdminEntry[], identifier: string): ResolveResult {
  const id = identifier.trim();
  if (!id) return { kind: "not_found" };

  // 1-based list index.
  if (/^\d+$/.test(id)) {
    const idx = Number(id) - 1;
    if (idx >= 0 && idx < admins.length) return { kind: "ok", admin: admins[idx]! };
    return { kind: "not_found" };
  }

  // Exact userId.
  const exact = admins.find((a) => a.userId === id);
  if (exact) return { kind: "ok", admin: exact };

  // Unambiguous userId prefix.
  const prefixed = admins.filter((a) => a.userId.startsWith(id));
  if (prefixed.length === 1) return { kind: "ok", admin: prefixed[0]! };
  if (prefixed.length > 1) return { kind: "ambiguous", matches: prefixed };
  return { kind: "not_found" };
}
