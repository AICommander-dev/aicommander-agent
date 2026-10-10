import os from "os";
import { AGENT_VERSION } from "./version.js";
import type { DeviceIdentity } from "./device.js";

export interface RegisterResult {
  sessionCode: string;
  agentToken: string;
}

/** Machine-readable `code` the relay sends for a stale/unknown device identity
 * 403 — the ONLY 403 that should trigger identity regeneration. */
export const DEVICE_SECRET_MISMATCH = "device_secret_mismatch";

/** Pull the relay's machine-readable `code` out of a JSON error body, if any. */
function parseErrorCode(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as { code?: unknown };
    return typeof parsed.code === "string" ? parsed.code : null;
  } catch {
    return null;
  }
}

/**
 * Thrown when the relay rejects a registration with a non-2xx status. Carries
 * the HTTP `status` plus the relay's machine-readable `code` (parsed from the
 * JSON body, when present) so callers can distinguish a fatal client error
 * (e.g. a `device_secret_mismatch` 403 — retrying the same identity will fail
 * forever, so the agent must regenerate) from a transient/server error or some
 * OTHER 403 that must NOT discard the device identity.
 */
export class RegistrationError extends Error {
  /** Relay-supplied machine-readable error code, or null if the body had none. */
  readonly code: string | null;

  constructor(
    readonly status: number,
    readonly body: string,
  ) {
    super(`Registration failed (${status}): ${body}`);
    this.name = "RegistrationError";
    this.code = parseErrorCode(body);
  }
}

interface RegisterRequestBody {
  hostname: string;
  platform: string;
  arch: string;
  agentVersion: string;
  deviceId?: string;
  deviceSecret?: string;
  currentCode?: string;
  forceNew?: boolean;
}

export interface RegisterOptions {
  /** The stored session code, so the server can restore it if its KV record
   * was evicted. Ignored when `forceNew` is set. */
  currentCode?: string;
  /** Force a brand-new code (change-code path). */
  forceNew?: boolean;
}

export async function register(
  serverUrl: string,
  device?: DeviceIdentity,
  options: RegisterOptions = {},
): Promise<RegisterResult> {
  const body: RegisterRequestBody = {
    hostname: os.hostname(),
    platform: process.platform,
    arch: process.arch,
    agentVersion: AGENT_VERSION,
    ...(device ? { deviceId: device.deviceId, deviceSecret: device.deviceSecret } : {}),
    ...(options.forceNew
      ? { forceNew: true }
      : options.currentCode
        ? { currentCode: options.currentCode }
        : {}),
  };

  const res = await fetch(`${serverUrl}/api/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new RegistrationError(res.status, text);
  }

  return res.json() as Promise<RegisterResult>;
}
