/**
 * Lightweight "is there a newer release?" check shared by the desktop tray and
 * the headless Linux agent. Apps poll the small `/dist/latest` JSON (a few
 * hundred bytes) — NOT the multi-MB binaries — and compare the published
 * `version` against their own. Downloading the actual build only happens when
 * the user explicitly clicks "Download" / runs the install script.
 */

export interface LatestDist {
  /** Latest published version, e.g. "1.0.18". null until a release is published. */
  version: string | null;
  /** Direct download paths (relative to the server origin), null if missing. */
  mac: string | null;
  /**
   * The macOS .pkg installer (the primary mac download once published) —
   * null until a pkg release exists, or when talking to an older server.
   * Optional so existing consumers constructing LatestDist keep compiling;
   * `fetchLatestDist` always fills it in (with an explicit null when absent).
   */
  macPkg?: string | null;
  win: string | null;
  agentLinuxX64: string | null;
  agentLinuxArm64: string | null;
}

// The comparison itself lives in @aicommander/protocol (the Worker's update
// feed uses the same implementation); these thin wrappers keep the public
// @aicommander/agent API unchanged (the desktop tray imports from here).
// Deliberately NOT `export ... from` re-exports: that would emit an
// `import("@aicommander/protocol")` reference into the published
// dist/src/update-check.d.ts, and protocol is a private workspace package
// external npm consumers can't resolve. Explicit signatures keep the
// generated d.ts self-contained. (The runtime JS is bundled either way —
// scripts/build-npm.mjs inlines protocol from source.)
import { compareVersions as protoCompare, isNewerVersion as protoIsNewer } from "@aicommander/protocol";

/**
 * Compare dotted numeric versions ("1.0.18" vs "1.0.9"). Returns >0 if a>b,
 * <0 if a<b, 0 if equal. Missing/short segments count as 0; non-numeric parts
 * (e.g. a "-beta" suffix) are coerced to 0 so a malformed tag never throws.
 */
export function compareVersions(a: string, b: string): number {
  return protoCompare(a, b);
}

/** True when `latest` is a strictly newer version than `current`. */
export function isNewerVersion(latest: string, current: string): boolean {
  return protoIsNewer(latest, current);
}

/**
 * Fetch the `/dist/latest` metadata blob. Returns null on any network error,
 * non-2xx, timeout, or malformed body — callers treat null as "couldn't check,
 * assume up to date" and never surface an error to the user.
 */
export async function fetchLatestDist(
  serverUrl: string,
  timeoutMs = 10_000,
): Promise<LatestDist | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${serverUrl.replace(/\/+$/, "")}/dist/latest`, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    if (!res.ok) return null;
    const body = (await res.json()) as Partial<LatestDist>;
    return {
      version: typeof body.version === "string" ? body.version : null,
      mac: typeof body.mac === "string" ? body.mac : null,
      macPkg: typeof body.macPkg === "string" ? body.macPkg : null,
      win: typeof body.win === "string" ? body.win : null,
      agentLinuxX64: typeof body.agentLinuxX64 === "string" ? body.agentLinuxX64 : null,
      agentLinuxArm64: typeof body.agentLinuxArm64 === "string" ? body.agentLinuxArm64 : null,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
