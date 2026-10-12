/**
 * Dotted numeric version comparison shared by every side of the update flow:
 * the desktop tray + headless agent (via @aicommander/agent's update-check)
 * and the Worker's /dist/mac-update-feed. Lives in protocol so the "is this
 * newer?" verdict can never drift between client and server.
 */

/**
 * Compare dotted numeric versions ("1.0.18" vs "1.0.9"). Returns >0 if a>b,
 * <0 if a<b, 0 if equal. Missing/short segments count as 0; non-numeric parts
 * (e.g. a "-beta" suffix) are coerced to 0 so a malformed tag never throws.
 */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

/** True when `latest` is a strictly newer version than `current`. */
export function isNewerVersion(latest: string, current: string): boolean {
  return compareVersions(latest, current) > 0;
}
