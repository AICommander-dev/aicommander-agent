// Helper build version, surfaced in the handshake for tray↔helper skew detection
// and audit. Bumped in lockstep with the agent/desktop release by scripts/release.mjs
// and enforced against package.json + the canonical version by
// scripts/check-distribution-parity.mjs (CI).
export const HELPER_VERSION = "1.3.0";
