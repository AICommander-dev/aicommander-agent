import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { WINDOWS_LAUNCHER_NAME_X64 } from "@aicommander/priv-helper";
export {
  encodeWindowsLauncherRequest,
  encodeWindowsLauncherResponseForTest,
  type LauncherHandshakeError,
  type LauncherHandshakeReady,
  type LauncherHandshakeResult,
  WindowsLauncherHandshakeDecoder,
  WINDOWS_LAUNCHER_HANDSHAKE_TIMEOUT_MS,
  WINDOWS_LAUNCHER_NAME_X64,
} from "@aicommander/priv-helper";

export interface WindowsLauncherPathOptions {
  explicitPath?: string | undefined;
  arch?: string | undefined;
  moduleUrl?: string | undefined;
  exists?: ((path: string) => boolean) | undefined;
}

/**
 * Resolve the signed native launcher. The current Windows product is x64 only;
 * ARM64 must not silently fall back to raw cmd.exe or an untested emulated
 * binary. Desktop passes an explicit extraResources path because ASAR contents
 * are not executable. npm/source builds use one of the two bundle-relative
 * candidates below.
 */
export function resolveWindowsLauncherPath(options: WindowsLauncherPathOptions = {}): string {
  const arch = options.arch ?? process.arch;
  if (arch !== "x64") {
    throw new Error("Windows command execution is unavailable on this architecture");
  }
  const pathExists = options.exists ?? existsSync;
  if (options.explicitPath) {
    if (pathExists(options.explicitPath)) return options.explicitPath;
    throw new Error("Windows command launcher is unavailable");
  }

  const moduleUrl = options.moduleUrl ?? import.meta.url;
  const candidates = [
    fileURLToPath(new URL(`../dist-native/${WINDOWS_LAUNCHER_NAME_X64}`, moduleUrl)),
    fileURLToPath(new URL(`../../dist-native/${WINDOWS_LAUNCHER_NAME_X64}`, moduleUrl)),
  ];
  for (const candidate of candidates) {
    if (pathExists(candidate)) return candidate;
  }
  throw new Error("Windows command launcher is unavailable");
}
