// Where the privileged helper listens and where it is installed on disk. Shared
// by the helper (server), the agent (client), and the installers so all three
// agree on the exact paths — a mismatch here is a silent "helper not available".
//
// All paths are FIXED, well-known, and root/SYSTEM-owned. They are never derived
// from user-controlled input: a per-user process must not be able to redirect
// the endpoint (that would let it stand up a fake helper the tray then trusts).

import { platform } from "node:os";

/** macOS LaunchDaemon label; must match the plist the pkg installer writes. */
export const MAC_DAEMON_LABEL = "dev.aicommander.privhelper";
/** macOS LaunchDaemon plist path; must match the pkg installer. */
export const MAC_DAEMON_PLIST = `/Library/LaunchDaemons/${MAC_DAEMON_LABEL}.plist`;

/** Unix-domain-socket path on macOS (root:wheel dir; socket root:staff 0660). */
const MAC_SOCKET_PATH =
  "/Library/Application Support/AI Commander/priv-helper/helper.sock";

/**
 * Loopback TCP host + candidate ports the Windows helper listens on. Windows uses
 * loopback TCP (NOT a named pipe) deliberately: a named pipe created by the SYSTEM
 * helper is (a) reachable REMOTELY over SMB (libuv doesn't set
 * PIPE_REJECT_REMOTE_CLIENTS) and (b) prone to instance-squatting; 127.0.0.1 is
 * local-only and has neither problem. Access control is the relay-signed,
 * machine-bound capability — loopback grants local reach, the signature grants
 * authority.
 *
 * Why a POOL and not one fixed port: a single hard-coded port is fragile.
 *  - Every port here is BELOW 49152, the default Windows ephemeral floor
 *    (`netsh int ipv4 show dynamicportrange`), so an unrelated process's OUTBOUND
 *    connection can never transiently occupy it and knock the helper's bind out.
 *  - Hyper-V / WSL2 / Docker reserve scattered blocks in this space
 *    (`netsh int ipv4 show excludedportrange tcp`); the candidates are spread
 *    ~2000 apart so one contiguous reserved block cannot take more than one.
 * The helper binds EVERY candidate it can (see createTransportServer) at boot,
 * before any user logs in, so it owns the whole pool; a later bind by anyone else
 * fails (EADDRINUSE). Owning every port matters: with only one bound, a local
 * squatter could sit on an EARLIER candidate and answer the agent's discovery scan
 * ahead of the genuine helper. The agent probes the whole list (see discoverHelper)
 * and fails closed when the answers disagree on bootId — so a port squatted while
 * the helper was down downgrades elevated exec to unavailable (DoS) instead of
 * letting the squatter impersonate the helper.
 */
export const WIN_LOOPBACK_HOST = "127.0.0.1";
export const WIN_LOOPBACK_PORTS = [42847, 44847, 46847, 48847] as const;

/** The IPC endpoint the helper listens on and the agent connects to. */
export type ElevatedEndpoint =
  | { transport: "unix"; path: string }
  | { transport: "tcp"; host: string; port: number };

/**
 * Ordered list of candidate IPC endpoints for THIS platform:
 *  - win32: loopback TCP 127.0.0.1 across WIN_LOOPBACK_PORTS (helper binds all free)
 *  - darwin: the single root-owned unix socket under /Library/Application Support
 *  - other: empty — elevated exec is a mac/Windows feature, so callers fail closed
 *    (Linux root already runs commands directly, no helper hop).
 */
export function elevatedEndpoints(): ElevatedEndpoint[] {
  switch (platform()) {
    case "win32":
      return WIN_LOOPBACK_PORTS.map((port) => ({
        transport: "tcp" as const,
        host: WIN_LOOPBACK_HOST,
        port,
      }));
    case "darwin":
      return [{ transport: "unix", path: MAC_SOCKET_PATH }];
    default:
      return [];
  }
}

/**
 * The PRIMARY (first) candidate endpoint, or null on an unsupported platform.
 * Convenience for callers that only need a platform-support check or a single
 * default; discovery/binding walk the full elevatedEndpoints() list.
 */
export function elevatedEndpoint(): ElevatedEndpoint | null {
  return elevatedEndpoints()[0] ?? null;
}

/**
 * Root/SYSTEM-owned directory the helper runtime + its version marker live in.
 * Deliberately OUTSIDE the replaceable app bundle so an app auto-update (which
 * swaps the .app / Program Files\AI Commander) cannot tamper with the helper.
 */
export function helperInstallDir(): string | null {
  switch (platform()) {
    case "win32":
      // SIBLING of INSTDIR — NOT under %ProgramFiles%\AI Commander, whose
      // uninstaller recursively deletes $INSTDIR before customUnInstall runs.
      return `${process.env["ProgramFiles"] ?? "C:\\Program Files"}\\AI Commander Privileged Helper`;
    case "darwin":
      return "/Library/Application Support/AI Commander/priv-helper";
    default:
      return null;
  }
}

/**
 * PRESENCE marker file written by the installers (win-privhelper-task.ps1 /
 * pkg-scripts/postinstall). The agent only checks that it EXISTS — see
 * isElevatedHelperAvailable(). It is NOT a skew signal — nothing is: helper↔agent
 * compatibility is enforced SOLELY by IPC_PROTOCOL_VERSION (compared fail-closed
 * on both sides). The `hello.helperVersion` / `clientVersion` fields are
 * INFORMATIONAL only (diagnostics/logs); no code compares them, so an app/helper
 * version mismatch under an unchanged protocol version is accepted.
 */
export function helperVersionMarkerPath(): string | null {
  const dir = helperInstallDir();
  return dir === null ? null : `${dir}/VERSION`;
}
