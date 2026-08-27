import EventEmitter from "node:events";
import { register, RegistrationError, DEVICE_SECRET_MISMATCH } from "./register.js";
import { runConnectionLoop, sleepAbortable, AGENT_TOKEN_ROTATE_MS } from "./connection.js";
import { loadOrCreateDevice, regenerateDevice } from "./device.js";
import { fetchAdmins, blockAdmin, unblockAdmin } from "./device-admin.js";
import type { AdminsResult, BlockResult } from "./device-admin.js";
import {
  loadSession,
  saveSession,
  clearSession,
  writeRotateMarker,
  consumeRotateMarker,
  type TokenVault,
  type SessionStoreContext,
} from "./session-store.js";
import { RemoteNotifier } from "./remote-notify.js";
import { resolveTrustedServerUrl } from "./relay-url.js";
import { getJobManager } from "./job-manager.js";
import type { JobManager } from "./job-manager.js";

import type { ScreenShareState, RemoteOperator } from "@aicommander/protocol";
import type { CapturedScreenshot, ScreenshotOptions } from "./screenshot.js";

export type AgentStatus = "connecting" | "connected" | "disconnected" | "disabled";

/**
 * Emitted as the controller's "remote-connect" event when a remote operator's
 * command clears the rate limit (see RemoteNotifier). The desktop app turns this
 * into the "someone connected" notice; the headless agent simply has no listener.
 */
export interface RemoteConnectInfo {
  /** Stable operator key: an account userId, or "anon" for session-code callers. */
  id: string;
  anonymous: boolean;
}

/**
 * Supplies the connection layer with the desktop screen-share grant state and a
 * way to capture the screen. Only the desktop app provides one; the headless
 * Linux agent leaves it undefined (so it reports `capable: false`). Implementers
 * emit "change" whenever the grant flips (user toggle or 24h auto-expiry) so the
 * live connection can push the new state to the relay without reconnecting.
 */
export interface ScreenShareProvider {
  getState(): ScreenShareState;
  /**
   * `options` is optional so a provider written before multi-display support
   * still satisfies this type; the connection layer always passes it, and any
   * provider that ignores it simply captures the primary display — which the
   * reply then reports honestly, because the metadata comes back from the
   * capture, never from the request.
   */
  capture(options?: ScreenshotOptions): Promise<CapturedScreenshot>;
  on(event: "change", listener: () => void): void;
  off(event: "change", listener: () => void): void;
}

export interface AgentControllerOptions {
  /**
   * Directory for the durable device identity + session store. The desktop app
   * passes its per-user data dir (e.g. Electron's `app.getPath("userData")`) so
   * the STABLE session code survives app updates and is removed only on full
   * uninstall. When omitted, the device/session-store defaults are used — the
   * Linux CLI behavior: AICOMMANDER_CONFIG_DIR when it is set (see config-dir.ts),
   * otherwise /etc with a ~/.config fallback.
   */
  configDir?: string;
  /** Desktop-only OS-protected storage for the reusable agent token. */
  tokenVault?: TokenVault;
  /**
   * Desktop-only screen-share provider. When supplied, the agent advertises
   * screen-share capability/state and can answer screenshot requests.
   */
  screenShare?: ScreenShareProvider;
  /** Desktop-only signed native Windows exec launcher outside Electron ASAR. */
  windowsExecLauncherPath?: string;
}

export class AgentController extends EventEmitter {
  private serverUrl: string;
  private configDir?: string;
  private tokenVault?: TokenVault;
  private screenShare?: ScreenShareProvider;
  private windowsExecLauncherPath?: string;
  private abortController: AbortController | null = null;
  private _status: AgentStatus = "disabled";
  private _code: string | null = null;
  private _active = false;
  private _lastHeartbeatAt = 0;
  private _jobs: JobManager | null = null;
  private readonly _remote = new RemoteNotifier();

  constructor(serverUrl: string, opts?: AgentControllerOptions) {
    super();
    // Host-lock the relay (see relay-url.ts): a non-canonical origin is accepted
    // only under the dev escape hatch / loopback, else it falls back to the
    // canonical relay. The desktop agent runs the same root-exec path.
    this.serverUrl = resolveTrustedServerUrl(serverUrl);
    this.configDir = opts?.configDir;
    this.tokenVault = opts?.tokenVault;
    this.screenShare = opts?.screenShare;
    this.windowsExecLauncherPath = opts?.windowsExecLauncherPath;
    // Safety: prevent Node.js from throwing when 'error' is emitted with no listener
    this.on("error", () => {});
  }

  get status(): AgentStatus { return this._status; }
  get sessionCode(): string | null { return this._code; }
  /** True while a remote command is actively executing on this machine. */
  get active(): boolean { return this._active; }
  /** Epoch-ms of the last proof the link is alive (open or server ping), or 0. */
  get lastHeartbeatAt(): number { return this._lastHeartbeatAt; }

  private sessionStoreCtx(): SessionStoreContext {
    return { configDir: this.configDir, tokenVault: this.tokenVault };
  }

  start(): void {
    if (this.abortController) return;
    // Jobs outlive the agent process, so the FIRST thing a start does is settle
    // what the previous run left behind: adopt jobs still running, mark the ones
    // whose outcome is unknowable, release GPU locks their dead holders were
    // wedging, and delete directories past JOB_RETENTION_MS. It must happen before
    // we connect — otherwise the first job_list after a restart would report a
    // week-old "running" job that died with the machine. Never throws; a machine
    // with an unusable jobs root still comes online for exec/screenshot.
    try {
      this._jobs = getJobManager(this.configDir);
    } catch {
      // Only an unusable AICOMMANDER_CONFIG_DIR reaches here (recover() itself
      // swallows everything). Leave jobs unwired rather than blocking startup;
      // individual job calls then answer with an error the caller can act on.
      this._jobs = null;
    }
    this._setStatus("connecting");
    this.abortController = new AbortController();
    void this._runLoop(this.abortController);
  }

  // Retries register() + runConnectionLoop() with exponential backoff until aborted.
  private async _runLoop(ac: AbortController): Promise<void> {
    let backoffMs = 1_000;
    const MAX_BACKOFF = 30_000;

    // Stable device identity — survives reboots/updates so the relay can map a
    // re-registering agent back to the same saved machine. Mutable so we can
    // regenerate it once if the relay rejects it (see the 403 path below).
    let device = loadOrCreateDevice(this.configDir);
    let deviceReset = false;

    // The session code is STABLE: reused across restarts/reconnects. It changes
    // ONLY when the one-shot rotate marker is present (change-code path), which
    // forces a brand-new code. On a normal start we pass the stored code as
    // `currentCode` so the relay can restore the exact code even if its KV
    // record was evicted. We consume the marker once, before the retry loop.
    let forceNew = consumeRotateMarker(this.sessionStoreCtx());

    while (!ac.signal.aborted) {
      this._setStatus("connecting");
      try {
        const stored = forceNew ? null : loadSession(this.sessionStoreCtx());
        const { sessionCode, agentToken } = await register(this.serverUrl, device, {
          forceNew,
          ...(stored ? { currentCode: stored.sessionCode } : {}),
        });
        if (ac.signal.aborted) break;

        saveSession({ sessionCode, agentToken }, this.sessionStoreCtx());
        forceNew = false; // subsequent reconnects re-assert the now-stored code

        this._code = sessionCode;
        try { this.emit("code", sessionCode); } catch {}

        // Runs until signal is aborted; retries WebSocket drops internally
        await runConnectionLoop({
          serverUrl: this.serverUrl,
          sessionCode,
          agentToken,
          signal: ac.signal,
          silent: true,
          ...(this.screenShare ? { screenShare: this.screenShare } : {}),
          ...(this.windowsExecLauncherPath
            ? { windowsExecLauncherPath: this.windowsExecLauncherPath }
            : {}),
          // Pass the ALREADY-RECOVERED manager (built with this controller's
          // configDir) so the connection never has to resolve a jobs root of its
          // own — the desktop app's data dir is not the CLI default.
          ...(this._jobs ? { jobManager: this._jobs } : {}),
          onStatus: (s) => this._setStatus(s),
          onActivity: (a) => this._setActive(a),
          onRemoteActivity: (op) => this._noteRemote(op),
          onHeartbeat: () => this._onHeartbeat(),
          // Periodically rotate the agent token while idle (re-assert same code).
          reauthIntervalMs: AGENT_TOKEN_ROTATE_MS,
          reauth: async () => {
            const r = await register(this.serverUrl, device, { currentCode: sessionCode });
            if (ac.signal.aborted || this.abortController !== ac) {
              throw new DOMException("Aborted", "AbortError");
            }
            saveSession({ sessionCode: r.sessionCode, agentToken: r.agentToken }, this.sessionStoreCtx());
            return r.agentToken;
          },
        });

        break; // signal aborted — clean exit from runConnectionLoop
      } catch (err) {
        if (ac.signal.aborted) break;

        // A `device_secret_mismatch` 403 means the relay rejects THIS device
        // identity (e.g. a stale or legacy device record whose secret no longer
        // matches ours). Retrying the same identity would 403 forever — the silent
        // perpetual "Reconnecting…". Regenerate the identity ONCE and retry as a
        // fresh device. We key off the relay's machine-readable error code, NOT a
        // bare status===403: other 403 reasons (rate-limit, auth policy, etc.) must
        // NOT discard the device binding. Guarded with `deviceReset` so even a
        // persistent mismatch can't spin regenerating unbounded.
        if (
          err instanceof RegistrationError &&
          err.status === 403 &&
          err.code === DEVICE_SECRET_MISMATCH &&
          !deviceReset
        ) {
          deviceReset = true;
          console.error(
            `[AIC] Relay rejected this device: ${err.message}. ` +
              `Regenerating device identity and retrying as a new device.`,
          );
          device = regenerateDevice(this.configDir);
          clearSession(this.sessionStoreCtx()); // stored session belonged to the old identity
          forceNew = false; // fresh device → register() mints a brand-new code
          continue; // retry immediately, no backoff
        }

        if (err instanceof RegistrationError) {
          console.error(`[AIC] ${err.message}`);
        }
        this._setStatus("disconnected");
        try {
          await sleepAbortable(backoffMs, ac.signal);
        } catch {
          break; // aborted during backoff sleep
        }
        backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF);
      }
    }

    // Only update status/state if we own the current controller
    // (stop() may have already set a new state synchronously)
    if (this.abortController === ac) {
      this._setStatus("disabled");
      this.abortController = null;
    }
  }

  stop(): void {
    this.abortController?.abort();
    this.abortController = null;
    this._code = null;
    this._setStatus("disabled");
  }

  async restart(): Promise<void> {
    this.stop();
    await Promise.resolve(); // let pending microtasks from old loop flush
    this.start();
  }

  /**
   * Force a brand-new session code (change-code path). Clears the stored session
   * and writes the one-shot rotate marker, then restarts the connection so the
   * register loop mints a fresh code with `forceNew`. Emits the new `code`.
   */
  async changeCode(): Promise<void> {
    clearSession(this.sessionStoreCtx());
    writeRotateMarker(this.sessionStoreCtx());
    await this.restart();
  }

  /**
   * List the accounts ("admins") linked to THIS device, with masked emails. Uses
   * the controller's own device identity (configDir) so the relay sees the exact
   * registered device. For the desktop "Linked Accounts" UI.
   */
  async listAdmins(): Promise<AdminsResult> {
    const device = loadOrCreateDevice(this.configDir);
    return fetchAdmins(this.serverUrl, device);
  }

  /** Block one linked account by userId — refuses its access, keeps it listed. */
  async blockAdmin(userId: string): Promise<BlockResult> {
    const device = loadOrCreateDevice(this.configDir);
    return blockAdmin(this.serverUrl, device, userId);
  }

  /** Unblock one account by userId — restores its access immediately. */
  async unblockAdmin(userId: string): Promise<BlockResult> {
    const device = loadOrCreateDevice(this.configDir);
    return unblockAdmin(this.serverUrl, device, userId);
  }

  private _setStatus(s: AgentStatus): void {
    // Leaving the "connected" state always ends any in-flight activity.
    if (s !== "connected" && this._active) this._setActive(false);
    if (this._status !== s) {
      this._status = s;
      try {
        this.emit("status", s);
      } catch {
        // listener errors must not propagate into ws event handlers
      }
    }
  }

  /**
   * Funnel an operator-initiated command through the connect-notice rate limiter;
   * emit "remote-connect" only when a fresh notice is due. Never throws into the
   * ws event handler that calls it.
   */
  private _noteRemote(operator: RemoteOperator): void {
    const now = Date.now();
    if (this._remote.note(operator.id, now)) {
      try {
        this.emit("remote-connect", {
          id: operator.id,
          anonymous: operator.anonymous,
        } satisfies RemoteConnectInfo);
      } catch {
        // listener errors must not propagate into ws event handlers
      }
    }
  }

  private _onHeartbeat(): void {
    this._lastHeartbeatAt = Date.now();
    try {
      this.emit("heartbeat", this._lastHeartbeatAt);
    } catch {
      // listener errors must not propagate into ws event handlers
    }
  }

  private _setActive(active: boolean): void {
    if (this._active !== active) {
      this._active = active;
      try {
        this.emit("activity", active);
      } catch {
        // listener errors must not propagate into ws event handlers
      }
    }
  }
}
