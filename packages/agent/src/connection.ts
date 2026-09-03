import WebSocket from "ws";
import os from "os";
import { AGENT_VERSION } from "./version.js";
import { executeCommand } from "./executor.js";
import { executeSecureCommand } from "./secure-executor.js";
import { executeElevatedCommand } from "./elevated-executor.js";
import { resolveElevatedAvailability, staticElevatedUnavailableReason } from "./elevated-availability.js";
import { showReconnecting, showRelayConnected, showExecuting, showDone } from "./display.js";
import { assertSecureWsUrl } from "./relay-url.js";
import { knownGpus, probeGpuState, wireGpus } from "./gpu.js";
import type { GpuProbeState } from "./gpu.js";
import { startLoginShellPathProbe, pendingLoginShellPath } from "./login-shell-path.js";
import { startInstalledVersionProbe, installedVersionSnapshot } from "./installed-version.js";
import { startJobScopeProbe, pendingJobScope } from "./job-scope.js";
import { getJobManager, JobError } from "./job-manager.js";
import { pullFileToRelay, pushFileFromRelay } from "./file-transfer.js";
import { alreadyDiagnosed, diag, diagJobId, errorFields } from "./diag-log.js";
import type { DiagFields } from "./diag-log.js";
import type { JobManager } from "./job-manager.js";
import type { ScreenShareProvider } from "./agent-controller.js";
import type { AgentToDoMsg, DoToAgentMsg, ScreenShareState, ScreenshotDisplaySelector, RemoteOperator, GpuDevice, JobRpcResult, FileRpcResult, ElevatedUnavailableReason } from "@aicommander/protocol";
import { clampCommandTimeout, EXEC_IDLE_THRESHOLD_MS, GPU_POLL_INTERVAL_MS, SCREENSHOT_CHUNK_SIZE, SCREENSHOT_MAX_BYTES } from "@aicommander/protocol";
import type { ElevatedEndpoint } from "@aicommander/priv-helper";

const SCREEN_SHARE_OFF: ScreenShareState = { capable: false, enabled: false, expiresAt: null };

/**
 * What a job start that THREW may say in the diagnostic log.
 *
 * A JobError's `code` is the machine-readable cause (`job_script_removed`) and
 * its `detail` names a file of OURS and what happened to it ("wrapper.cmd is
 * gone") — both authored here, both exactly what an antivirus submission needs.
 * The MESSAGE is never logged: it is written for a human, carries prose and a
 * URL today and could carry something else tomorrow. Anything that is not a
 * JobError degrades to `errorFields`, i.e. an errno and a syscall.
 */
function startFailureFields(err: unknown): DiagFields {
  const fields = errorFields(err);
  const detail = err instanceof JobError ? err.detail : undefined;
  return detail === undefined ? fields : { ...fields, detail };
}

interface ConnectionOpts {
  serverUrl: string;
  sessionCode: string;
  agentToken: string;
  signal?: AbortSignal;
  /** Desktop-only screen-share provider; absent on the headless Linux agent. */
  screenShare?: ScreenShareProvider;
  /**
   * Job manager answering the `do:job_*` RPCs. The controller supplies one built
   * with its own configDir (and already recovered) at startup; when absent we
   * fall back to the process-wide instance, which is the headless CLI path.
   */
  jobManager?: JobManager;
  /** Signed native Windows launcher; desktop supplies its extraResources copy. */
  windowsExecLauncherPath?: string;
  onStatus?: (s: 'connecting' | 'connected' | 'disconnected') => void;
  onActivity?: (active: boolean) => void;
  /**
   * Fired with the driving operator on each operator-initiated command (exec /
   * screenshot) that carries an identity. The controller rate-limits these into a
   * desktop "someone connected" notice; absent on the headless agent.
   */
  onRemoteActivity?: (operator: RemoteOperator) => void;
  /**
   * Fired whenever the link proves alive (on open and on every server ping).
   * Lets a supervisor watch link liveness independently of command workload —
   * pings flow every 20s even during a long command, so a stalled heartbeat
   * means a genuinely dead link, not a busy one.
   */
  onHeartbeat?: () => void;
  silent?: boolean;
  /**
   * If set, the agent rotates its agentToken roughly this often: while idle it
   * cleanly drops the connection, calls `reauth()` for a fresh token, and
   * reconnects — bounding the lifetime of any single (potentially leaked) token.
   */
  reauthIntervalMs?: number;
  /** Re-register and return a fresh agentToken (caller persists it). */
  reauth?: () => Promise<string>;
}

/** Default agent-token rotation cadence (6h). */
export const AGENT_TOKEN_ROTATE_MS = 6 * 60 * 60 * 1000;
const CONNECTION_TICKET_PATTERN = /^[a-f0-9]{64}$/;

/**
 * What we have LEARNED about this machine's cards, kept across reconnects.
 *
 * The rule is one line — a CONFIDENT probe (cards, or a real "none") updates the
 * list, an `unknown` changes NOTHING, because a failed re-probe is not news —
 * but it has to hold at EVERY point that can reach `JobManager.setKnownGpus`,
 * not just at the poll where it was first written. The manager is a singleton
 * that outlives any one socket (getJobManager()), while the probe used to be a
 * per-connection local: a transient nvidia-smi failure during the INITIAL probe
 * after a reconnect therefore pushed `undefined` into a manager that already
 * knew about an RTX 5080, silently downgrading a characterised machine back to
 * "we know nothing" and making `gpuIndex` permissive again — the phantom-job
 * bug reopened by a hiccup nobody would ever see. Owning the knowledge here, one
 * level ABOVE a single connection, is what makes that unrepresentable.
 *
 * This is the LOCAL half only. The wire half (`latestGpus` / `wireGpus`) stays
 * deliberately separate and stricter: `[]` is forbidden there and permitted —
 * indeed load-bearing — here.
 */
interface GpuKnowledge {
  /** The cards we are confident about; `undefined` = never learned anything. */
  known(): readonly GpuDevice[] | undefined;
  /** Fold in one probe result. An `unknown` is a no-op, by design. */
  learn(state: GpuProbeState): void;
}

function createGpuKnowledge(): GpuKnowledge {
  let known: readonly GpuDevice[] | undefined;
  return {
    known: () => known,
    learn: (state) => {
      if (state.certainty !== "unknown") known = knownGpus(state);
    },
  };
}

export function sleepAbortable(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new DOMException('Aborted', 'AbortError')); return; }
    const id = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => { clearTimeout(id); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });
}

export async function runConnectionLoop(opts: ConnectionOpts): Promise<void> {
  let backoffMs = 1_000;
  const MAX_BACKOFF = 30_000;
  let attempt = 0;
  let token = opts.agentToken;
  // Owned by the agent RUN, not by one socket: every reconnect below folds its
  // initial probe into the same knowledge, so an `unknown` at reconnect time
  // leaves what we already knew standing. See GpuKnowledge.
  const gpuKnowledge = createGpuKnowledge();

  // Warm the macOS login-shell PATH probe HERE, on the agent's startup path,
  // before a single frame can arrive. Both `do:exec` and job spawning need the
  // user's real PATH (launchd hands us /usr/bin:/bin:/usr/sbin:/sbin and nothing
  // else), but only exec can afford to await it: JobManager.start() never waits
  // for a probe (its reply carries the jobId, so it waits for nothing it does
  // not have to), so it uses whatever the memoized probe has resolved SO FAR.
  // Relying on JobManager.recover() to have warmed it is not enough —
  // the desktop path reaches the manager lazily through getJobManager() inside
  // jobs(), i.e. only once a `do:job_*` frame lands, which is precisely too late
  // for the first job. Fire-and-forget: memoized process-wide, bounded at
  // LOGIN_SHELL_PATH_TIMEOUT_MS, fail-open, and a no-op off macOS.
  void startLoginShellPathProbe();

  // And the systemd-scope capability probe, on the same startup path and for the
  // same reason. It used to run synchronously inside JobManager.start(), on this
  // handler's own thread, where a wedged system bus or an unresponsive polkit —
  // the exact machines it exists to detect — stalled the first job start (and
  // with it `do:ping` and every concurrent `do:exec`) for its whole timeout.
  // Started here, it has settled long before a frame arrives; do:job_start below
  // awaits it for the residual window, and spawnJob only ever reads the settled
  // answer. Fire-and-forget: memoized process-wide, bounded, fail-open (an
  // unsettled or failed probe simply means the job is launched unscoped), and a
  // no-op anywhere but Linux-as-root-under-systemd.
  void startJobScopeProbe();

  while (!opts.signal?.aborted) {
    attempt++;
    try {
      const reauthRequested = await connectAndServe(opts, token, gpuKnowledge);
      // Clean disconnect — reset backoff
      backoffMs = 1_000;
      attempt = 0;
      if (reauthRequested && opts.reauth && !opts.signal?.aborted) {
        // Rotate the token before reconnecting. Best-effort: on failure keep the
        // current token (still valid until the relay re-issues) and retry.
        // Best-effort, and named ONCE: a rotation that failed because our own
        // credential store refused the write has already been recorded as
        // `path.error path_role=sessionStore` by the code that raised it (see
        // agent-controller.ts), and renaming it here is what made one fault read
        // as two events. Everything else — the relay refusing the re-register, a
        // network fault — is named here, because nothing else named it.
        try {
          token = await opts.reauth();
        } catch (err) {
          if (!alreadyDiagnosed(err)) diag("conn.token_rotate_failed", errorFields(err));
          /* keep current token */
        }
      }
    } catch (err) {
      if ((err as DOMException).name === 'AbortError') break;
      const jitter = 0.8 + Math.random() * 0.4;
      const delay = Math.min(backoffMs * jitter, MAX_BACKOFF);
      // The backoff state itself: an agent stuck reconnecting forever looks
      // identical from outside to one that is simply idle (see diag-log.ts).
      diag("conn.retry", { attempt, delayMs: Math.round(delay) });
      if (!opts.silent) showReconnecting(attempt, delay);
      try {
        await sleepAbortable(delay, opts.signal ?? new AbortController().signal);
      } catch (sleepErr) {
        if ((sleepErr as DOMException).name === 'AbortError') break;
      }
      backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF);
    }
  }

  return;
}

async function requestConnectionTicket(
  opts: ConnectionOpts,
  token: string,
): Promise<string> {
  let response: Response;
  try {
    response = await fetch(`${opts.serverUrl}/api/agent/ws-ticket`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sessionCode: opts.sessionCode }),
      ...(opts.signal ? { signal: opts.signal } : {}),
    });
  } catch (err) {
    if ((err as DOMException).name === "AbortError") throw err;
    diag("conn.ticket_error", errorFields(err));
    // Never propagate fetch/request details: implementations may include the
    // request URL or headers in their Error object.
    throw new Error("Failed to request WebSocket connection ticket.");
  }

  if (!response.ok) {
    // THE line the 2026-09-02 incident needed and did not have: the ticket
    // exchange that precedes the ws upgrade, with its HTTP status.
    diag("conn.ticket_failed", { status: response.status });
    throw new Error(`WebSocket connection ticket request failed (${response.status}).`);
  }
  try {
    const body = (await response.json()) as { ticket?: unknown };
    if (typeof body.ticket !== "string" || !CONNECTION_TICKET_PATTERN.test(body.ticket)) {
      throw new Error("invalid ticket");
    }
    return body.ticket;
  } catch {
    diag("conn.ticket_invalid");
    throw new Error("Relay returned an invalid WebSocket connection ticket.");
  }
}

async function connectAndServe(
  opts: ConnectionOpts,
  token: string,
  gpuKnowledge: GpuKnowledge,
): Promise<boolean> {
  const { serverUrl } = opts;
  const wsEndpoint = `${serverUrl.replace(/^http/, "ws")}/ws/agent`;
  // Check transport security before sending the Bearer credential on the ticket
  // POST. runConnectionLoop is a public library API, so do not rely solely on
  // higher-level callers having passed through resolveTrustedServerUrl.
  assertSecureWsUrl(wsEndpoint);
  // Probe the GPUs BEFORE the ticket request, so the (short-lived) ticket is not
  // spent waiting on nvidia-smi and agent:register can still be sent the instant
  // the socket opens — the relay treats a machine as offline until it lands.
  // `latestGpus === undefined` means "no NVIDIA hardware / unknown", and stays
  // undefined: the field is then omitted from register and the poll loop never
  // starts, so a Mac or a plain server pays nothing for this feature.
  //
  // `gpuKnowledge` is the LOCAL-ONLY half of the same probe and never reaches
  // the wire: `[]` there is the confident claim "this machine has no NVIDIA GPU"
  // — and after the certainty rework that can ONLY come from an nvidia-smi that
  // ran, exited 0 and listed nothing, never from a missing binary — which is
  // what lets job_start refuse a gpuIndex. `undefined` is "we could not tell"
  // and keeps the job check permissive. See gpu.ts probeGpuState.
  //
  // Folded in through `learn`, exactly like the poll's re-probes: this is the
  // RECONNECT path, and an initial probe that failed here must not wipe what an
  // earlier connection confidently established (see GpuKnowledge).
  // Started BEFORE the ticket round trip, never awaited: the register frame reads
  // whatever the probe has by then (macOS resolves synchronously — one file read),
  // and one still running leaves the previous connect's answer in place. Nothing
  // here may delay a connect; a machine that cannot say what is on its disk is
  // still a machine that must come online.
  //
  // Re-run per CONNECT rather than once per process: a pkg upgrade replaces the
  // .app under this live process, so the whole point is to re-read the disk on
  // every reconnect instead of re-registering the pre-upgrade number forever.
  startInstalledVersionProbe();
  const initialGpuState = await probeGpuState();
  gpuKnowledge.learn(initialGpuState);
  let latestGpus: GpuDevice[] | undefined = wireGpus(initialGpuState);
  const ticket = await requestConnectionTicket(opts, token);
  const wsUrl = `${wsEndpoint}?ticket=${ticket}`;
  // Belt-and-suspenders on top of resolveTrustedServerUrl: never open a plaintext
  // relay socket (only wss://, or ws:// to an explicit loopback dev target). A root
  // agent on an unencrypted, unauthenticated link is trivially MITM'able into RCE.
  assertSecureWsUrl(wsUrl);

  const callOnStatus = (s: 'connecting' | 'connected' | 'disconnected') => {
    try { opts.onStatus?.(s); } catch { /* listener errors must not propagate */ }
  };

  const callOnActivity = (active: boolean) => {
    try { opts.onActivity?.(active); } catch { /* listener errors must not propagate */ }
  };

  const callOnRemoteActivity = (operator: RemoteOperator | undefined) => {
    if (!operator) return;
    try { opts.onRemoteActivity?.(operator); } catch { /* listener errors must not propagate */ }
  };

  const callOnHeartbeat = () => {
    try { opts.onHeartbeat?.(); } catch { /* listener errors must not propagate */ }
  };

  callOnStatus('connecting');

  // Resolves true when the connection ended because a token rotation is due.
  return new Promise<boolean>((resolve, reject) => {
    const ws = new WebSocket(wsUrl, {
      headers: { Authorization: `Bearer ${token}` },
    });
    type ActiveCommand = {
      commandId: string;
      terminalResponseSent: boolean;
      executionSettled: boolean;
      kill: (() => void) | null;
      idleCheck: ReturnType<typeof setInterval> | null;
      timeout: ReturnType<typeof setTimeout> | null;
    };
    let activeCommand: ActiveCommand | null = null;
    // File transfers run detached from the message handler (see replyFile), so unlike
    // an exec they cannot live in the single command slot: several can legitimately
    // overlap. They are tracked all the same — teardown has to be able to stop them.
    const inFlightTransfers = new Set<AbortController>();
    let pingTimeout: ReturnType<typeof setTimeout> | null = null;
    let reauthTimer: ReturnType<typeof setTimeout> | null = null;
    let reauthRequested = false;
    let settled = false;
    // `settled` as something a running operation can be handed. A boolean can
    // only be re-read at a point somebody remembered to put a check; work that is
    // already parked inside an await needs to be TOLD. Aborted exactly where
    // `settled` is set (doResolve/doReject), never anywhere else, so the two can
    // never disagree — see the do:job_start handler, which is what it is for.
    const socketGone = new AbortController();
    // The elevated per-boot nonce last advertised to the relay in agent:register.
    // The relay binds this into every elevated capability (machine + boot binding)
    // and the helper rejects any capability whose helperInstanceId != its live
    // bootId. If the helper RESTARTS (new bootId) while this socket stays up, the
    // relay would keep minting stale-bound capabilities → the helper rejects them.
    // We refresh this and re-register whenever an elevated exec observes a
    // different bootId (see the do:elevated_exec onBootId callback below).
    let registeredBootId: string | undefined;
    // Bumped on every sendRegister. reconcileElevated snapshots it before its
    // (slow) discovery await and discards the result if anything re-registered
    // meanwhile — otherwise a discovery that started BEFORE a helper restart
    // could re-advertise the pre-restart bootId over the fresh one the
    // onBootId fast path just registered.
    let registerEpoch = 0;
    // The IPC endpoint discovery pinned (the Windows helper binds every free pool
    // port; this is the first that answered). Reused for every elevated exec so
    // we don't re-scan the pool per command.
    let elevatedEndpointPinned: ElevatedEndpoint | null = null;
    // The reason last advertised for having NO helper (see
    // ElevatedUnavailableReason). Tracked next to `registeredBootId` because it is
    // the other half of the same claim: reconcileElevated re-registers when either
    // one changes, so a machine that turns out to have no helper — the state that
    // was invisible on the 2026-09-02 machine — reaches the relay instead of
    // sitting silently behind an initial register that said nothing.
    let registeredElevatedReason: ElevatedUnavailableReason | undefined;

    // Build + send an agent:register frame. `elevatedBootId` (when defined) both
    // advertises elevatedExec:true and carries the nonce the relay binds into
    // capabilities. `elevatedUnavailableReason` is its opposite number: sent ONLY
    // alongside elevatedExec:false, purely so consumers can say WHY, never as a
    // capability. Records what we advertised so a later change can be detected.
    // No-op once the connection has settled.
    const sendRegister = (
      elevatedBootId: string | undefined,
      elevatedUnavailableReason?: ElevatedUnavailableReason,
    ): void => {
      if (settled) return;
      registerEpoch++;
      registeredBootId = elevatedBootId;
      registeredElevatedReason = elevatedBootId === undefined ? elevatedUnavailableReason : undefined;
      const installedVersion = installedVersionSnapshot();
      const registerMsg: AgentToDoMsg = {
        type: "agent:register",
        hostname: os.hostname(),
        platform: process.platform,
        arch: process.arch,
        agentVersion: AGENT_VERSION,
        // What is on DISK, when we could tell — the relay compares it against the
        // running version above and says so when an update landed without a
        // restart. Omitted rather than guessed: absent means "unknown" on the wire,
        // never "same as running" (see AgentRegisterMsg.installedVersion).
        ...(installedVersion !== undefined ? { installedVersion } : {}),
        screenShare: opts.screenShare?.getState() ?? SCREEN_SHARE_OFF,
        elevatedExec: elevatedBootId !== undefined,
        ...(elevatedBootId !== undefined ? { elevatedBootId } : {}),
        // Diagnostic only, and only when there is nothing to advertise: a machine
        // that CAN run elevated work has nothing to explain, and an omitted reason
        // reads on the relay exactly as an agent too old to report one.
        ...(registeredElevatedReason !== undefined
          ? { elevatedUnavailableReason: registeredElevatedReason }
          : {}),
        // Omitted entirely when the probe found nothing: `undefined` means
        // "unknown or none", and `[]` would claim the same thing less clearly.
        // Re-registrations (elevated reconcile) carry the freshest snapshot the
        // poll loop has seen rather than the one taken before the socket opened.
        ...(latestGpus ? { gpus: latestGpus } : {}),
        // Capability flag: from this version on we answer the do:job_* RPCs. The
        // relay refuses job calls to agents that do NOT advertise it, because an
        // older agent's switch drops unknown message types silently and the call
        // would hang until JOB_RPC_TIMEOUT_MS with no explanation.
        jobs: true,
        // Capability flag: from this version on we HONOUR do:exec `shell` — we
        // run the requested interpreter or answer agent:error, never the default
        // one. The relay refuses a `shell` request to agents that do not
        // advertise it, because an older agent silently drops the field and the
        // caller would be told a PowerShell script ran in cmd.exe.
        shellSelect: true,
        // Capability flag: from this version on we answer the do:file_* RPCs. Same
        // fail-closed contract as `jobs` — an agent that does not advertise it would
        // drop a transfer frame silently and leave the caller waiting out
        // FILE_RPC_TIMEOUT_MS, so the relay refuses transfers without it.
        fileTransfer: true,
      };
      ws.send(JSON.stringify(registerMsg));
    };

    // Reconcile the advertised elevated state with the helper actually reachable
    // right now. Called once on open and then on an interval, so a helper that is
    // installed/removed/restarted (new bootId, possibly different pool ports)
    // AFTER we connected is picked up WITHOUT waiting for a reconnect:
    //  - reachable: pin its endpoint and, if the bootId changed, re-register
    //    advertising it;
    //  - unreachable: drop the pin and, if we'd previously advertised a helper,
    //    retract it (elevatedExec:false) so the relay stops minting capabilities
    //    the helper would reject — carrying the REASON there is none, so the relay
    //    can say "no helper installed" instead of leaving every consumer to guess
    //    between that, an old agent and an offline machine.
    // resolveElevatedAvailability() retries discovery a few times, so a transient
    // probe failure at register time no longer wrongly disables elevated exec for
    // the whole session. It grants nothing: `available` still means a completed
    // handshake, and the reason is only ever words.
    const reconcileElevated = async (): Promise<void> => {
      if (settled) return;
      const epoch = registerEpoch;
      const found = await resolveElevatedAvailability();
      // Discard a stale result: the connection settled, or something else (the
      // onBootId fast path below) re-registered while we were probing — its
      // nonce is fresher than whatever this pre-await snapshot observed.
      if (settled || epoch !== registerEpoch) return;
      if (!found.available) {
        elevatedEndpointPinned = null;
        // Re-register when the CLAIM changed: we had advertised a helper and no
        // longer can, or the reason itself is new (the usual case on a machine
        // that never had one — the immediate register at open said nothing at all).
        if (registeredBootId !== undefined || registeredElevatedReason !== found.reason) {
          sendRegister(undefined, found.reason);
        }
        return;
      }
      elevatedEndpointPinned = found.endpoint;
      if (found.bootId !== registeredBootId) sendRegister(found.bootId);
    };
    let elevatedReconcile: ReturnType<typeof setInterval> | null = null;
    const stopElevatedReconcile = () => {
      if (elevatedReconcile) { clearInterval(elevatedReconcile); elevatedReconcile = null; }
    };

    const clearReauth = () => { if (reauthTimer) { clearTimeout(reauthTimer); reauthTimer = null; } };

    const stopIdleCheck = (command = activeCommand) => {
      if (command?.idleCheck) {
        clearInterval(command.idleCheck);
        command.idleCheck = null;
      }
    };

    const stopCommandTimeout = (command = activeCommand) => {
      if (command?.timeout) {
        clearTimeout(command.timeout);
        command.timeout = null;
      }
    };

    // Claims the one connection-wide execution slot. All three foreground exec
    // modes share it: their kill handles, idle intervals and (for legacy exec)
    // deadlines must never be overwritten by a second relay frame.
    const beginCommand = (commandId: string): ActiveCommand | null => {
      if (activeCommand) {
        const busy: AgentToDoMsg = {
          type: "agent:error",
          commandId,
          error: "Another command is already running on this connection.",
        };
        try { ws.send(JSON.stringify(busy)); } catch { /* socket gone */ }
        return null;
      }
      const command: ActiveCommand = {
        commandId,
        terminalResponseSent: false,
        executionSettled: false,
        kill: null,
        idleCheck: null,
        timeout: null,
      };
      activeCommand = command;
      return command;
    };

    // Releases the slot only when the executor confirms that its process is
    // actually gone. A timeout sends its response and starts termination, but
    // deliberately leaves executionSettled=false so TERM→KILL/taskkill cannot
    // overlap a new command. Queued callbacks retain this command token and can
    // therefore never release a later occupant of the slot.
    const settleCommandExecution = (command: ActiveCommand): boolean => {
      if (command.executionSettled) return false;
      command.executionSettled = true;
      stopIdleCheck(command);
      stopCommandTimeout(command);
      if (activeCommand === command) activeCommand = null;
      return true;
    };

    const abortActiveCommand = (): void => {
      const command = activeCommand;
      if (!command) return;
      const kill = command.kill;
      command.terminalResponseSent = true;
      if (!settleCommandExecution(command)) return;
      command.kill = null;
      try { kill?.(); } catch { /* connection cleanup remains terminal */ }
      callOnActivity(false);
    };

    // Re-probes nvidia-smi and pushes agent:gpu_state so used-VRAM/utilization in
    // the relay's stored metadata stay fresh enough to pick a card for a job.
    // Started only when the machine actually has a GPU, and torn down on EVERY
    // exit from this connection (both cleanup paths below) — a leaked interval
    // would keep probing for a socket that no longer exists, once per reconnect.
    let gpuPoll: ReturnType<typeof setInterval> | null = null;
    const stopGpuPoll = () => {
      if (gpuPoll) { clearInterval(gpuPoll); gpuPoll = null; }
    };

    /**
     * The job manager, resolved on first use so a machine that never receives a
     * job call never touches the jobs directory. Cached per connection because
     * `getJobManager()` runs restart recovery on the very first call.
     */
    let jobManagerCache: JobManager | null = null;
    const jobs = (): JobManager => {
      if (!jobManagerCache) jobManagerCache = opts.jobManager ?? getJobManager();
      // Hand it the cards we know about, so job_start can refuse a gpuIndex this
      // machine does not have instead of running the job with a
      // CUDA_VISIBLE_DEVICES that names nothing. Pushed IN rather than probed
      // there: a start must not wait on `nvidia-smi` (the only I/O it awaits is
      // the job's own two script files), and the probe policy (notably "a failed re-probe is not
      // news") lives here. Done on every access rather than at creation because
      // the manager's lifecycle is independent of this connection's — it may have
      // been created by the desktop controller long before we probed — and the
      // knowledge only ever moves to a FRESHER CONFIDENT answer (see
      // GpuKnowledge), so re-stating it is free of ordering questions. This is
      // the local list, NOT the wire `latestGpus`: an empty array here is the
      // confident "no NVIDIA GPU on this box" that makes the refusal fire, while
      // `undefined` ("we could not tell") leaves the manager permissive — and is
      // only ever passed when NO probe, on ANY connection, has ever succeeded.
      jobManagerCache.setKnownGpus(gpuKnowledge.known());
      return jobManagerCache;
    };

    /**
     * Answer one do:job_* RPC, correlated by requestId (the screenshot pattern —
     * the relay routes the reply to the one waiting caller, never broadcasts it).
     *
     * A structured refusal (gpu_busy / not_found / too_many_jobs /
     * invalid_request) is an EXPECTED outcome and travels as a successful
     * agent:job_result with ok:false, so the caller can branch on it.
     * agent:job_error is reserved for genuine failures OF THIS MACHINE and carries
     * only a message we authored — never job output, never a command.
     */
    const replyJob = (requestId: string, run: () => JobRpcResult | Promise<JobRpcResult>): void => {
      // `run` may be asynchronous: a Windows job start writes and reads back its
      // scripts, and those two touches of a filesystem an on-access scanner may
      // be holding must not run on the desktop host's Electron main loop (see
      // job-scripts.ts). Every other job RPC is still disk-local and synchronous;
      // it simply has its reply sent one microtask later.
      void (async () => {
        let reply: AgentToDoMsg;
        try {
          reply = { type: "agent:job_result", requestId, result: await run() };
        } catch (err) {
          reply = {
            type: "agent:job_error",
            requestId,
            // JobError messages are written by us and safe to surface. Anything
            // else (an fs errno, a spawn failure) is reported generically rather
            // than risking a path or payload fragment on the wire.
            error: err instanceof JobError ? err.message : "The job request failed on the target machine.",
          };
        }
        try { ws.send(JSON.stringify(reply)); } catch { /* socket gone */ }
      })();
    };

    /**
     * Start a job, but not before the login-shell PATH probe and the systemd
     * scope probe have settled.
     *
     * The probe is kicked off at process start (runConnectionLoop above), so on
     * every real connection it resolved long before any frame arrived and this
     * awaits `null` — `pendingLoginShellPath()` returns null once resolved and
     * off macOS. It exists to close the one residual window: a job_start landing
     * within the probe's first LOGIN_SHELL_PATH_TIMEOUT_MS, which would otherwise
     * spawn with launchd's minimal PATH and fail "command not found" — the exact
     * silent symptom this whole effort is about.
     *
     * Deferring HERE, not inside JobManager.start(), is what keeps that fix
     * compatible with the manager's invariants: the record is still written
     * before the spawn, and the delay lives in the frame handler, which is
     * already async and does not block the socket — `do:ping` keeps being
     * answered throughout. The cost is bounded and paid at most once per process.
     *
     * `start()` itself is no longer synchronous: on Windows it writes the job's
     * two scripts and reads them back immediately before the spawn, and doing
     * that synchronously would block Electron's main loop on a filesystem an
     * on-access scanner is holding. The invariant that made it synchronous —
     * "a status poll can never observe a `running` job with no pid" — is kept by
     * the manager itself (see startingJobs in job-manager.ts) rather than by the
     * absence of an await, and the two frames that CAN now land inside that
     * window are answered rather than raced: a cancel for the job stops the spawn
     * (job-manager's cancel()), and the loss of this socket does the same through
     * the signal passed below.
     *
     * The systemd scope probe is awaited HERE for all of the same reasons. Its
     * residual window has the same shape: a job_start landing before it settles
     * would be launched unscoped and would then die with the next agent restart
     * — the very failure scopes exist to fix. Its own memo makes this free on
     * every machine that cannot have scopes (pendingJobScope returns null) and
     * on every job after the first.
     */
    const startJob = async (msg: Extract<DoToAgentMsg, { type: "do:job_start" }>): Promise<void> => {
      const pending = pendingLoginShellPath();
      // Never rejects (the probe is fail-open), but this must not become an
      // unhandled rejection if that ever changes.
      if (pending) await pending.catch(() => undefined);
      const pendingScope = pendingJobScope();
      if (pendingScope) await pendingScope.catch(() => undefined);
      // The socket died while we waited: a job started now could never report
      // its id back, so it would run unreachable. Drop it instead.
      if (settled) return;
      replyJob(msg.requestId, async () => {
        let result: JobRpcResult;
        try {
          result = await jobs().start({
            // The same sentence as the check above, for the awaits BELOW it.
            // start() is asynchronous now: on Windows it writes the job's two
            // scripts and reads them back, and a socket dying inside THAT window
            // left exactly the orphan this handler refuses to create — a running
            // job whose id was never delivered, holding a GPU lock and a
            // concurrency slot that only a restart would free. The manager drops
            // such a start before the spawn and leaves nothing behind.
            signal: socketGone.signal,
            command: msg.command,
            ...(msg.cwd !== undefined ? { cwd: msg.cwd } : {}),
            ...(msg.env !== undefined ? { env: msg.env } : {}),
            ...(msg.name !== undefined ? { name: msg.name } : {}),
            ...(msg.gpuIndex !== undefined ? { gpuIndex: msg.gpuIndex } : {}),
          });
        } catch (err) {
          // A start that THREW, which is a different event from one that
          // REFUSED and the one the log used to miss entirely: `job_script_removed`
          // — the antivirus taking our scripts between the write and the spawn —
          // reaches replyJob's catch, so the remote caller learned what happened
          // and the file meant to be attached to the ticket did not.
          //
          // The cause code and our own detail, never the message: the message is
          // written for a human and carries prose and a URL (see JobError).
          diag("job.start_failed", startFailureFields(err));
          throw err;
        }
        // Job id only — never the command, the cwd or the env (see diag-log.ts).
        //
        // `ok` is not the same as "a command started". A start cancelled inside
        // the record→pid window also answers ok/job — with a TERMINAL job, the
        // `unknown` the cancel settled it as (job-manager's cancel()) — and no
        // process of it ever existed. Logging that as `job.start` put a claim in
        // the vendor-bound file that the machine can disprove: a command that
        // provably never ran. The ending is already in the log twice over,
        // through the cancel's own `job.cancel` and settle()'s `job.exit`, so
        // there is nothing to add here beyond not lying.
        if (result.ok && result.kind === "job") {
          if (result.job.status === "running") diag("job.start", { jobId: diagJobId(result.job.jobId) });
        } else if (!result.ok) diag("job.refused", { reason: result.reason });
        return result;
      });
    };

    /**
     * Run one file transfer and answer the relay.
     *
     * Deliberately NOT awaited by the message handler: a transfer takes as long as
     * the bytes take, and blocking the socket would stop `do:ping` from being
     * answered — the relay would then declare the machine dead in the middle of a
     * perfectly healthy 100 MiB upload. Job RPCs are answered as soon as they
     * resolve precisely because they are disk-local and quick — a start's own
     * I/O is two small files in the job's directory; this one cannot be.
     *
     * Detached is not the same as untracked. Every transfer is registered here with
     * its own AbortController for the same reason `activeCommand` exists: work that
     * outlives the frame that started it has to be reachable from teardown. Untracked,
     * disabling the agent or resetting its access code left an upload still streaming
     * the user's bytes and a push still about to overwrite a file, both AFTER access
     * was revoked — revocation that revokes nothing.
     */
    const replyFile = (requestId: string, run: (signal: AbortSignal) => Promise<FileRpcResult>): void => {
      const transfer = new AbortController();
      inFlightTransfers.add(transfer);
      void (async () => {
        let reply: AgentToDoMsg;
        try {
          reply = { type: "agent:file_result", requestId, result: await run(transfer.signal) };
        } catch {
          // The thrown value is never surfaced: an fs/fetch error message routinely
          // embeds the path, which is payload.
          reply = {
            type: "agent:file_error",
            requestId,
            error: "The file transfer failed on the target machine.",
          };
        } finally {
          inFlightTransfers.delete(transfer);
        }
        // The socket may have died during a long transfer. Nothing to do about it:
        // the relay times the request out, and for a push the file is already
        // written (atomically), which is the outcome the caller asked for anyway.
        if (settled) return;
        try { ws.send(JSON.stringify(reply)); } catch { /* socket gone */ }
      })();
    };

    // Stop every detached transfer. Called from both teardown paths alongside
    // abortActiveCommand, which is the whole point: a transfer is in-flight work on
    // this connection, and this connection is over.
    const abortTransfers = (): void => {
      for (const transfer of inFlightTransfers) {
        try { transfer.abort(); } catch { /* connection cleanup remains terminal */ }
      }
      inFlightTransfers.clear();
    };

    // Rotate the token only while idle: if a command is running when the timer
    // fires, defer the rotation rather than interrupting it. A transfer counts as
    // busy for exactly the same reason — rotating closes the socket, and a transfer
    // whose socket is gone finishes with nobody left to tell, leaving an orphaned
    // upload or a push whose success the caller never learns.
    const scheduleReauth = () => {
      if (!opts.reauthIntervalMs || !opts.reauth) return;
      const check = () => {
        if (activeCommand || inFlightTransfers.size > 0) { reauthTimer = setTimeout(check, 30_000); return; }
        reauthRequested = true;
        ws.close(1000, 'reauth');
      };
      reauthTimer = setTimeout(check, opts.reauthIntervalMs);
    };

    const doResolve = () => { if (!settled) { settled = true; socketGone.abort(); clearReauth(); abortActiveCommand(); abortTransfers(); stopGpuPoll(); stopElevatedReconcile(); resolve(reauthRequested); } };
    const doReject = (err: Error) => { if (!settled) { settled = true; socketGone.abort(); clearReauth(); abortActiveCommand(); abortTransfers(); stopGpuPoll(); stopElevatedReconcile(); reject(err); } };

    const resetPingTimeout = () => {
      callOnHeartbeat();
      if (pingTimeout) clearTimeout(pingTimeout);
      // If no ping received in 90s, consider connection dead
      pingTimeout = setTimeout(() => {
        ws.terminate();
        doReject(new Error("Ping timeout"));
      }, 90_000);
    };

    // Being disabled stops the transfers immediately rather than waiting for the
    // close handshake to come back around: the bytes are the thing being revoked.
    opts.signal?.addEventListener('abort', () => { abortTransfers(); ws.close(1000, 'disabled'); }, { once: true });

    // Push the latest screen-share state to the relay whenever the desktop grant
    // flips (user toggle or 24h expiry), so an MCP caller always sees current
    // state without making a call. Registered on open, removed on close.
    const onScreenShareChange = () => {
      if (settled) return;
      const msg: AgentToDoMsg = {
        type: "agent:screen_state",
        screenShare: opts.screenShare?.getState() ?? SCREEN_SHARE_OFF,
      };
      try { ws.send(JSON.stringify(msg)); } catch { /* socket gone */ }
    };

    ws.on("open", () => {
      diag("conn.ws_open");
      callOnStatus('connected');
      resetPingTimeout();
      scheduleReauth();
      // Register IMMEDIATELY, with no elevated advertisement: helper discovery
      // scans candidate endpoints with retries and can take seconds in the worst
      // case, and until agent:register lands the relay treats this machine as
      // offline. Elevated capability is advertised by a follow-up register the
      // moment discovery completes (reconcileElevated below) — the relay handles
      // repeated agent:register frames on one socket.
      //
      // It does carry the REASON when the reason is knowable without probing —
      // no helper on this platform, or the files are not installed. Both are two
      // `existsSync` calls and neither can be overturned by discovery, so the
      // first frame is already right and reconcileElevated finds nothing to
      // change. Without it every helper-less machine in the fleet (all of Linux,
      // every mac/Windows box without one) sent a second agent:register on every
      // connection, and each register costs the relay two storage writes, a
      // pending-register clear, a dashboard broadcast and a ping.
      sendRegister(undefined, staticElevatedUnavailableReason());
      // reconcileElevated discovers the reachable helper (candidate scan +
      // handshake) and re-registers advertising its per-boot nonce; installed-but-
      // unreachable stays elevatedExec:false (fail-closed). It then keeps running
      // on an interval, so a helper installed, removed, or restarted (new bootId /
      // different pool ports) AFTER we connected is picked up without a reconnect.
      // The do:elevated_exec onBootId callback is the fast path for a restart
      // observed mid-command; the interval is the catch-all.
      void reconcileElevated();
      elevatedReconcile = setInterval(() => { void reconcileElevated(); }, 60_000);
      elevatedReconcile.unref?.();
      // GPU telemetry, only on machines that have any. A later probe returning
      // undefined (driver hiccup, nvidia-smi wedged) is IGNORED rather than
      // published: "we could not read the card" is not the same claim as "the
      // card is gone", and the relay's last known value plus the online flag
      // already tell a caller how stale the reading is.
      if (latestGpus) {
        gpuPoll = setInterval(() => {
          void (async () => {
            const state = await probeGpuState();
            // A re-probe that learned NOTHING changes nothing: a failed re-probe
            // is not news, and must never downgrade the local list to "none" and
            // start refusing gpuIndex on a box that has cards.
            if (settled || state.certainty === "unknown") return;
            // A CONFIDENT result does update it — including a confident EMPTY
            // one. Since the rework, "none" can only come from an nvidia-smi that
            // ran and reported zero devices, which is real information: a card
            // pulled, failed, or handed to another container is exactly the case
            // where continuing to accept its index would start a phantom job.
            gpuKnowledge.learn(state);
            // The WIRE half keeps its stricter rule: only a non-empty list is
            // published, and `[]` is never sent (AgentRegisterMsg.gpus). So a
            // confident-empty re-probe tightens local validation while the relay
            // keeps its last known reading — "we read the card" and "the card is
            // gone" stay different claims on the wire.
            const gpus = wireGpus(state);
            if (!gpus) return;
            latestGpus = gpus;
            const msg: AgentToDoMsg = { type: "agent:gpu_state", gpus };
            try { ws.send(JSON.stringify(msg)); } catch { /* socket gone */ }
          })();
        }, GPU_POLL_INTERVAL_MS);
        gpuPoll.unref?.();
      }
      opts.screenShare?.on("change", onScreenShareChange);
      if (!opts.silent) showRelayConnected();
    });

    ws.on("message", (raw) => {
      let msg: DoToAgentMsg;
      try {
        msg = JSON.parse(String(raw)) as DoToAgentMsg;
      } catch {
        return;
      }

      switch (msg.type) {
        case "do:ping":
          resetPingTimeout();
          const pong: AgentToDoMsg = { type: "agent:pong", ts: msg.ts };
          ws.send(JSON.stringify(pong));
          break;

        case "do:exec": {
          const { commandId, command, cwd, env: cmdEnv, shell } = msg;
          const commandState = beginCommand(commandId);
          if (!commandState) break;
          // Treat the relay frame as untrusted even though the Worker normally
          // normalizes it first. This local deadline is the final enforcement
          // boundary: it kills the process and reports a deterministic terminal
          // error without depending on Worker/DO timers or another network hop.
          const timeoutMs = clampCommandTimeout(msg.timeoutMs);

          const onDone = (exitCode: number, durationMs: number) => {
            if (!settleCommandExecution(commandState)) return;
            commandState.kill = null;
            callOnActivity(false);
            if (commandState.terminalResponseSent) return;
            commandState.terminalResponseSent = true;
            if (!opts.silent) showDone("command", exitCode, durationMs);
            const done: AgentToDoMsg = { type: "agent:done", commandId, exitCode, durationMs };
            ws.send(JSON.stringify(done));
          };
          const onError = (error: string) => {
            if (!settleCommandExecution(commandState)) return;
            commandState.kill = null;
            callOnActivity(false);
            if (commandState.terminalResponseSent) return;
            commandState.terminalResponseSent = true;
            const errMsg: AgentToDoMsg = { type: "agent:error", commandId, error };
            ws.send(JSON.stringify(errMsg));
          };

          try {
            // Local output is intentionally metadata-only in every context. In
            // particular, systemd inherits stdout into journald, while library
            // consumers (including desktop) use silent mode.
            if (!opts.silent) showExecuting("command");
            callOnActivity(true);
            callOnRemoteActivity(msg.operator);

            // W4: surface a "possibly stuck" notice if the command goes quiet for a
            // long time. Informational ONLY — never kills (silence is normal for
            // builds, sleeps, and servers). Reset on every output chunk; report at
            // most once per idle stretch.
            let lastOutputAt = Date.now();
            let idleReported = false;
            commandState.idleCheck = setInterval(() => {
              if (commandState.terminalResponseSent || commandState.executionSettled) return;
              const idleMs = Date.now() - lastOutputAt;
              if (idleMs >= EXEC_IDLE_THRESHOLD_MS && !idleReported) {
                idleReported = true;
                const idle: AgentToDoMsg = { type: "agent:exec_idle", commandId, idleMs };
                ws.send(JSON.stringify(idle));
              }
            }, EXEC_IDLE_THRESHOLD_MS);
            commandState.idleCheck.unref?.();

            // The one instant that defines this command's deadline. Derived
            // from the SAME timeoutMs, at the SAME moment the timer below is
            // armed, and handed to the executor so its post-exit drain can end
            // before we would declare a timeout. Recomputing it anywhere else
            // would let the two drift apart, which is precisely the bug.
            const deadlineMs = Date.now() + timeoutMs;
            commandState.timeout = setTimeout(() => {
              if (commandState.executionSettled || commandState.terminalResponseSent) return;
              const kill = commandState.kill;
              commandState.terminalResponseSent = true;
              stopCommandTimeout(commandState);
              stopIdleCheck(commandState);
              commandState.kill = null;
              callOnActivity(false);
              const timedOut: AgentToDoMsg = {
                type: "agent:error",
                commandId,
                error: `Command timed out after ${timeoutMs}ms`,
              };
              try { ws.send(JSON.stringify(timedOut)); } catch { /* socket gone */ }
              // Mark the response terminal before killing: kill() may
              // synchronously deliver the executor's close callback. That
              // callback releases the slot but cannot emit a second terminal
              // response. Async termination keeps the slot occupied meanwhile.
              try { kill?.(); } catch { /* keep the slot fail-closed */ }
            }, timeoutMs);
            commandState.timeout.unref?.();

            const running = executeCommand(command, cwd, cmdEnv, {
              onOutput: (chunk, stream) => {
                if (commandState.terminalResponseSent || commandState.executionSettled) return;
                lastOutputAt = Date.now();
                idleReported = false;
                const out: AgentToDoMsg = { type: "agent:output", commandId, chunk, stream };
                ws.send(JSON.stringify(out));
              },
              onDone,
              onError,
            }, {
              windowsExecLauncherPath: opts.windowsExecLauncherPath,
              deadlineMs,
              // Forwarded verbatim, INCLUDING a value this machine cannot run:
              // the executor refuses it with a message naming what is available
              // here. Silently dropping it would run the command in the default
              // interpreter and report success for a language the caller never
              // asked for. Omitted ⇒ the machine default, as before.
              ...(shell !== undefined ? { shell } : {}),
            });
            // An executor may complete synchronously in tests or fail during
            // startup. Never resurrect its kill handle after a terminal callback.
            if (!commandState.executionSettled) commandState.kill = running.kill;
          } catch (err) {
            // A malformed relay frame or synchronous spawn rejection is returned
            // to the caller, but the Error object is never written locally.
            onError(err instanceof Error ? err.message : String(err));
          }
          break;
        }

        case "do:secure_exec": {
          const { commandId, argv, allowedCommands, input, cwd, env: cmdEnv } = msg;
          const commandState = beginCommand(commandId);
          if (!commandState) break;

          const onDone = (exitCode: number, durationMs: number) => {
            if (!settleCommandExecution(commandState)) return;
            commandState.kill = null;
            callOnActivity(false);
            if (commandState.terminalResponseSent) return;
            commandState.terminalResponseSent = true;
            if (!opts.silent) showDone("secure-exec", exitCode, durationMs);
            const done: AgentToDoMsg = { type: "agent:done", commandId, exitCode, durationMs };
            ws.send(JSON.stringify(done));
          };
          const onError = (error: string) => {
            if (!settleCommandExecution(commandState)) return;
            commandState.kill = null;
            callOnActivity(false);
            if (commandState.terminalResponseSent) return;
            commandState.terminalResponseSent = true;
            const errMsg: AgentToDoMsg = { type: "agent:error", commandId, error };
            ws.send(JSON.stringify(errMsg));
          };

          try {
            // Everything below is inside the try so ANY malformed frame (e.g. a
            // non-array argv) fails closed via onError → agent:error rather than
            // throwing past the switch. Only a validated printable executable
            // basename may enter local display; the rest of argv never does.
            if (!opts.silent) {
              const executableBasename =
                Array.isArray(argv) && typeof argv[0] === "string" ? argv[0] : undefined;
              showExecuting("secure-exec", executableBasename);
            }
            callOnActivity(true);

            // Idle observability, mirroring do:exec.
            let lastOutputAt = Date.now();
            let idleReported = false;
            commandState.idleCheck = setInterval(() => {
              if (commandState.terminalResponseSent || commandState.executionSettled) return;
              const idleMs = Date.now() - lastOutputAt;
              if (idleMs >= EXEC_IDLE_THRESHOLD_MS && !idleReported) {
                idleReported = true;
                const idle: AgentToDoMsg = { type: "agent:exec_idle", commandId, idleMs };
                ws.send(JSON.stringify(idle));
              }
            }, EXEC_IDLE_THRESHOLD_MS);
            commandState.idleCheck.unref?.();

            const running = executeSecureCommand(
              { argv, allowedCommands, input, cwd, env: cmdEnv },
              {
                onOutput: (chunk, stream) => {
                  if (commandState.terminalResponseSent || commandState.executionSettled) return;
                  lastOutputAt = Date.now();
                  idleReported = false;
                  const out: AgentToDoMsg = { type: "agent:output", commandId, chunk, stream };
                  ws.send(JSON.stringify(out));
                },
                onDone,
                onError,
              },
            );
            if (!commandState.executionSettled) commandState.kill = running.kill;
          } catch (err) {
            // Pre-flight rejection (bad platform/privilege, unknown user,
            // disallowed argv, oversized input). Report as a terminal error.
            onError(err instanceof Error ? err.message : String(err));
          }
          break;
        }

        case "do:elevated_exec": {
          const { commandId } = msg;
          const commandState = beginCommand(commandId);
          if (!commandState) break;

          const onDone = (exitCode: number, durationMs: number) => {
            if (!settleCommandExecution(commandState)) return;
            commandState.kill = null;
            callOnActivity(false);
            if (commandState.terminalResponseSent) return;
            commandState.terminalResponseSent = true;
            if (!opts.silent) showDone("elevated-exec", exitCode, durationMs);
            const done: AgentToDoMsg = { type: "agent:done", commandId, exitCode, durationMs };
            ws.send(JSON.stringify(done));
          };
          const onError = (error: string) => {
            if (!settleCommandExecution(commandState)) return;
            commandState.kill = null;
            callOnActivity(false);
            if (commandState.terminalResponseSent) return;
            commandState.terminalResponseSent = true;
            const errMsg: AgentToDoMsg = { type: "agent:error", commandId, error };
            ws.send(JSON.stringify(errMsg));
          };

          try {
            // Payload (the signed capability) never enters local display — it is
            // opaque to the agent, which only relays it to the privileged helper.
            if (!opts.silent) showExecuting("elevated-exec");
            callOnActivity(true);
            callOnRemoteActivity(msg.operator);

            // Idle observability, mirroring do:exec.
            let lastOutputAt = Date.now();
            let idleReported = false;
            commandState.idleCheck = setInterval(() => {
              if (commandState.terminalResponseSent || commandState.executionSettled) return;
              const idleMs = Date.now() - lastOutputAt;
              if (idleMs >= EXEC_IDLE_THRESHOLD_MS && !idleReported) {
                idleReported = true;
                const idle: AgentToDoMsg = { type: "agent:exec_idle", commandId, idleMs };
                ws.send(JSON.stringify(idle));
              }
            }, EXEC_IDLE_THRESHOLD_MS);
            commandState.idleCheck.unref?.();

            const running = executeElevatedCommand(
              msg.capability,
              commandId,
              {
                onOutput: (chunk, stream) => {
                  if (commandState.terminalResponseSent || commandState.executionSettled) return;
                  lastOutputAt = Date.now();
                  idleReported = false;
                  const out: AgentToDoMsg = { type: "agent:output", commandId, chunk, stream };
                  ws.send(JSON.stringify(out));
                },
                onDone,
                onError,
              },
              {
                // Connect the endpoint discovery pinned (the first pool port that
                // answered the handshake — reuse it rather than re-scanning).
                // Omitted (→ default) only if we somehow have no pin;
                // executeElevatedCommand fails closed if that endpoint is dead.
                ...(elevatedEndpointPinned ? { endpoint: elevatedEndpointPinned } : {}),
                // Self-heal on helper restart: if the helper now reports a bootId
                // different from the one we advertised, the relay is minting
                // capabilities bound to a stale nonce (the helper rejects them, so
                // THIS request fails closed — correct). Re-register with the fresh
                // nonce so the NEXT elevated exec succeeds, instead of waiting up
                // to a full reauth cycle (~6h).
                onBootId: (bootId) => {
                  if (!commandState.executionSettled && !settled && bootId !== registeredBootId) {
                    sendRegister(bootId);
                  }
                },
              },
            );
            if (!commandState.executionSettled) commandState.kill = running.kill;
          } catch (err) {
            // Fail-closed: any synchronous rejection is a terminal error, never a
            // fallback to unprivileged exec.
            onError(err instanceof Error ? err.message : String(err));
          }
          break;
        }

        case "do:kill":
          if (activeCommand?.commandId === msg.commandId && activeCommand.kill) {
            // Request termination; the terminal agent:done/error is emitted by
            // the executor's "close" handler once the process tree actually dies
            // (SIGTERM, escalating to SIGKILL). Do not clear activity here — wait
            // for the real terminal so the controller's state stays accurate.
            const commandState = activeCommand;
            const kill = commandState.kill;
            if (!kill) break;
            kill();
            // kill() may synchronously deliver the terminal callback. Only clear
            // the handle on the same token; never reach through to a later slot.
            commandState.kill = null;
          }
          break;

        case "do:screenshot":
          callOnRemoteActivity(msg.operator);
          // `display` is forwarded as-is (including undefined = primary). It is
          // never echoed back from here — the echo the relay reports comes out of
          // the capture itself, so a request we cannot honour can't be reported
          // as honoured.
          void streamScreenshot(ws, msg.requestId, opts.screenShare, msg.display);
          break;

        // Job RPCs. Each is a short, disk-local operation — no output ever streams
        // back here, it is read afterwards with do:job_logs. All resolve at once
        // except do:job_start, which may first wait out the login-shell PATH
        // probe and, on Windows, its own two script files (see startJob).
        case "do:job_start":
          // A job IS a remote operator taking hold of the machine, so the desktop
          // connect-notice must fire for it exactly as it does for do:exec.
          callOnRemoteActivity(msg.operator);
          void startJob(msg);
          break;

        case "do:job_list":
          replyJob(msg.requestId, () =>
            jobs().list({
              ...(msg.status !== undefined ? { status: msg.status } : {}),
              ...(msg.limit !== undefined ? { limit: msg.limit } : {}),
              ...(msg.includeCommand !== undefined ? { includeCommand: msg.includeCommand } : {}),
            }),
          );
          break;

        case "do:job_status":
          replyJob(msg.requestId, () =>
            jobs().status({
              jobId: msg.jobId,
              ...(msg.includeCommand !== undefined ? { includeCommand: msg.includeCommand } : {}),
            }),
          );
          break;

        case "do:job_logs":
          replyJob(msg.requestId, () =>
            jobs().logs({
              jobId: msg.jobId,
              ...(msg.tailLines !== undefined ? { tailLines: msg.tailLines } : {}),
              ...(msg.offsetBytes !== undefined ? { offsetBytes: msg.offsetBytes } : {}),
              ...(msg.maxBytes !== undefined ? { maxBytes: msg.maxBytes } : {}),
            }),
          );
          break;

        case "do:job_cancel":
          // The frame is untrusted and this line is bound for a vendor's inbox:
          // a job id, or the word `invalid` — never the raw field (see diagJobId).
          diag("job.cancel", { jobId: diagJobId(msg.jobId) });
          replyJob(msg.requestId, () => jobs().cancel({ jobId: msg.jobId }));
          break;

        // File transfers. The bytes travel over a separate HTTPS request built from
        // OUR OWN trusted relay origin — the frame carries a one-time token, never a
        // URL, so the relay cannot point this root process at another host.
        case "do:file_pull":
          // A transfer IS a remote operator taking hold of the machine, so the
          // desktop connect-notice fires for it exactly as it does for do:exec.
          callOnRemoteActivity(msg.operator);
          replyFile(msg.requestId, (signal) =>
            // `maxBytes` goes through as-is because pullFileToRelay clamps it to the
            // machine's own ceiling — the relay asks for a limit, it does not set one.
            pullFileToRelay({
              serverUrl: opts.serverUrl,
              path: msg.path,
              token: msg.token,
              maxBytes: msg.maxBytes,
              signal,
            }),
          );
          break;

        case "do:file_push":
          callOnRemoteActivity(msg.operator);
          replyFile(msg.requestId, (signal) =>
            pushFileFromRelay({
              serverUrl: opts.serverUrl,
              destPath: msg.destPath,
              token: msg.token,
              expectedBytes: msg.expectedBytes,
              signal,
            }),
          );
          break;
      }
    });

    ws.on("close", (code) => {
      diag("conn.ws_close", { code });
      if (pingTimeout) clearTimeout(pingTimeout);
      stopGpuPoll();
      opts.screenShare?.off("change", onScreenShareChange);
      abortActiveCommand();
      abortTransfers();
      callOnStatus('disconnected');
      if (code === 1000 || code === 4001) {
        doResolve(); // clean close
      } else {
        // The close reason is relay-controlled and can contain reflected input.
        doReject(new Error(`WebSocket closed (${code}).`));
      }
    });

    ws.on("error", (err) => {
      diag("conn.ws_error", errorFields(err));
      if (pingTimeout) clearTimeout(pingTimeout);
      stopGpuPoll();
      opts.screenShare?.off("change", onScreenShareChange);
      abortActiveCommand();
      abortTransfers();
      callOnStatus('disconnected');
      // Do not propagate ws Error objects: some implementations include the
      // request URL or request headers.
      doReject(new Error("WebSocket connection error."));
    });

    ws.on("unexpected-response", (_req, res) => {
      // A refused UPGRADE, distinct from a refused ticket — different fix.
      diag("conn.ws_upgrade_failed", { status: res.statusCode ?? null });
      doReject(new Error(`Unexpected WebSocket HTTP response (${res.statusCode}).`));
    });
  });
}

/**
 * Capture a screenshot and stream it back as base64 chunks. The grant is
 * re-checked here (defense in depth — the relay/MCP layer also gates it) so a
 * disabled or non-capable agent never leaks pixels. Errors are reported as a
 * single agent:screenshot_error; success ends with agent:screenshot_done.
 */
async function streamScreenshot(
  ws: WebSocket,
  requestId: string,
  provider: ScreenShareProvider | undefined,
  display?: ScreenshotDisplaySelector,
): Promise<void> {
  const send = (msg: AgentToDoMsg) => {
    try { ws.send(JSON.stringify(msg)); } catch { /* socket gone */ }
  };
  const fail = (error: string) =>
    send({ type: "agent:screenshot_error", requestId, error });

  const state = provider?.getState() ?? SCREEN_SHARE_OFF;
  if (!provider || !state.capable) {
    fail("This machine cannot share its screen (desktop macOS/Windows only).");
    return;
  }
  if (!state.enabled) {
    fail("Screen sharing is turned off on this machine.");
    return;
  }
  // The OS permission is a SEPARATE grant from the owner's tray toggle, and on an
  // unattended machine nobody is there to answer the dialog macOS raises at the
  // first real capture. Without this guard the caller gets either a black
  // rectangle it will describe as if it were the screen, or a hang that surfaces
  // 30s later as a generic timeout — both of which hide the one fact that would
  // let a human fix it. "unknown" is NOT treated as a refusal: a failed query is
  // not a denial, and we would rather attempt a capture than invent a blocker.
  const denial = osPermissionRefusal(state.osPermission);
  if (denial) {
    fail(denial);
    return;
  }

  try {
    const { data, mimeType, meta } = await provider.capture({ display });
    if (data.length > SCREENSHOT_MAX_BYTES) {
      const mb = (data.length / (1024 * 1024)).toFixed(1);
      fail(`Screenshot is ${mb} MB, which exceeds the ${SCREENSHOT_MAX_BYTES / (1024 * 1024)} MB limit.`);
      return;
    }
    const b64 = data.toString("base64");
    for (let i = 0; i < b64.length; i += SCREENSHOT_CHUNK_SIZE) {
      send({ type: "agent:screenshot_chunk", requestId, chunk: b64.slice(i, i + SCREENSHOT_CHUNK_SIZE) });
    }
    send({
      type: "agent:screenshot_done",
      requestId,
      mimeType,
      totalBytes: data.length,
      ...(meta ? { meta } : {}),
    });
  } catch (err) {
    fail(`Screenshot failed: ${(err as Error).message}`);
  }
}

/**
 * Turn a non-granted OS screen-capture permission into a sentence a caller — and
 * through it, a human at the far end — can act on. Returns null when there is
 * nothing blocking (granted, unqueryable, or an agent that doesn't report it).
 */
function osPermissionRefusal(permission: ScreenShareState["osPermission"]): string | null {
  switch (permission) {
    case "denied":
      return (
        "macOS is blocking screen capture on this machine: AI Commander does not have the Screen Recording permission. " +
        "The tray's 'Share Screen' toggle is the owner's intent — this is the separate OS permission, and only a person " +
        "at that machine can grant it, in System Settings ▸ Privacy & Security ▸ Screen Recording (enable AI Commander, " +
        "then quit and reopen the app). Retrying before that changes nothing."
      );
    case "not-determined":
      return (
        "macOS has not yet been asked for the Screen Recording permission on this machine, and it prompts for it at the " +
        "first capture — on an unattended machine there is nobody to click Allow, so the screenshot would hang or come " +
        "back blank. Someone at that machine must grant it in System Settings ▸ Privacy & Security ▸ Screen Recording " +
        "(enable AI Commander, then quit and reopen the app). Retrying before that changes nothing."
      );
    case "granted-pending-restart":
      return (
        "macOS has granted AI Commander the Screen Recording permission on this machine, but it was granted after the " +
        "app started — and macOS only hands that permission to an app at launch, so this running copy would capture a " +
        "blank screen. Someone at that machine must quit and reopen AI Commander (the app is prompting them to); " +
        "retrying before that changes nothing."
      );
    case "restricted":
      return (
        "macOS reports screen capture as restricted on this machine — typically an MDM/parental-controls policy, which " +
        "the machine's owner cannot override from System Settings. Retrying will not help; whoever administers the " +
        "device has to allow Screen Recording for AI Commander."
      );
    default:
      // "granted", "unknown", or an agent too old to report it at all.
      return null;
  }
}
