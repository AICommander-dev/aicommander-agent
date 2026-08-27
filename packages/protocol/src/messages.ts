import type { ExecShell } from "./exec-shell.js";

/**
 * Screen-sharing capability + grant state for a machine. Reported by the agent
 * at register time and whenever it changes, so an MCP caller can tell — without
 * making a call — whether a screenshot is even possible right now.
 *
 * - `capable`   — true only on a desktop (mac/win) build that can grab a screen.
 *                 Headless Linux agents report false.
 * - `enabled`   — true while the user's 24h "Share Screen" grant is active.
 * - `expiresAt` — epoch-ms the current grant auto-expires, or null when off.
 * - `osPermission` — the OS-level screen-capture grant, which is a SEPARATE thing
 *                 from `enabled` and is the one that actually decides whether
 *                 pixels come back (see ScreenCaptureOsPermission).
 */
export interface ScreenShareState {
  capable: boolean;
  enabled: boolean;
  expiresAt: number | null;
  /**
   * OPTIONAL — omitted by agents older than 1.0.50, which had no concept of it.
   * `undefined` therefore means "this agent cannot tell us", NOT "denied"; a
   * reader must not turn a missing field into a scary false negative.
   */
  osPermission?: ScreenCaptureOsPermission;
}

/**
 * The OS's own screen-capture permission, distinct from the tray toggle.
 *
 * On macOS, capturing the screen needs the **Screen Recording** TCC grant, which
 * the OS asks for in its own dialog at the first real capture — the user's tray
 * toggle records intent and grants nothing. On an unattended machine there is
 * nobody to click Allow, so "toggle ON + permission not granted" is a real and
 * silent failure mode: that combination is exactly what this field exists to
 * make visible before a caller wastes a screenshot on it.
 *
 * Windows/Linux have no such per-app permission, so those agents report
 * "granted" — there is nothing to ask for, and reporting "unknown" there would
 * make every Windows machine look suspect.
 *
 * "unknown" means the query itself failed, not that capture will fail.
 *
 * "granted-pending-restart" is the macOS window between the two: TCC has recorded
 * the grant, so the OS reports "granted", but the ALREADY-RUNNING app does not
 * gain the capability until it is quit and reopened — until then its captures come
 * back blank or black. Reporting that window as plain "granted" is the same silent
 * false success this whole field exists to prevent, so the desktop reports it
 * separately: the fix is a relaunch by a human at the machine, not a retry.
 */
export type ScreenCaptureOsPermission =
  | "granted"
  | "granted-pending-restart"
  | "denied"
  | "not-determined"
  | "restricted"
  | "unknown";

/**
 * Which display a screenshot request wants: a 0-based index into the machine's
 * display list, or "all" for the whole virtual desktop as one image.
 *
 * Omitted everywhere it appears — an absent selector means the PRIMARY display,
 * which is what every agent did before this field existed.
 */
export type ScreenshotDisplaySelector = number | "all";

/**
 * What the agent ACTUALLY captured, echoed back with the finished image.
 *
 * The relay reports this echo rather than the selector it sent, because an agent
 * older than 1.0.50 ignores `display` entirely and returns the primary screen. If
 * the relay described the reply from its own request, a caller asking for display
 * 2 on such a machine would be told it is looking at display 2 while looking at
 * display 0 — a confident, invisible lie. An agent that cannot fill this in sends
 * nothing, and the relay says so out loud instead of guessing.
 *
 * Every field is optional for the same reason: this whole block is absent on an
 * older agent, and a newer agent may learn to fill in more of it later.
 */
export interface ScreenshotCaptureMeta {
  /** How many displays the machine reports; omitted when enumeration failed. */
  displayCount?: number;
  /** Which display these pixels are — 0-based index, or "all" (virtual desktop). */
  display?: ScreenshotDisplaySelector;
  /** Pixel size of the returned image. */
  width?: number;
  height?: number;
  /** Pixel size BEFORE any downscale; equal to width/height when nothing was scaled. */
  sourceWidth?: number;
  sourceHeight?: number;
  /** True when the image was downscaled to fit the size cap (see SCREENSHOT_MAX_BYTES). */
  scaled?: boolean;
  /** ISO-8601 capture time on the MACHINE's clock — not the relay's. */
  capturedAt?: string;
  /** One line per display, for a caller deciding which one to ask for next. */
  displays?: ScreenshotDisplayInfo[];
}

/** One display on the machine, as the agent enumerated it. */
export interface ScreenshotDisplayInfo {
  /** 0-based index; the value to pass back as `display`. */
  index: number;
  width: number;
  height: number;
  /** True for the display a screenshot with no `display` argument returns. */
  primary: boolean;
}

/**
 * One CUDA device as reported by `nvidia-smi` on the agent's machine.
 *
 * Exists so an MCP caller can pick a box for a compute job from data it already
 * fetches (list_machines / session_status) instead of blind-probing every machine
 * with a shell command. Everything here is a point-in-time reading the agent
 * re-pushes on a timer: `name`/`memoryTotalMiB` are effectively static, while
 * `memoryUsedMiB`/`utilizationPct` are the fields that actually decide "is this
 * card free?" and go stale within seconds of the machine going offline.
 */
export interface GpuDevice {
  /** nvidia-smi device index; also the value to pass as a job's `gpuIndex`. */
  index: number;
  /** Marketing name, e.g. "NVIDIA GeForce RTX 5080". */
  name: string;
  memoryTotalMiB: number;
  memoryUsedMiB: number;
  utilizationPct: number;
  /** Driver version, when nvidia-smi reports one. */
  driverVersion?: string;
}

// Agent → Durable Object
export interface AgentRegisterMsg {
  type: "agent:register";
  hostname: string;
  platform: string;
  arch: string;
  agentVersion: string;
  /** Desktop (mac/win) screen-share state; omitted by headless agents. */
  screenShare?: ScreenShareState;
  /**
   * True when this machine can run relay-signed elevated commands right now: a
   * privileged helper (mac LaunchDaemon / Windows Service) is installed and reachable,
   * or (headless Linux) the agent already runs as root. The relay refuses elevated
   * remote_exec unless the target advertised this, so an old agent or a desktop
   * without the helper fails closed instead of silently running unprivileged.
   */
  elevatedExec?: boolean;
  /**
   * The privileged helper's CURRENT per-boot nonce, learned by the agent doing a
   * handshake to the helper at register time. Present ⟺ the agent actually reached
   * the helper (so `elevatedExec` is true). The relay binds this into every elevated
   * capability's `helperInstanceId`; the helper then rejects any capability not
   * bound to its own current boot — this is what machine/boot-binds a capability
   * (the fleet-wide signing key does not). A helper restart changes it, invalidating
   * outstanding capabilities until the agent re-registers with the new value.
   */
  elevatedBootId?: string;
  /**
   * NVIDIA devices found on this machine. OMITTED ENTIRELY when the probe found
   * none (no driver, no card, macOS): `undefined` means "unknown or none" and an
   * empty array would claim the same thing less clearly, so agents must never
   * send `[]`. Consumers therefore only ever test for presence.
   */
  gpus?: GpuDevice[];
  /**
   * True from the agent version that implements the `do:job_*` RPCs onward. An
   * older agent's message switch drops unknown types SILENTLY, so a job call sent
   * to it would hang until JOB_RPC_TIMEOUT_MS with no explanation. The relay
   * refuses job calls outright when this flag is absent — same fail-closed shape
   * as `elevatedExec`, turning version skew into a clear "update the agent".
   */
  jobs?: boolean;
  /**
   * True from the agent version that HONOURS `DoExecMsg.shell` onward. An older agent
   * destructures only the fields it knows off `do:exec`, so a `shell` it has never heard
   * of is dropped and the command runs in the machine's DEFAULT interpreter while the
   * caller believes otherwise — a silent false success. The relay refuses any exec
   * carrying `shell` when this flag is absent: same fail-closed shape as `elevatedExec`
   * and `jobs`, turning version skew into an actionable "update the agent".
   */
  shellSelect?: boolean;
  /**
   * True from the agent version that answers the `do:file_*` RPCs onward. Same
   * fail-closed contract as `jobs`: an older agent drops an unknown message type
   * silently, so a transfer sent to one would hang until FILE_RPC_TIMEOUT_MS —
   * ten minutes of a caller waiting for a machine that never heard the request.
   * The relay refuses file calls outright unless the CURRENTLY connected agent
   * advertised this.
   */
  fileTransfer?: boolean;
}

/** Pushed whenever the desktop screen-share grant changes (toggle / 24h expiry). */
export interface AgentScreenStateMsg {
  type: "agent:screen_state";
  screenShare: ScreenShareState;
}

/**
 * Pushed on a timer (GPU_POLL_INTERVAL_MS) while the machine has at least one
 * NVIDIA device, so used-VRAM/utilization in the relay's stored agentInfo stay
 * fresh enough to pick a card. Mirrors AgentScreenStateMsg: a full replacement
 * snapshot, never a delta — the relay overwrites, it does not merge. Agents with
 * no GPU never send this at all.
 */
export interface AgentGpuStateMsg {
  type: "agent:gpu_state";
  gpus: GpuDevice[];
}

/** One base64 slice of a screenshot, in order. Terminated by AgentScreenshotDoneMsg. */
export interface AgentScreenshotChunkMsg {
  type: "agent:screenshot_chunk";
  requestId: string;
  chunk: string; // base64 slice of the full image
}

export interface AgentScreenshotDoneMsg {
  type: "agent:screenshot_done";
  requestId: string;
  mimeType: string;
  totalBytes: number;
  /**
   * What was actually captured. OPTIONAL: agents older than 1.0.50 send none, and
   * the relay must describe that reply as "display unknown, primary assumed"
   * rather than repeating back the display it asked for. See ScreenshotCaptureMeta.
   */
  meta?: ScreenshotCaptureMeta;
}

export interface AgentScreenshotErrorMsg {
  type: "agent:screenshot_error";
  requestId: string;
  error: string;
}

export interface AgentOutputMsg {
  type: "agent:output";
  commandId: string;
  chunk: string; // base64-encoded
  stream: "stdout" | "stderr";
}

export interface AgentDoneMsg {
  type: "agent:done";
  commandId: string;
  exitCode: number;
  durationMs: number;
}

export interface AgentErrorMsg {
  type: "agent:error";
  commandId: string;
  error: string;
}

export interface AgentPongMsg {
  type: "agent:pong";
  ts: number;
}

/**
 * Informational: a running command has produced no output for a while and has
 * not exited. Purely observational — the agent never kills on idle (silence is
 * normal for builds, sleeps, and servers). Surfaced so an operator can decide.
 */
export interface AgentExecIdleMsg {
  type: "agent:exec_idle";
  commandId: string;
  idleMs: number;
}

// ── Detached jobs ────────────────────────────────────────────────────────────
// A job is a long-running command (training runs, dataset processing, long
// builds) that outlives the request that started it: its output goes to a file
// ON THE TARGET MACHINE and only bounded slices ever cross the relay. That is
// what lifts `do:exec`'s two different caps: the 1 h deadline hard-kills the
// process tree, while MAX_OUTPUT_TOTAL_BYTES truncates the reply and triggers a
// best-effort stop that can lose its race with the command. All job state lives
// on the machine's disk, so a job survives agent restart, relay disconnection
// and the caller going away; the relay stays a stateless pass-through.

/**
 * - `running` — the process was alive at the moment the agent looked.
 * - `exited`  — the wrapper wrote an exit code to disk; `exitCode` is authoritative.
 * - `unknown` — the agent restarted and the pid is gone with no exit file, so the
 *               outcome is genuinely unknowable. Deliberately NOT collapsed into
 *               "exited": reporting a success we cannot prove is the worse error.
 */
export type JobStatus = "running" | "exited" | "unknown";

/** What a job's on-disk state looks like to a caller. */
export interface JobSummary {
  jobId: string;
  /** Caller-supplied label, or an agent-generated one; purely for human/agent recall. */
  name: string;
  status: JobStatus;
  /** Non-null only for `exited`; `null` while running and for `unknown`. */
  exitCode: number | null;
  /** Epoch ms. */
  startedAt: number;
  /** Epoch ms the job ended; null while running. */
  endedAt: number | null;
  /**
   * True when `endedAt` is an ESTIMATE rather than an observed instant.
   *
   * An `exited` job's timestamp comes from the exit file the wrapper wrote, so it
   * is the moment the process really finished. An `unknown` job's cannot: nobody
   * recorded an ending, so the agent estimates one from the last byte written to
   * output.log (floored at `startedAt`, and falling back to "when we noticed" for
   * a job that never wrote anything). Measured skew of the old
   * noticed-it-just-now value: ~14 s on Linux, 1 m 52 s on Windows — where NTFS
   * additionally defers last-write-time updates while the wrapper holds the log
   * open, so the estimate there may still be minutes late.
   *
   * Optional per the one-directional widening contract (see jobs-relay.ts): an
   * older relay simply ignores it. Absent means "not an estimate" — every
   * `exited` job, and every record written before this field existed.
   */
  endedAtApproximate?: boolean;
  /** The card reserved for this job via the GPU lock, or null if none was requested. */
  gpuIndex: number | null;
  /** Current size of output.log — lets a caller page logs without a probe read. */
  logBytes: number;
  /** True once output.log hit JOB_MAX_LOG_BYTES and the agent stopped appending. */
  truncated: boolean;
  /**
   * The job's command line. Present ONLY when the caller explicitly asked for it
   * (`includeCommand`): a command string is user payload, and the payload-safety
   * invariant keeps it out of every reply that did not specifically request it.
   */
  command?: string;
}

/**
 * One bounded slice of a job's output.log. `chunk` is base64 for the same reason
 * AgentOutputMsg.chunk is: process output is arbitrary bytes, not valid UTF-8.
 *
 * Pagination is byte-offset based rather than cursor based so it is stateless on
 * both sides: feed `nextOffsetBytes` back as `offsetBytes` to follow a growing
 * log. `eof` means "you have read up to the current end", not "the job ended" —
 * a running job will have more later.
 */
export interface JobLogs {
  jobId: string;
  /** base64 of the raw slice; decoded length ≤ JOB_LOGS_MAX_SLICE_BYTES. */
  chunk: string;
  /** Byte offset in output.log this slice starts at. */
  offsetBytes: number;
  /** Offset to pass next; equals offsetBytes + decoded chunk length. */
  nextOffsetBytes: number;
  /** True when nextOffsetBytes is the current end of the file. */
  eof: boolean;
  /** True when output.log itself is truncated (see JobSummary.truncated). */
  truncated: boolean;
}

/**
 * Why a job RPC was refused. These are EXPECTED outcomes with a machine-readable
 * shape, distinct from `agent:job_error` (which means something went wrong): the
 * caller is meant to branch on them, e.g. poll-and-retry on `gpu_busy`.
 */
export type JobRefusalReason =
  /** The requested gpuIndex is already reserved; `heldBy` names the holder. v1 refuses rather than queues. */
  | "gpu_busy"
  /** No job with that id on this machine — also the answer for a malformed id, so probing reveals nothing. */
  | "not_found"
  /** JOB_MAX_CONCURRENT already running on this machine. */
  | "too_many_jobs"
  /**
   * The REQUEST ITSELF cannot succeed, on this machine or any other: no command,
   * a command past the size cap, a relative `cwd`, a gpuIndex that cannot name a
   * card. Decided from the request alone, with no machine state involved — which
   * is exactly what separates it from `agent:job_error`. It travels as a refusal
   * so the caller learns "fix the request" (REST maps it to 400) instead of the
   * "the machine failed" 502 an error frame necessarily means.
   */
  | "invalid_request";

export interface JobRefusal {
  ok: false;
  reason: JobRefusalReason;
  /** The jobId currently holding the GPU; set only for `gpu_busy`. */
  heldBy?: string;
  /** Human-readable detail, safe to surface to the caller (never job output). */
  message?: string;
}

/**
 * The single reply payload for every `do:job_*` RPC — one type keeps the DO a
 * dumb router that never has to know which call it is forwarding. Discriminate
 * on `ok` first, then on `kind`.
 */
export type JobRpcResult =
  /** Reply to job_start / job_status / job_cancel. */
  | { ok: true; kind: "job"; job: JobSummary }
  /**
   * Reply to job_list. `omitted` is how many stored records the agent did NOT
   * walk because the page was full — present only when it is greater than zero,
   * so a caller can render "N older jobs not shown" and ask for them with a
   * bigger `limit`. It counts RECORDS, not matches: with a `status` filter the
   * agent stops walking at the first N matches and cannot know how many of the
   * records behind them would have matched, so treat it as an upper bound there.
   *
   * Optional per the one-directional widening contract (see jobs-relay.ts).
   */
  | { ok: true; kind: "jobs"; jobs: JobSummary[]; omitted?: number }
  /** Reply to job_logs. */
  | { ok: true; kind: "logs"; logs: JobLogs }
  | JobRefusal;

/**
 * Why a machine refused a file transfer.
 *
 * A refusal is an ANSWER, not a transport failure: the machine was reached, it
 * understood the request, and it is telling the caller something actionable about
 * the filesystem. Each reason maps to a different next move, which is the whole
 * reason they are distinguished rather than collapsed into one error string:
 *  - `not_found`      — nothing at that path (typo, or the job has not written it yet)
 *  - `not_a_file`     — a directory or a device; archive it first
 *  - `too_large`      — over FILE_MAX_BYTES; push it to the caller's own storage instead
 *  - `unreadable`     — it exists but the agent cannot read it (permissions)
 *  - `unwritable`     — the destination cannot be written (permissions, missing parent,
 *                       no space)
 *  - `transfer_failed`— the bytes did not make it between machine and relay
 *  - `invalid_request`— the request itself is malformed (relative path, bad token)
 */
export type FileTransferRefusalReason =
  | "not_found"
  | "not_a_file"
  | "too_large"
  | "unreadable"
  | "unwritable"
  | "transfer_failed"
  | "invalid_request";

/** A refused file transfer. `message` is agent-authored and always bounded. */
export interface FileTransferRefusal {
  ok: false;
  reason: FileTransferRefusalReason;
  /**
   * Optional detail. NEVER the path, the file's contents, or an errno string: this
   * text is rendered straight to an LLM caller, and everything about the file is
   * payload. The reason code carries the meaning; this only ever adds a bound.
   */
  message?: string;
}

/**
 * What a machine reports after a transfer it actually performed.
 *
 * `bytes` is the size the machine moved, and it is deliberately the only fact
 * reported back: not a hash, not an mtime, not a mode. The relay counts the same
 * bytes independently while streaming, and disagreeing with the machine is how a
 * partial transfer is caught.
 */
export type FileRpcResult =
  | { ok: true; kind: "pulled"; bytes: number }
  | { ok: true; kind: "pushed"; bytes: number }
  | FileTransferRefusal;

/**
 * Reply to any `do:job_*`, correlated by the request's `requestId` — the
 * screenshot pattern, not the streaming exec pattern: the DO routes it back to
 * the ONE waiting caller (sendToCommand), never broadcasts it, because a job's
 * command line and log bytes are private to whoever asked.
 */
export interface AgentJobResultMsg {
  type: "agent:job_result";
  requestId: string;
  result: JobRpcResult;
}

/**
 * The RPC failed for a reason that is not an expected refusal (unreadable job
 * directory, spawn failure, …). `error` is a human-readable message and must
 * never carry job output or the command string.
 */
export interface AgentJobErrorMsg {
  type: "agent:job_error";
  requestId: string;
  error: string;
}

/**
 * A machine's answer to a file RPC. Mirrors AgentJobResultMsg: routed back to the
 * single admin whose requestId it matches, never broadcast — a reply concerns one
 * caller's file and nobody else's.
 */
export interface AgentFileResultMsg {
  type: "agent:file_result";
  requestId: string;
  result: FileRpcResult;
}

/** A file RPC that failed on the machine in a way no refusal reason describes. */
export interface AgentFileErrorMsg {
  type: "agent:file_error";
  requestId: string;
  error: string;
}

/**
 * Who is driving a remote command, carried through to the agent so the desktop
 * app can warn the local user that someone connected. `id` is a STABLE per-operator
 * key the agent uses ONLY for rate-limiting/dedup of the connect notice — a signed-in
 * account's userId, or the literal "anon" for anonymous session-code callers (who all
 * share one bucket, since the shared code can't tell them apart). The agent resolves a
 * human-readable label locally from its linked-accounts list; none is sent on the wire.
 */
export interface RemoteOperator {
  id: string;
  anonymous: boolean;
}

// Durable Object → Agent
export interface DoExecMsg {
  type: "do:exec";
  commandId: string;
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  /**
   * Which interpreter to run `command` in (see exec-shell.ts). OMITTED means "this
   * machine's default" — `/bin/sh -c` on POSIX, `cmd.exe /d /s /c` on Windows — which
   * is exactly what every agent did before the field existed, so omitting it is always
   * safe across version skew. PRESENT is a hard requirement: the agent must run that
   * interpreter or answer agent:error, never fall back to the default. The relay only
   * ever sends it to an agent that advertised `shellSelect` at register time.
   */
  shell?: ExecShell;
  /** Present for operator-driven exec (remote_exec); omitted by automation paths. */
  operator?: RemoteOperator;
}

/**
 * Sandboxed execution, reached only via a service token (never `remote_exec`).
 * Carries an explicit argv[] — the agent runs it WITHOUT a shell, so metacharacters
 * are inert literals and injection is impossible by construction. The agent checks
 * `basename(argv[0])` against `allowedCommands` and the shared command denylist,
 * verifies the local sandbox user's groups, drops to the dedicated non-root
 * SECURE_EXEC_USER (uid resolved locally, never from this message), and feeds
 * `input` (base64, ≤ SECURE_EXEC_MAX_INPUT_BYTES decoded) to the child's stdin.
 * Output reuses agent:output / agent:done / agent:error, routed by commandId.
 */
export interface DoSecureExecMsg {
  type: "do:secure_exec";
  commandId: string;
  argv: string[];
  /** Command basenames this token may run; agent rejects argv[0] outside it. */
  allowedCommands: string[];
  /** Optional stdin payload, base64-encoded; ≤ SECURE_EXEC_MAX_INPUT_BYTES decoded. */
  input?: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

/**
 * The claims inside a relay-signed elevated-execution capability. The Worker (relay)
 * signs these with the private half of a pinned Ed25519 key; the per-machine
 * privileged helper (root/LocalSystem) verifies the signature against the pinned
 * PUBLIC half before running ANYTHING elevated.
 *
 * The security model is deliberately relay-anchored, NOT local-channel-anchored:
 * the local IPC auth (peer-cred + shared secret) is only channel hygiene, so a
 * same-user process that reaches the socket/pipe still cannot MINT a new root
 * command — it can only replay a live, signed, short-lived, single-use one.
 *
 * Binding rules the helper MUST enforce (see verifyElevatedCapability):
 *  - signature valid against the pinned public key; ANY altered field ⇒ reject;
 *  - `expiresAt` in the future and the window short (minutes, not hours);
 *  - `requestId` not seen before (anti-replay); it equals the command's id;
 *  - `helperInstanceId` equals the helper's current per-boot nonce (bootId): the
 *    relay ALWAYS binds it and the helper REQUIRES it — a missing or mismatched
 *    value is rejected. This machine/boot-binds the capability, invalidating every
 *    capability minted before the last helper restart and blocking remote replay;
 *  - `deviceId`, when present, matches this machine's bound identity.
 */
export interface ElevatedCapabilityClaims {
  /** Bumped when the claim shape or verification rules change; helper pins a min. */
  protocolVersion: number;
  /** Peppered device identity this capability is bound to (absent on legacy sessions). */
  deviceId?: string;
  /** Account that authorized this elevated command (elevated is account-only). */
  accountId: string;
  /** Anti-replay + correlation; equals the DoElevatedExecMsg.commandId. */
  requestId: string;
  /** The EXACT shell command to run elevated. The unsigned copy on the wire is display-only. */
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs: number;
  /**
   * Helper per-boot nonce (bootId). Mandatory in practice: the relay always binds
   * the value the agent reported (`elevatedBootId`), and the helper REQUIRES
   * `helperInstanceId === its bootId` (missing/mismatched ⇒ rejected). Optional in
   * the type only for legacy/shape compatibility.
   */
  helperInstanceId?: string;
  /** Epoch ms the relay signed this. */
  issuedAt: number;
  /** Epoch ms this capability stops being valid (short window). */
  expiresAt: number;
}

export interface DoPingMsg {
  type: "do:ping";
  ts: number;
}

/**
 * Durable Object → Agent: run ONE command with elevated privileges (root on macOS,
 * LocalSystem on Windows) via the per-machine privileged helper.
 *
 * DELIBERATELY a DISTINCT message type, not an `elevated` flag on DoExecMsg: an older
 * agent destructures only the fields it knows on `do:exec` and would SILENTLY run an
 * elevated request as the ordinary user (fail-OPEN). A distinct type falls through the
 * agent's switch and does nothing — the caller times out — so version skew fails CLOSED.
 * The relay only ever sends this to an agent that advertised `elevatedExec` at register.
 *
 * `capability` is a compact-JWS (EdDSA) ElevatedCapabilityClaims; the helper verifies it.
 * The agent itself does NOT trust or parse it — it relays it to the helper and, if no
 * helper is installed/running, returns agent:error (never falls back to unprivileged exec).
 */
export interface DoElevatedExecMsg {
  type: "do:elevated_exec";
  commandId: string;
  /** Compact JWS (EdDSA) of ElevatedCapabilityClaims; verified by the privileged helper. */
  capability: string;
  /**
   * Cleartext copy of the (clamped) timeout, used SOLELY for the DO's active-command
   * bookkeeping (the guard that rejects a concurrent command and clears on settle).
   * The authoritative, enforced timeout is the one SIGNED inside the capability and
   * verified by the privileged helper — never trust this field for enforcement.
   */
  timeoutMs: number;
  /** Present for operator-driven exec (remote_exec); omitted by automation paths. */
  operator?: RemoteOperator;
}

export interface DoKillMsg {
  type: "do:kill";
  commandId: string;
}

/** Request the agent to capture and stream back a screenshot. */
export interface DoScreenshotMsg {
  type: "do:screenshot";
  requestId: string;
  /** Present for operator-driven screenshots; omitted by automation paths. */
  operator?: RemoteOperator;
  /**
   * Which display to capture. OPTIONAL, and safe to send to ANY agent: one that
   * predates the field simply destructures around it and captures the primary
   * display as it always did — which is why the reply carries an echo (see
   * AgentScreenshotDoneMsg.meta) instead of the relay assuming it was honored.
   */
  display?: ScreenshotDisplaySelector;
}

/**
 * Start a detached job. Strictly ⊆ the power `do:exec` already grants — same
 * authorization chain, and `elevated` has no counterpart here by design.
 *
 * The reply is a single agent:job_result carrying the new job's JobSummary; the
 * job's output never streams back, it is read afterwards with do:job_logs.
 */
export interface DoJobStartMsg {
  type: "do:job_start";
  requestId: string;
  command: string;
  /** Defaults to the job's own workspace directory, giving each job a clean cwd. */
  cwd?: string;
  env?: Record<string, string>;
  /** Human-readable label for later recall; the agent generates one if omitted. */
  name?: string;
  /**
   * Reserve this GPU for the job (exclusive lock + CUDA_VISIBLE_DEVICES). Refused
   * with `gpu_busy` if another job holds it — two jobs on one card means OOM.
   */
  gpuIndex?: number;
  /**
   * Present for operator-driven starts, exactly as on do:exec — a job is a remote
   * operator taking hold of the machine, so the desktop connect-notice must fire
   * for it just like it does for remote_exec.
   */
  operator?: RemoteOperator;
}

export interface DoJobListMsg {
  type: "do:job_list";
  requestId: string;
  /** Return only jobs in this state; omitted ⇒ all retained jobs. */
  status?: JobStatus;
  /**
   * How many summaries to return, newest first. Defaults to
   * JOB_LIST_DEFAULT_ENTRIES and is clamped to JOB_WIRE_MAX_LIST_ENTRIES, so a
   * caller can only ever shrink the reply below the page cap, never grow it past
   * one. Whatever is left over is counted in the reply's `omitted`.
   */
  limit?: number;
  /** Include each job's command string (payload — off by default, see JobSummary.command). */
  includeCommand?: boolean;
}

export interface DoJobStatusMsg {
  type: "do:job_status";
  requestId: string;
  jobId: string;
  /** Include the job's command string (payload — off by default, see JobSummary.command). */
  includeCommand?: boolean;
}

export interface DoJobLogsMsg {
  type: "do:job_logs";
  requestId: string;
  jobId: string;
  /**
   * Read the last N lines instead of a byte range — the natural "how is it going?"
   * call. Ignored when `offsetBytes` is given; defaults to
   * JOB_LOGS_DEFAULT_TAIL_LINES when neither is given.
   */
  tailLines?: number;
  /** Read forward from this byte offset; pass back a previous reply's nextOffsetBytes. */
  offsetBytes?: number;
  /** Requested slice size; the agent clamps it to JOB_LOGS_MAX_SLICE_BYTES regardless. */
  maxBytes?: number;
}

/**
 * Terminate a running job (its whole process group / process tree, since a
 * training run is rarely a single process). Cancelling an already-finished job is
 * not an error — the reply is just its current JobSummary.
 */
export interface DoJobCancelMsg {
  type: "do:job_cancel";
  requestId: string;
  jobId: string;
}

/**
 * Read a file off the machine and hand it to the relay.
 *
 * The relay supplies a `token`, NOT a URL. That is a security decision, not an
 * ergonomic one: the agent builds the endpoint from the relay origin it was
 * configured with and already trusts, so a compromised or confused relay cannot
 * point a root process at an arbitrary host. The token authorizes exactly one
 * upload of exactly one blob and is consumed on first use.
 */
export interface DoFilePullMsg {
  type: "do:file_pull";
  requestId: string;
  /** Absolute path on the machine. Relative paths are refused, never resolved. */
  path: string;
  /** One-time upload credential; see the URL note above. */
  token: string;
  /** Refuse before reading anything larger than this (FILE_MAX_BYTES or below). */
  maxBytes: number;
  /** Present for operator-driven transfers, exactly as on do:exec. */
  operator?: RemoteOperator;
}

/**
 * Fetch a stored blob from the relay and write it to the machine.
 *
 * Same token-not-URL contract as do:file_pull. `expectedBytes` lets the agent
 * refuse before it starts writing (no space, over its own ceiling) and lets it
 * detect a short read afterwards rather than leaving a truncated file in place.
 * It is also a HARD CAP on the download: the agent aborts the write at the first
 * byte beyond it, so a relay that hands back a larger object than it declared
 * cannot fill the machine's disk.
 */
export interface DoFilePushMsg {
  type: "do:file_push";
  requestId: string;
  /** Absolute destination path. Written atomically (temp file + rename). */
  destPath: string;
  /** One-time download credential. */
  token: string;
  /** The blob's size as the relay stored it; also the agent's hard write cap. */
  expectedBytes: number;
  /** Present for operator-driven transfers, exactly as on do:exec. */
  operator?: RemoteOperator;
}

// Admin → Durable Object
export interface AdminExecMsg {
  type: "admin:exec";
  commandId: string;
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  /** Forwarded verbatim into do:exec; see DoExecMsg.shell. Omitted ⇒ machine default. */
  shell?: ExecShell;
  /** Identity of the caller, forwarded verbatim into do:exec for the connect notice. */
  operator?: RemoteOperator;
}

/** Admin → DO request to run a sandboxed service-token command (see DoSecureExecMsg). */
export interface AdminSecureExecMsg {
  type: "admin:secure_exec";
  commandId: string;
  argv: string[];
  allowedCommands: string[];
  input?: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
}

/** Admin → DO request to run a relay-signed elevated command (see DoElevatedExecMsg). */
export interface AdminElevatedExecMsg {
  type: "admin:elevated_exec";
  commandId: string;
  /** Compact JWS (EdDSA) of ElevatedCapabilityClaims; forwarded verbatim into do:elevated_exec. */
  capability: string;
  /**
   * Cleartext copy of the (clamped) timeout — the SAME value the relay signed into
   * the capability's claims. Used SOLELY for the DO's active-command bookkeeping, never
   * for enforcement; the authoritative timeout is the signed one the helper verifies.
   */
  timeoutMs: number;
  /** Identity of the caller, forwarded verbatim for the connect notice. */
  operator?: RemoteOperator;
}

export interface AdminKillMsg {
  type: "admin:kill";
  commandId: string;
}

/** Admin asks the DO to obtain a screenshot from the connected agent. */
export interface AdminScreenshotMsg {
  type: "admin:screenshot";
  requestId: string;
  /** Identity of the caller, forwarded verbatim into do:screenshot for the connect notice. */
  operator?: RemoteOperator;
  /** Requested display, forwarded verbatim into do:screenshot (see DoScreenshotMsg.display). */
  display?: ScreenshotDisplaySelector;
}

// Admin → DO job RPCs. Each is forwarded field-for-field into its do:job_*
// counterpart (same requestId), exactly as admin:screenshot → do:screenshot: the
// DO adds no policy of its own beyond the agent-capability check, because the
// authorization decision was already made on the way in.

export interface AdminJobStartMsg {
  type: "admin:job_start";
  requestId: string;
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  name?: string;
  gpuIndex?: number;
  /** Identity of the caller, forwarded verbatim into do:job_start for the connect notice. */
  operator?: RemoteOperator;
}

export interface AdminJobListMsg {
  type: "admin:job_list";
  requestId: string;
  status?: JobStatus;
  includeCommand?: boolean;
  /** Forwarded verbatim into do:job_list; see DoJobListMsg.limit. */
  limit?: number;
}

export interface AdminJobStatusMsg {
  type: "admin:job_status";
  requestId: string;
  jobId: string;
  includeCommand?: boolean;
}

export interface AdminJobLogsMsg {
  type: "admin:job_logs";
  requestId: string;
  jobId: string;
  tailLines?: number;
  offsetBytes?: number;
  maxBytes?: number;
}

export interface AdminJobCancelMsg {
  type: "admin:job_cancel";
  requestId: string;
  jobId: string;
}

/** Admin → DO request to pull a file off the machine (see DoFilePullMsg). */
export interface AdminFilePullMsg {
  type: "admin:file_pull";
  requestId: string;
  path: string;
  token: string;
  maxBytes: number;
  operator?: RemoteOperator;
}

/** Admin → DO request to push a stored blob onto the machine (see DoFilePushMsg). */
export interface AdminFilePushMsg {
  type: "admin:file_push";
  requestId: string;
  destPath: string;
  token: string;
  expectedBytes: number;
  operator?: RemoteOperator;
}

// Durable Object → Admin
export interface DoAgentInfoMsg {
  type: "do:agent_info";
  hostname: string;
  platform: string;
  arch: string;
  agentVersion: string;
  connectedAt: string;
  /** Present when the agent reported screen-share state at register time. */
  screenShare?: ScreenShareState;
  /** Whether the connected agent can run relay-signed elevated commands (see AgentRegisterMsg). */
  elevatedExec?: boolean;
  /** The connected agent's reported helper boot nonce (see AgentRegisterMsg.elevatedBootId). */
  elevatedBootId?: string;
  /** Last known NVIDIA devices; absent when the agent reported none (see AgentRegisterMsg.gpus). */
  gpus?: GpuDevice[];
  /** Whether the connected agent understands the do:job_* RPCs (see AgentRegisterMsg.jobs). */
  jobs?: boolean;
  /** Whether the connected agent honours do:exec `shell` (see AgentRegisterMsg.shellSelect). */
  shellSelect?: boolean;
  /** Whether the connected agent answers the do:file_* RPCs (see AgentRegisterMsg.fileTransfer). */
  fileTransfer?: boolean;
}

/** Relayed screen-share state change (see AgentScreenStateMsg). */
export interface DoScreenStateMsg {
  type: "do:screen_state";
  screenShare: ScreenShareState;
}

/**
 * Relayed GPU reading (see AgentGpuStateMsg). Broadcast to every attached admin
 * like do:screen_state, because a VRAM/utilization snapshot is machine metadata,
 * not the private payload of one request. The last value is kept when the agent
 * goes offline — `online: false` is what marks it stale, not its absence.
 */
export interface DoGpuStateMsg {
  type: "do:gpu_state";
  gpus: GpuDevice[];
}

export interface DoScreenshotChunkMsg {
  type: "do:screenshot_chunk";
  requestId: string;
  chunk: string;
}

export interface DoScreenshotDoneMsg {
  type: "do:screenshot_done";
  requestId: string;
  mimeType: string;
  totalBytes: number;
  /** Relayed verbatim from the agent's echo; absent when the agent sent none. */
  meta?: ScreenshotCaptureMeta;
}

export interface DoScreenshotErrorMsg {
  type: "do:screenshot_error";
  requestId: string;
  error: string;
}

/**
 * Relayed job RPC reply (see AgentJobResultMsg). Routed to the single admin whose
 * requestId it matches — never broadcast, exactly like screenshot bytes: a reply
 * can carry log slices and command strings belonging to that one caller.
 */
export interface DoJobResultMsg {
  type: "do:job_result";
  requestId: string;
  result: JobRpcResult;
}

/** Relayed job RPC failure (see AgentJobErrorMsg). Same per-request routing. */
export interface DoJobErrorMsg {
  type: "do:job_error";
  requestId: string;
  error: string;
}

/** Relayed file RPC reply (see AgentFileResultMsg). Same per-request routing. */
export interface DoFileResultMsg {
  type: "do:file_result";
  requestId: string;
  result: FileRpcResult;
}

/** Relayed file RPC failure (see AgentFileErrorMsg). Same per-request routing. */
export interface DoFileErrorMsg {
  type: "do:file_error";
  requestId: string;
  error: string;
}

export interface DoAuthOkMsg {
  type: "do:auth_ok";
  sessionCode: string;
  agentConnected: boolean;
  /**
   * Whether the connected agent advertised elevated-exec capability. The relay's
   * runCommand path reads this to refuse an elevated request up front (before signing
   * or sending anything) when the target machine has no privileged helper.
   */
  elevatedCapable?: boolean;
  /**
   * The connected agent's current helper boot nonce. The relay binds it into the
   * minted capability's `helperInstanceId` so the helper accepts it only on that
   * exact machine + boot. Absent ⟺ no reachable helper — elevated is refused
   * (fail-closed): a capability with no boot binding would be rejected by the helper.
   */
  elevatedBootId?: string;
  /**
   * Whether the connected agent advertised that it HONOURS the `shell` field on
   * do:exec. The relay's runCommand path reads this to refuse a `shell` request up
   * front (before sending anything) when the target's agent is too old to act on it —
   * an older agent would drop the field and run the machine's default interpreter
   * while reporting success. Absent ⇒ refuse; never send `shell` and hope.
   */
  shellSelectCapable?: boolean;
  /**
   * Whether the connected agent advertised the `do:file_*` RPCs. The relay reads
   * this to refuse a transfer up front rather than sending a frame an older agent
   * would drop silently, leaving the caller to wait out FILE_RPC_TIMEOUT_MS.
   * Absent ⇒ refuse; never send a file request and hope.
   */
  fileTransferCapable?: boolean;
}

export interface DoAuthErrorMsg {
  type: "do:auth_error";
  reason: string;
}

export interface DoOutputMsg {
  type: "do:output";
  commandId: string;
  chunk: string; // base64-encoded
  stream: "stdout" | "stderr";
}

export interface DoDoneMsg {
  type: "do:done";
  commandId: string;
  exitCode: number;
  durationMs: number;
}

export interface DoErrorMsg {
  type: "do:error";
  commandId: string;
  error: string;
}

export interface DoAgentDisconnectedMsg {
  type: "do:agent_disconnected";
  reason: string;
}

/** Relayed exec-idle notice (see AgentExecIdleMsg). Informational only. */
export interface DoExecIdleMsg {
  type: "do:exec_idle";
  commandId: string;
  idleMs: number;
}

// Union types
export type AgentToDoMsg =
  | AgentRegisterMsg
  | AgentOutputMsg
  | AgentDoneMsg
  | AgentErrorMsg
  | AgentPongMsg
  | AgentExecIdleMsg
  | AgentScreenStateMsg
  | AgentScreenshotChunkMsg
  | AgentScreenshotDoneMsg
  | AgentScreenshotErrorMsg
  | AgentGpuStateMsg
  | AgentJobResultMsg
  | AgentJobErrorMsg
  | AgentFileResultMsg
  | AgentFileErrorMsg;

export type DoToAgentMsg =
  | DoExecMsg
  | DoSecureExecMsg
  | DoElevatedExecMsg
  | DoPingMsg
  | DoKillMsg
  | DoScreenshotMsg
  | DoJobStartMsg
  | DoJobListMsg
  | DoJobStatusMsg
  | DoJobLogsMsg
  | DoJobCancelMsg
  | DoFilePullMsg
  | DoFilePushMsg;

export type AdminToDoMsg =
  | AdminExecMsg
  | AdminSecureExecMsg
  | AdminElevatedExecMsg
  | AdminKillMsg
  | AdminScreenshotMsg
  | AdminJobStartMsg
  | AdminJobListMsg
  | AdminJobStatusMsg
  | AdminJobLogsMsg
  | AdminJobCancelMsg
  | AdminFilePullMsg
  | AdminFilePushMsg;

export type DoToAdminMsg =
  | DoAgentInfoMsg
  | DoAuthOkMsg
  | DoAuthErrorMsg
  | DoOutputMsg
  | DoDoneMsg
  | DoErrorMsg
  | DoAgentDisconnectedMsg
  | DoExecIdleMsg
  | DoScreenStateMsg
  | DoScreenshotChunkMsg
  | DoScreenshotDoneMsg
  | DoScreenshotErrorMsg
  | DoGpuStateMsg
  | DoJobResultMsg
  | DoJobErrorMsg
  | DoFileResultMsg
  | DoFileErrorMsg;

// HTTP API types
export interface RegisterRequest {
  hostname: string;
  platform: string;
  arch: string;
  agentVersion: string;
  /** Stable device identity (Stream D) — persisted by the agent across reboots. */
  deviceId?: string;
  /** Per-device secret; relay stores hashToken(deviceSecret) on first sight. */
  deviceSecret?: string;
}

export interface RegisterResponse {
  sessionCode: string;
  agentToken: string;
}

export interface SessionStatusResponse {
  sessionCode: string;
  agentConnected: boolean;
  agentInfo?: {
    hostname: string;
    platform: string;
    arch: string;
    agentVersion: string;
    connectedAt: string;
    screenShare?: ScreenShareState;
    /** Last known NVIDIA devices; absent when the machine reported none. */
    gpus?: GpuDevice[];
    /** Whether this machine's agent supports detached jobs (see AgentRegisterMsg.jobs). */
    jobs?: boolean;
  };
  createdAt: string;
  expiresAt: string;
}

export interface AdminTokenResponse {
  adminToken: string;
  expiresAt: string;
}
