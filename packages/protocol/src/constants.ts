// Default relay server URL. Single source of truth shared by the agent's `run`
// and `install` paths (and anywhere else that needs the canonical relay).
export const DEFAULT_SERVER = "https://aicommander.dev";

export const PING_INTERVAL_MS = 20_000;
export const AGENT_TIMEOUT_MS = 60_000;
// remote_exec timeout contract, enforced independently by the Worker, relay DO,
// and agent. Missing/non-finite values use DEFAULT; finite values are clamped to
// [MIN, MAX], so zero/negative deadlines cannot become an immediate kill and an
// oversized deadline cannot outlive the documented one-hour remote_exec limit.
export const COMMAND_MIN_TIMEOUT_MS = 1_000;
export const COMMAND_DEFAULT_TIMEOUT_MS = 300_000;
export const COMMAND_MAX_TIMEOUT_MS = 3_600_000;

/** Normalize an untrusted command timeout to the documented protocol bounds. */
export function clampCommandTimeout(requested: unknown): number {
  const base =
    typeof requested === "number" && Number.isFinite(requested)
      ? requested
      : COMMAND_DEFAULT_TIMEOUT_MS;
  return Math.min(Math.max(base, COMMAND_MIN_TIMEOUT_MS), COMMAND_MAX_TIMEOUT_MS);
}
export const SESSION_EXPIRY_SECONDS = 86_400;
// How long a session code + device binding persist in KV so a briefly-offline
// machine keeps the SAME code across reboots/restarts. Refreshed on every
// register. A machine offline longer than this may be issued a new code.
export const SESSION_PERSIST_SECONDS = 60 * 60 * 24 * 30; // 30 days
export const ADMIN_TOKEN_EXPIRY_SECONDS = 3_600;
export const MAX_OUTPUT_CHUNK_SIZE = 65_536;
// Hard cap on the TOTAL command output (stdout+stderr combined) the relay will
// buffer and return for a single command. The Worker accumulates output in
// memory before emitting the final result, so without this cap a command like
// `cat hugefile` would exhaust the isolate's ~128 MB heap. Beyond the cap the
// output is truncated (with a notice) and the Worker sends a best-effort stop.
// That request races the command over several network hops and may lose, so the
// process can keep running after the reply is truncated. 1 MiB is far more than
// is useful to an LLM caller while leaving a huge safety margin.
export const MAX_OUTPUT_TOTAL_BYTES = 1_048_576;
export const RATE_LIMIT_REGISTER_PER_HOUR = 100;

// ── Secure exec (service-token, sandboxed) ───────────────────────────────────
// A SEPARATE execution path from `do:exec`, reached ONLY by a long-lived service
// token and never by `remote_exec`. It runs an explicit argv[] (no shell, so
// `&&`/`;`/`$(...)` are inert literals — injection is impossible by construction)
// as a dedicated NON-ROOT user, with the command's basename checked against the
// token's allowlist. These limits are part of the wire contract and are mirrored
// in the public docs.
//
// The dedicated unprivileged user the agent drops to before exec. Created at
// install time on Linux; the agent resolves its uid/gid at startup and runs
// every secure-exec child as this user — the value is HARDCODED here, never
// taken from the relay message, so a compromised relay cannot raise privilege.
export const SECURE_EXEC_USER = "aicommander-exec";

/**
 * Known generic execution/privilege primitives that must never be accepted as
 * secure-exec allowlist entries. This is intentionally a conservative denylist,
 * NOT a complete sandbox policy: many otherwise useful programs can launch
 * subprocesses in some configuration. The dedicated non-root uid/group boundary
 * remains the containment mechanism.
 *
 * Categories:
 *  - shells: sh … tcsh;
 *  - language runtimes: python … lua;
 *  - argument/multi-call runners: env … sed (awk has system(), GNU sed has `e`);
 *  - privilege tools: sudo … pkexec;
 *  - container/orchestration clients: docker … kubectl (plugins/exec included).
 */
export const SECURE_EXEC_DENIED_COMMANDS = [
  "sh", "bash", "dash", "zsh", "fish", "ash", "ksh", "mksh", "csh", "tcsh",
  "python", "python2", "python3", "pypy", "pypy3",
  "node", "nodejs", "perl", "ruby", "php", "lua",
  "env", "busybox", "find", "xargs", "awk", "gawk", "mawk", "nawk", "sed",
  "sudo", "su", "doas", "pkexec",
  "docker", "podman", "nerdctl",
  "kubectl",
] as const;

const SECURE_EXEC_DENIED_COMMAND_SET: ReadonlySet<string> =
  new Set(SECURE_EXEC_DENIED_COMMANDS);

// Common distro-provided version-suffixed runtime basenames (python3.13,
// perl5.40.0, ruby3.4, php8.4, lua5.4, etc.) are the same execution primitive.
const SECURE_EXEC_VERSIONED_RUNTIME =
  /^(?:python[23]\.\d+(?:\.\d+)*|pypy[23]\.\d+(?:\.\d+)*|perl\d+(?:\.\d+)*|ruby\d+(?:\.\d+)*|php\d+(?:\.\d+)*|lua\d+(?:\.\d+)*)$/;

/** True when a bare command basename is covered by the secure-exec denylist. */
export function isSecureExecCommandDenied(command: string): boolean {
  return (
    SECURE_EXEC_DENIED_COMMAND_SET.has(command) ||
    SECURE_EXEC_VERSIONED_RUNTIME.test(command)
  );
}

/**
 * Local groups whose membership defeats a non-root secure-exec boundary.
 * Runtime checks both the sandbox user's primary gid and /etc/group
 * supplementary memberships; numeric gid 0 is rejected independently.
 */
export const SECURE_EXEC_PRIVILEGED_GROUPS = [
  "root", "wheel", "sudo", "docker", "podman", "lxd", "incus", "disk", "libvirt",
] as const;
// Max stdin payload (decoded bytes) carried inline in a single do:secure_exec
// frame. 256 KiB stays comfortably under Cloudflare's ~1 MiB per-WS-message
// limit on the agent → DO and DO → worker hops, so input needs no chunking.
export const SECURE_EXEC_MAX_INPUT_BYTES = 262_144;
// Hard 8 MiB cap on TOTAL secure-exec output (stdout+stderr) the RELAY/worker
// buffers and returns. Higher than MAX_OUTPUT_TOTAL_BYTES because secure-exec
// targets large machine-readable results (e.g. `claude -p` JSON), but still well
// inside the isolate's ~128 MB heap. Beyond it the RELAY truncates the output
// and sends a best-effort kill request. That request can lose its cross-hop race,
// so truncation is not proof the process stopped; it may keep running. The cap is
// enforced relay-side, not in the agent.
export const SECURE_EXEC_MAX_OUTPUT_TOTAL_BYTES = 8_388_608;

// ── Screen sharing (desktop mac/win only) ────────────────────────────────────
// Hard ceiling on a single screenshot. A capture larger than this is rejected
// (rather than streamed) so a runaway image can never exhaust memory along the
// agent → DO → worker path.
export const SCREENSHOT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
// Base64 characters per relayed screenshot chunk. A screenshot is base64-encoded
// and sliced into pieces this size so each WebSocket frame stays well under
// Cloudflare's 1 MiB per-message limit (agent → DO and DO → worker both hop a WS).
export const SCREENSHOT_CHUNK_SIZE = 512 * 1024; // 512 KB of base64 per frame
// A desktop "Share Screen" grant lasts this long, then auto-disables. The user
// must re-enable it in the tray to allow screenshots again.
export const SCREEN_SHARE_WINDOW_MS = 24 * 60 * 60 * 1000; // 24h

// ── GPU telemetry ────────────────────────────────────────────────────────────
// How often the agent re-probes nvidia-smi and pushes agent:gpu_state.
// Static fields (name/total VRAM) never change; used-VRAM/utilization do, and
// a stale "free" reading is worse than none when picking a box for a job.
export const GPU_POLL_INTERVAL_MS = 60_000;
// Hard timeout on the nvidia-smi probe. A hung/zombie driver must never stall
// registration or the poll loop.
export const GPU_PROBE_TIMEOUT_MS = 5_000;

// ── Detached jobs ────────────────────────────────────────────────────────────
// A job's output lives in a file on the target machine, so these caps bound DISK
// and per-reply WIRE size. By contrast, MAX_OUTPUT_TOTAL_BYTES truncates a
// remote_exec reply and sends a best-effort stop that can lose its race, so the
// process may keep running. A job's log cap never requests a stop: that
// difference is the whole point of jobs, where a 5-hour training run must not
// die because it was chatty.
//
// Ceiling on one job's output.log. On overflow the agent appends a truncation
// notice and stops appending — it does NOT kill the job. 256 MiB is far more
// than any sane log while keeping a full retention window bounded on disk.
export const JOB_MAX_LOG_BYTES = 268_435_456; // 256 MiB on disk
// Max decoded bytes returned by ONE do:job_logs call. Deliberately far under
// MAX_OUTPUT_TOTAL_BYTES: a log slice is base64-encoded and buffered in the
// Worker isolate, so this reply must never be the thing that blows its ~128 MB
// heap. Pagination via offsetBytes/nextOffsetBytes lets a caller follow an
// arbitrarily long log without ever exceeding it.
export const JOB_LOGS_MAX_SLICE_BYTES = 262_144; // 256 KiB per job_logs call
// Tail size when a caller asks for logs without specifying a range — the common
// "how is it going?" call. Big enough to show a stack trace, small enough to be
// a cheap poll.
export const JOB_LOGS_DEFAULT_TAIL_LINES = 200;
// How long a finished job's directory (meta, log, workspace) is kept before the
// agent deletes it at startup. Bounds disk growth with no user action, while
// leaving a week to come back and read the result of a weekend run.
export const JOB_RETENTION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
// How long the relay waits for an agent:job_result before giving up on a job
// RPC. These are disk-local operations on the agent, so anything near this means
// the agent is wedged, not busy.
export const JOB_RPC_TIMEOUT_MS = 30_000;
// Ceiling on simultaneously RUNNING jobs per machine; job_start beyond it is
// refused with `too_many_jobs`. Prevents an agent loop from forking a machine to
// death — it is a safety rail, not a scheduling policy.
export const JOB_MAX_CONCURRENT = 32;

// ── Job wire contract ────────────────────────────────────────────────────────
// The values below are the ones the agent and the relay reason about TOGETHER
// rather than each picking privately. They are of two kinds, and telling them
// apart is most of what this section is for:
//
//   • values both sides must AGREE on EXACTLY — character for character, slot for
//     slot, or digit for digit: JOB_ID_PATTERN, JOB_MAX_GPU_INDEX and MAX_EPOCH_MS.
//     What they have in common is that neither side may loosen its half. A mismatched
//     id pattern is an unroutable job; a mismatched index ceiling is a lockfile
//     namespace one side cannot name. MAX_EPOCH_MS is here for a different reason:
//     both sides only ever REFUSE past it, so a mismatch is merely a rejected field —
//     but the value is a JavaScript language fact, identical in every runtime and
//     every agent generation, so the producing/accepting split has nothing to buy,
//     and a relay tolerating a larger value would only be accepting a timestamp it
//     must then refuse to render.
//   • values that are only the PRODUCING half of a ONE-DIRECTIONAL contract —
//     JOB_WIRE_MAX_NAME_CHARS / JOB_WIRE_MAX_COMMAND_CHARS /
//     JOB_WIRE_MAX_LIST_ENTRIES, what the agent truncates to on the way out. The
//     relay's accepting bounds are deliberately NOT these (see below); they
//     merely have to be >= these.
//
// They live here because the alternative already cost us an outage: `readExitFile`
// recorded a sub-millisecond mtime, the relay independently required a safe
// integer, and every EXITED job was rejected at the package boundary with a 502 —
// two definitions of one contract, with nothing keeping them honest.
//
// Note what is deliberately NOT here. The relay's accepting LENGTH bounds — how
// long a name, a command or a job list it will take — stay in
// worker/src/jobs-relay.ts and are allowed to be LOOSER than what the agent
// emits: agent and relay deploy independently (a machine may run an agent months
// older or newer than the Worker), so the relay must tolerate records from both.
// Pinning those bounds to these would destroy that tolerance and recreate the same
// 502 in a new place. What must never happen is drift in the OTHER direction — a
// relay stricter than what the agent can emit — and that is enforced by
// `jobs-wire-contract.test.ts` in the worker, not by sharing the constant.
//
// MAX_EPOCH_MS is the exception that proves the rule: it IS one of the relay's
// accepting bounds and it lives here anyway, because it is not a bound anyone chose
// and so not one either side may loosen (see its own comment below). Tolerance is
// worth having only where a future agent could legitimately emit something wider.

/**
 * The EXACT shape of a job id: 8 random bytes as lowercase hex, generated by the
 * agent and never caller-supplied.
 *
 * Shared rather than merely related, because an id is a hard contract with no
 * room for tolerance: a mismatch does not mean a rejected field, it means an
 * unroutable job — the relay would refuse an id the agent legitimately minted, or
 * pass one no jobs root can ever contain. It is also the reason the id is safe to
 * echo into caller-visible text in front of an LLM: 16 hex characters are inert,
 * where a merely BOUNDED string admits newlines and "IGNORE PREVIOUS INSTRUCTIONS".
 *
 * Stateless (no /g), so the single shared instance has no lastIndex to carry
 * between callers.
 */
export const JOB_ID_PATTERN = /^[0-9a-f]{16}$/;

/**
 * Highest `gpuIndex` that may appear anywhere: in a job_start request, in a
 * reservation lockfile name, or in a JobSummary on the wire.
 *
 * Shared as ONE value rather than as a tolerated pair, unlike the length bounds
 * declared BELOW in this section. A device index is not a length: it names a slot
 * in a finite, enumerable namespace (`gpu-<index>.lock` in the jobs root), and
 * 0..4095 is 4096 cards — chosen to bound that namespace so a nonsense index
 * cannot create unbounded files, not to describe hardware. A future agent has no
 * legitimate reason to emit a larger one, because this same constant is what
 * refuses the job at start time, so there is nothing for a looser relay bound to
 * tolerate.
 */
export const JOB_MAX_GPU_INDEX = 4095;

/**
 * The prefix an agent puts in front of a `do:job_error` when a job could not be
 * started because its own scripts were gone, altered or unwritable at the moment
 * of the spawn — the signature of security software quarantining them (see
 * PLAN-av-hardening.md §2 W3.1; measured on 2026-09-02, Bitdefender took six of
 * them and most of the installation with them).
 *
 * Shared rather than merely related, and for the same reason as JOB_ID_PATTERN:
 * this is a token one side WRITES and the other MATCHES, character for
 * character. A drifted copy does not degrade the message, it silently turns the
 * one failure we can name back into the generic "the job request failed on the
 * machine" that cost an hour of black-box forensics. The prose on either side is
 * free to differ (the agent's is a log line, the relay's is written for an AI
 * caller); the token is not.
 *
 * The WIRE SHAPE the token introduces, in full, because the relay parses it:
 *
 *   job_script_removed: <short detail>; <prose the agent can also log>
 *
 * The detail is everything between the colon and the FIRST semicolon — a few
 * words naming the file and what happened to it ("wrapper.cmd is gone"), never
 * the command, which is caller payload. Everything after that semicolon is prose
 * for a reader with nothing to map the token with: an agent talking to an older
 * Worker, a log line, the CLI on the box itself.
 *
 * The relay never renders the token itself — it recognises it, takes the detail,
 * and replaces the whole string with its own caller-facing text.
 */
export const JOB_SCRIPT_REMOVED_ERROR = "job_script_removed";

const GPU_LOCK_PREFIX = "gpu-";
const GPU_LOCK_SUFFIX = ".lock";

/** The lockfile name reserving `index` in a jobs root. The ONLY place it is built. */
export function gpuLockFileName(index: number): string {
  return `${GPU_LOCK_PREFIX}${index}${GPU_LOCK_SUFFIX}`;
}

/**
 * Whether `name` is a lockfile `gpuLockFileName` could have produced.
 *
 * Recognition is defined by ROUND-TRIPPING through the builder above rather than by
 * a hand-written digit count, because the two places that recognise these files —
 * the agent's stale-lock reaping and uninstall's "is this jobs root ours?" check —
 * are both statements about what job-manager could have WRITTEN, and a `\d{1,4}`
 * copy of that claim silently stops being true the moment JOB_MAX_GPU_INDEX moves.
 * The round-trip also settles the shapes a digit count leaves open: `gpu-007.lock`,
 * `gpu-1e3.lock` and `gpu-+1.lock` are not names we emit, so they are not ours.
 */
export function isGpuLockFileName(name: string): boolean {
  if (!name.startsWith(GPU_LOCK_PREFIX) || !name.endsWith(GPU_LOCK_SUFFIX)) return false;
  const index = Number(name.slice(GPU_LOCK_PREFIX.length, name.length - GPU_LOCK_SUFFIX.length));
  return (
    Number.isInteger(index) &&
    index >= 0 &&
    index <= JOB_MAX_GPU_INDEX &&
    gpuLockFileName(index) === name
  );
}

/**
 * The largest |epoch ms| a `Date` can represent. Past it a Date is invalid and
 * `toISOString()` THROWS — that crash, in whatever renders a job's timestamps, is
 * the whole reason both sides check it.
 *
 * Shared as ONE value rather than as a tolerated pair, like JOB_ID_PATTERN and
 * JOB_MAX_GPU_INDEX above and unlike the JOB_WIRE_MAX_* bounds below. This is not a
 * bound anyone CHOSE: it is a hard JavaScript language limit, identical in every
 * runtime and every agent generation. So the version tolerance the producing/accepting
 * split exists to buy has nothing to buy here — no future agent can legitimately emit
 * a timestamp Date cannot represent, and a relay that tolerated one would only be
 * accepting a value it must then refuse to render.
 */
export const MAX_EPOCH_MS = 8.64e15;

/**
 * The bounds the AGENT truncates a JobSummary's `name` / `command` to before
 * putting them on the wire, in UTF-16 code units (what `String.length` counts —
 * and `String.length` is what the relay measures).
 *
 * These are the PRODUCING side of the contract: the relay's accepting bounds are
 * separately declared in worker/src/jobs-relay.ts and must be >= these (see the
 * note above). They are deliberately looser than what the agent accepts at
 * job_start, because a name or command that reached disk some other way — a
 * hand-edited meta.json, a record written by a future version — must not make a
 * reply unrenderable. Truncating here costs the caller the tail of one field;
 * emitting it whole costs them the whole answer.
 *
 * BEFORE RAISING EITHER NUMBER, read this. The relay's bounds are separate so they
 * MAY be widened independently, but as things stand each pair is EQUAL (256 and
 * 131072 on both sides): the version tolerance the split exists to provide has
 * ZERO headroom today. So raising a value here is a two-step DEPLOY, not a
 * one-line edit — widen the relay's bound and get the WORKER live FIRST, then ship
 * the agent that emits the wider value. An agent that reaches users ahead of the
 * worker has its replies rejected at the package boundary, which for a
 * `kind:"job"` reply is a 502 with no job in it: the incident this whole section
 * was written after. `jobs-wire-contract.test.ts` in the worker asserts the pair
 * so the repo cannot merge inconsistent halves; it knows nothing about the order
 * in which the two halves reach production, and that order is the remaining way to
 * get this wrong.
 */
export const JOB_WIRE_MAX_NAME_CHARS = 256;
export const JOB_WIRE_MAX_COMMAND_CHARS = 131_072;

/**
 * How many summaries the AGENT puts in ONE job_list reply, newest first; it stops
 * walking at this many rather than rejecting anything. A machine can hold a week of
 * finished jobs (JOB_RETENTION_MS) and the reply is buffered whole in a Worker
 * isolate, so an unbounded list would eventually be the thing that breaks — the same
 * reasoning as JOB_LOGS_MAX_SLICE_BYTES.
 *
 * The PRODUCING half of the same one-directional contract as the two bounds above,
 * for the same reason: the relay's accepting bound (MAX_JOBS_IN_LIST in
 * worker/src/jobs-relay.ts) is separate and must merely be >= this. Unlike the
 * name/command pairs it is not equal but far LARGER — 5000 — because the two halves
 * answer different questions. This one is a page size, a judgement about how much of
 * a machine's history is useful in one reply, and it may move with that judgement.
 * The relay's is a hostile-input ceiling: a list past it is an agent ignoring
 * retention entirely, not a page. That headroom is what lets this number be raised in
 * a single deploy, where raising a JOB_WIRE_MAX_*_CHARS cannot be.
 */
export const JOB_WIRE_MAX_LIST_ENTRIES = 200;

/**
 * How many summaries a job_list reply carries when the caller did not say.
 *
 * The page cap above is a WIRE bound — what a reply may never exceed. This is a
 * CONTEXT bound, and the two are far apart on purpose: the caller is an LLM, and
 * one measured call on a real ML box returned 38 jobs ≈ 2.5k tokens of its
 * context, almost all of it finished runs nobody asked about. 20 newest is about
 * what a human recognises as "recent work" and costs ~1.3k tokens; anything older
 * is one more call away with an explicit `limit`, and the reply says how many
 * records it did not walk (`omitted`) so the caller knows there IS more.
 *
 * Only a default: `limit` may raise it up to JOB_WIRE_MAX_LIST_ENTRIES and no
 * further, so a caller can never enlarge the reply past the wire page cap.
 */
export const JOB_LIST_DEFAULT_ENTRIES = 20;

// ── Self-healing (agent watchdog) ────────────────────────────────────────────
// The agent runs as a thin SUPERVISOR that spawns the real agent as a WORKER and
// watches a heartbeat file the worker stamps from a timer. The heartbeat proves
// only that the worker's event loop is turning — it is deliberately INDEPENDENT
// of command workload, so a long/quiet command (a build, `sleep 3600`, a server)
// can never look "stuck". A stalled heartbeat therefore means a genuinely wedged
// loop, which has no benign explanation, so the supervisor force-restarts it.
//
// HEARTBEAT_INTERVAL_MS: how often the worker stamps the heartbeat file.
// WATCHDOG_CHECK_INTERVAL_MS: how often the supervisor reads it.
// WATCHDOG_STALL_MS: stall budget before a force-restart. Generous (6+ missed
// stamps) so a brief GC pause or disk hiccup never trips it → no false positives.
export const HEARTBEAT_INTERVAL_MS = 5_000;
export const WATCHDOG_CHECK_INTERVAL_MS = 10_000;
export const WATCHDOG_STALL_MS = 30_000;

// Crash-loop guard: if the worker restarts more than WATCHDOG_MAX_RESTARTS times
// within WATCHDOG_RESTART_WINDOW_MS, the supervisor backs off to
// WATCHDOG_BACKOFF_MS between respawns so self-healing never hammers the
// rate-limited /api/register endpoint.
export const WATCHDOG_MAX_RESTARTS = 5;
export const WATCHDOG_RESTART_WINDOW_MS = 300_000;
export const WATCHDOG_BACKOFF_MS = 60_000;

// Grace period between SIGTERM and SIGKILL when terminating a command's process
// group. Guarantees the process actually dies (and a terminal agent:done/error
// is always emitted) even if it ignores SIGTERM.
export const KILL_ESCALATION_MS = 5_000;

// Exec-idle observability (W4): if a running command produces no output for this
// long and has not exited, the agent emits an INFORMATIONAL agent:exec_idle. It
// never kills — silence is normal for builds, sleeps, and servers. Only the
// explicit per-command timeout (caller-controlled) ever auto-terminates.
export const EXEC_IDLE_THRESHOLD_MS = 300_000;

// Anonymous-access window. A session code's AGE is the proof of current machine
// control for callers WITHOUT an account: codes are minted fresh on install and
// on every change-code / re-registration, and an anonymous caller may operate on
// a code only within this window of its createdAt. Signed-in accounts are NOT
// gated by this window — they may use (and auto-link with) a code of any age,
// because the account is itself identifiable and revocable by the owner.
export const BIND_WINDOW_SECONDS = 3_600;

// ── File transfer (temporary relay-brokered blobs) ───────────────────────────
//
// The one primitive the compute story was missing: a checkpoint, a rendered
// image, a dataset can now cross the relay instead of being base64'd through a
// shell, where MAX_OUTPUT_TOTAL_BYTES truncates the reply and sends a
// best-effort stop that can lose its race, leaving the process running. The
// design is deliberately NOT "storage": a blob is a courier package that exists
// only long enough to be collected, and every constant below exists to keep it
// that way.
//
// Bytes never travel over the relay WebSocket. The socket carries a request and
// an opaque one-time token; the bytes go over an ordinary HTTPS request between
// the machine and the relay. That keeps a multi-hundred-megabyte transfer out of
// the Durable Object entirely, and out of the isolate heap that MAX_OUTPUT_TOTAL_BYTES
// exists to protect.

/**
 * Hard ceiling on one blob, enforced independently by the agent (before it reads
 * a file), by the relay (while streaming into R2), and by the caller-facing
 * upload route.
 *
 * 100 MiB is a PLATFORM limit, not a product opinion: a blob crosses the relay as
 * one ordinary HTTPS request body, and the Workers runtime caps a request body
 * well below the sizes a training checkpoint reaches. Raising it means teaching
 * both sides R2 multipart upload (the agent would send parts, the relay would
 * assemble them) — a real feature, not a constant change. Until then a caller
 * with a 4 GB checkpoint is told to have the JOB push it to their own storage,
 * which is the same advice that predates this feature.
 */
export const FILE_MAX_BYTES = 104_857_600; // 100 MiB

/**
 * How long a stored blob survives before the relay deletes it, whether or not it
 * was collected.
 *
 * This is the constant that makes the feature "temporary storage": there is no
 * path by which a blob becomes permanent, no renewal, and no per-account library
 * of files. A caller who misses the window pulls the file again — the machine
 * still has it; the relay was only ever the courier.
 */
export const FILE_BLOB_TTL_MS = 24 * 60 * 60 * 1000; // 24h

/**
 * Lifetime of the one-time token the relay hands a machine so it can upload or
 * download ONE blob.
 *
 * Far shorter than the blob's own TTL, because it is a credential rather than a
 * lifetime: it authorizes exactly one transfer of exactly one blob and is
 * consumed on first use. An hour is generous for a 100 MiB transfer on a slow
 * home connection and short enough that a token recovered from a wedged agent's
 * memory is worthless.
 */
export const FILE_TRANSFER_TOKEN_TTL_MS = 60 * 60 * 1000; // 1h

/**
 * Lifetime of the link a caller uses to fetch a pulled blob.
 *
 * A link carries its own bearer token in the URL, which is a real cost: URLs land
 * in shell history and in an LLM's context. It buys the only download path that
 * works for a caller with no account (the anonymous first-hour path) and for a
 * human who was handed a link by their agent. The mitigation is time — one hour,
 * against a 24h blob — plus the fact that the token names one blob and nothing else.
 */
export const FILE_DOWNLOAD_LINK_TTL_MS = 60 * 60 * 1000; // 1h

/**
 * How long the relay waits for a machine to answer a file RPC.
 *
 * Much longer than JOB_RPC_TIMEOUT_MS, and for a reason that matters: a job RPC is
 * a disk-local metadata operation, whereas a file RPC includes the transfer itself
 * — the machine only answers once the bytes are in (or out of) the relay. A 100 MiB
 * upload from a home connection at 2 MB/s takes most of a minute; ten minutes leaves
 * room for a slow link without letting a wedged agent hold a caller forever.
 */
export const FILE_RPC_TIMEOUT_MS = 10 * 60 * 1000; // 10m

/**
 * The shape of a blob id: 32 lowercase hex characters (128 bits).
 *
 * An exact shape rather than a length bound, for the same reason JOB_ID_PATTERN is:
 * an id is echoed into caller-visible text in front of an LLM, and 32 hex characters
 * are inert where a merely bounded string admits newlines and instructions. It is
 * also the R2 key suffix, so the pattern is what keeps a caller-supplied id from
 * naming anything but a blob.
 *
 * Stateless (no /g), so the shared instance carries no lastIndex between callers.
 */
export const FILE_BLOB_ID_PATTERN = /^[0-9a-f]{32}$/;

/** Longest destination/source path a file RPC will carry, matching the exec cwd bound. */
export const FILE_MAX_PATH_CHARS = 4_096;

// ── Remote-access connect notice (desktop only) ──────────────────────────────
// The desktop app warns the local user when a remote operator drives a command,
// so an unexpected connection never goes unnoticed. To avoid nagging during
// normal use the notice is rate-limited PER OPERATOR by two rules, evaluated on
// every command the operator runs:
//   • REMOTE_NOTIFY_MIN_INTERVAL_MS — a hard floor between two notices for the
//     same operator (at most once an hour), and
//   • REMOTE_ACTIVITY_GAP_MS — only the FIRST command after an idle gap this long
//     counts as a new "connection"; a continuous working session (commands closer
//     together than the gap) is notified once at its start, never mid-stream.
// The very first contact with an operator always notifies, regardless of either.
export const REMOTE_NOTIFY_MIN_INTERVAL_MS = 60 * 60 * 1000; // 1h per operator
export const REMOTE_ACTIVITY_GAP_MS = 10 * 60 * 1000; // 10m idle ⇒ new session
// Absolute ceiling: an operator who works NON-STOP (commands always closer together
// than the idle gap, so a new "connection" is never detected) would otherwise be
// announced only once, ever. To keep a long unbroken remote session visible, re-warn
// regardless of the idle gap once this long has passed since the last notice — i.e.
// during continuous work the notice fires at most once per this interval.
export const REMOTE_NOTIFY_MAX_INTERVAL_MS = 8 * 60 * 60 * 1000; // 8h continuous-session ceiling

export const SESSION_CODE_ADJECTIVES = [
  "SWIFT", "BOLD", "CALM", "DARK", "EPIC",
  "FAST", "GOLD", "HARD", "IRON", "JADE",
] as const;

export const SESSION_CODE_NOUNS = [
  "WOLF", "BEAR", "HAWK", "LYNX", "RAVEN",
  "OAK", "ELM", "ASH", "PINE", "CROW",
] as const;
