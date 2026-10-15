// Recoverable job starts: idempotent `operationId`, named resource locks.
//
// Kept out of messages.ts (past its size limit); the message interfaces there
// extend the field groups below. All state lives on the AGENT's disk: the relay
// only hashes the caller's operationId into a per-principal key and forwards it.
//
// Contract in one paragraph: a start that carries an operationId is deduplicated
// per machine — a retry with the same id returns the job the first attempt
// started (`deduplicated: true`), even after that job ended; a different command
// under the same id is refused with `operation_conflict`. A start carrying `locks`
// takes every named lock or none, and a held lock refuses with `resource_busy`
// (no queueing). Locks are per machine and shared by every account on it.

/** Longest accepted operationId / lock name. */
export const JOB_OPS_NAME_MAX_CHARS = 128;
/** Most named locks one job may take. */
export const JOB_LOCKS_MAX = 8;
/** The alphabet of an operationId and of a lock name. */
export const JOB_OPS_NAME_PATTERN = /^[A-Za-z0-9._:@/-]+$/;
/** hex(sha256(principal + "\n" + operationId)), computed by the relay. */
export const OPERATION_KEY_PATTERN = /^[0-9a-f]{64}$/;

/** Refused when a start or lookup needs `jobOps` and the agent did not advertise it. */
export const JOB_OPS_UNSUPPORTED_MESSAGE =
  "This machine's AI Commander agent is too old for `operation_id` / `locks` (it would silently ignore them and could start the job twice). Update the agent on that machine, or call again without those arguments.";

export function isJobOpsName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= JOB_OPS_NAME_MAX_CHARS &&
    JOB_OPS_NAME_PATTERN.test(value)
  );
}

export function isOperationKey(value: unknown): value is string {
  return typeof value === "string" && OPERATION_KEY_PATTERN.test(value);
}

const NAME_RULE = `1–${JOB_OPS_NAME_MAX_CHARS} characters from A-Z a-z 0-9 . _ : @ / -`;

/**
 * Validate a caller-supplied operationId; absent / null means "none". An explicit
 * "" is refused: the caller asked for idempotency, so it must not silently vanish.
 */
export function validateOperationId(
  raw: unknown,
): { ok: true; operationId?: string } | { ok: false; message: string } {
  if (raw === undefined || raw === null) return { ok: true };
  if (isJobOpsName(raw)) return { ok: true, operationId: raw };
  return {
    ok: false,
    message: `\`operation_id\` must be ${NAME_RULE} — an idempotency key you choose, e.g. "train-resnet-2026-10-15". Correct the argument and call again.`,
  };
}

/**
 * Validate caller-supplied lock names. Duplicates are dropped and the result is
 * sorted (the agent acquires in that order); an empty list means "no locks".
 */
export function validateJobLocks(
  raw: unknown,
): { ok: true; locks?: string[] } | { ok: false; message: string } {
  if (raw === undefined || raw === null) return { ok: true };
  if (!Array.isArray(raw)) {
    return { ok: false, message: "`locks` must be an array of resource names." };
  }
  if (!raw.every(isJobOpsName)) {
    return {
      ok: false,
      message: `Every entry of \`locks\` must be ${NAME_RULE}. Correct the argument and call again.`,
    };
  }
  const locks = [...new Set(raw as string[])].sort();
  if (locks.length > JOB_LOCKS_MAX) {
    return { ok: false, message: `\`locks\` takes at most ${JOB_LOCKS_MAX} names.` };
  }
  return locks.length > 0 ? { ok: true, locks } : { ok: true };
}

/** Agent capability (AgentRegisterMsg.jobOps); same fail-closed contract as `jobs`. */
export interface JobOpsCapability {
  /**
   * True from the agent version that honours `operationKey` / `locks` on
   * do:job_start and `operationKey` on do:job_status. An older agent would drop
   * them and start a duplicate, so the relay never sends them without this.
   */
  jobOps?: boolean;
}

/** Start fields (admin:job_start and do:job_start). Sent only to `jobOps` agents. */
export interface JobOpsStartFields {
  /** Per-principal idempotency key (OPERATION_KEY_PATTERN); the agent's dedup key. */
  operationKey?: string;
  /** The caller's raw operationId, kept for display and AIC_OPERATION_ID. */
  operationId?: string;
  /** Validated, deduplicated, sorted lock names. */
  locks?: string[];
}

/** Status lookup by operation instead of jobId (`jobId` is then ignored). */
export interface JobOpsLookupFields {
  operationKey?: string;
}

/** JobSummary additions; optional per the one-directional widening contract. */
export interface JobOpsSummaryFields {
  /** The operationId the job was started with. */
  operationId?: string;
  /** The named locks the job holds (while running) or held. */
  locks?: string[];
  /** True when this start was a retry answered with the existing job; nothing new ran. */
  deduplicated?: boolean;
}

/**
 * - `operation_conflict`    — the operationId already names a DIFFERENT start
 *                             (command, cwd, gpu or locks); `jobId` names it.
 * - `operation_in_progress` — the first start under this operationId is still being
 *                             spawned; retry the same call shortly.
 * - `resource_busy`         — a named lock is held; `lock` and `heldBy` name it.
 */
export type JobOpsRefusalReason = "operation_conflict" | "operation_in_progress" | "resource_busy";

export interface JobOpsRefusalFields {
  /** The existing job for `operation_conflict`. */
  jobId?: string;
  /** The held lock for `resource_busy` (its holder is in `heldBy`). */
  lock?: string;
}
