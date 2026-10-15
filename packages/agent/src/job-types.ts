import type { JobRefusal, JobRpcResult, JobStatus } from "@aicommander/protocol";

/** Version-one record stored in each job directory. */
export interface JobMeta {
  v: 1;
  jobId: string;
  name: string;
  command: string;
  cwd: string;
  status: JobStatus;
  exitCode: number | null;
  startedAt: number;
  endedAt: number | null;
  endedAtApproximate?: boolean;
  /** Kept open-ended so records from newer agents remain readable. */
  unknownReason?: string;
  gpuIndex: number | null;
  pid: number | null;
  procIdentity: string | null;
  retiring?: boolean;
  /** Durable cancellation marker; it survives an agent restart. */
  cancelRequestedAt?: number;
  scope?: string;
  /** Served log boundary; the process may continue writing beyond it. */
  truncatedAt: number | null;
  /** Opaque relay key to report in agent:job_ended (see job-ended-reporter.ts). */
  webhookId?: string;
  /** The end event is not yet acked; written WITH the terminal state, never apart. */
  endedUnacked?: boolean;
  /** Per-principal idempotency key; its index lives in job-ops.ts. */
  operationKey?: string;
  /** The caller's operationId, for display and AIC_OPERATION_ID. */
  operationId?: string;
  /** Named locks held while running (job-locks.ts), sorted. */
  locks?: string[];
}

export interface JobStartRequest {
  /** Internal, best-effort masked identity lookup; never persisted in job metadata. */
  resolveOperator?: () => Promise<string>;
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  name?: string;
  gpuIndex?: number;
  /** Relay webhook key; anything failing isWebhookId is ignored. */
  webhookId?: string;
  /** Idempotency key + raw id (protocol job-ops.ts); both or neither. */
  operationKey?: string;
  operationId?: string;
  /** Named resource locks, all or nothing. */
  locks?: string[];
  /** Aborted when the connection can no longer receive the new job id. */
  signal?: AbortSignal;
}

export interface JobListRequest {
  status?: JobStatus;
  limit?: number;
  includeCommand?: boolean;
}

export interface JobStatusRequest {
  jobId: string;
  /** Look the job up by its operation instead; `jobId` is then ignored. */
  operationKey?: string;
  includeCommand?: boolean;
}

export interface JobLogsRequest {
  jobId: string;
  tailLines?: number;
  offsetBytes?: number;
  maxBytes?: number;
}

export interface JobCancelRequest {
  jobId: string;
}

/** Unexpected local-machine failure, distinct from a request refusal. */
export class JobError extends Error {
  readonly code: string | undefined;
  readonly detail: string | undefined;

  constructor(message: string, code?: string, detail?: string) {
    super(message);
    this.name = "JobError";
    this.code = code;
    this.detail = detail;
  }
}

export type StartAbortReason = "cancelled" | "abandoned";

/** Mutable state for the interruptible record-to-process start window. */
export interface StartWindow {
  abort: StartAbortReason | null;
  erasing: boolean;
}

export class StartAborted extends Error {
  readonly reason: StartAbortReason;

  constructor(reason: StartAbortReason) {
    super(`the start was ${reason} before the job was spawned`);
    this.name = "StartAborted";
    this.reason = reason;
  }
}

export function notFound(): JobRpcResult {
  return { ok: false, reason: "not_found", message: "No such job on this machine." };
}

export function invalidRequest(message: string): JobRefusal {
  return { ok: false, reason: "invalid_request", message };
}

export function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
