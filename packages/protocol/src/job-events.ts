// Job end events (agent:job_ended / do:job_ended_ack) and the webhook payloads the
// relay builds from them. Kept out of messages.ts on purpose: both ends of the wire
// need the same narrowing rule, and the relay must never sign and deliver to a
// third party anything an agent could use to inject arbitrary fields or text.
//
// Contract direction: the agent only reports how a job ended and which opaque
// `webhookId` the relay attached at start. The URL never reaches the agent, and
// `webhookId` never leaves the relay (deliveries carry an independent deliveryId).

import { JOB_ID_PATTERN } from "./constants.js";
import type { JobStatus } from "./messages.js";

/** Opaque relay-generated webhook key: 128 random bits as 32 lowercase hex chars. */
export const WEBHOOK_ID_PATTERN = /^[0-9a-f]{32}$/;

export function isWebhookId(v: unknown): v is string {
  return typeof v === "string" && WEBHOOK_ID_PATTERN.test(v);
}

/** The statuses a job can END in; `running` is never reported as an end. */
export type JobEndedStatus = Exclude<JobStatus, "running">;

/**
 * Agent → relay: a job started with a `webhookId` has settled. Re-sent (with
 * backoff, see JOB_ENDED_RETRY_*) until the relay answers do:job_ended_ack, so the
 * relay must treat duplicates as idempotent.
 */
export interface AgentJobEndedMsg {
  type: "agent:job_ended";
  webhookId: string;
  jobId: string;
  status: JobEndedStatus;
  /** An int32 when `status` is "exited"; always null when "unknown". */
  exitCode: number | null;
  /** Epoch ms of the end. */
  endedAt: number;
  /** True when `endedAt` was reconstructed (e.g. noticed after an agent restart). */
  endedAtApproximate?: boolean;
}

/** Relay → agent: the event is durably recorded; the agent may forget it. */
export interface DoJobEndedAckMsg {
  type: "do:job_ended_ack";
  webhookId: string;
}

const INT32_MIN = -2_147_483_648;
const INT32_MAX = 2_147_483_647;

function isInt32(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= INT32_MIN && v <= INT32_MAX;
}

/**
 * Narrow an untrusted agent:job_ended frame to its exact shape, or `undefined`.
 * Unknown extra keys are dropped (the returned object is rebuilt from known
 * fields only). Never throws, including on getters or exotic objects.
 */
export function parseAgentJobEnded(raw: unknown): AgentJobEndedMsg | undefined {
  try {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
    const r = raw as Record<string, unknown>;
    const { type, webhookId, jobId, status, exitCode, endedAt, endedAtApproximate } = r;
    if (type !== "agent:job_ended") return undefined;
    if (!isWebhookId(webhookId)) return undefined;
    if (typeof jobId !== "string" || !JOB_ID_PATTERN.test(jobId)) return undefined;
    if (status === "exited") {
      if (!isInt32(exitCode)) return undefined;
    } else if (status === "unknown") {
      if (exitCode !== null) return undefined;
    } else {
      return undefined;
    }
    if (typeof endedAt !== "number" || !Number.isSafeInteger(endedAt) || endedAt <= 0) return undefined;
    if (endedAtApproximate !== undefined && typeof endedAtApproximate !== "boolean") return undefined;
    const msg: AgentJobEndedMsg = { type, webhookId, jobId, status, exitCode, endedAt };
    if (endedAtApproximate !== undefined) msg.endedAtApproximate = endedAtApproximate;
    return msg;
  } catch {
    return undefined;
  }
}

/** Unacked end events an agent keeps for replay; older ones are dropped first. */
export const JOB_ENDED_REPLAY_MAX = 50;
/** Agent replay backoff: starts at BASE, doubles, capped at MAX. */
export const JOB_ENDED_RETRY_BASE_MS = 60_000;
export const JOB_ENDED_RETRY_MAX_MS = 900_000;

/** How long the relay waits for an end event before sending `job.deadline`. */
export const WEBHOOK_DEADLINE_DEFAULT_SECONDS = 86_400;
export const WEBHOOK_DEADLINE_MIN_SECONDS = 60;
export const WEBHOOK_DEADLINE_MAX_SECONDS = 604_800;
export const WEBHOOK_URL_MAX_LENGTH = 2048;
/** Total HTTP attempts per webhook (first try included). */
export const WEBHOOK_MAX_ATTEMPTS = 3;
/** Attempt n is due WEBHOOK_ATTEMPT_OFFSETS_MS[n-1] after the event. */
export const WEBHOOK_ATTEMPT_OFFSETS_MS: readonly number[] = [0, 60_000, 300_000];
/** In-flight (not yet delivered/failed) webhooks per account. */
export const WEBHOOK_MAX_PENDING_PER_ACCOUNT = 100;

export const WEBHOOK_PAYLOAD_VERSION = 1;
export type WebhookEventName = "job.ended" | "job.deadline";

/** Body of a `job.ended` delivery — exactly these fields, nothing else. */
export interface JobEndedWebhookPayload {
  v: typeof WEBHOOK_PAYLOAD_VERSION;
  event: "job.ended";
  deliveryId: string;
  jobId: string;
  status: JobEndedStatus;
  exitCode: number | null;
  endedAt: number;
  endedAtApproximate: boolean;
  attempt: number;
}

/**
 * Body of a `job.deadline` delivery: no end event arrived before the deadline.
 * Says NOTHING about the job's state — confirm with GET /jobs/{id}.
 */
export interface JobDeadlineWebhookPayload {
  v: typeof WEBHOOK_PAYLOAD_VERSION;
  event: "job.deadline";
  deliveryId: string;
  jobId: string;
  attempt: number;
}
