// The cheap, NON-PROBING settle path for jobs started with a webhookId.
//
// Why it exists: a job recovered after an agent restart has no exit callback, and
// the only code that settles it today is refresh(), reached from a job RPC. The
// agent:job_state poll counts such a job out when it dies but settles nothing, and
// on desktop the manager is created lazily — its recover() → refresh() runs the
// synchronous process-identity probe (ps / wmic / PowerShell via execFileSync),
// which must never run on the main loop unprompted. Without this path a webhook
// job that ended while nobody asked about it would never produce agent:job_ended.
//
// Evidence used, and nothing else: the exit marker, and kill(pid, 0). Only ESRCH
// proves the process gone (EPERM or anything else holds), and even then the marker
// is read AGAIN, because the wrapper writes it before its process dies (the same
// order refresh() relies on). Only with no marker after ESRCH is the job settled
// as `unknown`.
//
// Accepted gap: when the pid was REUSED by an unrelated process, ESRCH never
// arrives, so the job stays "running" here and no job.ended is sent until a job RPC
// refreshes it; the relay's deadline (job.deadline) covers that case.

import { JOB_ENDED_REPLAY_MAX, type JobStatus, type JobUnknownReason } from "@aicommander/protocol";
import { JobStore, LOG_FILE } from "./job-store.js";
import type { JobMeta } from "./job-types.js";

/** How a webhook job was found to have ended. */
export type CheapEnd =
  | { kind: "marker"; marker: { code: number; at: number } }
  | { kind: "vanished" };

/**
 * Store-only path (no JobManager in this process): a pid-less record younger than
 * this is treated as a start still in flight elsewhere, never as vanished.
 */
export const STORE_ONLY_START_GRACE_MS = 60_000;

export interface CheapSettleOptions {
  /** Records the caller already knows are terminal. */
  skip?: (jobId: string) => boolean;
  /** Records in an in-memory start/retire window: never settle them here. */
  live?: (jobId: string) => boolean;
  /**
   * Write the terminal state and return it. Defaults to a store-only write (see
   * settleRecordOnDisk); a JobManager passes its own settle() instead.
   */
  settle?: (meta: JobMeta, end: CheapEnd) => JobMeta;
}

/** What one pass over the webhook records found. */
export interface WebhookScan {
  /** Unacked end events to send: newest first, capped (older ones un-flagged on disk). */
  unacked: JobMeta[];
  /** Any webhook record still running or unacked: the replay timer must keep going. */
  pending: boolean;
}

/**
 * ONE pass over the records: settle every running webhook record that is
 * provably over, and collect what still has to be reported. Never throws.
 */
export function settleEndedWebhookRecords(store: JobStore, opts: CheapSettleOptions = {}): WebhookScan {
  const settle = opts.settle ?? ((meta: JobMeta, end: CheapEnd) => settleRecordOnDisk(store, meta, end));
  const storeOnly = opts.settle === undefined;
  const unacked: JobMeta[] = [];
  let running = false;
  for (const jobId of store.listJobIds()) {
    try {
      let meta = store.readMeta(jobId);
      if (!meta || meta.webhookId === undefined) continue;
      if (
        meta.status === "running" && !opts.skip?.(jobId) && !opts.live?.(jobId) &&
        !(storeOnly && inStartGrace(meta))
      ) {
        const end = observeEnd(store, meta);
        if (end) meta = settle(meta, end);
      }
      if (meta.status === "running") running = true;
      else if (meta.endedUnacked === true && meta.endedAt !== null) unacked.push(meta);
    } catch {
      // One damaged record must not stop the others from being reported.
    }
  }
  unacked.sort((a, b) => (b.endedAt as number) - (a.endedAt as number));
  for (const old of unacked.splice(JOB_ENDED_REPLAY_MAX)) {
    try {
      const next = { ...old };
      delete next.endedUnacked;
      store.writeMeta(next);
    } catch {
      // Best effort: it is re-evaluated (and un-flagged) on the next pass.
    }
  }
  return { unacked, pending: running || unacked.length > 0 };
}

function inStartGrace(meta: JobMeta): boolean {
  return meta.pid === null && Date.now() - meta.startedAt < STORE_ONLY_START_GRACE_MS;
}

function observeEnd(store: JobStore, meta: JobMeta): CheapEnd | null {
  const marker = store.readExit(meta.jobId);
  if (marker) return { kind: "marker", marker };
  // A pid-less record outside any start window belongs to a dead agent's start.
  if (meta.pid !== null && !pidIsGone(meta.pid)) return null;
  // Re-read after proving the pid gone: the wrapper writes the marker first.
  const late = store.readExit(meta.jobId);
  if (late) return { kind: "marker", marker: late };
  return { kind: "vanished" };
}

/**
 * Store-only settle, for when NO JobManager exists (creating one would run
 * recover()). A `retiring` record (an abandoned start) is discarded exactly as
 * the manager's settle() → discardRetired does it: the job directory goes, no
 * terminal write, no endedUnacked, so no agent:job_ended for a start the relay
 * was never told succeeded. Otherwise it writes the terminal state and endedUnacked in ONE writeMeta. It
 * deliberately leaves the GPU lock and the systemd scope alone: once a manager
 * exists, refresh() of this now-terminal record runs markSettled(false), which
 * queues the batched scope reap, and recover()'s reapGpuLocks (or the stale-lock
 * check in a later acquire) frees the card — both see a terminal record.
 */
export function settleRecordOnDisk(store: JobStore, meta: JobMeta, end: CheapEnd): JobMeta {
  if (meta.retiring === true) {
    store.removeJobDir(meta.jobId);
    const endedAt = end.kind === "marker" ? end.marker.at : Date.now();
    return { ...meta, status: "unknown", exitCode: null, endedAt };
  }
  const cancelled = meta.cancelRequestedAt !== undefined;
  let status: JobStatus;
  let exitCode: number | null;
  let endedAt: number;
  let approximate = false;
  let unknownReason: JobUnknownReason | undefined;
  if (end.kind === "marker" && !cancelled) {
    status = "exited";
    exitCode = end.marker.code;
    endedAt = end.marker.at;
  } else {
    status = "unknown";
    exitCode = null;
    unknownReason = cancelled ? "cancelled" : "undetermined";
    if (end.kind === "marker") {
      endedAt = end.marker.at;
    } else {
      endedAt = estimateEndedAt(store, meta);
      approximate = true;
    }
  }
  const settled: JobMeta = { ...meta, status, exitCode, endedAt, endedAtApproximate: approximate };
  if (unknownReason !== undefined) settled.unknownReason = unknownReason;
  else delete settled.unknownReason;
  markEndedUnacked(settled);
  store.writeMeta(settled);
  return settled;
}

/** Flag a terminal record whose end event is still owed to the relay. */
export function markEndedUnacked(settled: JobMeta): void {
  if (settled.webhookId !== undefined) settled.endedUnacked = true;
}

/** Last log write, clamped to [startedAt, now]; now when there is no output. */
function estimateEndedAt(store: JobStore, meta: JobMeta): number {
  const now = Date.now();
  const log = store.fileStat(meta.jobId, LOG_FILE);
  if (!log || log.size === 0 || !Number.isFinite(log.mtimeMs)) return now;
  const ended = Math.round(log.mtimeMs);
  if (!Number.isSafeInteger(ended)) return now;
  const floor = Number.isSafeInteger(meta.startedAt) ? meta.startedAt : 0;
  return Math.min(Math.max(ended, floor), now);
}

/** Only ESRCH proves absence; EPERM and anything else hold. */
export function pidIsGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ESRCH";
  }
}
