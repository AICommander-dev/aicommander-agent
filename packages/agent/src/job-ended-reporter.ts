// Sends agent:job_ended for jobs started with a relay webhookId, and replays it
// until the relay answers do:job_ended_ack. One reporter per connection; the
// JobManager outlives connections, so the reporter never owns it (and never
// creates it: creation runs recover() and its synchronous process probe).
//
// Durability lives on disk, not here: settle() writes `endedUnacked` in the same
// meta write as the terminal state, so every trigger only has to look at disk.
// Triggers: connect (start, right after agent:register), a settle (onSettled),
// the agent:job_state recount (poke — which also runs the cheap settle path, so a
// job recovered after a restart is noticed within one telemetry poll, including
// the recount that drops to 0), and a backoff timer that keeps replaying while ANY
// webhook record is still running or unacked. The timer backs off exponentially
// with jitter (JOB_ENDED_RETRY_BASE_MS … JOB_ENDED_RETRY_MAX_MS), so a relay that
// cannot record events does not get a fleet-wide replay storm.
//
// Cost: one pass over the records per trigger (settle and scan are the same
// pass), and NONE at all from poke() once a pass found no webhook record running
// or unacked — until a webhook job starts (noteWebhookJob) or settles (onSettled).
// So the 30 s recount is free on machines that never ran a webhook job.
//
// Only the newest JOB_ENDED_REPLAY_MAX unacked events are kept; older ones are
// explicitly un-flagged so they are not re-evaluated on every connect.

import { existsSync } from "node:fs";
import {
  isWebhookId,
  JOB_ENDED_RETRY_BASE_MS,
  JOB_ENDED_RETRY_MAX_MS,
  type AgentJobEndedMsg,
} from "@aicommander/protocol";
import { settleEndedWebhookRecords, type WebhookScan } from "./job-ended-settle.js";
import { JobStore, resolveJobsRoot } from "./job-store.js";
import { peekJobManager, type JobManager } from "./job-manager.js";
import type { JobMeta } from "./job-types.js";

/** Fraction of each backoff delay taken off at random: delay ∈ [(1-J)·d, d]. */
export const JOB_ENDED_RETRY_JITTER = 0.2;

/** Backoff for the n-th replay (0-based): BASE·2^n capped at MAX, minus jitter. */
export function jobEndedRetryDelay(
  attempt: number,
  random: () => number = Math.random,
  baseMs = JOB_ENDED_RETRY_BASE_MS,
  maxMs = JOB_ENDED_RETRY_MAX_MS,
): number {
  const nominal = Math.min(baseMs * 2 ** Math.min(attempt, 30), maxMs);
  const r = Math.min(Math.max(random(), 0), 1);
  return Math.round(nominal * (1 - JOB_ENDED_RETRY_JITTER * r));
}

export interface JobEndedReporterOptions {
  /**
   * The manager when one exists; null/undefined falls back to the process-wide
   * singleton (peekJobManager), and only without one to "read disk directly".
   */
  manager?: () => JobManager | null | undefined;
  /** Deliver one event. Must not throw (socket errors swallowed). */
  send: (msg: AgentJobEndedMsg) => void;
  jobsRoot?: () => string;
  random?: () => number;
  baseMs?: number;
  maxMs?: number;
}

export class JobEndedReporter {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private flush: ReturnType<typeof setTimeout> | null = null;
  private attempt = 0;
  private stopped = false;
  /** webhookIds sent on THIS connection; only the backoff replay resends them. */
  private readonly sent = new Set<string>();
  /** webhookId → jobId of the last scan's unacked events (≤ JOB_ENDED_REPLAY_MAX), for ack(). */
  private readonly owed = new Map<string, string>();
  /** Whether disk may hold a pending webhook record; null = not scanned yet. */
  private mayHavePending: boolean | null = null;
  private unsubscribe: (() => void) | null = null;

  constructor(private readonly opts: JobEndedReporterOptions) {}

  /**
   * After this connection's first agent:register: send everything unacked that
   * this connection has not sent yet (a recount may already have sent some).
   */
  start(): void {
    this.attempt = 0;
    this.clearTimer();
    this.cycle(false, true);
  }

  /** Subscribe to the manager's settles; undone by stop(). */
  attach(manager: JobManager): void {
    if (this.stopped || this.unsubscribe) return;
    this.unsubscribe = manager.onJobEnded(() => this.onSettled());
  }

  /** A job carrying a webhookId is being started: the next poke must look at disk. */
  noteWebhookJob(): void {
    this.mayHavePending = true;
  }

  /** A webhook job settled (JobManager.onJobEnded): send it soon, not inside settle. */
  onSettled(): void {
    this.mayHavePending = true;
    if (this.stopped || this.flush) return;
    this.flush = setTimeout(() => {
      this.flush = null;
      this.cycle(false);
    }, 0);
    this.flush.unref?.();
  }

  /**
   * Run the cheap settle path and send what it ended. Called from the
   * agent:job_state recount (which may run with no manager at all).
   */
  poke(): void {
    if (this.mayHavePending === false) return;
    this.cycle(false);
  }

  /**
   * do:job_ended_ack: the relay recorded it. Idempotent; unknown ids are a no-op
   * (every event this process sent came from a scan that filled `owed`, and
   * start() rescans on every connection). Reads ONE record, never the whole store.
   */
  ack(webhookId: unknown): void {
    if (!isWebhookId(webhookId)) return;
    const jobId = this.owed.get(webhookId);
    if (jobId === undefined) return;
    this.owed.delete(webhookId);
    this.sent.delete(webhookId);
    try {
      const store = this.store();
      const meta = store?.readMeta(jobId);
      if (!store || !meta || meta.webhookId !== webhookId || meta.endedUnacked !== true) return;
      const next = { ...meta };
      delete next.endedUnacked;
      store.writeMeta(next);
    } catch {
      // Best effort: an ack we failed to record only causes a duplicate replay.
    }
  }

  stop(): void {
    this.stopped = true;
    this.unsubscribe?.();
    this.unsubscribe = null;
    this.clearTimer();
    if (this.flush) { clearTimeout(this.flush); this.flush = null; }
  }

  private cycle(replayAll: boolean, restart = false): void {
    if (this.stopped) return;
    let pending = false;
    try {
      const scan = this.settleAndScan();
      pending = scan.pending;
      this.mayHavePending = pending;
      // The scan is the complete owed set (capped), so the map stays bounded.
      this.owed.clear();
      for (const meta of scan.unacked) this.owed.set(meta.webhookId as string, meta.jobId);
      for (const meta of scan.unacked) {
        const id = meta.webhookId as string;
        if (!replayAll && this.sent.has(id)) continue;
        this.sent.add(id);
        this.sendOne(meta);
      }
    } catch {
      // Never out of a socket handler or a timer; the next trigger converges.
      this.mayHavePending = null;
    }
    // A fresh event never pushes an armed timer later (that would starve older
    // unacked events under a steady stream of completions); the backoff resets
    // only when nothing is pending (arm) or on a new connection (start).
    this.arm(pending, replayAll || restart);
  }

  private arm(pending: boolean, fired: boolean): void {
    if (this.stopped) return;
    if (!pending) {
      this.clearTimer();
      this.attempt = 0;
      return;
    }
    if (this.timer && !fired) return;
    this.clearTimer();
    const delay = jobEndedRetryDelay(this.attempt++, this.opts.random, this.opts.baseMs, this.opts.maxMs);
    this.timer = setTimeout(() => {
      this.timer = null;
      this.cycle(true);
    }, delay);
    this.timer.unref?.();
  }

  private clearTimer(): void {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
  }

  private sendOne(meta: JobMeta): void {
    const msg: AgentJobEndedMsg = {
      type: "agent:job_ended",
      webhookId: meta.webhookId as string,
      jobId: meta.jobId,
      status: meta.status === "exited" ? "exited" : "unknown",
      exitCode: meta.status === "exited" ? meta.exitCode : null,
      endedAt: meta.endedAt as number,
      ...(meta.endedAtApproximate === true ? { endedAtApproximate: true } : {}),
    };
    try {
      this.opts.send(msg);
    } catch {
      // Best effort; the replay timer retries.
    }
  }

  /** One pass: the cheap settle and the scan of what is owed. */
  private settleAndScan(): WebhookScan {
    const none: WebhookScan = { unacked: [], pending: false };
    const manager = this.manager();
    if (manager) {
      // A manager that outlived an earlier connection: hear its settles too.
      this.attach(manager);
      return manager.settleEndedWebhookJobs() ?? none;
    }
    const store = this.store();
    return store ? settleEndedWebhookRecords(store) : none;
  }

  private manager(): JobManager | null {
    return this.opts.manager?.() ?? peekJobManager();
  }

  private store(): JobStore | null {
    const manager = this.manager();
    if (manager) return new JobStore(manager.jobsRoot);
    const root = (this.opts.jobsRoot ?? (() => resolveJobsRoot()))();
    return existsSync(root) ? new JobStore(root) : null;
  }
}
