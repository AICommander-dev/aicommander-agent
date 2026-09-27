// Pushes agent:job_state — the number of RUNNING detached jobs — to the relay, so
// list_machines / session_status / the dashboard can show it with no extra RPC at
// read time. One reporter per connection; the JobManager outlives connections, so
// the reporter never owns it, it only asks for a count.
//
// Convergence, not bookkeeping: every trigger (connect, start, exit, cancel, a
// vanished process) just schedules a fresh count from disk, coalesced by a short
// debounce. While the last reported count is non-zero a slow poll re-counts too,
// because a job recovered after an agent restart has no exit callback here and
// its disappearance is only noticed by a re-read.
//
// The count itself (JobManager.runningJobCount) never runs a synchronous process
// probe — no execFileSync of ps / wmic / PowerShell on the main loop — only record
// reads, the exit marker and kill(pid, 0). Bound: a job recovered after a restart
// is dropped within one poll interval of exiting; only a dead job whose pid was
// reused lingers until the next job RPC refreshes it.

import { existsSync } from "node:fs";
import { JOB_STATE_POLL_INTERVAL_MS, parseRunningJobs } from "@aicommander/protocol";
import { JobStore, resolveJobsRoot } from "./job-store.js";
import { countRunningJobRecords, type JobManager } from "./job-manager.js";

/** Coalesces a burst of transitions (a cancel settles, then its GPU frees, …). */
export const JOB_STATE_DEBOUNCE_MS = 500;

export interface JobStateReporterOptions {
  /** Fresh running-job count, or null when it cannot be determined right now. */
  count: () => number | null;
  /** Deliver one snapshot to the relay. Must not throw (socket errors swallowed). */
  send: (runningJobs: number) => void;
  debounceMs?: number;
  pollMs?: number;
}

export class JobStateReporter {
  private lastSent: number | null = null;
  private debounce: ReturnType<typeof setTimeout> | null = null;
  private poll: ReturnType<typeof setInterval> | null = null;
  private stopped = false;
  private forceNext = false;

  constructor(private readonly opts: JobStateReporterOptions) {}

  /**
   * Report the current count UNCONDITIONALLY (even if unchanged): called right
   * after each connection's first agent:register, which gives the relay a fresh
   * stored snapshot without one.
   */
  start(): void {
    this.forceNext = true;
    this.schedule();
  }

  /** Something may have changed: recount soon, send only if the count differs. */
  schedule(): void {
    if (this.stopped || this.debounce) return;
    this.debounce = setTimeout(() => {
      this.debounce = null;
      this.report();
    }, this.opts.debounceMs ?? JOB_STATE_DEBOUNCE_MS);
    this.debounce.unref?.();
  }

  stop(): void {
    this.stopped = true;
    if (this.debounce) { clearTimeout(this.debounce); this.debounce = null; }
    this.setPolling(false);
  }

  private report(): void {
    if (this.stopped) return;
    let raw: number | null;
    try {
      raw = this.opts.count();
    } catch {
      raw = null;
    }
    // Never send a value the relay would reject; "could not count" is not news.
    const count = parseRunningJobs(raw);
    if (count === undefined) return;
    if (this.forceNext || count !== this.lastSent) {
      this.forceNext = false;
      this.lastSent = count;
      this.opts.send(count);
    }
    this.setPolling(count > 0);
  }

  private setPolling(on: boolean): void {
    if (on && !this.poll && !this.stopped) {
      this.poll = setInterval(() => this.report(), this.opts.pollMs ?? JOB_STATE_POLL_INTERVAL_MS);
      this.poll.unref?.();
    } else if (!on && this.poll) {
      clearInterval(this.poll);
      this.poll = null;
    }
  }
}

/**
 * The count for a connection whose manager may not exist yet. It NEVER creates
 * the manager: creation runs restart recovery (refresh → a synchronous process
 * probe per running job), which must wait for a real job RPC. With no manager,
 * the records on disk are counted with the same non-probing rules
 * (countRunningJobRecords); with no jobs directory the answer is 0 and nothing is
 * touched. Once a job RPC created the manager, it is asked instead.
 */
export function lazyRunningJobCount(
  existing: JobManager | null | undefined,
  jobsRoot: () => string = () => resolveJobsRoot(),
): number {
  if (existing) return existing.runningJobCount();
  const root = jobsRoot();
  if (!existsSync(root)) return 0;
  return countRunningJobRecords(new JobStore(root));
}
