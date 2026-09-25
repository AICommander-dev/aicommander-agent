// The running-job count an agent reports to the relay (AgentJobStateMsg). Kept in
// its own module because BOTH ends of the wire need the same narrowing rule: the
// agent must never send a value the relay would reject, and the relay must never
// store — and later print into list_machines / session_status — a value an agent
// could use to write arbitrary text or an absurd number into a relay message.

import { JOB_MAX_CONCURRENT } from "./constants.js";

/**
 * Highest count the relay accepts. A little above JOB_MAX_CONCURRENT on purpose:
 * the agent's own ceiling only refuses NEW starts, and jobs recovered after a
 * restart (or started by a build with a higher limit) may briefly exceed it. A
 * value past this is garbage, not a busy machine.
 */
export const RUNNING_JOBS_REPORT_MAX = JOB_MAX_CONCURRENT * 4;

/**
 * While the last reported count is non-zero, the agent re-counts on this interval.
 * Exit callbacks cover jobs this process spawned; a job recovered after a restart
 * has no child handle, so its disappearance is only noticed by a re-read — this is
 * what makes the reported count converge instead of sticking at "1 running".
 */
export const JOB_STATE_POLL_INTERVAL_MS = 30_000;

/**
 * Narrow an untrusted running-job count: a non-negative safe integer no larger
 * than RUNNING_JOBS_REPORT_MAX, or `undefined` (reject — never clamp a garbage
 * value into a plausible-looking one).
 */
export function parseRunningJobs(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) return undefined;
  if (value < 0 || value > RUNNING_JOBS_REPORT_MAX) return undefined;
  return value;
}
