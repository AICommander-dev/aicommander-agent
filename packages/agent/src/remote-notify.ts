import {
  REMOTE_NOTIFY_MIN_INTERVAL_MS,
  REMOTE_NOTIFY_MAX_INTERVAL_MS,
  REMOTE_ACTIVITY_GAP_MS,
} from "@aicommander/protocol";

/** Per-operator bookkeeping for the connect notice (see shouldNotify). */
export interface OperatorState {
  /** Epoch-ms of this operator's most recent command (notified or not). */
  lastActivityAt: number;
  /** Epoch-ms the last notice for this operator fired, or 0 if never. */
  lastNotifiedAt: number;
}

/**
 * Decide whether an operator's command at `now` should raise a fresh "someone
 * connected" notice, given their prior state (undefined = first contact ever):
 *
 *  - first contact always notifies (`pierwsza notyfikacja powinna pójść`);
 *  - a NEW session notifies when BOTH hold:
 *      • the operator has been idle longer than REMOTE_ACTIVITY_GAP_MS — so a
 *        continuous working session (back-to-back commands) is one "connection",
 *        notified once at its start and never mid-stream; and
 *      • their last notice was at least REMOTE_NOTIFY_MIN_INTERVAL_MS ago — a hard
 *        one-per-hour-per-operator floor between session notices;
 *  - additionally, a continuous-session CEILING fires regardless of the idle gap
 *    once REMOTE_NOTIFY_MAX_INTERVAL_MS has passed since the last notice, so an
 *    operator working non-stop all day is still re-announced periodically (≤ once
 *    per that interval) instead of only the very first time.
 *
 * Pure: the caller supplies `now` and the prior state, so it is trivially testable.
 */
export function shouldNotify(prev: OperatorState | undefined, now: number): boolean {
  if (!prev) return true;
  const sinceNotice = now - prev.lastNotifiedAt;
  // Continuous-session ceiling: re-warn even mid-stream after a long unbroken run.
  if (sinceNotice >= REMOTE_NOTIFY_MAX_INTERVAL_MS) return true;
  const idleEnough = now - prev.lastActivityAt > REMOTE_ACTIVITY_GAP_MS;
  const cooledDown = sinceNotice >= REMOTE_NOTIFY_MIN_INTERVAL_MS;
  return idleEnough && cooledDown;
}

/**
 * Tracks remote operators and applies the connect-notice rate limit. Holds the
 * per-operator state in memory (reset on agent restart — a fresh start re-notifies,
 * which is the safe direction). `note()` is the single entry point: record an
 * operator's activity and learn whether to surface a notice. Time is injected so
 * the whole thing is deterministic under test.
 */
export class RemoteNotifier {
  private readonly seen = new Map<string, OperatorState>();

  /**
   * Record a command from operator `id` at `now`; returns true iff a notice should
   * fire. Always advances `lastActivityAt`; advances `lastNotifiedAt` only when it
   * returns true, so the one-per-hour ceiling is measured from the last NOTICE, not
   * the last command.
   */
  note(id: string, now: number): boolean {
    const prev = this.seen.get(id);
    const notify = shouldNotify(prev, now);
    this.seen.set(id, {
      lastActivityAt: now,
      lastNotifiedAt: notify ? now : (prev?.lastNotifiedAt ?? 0),
    });
    return notify;
  }
}
