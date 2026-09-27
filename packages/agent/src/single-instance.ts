/**
 * "May I start an agent on this machine right now?"
 *
 * Two agents on one machine is not a merge conflict, it is a takeover. Both
 * register the SAME durable device identity, the relay keeps only the newest
 * connection for a session, and the loser is simply gone — along with whatever
 * remote operator was driving through it. There is no error anywhere: the second
 * agent looks perfectly healthy, and the machine looks offline to the person who
 * was using it a second ago.
 *
 * That is not a theoretical race. On 2026-08-10 an assistant probing a live box
 * ran `aicommander-agent version`, which (commander routes an unknown argument to
 * the default command) started a second agent, took the session, and then died
 * with the exec that spawned it — leaving a production machine unreachable until
 * someone with local access restarted the service. cli-guard.ts closed the typo
 * that got there; this closes the door itself, for every spelling that means
 * "run": the bare invocation, an explicit `run`, and anything a future default
 * command might swallow.
 *
 * FAIL CLOSED ON DOUBT. `findRunningAgents` deliberately reports "could not tell"
 * separately from "nothing there" — an alive pid whose identity was unreadable, or
 * a /proc walk that failed. Both mean the same thing here: we cannot promise we
 * are alone, and the cost of being wrong (a machine falls off the network) is far
 * higher than the cost of stopping (a human reads one message and decides). The
 * operator overrides with --force; nothing overrides itself.
 */

import type { LiveAgentScan } from "./live-agent.js";

export type SingleInstanceVerdict =
  /** Nothing else is running, and we were able to look properly. Start. */
  | { kind: "clear" }
  /** Proven: an agent process is alive right now. */
  | { kind: "running"; pids: number[] }
  /**
   * Unproven either way. `pids` are alive but unidentifiable; `scanFailed` means
   * the process table itself could not be walked — the source that finds an agent
   * nobody wrote down, so its failure is exactly as disqualifying as an
   * unreadable pid.
   */
  | { kind: "uncertain"; pids: number[]; scanFailed: boolean };

/**
 * Turn a scan into a start/stop decision. Proven-running outranks uncertainty so
 * the operator gets the specific message when we actually know something.
 */
export function singleInstanceVerdict(scan: LiveAgentScan): SingleInstanceVerdict {
  if (scan.running.length > 0) return { kind: "running", pids: scan.running };
  if (scan.unverified.length > 0 || scan.scanFailed) {
    return { kind: "uncertain", pids: scan.unverified, scanFailed: scan.scanFailed };
  }
  return { kind: "clear" };
}

/**
 * How the operator is told to look, and how to override.
 *
 * Platform-aware because this refusal fires everywhere, not just on a systemd box:
 * the probe answers "could not tell" on any platform where it cannot read a
 * process's identity, and macOS reaches it through `ps` just as readily. Handing
 * someone `systemctl` on a Mac reads as a broken tool and buries the one line that
 * actually applies to them.
 */
function howToProceed(platform: NodeJS.Platform): string {
  const inspect =
    platform === "linux"
      ? "  Check it:      systemctl status aicommander-agent\n" +
        "  Restart it:    systemctl restart aicommander-agent"
      : platform === "darwin"
        ? "  Check it:      ps -ef | grep aicommander-agent\n" +
          "                 (desktop app? quit and reopen AI Commander from the tray)"
        : "  Check it:      look for a running aicommander-agent process";
  return `${inspect}\n  Start anyway:  aicommander-agent run --force`;
}

/**
 * What the operator reads instead of a silent takeover. It states the
 * consequence rather than the rule, because the person seeing this is usually
 * mid-task and needs to know what they were about to break, not which check
 * fired.
 */
export function singleInstanceMessage(
  verdict: SingleInstanceVerdict,
  platform: NodeJS.Platform = process.platform,
): string {
  if (verdict.kind === "clear") return "";

  const consequence =
    "Starting a second agent takes this machine's relay session away from the first:\n" +
    "both register the same device identity, the relay keeps only the newest\n" +
    "connection, and anyone driving this machine right now is cut off without an error.";

  if (verdict.kind === "running") {
    const pids = verdict.pids.join(", ");
    return (
      `Refusing to start: an AI Commander agent is already running on this machine (pid ${pids}).\n\n` +
      `${consequence}\n\n${howToProceed(platform)}`
    );
  }

  const why = verdict.scanFailed
    ? verdict.pids.length > 0
      ? `the process table could not be read, and pid ${verdict.pids.join(", ")} is alive but unidentifiable`
      : "the process table could not be read, so an agent nobody recorded would be invisible here"
    : `pid ${verdict.pids.join(", ")} is alive but its identity could not be read`;

  return (
    `Refusing to start: could not rule out an agent already running on this machine —\n` +
    `${why}.\n\n` +
    `${consequence}\n\n` +
    `This is a refusal to GUESS, not a detection: if nothing is running, --force is correct\n` +
    `and safe. Deciding that is yours, because only you can look at the machine.\n\n` +
    `${howToProceed(platform)}`
  );
}
