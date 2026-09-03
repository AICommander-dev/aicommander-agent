// Whether this machine can run elevated commands right now — and, when it cannot,
// WHY, in the one vocabulary the relay, the doctor and the caller-facing messages
// all share (@aicommander/protocol ElevatedUnavailableReason).
//
// This is the presentation half of the 2026-09-02 finding. The plumbing was
// already right: the agent advertises `elevatedExec` only after it has actually
// reached a helper, reconciles that every 60 seconds, and the relay refuses
// elevated work without it. What was missing is that a machine with NO helper
// looked exactly like one whose agent was too old to say, or one that was simply
// offline — so nobody, human or model, could state the fact. On the incident
// machine the helper had never been registered and every elevated call would have
// failed on a box that looked completely healthy.
//
// ── THIS MODULE GRANTS NOTHING ───────────────────────────────────────────────
// It answers one question and produces one word. `available: true` still comes
// SOLELY from discoverHelperDetailed() completing a handshake with a helper that
// answered on a protocol we speak, with a single consistent boot nonce — the same
// verdict the fail-closed path always used. No reason, however benign, is ever a
// reason to proceed: a helper that failed verification is refused exactly as
// firmly as before, it just now says so out loud.
//
// ── NOTHING IDENTIFYING LEAVES HERE ──────────────────────────────────────────
// The reason travels to the relay and into text an LLM caller reads, so it is a
// closed vocabulary and never a path, a port, a hostname or a signer subject.
// `aicommander-agent doctor` prints those, on the machine, to the person there.

import fs from "node:fs";
import path from "node:path";
import {
  elevatedEndpoints,
  helperInstallDir,
  helperVersionMarkerPath,
  MAC_DAEMON_PLIST,
  WIN_HELPER_TASK_NAME,
  type ElevatedEndpoint,
} from "@aicommander/priv-helper";
import type { ElevatedUnavailableReason } from "@aicommander/protocol";
import { discoverHelperDetailed } from "./elevated-executor.js";
// A neutral module on purpose: this file is fail-closed RUNTIME logic and must
// not depend on the diagnostics subtree (see windows-scheduled-task.ts).
import { queryScheduledTask } from "./windows-scheduled-task.js";

/** A reachable helper, or the reason there is none. */
export type ElevatedAvailability =
  | { available: true; bootId: string; endpoint: ElevatedEndpoint }
  | { available: false; reason: ElevatedUnavailableReason };

/**
 * How long a Windows registration answer is reused.
 *
 * The reconciler runs every 60 seconds and the registration question costs a
 * PowerShell process; asking it every minute forever on every machine that has no
 * helper is a real cost for an answer that changes only when somebody runs an
 * installer. The ENDPOINT is still probed every cycle — the moment a helper
 * answers, the machine is capable again and no registration lookup is consulted
 * at all — so this cache can only ever delay a change in the WORDS, never in the
 * verdict.
 */
const REGISTRATION_TTL_MS = 10 * 60_000;

/**
 * How long a "we could not ask" is reused — which is NOT the same question.
 *
 * The ten-minute TTL is justified by an answer that "changes only when somebody
 * runs an installer". A `null` makes no claim about the machine at all: it says
 * the query did not come back, which is a property of THIS MOMENT (a PowerShell
 * that lost a race with a CIM module cold-load under an AV scan) and can be true
 * once and false a minute later. Cached like a verdict, it pinned the incident
 * machine — the one this work exists for — to `endpoint_unreachable` ten minutes
 * at a stretch, and could keep it there indefinitely, so `not_registered` never
 * got said. One reconcile interval is the floor: enough that a wedged host is not
 * re-probed within a single cycle, short enough that the next cycle can ask again.
 */
const REGISTRATION_UNKNOWN_TTL_MS = 60_000;

let registrationCache: { at: number; registered: boolean | null } | null = null;

/** Test seam: drop the memoized Windows registration answer. */
export function __resetRegistrationCache(): void {
  registrationCache = null;
}

/**
 * The helper binary the marker claims is installed, or null on a platform that
 * has none.
 *
 * The name is repeated here rather than imported because the helper package
 * spells it inside its own doctor verb, which runs AS the helper and asks a
 * different question ("am I the installed copy?"). What is needed here is only
 * "is there an executable where the installer puts one", from the agent's
 * unprivileged side, and the install directory is already exported.
 */
function helperExecutablePath(): string | null {
  const dir = helperInstallDir();
  if (dir === null) return null;
  return path.join(dir, process.platform === "win32" ? "aicommander-priv-helper.exe" : "aicommander-priv-helper");
}

function exists(target: string): boolean {
  try {
    return fs.existsSync(target);
  } catch {
    return false;
  }
}

/**
 * Has the OS been told to RUN the helper? `true` yes, `false` no, `null` we could
 * not find out — and `null` must stay a real answer: reporting "never registered"
 * because a PowerShell query failed would invent the incident's signature on a
 * healthy machine.
 *
 *  - Windows: the SYSTEM AtStartup task the installer registers (only after both
 *    installed copies pass its exact-signer Authenticode check, which it ignores
 *    the failure of — hence a healthy install with no helper).
 *  - macOS: the root LaunchDaemon plist, which only the .pkg installs; whether
 *    launchd has LOADED it needs root to read, and the endpoint probe already
 *    answered that question.
 */
async function helperRegistered(): Promise<boolean | null> {
  if (process.platform === "darwin") return exists(MAC_DAEMON_PLIST);
  if (process.platform !== "win32") return null;
  const now = Date.now();
  if (registrationCache !== null) {
    const ttl = registrationCache.registered === null ? REGISTRATION_UNKNOWN_TTL_MS : REGISTRATION_TTL_MS;
    if (now - registrationCache.at < ttl) return registrationCache.registered;
  }
  const task = await queryScheduledTask(WIN_HELPER_TASK_NAME);
  const registered = task.queried ? task.registered : null;
  registrationCache = { at: now, registered };
  return registered;
}

/**
 * The part of the verdict that costs nothing to know: no helper on this platform
 * at all, or the installed files are not there. `undefined` means "everything
 * cheap says a helper could be here" — never that one is reachable, which only a
 * handshake can establish.
 *
 * SYNCHRONOUS, and that is what it is for. connection.ts registers the moment the
 * socket opens, before helper discovery has had a chance to run, and used to send
 * that first frame with no reason at all — so on every helper-less machine (all
 * of Linux, every mac/Windows box without one) the first reconcile found a reason
 * where there had been none and sent a SECOND register. On the relay each
 * register is two storage writes, a pending-register clear, a broadcast to every
 * dashboard and a ping; the fleet paid all of it twice for a fact that was
 * knowable in two `existsSync` calls. Both verdicts this returns are final —
 * discovery cannot overturn "there is no helper on this platform" or "the files
 * are missing" — so the frame that carries one is right the first time.
 */
export function staticElevatedUnavailableReason(): ElevatedUnavailableReason | undefined {
  const marker = helperVersionMarkerPath();
  if (elevatedEndpoints().length === 0 || marker === null) return "platform_unsupported";
  const helperExe = helperExecutablePath();
  if (!exists(marker) || (helperExe !== null && !exists(helperExe))) return "not_installed";
  return undefined;
}

/**
 * Resolve the machine's elevated-execution state.
 *
 * The order is the doctor's order, because each step is only meaningful once the
 * one before it holds: no helper on this platform at all → files present? → the
 * OS told to run them? → does it answer, on our protocol, as one identity?
 *
 * `opts` exists for tests only; production callers pass nothing.
 */
export async function resolveElevatedAvailability(opts?: {
  discover?: typeof discoverHelperDetailed;
  registered?: () => Promise<boolean | null>;
}): Promise<ElevatedAvailability> {
  // The two cheap verdicts, in the doctor's order (see
  // staticElevatedUnavailableReason):
  //  - Linux (and anything else without an endpoint) has no helper BY DESIGN:
  //    the agent already runs commands as the user it was installed under, so
  //    the answer is "stop asking for elevated", not "install something";
  //  - no marker, no discovery — the on-disk gate the agent has always applied
  //    before any probe. An unreadable marker counts as absent, which is the
  //    fail-closed reading and the one a re-install fixes. The EXECUTABLE counts
  //    as well, and for the incident's own reason: the marker is a text file the
  //    installer drops, the helper is a binary that looks like a dropper to a
  //    behavioural engine, so quarantining the executable and leaving the marker
  //    is an ordinary outcome. Judged on the marker alone that machine reads as
  //    "installed but silent", which sends the operator to reboot or repair the
  //    task; there is nothing there to start. Missing files means not installed,
  //    whichever of them is missing.
  const staticReason = staticElevatedUnavailableReason();
  if (staticReason !== undefined) return { available: false, reason: staticReason };

  const found = await (opts?.discover ?? discoverHelperDetailed)();
  if (found.ok) return { available: true, bootId: found.bootId, endpoint: found.endpoint };
  if (found.cause === "protocol_mismatch") {
    return { available: false, reason: "protocol_mismatch" };
  }
  if (found.cause === "conflict") return { available: false, reason: "endpoint_conflict" };

  // Installed, and silent. The registration answer is what separates the incident
  // state (the installer never registered it, so nothing ever starts it) from a
  // helper that is registered and simply not running right now — two states with
  // two different remedies. "We could not tell" falls back to the weaker,
  // always-true statement rather than guessing the more alarming one.
  const registered = await (opts?.registered ?? helperRegistered)();
  return { available: false, reason: registered === false ? "not_registered" : "endpoint_unreachable" };
}
