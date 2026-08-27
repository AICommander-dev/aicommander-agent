import { JOB_MAX_GPU_INDEX } from "@aicommander/protocol";
import type { GpuDevice } from "@aicommander/protocol";

/**
 * Deciding whether a `gpuIndex` a caller sent can name a card ON THIS MACHINE.
 *
 * Split out of job-manager.ts rather than added to it for two reasons: the whole
 * concern is PURE (a number, a device list, a sentence), and job-manager is far
 * past the 1000-line limit already. Nothing here touches disk, and nothing here
 * probes hardware — the device list is INJECTED (JobManager.setKnownGpus), which
 * is what keeps the probe/telemetry policy in exactly one place (gpu.ts, driven
 * by connection.ts) instead of forking a second copy behind job_start.
 *
 * Two bounds, deliberately different in kind:
 *  - JOB_MAX_GPU_INDEX is a NAMESPACE bound (0..4095 = the `gpu-<n>.lock` names
 *    we may ever create). It says nothing about hardware, and it is what made
 *    `gpuIndex: 7` on a one-card box a perfectly acceptable request that then
 *    ran with CUDA_VISIBLE_DEVICES=7, found no card, and either died hours later
 *    or silently fell back to CPU.
 *  - the known device list is a HARDWARE bound, and it is only consulted when we
 *    actually have one. `probeGpuState()` is what tells those two apart, and it
 *    is deliberately STINGY with confidence: ONLY a clean `nvidia-smi` run that
 *    reported zero devices yields a CONFIDENT empty list. An absent binary (it
 *    may simply be off the service's minimal PATH), a wedged driver, a
 *    `nvidia-smi` that would not fork on a loaded box, or output that parsed
 *    only in part are all "we could not tell". So an unknown list
 *    (`null` here) must stay PERMISSIVE:
 *    refusing a legitimate training run because the probe hiccuped would be a
 *    worse bug than the one this fixes.
 */

/** What `JobManager` knows about this machine's cards; `null` = we do not know. */
export type KnownGpus = readonly GpuDevice[] | null;

/** Either the value to use, or the sentence to refuse the request with. */
export type GpuIndexDecision = { gpuIndex: number | null } | { invalid: string };

/**
 * How many cards a refusal enumerates before it summarises the rest. A refusal
 * message is text on its way into an LLM's context (and is length-bounded at the
 * relay), so an 8-GPU box names its cards and a 64-GPU host does not blow the
 * budget listing all of them.
 */
const MAX_LISTED_DEVICES = 8;

/** Longest device name a refusal quotes. Names come from the driver, not a caller. */
const MAX_QUOTED_NAME_CHARS = 48;

/**
 * A gpuIndex from the wire. Anything that is not a plausible device index cannot
 * name a card on ANY machine, so it comes back as an `invalid_request` refusal —
 * never as a silently dropped field, which would start an unreserved GPU job and
 * cause the exact OOM collision the lock exists to prevent.
 *
 * The hardware check answers the same class of question — "retrying this exact
 * request fails identically" — so it is the same `invalid_request` refusal, not
 * a machine error. And it is worded like the `gpu_busy` message it sits next to:
 * name the culprit, then give the concrete ways out, because the caller is an
 * agent that has to pick one without asking anybody.
 *
 * Returns either the normalized value or the refusal text; wrapping the number
 * keeps `null` (no GPU asked for) distinguishable from a refusal without another
 * sentinel.
 */
export function decideGpuIndex(value: unknown, known: KnownGpus): GpuIndexDecision {
  if (value === undefined || value === null) return { gpuIndex: null };
  // These strings are relayed verbatim to the MCP caller, so they must spell the
  // parameter the way that caller passes it: `gpu_index`. The internal wire field
  // is `gpuIndex`, and naming THAT here tells a reader to send a key the tool
  // schema does not have — a refusal whose suggested fix does not work is barely
  // better than no refusal. The relay's own gpu_busy message already says
  // `gpu_index`; this one must not disagree with it.
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > JOB_MAX_GPU_INDEX) {
    return { invalid: "gpu_index must be a non-negative device index." };
  }
  // Unknown list ⇒ today's permissive behaviour, on purpose (see the header).
  if (known === null) return { gpuIndex: value };
  if (known.some((device) => device.index === value)) return { gpuIndex: value };
  if (known.length === 0) {
    return {
      invalid:
        `This machine has no NVIDIA GPU, so gpu_index ${value} cannot name a card here. ` +
        "Start the job without gpu_index — it still runs, just with no card reserved.",
    };
  }
  return {
    invalid:
      `This machine has no GPU ${value} — available: ${describeGpus(known)}. ` +
      "Use one of those gpu_index values, pick another machine, or start the job without gpu_index.",
  };
}

/**
 * The card list as a caller-facing phrase: `[0] RTX 5080, [1] RTX 4090`.
 *
 * Names are re-sanitised here even though gpu.ts already did it at the probe:
 * this string is authored INTO a refusal an LLM reads, and the payload-safety
 * invariant does not get to assume the value took the path we expect.
 */
export function describeGpus(known: readonly GpuDevice[]): string {
  const shown = known.slice(0, MAX_LISTED_DEVICES).map((device) => {
    const name = quoteDeviceName(device.name);
    return name === "" ? `[${device.index}]` : `[${device.index}] ${name}`;
  });
  const rest = known.length - shown.length;
  return rest > 0 ? `${shown.join(", ")}, +${rest} more` : shown.join(", ");
}

function quoteDeviceName(value: unknown): string {
  if (typeof value !== "string") return "";
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, MAX_QUOTED_NAME_CHARS);
}
