import { spawn } from "node:child_process";
import { GPU_PROBE_TIMEOUT_MS } from "@aicommander/protocol";
import type { GpuDevice } from "@aicommander/protocol";

/**
 * NVIDIA GPU discovery for machine metadata.
 *
 * The relay publishes what this returns in `list_machines` / `session_status`, so
 * an MCP caller can pick a box for a compute job from data it already has instead
 * of shelling into every machine to run `nvidia-smi` by hand.
 *
 * Three properties matter more than completeness here:
 *  - it must NEVER throw (it runs on the registration path and on a timer);
 *  - it must NEVER stall (a hung/zombie driver would otherwise hold registration
 *    hostage — hence the hard kill timer, not just a `timeout` option);
 *  - it must NEVER log content. Probe failures are silent by design: this file
 *    obeys the same payload-safety invariant as the executor.
 */

/**
 * Queried in a fixed order; the parser is positional. `--format=csv,noheader,nounits`
 * makes every value a bare number (except `name`/`driver_version`), which is what
 * lets the row parser stay this small.
 */
const QUERY_FIELDS =
  "index,name,memory.total,memory.used,utilization.gpu,driver_version";

/**
 * Ceiling on the probe's stdout. A well-behaved `nvidia-smi` emits ~100 bytes per
 * device; 64 KiB is thousands of rows. Anything past it means we are not talking
 * to the tool we think we are, so the probe is abandoned rather than parsed.
 */
const MAX_STDOUT_BYTES = 64 * 1024;

/** Longest device name we keep — the rest is truncated payload. */
const MAX_DEVICE_NAME_LENGTH = 128;
/** Longest driver version string we keep — the rest is truncated payload. */
const MAX_DRIVER_LENGTH = 64;

/**
 * What the probe LEARNED, as opposed to what goes on the wire.
 *
 * `probeGpus()` collapses "this machine has no NVIDIA card" and "the probe did
 * not work" into one `undefined`, because the wire format wants exactly that
 * collapse (see AgentRegisterMsg.gpus). Local consumers need them apart: the job
 * GPU check may only refuse a `gpuIndex` on a machine it KNOWS is GPU-less, and
 * must stay permissive when the probe merely hiccuped.
 *
 * THREE states, not two, and the third is the point of the type:
 *  - `devices` — the probe RAN, exited cleanly, and EVERY row parsed. The list
 *    is authoritative and non-empty.
 *  - `none` — the probe RAN, exited cleanly, and reported zero devices. Only a
 *    successful execution may produce this, so it is a real claim about the
 *    hardware ("there are no NVIDIA GPUs here"), not an absence of information.
 *  - `unknown` — we learned nothing; every consumer must fall back to whatever
 *    it does without hardware knowledge.
 *
 * Three variants rather than one `known` carrying a possibly-empty array,
 * because the two confident answers have different consequences (one enumerates
 * cards in a refusal, one refuses outright) and an `if (devices.length === 0)`
 * inside a `known` branch is exactly the kind of implicit second discriminant
 * that let a FAILED probe be read as "no GPUs" once already.
 */
export type GpuProbeState =
  | { certainty: "devices"; devices: GpuDevice[] }
  | { certainty: "none" }
  | { certainty: "unknown" };

/** Reusable singletons for the two payload-free states. */
const NONE: GpuProbeState = { certainty: "none" };
const UNKNOWN: GpuProbeState = { certainty: "unknown" };

/**
 * The probe state as a LOCAL consumer wants it: the cards we know about, or
 * `undefined` when we know nothing. `[]` here is the confident "no cards", which
 * is why this reduction and `wireGpus()` are deliberately NOT the same function —
 * on the wire `[]` is forbidden, locally it is the whole signal.
 */
export function knownGpus(state: GpuProbeState): readonly GpuDevice[] | undefined {
  if (state.certainty === "devices") return state.devices;
  return state.certainty === "none" ? [] : undefined;
}

/**
 * Probe the local NVIDIA devices.
 *
 * Returns `undefined` — meaning "unknown or none" — when the binary is missing
 * (the normal case on macOS and every GPU-less Linux box), the process exits
 * non-zero, the probe times out, the output overflows, or the output does not
 * parse in full. Callers must OMIT the `gpus` field entirely in that case; an empty
 * array would claim the same thing less clearly (see AgentRegisterMsg.gpus).
 *
 * Kept as a thin wrapper over `probeGpuState()` precisely so the wire contract
 * has ONE shape and cannot drift: everything richer is a local-only concern.
 * connection.ts calls `probeGpuState()` and reduces with `wireGpus()` instead —
 * it needs BOTH answers from ONE probe rather than a second spawn — so this is
 * the entry point for anything that only cares what goes on the wire.
 *
 * No platform branch: `nvidia-smi.exe` is on PATH wherever the Windows driver is
 * installed, and macOS simply ENOENTs.
 */
export async function probeGpus(): Promise<GpuDevice[] | undefined> {
  return wireGpus(await probeGpuState());
}

/**
 * The probe state as the WIRE wants it: devices, or nothing at all.
 *
 * The "never send `[]`" rule of AgentRegisterMsg.gpus lives here and only here,
 * so a confident "no GPUs" cannot leak onto a register frame through some second
 * caller reducing the state its own way.
 */
export function wireGpus(state: GpuProbeState): GpuDevice[] | undefined {
  return state.certainty === "devices" ? state.devices : undefined;
}

/**
 * Probe, and say how much to trust the answer.
 *
 * EXACTLY ONE path produces a CONFIDENT "none": the tool RAN, exited 0, and
 * printed nothing. That is what a working driver on a machine with zero visible
 * devices does, and it is the only observation that actually distinguishes "no
 * cards" from "we could not look".
 *
 * EVERYTHING else is `unknown`, including — deliberately — the spawn ENOENT.
 * An earlier revision read "nvidia-smi is not on PATH" as "there is no NVIDIA
 * driver, hence no usable card". That inference is wrong often enough to matter:
 * this agent is started by launchd/systemd/a service wrapper with a minimal
 * PATH (/usr/bin:/bin:/usr/sbin:/sbin on macOS), so the binary can be installed
 * and working — and libcuda perfectly able to bind a device — while THIS process
 * cannot see it. Treating that as "confidently GPU-less" made every such box
 * answer a `gpuIndex` with a hard `invalid_request` refusal, killing GPU jobs
 * that used to run fine. The reclassification knowingly TRADES COVERAGE FOR
 * HONESTY: the GPU-less-machine refusal now only fires where `nvidia-smi` exists, is
 * reachable, and reports zero cards. That is a narrower guarantee — and the only
 * one we can actually stand behind. Everywhere else we stay permissive, exactly
 * as before this feature existed.
 *
 * Also `unknown`: a non-zero exit, a timeout, stdout overflow, a stdout stream
 * error, a synchronous spawn throw (EACCES on a non-executable file, …), output
 * that came back non-empty but produced no parseable row, AND a PARTIAL parse
 * where some rows parsed and at least one did not. The last one is issue 14: an
 * incomplete list that still claimed to be authoritative would reject a real
 * GPU index whose row happened to be the one we could not read. A probe is
 * authoritative only if we understood ALL of it.
 */
export async function probeGpuState(): Promise<GpuProbeState> {
  const result = await runNvidiaSmi();
  if (result.status !== "ok") return UNKNOWN;
  if (result.stdout.trim() === "") return NONE;
  const { devices, malformed } = parseGpuRows(result.stdout);
  if (malformed > 0 || devices.length === 0) return UNKNOWN;
  return { certainty: "devices", devices };
}

/**
 * Outcome of one probe run.
 *
 * A missing binary is NOT split out from any other failure: it says nothing
 * about the hardware, only about this process's PATH (see probeGpuState).
 */
type NvidiaSmiResult = { status: "ok"; stdout: string } | { status: "failed" };

const FAILED: NvidiaSmiResult = { status: "failed" };

/**
 * Run the probe and resolve its stdout, or the reason we have none.
 *
 * `spawn` is called with an argv and NO shell, so nothing here is ever exposed to
 * shell metacharacter interpretation — there is no untrusted input on this path
 * today and this keeps it that way if one is ever added.
 */
function runNvidiaSmi(): Promise<NvidiaSmiResult> {
  return new Promise((resolve) => {
    let proc;
    try {
      proc = spawn(
        "nvidia-smi",
        [`--query-gpu=${QUERY_FIELDS}`, "--format=csv,noheader,nounits"],
        {
          // stderr is discarded outright: a driver error message is content we
          // have no use for and must not surface anywhere.
          stdio: ["ignore", "pipe", "ignore"],
          windowsHide: true,
        },
      );
    } catch {
      // Synchronous spawn rejection (EACCES on a non-executable file, and on
      // Windows a missing binary too). No code inspection: every spawn failure,
      // ENOENT included, is the same non-answer.
      resolve(FAILED);
      return;
    }

    let out = "";
    let bytes = 0;
    let overflowed = false;
    let settled = false;

    const finish = (value: NvidiaSmiResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    // Hard deadline. `proc.kill` alone is not enough — we resolve immediately
    // rather than waiting for the "close" that a wedged driver may never send.
    const timer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {
        // Already gone.
      }
      finish(FAILED);
    }, GPU_PROBE_TIMEOUT_MS);
    timer.unref?.();

    proc.stdout?.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_STDOUT_BYTES) {
        overflowed = true;
        try {
          proc.kill("SIGKILL");
        } catch {
          // Already gone.
        }
        return;
      }
      out += chunk.toString("utf8");
    });
    // A pipe error (the child died mid-write) means the bytes we hold may be a
    // TRUNCATED reading, and a truncated device list that still parses cleanly is
    // precisely the "authoritative but incomplete" answer that rejects a real GPU
    // index. So it fails the whole probe rather than being swallowed — which also
    // keeps it from becoming an unhandled 'error' event on the stream.
    proc.stdout?.on("error", () => {
      try {
        proc.kill("SIGKILL");
      } catch {
        // Already gone.
      }
      finish(FAILED);
    });

    // The asynchronous spawn failure, ENOENT (binary absent or merely off this
    // process's PATH) included: all of it is "we could not look".
    proc.on("error", () => finish(FAILED));
    proc.on("close", (code) =>
      finish(code === 0 && !overflowed ? { status: "ok", stdout: out } : FAILED),
    );
  });
}

/** What a parse produced, and how much of it we failed to understand. */
export type GpuParseResult = {
  devices: GpuDevice[];
  /** Non-blank rows we could not read. Any of these makes the probe `unknown`. */
  malformed: number;
};

/**
 * Parse `nvidia-smi --format=csv,noheader,nounits` rows.
 *
 * Defensive by construction: every row that does not have the exact shape we
 * asked for is SKIPPED rather than coerced. `[N/A]` — which nvidia-smi prints
 * for unsupported queries, notably utilization on some laptop/vGPU parts —
 * coerces to NaN and drops the row with everything else that is not a finite
 * number.
 *
 * But a skipped row is COUNTED, not silently forgotten: the caller needs to know
 * that the list it got is partial, because "these are the cards" and "these are
 * the cards whose rows I happened to understand" are different claims, and only
 * the first may be used to refuse a gpuIndex (issue 14).
 *
 * Exported for tests; `probeGpuState` is the only production caller.
 */
export function parseGpuRows(stdout: string): GpuParseResult {
  const devices: GpuDevice[] = [];
  let malformed = 0;

  for (const line of stdout.split(/\r?\n/)) {
    const row = line.trim();
    if (!row) continue;

    // Exactly the 6 requested fields (5 when the driver version is absent).
    // A different count means either a different tool or a name containing a
    // comma, which would silently shift every positional field — skip it.
    const parts = row.split(",").map((part) => part.trim());
    if (parts.length !== 6 && parts.length !== 5) {
      malformed++;
      continue;
    }

    const index = Number(parts[0]);
    const name = sanitizeText(parts[1], MAX_DEVICE_NAME_LENGTH);
    const memoryTotalMiB = Number(parts[2]);
    const memoryUsedMiB = Number(parts[3]);
    const utilizationPct = Number(parts[4]);
    if (
      !Number.isInteger(index) ||
      index < 0 ||
      !name ||
      !Number.isFinite(memoryTotalMiB) ||
      memoryTotalMiB < 0 ||
      !Number.isFinite(memoryUsedMiB) ||
      memoryUsedMiB < 0 ||
      !Number.isFinite(utilizationPct) ||
      utilizationPct < 0
    ) {
      malformed++;
      continue;
    }

    const driverVersion = sanitizeText(parts[5], MAX_DRIVER_LENGTH);
    devices.push({
      index,
      name,
      memoryTotalMiB,
      memoryUsedMiB,
      utilizationPct,
      // Optional on the wire: omitted rather than sent empty when the driver
      // version is missing or unusable.
      ...(driverVersion ? { driverVersion } : {}),
    });
  }

  return { devices, malformed };
}

/**
 * Keep only printable, bounded text. Device names come from the driver, so this
 * is not a trust boundary — but they end up in relay-stored metadata and in an
 * LLM's context, and control characters have no business in either.
 */
function sanitizeText(value: string | undefined, maxLength: number): string {
  if (!value) return "";
  // eslint-disable-next-line no-control-regex
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (!cleaned || cleaned === "[N/A]" || cleaned === "N/A") return "";
  return cleaned.slice(0, maxLength);
}
