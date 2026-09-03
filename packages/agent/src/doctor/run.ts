import { resolveTrustedServerUrl } from "../relay-url.js";
import { AGENT_VERSION } from "../version.js";
import { antivirusProbeChecks } from "./checks/av-probe.js";
import { connectivityChecks } from "./checks/connectivity.js";
import { environmentChecks } from "./checks/environment.js";
import { installChecks } from "./checks/install.js";
import { persistenceChecks } from "./checks/persistence.js";
import { privHelperChecks } from "./checks/priv-helper.js";
import { storageChecks } from "./checks/storage.js";
import {
  errorText,
  fail,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorOptions,
  type DoctorReport,
  type DoctorSummary,
} from "./types.js";

/**
 * The runner: turns the check library into one report.
 *
 * ── ORDER, AND WHY IT IS SEQUENTIAL ──────────────────────────────────────────
 * The groups run one after another, not in parallel. Two reasons, and neither is
 * caution for its own sake. The install write probe and the antivirus probe both
 * measure a filesystem that the other one is writing to, and a scanner's
 * response to one would land inside the other's timing window — a report in
 * which "the write was refused" cannot be attributed to a cause is worth less
 * than one that took four seconds longer. And a diagnostic's output is read by
 * people: a stable order is what lets two runs be diffed.
 *
 * The order itself is the order of the incident: what is installed, whether
 * something is eating it, whether we can reach the relay, whether we start at
 * boot, whether the privileged half exists, where the credentials and the log
 * are, and what the machine looks like.
 *
 * ── ONE FAILING CHECK CANNOT SILENCE THE OTHERS ──────────────────────────────
 * Every group is wrapped: a group that throws becomes one `fail` result naming
 * the group and the error, and the run continues. A doctor that dies on its
 * third check is worse than no doctor, because the user has already concluded
 * the product cannot describe itself — which is the finding this whole effort
 * came from.
 */

/** In the order they run and in the order they print. */
export const DOCTOR_GROUPS: DoctorCheckGroup[] = [
  installChecks,
  antivirusProbeChecks,
  connectivityChecks,
  persistenceChecks,
  privHelperChecks,
  storageChecks,
  environmentChecks,
];

const DEFAULT_NETWORK_TIMEOUT_MS = 10_000;
/**
 * How long the antivirus probe waits before reading its scripts back.
 *
 * An on-access engine acts on its own schedule and quarantine is not part of our
 * write returning; job-manager's real read-back happens with no deliberate pause
 * because it is on a hot path and cannot afford one. The doctor can, and a
 * quarter of a second is comfortably inside what a scanner takes to act on a
 * freshly created `.cmd` while being invisible to the user.
 */
const DEFAULT_PROBE_DELAY_MS = 250;

export function resolveDoctorContext(opts: DoctorOptions = {}): DoctorContext {
  return {
    ...(opts.resourcesPath ? { resourcesPath: opts.resourcesPath } : {}),
    ...(opts.configDir ? { configDir: opts.configDir } : {}),
    ...(opts.tokenVault ? { tokenVault: opts.tokenVault } : {}),
    // Through the host-lock, exactly like the agent itself — and the OPTION goes
    // through it too, not only the env var. The ticket leg POSTs this machine's
    // stored agent token to whatever this resolves to, so an in-process caller
    // passing `serverUrl` would otherwise be a way to hand a root agent's
    // credential to an arbitrary origin. `resolveTrustedServerUrl` never throws:
    // an untrusted or malformed value falls back to the canonical relay, loudly
    // (see relay-url.ts), which is also what makes loopback dev targets work.
    serverUrl: resolveTrustedServerUrl(opts.serverUrl ?? process.env["AICOMMANDER_SERVER"]),
    offline: opts.offline ?? false,
    networkTimeoutMs: opts.networkTimeoutMs ?? DEFAULT_NETWORK_TIMEOUT_MS,
    probeDelayMs: opts.probeDelayMs ?? DEFAULT_PROBE_DELAY_MS,
  };
}

function summarize(checks: CheckResult[]): DoctorSummary {
  const summary: DoctorSummary = { ok: 0, warn: 0, fail: 0, skipped: 0 };
  for (const check of checks) summary[check.verdict]++;
  return summary;
}

export async function runDoctor(opts: DoctorOptions = {}): Promise<DoctorReport> {
  const ctx = resolveDoctorContext(opts);
  const checks: CheckResult[] = [];

  for (const group of DOCTOR_GROUPS) {
    try {
      checks.push(...(await group.run(ctx)));
    } catch (err) {
      checks.push(
        fail(
          group.id,
          group.title,
          `this check could not be completed: ${errorText(err)}`,
          "This is a fault in the diagnostic itself, not necessarily in the machine. The other checks still ran.",
        ),
      );
    }
  }

  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  return {
    schema: 1,
    generatedAt: new Date().toISOString(),
    agentVersion: AGENT_VERSION,
    platform: process.platform,
    arch: process.arch,
    node: process.versions.node,
    elevated: uid === null ? "unknown" : uid === 0,
    redacted: false,
    checks,
    summary: summarize(checks),
  };
}
