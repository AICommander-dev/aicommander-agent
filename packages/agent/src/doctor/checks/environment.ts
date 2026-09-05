import fs from "node:fs";
import path from "node:path";
import { doctorJobsRoot, NO_JOBS_ROOT_REASON } from "./paths.js";
import { pathPresence } from "./presence.js";
import {
  errorText,
  ok,
  skipped,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorFactValue,
  type DoctorFacts,
} from "../types.js";

/**
 * The two environmental causes that look exactly like the interesting ones.
 *
 * A full disk and a proxy variable each produce "jobs fail" and "the machine is
 * offline" — the same sentences an antivirus incident produces — and each has a
 * completely different fix. Ruling them out cheaply is what keeps the rest of
 * this report worth reading. (Clock skew is the third; it lives with the
 * connectivity checks because it is measured against the relay's own Date
 * header, which those already have in hand.)
 */

/** Below this much free space, a job's logs and workspaces start failing. */
const LOW_DISK_BYTES = 1024 * 1024 * 1024;

/**
 * Every environment variable that a user, an IT policy or an installer might
 * set expecting it to route our traffic. Both cases, because Windows preserves
 * the case an operator typed and POSIX tools disagree about which is canonical.
 */
const PROXY_VARS = [
  "HTTP_PROXY",
  "http_proxy",
  "HTTPS_PROXY",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "NO_PROXY",
  "no_proxy",
  "NODE_EXTRA_CA_CERTS",
];

/**
 * A proxy URL with its credentials taken out.
 *
 * `http://user:hunter2@proxy.corp:8080` is a real and common shape, and this
 * value goes into a file that is emailed to antivirus vendors. The host and the
 * port are the diagnostic; the password is somebody's corporate credential.
 * Falls back to a blanket redaction for anything that does not parse, because a
 * value we could not understand is a value we cannot promise to have cleaned.
 */
export function redactProxyValue(value: string): string {
  try {
    const url = new URL(value);
    if (url.username || url.password) {
      url.username = "";
      url.password = "";
      return `${url.toString()} (credentials removed)`;
    }
    return url.toString();
  } catch {
    return /[:@]/.test(value) ? "[redacted — unparseable, may contain credentials]" : value;
  }
}

/** Which volume `statfs` should be asked about — or why it may not be asked. */
type VolumeTarget =
  | { kind: "path"; path: string }
  | { kind: "none" }
  | { kind: "unknown"; path: string; error: string; code: string | null };

/**
 * The nearest ancestor of `target` that exists, so statfs has something to
 * answer about — and NOTHING when we could not find out.
 *
 * This walked up on ANY `stat` error, which folds "it is not there" into
 * "I could not look". On a machine whose filter driver denies the jobs
 * directory — the exact machine this whole feature set exists for — an EACCES
 * was read as an absence, and `statfs` then measured the PARENT's filesystem and
 * reported it as the volume holding the jobs directory: a confident `ok` about a
 * volume nobody asked about. Same class of mistake as `stat().catch(() => null)`,
 * which is why absence is not decided here at all: `pathPresence` decides it, in
 * one place, as ENOENT/ENOTDIR and nothing else, and an unknown gets its own
 * verdict at the call site.
 *
 * ASYNCHRONOUS, like every filesystem call under `doctor/checks/`. The tray runs
 * this same library on Electron's main loop (desktop/src/diagnostics.ts), and a
 * synchronous stat there blocks the loop for as long as a filter driver sits on
 * it — starving the relay heartbeat into the "Reconnecting…" state the user
 * opened diagnostics to investigate.
 */
async function volumeTarget(target: string): Promise<VolumeTarget> {
  let current = path.resolve(target);
  for (let i = 0; i < 64; i++) {
    const presence = await pathPresence(current);
    if (presence.kind === "present") return { kind: "path", path: current };
    if (presence.kind === "unknown") {
      return { kind: "unknown", path: current, error: presence.error, code: presence.code };
    }
    const parent = path.dirname(current);
    if (parent === current) return { kind: "none" };
    current = parent;
  }
  return { kind: "none" };
}

async function checkDisk(ctx: DoctorContext): Promise<CheckResult> {
  const id = "env.disk";
  const title = "Disk space";
  const jobsRoot = doctorJobsRoot(ctx.configDir);
  if (!jobsRoot) return skipped(id, title, NO_JOBS_ROOT_REASON);
  const located = await volumeTarget(jobsRoot);
  if (located.kind === "none") {
    return skipped(id, title, `neither ${jobsRoot} nor any of its parents exists.`);
  }
  if (located.kind === "unknown") {
    // "Could not check" is its own verdict. Walking past an unreadable directory
    // would measure whichever volume the parent happens to sit on and present it
    // as this one — and on a machine where a filter driver denies the jobs
    // directory, that is the reassuring answer given at the worst moment.
    return skipped(
      id,
      title,
      `${located.path} could not be examined (${located.error}), so the volume holding the jobs directory ` +
        "could not be identified — and measuring its parent's volume instead would report free space for " +
        "somewhere else.",
      { path: located.path, ...(located.code ? { code: located.code } : {}) },
    );
  }
  const target = located.path;

  try {
    const stats = await fs.promises.statfs(target);
    const free = stats.bavail * stats.bsize;
    const total = stats.blocks * stats.bsize;
    const freeMiB = Math.round(free / (1024 * 1024));
    const percent = total > 0 ? Math.round((free / total) * 100) : 0;
    const facts: DoctorFacts = { path: target, freeBytes: free, totalBytes: total, freePercent: percent };
    return free >= LOW_DISK_BYTES
      ? ok(id, title, `${freeMiB} MiB free (${percent}%) on the volume holding the jobs directory.`, facts)
      : warn(
          id,
          title,
          `only ${freeMiB} MiB free (${percent}%) on the volume holding the jobs directory.`,
          "Job logs, workspaces and the diagnostic log all live here. A full volume fails jobs in ways that " +
            "look like something else entirely.",
          facts,
        );
  } catch (err) {
    return skipped(id, title, `the free space of ${target} could not be read (${errorText(err)}).`);
  }
}

/**
 * Proxy variables, and the thing about them nobody expects.
 *
 * Node's built-in `fetch` (undici) does NOT honour HTTP_PROXY / HTTPS_PROXY, and
 * neither does the `ws` client. So a machine whose only route out is a proxy has
 * those variables set, every other tool on the box works, and the agent alone
 * cannot reach the relay — which presents as "offline for no reason", the exact
 * complaint this command exists to answer. Their presence is therefore reported
 * as a WARNING even though nothing about them is malformed: it is a warning
 * about us, not about them.
 */
function checkProxy(): CheckResult {
  const id = "env.proxy";
  const title = "Proxy environment";
  const facts: DoctorFacts = {};
  const set: string[] = [];
  for (const name of PROXY_VARS) {
    const value = process.env[name];
    if (!value) continue;
    set.push(name);
    facts[name] = name === "NODE_EXTRA_CA_CERTS" ? value : redactProxyValue(value);
  }
  if (set.length === 0) return ok(id, title, "no proxy variables are set in this process's environment.");
  const proxying = set.filter((name) => /proxy/i.test(name) && !/^no_proxy$/i.test(name));
  if (proxying.length === 0) {
    return ok(id, title, `${set.join(", ")} set, but nothing that routes traffic through a proxy.`, facts);
  }
  return warn(
    id,
    title,
    `${proxying.join(", ")} set in this process's environment.`,
    "The agent's HTTPS and WebSocket clients do NOT honour these variables. If this machine can only reach the " +
      "internet through that proxy, the agent cannot reach the relay at all — which looks exactly like being " +
      "offline for no reason. Allow direct outbound HTTPS to the relay host.",
    facts,
  );
}

/**
 * The ORIGIN of a URL an operator set, and nothing else.
 *
 * `AICOMMANDER_SERVER` is a value we did not write, and it goes into a file that
 * is emailed to antivirus vendors: `https://user:token@relay.example/x?k=v` is a
 * perfectly ordinary thing to find in an env var and every part of it except the
 * origin is either a credential or somebody's private path. What the report
 * needs from it is the one question a support engineer asks — "was this machine
 * pointed somewhere other than the canonical relay?" — which the origin answers
 * in full. Anything that does not parse is named as such rather than printed.
 */
function serverOverrideFact(): DoctorFactValue {
  const raw = process.env["AICOMMANDER_SERVER"]?.trim();
  if (!raw) return null;
  try {
    return new URL(raw).origin;
  } catch {
    return "[set, and not a parseable URL]";
  }
}

/** Bare facts about the process, so a report answers "what were we even running" without being asked. */
function checkRuntime(ctx: DoctorContext): CheckResult {
  const id = "env.runtime";
  const title = "Runtime";
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  return ok(
    id,
    title,
    `${process.platform}/${process.arch} on Node ${process.versions.node}.`,
    {
      // `execPath` is OUR binary and is the diagnostic (an npm agent under node,
      // a packaged tray, a copy running from a stale directory). The working
      // directory is NOT: it is whatever shell or service launched us happened
      // to be sitting in, it answers no question this report asks, and it is an
      // arbitrary customer path the generic redactor has no rule for. See the
      // fact contract in types.ts.
      execPath: process.execPath,
      // Windows has no cheap non-blocking elevation query; "unknown" is honest
      // and a guess is not (same rule as diag-log.ts's logStartup).
      elevated: uid === null ? "unknown" : uid === 0,
      configDirOverride: process.env["AICOMMANDER_CONFIG_DIR"] ?? null,
      serverOverride: serverOverrideFact(),
      // What the host-lock actually resolved that to, which is the relay every
      // network leg below was measured against.
      server: ctx.serverUrl,
    },
  );
}

export const environmentChecks: DoctorCheckGroup = {
  id: "env",
  title: "Environment",
  async run(ctx) {
    return [checkRuntime(ctx), await checkDisk(ctx), checkProxy()];
  },
};
