import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

/**
 * What is INSTALLED on disk, as opposed to what is RUNNING.
 *
 * `AGENT_VERSION` is compiled into the running process, so it answers "which
 * build is serving this relay connection" and nothing else. On macOS that is not
 * the same question as "which build is installed": the pkg upgrade swaps
 * /Applications/AI Commander.app under a LIVE tray, and if the old process
 * survives the swap (measured on 2026-08-27, upgrading 1.0.56 → 1.1.0 on two
 * Macs — one process died and came back new, the other did not) it keeps serving
 * commands, keeps advertising 1.0.56, and nothing anywhere says the disk has
 * moved on. The machine then looks like an upgrade that never happened; the tray
 * recovery script even logs success, because a tray IS running.
 *
 * So the agent reports both numbers and lets the relay say the rest.
 *
 * Four properties, in the same spirit as gpu.ts:
 *  - it must NEVER throw — it runs on the registration path;
 *  - it must NEVER hold up a connect. The probe is started before the WebSocket
 *    is opened and read synchronously when the register frame is built; if it has
 *    not finished, the field carries whatever the last finished probe said (or is
 *    simply absent, when none has finished yet);
 *  - it must be RE-READ on every connect. The disk changing under a surviving
 *    process is the ENTIRE point of this file, and that swap happens long after
 *    the first probe — a value memoized for the process lifetime would re-register
 *    the pre-upgrade number forever and prove the machine healthy;
 *  - it must NEVER report a value it is not sure of. Every failure mode — no
 *    bundle, a bundle that is not ours, unreadable plist, a JS runtime instead of
 *    our binary, output that does not look like a version — collapses to
 *    `undefined`, which the wire format defines as "unknown", never as "same as
 *    running".
 */

/** How long the (spawning) Windows/Linux probes get before they are abandoned. */
export const INSTALLED_VERSION_TIMEOUT_MS = 5_000;

/** An Info.plist bigger than this is not an Info.plist we want to scan. */
const MAX_PLIST_BYTES = 512 * 1024;

/** Ceiling on a version probe's stdout; a real answer is a few dozen bytes. */
const MAX_PROBE_OUTPUT_BYTES = 8 * 1024;

/** Runtimes that mean "the executable is not us" (the npm install shape). */
const JS_RUNTIMES = new Set(["node", "bun", "deno"]);

/**
 * The bundle identifier the installer stamps on OUR app. Only a bundle carrying
 * it may report a version: without the check, a dev run under
 * `packages/desktop/node_modules/electron/dist/Electron.app` would report
 * Electron's own CFBundleShortVersionString (39.8.10) as the installed build and
 * every developer machine would show a permanent "an update landed and the app
 * was never restarted" that no restart can clear.
 */
const MAC_BUNDLE_ID = "dev.aicommander.desktop";

/**
 * What we are willing to call a version. Deliberately narrow: a probe that
 * printed a banner, a path, or an error must fail the check rather than be
 * reported as the installed build, because the ONLY use of this value is to be
 * compared against the running one and shown as a mismatch.
 */
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]{1,32})?$/;

/**
 * Normalize a probed version, or reject it.
 *
 * A leading `v` is stripped (`node --version` shape, and some `--version`
 * outputs) and a FOURTH component equal to zero is dropped: Windows version
 * resources are four-part by construction, so electron-builder's "1.1.0" is read
 * back as "1.1.0.0" and comparing it verbatim against the running "1.1.0" would
 * report a mismatch on every healthy Windows machine. A non-zero fourth
 * component is kept as-is — that one is a real difference we should not hide.
 */
export function sanitizeInstalledVersion(raw: string): string | undefined {
  const value = raw.trim().replace(/^v/, "");
  if (!VERSION_PATTERN.test(value)) return undefined;
  return value.replace(/^(\d+\.\d+\.\d+)\.0$/, "$1");
}

/**
 * True when `execPath` is a JS runtime rather than one of our own binaries.
 *
 * Splits on BOTH separators instead of `path.basename`, which on a POSIX host
 * (where the tests run) would take `C:\...\node.exe` for one long filename.
 */
export function isJsRuntimeExecutable(execPath: string): boolean {
  const base = execPath.split(/[\\/]/).pop() ?? "";
  return JS_RUNTIMES.has(base.replace(/\.exe$/i, "").toLowerCase());
}

/**
 * Every .app bundle `execPath` sits inside, innermost first — the Info.plist path
 * of each, not the bundle directory.
 *
 * Walks UP from the executable rather than assuming
 * `<bundle>/Contents/MacOS/<exe>` (helpers and login items sit at other depths),
 * and returns the WHOLE chain rather than the nearest match, because the nearest
 * `.app` is not necessarily ours: a helper bundle nested in our app is not, and
 * neither is `node_modules/electron/dist/Electron.app` under `pnpm dev`. The
 * caller picks the bundle whose identifier says it is the one the installer
 * wrote; an executable in no bundle at all yields an empty list.
 */
export function macBundleInfoPlistPaths(execPath: string): string[] {
  const found: string[] = [];
  let dir = path.dirname(execPath);
  for (let depth = 0; depth < 12; depth++) {
    if (dir.endsWith(".app")) found.push(path.join(dir, "Contents", "Info.plist"));
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return found;
}

/**
 * Pull CFBundleShortVersionString out of an XML Info.plist.
 *
 * Text scan, not a plist parser: Electron/electron-builder bundles ship the XML
 * form, and a BINARY plist (or anything else unexpected) simply fails the match
 * and leaves the field absent — which is the correct outcome for "we could not
 * tell", and a great deal safer than shelling out to `defaults read` on the
 * registration path.
 */
export function parseBundleShortVersion(plist: string): string | undefined {
  const match = /<key>CFBundleShortVersionString<\/key>\s*<string>([^<]{1,64})<\/string>/.exec(plist);
  return match ? sanitizeInstalledVersion(match[1]!) : undefined;
}

/** The same text scan, for CFBundleIdentifier — "is this bundle ours at all". */
export function parseBundleIdentifier(plist: string): string | undefined {
  const match = /<key>CFBundleIdentifier<\/key>\s*<string>([^<]{1,128})<\/string>/.exec(plist);
  return match ? match[1]!.trim() : undefined;
}

/**
 * macOS: OUR bundle's own version, read straight off disk. Never throws.
 *
 * Reports a version only for a bundle whose CFBundleIdentifier is
 * `MAC_BUNDLE_ID`; anything else — a nested helper, Electron's dist bundle under
 * a dev checkout, a binary in no bundle — is "unknown".
 */
export function probeMacInstalledVersion(execPath: string): string | undefined {
  for (const plistPath of macBundleInfoPlistPaths(execPath)) {
    try {
      if (fs.statSync(plistPath).size > MAX_PLIST_BYTES) continue;
      const plist = fs.readFileSync(plistPath, "utf8");
      if (parseBundleIdentifier(plist) !== MAC_BUNDLE_ID) continue;
      return parseBundleShortVersion(plist);
    } catch {
      // Missing bundle, unreadable file, a path we have no business reading —
      // all of it means "keep looking, then unknown", none of it means "broken".
      continue;
    }
  }
  return undefined;
}

/**
 * Run a command and hand back its stdout, or "" for any failure at all.
 *
 * The collapse is DELIBERATE here and only here: a version probe that timed out,
 * exited non-zero or printed half a line has not told us which build is
 * installed, and a partial answer is a wrong answer — `undefined` ("unknown") is
 * the only safe outcome. Anything that has to tell "it answered no" from "it
 * could not answer" uses capture.ts's tri-state instead; the scheduled-task
 * query used to bend this function with a `keepPartialOutput` flag and now does
 * exactly that.
 *
 * Exported for tests; the two spawning probes below are the production callers.
 */
export function runCapture(command: string, args: string[]): Promise<string> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, { stdio: ["ignore", "pipe", "ignore"] });
    } catch {
      resolve("");
      return;
    }
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const finish = (value: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const captured = (): string => Buffer.concat(chunks).toString("utf8");
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
      finish("");
    }, INSTALLED_VERSION_TIMEOUT_MS);
    timer.unref?.();
    child.stdout?.on("data", (chunk: Buffer) => {
      if (bytes > MAX_PROBE_OUTPUT_BYTES) return;
      bytes += chunk.length;
      chunks.push(Buffer.from(chunk));
    });
    child.on("error", () => finish(""));
    child.on("close", (code) => {
      finish(code === 0 ? captured() : "");
    });
  });
}

/**
 * Quote a value for PowerShell as a LITERAL single-quoted string.
 *
 * `JSON.stringify` is not a PowerShell quoter and must not be used here: inside a
 * double-quoted PowerShell string a backslash is not an escape (so JSON's doubled
 * backslashes arrive doubled and the path does not exist), while `$` and the
 * backtick ARE special — an install path containing `$(...)` would be EVALUATED.
 * In a single-quoted string nothing is special except the quote itself, which is
 * escaped by doubling.
 */
export function powerShellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * Windows: the ProductVersion recorded in the installed exe's version resource —
 * what electron-builder stamps with the app version, and what the installer
 * updates when it replaces the file.
 *
 * Skipped for the npm install shape, exactly like the Linux probe: on
 * `npx @aicommander/agent` the executable is `node.exe`, whose ProductVersion
 * ("22.11.0") is a perfectly well-formed version and would be published as a
 * permanent, unfixable mismatch telling the user to restart an app that is not
 * the problem.
 */
export async function probeWindowsInstalledVersion(execPath: string): Promise<string | undefined> {
  if (isJsRuntimeExecutable(execPath)) return undefined;
  const script =
    "$ErrorActionPreference='Stop';" +
    `[System.Diagnostics.FileVersionInfo]::GetVersionInfo(${powerShellSingleQuote(execPath)}).ProductVersion`;
  const out = await runCapture("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script,
  ]);
  return sanitizeInstalledVersion(out.split(/\r?\n/)[0] ?? "");
}

/**
 * Linux/headless: ask the binary ON DISK what it is — the same question
 * self-update asks after an install, and for the same reason.
 *
 * Skipped for the npm install shape (the executable is a JS runtime, so its
 * `--version` describes node, not us) — reporting `22.11.0` as the installed
 * agent build would be worse than reporting nothing.
 */
export async function probeBinaryInstalledVersion(execPath: string): Promise<string | undefined> {
  if (isJsRuntimeExecutable(execPath)) return undefined;
  const out = await runCapture(execPath, ["--version"]);
  return sanitizeInstalledVersion(out.split(/\r?\n/)[0] ?? "");
}

/** The last FINISHED probe's answer; `undefined` also means "nothing known yet". */
let value: string | undefined;
/**
 * Which probe is allowed to publish its answer. Bumped by every start, so a slow
 * probe from a previous connect can never overwrite a newer one's result — the
 * register frame must carry the freshest reading of the disk, not the last one to
 * come back.
 */
let generation = 0;

/**
 * Start a FRESH on-disk version probe — once per connect, like the GPU probe.
 *
 * Deliberately not memoized. The scenario this whole file exists for is the disk
 * changing under a process that keeps running, so a value read once at the first
 * connect is precisely the value we must not keep re-registering; every reconnect
 * re-reads and a changed answer replaces the old one.
 *
 * The connect never waits on this and never fails because of it: the returned
 * promise is not awaited by the caller, it cannot reject, and the register frame
 * takes whatever `installedVersionSnapshot()` has at the moment it is built. Until
 * a probe on THIS connect finishes, that is the previous connect's answer — stale
 * by at most one reconnect, and strictly better than dropping the field.
 *
 * macOS resolves SYNCHRONOUSLY — it is one file read, and it is the platform the
 * stale-process problem actually happens on, so the register frame that is built
 * milliseconds later must not miss it.
 */
export function startInstalledVersionProbe(): Promise<string | undefined> {
  const mine = ++generation;
  const publish = (probed: string | undefined): string | undefined => {
    // A probe superseded by a newer one keeps its answer to itself.
    if (mine === generation) value = probed;
    return probed;
  };
  if (process.platform === "darwin") {
    return Promise.resolve(publish(probeMacInstalledVersion(process.execPath)));
  }
  const run =
    process.platform === "win32"
      ? probeWindowsInstalledVersion(process.execPath)
      : probeBinaryInstalledVersion(process.execPath);
  return run.catch(() => undefined).then(publish);
}

/**
 * The probed on-disk version for the register frame, or undefined when we do not
 * know one (no probe has finished, or the last one finished with nothing).
 * Synchronous by design: the register frame is built inside the socket's `open`
 * handler and may not wait on anything.
 */
export function installedVersionSnapshot(): string | undefined {
  return value;
}

/** Test helper: forget what the last probe learned. */
export function resetInstalledVersionForTest(): void {
  value = undefined;
  generation++;
}
