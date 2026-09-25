/**
 * The privileged helper's own `doctor` verb (PLAN-av-hardening W2.3).
 *
 * Two things are worth testing here and one of them is unusual: that the verb
 * reports the incident's central fact ("80 of 81 files are gone") from OUTSIDE
 * the directory that was gutted, and that it is HONEST about being a smaller
 * check set than `aicommander-agent doctor` — a clean run from this binary must
 * never be mistakable for a clean bill of health for the whole product.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

import type { ElevatedEndpoint } from "../endpoint.js";
import { encodeFrame, IPC_PROTOCOL_VERSION } from "../protocol.js";
import {
  UNCHECKED_HERE,
  helperDoctorExitCode,
  renderHelperDoctor,
  runHelperDoctor,
  type HelperCheck,
} from "../doctor.js";
import { HELPER_VERSION } from "../version.js";
import type { InstallSignals } from "../win-watchdog.js";
import type { ProbeResult } from "../win-watchdog.js";
import type { InstallScan, InstallScanResult } from "../install-scan.js";

let originalPlatform: PropertyDescriptor | undefined;

function setPlatform(value: string): void {
  originalPlatform ??= Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value, writable: true, configurable: true });
}

afterEach(() => {
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  originalPlatform = undefined;
});

function snapshotWith(install: Partial<InstallSignals>): ProbeResult {
  return {
    ok: true,
    snapshot: {
      sessions: [],
      trayOwnerSids: [],
      skippedSessions: 0,
      unverifiedTrayProcesses: 0,
      unverifiedSessionShells: 0,
      install: {
        updateTaskRunning: false,
        msSinceInstallDirChange: null,
        trayExeInstalled: true,
        manifest: null,
        ...install,
      },
    },
  };
}

/**
 * A socket path nothing is listening on — so `helper.endpoint` reports "nothing
 * answered" deterministically instead of talking to the HOST.
 *
 * THE REGRESSION THIS CLOSES: `run` injected the probe and the scan and left
 * `endpoints` alone, so every case below connected to the developer's real
 * helper socket (or, on Windows, to the real loopback pool). The suite's
 * behaviour then depended on whether a helper happened to be installed on the
 * machine running it, which is the one thing a test may never depend on.
 */
const NOWHERE: ElevatedEndpoint = {
  transport: "unix",
  path: path.join(tmpdir(), "aic-helper-doctor-nothing-here.sock"),
};

/** Every run in this suite injects the probe; nothing here talks to the host. */
function run(
  probe: () => Promise<ProbeResult>,
  scan: () => Promise<InstallScanResult> = async () => ({ ok: false, reason: "no-manifest-found" }),
): Promise<HelperCheck[]> {
  return runHelperDoctor({
    probe,
    scan,
    endpointTimeoutMs: 25,
    endpoints: [NOWHERE],
    // Likewise the marker: unset, this read a real path under
    // %ProgramFiles% / /Library and reported on the developer's machine.
    markerPath: null,
  });
}

/** The probe answer a NON-ADMINISTRATOR gets: the Relaunch task is not readable. */
const DENIED_PROBE = async () => ({ ok: false, reason: "query-relaunch-task" }) as ProbeResult;

const scanned = (over: Partial<InstallScan> = {}): (() => Promise<InstallScanResult>) => {
  const scan: InstallScan = {
    root: "C:\\Program Files\\AICommander",
    totalFiles: 81,
    missingFiles: 0,
    missingCritical: 0,
    unreadableFiles: 0,
    version: "1.1.0",
    source: "install",
    ...over,
  };
  return async () => ({ ok: true, scan });
};

function byId(checks: HelperCheck[], id: string): HelperCheck {
  const found = checks.find((c) => c.id === id);
  if (!found) throw new Error(`no check ${id} in ${checks.map((c) => c.id).join(", ")}`);
  return found;
}

describe("runHelperDoctor — the check set it ships", () => {
  it("runs exactly the documented checks, in a stable order", async () => {
    const checks = await run(async () => snapshotWith({}));
    expect(checks.map((c) => c.id)).toEqual([
      "helper.binary",
      "helper.marker",
      "helper.registration",
      "helper.endpoint",
      "app.install",
      "watchdog.log",
    ]);
  });

  it("names what it does NOT check, rather than shipping a narrower set silently", async () => {
    const text = renderHelperDoctor(await run(async () => snapshotWith({})));
    expect(text).toContain("REDUCED check set");
    for (const gap of UNCHECKED_HERE) expect(text).toContain(gap);
    // The full set, and where to get it.
    expect(text).toContain("aicommander-agent doctor");
    expect(text).toContain("Run Diagnostics…");
  });

  it("checks none of the per-user things the agent's doctor checks", () => {
    // Stated as ids so the gap is asserted, not assumed: relay connectivity, the
    // antivirus write probe, the session/config store and the environment group
    // all belong to ONE USER'S session, and this binary may be running as SYSTEM.
    const joined = UNCHECKED_HERE.join(" ").toLowerCase();
    expect(joined).toContain("relay");
    expect(joined).toContain("antivirus");
    expect(joined).toContain("autostart");
  });

  it("survives a check that throws instead of dying on it", async () => {
    setPlatform("win32");
    const checks = await run(async () => {
      throw new Error("CIM exploded");
    });
    const faulted = byId(checks, "doctor.error");
    expect(faulted.verdict).toBe("fail");
    expect(faulted.detail).toContain("CIM exploded");
    // The checks after the fault still ran.
    expect(checks.map((c) => c.id)).toContain("watchdog.log");
  });
});

describe("app.install — the incident question, answered from outside $INSTDIR", () => {
  it("calls a gutted install a failure and names security software", async () => {
    setPlatform("win32");
    const checks = await run(async () =>
      snapshotWith({
        trayExeInstalled: false,
        manifest: {
          totalFiles: 81,
          missingFiles: 80,
          missingCritical: 12,
          unreadableFiles: 0,
          version: "1.1.0",
          source: "install",
        },
      }),
    );
    const install = byId(checks, "app.install");
    expect(install.verdict).toBe("fail");
    expect(install.detail).toContain("80 of 81");
    expect(install.remedy).toContain("antivirus");
    expect(helperDoctorExitCode(checks)).toBe(1);
  });

  it("does not raise an alarm for non-critical files (a pruned locale pack)", async () => {
    setPlatform("win32");
    const checks = await run(async () =>
      snapshotWith({
        manifest: {
          totalFiles: 81,
          missingFiles: 2,
          missingCritical: 0,
          unreadableFiles: 0,
          version: "1.1.0",
          source: "install",
        },
      }),
    );
    expect(byId(checks, "app.install").verdict).toBe("warn");
  });

  it("reports a complete install as complete", async () => {
    setPlatform("win32");
    const checks = await run(async () =>
      snapshotWith({
        manifest: {
          totalFiles: 81,
          missingFiles: 0,
          missingCritical: 0,
          unreadableFiles: 0,
          version: "1.1.0",
          source: "install",
        },
      }),
    );
    expect(byId(checks, "app.install").verdict).toBe("ok");
  });

  it("treats a probe that could not run as no evidence, never as damage", async () => {
    setPlatform("win32");
    const checks = await run(async () => ({ ok: false, reason: "timeout" }) as ProbeResult);
    const install = byId(checks, "app.install");
    expect(install.verdict).toBe("warn");
    expect(install.detail).toContain("timeout");
  });

  it("still answers the incident question for a NON-ADMINISTRATOR", async () => {
    // The path this whole binary exists for: the Start Menu shortcut the
    // installer creates launches unelevated, and the Relaunch task the probe
    // reads is admin-only — so the probe cannot answer. Falling back to
    // "Windows could not be queried" made the one check that matters useless to
    // the only user likely to run it.
    setPlatform("win32");
    const checks = await run(DENIED_PROBE, scanned({ missingFiles: 80, missingCritical: 12 }));
    const install = byId(checks, "app.install");
    expect(install.verdict).toBe("fail");
    expect(install.detail).toContain("80 of 81");
    expect(install.remedy).toContain("antivirus");
    // ...and it says where the number came from, and that the folder was not
    // confirmed against Windows. A count is worth what the reader knows about it.
    expect(install.detail).toContain("C:\\Program Files\\AICommander");
    expect(install.detail).toContain("query-relaunch-task");
  });

  it("reports a healthy install from the unelevated path too", async () => {
    setPlatform("win32");
    const install = byId(await run(DENIED_PROBE, scanned()), "app.install");
    expect(install.verdict).toBe("ok");
    expect(install.detail).toContain("all 81 shipped files are present");
  });

  it("never turns files it could not READ into files that are missing", async () => {
    setPlatform("win32");
    const install = byId(
      await run(DENIED_PROBE, scanned({ unreadableFiles: 81 })),
      "app.install",
    );
    expect(install.verdict).toBe("ok");
    expect(install.detail).toContain("could not be read");
  });

  it("counts nothing, and accuses nobody, when it cannot find the install either", async () => {
    setPlatform("win32");
    const install = byId(await run(DENIED_PROBE), "app.install");
    expect(install.verdict).toBe("warn");
    expect(install.detail).toContain("nothing was counted");
  });

  it("names the limitation instead of leaving a bare 'not confirmed'", async () => {
    // A `/D=` custom install directory is not derivable from this binary's own
    // path, and the probe that CAN read the real one off the Relaunch task needs
    // administrative rights. Saying only "not confirmed" leaves the reader to
    // guess whether their app is gone; the sentence has to say what was looked
    // at and why the rest was out of reach.
    setPlatform("win32");
    const install = byId(
      await run(DENIED_PROBE, async () => ({
        ok: false,
        reason: "no-manifest-found",
        triedRoots: ["C:\\Program Files\\AICommander", "C:\\Program Files\\AI Commander"],
      })),
      "app.install",
    );
    expect(install.verdict).toBe("warn");
    expect(install.detail).toContain("C:\\Program Files\\AICommander");
    expect(install.detail).toContain("Only the default install locations");
    expect(install.remedy).toContain("administrator");
  });

  it("calls an EMPTY manifest a damaged manifest, never a complete install", async () => {
    // "all 0 shipped files are present" is the healthiest-looking sentence this
    // verb could print about a wrecked machine. Both paths to it are closed:
    // the elevated probe...
    setPlatform("win32");
    const elevated = byId(
      await run(async () =>
        snapshotWith({
          manifest: {
            totalFiles: 0,
            missingFiles: 0,
            missingCritical: 0,
            unreadableFiles: 0,
            version: "1.1.0",
            source: "install",
          },
        }),
      ),
      "app.install",
    );
    expect(elevated.verdict).toBe("warn");
    expect(elevated.detail).toContain("empty or damaged");
    expect(elevated.detail).not.toContain("complete");

    // ...and the unelevated scan, which reports the same condition as a reason.
    const unelevated = byId(
      await run(DENIED_PROBE, async () => ({ ok: false, reason: "manifest-unusable", triedRoots: [] })),
      "app.install",
    );
    expect(unelevated.verdict).toBe("warn");
    // The unelevated scan reaches this verdict two ways — an empty `files`, or an
    // entry outside the shared entry-path rule — so it names both and, either
    // way, refuses to be read as evidence about the FILES.
    expect(unelevated.detail).toContain("damaged");
    expect(unelevated.detail).toContain("a path we will not follow");
    expect(unelevated.detail).toContain("not a statement that files are missing");
  });

  it("calls 'no manifest anywhere' a question it could not answer, never a pass", async () => {
    // THE REGRESSION: `manifest === null` with the tray exe present reported
    // `ok` — "the installed application is present (this build shipped no file
    // manifest, so nothing was counted)" — a fact the probe cannot possibly
    // know. It emits null identically for a build that shipped none, for a
    // manifest quarantined with everything else, and for a read that was
    // denied. So the incident's own shape printed a PASSING verdict to an
    // administrator, on the one check this verb exists for.
    setPlatform("win32");
    const install = byId(await run(async () => snapshotWith({ manifest: null })), "app.install");
    expect(install.verdict).toBe("warn");
    expect(install.detail).toContain("NOTHING COULD BE COUNTED");
    expect(install.detail).toContain("beside this helper");
    // ...and it is still not an accusation: "could not check" is a third
    // verdict, never rounded to "files are missing" either.
    expect(install.detail).toContain("not a statement that files are missing");
    expect(install.remedy).toBeDefined();
  });

  it("says when the counts came from the copy beside this helper", async () => {
    // A count taken from the sibling inventory is a count from a file that may
    // describe a slightly different build — and the fact that the in-tree copy
    // was gone is itself part of the diagnosis.
    setPlatform("win32");
    const install = byId(
      await run(async () =>
        snapshotWith({
          trayExeInstalled: false,
          manifest: {
            totalFiles: 81,
            missingFiles: 80,
            missingCritical: 12,
            unreadableFiles: 0,
            version: "1.1.0",
            source: "helper",
          },
        }),
      ),
      "app.install",
    );
    expect(install.verdict).toBe("fail");
    expect(install.detail).toContain("80 of 81");
    expect(install.detail).toContain("copy beside this helper");
  });

  it("skips the count off Windows rather than guessing", async () => {
    setPlatform("darwin");
    const checks = await run(async () => snapshotWith({}));
    expect(byId(checks, "app.install").verdict).toBe("skipped");
    expect(byId(checks, "watchdog.log").verdict).toBe("skipped");
  });
});

describe("helper.endpoint — WHICH process answered, not whether one did", () => {
  const servers: net.Server[] = [];
  const accepted: net.Socket[] = [];
  const intervals: NodeJS.Timeout[] = [];
  let socketDir: string;

  beforeEach(() => {
    socketDir = mkdtempSync(path.join(tmpdir(), "aic-helper-doctor-"));
  });

  afterEach(async () => {
    for (const interval of intervals.splice(0)) clearInterval(interval);
    for (const socket of accepted.splice(0)) socket.destroy();
    await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => s.close(() => r()))));
    rmSync(socketDir, { recursive: true, force: true });
  });

  /** A listener that answers `hello` however the test says — or not at all. */
  async function listen(name: string, reply: ((socket: net.Socket) => void) | null): Promise<ElevatedEndpoint> {
    const socketPath = path.join(socketDir, name);
    const server = net.createServer((socket) => {
      accepted.push(socket);
      if (reply) socket.on("data", () => reply(socket));
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    return { transport: "unix", path: socketPath };
  }

  const helloOk = (bootId: string) => (socket: net.Socket) =>
    socket.write(
      encodeFrame({
        t: "hello-ok",
        protocolVersion: IPC_PROTOCOL_VERSION,
        helperVersion: "1.1.0",
        bootId,
        effectiveIdentity: "root",
      }),
    );

  const endpointCheck = async (endpoints: ElevatedEndpoint[]): Promise<HelperCheck> =>
    byId(
      await runHelperDoctor({
        probe: DENIED_PROBE,
        scan: async () => ({ ok: false, reason: "no-manifest-found" }),
        endpointTimeoutMs: 250,
        endpoints,
        markerPath: null,
      }),
      "helper.endpoint",
    );

  it("reports the helper only when the helper identifies itself", async () => {
    const check = await endpointCheck([await listen("ok.sock", helloOk("boot-1"))]);
    expect(check.verdict).toBe("ok");
    expect(check.detail).toContain("answered its handshake");
  });

  it("does NOT call a silent squatter the privileged helper", async () => {
    // The regression this pins: a bare TCP connect reported "the privileged
    // helper is listening" for anything that accepted a connection, so any
    // unprivileged process holding one candidate port produced a healthy
    // verdict — about the exact state in which the agent refuses every elevated
    // command.
    const check = await endpointCheck([await listen("mute.sock", null)]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("did not identify itself");
    expect(check.detail).not.toContain("the privileged helper");
  });

  it("gives up on a responder that talks forever without ever answering", async () => {
    // THE REGRESSION: the exchange was bounded by `socket.setTimeout`, which is
    // an INACTIVITY timer — every arriving byte rearms it. The frame loop skips
    // everything that is not `hello-ok` or `error`, so a process squatting on a
    // candidate endpoint had only to write a well-formed frame of some other
    // type on a repeating interval and this check never returned. The endpoint
    // check is awaited in sequence with the rest, so the WHOLE report hung — in
    // exactly the state the report exists to describe.
    const started = Date.now();
    const check = await endpointCheck([
      await listen("chatty.sock", (socket) => {
        const frame = encodeFrame({ t: "output", requestId: "r1", stream: "stdout", chunk: "" });
        const interval = setInterval(() => socket.write(frame), 10);
        intervals.push(interval);
        socket.on("close", () => clearInterval(interval));
      }),
    ]);
    // The budget above is 250 ms; anything under a second proves the deadline
    // is real without pinning the exact scheduling.
    expect(Date.now() - started).toBeLessThan(1000);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("did not identify itself");
    expect(check.detail).toContain("kept the connection open without answering");
    // Still nothing the responder said, in a report whose footer says it is
    // safe to forward.
    expect(check.detail).not.toContain("output");
  });

  it("does not accept an answer with no usable bootId", async () => {
    const check = await endpointCheck([
      await listen("anon.sock", (socket) =>
        socket.write(
          encodeFrame({
            t: "hello-ok",
            protocolVersion: IPC_PROTOCOL_VERSION,
            helperVersion: "1.1.0",
            bootId: "",
            effectiveIdentity: "root",
          }),
        ),
      ),
    ]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("did not identify itself");
  });

  it("fails closed when two endpoints disagree about who they are", async () => {
    const check = await endpointCheck([
      await listen("a.sock", helloOk("boot-1")),
      await listen("b.sock", helloOk("boot-2")),
    ]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("2 different processes");
  });

  it("calls a REFUSED handshake a protocol mismatch, not a squatter", async () => {
    // THE REGRESSION: `handshake` discarded every frame that was not `hello-ok`
    // — including the live helper's own
    // `{t:"error", message:"unsupported IPC protocol version …"}`, which is what
    // helper.ts sends before closing on a version it will not speak. The close
    // that followed was then reported as "something is listening … did not
    // identify itself", with a remedy telling the reader to go and find what
    // else is on the port. The truth is a half-applied upgrade, and the machine
    // is fine.
    const check = await endpointCheck([
      await listen("skew.sock", (socket) => {
        socket.write(encodeFrame({ t: "error", message: "unsupported IPC protocol version 9 (helper speaks 3)" }));
        socket.end();
      }),
    ]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("protocol mismatch");
    expect(check.detail).not.toContain("did not identify itself");
    expect(check.remedy).toContain("Re-run the installer");
    // The responder's own text is UNTRUSTED and is never quoted into a report
    // whose footer says it is safe to forward.
    expect(check.detail).not.toContain("helper speaks");
  });

  it("does not introduce an error-frame responder as OUR helper", async () => {
    // THE REGRESSION IN THE OTHER DIRECTION. Treating `{t:"error"}` as evidence
    // of a protocol-mismatched HELPER made the fix above overshoot: this
    // listener is a plain user-space server in a temp directory — nothing about
    // it is privileged, and an `error` frame carries no boot id — yet the check
    // introduced it as "the helper answered … a half-applied upgrade, not an
    // impostor on the port", with a re-install remedy. That is worse than the
    // squatter sentence it replaced, because it tells the reader the endpoint is
    // legitimately ours. Both possibilities must be named, and neither rounded
    // away.
    const check = await endpointCheck([
      await listen("stranger.sock", (socket) => {
        socket.write(encodeFrame({ t: "error", message: "unsupported IPC protocol version 9 (helper speaks 3)" }));
        socket.end();
      }),
    ]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("cannot tell which");
    expect(check.detail).toContain("something else holding the endpoint");
    expect(check.detail).not.toContain("not an impostor");
    expect(check.detail).not.toMatch(/the (privileged )?helper answered/);
    expect(check.remedy).toContain("find what else is holding the endpoint");
    // Still the untrusted-text rule, and still fail-closed.
    expect(check.detail).not.toContain("unsupported");
  });

  it("does not call a responder on ANOTHER protocol version a healthy helper", async () => {
    // The same skew from the other end, and the one the old `identified` filter
    // let through: a complete `hello-ok` with a usable bootId but a protocol
    // version we do not speak. The agent refuses elevated execution in exactly
    // this state (`protocol_mismatch`), so reporting it as `ok` here is a clean
    // verdict about a machine where every elevated command correctly fails.
    const check = await endpointCheck([
      await listen("wrongproto.sock", (socket) =>
        socket.write(
          encodeFrame({
            t: "hello-ok",
            protocolVersion: IPC_PROTOCOL_VERSION + 1,
            helperVersion: "1.0.54",
            bootId: "boot-1",
            effectiveIdentity: "root",
          }),
        ),
      ),
    ]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("protocol mismatch");
    expect(check.detail).toContain(String(IPC_PROTOCOL_VERSION + 1));
    expect(check.remedy).toContain("Re-run the installer");
  });

  it("still says plainly when nothing is there at all", async () => {
    const check = await endpointCheck([{ transport: "unix", path: path.join(socketDir, "absent.sock") }]);
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("nothing answered");
  });
});

describe("helper.marker — what it READ, never what it assumed", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "aic-helper-marker-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const marker = async (markerPath: string | null): Promise<HelperCheck> =>
    byId(
      await runHelperDoctor({
        probe: DENIED_PROBE,
        scan: async () => ({ ok: false, reason: "no-manifest-found" }),
        endpointTimeoutMs: 25,
        endpoints: [],
        markerPath,
      }),
      "helper.marker",
    );

  it("reports the version it actually read", async () => {
    const file = path.join(dir, "VERSION");
    writeFileSync(file, `${HELPER_VERSION}\n`);
    const check = await marker(file);
    expect(check.verdict).toBe("ok");
    expect(check.detail).toContain(`marked as ${HELPER_VERSION}`);
  });

  it("does not claim to have read a marker it could not read", async () => {
    // THE REGRESSION: an unreadable marker left `recorded` empty and the success
    // sentence printed `recorded || HELPER_VERSION` — i.e. "installed and marked
    // as <this build>", asserting a value it never read, in a report the footer
    // tells the reader is safe to forward. A directory where the file should be
    // reproduces the shape (statSync succeeds, readFileSync throws) without
    // needing a Windows ACL.
    const file = path.join(dir, "VERSION");
    mkdirSync(file);
    const check = await marker(file);
    expect(check.verdict).toBe("warn");
    expect(check.detail).toContain("could not be read");
    expect(check.detail).not.toContain(`marked as ${HELPER_VERSION}`);
    expect(check.remedy).toContain("installer");
  });

  it("does not read a version out of content that is not one", async () => {
    // Beside a COPIED helper the marker is a file whoever made the copy wrote.
    // Its content is dropped rather than printed — and the check then says the
    // recorded build is unknown instead of substituting its own.
    const file = path.join(dir, "VERSION");
    writeFileSync(file, "not a version at all");
    const check = await marker(file);
    expect(check.verdict).toBe("warn");
    expect(check.detail).toContain("does not contain a version");
    expect(check.detail).not.toContain("not a version at all");
  });

  it("still fails outright when the marker is absent", async () => {
    const check = await marker(path.join(dir, "absent", "VERSION"));
    expect(check.verdict).toBe("fail");
    expect(check.detail).toContain("missing");
  });

  it("still reports a genuine skew as a half-applied upgrade", async () => {
    const file = path.join(dir, "VERSION");
    writeFileSync(file, "0.0.1");
    const check = await marker(file);
    expect(check.verdict).toBe("warn");
    expect(check.detail).toContain("half-applied upgrade");
  });
});

describe("renderHelperDoctor", () => {
  it("prints nothing that would need redacting", async () => {
    const text = renderHelperDoctor(await run(async () => snapshotWith({})));
    // The agent's report bundle exists because it carries user paths; this one
    // collects only fixed machine-wide locations, which is why this package has
    // no second copy of redactDiagText. Keep that true.
    expect(text).not.toContain(os.homedir());
    // Including the path this very binary was launched from: anybody may run the
    // helper out of their Downloads folder, which makes that a user path too.
    expect(text).not.toContain(process.execPath);
    expect(text).toContain("safe to paste into a support case");
  });

  it("redacts the report it tells the reader is safe to forward", async () => {
    // The regression: this verb interpolated a scanned install root (a user path
    // the moment somebody runs the helper out of their Downloads folder), the
    // VERSION marker's content and exception messages into a page whose own
    // footer says it is safe to send to an antivirus vendor — with no redaction
    // anywhere in the package.
    setPlatform("win32");
    const checks = await run(
      DENIED_PROBE,
      scanned({ root: "C:\\Users\\alice\\Downloads\\AICommander", missingFiles: 80, missingCritical: 12 }),
    );
    const install = byId(checks, "app.install");
    expect(install.detail).not.toContain("alice");
    expect(install.detail).toContain("C:\\Users\\<user>\\Downloads\\AICommander");
    // ...and the count survives the redaction: a report that redacted the
    // diagnosis away would be no safer and no use.
    expect(install.detail).toContain("80 of 81");
    expect(renderHelperDoctor(checks)).not.toContain("alice");
  });

  it("redacts what a FAULTING check says, not only what a working one prints", async () => {
    // An fs error's message embeds the path it failed on, and that path may be
    // anybody's.
    setPlatform("win32");
    const checks = await run(async () => {
      throw new Error("EACCES: permission denied, stat '/home/bob/Library/AI Commander'");
    });
    const faulted = byId(checks, "doctor.error");
    expect(faulted.detail).not.toContain("bob");
    expect(faulted.detail).toContain("/home/<user>/");
  });

  it("redacts a page it did not build itself, so the footer's promise holds", () => {
    const text = renderHelperDoctor([
      { id: "x", title: "X", verdict: "warn", detail: "counted in /home/carol/app", remedy: "ask /home/carol" },
    ]);
    expect(text).not.toContain("carol");
  });

  it("exits 0 when nothing failed, whatever was skipped", () => {
    const checks: HelperCheck[] = [
      { id: "a", title: "A", verdict: "ok", detail: "" },
      { id: "b", title: "B", verdict: "skipped", detail: "" },
      { id: "c", title: "C", verdict: "warn", detail: "" },
    ];
    expect(helperDoctorExitCode(checks)).toBe(0);
  });
});
