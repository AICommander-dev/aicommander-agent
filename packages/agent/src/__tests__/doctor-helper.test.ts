// The privileged-helper checks.
//
// On the machine that produced the 2026-09-02 incident the helper had never been
// registered and NOTHING said so, so the assertions that matter are the ones
// about telling the five causes apart: files absent, task not registered,
// signature wrong, nothing answering, protocol skew. Collapsing any two of them
// is what made that day expensive.
//
// PLATFORM NOTE. Driven on POSIX with `process.platform` pinned before the
// dynamic import, like the other Windows-shaped suites here. The platform-owned
// values (where the helper lives, which endpoints it binds) come from
// @aicommander/priv-helper and are staged, so this suite tests the doctor's
// logic rather than a temp directory named to look like C:\Program Files.
//
// Staging a UNIX socket while pinned to win32 tests a shape that never runs on
// Windows: `elevatedEndpoints()` there returns a POOL of loopback TCP ports, and
// the helper binds every one it can precisely so nobody else can. So the TCP
// branch of `net.connect`, the walk across the whole pool, and the fail-closed
// verdict when two ports answer with DIFFERENT identities are staged as TCP here
// — they are the shapes that actually run on the platform this suite pins.

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

type StagedEndpoint =
  | { transport: "unix"; path: string }
  | { transport: "tcp"; host: string; port: number };

const helperEnv = vi.hoisted(() => ({
  dir: null as string | null,
  endpoints: [] as StagedEndpoint[],
  /** Where the macOS LaunchDaemon plist is staged; the real path is /Library. */
  plist: null as string | null,
}));

vi.mock("@aicommander/priv-helper", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@aicommander/priv-helper")>();
  return {
    ...actual,
    helperInstallDir: () => helperEnv.dir,
    helperVersionMarkerPath: () => (helperEnv.dir === null ? null : path.join(helperEnv.dir, "VERSION")),
    elevatedEndpoints: () => helperEnv.endpoints,
    // A getter, so a test can move the plist AFTER the module under test has
    // imported the binding: /Library/LaunchDaemons is not ours to write to.
    get MAC_DAEMON_PLIST(): string {
      return helperEnv.plist ?? actual.MAC_DAEMON_PLIST;
    },
  };
});

// ONE command seam, capture.ts's `runCaptured`, and not installed-version.ts's
// `runCapture`: a single string could not separate "the command ran and printed
// nothing" from "the command never ran", and three checks rounded the second
// into a verdict about the machine. Staging the tri-state here is what lets
// those two shapes be tested apart. Both PowerShell questions below come through
// it — the RUNTIME's scheduled-task query (windows-scheduled-task.ts, shared
// with elevated-availability.ts) and the diagnostic Authenticode read — and both
// are answered from `shell.powershell`, exactly as one real PowerShell would.
type Captured = import("../capture.js").Captured;

const shell = vi.hoisted(() => ({
  powershell: "",
  /** What `launchctl print` did — the tri-state, because root changes what it means. */
  launchctl: { kind: "output", stdout: "" } as Captured,
}));
vi.mock("../capture.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../capture.js")>();
  return {
    ...actual,
    runCaptured: async (command: string): Promise<Captured> => {
      if (/powershell\.exe$/i.test(command)) return { kind: "output", stdout: shell.powershell };
      if (/launchctl$/.test(command)) return shell.launchctl;
      return { kind: "output", stdout: "" };
    },
  };
});

type HelperModule = typeof import("../doctor/checks/priv-helper.js");
let helper: HelperModule;
let protocol: typeof import("@aicommander/priv-helper");
const realPlatform = process.platform;

beforeAll(async () => {
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  helper = await import("../doctor/checks/priv-helper.js");
  protocol = await import("@aicommander/priv-helper");
});

afterAll(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

let tmp: string;
const servers: net.Server[] = [];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-helper-"));
  helperEnv.dir = null;
  helperEnv.endpoints = [];
  helperEnv.plist = null;
  shell.powershell = "";
  shell.launchctl = { kind: "output", stdout: "" };
});

afterEach(async () => {
  for (const server of servers.splice(0)) await new Promise((r) => server.close(r));
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Install a helper directory that looks the way the installer leaves it. */
function stageInstalledHelper(): string {
  helperEnv.dir = path.join(tmp, "helper");
  fs.mkdirSync(helperEnv.dir);
  fs.writeFileSync(path.join(helperEnv.dir, "VERSION"), "1.1.0\n");
  fs.writeFileSync(path.join(helperEnv.dir, "aicommander-priv-helper.exe"), "sea");
  return helperEnv.dir;
}

/** A responder that completes `hello` however the caller asks it to. */
function helloServer(frame: Record<string, unknown>): net.Server {
  const server = net.createServer((socket) => {
    socket.on("data", () => {
      // Cast: a responder that OMITS bootId is not a valid HelperToClientMsg,
      // and staging exactly that is the point of one of the tests below.
      socket.write(protocol.encodeFrame(frame as unknown as Parameters<typeof protocol.encodeFrame>[0]));
    });
  });
  servers.push(server);
  return server;
}

/**
 * The helper's OWN answer to a `hello` it cannot speak to: an `error` frame,
 * then the socket closes (priv-helper/src/helper.ts). It never reaches
 * `hello-ok`, which is why this shape — not a mismatched `hello-ok` — is what a
 * real half-applied upgrade puts on the wire.
 */
const REFUSAL_MESSAGE = "unsupported IPC protocol version 1 (helper speaks 99)";

async function stageRefusingTcpHelper(): Promise<StagedEndpoint> {
  const server = net.createServer((socket) => {
    socket.on("data", () => {
      socket.write(protocol.encodeFrame({ t: "error", message: REFUSAL_MESSAGE }));
      socket.end();
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no TCP port");
  return { transport: "tcp", host: "127.0.0.1", port: address.port };
}

/** A helper on a unix socket that says it speaks `protocolVersion`. */
async function stageHelperEndpoint(protocolVersion: number): Promise<void> {
  const socketPath = path.join(tmp, "helper.sock");
  const server = helloServer({
    t: "hello-ok",
    protocolVersion,
    helperVersion: "1.1.0",
    bootId: "b".repeat(32),
    effectiveIdentity: "SYSTEM",
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  helperEnv.endpoints = [{ transport: "unix", path: socketPath }];
}

/**
 * A helper on LOOPBACK TCP — the only endpoint shape that exists on Windows.
 * Returns the staged endpoint so a test can compose a pool out of several.
 */
async function stageTcpHelper(
  bootId: string,
  protocolVersion: number = protocol.IPC_PROTOCOL_VERSION,
): Promise<StagedEndpoint> {
  const server = helloServer({
    t: "hello-ok",
    protocolVersion,
    helperVersion: "1.1.0",
    bootId,
    effectiveIdentity: "SYSTEM",
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no TCP port");
  return { transport: "tcp", host: "127.0.0.1", port: address.port };
}

/** A port nothing is listening on. */
async function deadTcpEndpoint(): Promise<StagedEndpoint> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no TCP port");
  await new Promise((resolve) => server.close(resolve));
  return { transport: "tcp", host: "127.0.0.1", port: address.port };
}

/** The groups ignore the context; the interface still asks for one. */
const ctx = () => ({
  serverUrl: "https://relay.invalid",
  offline: true,
  networkTimeoutMs: 100,
  probeDelayMs: 0,
});

function verdicts(results: Awaited<ReturnType<HelperModule["privHelperChecks"]["run"]>>) {
  return Object.fromEntries(results.map((r) => [r.id, r]));
}

describe("privileged helper checks", () => {
  it("names a missing installation as such, and points at the installer", async () => {
    helperEnv.dir = path.join(tmp, "absent");
    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.installed"]!.verdict).toBe("fail");
    expect(by["helper.installed"]!.remedy).toMatch(/Re-run the installer/);
    // With no binary there is nothing to verify — skipped, not failed.
    expect(by["helper.signature"]!.verdict).toBe("skipped");
  });

  it("fails a half-present installation rather than calling it installed", async () => {
    helperEnv.dir = path.join(tmp, "helper");
    fs.mkdirSync(helperEnv.dir);
    fs.writeFileSync(path.join(helperEnv.dir, "aicommander-priv-helper.exe"), "sea");
    // No VERSION marker: isElevatedHelperAvailable() treats that as unavailable,
    // so the doctor must not report it as installed.
    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.installed"]!.verdict).toBe("fail");
  });

  it("says out loud that the SYSTEM task is not registered — the incident's silent state", async () => {
    stageInstalledHelper();
    // The sentinel is what makes this an ANSWER: PowerShell ran, looked, and
    // found no such task. Without it the same empty string would mean "we never
    // got to ask" (see the next test).
    shell.powershell = "QUERIED=1";
    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.installed"]!.verdict).toBe("ok");
    expect(by["helper.registered"]!.verdict).toBe("fail");
    expect(by["helper.registered"]!.detail).toMatch(/NOT registered/);
  });

  // ── macOS registration: the plist is HALF the question ────────────────────
  //
  // `launchctl print system/<label>` exits non-zero both for "you may not ask"
  // and for "launchd does not hold that service", so WHO IS ASKING decides
  // which one it was. Reading the failure without the uid reported a Mac whose
  // helper is installed but not loaded as healthy, and blamed a lack of
  // privilege the run did not lack — on the one check whose job is to separate
  // "registered" from "running".
  describe("macOS registration", () => {
    let realGetuid: typeof process.getuid;

    beforeEach(() => {
      Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
      helperEnv.plist = path.join(tmp, "dev.aicommander.privhelper.plist");
      fs.writeFileSync(helperEnv.plist, "<plist/>\n");
      realGetuid = process.getuid;
    });

    afterEach(() => {
      Object.defineProperty(process, "platform", { value: "win32", configurable: true });
      Object.defineProperty(process, "getuid", { value: realGetuid, configurable: true });
    });

    const asUid = (uid: number): void => {
      Object.defineProperty(process, "getuid", { value: () => uid, configurable: true });
    };

    const registered = async () =>
      verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;

    it("FAILS when root asked launchd and launchd does not have it loaded", async () => {
      // The regression: `runCapture` returned "" here and the check answered
      // `ok` with "launchd's own state was not readable from here (it needs
      // root)" — an excuse, given as root, for a daemon that is genuinely not
      // loaded. Nothing starts the helper on this machine.
      stageInstalledHelper();
      asUid(0);
      shell.launchctl = { kind: "failed", stdout: "", code: 113, signal: null };
      const result = await registered();
      expect(result.verdict).toBe("fail");
      expect(result.detail).toMatch(/does not have .* loaded/);
      expect(result.facts?.["loaded"]).toBe(false);
      expect(result.facts?.["root"]).toBe(true);
    });

    it("still excuses an UNPRIVILEGED run, which genuinely cannot read launchd", async () => {
      stageInstalledHelper();
      asUid(501);
      shell.launchctl = { kind: "failed", stdout: "", code: 1, signal: null };
      const result = await registered();
      expect(result.verdict).toBe("ok");
      expect(result.detail).toMatch(/needs root/);
      // Not established either way — never rounded to "loaded" or "not loaded".
      expect(result.facts?.["loaded"]).toBeNull();
    });

    it("does not blame root when launchctl itself never ran", async () => {
      stageInstalledHelper();
      asUid(0);
      shell.launchctl = {
        kind: "unavailable",
        reason: "/bin/launchctl could not be started: ENOENT",
        partialStdout: "",
      };
      const result = await registered();
      expect(result.verdict).toBe("ok");
      expect(result.detail).toMatch(/launchd was not asked/);
      expect(result.facts?.["loaded"]).toBeNull();
    });

    it("passes a daemon launchd answers for", async () => {
      stageInstalledHelper();
      asUid(0);
      shell.launchctl = { kind: "output", stdout: "system/dev.aicommander.privhelper = {\n  state = running\n}" };
      const result = await registered();
      expect(result.verdict).toBe("ok");
      expect(result.facts?.["loaded"]).toBe(true);
    });
  });

  it("does NOT accuse a machine whose PowerShell query never ran", async () => {
    stageInstalledHelper();
    // runCapture answers "" for a spawn failure, a non-zero exit, a timeout, an
    // AppLocker or ConstrainedLanguage block and an access error alike. Reading
    // that as "the task was never registered" invents the incident's signature
    // on a machine that may be perfectly healthy — which is the one thing a
    // diagnostic must never do.
    shell.powershell = "";
    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.registered"]!.verdict).toBe("skipped");
    expect(by["helper.registered"]!.detail).toMatch(/could not be determined/);
  });

  it("blames the ACL only when the ACL is what refused, and elevation only when it would help", async () => {
    // Every unanswered query used to be reported with the same sentence — "a
    // standard user cannot read this task's ACL, re-run elevated" — including
    // the timeout, the missing PowerShell and the blocked COM, where elevation
    // changes nothing and the words send the reader after the wrong thing.
    stageInstalledHelper();
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    const denied = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
    expect(denied.verdict).toBe("skipped");
    // A refusal is Task Scheduler confirming the task EXISTS, so the report may
    // not leave the reader thinking the helper is missing.
    expect(denied.detail).toMatch(/only does for a task that EXISTS/);
    expect(denied.detail).toMatch(/elevated prompt/);

    shell.powershell = "QUERIED=1\r\nLOOKUPFAIL=ComConnect";
    const broke = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
    expect(broke.verdict).toBe("skipped");
    expect(broke.detail).toMatch(/nothing was learned about the task/i);
    expect(broke.detail).not.toMatch(/cannot read this task's ACL/);
  });

  it("does not tell the reader nothing was learned when the service just read the task", async () => {
    // The CONTRADICTION case, which used to arrive as `lookup_failed` and so got
    // the "nothing was learned about the task either way" sentence — printed
    // immediately after a `reason` saying the Task Scheduler service had read the
    // task out of the root folder. One detail, both claims.
    stageInstalledHelper();
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nCONTRADICTION=1";
    const clash = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
    expect(clash.verdict).toBe("skipped");
    expect(clash.detail).toMatch(/Task Scheduler service read it/);
    expect(clash.detail).toMatch(/Something WAS learned/);
    expect(clash.detail).not.toMatch(/nothing was learned about the task/i);
  });

  it("passes a registered, correctly signed, answering helper", async () => {
    stageInstalledHelper();
    shell.powershell = [
      "STATE=Running",
      "EXECUTE=C:\\Program Files\\AI Commander Privileged Helper\\aicommander-priv-helper.exe",
      "STATUS=Valid",
      "SUBJECT=CN=WEARFITS sp. z o.o., O=WEARFITS sp. z o.o., L=Krakow, C=PL",
    ].join("\r\n");
    await stageHelperEndpoint(protocol.IPC_PROTOCOL_VERSION);

    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.registered"]!.verdict).toBe("ok");
    expect(by["helper.signature"]!.verdict).toBe("ok");
    expect(by["helper.endpoint"]!.verdict).toBe("ok");
    expect(by["helper.endpoint"]!.facts?.["helperVersion"]).toBe("1.1.0");
  });

  it("fails an invalid signature and only WARNS on an unexpected subject", async () => {
    stageInstalledHelper();
    shell.powershell = "STATE=Running\r\nSTATUS=HashMismatch\r\nSUBJECT=CN=Somebody Else";
    expect(verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!.verdict).toBe("fail");

    // A validly signed binary carrying a different subject may equally mean the
    // certificate rotated, so the doctor reports rather than accuses.
    shell.powershell = "STATE=Running\r\nSTATUS=Valid\r\nSUBJECT=CN=Somebody Else";
    const warned = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
    expect(warned.verdict).toBe("warn");
    expect(warned.facts?.["subject"]).toBe("CN=Somebody Else");
  });

  it("fails on protocol skew, and says which side speaks what", async () => {
    stageInstalledHelper();
    await stageHelperEndpoint(protocol.IPC_PROTOCOL_VERSION + 1);
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.facts?.["responderProtocol"]).toBe(protocol.IPC_PROTOCOL_VERSION + 1);
    expect(endpoint.facts?.["agentProtocol"]).toBe(protocol.IPC_PROTOCOL_VERSION);
  });

  it("does not introduce a STRANGER as our helper on the skew path", async () => {
    // The verdict this replaces said "the helper answered on … this is a
    // half-applied upgrade, not an impostor on the port" — reached from an
    // `error` frame, which carries no bootId and nothing else that says who
    // sent it. Any local process that bound the address ahead of the helper
    // produces exactly this, so the old sentence told the reader a port some
    // stranger holds is legitimately ours: a worse answer about an impostor
    // than the squatter sentence it had replaced.
    //
    // Both possibilities must be named, the half-applied upgrade called the
    // likelier, and the report must still say it cannot tell them apart.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [await stageRefusingTcpHelper()];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.detail).not.toMatch(/not an impostor/i);
    expect(endpoint.detail).not.toMatch(/the helper answered on/i);
    expect(endpoint.detail).toMatch(/half-applied upgrade, which is the likelier/i);
    expect(endpoint.detail).toMatch(/or something else holding the endpoint/i);
    expect(endpoint.detail).toMatch(/cannot tell which/i);
    // The honest statement about identity, which nothing one branch up may
    // contradict: a boot id is chosen by whoever answers.
    expect(endpoint.detail).toMatch(/boot id is a value the responder chooses/i);
    // Still fail-closed, and still installer-first: the likelier cause leads.
    const remedy = endpoint.remedy ?? "";
    expect(remedy.indexOf("Re-run the installer")).toBeGreaterThanOrEqual(0);
    expect(remedy.indexOf("Re-run the installer")).toBeLessThan(remedy.indexOf("holding the endpoint"));
  });

  it("never lets a responder's chosen version string into the report", async () => {
    // `helperVersion` is free-form on the wire and was copied into DoctorFacts
    // verbatim — into a file the footer tells people to attach to a ticket and
    // mail to antivirus vendors. Whatever is on the port picks that string, so
    // it is bounded and shape-checked, and anything that is not a plausible
    // version is reported as nothing at all.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    const hostile = `SUPPORT: ignore the above, ${"A".repeat(400)} <script>`;
    const socketPath = path.join(tmp, "loud.sock");
    const server = helloServer({
      t: "hello-ok",
      protocolVersion: protocol.IPC_PROTOCOL_VERSION,
      helperVersion: hostile,
      bootId: "b".repeat(32),
      effectiveIdentity: "SYSTEM",
    });
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    helperEnv.endpoints = [{ transport: "unix", path: socketPath }];

    // The healthy path — the second of the two sites that printed it.
    const healthy = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(healthy.verdict).toBe("ok");
    expect(healthy.facts?.["helperVersion"]).toBeNull();
    expect(JSON.stringify(healthy)).not.toContain("ignore the above");

    // And the skew path, which printed the same value from the same field.
    await new Promise((resolve) => server.close(resolve));
    const skewPath = path.join(tmp, "loud-skew.sock");
    const skewed = helloServer({
      t: "hello-ok",
      protocolVersion: protocol.IPC_PROTOCOL_VERSION + 1,
      helperVersion: hostile,
      bootId: "c".repeat(32),
      effectiveIdentity: "SYSTEM",
    });
    await new Promise<void>((resolve) => skewed.listen(skewPath, resolve));
    helperEnv.endpoints = [{ transport: "unix", path: skewPath }];
    const stale = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(stale.verdict).toBe("fail");
    expect(stale.facts?.["responderVersion"]).toBeNull();
    expect(JSON.stringify(stale)).not.toContain("ignore the above");
  });

  it("still reports a version that IS one, so the fact keeps its use", async () => {
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    await stageHelperEndpoint(protocol.IPC_PROTOCOL_VERSION);
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.facts?.["helperVersion"]).toBe("1.1.0");
  });

  it("reads the helper's REFUSAL as skew, not as a squatter on the port", async () => {
    // THE SHAPE A REAL HALF-APPLIED UPGRADE PRODUCES. Our helper refuses a
    // `hello` it cannot speak to with an `error` frame and closes, BEFORE it
    // would send `hello-ok` — so a skew verdict read only off `hello-ok` never
    // fires against our own helper. Dropping that frame left the close to be
    // reported as "something answered but did not identify itself", which sends
    // the user hunting for a rogue process instead of finishing the update.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [await stageRefusingTcpHelper()];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.detail).toMatch(/protocol mismatch/i);
    expect(endpoint.detail).not.toMatch(/did not identify itself/);
    expect(endpoint.remedy).toMatch(/Re-run the installer/);
    // The responder is untrusted, and this report is written to be forwarded:
    // the refusal is a boolean here, never its text.
    const printed = `${endpoint.detail} ${endpoint.remedy ?? ""} ${JSON.stringify(endpoint.facts ?? {})}`;
    expect(printed).not.toMatch(/unsupported IPC protocol version/);
    expect(endpoint.facts?.["incompatibleResponders"]).toBe(1);
  });

  it("reports both shapes of skew — the refusal and an unspeakable hello-ok — as one state", async () => {
    // Which shape the wire carries depends only on which side is older, so both
    // must reach the same verdict. Counting the `hello-ok` half alone reported
    // the refusing endpoint as an anonymous listener.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [
      await stageRefusingTcpHelper(),
      await stageTcpHelper("c".repeat(32), protocol.IPC_PROTOCOL_VERSION + 1),
    ];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.detail).toMatch(/protocol mismatch/i);
    expect(endpoint.detail).not.toMatch(/did not identify itself/);
    expect(endpoint.facts?.["incompatibleResponders"]).toBe(2);
  });

  it("fails the endpoint when nothing is listening", async () => {
    stageInstalledHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "not-there.sock") }];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.remedy).toMatch(/not running/);
  });

  it("answers on a loopback TCP endpoint — the only shape Windows ever uses", async () => {
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [await stageTcpHelper("b".repeat(32))];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("ok");
    expect(String(endpoint.facts?.["endpoint"])).toMatch(/^127\.0\.0\.1:\d+$/);
  });

  it("walks the WHOLE pool, so a dead first port does not hide a live helper", async () => {
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [await deadTcpEndpoint(), await stageTcpHelper("b".repeat(32))];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("ok");
    expect(endpoint.facts?.["answered"]).toBe(1);
  });

  it("fails closed when two ports answer with DIFFERENT identities", async () => {
    // The helper binds every candidate it can, so a second distinct bootId means
    // something the helper does not own is answering — a squatter that took a
    // port while the helper was down. The agent refuses elevated exec in exactly
    // this state; a doctor that reported "healthy" would contradict the product.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [await stageTcpHelper("b".repeat(32)), await stageTcpHelper("c".repeat(32))];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.detail).toMatch(/not the privileged helper/);
    expect(endpoint.facts?.["distinctIdentities"]).toBe(2);
  });

  it("does not let an INCOMPATIBLE responder manufacture a conflict", async () => {
    // `discoverHelperDetailed` puts only protocol-compatible answers in its
    // candidate set, so a stale responder on a spare port cannot make discovery
    // fail closed — elevated exec works on such a machine. A doctor that kept it
    // among the identities reported a bootId conflict, or a protocol failure, on
    // a machine where the product is fine. Diagnostics that contradict the thing
    // they diagnose are worse than none.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [
      await stageTcpHelper("c".repeat(32), protocol.IPC_PROTOCOL_VERSION + 1),
      await stageTcpHelper("b".repeat(32)),
    ];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("warn");
    expect(endpoint.detail).not.toMatch(/not the privileged helper/);
    expect(endpoint.facts?.["distinctIdentities"]).toBeUndefined();
    expect(endpoint.facts?.["helperProtocol"]).toBe(protocol.IPC_PROTOCOL_VERSION);
    expect(endpoint.facts?.["incompatibleResponders"]).toBe(1);
  });

  it("still fails on protocol skew when nothing compatible answers anywhere", async () => {
    // The fallback order discovery uses: a mismatch is the verdict only once the
    // candidate set is empty.
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    helperEnv.endpoints = [
      await deadTcpEndpoint(),
      await stageTcpHelper("c".repeat(32), protocol.IPC_PROTOCOL_VERSION + 1),
    ];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.detail).toMatch(/IPC protocol/);
    expect(endpoint.facts?.["responderProtocol"]).toBe(protocol.IPC_PROTOCOL_VERSION + 1);
  });

  it("does not trust a responder that will not say which process it is", async () => {
    stageInstalledHelper();
    shell.powershell = "STATE=Running";
    const server = helloServer({
      t: "hello-ok",
      protocolVersion: protocol.IPC_PROTOCOL_VERSION,
      helperVersion: "1.1.0",
      effectiveIdentity: "SYSTEM",
    });
    const socketPath = path.join(tmp, "anonymous.sock");
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    helperEnv.endpoints = [{ transport: "unix", path: socketPath }];
    const endpoint = verdicts(await helper.privHelperChecks.run(ctx()))["helper.endpoint"]!;
    expect(endpoint.verdict).toBe("fail");
    expect(endpoint.detail).toMatch(/did not identify itself/);
  });

  it("skips the whole group where there is no helper — Linux root needs none", async () => {
    helperEnv.dir = null;
    helperEnv.endpoints = [];
    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.installed"]!.verdict).toBe("skipped");
    expect(by["helper.endpoint"]!.verdict).toBe("skipped");
  });
});
