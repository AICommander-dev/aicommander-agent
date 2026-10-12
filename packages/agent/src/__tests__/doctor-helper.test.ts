// Privileged-helper files, registration, signature, endpoint and protocol checks.
// Platform-owned paths and endpoints are staged while process.platform is pinned.
//
// What these assertions are for: on the machine behind the 2026-09-02 incident
// the helper had never been registered and nothing said so. Keeping the five
// causes apart — files absent, task not registered, signature wrong, nothing
// answering, protocol skew — is the point; collapsing any two is what made that
// day expensive.
//
// Endpoints are staged as TCP under a pinned win32, never as a UNIX socket: on
// Windows `elevatedEndpoints()` returns a POOL of loopback ports and the helper
// binds every one it can, so the pool walk and the fail-closed verdict when two
// ports answer with different identities are the shapes that actually run there.

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
  commands: [] as string[],
  /** What `launchctl print` did — the tri-state, because root changes what it means. */
  launchctl: { kind: "output", stdout: "" } as Captured,
  /**
   * What `codesign` did, staged as the two questions the check actually asks:
   * the `--verify` sentinel (whose EXIT STATUS is the measurement, so a refusal
   * is a non-zero `failed`, exactly as a real codesign that cannot open the file
   * or dislikes what it finds produces) and the `-dv` authority line. `null`
   * leaves the old blanket empty answer in place for the suites that predate it.
   */
  codesign: null as null | { verified: boolean; authority: string },
}));
vi.mock("../capture.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../capture.js")>();
  return {
    ...actual,
    runCaptured: async (command: string, args: string[]): Promise<Captured> => {
      shell.commands.push(`${command} ${args.join(" ")}`);
      if (/powershell\.exe$/i.test(command)) return { kind: "output", stdout: shell.powershell };
      if (/launchctl$/.test(command)) return shell.launchctl;
      if (command === "/bin/sh" && shell.codesign) {
        const script = args[1] ?? "";
        if (script.includes("--verify")) {
          return shell.codesign.verified
            ? { kind: "output", stdout: "VERIFIED\n" }
            : { kind: "failed", stdout: "", code: 1, signal: null };
        }
        if (script.includes("-dv")) {
          const authority = shell.codesign.authority;
          return { kind: "output", stdout: authority ? `Authority=${authority}\n` : "" };
        }
      }
      return { kind: "output", stdout: "" };
    },
  };
});

type HelperModule = typeof import("../doctor/checks/priv-helper.js");
let helper: HelperModule;
let protocol: typeof import("@aicommander/priv-helper");
/** For the one refusal sentence both Windows task checks must print verbatim. */
let windows: typeof import("../doctor/checks/windows.js");
const realPlatform = process.platform;

beforeAll(async () => {
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  helper = await import("../doctor/checks/priv-helper.js");
  protocol = await import("@aicommander/priv-helper");
  windows = await import("../doctor/checks/windows.js");
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
  shell.commands = [];
  shell.launchctl = { kind: "output", stdout: "" };
  shell.codesign = null;
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
    shell.powershell =
      "STATUS=Valid\r\nSUBJECT=CN=WEARFITS sp. z o.o., O=WEARFITS sp. z o.o., L=Krakow, C=PL";
    const by = verdicts(await helper.privHelperChecks.run(ctx()));
    expect(by["helper.installed"]!.verdict).toBe("fail");
    // The binary itself is present, so its signature is still checked.
    expect(by["helper.signature"]!.verdict).toBe("ok");
    expect(shell.commands.some((command) => command.includes("Get-AuthenticodeSignature"))).toBe(true);
  });

  // EACCES, EPERM and EIO are unknown observations, distinct from ENOENT.
  describe("paths that will not answer", () => {
    /**
     * Fail `stat` with `code` for exactly these paths, leaving every other path
     * real — the shape an ACL, a filter driver (EACCES/EPERM) and a failing
     * disk (EIO) produce. None of them is ENOENT.
     */
    function denyStat(codes: Record<string, string>) {
      const real = fs.promises.stat.bind(fs.promises);
      return vi.spyOn(fs.promises, "stat").mockImplementation((async (target: fs.PathLike, ...rest: unknown[]) => {
        const code = codes[String(target)];
        if (code) throw Object.assign(new Error(`${code}: staged, stat '${String(target)}'`), { code });
        return (real as (...a: unknown[]) => unknown)(target, ...rest);
      }) as unknown as typeof fs.promises.stat);
    }

    const allOf = (dir: string, code: string): Record<string, string> => ({
      [dir]: code,
      [path.join(dir, "VERSION")]: code,
      [path.join(dir, "aicommander-priv-helper.exe")]: code,
    });

    it("reports an install it may not stat as UNDETERMINED, never as missing", async () => {
      const dir = stageInstalledHelper();
      const denied = denyStat(allOf(dir, "EACCES"));
      try {
        const by = verdicts(await helper.privHelperChecks.run(ctx()));
        const installed = by["helper.installed"]!;
        expect(installed.verdict).toBe("warn");
        expect(installed.detail).toMatch(/could not be determined/);
        expect(installed.detail).toContain("EACCES");
        expect(installed.detail).not.toMatch(/is not installed|does not exist/);
        expect(installed.facts?.["code"]).toBe("EACCES");
        // The remedy points at the path, not at a re-install that would not
        // touch a lock, a quarantine or an ACL.
        expect(installed.remedy).toMatch(/Inspect it by hand/);
        expect(installed.remedy).toMatch(/Nothing here says anything is missing/);
        // And the binary was NOT proved absent, so the signature check is not
        // told there is nothing to verify — that would be the same invented
        // absence one layer down.
        expect(by["helper.signature"]!.verdict).not.toBe("skipped");
      } finally {
        denied.mockRestore();
      }
    });

    it("still calls an install missing when the OS positively says ENOENT", async () => {
      // The discrimination, from the other side: a real absence must keep
      // failing, or the fix for the false absence has bought a false pass.
      const dir = stageInstalledHelper();
      const denied = denyStat(allOf(dir, "ENOENT"));
      try {
        const installed = verdicts(await helper.privHelperChecks.run(ctx()))["helper.installed"]!;
        expect(installed.verdict).toBe("fail");
        expect(installed.detail).toMatch(/is not installed/);
        expect(installed.remedy).toMatch(/Re-run the installer/);
      } finally {
        denied.mockRestore();
      }
    });

    it("does not read 'one file present, one unreadable' as a half-present install", async () => {
      // The combination the tri-state creates and the boolean could not: the
      // VERSION marker reads fine and the binary answers EIO. "The helper
      // binary is missing" is a claim about a file this run never looked at.
      const dir = stageInstalledHelper();
      const denied = denyStat({ [path.join(dir, "aicommander-priv-helper.exe")]: "EIO" });
      try {
        const installed = verdicts(await helper.privHelperChecks.run(ctx()))["helper.installed"]!;
        expect(installed.verdict).toBe("warn");
        expect(installed.detail).toMatch(/could not be determined/);
        expect(installed.detail).toContain("EIO");
        expect(installed.detail).not.toMatch(/missing/);
        expect(installed.facts?.["code"]).toBe("EIO");
      } finally {
        denied.mockRestore();
      }
    });

    it.each([
      { missing: "VERSION marker", missingFile: "VERSION", unknownFile: "aicommander-priv-helper.exe", code: "EACCES", signature: "warn" },
      { missing: "helper binary", missingFile: "aicommander-priv-helper.exe", unknownFile: "VERSION", code: "EPERM", signature: "skipped" },
      { missing: "helper binary", missingFile: "aicommander-priv-helper.exe", unknownFile: "VERSION", code: "EIO", signature: "skipped" },
    ])("fails for a missing $missing even when its sibling answers $code", async (scenario) => {
      const dir = stageInstalledHelper();
      const missingPath = path.join(dir, scenario.missingFile);
      const unknownPath = path.join(dir, scenario.unknownFile);
      fs.rmSync(missingPath);
      const denied = denyStat({ [unknownPath]: scenario.code });
      try {
        const by = verdicts(await helper.privHelperChecks.run(ctx()));
        const installed = by["helper.installed"]!;
        expect(installed.verdict).toBe("fail");
        expect(installed.detail).toContain(scenario.missing);
        expect(installed.detail).toContain(missingPath);
        expect(installed.detail).toContain(scenario.code);
        expect(installed.detail).toMatch(/Separately, .* could not be inspected/);
        expect(installed.remedy).toMatch(/restore the missing/);
        expect(installed.remedy).toMatch(/Separately inspect/);
        expect(installed.remedy).not.toMatch(/Nothing here says anything is missing/);
        expect(by["helper.signature"]!.verdict).toBe(scenario.signature);
        expect(shell.commands.some((command) => command.includes("Get-AuthenticodeSignature"))).toBe(false);
      } finally {
        denied.mockRestore();
      }
    });

    it("calls an install INSTALLED when both files read, whatever the directory's stat did", async () => {
      // A file cannot be stat'd through a directory that is not there, so the
      // two files present is the one combination an unreadable directory cannot
      // cast doubt on — and it is the shape the review reproduced.
      const dir = stageInstalledHelper();
      const denied = denyStat({ [dir]: "EACCES" });
      try {
        const installed = verdicts(await helper.privHelperChecks.run(ctx()))["helper.installed"]!;
        expect(installed.verdict).toBe("ok");
        expect(installed.detail).toMatch(/is installed/);
      } finally {
        denied.mockRestore();
      }
    });

    // An unreadable binary must not reach the platform signature command.
    it("never tells the reader to distrust a Windows binary it could not read", async () => {
      const dir = stageInstalledHelper();
      // The status a real `Get-AuthenticodeSignature` produces for a file it
      // could not open when it does not throw outright. Under the old rule this
      // alone was enough for "Do not trust this binary".
      shell.powershell = "QUERIED=1\r\nSTATUS=UnknownError\r\nSUBJECT=";
      const denied = denyStat({ [path.join(dir, "aicommander-priv-helper.exe")]: "EACCES" });
      try {
        const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
        expect(sig.verdict).toBe("warn");
        expect(sig.detail).toMatch(/could not be determined/);
        expect(sig.detail).toContain("EACCES");
        expect(sig.detail).not.toMatch(/Do not trust|is UnknownError/);
        expect(sig.remedy).not.toMatch(/Do not trust/);
        expect(sig.facts?.["code"]).toBe("EACCES");
      } finally {
        denied.mockRestore();
      }
    });

    it("says the same about a macOS binary it could not read", async () => {
      Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
      const dir = stageInstalledHelper();
      fs.writeFileSync(path.join(dir, "aicommander-priv-helper"), "mach-o");
      // codesign staged as VERIFYING, so nothing but the unreadable stat can
      // produce the verdict: the point is that the check leaves before it runs.
      shell.codesign = { verified: true, authority: "Developer ID Application: WEARFITS" };
      const denied = denyStat({ [path.join(dir, "aicommander-priv-helper")]: "EPERM" });
      try {
        const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
        expect(sig.verdict).toBe("warn");
        expect(sig.detail).toMatch(/could not be determined/);
        expect(sig.detail).toContain("EPERM");
        expect(sig.detail).not.toMatch(/verifies/);
        expect(sig.remedy).toMatch(/Inspect it by hand/);
        expect(sig.facts?.["code"]).toBe("EPERM");
      } finally {
        denied.mockRestore();
        Object.defineProperty(process, "platform", { value: "win32", configurable: true });
      }
    });

    // The macOS half of the same defect: the LaunchDaemon plist.
    describe("the LaunchDaemon plist", () => {
      let realGetuid: typeof process.getuid;

      beforeEach(() => {
        Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
        helperEnv.plist = path.join(tmp, "dev.aicommander.privhelper.plist");
        fs.writeFileSync(helperEnv.plist, "<plist/>\n");
        stageInstalledHelper();
        realGetuid = process.getuid;
        Object.defineProperty(process, "getuid", { value: () => 501, configurable: true });
      });

      afterEach(() => {
        Object.defineProperty(process, "platform", { value: "win32", configurable: true });
        Object.defineProperty(process, "getuid", { value: realGetuid, configurable: true });
      });

      it("does not say the plist 'is not there' when it could not be read", async () => {
        shell.launchctl = { kind: "failed", stdout: "", code: 1, signal: null };
        const denied = denyStat({ [helperEnv.plist!]: "EACCES" });
        try {
          const registered = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
          expect(registered.verdict).toBe("warn");
          expect(registered.detail).toMatch(/could not be determined/);
          expect(registered.detail).toMatch(/UNKNOWN, not missing/);
          expect(registered.detail).toContain("EACCES");
          expect(registered.detail).not.toMatch(/is not there/);
          expect(registered.remedy).not.toMatch(/Re-install with the \.pkg/);
          expect(registered.remedy).toMatch(/Inspect it by hand/);
        } finally {
          denied.mockRestore();
        }
      });

      it("lets launchd settle it: a daemon it reports LOADED is registered, unreadable plist or not", async () => {
        shell.launchctl = { kind: "output", stdout: "state = running\n" };
        const denied = denyStat({ [helperEnv.plist!]: "EPERM" });
        try {
          const registered = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
          expect(registered.verdict).toBe("ok");
          expect(registered.detail).toMatch(/is loaded/);
        } finally {
          denied.mockRestore();
        }
      });

      it("lets root launchd settle NOT LOADED even when the plist is unreadable", async () => {
        Object.defineProperty(process, "getuid", { value: () => 0, configurable: true });
        shell.launchctl = { kind: "failed", stdout: "", code: 113, signal: null };
        const denied = denyStat({ [helperEnv.plist!]: "EPERM" });
        try {
          const registered = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
          expect(registered.verdict).toBe("fail");
          expect(registered.detail).toMatch(/could not be inspected .*EPERM/);
          expect(registered.detail).toMatch(/does not have .* loaded/);
          expect(registered.detail).not.toMatch(/plist .* is installed/);
          expect(registered.facts?.["loaded"]).toBe(false);
          expect(registered.facts?.["root"]).toBe(true);
        } finally {
          denied.mockRestore();
        }
      });

      it("still FAILS a plist the OS positively says is not there", async () => {
        shell.launchctl = { kind: "failed", stdout: "", code: 1, signal: null };
        const denied = denyStat({ [helperEnv.plist!]: "ENOENT" });
        try {
          const registered = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
          expect(registered.verdict).toBe("fail");
          expect(registered.detail).toMatch(/is not there/);
        } finally {
          denied.mockRestore();
        }
      });
    });
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
    //
    // THE REFUSAL IS NOT ONE OF THEM, and this is what the assertions below pin.
    // Only `$folder.GetTask(<name>)` can produce DENIED=1, so a denial PROVES the
    // named task exists; reporting it under the shared "could not be determined"
    // opening — which is what this test used to accept — withheld a fact the same
    // detail then asserted, and said the opposite of what persistence.ts says
    // about the very same marker.
    stageInstalledHelper();
    shell.powershell = "QUERIED=1\r\nADMIN=0\r\nDENIED=1";
    const denied = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
    // A warn, not `ok` and not `skipped`: registration is answered, but the
    // refusal withheld the task's state and the program it starts.
    expect(denied.verdict).toBe("warn");
    expect(denied.detail).toMatch(/IS registered/);
    expect(denied.detail).not.toMatch(/could not be determined/);
    // THE SHARED CLAUSE, verbatim from the module that measures it. Both this
    // check and persistence.ts assert it, so rewording either one alone — the
    // drift that produced the contradictory pair — fails a test.
    expect(denied.detail).toContain(windows.DENIAL_PROVES_TASK_EXISTS);
    expect(denied.remedy).toMatch(/elevated prompt/);

    shell.powershell = "QUERIED=1\r\nLOOKUPFAIL=ComConnect";
    const broke = verdicts(await helper.privHelperChecks.run(ctx()))["helper.registered"]!;
    expect(broke.verdict).toBe("skipped");
    expect(broke.detail).toMatch(/could not be determined/);
    expect(broke.detail).toMatch(/nothing was learned about the task/i);
    expect(broke.detail).not.toMatch(/cannot read this task's ACL/);
    // Elevation answers a refusal, and nothing else — a broken lookup never
    // reached the task, so the remedy may not send the reader to a prompt.
    expect(broke.detail).not.toMatch(/elevated/i);
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

  // ── THE OVER-CORRECTION GUARD ─────────────────────────────────────────────
  //
  // Softening the unreadable case must not soften the case the check exists
  // for. These are findings about the BYTES ON DISK — a replaced, unsigned or
  // re-hashed helper — and every one of them stays a loud failure that says so.
  it("keeps shouting about a signature Windows positively says is bad", async () => {
    stageInstalledHelper();
    for (const status of ["NotSigned", "HashMismatch", "NotTrusted", "NotSupportedFileFormat"]) {
      shell.powershell = `STATE=Running\r\nSTATUS=${status}\r\nSUBJECT=`;
      const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
      expect(sig.verdict, status).toBe("fail");
      expect(sig.detail, status).toContain(status);
      expect(sig.remedy, status).toMatch(/Do not trust this binary/);
    }
  });

  it("fails UnknownError as unverified without claiming the binary was tampered with", async () => {
    stageInstalledHelper();
    shell.powershell = "STATE=Running\r\nSTATUS=UnknownError\r\nSUBJECT=";
    const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
    expect(sig.verdict).toBe("fail");
    expect(sig.detail).toMatch(/signature could not be confirmed/);
    expect(sig.detail).not.toMatch(/tampered|malicious|corrupt/i);
    expect(sig.remedy).toMatch(/Treat the helper as unverified/);
    expect(sig.remedy).not.toMatch(/Nothing here says/);
  });

  // These statuses describe an evaluation that did not complete.
  it("does not read 'the check did not complete' as a tamper verdict", async () => {
    stageInstalledHelper();
    for (const status of ["Incompatible"]) {
      shell.powershell = `STATE=Running\r\nSTATUS=${status}\r\nSUBJECT=`;
      const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
      expect(sig.verdict, status).toBe("warn");
      expect(sig.detail, status).toMatch(/could not be determined/);
      expect(sig.remedy, status).not.toMatch(/Do not trust/);
      expect(sig.facts?.["status"], status).toBe(status);
    }
    // And output with no STATUS line at all: the missing value used to be
    // printed back as the status ("the signature is unknown") and failed on.
    shell.powershell = "STATE=Running\r\nSUBJECT=CN=Whoever";
    const unparsed = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
    expect(unparsed.verdict).toBe("warn");
    expect(unparsed.facts?.["status"]).toBe("unreadable");
  });

  // ── macOS, where the verdicts are quieter but the rule is the same ────────
  describe("the macOS signature", () => {
    beforeEach(() => {
      Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
      const dir = stageInstalledHelper();
      fs.writeFileSync(path.join(dir, "aicommander-priv-helper"), "mach-o");
    });

    afterEach(() => {
      Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    });

    it("reports a signature codesign verifies, and names the authority", async () => {
      shell.codesign = { verified: true, authority: "Developer ID Application: WEARFITS sp. z o.o." };
      const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
      expect(sig.verdict).toBe("ok");
      expect(sig.detail).toMatch(/verifies/);
      expect(sig.facts?.["authority"]).toBe("Developer ID Application: WEARFITS sp. z o.o.");
    });

    it("warns — and does not accuse — when codesign read the file and would not vouch for it", async () => {
      // codesign that opened the file and disliked it exits exactly like
      // codesign that could not open it, so this branch cannot tell them apart
      // and must not pretend to. It says "could not be verified", which is true
      // of both, and never tells anyone the binary is untrustworthy. The
      // discrimination lives in the caller (the unreadable-stat test above).
      shell.codesign = { verified: false, authority: "" };
      const sig = verdicts(await helper.privHelperChecks.run(ctx()))["helper.signature"]!;
      expect(sig.verdict).toBe("warn");
      expect(sig.detail).toMatch(/could not be verified/);
      expect(sig.remedy).not.toMatch(/Do not trust/);
      expect(sig.facts?.["authority"]).toBeNull();
    });
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
