import { describe, it, expect, afterEach, vi } from "vitest";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  INSTALLED_VERSION_TIMEOUT_MS,
  installedVersionSnapshot,
  isJsRuntimeExecutable,
  macBundleInfoPlistPaths,
  parseBundleIdentifier,
  parseBundleShortVersion,
  powerShellSingleQuote,
  probeBinaryInstalledVersion,
  probeMacInstalledVersion,
  probeWindowsInstalledVersion,
  resetInstalledVersionForTest,
  runCapture,
  sanitizeInstalledVersion,
  startInstalledVersionProbe,
} from "../installed-version.js";

// The spawn boundary, kept REAL by default (the runCapture and Linux-probe tests
// below want a genuine child process) and overridable for the Windows probe,
// whose PowerShell obviously cannot run here. An ESM namespace cannot be spied
// on, hence the module mock rather than vi.spyOn.
const spawnHook = vi.hoisted(() => ({
  override: null as null | ((command: string, args: string[]) => unknown),
  calls: [] as Array<[string, string[]]>,
}));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (command: string, args: string[], options: unknown) => {
      spawnHook.calls.push([command, args]);
      return spawnHook.override
        ? spawnHook.override(command, args)
        : (actual.spawn as unknown as (c: string, a: string[], o: unknown) => unknown)(command, args, options);
    },
  };
});

// What is on DISK vs what is RUNNING. The probe's whole contract is that it is
// allowed to know nothing: a missing bundle, a bundle that is not ours, an
// unreadable plist or output that does not look like a version must produce
// `undefined` — never an exception on the registration path, and never a number
// the relay would then publish as a mismatch. So most of this suite is failure
// modes, plus the lifecycle: the disk is re-read on EVERY connect, because the
// swap this feature exists to catch happens after the first one.

const APP_BUNDLE_ID = "dev.aicommander.desktop";
const isWindows = process.platform === "win32";
const itOnPosix = it.skipIf(isWindows);

const created: string[] = [];

/** A throwaway .app bundle with the given Info.plist body (or none at all). */
function makeBundle(plist: string | null, bundleName = "AI Commander.app"): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aic-bundle-"));
  created.push(root);
  const macos = path.join(root, bundleName, "Contents", "MacOS");
  fs.mkdirSync(macos, { recursive: true });
  const exe = path.join(macos, "AI Commander");
  fs.writeFileSync(exe, "");
  if (plist !== null) {
    fs.writeFileSync(path.join(root, bundleName, "Contents", "Info.plist"), plist);
  }
  return exe;
}

function plistWith(version: string, bundleId: string = APP_BUNDLE_ID): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<plist version="1.0">\n<dict>\n' +
    "  <key>CFBundleName</key>\n  <string>AI Commander</string>\n" +
    `  <key>CFBundleIdentifier</key>\n  <string>${bundleId}</string>\n` +
    `  <key>CFBundleShortVersionString</key>\n  <string>${version}</string>\n` +
    "  <key>CFBundleVersion</key>\n  <string>99</string>\n" +
    "</dict>\n</plist>\n"
  );
}

/** An executable script that prints `text` and exits 0. POSIX only. */
function makeScript(body: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "aic-probe-"));
  created.push(root);
  const script = path.join(root, "aicommander-agent");
  fs.writeFileSync(script, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  return script;
}

/** Swap `process.platform` / `process.execPath` for one test. */
function stubProcess(platform: string, execPath: string): () => void {
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const originalExecPath = process.execPath;
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  process.execPath = execPath;
  return () => {
    Object.defineProperty(process, "platform", platformDescriptor);
    process.execPath = originalExecPath;
  };
}

afterEach(() => {
  while (created.length > 0) {
    fs.rmSync(created.pop()!, { recursive: true, force: true });
  }
  resetInstalledVersionForTest();
});

describe("macBundleInfoPlistPaths", () => {
  it("returns every enclosing .app, innermost first", () => {
    expect(macBundleInfoPlistPaths("/Applications/AI Commander.app/Contents/MacOS/AI Commander")).toEqual([
      "/Applications/AI Commander.app/Contents/Info.plist",
    ]);
    // A nested helper must not hide the app that encloses it — the caller needs
    // the whole chain to find the bundle the installer actually wrote.
    expect(
      macBundleInfoPlistPaths("/Applications/AI Commander.app/Contents/Frameworks/Helper.app/Contents/MacOS/h"),
    ).toEqual([
      "/Applications/AI Commander.app/Contents/Frameworks/Helper.app/Contents/Info.plist",
      "/Applications/AI Commander.app/Contents/Info.plist",
    ]);
  });

  it("returns nothing for an executable that is not inside a bundle", () => {
    expect(macBundleInfoPlistPaths("/usr/local/bin/aicommander-agent")).toEqual([]);
    expect(macBundleInfoPlistPaths("/usr/local/bin/node")).toEqual([]);
  });
});

describe("sanitizeInstalledVersion", () => {
  it("accepts a version, with or without a leading v", () => {
    expect(sanitizeInstalledVersion("1.1.0")).toBe("1.1.0");
    expect(sanitizeInstalledVersion(" v1.0.56\n")).toBe("1.0.56");
    expect(sanitizeInstalledVersion("1.2.0-beta.3")).toBe("1.2.0-beta.3");
  });

  it("drops the zero fourth component Windows version resources always carry", () => {
    // Otherwise every healthy Windows machine reports "1.1.0.0" installed against
    // a running "1.1.0" and the relay cries mismatch on all of them.
    expect(sanitizeInstalledVersion("1.1.0.0")).toBe("1.1.0");
    // A non-zero fourth component is a real difference and is kept.
    expect(sanitizeInstalledVersion("1.1.0.4")).toBe("1.1.0.4");
  });

  it("rejects anything that is not a version rather than reporting it", () => {
    for (const junk of ["", "AI Commander", "not a version", "1.1", "<html>", "1.1.0 (build 7)"]) {
      expect(sanitizeInstalledVersion(junk)).toBeUndefined();
    }
  });
});

describe("isJsRuntimeExecutable", () => {
  it("recognizes the npm install shape on both spellings of the executable", () => {
    expect(isJsRuntimeExecutable("/usr/bin/node")).toBe(true);
    // The Windows path used to skip this check entirely and reported node's own
    // ProductVersion (22.11.0) as the installed build — a permanent mismatch.
    expect(isJsRuntimeExecutable("C:\\Program Files\\nodejs\\node.exe")).toBe(true);
    expect(isJsRuntimeExecutable("C:\\Program Files\\nodejs\\NODE.EXE")).toBe(true);
    expect(isJsRuntimeExecutable("/opt/homebrew/bin/bun")).toBe(true);
    expect(isJsRuntimeExecutable("/usr/bin/deno")).toBe(true);
  });

  it("does not mistake our own binaries for a runtime", () => {
    expect(isJsRuntimeExecutable("/usr/local/bin/aicommander-agent")).toBe(false);
    expect(isJsRuntimeExecutable("C:\\Program Files\\AI Commander\\AI Commander.exe")).toBe(false);
  });
});

describe("parseBundleShortVersion", () => {
  it("reads CFBundleShortVersionString out of an XML Info.plist", () => {
    expect(parseBundleShortVersion(plistWith("1.1.0"))).toBe("1.1.0");
  });

  it("returns nothing for a binary plist, or a plist without the key", () => {
    expect(parseBundleShortVersion("bplist00\x00\x01garbage")).toBeUndefined();
    expect(parseBundleShortVersion("<plist><dict><key>CFBundleVersion</key><string>9</string></dict></plist>"))
      .toBeUndefined();
  });
});

describe("parseBundleIdentifier", () => {
  it("reads CFBundleIdentifier, or nothing when it is absent", () => {
    expect(parseBundleIdentifier(plistWith("1.1.0"))).toBe(APP_BUNDLE_ID);
    expect(parseBundleIdentifier(plistWith("39.8.10", "com.github.Electron"))).toBe("com.github.Electron");
    expect(parseBundleIdentifier("<plist><dict></dict></plist>")).toBeUndefined();
  });
});

describe("probeMacInstalledVersion", () => {
  it("reports the bundle version of the .app the executable runs from", () => {
    expect(probeMacInstalledVersion(makeBundle(plistWith("1.1.0")))).toBe("1.1.0");
  });

  it("ignores a bundle that is not ours, so a dev run reports nothing", () => {
    // `pnpm dev` runs packages/desktop/node_modules/electron/dist/Electron.app,
    // whose CFBundleShortVersionString is Electron's own. Reporting it would show
    // a loud "an update landed and the app was never restarted" on every
    // developer machine that no restart could ever clear.
    const exe = makeBundle(plistWith("39.8.10", "com.github.Electron"), "Electron.app");
    expect(probeMacInstalledVersion(exe)).toBeUndefined();
  });

  it("skips a nested helper bundle and reports the app that encloses it", () => {
    const exe = makeBundle(plistWith("1.1.0"));
    const contents = path.dirname(path.dirname(exe));
    const helperMacos = path.join(contents, "Frameworks", "AI Commander Helper.app", "Contents", "MacOS");
    fs.mkdirSync(helperMacos, { recursive: true });
    fs.writeFileSync(
      path.join(path.dirname(helperMacos), "Info.plist"),
      plistWith("39.8.10", `${APP_BUNDLE_ID}.helper`),
    );
    const helperExe = path.join(helperMacos, "AI Commander Helper");
    fs.writeFileSync(helperExe, "");
    expect(probeMacInstalledVersion(helperExe)).toBe("1.1.0");
  });

  it("returns nothing — and does not throw — when the plist is missing", () => {
    const exe = makeBundle(null);
    expect(() => probeMacInstalledVersion(exe)).not.toThrow();
    expect(probeMacInstalledVersion(exe)).toBeUndefined();
  });

  it("returns nothing — and does not throw — for a path that does not exist at all", () => {
    const missing = "/nonexistent-aic/AI Commander.app/Contents/MacOS/AI Commander";
    expect(() => probeMacInstalledVersion(missing)).not.toThrow();
    expect(probeMacInstalledVersion(missing)).toBeUndefined();
  });

  it("returns nothing when the plist is unreadable", () => {
    const exe = makeBundle(plistWith("1.1.0"));
    const plist = path.join(path.dirname(path.dirname(exe)), "Info.plist");
    // Reading a DIRECTORY as a file is the portable stand-in for "unreadable":
    // chmod 000 does not stop root, and CI runs as root often enough.
    fs.rmSync(plist);
    fs.mkdirSync(plist);
    expect(() => probeMacInstalledVersion(exe)).not.toThrow();
    expect(probeMacInstalledVersion(exe)).toBeUndefined();
  });

  it("returns nothing when the executable is not in a bundle", () => {
    expect(probeMacInstalledVersion("/usr/local/bin/aicommander-agent")).toBeUndefined();
  });
});

describe("powerShellSingleQuote", () => {
  it("keeps every PowerShell metacharacter literal", () => {
    // The bug this replaced: JSON.stringify inside a DOUBLE-quoted PowerShell
    // string doubles every backslash and lets `$`/backtick expand — a path with
    // `$(...)` in it would have been EVALUATED by the probe.
    expect(powerShellSingleQuote("C:\\Program Files\\AI Commander\\AI Commander.exe")).toBe(
      "'C:\\Program Files\\AI Commander\\AI Commander.exe'",
    );
    expect(powerShellSingleQuote("C:\\apps\\$(calc)\\AI Commander.exe")).toBe(
      "'C:\\apps\\$(calc)\\AI Commander.exe'",
    );
    expect(powerShellSingleQuote("C:\\a`b\\c$d\\app.exe")).toBe("'C:\\a`b\\c$d\\app.exe'");
  });

  it("closes the quote hole by doubling an embedded single quote", () => {
    expect(powerShellSingleQuote("C:\\Lukasz's Apps\\app.exe")).toBe("'C:\\Lukasz''s Apps\\app.exe'");
  });
});

describe("probeWindowsInstalledVersion", () => {
  // The probe itself only ever runs on Windows, so the PowerShell process is
  // faked here: the branch under test is ours (how the command is built and how
  // its output is read), not what FileVersionInfo does. What stays runtime-only
  // is exactly one thing — whether PowerShell's own parser accepts the quoted
  // path and whether the version resource really carries ProductVersion; that
  // needs a Windows box with an installed exe and cannot be asserted here.
  const WIN_EXE = "C:\\Program Files\\AI Commander\\AI Commander.exe";

  /** Stand in for powershell.exe: emit `stdout`, then exit with `code`. */
  function mockPowerShell(stdout: string, code = 0): void {
    spawnHook.calls.length = 0;
    spawnHook.override = () => {
      const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; kill: () => void };
      child.stdout = new EventEmitter();
      child.kill = () => {};
      process.nextTick(() => {
        if (stdout !== "") child.stdout.emit("data", Buffer.from(stdout, "utf8"));
        child.emit("close", code);
      });
      return child;
    };
  }

  afterEach(() => {
    spawnHook.override = null;
    spawnHook.calls.length = 0;
  });

  it("reports the ProductVersion PowerShell printed", async () => {
    mockPowerShell("1.1.0\r\n");
    await expect(probeWindowsInstalledVersion(WIN_EXE)).resolves.toBe("1.1.0");
  });

  it("normalizes the four-part form the Windows version resource always has", async () => {
    // electron-builder's "1.1.0" reads back as "1.1.0.0"; reporting it verbatim
    // would cry mismatch on every healthy Windows machine.
    mockPowerShell("1.1.0.0\r\n");
    await expect(probeWindowsInstalledVersion(WIN_EXE)).resolves.toBe("1.1.0");
  });

  it("hands PowerShell the execPath as a LITERAL single-quoted string", async () => {
    // Regression guard for the JSON.stringify bug: inside a double-quoted
    // PowerShell string the backslashes arrived doubled and `$(...)` would have
    // been EVALUATED.
    mockPowerShell("1.1.0\r\n");
    const hostile = "C:\\apps\\$(calc)\\Lukasz's App.exe";
    await probeWindowsInstalledVersion(hostile);
    const [command, args] = spawnHook.calls[0]!;
    expect(command).toBe("powershell.exe");
    const script = args[args.indexOf("-Command") + 1]!;
    expect(script).toContain(powerShellSingleQuote(hostile));
    expect(script).toContain("'C:\\apps\\$(calc)\\Lukasz''s App.exe'");
    expect(script).not.toContain('"');
  });

  it("reads only the first line, whatever else PowerShell decided to print", async () => {
    mockPowerShell("1.1.0.0\r\nsomething else\r\n");
    await expect(probeWindowsInstalledVersion(WIN_EXE)).resolves.toBe("1.1.0");
  });

  it("reports nothing rather than a bogus value for output that is not a version", async () => {
    for (const junk of ["", "   \r\n", "AI Commander 1.1\r\n", "GetVersionInfo : path not found\r\n"]) {
      mockPowerShell(junk);
      await expect(probeWindowsInstalledVersion(WIN_EXE)).resolves.toBeUndefined();
    }
  });

  it("reports nothing when PowerShell exits non-zero, output and all", async () => {
    mockPowerShell("1.1.0\r\n", 1);
    await expect(probeWindowsInstalledVersion(WIN_EXE)).resolves.toBeUndefined();
  });

  it("reports nothing for an npm-installed agent instead of node's own version", async () => {
    // No spawn happens at all — the guard is what keeps `npx @aicommander/agent`
    // on Windows from publishing "22.11.0" as the installed build forever.
    mockPowerShell("22.11.0\r\n");
    await expect(probeWindowsInstalledVersion("C:\\Program Files\\nodejs\\node.exe")).resolves.toBeUndefined();
    expect(spawnHook.calls).toEqual([]);
  });
});

describe("probeBinaryInstalledVersion", () => {
  itOnPosix("asks the binary on disk what it is", async () => {
    await expect(probeBinaryInstalledVersion(makeScript("echo v1.2.3"))).resolves.toBe("1.2.3");
  });

  itOnPosix("reports nothing when the binary prints something that is not a version", async () => {
    await expect(probeBinaryInstalledVersion(makeScript("echo 'AI Commander agent'"))).resolves.toBeUndefined();
  });

  itOnPosix("reports nothing when the binary fails", async () => {
    await expect(probeBinaryInstalledVersion(makeScript("echo 1.2.3; exit 3"))).resolves.toBeUndefined();
  });

  it("skips the JS runtime shape rather than reporting node's version", async () => {
    await expect(probeBinaryInstalledVersion("/usr/bin/node")).resolves.toBeUndefined();
  });

  it("reports nothing — and does not reject — when the binary is not there", async () => {
    await expect(probeBinaryInstalledVersion("/nonexistent-aic/agent")).resolves.toBeUndefined();
  });
});

describe("runCapture", () => {
  it("hands back an empty string when the command cannot be spawned", async () => {
    await expect(runCapture("/nonexistent-aic/nope", ["--version"])).resolves.toBe("");
  });

  itOnPosix("hands back an empty string for a non-zero exit, output and all", async () => {
    await expect(runCapture(makeScript("echo 1.2.3; exit 1"), [])).resolves.toBe("");
  });

  itOnPosix("stops accumulating output well before a flood becomes a payload", async () => {
    const out = await runCapture(makeScript("head -c 200000 /dev/zero | tr '\\0' 'x'"), []);
    // The cap is checked per chunk, so the tail of the chunk that crosses it is
    // kept — what matters is that 200 KB does not land in memory as a "version".
    expect(out.length).toBeLessThan(100_000);
    expect(out.length).toBeGreaterThan(0);
  });

  itOnPosix("kills a command that never finishes and reports nothing", async () => {
    vi.useFakeTimers();
    try {
      const pending = runCapture(makeScript("sleep 300"), []);
      await vi.advanceTimersByTimeAsync(INSTALLED_VERSION_TIMEOUT_MS);
      await expect(pending).resolves.toBe("");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("the probe lifecycle", () => {
  it("knows nothing until a probe has finished", () => {
    expect(installedVersionSnapshot()).toBeUndefined();
  });

  it("re-reads the disk on EVERY connect, so a swap under a live process shows up", async () => {
    // The entire reason this file exists: the pkg upgrade replaces the .app while
    // this process keeps serving the relay. A value memoized for the process
    // lifetime would re-register 1.0.56 forever and prove the machine healthy.
    const exe = makeBundle(plistWith("1.0.56"));
    const restore = stubProcess("darwin", exe);
    try {
      await startInstalledVersionProbe();
      expect(installedVersionSnapshot()).toBe("1.0.56");

      fs.writeFileSync(path.join(path.dirname(path.dirname(exe)), "Info.plist"), plistWith("1.1.0"));
      await startInstalledVersionProbe();
      expect(installedVersionSnapshot()).toBe("1.1.0");
    } finally {
      restore();
    }
  });

  it("resolves synchronously on macOS, so the first register frame carries it", () => {
    const restore = stubProcess("darwin", makeBundle(plistWith("1.1.0")));
    try {
      // Not awaited — this is exactly what connection.ts does before the ticket
      // round trip, and the register frame reads the snapshot moments later.
      void startInstalledVersionProbe();
      expect(installedVersionSnapshot()).toBe("1.1.0");
    } finally {
      restore();
    }
  });

  it("forgets a version once the app it read is gone", async () => {
    const exe = makeBundle(plistWith("1.1.0"));
    const restore = stubProcess("darwin", exe);
    try {
      await startInstalledVersionProbe();
      expect(installedVersionSnapshot()).toBe("1.1.0");
      fs.rmSync(path.join(path.dirname(path.dirname(exe)), "Info.plist"));
      await startInstalledVersionProbe();
      expect(installedVersionSnapshot()).toBeUndefined();
    } finally {
      restore();
    }
  });

  itOnPosix("lets the newest probe win, not the last one to come back", async () => {
    // Reconnects overlap: a slow probe from the previous connect must not
    // overwrite the fresher reading with the pre-upgrade number.
    const slow = stubProcess("linux", makeScript("sleep 1; echo 1.0.56"));
    const slowProbe = startInstalledVersionProbe();
    slow();
    const fast = stubProcess("linux", makeScript("echo 1.1.0"));
    const fastProbe = startInstalledVersionProbe();
    fast();
    await Promise.all([slowProbe, fastProbe]);
    expect(installedVersionSnapshot()).toBe("1.1.0");
  }, 15_000);

  itOnPosix("never rejects, whatever the binary on disk does", async () => {
    const restore = stubProcess("linux", "/nonexistent-aic/agent");
    try {
      await expect(startInstalledVersionProbe()).resolves.toBeUndefined();
      expect(installedVersionSnapshot()).toBeUndefined();
    } finally {
      restore();
    }
  });

  it("forgets everything on reset", async () => {
    const restore = stubProcess("darwin", makeBundle(plistWith("1.1.0")));
    try {
      await startInstalledVersionProbe();
      expect(installedVersionSnapshot()).toBe("1.1.0");
    } finally {
      restore();
    }
    resetInstalledVersionForTest();
    expect(installedVersionSnapshot()).toBeUndefined();
  });
});
