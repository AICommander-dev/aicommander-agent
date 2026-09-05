import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";

// install writes the systemd unit and (re)starts the service as ROOT, so it is
// security-relevant. We mock node:fs + systemctl + state + ui so nothing touches
// the real system, and assert: the non-Linux guard, server-URL validation, that
// ExecStart is double-quoted, the unit directives, the restart-failure fallback,
// and that success requires the unit to be active.
vi.mock("node:fs", () => ({
  default: {
    realpathSync: vi.fn((p: string) => p),
    mkdirSync: vi.fn(),
    chmodSync: vi.fn(),
    writeFileSync: vi.fn(),
    existsSync: vi.fn(() => true),
  },
}));

// ensureSecureExecUser() shells out to getent/useradd. Mock node:child_process so
// the install test never touches the real system. Default: getent SUCCEEDS, so the
// sandbox user reads as "already present" and useradd is never invoked.
vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(() => ""),
}));

vi.mock("../ctl/systemctl.js", () => ({
  daemonReload: vi.fn(),
  systemctlEnable: vi.fn(),
  systemctlRestart: vi.fn(),
  systemctlStop: vi.fn(),
  systemctlKill: vi.fn(),
  systemctlStart: vi.fn(),
  systemctlActiveState: vi.fn(() => "active"),
  systemdManagerAvailable: vi.fn(() => true),
}));

// A canonical, VALID session code (alphabet excludes O/I/L/U) so the real
// maskSessionCode() actually masks it — masking is a no-op on invalid formats.
const MOCK_SESSION_CODE = "AIC-7K3P-WX9M-RTBN";
const MOCK_SESSION_CODE_MASKED = "AIC-7K3P-***-***";

vi.mock("../state.js", () => ({
  // Resolve a session code immediately so the poll loop exits on the first pass.
  readState: vi.fn(async () => ({
    sessionCode: "AIC-7K3P-WX9M-RTBN",
    pid: 1,
    startedAt: "2026-06-20T00:00:00.000Z",
    serverUrl: "https://aicommander.dev",
  })),
}));

vi.mock("../ctl/ui.js", () => ({
  requireRoot: vi.fn(),
  ui: {
    header: vi.fn(),
    ok: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    step: vi.fn(),
    blank: vi.fn(),
  },
}));

import fs from "node:fs";
import {
  daemonReload,
  systemctlEnable,
  systemctlRestart,
  systemctlStop,
  systemctlKill,
  systemctlStart,
  systemctlActiveState,
  systemdManagerAvailable,
} from "../ctl/systemctl.js";
import { ui, requireRoot } from "../ctl/ui.js";
import { execFileSync } from "node:child_process";
import { cmdInstall } from "../ctl/commands/install.js";

const SERVICE_FILE = "/etc/systemd/system/aicommander-agent.service";

// process.exit is mocked to THROW (not no-op) so it halts execution exactly like
// the real thing — otherwise a validation/guard "exit" would fall through and run
// the rest of install. Tests that expect an exit catch the sentinel.
class ProcessExit extends Error {
  constructor(public code?: number | string | null) {
    super(`process.exit(${code})`);
  }
}

let exitSpy: MockInstance<typeof process.exit>;
let platformSpy: MockInstance;
const origArgv1 = process.argv[1];

/** Run cmdInstall, swallowing the ProcessExit sentinel so assertions can run. */
async function runInstall(opts: { server?: string }): Promise<void> {
  try {
    await cmdInstall(opts);
  } catch (err) {
    if (!(err instanceof ProcessExit)) throw err;
  }
}

/** The unit text passed to fs.writeFileSync(SERVICE_FILE, …). */
function writtenUnit(): string {
  const call = vi
    .mocked(fs.writeFileSync)
    .mock.calls.find((c) => c[0] === SERVICE_FILE);
  return call ? String(call[1]) : "";
}

/** The ExecStart value rendered into the unit. */
function execStartLine(): string {
  return writtenUnit()
    .split("\n")
    .find((l) => l.startsWith("ExecStart=")) ?? "";
}

beforeEach(() => {
  vi.clearAllMocks();
  exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
    throw new ProcessExit(code);
  }) as never);
  // Pretend we're on Linux with a known script path + node binary.
  platformSpy = vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  process.argv[1] = "/opt/aic/agent.js";
  vi.mocked(systemctlActiveState).mockReturnValue("active");
  vi.mocked(systemdManagerAvailable).mockReturnValue(true);
  delete process.env["AICOMMANDER_SERVER"];
});

afterEach(() => {
  vi.restoreAllMocks();
  platformSpy.mockRestore();
  process.argv[1] = origArgv1;
});

describe("cmdInstall — guards & validation", () => {
  it("requires root", async () => {
    await runInstall({});
    expect(vi.mocked(requireRoot)).toHaveBeenCalled();
  });

  it("exits non-zero on a non-Linux platform", async () => {
    platformSpy.mockReturnValue("darwin");
    await runInstall({});
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
    // Must not write the unit on an unsupported platform.
    expect(vi.mocked(fs.writeFileSync)).not.toHaveBeenCalled();
  });

  it("fails before every install side effect when no systemd manager is reachable", async () => {
    vi.mocked(systemdManagerAvailable).mockReturnValue(false);

    await runInstall({});

    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(vi.mocked(fs.mkdirSync)).not.toHaveBeenCalled();
    expect(vi.mocked(fs.chmodSync)).not.toHaveBeenCalled();
    expect(vi.mocked(fs.writeFileSync)).not.toHaveBeenCalled();
    expect(vi.mocked(execFileSync)).not.toHaveBeenCalled();
    expect(vi.mocked(daemonReload)).not.toHaveBeenCalled();
    expect(vi.mocked(systemctlEnable)).not.toHaveBeenCalled();
    expect(vi.mocked(systemctlRestart)).not.toHaveBeenCalled();
    expect(vi.mocked(systemctlStop)).not.toHaveBeenCalled();
    expect(vi.mocked(systemctlKill)).not.toHaveBeenCalled();
    expect(vi.mocked(systemctlStart)).not.toHaveBeenCalled();

    const output = [
      ...vi.mocked(ui.error).mock.calls,
      ...vi.mocked(ui.step).mock.calls,
    ].flat().join("\n");
    expect(output).toMatch(/No service was installed/i);
    expect(output).toContain("aicommander-agent run");
    expect(output).toMatch(/only until.*process or terminal closes/i);
    expect(output).toMatch(/init\/process manager|platform autostart/i);
  });

  it("rejects a server URL containing a newline (unit-injection vector)", async () => {
    await runInstall({ server: "https://evil\nEnvironment=FOO=bar" });
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("rejects a non-http(s) scheme", async () => {
    await runInstall({ server: "file:///etc/passwd" });
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("rejects a non-URL value", async () => {
    await runInstall({ server: "not a url" });
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("accepts a valid https URL and bakes it into the Environment line", async () => {
    await runInstall({ server: "https://relay.example.com" });
    expect(writtenUnit()).toContain("Environment=AICOMMANDER_SERVER=https://relay.example.com");
    // A valid input never triggers a validation exit.
    expect(exitSpy).not.toHaveBeenCalled();
  });
});

describe("cmdInstall — secure-exec sandbox user", () => {
  it("is treated as present when getent succeeds (no useradd)", async () => {
    vi.mocked(execFileSync).mockReturnValue("");
    await runInstall({});
    const calledUseradd = vi
      .mocked(execFileSync)
      .mock.calls.some((c) => c[0] === "useradd");
    expect(calledUseradd).toBe(false);
    expect(vi.mocked(ui.warn)).toHaveBeenCalledWith(
      expect.stringMatching(/permissions and groups were preserved.*runtime group check/i),
    );
  });

  it("creates a group-free system user and secures its home to 0700", async () => {
    let passwdLookups = 0;
    vi.mocked(execFileSync).mockImplementation(((cmd: string) => {
      if (cmd === "getent" && passwdLookups++ === 0) throw new Error("not found");
      if (cmd === "getent") {
        return "aicommander-exec:x:999:999::/home/aicommander-exec:/usr/sbin/nologin\n";
      }
      return "";
    }) as never);
    await runInstall({});
    const useraddCall = vi
      .mocked(execFileSync)
      .mock.calls.find((c) => c[0] === "useradd");
    expect(useraddCall).toBeDefined();
    const args = useraddCall![1] as string[];
    expect(args).toContain("--system");
    expect(args).toContain("aicommander-exec");
    expect(args).not.toContain("--groups");
    expect(args).not.toContain("-G");
    expect(vi.mocked(fs.chmodSync)).toHaveBeenCalledWith(
      "/home/aicommander-exec",
      0o700,
    );
  });
});

describe("cmdInstall — unit text", () => {
  it("quotes both ExecStart paths (handles spaces)", async () => {
    process.argv[1] = "/opt/with space/agent.js";
    vi.mocked(fs.realpathSync).mockReturnValue("/opt/with space/agent.js" as never);
    const origExec = process.execPath;
    Object.defineProperty(process, "execPath", { value: "/usr/bin/node", configurable: true });
    try {
      await runInstall({});
      const line = execStartLine();
      // Format: ExecStart="…/node" "…/agent.js" run
      expect(line).toContain('"/usr/bin/node"');
      expect(line).toContain('"/opt/with space/agent.js"');
      expect(line.endsWith('" run')).toBe(true);
    } finally {
      Object.defineProperty(process, "execPath", { value: origExec, configurable: true });
    }
  });

  it("contains the expected systemd directives", async () => {
    await runInstall({ server: "https://aicommander.dev" });
    const unit = writtenUnit();
    expect(unit).toContain("RuntimeDirectory=aicommander-agent");
    expect(unit).toContain("Restart=always");
    expect(unit).toContain("KillSignal=SIGINT");
    expect(unit).toContain("WantedBy=multi-user.target");
    expect(unit).toContain("Environment=AICOMMANDER_SERVER=https://aicommander.dev");
    expect(unit).toContain("Environment=AICOMMANDER_SERVICE=1");
    expect(unit).toContain("Environment=NODE_ENV=production");
  });

  it("escapes `%` in the server URL (systemd specifier escape)", async () => {
    // systemd treats `%` as a specifier introducer; a literal `%` in the URL
    // (e.g. percent-encoded path) must be doubled to `%%` so it is passed
    // through verbatim and does not inject/expand a specifier.
    await runInstall({ server: "https://relay.example.com/a%20b?x=%25" });
    const unit = writtenUnit();
    expect(unit).toContain(
      "Environment=AICOMMANDER_SERVER=https://relay.example.com/a%%20b?x=%%25",
    );
    // No single (unescaped) `%` survives on the Environment line.
    const envLine = unit.split("\n").find((l) => l.startsWith("Environment=")) ?? "";
    expect(envLine.replace(/%%/g, "")).not.toContain("%");
  });

  it("escapes `%` in an ExecStart path (systemd specifier escape)", async () => {
    process.argv[1] = "/opt/aic%dir/agent.js";
    vi.mocked(fs.realpathSync).mockReturnValue("/opt/aic%dir/agent.js" as never);
    const origExec = process.execPath;
    Object.defineProperty(process, "execPath", { value: "/usr/bin/node", configurable: true });
    try {
      await runInstall({});
      const line = execStartLine();
      expect(line).toContain('"/opt/aic%%dir/agent.js"');
      // The path's `%` must be doubled — no lone `%` remains in the line.
      expect(line.replace(/%%/g, "")).not.toContain("%");
    } finally {
      Object.defineProperty(process, "execPath", { value: origExec, configurable: true });
    }
  });
});

describe("cmdInstall — session code output", () => {
  // The install flow polls agent state for the live session code, which is a
  // root-exec credential. In this service/log context the success banner MUST
  // print the MASKED code (AIC-XXXX-***-***), never the full value.
  it("prints the session code MASKED, never in full", async () => {
    await runInstall({});
    const infoCalls = vi.mocked(ui.info).mock.calls;
    const sessionInfo = infoCalls.find((c) => String(c[0]) === "Session code");
    expect(sessionInfo).toBeDefined();
    // chalk may wrap the value in ANSI; strip color codes before asserting.
    // eslint-disable-next-line no-control-regex
    const printed = String(sessionInfo![1]).replace(/\[[0-9;]*m/g, "");
    // The mocked state resolves AIC-7K3P-WX9M-RTBN to masked AIC-7K3P-***-***.
    expect(printed).toContain(MOCK_SESSION_CODE_MASKED);
    expect(printed).not.toContain("WX9M");
    expect(printed).not.toContain("RTBN");

    // Defensively scan EVERY string sent to any ui.* method — the full code must
    // not appear anywhere in the install output.
    const allOutput = [
      ...vi.mocked(ui.info).mock.calls,
      ...vi.mocked(ui.ok).mock.calls,
      ...vi.mocked(ui.step).mock.calls,
      ...vi.mocked(ui.warn).mock.calls,
    ]
      .flat()
      .map((a) => String(a))
      .join("\n");
    expect(allOutput).not.toContain(MOCK_SESSION_CODE);
  });
});

describe("cmdInstall — (re)start robustness", () => {
  it("falls back to stop ? kill ? start when graceful restart fails", async () => {
    vi.mocked(systemctlRestart).mockImplementation(() => {
      throw new Error("restart failed");
    });
    await runInstall({});
    expect(vi.mocked(systemctlStop)).toHaveBeenCalled();
    expect(vi.mocked(systemctlKill)).toHaveBeenCalled();
    expect(vi.mocked(systemctlStart)).toHaveBeenCalled();
    // is-active reports active ? success, no error exit.
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("exits non-zero when the fallback start also fails", async () => {
    vi.mocked(systemctlRestart).mockImplementation(() => {
      throw new Error("restart failed");
    });
    vi.mocked(systemctlStart).mockImplementation(() => {
      throw new Error("start failed");
    });
    await runInstall({});
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("exits non-zero when the unit is not active after (re)start", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue("failed");
    await runInstall({});
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("reports success when the unit is active", async () => {
    await runInstall({});
    expect(vi.mocked(daemonReload)).toHaveBeenCalled();
    expect(vi.mocked(systemctlEnable)).toHaveBeenCalled();
    expect(vi.mocked(systemctlRestart)).toHaveBeenCalled();
    expect(vi.mocked(ui.ok)).toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
  });
});
