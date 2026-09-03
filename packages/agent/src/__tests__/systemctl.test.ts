import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// systemctl.ts wraps `systemctl` via execFileSync. We mock node:child_process
// to assert the exact verbs/args passed and the read-back parsing logic.
vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
}));

import { execFileSync } from "node:child_process";
import * as systemctl from "../ctl/systemctl.js";

const SERVICE = "aicommander-agent";

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("systemctl action verbs", () => {
  const cases: Array<[() => void, string]> = [
    [systemctl.systemctlStart, "start"],
    [systemctl.systemctlStop, "stop"],
    [systemctl.systemctlEnable, "enable"],
    [systemctl.systemctlDisable, "disable"],
    [systemctl.systemctlRestart, "restart"],
  ];

  for (const [fn, verb] of cases) {
    it(`${verb} runs: systemctl ${verb} ${SERVICE}`, () => {
      fn();
      expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
        "systemctl",
        [verb, SERVICE],
        { stdio: "inherit" },
      );
    });
  }

  it("daemonReload runs: systemctl daemon-reload", () => {
    systemctl.daemonReload();
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["daemon-reload"],
      { stdio: "inherit" },
    );
  });
});

describe("systemdManagerAvailable", () => {
  it("returns true only when the live manager returns a non-empty version", () => {
    vi.mocked(execFileSync).mockReturnValue("255\n" as unknown as ReturnType<typeof execFileSync>);

    expect(systemctl.systemdManagerAvailable()).toBe(true);
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["show", "--property=Version", "--value"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
  });

  it("returns false for an empty manager response", () => {
    vi.mocked(execFileSync).mockReturnValue("  \n" as unknown as ReturnType<typeof execFileSync>);
    expect(systemctl.systemdManagerAvailable()).toBe(false);
  });

  it("returns false when systemctl exists but cannot reach a manager", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw Object.assign(new Error("System has not been booted with systemd"), {
        status: 1,
        stderr: "Failed to connect to bus: Host is down",
      });
    });
    expect(systemctl.systemdManagerAvailable()).toBe(false);
  });
});

describe("systemctlActiveState", () => {
  /** How execFileSync reports a command that RAN and exited non-zero. */
  function exitedNonZero(status: number, stdout: string | Buffer): Error {
    return Object.assign(new Error(`Command failed`), { status, stdout, stderr: "" });
  }

  /** How it reports a command that could not be spawned at all. */
  function spawnFailed(code: string): Error {
    return Object.assign(new Error(`spawnSync systemctl ${code}`), { code, syscall: "spawnSync" });
  }

  it("returns the trimmed is-active output", () => {
    vi.mocked(execFileSync).mockReturnValue("active\n" as unknown as ReturnType<typeof execFileSync>);
    expect(systemctl.systemctlActiveState()).toBe("active");
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["is-active", SERVICE],
      expect.objectContaining({ encoding: "utf8" }),
    );
  });

  // `is-active` exits 3 for these — a perfectly normal answer, not an error, so
  // the exit code must not be allowed to overrule the word on stdout.
  for (const state of ["inactive", "failed", "unknown"]) {
    it(`reads '${state}' back off a non-zero exit`, () => {
      vi.mocked(execFileSync).mockImplementation(() => {
        throw exitedNonZero(3, `${state}\n`);
      });
      expect(systemctl.systemctlActiveState()).toBe(state);
    });
  }

  // The regression: a unit that is still going down used to be reported as
  // "inactive", which uninstall reads as "verified stopped".
  it("reports 'deactivating' rather than collapsing it into 'inactive'", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw exitedNonZero(3, "deactivating\n");
    });
    expect(systemctl.systemctlActiveState()).toBe("deactivating");
  });

  it("reports 'activating' rather than collapsing it into 'inactive'", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw exitedNonZero(3, "activating\n");
    });
    expect(systemctl.systemctlActiveState()).toBe("activating");
  });

  it("decodes a Buffer stdout the same way", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw exitedNonZero(3, Buffer.from("deactivating\n"));
    });
    expect(systemctl.systemctlActiveState()).toBe("deactivating");
  });

  // No systemctl binary = no systemd = no unit. A definite answer — and only the
  // errnos that mean "this path names nothing at all" are one. Codes verified
  // against real spawnSync/execFileSync failures on this Node: a missing file and
  // a bare name absent from every PATH entry both give ENOENT; a non-directory in
  // the path prefix gives ENOTDIR.
  for (const code of ["ENOENT", "ENOTDIR"]) {
    it(`reports NO_SYSTEMD on ${code} — there is no binary (macOS, container, QTS)`, () => {
      vi.mocked(execFileSync).mockImplementation(() => {
        throw spawnFailed(code);
      });
      expect(systemctl.systemctlActiveState()).toBe(systemctl.NO_SYSTEMD);
    });
  }

  // The regression this file exists to pin. A spawn failure that is NOT "no such
  // file" says the binary is THERE and we could not run it, so systemd may be
  // running the agent right now. Folding these into NO_SYSTEMD let cmdUninstall
  // delete a live root agent's unit file, binary and credentials.
  //
  // EACCES is the load-bearing one and is genuinely reachable: real execFileSync
  // raises it for a systemctl that exists but is not executable by us — a noexec
  // mount, mode bits, a PATH directory we may not traverse. EPERM/ENOEXEC and the
  // resource-exhaustion family are the same class of non-answer.
  for (const code of ["EACCES", "EPERM", "ENOEXEC", "EMFILE", "ENFILE", "ENOMEM", "EAGAIN", "EWHAT"]) {
    it(`reports ACTIVE_STATE_UNKNOWN on ${code} — systemctl exists, we just could not run it`, () => {
      vi.mocked(execFileSync).mockImplementation(() => {
        throw spawnFailed(code);
      });
      expect(systemctl.systemctlActiveState()).toBe(systemctl.ACTIVE_STATE_UNKNOWN);
      expect(systemctl.systemctlActiveState()).not.toBe(systemctl.NO_SYSTEMD);
    });
  }

  // systemd IS installed but told us nothing usable (no bus, empty output, a word
  // we do not know). Fail closed: callers must see this as "we do not know".
  it("reports ACTIVE_STATE_UNKNOWN when systemctl runs but answers nothing", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw exitedNonZero(1, ""); // e.g. "Failed to connect to bus" on stderr
    });
    expect(systemctl.systemctlActiveState()).toBe(systemctl.ACTIVE_STATE_UNKNOWN);
  });

  it("reports ACTIVE_STATE_UNKNOWN for output that is not a known state word", () => {
    vi.mocked(execFileSync).mockReturnValue(
      "Failed to get properties: Connection timed out\n" as unknown as ReturnType<typeof execFileSync>,
    );
    expect(systemctl.systemctlActiveState()).toBe(systemctl.ACTIVE_STATE_UNKNOWN);
  });

  it("never uses a sentinel systemd itself could print", () => {
    // Otherwise "we could not find out" would be indistinguishable from a state.
    expect(systemctl.ACTIVE_STATE_UNKNOWN).not.toBe("unknown");
    expect(systemctl.NO_SYSTEMD).not.toBe("inactive");
  });
});

describe("systemctlIsEnabled", () => {
  it("returns true only when output is exactly 'enabled'", () => {
    vi.mocked(execFileSync).mockReturnValue("enabled\n" as unknown as ReturnType<typeof execFileSync>);
    expect(systemctl.systemctlIsEnabled()).toBe(true);
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["is-enabled", SERVICE],
      expect.objectContaining({ encoding: "utf8" }),
    );
  });

  it("returns false for any other output (e.g. 'disabled')", () => {
    vi.mocked(execFileSync).mockReturnValue("disabled\n" as unknown as ReturnType<typeof execFileSync>);
    expect(systemctl.systemctlIsEnabled()).toBe(false);
  });

  it("returns false when systemctl throws", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw new Error("not found");
    });
    expect(systemctl.systemctlIsEnabled()).toBe(false);
  });
});

/**
 * The parse that decides what a root `systemctl stop` is aimed at. It reads
 * `list-units` TEXT output, and the module's comment claims it survives a
 * systemd that ignores `--plain` — neither claim was verified anywhere until
 * here (uninstall.test.ts mocks the whole function away).
 */
describe("listJobScopeUnits", () => {
  const SCOPE_A = "aic-job-0123456789abcdef.scope";
  const SCOPE_B = "aic-job-fedcba9876543210.scope";

  function givenOutput(out: string): void {
    vi.mocked(execFileSync).mockReturnValue(out as unknown as ReturnType<typeof execFileSync>);
  }

  it("asks systemd for our glob only, and bounds the call", () => {
    givenOutput("");
    systemctl.listJobScopeUnits();
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["list-units", "--type=scope", "--all", "--no-legend", "--plain", "aic-job-*.scope"],
      expect.objectContaining({ timeout: systemctl.SCOPE_LIST_TIMEOUT_MS }),
    );
  });

  it("reads the --plain shape: one bare unit name per line", () => {
    givenOutput(`${SCOPE_A}\n${SCOPE_B}\n`);
    expect(systemctl.listJobScopeUnits()).toEqual([SCOPE_A, SCOPE_B]);
  });

  // The shape a systemd that ignored --plain prints: indented, and the unit name
  // followed by the LOAD/ACTIVE/SUB/DESCRIPTION columns.
  it("reads the legacy indented, columned shape", () => {
    givenOutput(
      `  ${SCOPE_A} loaded active running /bin/sh -c job\n` +
      `  ${SCOPE_B} loaded active running /bin/sh -c job\n`,
    );
    expect(systemctl.listJobScopeUnits()).toEqual([SCOPE_A, SCOPE_B]);
  });

  it("reads a line whose first column is a status bullet", () => {
    givenOutput(`● ${SCOPE_A} loaded active running /bin/sh -c job\n`);
    expect(systemctl.listJobScopeUnits()).toEqual([SCOPE_A]);
  });

  // The reason isJobScopeUnitName re-checks every parsed name: a localised
  // header, a legend --no-legend did not suppress, or any line we did not
  // expect must never become the target of a root `systemctl stop`.
  it("drops lines that are not one of our unit names", () => {
    givenOutput(
      "UNIT LOAD ACTIVE SUB DESCRIPTION\n" +
      "session-3.scope loaded active running Session 3 of user root\n" +
      "1 Einheiten geladen.\n" +
      `${SCOPE_A}\n` +
      "\n",
    );
    expect(systemctl.listJobScopeUnits()).toEqual([SCOPE_A]);
  });

  it("drops a name that only looks like ours (wrong job-id shape)", () => {
    givenOutput("aic-job-notahexjobid.scope\naic-job-.scope\naic-job-0123456789abcdefg.scope\n");
    expect(systemctl.listJobScopeUnits()).toEqual([]);
  });

  it("does not repeat a unit systemd printed twice", () => {
    givenOutput(`${SCOPE_A}\n${SCOPE_A}\n`);
    expect(systemctl.listJobScopeUnits()).toEqual([SCOPE_A]);
  });

  // The load-bearing distinction: [] is "we looked and there is nothing", null
  // is "we could not look". Only the first lets cmdUninstall delete job data.
  it("returns [] for empty output — a real answer", () => {
    givenOutput("\n");
    expect(systemctl.listJobScopeUnits()).toEqual([]);
  });

  it("returns null when the command fails — NOT an empty list", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw Object.assign(new Error("Failed to connect to bus"), { status: 1 });
    });
    expect(systemctl.listJobScopeUnits()).toBeNull();
  });

  it("returns null when the listing hits its timeout", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw Object.assign(new Error("ETIMEDOUT"), { killed: true, signal: "SIGTERM" });
    });
    expect(systemctl.listJobScopeUnits()).toBeNull();
  });
});

describe("systemctlStopUnit / systemctlKillUnit", () => {
  const SCOPE_A = "aic-job-0123456789abcdef.scope";

  it("stops exactly the named unit, with a bounded wait", () => {
    systemctl.systemctlStopUnit(SCOPE_A);
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["stop", SCOPE_A],
      expect.objectContaining({ timeout: systemctl.SCOPE_STOP_TIMEOUT_MS }),
    );
  });

  it("kills the WHOLE cgroup, not just the scope's main process", () => {
    systemctl.systemctlKillUnit(SCOPE_A);
    expect(vi.mocked(execFileSync)).toHaveBeenCalledWith(
      "systemctl",
      ["kill", "--kill-who=all", "--signal=SIGKILL", SCOPE_A],
      expect.objectContaining({ timeout: systemctl.SCOPE_KILL_TIMEOUT_MS }),
    );
  });

  it("propagates a failure so the caller can account for a scope that would not go", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw new Error("Failed to stop");
    });
    expect(() => systemctl.systemctlStopUnit(SCOPE_A)).toThrow();
  });

  // These run as root. A name that reached here from parsed text output and is
  // not provably one of ours must never become a `stop`/`kill` target — the
  // glob especially: the enumeration expands the pattern, these do not.
  const foreign = [
    "aic-job-*.scope",              // a glob would stop EVERY job at once
    "*",                            // …or every unit on the machine
    "../../etc/systemd/system.scope",
    "aic-job-0123456789abcdef.service", // right id, wrong type
    "sshd.service",                 // plausible, foreign, and fatal to stop
    "session-1.scope",
    "",
  ];
  for (const unit of foreign) {
    it(`refuses to stop or kill ${JSON.stringify(unit)}`, () => {
      expect(() => systemctl.systemctlStopUnit(unit)).toThrow(/not an AI Commander job scope/);
      expect(() => systemctl.systemctlKillUnit(unit)).toThrow(/not an AI Commander job scope/);
      expect(vi.mocked(execFileSync)).not.toHaveBeenCalled();
    });
  }
});
