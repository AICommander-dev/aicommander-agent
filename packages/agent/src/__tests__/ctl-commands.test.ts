import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";

// We mock the systemctl wrapper, the state store, and the ui module so we can
// assert which systemctl verbs each command calls, that requireRoot is enforced,
// and how status renders online/offline/missing-state.
// The state SENTINELS come from the real module so this suite pins the actual
// contract (systemctlActiveState NEVER throws; it reports those words instead).
vi.mock("../ctl/systemctl.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../ctl/systemctl.js")>()),
  systemctlStart: vi.fn(),
  systemctlStop: vi.fn(),
  systemctlEnable: vi.fn(),
  systemctlDisable: vi.fn(),
  systemctlRestart: vi.fn(),
  systemctlActiveState: vi.fn(() => "inactive"),
  systemctlIsEnabled: vi.fn(() => false),
  // Stopping the service no longer stops the jobs (job-scope.ts), so cmdDisable
  // has to ask what is still running. Default: systemd answered, nothing left.
  listJobScopeUnits: vi.fn((): string[] | null => []),
  daemonReload: vi.fn(),
}));

vi.mock("../state.js", () => ({
  readState: vi.fn(async () => null),
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

import {
  systemctlStart,
  systemctlStop,
  systemctlEnable,
  systemctlDisable,
  systemctlActiveState,
  systemctlIsEnabled,
  listJobScopeUnits,
  NO_SYSTEMD,
  ACTIVE_STATE_UNKNOWN,
} from "../ctl/systemctl.js";
import { readState } from "../state.js";
import { ui, requireRoot } from "../ctl/ui.js";
import { cmdEnable } from "../ctl/commands/enable.js";
import { cmdDisable } from "../ctl/commands/disable.js";
import { cmdStatus } from "../ctl/commands/status.js";

let exitSpy: MockInstance<typeof process.exit>;

beforeEach(() => {
  vi.clearAllMocks();
  exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("cmdEnable", () => {
  it("requires root", () => {
    cmdEnable();
    expect(vi.mocked(requireRoot)).toHaveBeenCalled();
  });

  it("starts the service when not already active, then enables it", () => {
    vi.mocked(systemctlActiveState).mockReturnValue("inactive");
    cmdEnable();
    expect(vi.mocked(systemctlStart)).toHaveBeenCalled();
    expect(vi.mocked(systemctlEnable)).toHaveBeenCalled();
  });

  it("does NOT start when already active, but still enables", () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    cmdEnable();
    expect(vi.mocked(systemctlStart)).not.toHaveBeenCalled();
    expect(vi.mocked(ui.warn)).toHaveBeenCalled();
    expect(vi.mocked(systemctlEnable)).toHaveBeenCalled();
  });
});

describe("cmdDisable", () => {
  const SCOPE_A = "aic-job-0123456789abcdef.scope";
  const SCOPE_B = "aic-job-fedcba9876543210.scope";

  it("requires root and calls stop + disable", () => {
    cmdDisable();
    expect(vi.mocked(requireRoot)).toHaveBeenCalled();
    expect(vi.mocked(systemctlStop)).toHaveBeenCalled();
    expect(vi.mocked(systemctlDisable)).toHaveBeenCalled();
  });

  it("says nothing extra when no job scope is left running", () => {
    cmdDisable();
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("stopped and disabled");
    expect(vi.mocked(ui.warn)).not.toHaveBeenCalled();
  });

  // The consequence of job-scope.ts: "Service stopped and disabled." used to
  // mean the jobs were down too. A scoped job survives the stop, as root, with
  // no agent left to cancel it through — so the operator has to be told.
  it("names the jobs that keep running as root, and how to stop them", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A, SCOPE_B]);
    cmdDisable();
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("2 job(s) are STILL RUNNING");
    expect(warnings).toContain(SCOPE_A);
    expect(warnings).toContain(SCOPE_B);
    expect(warnings).toContain("cancelled");
    expect(warnings).toContain("systemctl stop 'aic-job-*.scope'");
  });

  // disable is not uninstall: turning the agent off on boot is not consent to
  // destroy a running training job.
  it("never stops or kills the jobs itself", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A]);
    cmdDisable();
    expect(vi.mocked(systemctlStop)).toHaveBeenCalledTimes(1); // the service only
  });

  it("warns rather than staying silent when the scopes could not be listed", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue(null);
    cmdDisable();
    expect(vi.mocked(ui.warn).mock.calls.flat().join(" ")).toContain("cannot be ruled out");
  });
});

describe("cmdStatus", () => {
  it("renders running + session details when active and state present", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    vi.mocked(systemctlIsEnabled).mockReturnValue(true);
    vi.mocked(readState).mockResolvedValue({
      sessionCode: "AIC-WOLF-2345-WXYZ",
      pid: 1234,
      startedAt: "2026-06-14T00:00:00.000Z",
      serverUrl: "https://aicommander.dev",
    });
    await cmdStatus();

    const infoCalls = vi.mocked(ui.info).mock.calls;
    const keys = infoCalls.map((c) => c[0]);
    expect(keys).toContain("Session code");
    expect(keys).toContain("PID");
    expect(keys).toContain("Server");
    // State line shows "running" (it's the value of the "State" info row).
    const stateRow = infoCalls.find((c) => c[0] === "State");
    expect(String(stateRow?.[1])).toContain("running");
  });

  it("masks the session code by default", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    vi.mocked(readState).mockResolvedValue({
      sessionCode: "AIC-ABCD-2345-WXYZ",
      pid: 1234,
      startedAt: "2026-06-14T00:00:00.000Z",
      serverUrl: "https://aicommander.dev",
    });
    await cmdStatus();
    const sessionRow = vi.mocked(ui.info).mock.calls.find((c) => c[0] === "Session code");
    expect(String(sessionRow?.[1])).not.toContain("AIC-ABCD-2345-WXYZ");
    expect(vi.mocked(requireRoot)).not.toHaveBeenCalled();
  });

  it("requires root when revealing the full session code", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    vi.mocked(readState).mockResolvedValue({
      sessionCode: "AIC-ABCD-2345-WXYZ",
      pid: 1234,
      startedAt: "2026-06-14T00:00:00.000Z",
      serverUrl: "https://aicommander.dev",
    });
    await cmdStatus({ reveal: true });
    expect(vi.mocked(requireRoot)).toHaveBeenCalled();
    const sessionRow = vi.mocked(ui.info).mock.calls.find((c) => c[0] === "Session code");
    expect(String(sessionRow?.[1])).toContain("AIC-ABCD-2345-WXYZ");
  });

  it("warns when active but state is missing (agent still starting)", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    vi.mocked(readState).mockResolvedValue(null);
    await cmdStatus();
    expect(vi.mocked(ui.warn)).toHaveBeenCalled();
    // No session-code row when state is absent.
    const keys = vi.mocked(ui.info).mock.calls.map((c) => c[0]);
    expect(keys).not.toContain("Session code");
  });

  it("renders the inactive state when service is offline", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue("inactive");
    vi.mocked(readState).mockResolvedValue(null);
    await cmdStatus();
    const stateRow = vi.mocked(ui.info).mock.calls.find((c) => c[0] === "State");
    expect(String(stateRow?.[1])).toContain("inactive");
    // Offline + no state → no "still starting" warning.
    expect(vi.mocked(ui.warn)).not.toHaveBeenCalled();
  });

  // systemctlActiveState() reports "there is no systemd here" as a STATE and
  // never throws, so status prints it and keeps going: on a machine with no unit
  // the session code, pid and uptime are exactly what the operator came for.
  it("reports a machine with no systemd instead of exiting", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue(NO_SYSTEMD);
    vi.mocked(readState).mockResolvedValue({
      sessionCode: "AIC-ABCD-2345-WXYZ",
      pid: 1234,
      startedAt: "2026-06-14T00:00:00.000Z",
      serverUrl: "https://aicommander.dev",
    });
    await cmdStatus();
    expect(exitSpy).not.toHaveBeenCalled();
    const stateRow = vi.mocked(ui.info).mock.calls.find((c) => c[0] === "State");
    expect(String(stateRow?.[1])).toContain(NO_SYSTEMD);
    expect(vi.mocked(ui.info).mock.calls.map((c) => c[0])).toContain("Session code");
  });

  // The other sentinel: a systemd we could not question. Also a state, also
  // printed — status reports, it does not decide.
  it("reports an unanswerable is-active query instead of exiting", async () => {
    vi.mocked(systemctlActiveState).mockReturnValue(ACTIVE_STATE_UNKNOWN);
    await cmdStatus();
    expect(exitSpy).not.toHaveBeenCalled();
    const stateRow = vi.mocked(ui.info).mock.calls.find((c) => c[0] === "State");
    expect(String(stateRow?.[1])).toContain(ACTIVE_STATE_UNKNOWN);
  });
});
