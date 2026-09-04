import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";

// uninstall is security-relevant: it MUST wipe the device identity, the stored
// session (token + secret), the rotate marker, the state dir, the systemd unit,
// and the ctl symlink. We mock node:fs + systemctl + ui to assert exactly what
// gets removed and that requireRoot + the --force gate are enforced.
// mkdirSync/accessSync/constants are here for config-dir.ts, which uninstall
// consults to find the ACTIVE identity directory (AICOMMANDER_CONFIG_DIR).
// lstatSync/readdirSync answer "an empty directory of ours" by default, which is
// what the jobs-root safety check inspects before any recursive delete.
// readFileSync/readlinkSync belong to live-agent.ts, which uninstall consults
// before it deletes anything: they read state.json and /proc. They throw by
// default — "no evidence of a running agent", the ordinary uninstall.
vi.mock("node:fs", () => ({
  default: {
    existsSync: vi.fn(() => true),
    lstatSync: vi.fn(() => ({
      isSymbolicLink: () => false,
      isDirectory: () => true,
    })) as unknown,
    readdirSync: vi.fn(() => [] as string[]),
    readFileSync: vi.fn(() => {
      throw new Error("ENOENT");
    }),
    readlinkSync: vi.fn(() => {
      throw new Error("ENOENT");
    }),
    rmSync: vi.fn(),
    rmdirSync: vi.fn(),
    mkdirSync: vi.fn(),
    accessSync: vi.fn(),
    constants: { W_OK: 2 },
  },
}));

// systemctlActiveState is the ONLY proof the unit actually stopped — a stop
// error is ambiguous (never installed / no systemd / genuinely unkillable) — so
// it answers "inactive" by default here, i.e. "the service is gone".
// The state SENTINELS come from the real module (importOriginal) so this suite
// pins the actual contract instead of a copy of it that could drift.
vi.mock("../ctl/systemctl.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../ctl/systemctl.js")>()),
  systemctlStop: vi.fn(),
  systemctlDisable: vi.fn(),
  systemctlKill: vi.fn(),
  systemctlActiveState: vi.fn(() => "inactive"),
  // The job scopes (job-scope.ts) are a SECOND thing that can still be running
  // once the unit is down, and stopping them is now part of the uninstall — so
  // they are stubbed here too. The default is the ordinary machine: systemd
  // answered, and there were no leftover job scopes.
  listJobScopeUnits: vi.fn((): string[] | null => []),
  systemctlStopUnit: vi.fn(),
  // The escalation for a scope that will not stop gracefully. Stubbed for the
  // same reason as the stop: this suite must never send a real signal.
  systemctlKillUnit: vi.fn(),
  daemonReload: vi.fn(),
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

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  systemctlStop,
  systemctlDisable,
  systemctlKill,
  systemctlActiveState,
  listJobScopeUnits,
  systemctlStopUnit,
  systemctlKillUnit,
  daemonReload,
  NO_SYSTEMD,
  ACTIVE_STATE_UNKNOWN,
} from "../ctl/systemctl.js";
import { requireRoot, ui } from "../ctl/ui.js";
import { cmdUninstall } from "../ctl/commands/uninstall.js";

const SERVICE_FILE = "/etc/systemd/system/aicommander-agent.service";
const CTL_SYMLINK = "/usr/local/bin/aicommander-ctl";
const BIN = "/usr/local/bin/aicommander-agent";
const STATE_DIR = "/var/run/aicommander-agent";
const DEVICE_DIR = "/etc/aicommander-agent";
const SESSION_FILE = "/etc/aicommander-agent/session.json";
const ROTATE_MARKER = "/etc/aicommander-agent/.rotate";

const ENV_DIR_VAR = "AICOMMANDER_CONFIG_DIR";
const OVERRIDE_DIR = "/share/CACHEDEV1_DATA/aicommander/config";
// Same derivation as device.ts / session-store.ts / job-manager.ts.
const FALLBACK_DIR = path.join(os.homedir(), ".config", "aicommander-agent");
const USER_JOBS_ROOT = path.join(os.homedir(), ".local", "share", "aicommander", "jobs");
const SERVICE_JOBS_ROOT = "/var/lib/aicommander/jobs";

let exitSpy: MockInstance<typeof process.exit>;
let savedEnvDir: string | undefined;
let savedSudoUser: string | undefined;
let savedPlatform: PropertyDescriptor | undefined;

function removedPaths(): string[] {
  return vi.mocked(fs.rmSync).mock.calls.map((c) => String(c[0]));
}

/**
 * A REAL `execFileSync` timeout error, produced once by this suite instead of
 * hand-written — because a hand-written one is exactly how the bug this pins got
 * in. The stop path used to look for `killed: true`, which is the shape of the
 * ASYNC `execFile` callback and never appears here, and a test that fabricated
 * `{ killed: true }` certified a branch Node can never take.
 *
 * The observed error (Node 24) has own keys
 * errno,code,syscall,path,spawnargs,error,status,signal,output,pid,stdout,stderr
 * with `killed` undefined, `code: "ETIMEDOUT"`, `status: null`,
 * `signal: "SIGTERM"`. Provoking it costs one ~100 ms spawn for the whole file,
 * and it cannot drift away from Node's behaviour the way a literal can.
 *
 * node:child_process is deliberately NOT mocked in this suite, so this is the
 * real thing; the child is `process.execPath` idling, which is portable.
 */
function realExecFileSyncTimeoutError(): unknown {
  try {
    execFileSync(process.execPath, ["-e", "setTimeout(() => {}, 5000)"], {
      timeout: 100,
      stdio: "pipe",
    });
  } catch (err) {
    return err;
  }
  throw new Error("expected execFileSync to time out");
}

function dirStat(): ReturnType<typeof fs.lstatSync> {
  return {
    isSymbolicLink: () => false,
    isDirectory: () => true,
  } as unknown as ReturnType<typeof fs.lstatSync>;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(fs.existsSync).mockReturnValue(true);
  vi.mocked(fs.lstatSync).mockReturnValue(dirStat());
  vi.mocked(fs.readdirSync).mockReturnValue([] as never);
  // "Nothing recorded a running agent, and /proc has nothing to say" — the state
  // every test that is not about the process check needs.
  vi.mocked(fs.readFileSync).mockImplementation(() => {
    throw new Error("ENOENT");
  });
  vi.mocked(fs.readlinkSync).mockImplementation(() => {
    throw new Error("ENOENT");
  });
  savedPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  // Re-assert per test: an implementation set by one test must not decide
  // whether the next one believes the service is still running.
  vi.mocked(systemctlActiveState).mockReturnValue("inactive");
  vi.mocked(systemctlStop).mockImplementation(() => {});
  vi.mocked(systemctlKill).mockImplementation(() => {});
  vi.mocked(systemctlDisable).mockImplementation(() => {});
  vi.mocked(listJobScopeUnits).mockReturnValue([]);
  vi.mocked(systemctlStopUnit).mockImplementation(() => {});
  exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  savedEnvDir = process.env[ENV_DIR_VAR];
  savedSudoUser = process.env["SUDO_USER"];
  delete process.env[ENV_DIR_VAR];
  delete process.env["SUDO_USER"];
});

afterEach(() => {
  vi.restoreAllMocks();
  // The process check is platform-specific, and the suite must behave the same
  // on the CI Linux box and on a maintainer's Mac — so it is always stated
  // explicitly and always put back.
  if (savedPlatform) Object.defineProperty(process, "platform", savedPlatform);
  if (savedEnvDir === undefined) delete process.env[ENV_DIR_VAR];
  else process.env[ENV_DIR_VAR] = savedEnvDir;
  if (savedSudoUser === undefined) delete process.env["SUDO_USER"];
  else process.env["SUDO_USER"] = savedSudoUser;
});

describe("cmdUninstall", () => {
  it("requires root", () => {
    cmdUninstall({ force: true });
    expect(vi.mocked(requireRoot)).toHaveBeenCalled();
  });

  it("refuses without --force and exits(1)", () => {
    cmdUninstall({ force: false });
    // In production process.exit(1) halts here before any removal. We can only
    // assert the exit + the operator-facing error (exit is mocked in tests).
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(vi.mocked(ui.error)).toHaveBeenCalled();
  });

  it("stops and disables the service", () => {
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlStop)).toHaveBeenCalled();
    expect(vi.mocked(systemctlDisable)).toHaveBeenCalled();
    expect(vi.mocked(daemonReload)).toHaveBeenCalled();
  });

  it("wipes the device identity, session, rotate marker, state, unit, and ctl symlink", () => {
    cmdUninstall({ force: true });
    const removed = removedPaths();
    expect(removed).toContain(SERVICE_FILE);
    expect(removed).toContain(CTL_SYMLINK);
    expect(removed).toContain(BIN);
    expect(removed).toContain(STATE_DIR);
    expect(removed).toContain(SESSION_FILE); // token
    expect(removed).toContain(ROTATE_MARKER);
    expect(removed).toContain(DEVICE_DIR); // device secret
  });

  it("removes the ctl symlink before the binary (avoids dangling link)", () => {
    cmdUninstall({ force: true });
    const removed = removedPaths();
    expect(removed.indexOf(CTL_SYMLINK)).toBeLessThan(removed.indexOf(BIN));
  });

  it("is best-effort: tolerates an already-missing file without throwing", () => {
    // Simulate every target missing: existsSync false and lstatSync throws ENOENT.
    vi.mocked(fs.existsSync).mockReturnValue(false);
    vi.mocked(fs.lstatSync).mockImplementation(() => {
      throw new Error("ENOENT");
    });
    expect(() => cmdUninstall({ force: true })).not.toThrow();
    // With nothing present, nothing is rmSync'd.
    expect(removedPaths()).toEqual([]);
  });

  it("tolerates systemctl stop/disable failures (already stopped)", () => {
    vi.mocked(systemctlStop).mockImplementation(() => {
      throw new Error("not running");
    });
    vi.mocked(systemctlDisable).mockImplementation(() => {
      throw new Error("not enabled");
    });
    expect(() => cmdUninstall({ force: true })).not.toThrow();
    // Removals still proceed afterwards.
    expect(removedPaths()).toContain(DEVICE_DIR);
    // "Not installed / not running" needs no SIGKILL escalation.
    expect(vi.mocked(systemctlKill)).not.toHaveBeenCalled();
  });

  // A stop we could not verify is not a stop. Everything below the stop step
  // deletes the workspaces, logs, binary and credentials of a service that may
  // still be running as root and connected to the relay.
  it("escalates to SIGKILL when the unit is still active after stop", () => {
    let calls = 0;
    // active right after `stop`, gone once SIGKILL lands.
    vi.mocked(systemctlActiveState).mockImplementation(() => (++calls === 1 ? "active" : "inactive"));
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlKill)).toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("aborts without deleting anything when the service survives stop AND SIGKILL", () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlKill)).toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
    // NOTHING was removed — not the unit file, not the binary, not the identity.
    expect(removedPaths()).toEqual([]);
    expect(vi.mocked(fs.rmdirSync)).not.toHaveBeenCalled();
    // …and it never claims success.
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain("STILL running");
  });

  // "Not active" is a weaker statement than "stopped". A unit that is still
  // deactivating is a live root process that still holds its credentials, and one
  // systemd will not tell us about is not evidence of anything at all — neither
  // may buy the uninstall its go-ahead.
  for (const state of ["deactivating", "activating", "reloading", "maintenance"]) {
    it(`refuses to delete anything while the unit is '${state}'`, () => {
      vi.mocked(systemctlActiveState).mockReturnValue(state);
      cmdUninstall({ force: true });
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(removedPaths()).toEqual([]);
      expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
    });
  }

  it("refuses to delete anything when is-active could not be answered", () => {
    vi.mocked(systemctlActiveState).mockReturnValue(ACTIVE_STATE_UNKNOWN);
    cmdUninstall({ force: true });
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(removedPaths()).toEqual([]);
    // …and says WHY, rather than claiming a service it never saw is running.
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain("Could NOT determine");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  // The other side of that coin: these are genuinely "not running", and used to
  // be the ordinary uninstall path. Tightening the check must not break them.
  for (const state of ["inactive", "failed", "unknown"]) {
    it(`proceeds when the unit is '${state}' (nothing is running)`, () => {
      vi.mocked(systemctlActiveState).mockReturnValue(state);
      cmdUninstall({ force: true });
      expect(exitSpy).not.toHaveBeenCalled();
      expect(removedPaths()).toContain(DEVICE_DIR);
    });
  }

  it("proceeds on a machine with no systemd at all — there is no unit to stop", () => {
    vi.mocked(systemctlActiveState).mockReturnValue(NO_SYSTEMD);
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
    // Nothing to escalate against either.
    expect(vi.mocked(systemctlKill)).not.toHaveBeenCalled();
  });

  it("does not disable the unit it could not stop", () => {
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    cmdUninstall({ force: true });
    // Disabling a service that is still running only hides it from the next boot.
    expect(vi.mocked(systemctlDisable)).not.toHaveBeenCalled();
  });

  it("tolerates a daemon-reload failure (non-critical)", () => {
    vi.mocked(daemonReload).mockImplementation(() => {
      throw new Error("dbus error");
    });
    expect(() => cmdUninstall({ force: true })).not.toThrow();
    expect(removedPaths()).toContain(SERVICE_FILE);
  });
});

// Where /etc is a ramdisk (QNAP) the identity lives under AICOMMANDER_CONFIG_DIR.
// Uninstall reporting "fully removed" while leaving session.json there would
// leave a live root-exec credential on the data volume.
describe("cmdUninstall — AICOMMANDER_CONFIG_DIR override", () => {
  it("purges the identity from the overridden config dir", () => {
    process.env[ENV_DIR_VAR] = OVERRIDE_DIR;
    cmdUninstall({ force: true });
    const removed = removedPaths();
    expect(removed).toContain(`${OVERRIDE_DIR}/session.json`);
    expect(removed).toContain(`${OVERRIDE_DIR}/session.token`);
    expect(removed).toContain(`${OVERRIDE_DIR}/device.json`);
    expect(removed).toContain(`${OVERRIDE_DIR}/.rotate`);
  });

  it("still purges the stale /etc copy that a pre-override install left behind", () => {
    process.env[ENV_DIR_VAR] = OVERRIDE_DIR;
    cmdUninstall({ force: true });
    const removed = removedPaths();
    expect(removed).toContain(SESSION_FILE);
    expect(removed).toContain(ROTATE_MARKER);
    expect(removed).toContain(DEVICE_DIR);
  });

  it("drops the override dir only when it is left empty (jobs data may live there)", () => {
    process.env[ENV_DIR_VAR] = OVERRIDE_DIR;
    cmdUninstall({ force: true });
    expect(vi.mocked(fs.rmdirSync)).toHaveBeenCalledWith(OVERRIDE_DIR);
    // rmdir is non-recursive on purpose: a non-empty dir throws and survives.
    expect(removedPaths()).not.toContain(OVERRIDE_DIR);
  });

  it("does not double-purge when the override points at the default dir", () => {
    process.env[ENV_DIR_VAR] = DEVICE_DIR;
    cmdUninstall({ force: true });
    // /etc is removed wholesale, never rmdir'd as if it were an operator path.
    expect(vi.mocked(fs.rmdirSync)).not.toHaveBeenCalledWith(DEVICE_DIR);
    expect(removedPaths().filter((p) => p === SESSION_FILE)).toHaveLength(1);
  });

  it("removes what it can and refuses to claim success when the override is unusable", () => {
    process.env[ENV_DIR_VAR] = "relative/config"; // ConfigDirError
    cmdUninstall({ force: true });
    // /etc is still wiped …
    expect(removedPaths()).toContain(DEVICE_DIR);
    // … but the summary reports the leftover instead of "fully removed".
    const ok = vi.mocked(ui.ok).mock.calls.flat().join(" ");
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(ok).not.toContain("fully removed");
    expect(errors).toContain("AICOMMANDER_CONFIG_DIR");
    expect(errors).toContain("relative/config");
  });

  // resolveJobsRoot() consults the same variable, so an unusable value must not
  // be allowed to throw a second time and abort the rest of the uninstall.
  it("still purges job data when the override is unusable", () => {
    process.env[ENV_DIR_VAR] = "relative/config";
    expect(() => cmdUninstall({ force: true })).not.toThrow();
    expect(removedPaths()).toContain(SERVICE_JOBS_ROOT);
    expect(removedPaths()).toContain(DEVICE_DIR);
  });

  it("reports a path that could not be deleted instead of 'fully removed'", () => {
    vi.mocked(fs.rmSync).mockImplementation((target) => {
      if (String(target) === DEVICE_DIR) throw new Error("EACCES: permission denied");
    });
    cmdUninstall({ force: true });
    const ok = vi.mocked(ui.ok).mock.calls.flat().join(" ");
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(ok).not.toContain("fully removed");
    expect(errors).toContain(DEVICE_DIR);
  });

  it("says 'fully removed' when nothing is left", () => {
    cmdUninstall({ force: true });
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });
});

// A non-root run persists the identity in ~/.config/aicommander-agent, and
// session-store.ts adopts it again (inheritedDirs) — the same resurrection path
// the /etc purge closes.
describe("cmdUninstall — user config fallback", () => {
  it("purges the identity from ~/.config/aicommander-agent", () => {
    cmdUninstall({ force: true });
    const removed = removedPaths();
    expect(removed).toContain(path.join(FALLBACK_DIR, "session.json"));
    expect(removed).toContain(path.join(FALLBACK_DIR, "session.token"));
    expect(removed).toContain(path.join(FALLBACK_DIR, "device.json"));
    expect(removed).toContain(path.join(FALLBACK_DIR, ".rotate"));
  });

  it("drops the fallback dir only when it is left empty", () => {
    cmdUninstall({ force: true });
    expect(vi.mocked(fs.rmdirSync)).toHaveBeenCalledWith(FALLBACK_DIR);
    expect(removedPaths()).not.toContain(FALLBACK_DIR);
  });

  // HOME under sudo is either root's or the invoking user's; we purge the one
  // os.homedir() resolves to and refuse to guess at the other.
  it("reports the invoking user's home as unchecked when HOME is not theirs", () => {
    process.env["SUDO_USER"] = "somebody-else";
    cmdUninstall({ force: true });
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("somebody-else");
    expect(warnings).toContain("NOT checked");
    // …and it never invents a path in that user's home.
    expect(removedPaths().some((p) => p.includes("somebody-else"))).toBe(false);
  });

  // "Fully removed" is a claim about fact: an unchecked location is not a known
  // remnant, but it is not proof of a clean machine either.
  it("does not claim 'fully removed' while a location went unchecked", () => {
    process.env["SUDO_USER"] = "somebody-else";
    cmdUninstall({ force: true });
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("could NOT be checked");
    expect(warnings).toContain("somebody-else");
    // The distinction stays visible: nothing was reported as a known leftover,
    // so the real-failure channel keeps its signal.
    expect(vi.mocked(ui.error)).not.toHaveBeenCalled();
  });

  it("keeps unchecked locations separate from paths that could not be deleted", () => {
    process.env["SUDO_USER"] = "somebody-else";
    vi.mocked(fs.rmSync).mockImplementation((target) => {
      if (String(target) === DEVICE_DIR) throw new Error("EACCES: permission denied");
    });
    cmdUninstall({ force: true });
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    // The known remnant is an error; the unchecked home is only a warning.
    expect(errors).toContain(DEVICE_DIR);
    expect(errors).not.toContain("could NOT be checked");
    expect(warnings).toContain("could NOT be checked");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  // The identity is not the only per-user thing an uninstall purges: a non-root
  // run keeps job workspaces and their output.log under ~/.local/share, which is
  // user data by the same standard as the credential.
  it("reports the invoking user's jobs root as unchecked, not just their config dir", () => {
    process.env["SUDO_USER"] = "somebody-else";
    cmdUninstall({ force: true });
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("somebody-else's ~/.config/aicommander-agent");
    expect(warnings).toContain("somebody-else's ~/.local/share/aicommander/jobs");
    // Still no guessing at a path inside that user's home.
    expect(removedPaths().some((p) => p.includes("somebody-else"))).toBe(false);
  });

  // cmdUninstall opens with requireRoot(), so a remedy of "re-run as <user>" can
  // only ever produce "This command must be run as root" — while the operator
  // believes they just cleared the credential we warned them about.
  it("offers a remedy that keeps root, since uninstall refuses to run as anyone else", () => {
    process.env["SUDO_USER"] = "somebody-else";
    cmdUninstall({ force: true });
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).not.toMatch(/re-run as somebody-else/i);
    // `~user/` is expanded by the operator's shell — the one derivation of that
    // home directory we are willing to rely on — and both paths are named exactly.
    expect(warnings).toContain(
      "sudo rm -rf ~somebody-else/.config/aicommander-agent ~somebody-else/.local/share/aicommander/jobs",
    );
  });

  it("prints no shell command when SUDO_USER is not a plain username", () => {
    process.env["SUDO_USER"] = "evil; rm -rf /";
    cmdUninstall({ force: true });
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    // The locations are still reported honestly …
    expect(warnings).toContain("could NOT be checked");
    // … but nothing that could be pasted into a shell is built out of that value.
    expect(warnings).not.toContain("sudo rm -rf");
  });

  it("stays quiet when HOME already belongs to the invoking user (sudo -E)", () => {
    process.env["SUDO_USER"] = path.basename(os.homedir());
    cmdUninstall({ force: true });
    expect(vi.mocked(ui.warn).mock.calls.flat().join(" ")).not.toContain("NOT checked");
  });
});

// Job workspaces and logs are job OUTPUT — user data — and used to survive a
// full uninstall.
describe("cmdUninstall — job data", () => {
  it("removes the service and per-user jobs roots recursively", () => {
    cmdUninstall({ force: true });
    const removed = removedPaths();
    expect(removed).toContain(SERVICE_JOBS_ROOT);
    expect(removed).toContain(USER_JOBS_ROOT);
    const recursive = vi
      .mocked(fs.rmSync)
      .mock.calls.find((c) => String(c[0]) === SERVICE_JOBS_ROOT)?.[1];
    expect(recursive).toMatchObject({ recursive: true });
  });

  it("removes the jobs root inside AICOMMANDER_CONFIG_DIR", () => {
    process.env[ENV_DIR_VAR] = OVERRIDE_DIR;
    cmdUninstall({ force: true });
    expect(removedPaths()).toContain(path.join(OVERRIDE_DIR, "jobs"));
  });

  it("takes the jobs root before the config dir, so the config dir can go too", () => {
    process.env[ENV_DIR_VAR] = OVERRIDE_DIR;
    cmdUninstall({ force: true });
    const jobs = removedPaths().indexOf(path.join(OVERRIDE_DIR, "jobs"));
    const session = removedPaths().indexOf(path.join(OVERRIDE_DIR, "session.json"));
    expect(jobs).toBeGreaterThanOrEqual(0);
    expect(jobs).toBeLessThan(session);
  });

  it("accepts a root holding job dirs, gpu locks and the shared home", () => {
    vi.mocked(fs.readdirSync).mockReturnValue([
      "0123456789abcdef",
      "gpu-0.lock",
      "home",
    ] as never);
    cmdUninstall({ force: true });
    expect(removedPaths()).toContain(SERVICE_JOBS_ROOT);
  });

  it("refuses a root holding a lock name job-manager could not have written", () => {
    // The lock recogniser is the protocol package's own (isGpuLockFileName), so it
    // bounds the index exactly as the agent does when it CREATES one. A file that
    // merely looks lock-ish is a stranger's file, and a root containing one does
    // not get an rm -rf.
    vi.mocked(fs.readdirSync).mockReturnValue(["0123456789abcdef", "gpu-9999.lock"] as never);
    cmdUninstall({ force: true });
    expect(removedPaths()).not.toContain(SERVICE_JOBS_ROOT);
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain(SERVICE_JOBS_ROOT);
  });

  it("refuses to delete a path that does not look like a jobs root", () => {
    vi.mocked(fs.readdirSync).mockReturnValue(["important-user-file.txt"] as never);
    cmdUninstall({ force: true });
    expect(removedPaths()).not.toContain(SERVICE_JOBS_ROOT);
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain(SERVICE_JOBS_ROOT);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  it("refuses to follow a symlinked jobs root", () => {
    vi.mocked(fs.lstatSync).mockReturnValue({
      isSymbolicLink: () => true,
      isDirectory: () => true,
    } as unknown as ReturnType<typeof fs.lstatSync>);
    cmdUninstall({ force: true });
    expect(removedPaths()).not.toContain(SERVICE_JOBS_ROOT);
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain(SERVICE_JOBS_ROOT);
  });

  it("refuses a root it cannot inspect rather than deleting it blind", () => {
    // Throw for the JOBS ROOT only. /proc is walked by this same readdirSync,
    // and an unreadable /proc aborts the uninstall before the jobs root is ever
    // inspected — fail-closed, and covered by its own test below. Throwing for
    // every path made this assert THAT path instead: green on macOS, where
    // scanProcFs() returns [] without touching readdirSync, and red on Linux.
    vi.mocked(fs.readdirSync).mockImplementation(((dir: string) => {
      if (String(dir) === SERVICE_JOBS_ROOT) throw new Error("EACCES: permission denied");
      return [];
    }) as never);
    cmdUninstall({ force: true });
    expect(removedPaths()).not.toContain(SERVICE_JOBS_ROOT);
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain(SERVICE_JOBS_ROOT);
  });

  it("skips a jobs root that is not there", () => {
    vi.mocked(fs.lstatSync).mockImplementation(() => {
      throw new Error("ENOENT");
    });
    cmdUninstall({ force: true });
    expect(removedPaths()).not.toContain(SERVICE_JOBS_ROOT);
    // Absent is not a leftover.
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).not.toContain(SERVICE_JOBS_ROOT);
  });

  it("drops /var/lib/aicommander itself once its jobs root is gone", () => {
    cmdUninstall({ force: true });
    expect(vi.mocked(fs.rmdirSync)).toHaveBeenCalledWith("/var/lib/aicommander");
  });
});

// A stopped UNIT is not a stopped AGENT. Every one of these agents makes
// `systemctl is-active` answer `inactive` truthfully — it was started by hand,
// by the QNAP init script, or it outlived the unit that once owned it — and the
// removals below would take the binary, the session credential and the device
// identity away from a live root-exec process.
describe("cmdUninstall — a live agent process outside the unit", () => {
  const STATE_FILE = `${STATE_DIR}/state.json`;
  const AGENT_ARGV = [BIN, "run"];

  /**
   * A synthetic process-table entry. "opaque" (or the object form with `opaque`)
   * is alive but indescribable — exe and cmdline unreadable; the object form can
   * additionally carry a /proc/<pid>/stat line, which is what stays readable for
   * the kernel threads and zombies a stale recorded pid gets recycled onto.
   */
  type FakeProcEntry =
    | { exe: string; argv: string[] }
    | { opaque: true; stat?: string }
    | "opaque";

  function isOpaque(proc: FakeProcEntry): proc is { opaque: true; stat?: string } | "opaque" {
    return proc === "opaque" || "opaque" in proc;
  }

  /**
   * Install a synthetic Linux process table. Platform is forced so the same
   * assertions run identically on Linux and macOS, and `process.kill` answers
   * from the table rather than from whatever this machine happens to be running.
   */
  function givenProcesses(
    procs: Record<number, FakeProcEntry>,
    state?: { pid: number },
  ): void {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    vi.spyOn(process, "kill").mockImplementation(((pid: number) => {
      if (!(pid in procs)) {
        const err = new Error("ESRCH") as NodeJS.ErrnoException;
        err.code = "ESRCH";
        throw err;
      }
      return true;
    }) as never);
    vi.mocked(fs.readFileSync).mockImplementation(((file: string) => {
      if (String(file) === STATE_FILE) {
        if (!state) throw new Error("ENOENT");
        return JSON.stringify({ ...state, sessionCode: "AIC-WOLF-2345-WXYZ" });
      }
      const statMatch = /^\/proc\/(\d+)\/stat$/.exec(String(file));
      if (statMatch) {
        const proc = procs[Number(statMatch[1])];
        if (proc && proc !== "opaque" && "stat" in proc && proc.stat !== undefined) return proc.stat;
        throw new Error("ENOENT");
      }
      const match = /^\/proc\/(\d+)\/cmdline$/.exec(String(file));
      const proc = match ? procs[Number(match[1])] : undefined;
      if (!proc || isOpaque(proc)) throw new Error("ENOENT");
      return `${proc.argv.join("\0")}\0`;
    }) as never);
    vi.mocked(fs.readlinkSync).mockImplementation(((file: string) => {
      const match = /^\/proc\/(\d+)\/exe$/.exec(String(file));
      const proc = match ? procs[Number(match[1])] : undefined;
      if (!proc || isOpaque(proc)) throw new Error("EACCES");
      return proc.exe;
    }) as never);
    // /proc is walked by the same readdirSync the jobs-root check uses, so keep
    // the two apart: only /proc holds pids.
    vi.mocked(fs.readdirSync).mockImplementation(((dir: string) =>
      String(dir) === "/proc" ? Object.keys(procs) : []) as never);
  }

  it("removes NOTHING while an agent is running outside the unit", () => {
    givenProcesses({ 4242: { exe: BIN, argv: AGENT_ARGV } });
    cmdUninstall({ force: true });
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(removedPaths()).toEqual([]);
    expect(vi.mocked(fs.rmdirSync)).not.toHaveBeenCalled();
    // Not even the unit is touched: nothing changed, so a retry starts clean.
    expect(vi.mocked(systemctlDisable)).not.toHaveBeenCalled();
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  it("names the surviving pid and how to deal with it", () => {
    givenProcesses({ 4242: { exe: BIN, argv: AGENT_ARGV } });
    cmdUninstall({ force: true });
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(errors).toContain("STILL running");
    expect(errors).toContain("4242");
    expect(warnings).toContain("kill 4242");
    expect(warnings).toContain("uninstall --force");
  });

  it("names the supervisor AND the worker, not just the one state.json recorded", () => {
    givenProcesses(
      { 100: { exe: BIN, argv: AGENT_ARGV }, 101: { exe: BIN, argv: AGENT_ARGV } },
      { pid: 101 },
    );
    cmdUninstall({ force: true });
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain("100");
    expect(errors).toContain("101");
    expect(removedPaths()).toEqual([]);
  });

  // The mirror case, and the one a fail-closed check must not break: the file
  // outlives its process (clearState runs only from the signal handler), so a
  // recorded pid is a claim, not a fact.
  it("proceeds when state.json records a pid that is dead", () => {
    givenProcesses({}, { pid: 31337 });
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  it("proceeds when the recorded pid was recycled onto an unrelated process", () => {
    givenProcesses({ 555: { exe: "/usr/sbin/nginx", argv: ["nginx: worker"] } }, { pid: 555 });
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
  });

  // Trap and hard requirement: `aicommander-agent uninstall` IS the binary the
  // check looks for, and its own pid is in the very /proc it walks.
  it("does not detect itself and abort every uninstall", () => {
    givenProcesses(
      { [process.pid]: { exe: BIN, argv: [BIN, "uninstall", "--force"] } },
      { pid: process.pid },
    );
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  it("fails closed when something is alive under the recorded pid but unreadable", () => {
    givenProcesses({ 556: "opaque" }, { pid: 556 });
    cmdUninstall({ force: true });
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(removedPaths()).toEqual([]);
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain("Could NOT determine");
    expect(errors).toContain("556");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  // The /proc walk is the only source that finds an agent nobody wrote down —
  // which is the whole reason the process check exists — so a walk that could
  // not run must be an abort, not a silent "found nothing". Before the fix, an
  // unreadable /proc read as an empty one and the root credential was deleted
  // on the strength of a scan that never happened.
  it("removes NOTHING when /proc itself cannot be enumerated", () => {
    givenProcesses({});
    vi.mocked(fs.readdirSync).mockImplementation(((dir: string) => {
      if (String(dir) === "/proc") throw new Error("EACCES");
      return [];
    }) as never);
    cmdUninstall({ force: true });
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(removedPaths()).toEqual([]);
    expect(vi.mocked(fs.rmdirSync)).not.toHaveBeenCalled();
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain("Could NOT scan");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  it("proceeds when /proc is readable and simply holds no agent", () => {
    // The other half of the same distinction: an EMPTY scan is a real answer,
    // and must not be caught in the failed-scan net — a fail-closed check that
    // also fails on success would make every uninstall impossible.
    givenProcesses({});
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  // A stale state.json is routine (clearState raced process.exit for years) and
  // pids get recycled — sometimes onto things that pass kill(pid, 0) but have
  // no exe to read: kernel threads and zombies. Aborting there printed a
  // `kill <pid>` remedy that cannot work on either, leaving reboot as the only
  // way to ever uninstall.
  it("proceeds when the recorded pid was recycled onto a kernel thread", () => {
    givenProcesses(
      // PF_KTHREAD (0x00200000) set in stat field 9.
      { 600: { opaque: true, stat: "600 (kworker/0:1) I 2 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 22 0 0" } },
      { pid: 600 },
    );
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  it("proceeds when the recorded pid is a zombie", () => {
    givenProcesses(
      { 601: { opaque: true, stat: "601 (agent) Z 1 601 601 0 -1 4194364 0 0 0 0 0 0 0 0 20 0 1 0 22 0 0" } },
      { pid: 601 },
    );
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
  });

  it("still completes a normal uninstall with nothing running at all", () => {
    givenProcesses({ 2: { exe: "/usr/sbin/sshd", argv: ["sshd: root@pts/0"] } });
    cmdUninstall({ force: true });
    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(BIN);
    expect(removedPaths()).toContain(DEVICE_DIR);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  // The process check runs AFTER the unit is proven stopped, and only then: a
  // unit we could not stop already aborts, and must keep its own message.
  it("keeps the unit's own abort message when the unit itself is still active", () => {
    givenProcesses({ 4242: { exe: BIN, argv: AGENT_ARGV } });
    vi.mocked(systemctlActiveState).mockReturnValue("active");
    cmdUninstall({ force: true });
    expect(removedPaths()).toEqual([]);
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain("after stop and SIGKILL");
  });
});

/**
 * The consequence of job-scope.ts. Jobs used to die with the unit — the unit is
 * KillMode=control-group, so `systemctl stop` emptied the whole cgroup — and the
 * removals below leaned on that. A job in its own scope survives the stop, so
 * the uninstall has to take it down itself before deleting the output.log and
 * workspace it is still writing to.
 */
describe("cmdUninstall — leftover job scopes", () => {
  const SCOPE_A = "aic-job-0123456789abcdef.scope";
  const SCOPE_B = "aic-job-fedcba9876543210.scope";
  const JOBS_ROOT = "/var/lib/aicommander/jobs";

  it("stops every leftover scope BEFORE deleting the jobs roots", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A, SCOPE_B]);
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlStopUnit).mock.calls.map((c) => c[0])).toEqual([SCOPE_A, SCOPE_B]);
    // Order is the whole point: a scope stopped after the delete would have had
    // its log and workspace pulled out from under a live root process.
    const lastStop = Math.max(
      ...vi.mocked(systemctlStopUnit).mock.invocationCallOrder,
    );
    const jobsRootDelete = vi
      .mocked(fs.rmSync)
      .mock.calls.findIndex((c) => String(c[0]) === JOBS_ROOT);
    expect(jobsRootDelete).toBeGreaterThanOrEqual(0);
    expect(vi.mocked(fs.rmSync).mock.invocationCallOrder[jobsRootDelete]).toBeGreaterThan(lastStop);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  // The success case, asserted explicitly so the suppression tests below cannot
  // pass by simply never deleting anything.
  it("DOES delete the jobs roots once every scope is verifiably down", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A]);
    cmdUninstall({ force: true });
    expect(removedPaths()).toContain(JOBS_ROOT);
    expect(removedPaths()).toContain(USER_JOBS_ROOT);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  it("a scope that survives even SIGKILL KEEPS the jobs roots on disk", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A]);
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      throw new Error("Failed to stop aic-job-0123456789abcdef.scope");
    });
    vi.mocked(systemctlKillUnit).mockImplementation(() => {
      throw new Error("Failed to kill aic-job-0123456789abcdef.scope");
    });
    cmdUninstall({ force: true });
    // The whole point of issue 1: the command KNOWS a root job may still be
    // running, so it must not delete the output.log and workspace it is writing.
    expect(removedPaths()).not.toContain(JOBS_ROOT);
    expect(removedPaths()).not.toContain(USER_JOBS_ROOT);
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain(SCOPE_A);
    expect(errors).toContain("KEPT");
    expect(errors).toContain(JOBS_ROOT);
    // …and the operator is told how to finish once it is safe.
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("systemctl stop 'aic-job-*.scope'");
    expect(warnings).toContain(`rm -rf ${JOBS_ROOT}`);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  // Escalation: a stop that will not go is SIGKILLed, and the kill is VERIFIED
  // by re-listing before the job data may be deleted.
  it("SIGKILLs a scope that would not stop, says so, and then deletes", () => {
    vi.mocked(listJobScopeUnits)
      .mockReturnValueOnce([SCOPE_A]) // the teardown's own enumeration
      .mockReturnValue([]);           // the post-kill verification: it is gone
    // The genuine article, not a guess at its shape — see the helper.
    const timeout = realExecFileSyncTimeoutError();
    expect((timeout as NodeJS.ErrnoException).code).toBe("ETIMEDOUT");
    expect((timeout as { killed?: boolean }).killed).toBeUndefined();
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      throw timeout;
    });
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlKillUnit).mock.calls.map((c) => c[0])).toEqual([SCOPE_A]);
    // Destroying a running job is never done quietly.
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("SIGKILL");
    expect(warnings).toContain("ENDED");
    // A stop that TIMED OUT is a unit that demonstrably still exists, so the
    // operator gets the blunt wording, not the hedged "if it is still running".
    expect(warnings).toContain("did not stop within 15s");
    expect(warnings).not.toContain("could not be stopped");
    expect(removedPaths()).toContain(JOBS_ROOT);
  });

  // The other half of that distinction: a stop that failed for ANY other reason
  // may be a unit that simply ended, so the warning must not claim it is there.
  it("hedges the wording when a stop failed for a reason other than a timeout", () => {
    vi.mocked(listJobScopeUnits)
      .mockReturnValueOnce([SCOPE_A])
      .mockReturnValue([]);
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      // What a non-zero systemctl exit really looks like: a numeric status and
      // no string `code` — nothing a timeout check may confuse for ETIMEDOUT.
      throw Object.assign(new Error("Command failed"), { status: 5, signal: null });
    });
    cmdUninstall({ force: true });
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("could not be stopped — escalating to SIGKILL");
    expect(warnings).not.toContain("did not stop within");
  });

  it("treats a killed scope that is STILL listed as alive and keeps the data", () => {
    // The kill only SENDS the signal; a unit still there afterwards was not
    // proven gone, and an unproven kill must not buy the delete its go-ahead.
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A]);
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      throw new Error("Failed to stop");
    });
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlKillUnit)).toHaveBeenCalled();
    expect(removedPaths()).not.toContain(JOBS_ROOT);
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  // A job that ENDS NORMALLY between the listing and the stop. systemd answers
  // "Unit … not loaded." with a non-zero exit to BOTH the stop and the kill —
  // the exact shape of a scope that would not die — so nothing but a fresh
  // listing can tell the two apart, and the asymmetry cuts both ways: cleanup
  // must not be withheld from a job that has demonstrably finished.
  it("treats a scope that disappeared before the stop as gone, and deletes", () => {
    vi.mocked(listJobScopeUnits)
      .mockReturnValueOnce([SCOPE_A]) // the teardown's own enumeration
      .mockReturnValue([]);           // it ended on its own in the meantime
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      throw new Error("Failed to stop aic-job-0123456789abcdef.scope: Unit aic-job-0123456789abcdef.scope not loaded.");
    });
    vi.mocked(systemctlKillUnit).mockImplementation(() => {
      throw new Error("Failed to kill unit aic-job-0123456789abcdef.scope: Unit aic-job-0123456789abcdef.scope not loaded.");
    });
    cmdUninstall({ force: true });
    expect(removedPaths()).toContain(JOBS_ROOT);
    expect(removedPaths()).toContain(USER_JOBS_ROOT);
    // …and the operator is not told a job may still be running as root.
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).not.toContain("could NOT be stopped");
    expect(errors).not.toContain("KEPT");
    // It ended by itself; we did not destroy it, so it is not reported as ENDED.
    expect(vi.mocked(ui.warn).mock.calls.flat().join(" ")).not.toContain("ENDED");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });

  // A machine that never ran a job has no jobs root on disk. A failed teardown
  // must still be reported — but not as "workspaces were KEPT", which would
  // announce data that does not exist and send the operator hunting for it.
  it("does not claim job data was KEPT when there is no jobs root at all", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A]);
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      throw new Error("Failed to stop");
    });
    vi.mocked(systemctlKillUnit).mockImplementation(() => {
      throw new Error("Failed to kill");
    });
    // Nothing is there to classify: every jobs root is absent.
    vi.mocked(fs.lstatSync).mockImplementation((() => {
      throw new Error("ENOENT");
    }) as never);
    cmdUninstall({ force: true });
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).not.toContain("KEPT");
    // The scope that would not die is still named, and the remedy for IT stands.
    expect(errors).toContain(SCOPE_A);
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain("systemctl stop 'aic-job-*.scope'");
    expect(warnings).not.toContain("rm -rf");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  // The keep branch must apply the SAME classification as the delete branch: a
  // directory we refuse to delete because it is not ours must not then be named
  // as our job workspace, nor pasted into a remedy that deletes it by hand.
  it("never names — or pastes — a foreign root among the kept job workspaces", () => {
    vi.mocked(listJobScopeUnits).mockReturnValue([SCOPE_A]);
    vi.mocked(systemctlStopUnit).mockImplementation(() => {
      throw new Error("Failed to stop");
    });
    vi.mocked(systemctlKillUnit).mockImplementation(() => {
      throw new Error("Failed to kill");
    });
    vi.mocked(fs.readdirSync).mockImplementation(((dir: string) =>
      String(dir) === JOBS_ROOT ? ["important-user-file.txt"] : []) as never);
    cmdUninstall({ force: true });
    const errors = vi.mocked(ui.error).mock.calls.flat().join(" ");
    expect(errors).toContain(`${JOBS_ROOT} does not look like a jobs directory`);
    const warnings = vi.mocked(ui.warn).mock.calls.flat().join(" ");
    expect(warnings).toContain(`rm -rf ${USER_JOBS_ROOT}`);
    expect(warnings).not.toContain(`rm -rf ${JOBS_ROOT}`);
    // Still a leftover, so the claim at the end stays false.
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  it("keeps the jobs roots when the scopes could not even be listed", () => {
    // Null, not []: "we could not look" and "there was nothing" are different
    // answers, and only one of them supports deleting a job's files — or the
    // claim at the end.
    vi.mocked(listJobScopeUnits).mockReturnValue(null);
    cmdUninstall({ force: true });
    expect(vi.mocked(systemctlStopUnit)).not.toHaveBeenCalled();
    expect(removedPaths()).not.toContain(JOBS_ROOT);
    expect(removedPaths()).not.toContain(USER_JOBS_ROOT);
    expect(vi.mocked(ui.warn).mock.calls.flat().join(" ")).toContain("aic-job-*.scope");
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain("KEPT");
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
  });

  it("never asks about scopes on a machine that has no systemd", () => {
    // No manager, no scopes — and a systemctl call there is pure noise.
    vi.mocked(systemctlActiveState).mockReturnValue(NO_SYSTEMD);
    cmdUninstall({ force: true });
    expect(vi.mocked(listJobScopeUnits)).not.toHaveBeenCalled();
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).toContain("fully removed");
  });
});
