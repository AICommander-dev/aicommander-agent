import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { MockInstance } from "vitest";

/**
 * The uninstall ← systemctl chain, end to end, with NOTHING between cmdUninstall
 * and a real `execFileSync` failure.
 *
 * uninstall.test.ts mocks ctl/systemctl.js and feeds cmdUninstall state strings
 * directly, which pins the STOPPED_STATES decision but cannot catch the bug this
 * file is about: which errno systemctlActiveState TRANSLATES into which state.
 * That mapping is the whole safety property — get it wrong and cmdUninstall is
 * handed a "nothing is running here" it was never entitled to, and deletes the
 * unit file, binary and root-exec credentials of a live agent. So here the real
 * systemctl.ts runs and only node:child_process is faked.
 */
vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
  // job-manager.ts and gpu.ts pull `spawn` off this module at import time;
  // uninstall.ts reaches job-manager.ts for resolveJobsRoot(). Never called here.
  spawn: vi.fn(),
}));

// Same fs mock as uninstall.test.ts: every path "exists" (so a removal that is
// attempted is visible as an rmSync call) and every jobs root looks like an empty
// directory of ours (so the safety classifier would allow the recursive delete).
// Both are deliberately permissive — nothing but the systemctl verdict should be
// able to stop the deletions below.
vi.mock("node:fs", () => ({
  default: {
    existsSync: vi.fn(() => true),
    lstatSync: vi.fn(() => ({
      isSymbolicLink: () => false,
      isDirectory: () => true,
    })) as unknown,
    readdirSync: vi.fn(() => [] as string[]),
    rmSync: vi.fn(),
    rmdirSync: vi.fn(),
    mkdirSync: vi.fn(),
    accessSync: vi.fn(),
    constants: { W_OK: 2 },
  },
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
import { ui } from "../ctl/ui.js";
import { cmdUninstall } from "../ctl/commands/uninstall.js";

const DEVICE_DIR = "/etc/aicommander-agent";

let exitSpy: MockInstance<typeof process.exit>;
let savedEnvDir: string | undefined;
let savedSudoUser: string | undefined;

/**
 * Exactly how Node reports a command it could not spawn: a STRING `code`,
 * `status: null`, and no stdout. Verified against real execFileSync failures —
 * a missing binary yields ENOENT, a present-but-unexecutable one yields EACCES,
 * a non-directory in the path prefix yields ENOTDIR. Crucially, none of these
 * depend on who the test runs as: the errno is produced by the kernel's exec,
 * and we are asserting on the mapping, not on this machine's file modes.
 */
function spawnFailed(code: string): Error {
  return Object.assign(new Error(`spawnSync systemctl ${code}`), {
    code,
    errno: -1,
    syscall: "spawnSync systemctl",
    status: null,
    stdout: undefined,
  });
}

function removedPaths(): string[] {
  return vi.mocked(fs.rmSync).mock.calls.map((c) => String(c[0]));
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(fs.existsSync).mockReturnValue(true);
  vi.mocked(fs.lstatSync).mockReturnValue({
    isSymbolicLink: () => false,
    isDirectory: () => true,
  } as unknown as ReturnType<typeof fs.lstatSync>);
  vi.mocked(fs.readdirSync).mockReturnValue([] as never);
  exitSpy = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  savedEnvDir = process.env["AICOMMANDER_CONFIG_DIR"];
  savedSudoUser = process.env["SUDO_USER"];
  delete process.env["AICOMMANDER_CONFIG_DIR"];
  // SUDO_USER only adds "could not be checked" notes; it would not change any
  // deletion, but clear it so the assertions below read the same everywhere.
  delete process.env["SUDO_USER"];
});

afterEach(() => {
  vi.restoreAllMocks();
  if (savedEnvDir === undefined) delete process.env["AICOMMANDER_CONFIG_DIR"];
  else process.env["AICOMMANDER_CONFIG_DIR"] = savedEnvDir;
  if (savedSudoUser === undefined) delete process.env["SUDO_USER"];
  else process.env["SUDO_USER"] = savedSudoUser;
});

describe("cmdUninstall against a real systemctl spawn failure", () => {
  /**
   * THE regression. A systemctl we cannot execute is not a systemctl that is not
   * there: on a noexec mount, behind a PATH directory we may not traverse, or in
   * a hardened container, the binary exists and systemd may be running the agent
   * at that exact moment. Mapping EACCES to "no systemd" made STOPPED_STATES
   * accept it and the uninstall proceeded — deleting the unit file, the binary
   * and the credentials of a live root-exec agent, the precise outcome the abort
   * path was added to prevent.
   */
  it("deletes NOTHING when systemctl exists but cannot be executed (EACCES)", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      throw spawnFailed("EACCES");
    });

    cmdUninstall({ force: true });

    expect(removedPaths()).toEqual([]);
    expect(vi.mocked(fs.rmdirSync)).not.toHaveBeenCalled();
    expect(exitSpy).toHaveBeenCalledWith(1);
    // It must also not claim a removal it did not perform…
    expect(vi.mocked(ui.ok).mock.calls.flat().join(" ")).not.toContain("fully removed");
    // …and must say it could not find out, rather than assert a running service
    // it never actually observed.
    expect(vi.mocked(ui.error).mock.calls.flat().join(" ")).toContain("Could NOT determine");
  });

  // Same class of non-answer, same verdict: we did not get to ask, so we do not
  // get to delete.
  for (const code of ["EPERM", "ENOEXEC", "EMFILE", "ENOMEM", "EAGAIN"]) {
    it(`deletes NOTHING when the spawn fails with ${code}`, () => {
      vi.mocked(execFileSync).mockImplementation(() => {
        throw spawnFailed(code);
      });

      cmdUninstall({ force: true });

      expect(removedPaths()).toEqual([]);
      expect(exitSpy).toHaveBeenCalledWith(1);
    });
  }

  /**
   * The other side, which must keep working: a box with no systemd at all (macOS,
   * a plain container, QTS) has no unit, nothing to stop, and must stay
   * uninstallable without drama. Tightening the errno mapping must not turn every
   * non-Linux uninstall into a refusal.
   */
  for (const code of ["ENOENT", "ENOTDIR"]) {
    it(`proceeds when there is genuinely no systemctl binary (${code})`, () => {
      vi.mocked(execFileSync).mockImplementation(() => {
        throw spawnFailed(code);
      });

      cmdUninstall({ force: true });

      expect(exitSpy).not.toHaveBeenCalled();
      expect(removedPaths()).toContain(DEVICE_DIR);
    });
  }

  /**
   * A systemctl that RAN still decides on its own answer, unchanged by any of the
   * above: `is-active` exits 3 while printing `inactive`, which is an ordinary
   * "not running" and must not be mistaken for a failed query.
   */
  it("still proceeds when systemctl runs and answers 'inactive' on a non-zero exit", () => {
    vi.mocked(execFileSync).mockImplementation(() => {
      // No `code` — the shape Node uses for "ran, exited non-zero".
      throw Object.assign(new Error("Command failed"), { status: 3, stdout: "inactive\n" });
    });

    cmdUninstall({ force: true });

    expect(exitSpy).not.toHaveBeenCalled();
    expect(removedPaths()).toContain(DEVICE_DIR);
  });
});
