// The live antivirus-interference probe.
//
// PLATFORM NOTE. This is a Windows story — the artefact a behavioural engine
// scores is a `.cmd` — and the agent package's Windows CI job is deliberately
// narrow because most of the suite assumes POSIX. So the Windows path is DRIVEN
// here the way job-scripts.test.ts and job-manager-start-window.test.ts drive
// theirs: `process.platform` is pinned to win32 BEFORE the dynamic import,
// because av-probe.ts reads it once at module load.
//
// Three things are pinned, and each of them is a way the check could quietly
// stop being worth running:
//   - a clean machine passes, and the scratch directory is GONE afterwards;
//   - a refused write and a vanished read-back are both reported as
//     interference, with the fault detail carried through verbatim;
//   - the scratch directory is gone after a failure too, and after a throw.

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Staged faults. Off by default, so the happy path writes and reads for real. */
const stage = vi.hoisted(() => ({
  writeFault: null as string | null,
  writeThrows: null as string | null,
  readFault: null as string | null,
  /**
   * What was actually ON DISK when the read-back ran, captured by the verifier's
   * pass-through. The WRITER is never mocked in the test that checks these: the
   * whole reason the probe reuses `writeWindowsJobScripts` is that the bytes a
   * scanner scores must be the bytes a real job start writes, and a mocked
   * writer asserts nothing about them.
   */
  onDisk: null as { wrapper: string; command: string } | null,
  /** Simulates a REAL job appearing in the jobs root while the probe is running. */
  plantInJobsRoot: false,
}));

vi.mock("../job-scripts.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../job-scripts.js")>();
  return {
    ...actual,
    writeWindowsJobScripts: async (dir: string, command: string): Promise<string | null> => {
      if (stage.writeThrows !== null) {
        const err: NodeJS.ErrnoException = new Error(`${stage.writeThrows}: no space left on device`);
        err.code = stage.writeThrows;
        throw err;
      }
      if (stage.writeFault !== null) return stage.writeFault;
      return actual.writeWindowsJobScripts(dir, command);
    },
    verifyWindowsJobScripts: async (dir: string, command: string): Promise<string | null> => {
      // Read the real files before anything else touches them; this is the last
      // moment they exist (the probe removes the directory straight after).
      try {
        stage.onDisk = {
          wrapper: fs.readFileSync(path.join(dir, actual.WRAPPER_FILE), "utf8"),
          command: fs.readFileSync(path.join(dir, actual.COMMAND_FILE), "utf8"),
        };
      } catch {
        stage.onDisk = null;
      }
      if (stage.plantInJobsRoot) fs.writeFileSync(path.join(dir, "..", "a-real-job.txt"), "x");
      if (stage.readFault !== null) return stage.readFault;
      return actual.verifyWindowsJobScripts(dir, command);
    },
  };
});

type ProbeModule = typeof import("../doctor/checks/av-probe.js");
let probeModule: ProbeModule;
const realPlatform = process.platform;

beforeAll(async () => {
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  probeModule = await import("../doctor/checks/av-probe.js");
});

afterAll(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

let configDir: string;

beforeEach(() => {
  stage.writeFault = null;
  stage.writeThrows = null;
  stage.readFault = null;
  stage.onDisk = null;
  stage.plantInJobsRoot = false;
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-av-"));
});

afterEach(() => {
  fs.rmSync(configDir, { recursive: true, force: true });
});

function ctx() {
  return {
    configDir,
    serverUrl: "https://relay.invalid",
    offline: true,
    networkTimeoutMs: 100,
    // No pause: the delay exists for a real scanner, and a test that waited for
    // one would only be slower.
    probeDelayMs: 0,
  };
}

/** Everything the probe could have left behind, under the jobs root it uses. */
function leftovers(): string[] {
  const jobsRoot = path.join(configDir, "jobs");
  try {
    return fs.readdirSync(jobsRoot);
  } catch {
    return [];
  }
}

describe("antivirus interference probe", () => {
  it("passes on a machine with nothing interfering, and leaves nothing behind", async () => {
    const [result] = await probeModule.antivirusProbeChecks.run(ctx());
    expect(result!.verdict).toBe("ok");
    expect(result!.detail).toMatch(/read them back unchanged/);
    expect(leftovers()).toEqual([]);
  });

  it("fails when the write is refused, and still cleans up", async () => {
    stage.writeFault = "wrapper.cmd could not be written (EACCES)";
    const results = await probeModule.antivirusProbeChecks.run(ctx());
    expect(results[0]!.verdict).toBe("fail");
    expect(results[0]!.detail).toContain("wrapper.cmd could not be written (EACCES)");
    expect(results[0]!.facts?.["stage"]).toBe("write");
    expect(results[0]!.remedy).toMatch(/aicommander\.dev\/antivirus/);
    expect(leftovers()).toEqual([]);
    // The cleanup is REPORTED even when it worked: "nothing was left behind" is
    // a claim, and the report has to be able to support it — including the
    // window over which it was actually verified.
    const cleanup = results.find((r) => r.id === "av.probe_cleanup");
    expect(cleanup?.verdict).toBe("ok");
    expect(cleanup?.detail).toMatch(/still gone \d+ms later/);
    expect(typeof cleanup?.facts?.["observedForMs"]).toBe("number");
  });

  it("fails when a script does not survive to the read-back — the incident's exact moment", async () => {
    stage.readFault = "wrapper.cmd is gone";
    const [result] = await probeModule.antivirusProbeChecks.run(ctx());
    expect(result!.verdict).toBe("fail");
    expect(result!.detail).toContain("wrapper.cmd is gone");
    expect(result!.detail).toMatch(/[Ss]ecurity software/);
    expect(result!.facts?.["stage"]).toBe("read-back");
    expect(leftovers()).toEqual([]);
  });

  it("calls a storage fault a storage fault, not an antivirus incident", async () => {
    // job-scripts.ts throws (rather than returning a detail) for anything that
    // is not the interference family, and sending that operator to the
    // antivirus page would be sending them to the wrong page.
    stage.writeThrows = "ENOSPC";
    const [result] = await probeModule.antivirusProbeChecks.run(ctx());
    expect(result!.verdict).toBe("fail");
    expect(result!.remedy).toMatch(/storage fault/);
    expect(result!.remedy).not.toMatch(/antivirus/);
    expect(leftovers()).toEqual([]);
  });

  it("writes the real wrapper VERBATIM and an inert command, and executes nothing", async () => {
    // The property this protects is byte-for-byte identity with the frozen
    // WINDOWS_JOB_WRAPPER (PLAN-av-hardening W4): a probe that wrote a lookalike
    // would be measuring a scanner's response to something no job ever writes.
    // So nothing is mocked out here — the real writer runs and the bytes are
    // read back off disk.
    const jobScripts = await import("../job-scripts.js");
    const [result] = await probeModule.antivirusProbeChecks.run(ctx());
    expect(result!.verdict).toBe("ok");
    expect(stage.onDisk).not.toBeNull();
    expect(stage.onDisk!.wrapper).toBe(jobScripts.WINDOWS_JOB_WRAPPER);
    // The command batch is the real one too, carrying an inert command of ours.
    expect(stage.onDisk!.command).toContain("echo aicommander-doctor-probe");
    // Nothing is executed: no shell is started, so the batch's own marker
    // (written by a RUN, not by a write) is nowhere on disk.
    expect(leftovers()).toEqual([]);
  });

  it("names the scratch directory so no job manager can mistake it for a job", async () => {
    let seen = "";
    const jobScripts = await import("../job-scripts.js");
    const spy = vi
      .spyOn(jobScripts, "verifyWindowsJobScripts")
      .mockImplementation(async (dir: string) => {
        seen = dir;
        return null;
      });
    try {
      await probeModule.antivirusProbeChecks.run(ctx());
    } finally {
      spy.mockRestore();
    }
    // Dot-prefixed, so a job manager in another process cannot mistake the
    // scratch directory for a job while it exists.
    expect(path.basename(seen).startsWith(".doctor-probe-")).toBe(true);
  });

  it("does not leave the JOBS ROOT behind on a machine that never ran a job", async () => {
    // atomicWriteUtf8Async opens with mkdir({recursive:true}), so the probe
    // brings the whole jobs directory into existence on a fresh machine. "Leaves
    // behind NOTHING" includes the directory we had to create to probe at all.
    const jobsRoot = path.join(configDir, "jobs");
    expect(fs.existsSync(jobsRoot)).toBe(false);
    await probeModule.antivirusProbeChecks.run(ctx());
    expect(fs.existsSync(jobsRoot)).toBe(false);
  });

  it("keeps a jobs root that was already there, and anything in it", async () => {
    const jobsRoot = path.join(configDir, "jobs");
    fs.mkdirSync(path.join(jobsRoot, "20260902-abcdef"), { recursive: true });
    await probeModule.antivirusProbeChecks.run(ctx());
    expect(fs.readdirSync(jobsRoot)).toEqual(["20260902-abcdef"]);
  });

  it("reports a scratch directory that would not stay deleted", async () => {
    // The write we gave up on cannot be cancelled — when the scanner lets go,
    // the abandoned call recreates what we removed. A cleanup that reported
    // success on the strength of one `rm` would say the machine is clean while
    // a `.cmd` sits in the jobs root waiting for the next scan.
    let probeDir = "";
    const jobScripts = await import("../job-scripts.js");
    const spy = vi
      .spyOn(jobScripts, "verifyWindowsJobScripts")
      .mockImplementation(async (dir: string) => {
        probeDir = dir;
        return null;
      });
    const realRm = fs.promises.rm.bind(fs.promises);
    let resurrected = false;
    const rm = vi.spyOn(fs.promises, "rm").mockImplementation((async (target: string, opts: unknown) => {
      await realRm(target, opts as Parameters<typeof realRm>[1]);
      // The abandoned write landing a moment AFTER the removal, exactly once —
      // which is what a filter driver finally letting go of the handle looks
      // like from here.
      if (probeDir && String(target) === probeDir && !resurrected) {
        resurrected = true;
        setTimeout(() => fs.mkdirSync(probeDir, { recursive: true }), 5);
      }
    }) as unknown as typeof fs.promises.rm);
    let results;
    try {
      results = await probeModule.antivirusProbeChecks.run(ctx());
    } finally {
      rm.mockRestore();
      spy.mockRestore();
      fs.rmSync(probeDir, { recursive: true, force: true });
    }
    const cleanup = results.find((r) => r.id === "av.probe_cleanup")!;
    expect(cleanup).toBeDefined();
    expect(cleanup.verdict).toBe("warn");
    expect(cleanup.detail).toMatch(/came BACK/);
  });

  it("skips itself when the config override leaves no jobs directory to probe", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = "relative/not/absolute";
    try {
      const [result] = await probeModule.antivirusProbeChecks.run({
        serverUrl: "https://relay.invalid",
        offline: true,
        networkTimeoutMs: 100,
        probeDelayMs: 0,
      });
      expect(result!.verdict).toBe("skipped");
      expect(result!.detail).toMatch(/refuses to start with/);
    } finally {
      delete process.env["AICOMMANDER_CONFIG_DIR"];
    }
  });
});

describe("what the probe leaves behind, one level up", () => {
  // `atomicWriteUtf8Async` creates the jobs root with mkdir -p, so on a machine
  // that has never run a job the probe brings the whole directory into
  // existence. Removing it again used to be `.catch(() => undefined)`: the
  // scratch directory was verified and the directory above it, which we had also
  // created, was not — a one-sided cleanup under a header promising nothing is
  // left behind.
  it("removes the jobs root it created, and says that it did", async () => {
    const results = await probeModule.antivirusProbeChecks.run(ctx());
    const cleanup = results.find((r) => r.id === "av.probe_cleanup")!;
    expect(cleanup.verdict).toBe("ok");
    expect(cleanup.facts?.["jobsRootCleanup"]).toBe("removed");
    expect(fs.existsSync(path.join(configDir, "jobs"))).toBe(false);
  });

  it("keeps — and reports keeping — a jobs root a real job moved into meanwhile", async () => {
    // rmdir, never rm -r: the directory is no longer ours alone.
    stage.plantInJobsRoot = true;
    const results = await probeModule.antivirusProbeChecks.run(ctx());
    const cleanup = results.find((r) => r.id === "av.probe_cleanup")!;
    expect(cleanup.verdict).toBe("ok");
    expect(cleanup.facts?.["jobsRootCleanup"]).toBe("kept");
    expect(cleanup.detail).toMatch(/left in place/);
    expect(fs.existsSync(path.join(configDir, "jobs", "a-real-job.txt"))).toBe(true);
  });
});
