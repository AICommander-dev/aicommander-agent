// What the manager does with a start that failed because the job's own scripts
// were gone — the W3.1 path (PLAN-av-hardening.md), where security software takes
// wrapper.cmd / command.cmd between our write and cmd.exe's read.
//
// The scripts themselves, and the check that spots the fault, are covered
// platform-neutrally in job-scripts.test.ts. What is left to pin is the WIRING,
// and it has two parts that are easy to get wrong and impossible to notice:
//
//  - the named cause must reach the caller INTACT. start() wraps whatever
//    spawnJob throws into "Could not start the job: …", which would bury the one
//    error the relay recognises (jobs-relay.ts matches on its leading token)
//    inside a generic sentence.
//  - nothing may be left on disk. The manager reconciles jobs across restarts,
//    and a record whose process never existed — with a GPU lock still held — is
//    exactly the state refresh() and the retention sweep have to puzzle over.
//
// Staged on any platform by making the SPAWN itself throw that error, because the
// real producer is behind `isWindows` and a macOS/Linux run would skip the whole
// group otherwise. On Windows the identical JobError arrives from
// verifyWindowsJobScripts one line earlier, and everything below it is the same
// code.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gpuLockFileName, JOB_SCRIPT_REMOVED_ERROR } from "@aicommander/protocol";

/** The spawn boundary, with a start failure available on demand. */
const spawnFault = vi.hoisted(() => ({ error: null as Error | null }));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (...args: unknown[]) => {
      if (spawnFault.error !== null) throw spawnFault.error;
      return (actual.spawn as unknown as (...a: unknown[]) => unknown)(...args);
    },
  };
});

import { JobError, JobManager, resetJobManagerForTests } from "../job-manager.js";
import { jobScriptRemovedMessage, WRAPPER_FILE } from "../job-scripts.js";

const FAULT = `${WRAPPER_FILE} is gone`;

let tmpBase: string;
let jobsRoot: string;
let manager: JobManager;

beforeEach(() => {
  spawnFault.error = null;
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobs-fault-"));
  jobsRoot = path.join(tmpBase, "jobs");
  manager = new JobManager({ jobsRoot });
});

afterEach(() => {
  spawnFault.error = null;
  vi.restoreAllMocks();
  resetJobManagerForTests();
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

async function startWithFault(req: Parameters<JobManager["start"]>[0]): Promise<JobError> {
  // The identical error the real producer throws, cause and detail included —
  // both are what the diagnostic log records (see connection.ts).
  spawnFault.error = new JobError(jobScriptRemovedMessage(FAULT), JOB_SCRIPT_REMOVED_ERROR, FAULT);
  try {
    await manager.start(req);
  } catch (err) {
    spawnFault.error = null;
    if (err instanceof JobError) return err;
    throw err;
  }
  spawnFault.error = null;
  throw new Error("expected the start to fail");
}

describe("a start whose scripts did not survive", () => {
  it("hands the named cause to the caller unchanged", async () => {
    const err = await startWithFault({ command: "whoami" });

    // Byte-identical, not merely "contains": the relay recognises this error by
    // its leading token, and a prefix of ours would move the token off the front.
    expect(err.message).toBe(jobScriptRemovedMessage(FAULT));
    expect(err.message).not.toContain("Could not start the job");
  });

  it("still wraps an unclassified spawn failure", async () => {
    // The counterpart, so the rule above is "keep a JobError" and not "stop
    // explaining anything". A shell that would not start is not a diagnosis.
    spawnFault.error = new Error("posix_spawn failed");
    await expect(manager.start({ command: "whoami" })).rejects.toThrow(/Could not start the job/);
    spawnFault.error = null;
  });

  it("leaves nothing behind for a later pass to puzzle over", async () => {
    await startWithFault({ command: "whoami" });

    // No record, so refresh() has no `running` job with a pid that never
    // existed, and the retention sweep has no directory it cannot classify.
    const entries = fs.existsSync(jobsRoot) ? fs.readdirSync(jobsRoot) : [];
    expect(entries).toEqual([]);
    const listed = manager.list({});
    expect(listed.ok && listed.kind === "jobs" ? listed.jobs : null).toEqual([]);
  });

  it("gives the card back", async () => {
    // The reservation is taken before the spawn, and a job that never ran is not
    // holding anything. Stranding it would refuse every later job on that card
    // until someone reaped a lock by hand.
    await startWithFault({ command: "whoami", gpuIndex: 0 });

    expect(fs.existsSync(path.join(jobsRoot, gpuLockFileName(0)))).toBe(false);
    // …and the proof that it is really free: the next start gets it.
    const next = await manager.start({ command: "true", gpuIndex: 0 });
    expect(next.ok).toBe(true);
  });
});
