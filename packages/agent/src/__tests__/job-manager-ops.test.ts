// Recoverable starts: the operation index (idempotent operationId), named
// resource locks and the job identity env. POSIX only, like job-manager.test.ts:
// real processes, a temporary jobs root.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { JOB_ID_PATTERN, JOB_RETENTION_MS } from "@aicommander/protocol";
import type { JobRpcResult, JobSummary } from "@aicommander/protocol";
import { JobManager } from "../job-manager.js";

const DEAD_PID = 4_194_305;
const LONG_RUNNING = "sleep 30";

let tmpBase: string;
let jobsRoot: string;
let manager: JobManager;

beforeEach(() => {
  tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "aic-jobops-"));
  jobsRoot = path.join(tmpBase, "jobs");
  manager = new JobManager({ jobsRoot });
});

afterEach(async () => {
  for (const entry of jobDirNames()) {
    try {
      const meta = JSON.parse(fs.readFileSync(path.join(jobsRoot, entry, "meta.json"), "utf8")) as { pid?: number | null };
      if (typeof meta.pid === "number" && meta.pid !== DEAD_PID) process.kill(-meta.pid, "SIGKILL");
    } catch {
      // Already gone, or not a job.
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 25));
  fs.rmSync(tmpBase, { recursive: true, force: true });
});

function opKey(seed: string): string {
  return createHash("sha256").update(seed).digest("hex");
}

function op(seed: string): { operationKey: string; operationId: string } {
  return { operationKey: opKey(seed), operationId: seed };
}

function expectJob(result: JobRpcResult): JobSummary {
  if (!result.ok || result.kind !== "job") throw new Error(`expected a job, got ${JSON.stringify(result)}`);
  return result.job;
}

function expectRefusal(result: JobRpcResult): Extract<JobRpcResult, { ok: false }> {
  if (result.ok) throw new Error(`expected a refusal, got ${JSON.stringify(result)}`);
  return result;
}

function jobDirNames(): string[] {
  try {
    return fs.readdirSync(jobsRoot).filter((entry) => JOB_ID_PATTERN.test(entry));
  } catch {
    return [];
  }
}

function indexPath(seed: string): string {
  return path.join(jobsRoot, ".ops", opKey(seed));
}

function lockPath(name: string): string {
  return path.join(jobsRoot, ".locks", createHash("sha256").update(name).digest("hex"));
}

async function waitFor(what: string, predicate: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function waitForExit(jobId: string): Promise<void> {
  return waitFor(`job ${jobId} to exit`, () => {
    try {
      return /^-?\d+$/.test(fs.readFileSync(path.join(jobsRoot, jobId, "exit"), "utf8").trim());
    } catch {
      return false;
    }
  });
}

/** A finished job record with no process, for the reaping and prune branches. */
function seedJob(extra: Record<string, unknown>): string {
  const jobId = randomBytes(8).toString("hex");
  const dir = path.join(jobsRoot, jobId);
  fs.mkdirSync(path.join(dir, "workspace"), { recursive: true });
  fs.writeFileSync(path.join(dir, "meta.json"), JSON.stringify({
    v: 1, jobId, name: "seeded", command: "seeded", cwd: dir, status: "running", exitCode: null,
    startedAt: Date.now() - 1_000, endedAt: null, gpuIndex: null, pid: DEAD_PID, procIdentity: null,
    truncatedAt: null, ...extra,
  }));
  return jobId;
}

describe("operationId deduplication", () => {
  it("answers a sequential retry with the same job", async () => {
    const first = expectJob(await manager.start({ command: LONG_RUNNING, ...op("train-a") }));
    expect(first.deduplicated).toBeUndefined();
    expect(first.operationId).toBe("train-a");
    const again = expectJob(await manager.start({ command: LONG_RUNNING, ...op("train-a") }));
    expect(again.jobId).toBe(first.jobId);
    expect(again.deduplicated).toBe(true);
    expect(jobDirNames()).toEqual([first.jobId]);
  });

  it("spawns once for 10 parallel starts with the same key", async () => {
    const results = await Promise.all(
      Array.from({ length: 10 }, () => manager.start({ command: LONG_RUNNING, ...op("race") })),
    );
    const fresh = results.filter((r) => r.ok && r.kind === "job" && r.job.deduplicated !== true);
    expect(fresh).toHaveLength(1);
    for (const r of results) {
      if (r.ok) expect(r.kind === "job" && r.job.jobId).toBe(expectJob(fresh[0]!).jobId);
      else expect(r.reason).toBe("operation_in_progress");
    }
    expect(jobDirNames()).toHaveLength(1);
  });

  it("refuses a different start under the same operationId", async () => {
    const first = expectJob(await manager.start({ command: LONG_RUNNING, ...op("conf") }));
    const refusal = expectRefusal(await manager.start({ command: "sleep 31", ...op("conf") }));
    expect(refusal.reason).toBe("operation_conflict");
    expect(refusal.jobId).toBe(first.jobId);
    const locked = expectRefusal(await manager.start({ command: LONG_RUNNING, locks: ["r"], ...op("conf") }));
    expect(locked.reason).toBe("operation_conflict");
  });

  it("removes the index when the start is aborted before the pid, so a retry starts", async () => {
    await expect(
      manager.start({ command: LONG_RUNNING, signal: AbortSignal.abort(), ...op("abort") }),
    ).rejects.toThrow(/nothing was started/);
    expect(fs.existsSync(indexPath("abort"))).toBe(false);
    expect(jobDirNames()).toEqual([]);
    const retry = expectJob(await manager.start({ command: LONG_RUNNING, ...op("abort") }));
    expect(retry.deduplicated).toBeUndefined();
  });

  it("treats an index whose job directory is gone as stale", async () => {
    const first = expectJob(await manager.start({ command: "true", ...op("stale") }));
    await waitForExit(first.jobId);
    fs.rmSync(path.join(jobsRoot, first.jobId), { recursive: true, force: true });
    const second = expectJob(await manager.start({ command: "true", ...op("stale") }));
    expect(second.jobId).not.toBe(first.jobId);
    expect(second.deduplicated).toBeUndefined();
  });

  it("still deduplicates once the job has ended", async () => {
    const first = expectJob(await manager.start({ command: "exit 3", ...op("done") }));
    await waitForExit(first.jobId);
    const again = expectJob(await manager.start({ command: "exit 3", ...op("done") }));
    expect(again).toMatchObject({ jobId: first.jobId, deduplicated: true, status: "exited", exitCode: 3 });
  });

  it("prune removes the index with the job, and recovery reaps orphans", async () => {
    const old = Date.now() - JOB_RETENTION_MS - 60_000;
    const jobId = seedJob({ status: "exited", exitCode: 0, endedAt: old, operationKey: opKey("pruned"), operationId: "pruned" });
    fs.mkdirSync(path.join(jobsRoot, ".ops"), { recursive: true });
    fs.writeFileSync(indexPath("pruned"), JSON.stringify({ jobId, fingerprint: "x" }));
    fs.writeFileSync(indexPath("orphan"), JSON.stringify({ jobId: "aaaaaaaaaaaaaaaa", fingerprint: "x" }));
    manager.recover();
    expect(jobDirNames()).toEqual([]);
    expect(fs.existsSync(indexPath("pruned"))).toBe(false);
    expect(fs.existsSync(indexPath("orphan"))).toBe(false);
  });

  it("looks a job up by operation key", async () => {
    const first = expectJob(await manager.start({ command: LONG_RUNNING, ...op("lookup") }));
    expect(expectJob(manager.status({ jobId: "", operationKey: opKey("lookup") })).jobId).toBe(first.jobId);
    expect(expectRefusal(manager.status({ jobId: "", operationKey: opKey("nope") })).reason).toBe("not_found");
  });

  it("lookup: a torn index is an error, never not_found", () => {
    fs.mkdirSync(path.join(jobsRoot, ".ops"), { recursive: true });
    fs.writeFileSync(indexPath("torn"), "{");
    expect(() => manager.status({ jobId: "", operationKey: opKey("torn") })).toThrow(/operation index/);
  });

  it("lookup: an index whose job directory is gone is stale — not_found, and the index is dropped", async () => {
    const first = expectJob(await manager.start({ command: "true", ...op("gone") }));
    await waitForExit(first.jobId);
    fs.rmSync(path.join(jobsRoot, first.jobId), { recursive: true, force: true });
    expect(expectRefusal(manager.status({ jobId: "", operationKey: opKey("gone") })).reason).toBe("not_found");
    expect(fs.existsSync(indexPath("gone"))).toBe(false);
  });

  it("dedups before the GPU check: a retry is answered after the card disappeared", async () => {
    manager.setKnownGpus([{ index: 0, name: "Test GPU", memoryTotalMb: 1024 } as never]);
    const first = expectJob(await manager.start({ command: LONG_RUNNING, gpuIndex: 0, ...op("gpu-gone") }));
    manager.setKnownGpus([]);
    const again = expectJob(await manager.start({ command: LONG_RUNNING, gpuIndex: 0, ...op("gpu-gone") }));
    expect(again).toMatchObject({ jobId: first.jobId, deduplicated: true });
  });
});

describe("named resource locks", () => {
  it("refuses a held lock and names the holder", async () => {
    const a = expectJob(await manager.start({ command: LONG_RUNNING, locks: ["res"] }));
    expect(a.locks).toEqual(["res"]);
    const refusal = expectRefusal(await manager.start({ command: LONG_RUNNING, locks: ["res"] }));
    expect(refusal).toMatchObject({ reason: "resource_busy", lock: "res", heldBy: a.jobId });
  });

  it("is all-or-nothing: a refused start leaks none of the locks it took", async () => {
    await manager.start({ command: LONG_RUNNING, locks: ["x", "y"] });
    expect(expectRefusal(await manager.start({ command: LONG_RUNNING, locks: ["y", "z"] })).lock).toBe("y");
    expect(fs.existsSync(lockPath("z"))).toBe(false);
    expectJob(await manager.start({ command: LONG_RUNNING, locks: ["z"] }));
    // And the refused start left no job behind (two jobs, not three).
    expect(jobDirNames()).toHaveLength(2);
  });

  it("rolls back a partially acquired set: the free lock taken before the busy one is released", async () => {
    await manager.start({ command: LONG_RUNNING, locks: ["y"] });
    // "a" sorts first, so it IS taken before "y" refuses.
    expect(expectRefusal(await manager.start({ command: LONG_RUNNING, locks: ["a", "y"] })).lock).toBe("y");
    expect(fs.existsSync(lockPath("a"))).toBe(false);
    expectJob(await manager.start({ command: LONG_RUNNING, locks: ["a"] }));
  });

  it("releases the locks when the job settles", async () => {
    const a = expectJob(await manager.start({ command: "true", locks: ["short"] }));
    await waitForExit(a.jobId);
    expect(expectJob(manager.status({ jobId: a.jobId })).status).toBe("exited");
    expect(fs.existsSync(lockPath("short"))).toBe(false);
    expectJob(await manager.start({ command: LONG_RUNNING, locks: ["short"] }));
  });

  it("reaps a lock whose holder's process is dead", async () => {
    const dead = seedJob({});
    fs.mkdirSync(path.join(jobsRoot, ".locks"), { recursive: true });
    fs.writeFileSync(lockPath("orphaned"), JSON.stringify({ name: "orphaned", jobId: dead }));
    const b = expectJob(await manager.start({ command: LONG_RUNNING, locks: ["orphaned"] }));
    expect(JSON.parse(fs.readFileSync(lockPath("orphaned"), "utf8"))).toMatchObject({ jobId: b.jobId });
  });

  it("survives recover() while the holder is alive, and recovery reaps dead holders", async () => {
    const a = expectJob(await manager.start({ command: LONG_RUNNING, locks: ["kept"] }));
    const dead = seedJob({});
    fs.writeFileSync(lockPath("dropped"), JSON.stringify({ name: "dropped", jobId: dead }));
    const restarted = new JobManager({ jobsRoot });
    restarted.recover();
    expect(fs.existsSync(lockPath("kept"))).toBe(true);
    expect(fs.existsSync(lockPath("dropped"))).toBe(false);
    expect(expectRefusal(await restarted.start({ command: LONG_RUNNING, locks: ["kept"] })))
      .toMatchObject({ reason: "resource_busy", heldBy: a.jobId });
  });

  it("releases the locks and keeps the index for a cancelled job", async () => {
    const a = expectJob(await manager.start({ command: LONG_RUNNING, locks: ["c"], ...op("cancel-me") }));
    manager.cancel({ jobId: a.jobId });
    await waitFor("the cancelled job to settle", () => expectJob(manager.status({ jobId: a.jobId })).status !== "running");
    expect(fs.existsSync(lockPath("c"))).toBe(false);
    expect(fs.existsSync(indexPath("cancel-me"))).toBe(true);
  });
});

describe("job identity env", () => {
  it("sets AIC_JOB_ID always and AIC_OPERATION_ID when given, ignoring caller overrides", async () => {
    const plain = expectJob(await manager.start({
      command: 'printf "%s|%s" "$AIC_JOB_ID" "${AIC_OPERATION_ID-unset}"',
      env: { AIC_JOB_ID: "spoofed" },
    }));
    const withOp = expectJob(await manager.start({
      command: 'printf "%s|%s" "$AIC_JOB_ID" "$AIC_OPERATION_ID"',
      ...op("env-op"),
    }));
    await waitForExit(plain.jobId);
    await waitForExit(withOp.jobId);
    const log = (jobId: string) => fs.readFileSync(path.join(jobsRoot, jobId, "output.log"), "utf8");
    expect(log(plain.jobId)).toBe(`${plain.jobId}|unset`);
    expect(log(withOp.jobId)).toBe(`${withOp.jobId}|env-op`);
  });
});
