import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

// nvidia-smi is not installed on the machines this suite runs on (and must not be
// required), so the process boundary is mocked and every failure mode is driven
// explicitly: missing binary, non-zero exit, hung driver, garbage output.
vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

import { spawn } from "node:child_process";
import { probeGpus, probeGpuState, parseGpuRows, knownGpus, wireGpus } from "../gpu.js";

/** A minimal ChildProcess stand-in: stdout stream + kill + the two events we use. */
class FakeProc extends EventEmitter {
  stdout = new EventEmitter();
  killed = false;
  kill(): boolean {
    this.killed = true;
    return true;
  }
}

function mockSpawn(): FakeProc {
  const proc = new FakeProc();
  vi.mocked(spawn).mockReturnValue(proc as never);
  return proc;
}

const VALID_ROW = "0, NVIDIA GeForce RTX 5080, 16303, 1024, 37, 570.86.16";

beforeEach(() => {
  vi.mocked(spawn).mockReset();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("probeGpus", () => {
  it("parses a successful probe", async () => {
    const proc = mockSpawn();
    const promise = probeGpus();
    proc.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
    proc.emit("close", 0);
    expect(await promise).toEqual([
      {
        index: 0,
        name: "NVIDIA GeForce RTX 5080",
        memoryTotalMiB: 16303,
        memoryUsedMiB: 1024,
        utilizationPct: 37,
        driverVersion: "570.86.16",
      },
    ]);
  });

  it("runs nvidia-smi as an argv with no shell", async () => {
    const proc = mockSpawn();
    const promise = probeGpus();
    proc.emit("close", 0);
    await promise;
    const [file, args, options] = vi.mocked(spawn).mock.calls[0]!;
    expect(file).toBe("nvidia-smi");
    expect(args).toEqual([
      "--query-gpu=index,name,memory.total,memory.used,utilization.gpu,driver_version",
      "--format=csv,noheader,nounits",
    ]);
    // A shell would make a future caller-supplied argument injectable.
    expect((options as { shell?: boolean }).shell).toBeUndefined();
  });

  it("returns undefined when the binary is missing (ENOENT)", async () => {
    const proc = mockSpawn();
    const promise = probeGpus();
    proc.emit("error", Object.assign(new Error("spawn nvidia-smi ENOENT"), { code: "ENOENT" }));
    expect(await promise).toBeUndefined();
  });

  it("returns undefined when spawn throws synchronously", async () => {
    vi.mocked(spawn).mockImplementation(() => {
      throw new Error("EACCES");
    });
    expect(await probeGpus()).toBeUndefined();
  });

  it("returns undefined on a non-zero exit, even with parseable stdout", async () => {
    const proc = mockSpawn();
    const promise = probeGpus();
    proc.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
    proc.emit("close", 9);
    expect(await promise).toBeUndefined();
  });

  it("kills and gives up when the probe times out", async () => {
    vi.useFakeTimers();
    const proc = mockSpawn();
    const promise = probeGpus();
    // A wedged driver never emits "close"; the deadline must resolve on its own.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(proc.killed).toBe(true);
    expect(await promise).toBeUndefined();
  });

  it("abandons a probe whose output overflows the cap", async () => {
    const proc = mockSpawn();
    const promise = probeGpus();
    proc.stdout.emit("data", Buffer.alloc(64 * 1024 + 1, 0x41));
    proc.emit("close", 0);
    expect(proc.killed).toBe(true);
    expect(await promise).toBeUndefined();
  });

  it("returns undefined when the output is garbage", async () => {
    const proc = mockSpawn();
    const promise = probeGpus();
    proc.stdout.emit("data", Buffer.from("Unable to determine the device handle\n"));
    proc.emit("close", 0);
    expect(await promise).toBeUndefined();
  });
});

// The richer, LOCAL-ONLY signal: probeGpus() collapses "no card" and "probe
// broke" into one undefined because the wire wants that; the job gpuIndex check
// may only refuse on the first. Confidence is deliberately STINGY — only a probe
// that ran, exited 0 and was understood IN FULL is authoritative.
describe("probeGpuState", () => {
  it("stays unknown when the binary is missing (ENOENT)", async () => {
    // Deliberate: nvidia-smi off THIS process's PATH (launchd/systemd hand the
    // agent a minimal one) proves nothing about whether libcuda can bind a
    // device. Coverage traded for honesty — a GPU box whose driver is simply not
    // on our PATH stays permissive instead of being refused outright.
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.emit("error", Object.assign(new Error("spawn nvidia-smi ENOENT"), { code: "ENOENT" }));
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when spawn throws ENOENT synchronously", async () => {
    // Windows can surface a missing binary here rather than as an 'error' event.
    vi.mocked(spawn).mockImplementation(() => {
      throw Object.assign(new Error("spawn nvidia-smi ENOENT"), { code: "ENOENT" });
    });
    expect(await probeGpuState()).toEqual({ certainty: "unknown" });
  });

  it("reports a confident 'none' ONLY when the probe ran and listed nothing", async () => {
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.emit("close", 0);
    expect(await promise).toEqual({ certainty: "none" });
  });

  it("reports the devices a successful probe found", async () => {
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
    proc.emit("close", 0);
    const state = await promise;
    expect(state.certainty).toBe("devices");
    expect(state.certainty === "devices" && state.devices.map((d) => d.index)).toEqual([0]);
  });

  it("stays unknown when only SOME rows parsed", async () => {
    // Issue 14: a partial parse that still claimed to be authoritative would
    // reject the very GPU index whose row we failed to read.
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.stdout.emit("data", Buffer.from(`${VALID_ROW}\n1, Card, 1, 2, [N/A], 570.86.16\n`));
    proc.emit("close", 0);
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when the stdout stream errors mid-read", async () => {
    // Truncated output that happens to parse is "authoritative but incomplete".
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
    proc.stdout.emit("error", new Error("EPIPE"));
    proc.emit("close", 0);
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown on a non-zero exit", async () => {
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
    proc.emit("close", 9);
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when the probe times out", async () => {
    vi.useFakeTimers();
    const proc = mockSpawn();
    const promise = probeGpuState();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(proc.killed).toBe(true);
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when the output overflows the cap", async () => {
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.stdout.emit("data", Buffer.alloc(64 * 1024 + 1, 0x41));
    proc.emit("close", 0);
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when spawn throws for a reason other than ENOENT", async () => {
    vi.mocked(spawn).mockImplementation(() => {
      throw Object.assign(new Error("EACCES"), { code: "EACCES" });
    });
    expect(await probeGpuState()).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when the spawn error is not ENOENT", async () => {
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.emit("error", Object.assign(new Error("EPERM"), { code: "EPERM" }));
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("stays unknown when the output is non-empty but unparseable", async () => {
    // Something answered — that is a tool/parser mismatch, not absent hardware.
    const proc = mockSpawn();
    const promise = probeGpuState();
    proc.stdout.emit("data", Buffer.from("Unable to determine the device handle\n"));
    proc.emit("close", 0);
    expect(await promise).toEqual({ certainty: "unknown" });
  });

  it("keeps the WIRE payload identical across every failure mode", async () => {
    // The whole certainty rework is local-only: AgentRegisterMsg.gpus must still
    // be a non-empty list or ABSENT — never [] — whatever the probe did. Each
    // case drives one failure mode and asserts the value that reaches
    // agent:register, so a future re-classification cannot leak onto the wire.
    const drive = async (act: (proc: FakeProc) => void) => {
      const proc = mockSpawn();
      const promise = probeGpus();
      act(proc);
      return promise;
    };

    // Missing binary / unreachable PATH.
    expect(
      await drive((p) =>
        p.emit("error", Object.assign(new Error("ENOENT"), { code: "ENOENT" })),
      ),
    ).toBeUndefined();
    // Other async spawn error.
    expect(
      await drive((p) => p.emit("error", Object.assign(new Error("EPERM"), { code: "EPERM" }))),
    ).toBeUndefined();
    // Ran, reported nothing — the ONE confident "none", still omitted on the wire.
    expect(await drive((p) => p.emit("close", 0))).toBeUndefined();
    // Non-zero exit, even with parseable stdout.
    expect(
      await drive((p) => {
        p.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
        p.emit("close", 9);
      }),
    ).toBeUndefined();
    // Unparseable output.
    expect(
      await drive((p) => {
        p.stdout.emit("data", Buffer.from("Unable to determine the device handle\n"));
        p.emit("close", 0);
      }),
    ).toBeUndefined();
    // PARTIAL parse — one good row, one bad.
    expect(
      await drive((p) => {
        p.stdout.emit("data", Buffer.from(`${VALID_ROW}\nnot,a,row\n`));
        p.emit("close", 0);
      }),
    ).toBeUndefined();
    // stdout stream error.
    expect(
      await drive((p) => {
        p.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
        p.stdout.emit("error", new Error("EPIPE"));
        p.emit("close", 0);
      }),
    ).toBeUndefined();
    // Overflow.
    expect(
      await drive((p) => {
        p.stdout.emit("data", Buffer.alloc(64 * 1024 + 1, 0x41));
        p.emit("close", 0);
      }),
    ).toBeUndefined();
    // Synchronous spawn throw.
    vi.mocked(spawn).mockImplementation(() => {
      throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    });
    expect(await probeGpus()).toBeUndefined();
    vi.mocked(spawn).mockReset();

    // Timeout.
    vi.useFakeTimers();
    const wedged = mockSpawn();
    const timedOut = probeGpus();
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await timedOut).toBeUndefined();
    vi.useRealTimers();

    // …and the only case that DOES put something on the wire.
    const found = await drive((p) => {
      p.stdout.emit("data", Buffer.from(`${VALID_ROW}\n`));
      p.emit("close", 0);
    });
    expect(found?.map((d) => d.index)).toEqual([0]);
  });
});

// The two reductions of one state, deliberately different: `[]` is forbidden on
// the wire and is the whole signal locally.
describe("knownGpus / wireGpus", () => {
  const CARD = {
    index: 0,
    name: "NVIDIA GeForce RTX 5080",
    memoryTotalMiB: 16303,
    memoryUsedMiB: 1024,
    utilizationPct: 37,
  };

  it("reduces each state the way its consumer needs", () => {
    expect(knownGpus({ certainty: "devices", devices: [CARD] })).toEqual([CARD]);
    expect(knownGpus({ certainty: "none" })).toEqual([]);
    expect(knownGpus({ certainty: "unknown" })).toBeUndefined();

    expect(wireGpus({ certainty: "devices", devices: [CARD] })).toEqual([CARD]);
    // Never [] on the wire — the field is omitted instead.
    expect(wireGpus({ certainty: "none" })).toBeUndefined();
    expect(wireGpus({ certainty: "unknown" })).toBeUndefined();
  });
});

describe("parseGpuRows", () => {
  it("parses several devices and tolerates CRLF and blank lines", () => {
    const { devices, malformed } = parseGpuRows(
      `${VALID_ROW}\r\n\r\n1, NVIDIA RTX A4000, 16376, 0, 0, 570.86.16\n`,
    );
    expect(devices.map((d) => d.index)).toEqual([0, 1]);
    expect(devices[1]?.memoryUsedMiB).toBe(0);
    // Blank lines are not rows and must not count as failures.
    expect(malformed).toBe(0);
  });

  it("omits driverVersion when nvidia-smi reports none", () => {
    const { devices, malformed } = parseGpuRows("0, NVIDIA RTX A4000, 16376, 0, 0");
    expect(devices).toHaveLength(1);
    expect(devices[0]).not.toHaveProperty("driverVersion");
    expect(malformed).toBe(0);
  });

  it("omits driverVersion reported as [N/A]", () => {
    const { devices } = parseGpuRows("0, NVIDIA RTX A4000, 16376, 0, 0, [N/A]");
    expect(devices[0]).not.toHaveProperty("driverVersion");
  });

  it("counts a row whose utilization is unsupported ([N/A]) as malformed", () => {
    // Partial output must not turn into a device with NaN fields — and the
    // caller must learn the row was dropped (issue 14).
    expect(parseGpuRows("0, NVIDIA RTX A4000, 16376, 0, [N/A], 570.86.16")).toEqual({
      devices: [],
      malformed: 1,
    });
  });

  it("keeps the good rows but reports how many it could not read", () => {
    const { devices, malformed } = parseGpuRows(
      ["not,enough", VALID_ROW, "x, Card, 1, 2, 3, 4", "1, Card, 1, 2, 3, 4, 5"].join("\n"),
    );
    expect(devices.map((d) => d.index)).toEqual([0]);
    expect(malformed).toBe(3);
  });

  it("reports every row malformed when nothing parses", () => {
    expect(parseGpuRows("garbage\nmore garbage\n")).toEqual({ devices: [], malformed: 2 });
    // Empty output is NOT a malformed row: it is the "ran, listed nothing" case,
    // which probeGpuState answers as a confident "none" before reaching here.
    expect(parseGpuRows("")).toEqual({ devices: [], malformed: 0 });
  });

  it("strips control characters from device names", () => {
    // A device name ends up in relay-stored metadata and in an LLM context.
    const { devices } = parseGpuRows("0, NVIDIA\u0007 RTX A4000, 16376, 0, 0, 1.0");
    expect(devices[0]?.name).toBe("NVIDIA RTX A4000");
  });
});
