import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// The detector's whole job is to ask the KERNEL what is running, so both of its
// doors to the kernel are mocked and every case below is a synthetic process
// table: /proc for Linux, `ps` for macOS. Nothing here may depend on what is
// actually running on the machine (or as which user) the suite runs on.
vi.mock("node:fs", () => ({
  default: {
    readFileSync: vi.fn(() => {
      throw new Error("ENOENT");
    }),
    readlinkSync: vi.fn(() => {
      throw new Error("ENOENT");
    }),
    readdirSync: vi.fn(() => [] as string[]),
  },
}));

vi.mock("node:child_process", () => ({ execFileSync: vi.fn() }));

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { findRunningAgents } from "../live-agent.js";

const STATE_FILE = "/var/run/aicommander-agent/state.json";
const BIN = "/usr/local/bin/aicommander-agent";

interface FakeProc {
  exe: string;
  argv: string[];
  /** Alive, but the kernel will not describe it (hidepid, a hardened container). */
  opaque?: boolean;
  /**
   * /proc/<pid>/stat content, for the pids whose exe/cmdline are unreadable but
   * whose stat line still answers "is this even a userspace process": kernel
   * threads and zombies. Unset means stat is unreadable too.
   */
  stat?: string;
}

/** PF_KTHREAD (0x00200000) set in stat field 9 — a kthread has no exe to readlink. */
function kernelThreadProc(pid: number): FakeProc {
  return { exe: "", argv: [], opaque: true, stat: `${pid} (kworker/0:1) I 2 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 22 0 0` };
}

/** State 'Z': the exit-notification husk of a process that already ended. */
function zombieProc(pid: number): FakeProc {
  return { exe: "", argv: [], opaque: true, stat: `${pid} (agent) Z 1 ${pid} ${pid} 0 -1 4194364 0 0 0 0 0 0 0 0 20 0 1 0 22 0 0` };
}

let procs: Map<number, FakeProc>;
let stateRaw: string | null;
let realPlatform: PropertyDescriptor | undefined;

function setPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

/** A supervisor/worker pair as supervisor.ts actually launches it: same argv. */
function agentProc(): FakeProc {
  return { exe: BIN, argv: [BIN, "run"] };
}

function writeState(pid: number | unknown): void {
  stateRaw = JSON.stringify({
    sessionCode: "AIC-WOLF-2345-WXYZ",
    pid,
    startedAt: "2026-06-14T00:00:00.000Z",
    serverUrl: "https://aicommander.dev",
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  procs = new Map();
  stateRaw = null;
  realPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  setPlatform("linux");

  // Liveness is a real syscall; here it answers from the synthetic table.
  vi.spyOn(process, "kill").mockImplementation(((pid: number) => {
    if (!procs.has(pid)) {
      const err = new Error("ESRCH") as NodeJS.ErrnoException;
      err.code = "ESRCH";
      throw err;
    }
    return true;
  }) as never);

  vi.mocked(fs.readFileSync).mockImplementation(((file: string) => {
    if (String(file) === STATE_FILE) {
      if (stateRaw === null) throw new Error("ENOENT");
      return stateRaw;
    }
    const stat = /^\/proc\/(\d+)\/stat$/.exec(String(file));
    if (stat) {
      const proc = procs.get(Number(stat[1]));
      if (proc?.stat === undefined) throw new Error("ENOENT");
      return proc.stat;
    }
    const match = /^\/proc\/(\d+)\/cmdline$/.exec(String(file));
    const proc = match ? procs.get(Number(match[1])) : undefined;
    if (!proc || proc.opaque) throw new Error("ENOENT");
    // The kernel NUL-terminates every argument, including the last.
    return `${proc.argv.join("\0")}\0`;
  }) as never);

  vi.mocked(fs.readlinkSync).mockImplementation(((file: string) => {
    const match = /^\/proc\/(\d+)\/exe$/.exec(String(file));
    const proc = match ? procs.get(Number(match[1])) : undefined;
    if (!proc || proc.opaque) throw new Error("EACCES");
    return proc.exe;
  }) as never);

  vi.mocked(fs.readdirSync).mockImplementation(((dir: string) =>
    String(dir) === "/proc"
      ? [...procs.keys()].map(String).concat("self", "meminfo")
      : []) as never);

  vi.mocked(execFileSync).mockImplementation(((_file: string, args: string[]) => {
    const pid = Number(args[args.indexOf("-p") + 1]);
    const proc = procs.get(pid);
    if (!proc || proc.opaque) throw new Error("ps: no such process");
    if (args.includes("comm=")) return proc.exe;
    if (args.includes("args=")) return proc.argv.join(" ");
    // No parent worth reporting unless a test says otherwise.
    return "1\n";
  }) as never);
});

afterEach(() => {
  vi.restoreAllMocks();
  if (realPlatform) Object.defineProperty(process, "platform", realPlatform);
});

describe("findRunningAgents — Linux /proc", () => {
  it("finds an agent no state.json knows about", () => {
    // The hand-started run, the NAS cron-started service, the survivor of a botched install:
    // nothing recorded it, and `systemctl is-active` says `inactive` truthfully.
    procs.set(4242, agentProc());
    expect(findRunningAgents()).toEqual({ running: [4242], unverified: [], scanFailed: false });
  });

  it("finds BOTH the supervisor and the worker", () => {
    // state.json carries the worker's pid only; the supervisor is a second root
    // process running the same binary, and leaving it out would delete the
    // binary from under the half of the pair that restarts the other.
    procs.set(100, agentProc());
    procs.set(101, agentProc());
    writeState(101);
    expect(findRunningAgents().running).toEqual([100, 101]);
  });

  it("recognises the default (argument-less) run the operator is told to use", () => {
    // `sudo aicommander-agent` — commander's default sub-command IS `run`.
    procs.set(7, { exe: BIN, argv: [BIN] });
    expect(findRunningAgents().running).toEqual([7]);
  });

  it("recognises the npm/systemd shape: node <script> run", () => {
    procs.set(8, {
      exe: "/usr/bin/node",
      argv: ["/usr/bin/node", "/usr/lib/node_modules/@aicommander/agent/dist/bin/agent.js", "run"],
    });
    expect(findRunningAgents().running).toEqual([8]);
  });

  it("recognises the binary left running as a deleted inode by an upgrade", () => {
    procs.set(9, { exe: `${BIN} (deleted)`, argv: [BIN, "run"] });
    expect(findRunningAgents().running).toEqual([9]);
  });

  it("recognises an agent installed somewhere else entirely (a NAS data volume)", () => {
    const nas = "/share/CACHEDEV1_DATA/aicommander/bin/aicommander-agent";
    procs.set(10, { exe: nas, argv: [nas, "run"] });
    expect(findRunningAgents().running).toEqual([10]);
  });

  it("ignores the CLI sub-commands that share the very same binary", () => {
    procs.set(11, { exe: BIN, argv: [BIN, "status"] });
    procs.set(12, { exe: BIN, argv: [BIN, "change-code", "--yes"] });
    procs.set(13, { exe: BIN, argv: [BIN, "install", "--server", "https://x"] });
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
  });

  it("ignores the secure-exec privilege dropper, which re-execs this binary", () => {
    // A sandboxed USER command wearing our argv[0]; killing an uninstall over it
    // would make every machine running a long job un-uninstallable.
    procs.set(14, { exe: BIN, argv: [BIN, "__secure-exec-drop", "aicommander", "sleep", "run"] });
    expect(findRunningAgents().running).toEqual([]);
  });

  it("ignores a process that merely NAMES the binary in its arguments", () => {
    // argv is text any process may write; only the exe is the kernel's word.
    procs.set(15, { exe: "/usr/bin/vim", argv: ["vim", BIN] });
    procs.set(16, { exe: "/usr/bin/grep", argv: ["grep", "-r", "aicommander-agent", "run"] });
    expect(findRunningAgents().running).toEqual([]);
  });

  it("ignores an unrelated node process that happens to take a `run` argument", () => {
    procs.set(17, { exe: "/usr/bin/node", argv: ["node", "/srv/other/cli.js", "run"] });
    expect(findRunningAgents().running).toEqual([]);
  });

  it("ignores `bun run …`, where the runtime AND the sub-command both match", () => {
    // The npm shape means the exe can legitimately be a JS runtime, so the
    // runtime alone must never be enough: `bun run dev` on a developer's box
    // would otherwise make this machine impossible to uninstall from.
    procs.set(18, { exe: "/usr/local/bin/bun", argv: ["bun", "run", "dev"] });
    procs.set(19, { exe: "/usr/bin/node", argv: ["node", "run"] });
    expect(findRunningAgents().running).toEqual([]);
  });

  it("never reports the uninstall process itself", () => {
    // The uninstall IS this binary, and its own pid is the first thing a /proc
    // walk finds. Detecting it would abort every uninstall forever.
    procs.set(process.pid, agentProc());
    writeState(process.pid);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
  });

  it("skips kernel threads and pids that vanish mid-walk without failing closed", () => {
    // /proc is full of entries with no readable exe. Treating those as
    // "unverified" would make the answer useless on every machine.
    procs.set(20, { exe: "", argv: [], opaque: true });
    procs.set(21, agentProc());
    expect(findRunningAgents()).toEqual({ running: [21], unverified: [], scanFailed: false });
  });
});

describe("findRunningAgents — a /proc walk that could not run", () => {
  it("reports scanFailed rather than 'no agents found'", () => {
    // The walk is the ONLY source that finds an agent nobody wrote down — the
    // hand-started run, the NAS survivor — so an unreadable /proc used to be
    // indistinguishable from an empty one, and the uninstall deleted a root
    // credential on the strength of a scan that never happened.
    vi.mocked(fs.readdirSync).mockImplementation((() => {
      throw new Error("EACCES");
    }) as never);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: true });
  });

  it("still reports what the recorded pid alone could prove", () => {
    // The two sources are independent: a broken walk must not hide the agent
    // the state file DOES know about.
    procs.set(700, agentProc());
    writeState(700);
    vi.mocked(fs.readdirSync).mockImplementation((() => {
      throw new Error("EACCES");
    }) as never);
    expect(findRunningAgents()).toEqual({ running: [700], unverified: [], scanFailed: true });
  });
});

describe("findRunningAgents — the recorded pid", () => {
  it("does not block on a state.json whose process is long dead", () => {
    // clearState() runs only from the SIGINT/SIGTERM handler, so a SIGKILLed
    // worker leaves this file behind for the rest of the boot. A recorded pid is
    // not evidence of life.
    writeState(31337);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
  });

  it("does not block when the recorded pid was recycled onto something else", () => {
    // Aborting because an unrelated process inherited the number would be a bad
    // failure — which is why the pid is verified, not trusted.
    procs.set(555, { exe: "/usr/sbin/nginx", argv: ["nginx: worker process"] });
    writeState(555);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
  });

  it("reports a recorded pid that is alive but unreadable as unverified", () => {
    procs.set(556, { exe: "", argv: [], opaque: true });
    writeState(556);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [556], scanFailed: false });
  });

  // clearState used to race process.exit, so a stale state.json is ROUTINE, and
  // its pid will eventually be recycled. Onto an ordinary process the exe check
  // already answers; onto a kernel thread or a zombie there IS no exe, which
  // used to read as "unverified" and abort the uninstall with a `kill <pid>`
  // remedy that cannot work on either — the /proc walk meanwhile SKIPS exactly
  // these pids, so the two paths contradicted each other about one condition.
  it("does not block on a recorded pid recycled onto a kernel thread", () => {
    procs.set(600, kernelThreadProc(600));
    writeState(600);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
  });

  it("does not block on a recorded pid left as a zombie", () => {
    // A zombie passes kill(pid, 0) but is only an exit notification nobody
    // reaped: the process it was is over, so there is nothing to fail closed on.
    procs.set(601, zombieProc(601));
    writeState(601);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
  });

  it("still fails closed on a REAL process whose exe it may not read", () => {
    // The stat line proves a live userspace process (state S, no PF_KTHREAD),
    // and for the recorded pid that is positive reason to keep refusing: the
    // kthread/zombie corroboration must not blanket-proceed whenever stat is
    // readable.
    procs.set(602, {
      exe: "", argv: [], opaque: true,
      stat: "602 (agent) S 1 602 602 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 22 0 0",
    });
    writeState(602);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [602], scanFailed: false });
  });

  it("treats a missing, unparseable or pid-less state.json as no evidence", () => {
    for (const raw of [null, "{ not json", "{}", '{"pid":"1234"}', '{"pid":0}', '{"pid":1}']) {
      stateRaw = raw;
      expect(findRunningAgents()).toEqual({ running: [], unverified: [], scanFailed: false });
    }
  });
});

describe("findRunningAgents — macOS", () => {
  beforeEach(() => {
    setPlatform("darwin");
  });

  it("verifies the recorded pid through ps, and its supervisor parent with it", () => {
    // No systemd here at all, so this check is the ONLY guard a macOS agent has.
    procs.set(900, agentProc()); // supervisor
    procs.set(901, agentProc()); // worker — the one state.json records
    writeState(901);
    vi.mocked(execFileSync).mockImplementation(((_file: string, args: string[]) => {
      const pid = Number(args[args.indexOf("-p") + 1]);
      const proc = procs.get(pid);
      if (!proc) throw new Error("ps: no such process");
      if (args.includes("ppid=")) return pid === 901 ? " 900\n" : " 1\n";
      if (args.includes("comm=")) return `${proc.exe}\n`;
      return `${proc.argv.join(" ")}\n`;
    }) as never);
    expect(findRunningAgents().running).toEqual([900, 901]);
  });

  it("does not report a parent that is not an agent", () => {
    // A worker started straight from a shell has no supervisor above it, and the
    // shell is not something an uninstall may point the operator at.
    procs.set(902, agentProc());
    procs.set(800, { exe: "/bin/zsh", argv: ["-zsh"] });
    writeState(902);
    vi.mocked(execFileSync).mockImplementation(((_file: string, args: string[]) => {
      const pid = Number(args[args.indexOf("-p") + 1]);
      const proc = procs.get(pid);
      if (!proc) throw new Error("ps: no such process");
      if (args.includes("ppid=")) return pid === 902 ? "800\n" : "1\n";
      if (args.includes("comm=")) return `${proc.exe}\n`;
      return `${proc.argv.join(" ")}\n`;
    }) as never);
    expect(findRunningAgents().running).toEqual([902]);
  });

  it("reports a live pid ps could not describe as unverified", () => {
    procs.set(903, agentProc());
    writeState(903);
    vi.mocked(execFileSync).mockImplementation((() => {
      throw new Error("ps: cannot fork");
    }) as never);
    expect(findRunningAgents()).toEqual({ running: [], unverified: [903], scanFailed: false });
  });

  it("never walks a /proc that does not exist here", () => {
    procs.set(904, agentProc());
    findRunningAgents();
    expect(vi.mocked(fs.readdirSync)).not.toHaveBeenCalled();
  });
});
