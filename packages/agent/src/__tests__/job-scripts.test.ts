// The Windows job scripts, and the check that they survived to the spawn.
//
// PLATFORM NOTE, deliberately: this file has NO platform gate. Every existing
// Windows job test is either a string assertion in a describeOnPosix group or an
// executing one in describeOnWindows, because the mechanism under test there is
// cmd.exe itself and cmd.exe only exists on Windows. The mechanism under test
// HERE is different: writing two files, reading them back, and comparing. That is
// ordinary filesystem code with no cmd in it, so it runs — and must pass —
// everywhere, which matters because the agent package's Windows CI job is
// deliberately narrow (the bulk of the suite assumes POSIX) and the failure this
// guards is one nobody can reproduce on a developer machine.
//
// What it therefore does NOT prove: that a real Windows spawn refuses to start
// after a fault. That belongs to job-manager.ts and is asserted where the wiring
// is (job-manager.test.ts).

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { JOB_RPC_TIMEOUT_MS, JOB_SCRIPT_REMOVED_ERROR } from "@aicommander/protocol";

/**
 * The write, with the errno a denying scanner produces available on demand.
 *
 * Mode bits cannot stage this one: the write reasserts 0700 on the job
 * directory (the async twin does exactly what ensurePrivateDir does), so an owner can
 * never make their own directory refuse them. The failure being modelled is not
 * a permission the agent lacks anyway — it is a filter driver answering EACCES
 * for a file it has decided it does not like — and an injected errno is a truer
 * stand-in for that than any mode bit would be. Off by default, so every other
 * test in this file writes for real.
 */
const write = vi.hoisted(() => ({ failWith: null as string | null, hang: false }));
vi.mock("../atomic-file.js", async () => {
  const actual = await vi.importActual<typeof import("../atomic-file.js")>("../atomic-file.js");
  return {
    ...actual,
    atomicWriteUtf8Async: async (dir: string, file: string, contents: string): Promise<void> => {
      // The other half of the same incident: a filter driver that answers
      // nothing at all because it is still deciding, holding the file open. There
      // is no errno for it, which is why it needs a bound rather than a code.
      if (write.hang) await new Promise<void>(() => undefined);
      if (write.failWith !== null) {
        const err: NodeJS.ErrnoException = new Error(`EACCES: permission denied, open '${file}'`);
        err.code = write.failWith;
        throw err;
      }
      await actual.atomicWriteUtf8Async(dir, file, contents);
    },
  };
});

import {
  buildWindowsJobCommandScript,
  COMMAND_FILE,
  JOB_SCRIPT_IO_TIMEOUT_MS,
  jobScriptRemovedMessage,
  verifyWindowsJobScripts,
  WINDOWS_JOB_WRAPPER,
  WRAPPER_FILE,
  writeWindowsJobScripts,
} from "../job-scripts.js";

// The refused-READ case denies with mode bits, which say nothing on Windows (the
// ACL decides there) and nothing to root (which passes straight through them).
// Skipped rather than weakened: the same class of fault is covered on every
// platform by the deleted/altered/emptied cases, which need no permissions at all
// — that is why those carry the weight of this file.
const itWhereModeBitsDeny = it.skipIf(
  process.platform === "win32" || (typeof process.getuid === "function" && process.getuid() === 0),
);
const itOnPosix = it.skipIf(process.platform === "win32");

const COMMAND = "python.exe -c \"print('a', '| b')\"";

let dir: string;

beforeEach(() => {
  write.failWith = null;
  write.hang = false;
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-job-scripts-"));
});

afterEach(() => {
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // Already writable, or Windows.
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

const wrapperPath = (): string => path.join(dir, WRAPPER_FILE);
const commandPath = (): string => path.join(dir, COMMAND_FILE);

describe("writing the Windows job scripts", () => {
  it("writes both files with exactly the text that runs", async () => {
    expect(await writeWindowsJobScripts(dir, COMMAND)).toBeNull();

    // Byte for byte, because the whole verification below is an equality check:
    // a writer that normalised line endings would make every later job look
    // tampered with.
    expect(fs.readFileSync(wrapperPath(), "utf8")).toBe(WINDOWS_JOB_WRAPPER);
    expect(fs.readFileSync(commandPath(), "utf8")).toBe(buildWindowsJobCommandScript(COMMAND));
  });

  it("names the fault when the write itself is refused", async () => {
    // The scanner that denies the write outright, rather than letting it land and
    // taking the file afterwards. Both halves are the same incident, and only
    // this one leaves nothing on disk to notice later.
    write.failWith = "EACCES";

    const fault = await writeWindowsJobScripts(dir, COMMAND);
    expect(fault).toBe(`${WRAPPER_FILE} could not be written (EACCES)`);
  });

  it("keeps an unclassified write error unclassified", async () => {
    // A full volume is not an antivirus incident, and saying it is would send the
    // operator to the wrong page. It throws, and the generic start failure
    // describes it.
    write.failWith = "ENOSPC";

    await expect(writeWindowsJobScripts(dir, COMMAND)).rejects.toThrow(/ENOSPC|permission denied/);
  });

  it("lets a storage fault stay a storage fault", async () => {
    // ENOTDIR: the job "directory" is a file. Not an interference shape, so it
    // throws and keeps the generic "could not start the job" answer rather than
    // sending an operator to the antivirus page over a broken path.
    const file = path.join(dir, "not-a-directory");
    fs.writeFileSync(file, "x");

    await expect(writeWindowsJobScripts(file, COMMAND)).rejects.toThrow();
  });
});

describe("preparing and checking the scripts without blocking", () => {
  it("touches the disk asynchronously, both writing and reading back", async () => {
    // This pair runs inside the WebSocket frame handler, immediately before the
    // spawn — and on the desktop host that handler IS Electron's main loop. A
    // synchronous read of a filesystem an on-access scanner is holding blocks it
    // exactly as the modal in tray.ts once did, starving the heartbeat into the
    // "Reconnecting…" state this whole feature exists to prevent. So: no
    // synchronous filesystem call may appear on this path, and the adjacency to
    // the spawn is kept by the caller awaiting it (see spawnJob).
    const syncCalls = [
      vi.spyOn(fs, "readFileSync"),
      vi.spyOn(fs, "writeFileSync"),
      vi.spyOn(fs, "openSync"),
      vi.spyOn(fs, "renameSync"),
      vi.spyOn(fs, "mkdirSync"),
    ];

    expect(await writeWindowsJobScripts(dir, COMMAND)).toBeNull();
    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBeNull();

    for (const spy of syncCalls) expect(spy).not.toHaveBeenCalled();
  });
});

describe("verifying the Windows job scripts survived", () => {
  beforeEach(async () => {
    expect(await writeWindowsJobScripts(dir, COMMAND)).toBeNull();
  });

  it("says nothing when both files are intact", async () => {
    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBeNull();
  });

  it("catches the wrapper being taken away", async () => {
    // The 2026-09-02 shape: the engine quarantines the file, which from here is
    // an ordinary ENOENT.
    fs.rmSync(wrapperPath());

    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBe(`${WRAPPER_FILE} is gone`);
  });

  it("catches the command file being taken away", async () => {
    // Both files are checked: quarantining only the one that carries the
    // operator's command is just as fatal and just as silent.
    fs.rmSync(commandPath());

    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBe(`${COMMAND_FILE} is gone`);
  });

  it("catches a file that was emptied rather than removed", async () => {
    // A truncated wrapper still opens and still runs — it just does nothing, and
    // the job's log is empty. Distinguished from "gone" because it is what a
    // scanner that scrubs rather than quarantines leaves behind.
    fs.writeFileSync(wrapperPath(), "");

    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBe(`${WRAPPER_FILE} was emptied`);
  });

  it("catches a file that was altered", async () => {
    // Equality, not "is it non-empty": a wrapper that kept its first line and
    // lost its redirect produces the same empty log as a missing one.
    fs.writeFileSync(commandPath(), `${buildWindowsJobCommandScript(COMMAND)}rem tampered\r\n`);

    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBe(
      `${COMMAND_FILE} no longer holds what was written`,
    );
  });

  it("passes a command JSON can carry but UTF-8 cannot hold", async () => {
    // A lone surrogate is valid JSON (`"\ud800"`) and an unpaired half of a code
    // point, so it survives the relay and reaches us as a JavaScript string.
    // Writing it as UTF-8 substitutes U+FFFD — the file on disk is byte-perfect
    // and yet differs from the string we started from. Compared literally, that
    // told a HEALTHY machine its scripts had been quarantined and sent its
    // operator to antivirus support, for a job that before this check simply ran.
    const lone = "echo \ud800 tail";
    expect(await writeWindowsJobScripts(dir, lone)).toBeNull();

    expect(await verifyWindowsJobScripts(dir, lone)).toBeNull();
    // …and the check has not gone blind: the same command, altered, is still a
    // fault.
    fs.writeFileSync(commandPath(), `${buildWindowsJobCommandScript(lone)}rem tampered\r\n`);
    expect(await verifyWindowsJobScripts(dir, lone)).toBe(
      `${COMMAND_FILE} no longer holds what was written`,
    );
  });

  it("is not fooled by a DIFFERENT job's command file", async () => {
    // The wrapper is byte-identical for every job, so only the command file can
    // carry the wrong job's text. Verifying against the command we were handed is
    // what makes that a fault rather than a pass.
    fs.writeFileSync(commandPath(), buildWindowsJobCommandScript("whoami"));

    expect(await verifyWindowsJobScripts(dir, COMMAND)).toBe(
      `${COMMAND_FILE} no longer holds what was written`,
    );
  });

  itWhereModeBitsDeny("names the fault when the read back is refused", async () => {
    fs.chmodSync(wrapperPath(), 0o000);

    const fault = await verifyWindowsJobScripts(dir, COMMAND);
    expect(fault).not.toBeNull();
    expect(fault).toContain(WRAPPER_FILE);
    expect(fault).toMatch(/EACCES|EPERM/);
  });

  itOnPosix("lets a storage fault stay a storage fault", async () => {
    // EISDIR — nothing an antivirus does. It throws rather than being reported as
    // interference, for the same reason the write path does.
    fs.rmSync(wrapperPath());
    fs.mkdirSync(wrapperPath());

    await expect(verifyWindowsJobScripts(dir, COMMAND)).rejects.toThrow();
  });
});

describe("a filesystem that never answers", () => {
  // The failure mode the bound exists for, and the one the SYNCHRONOUS code this
  // replaced could not produce. That code blocked the event loop, so a hung
  // scanner took the machine visibly offline and somebody noticed. This code does
  // not: the heartbeat keeps answering, the machine looks healthy, and without a
  // bound the job stays inside JobManager's start window holding its GPU lock and
  // its concurrency slot forever, after which every later start is refused
  // `too_many_jobs` for no visible reason.

  it("gives up on a write that never returns, and calls it the same fault", async () => {
    write.hang = true;

    const fault = await writeWindowsJobScripts(dir, COMMAND, 250);

    expect(fault).toContain(WRAPPER_FILE);
    expect(fault).toContain("timed out being written");
    // A detail, not a throw: this is the job_script_removed family, because an
    // on-access scanner holding our file open and one deleting it are one story.
    expect(jobScriptRemovedMessage(fault!)).toContain(JOB_SCRIPT_REMOVED_ERROR);
  });

  it("gives up on a read-back that never returns", async () => {
    expect(await writeWindowsJobScripts(dir, COMMAND)).toBeNull();
    vi.spyOn(fs.promises, "readFile").mockImplementation(() => new Promise(() => undefined) as never);

    const fault = await verifyWindowsJobScripts(dir, COMMAND, 250);

    expect(fault).toContain(WRAPPER_FILE);
    expect(fault).toContain("timed out being read back");
    vi.restoreAllMocks();
  });

  it("bounds the pair well inside the relay's own job RPC timeout", async () => {
    // A start pays this bound at most twice — the write, then the read-back — and
    // the caller must be told `job_script_removed` rather than being handed the
    // relay's generic timeout, which explains nothing and names nobody.
    expect(JOB_SCRIPT_IO_TIMEOUT_MS * 2).toBeLessThan(JOB_RPC_TIMEOUT_MS);
    // And far enough above a healthy write of two ~1 KB files that it can never
    // fire on a machine that is merely slow.
    expect(JOB_SCRIPT_IO_TIMEOUT_MS).toBeGreaterThanOrEqual(5_000);
  });
});

describe("what the operator is told", () => {
  const message = jobScriptRemovedMessage(`${WRAPPER_FILE} is gone`);

  it("leads with the token the relay matches on, then the detail", () => {
    // The wire shape the protocol constant documents: token, colon, detail,
    // semicolon, prose. The relay lifts the detail out of exactly this.
    expect(message.startsWith(`${JOB_SCRIPT_REMOVED_ERROR}: ${WRAPPER_FILE} is gone;`)).toBe(true);
  });

  it("says what happened and where to go, for a reader with nothing to map it", () => {
    expect(message).toContain("security software");
    expect(message).toContain("https://aicommander.dev/antivirus");
    // "the job never started" is the fact that separates this from a job that ran
    // and failed — an operator must not go looking for partial work.
    expect(message).toContain("never started");
  });

  it("never carries the command", () => {
    // The message crosses the relay into caller-visible text. Nothing about the
    // diagnosis needs the command, which is the caller's own payload.
    expect(jobScriptRemovedMessage(`${COMMAND_FILE} is gone`)).not.toContain(
      "python.exe",
    );
  });
});
