// The WIRING between exec-shell.ts's plan and powershell-clixml.ts, inside
// executor.ts — the half that decoder unit tests cannot see.
//
// Three claims live only here, and each one was previously asserted by a comment
// in executor.ts and by nothing else:
//   * every stderr byte goes through ONE funnel (emitStderr), so the decoder
//     sees the stream once, in order;
//   * the Windows launcher's PRE-HANDSHAKE stderr, replayed after the ready
//     frame, goes through that same funnel — replaying it around the decoder
//     would hand the caller half a CLIXML block;
//   * the decoder is FLUSHED before `settled`, so a block cut off mid-record
//     still reaches the caller instead of dying in the parser's buffer.
//
// The suite runs everywhere by mocking child_process and pointing
// `shellExists` at a filesystem that has powershell.exe — the only way
// `plan.clixmlStderr` is reachable off Windows.

import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

import { spawn } from "node:child_process";
import { executeCommand } from "../executor.js";
import { encodeWindowsLauncherResponseForTest } from "../windows-exec-launcher.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
const originalArch = Object.getOwnPropertyDescriptor(process, "arch");

const HEADER = "#< CLIXML\r\n";
const OBJS_OPEN =
  '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">';
const PROGRESS_OBJ =
  '<Obj S="progress" RefId="0"><TN RefId="0"><T>System.Management.Automation.PSCustomObject</T>' +
  "<T>System.Object</T></TN><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\">" +
  "<AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC>" +
  "<T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj>";
const ERROR_RECORDS =
  '<S S="Error">C:\\path\\script.ps1 : this_x000D__x000A_</S>' +
  '<S S="Error">-is-a-real-error_x000D__x000A_</S>';
const ERROR_TEXT = "C:\\path\\script.ps1 : this\r\n-is-a-real-error\r\n";

type FakeStream = EventEmitter & { resume: () => void; unref: () => void };

function fakeStream(): FakeStream {
  return Object.assign(new EventEmitter(), { resume: () => {}, unref: () => {} });
}

function fakeChild() {
  return Object.assign(new EventEmitter(), {
    stdin: Object.assign(new EventEmitter(), { end: vi.fn() }),
    stdout: fakeStream(),
    stderr: fakeStream(),
    pid: 4321,
  });
}

function setPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
}

/** Start a command on the mocked Windows launcher and collect what the caller sees. */
function start(shell: string) {
  const child = fakeChild();
  vi.mocked(spawn).mockReturnValue(child as never);
  const stderr: Buffer[] = [];
  const onDone = vi.fn();
  const onError = vi.fn();
  executeCommand(
    'Write-Error "this-is-a-real-error"',
    undefined,
    undefined,
    {
      onOutput: (chunk, stream) => {
        if (stream === "stderr") stderr.push(Buffer.from(chunk, "base64"));
      },
      onDone,
      onError,
    },
    {
      shell,
      // The one machine fact the plan needs, supplied instead of measured: this
      // suite does not run on Windows.
      shellExists: () => true,
      windowsExecLauncherPath: process.execPath,
    },
  );
  return {
    child,
    onDone,
    onError,
    stderr: () => Buffer.concat(stderr).toString("latin1"),
  };
}

const ready = () => encodeWindowsLauncherResponseForTest("ready", "", Buffer.from(""));

beforeEach(() => {
  Object.defineProperty(process, "arch", { value: "x64", configurable: true });
  setPlatform("win32");
  vi.mocked(spawn).mockReset();
  vi.mocked(spawn).mockReturnValue(fakeChild() as never);
});

afterEach(() => {
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  if (originalArch) Object.defineProperty(process, "arch", originalArch);
});

describe("executeCommand — CLIXML stderr on the PowerShell path", () => {
  it("decodes stderr written before AND after the launcher handshake as one stream", () => {
    const run = start("powershell");
    // The launcher is not ready yet, so these bytes are buffered by the executor
    // and replayed later. They are the FIRST half of a CLIXML block: replaying
    // them past the decoder (or feeding the decoder the two halves out of order)
    // leaves the caller with `#< CLIXML` and a naked `<Objs …>`.
    run.child.stderr.emit("data", Buffer.from(`${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}`, "latin1"));
    run.child.stdout.emit("data", ready());
    run.child.stderr.emit("data", Buffer.from(`${ERROR_RECORDS}</Objs>`, "latin1"));
    run.child.emit("close", 0);

    expect(run.onError).not.toHaveBeenCalled();
    expect(run.onDone).toHaveBeenCalledWith(0, expect.any(Number));
    // The measured noise is gone and the shredded error is one readable message.
    expect(run.stderr()).toBe(ERROR_TEXT);
  });

  it("flushes a block cut off mid-record instead of settling on top of it", () => {
    const run = start("powershell");
    run.child.stdout.emit("data", ready());
    // PowerShell killed, or the relay's cap hit: the closing tag never comes and
    // the decoder is holding these bytes. Without the flush before `settled`,
    // emitOutput refuses to run and the caller is told the command produced no
    // stderr at all — a lost error, which is the one thing this must never do.
    run.child.stderr.emit(
      "data",
      Buffer.from(`${HEADER}${OBJS_OPEN}<S S="Error">half a message`, "latin1"),
    );
    run.child.emit("close", 1);

    expect(run.onDone).toHaveBeenCalledWith(1, expect.any(Number));
    expect(run.stderr()).toBe(`${OBJS_OPEN}<S S="Error">half a message`);
  });

  it("leaves stderr byte-for-byte alone for a shell the plan did not wrap", () => {
    // Same platform, same launcher, same CLIXML-shaped bytes — but `cmd` never
    // carries clixmlStderr, so nothing may touch its stderr, not even output
    // that looks exactly like PowerShell's.
    const run = start("cmd");
    run.child.stdout.emit("data", ready());
    const raw = `${HEADER}${OBJS_OPEN}${PROGRESS_OBJ}${ERROR_RECORDS}</Objs>`;
    run.child.stderr.emit("data", Buffer.from(raw, "latin1"));
    run.child.emit("close", 0);

    expect(run.stderr()).toBe(raw);
  });
});
