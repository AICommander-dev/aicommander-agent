// executeCommand's `shell` option end-to-end on THIS machine: a supported value
// really changes the interpreter (verified by running something only that
// interpreter understands), and an unsupported one produces an error instead of
// a command that ran somewhere else. The Windows half of the matrix is unit
// tested in exec-shell.test.ts, which is platform-parameterised; here we can
// only exercise the platform the tests are running on.

import { describe, it, expect } from "vitest";
import { executeCommand } from "../executor.js";

const isWindows = process.platform === "win32";

interface RunOutcome {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  error: string | null;
}

function run(command: string, shell?: string): Promise<RunOutcome> {
  return new Promise((resolve) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    executeCommand(
      command,
      undefined,
      undefined,
      {
        onOutput: (chunk, stream) => {
          const decoded = Buffer.from(chunk, "base64");
          if (stream === "stdout") stdout.push(decoded);
          else stderr.push(decoded);
        },
        onDone: (exitCode) =>
          resolve({
            stdout: Buffer.concat(stdout).toString("utf8"),
            stderr: Buffer.concat(stderr).toString("utf8"),
            exitCode,
            error: null,
          }),
        onError: (error) =>
          resolve({
            stdout: Buffer.concat(stdout).toString("utf8"),
            stderr: Buffer.concat(stderr).toString("utf8"),
            exitCode: null,
            error,
          }),
      },
      shell === undefined ? {} : { shell },
    );
  });
}

describe("executeCommand shell selection", () => {
  it("runs the machine's default shell when none is requested", async () => {
    const { stdout, exitCode } = await run("echo default-shell");
    expect(stdout.trim()).toBe("default-shell");
    expect(exitCode).toBe(0);
  });

  it.skipIf(isWindows)("honours bash — and the command proves which shell ran", async () => {
    // $BASH_VERSION is set by bash and by nothing else, so this cannot pass by
    // accident if the request were quietly served by /bin/sh.
    const { stdout, error } = await run('echo "${BASH_VERSION:-no-bash}"', "bash");
    expect(error).toBeNull();
    expect(stdout.trim()).not.toBe("no-bash");
    expect(stdout.trim().length).toBeGreaterThan(0);
  });

  it.skipIf(isWindows)("runs sh when sh is asked for", async () => {
    const { stdout, exitCode } = await run("echo sh-ran", "sh");
    expect(stdout.trim()).toBe("sh-ran");
    expect(exitCode).toBe(0);
  });

  it.skipIf(isWindows)("refuses a Windows shell instead of running the command in sh", async () => {
    const { error, exitCode, stdout } = await run("echo must-not-run", "powershell");
    expect(exitCode).toBeNull();
    expect(stdout).toBe("");
    expect(error).toContain("powershell");
    expect(error).toMatch(/was NOT run/i);
  });

  it.skipIf(isWindows)(
    "leaves stderr byte-for-byte alone on every non-PowerShell shell",
    async () => {
      // The CLIXML decoder exists for ONE path (the -EncodedCommand wrapping in
      // exec-shell.ts) and must be invisible everywhere else — including for a
      // command that deliberately prints something shaped exactly like
      // PowerShell's serialized stderr. If the decoder were ever wired on by
      // shell rather than by plan.clixmlStderr, this is the test that notices.
      const payload =
        '#< CLIXML\\n<Objs Version="1.1.0.1"><S S="Error">kept_x000D_</S></Objs>';
      for (const shell of [undefined, "sh"]) {
        const { stderr, exitCode } = await run(`printf '%b' '${payload}' 1>&2`, shell);
        expect(exitCode).toBe(0);
        expect(stderr).toBe(
          '#< CLIXML\n<Objs Version="1.1.0.1"><S S="Error">kept_x000D_</S></Objs>',
        );
      }
    },
  );

  it("refuses an unknown shell without spawning anything", async () => {
    const { error, exitCode, stdout } = await run("echo must-not-run", "zsh");
    expect(exitCode).toBeNull();
    expect(stdout).toBe("");
    expect(error).toContain('"zsh"');
    expect(error).toMatch(/retrying/i);
  });
});
