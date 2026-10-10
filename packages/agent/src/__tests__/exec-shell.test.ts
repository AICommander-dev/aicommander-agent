// planExecShell (exec-shell.ts): the agent's own, authoritative answer to "can
// this machine run the interpreter that was asked for". Every case here is
// platform-driven, so the platform is a parameter rather than the host's — these
// run identically on a Mac, a Linux CI box and a Windows runner.

import { describe, it, expect } from "vitest";
import { planExecShell } from "../exec-shell.js";
import { encodeWindowsLauncherRequest } from "../windows-exec-launcher.js";

const WINDOWS_OPTS = { exists: () => true };

/** The one interpreter path the agent will run, duplicated here on purpose. */
const POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

/** The base64 payload out of a wrapped PowerShell launcher line. */
function encodedPayload(line: string): string {
  const marker = "-EncodedCommand ";
  const at = line.indexOf(marker);
  expect(at).toBeGreaterThan(-1);
  return line.slice(at + marker.length);
}

function decodeWrapped(line: string): string {
  return Buffer.from(encodedPayload(line), "base64").toString("utf16le");
}

describe("planExecShell — the default", () => {
  it("changes nothing at all when no shell was requested", () => {
    for (const platform of ["darwin", "linux", "win32"]) {
      const plan = planExecShell(platform, undefined, "echo hi", WINDOWS_OPTS);
      expect(plan).toEqual({ ok: true, command: "echo hi", posixShell: true });
    }
  });

  it("treats the explicit default as the default", () => {
    expect(planExecShell("linux", "sh", "echo hi")).toEqual({
      ok: true,
      command: "echo hi",
      posixShell: true,
    });
    expect(planExecShell("win32", "cmd", "echo hi", WINDOWS_OPTS)).toEqual({
      ok: true,
      command: "echo hi",
      posixShell: true,
    });
  });
});

describe("planExecShell — POSIX", () => {
  it("spawns the first bash it finds and leaves the command untouched", () => {
    const plan = planExecShell("darwin", "bash", "shopt -s globstar", {
      exists: (candidate) => candidate === "/opt/homebrew/bin/bash",
    });
    expect(plan).toEqual({
      ok: true,
      command: "shopt -s globstar",
      posixShell: "/opt/homebrew/bin/bash",
    });
  });

  it("prefers /bin/bash when several exist", () => {
    const plan = planExecShell("linux", "bash", "echo hi", { exists: () => true });
    expect(plan.ok && plan.posixShell).toBe("/bin/bash");
  });

  it("REFUSES rather than falling back to sh when the machine has no bash", () => {
    const plan = planExecShell("linux", "bash", "echo hi", { exists: () => false });
    expect(plan.ok).toBe(false);
    if (plan.ok) throw new Error("unreachable");
    expect(plan.message).toContain("/bin/bash");
    expect(plan.message).toContain("was NOT run");
    expect(plan.message).toMatch(/install bash/i);
  });

  it("refuses a Windows shell on a POSIX machine, naming what is available", () => {
    for (const shell of ["cmd", "powershell"]) {
      const plan = planExecShell("darwin", shell, "echo hi");
      expect(plan.ok).toBe(false);
      if (plan.ok) throw new Error("unreachable");
      expect(plan.message).toContain("bash");
      expect(plan.message).toContain("win32");
    }
  });

  it("refuses an unknown value instead of guessing the closest one", () => {
    const plan = planExecShell("linux", "zsh", "echo hi");
    expect(plan.ok).toBe(false);
    if (plan.ok) throw new Error("unreachable");
    expect(plan.message).toContain('"zsh"');
  });
});

describe("planExecShell — Windows PowerShell", () => {
  it("wraps the script as a base64 -EncodedCommand line under the system directory", () => {
    const plan = planExecShell("win32", "powershell", "Get-ChildItem C:\\", WINDOWS_OPTS);
    expect(plan.ok).toBe(true);
    if (!plan.ok) throw new Error("unreachable");
    expect(plan.command).toContain(`"${POWERSHELL_PATH}"`);
    expect(plan.command).toContain("-NoProfile -NonInteractive -EncodedCommand");
    expect(decodeWrapped(plan.command)).toBe("Get-ChildItem C:\\");
  });

  it("IGNORES %SystemRoot% entirely — the interpreter path is a fixed literal", () => {
    // The whole point: an environment-derived interpreter path is redirectable,
    // and whoever can seed the agent's environment would then choose the binary
    // every `shell: "powershell"` command runs. Nothing here may follow it — not
    // the existence check, not the line we hand the launcher.
    const previous = process.env["SystemRoot"];
    process.env["SystemRoot"] = "D:\\Attacker";
    try {
      const probed: string[] = [];
      const plan = planExecShell("win32", "powershell", "Get-Date", {
        exists: (candidate) => {
          probed.push(candidate);
          return true;
        },
      });
      expect(probed).toEqual([POWERSHELL_PATH]);
      expect(plan.ok).toBe(true);
      if (!plan.ok) throw new Error("unreachable");
      expect(plan.command).toContain(`"${POWERSHELL_PATH}"`);
      expect(plan.command).not.toContain("D:\\Attacker");
    } finally {
      if (previous === undefined) delete process.env["SystemRoot"];
      else process.env["SystemRoot"] = previous;
    }
  });

  it("has nothing cmd.exe can reparse, whatever the script contains", () => {
    // The reason for base64 rather than quoting: these characters are cmd.exe
    // syntax, and any quoting scheme that lets them through is an injection bug.
    const nasty = 'Write-Output "a & b | c > d ^ e %PATH% \' `"';
    const plan = planExecShell("win32", "powershell", nasty, WINDOWS_OPTS);
    expect(plan.ok).toBe(true);
    if (!plan.ok) throw new Error("unreachable");
    expect(encodedPayload(plan.command)).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(decodeWrapped(plan.command)).toBe(nasty);
  });

  it("accepts a MULTI-LINE script and still hands the launcher a single line", () => {
    // The interior-line-break rejection exists because cmd.exe stops at the
    // first newline. base64 keeps that guarantee true — the newline provably
    // cannot reach cmd.exe — so a real script is finally writable on Windows.
    const script = "$ErrorActionPreference = 'Stop'\nGet-Date\nWrite-Output 'done'";
    const plan = planExecShell("win32", "powershell", script, WINDOWS_OPTS);
    expect(plan.ok).toBe(true);
    if (!plan.ok) throw new Error("unreachable");
    expect(plan.command).not.toMatch(/[\r\n]/);
    expect(decodeWrapped(plan.command)).toBe(script);
    // And the protocol encoder — the thing that enforces the guarantee — agrees.
    expect(() => encodeWindowsLauncherRequest(plan.command)).not.toThrow();
  });

  it("REFUSES a script too long for cmd.exe's line limit instead of truncating it", () => {
    const plan = planExecShell("win32", "powershell", "x".repeat(8000), WINDOWS_OPTS);
    expect(plan.ok).toBe(false);
    if (plan.ok) throw new Error("unreachable");
    expect(plan.message).toContain("8000 characters");
    expect(plan.message).toMatch(/nothing was truncated/i);
    expect(plan.message).toContain("powershell -NoProfile -File");
  });

  it("accepts a script comfortably under that limit", () => {
    const plan = planExecShell("win32", "powershell", "x".repeat(2500), WINDOWS_OPTS);
    expect(plan.ok).toBe(true);
  });

  it("refuses when PowerShell is not installed, rather than running cmd.exe", () => {
    const plan = planExecShell("win32", "powershell", "Get-Date", { exists: () => false });
    expect(plan.ok).toBe(false);
    if (plan.ok) throw new Error("unreachable");
    expect(plan.message).toContain("powershell.exe");
    expect(plan.message).toMatch(/was NOT run in cmd\.exe instead/i);
    // And it says WHY the search stopped there, so a machine with Windows on
    // another drive is not read as "PowerShell is broken".
    expect(plan.message).toContain("%SystemRoot%");
  });

  it("refuses a NUL, which base64 would otherwise hide from the launcher's check", () => {
    const plan = planExecShell("win32", "powershell", "Get-Date\0", WINDOWS_OPTS);
    expect(plan.ok).toBe(false);
    if (plan.ok) throw new Error("unreachable");
    expect(plan.message).toContain("NUL");
  });

  it("refuses a POSIX shell on a Windows machine", () => {
    for (const shell of ["sh", "bash"]) {
      const plan = planExecShell("win32", shell, "echo hi", WINDOWS_OPTS);
      expect(plan.ok).toBe(false);
      if (plan.ok) throw new Error("unreachable");
      expect(plan.message).toContain("cmd");
      expect(plan.message).toContain("powershell");
    }
  });
});
