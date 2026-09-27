// The shared shell vocabulary (exec-shell.ts): which values each platform
// accepts, and that every refusal actually TELLS the caller what to do. These
// strings are read by an LLM with no other window onto the machine, so their
// content is part of the contract, not decoration.

import { describe, it, expect } from "vitest";
import {
  defaultExecShell,
  EXEC_SHELLS,
  execShellAgentTooOldMessage,
  execShellsForPlatform,
  isExecShell,
  POSIX_EXEC_SHELLS,
  SHELL_NOT_SUPPORTED_FOR_JOBS_MESSAGE,
  SHELL_WITH_ELEVATED_MESSAGE,
  unsupportedExecShellMessage,
  WINDOWS_EXEC_SHELLS,
} from "../exec-shell.js";

describe("exec shell vocabulary", () => {
  it("splits the values by platform family and knows nothing about anything else", () => {
    expect(execShellsForPlatform("win32")).toEqual(WINDOWS_EXEC_SHELLS);
    expect(execShellsForPlatform("darwin")).toEqual(POSIX_EXEC_SHELLS);
    expect(execShellsForPlatform("linux")).toEqual(POSIX_EXEC_SHELLS);
    // An unrecognised/absent platform yields null — "cannot decide here", NOT
    // "no shells": the machine itself makes the call in that case.
    expect(execShellsForPlatform("freebsd")).toBeNull();
    expect(execShellsForPlatform(undefined)).toBeNull();
  });

  it("keeps the historical default per platform", () => {
    expect(defaultExecShell("win32")).toBe("cmd");
    expect(defaultExecShell("darwin")).toBe("sh");
    expect(defaultExecShell("linux")).toBe("sh");
  });

  it("recognises exactly the four canonical values", () => {
    for (const shell of EXEC_SHELLS) expect(isExecShell(shell)).toBe(true);
    for (const bogus of ["zsh", "pwsh", "PowerShell", "", 3, null, undefined]) {
      expect(isExecShell(bogus)).toBe(false);
    }
  });
});

describe("refusal messages", () => {
  it("names what the machine DOES accept, and that a retry will not help", () => {
    const message = unsupportedExecShellMessage("powershell", "darwin");
    expect(message).toContain("powershell");
    expect(message).toContain("macOS");
    expect(message).toContain("sh");
    expect(message).toContain("bash");
    expect(message).toMatch(/retrying/i);
    // And points at the platform where the value WOULD have worked, so the
    // caller does not conclude the feature is broken.
    expect(message).toContain("win32");
  });

  it("names the POSIX values as Windows-only mistakes on a Windows machine", () => {
    const message = unsupportedExecShellMessage("bash", "win32");
    expect(message).toContain("Windows");
    expect(message).toContain("cmd");
    expect(message).toContain("powershell");
    expect(message).toContain("macOS/Linux");
  });

  it("lists every value when the platform is unknown", () => {
    const message = unsupportedExecShellMessage("fish", undefined);
    for (const shell of EXEC_SHELLS) expect(message).toContain(shell);
  });

  it("never claims the command ran", () => {
    for (const message of [
      unsupportedExecShellMessage("fish", "linux"),
      execShellAgentTooOldMessage("win32"),
      SHELL_WITH_ELEVATED_MESSAGE,
      SHELL_NOT_SUPPORTED_FOR_JOBS_MESSAGE,
    ]) {
      expect(message.length).toBeGreaterThan(80);
      expect(message).toMatch(/not run|not supported|cannot be combined/i);
    }
  });

  it("tells a too-old-agent caller both ways out, with the platform's own escape hatch", () => {
    const windows = execShellAgentTooOldMessage("win32");
    expect(windows).toMatch(/update/i);
    expect(windows).toContain("powershell -NoProfile -Command");
    const posix = execShellAgentTooOldMessage("darwin");
    expect(posix).toContain("bash -c");
  });
});
