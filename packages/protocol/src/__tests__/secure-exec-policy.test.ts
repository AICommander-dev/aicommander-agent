import { describe, expect, it } from "vitest";

import {
  isSecureExecCommandDenied,
  SECURE_EXEC_DENIED_COMMANDS,
  SECURE_EXEC_PRIVILEGED_GROUPS,
} from "../constants.js";

describe("secure-exec shared policy", () => {
  it("keeps the exact denylist unique and enforced", () => {
    expect(new Set(SECURE_EXEC_DENIED_COMMANDS).size).toBe(
      SECURE_EXEC_DENIED_COMMANDS.length,
    );
    for (const command of SECURE_EXEC_DENIED_COMMANDS) {
      expect(isSecureExecCommandDenied(command), command).toBe(true);
    }
  });

  it.each([
    "python3.13",
    "pypy3.11",
    "perl5.40.0",
    "ruby3.4",
    "php8.4",
    "lua5.4",
  ])("denies common version-suffixed runtime %s", (command) => {
    expect(isSecureExecCommandDenied(command)).toBe(true);
  });

  it.each(["git", "claude", "df", "npm"])(
    "does not claim ordinary product command %s is universally unsafe",
    (command) => {
      expect(isSecureExecCommandDenied(command)).toBe(false);
    },
  );

  it("tracks the required privileged-group boundary names", () => {
    expect(SECURE_EXEC_PRIVILEGED_GROUPS).toEqual([
      "root", "wheel", "sudo", "docker", "podman", "lxd", "incus", "disk", "libvirt",
    ]);
  });
});
