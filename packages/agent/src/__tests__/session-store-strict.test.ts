import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { TokenVault } from "../session-store.js";

let tmpHome: string;

async function loadStore() {
  vi.resetModules();
  return import("../session-store.js");
}

function mockVault(available = true): TokenVault {
  const key = Buffer.from("test-key");
  return {
    isAvailable: () => available,
    encrypt: (plaintext) => Buffer.from(`${key.toString("hex")}:${plaintext}`),
    decrypt: (ciphertext) => {
      const text = ciphertext.toString("utf8");
      const sep = text.indexOf(":");
      return sep >= 0 ? text.slice(sep + 1) : "";
    },
  };
}

beforeEach(() => {
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-strict-"));
  vi.spyOn(os, "homedir").mockReturnValue(tmpHome);
  // A systemd-managed runner must not turn the dev cases into service cases.
  for (const key of ["AICOMMANDER_SERVICE", "NODE_ENV", "INVOCATION_ID", "JOURNAL_STREAM"]) {
    vi.stubEnv(key, undefined);
  }
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmpHome, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("session-store — atomic write + permissions", () => {
  it("uses temp+rename and leaves no orphan temp files on success", async () => {
    const { saveSession, loadSession } = await loadStore();
    saveSession({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    const dir = path.join(tmpHome, ".config", "aicommander-agent");
    const temps = fs.readdirSync(dir).filter((n) => n.includes(".tmp"));
    expect(temps).toHaveLength(0);
    expect(loadSession()).toEqual({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
  });

  it("persists the session directory at 0700 and file at 0600", async () => {
    const { saveSession } = await loadStore();
    saveSession({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    const dir = path.join(tmpHome, ".config", "aicommander-agent");
    const file = path.join(dir, "session.json");
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it("cleans up temp files when rename fails", async () => {
    const { saveSession } = await loadStore();
    const rename = fs.renameSync.bind(fs);
    vi.spyOn(fs, "renameSync").mockImplementation((from, to) => {
      if (String(from).includes(".tmp")) throw new Error("EXDEV");
      return rename(from, to);
    });
    expect(() => saveSession({ sessionCode: "AIC-X", agentToken: "tok" })).not.toThrow();
    const dir = path.join(tmpHome, ".config", "aicommander-agent");
    const temps = fs.existsSync(dir) ? fs.readdirSync(dir).filter((n) => n.includes(".tmp")) : [];
    expect(temps).toHaveLength(0);
  });

  it("reasserts modes on read without failing", async () => {
    const { saveSession, loadSession } = await loadStore();
    saveSession({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    const dir = path.join(tmpHome, ".config", "aicommander-agent");
    const file = path.join(dir, "session.json");
    fs.chmodSync(dir, 0o755);
    fs.chmodSync(file, 0o644);
    expect(loadSession()).toEqual({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });
});

describe("session-store — strict vs dev write failures", () => {
  it("tolerates write failure in dev (no throw)", async () => {
    const { saveSession, loadSession } = await loadStore();
    vi.spyOn(fs, "openSync").mockImplementation(() => {
      throw new Error("EACCES");
    });
    expect(() => saveSession({ sessionCode: "AIC-X", agentToken: "tok" })).not.toThrow();
    expect(loadSession()).toBeNull();
  });

  it("throws in service mode when persistence fails", async () => {
    process.env["AICOMMANDER_SERVICE"] = "1";
    const { saveSession } = await loadStore();
    vi.spyOn(fs, "openSync").mockImplementation(() => {
      throw new Error("EACCES");
    });
    expect(() => saveSession({ sessionCode: "AIC-X", agentToken: "tok" })).toThrow(
      /session credentials/i,
    );
  });
});

describe("session-store — token vault", () => {
  it("stores the token outside session.json when a vault is provided", async () => {
    const configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-vault-"));
    try {
      const { saveSession, loadSession } = await loadStore();
      saveSession(
        { sessionCode: "AIC-VAULT-1111", agentToken: "secret-token" },
        { configDir, tokenVault: mockVault() },
      );
      const json = JSON.parse(fs.readFileSync(path.join(configDir, "session.json"), "utf8"));
      expect(json.sessionCode).toBe("AIC-VAULT-1111");
      expect(json.tokenProtected).toBe(true);
      expect(json.agentToken).toBeUndefined();
      expect(fs.existsSync(path.join(configDir, "session.token"))).toBe(true);
      expect(loadSession({ configDir, tokenVault: mockVault() })).toEqual({
        sessionCode: "AIC-VAULT-1111",
        agentToken: "secret-token",
      });
    } finally {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
  });

  it("clearSession removes the encrypted token blob", async () => {
    const configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-vault-"));
    try {
      const { saveSession, clearSession } = await loadStore();
      saveSession(
        { sessionCode: "AIC-VAULT-2222", agentToken: "secret-token" },
        { configDir, tokenVault: mockVault() },
      );
      clearSession(configDir);
      expect(fs.existsSync(path.join(configDir, "session.json"))).toBe(false);
      expect(fs.existsSync(path.join(configDir, "session.token"))).toBe(false);
    } finally {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
  });
});
