import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// session-store.ts computes its FALLBACK_DIR from os.homedir() at module load,
// and its PRIMARY_DIR is /etc (not writable as non-root in tests). We point
// homedir() at a fresh temp dir and dynamically import the module per-test so
// each test gets an isolated, writable store under <tmp>/.config/aicommander-agent.
let tmpHome: string;

const ENV_DIR_VAR = "AICOMMANDER_CONFIG_DIR";
let savedEnvDir: string | undefined;

async function loadStore() {
  vi.resetModules();
  return import("../session-store.js");
}

beforeEach(() => {
  // These cases choose dev/service mode explicitly, independent of the runner.
  for (const key of ["AICOMMANDER_SERVICE", "NODE_ENV", "INVOCATION_ID", "JOURNAL_STREAM"]) {
    vi.stubEnv(key, undefined);
  }
  // The override is process-wide: a value inherited from the developer's shell or
  // a CI runner would redirect every "default path" / precedence test below —
  // outside the mocked temp home — while still passing. Each test opts in.
  savedEnvDir = process.env[ENV_DIR_VAR];
  delete process.env[ENV_DIR_VAR];
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-"));
  vi.spyOn(os, "homedir").mockReturnValue(tmpHome);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  if (savedEnvDir === undefined) delete process.env[ENV_DIR_VAR];
  else process.env[ENV_DIR_VAR] = savedEnvDir;
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe("session-store", () => {
  it("saves and loads a session round-trip", async () => {
    const { saveSession, loadSession } = await loadStore();
    expect(loadSession()).toBeNull();

    saveSession({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    expect(loadSession()).toEqual({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
  });

  it("persists the session file with 0600 perms", async () => {
    const { saveSession } = await loadStore();
    saveSession({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    const file = path.join(tmpHome, ".config", "aicommander-agent", "session.json");
    const mode = fs.statSync(file).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("clearSession removes the stored session", async () => {
    const { saveSession, loadSession, clearSession } = await loadStore();
    saveSession({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok-123" });
    expect(loadSession()).not.toBeNull();
    clearSession();
    expect(loadSession()).toBeNull();
  });

  it("ignores a malformed session file", async () => {
    const { loadSession } = await loadStore();
    const dir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "session.json"), "{ not json");
    expect(loadSession()).toBeNull();
  });

  it("rotate marker: consume returns false when absent, true once after write", async () => {
    const { writeRotateMarker, consumeRotateMarker } = await loadStore();
    expect(consumeRotateMarker()).toBe(false);

    writeRotateMarker();
    // First consume sees it and deletes it; second does not.
    expect(consumeRotateMarker()).toBe(true);
    expect(consumeRotateMarker()).toBe(false);
  });

  it("treats a session with empty fields (isValidSession false) as absent", async () => {
    const { loadSession } = await loadStore();
    const dir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "session.json"),
      JSON.stringify({ sessionCode: "", agentToken: "" }),
    );
    expect(loadSession()).toBeNull();
  });

  it("saveSession tolerates a write failure in dev (no throw, nothing persisted)", async () => {
    const { saveSession, loadSession } = await loadStore();
    vi.spyOn(fs, "openSync").mockImplementation(() => {
      throw new Error("EACCES");
    });
    expect(() => saveSession({ sessionCode: "AIC-X", agentToken: "tok" })).not.toThrow();
    vi.restoreAllMocks();
    vi.spyOn(os, "homedir").mockReturnValue(tmpHome);
    expect(loadSession()).toBeNull();
  });
});

describe("session-store — primary/fallback precedence", () => {
  // The default (no-configDir) path reads PRIMARY (/etc) first, then the
  // user-config FALLBACK. We mock fs.readFileSync to simulate both locations
  // existing and assert the PRIMARY value wins.
  let primarySession: string | null;
  let fallbackSession: string | null;

  beforeEach(() => {
    primarySession = null;
    fallbackSession = null;
    vi.spyOn(fs, "existsSync").mockImplementation((file) => {
      const p = String(file);
      if (p.startsWith("/etc/")) return primarySession !== null;
      if (p.includes("aicommander-agent")) return fallbackSession !== null;
      return false;
    });
    vi.spyOn(fs, "chmodSync").mockImplementation(() => undefined);
    vi.spyOn(fs, "readFileSync").mockImplementation(((file: string) => {
      if (file.startsWith("/etc/")) {
        if (primarySession === null) throw new Error("ENOENT");
        return primarySession;
      }
      if (fallbackSession === null) throw new Error("ENOENT");
      return fallbackSession;
    }) as typeof fs.readFileSync);
  });

  it("prefers the primary (/etc) session when both locations exist", async () => {
    const { loadSession } = await loadStore();
    primarySession = JSON.stringify({ sessionCode: "AIC-PRIMARY", agentToken: "p" });
    fallbackSession = JSON.stringify({ sessionCode: "AIC-FALLBACK", agentToken: "f" });
    expect(loadSession()).toEqual({ sessionCode: "AIC-PRIMARY", agentToken: "p" });
  });

  it("falls back to the user-config session when primary is absent", async () => {
    const { loadSession } = await loadStore();
    primarySession = null;
    fallbackSession = JSON.stringify({ sessionCode: "AIC-FALLBACK", agentToken: "f" });
    expect(loadSession()).toEqual({ sessionCode: "AIC-FALLBACK", agentToken: "f" });
  });
});

describe("session-store — custom configDir", () => {
  let configDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-cfg-"));
  });

  afterEach(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("saves/loads/clears under configDir and writes session.json there", async () => {
    const { saveSession, loadSession, clearSession } = await loadStore();
    expect(loadSession(configDir)).toBeNull();

    saveSession({ sessionCode: "AIC-CFG-1111", agentToken: "tok" }, configDir);
    expect(fs.existsSync(path.join(configDir, "session.json"))).toBe(true);
    expect(loadSession(configDir)).toEqual({ sessionCode: "AIC-CFG-1111", agentToken: "tok" });

    clearSession(configDir);
    expect(loadSession(configDir)).toBeNull();
  });

  it("does NOT write into the default location when configDir is given", async () => {
    const { saveSession } = await loadStore();
    saveSession({ sessionCode: "AIC-CFG-2222", agentToken: "tok" }, configDir);
    const defaultFile = path.join(tmpHome, ".config", "aicommander-agent", "session.json");
    expect(fs.existsSync(defaultFile)).toBe(false);
  });

  it("rotate marker honors configDir", async () => {
    const { writeRotateMarker, consumeRotateMarker } = await loadStore();
    expect(consumeRotateMarker(configDir)).toBe(false);

    writeRotateMarker(configDir);
    expect(fs.existsSync(path.join(configDir, ".rotate"))).toBe(true);
    expect(consumeRotateMarker(configDir)).toBe(true);
    expect(consumeRotateMarker(configDir)).toBe(false);
  });
});

// The session code is what keeps linked accounts working across restarts, so it
// has to follow the identity onto durable storage wherever /etc is a ramdisk
// (QNAP QTS). The headless CLI passes no configDir, so only the env var can do it.
describe("session-store — AICOMMANDER_CONFIG_DIR override", () => {
  let envDir: string;

  beforeEach(() => {
    envDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-env-"));
  });

  afterEach(() => {
    delete process.env["AICOMMANDER_CONFIG_DIR"];
    fs.rmSync(envDir, { recursive: true, force: true });
  });

  it("stores and reloads the session from the env dir when no ctx is given", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { saveSession, loadSession } = await loadStore();

    saveSession({ sessionCode: "AIC-ENV-0001", agentToken: "tok-env" });

    expect(fs.existsSync(path.join(envDir, "session.json"))).toBe(true);
    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", "session.json"))).toBe(
      false,
    );
    expect(loadSession()?.sessionCode).toBe("AIC-ENV-0001");
  });

  it("keeps the default fallback when the variable is blank", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = "  ";
    const { saveSession } = await loadStore();

    saveSession({ sessionCode: "AIC-DEF-0002", agentToken: "tok-def" });

    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", "session.json"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(envDir, "session.json"))).toBe(false);
  });

  // The backwards-compatibility guarantee: unset must behave exactly as before.
  it("keeps the default fallback when the variable is unset", async () => {
    delete process.env["AICOMMANDER_CONFIG_DIR"];
    const { saveSession } = await loadStore();

    saveSession({ sessionCode: "AIC-DEF-0004", agentToken: "tok-def" });

    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", "session.json"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(envDir, "session.json"))).toBe(false);
  });

  it("lets an explicit configDir win over the env var", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { saveSession } = await loadStore();
    const explicit = fs.mkdtempSync(path.join(os.tmpdir(), "aic-session-explicit-"));

    try {
      saveSession({ sessionCode: "AIC-EXP-0003", agentToken: "tok-exp" }, explicit);
      expect(fs.existsSync(path.join(explicit, "session.json"))).toBe(true);
      expect(fs.existsSync(path.join(envDir, "session.json"))).toBe(false);
    } finally {
      fs.rmSync(explicit, { recursive: true, force: true });
    }
  });

  // The session code is a root-exec credential wherever it lands.
  it("persists session.json in the env dir with 0600 perms", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { saveSession } = await loadStore();

    saveSession({ sessionCode: "AIC-ENV-0600", agentToken: "tok" });

    const mode = fs.statSync(path.join(envDir, "session.json")).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("reuses a session left in the default location, then moves it on save", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    fs.writeFileSync(
      path.join(fallbackDir, "session.json"),
      JSON.stringify({ sessionCode: "AIC-LEGACY-0001", agentToken: "tok-legacy" }),
    );

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { loadSession, saveSession } = await loadStore();

    const stored = loadSession();
    expect(stored?.sessionCode).toBe("AIC-LEGACY-0001");
    expect(warn.mock.calls.flat().join(" ")).toContain(fallbackDir);

    // run.ts re-asserts the same code right after registering — that save lands
    // in the override dir, and the env copy wins from then on.
    saveSession(stored!);
    expect(fs.existsSync(path.join(envDir, "session.json"))).toBe(true);
    expect(loadSession()?.sessionCode).toBe("AIC-LEGACY-0001");
  });

  it("prefers the env dir over a stale session in the default location", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    fs.writeFileSync(
      path.join(fallbackDir, "session.json"),
      JSON.stringify({ sessionCode: "AIC-STALE-0002", agentToken: "tok-stale" }),
    );

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { saveSession, loadSession } = await loadStore();

    saveSession({ sessionCode: "AIC-ENV-0002", agentToken: "tok-env" });
    expect(loadSession()?.sessionCode).toBe("AIC-ENV-0002");
  });

  it("clearSession also removes a copy left in the default location", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    fs.writeFileSync(
      path.join(fallbackDir, "session.json"),
      JSON.stringify({ sessionCode: "AIC-LEGACY-0003", agentToken: "tok-legacy" }),
    );

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { saveSession, clearSession, loadSession } = await loadStore();

    saveSession({ sessionCode: "AIC-ENV-0003", agentToken: "tok-env" });
    clearSession();

    // A surviving default-location copy would be read back as the "current" code.
    expect(fs.existsSync(path.join(fallbackDir, "session.json"))).toBe(false);
    expect(loadSession()).toBeNull();
  });

  // `change-code` invoked without the variable writes the marker to the default
  // location; the service must still rotate rather than keep the leaked code.
  it("consumeRotateMarker finds a marker left in the default location", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    fs.writeFileSync(path.join(fallbackDir, ".rotate"), "");

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { consumeRotateMarker } = await loadStore();

    expect(consumeRotateMarker()).toBe(true);
    expect(fs.existsSync(path.join(fallbackDir, ".rotate"))).toBe(false);
    expect(consumeRotateMarker()).toBe(false);
  });

  it("writeRotateMarker writes only to the env dir", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { writeRotateMarker } = await loadStore();

    writeRotateMarker();

    expect(fs.existsSync(path.join(envDir, ".rotate"))).toBe(true);
    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", ".rotate"))).toBe(false);
  });
});
