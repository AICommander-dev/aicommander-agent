import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// device.ts computes its FALLBACK_DIR from os.homedir() at module load, and its
// PRIMARY_DIR is /etc (not writable as non-root in tests). We point homedir() at
// a fresh temp dir and dynamically import the module per-test so the default path
// resolves to a writable <tmp>/.config/aicommander-agent location.
let tmpHome: string;

const ENV_DIR_VAR = "AICOMMANDER_CONFIG_DIR";
let savedEnvDir: string | undefined;

async function loadDevice() {
  vi.resetModules();
  return import("../device.js");
}

beforeEach(() => {
  // The override is process-wide: a value inherited from the developer's shell or
  // a CI runner would redirect every "default path" test below — outside the
  // mocked temp home — while still passing. Each test opts in explicitly.
  savedEnvDir = process.env[ENV_DIR_VAR];
  delete process.env[ENV_DIR_VAR];
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-"));
  vi.spyOn(os, "homedir").mockReturnValue(tmpHome);
});

afterEach(() => {
  vi.restoreAllMocks();
  if (savedEnvDir === undefined) delete process.env[ENV_DIR_VAR];
  else process.env[ENV_DIR_VAR] = savedEnvDir;
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

const PRIMARY_DEVICE_FILE = "/etc/aicommander-agent/device.json";

/** Make /etc/aicommander-agent/device.json readable without root. */
function mockPrimaryDevice(contents: string): void {
  const realRead = fs.readFileSync.bind(fs);
  vi.spyOn(fs, "readFileSync").mockImplementation(((
    file: fs.PathOrFileDescriptor,
    ...rest: unknown[]
  ) => {
    if (String(file) === PRIMARY_DEVICE_FILE) return contents;
    return (realRead as (...a: unknown[]) => unknown)(file, ...rest);
  }) as typeof fs.readFileSync);
}

describe("device — default path", () => {
  it("creates and persists a device under ~/.config/aicommander-agent", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const device = loadOrCreateDevice();
    expect(device.deviceId.length).toBeGreaterThan(0);
    expect(device.deviceSecret.length).toBeGreaterThan(0);

    const file = path.join(tmpHome, ".config", "aicommander-agent", "device.json");
    expect(fs.existsSync(file)).toBe(true);
  });

  it("reuses the same identity on a second call (default path)", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const first = loadOrCreateDevice();
    const second = loadOrCreateDevice();
    expect(second).toEqual(first);
  });

  it("does NOT write into a custom dir when configDir is omitted", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const customDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-custom-"));
    loadOrCreateDevice();
    expect(fs.existsSync(path.join(customDir, "device.json"))).toBe(false);
    fs.rmSync(customDir, { recursive: true, force: true });
  });
});

describe("device — custom configDir", () => {
  let configDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-cfg-"));
  });

  afterEach(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("stores device.json directly under configDir", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const device = loadOrCreateDevice(configDir);
    const file = path.join(configDir, "device.json");
    expect(fs.existsSync(file)).toBe(true);

    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(parsed).toEqual(device);
  });

  it("reuses the same identity from configDir on subsequent calls", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const first = loadOrCreateDevice(configDir);
    const second = loadOrCreateDevice(configDir);
    expect(second).toEqual(first);
  });

  it("creates the configDir (with subpath) if missing", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const nested = path.join(configDir, "nested", "userData");
    const device = loadOrCreateDevice(nested);
    expect(fs.existsSync(path.join(nested, "device.json"))).toBe(true);
    expect(device.deviceId.length).toBeGreaterThan(0);
  });

  it("does NOT touch the default location when configDir is given", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    loadOrCreateDevice(configDir);
    const defaultFile = path.join(tmpHome, ".config", "aicommander-agent", "device.json");
    expect(fs.existsSync(defaultFile)).toBe(false);
  });

  it("regenerates when device.json is corrupt (invalid JSON)", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    fs.writeFileSync(path.join(configDir, "device.json"), "{ not json");
    const device = loadOrCreateDevice(configDir);
    expect(device.deviceId.length).toBeGreaterThan(0);
    expect(device.deviceSecret.length).toBeGreaterThan(0);
    // The corrupt file is overwritten with a valid identity.
    const parsed = JSON.parse(fs.readFileSync(path.join(configDir, "device.json"), "utf8"));
    expect(parsed).toEqual(device);
  });

  it("regenerates when device.json fails isValidDevice (missing fields)", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    fs.writeFileSync(
      path.join(configDir, "device.json"),
      JSON.stringify({ deviceId: "", deviceSecret: "" }),
    );
    const device = loadOrCreateDevice(configDir);
    expect(device.deviceId.length).toBeGreaterThan(0);
    expect(device.deviceSecret.length).toBeGreaterThan(0);
  });
});

describe("device — regenerateDevice (recovery)", () => {
  const PRIMARY_DIR = "/etc/aicommander-agent";
  let configDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-regen-"));
  });

  afterEach(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("mints a brand-new identity into configDir, overwriting the old one", async () => {
    const { loadOrCreateDevice, regenerateDevice } = await loadDevice();
    const old = loadOrCreateDevice(configDir);
    const fresh = regenerateDevice(configDir);

    expect(fresh.deviceId).not.toBe(old.deviceId);
    expect(fresh.deviceSecret).not.toBe(old.deviceSecret);
    // The on-disk file now holds the fresh identity, not the rejected one.
    const parsed = JSON.parse(fs.readFileSync(path.join(configDir, "device.json"), "utf8"));
    expect(parsed).toEqual(fresh);
  });

  it("writes the FALLBACK dir and purges a stale PRIMARY file when /etc is unwritable", async () => {
    const { regenerateDevice } = await loadDevice();
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");

    // /etc is not writable as non-root: force the PRIMARY write to fail so the
    // implementation falls back to ~/.config (the real dual-directory path).
    const realWrite = fs.writeFileSync.bind(fs);
    vi.spyOn(fs, "writeFileSync").mockImplementation(((file: fs.PathOrFileDescriptor, ...rest: unknown[]) => {
      if (String(file).startsWith(PRIMARY_DIR)) throw new Error("EACCES");
      return (realWrite as (...a: unknown[]) => unknown)(file, ...rest);
    }) as typeof fs.writeFileSync);

    // Capture the best-effort cleanup so we can assert the OTHER (PRIMARY) dir's
    // stale identity is removed — that's what prevents the rejected identity from
    // being read back ahead of the fresh FALLBACK one.
    const rmSpy = vi.spyOn(fs, "rmSync");

    const fresh = regenerateDevice();

    // Fresh identity persisted under FALLBACK.
    const parsed = JSON.parse(fs.readFileSync(path.join(fallbackDir, "device.json"), "utf8"));
    expect(parsed).toEqual(fresh);

    // The stale PRIMARY identity file was removed (best-effort, force:true).
    const removedPrimary = rmSpy.mock.calls.some(
      ([p]) => String(p) === path.join(PRIMARY_DIR, "device.json"),
    );
    expect(removedPrimary).toBe(true);
  });

  it("purges a stale FALLBACK file when PRIMARY is writable", async () => {
    const { regenerateDevice } = await loadDevice();
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");

    // Seed a stale identity in FALLBACK that must NOT survive regeneration.
    fs.mkdirSync(fallbackDir, { recursive: true });
    const stale = { deviceId: "stale-id", deviceSecret: "stale-secret" };
    fs.writeFileSync(path.join(fallbackDir, "device.json"), JSON.stringify(stale));

    // Make PRIMARY (/etc) appear writable by redirecting its writes into a temp
    // dir, so regenerate takes the "PRIMARY succeeds → purge FALLBACK" branch.
    const primaryProxy = fs.mkdtempSync(path.join(os.tmpdir(), "aic-primary-"));
    const realWrite = fs.writeFileSync.bind(fs);
    const realMkdir = fs.mkdirSync.bind(fs);
    vi.spyOn(fs, "mkdirSync").mockImplementation(((dir: fs.PathLike, ...rest: unknown[]) => {
      const target = String(dir).startsWith(PRIMARY_DIR) ? primaryProxy : dir;
      return (realMkdir as (...a: unknown[]) => unknown)(target, ...rest);
    }) as typeof fs.mkdirSync);
    vi.spyOn(fs, "writeFileSync").mockImplementation(((file: fs.PathOrFileDescriptor, ...rest: unknown[]) => {
      const target = String(file).startsWith(PRIMARY_DIR)
        ? path.join(primaryProxy, "device.json")
        : file;
      return (realWrite as (...a: unknown[]) => unknown)(target, ...rest);
    }) as typeof fs.writeFileSync);

    const fresh = regenerateDevice();

    // The stale FALLBACK file is gone (purged), so it can't resurrect old id.
    expect(fs.existsSync(path.join(fallbackDir, "device.json"))).toBe(false);
    expect(fresh.deviceId).not.toBe(stale.deviceId);

    fs.rmSync(primaryProxy, { recursive: true, force: true });
  });

  // Every purge is gated on a write that actually landed. With NEITHER location
  // writable, deleting the identity that is still readable would turn this
  // machine into a new device on every single start.
  it("purges nothing when neither default location accepted the fresh identity", async () => {
    const { regenerateDevice } = await loadDevice();
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    const existing = { deviceId: "existing-id", deviceSecret: "existing-secret" };
    fs.writeFileSync(path.join(fallbackDir, "device.json"), JSON.stringify(existing));

    vi.spyOn(fs, "writeFileSync").mockImplementation(() => {
      throw new Error("EROFS: read-only file system");
    });
    const rmSpy = vi.spyOn(fs, "rmSync");

    // The default path stays best-effort — no operator promised these locations
    // are durable, and a non-root dev run legitimately cannot write /etc.
    const fresh = regenerateDevice();
    expect(fresh.deviceId.length).toBeGreaterThan(0);
    expect(rmSpy).not.toHaveBeenCalled();
    expect(JSON.parse(fs.readFileSync(path.join(fallbackDir, "device.json"), "utf8"))).toEqual(
      existing,
    );
  });
});

describe("device — write failure fallback", () => {
  let configDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-fail-"));
  });

  afterEach(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("returns an in-memory identity without throwing when persistence fails", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    vi.spyOn(fs, "writeFileSync").mockImplementation(() => {
      throw new Error("EACCES");
    });
    const device = loadOrCreateDevice(configDir);
    expect(device.deviceId.length).toBeGreaterThan(0);
    expect(device.deviceSecret.length).toBeGreaterThan(0);
    // Nothing was written to disk.
    expect(fs.existsSync(path.join(configDir, "device.json"))).toBe(false);
  });

  it("generates distinct, non-empty identities across fresh dirs", async () => {
    const { loadOrCreateDevice } = await loadDevice();
    const dirA = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-a-"));
    const dirB = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-b-"));
    try {
      const a = loadOrCreateDevice(dirA);
      const b = loadOrCreateDevice(dirB);
      expect(a.deviceId).not.toBe(b.deviceId);
      expect(a.deviceSecret).not.toBe(b.deviceSecret);
      expect(a.deviceId.length).toBeGreaterThan(0);
      expect(a.deviceSecret.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dirA, { recursive: true, force: true });
      fs.rmSync(dirB, { recursive: true, force: true });
    }
  });
});

// The headless CLI calls loadOrCreateDevice() with NO argument (run.ts), so this
// env override is the only way to move the identity off a non-durable /etc — on
// QNAP QTS the whole root filesystem, /etc included, is a ramdisk rebuilt at boot.
describe("device — AICOMMANDER_CONFIG_DIR override", () => {
  let envDir: string;

  beforeEach(() => {
    envDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-env-"));
  });

  afterEach(() => {
    delete process.env["AICOMMANDER_CONFIG_DIR"];
    fs.rmSync(envDir, { recursive: true, force: true });
  });

  it("persists the identity under the env dir when no configDir is passed", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { loadOrCreateDevice } = await loadDevice();

    const device = loadOrCreateDevice();

    expect(fs.existsSync(path.join(envDir, "device.json"))).toBe(true);
    // And specifically NOT in the default fallback location.
    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", "device.json"))).toBe(
      false,
    );
    expect(loadOrCreateDevice().deviceId).toBe(device.deviceId);
  });

  it("keeps the default fallback when the variable is blank", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = "   ";
    const { loadOrCreateDevice } = await loadDevice();

    loadOrCreateDevice();

    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", "device.json"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(envDir, "device.json"))).toBe(false);
  });

  // The backwards-compatibility guarantee: unset must behave exactly as before.
  it("keeps the default fallback when the variable is unset", async () => {
    delete process.env["AICOMMANDER_CONFIG_DIR"];
    const { loadOrCreateDevice } = await loadDevice();

    loadOrCreateDevice();

    expect(fs.existsSync(path.join(tmpHome, ".config", "aicommander-agent", "device.json"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(envDir, "device.json"))).toBe(false);
  });

  it("lets an explicit configDir win over the env var", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { loadOrCreateDevice } = await loadDevice();
    const explicit = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-explicit-"));

    try {
      loadOrCreateDevice(explicit);
      expect(fs.existsSync(path.join(explicit, "device.json"))).toBe(true);
      expect(fs.existsSync(path.join(envDir, "device.json"))).toBe(false);
    } finally {
      fs.rmSync(explicit, { recursive: true, force: true });
    }
  });

  it("regenerateDevice honours the env dir too", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { loadOrCreateDevice, regenerateDevice } = await loadDevice();

    const first = loadOrCreateDevice();
    const second = regenerateDevice();

    expect(second.deviceId).not.toBe(first.deviceId);
    expect(fs.existsSync(path.join(envDir, "device.json"))).toBe(true);
    // The regenerated identity must be what a later load reads back.
    expect(loadOrCreateDevice().deviceId).toBe(second.deviceId);
  });

  // Switching the override on for an ALREADY REGISTERED machine must not orphan
  // it: a fresh identity there means a new session code and every linked account
  // lost, silently.
  it("adopts an existing FALLBACK identity into the env dir", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    const legacy = { deviceId: "legacy-id", deviceSecret: "legacy-secret" };
    fs.writeFileSync(path.join(fallbackDir, "device.json"), JSON.stringify(legacy));

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { loadOrCreateDevice } = await loadDevice();

    expect(loadOrCreateDevice()).toEqual(legacy);
    // Copied (not merely read through): /etc-style storage may be gone next boot.
    expect(JSON.parse(fs.readFileSync(path.join(envDir, "device.json"), "utf8"))).toEqual(legacy);
    expect(warn.mock.calls.flat().join(" ")).toContain("Adopting");
  });

  it("adopts an existing PRIMARY identity into the env dir", async () => {
    const legacy = { deviceId: "primary-id", deviceSecret: "primary-secret" };
    mockPrimaryDevice(JSON.stringify(legacy));

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { loadOrCreateDevice } = await loadDevice();

    expect(loadOrCreateDevice()).toEqual(legacy);
    expect(JSON.parse(fs.readFileSync(path.join(envDir, "device.json"), "utf8"))).toEqual(legacy);
  });

  it("does NOT adopt a default-location identity when an explicit configDir is given", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    fs.writeFileSync(
      path.join(fallbackDir, "device.json"),
      JSON.stringify({ deviceId: "legacy-id", deviceSecret: "legacy-secret" }),
    );

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { loadOrCreateDevice } = await loadDevice();
    const explicit = fs.mkdtempSync(path.join(os.tmpdir(), "aic-device-explicit-"));

    try {
      // The desktop app's per-user data dir is authoritative and self-contained.
      expect(loadOrCreateDevice(explicit).deviceId).not.toBe("legacy-id");
    } finally {
      fs.rmSync(explicit, { recursive: true, force: true });
    }
  });

  // The env var can be absent on a later manual `run`, which would read the
  // REJECTED identity straight back out of the default locations (403 loop).
  it("regenerateDevice purges the default locations under the env override", async () => {
    const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
    fs.mkdirSync(fallbackDir, { recursive: true });
    fs.writeFileSync(
      path.join(fallbackDir, "device.json"),
      JSON.stringify({ deviceId: "rejected-id", deviceSecret: "rejected-secret" }),
    );

    process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
    const { loadOrCreateDevice, regenerateDevice } = await loadDevice();
    const rmSpy = vi.spyOn(fs, "rmSync");
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const fresh = regenerateDevice();

    expect(JSON.parse(fs.readFileSync(path.join(envDir, "device.json"), "utf8"))).toEqual(fresh);
    expect(fs.existsSync(path.join(fallbackDir, "device.json"))).toBe(false);
    expect(rmSpy.mock.calls.some(([p]) => String(p) === PRIMARY_DEVICE_FILE)).toBe(true);

    // A later start without the variable must not resurrect the rejected identity.
    delete process.env["AICOMMANDER_CONFIG_DIR"];
    expect(loadOrCreateDevice().deviceId).not.toBe("rejected-id");
  });

  // envConfigDir() checks writability ONCE per process and caches it, so a volume
  // that fills up or goes read-only afterwards fails only at the actual write.
  // Treating that write as successful is how the identity ends up persisted
  // NOWHERE while the fallbacks are deleted — a brand-new session code on the
  // next start, which is exactly what the override exists to prevent.
  describe("write failures under the override", () => {
    /** Make every write inside `dir` fail, as a full or read-only volume would. */
    function breakWritesInto(dir: string): void {
      const realWrite = fs.writeFileSync.bind(fs);
      vi.spyOn(fs, "writeFileSync").mockImplementation(((
        file: fs.PathOrFileDescriptor,
        ...rest: unknown[]
      ) => {
        if (String(file).startsWith(dir)) throw new Error("ENOSPC: no space left on device");
        return (realWrite as (...a: unknown[]) => unknown)(file, ...rest);
      }) as typeof fs.writeFileSync);
    }

    it("regenerateDevice throws instead of purging the defaults it could not replace", async () => {
      const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
      fs.mkdirSync(fallbackDir, { recursive: true });
      const existing = { deviceId: "existing-id", deviceSecret: "existing-secret" };
      fs.writeFileSync(path.join(fallbackDir, "device.json"), JSON.stringify(existing));

      process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
      const { regenerateDevice } = await loadDevice();
      breakWritesInto(envDir);
      const rmSpy = vi.spyOn(fs, "rmSync");

      expect(() => regenerateDevice()).toThrow(/AICOMMANDER_CONFIG_DIR/);
      // The only identity on disk is untouched — not deleted on the strength of
      // a write that never landed.
      expect(JSON.parse(fs.readFileSync(path.join(fallbackDir, "device.json"), "utf8"))).toEqual(
        existing,
      );
      expect(rmSpy).not.toHaveBeenCalled();
    });

    it("loadOrCreateDevice throws rather than adopting an identity it cannot copy", async () => {
      const fallbackDir = path.join(tmpHome, ".config", "aicommander-agent");
      fs.mkdirSync(fallbackDir, { recursive: true });
      const legacy = { deviceId: "legacy-id", deviceSecret: "legacy-secret" };
      fs.writeFileSync(path.join(fallbackDir, "device.json"), JSON.stringify(legacy));

      process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
      vi.spyOn(console, "warn").mockImplementation(() => {});
      const { loadOrCreateDevice } = await loadDevice();
      breakWritesInto(envDir);

      // Returning `legacy` here would work today and lose the machine on the next
      // QTS boot, when the ramdisk copy it came from is gone.
      expect(() => loadOrCreateDevice()).toThrow(/AICOMMANDER_CONFIG_DIR/);
    });

    it("loadOrCreateDevice throws rather than running on an unpersisted new identity", async () => {
      process.env["AICOMMANDER_CONFIG_DIR"] = envDir;
      const { loadOrCreateDevice } = await loadDevice();
      breakWritesInto(envDir);

      expect(() => loadOrCreateDevice()).toThrow(/AICOMMANDER_CONFIG_DIR/);
      expect(fs.existsSync(path.join(envDir, "device.json"))).toBe(false);
    });
  });

  // The only in-process signal that a CLI subcommand is addressing a DIFFERENT
  // store than the service (which runs with the override exported).
  it("warns on stderr when it mints a new identity with no override in play", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { loadOrCreateDevice } = await loadDevice();

    loadOrCreateDevice();
    expect(warn.mock.calls.flat().join(" ")).toContain("AICOMMANDER_CONFIG_DIR");

    // Not on the next call — that one finds the identity it just persisted.
    warn.mockClear();
    loadOrCreateDevice();
    expect(warn).not.toHaveBeenCalled();
  });
});
