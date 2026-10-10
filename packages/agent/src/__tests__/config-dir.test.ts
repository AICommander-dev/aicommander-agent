import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// envConfigDir() caches its validation per process, so every test re-imports the
// module to get a clean cache.
const ENV_DIR_VAR = "AICOMMANDER_CONFIG_DIR";
let savedEnvDir: string | undefined;

async function loadConfigDir() {
  vi.resetModules();
  return import("../config-dir.js");
}

beforeEach(() => {
  savedEnvDir = process.env[ENV_DIR_VAR];
  delete process.env[ENV_DIR_VAR];
});

afterEach(() => {
  vi.restoreAllMocks();
  if (savedEnvDir === undefined) delete process.env[ENV_DIR_VAR];
  else process.env[ENV_DIR_VAR] = savedEnvDir;
});

describe("config-dir", () => {
  it("returns undefined when the variable is unset", async () => {
    const { envConfigDir } = await loadConfigDir();
    expect(envConfigDir()).toBeUndefined();
  });

  // Blank is deliberately "unset", not "misconfigured": `FOO=` and an absent FOO
  // are the same statement of intent from a shell / service wrapper, and the wrappers
  // that export this variable can legitimately compute an empty value.
  it("returns undefined for a whitespace-only value", async () => {
    process.env[ENV_DIR_VAR] = "   ";
    const { envConfigDir } = await loadConfigDir();
    expect(envConfigDir()).toBeUndefined();
  });

  it("returns undefined for an empty value", async () => {
    process.env[ENV_DIR_VAR] = "";
    const { envConfigDir } = await loadConfigDir();
    expect(envConfigDir()).toBeUndefined();
  });

  it("trims surrounding whitespace and creates the directory", async () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "aic-cfgdir-"));
    const target = path.join(base, "config");
    process.env[ENV_DIR_VAR] = `  ${target}  `;
    const { envConfigDir } = await loadConfigDir();

    try {
      expect(envConfigDir()).toBe(target);
      expect(fs.statSync(target).isDirectory()).toBe(true);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  // Falling back to the (volatile) default would be the exact silent failure the
  // override exists to prevent, so an unusable value is fatal instead.
  it("throws on a relative path", async () => {
    process.env[ENV_DIR_VAR] = "relative/config";
    const { envConfigDir, ConfigDirError } = await loadConfigDir();
    expect(() => envConfigDir()).toThrow(ConfigDirError);
    expect(() => envConfigDir()).toThrow(/absolute path/);
  });

  it("throws when the directory cannot be created or written", async () => {
    process.env[ENV_DIR_VAR] = "/nonexistent-volume/aicommander/config";
    const { envConfigDir, ConfigDirError } = await loadConfigDir();
    vi.spyOn(fs, "mkdirSync").mockImplementation(() => {
      throw new Error("EROFS: read-only file system");
    });
    expect(() => envConfigDir()).toThrow(ConfigDirError);
    expect(() => envConfigDir()).toThrow(/not a usable directory/);
  });

  it("throws when the path exists but is a file", async () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "aic-cfgdir-file-"));
    const target = path.join(base, "config");
    fs.writeFileSync(target, "not a directory");
    process.env[ENV_DIR_VAR] = target;
    const { envConfigDir, ConfigDirError } = await loadConfigDir();

    try {
      expect(() => envConfigDir()).toThrow(ConfigDirError);
      expect(() => envConfigDir()).toThrow(/not a usable directory/);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  // The real-world case the fatal-error rule exists for: the directory is there
  // (so mkdirSync is a no-op) but we cannot write the identity into it.
  it("throws for an existing directory we cannot write to", async () => {
    if (process.getuid?.() === 0) {
      // Running as root: W_OK succeeds regardless of mode, so there is no
      // unwritable directory to construct. Nothing to assert.
      return;
    }
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "aic-cfgdir-ro-"));
    const target = path.join(base, "config");
    fs.mkdirSync(target, { mode: 0o500 });
    process.env[ENV_DIR_VAR] = target;
    const { envConfigDir, ConfigDirError } = await loadConfigDir();

    try {
      expect(() => envConfigDir()).toThrow(ConfigDirError);
      expect(() => envConfigDir()).toThrow(/not a usable directory/);
    } finally {
      fs.chmodSync(target, 0o700);
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  // Pinned behaviour, not an accident: a symlink to a writable directory is
  // accepted (recursive mkdirSync is a no-op on it, accessSync follows it).
  // Operators legitimately symlink the agent config dir at a data volume, and the
  // durability the override buys depends on the link TARGET, which we cannot
  // judge anyway. Change this only with a deliberate decision.
  it("accepts a symlink pointing at a writable directory", async () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "aic-cfgdir-link-"));
    const target = path.join(base, "real");
    const link = path.join(base, "config");
    fs.mkdirSync(target, { mode: 0o700 });
    fs.symlinkSync(target, link);
    process.env[ENV_DIR_VAR] = link;
    const { envConfigDir } = await loadConfigDir();

    try {
      expect(envConfigDir()).toBe(link);
      expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  // The directory holds the device secret and the session token, so it is
  // created 0700 — including any parent we have to create on the way.
  it("creates the directory (and its parents) private to the owner", async () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "aic-cfgdir-mode-"));
    const parent = path.join(base, "aicommander");
    const target = path.join(parent, "config");
    process.env[ENV_DIR_VAR] = target;
    const { envConfigDir } = await loadConfigDir();

    try {
      expect(envConfigDir()).toBe(target);
      for (const dir of [target, parent]) {
        const mode = fs.statSync(dir).mode & 0o777;
        expect(mode & 0o700).toBe(0o700); // owner keeps full access
        expect(mode & 0o077).toBe(0); // group/other get nothing
      }
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  it("validates only once per value", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-cfgdir-cache-"));
    process.env[ENV_DIR_VAR] = dir;
    const { envConfigDir } = await loadConfigDir();

    try {
      envConfigDir();
      const mkdirSpy = vi.spyOn(fs, "mkdirSync");
      expect(envConfigDir()).toBe(dir);
      expect(mkdirSpy).not.toHaveBeenCalled();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
