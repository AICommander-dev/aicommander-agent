// Config, credential store, diagnostic log — and the two environmental causes
// that impersonate the interesting ones.
//
// The store check's pass/fail/skip boundary is the subtle part: a directory that
// is missing but CREATABLE is how a non-root agent's /etc candidate legitimately
// looks, and reporting that as a fault would fire on every user install.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { storageChecks } from "../doctor/checks/storage.js";
import { environmentChecks, redactProxyValue } from "../doctor/checks/environment.js";
import type { CheckResult, DoctorContext } from "../doctor/types.js";

let configDir: string;

function ctx(overrides: Partial<DoctorContext> = {}): DoctorContext {
  return {
    configDir,
    serverUrl: "https://relay.invalid",
    offline: true,
    networkTimeoutMs: 100,
    probeDelayMs: 0,
    ...overrides,
  };
}

function byId(results: CheckResult[], id: string): CheckResult {
  const found = results.find((r) => r.id === id);
  if (!found) throw new Error(`no check ${id} in ${results.map((r) => r.id).join(", ")}`);
  return found;
}

const savedEnv = { ...process.env };

beforeEach(() => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-store-"));
});

afterEach(() => {
  fs.rmSync(configDir, { recursive: true, force: true });
  process.env = { ...savedEnv };
});

describe("credential store check", () => {
  it("warns — not fails — when the store is writable but empty", async () => {
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/never completed a registration|no identity or session file/);
  });

  it("passes when the identity and session files are there with the right modes", async () => {
    fs.writeFileSync(path.join(configDir, "device.json"), "{}", { mode: 0o600 });
    fs.writeFileSync(path.join(configDir, "session.json"), "{}", { mode: 0o600 });
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("ok");
    expect(String(result.facts?.["found"])).toContain("device.json");
  });

  it("reads device.json WITHOUT session.json as never-registered, not as damage", async () => {
    // The most common state there is at the moment somebody runs diagnostics.
    // `loadOrCreateDevice()` persists device.json BEFORE register() is even
    // attempted, so a machine that has never reached the relay — first start,
    // offline, or registration failing — legitimately looks exactly like this.
    // Calling it "the signature of a scanner having quarantined it" told that
    // user their store was damaged when it is simply new.
    fs.writeFileSync(path.join(configDir, "device.json"), "{}", { mode: 0o600 });
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/never completed a registration/);
    expect(result.detail).not.toMatch(/lost a file/);
    expect(result.remedy).not.toMatch(/quarantine/);
    expect(result.facts?.["registered"]).toBe(false);
    expect(result.facts?.["damaged"]).toBeNull();
  });

  it("reads session.json WITHOUT device.json as a store that has lost a file", async () => {
    // The other order cannot happen on its own: the session is only ever written
    // after the identity. This one IS the quarantine signature.
    fs.writeFileSync(path.join(configDir, "session.json"), "{}", { mode: 0o600 });
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/lost a file/);
    expect(String(result.facts?.["damaged"])).toContain("device.json");
    expect(result.remedy).toMatch(/quarantine/);
  });

  it("catches a protected session whose token sidecar has gone missing", async () => {
    // `session.token` is optional in general and REQUIRED here: the flag that
    // says so lives inside session.json, so a rule that only stats the files
    // reported this machine — which cannot present a credential any more — as a
    // complete, healthy store.
    fs.writeFileSync(path.join(configDir, "device.json"), "{}", { mode: 0o600 });
    fs.writeFileSync(
      path.join(configDir, "session.json"),
      JSON.stringify({ sessionCode: "AAAA-BBBB", tokenProtected: true }),
      { mode: 0o600 },
    );
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("warn");
    expect(String(result.facts?.["damaged"])).toContain("session.token");
  });

  it("passes a protected session that still has its sidecar", async () => {
    fs.writeFileSync(path.join(configDir, "device.json"), "{}", { mode: 0o600 });
    fs.writeFileSync(
      path.join(configDir, "session.json"),
      JSON.stringify({ sessionCode: "AAAA-BBBB", tokenProtected: true }),
      { mode: 0o600 },
    );
    fs.writeFileSync(path.join(configDir, "session.token"), "x", { mode: 0o600 });
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("ok");
  });

  it("keeps the credential out of the result when it opens session.json", async () => {
    // The completeness rule reads ONE boolean out of that file. Nothing else
    // from it may reach a fact, a detail or a remedy — the report goes to a
    // vendor's inbox.
    fs.writeFileSync(path.join(configDir, "device.json"), "{}", { mode: 0o600 });
    fs.writeFileSync(
      path.join(configDir, "session.json"),
      JSON.stringify({ sessionCode: "SECRET-CODE", agentToken: "hunter2-token" }),
      { mode: 0o600 },
    );
    const serialized = JSON.stringify(byId(await storageChecks.run(ctx()), "config.store"));
    expect(serialized).not.toContain("hunter2-token");
    expect(serialized).not.toContain("SECRET-CODE");
  });

  it("warns about a store file a local user can read", async () => {
    fs.writeFileSync(path.join(configDir, "session.json"), "{}", { mode: 0o644 });
    const result = byId(await storageChecks.run(ctx()), "config.store");
    expect(result.verdict).toBe("warn");
    expect(result.detail).toMatch(/local user can read/);
  });

  it("fails when the store directory refuses a write", async () => {
    fs.chmodSync(configDir, 0o500);
    try {
      const result = byId(await storageChecks.run(ctx()), "config.store");
      expect(result.verdict).toBe(process.getuid?.() === 0 ? "warn" : "fail");
    } finally {
      fs.chmodSync(configDir, 0o700);
    }
  });

  it("leaves no probe file behind", async () => {
    await storageChecks.run(ctx());
    expect(fs.readdirSync(configDir)).toEqual([]);
  });

  it("NAMES a probe file it could not remove, instead of calling the directory unwritable", async () => {
    // The regression: a probe that was WRITTEN and could not be removed came
    // back as `refused`, so the verdict said "no store directory accepted a
    // write" — false — while a real .aicommander-doctor-*.tmp sat in the store
    // directory with nothing naming it. Both halves were wrong at once, and the
    // leftover broke the no-file-left-behind rule this command promises.
    const realRm = fs.promises.rm;
    const rm = vi.spyOn(fs.promises, "rm").mockImplementation(async (target, options) => {
      if (String(target).includes(".aicommander-doctor-")) {
        throw Object.assign(new Error(`EPERM: operation not permitted, unlink '${String(target)}'`), {
          code: "EPERM",
        });
      }
      return realRm(target, options);
    });
    try {
      const result = byId(await storageChecks.run(ctx()), "config.store");
      expect(result.detail).not.toMatch(/no store directory accepted a write/);
      expect(result.detail).toMatch(/LEFT a probe file behind/);
      // The file itself, by name, in the detail, the remedy and the facts.
      const leftover = fs.readdirSync(configDir).find((n) => n.startsWith(".aicommander-doctor-"));
      expect(leftover).toBeDefined();
      expect(result.detail).toContain(leftover!);
      expect(result.remedy).toMatch(/Delete .* by hand/);
      expect(String(result.facts?.["leftover"])).toContain(leftover!);
      // A leftover is worth telling somebody about; it is not a broken store.
      expect(result.verdict).toBe("warn");
    } finally {
      rm.mockRestore();
      for (const name of fs.readdirSync(configDir)) fs.rmSync(path.join(configDir, name), { force: true });
    }
  });
});

describe("AICOMMANDER_CONFIG_DIR check", () => {
  it("reports 'not set' as a normal, passing state", async () => {
    delete process.env["AICOMMANDER_CONFIG_DIR"];
    expect(byId(await storageChecks.run(ctx()), "config.override").verdict).toBe("ok");
  });

  it("fails a relative override, which the agent refuses to start with", async () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = "relative/path";
    const result = byId(await storageChecks.run(ctx()), "config.override");
    expect(result.verdict).toBe("fail");
    expect(result.detail).toMatch(/not an absolute path/);
  });

  it("does NOT create the directory it was pointed at", async () => {
    // envConfigDir() creates and asserts; a diagnostic must not. Pointing the
    // override at a path that does not exist has to leave it not existing —
    // and, since the agent DOES create it at startup, must not be reported as a
    // fault either. (A verdict that depended on whether some earlier check had
    // happened to create the directory first was not a measurement of anything.)
    const target = path.join(configDir, "nope");
    process.env["AICOMMANDER_CONFIG_DIR"] = target;
    const result = byId(await storageChecks.run(ctx()), "config.override");
    expect(result.verdict).toBe("ok");
    expect(result.detail).toMatch(/does not exist yet/);
    expect(fs.existsSync(target)).toBe(false);
  });

  it("accepts an override several levels below the nearest existing directory", async () => {
    // envConfigDir() creates with mkdir -p, so the question is whether the CHAIN
    // accepts a directory, not whether the immediate parent already exists.
    // Testing only the parent reported "unusable" for a path the agent creates
    // without complaint.
    const target = path.join(configDir, "a", "b", "store");
    process.env["AICOMMANDER_CONFIG_DIR"] = target;
    const result = byId(await storageChecks.run(ctx()), "config.override");
    expect(result.verdict).toBe("ok");
    expect(fs.existsSync(path.join(configDir, "a"))).toBe(false);
  });

  it("warns — neither ok nor fail — for an override it could not inspect at all", async () => {
    // The regression this pins: `stat().catch(() => null)` folded EACCES into
    // "absent", so an override nobody can even stat was reported healthy, as
    // "does not exist yet, the agent will create it". An unknowable path is its
    // own verdict; both of the other two would be a claim this run did not make.
    if (process.getuid?.() === 0) return; // root ignores the mode bits
    const sealed = path.join(configDir, "sealed");
    fs.mkdirSync(sealed, { mode: 0o700 });
    fs.writeFileSync(path.join(sealed, "keep"), "x");
    fs.chmodSync(sealed, 0o000);
    process.env["AICOMMANDER_CONFIG_DIR"] = path.join(sealed, "store");
    try {
      const result = byId(await storageChecks.run(ctx()), "config.override");
      expect(result.verdict).toBe("warn");
      expect(result.detail).toMatch(/could not be determined/);
      expect(result.detail).not.toMatch(/does not exist yet/);
    } finally {
      fs.chmodSync(sealed, 0o700);
    }
  });

  it("fails an override whose PARENT will not accept a directory either", async () => {
    const parent = path.join(configDir, "sealed");
    fs.mkdirSync(parent, { mode: 0o500 });
    process.env["AICOMMANDER_CONFIG_DIR"] = path.join(parent, "store");
    try {
      const result = byId(await storageChecks.run(ctx()), "config.override");
      // Root ignores the mode bits, so the honest expectation differs there.
      expect(result.verdict).toBe(process.getuid?.() === 0 ? "ok" : "fail");
    } finally {
      fs.chmodSync(parent, 0o700);
    }
  });
});

describe("diagnostic log check", () => {
  it("says where the log is and how big it is", async () => {
    const logDir = path.join(configDir, "logs");
    fs.mkdirSync(logDir);
    fs.writeFileSync(path.join(logDir, "worker.log"), "x".repeat(2048));
    const result = byId(await storageChecks.run(ctx()), "diag.log");
    expect(result.verdict).toBe("ok");
    expect(result.detail).toContain("worker.log");
    expect(String(result.facts?.["dir"])).toBe(logDir);
  });

  it("warns, with the path, when nothing has written a log yet", async () => {
    const result = byId(await storageChecks.run(ctx()), "diag.log");
    expect(result.verdict).toBe("warn");
    expect(String(result.facts?.["dir"])).toContain("logs");
  });

  it("does NOT create the configured directory just to name the log inside it", async () => {
    // The mutation this pins: `resolveDiagLogDir` falls back to `envConfigDir()`,
    // which mkdirSync's the override — so a CLI `doctor` on a machine with a
    // mistyped AICOMMANDER_CONFIG_DIR created that directory, synchronously, on
    // Electron's main loop, while the header above claimed no check under
    // doctor/checks/ does that.
    const target = path.join(configDir, "never-created");
    process.env["AICOMMANDER_CONFIG_DIR"] = target;
    const result = byId(await storageChecks.run(ctx({ configDir: undefined })), "diag.log");
    expect(String(result.facts?.["dir"])).toBe(path.join(target, "logs"));
    expect(fs.existsSync(target)).toBe(false);
  });
});

describe("environment checks", () => {
  it("reports the runtime and the free space", async () => {
    const results = await environmentChecks.run(ctx());
    expect(byId(results, "env.runtime").verdict).toBe("ok");
    expect(["ok", "warn", "skipped"]).toContain(byId(results, "env.disk").verdict);
  });

  it("does not report a confident OK about a volume it could not look at", async () => {
    // The walk up to an existing ancestor used to catch EVERY stat error and go
    // to the parent, so an EACCES on the jobs directory — the signature of the
    // filter driver this whole feature exists for — was read as "it does not
    // exist" and statfs then measured the PARENT's volume and presented it as
    // the volume holding the jobs directory. "Could not check" is a third
    // verdict, never rounded to the reassuring neighbour.
    if (process.platform === "win32" || process.getuid?.() === 0) return; // chmod proves nothing there
    fs.mkdirSync(path.join(configDir, "jobs"), { recursive: true });
    fs.chmodSync(configDir, 0o000);
    try {
      const result = byId(await environmentChecks.run(ctx()), "env.disk");
      expect(result.verdict).toBe("skipped");
      expect(result.detail).toMatch(/could not be examined/);
      expect(result.facts?.["code"]).toMatch(/EACCES|EPERM/);
      // And emphatically not a measurement of the temp directory above it.
      expect(result.facts?.["freeBytes"]).toBeUndefined();
    } finally {
      fs.chmodSync(configDir, 0o700);
    }
  });

  it("passes when no proxy is configured", async () => {
    for (const name of ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]) {
      delete process.env[name];
    }
    expect(byId(await environmentChecks.run(ctx()), "env.proxy").verdict).toBe("ok");
  });

  it("warns when a proxy IS configured, because our clients ignore it", async () => {
    process.env["HTTPS_PROXY"] = "http://proxy.corp:8080";
    const result = byId(await environmentChecks.run(ctx()), "env.proxy");
    expect(result.verdict).toBe("warn");
    expect(result.remedy).toMatch(/do NOT honour/);
  });

  it("keeps the caller's working directory and a raw server override out of the report", async () => {
    // Both go into a file emailed to antivirus vendors, and redactDiagText has
    // no rule for either: a cwd is an arbitrary customer path, and an
    // AICOMMANDER_SERVER value can carry userinfo. The cwd answers no question
    // this report asks; the override's ORIGIN answers the only one it does.
    process.env["AICOMMANDER_SERVER"] = "https://someone:hunter2@relay.example/path?key=secret";
    const runtime = byId(await environmentChecks.run(ctx()), "env.runtime");
    const serialized = JSON.stringify(runtime);
    expect(serialized).not.toContain("hunter2");
    expect(serialized).not.toContain("key=secret");
    expect(serialized).not.toContain(process.cwd());
    expect(runtime.facts?.["serverOverride"]).toBe("https://relay.example");
    // And what the host-lock actually resolved it to, which is what was measured.
    expect(runtime.facts?.["server"]).toBe("https://relay.invalid");
  });

  it("strips credentials out of a proxy URL before it reaches the report", () => {
    // This value goes into a file that is emailed to antivirus vendors.
    const redacted = redactProxyValue("http://alice:hunter2@proxy.corp:8080");
    expect(redacted).not.toContain("hunter2");
    expect(redacted).not.toContain("alice");
    expect(redacted).toContain("proxy.corp:8080");
    // Anything we cannot parse is redacted wholesale rather than guessed at.
    expect(redactProxyValue("not a url: user:pass@host")).toMatch(/redacted/);
  });
});
