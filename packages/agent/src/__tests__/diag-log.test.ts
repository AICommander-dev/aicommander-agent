/**
 * diag-log.ts — the diagnostic log both hosts write.
 *
 * The properties under test are the ones a support engineer and a vendor
 * submission depend on: it is BOUNDED (rotates at the cap, keeps a fixed number
 * of generations), it is REDACTED (no session code, no token, no ticket), it
 * never THROWS and never BLOCKS (a dead disk degrades to silence, and the
 * calling turn does no I/O at all).
 *
 * Platform-neutral by construction: everything goes through a temp dir and
 * path.join, and the only mode assertion is skipped on Windows, where POSIX
 * permission bits do not apply (the agent's Windows CI job is deliberately
 * narrow — see vitest.config.ts).
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  closeDiagLog,
  diag,
  diagJobId,
  diagLogPath,
  errorFields,
  flushDiagLog,
  initDiagLog,
  logStartup,
  redactDiagText,
  redactHomePaths,
  resolveDiagLogDir,
} from "../diag-log.js";

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "aic-diag-"));
}

function readLog(dir: string, suffix = ""): string {
  return fs.readFileSync(path.join(dir, `worker.log${suffix}`), "utf8");
}

afterEach(() => {
  closeDiagLog();
  vi.restoreAllMocks();
});

describe("diag-log writing", () => {
  it("writes one line per event with role, pid and fields", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    diag("conn.ticket_failed", { status: 403 });
    diag("conn.ws_close", { code: 1006 });
    await flushDiagLog();

    const lines = readLog(dir).trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain(` worker ${process.pid} conn.ticket_failed status=403`);
    expect(lines[1]).toContain("conn.ws_close code=1006");
    // Leading ISO timestamp, so two role files sort into one timeline.
    expect(lines[0]).toMatch(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z /);
  });

  it("is inert until a host initializes it", async () => {
    closeDiagLog();
    expect(diagLogPath()).toBeNull();
    expect(() => diag("startup")).not.toThrow();
    await expect(flushDiagLog()).resolves.toBeUndefined();
  });

  it("appends to an existing file across restarts", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    diag("startup");
    await flushDiagLog();
    closeDiagLog();

    initDiagLog({ dir, role: "worker" });
    diag("shutdown");
    await flushDiagLog();

    const lines = readLog(dir).trim().split("\n");
    expect(lines).toHaveLength(2);
  });

  it("keeps roles in separate files, so two processes never interleave", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "supervisor" });
    diag("supervisor.worker_spawned", { spawn: 1 });
    await flushDiagLog();
    initDiagLog({ dir, role: "worker" });
    diag("startup");
    await flushDiagLog();

    expect(fs.existsSync(path.join(dir, "supervisor.log"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "worker.log"))).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "creates the directory owner-only",
    () => {
      const dir = path.join(tmpDir(), "logs");
      initDiagLog({ dir, role: "worker" });
      expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    },
  );
});

describe("diag-log rotation", () => {
  it("rotates at the cap and keeps a bounded number of generations", async () => {
    const dir = tmpDir();
    // Small cap so a handful of lines crosses it.
    initDiagLog({ dir, role: "worker", maxFileBytes: 200 });

    for (let i = 0; i < 40; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }

    const entries = fs.readdirSync(dir).sort();
    // worker.log + .1 + .2 — never more, however long the agent runs.
    expect(entries).toEqual(["worker.log", "worker.log.1", "worker.log.2"]);
    for (const name of entries) {
      expect(fs.statSync(path.join(dir, name)).size).toBeLessThanOrEqual(400);
    }
    // The live file holds the NEWEST events; the oldest generation was dropped.
    expect(readLog(dir)).toContain("attempt=39");
    expect(readLog(dir, ".2")).not.toContain("attempt=39");
  });

  it("does not restart the counter when the rename was refused", async () => {
    // The Windows case the rotation exists for: a scanner holding the log open
    // makes the rename fail. Setting the counter to zero there — which is what
    // this used to do unconditionally — leaves every byte in the live file and
    // postpones the next attempt by another whole maxFileBytes, i.e. the
    // documented 512 KiB/1.5 MiB ceiling stops being a ceiling.
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker", maxFileBytes: 200 });
    const rename = vi.spyOn(fs.promises, "rename").mockRejectedValue(
      Object.assign(new Error("EPERM: operation not permitted"), { code: "EPERM" }),
    );
    // Truncation is the fallback that keeps the bound without a rename; deny it
    // too, so what is left under test is the counter alone.
    const truncate = vi.spyOn(fs.promises, "truncate").mockRejectedValue(
      Object.assign(new Error("EBUSY: resource busy"), { code: "EBUSY" }),
    );

    const BATCHES = 20;
    for (let i = 0; i < BATCHES; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }

    // One line is ~65 bytes, so the 200-byte cap is passed within the first
    // handful of batches and EVERY batch after that must try to rotate again —
    // the counter still describes the bytes that are really in the file. A
    // counter zeroed on a failed rename would instead wait out another 200 bytes
    // between attempts, i.e. roughly a third as many tries.
    const liveFileRenames = rename.mock.calls.filter(
      ([from]) => String(from) === path.join(dir, "worker.log"),
    );
    expect(liveFileRenames.length).toBeGreaterThanOrEqual(BATCHES - 5);
    truncate.mockRestore();
    rename.mockRestore();
  });

  it("keeps the history it already has when the rename is refused", async () => {
    // The generation that exists is the one a support engineer is being asked
    // for, and it used to be deleted BEFORE the rename that would have refilled
    // it — with the live file's rename, the likeliest of all of them to fail,
    // going next. Two failed rotations on a Windows box where a scanner holds
    // the log therefore left an empty worker.log and no history at all: nothing
    // to attach to the report, on the machine the report is about.
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker", maxFileBytes: 200 });

    // A first, healthy rotation: worker.log.1 now holds real history.
    for (let i = 0; i < 8; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }
    expect(fs.existsSync(path.join(dir, "worker.log.1"))).toBe(true);
    const history = readLog(dir, ".1");
    expect(history).not.toBe("");

    // Now the scanner takes hold: every rename is refused, and truncation is the
    // only way the bound can still be kept.
    const rename = vi.spyOn(fs.promises, "rename").mockRejectedValue(
      Object.assign(new Error("EPERM: operation not permitted"), { code: "EPERM" }),
    );
    for (let i = 8; i < 40; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }
    rename.mockRestore();

    // Every rotation attempt failed, and the generation survived all of them
    // byte for byte.
    expect(readLog(dir, ".1")).toBe(history);
  });

  it("truncates in place when the rename is refused, so the bound still holds", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker", maxFileBytes: 200 });
    vi.spyOn(fs.promises, "rename").mockRejectedValue(
      Object.assign(new Error("EPERM: operation not permitted"), { code: "EPERM" }),
    );

    for (let i = 0; i < 60; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }

    // Nothing could be RENAMED, so the generation that exists was copied aside
    // (see below) — and both files are still bounded, which is the claim the
    // module documents.
    expect(fs.readdirSync(dir).sort()).toEqual(["worker.log", "worker.log.1"]);
    expect(fs.statSync(path.join(dir, "worker.log")).size).toBeLessThanOrEqual(400);
    expect(fs.statSync(path.join(dir, "worker.log.1")).size).toBeLessThanOrEqual(400);
    expect(readLog(dir)).toContain("attempt=59");
  });

  it("copies the history aside before the first in-place truncation", async () => {
    // The whole point of the fallback, and what it used to get exactly backwards.
    // A scanner holding worker.log open refuses the rename; the truncation that
    // keeps the bound then ran with NOTHING else on disk, so the FIRST rotation
    // deleted every byte the agent had recorded — on the machine whose antivirus
    // event we are asking the user to send to a vendor. A copy needs only a read
    // handle, which is precisely what the scanner's own open leaves us.
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker", maxFileBytes: 200 });
    const rename = vi.spyOn(fs.promises, "rename").mockRejectedValue(
      Object.assign(new Error("EPERM: operation not permitted"), { code: "EPERM" }),
    );

    // Enough to cross the cap exactly once.
    for (let i = 0; i < 5; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }
    rename.mockRestore();

    // The earliest events — the ones that explain how the machine got here — are
    // still on disk, and the live file was still bounded to get there.
    expect(fs.existsSync(path.join(dir, "worker.log.1"))).toBe(true);
    expect(readLog(dir, ".1")).toContain("attempt=0");
    expect(fs.statSync(path.join(dir, "worker.log")).size).toBeLessThanOrEqual(400);
  });

  it("lets the live file overshoot rather than delete the only copy of the history", async () => {
    // Nothing can be saved: the rename, the copy and the truncation are all
    // refused. Truncating anyway would destroy the only evidence there is, so
    // the file is allowed past the cap — but only up to the hard ceiling, so a
    // wedged machine cannot fill its disk with diagnostics either.
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker", maxFileBytes: 200 });
    const rename = vi.spyOn(fs.promises, "rename").mockRejectedValue(
      Object.assign(new Error("EPERM: operation not permitted"), { code: "EPERM" }),
    );
    const copy = vi.spyOn(fs.promises, "copyFile").mockRejectedValue(
      Object.assign(new Error("EBUSY: resource busy"), { code: "EBUSY" }),
    );

    // Past the 200-byte cap, but nowhere near the ceiling.
    for (let i = 0; i < 6; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }
    expect(fs.statSync(path.join(dir, "worker.log")).size).toBeGreaterThan(200);
    // The evidence is all still there — this is what a truncation here would
    // have thrown away, with no copy of it anywhere.
    expect(readLog(dir)).toContain("attempt=0");
    expect(readLog(dir)).toContain("attempt=5");
    expect(fs.readdirSync(dir)).toEqual(["worker.log"]);

    // And the overshoot is bounded: kept up long enough, the hard ceiling
    // (4 × 200 B, plus the batch that trips it) wins over the history.
    for (let i = 6; i < 60; i++) {
      diag("conn.retry", { attempt: i, delayMs: 1000 });
      await flushDiagLog();
    }
    rename.mockRestore();
    copy.mockRestore();

    expect(fs.statSync(path.join(dir, "worker.log")).size).toBeLessThanOrEqual(1000);
    expect(readLog(dir)).toContain("attempt=59");
  });
});

describe("diag-log redaction", () => {
  it("masks a session code anywhere in a value", () => {
    expect(redactDiagText("code AIC-7K3P-WX9M-RTBN here")).toBe(
      "code AIC-7K3P-***-*** here",
    );
    // Codes are case-insensitive by design; a lowercase one must not slip past.
    expect(redactDiagText("aic-7k3p-wx9m-rtbn")).toBe("AIC-7K3P-***-***");
  });

  it("never lets a session code or a token reach the file", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    const code = "AIC-7K3P-WX9M-RTBN";
    const token = "b6f0a1c2d3e4f5a60718293a4b5c6d7e8f90a1b2c3d4e5f6";
    const ticket = "a".repeat(64);
    const jws = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJtYWNoaW5lIn0.c2lnbmF0dXJlYmxvYg";
    diag("conn.register_ok", { code, token, ticket, jws });
    await flushDiagLog();

    const text = readLog(dir);
    expect(text).not.toContain(code);
    expect(text).not.toContain(token);
    expect(text).not.toContain(ticket);
    expect(text).not.toContain(jws);
    expect(text).toContain("AIC-7K3P-***-***");
    expect(text).toContain("[redacted]");
    expect(text).toContain("[redacted-jws]");
  });

  it("keeps job ids readable — they are the approved way to name a job", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    diag("job.start", { jobId: "0a1b2c3d4e5f6071" }); // 16 hex, as job-manager mints
    await flushDiagLog();
    expect(readLog(dir)).toContain("jobId=0a1b2c3d4e5f6071");
  });

  it("truncates long values and neutralizes newlines, so output can't be smuggled", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    diag("job.refused", { reason: `${"x ".repeat(300)}\nsecond line` });
    await flushDiagLog();

    const lines = readLog(dir).trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(lines[0]!.length).toBeLessThan(400);
    expect(lines[0]).toContain("…");
  });

  it("errorFields reports errno facts and never the failing path", () => {
    const err = Object.assign(
      new Error("EACCES: permission denied, open '/Users/someone/secret/file'"),
      { code: "EACCES", syscall: "open", path: "/Users/someone/secret/file" },
    );
    expect(errorFields(err)).toEqual({ code: "EACCES", syscall: "open" });
    expect(errorFields(new TypeError("boom"))).toEqual({ error: "TypeError" });
    expect(errorFields("nope")).toEqual({ error: "unknown" });
  });

  it("takes the account name out of a path but keeps the path", async () => {
    // The install location is the diagnosis; the account name is the user's
    // identity, and these files are attached to third-party antivirus reports.
    expect(redactHomePaths("C:\\Users\\alicja\\AppData\\Local\\aicommander\\app.exe")).toBe(
      "C:\\Users\\<user>\\AppData\\Local\\aicommander\\app.exe",
    );
    expect(redactHomePaths("/home/alicja/.local/share/aicommander/logs")).toBe(
      "/home/<user>/.local/share/aicommander/logs",
    );
    expect(redactHomePaths("/Users/alicja/Library/Application Support/aicommander")).toBe(
      "/Users/<user>/Library/Application Support/aicommander",
    );
    // This process's OWN home, whatever shape the OS gave it.
    expect(redactHomePaths(path.join(os.homedir(), "aic", "jobs"))).toBe(
      path.join("~", "aic", "jobs"),
    );
    // Redacting twice is not redacting harder.
    expect(redactHomePaths(redactHomePaths("/home/alicja/x"))).toBe("/home/<user>/x");
    // Nothing that is not a home path is touched.
    expect(redactHomePaths("/var/lib/aicommander/logs")).toBe("/var/lib/aicommander/logs");
  });

  it("collapses OUR home to ~ and never another account whose name starts the same", async () => {
    // `/Users/lukasz` matched inside `/Users/lukaszek/x` and produced `~ek/x`:
    // the tail of a SECOND account's name in a file that goes to an antivirus
    // vendor, on a path relabelled as being inside our own home — the exact
    // opposite of what the redaction promises. The boundary is what a directory
    // ends at, so a longer name that merely starts the same is a different
    // directory and falls to the generic /Users|/home rule instead.
    const home = vi.spyOn(os, "homedir").mockReturnValue("/Users/lukasz");
    try {
      vi.resetModules();
      const fresh = await import("../diag-log.js");
      expect(fresh.redactHomePaths("/Users/lukasz/aic/jobs")).toBe("~/aic/jobs");
      expect(fresh.redactHomePaths("/Users/lukaszek/x")).toBe("/Users/<user>/x");
      const other = fresh.redactHomePaths("/Users/lukaszek/x");
      expect(other).not.toContain("~");
      expect(other).not.toContain("ek");
    } finally {
      home.mockRestore();
      vi.resetModules();
    }
  });

  it("keeps that promise for an account name that continues with a NON-ASCII letter", async () => {
    // The boundary was `[A-Za-z0-9._~-]`, so `ż` was not a character a directory
    // name could continue with and `/Users/lukaszż/customer` collapsed to
    // `~ż/customer`: a second account's name, part of it verbatim, on a path
    // relabelled as sitting inside our own home — in a file we tell users to send
    // to antivirus vendors. Windows and macOS both allow non-ASCII account names.
    const home = vi.spyOn(os, "homedir").mockReturnValue("/Users/lukasz");
    try {
      vi.resetModules();
      const fresh = await import("../diag-log.js");
      expect(fresh.redactHomePaths("/Users/lukasz/aic/jobs")).toBe("~/aic/jobs");
      const other = fresh.redactHomePaths("/Users/lukaszż/customer");
      expect(other).toBe("/Users/<user>/customer");
      expect(other).not.toContain("~");
      expect(other).not.toContain("ż");
      // Not a Polish accident: any script's letters, digits and marks continue a
      // directory name just as `A-Za-z0-9` does.
      expect(fresh.redactHomePaths("/Users/lukaszи/x")).toBe("/Users/<user>/x");
      expect(fresh.redactHomePaths("/Users/lukasz٩/x")).toBe("/Users/<user>/x");
      // …and the real home still ends at a separator or at end of value.
      expect(fresh.redactHomePaths("/Users/lukasz")).toBe("~");
    } finally {
      home.mockRestore();
      vi.resetModules();
    }
  });

  it("takes out the config-dir override however the OS spells it back to us", async () => {
    // The value the operator EXPORTS and the value we WRITE are not the same
    // string: every path built from the override goes through path.join, which
    // normalises. `/share/DATA//aic` becomes `/share/DATA/aic/logs`, matched
    // nothing, and went verbatim into the first line of the file (logStartup's
    // logDir) — on the machines whose mounts are named after the operator's
    // company or customer, which is who sets this variable at all.
    const previous = process.env["AICOMMANDER_CONFIG_DIR"];
    process.env["AICOMMANDER_CONFIG_DIR"] = "/share/CACHEDEV1_DATA/kancelaria-nowak//aic";
    try {
      vi.resetModules();
      const fresh = await import("../diag-log.js");
      const logDir = path.join("/share/CACHEDEV1_DATA/kancelaria-nowak//aic", "logs");
      expect(fresh.redactHomePaths(logDir)).toBe(path.join("<config-dir>", "logs"));
      expect(fresh.redactHomePaths(logDir)).not.toContain("kancelaria-nowak");
      // The raw spelling is still covered — both forms are matched, not one.
      expect(fresh.redactHomePaths("/share/CACHEDEV1_DATA/kancelaria-nowak//aic/x")).toBe(
        "<config-dir>/x",
      );
    } finally {
      if (previous === undefined) delete process.env["AICOMMANDER_CONFIG_DIR"];
      else process.env["AICOMMANDER_CONFIG_DIR"] = previous;
      vi.resetModules();
    }
  });

  it("takes out an operator's config-dir override, which no home shape covers", async () => {
    // AICOMMANDER_CONFIG_DIR is set on exactly the machines whose layout we
    // cannot predict — a QNAP data volume, a mount named after the company whose
    // machine this is — so neither os.homedir() nor the /home|/Users|C:\Users
    // shapes can reach it, and logStartup writes it verbatim into a file that
    // goes to an antivirus vendor. Read at module load, so the module is loaded
    // with the variable in place, exactly as a real process would be.
    const previous = process.env["AICOMMANDER_CONFIG_DIR"];
    process.env["AICOMMANDER_CONFIG_DIR"] = "/share/CACHEDEV1_DATA/kancelaria-nowak/aic";
    try {
      vi.resetModules();
      const fresh = await import("../diag-log.js");
      expect(fresh.redactHomePaths("/share/CACHEDEV1_DATA/kancelaria-nowak/aic/session.json")).toBe(
        "<config-dir>/session.json",
      );
      // …and the ordinary paths are still exactly as informative as before.
      expect(fresh.redactHomePaths("/var/lib/aicommander/logs")).toBe("/var/lib/aicommander/logs");
    } finally {
      if (previous === undefined) delete process.env["AICOMMANDER_CONFIG_DIR"];
      else process.env["AICOMMANDER_CONFIG_DIR"] = previous;
      vi.resetModules();
    }
  });

  it("never writes the OS account name, whichever field carries it", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    diag("path.error", {
      path_role: "jobsRoot",
      execPath: "C:\\Users\\alicja\\AppData\\Local\\aicommander\\app.exe",
      logDir: "/home/alicja/.local/share/aicommander/logs",
    });
    await flushDiagLog();

    const text = readLog(dir);
    expect(text).not.toContain("alicja");
    // …and the parts that answer "where is this installed" survive.
    expect(text).toContain("aicommander");
    expect(text).toContain("<user>");
  });

  it("logs a job id only when it IS one", () => {
    // The cancel frame comes off the relay unvalidated, and this file goes to a
    // vendor. Anything but a 16-hex id is recorded as the fact that it was not.
    expect(diagJobId("0123456789abcdef")).toBe("0123456789abcdef");
    expect(diagJobId("../../etc/passwd")).toBe("invalid");
    expect(diagJobId("rm -rf /home/alicja")).toBe("invalid");
    expect(diagJobId(undefined)).toBe("invalid");
    expect(diagJobId(42)).toBe("invalid");
  });

  it("logStartup records the facts a ticket needs", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    logStartup({ version: "1.1.0" });
    await flushDiagLog();

    const text = readLog(dir);
    expect(text).toContain(`platform=${process.platform}`);
    expect(text).toContain("version=1.1.0");
    expect(text).toContain("elevated=");
    // The very first line of the file used to carry `C:\Users\<name>` /
    // `/home/<name>` through execPath, on a file we ask people to send to
    // antivirus vendors.
    const account = path.basename(os.homedir());
    if (account && account !== "root" && account.length > 2) {
      expect(text).not.toContain(account);
    }
  });
});

describe("diag-log failure and blocking contract", () => {
  it("swallows a write failure and keeps accepting events", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    const append = vi
      .spyOn(fs.promises, "appendFile")
      .mockRejectedValue(Object.assign(new Error("no"), { code: "EACCES" }));

    diag("startup");
    await expect(flushDiagLog()).resolves.toBeUndefined();
    expect(append).toHaveBeenCalled();

    append.mockRestore();
    diag("shutdown");
    await flushDiagLog();
    // The failed batch is gone (never retried against a dead disk); the next one lands.
    expect(readLog(dir)).toContain("shutdown");
  });

  it("stays inert when the log directory cannot be created", async () => {
    vi.spyOn(fs, "mkdirSync").mockImplementation(() => {
      throw Object.assign(new Error("denied"), { code: "EPERM" });
    });
    expect(() => initDiagLog({ dir: path.join(tmpDir(), "x"), role: "worker" })).not.toThrow();
    expect(diagLogPath()).toBeNull();
    expect(() => diag("startup")).not.toThrow();
    await expect(flushDiagLog()).resolves.toBeUndefined();
  });

  it("does no I/O on the caller's turn", () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    const append = vi.spyOn(fs.promises, "appendFile");
    const appendSync = vi.spyOn(fs, "appendFileSync");
    const writeSync = vi.spyOn(fs, "writeFileSync");

    diag("startup");

    // Nothing has touched the disk yet — the write is on a timer.
    expect(append).not.toHaveBeenCalled();
    expect(appendSync).not.toHaveBeenCalled();
    expect(writeSync).not.toHaveBeenCalled();
    expect(fs.existsSync(path.join(dir, "worker.log"))).toBe(false);
  });

  it("bounds the in-memory queue when the disk never comes back", async () => {
    const dir = tmpDir();
    initDiagLog({ dir, role: "worker" });
    const append = vi
      .spyOn(fs.promises, "appendFile")
      .mockRejectedValue(Object.assign(new Error("no"), { code: "EIO" }));

    // Far more than MAX_QUEUE_LINES, with no flush in between.
    for (let i = 0; i < 5_000; i++) diag("conn.retry", { attempt: i });
    await flushDiagLog();

    append.mockRestore();
    diag("startup");
    await flushDiagLog();
    // Dropped lines are counted and confessed, not silently forgotten.
    expect(readLog(dir)).toContain("diag.dropped");
  });
});

describe("resolveDiagLogDir", () => {
  it("puts logs beside the rest of an explicit config dir", () => {
    expect(resolveDiagLogDir(path.join("/some", "dir"))).toBe(
      path.join("/some", "dir", "logs"),
    );
  });

  it("falls back to a per-user data dir without one", () => {
    const dir = resolveDiagLogDir();
    expect(path.isAbsolute(dir)).toBe(true);
    expect(path.basename(dir)).toBe("logs");
  });
});
