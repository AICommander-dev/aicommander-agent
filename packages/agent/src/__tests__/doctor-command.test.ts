// The CLI wrapper: what `aicommander-agent doctor` writes, where, and with what
// exit code.
//
// The checks themselves are staged rather than run — they have their own suites —
// so what is pinned here is the surface a support engineer and a script depend
// on: redacted JSON on --json, a 0600 file on --report, exit 1 only when
// something actually FAILED.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const staged = vi.hoisted(() => ({
  checks: [] as Array<Record<string, unknown>>,
  summary: { ok: 0, warn: 0, fail: 0, skipped: 0 },
  options: null as unknown,
}));

vi.mock("../doctor/run.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../doctor/run.js")>();
  return {
    ...actual,
    runDoctor: async (opts: unknown) => {
      staged.options = opts;
      return {
        schema: 1,
        generatedAt: "2026-09-02T20:00:00.000Z",
        agentVersion: "1.1.0",
        platform: "win32",
        arch: "x64",
        node: "22.11.0",
        elevated: "unknown",
        redacted: false,
        checks: staged.checks,
        summary: staged.summary,
      };
    },
  };
});

import { cmdDoctor, writeReportFile } from "../ctl/commands/doctor.js";

let tmp: string;
let written: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-cmd-"));
  written = "";
  vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string) => {
    written += String(chunk);
    return true;
  }) as typeof process.stdout.write);
  staged.checks = [
    { id: "env.runtime", title: "Runtime", verdict: "ok", detail: "win32/x64 on Node 22.11.0" },
  ];
  staged.summary = { ok: 1, warn: 0, fail: 0, skipped: 0 };
  process.exitCode = undefined;
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
  process.exitCode = undefined;
});

describe("cmdDoctor", () => {
  it("prints the human view and exits 0 when nothing failed", async () => {
    await cmdDoctor({});
    expect(written).toContain("Runtime");
    expect(written).toContain("Nothing to report");
    expect(process.exitCode).toBeUndefined();
  });

  it("emits parseable, redacted JSON with --json", async () => {
    staged.checks = [
      {
        id: "net.ticket",
        title: "Connection ticket exchange",
        verdict: "ok",
        detail: "the relay accepted AIC-WXYZ-1234-ABCD",
      },
    ];
    await cmdDoctor({ json: true });
    const parsed = JSON.parse(written) as { redacted: boolean; checks: Array<{ detail: string }> };
    expect(parsed.redacted).toBe(true);
    expect(parsed.checks[0]!.detail).not.toContain("AIC-WXYZ-1234-ABCD");
  });

  it("writes the report file owner-only, and says so on stdout only in text mode", async () => {
    const target = path.join(tmp, "nested", "report.txt");
    await cmdDoctor({ report: target });
    const contents = fs.readFileSync(target, "utf8");
    expect(contents).toContain("AI Commander — diagnostic report");
    expect(contents).toContain("NO access code");
    if (process.platform !== "win32") {
      expect(fs.statSync(target).mode & 0o777).toBe(0o600);
    }
  });

  it("re-asserts 0600 over a file that already existed with a looser mode", async () => {
    if (process.platform === "win32") return;
    const target = path.join(tmp, "report.txt");
    fs.writeFileSync(target, "stale", { mode: 0o644 });
    await cmdDoctor({ report: target });
    // `mode` on writeFileSync applies only on CREATION, so re-running over
    // yesterday's world-readable report used to leave it world-readable.
    expect(fs.statSync(target).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(target, "utf8")).toContain("diagnostic report");
  });

  it("refuses to write THROUGH a symlink at the target", async () => {
    if (process.platform === "win32") return;
    // `sudo doctor --report /tmp/…` following a symlink is a way to truncate a
    // file the caller could not otherwise touch. The default `w` flag does
    // exactly that.
    const victim = path.join(tmp, "victim.txt");
    fs.writeFileSync(victim, "important");
    const target = path.join(tmp, "report.txt");
    fs.symlinkSync(victim, target);
    await cmdDoctor({ report: target });
    expect(fs.readFileSync(victim, "utf8")).toBe("important");
    expect(process.exitCode).toBe(1);
  });

  // ── The platform whose `open` cannot refuse a link ────────────────────────
  //
  // The comment that used to sit on `writeReportFile` rested on "Windows has no
  // /tmp-style shared, world-writable directory, so 0 is the honest default".
  // That is a mitigation and a weak one — a FILE symlink needs
  // SeCreateSymbolicLinkPrivilege, but junctions and hard links need no
  // privilege at all — and `--report` takes a CALLER-SUPPLIED path. So where
  // the open cannot be made to refuse, the write is made non-destructive
  // instead: no O_TRUNC, an lstat refusal, and truncation of the DESCRIPTOR
  // only after it. `openRefusesLinks: false` exercises that path here.
  describe("where open cannot refuse a link (the Windows shape)", () => {
    it("refuses a link at the target instead of truncating what it points at", async () => {
      if (process.platform === "win32") return;
      const victim = path.join(tmp, "victim.txt");
      fs.writeFileSync(victim, "important");
      const target = path.join(tmp, "report.txt");
      fs.symlinkSync(victim, target);
      expect(() => writeReportFile(target, "bundle", false)).toThrow(/is a link/);
      // The point of dropping O_TRUNC: the open itself destroyed nothing.
      expect(fs.readFileSync(victim, "utf8")).toBe("important");
    });

    it("still writes the WHOLE bundle to a real file, and re-asserts 0600", () => {
      const target = path.join(tmp, "report.txt");
      // Longer stale content, so a missing truncate would leave a tail behind.
      fs.writeFileSync(target, "x".repeat(500), { mode: 0o644 });
      writeReportFile(target, "the whole bundle", false);
      expect(fs.readFileSync(target, "utf8")).toBe("the whole bundle");
      if (process.platform !== "win32") {
        expect(fs.statSync(target).mode & 0o777).toBe(0o600);
      }
    });
  });

  it("exits 1 when a check failed, and not for warnings or skips", async () => {
    staged.summary = { ok: 0, warn: 2, fail: 0, skipped: 3 };
    await cmdDoctor({});
    expect(process.exitCode).toBeUndefined();

    staged.summary = { ok: 0, warn: 0, fail: 1, skipped: 0 };
    staged.checks = [
      { id: "av.probe", title: "Antivirus interference probe", verdict: "fail", detail: "wrapper.cmd is gone" },
    ];
    await cmdDoctor({});
    expect(process.exitCode).toBe(1);
  });

  it("passes --offline through to the checks", async () => {
    await cmdDoctor({ offline: true });
    expect(staged.options).toMatchObject({ offline: true });
  });
});
