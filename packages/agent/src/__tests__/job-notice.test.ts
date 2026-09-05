import { describe, expect, it, vi, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { boundedJobOperator, formatJobStartedAt, jobNoticeAdminsProvider, JOB_NOTICE_ACCOUNTS_TTL_MS, JOB_NOTICE_ID_ENV, JOB_NOTICE_OPERATOR_ENV,
  JOB_NOTICE_STARTED_ENV, resolveJobOperator, safeJobNoticeText, setJobNoticeEnv, UNKNOWN_OPERATOR } from "../job-notice.js";
import { WINDOWS_JOB_WRAPPER, writeWindowsJobScripts, JOB_CWD_ENV, JOB_EXIT_PATH_ENV, JOB_LOG_PATH_ENV } from "../job-scripts.js";
import type { AdminsResult } from "../device-admin.js";
import { JobManager } from "../job-manager.js";

afterEach(() => vi.useRealTimers());

describe("job terminal notice", () => {
  it.skipIf(process.platform === "win32")("does not resolve an operator for POSIX jobs", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-notice-posix-"));
    try {
      const manager = new JobManager({ jobsRoot: dir, scopeLauncher: () => null });
      const resolveOperator = vi.fn(async () => "unused");
      const result = await manager.start({ command: "printf payload", resolveOperator });
      expect(result).toMatchObject({ ok: true, kind: "job" });
      expect(resolveOperator).not.toHaveBeenCalled();
      if (result.ok && result.kind === "job") {
        await vi.waitFor(() => expect(fs.existsSync(path.join(dir, result.job.jobId, "exit"))).toBe(true));
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it("uses only the matching server-masked account, never its machine alias", async () => {
    const list = vi.fn(async (): Promise<AdminsResult> => ({ codeFresh: false, admins: [
      { userId: "owner", maskedEmail: "o***@example.com", alias: "private-machine", linkedAt: "", lastSeenAt: null, blocked: false },
    ] }));
    expect(await resolveJobOperator({ id: "owner", anonymous: false }, "", list)).toBe("o***@example.com");
    expect(await resolveJobOperator({ id: "missing", anonymous: false }, "", list)).toBe(UNKNOWN_OPERATOR);
    expect(await resolveJobOperator({ id: "owner", anonymous: false }, "", list)).toBe("o***@example.com");
    expect(list).toHaveBeenCalledOnce();
  });

  it("does not look up anonymous or missing operators", async () => {
    const list = vi.fn();
    expect(await resolveJobOperator({ id: "anon", anonymous: true }, "", list)).toBe("Anonymous user");
    expect(await resolveJobOperator(undefined, "", list)).toBe(UNKNOWN_OPERATOR);
    expect(list).not.toHaveBeenCalled();
  });

  it("coalesces concurrent users and caches missing users until the shared TTL expires", async () => {
    vi.useFakeTimers();
    let release!: (result: AdminsResult) => void;
    const list = vi.fn(() => new Promise<AdminsResult>((done) => { release = done; }));
    const lookup = (id: string) => resolveJobOperator({ id, anonymous: false }, "", list);
    const pending = Array.from({ length: 20 }, (_, i) => lookup(`user-${i}`));
    await Promise.resolve();
    expect(list).toHaveBeenCalledOnce();
    release({ codeFresh: false, admins: [] });
    expect(await Promise.all(pending)).toEqual(Array(20).fill(UNKNOWN_OPERATOR));
    await lookup("another-user");
    await vi.advanceTimersByTimeAsync(JOB_NOTICE_ACCOUNTS_TTL_MS - 1);
    await lookup("another-job");
    expect(list).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    const refreshed = lookup("another-user");
    await Promise.resolve();
    expect(list).toHaveBeenCalledTimes(2);
    release({ codeFresh: false, admins: [] });
    await refreshed;
  });

  it("keeps provider identity across reconnects and isolates server/device rotation", () => {
    const device = { deviceId: "device-a", deviceSecret: "secret-a" };
    const first = jobNoticeAdminsProvider("https://relay-a", device);
    expect(jobNoticeAdminsProvider("https://relay-a", { ...device })).toBe(first);
    expect(jobNoticeAdminsProvider("https://relay-b", device)).not.toBe(first);
    expect(jobNoticeAdminsProvider("https://relay-a", { ...device, deviceId: "device-b" })).not.toBe(first);
    expect(jobNoticeAdminsProvider("https://relay-a", { ...device, deviceSecret: "rotated" })).not.toBe(first);
  });

  it("backs off failures and isolates account providers", async () => {
    vi.useFakeTimers();
    const failed = vi.fn(async (): Promise<AdminsResult> => { throw new Error("HTTP 429"); });
    const other = vi.fn(async (): Promise<AdminsResult> => ({ codeFresh: false, admins: [] }));
    const operator = { id: "owner", anonymous: false };
    for (let i = 0; i < 20; i++) expect(await resolveJobOperator(operator, "", failed)).toBe(UNKNOWN_OPERATOR);
    await resolveJobOperator(operator, "", other);
    expect(failed).toHaveBeenCalledOnce();
    expect(other).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(JOB_NOTICE_ACCOUNTS_TTL_MS);
    await resolveJobOperator(operator, "", failed);
    expect(failed).toHaveBeenCalledTimes(2);
  });

  it("fails open on thrown errors, rejection and timeout", async () => {
    expect(await boundedJobOperator(() => { throw new Error("network"); })).toBe(UNKNOWN_OPERATOR);
    expect(await boundedJobOperator(() => Promise.reject(new Error("network")))).toBe(UNKNOWN_OPERATOR);
    vi.useFakeTimers();
    const result = boundedJobOperator(() => new Promise(() => undefined));
    await vi.advanceTimersByTimeAsync(750);
    expect(await result).toBe(UNKNOWN_OPERATOR);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("replaces all case variants of caller/inherited notice variables and removes CMD syntax", () => {
    const env = { aicommander_job_notice_id: "fake", AiCommander_Job_Notice_Operator: "fake",
      aicommander_job_notice_started: "fake", KEEP: "ok" };
    setJobNoticeEnv(env, 'job&echo HACK>%TEMP%!', 'x"|&<>^%!\r\n\u001b@example.com', 0);
    expect(Object.keys(env).sort()).toEqual([JOB_NOTICE_ID_ENV, JOB_NOTICE_OPERATOR_ENV, JOB_NOTICE_STARTED_ENV, "KEEP"].sort());
    expect(Object.values(env).join(" ")).not.toMatch(/[&<>^%!"|\r\n\u001b]/);
    expect(safeJobNoticeText("a".repeat(1000))).toHaveLength(160);
    expect(safeJobNoticeText("o***@example.com")).toBe("o***@example.com");
  });

  it("prints local start time with an explicit UTC offset", () => {
    const date = new Date(2026, 8, 5, 14, 30, 0);
    const formatted = formatJobStartedAt(date.getTime());
    expect(formatted).toMatch(/^2026-09-05 14:30:00 UTC[+-]\d{2}:\d{2}$/);
    expect(Date.parse(formatted.replace(" UTC", ""))).toBe(date.getTime());
    expect(formatJobStartedAt(NaN)).toBe("Time unavailable");
  });

  it("keeps the banner on CON before the unchanged nested command and immediate exit marker", () => {
    const lines = WINDOWS_JOB_WRAPPER.trimEnd().split("\r\n");
    expect(lines[1]).toBe("title AI Commander - running job");
    expect(lines.slice(2, -2)).toEqual([
      "echo AI Commander is running a remotely started job. > CON",
      `echo Job: %${JOB_NOTICE_ID_ENV}% > CON`,
      `echo Started by: %${JOB_NOTICE_OPERATOR_ENV}% > CON`,
      `echo Started at: %${JOB_NOTICE_STARTED_ENV}% > CON`,
      "echo Closing this window may stop the job. > CON",
      "echo View job output and status in AI Commander. > CON",
    ]);
    expect(lines.slice(-2)).toEqual([
      `cmd /d /s /c .\\command.cmd >> "%${JOB_LOG_PATH_ENV}%" 2>&1`,
      `echo %ERRORLEVEL% > "%${JOB_EXIT_PATH_ENV}%"`,
    ]);
  });

  it.skipIf(process.platform !== "win32")("executes with dangerous display values without changing job output or exit", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-notice-"));
    try {
      await writeWindowsJobScripts(dir, "echo payload&exit /b 7");
      const env = { ...process.env, [JOB_CWD_ENV]: dir, [JOB_LOG_PATH_ENV]: path.join(dir, "output.log"),
        [JOB_EXIT_PATH_ENV]: path.join(dir, "exit") };
      setJobNoticeEnv(env, 'id&echo hacked>injected', '%PATH%!PATH!&echo hacked>injected', 0);
      const result = spawnSync("cmd.exe", ["/d", "/v:on", "/s", "/c", ".\\wrapper.cmd"], { cwd: dir, env });
      expect(result.error).toBeUndefined();
      expect(fs.readFileSync(path.join(dir, "output.log"), "utf8").trim()).toBe("payload");
      expect(fs.readFileSync(path.join(dir, "exit"), "utf8").trim()).toBe("7");
      expect(fs.existsSync(path.join(dir, "injected"))).toBe(false);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it.skipIf(process.platform !== "win32")("shows the banner and title in the production detached job console", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-notice-console-"));
    try {
      const reportPath = path.join(dir, "console.json");
      const fixture = fs.readFileSync(fileURLToPath(new URL("./fixtures/job-console-report.ps1", import.meta.url)), "utf8");
      const encoded = Buffer.from(fixture, "utf16le").toString("base64");
      const manager = new JobManager({ jobsRoot: path.join(dir, "jobs") });
      const result = await manager.start({
        command: `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encoded}`,
        env: { AIC_TEST_CONSOLE_REPORT: reportPath },
        resolveOperator: async () => "o***@example.com",
      });
      expect(result).toMatchObject({ ok: true, kind: "job" });
      if (!result.ok || result.kind !== "job") throw new Error("Job did not start");
      const jobDir = path.join(dir, "jobs", result.job.jobId);
      await vi.waitFor(() => expect(fs.existsSync(path.join(jobDir, "exit"))).toBe(true), { timeout: 20_000 });
      expect(fs.readFileSync(path.join(jobDir, "exit"), "utf8").trim()).toBe("7");
      expect(fs.readFileSync(path.join(jobDir, "output.log"), "utf8").trim()).toBe("payload");
      const report = JSON.parse(fs.readFileSync(reportPath, "utf8").replace(/^\uFEFF/, "")) as { title: string; screen: string };
      // An elevated PowerShell host may prepend "Administrator: " to the inherited title.
      expect(report.title).toContain("AI Commander - running job");
      expect(report.screen).toContain("AI Commander is running a remotely started job.");
      expect(report.screen).toContain(`Job: ${result.job.jobId}`);
      expect(report.screen).toContain("Started by: o***@example.com");
      expect(report.screen).toContain(`Started at: ${formatJobStartedAt(result.job.startedAt)}`);
      expect(report.screen).toContain("Closing this window may stop the job.");
      expect(report.screen).toContain("View job output and status in AI Commander.");
    } finally {
      // The exit marker precedes cmd releasing its working-directory handle on Windows.
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 50 });
    }
  }, 30_000);
});
