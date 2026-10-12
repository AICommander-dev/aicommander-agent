// The report — the part of `doctor` that leaves the machine — and the runner's
// promise that one broken check cannot silence the others.
//
// The redaction assertions here are the ones that matter most in this whole
// feature: the bundle is written to be EMAILED TO ANTIVIRUS VENDORS, so a
// credential that survives into it is not a cosmetic bug.

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// The runner suite below calls the REAL runDoctor, which is the point of it —
// but a unit test may not reach the host it happens to run on. Left alone this
// spawns `/bin/launchctl` twice and `codesign` on any developer's or CI Mac, and
// opens a socket to the real root privileged helper. A test for error isolation
// that depends on the machine's launchd state, or that performs IPC with a root
// daemon, is testing the machine.
//
// So the two doors out of the process are shut: every shelled-out query answers
// nothing, and this platform is staged as having no helper endpoints at all. The
// network is closed separately, by `offline: true` on every call.
vi.mock("../installed-version.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../installed-version.js")>();
  return { ...actual, runCapture: async (): Promise<string> => "" };
});

vi.mock("@aicommander/priv-helper", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@aicommander/priv-helper")>();
  return {
    ...actual,
    helperInstallDir: () => null,
    helperVersionMarkerPath: () => null,
    elevatedEndpoints: () => [],
  };
});

import { doctorReportBundle, doctorReportJson, redactDoctorReport } from "../doctor/report.js";
import { renderDoctorReport } from "../doctor/render.js";
import { DOCTOR_GROUPS, runDoctor } from "../doctor/run.js";
import { fail, ok, warn, type DoctorReport } from "../doctor/types.js";

const SESSION_CODE = "AIC-WXYZ-1234-ABCD";
const AGENT_TOKEN = "Zm9vYmFyYmF6cXV4".repeat(3); // a 48-char opaque blob
const CAPABILITY = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhaWMifQ.c2lnbmF0dXJlLWJ5dGVz";

function reportWithSecrets(): DoctorReport {
  const home = os.homedir();
  const checks = [
    ok("net.ticket", "Connection ticket exchange", `the relay accepted ${SESSION_CODE}`, {
      token: AGENT_TOKEN,
      capability: CAPABILITY,
      status: 200,
    }),
    warn(
      "config.store",
      "Identity and session store",
      `the store is at ${home}/.config/aicommander-agent`,
      `Look in ${home}/.config for it.`,
      { writeDir: `${home}/.config/aicommander-agent`, other: "C:\\Users\\Alice\\AppData\\Local\\x" },
    ),
  ];
  return {
    schema: 1,
    generatedAt: "2026-09-02T20:00:00.000Z",
    agentVersion: "1.1.0",
    platform: "win32",
    arch: "x64",
    node: "22.11.0",
    elevated: "unknown",
    redacted: false,
    checks,
    summary: { ok: 1, warn: 1, fail: 0, skipped: 0 },
  };
}

function assertNoSecrets(text: string): void {
  expect(text).not.toContain(SESSION_CODE);
  expect(text).not.toContain(AGENT_TOKEN);
  expect(text).not.toContain(CAPABILITY);
  expect(text).not.toContain(os.homedir());
  // Another account's home, which the home-directory rule alone cannot reach.
  expect(text).not.toContain("Alice");
}

describe("report redaction", () => {
  it("removes the session code, tokens, capabilities and account names from every string", () => {
    const redacted = redactDoctorReport(reportWithSecrets());
    assertNoSecrets(JSON.stringify(redacted));
    expect(redacted.redacted).toBe(true);
  });

  it("redacts details, remedies AND facts, not only the headline", () => {
    const redacted = redactDoctorReport(reportWithSecrets());
    const store = redacted.checks.find((c) => c.id === "config.store")!;
    expect(store.remedy).not.toContain(os.homedir());
    expect(String(store.facts?.["writeDir"])).not.toContain(os.homedir());
    expect(String(store.facts?.["other"])).not.toContain("Alice");
  });

  it("keeps the evidence: paths in redacted form, status codes and errnos", () => {
    const redacted = redactDoctorReport(reportWithSecrets());
    const store = redacted.checks.find((c) => c.id === "config.store")!;
    // A redaction that dropped paths would take the diagnosis with it.
    expect(String(store.facts?.["writeDir"])).toContain(".config/aicommander-agent");
    expect(redacted.checks.find((c) => c.id === "net.ticket")!.facts?.["status"]).toBe(200);
  });

  it("is idempotent, so redacting twice does not mangle the placeholders", () => {
    const once = redactDoctorReport(reportWithSecrets());
    const twice = redactDoctorReport(once);
    expect(twice).toEqual(once);
  });

  it("redacts the --json output and the --report bundle alike", () => {
    assertNoSecrets(doctorReportJson(reportWithSecrets()));
    const bundle = doctorReportBundle(reportWithSecrets());
    assertNoSecrets(bundle);
    // The bundle says what it is, so nobody has to guess before attaching it.
    expect(bundle).toContain("NO access code");
    expect(bundle).toContain("aicommander.dev/antivirus");
    expect(bundle).toContain("machine-readable");
  });

  it("does NOT redact the human console rendering", () => {
    // Deliberate: a remedy that says "exclude ~ from your antivirus" is a
    // remedy the user cannot follow. The boundary is the file and --json.
    const rendered = renderDoctorReport(reportWithSecrets());
    expect(rendered).toContain(os.homedir());
  });
});

describe("renderer", () => {
  it("lists every verdict and repeats the failures at the end", () => {
    const report = reportWithSecrets();
    report.checks.push(fail("av.probe", "Antivirus interference probe", "wrapper.cmd is gone", "Exclude the jobs directory."));
    report.summary = { ok: 1, warn: 1, fail: 1, skipped: 0 };
    const text = renderDoctorReport(report);
    expect(text).toContain("Antivirus interference probe");
    expect(text).toContain("What is wrong:");
    expect(text).toContain("Exclude the jobs directory.");
    expect(text).toContain("1 OK · 1 WARN · 1 FAIL · 0 SKIP");
  });

  it("prints facts only when asked", () => {
    const report = reportWithSecrets();
    expect(renderDoctorReport(report)).not.toContain("status: 200");
    expect(renderDoctorReport(report, { verbose: true })).toContain("status: 200");
  });
});

describe("runner", () => {
  const originalLength = DOCTOR_GROUPS.length;
  // A temp config dir keeps the real checks (which DO run here — that is the
  // point of exercising the runner) off the developer's own jobs root and
  // credential store.
  let configDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-run-"));
  });

  afterEach(() => {
    DOCTOR_GROUPS.length = originalLength;
    fs.rmSync(configDir, { recursive: true, force: true });
  });

  it("turns a check that throws into one failed result and keeps going", async () => {
    DOCTOR_GROUPS.push({
      id: "broken",
      title: "Deliberately broken",
      run: async () => {
        throw new Error("boom");
      },
    });
    const report = await runDoctor({ offline: true, configDir });
    const broken = report.checks.find((c) => c.id === "broken")!;
    expect(broken.verdict).toBe("fail");
    expect(broken.detail).toContain("boom");
    // The groups after it — and before it — still reported.
    expect(report.checks.length).toBeGreaterThan(5);
    expect(report.checks.some((c) => c.id === "env.runtime")).toBe(true);
  });

  it("counts every verdict, and every check has a stable id and a title", async () => {
    const report = await runDoctor({ offline: true, configDir });
    const total =
      report.summary.ok + report.summary.warn + report.summary.fail + report.summary.skipped;
    expect(total).toBe(report.checks.length);
    for (const check of report.checks) {
      expect(check.id).toMatch(/^[a-z][a-z0-9_.]*$/);
      expect(check.title.length).toBeGreaterThan(0);
      expect(check.detail.length).toBeGreaterThan(0);
    }
  });

  it("gives every check its own id, so nothing is silently deduplicated", async () => {
    const report = await runDoctor({ offline: true, configDir });
    const ids = report.checks.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("does not reach the host: no shelled-out query and no helper socket", async () => {
    // The guard for the mocks above. A helper endpoint staged as absent must
    // read as `skipped`, not as a machine with a broken helper.
    const report = await runDoctor({ offline: true, configDir });
    const endpoint = report.checks.find((c) => c.id === "helper.endpoint")!;
    expect(endpoint.verdict).toBe("skipped");
  });

  it("puts an arbitrary serverUrl through the host-lock before any check sees it", async () => {
    // The ticket leg POSTs this machine's stored agent token to whatever this
    // resolves to. An in-process caller must not be able to choose that.
    const report = await runDoctor({ offline: true, configDir, serverUrl: "https://evil.example" });
    const runtime = report.checks.find((c) => c.id === "env.runtime")!;
    expect(runtime.facts?.["server"]).not.toContain("evil.example");
  });

  it("leaves nothing behind in the directory it was pointed at", async () => {
    // Every probe file, the antivirus probe's scratch directory, and the jobs
    // root it had to create to write into.
    await runDoctor({ offline: true, configDir });
    expect(fs.readdirSync(configDir)).toEqual([]);
  });
});
