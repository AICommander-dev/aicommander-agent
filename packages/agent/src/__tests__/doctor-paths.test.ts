// Where the doctor looks, and the one property that makes it a diagnostic
// rather than a participant: resolving a path must not bring one into existence.
//
// `envConfigDir()` (config-dir.ts) validates AICOMMANDER_CONFIG_DIR by CREATING
// the directory and asserting write access, and throws when it cannot. Every
// check under doctor/checks/ therefore resolves through paths.ts instead, and
// this suite pins both halves of that: the same answer as job-manager.ts's
// resolveJobsRoot where the two can agree, and no side effects where they cannot.

import { describe, it, expect, afterEach, beforeEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { resolveDiagLogDir } from "../diag-log.js";
import { resolveJobsRoot } from "../job-manager.js";
import { doctorConfigDirOverride, doctorDiagLogDir, doctorJobsRoot } from "../doctor/checks/paths.js";

const savedEnv = { ...process.env };
let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-paths-"));
  delete process.env["AICOMMANDER_CONFIG_DIR"];
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
  process.env = { ...savedEnv };
});

describe("doctor path resolution", () => {
  it("agrees with the agent's own jobs root when there is no override", () => {
    expect(doctorJobsRoot()).toBe(resolveJobsRoot());
    expect(doctorJobsRoot(tmp)).toBe(resolveJobsRoot(tmp));
  });

  it("honours an absolute override WITHOUT creating it", () => {
    const target = path.join(tmp, "durable");
    process.env["AICOMMANDER_CONFIG_DIR"] = target;
    expect(doctorConfigDirOverride()).toBe(target);
    expect(doctorJobsRoot()).toBe(path.join(target, "jobs"));
    // envConfigDir() would have mkdir'd it by now.
    expect(fs.existsSync(target)).toBe(false);
  });

  it("answers 'no jobs root' for an override the agent refuses to start with", () => {
    // Relative: envConfigDir() THROWS on this, which would turn a reportable
    // finding into a check group that failed to run. The doctor reports it
    // through the config.override check instead and skips what needed the path.
    process.env["AICOMMANDER_CONFIG_DIR"] = "relative/path";
    expect(doctorConfigDirOverride()).toBeNull();
    expect(doctorJobsRoot()).toBeNull();
  });

  it("treats an empty override the way the agent does — as unset", () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = "   ";
    expect(doctorJobsRoot()).toBe(resolveJobsRoot());
  });

  it("lets an explicit configDir win over the override, as the stores do", () => {
    process.env["AICOMMANDER_CONFIG_DIR"] = path.join(tmp, "durable");
    expect(doctorJobsRoot(tmp)).toBe(path.join(tmp, "jobs"));
  });

  it("agrees with the agent's own diagnostic log directory", () => {
    // Compared only where `resolveDiagLogDir` can be called without mutating
    // anything: unset, and an explicit configDir. Under an ABSOLUTE override the
    // agent's resolver would mkdir it, which is the whole reason paths.ts exists.
    expect(doctorDiagLogDir()).toBe(resolveDiagLogDir());
    expect(doctorDiagLogDir(tmp)).toBe(resolveDiagLogDir(tmp));
  });

  it("names the log directory of an absolute override WITHOUT creating it", () => {
    const target = path.join(tmp, "durable");
    process.env["AICOMMANDER_CONFIG_DIR"] = target;
    expect(doctorDiagLogDir()).toBe(path.join(target, "logs"));
    expect(fs.existsSync(target)).toBe(false);
  });

  it("falls back where diag-log.ts falls back for an override the agent refuses", () => {
    // Unlike the jobs root, the log directory has an answer here: the agent's
    // own resolver catches the ConfigDirError and lands on the platform default,
    // so that is where such a machine's logs really are.
    process.env["AICOMMANDER_CONFIG_DIR"] = "relative/path";
    expect(doctorDiagLogDir()).toBe(resolveDiagLogDir());
  });
});
