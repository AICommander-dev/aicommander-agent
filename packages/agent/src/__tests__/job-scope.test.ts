// The systemd scope every Linux job is launched into, and the reasons a machine
// does not get one. Pure decisions and pure argv — the pieces that must be right
// on a platform this suite mostly does not run on, and that a macOS or Windows
// box can still hold to account.

import { describe, it, expect } from "vitest";
import {
  buildJobScopeArgv,
  isJobScopeUnitName,
  jobScopeDecision,
  jobScopeDescription,
  jobScopeUnitName,
  resolveSystemdRun,
  JOB_SCOPE_UNIT_GLOB,
  SYSTEMD_RUN_PATHS,
  type JobScopeEnv,
} from "../job-scope.js";

/** A syntactically valid job id — 16 hex characters, as JOB_ID_PATTERN requires. */
const JOB_ID = "0123456789abcdef";

const linuxRoot = (over: Partial<JobScopeEnv> = {}): JobScopeEnv => ({
  platform: "linux",
  uid: 0,
  systemdRun: "/usr/bin/systemd-run",
  hasSystemd: true,
  ...over,
});

describe("jobScopeDecision", () => {
  it("supports the shape it was built for: Linux, root, systemd, systemd-run", () => {
    expect(jobScopeDecision(linuxRoot())).toEqual({
      supported: true,
      systemdRun: "/usr/bin/systemd-run",
    });
  });

  it("declines on every platform that has no systemd cgroups", () => {
    // Not a defect on either: a macOS job is an orphan of a launchd process and a
    // Windows job is a detached console-less child, and neither dies with the
    // agent. Linux was the only platform that needed fixing.
    for (const platform of ["darwin", "win32", "freebsd"] as const) {
      const decision = jobScopeDecision(linuxRoot({ platform }));
      expect(decision.supported).toBe(false);
      expect(decision.supported === false && decision.reason).toContain(platform);
    }
  });

  it("declines for a non-root agent rather than reaching for a --user scope", () => {
    // THE decision most likely to be "fixed" by someone who has not read why: a
    // --user scope lives under the login session's cgroup and is torn down when
    // the session ends, which is strictly worse than today's plain orphan.
    const decision = jobScopeDecision(linuxRoot({ uid: 1000 }));
    expect(decision.supported).toBe(false);
    expect(decision.supported === false && decision.reason).toMatch(/not root/);
    expect(decision.supported === false && decision.reason).toMatch(/session/);
  });

  it("declines when uid is unknown", () => {
    // process.getuid is undefined on Windows; "we do not know we are root" must
    // never read as "we are root".
    expect(jobScopeDecision(linuxRoot({ uid: undefined })).supported).toBe(false);
  });

  it("declines when systemd is not the init, even with the binary installed", () => {
    // Containers and non-systemd distributions ship systemd-run all the time.
    // /run/systemd/system is the same signal self-update.ts's preflight uses.
    const decision = jobScopeDecision(linuxRoot({ hasSystemd: false }));
    expect(decision.supported).toBe(false);
    expect(decision.supported === false && decision.reason).toContain("/run/systemd/system");
  });

  it("declines when there is no systemd-run, naming both paths it looked at", () => {
    const decision = jobScopeDecision(linuxRoot({ systemdRun: null }));
    expect(decision.supported).toBe(false);
    for (const candidate of SYSTEMD_RUN_PATHS) {
      expect(decision.supported === false && decision.reason).toContain(candidate);
    }
  });

  it("declines on every combination that is short of the full shape", () => {
    // The matrix, exhaustively: only the one row above may be supported.
    for (const platform of ["linux", "darwin", "win32"] as const) {
      for (const uid of [0, 1000]) {
        for (const hasSystemd of [true, false]) {
          for (const systemdRun of ["/usr/bin/systemd-run", null]) {
            const decision = jobScopeDecision({ platform, uid, systemdRun, hasSystemd });
            const shouldSupport =
              platform === "linux" && uid === 0 && hasSystemd && systemdRun !== null;
            expect(decision.supported).toBe(shouldSupport);
            // Every refusal says WHY — this is the line an operator reads in the
            // journal when a job did not get a scope.
            if (!decision.supported) expect(decision.reason.length).toBeGreaterThan(0);
          }
        }
      }
    }
  });
});

describe("resolveSystemdRun", () => {
  it("probes the absolute paths in order, and never asks PATH", () => {
    const seen: string[] = [];
    expect(
      resolveSystemdRun((p) => {
        seen.push(p);
        return p === "/bin/systemd-run";
      }),
    ).toBe("/bin/systemd-run");
    expect(seen).toEqual([...SYSTEMD_RUN_PATHS]);
    // A bare program name resolved through PATH is a hijack surface a root
    // service must not offer; nothing here may be relative.
    for (const candidate of SYSTEMD_RUN_PATHS) expect(candidate.startsWith("/")).toBe(true);
  });

  it("prefers /usr/bin when both exist", () => {
    expect(resolveSystemdRun(() => true)).toBe("/usr/bin/systemd-run");
  });

  it("returns null when neither exists, and survives an unreadable path prefix", () => {
    expect(resolveSystemdRun(() => false)).toBeNull();
    expect(
      resolveSystemdRun(() => {
        throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      }),
    ).toBeNull();
  });
});

describe("jobScopeUnitName", () => {
  it("derives the unit name from the job id", () => {
    expect(jobScopeUnitName(JOB_ID)).toBe(`aic-job-${JOB_ID}.scope`);
  });

  it("refuses anything that is not a job id", () => {
    // A unit name is the one place a job id would leave our own path handling
    // and become part of a command line, so it is re-validated rather than
    // trusted — a sanitised fallback would let two jobs share one unit.
    for (const bad of [
      "",
      "not-hex-at-all!!",
      "0123456789ABCDEF", // JOB_ID_PATTERN is lowercase hex
      "0123456789abcde", // 15
      "0123456789abcdef0", // 17
      "0123456789abcdef.scope",
      "../../etc/passwd",
      "0123456789abcde@",
    ]) {
      expect(() => jobScopeUnitName(bad)).toThrow(/refusing/);
    }
  });

  it("round-trips through the name check the uninstall path stops units by", () => {
    expect(isJobScopeUnitName(jobScopeUnitName(JOB_ID))).toBe(true);
    for (const bad of [
      "aicommander-agent.service",
      "aic-job-.scope",
      "aic-job-nothex0123456789.scope",
      "aic-job-0123456789abcdef.service",
      "session-3.scope",
      // A mis-parsed listing line must not become a `systemctl stop` target.
      "aic-job-0123456789abcdef.scope loaded active running",
      JOB_SCOPE_UNIT_GLOB,
    ]) {
      expect(isJobScopeUnitName(bad)).toBe(false);
    }
  });

  it("keeps the enumeration glob and the built name in agreement", () => {
    // uninstall.ts finds scopes with the glob and stops what it found; if the
    // two ever disagree, live jobs keep running while their logs are deleted.
    const [prefix, suffix] = JOB_SCOPE_UNIT_GLOB.split("*");
    expect(jobScopeUnitName(JOB_ID).startsWith(prefix!)).toBe(true);
    expect(jobScopeUnitName(JOB_ID).endsWith(suffix!)).toBe(true);
  });
});

describe("jobScopeDescription", () => {
  it("names the job id and nothing the caller supplied", () => {
    // The job's `name` is caller payload and would land in `systemctl status`
    // and the journal; the id is validated, unique and enough to find the record.
    expect(jobScopeDescription(JOB_ID)).toBe(`AI Commander job ${JOB_ID}`);
  });
});

describe("buildJobScopeArgv", () => {
  const wrap = (file: string, args: readonly string[]) =>
    buildJobScopeArgv({
      systemdRun: "/usr/bin/systemd-run",
      unit: jobScopeUnitName(JOB_ID),
      description: jobScopeDescription(JOB_ID),
      file,
      args,
    });

  it("is exactly the flags, then --, then the command", () => {
    expect(wrap("/bin/sh", ["-c", "echo hi"])).toEqual({
      file: "/usr/bin/systemd-run",
      args: [
        "--scope",
        "--quiet",
        "--collect",
        `--unit=aic-job-${JOB_ID}.scope`,
        `--description=AI Commander job ${JOB_ID}`,
        "--",
        "/bin/sh",
        "-c",
        "echo hi",
      ],
    });
  });

  it("keeps --quiet, without which the job's log opens with systemd's own line", () => {
    // "Running scope as unit …" goes to stderr, and stderr IS output.log.
    expect(wrap("/bin/sh", []).args).toContain("--quiet");
  });

  it("keeps --collect, so a FAILED scope is reaped instead of lingering as a unit", () => {
    // Not a collision defence for a LIVE unit — --collect reaps inactive and
    // failed units only; see job-scope.ts for the measured error that case gives.
    expect(wrap("/bin/sh", []).args).toContain("--collect");
  });

  it("puts -- before the command, so nothing after it can be read as an option", () => {
    const { args } = wrap("/bin/sh", ["-c", "--version"]);
    const separator = args.indexOf("--");
    expect(separator).toBeGreaterThan(0);
    // Everything of OURS is before it; everything of the command's is after.
    expect(args.slice(0, separator).every((a) => a.startsWith("--"))).toBe(true);
    expect(args.slice(separator + 1)).toEqual(["/bin/sh", "-c", "--version"]);
  });

  it("passes the wrapped command's argv through byte for byte", () => {
    // No quoting round happens here and none is needed: these are argv elements
    // handed to execvp, so the job's command text reaches exactly ONE shell —
    // the wrapper's own /bin/sh -c. Anything else would double-escape it.
    const nasty =
      "echo 'single' \"double\" $HOME `id` $(id) \\backslash\n" +
      "printf '%s\\n' \"a b\"; exit 3 # trailing comment";
    const { args } = wrap("/bin/sh", ["-c", nasty]);
    expect(args[args.length - 1]).toBe(nasty);
    expect(args.filter((a) => a === nasty)).toHaveLength(1);
  });

  it("carries the systemd-run path it was given, rather than a bare name", () => {
    expect(wrap("/bin/sh", []).file).toBe("/usr/bin/systemd-run");
  });
});
