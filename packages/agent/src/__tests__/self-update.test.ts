// The upgrade procedure as code. Every case below is a mistake that was actually
// made against a live machine on 2026-08-10 — see self-update.ts for the story.

import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync, readdirSync, statSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";
import crypto from "node:crypto";
import {
  selfUpdatePreflight,
  signingKeyFingerprint,
  verifyInstallerSignature,
  updateOutcome,
  selfUpdateLaunchArgv,
  evaluateTarget,
  replaceExecutable,
  lockVerdict,
  serverUrlFromUnitEnvironment,
  RELEASE_SIGNING_KEY_SHA256,
  type PreflightEnv,
} from "../self-update.js";

const linuxRoot = (over: Partial<PreflightEnv> = {}): PreflightEnv => ({
  platform: "linux",
  uid: 0,
  execName: "aicommander-agent",
  hasSystemd: true,
  ...over,
});

describe("selfUpdatePreflight", () => {
  it("allows the shape it was built for: Linux, root, standalone binary, systemd", () => {
    expect(selfUpdatePreflight(linuxRoot())).toBeNull();
  });

  it("sends macOS and Windows to their own update paths", () => {
    // Both already have a working, signed mechanism; a third one competing with
    // them is how you get two updaters racing over one app bundle.
    expect(selfUpdatePreflight(linuxRoot({ platform: "darwin" }))).toMatch(/Restart to install/);
    expect(selfUpdatePreflight(linuxRoot({ platform: "win32" }))).toMatch(/AI Commander Update/);
  });

  it("refuses without root, naming the command that works", () => {
    const refusal = selfUpdatePreflight(linuxRoot({ uid: 1000 }));
    expect(refusal).toMatch(/must run as root/);
    expect(refusal).toContain("sudo aicommander-agent self-update");
  });

  it("refuses the npm shape, whose upgrade a binary backup cannot undo", () => {
    for (const runtime of ["node", "bun", "deno"]) {
      const refusal = selfUpdatePreflight(linuxRoot({ execName: runtime }));
      expect(refusal).toMatch(/npm install shape/);
      expect(refusal).toContain("npm i -g @aicommander/agent@latest");
    }
  });

  it("refuses without systemd rather than hoping something restarts the agent", () => {
    // This is the QNAP case. Nothing here can promise the agent comes back, and an
    // agent that does not come back takes remote access with it.
    const refusal = selfUpdatePreflight(linuxRoot({ hasSystemd: false }));
    expect(refusal).toMatch(/No systemd/);
    expect(refusal).toMatch(/qnap/i);
  });

  it("tells the no-systemd operator the STEPS, not just a document to go read", () => {
    // The first version cited "the documented swap procedure" in a file that had no
    // such section, by a repo path the operator does not have on their NAS. A way
    // forward that does not exist is worse than none: it sends the caller straight
    // back to improvising, which is what this whole command exists to stop.
    const refusal = selfUpdatePreflight(linuxRoot({ hasSystemd: false }))!;
    expect(refusal).toMatch(/stage and verify/i);
    expect(refusal).toMatch(/stop the agent/i);
    expect(refusal).toMatch(/--version/);
    // A reachable URL, not a path inside this repository.
    expect(refusal).toContain("https://aicommander.dev/skill/qnap/SKILL.md");
    expect(refusal).not.toMatch(/web\/skill/);
  });

  it("every refusal offers a way forward", () => {
    // A bare "no" is what pushes a caller back into improvising, which is the
    // failure this command exists to prevent.
    const refusals = [
      selfUpdatePreflight(linuxRoot({ platform: "darwin" })),
      selfUpdatePreflight(linuxRoot({ uid: 1000 })),
      selfUpdatePreflight(linuxRoot({ execName: "node" })),
      selfUpdatePreflight(linuxRoot({ hasSystemd: false })),
    ];
    for (const refusal of refusals) expect(refusal!.length).toBeGreaterThan(80);
  });
});

describe("selfUpdateLaunchArgv", () => {
  // The updater must survive the restart it triggers. `detached: true` does NOT
  // achieve that: a detached child keeps the agent service's cgroup, and the unit
  // runs with systemd's default KillMode=control-group, so `systemctl restart`
  // kills it. That is not theory — on 2026-08-10 a setsid script's log stopped
  // dead after "backup ok"; the swap had happened and the verification and
  // rollback were killed with it. Only a transient unit escapes.
  it("launches the worker in its OWN transient unit", () => {
    const argv = selfUpdateLaunchArgv("/usr/local/bin/aicommander-agent", ["self-update"]);
    expect(argv).toContain("--collect");
    expect(argv.some((a) => a.startsWith("--unit="))).toBe(true);
    // The last tokens are the command itself, after systemd-run's own options.
    expect(argv.slice(-2)).toEqual(["/usr/local/bin/aicommander-agent", "self-update"]);
  });

  it("marks the child so it does the work instead of re-launching itself", () => {
    expect(selfUpdateLaunchArgv("/bin/agent", ["self-update"])).toContain(
      "--setenv=AIC_SELF_UPDATE_WORKER=1",
    );
  });

  it("forwards the caller's flags, so --force survives the hand-off", () => {
    const argv = selfUpdateLaunchArgv("/bin/agent", ["self-update", "--force"]);
    expect(argv.slice(-3)).toEqual(["/bin/agent", "self-update", "--force"]);
  });

  it("carries a relay override so a staging agent does not update from production", () => {
    const argv = selfUpdateLaunchArgv("/bin/agent", ["self-update"], {
      AICOMMANDER_SERVER: "https://relay.test",
    });
    expect(argv).toContain("--setenv=AICOMMANDER_SERVER=https://relay.test");
  });

  it("passes no relay override when none is set", () => {
    const argv = selfUpdateLaunchArgv("/bin/agent", ["self-update"], {});
    expect(argv.some((a) => a.startsWith("--setenv=AICOMMANDER_SERVER"))).toBe(false);
  });
});

describe("release signing key", () => {
  it("is the key README publishes, by fingerprint", () => {
    // Guards the compiled-in constant: a bad paste fails here rather than on a
    // machine that then trusts the wrong signer.
    expect(signingKeyFingerprint()).toBe(RELEASE_SIGNING_KEY_SHA256);
  });

  it("is byte-identical to the key scripts/release-key.mjs pins for the launcher", () => {
    // Third pinning site: the release-provenance gate the public mirror runs.
    // Rotating the key means rotating all three together.
    const here = path.dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(path.resolve(here, "../../scripts/release-key.mjs"), "utf8");
    expect(source).toContain(RELEASE_SIGNING_KEY_SHA256);
    const pem = source.slice(
      source.indexOf('"-----BEGIN PUBLIC KEY-----'),
      source.indexOf('-----END PUBLIC KEY-----\\n";'),
    );
    const base64 = /"([A-Za-z0-9+/=]{40,})\\n"/.exec(pem)?.[1];
    expect(base64).toBeTruthy();
    const der = crypto
      .createPublicKey(
        `-----BEGIN PUBLIC KEY-----\n${base64}\n-----END PUBLIC KEY-----\n`,
      )
      .export({ type: "spki", format: "der" });
    expect(crypto.createHash("sha256").update(der).digest("hex")).toBe(RELEASE_SIGNING_KEY_SHA256);
  });
});

describe("verifyInstallerSignature", () => {
  // A GENUINE signed release, checked in as a fixture. Rejection tests alone were
  // the gap here: a verifier that returns false for everything passes all of them
  // and refuses every real upgrade forever. This is the only case that proves the
  // embedded key and the release job's signature actually agree.
  //
  // Never needs regenerating — it is a fixed artifact for a fixed key, not a
  // "latest release" check. If it ever fails, either the constant in
  // self-update.ts was edited or the signing key was rotated; both are things a
  // machine must never discover on its own.
  const fixture = (name: string): Buffer =>
    readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", name));

  it("accepts the real v1.0.41 installer as published", () => {
    expect(verifyInstallerSignature(fixture("install-1.0.41"), fixture("install-1.0.41.sig"))).toBe(true);
  });

  it("rejects that same installer with one byte changed", () => {
    const tampered = Buffer.from(fixture("install-1.0.41"));
    tampered[100] = tampered[100]! ^ 0x01;
    expect(verifyInstallerSignature(tampered, fixture("install-1.0.41.sig"))).toBe(false);
  });

  it("the fixture is the VERSIONED installer, not the mutable template", () => {
    // The template refuses to run (its version placeholder is unsubstituted) and
    // is what a caller reaches by mistake via /install — the trap that cost three
    // attempts on 2026-08-10. Signing one and shipping the other would make this
    // suite green while the real path stayed broken.
    const text = fixture("install-1.0.41").toString("utf8");
    expect(text).toContain('INSTALLER_RELEASE_VERSION="1.0.41"');
    expect(text).not.toContain("__AIC_RELEASE_VERSION__");
  });

  it("rejects a signature from a different key", () => {
    // The whole point: a payload signed by anyone else is not our release.
    const impostor = crypto.generateKeyPairSync("ed25519");
    const installer = Buffer.from("#!/bin/bash\necho pwned\n");
    const signature = crypto.sign(null, installer, impostor.privateKey);
    expect(verifyInstallerSignature(installer, signature)).toBe(false);
  });

  it("rejects a valid signature over DIFFERENT bytes", () => {
    const impostor = crypto.generateKeyPairSync("ed25519");
    const signature = crypto.sign(null, Buffer.from("the real installer"), impostor.privateKey);
    expect(verifyInstallerSignature(Buffer.from("something else"), signature)).toBe(false);
  });

  it("returns false instead of throwing on a truncated signature", () => {
    // A short download is an ordinary outcome and must land in "do not install",
    // not in an exception that escapes and leaves the machine half-updated.
    expect(verifyInstallerSignature(Buffer.from("x"), Buffer.alloc(3))).toBe(false);
  });
});

describe("evaluateTarget", () => {
  it("installs a newer release", () => {
    expect(evaluateTarget("1.0.42", "1.0.41", false)).toEqual({ proceed: true });
  });

  it("does nothing when already on the published version", () => {
    const verdict = evaluateTarget("1.0.41", "1.0.41", false);
    expect(verdict.proceed).toBe(false);
    expect((verdict as { reason: string }).reason).toMatch(/already on 1\.0\.41/);
  });

  it("REFUSES a downgrade offered by the version pointer", () => {
    // Signing proves provenance, never freshness: an old release stays validly
    // signed forever, so a stale or attacker-controlled /dist/latest could walk a
    // fleet back onto known-vulnerable code with every crypto check passing.
    const verdict = evaluateTarget("1.0.30", "1.0.41", false);
    expect(verdict.proceed).toBe(false);
    expect((verdict as { reason: string }).reason).toMatch(/REFUSING TO DOWNGRADE/);
  });

  it("allows a deliberate downgrade under --force, and says so loudly", () => {
    const verdict = evaluateTarget("1.0.30", "1.0.41", true);
    expect(verdict.proceed).toBe(true);
    expect((verdict as { warning?: string }).warning).toMatch(/DOWN from 1\.0\.41 to 1\.0\.30/);
  });

  it("reinstalls the same version under --force without a downgrade warning", () => {
    expect(evaluateTarget("1.0.41", "1.0.41", true)).toEqual({ proceed: true });
  });
});

describe("replaceExecutable", () => {
  // copyFileSync opens the destination for writing, which Linux refuses with
  // ETXTBSY while that file is being executed — exactly the rollback case, where
  // the failed new agent is running from the path being restored. The throw would
  // escape before the restart, so the one path whose job is to rescue an
  // unreachable machine would be the one that fails on it.
  it("replaces the target and leaves no staging file behind", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "aic-replace-"));
    const target = path.join(dir, "agent");
    const source = path.join(dir, "agent.bak");
    writeFileSync(target, "new-and-broken");
    writeFileSync(source, "old-and-good");

    replaceExecutable(source, target);

    expect(readFileSync(target, "utf8")).toBe("old-and-good");
    expect(readdirSync(dir).filter((f) => f.includes("staged"))).toEqual([]);
    expect(statSync(target).mode & 0o777).toBe(0o755);
    rmSync(dir, { recursive: true, force: true });
  });

  it("cleans up its staging file when the replace fails", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "aic-replace-"));
    expect(() => replaceExecutable(path.join(dir, "does-not-exist"), path.join(dir, "agent"))).toThrow();
    expect(readdirSync(dir).filter((f) => f.includes("staged"))).toEqual([]);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("updateOutcome", () => {
  const ok = {
    activeState: "active",
    pidBeforeInstall: "1000",
    pidBefore: "1234",
    pidAfter: "1234",
    installedVersion: "1.0.41",
    targetVersion: "1.0.41",
  };

  it("accepts a stable service running the version we asked for", () => {
    expect(updateOutcome(ok)).toEqual({ ok: true });
  });

  it("REJECTS a healthy service still on the old version", () => {
    // The exact false pass that reported success for a failed upgrade: the old
    // agent never stopped, so "is it running?" was always going to say yes.
    const verdict = updateOutcome({ ...ok, installedVersion: "1.0.40" });
    expect(verdict).toEqual({ ok: false, reason: "still running 1.0.40, expected 1.0.41" });
  });

  it("rejects a flapping service, whose pid changes across the window", () => {
    // A binary that starts and crashes looks `active` at both ends, because
    // Restart=always keeps giving it another one.
    expect(updateOutcome({ ...ok, pidAfter: "1299" })).toEqual({
      ok: false,
      reason: "service is restarting (MainPID 1234 → 1299)",
    });
  });

  it("rejects a dead or unqueryable service", () => {
    expect(updateOutcome({ ...ok, activeState: "failed" })).toEqual({
      ok: false,
      reason: "service is failed, not active",
    });
    expect(updateOutcome({ ...ok, activeState: "unknown" })).toEqual({
      ok: false,
      reason: "service is unknown, not active",
    });
  });

  it("treats a missing MainPID as a failure, not as a stable match", () => {
    // "0" is systemd for "nothing is running"; comparing it to itself must not
    // read as "the same process throughout".
    expect(updateOutcome({ ...ok, pidBefore: "0", pidAfter: "0" }).ok).toBe(false);
    expect(updateOutcome({ ...ok, pidBefore: "", pidAfter: "" }).ok).toBe(false);
  });

  it("REJECTS a service that never restarted, however healthy it looks", () => {
    // The installer can swap the binary and then die before restarting systemd.
    // The old process stays active with a rock-steady pid, and installedVersion —
    // which executes the file on DISK, not the running process — reports the new
    // version. Every other check passes and the machine still serves the old agent.
    const verdict = updateOutcome({ ...ok, pidBeforeInstall: "1234" });
    expect(verdict).toEqual({
      ok: false,
      reason: "service never restarted (MainPID still 1234); the binary may be swapped but the running agent is not",
    });
  });

  it("says which version it actually found, so the log explains itself", () => {
    const verdict = updateOutcome({ ...ok, installedVersion: "" });
    expect(verdict).toEqual({ ok: false, reason: "still running an unknown version, expected 1.0.41" });
  });
});

describe("lockVerdict", () => {
  // The lock lives in a durable directory and its holder can die without unlinking
  // it — OOM, systemctl kill, a reboot mid-update. Honouring it blindly turns one
  // dead process into a machine that refuses to update forever, and quietly: the
  // refusal reaches only the log, while the caller was already told it started.
  const alive = (pids: number[]) => (pid: number) => pids.includes(pid);

  it("honours a lock whose holder is still alive", () => {
    expect(lockVerdict("4242", 60_000, alive([4242]))).toBe("held");
  });

  it("declares a lock stale when its holder is gone", () => {
    expect(lockVerdict("4242", 60_000, alive([]))).toBe("stale");
  });

  it("declares a lock stale once it is older than the backstop", () => {
    // After a reboot the recorded pid may well be alive again as something else.
    expect(lockVerdict("4242", 3 * 60 * 60_000, alive([4242]))).toBe("stale");
  });

  it("treats an unusable pid as stale rather than as a permanent block", () => {
    for (const content of ["", "not-a-pid", "0", "1", "-5"]) {
      expect(lockVerdict(content, 1_000, alive([4242]))).toBe("stale");
    }
  });
});

describe("serverUrlFromUnitEnvironment", () => {
  // sudo's env_reset strips AICOMMANDER_SERVER, so the caller's environment is the
  // wrong source: a staging box would fetch the PRODUCTION installer, which then
  // rewrites the unit's Environment line and moves that box onto production.
  it("reads the relay baked into the unit", () => {
    const show = 'Environment=AICOMMANDER_SERVER=https://staging.example AICOMMANDER_SERVICE=1 NODE_ENV=production';
    expect(serverUrlFromUnitEnvironment(show)).toBe("https://staging.example");
  });

  it("handles the quoted form systemd also prints", () => {
    expect(serverUrlFromUnitEnvironment('Environment="AICOMMANDER_SERVER=https://relay.test" NODE_ENV=production')).toBe(
      "https://relay.test",
    );
  });

  it("returns null when the unit sets no relay", () => {
    expect(serverUrlFromUnitEnvironment("Environment=NODE_ENV=production")).toBeNull();
    expect(serverUrlFromUnitEnvironment("")).toBeNull();
  });

  it("ignores a value that is not an http(s) origin", () => {
    // Never let a mangled unit file steer the download somewhere exotic.
    expect(serverUrlFromUnitEnvironment("Environment=AICOMMANDER_SERVER=file:///etc/passwd")).toBeNull();
  });
});
