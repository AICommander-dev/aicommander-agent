import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  parsePrivHelperCliArgs,
  PRIV_HELPER_USAGE,
} from "../cli.js";
import { HELPER_VERSION } from "../version.js";

const packageRoot = fileURLToPath(new URL("../../", import.meta.url));
const entrypoint = path.join(packageRoot, "bin", "priv-helper.ts");

describe("parsePrivHelperCliArgs", () => {
  it("reserves a bare invocation for the service-managed daemon", () => {
    expect(parsePrivHelperCliArgs([])).toBe("serve");
  });

  it("accepts exactly --version as the safe diagnostic", () => {
    expect(parsePrivHelperCliArgs(["--version"])).toBe("version");
  });

  it("accepts exactly `doctor` as the second safe diagnostic", () => {
    expect(parsePrivHelperCliArgs(["doctor"])).toBe("doctor");
  });

  it.each([
    ["--help"],
    ["-v"],
    ["version"],
    ["--unknown"],
    ["--version", "extra"],
    // `doctor` takes no options, and that is the security property: an option
    // accepted here is an option somebody can be talked into passing to a binary
    // that runs as SYSTEM. Every other shape fails closed.
    ["--doctor"],
    ["Doctor"],
    ["doctor", "--json"],
    ["doctor", "--report", "C:\\Users\\me\\out.txt"],
    ["doctor", ""],
  ])("rejects every other argument shape before daemon startup: %j", (...args) => {
    expect(parsePrivHelperCliArgs(args)).toBe("invalid");
  });
});

const describeUnix = process.platform === "win32" ? describe.skip : describe;

describeUnix("priv-helper CLI active-socket regression", () => {
  const cleanupDirs: string[] = [];
  const cleanupServers: net.Server[] = [];

  afterEach(async () => {
    for (const socket of accepted.splice(0)) socket.destroy();
    for (const server of cleanupServers.splice(0)) {
      if (server.listening) {
        server.close();
        await once(server, "close");
      }
    }
    for (const dir of cleanupDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  /** Connections the fake listener accepted, so `close()` cannot wait on one. */
  const accepted: net.Socket[] = [];

  async function activeSocket(): Promise<{
    endpoint: string;
    inode: number;
  }> {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-helper-cli-"));
    fs.chmodSync(dir, 0o700);
    cleanupDirs.push(dir);

    const endpoint = path.join(dir, "helper.sock");
    const server = net.createServer((socket) => {
      accepted.push(socket);
      socket.end();
    });
    cleanupServers.push(server);
    server.listen(endpoint);
    await once(server, "listening");
    return { endpoint, inode: fs.lstatSync(endpoint).ino };
  }

  function runCli(endpoint: string, args: string[]) {
    return spawnSync(
      process.execPath,
      ["--import", "tsx", entrypoint, ...args],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env: { ...process.env, AIC_HELPER_ENDPOINT: endpoint },
        // Was 3 s, which was only ever enough because `doctor` did not really
        // run: with no endpoint injected it talked to whatever the DEVELOPER'S
        // machine had listening and finished in milliseconds. It now runs the
        // real check set against the temp socket above (AIC_HELPER_ENDPOINT,
        // honoured by bin/priv-helper.ts for exactly this reason), which costs a
        // tsx cold start plus the endpoint budget. The cap is still here to stop
        // a wedged doctor hanging the suite; it is not a performance assertion.
        timeout: 20_000,
        killSignal: "SIGKILL",
      },
    );
  }

  async function expectOriginalSocketReachable(
    endpoint: string,
    inode: number,
  ): Promise<void> {
    expect(fs.lstatSync(endpoint).ino).toBe(inode);
    const probe = net.connect(endpoint);
    await once(probe, "connect");
    probe.destroy();
  }

  it("prints --version without replacing or disconnecting a live socket", async () => {
    const { endpoint, inode } = await activeSocket();

    const result = runCli(endpoint, ["--version"]);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`${HELPER_VERSION}\n`);
    expect(result.stderr).toBe("");
    await expectOriginalSocketReachable(endpoint, inode);
  });

  it("runs `doctor` to completion without starting the daemon", async () => {
    const { endpoint, inode } = await activeSocket();

    const result = runCli(endpoint, ["doctor"]);

    expect(result.error).toBeUndefined();
    // 0 or 1 depending on what this dev machine actually has installed; 2 would
    // mean the verb was rejected, and anything else means it crashed.
    expect([0, 1]).toContain(result.status);
    expect(result.stdout).toContain("privileged helper");
    expect(result.stdout).toContain("REDUCED check set");
    // The daemon's startup banner. Its absence is the assertion that matters:
    // no diagnostic invocation may fall through to daemon startup.
    expect(result.stdout).not.toContain("listening (boot");
    expect(result.stderr).toBe("");
    // stdio is piped, so nothing is a TTY and the "Press Enter to close" hold
    // for the Start Menu shortcut must not engage (spawnSync would time out).
    expect(result.stdout).not.toContain("Press Enter");
    await expectOriginalSocketReachable(endpoint, inode);
  });

  it("rejects an unknown argument without touching a live socket", async () => {
    const { endpoint, inode } = await activeSocket();

    const result = runCli(endpoint, ["--unknown"]);

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("priv-helper: invalid arguments");
    expect(result.stderr).toContain(PRIV_HELPER_USAGE);
    await expectOriginalSocketReachable(endpoint, inode);
  });
});
