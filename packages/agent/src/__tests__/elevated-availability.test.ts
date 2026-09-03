// Whether this machine can run elevated commands — and, when it cannot, the one
// word that says why.
//
// The 2026-09-02 machine had a privileged helper that had NEVER BEEN REGISTERED,
// and nothing anywhere said so. The signal was on the wire the whole time
// (`elevatedExec`, reconciled every 60s); what was missing was the ability to
// tell "no helper", "an agent too old to say" and "offline" apart. So each test
// here is a cause the agent must be able to name — and, just as important, the
// cases where it must stay silent rather than guess.
//
// TWO RULES THIS SUITE ENFORCES ON THE PRODUCTION CODE:
//  - `available: true` still comes ONLY from a completed handshake. No reason,
//    however benign, may produce it.
//  - a cause the code cannot establish is never asserted. A PowerShell query that
//    could not run must not be reported as "the task is not registered", which is
//    the incident's own signature.
//
// PLATFORM NOTE. Driven on POSIX with `process.platform` pinned before the
// dynamic import, like job-scripts.test.ts and doctor-helper.test.ts. The
// platform-owned locations come from @aicommander/priv-helper and are staged.

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import type { ElevatedEndpoint } from "@aicommander/priv-helper";

const helperEnv = vi.hoisted(() => ({
  dir: null as string | null,
  endpoints: [] as ElevatedEndpoint[],
}));

vi.mock("@aicommander/priv-helper", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@aicommander/priv-helper")>();
  return {
    ...actual,
    helperInstallDir: () => helperEnv.dir,
    helperVersionMarkerPath: () => (helperEnv.dir === null ? null : path.join(helperEnv.dir, "VERSION")),
    elevatedEndpoints: () => helperEnv.endpoints,
  };
});

// The seam is capture.ts's `runCaptured` — the ONE command primitive in the
// package that distinguishes "it answered" from "it never ran". It lives at
// `src/` and not under `doctor/` precisely so this module's query can be built
// on it without the runtime importing from the diagnostics subtree.
const shell = vi.hoisted(() => ({ powershell: "", calls: 0 }));
vi.mock("../capture.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../capture.js")>();
  return {
    ...actual,
    runCaptured: async (command: string): Promise<import("../capture.js").Captured> => {
      if (/powershell\.exe$/i.test(command)) {
        shell.calls++;
        return { kind: "output", stdout: shell.powershell };
      }
      return { kind: "output", stdout: "" };
    },
  };
});

type AvailabilityModule = typeof import("../elevated-availability.js");
type ExecutorModule = typeof import("../elevated-executor.js");
let availability: AvailabilityModule;
let executor: ExecutorModule;
let priv: typeof import("@aicommander/priv-helper");
const realPlatform = process.platform;

beforeAll(async () => {
  Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  availability = await import("../elevated-availability.js");
  executor = await import("../elevated-executor.js");
  priv = await import("@aicommander/priv-helper");
});

afterAll(() => {
  Object.defineProperty(process, "platform", { value: realPlatform, configurable: true });
});

let tmp: string;
const servers: net.Server[] = [];

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aic-elev-avail-"));
  helperEnv.dir = null;
  helperEnv.endpoints = [];
  shell.powershell = "";
  shell.calls = 0;
  availability.__resetRegistrationCache();
});

afterEach(async () => {
  for (const server of servers.splice(0)) await new Promise((r) => server.close(r));
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** The helper directory as the installer leaves it: a binary and a VERSION marker. */
function installHelper(): void {
  helperEnv.dir = path.join(tmp, "helper");
  fs.mkdirSync(helperEnv.dir, { recursive: true });
  fs.writeFileSync(path.join(helperEnv.dir, HELPER_EXE), "MZ");
  fs.writeFileSync(path.join(helperEnv.dir, "VERSION"), "1.0.0\n");
}

/** The name the installer gives the helper binary on the pinned platform. */
const HELPER_EXE = "aicommander-priv-helper.exe";

/** A helper endpoint that answers `hello` however the test tells it to. */
async function fakeHelper(reply: (frame: Record<string, unknown>) => Record<string, unknown> | null): Promise<ElevatedEndpoint> {
  const socketPath = path.join(tmp, `helper-${servers.length}.sock`);
  const server = net.createServer((socket) => {
    const decoder = new priv.FrameDecoder();
    socket.on("data", (chunk: Buffer) => {
      for (const frame of decoder.push(chunk)) {
        const answer = reply(frame);
        // The fake answers with whatever shape the test wants, including a
        // deliberately wrong protocol version, so the frame is cast rather than
        // typed as a legal message.
        if (answer) socket.write(priv.encodeFrame(answer as never));
      }
    });
    socket.on("error", () => undefined);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  return { transport: "unix", path: socketPath };
}

function helloOk(bootId: string, protocolVersion = priv.IPC_PROTOCOL_VERSION) {
  return (frame: Record<string, unknown>) =>
    frame["t"] === "hello"
      ? { t: "hello-ok", protocolVersion, helperVersion: "1.0.0", bootId, effectiveIdentity: "SYSTEM" }
      : null;
}

// --- What discovery can genuinely tell apart ---------------------------------

describe("discoverHelperDetailed — the causes the probe can actually establish", () => {
  it("returns the helper when one answers on our protocol", async () => {
    const endpoint = await fakeHelper(helloOk("boot-1"));
    const found = await executor.discoverHelperDetailed({ endpoints: [endpoint], attempts: 1 });
    expect(found).toEqual({ ok: true, bootId: "boot-1", endpoint });
  });

  it("reports nothing-answered as unreachable", async () => {
    const found = await executor.discoverHelperDetailed({
      endpoints: [{ transport: "unix", path: path.join(tmp, "absent.sock") }],
      attempts: 1,
    });
    expect(found).toEqual({ ok: false, cause: "unreachable" });
  });

  it("separates a version-skew answer from silence, and still refuses it", async () => {
    const endpoint = await fakeHelper(helloOk("boot-1", priv.IPC_PROTOCOL_VERSION + 1));
    const found = await executor.discoverHelperDetailed({ endpoints: [endpoint], attempts: 1 });
    // The cause is extra information, never a second opinion about whether to
    // proceed: anything but `ok` is "no helper".
    expect(found).toEqual({ ok: false, cause: "protocol_mismatch" });
  });

  it("remembers a version-skew answer across a retry that sees nothing", async () => {
    const skewed = await fakeHelper(helloOk("boot-1", priv.IPC_PROTOCOL_VERSION + 1));
    const dead: ElevatedEndpoint = { transport: "unix", path: path.join(tmp, "absent.sock") };
    const found = await executor.discoverHelperDetailed({
      endpoints: [skewed, dead],
      attempts: 2,
      retryDelayMs: 0,
    });
    expect(found).toEqual({ ok: false, cause: "protocol_mismatch" });
  });

  it("calls two different identities a conflict and trusts neither", async () => {
    // A live helper owns every port it could bind, so a second bootId means
    // something that is not the helper is answering. Refusing downgrades a local
    // squatter to a denial of service instead of handing it a capability.
    const a = await fakeHelper(helloOk("boot-A"));
    const b = await fakeHelper(helloOk("boot-B"));
    const found = await executor.discoverHelperDetailed({ endpoints: [a, b], attempts: 1 });
    expect(found).toEqual({ ok: false, cause: "conflict" });
  });
});

// --- The reason the agent puts on the wire -----------------------------------

describe("resolveElevatedAvailability — one word per cause", () => {
  it("says platform_unsupported where there is no helper by design", async () => {
    // No endpoints at all: Linux. The remedy is to stop asking for `elevated`.
    expect(await availability.resolveElevatedAvailability()).toEqual({
      available: false,
      reason: "platform_unsupported",
    });
  });

  it("says not_installed when the helper's files are absent, and probes nothing", async () => {
    // A platform WITH a helper location, whose files are simply not there.
    helperEnv.dir = path.join(tmp, "helper");
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    const discover = vi.fn();
    expect(
      await availability.resolveElevatedAvailability({ discover: discover as never }),
    ).toEqual({ available: false, reason: "not_installed" });
    // The on-disk gate has always come first: no marker, no handshake.
    expect(discover).not.toHaveBeenCalled();
  });

  it("says not_installed when the marker outlived the executable it vouches for", async () => {
    // A quarantine, not a corner case: the marker is a text file, the helper is
    // a binary that looks like a dropper to a behavioural engine, so taking the
    // one and leaving the other is an ordinary outcome. Judged on the marker
    // alone this machine read as "installed but silent" and the operator was
    // sent to reboot or repair a task with nothing to start.
    installHelper();
    fs.rmSync(path.join(helperEnv.dir!, HELPER_EXE));
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    const discover = vi.fn();
    expect(
      await availability.resolveElevatedAvailability({ discover: discover as never }),
    ).toEqual({ available: false, reason: "not_installed" });
    expect(discover).not.toHaveBeenCalled();
  });

  it("reports a reachable helper as available — only ever from a real handshake", async () => {
    installHelper();
    const endpoint = await fakeHelper(helloOk("boot-live"));
    helperEnv.endpoints = [endpoint];
    expect(await availability.resolveElevatedAvailability()).toEqual({
      available: true,
      bootId: "boot-live",
      endpoint,
    });
  });

  it("passes protocol skew and identity conflicts through as their own reasons", async () => {
    installHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    for (const [cause, reason] of [
      ["protocol_mismatch", "protocol_mismatch"],
      ["conflict", "endpoint_conflict"],
    ] as const) {
      expect(
        await availability.resolveElevatedAvailability({
          discover: (async () => ({ ok: false, cause })) as never,
          registered: async () => true,
        }),
      ).toEqual({ available: false, reason });
    }
  });

  it("says not_registered when the files are there and Windows has no task", async () => {
    // THE INCIDENT. The installer ran, the files landed, and the SYSTEM task was
    // never registered because the Authenticode check it gates on failed silently.
    installHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    shell.powershell = "QUERIED=1\r\n"; // Windows answered: no such task.
    expect(await availability.resolveElevatedAvailability()).toEqual({
      available: false,
      reason: "not_registered",
    });
  });

  it("says endpoint_unreachable when the task IS registered but nothing answers", async () => {
    installHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    shell.powershell = "QUERIED=1\r\nSTATE=Ready\r\nEXECUTE=powershell.exe\r\nARGS=-File x.ps1";
    expect(await availability.resolveElevatedAvailability()).toEqual({
      available: false,
      reason: "endpoint_unreachable",
    });
  });

  it("does NOT accuse a machine of the incident when the query itself failed", async () => {
    // An unanswerable question is not evidence. Reporting "never registered"
    // because PowerShell would not run invents the incident on a healthy box.
    installHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    shell.powershell = ""; // The query did not run at all.
    expect(await availability.resolveElevatedAvailability()).toEqual({
      available: false,
      reason: "endpoint_unreachable",
    });
  });

  it("asks Windows about the task at most once per cache window", async () => {
    // The reconciler runs every 60s forever; a PowerShell process a minute, on
    // every helper-less machine, to re-answer a question that changes only when
    // somebody runs an installer, is not a diagnostic worth paying for.
    installHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    shell.powershell = "QUERIED=1\r\n";
    await availability.resolveElevatedAvailability();
    await availability.resolveElevatedAvailability();
    expect(shell.calls).toBe(1);
    availability.__resetRegistrationCache();
    await availability.resolveElevatedAvailability();
    expect(shell.calls).toBe(2);
  });

  it("answers the cheap half of the verdict without probing anything", () => {
    // What connection.ts sends in its FIRST agent:register. Both of these are
    // final — no handshake can overturn "no helper on this platform" or "the
    // files are not there" — so a machine that has one of them says so in the
    // frame it already sends, instead of provoking a second register on every
    // connection of every helper-less box in the fleet.
    expect(availability.staticElevatedUnavailableReason()).toBe("platform_unsupported");

    helperEnv.dir = path.join(tmp, "helper");
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    expect(availability.staticElevatedUnavailableReason()).toBe("not_installed");

    // Installed: nothing cheap can say anything, and only discovery may.
    installHelper();
    expect(availability.staticElevatedUnavailableReason()).toBeUndefined();
  });

  it("does not depend on the diagnostics subtree", () => {
    // This module is fail-closed RUNTIME logic; `doctor/` is a report the user
    // asks for. Importing downwards made removing or moving the diagnostics break
    // the agent build and left the availability rule unreadable on its own. The
    // shared Windows scheduled-task query lives in a neutral module instead.
    const source = fs.readFileSync(
      path.join(__dirname, "..", "elevated-availability.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/from\s+"\.\/doctor\//);
    expect(source).toContain('from "./windows-scheduled-task.js"');
  });

  it("re-asks after a query that could not run, instead of shelving 'we could not tell'", async () => {
    // The TTL's justification — "it changes only when somebody runs an installer"
    // — is a statement about a VERDICT. A null is not one: it says the query did
    // not come back, which is a property of this moment (a PowerShell that lost a
    // race with a CIM module cold-load under an AV scan) and can be false a
    // minute later. Cached for the full ten minutes it pinned the incident
    // machine to `endpoint_unreachable` in ten-minute blocks, so `not_registered`
    // — the one verdict this work exists to produce — might never be said at all.
    installHelper();
    helperEnv.endpoints = [{ transport: "unix", path: path.join(tmp, "absent.sock") }];
    const silent = { discover: (async () => ({ ok: false, cause: "unreachable" })) as never };
    vi.useFakeTimers();
    try {
      shell.powershell = ""; // The query did not run at all.
      expect(await availability.resolveElevatedAvailability(silent)).toEqual({
        available: false,
        reason: "endpoint_unreachable",
      });
      expect(shell.calls).toBe(1);

      // A minute and a half later — deep inside the ten-minute window a real
      // answer would have earned.
      vi.setSystemTime(Date.now() + 90_000);
      shell.powershell = "QUERIED=1\r\n"; // This time Windows answers: no such task.
      expect(await availability.resolveElevatedAvailability(silent)).toEqual({
        available: false,
        reason: "not_registered",
      });
      expect(shell.calls).toBe(2);

      // …and THAT answer is a verdict, so it is kept: the cost the TTL exists to
      // avoid is not paid back by this change.
      vi.setSystemTime(Date.now() + 90_000);
      expect(await availability.resolveElevatedAvailability(silent)).toEqual({
        available: false,
        reason: "not_registered",
      });
      expect(shell.calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("never consults registration at all once a helper answers", async () => {
    installHelper();
    const endpoint = await fakeHelper(helloOk("boot-live"));
    helperEnv.endpoints = [endpoint];
    await availability.resolveElevatedAvailability();
    expect(shell.calls).toBe(0);
  });
});
