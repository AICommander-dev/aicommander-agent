// The connectivity ladder: DNS → HTTPS → ticket exchange → WebSocket upgrade,
// plus the clock skew read off the relay's own Date header.
//
// The load-bearing assertions are the two about LIVE STATE, because they are the
// ones a later change could break without any test noticing:
//   - `/api/register` is NEVER requested. Registering to "check registration"
//     would mint a session code on a machine that had none.
//   - the upgrade probe carries no Authorization header and a ticket the relay
//     never issued, so it cannot redeem anything and cannot displace the
//     machine's live relay session.
//
// After those, the assertions that matter most are the ones about how little
// evidence a verdict may be drawn from: a 2xx whose body is not a ticket, a 401
// that did not come from the relay, and a skew reading taken after two more
// network legs are each a HEALTHY verdict on a machine that cannot connect.
//
// The store is a temp directory throughout. These checks read the machine's real
// session ladder (/etc, ~/.config) when no configDir is given, and a unit test
// that found the developer's own session would POST their agent token.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import dns from "node:dns";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DoctorContext } from "../doctor/types.js";

/** Every request the checks made, in order. */
const requests = vi.hoisted(() => ({ urls: [] as string[], headers: [] as Array<Record<string, string>> }));

/** The staged WebSocket: what the "server" does with the upgrade. */
const upgrade = vi.hoisted(() => ({
  mode: "unexpected-response" as
    | "unexpected-response"
    | "open"
    | "error"
    | "silent"
    /** A refusal followed by a socket error — the settle-once race. */
    | "response-then-error",
  status: 401,
  /** What the refusal's body and content type look like. */
  contentType: "application/json" as string | null,
  body: '{"error":"Unauthorized"}',
  urls: [] as string[],
  options: [] as unknown[],
}));

vi.mock("ws", () => {
  /** Just enough of http.IncomingMessage for the refusal-body read. */
  function fakeResponse(): unknown {
    const listeners = new Map<string, (arg?: unknown) => void>();
    queueMicrotask(() => {
      if (upgrade.body) listeners.get("data")?.(upgrade.body);
      listeners.get("end")?.();
    });
    return {
      statusCode: upgrade.status,
      headers: upgrade.contentType ? { "content-type": upgrade.contentType } : {},
      setEncoding(): void {},
      destroy(): void {},
      on(event: string, handler: (arg?: unknown) => void): void {
        listeners.set(event, handler);
      },
    };
  }

  class FakeWebSocket {
    private readonly handlers = new Map<string, (...args: unknown[]) => void>();
    constructor(url: string, options?: unknown) {
      upgrade.urls.push(url);
      upgrade.options.push(options);
      queueMicrotask(() => {
        switch (upgrade.mode) {
          case "unexpected-response":
            this.handlers.get("unexpected-response")?.({}, fakeResponse());
            break;
          case "response-then-error":
            this.handlers.get("unexpected-response")?.({}, fakeResponse());
            this.handlers.get("error")?.(new Error("ECONNRESET"));
            break;
          case "open":
            this.handlers.get("open")?.();
            break;
          case "error":
            this.handlers.get("error")?.(new Error("ECONNRESET"));
            break;
          case "silent":
            // A firewall that DROPS the upgrade rather than refusing it — the
            // most common real cause of "the machine shows offline". Nothing
            // ever fires; only the probe's own timeout ends it.
            break;
        }
      });
    }
    on(event: string, handler: (...args: unknown[]) => void): this {
      this.handlers.set(event, handler);
      return this;
    }
    close(): void {}
    terminate(): void {}
  }
  return { default: FakeWebSocket };
});

import { connectivityChecks, tlsAnchorCaveat } from "../doctor/checks/connectivity.js";

const SERVER_DATE = "Tue, 02 Sep 2026 20:00:00 GMT";
const TICKET = "a".repeat(64);

let configDir: string;

function ctx(overrides: Partial<DoctorContext> = {}): DoctorContext {
  return {
    configDir,
    // Loopback so DNS resolves without leaving the machine.
    serverUrl: "https://localhost",
    offline: false,
    networkTimeoutMs: 500,
    probeDelayMs: 0,
    ...overrides,
  };
}

/** A registered machine, the way session-store.ts leaves one on disk. */
function stageSession(): void {
  fs.writeFileSync(
    path.join(configDir, "session.json"),
    JSON.stringify({ sessionCode: "AIC-ABCD-EFGH-IJKL", agentToken: "t".repeat(43) }),
    { mode: 0o600 },
  );
}

function stageFetch(responder: (url: string) => Response): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.urls.push(url);
      requests.headers.push((init?.headers ?? {}) as Record<string, string>);
      return responder(url);
    }),
  );
}

function jsonResponse(status: number, body: unknown = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", date: SERVER_DATE },
  });
}

/** The healthy relay: a ticket on the ticket route, a page everywhere else. */
function healthyRelay(url: string): Response {
  return url.endsWith("/api/agent/ws-ticket") ? jsonResponse(200, { ticket: TICKET }) : jsonResponse(200);
}

beforeEach(() => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-doctor-net-"));
  requests.urls = [];
  requests.headers = [];
  upgrade.mode = "unexpected-response";
  upgrade.status = 401;
  upgrade.contentType = "application/json";
  upgrade.body = '{"error":"Unauthorized"}';
  upgrade.urls = [];
  upgrade.options = [];
  stageSession();
  vi.useFakeTimers({ now: new Date(SERVER_DATE).getTime(), toFake: ["Date"] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  fs.rmSync(configDir, { recursive: true, force: true });
});

describe("connectivity checks", () => {
  it("skips every leg — and says so — when --offline is asked for", async () => {
    const results = await connectivityChecks.run(ctx({ offline: true }));
    expect(results.map((r) => r.id)).toEqual([
      "net.dns",
      "net.https",
      "net.ticket",
      "net.websocket",
      "env.clock",
    ]);
    expect(results.every((r) => r.verdict === "skipped")).toBe(true);
  });

  it("passes the whole ladder on a healthy machine", async () => {
    stageFetch(healthyRelay);
    const results = await connectivityChecks.run(ctx());
    const verdicts = Object.fromEntries(results.map((r) => [r.id, r.verdict]));
    expect(verdicts["net.dns"]).toBe("ok");
    expect(verdicts["net.https"]).toBe("ok");
    expect(verdicts["net.ticket"]).toBe("ok");
    // The relay refusing an invalid ticket is the PASSING answer.
    expect(verdicts["net.websocket"]).toBe("ok");
    expect(verdicts["env.clock"]).toBe("ok");
  });

  it("never touches /api/register — checking registration must not mint one", async () => {
    stageFetch(healthyRelay);
    await connectivityChecks.run(ctx());
    expect(requests.urls.some((u) => u.includes("/api/register"))).toBe(false);
    expect(requests.urls).toContain("https://localhost/api/agent/ws-ticket");
  });

  it("sends no credential and an unissued ticket on the upgrade probe", async () => {
    stageFetch(healthyRelay);
    await connectivityChecks.run(ctx());
    expect(upgrade.urls).toHaveLength(1);
    const probed = new URL(upgrade.urls[0]!);
    expect(probed.protocol).toBe("wss:");
    expect(probed.pathname).toBe("/ws/agent");
    expect(probed.searchParams.get("ticket")).toMatch(/^[0-9a-f]{64}$/);
    // No Authorization anywhere in the socket options: without the Bearer
    // credential the relay cannot redeem the ticket even if one existed.
    expect(JSON.stringify(upgrade.options[0] ?? {})).not.toMatch(/authorization/i);
  });

  it("does not read the session store the agent's way — no chmod, no directory created", async () => {
    // loadSession() reasserts 0600 on what it reads and creates the configured
    // directory; a diagnostic may do neither. 0644 has to still be 0644 after,
    // because storage.ts's store check reports exactly that as a finding.
    fs.chmodSync(path.join(configDir, "session.json"), 0o644);
    stageFetch(healthyRelay);
    await connectivityChecks.run(ctx());
    expect(fs.statSync(path.join(configDir, "session.json")).mode & 0o777).toBe(0o644);
  });

  it("reports the ticket exchange's ACTUAL status when the relay refuses the token", async () => {
    stageFetch((url) => (url.endsWith("/api/agent/ws-ticket") ? jsonResponse(401, { error: "no" }) : jsonResponse(200)));
    const results = await connectivityChecks.run(ctx());
    const ticket = results.find((r) => r.id === "net.ticket")!;
    expect(ticket.verdict).toBe("fail");
    expect(ticket.facts?.["status"]).toBe(401);
    expect(ticket.detail).toContain("401");
  });

  it("refuses to call a 200 that carries no ticket a successful exchange", async () => {
    // A captive portal or an inspecting proxy answers 200 with a page. The agent
    // parses this body and would reject it, so calling it healthy describes a
    // machine that cannot connect.
    stageFetch((url) =>
      url.endsWith("/api/agent/ws-ticket")
        ? new Response("<html>sign in</html>", {
            status: 200,
            headers: { "content-type": "text/html", date: SERVER_DATE },
          })
        : jsonResponse(200),
    );
    const ticket = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.ticket")!;
    expect(ticket.verdict).toBe("fail");
    expect(ticket.detail).toMatch(/not a connection ticket/);
    expect(ticket.facts?.["contentType"]).toMatch(/text\/html/);
  });

  it("refuses a 200 whose ticket is not the shape the relay issues", async () => {
    stageFetch((url) =>
      url.endsWith("/api/agent/ws-ticket") ? jsonResponse(200, { ticket: "nope" }) : jsonResponse(200),
    );
    const ticket = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.ticket")!;
    expect(ticket.verdict).toBe("fail");
  });

  it("never records the ticket it was issued", async () => {
    stageFetch(healthyRelay);
    const results = await connectivityChecks.run(ctx());
    // A ticket is a short-lived credential; the report is emailed to vendors.
    expect(JSON.stringify(results)).not.toContain(TICKET);
  });

  it("skips the ticket exchange when there is no stored session, rather than making one", async () => {
    fs.rmSync(path.join(configDir, "session.json"));
    stageFetch(() => jsonResponse(200));
    const ticket = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.ticket")!;
    expect(ticket.verdict).toBe("skipped");
    expect(ticket.detail).toMatch(/would mint a new/);
    expect(requests.urls.some((u) => u.includes("/api/agent/ws-ticket"))).toBe(false);
  });

  it("says the token is UNREADABLE, not absent, when it is in OS-protected storage", async () => {
    // A registered desktop install: the token is in safeStorage and this process
    // has no vault. "Never registered" would send its owner to re-register a
    // machine that is perfectly fine.
    fs.writeFileSync(
      path.join(configDir, "session.json"),
      JSON.stringify({ sessionCode: "AIC-ABCD-EFGH-IJKL", tokenProtected: true }),
    );
    stageFetch(() => jsonResponse(200));
    const ticket = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.ticket")!;
    expect(ticket.verdict).toBe("skipped");
    expect(ticket.detail).toMatch(/OS-protected storage/);
    expect(ticket.detail).not.toMatch(/no stored session/);
  });

  it("uses a supplied token vault, which is how the tray reaches a protected token", async () => {
    fs.writeFileSync(
      path.join(configDir, "session.json"),
      JSON.stringify({ sessionCode: "AIC-ABCD-EFGH-IJKL", tokenProtected: true }),
    );
    fs.writeFileSync(path.join(configDir, "session.token"), Buffer.from("cipher"));
    stageFetch(healthyRelay);
    const ticket = (
      await connectivityChecks.run(
        ctx({ tokenVault: { isAvailable: () => true, decrypt: () => "t".repeat(43) } }),
      )
    ).find((r) => r.id === "net.ticket")!;
    expect(ticket.verdict).toBe("ok");
    expect(requests.headers.some((h) => "Authorization" in h)).toBe(true);
  });

  it("fails the upgrade leg when nothing answers it", async () => {
    stageFetch(() => jsonResponse(200));
    upgrade.mode = "error";
    const ws = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.websocket")!;
    expect(ws.verdict).toBe("fail");
    expect(ws.detail).toMatch(/ECONNRESET/);
  });

  it("fails the upgrade leg when the handshake is BLACKHOLED rather than refused", async () => {
    // A firewall that drops the Upgrade answers nothing at all: no status, no
    // error, no close. Only the probe's own timeout ends it, and the timeout
    // has to produce a verdict rather than hang the command.
    stageFetch(() => jsonResponse(200));
    upgrade.mode = "silent";
    const ws = (await connectivityChecks.run(ctx({ networkTimeoutMs: 25 }))).find(
      (r) => r.id === "net.websocket",
    )!;
    expect(ws.verdict).toBe("fail");
    expect(ws.detail).toMatch(/timed out/);
  });

  it("settles the upgrade probe exactly once when a refusal is followed by an error", async () => {
    stageFetch(() => jsonResponse(200));
    upgrade.mode = "response-then-error";
    const ws = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.websocket")!;
    // The refusal won, and the error that arrived after it neither replaced the
    // verdict nor produced a second one.
    expect(ws.verdict).toBe("ok");
    expect(ws.facts?.["status"]).toBe(401);
    expect(ws.facts?.["error"]).toBeUndefined();
  });

  it("warns when something other than the relay answers the upgrade", async () => {
    stageFetch(() => jsonResponse(200));
    upgrade.mode = "open";
    const ws = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.websocket")!;
    expect(ws.verdict).toBe("warn");
    expect(ws.detail).toMatch(/not the AI Commander relay/);
  });

  it("does NOT call an intercepting proxy's 401 the relay's refusal", async () => {
    // A gateway that will not forward the upgrade answers 401 with an HTML login
    // page. The status alone is identical to the relay's; the body is not.
    stageFetch(() => jsonResponse(200));
    upgrade.contentType = "text/html";
    upgrade.body = "<html>Authentication required</html>";
    const ws = (await connectivityChecks.run(ctx())).find((r) => r.id === "net.websocket")!;
    expect(ws.verdict).toBe("warn");
    expect(ws.detail).toMatch(/shape the relay answers with/);
    // The proxy's own page is somebody else's text and stays out of the report.
    expect(JSON.stringify(ws)).not.toContain("Authentication required");
  });

  it("reports HTTPS failure without hiding the later legs", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw Object.assign(new Error("fetch failed"), { code: "ECONNREFUSED" });
      }),
    );
    const results = await connectivityChecks.run(ctx());
    expect(results.find((r) => r.id === "net.https")!.verdict).toBe("fail");
    // The ticket leg still RAN (and failed on its own), and the clock leg
    // reports honestly that it had nothing to compare against.
    expect(results.find((r) => r.id === "net.ticket")!.verdict).toBe("fail");
    expect(results.find((r) => r.id === "env.clock")!.verdict).toBe("skipped");
  });

  it("gives up on a resolver that never answers, inside the leg's own budget", async () => {
    // dns.lookup takes no AbortSignal, so without a bound of our own a
    // black-holing resolver holds the whole command open past every timeout the
    // caller was promised.
    vi.spyOn(dns.promises, "lookup").mockImplementation((() => new Promise(() => {})) as never);
    stageFetch(() => jsonResponse(200));
    vi.useRealTimers();
    const started = Date.now();
    const result = (await connectivityChecks.run(ctx({ networkTimeoutMs: 25 }))).find(
      (r) => r.id === "net.dns",
    )!;
    expect(result.verdict).toBe("fail");
    expect(result.detail).toMatch(/did not resolve within/);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("measures clock skew against the relay's Date header", async () => {
    stageFetch(healthyRelay);
    // Ten minutes ahead of the relay.
    vi.setSystemTime(new Date(new Date(SERVER_DATE).getTime() + 600_000));
    const clock = (await connectivityChecks.run(ctx())).find((r) => r.id === "env.clock")!;
    expect(clock.verdict).toBe("warn");
    expect(clock.facts?.["skewSeconds"]).toBe(600);
  });

  it("does not charge the ticket and upgrade legs to the clock", async () => {
    // The skew reading is taken when the Date header ARRIVES. Reading the local
    // clock in the clock check instead adds every leg that ran in between — up
    // to two full network timeouts — and warns a healthy machine about a clock
    // that is correct.
    stageFetch((url) => {
      if (url.endsWith("/api/agent/ws-ticket")) {
        // Time passes while the later legs run.
        vi.setSystemTime(new Date(Date.now() + 600_000));
        return jsonResponse(200, { ticket: TICKET });
      }
      return jsonResponse(200);
    });
    const clock = (await connectivityChecks.run(ctx())).find((r) => r.id === "env.clock")!;
    expect(clock.verdict).toBe("ok");
    expect(clock.facts?.["skewSeconds"]).toBe(0);
  });
});

describe("who answered the upgrade", () => {
  // The refusal SHAPE (401 + application/json + a string `error`) is copyable by
  // any intermediary, so it cannot identify the relay on its own — asserting
  // that it did reported a captive portal as a healthy WebSocket path. The one
  // thing an intermediary cannot copy is a publicly trusted certificate for the
  // relay's hostname, and the settings that take that anchor away are all
  // observable from here. Where the anchor is gone, the check says so instead.
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it("identifies the responder only over TLS anchored in Node's bundled roots", () => {
    delete process.env["NODE_TLS_REJECT_UNAUTHORIZED"];
    delete process.env["NODE_EXTRA_CA_CERTS"];
    delete process.env["NODE_OPTIONS"];
    expect(tlsAnchorCaveat("wss://relay.example/ws/agent?ticket=deadbeef")).toBeNull();
  });

  it("names the ambiguity when the connection is not TLS at all", () => {
    expect(tlsAnchorCaveat("ws://relay.example/ws/agent")).toMatch(/not made over TLS/);
  });

  it("names the ambiguity when certificate validation is off", () => {
    process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
    expect(tlsAnchorCaveat("wss://relay.example/ws/agent")).toMatch(/any responder is accepted/);
  });

  it("names the ambiguity when extra roots are trusted — how an inspecting proxy gets in", () => {
    process.env["NODE_EXTRA_CA_CERTS"] = "/etc/corp/ca.pem";
    expect(tlsAnchorCaveat("wss://relay.example/ws/agent")).toMatch(/outside Node's bundled store/);
  });

  it("names the ambiguity when the system trust store is the anchor", () => {
    process.env["NODE_OPTIONS"] = "--max-old-space-size=512 --use-openssl-ca";
    expect(tlsAnchorCaveat("wss://relay.example/ws/agent")).toMatch(/system trust store/);
  });

  it("names --use-system-ca, which this runtime has and which moves the anchor the same way", () => {
    // The caveat listed --use-openssl-ca and stopped there, while the Node the
    // agent runs on (v24) also has --use-system-ca: it makes the OS trust store
    // an anchor, so a corporate inspection CA installed system-wide is trusted
    // and an intercepting proxy passes as the relay. The whole verdict rests on
    // "an intermediary cannot hold a publicly trusted certificate for the relay
    // host", so a setting that widens the anchor and is not named makes the `ok`
    // unearned.
    process.env["NODE_OPTIONS"] = "--use-system-ca";
    expect(tlsAnchorCaveat("wss://relay.example/ws/agent")).toMatch(/operating system's trust store/);
  });

  it("finds an anchor-widening flag on the command line, not just in NODE_OPTIONS", () => {
    delete process.env["NODE_OPTIONS"];
    const saved = [...process.execArgv];
    process.execArgv.push("--use-system-ca");
    try {
      expect(tlsAnchorCaveat("wss://relay.example/ws/agent")).toMatch(/operating system's trust store/);
    } finally {
      process.execArgv.splice(0, process.execArgv.length, ...saved);
    }
  });

  it("does not read the NEGATION of a trust-store flag as the flag itself", () => {
    // `--no-use-system-ca` pins the bundled store: the assumption holding, not a
    // caveat. A caveat on a healthy machine is how this command loses its
    // credibility from the other side.
    process.env["NODE_OPTIONS"] = "--no-use-system-ca";
    expect(tlsAnchorCaveat("wss://relay.example/ws/agent")).toBeNull();
  });
});
