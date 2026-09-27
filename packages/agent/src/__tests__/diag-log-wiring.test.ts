/**
 * The incident's unanswered question, answered from the file alone.
 *
 * On 2026-09-02 the observable facts on the affected machine were "one HTTPS
 * connection ~10-15 s after start, then silence" — the ws-ticket exchange was
 * failing and nothing said so. This asserts the wiring that makes that visible:
 * a refused ticket lands in the diagnostic log WITH its HTTP status, and neither
 * the session code nor the agent token comes with it.
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { closeDiagLog, flushDiagLog, initDiagLog } from "../diag-log.js";
import { runConnectionLoop } from "../connection.js";

afterEach(() => {
  closeDiagLog();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("diagnostic log ↔ connection wiring", () => {
  it("records a refused ws-ticket with its status, and no credentials", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aic-diag-wire-"));
    initDiagLog({ dir, role: "worker" });

    const sessionCode = "AIC-7K3P-WX9M-RTBN";
    const agentToken = "a".repeat(48);
    const ac = new AbortController();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        // One attempt is enough; abort so the backoff loop exits immediately.
        ac.abort();
        return { ok: false, status: 403, text: async () => "forbidden" } as Response;
      }),
    );

    await runConnectionLoop({
      serverUrl: "https://aic-diag.test",
      sessionCode,
      agentToken,
      signal: ac.signal,
      silent: true,
    });
    await flushDiagLog();

    const text = fs.readFileSync(path.join(dir, "worker.log"), "utf8");
    expect(text).toContain("conn.ticket_failed status=403");
    expect(text).not.toContain(sessionCode);
    expect(text).not.toContain(agentToken);
  });
});
