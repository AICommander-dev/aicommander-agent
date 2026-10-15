import { describe, expect, it } from "vitest";

import {
  isWebhookId,
  JOB_ENDED_RETRY_BASE_MS,
  JOB_ENDED_RETRY_MAX_MS,
  parseAgentJobEnded,
  WEBHOOK_ATTEMPT_OFFSETS_MS,
  WEBHOOK_DEADLINE_DEFAULT_SECONDS,
  WEBHOOK_DEADLINE_MAX_SECONDS,
  WEBHOOK_DEADLINE_MIN_SECONDS,
  WEBHOOK_MAX_ATTEMPTS,
} from "../job-events.js";

const WID = "0123456789abcdef0123456789abcdef";
const JID = "0123456789abcdef";
const base = { type: "agent:job_ended", webhookId: WID, jobId: JID, status: "exited", exitCode: 0, endedAt: 1_700_000_000_000 };

describe("isWebhookId", () => {
  it("accepts exactly 32 lowercase hex", () => {
    expect(isWebhookId(WID)).toBe(true);
    for (const bad of [WID.toUpperCase(), WID.slice(1), WID + "0", "g".repeat(32), 123, null, undefined]) {
      expect(isWebhookId(bad)).toBe(false);
    }
  });
});

describe("parseAgentJobEnded", () => {
  it("accepts valid frames", () => {
    expect(parseAgentJobEnded(base)).toEqual(base);
    expect(parseAgentJobEnded({ ...base, exitCode: -2_147_483_648 })?.exitCode).toBe(-2_147_483_648);
    expect(parseAgentJobEnded({ ...base, exitCode: 2_147_483_647 })?.exitCode).toBe(2_147_483_647);
    const unk = { ...base, status: "unknown", exitCode: null, endedAtApproximate: true };
    expect(parseAgentJobEnded(unk)).toEqual(unk);
  });

  it("drops unknown extra keys", () => {
    const out = parseAgentJobEnded({ ...base, extra: "x", url: "https://evil" });
    expect(out).toEqual(base);
    const polluted = JSON.parse(`{"type":"agent:job_ended","webhookId":"${WID}","jobId":"${JID}","status":"exited","exitCode":1,"endedAt":5,"__proto__":{"admin":true},"constructor":1}`);
    const p = parseAgentJobEnded(polluted);
    expect(p).toEqual({ ...base, exitCode: 1, endedAt: 5 });
    expect(Object.keys(p!)).not.toContain("constructor");
    expect((p as unknown as Record<string, unknown>).admin).toBeUndefined();
  });

  it("rejects malformed frames", () => {
    const bads: unknown[] = [
      null, undefined, "x", 1, [], [base],
      { ...base, type: "agent:job_state" },
      { ...base, webhookId: WID.toUpperCase() },
      { ...base, webhookId: WID.slice(1) },
      { ...base, webhookId: "z".repeat(32) },
      { ...base, jobId: JID.toUpperCase() },
      { ...base, jobId: JID + "0" },
      { ...base, jobId: 5 },
      { ...base, status: "running" },
      { ...base, status: "EXITED" },
      { ...base, exitCode: null },
      { ...base, exitCode: 1.5 },
      { ...base, exitCode: NaN },
      { ...base, exitCode: 2_147_483_648 },
      { ...base, exitCode: "0" },
      { ...base, status: "unknown", exitCode: 0 },
      { ...base, status: "unknown", exitCode: undefined },
      { ...base, endedAt: 0 },
      { ...base, endedAt: -1 },
      { ...base, endedAt: 1.5 },
      { ...base, endedAt: NaN },
      { ...base, endedAt: Infinity },
      { ...base, endedAt: Number.MAX_SAFE_INTEGER + 1 },
      { ...base, endedAt: "1" },
      { ...base, endedAtApproximate: "true" },
      { ...base, endedAtApproximate: null },
    ];
    for (const bad of bads) expect(parseAgentJobEnded(bad)).toBeUndefined();
  });

  it("never throws", () => {
    const hostile = Object.defineProperty({ ...base }, "status", {
      get() {
        throw new Error("boom");
      },
    });
    expect(parseAgentJobEnded(hostile)).toBeUndefined();
    const proxy = new Proxy({}, { get() { throw new Error("boom"); } });
    expect(parseAgentJobEnded(proxy)).toBeUndefined();
  });
});

describe("job event constants", () => {
  it("are internally consistent", () => {
    expect(WEBHOOK_ATTEMPT_OFFSETS_MS).toHaveLength(WEBHOOK_MAX_ATTEMPTS);
    expect(WEBHOOK_ATTEMPT_OFFSETS_MS[0]).toBe(0);
    expect(WEBHOOK_DEADLINE_MIN_SECONDS).toBeLessThan(WEBHOOK_DEADLINE_DEFAULT_SECONDS);
    expect(WEBHOOK_DEADLINE_DEFAULT_SECONDS).toBeLessThan(WEBHOOK_DEADLINE_MAX_SECONDS);
    expect(JOB_ENDED_RETRY_BASE_MS).toBeLessThan(JOB_ENDED_RETRY_MAX_MS);
  });
});
