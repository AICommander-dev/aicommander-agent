import { describe, it, expect, vi, afterEach } from "vitest";
import { register } from "../register.js";
import type { DeviceIdentity } from "../device.js";

const device: DeviceIdentity = { deviceId: "dev-1", deviceSecret: "sec-1" };

function mockFetchOnce(): { calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: { body: string }) => {
      calls.push(JSON.parse(init.body));
      return {
        ok: true,
        json: async () => ({ sessionCode: "AIC-WOLF-2345-WXYZ", agentToken: "tok" }),
      } as unknown as Response;
    }),
  );
  return { calls };
}

afterEach(() => vi.unstubAllGlobals());

describe("register() body", () => {
  it("normal startup sends currentCode and no forceNew", async () => {
    const { calls } = mockFetchOnce();
    await register("https://x.test", device, { currentCode: "AIC-WOLF-2345-WXYZ" });
    expect(calls[0]!.currentCode).toBe("AIC-WOLF-2345-WXYZ");
    expect(calls[0]!.forceNew).toBeUndefined();
  });

  it("forceNew sends forceNew and omits currentCode", async () => {
    const { calls } = mockFetchOnce();
    await register("https://x.test", device, { forceNew: true, currentCode: "AIC-WOLF-2345-WXYZ" });
    expect(calls[0]!.forceNew).toBe(true);
    expect(calls[0]!.currentCode).toBeUndefined();
  });

  it("first install (no stored code, no forceNew) sends neither", async () => {
    const { calls } = mockFetchOnce();
    await register("https://x.test", device, {});
    expect(calls[0]!.forceNew).toBeUndefined();
    expect(calls[0]!.currentCode).toBeUndefined();
    expect(calls[0]!.deviceId).toBe("dev-1");
  });

  it("includes hostname/platform/arch/agentVersion in the body", async () => {
    const { calls } = mockFetchOnce();
    await register("https://x.test", device, {});
    expect(typeof calls[0]!.hostname).toBe("string");
    expect(calls[0]!.platform).toBe(process.platform);
    expect(calls[0]!.arch).toBe(process.arch);
    expect(typeof calls[0]!.agentVersion).toBe("string");
  });
});

describe("register() failure branches", () => {
  it("throws with the status code on a non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 503,
        text: async () => "service unavailable",
      } as unknown as Response)),
    );
    await expect(register("https://x.test", device, {})).rejects.toThrow(
      /Registration failed \(503\): service unavailable/,
    );
  });

  it("propagates a network/fetch rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );
    await expect(register("https://x.test", device, {})).rejects.toThrow(/ECONNREFUSED/);
  });

  it("propagates a malformed JSON body on an ok response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        json: async () => {
          throw new SyntaxError("Unexpected token < in JSON");
        },
      } as unknown as Response)),
    );
    await expect(register("https://x.test", device, {})).rejects.toThrow(/Unexpected token/);
  });

  it("posts to the /api/register endpoint", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({ sessionCode: "AIC-X", agentToken: "tok" }),
    } as unknown as Response));
    vi.stubGlobal("fetch", fetchMock);
    await register("https://x.test", device, {});
    expect(fetchMock).toHaveBeenCalledWith(
      "https://x.test/api/register",
      expect.objectContaining({ method: "POST" }),
    );
  });
});
