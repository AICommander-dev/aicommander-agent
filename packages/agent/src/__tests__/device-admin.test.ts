import { describe, it, expect, vi, afterEach } from "vitest";
import {
  resolveAdminIdentifier,
  orderAdmins,
  fetchAdmins,
  blockAdmin,
  type AdminEntry,
} from "../device-admin.js";
import type { DeviceIdentity } from "../device.js";

const admins: AdminEntry[] = [
  { userId: "abc123-aaaa", maskedEmail: "lu****@wear****.com", alias: "a", linkedAt: "2026-01-01", lastSeenAt: null, blocked: false },
  { userId: "abc999-bbbb", maskedEmail: "ad***@gm***.com", alias: "b", linkedAt: "2026-01-02", lastSeenAt: null, blocked: false },
  { userId: "xyz789-cccc", maskedEmail: "jo*@ex****.io", alias: "c", linkedAt: "2026-01-03", lastSeenAt: null, blocked: false },
];

describe("resolveAdminIdentifier", () => {
  it("resolves a 1-based list index", () => {
    expect(resolveAdminIdentifier(admins, "1")).toEqual({ kind: "ok", admin: admins[0] });
    expect(resolveAdminIdentifier(admins, "3")).toEqual({ kind: "ok", admin: admins[2] });
  });

  it("rejects an out-of-range index", () => {
    expect(resolveAdminIdentifier(admins, "0").kind).toBe("not_found");
    expect(resolveAdminIdentifier(admins, "9").kind).toBe("not_found");
  });

  it("resolves an exact userId", () => {
    expect(resolveAdminIdentifier(admins, "xyz789-cccc")).toEqual({ kind: "ok", admin: admins[2] });
  });

  it("resolves an unambiguous userId prefix", () => {
    expect(resolveAdminIdentifier(admins, "xyz")).toEqual({ kind: "ok", admin: admins[2] });
  });

  it("reports ambiguity for a prefix matching several", () => {
    const r = resolveAdminIdentifier(admins, "abc");
    expect(r.kind).toBe("ambiguous");
    if (r.kind === "ambiguous") expect(r.matches).toHaveLength(2);
  });

  it("returns not_found for empty or unknown input", () => {
    expect(resolveAdminIdentifier(admins, "").kind).toBe("not_found");
    expect(resolveAdminIdentifier(admins, "nope").kind).toBe("not_found");
  });
});

describe("orderAdmins", () => {
  it("puts active accounts before blocked, preserving order within each group", () => {
    const mixed: AdminEntry[] = [
      { ...admins[0]!, blocked: true },
      { ...admins[1]!, blocked: false },
      { ...admins[2]!, blocked: true },
    ];
    const ordered = orderAdmins(mixed);
    expect(ordered.map((a) => a.userId)).toEqual([
      "abc999-bbbb", // the only active one, first
      "abc123-aaaa", // blocked, original order
      "xyz789-cccc",
    ]);
  });
});

const device: DeviceIdentity = { deviceId: "dev-1", deviceSecret: "sec-1" };

describe("timeout / unreachable handling", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("fetchAdmins throws a descriptive error (not the raw abort) when fetch rejects", async () => {
    // Simulate the AbortSignal.timeout firing — fetch rejects with a DOMException.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("The operation was aborted.", "TimeoutError");
      }),
    );
    await expect(fetchAdmins("https://x.test", device)).rejects.toThrow("Failed to list linked accounts");
    // The raw DOMException text must not leak through to the CLI.
    await expect(fetchAdmins("https://x.test", device)).rejects.not.toThrow("operation was aborted");
  });

  it("blockAdmin returns { ok: false } (never throws) when fetch rejects", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("The operation was aborted.", "TimeoutError");
      }),
    );
    const result = await blockAdmin("https://x.test", device, "abc123-aaaa");
    expect(result.ok).toBe(false);
    expect(result.error).toBe("unreachable");
  });
});
