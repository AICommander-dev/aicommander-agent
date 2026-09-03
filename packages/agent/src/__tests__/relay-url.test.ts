import { describe, it, expect, afterEach } from "vitest";
import { DEFAULT_SERVER } from "@aicommander/protocol";
import { resolveTrustedServerUrl, assertSecureWsUrl } from "../relay-url.js";

const origDev = process.env["AICOMMANDER_DEV"];
afterEach(() => {
  if (origDev === undefined) delete process.env["AICOMMANDER_DEV"];
  else process.env["AICOMMANDER_DEV"] = origDev;
});

describe("resolveTrustedServerUrl — host-lock", () => {
  it("returns the canonical relay for empty/undefined input", () => {
    delete process.env["AICOMMANDER_DEV"];
    expect(resolveTrustedServerUrl(undefined)).toBe(DEFAULT_SERVER);
    expect(resolveTrustedServerUrl("")).toBe(DEFAULT_SERVER);
    expect(resolveTrustedServerUrl("   ")).toBe(DEFAULT_SERVER);
  });

  it("passes the canonical origin through (normalized)", () => {
    delete process.env["AICOMMANDER_DEV"];
    expect(resolveTrustedServerUrl(DEFAULT_SERVER)).toBe(DEFAULT_SERVER);
    expect(resolveTrustedServerUrl("https://aicommander.dev/")).toBe(DEFAULT_SERVER);
  });

  it("IGNORES a non-canonical https override without the dev flag (host-lock)", () => {
    delete process.env["AICOMMANDER_DEV"];
    expect(resolveTrustedServerUrl("https://evil.example.com")).toBe(DEFAULT_SERVER);
  });

  it("allows a non-canonical https relay only under AICOMMANDER_DEV=1", () => {
    process.env["AICOMMANDER_DEV"] = "1";
    expect(resolveTrustedServerUrl("https://staging.example.com")).toBe("https://staging.example.com");
  });

  it("allows loopback even without the dev flag (inherently local)", () => {
    delete process.env["AICOMMANDER_DEV"];
    expect(resolveTrustedServerUrl("http://localhost:8787")).toBe("http://localhost:8787");
    expect(resolveTrustedServerUrl("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787");
  });

  it("refuses a plaintext non-loopback relay even with the dev flag", () => {
    process.env["AICOMMANDER_DEV"] = "1";
    expect(resolveTrustedServerUrl("http://staging.example.com")).toBe(DEFAULT_SERVER);
  });

  it("falls back on a malformed URL", () => {
    process.env["AICOMMANDER_DEV"] = "1";
    expect(resolveTrustedServerUrl("not a url")).toBe(DEFAULT_SERVER);
  });
});

describe("assertSecureWsUrl", () => {
  it("accepts wss:// (with path + query)", () => {
    expect(() => assertSecureWsUrl("wss://aicommander.dev/ws/agent?ticket=abc")).not.toThrow();
  });

  it("accepts ws:// only for loopback dev targets", () => {
    expect(() => assertSecureWsUrl("ws://localhost:8787/ws/agent?ticket=abc")).not.toThrow();
    expect(() => assertSecureWsUrl("ws://127.0.0.1:8787/ws/agent?ticket=abc")).not.toThrow();
  });

  it("THROWS on a plaintext non-loopback socket", () => {
    expect(() => assertSecureWsUrl("ws://evil.example.com/ws/agent?ticket=abc")).toThrow(/plaintext/);
  });

  it("throws on a malformed URL", () => {
    expect(() => assertSecureWsUrl("::::")).toThrow();
  });
});
