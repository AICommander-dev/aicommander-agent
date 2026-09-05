import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CredentialStorageError,
  isStrictCredentialStorage,
  enforceCredentialStorageWrite,
} from "../credential-storage.js";

const KEYS = [
  "AICOMMANDER_SERVICE",
  "NODE_ENV",
  "INVOCATION_ID",
  "JOURNAL_STREAM",
] as const;

let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

describe("isStrictCredentialStorage", () => {
  it("is false in a typical dev shell", () => {
    expect(isStrictCredentialStorage()).toBe(false);
  });

  it("is true when AICOMMANDER_SERVICE=1", () => {
    process.env["AICOMMANDER_SERVICE"] = "1";
    expect(isStrictCredentialStorage()).toBe(true);
  });

  it("is true when NODE_ENV=production", () => {
    process.env["NODE_ENV"] = "production";
    expect(isStrictCredentialStorage()).toBe(true);
  });

  it("is true under systemd markers", () => {
    process.env["INVOCATION_ID"] = "abc";
    expect(isStrictCredentialStorage()).toBe(true);
    delete process.env["INVOCATION_ID"];
    process.env["JOURNAL_STREAM"] = "9:12345";
    expect(isStrictCredentialStorage()).toBe(true);
  });
});

describe("enforceCredentialStorageWrite", () => {
  it("throws CredentialStorageError with context", () => {
    expect(() => enforceCredentialStorageWrite("session credentials", new Error("EACCES"))).toThrow(
      CredentialStorageError,
    );
    expect(() => enforceCredentialStorageWrite("session credentials", new Error("EACCES"))).toThrow(
      /session credentials/i,
    );
  });
});
