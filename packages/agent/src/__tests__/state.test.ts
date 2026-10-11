import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// state.ts targets a fixed /var/run path that is not writable in tests, so we
// mock node:fs/promises with an in-memory filesystem keyed by path. This lets us
// assert the write/read/clear round-trip and the module's tolerance of a
// missing/garbled state file (all errors are swallowed by design).
const store = new Map<string, string>();

vi.mock("node:fs/promises", () => ({
  default: {
    mkdir: vi.fn(async () => undefined),
    open: vi.fn(async (file: string) => ({
      writeFile: vi.fn(async (data: string) => {
        store.set(file, data);
      }),
      close: vi.fn(async () => undefined),
    })),
    rename: vi.fn(async (from: string, to: string) => {
      if (!store.has(from)) throw new Error("ENOENT");
      store.set(to, store.get(from)!);
      store.delete(from);
    }),
    chmod: vi.fn(async () => undefined),
    readFile: vi.fn(async (file: string) => {
      if (!store.has(file)) throw new Error("ENOENT");
      return store.get(file)!;
    }),
    rm: vi.fn(async (file: string) => {
      store.delete(file);
    }),
  },
}));

import fsp from "node:fs/promises";
import { writeState, readState, clearState, type AgentState } from "../state.js";
import { CredentialStorageError } from "../credential-storage.js";

const sample: AgentState = {
  sessionCode: "AIC-WOLF-2345-WXYZ",
  pid: 4242,
  startedAt: "2026-06-14T00:00:00.000Z",
  serverUrl: "https://aicommander.dev",
};

beforeEach(() => {
  store.clear();
  vi.clearAllMocks();
  // A systemd-managed runner must not turn the dev cases into service cases.
  for (const key of ["AICOMMANDER_SERVICE", "NODE_ENV", "INVOCATION_ID", "JOURNAL_STREAM"]) {
    vi.stubEnv(key, undefined);
  }
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("state", () => {
  it("read returns null when no state file exists", async () => {
    expect(await readState()).toBeNull();
  });

  it("write then read returns the same state (round-trip)", async () => {
    await writeState(sample);
    expect(await readState()).toEqual(sample);
  });

  it("write creates the state directory recursively with 0700 mode", async () => {
    await writeState(sample);
    expect(vi.mocked(fsp.mkdir)).toHaveBeenCalledWith(
      expect.stringContaining("aicommander-agent"),
      { recursive: true, mode: 0o700 },
    );
  });

  it("writes the state file with restrictive 0700 dir and 0600 file perms", async () => {
    await writeState(sample);
    expect(vi.mocked(fsp.chmod)).toHaveBeenCalledWith(
      expect.stringContaining("aicommander-agent"),
      0o700,
    );
    expect(vi.mocked(fsp.open)).toHaveBeenCalledWith(
      expect.stringContaining(".state."),
      "wx",
      0o600,
    );
    expect(vi.mocked(fsp.chmod)).toHaveBeenCalledWith(
      expect.stringContaining("state.json"),
      0o600,
    );
  });

  it("clear removes a written state (subsequent read is null)", async () => {
    await writeState(sample);
    expect(await readState()).not.toBeNull();
    await clearState();
    expect(await readState()).toBeNull();
  });

  it("read tolerates a garbled (non-JSON) state file and returns null", async () => {
    // Write a known file, then corrupt its contents at the final state path.
    await writeState(sample);
    const writtenPath = vi.mocked(fsp.rename).mock.calls[0]![1] as string;
    store.set(writtenPath, "{ not valid json");
    expect(await readState()).toBeNull();
  });

  it("write throws in service mode when mkdir fails", async () => {
    process.env["AICOMMANDER_SERVICE"] = "1";
    vi.mocked(fsp.mkdir).mockRejectedValueOnce(new Error("EACCES"));
    await expect(writeState(sample)).rejects.toThrow(CredentialStorageError);
  });

  it("write swallows mkdir failure in dev (non-fatal, no throw)", async () => {
    vi.mocked(fsp.mkdir).mockRejectedValueOnce(new Error("EACCES"));
    await expect(writeState(sample)).resolves.toBeUndefined();
  });

  it("write swallows open failure in dev (non-fatal, no throw)", async () => {
    vi.mocked(fsp.open).mockRejectedValueOnce(new Error("EACCES"));
    await expect(writeState(sample)).resolves.toBeUndefined();
  });

  it("clear swallows rm failure (non-fatal, no throw)", async () => {
    vi.mocked(fsp.rm).mockRejectedValueOnce(new Error("EACCES"));
    await expect(clearState()).resolves.toBeUndefined();
  });

  it("cleans up the 0600 temp file when rename fails in dev (no orphaned credential file)", async () => {
    vi.mocked(fsp.rename).mockRejectedValueOnce(new Error("EXDEV"));
    await expect(writeState(sample)).resolves.toBeUndefined();

    // The temp file path the open() call created.
    const tmpPath = vi.mocked(fsp.open).mock.calls[0]![0] as string;
    expect(tmpPath).toContain(".state.");
    // It must have been unlinked (best-effort) and must NOT linger in the store.
    expect(vi.mocked(fsp.rm)).toHaveBeenCalledWith(tmpPath, { force: true });
    expect(store.has(tmpPath)).toBe(false);
    // And no real state.json was produced.
    expect(await readState()).toBeNull();
  });

  it("swallows a failure to unlink the temp file after a rename failure", async () => {
    vi.mocked(fsp.rename).mockRejectedValueOnce(new Error("EXDEV"));
    vi.mocked(fsp.rm).mockRejectedValueOnce(new Error("EACCES"));
    await expect(writeState(sample)).resolves.toBeUndefined();
  });
});
