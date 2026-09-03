// Machine-side file transfer (file-transfer.ts).
//
// Driven against a REAL temp directory and a stubbed `fetch`, because the two
// things worth proving are both about the filesystem:
//
//   * a push is ATOMIC — the destination is either the old file or the complete new
//     one, never a truncated one. The failure this prevents is a network hiccup
//     halfway through replacing a model checkpoint.
//   * a refusal never leaks a PATH. Paths are user data under the same invariant as
//     command text, and a refusal is the one place they would naturally be echoed.
//
// The relay side is stubbed rather than mocked away: the assertions include which
// URL was built (it must come from the agent's OWN configured origin, never from
// anything the relay said) and that the token travels as a header, not in the URL.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  mkdtemp, readFile, writeFile, appendFile, mkdir, readdir, stat, lstat, chmod,
  truncate, symlink, unlink, utimes, open, type FileHandle,
} from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { FILE_MAX_BYTES } from "@aicommander/protocol";
import { pullFileToRelay, pushFileFromRelay, sweepStaleTransferTemps } from "../file-transfer.js";

/**
 * A hook one test uses to hand back a doctored handle from `open`.
 *
 * `close` is an OWN property of every FileHandle, not something on the shared
 * prototype the write tests patch, so the only way to make a close misbehave the way
 * a filesystem does is to get at the handle the moment it is created. Null for every
 * other test: `open` then forwards to the real one untouched.
 */
const openHook = vi.hoisted(() => ({ current: null as null | ((handle: FileHandle) => FileHandle) }));

vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    default: actual,
    async open(...args: Parameters<typeof actual.open>) {
      const handle = await actual.open(...args);
      return openHook.current ? openHook.current(handle) : handle;
    },
  };
});

const SERVER = "https://relay.test";
const TOKEN = "one-time-token";

let dir: string;
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "aic-transfer-"));
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  openHook.current = null;
  // Some tests below spy on the shared FileHandle prototype; leaving one of those in
  // place would quietly break every later test that touches a file.
  vi.restoreAllMocks();
});

/** Every string in a refusal, so a path leak anywhere is caught. */
function refusalText(result: unknown): string {
  return JSON.stringify(result);
}

/**
 * The prototype every FileHandle shares, so a test can make one of its methods
 * misbehave the way a real filesystem does under stress. Node exposes no other way
 * in: the handle is created inside the module under test, and the interesting
 * failures (a write that accepts only part of its buffer) cannot be provoked from
 * the outside on a healthy tmpdir.
 */
/** The one `write` overload the transfer loop uses, in a shape a stub can forward. */
type RawWrite = (
  this: FileHandle,
  buffer: Buffer,
  offset: number,
  length: number,
  position?: number | null,
) => Promise<{ bytesWritten: number; buffer: Buffer }>;

async function fileHandlePrototype(): Promise<FileHandle> {
  const probe = join(dir, ".probe");
  const handle = await open(probe, "w");
  const proto = Object.getPrototypeOf(handle) as FileHandle;
  await handle.close();
  await unlink(probe);
  return proto;
}

describe("pullFileToRelay", () => {
  it("uploads a real file and reports the size it sent", async () => {
    const path = join(dir, "out.bin");
    await writeFile(path, Buffer.alloc(1234, 7));
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ ok: true, bytes: 1234 }),
    });

    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN, maxBytes: 10_000 });
    expect(result).toEqual({ ok: true, kind: "pulled", bytes: 1234 });

    const [url, init] = fetchMock.mock.calls[0]!;
    // Built from the agent's own trusted origin — the relay never supplies a URL.
    expect(url).toBe(`${SERVER}/api/v1/blob`);
    expect(init.method).toBe("PUT");
    // The token is a header, never a query parameter: a URL ends up in proxy logs
    // and shell history, and this credential can write to someone's machine.
    expect(init.headers["X-AIC-Blob-Token"]).toBe(TOKEN);
    expect(String(url)).not.toContain(TOKEN);
  });

  it("refuses a missing file without opening a socket", async () => {
    const result = await pullFileToRelay({
      serverUrl: SERVER,
      path: join(dir, "nope.bin"),
      token: TOKEN,
      maxBytes: 10_000,
    });
    expect(result).toMatchObject({ ok: false, reason: "not_found" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a directory", async () => {
    const sub = join(dir, "adir");
    await mkdir(sub);
    const result = await pullFileToRelay({ serverUrl: SERVER, path: sub, token: TOKEN, maxBytes: 10_000 });
    expect(result).toMatchObject({ ok: false, reason: "not_a_file" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses an oversized file by STAT, before transferring anything", async () => {
    const path = join(dir, "big.bin");
    await writeFile(path, Buffer.alloc(5000));
    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN, maxBytes: 1000 });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
    // The point of checking first: a 4 GB checkpoint costs a stat, not minutes of
    // upload that the relay then cuts off at the cap.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a relative path", async () => {
    const result = await pullFileToRelay({
      serverUrl: SERVER,
      path: "relative.bin",
      token: TOKEN,
      maxBytes: 10_000,
    });
    expect(result).toMatchObject({ ok: false, reason: "invalid_request" });
  });

  it("fails when the relay stored a different number of bytes", async () => {
    const path = join(dir, "out.bin");
    await writeFile(path, Buffer.alloc(100));
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ ok: true, bytes: 40 }) });

    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN, maxBytes: 10_000 });
    // Reporting success here would hand the caller a corrupt file with no reason
    // to suspect it.
    expect(result).toMatchObject({ ok: false, reason: "transfer_failed" });
  });

  it("maps the relay's 413 back to a size refusal", async () => {
    const path = join(dir, "out.bin");
    await writeFile(path, Buffer.alloc(10));
    fetchMock.mockResolvedValue({ ok: false, status: 413, json: async () => ({}) });
    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN, maxBytes: 10_000 });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
  });

  it("clamps a relay-supplied ceiling to the machine's own", async () => {
    const path = join(dir, "huge.bin");
    // Sparse: `stat` reports the full size, nothing is actually allocated.
    await writeFile(path, "");
    await truncate(path, FILE_MAX_BYTES + 1);

    for (const maxBytes of [undefined, FILE_MAX_BYTES * 10, Number.NaN, -1, 1.5, "1e9" as never]) {
      const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN, maxBytes });
      // A missing field used to compare `size > undefined` — always false — which
      // deleted this machine's ceiling entirely. The relay asks for a limit; the
      // machine decides what leaves it.
      expect(result).toMatchObject({ ok: false, reason: "too_large" });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still honours a ceiling BELOW its own", async () => {
    const path = join(dir, "small.bin");
    await writeFile(path, Buffer.alloc(2000));
    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN, maxBytes: 1000 });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
  });

  it("sends exactly the size it declared when the file GROWS mid-read", async () => {
    // The advertised use case is a log too big to print — i.e. a file a running job
    // is appending to. Unbounded, the read runs past the declared Content-Length,
    // undici rejects the body and the whole transfer dies as an opaque failure.
    const path = join(dir, "train.log");
    const original = 300_000;
    await writeFile(path, Buffer.alloc(original, 1));

    let received = 0;
    fetchMock.mockImplementation(async (_url: string, init: { body: ReadableStream }) => {
      await appendFile(path, Buffer.alloc(100_000, 2));
      const reader = init.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += (value as Uint8Array).length;
      }
      return { ok: true, status: 200, json: async () => ({ bytes: received }) };
    });

    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN });
    expect(result).toEqual({ ok: true, kind: "pulled", bytes: original });
    // The caller gets the snapshot the size check was made against — no more.
    expect(received).toBe(original);
  });

  it("names a file that SHRANK mid-read instead of failing opaquely", async () => {
    const path = join(dir, "rotated.log");
    await writeFile(path, Buffer.alloc(300_000, 1));

    fetchMock.mockImplementation(async (_url: string, init: { body: ReadableStream }) => {
      await truncate(path, 10);
      const reader = init.body.getReader();
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
      }
      // What undici does when the declared Content-Length is not met.
      throw new TypeError("fetch failed");
    });

    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN });
    expect(result).toMatchObject({ ok: false, reason: "transfer_failed" });
    // "Upload to the relay failed" would send the user looking at their network.
    expect(refusalText(result)).toContain("shrank");
  });

  it("does not blame the FILE when the upload itself is cut off", async () => {
    // The mirror of the test above, and the reason it exists: the shrink message is
    // only correct when the file was read to its END and was short. A dropped
    // connection or a relay 5xx before the body finished is also `sent < size`, and
    // reporting THAT as a shrink points the user at a file that is perfectly fine.
    const path = join(dir, "steady.log");
    await writeFile(path, Buffer.alloc(300_000, 1));

    fetchMock.mockImplementation(async (_url: string, init: { body: ReadableStream }) => {
      const reader = init.body.getReader();
      // Some bytes go out, then the request dies under the still-unfinished read.
      await reader.read();
      await reader.cancel();
      throw new TypeError("fetch failed");
    });

    const result = await pullFileToRelay({ serverUrl: SERVER, path, token: TOKEN });
    expect(result).toMatchObject({ ok: false, reason: "transfer_failed" });
    expect(refusalText(result)).not.toContain("shrank");
    expect(refusalText(result)).toContain("interrupted");
    // The file it was reading is untouched and still its original length.
    expect((await stat(path)).size).toBe(300_000);
  });

  it("never puts the path in a refusal", async () => {
    const secret = join(dir, "SECRET-FILENAME.bin");
    const missing = await pullFileToRelay({ serverUrl: SERVER, path: secret, token: TOKEN, maxBytes: 10 });
    expect(refusalText(missing)).not.toContain("SECRET-FILENAME");

    await writeFile(secret, Buffer.alloc(500));
    const tooBig = await pullFileToRelay({ serverUrl: SERVER, path: secret, token: TOKEN, maxBytes: 10 });
    expect(refusalText(tooBig)).not.toContain("SECRET-FILENAME");

    fetchMock.mockRejectedValue(new Error(`connect ECONNREFUSED reading ${secret}`));
    const failed = await pullFileToRelay({ serverUrl: SERVER, path: secret, token: TOKEN, maxBytes: 10_000 });
    // The thrown error embedded the path; the refusal must not.
    expect(refusalText(failed)).not.toContain("SECRET-FILENAME");
  });
});

describe("pushFileFromRelay", () => {
  function bodyOf(bytes: number[]): { ok: boolean; status: number; body: ReadableStream } {
    return {
      ok: true,
      status: 200,
      body: new Response(Buffer.from(bytes)).body as ReadableStream,
    };
  }

  it("writes the file and reports the byte count", async () => {
    const dest = join(dir, "in.bin");
    fetchMock.mockResolvedValue(bodyOf([1, 2, 3, 4]));

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 4,
    });
    expect(result).toEqual({ ok: true, kind: "pushed", bytes: 4 });
    expect([...(await readFile(dest))]).toEqual([1, 2, 3, 4]);
  });

  it("finishes a SHORT write instead of renaming a truncated file into place", async () => {
    // `write()` may accept fewer bytes than it was handed — at an ENOSPC boundary, on
    // a signal, on some network filesystems. The write STREAM this loop replaced
    // retried that for free; the handle does not.
    //
    // The partial write here is real, not a faked return value: the stub forwards a
    // SHORTER length to the genuine write, so exactly one byte reaches the disk and
    // `bytesWritten` honestly reports one. Code that trusts the chunk length instead
    // therefore leaves a file two bytes short while its counter says 4096 — which is
    // why this test reads the destination back rather than asserting on the counter,
    // which would agree with itself either way.
    const dest = join(dir, "dataset.bin");
    const payload = Array.from({ length: 4096 }, (_, i) => i % 251);

    const proto = await fileHandlePrototype();
    const writable = proto as unknown as { write: RawWrite };
    const realWrite = writable.write;
    let shortWrites = 0;
    // Assigned rather than vi.spyOn'd: `write` is overloaded eight ways, and a stub
    // that has to forward its arguments is far clearer without that ceremony.
    writable.write = function (buffer, offset, length, position) {
      if (shortWrites < 2 && length > 1) {
        shortWrites++;
        return realWrite.call(this, buffer, offset, 1, position);
      }
      return realWrite.call(this, buffer, offset, length, position);
    };

    try {
      fetchMock.mockResolvedValue(bodyOf(payload));
      const result = await pushFileFromRelay({
        serverUrl: SERVER,
        destPath: dest,
        token: TOKEN,
        expectedBytes: payload.length,
      });
      expect(result).toEqual({ ok: true, kind: "pushed", bytes: payload.length });
      // The bytes the guard vouched for are the bytes that are actually there.
      expect([...(await readFile(dest))]).toEqual(payload);
    } finally {
      writable.write = realWrite;
    }
    // The stub really did fire; without this the test would pass on a run where the
    // write loop never took the short path at all.
    expect(shortWrites).toBeGreaterThan(0);
  });

  it("refuses instead of renaming when CLOSING the temp file fails", async () => {
    // A close is where deferred write errors land: on a buffered or network
    // filesystem the ENOSPC or I/O fault belonging to an earlier `write()` is
    // reported here, so the bytes on disk may be nothing like what the counters
    // believe. Swallowing that and renaming anyway installs a corrupt file over a
    // good one and calls it a success.
    //
    // The failure is injected at the one point Node gives no other way to reach, but
    // it is not a faked outcome: the stub performs the REAL close first, so the
    // descriptor is genuinely spent and the temp file genuinely on disk. What the
    // assertions then prove is entirely the module's own doing — that a close which
    // reported an error stops the rename and cleans up after itself.
    const dest = join(dir, "model.ckpt");
    await writeFile(dest, "ORIGINAL");
    fetchMock.mockResolvedValue(bodyOf([1, 2, 3, 4]));

    let closeFailures = 0;
    openHook.current = (handle) => {
      const realClose = handle.close.bind(handle);
      handle.close = async () => {
        await realClose();
        // Only the transfer's own close fails; failing a second one would break the
        // cleanup path this test is here to check.
        if (closeFailures > 0) return;
        closeFailures++;
        throw Object.assign(new Error(`EIO: i/o error, close '${dest}'`), { code: "EIO" });
      };
      return handle;
    };

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 4,
    });

    // The stub really did fire — otherwise this passes against any implementation.
    expect(closeFailures).toBe(1);
    expect(result).toMatchObject({ ok: false, reason: "unwritable" });
    // The point of the whole exercise: the old file is still the old file.
    expect(await readFile(dest, "utf8")).toBe("ORIGINAL");
    expect((await readdir(dir)).filter((f) => f.includes("aic-transfer"))).toEqual([]);
    expect(refusalText(result)).not.toContain("model.ckpt");
  });

  it("leaves an existing file untouched when the download ends early", async () => {
    const dest = join(dir, "model.ckpt");
    await writeFile(dest, "ORIGINAL");
    fetchMock.mockResolvedValue(bodyOf([9, 9]));

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      // The relay said 100 bytes; only 2 arrived.
      expectedBytes: 100,
    });
    expect(result).toMatchObject({ ok: false, reason: "transfer_failed" });
    // The whole reason for writing to a temp file first: a half-finished transfer
    // must not replace a good checkpoint with a broken one.
    expect(await readFile(dest, "utf8")).toBe("ORIGINAL");
  });

  it("leaves no temp file behind after a failed transfer", async () => {
    const dest = join(dir, "out.bin");
    fetchMock.mockResolvedValue(bodyOf([1]));
    await pushFileFromRelay({ serverUrl: SERVER, destPath: dest, token: TOKEN, expectedBytes: 50 });

    const leftovers = (await readdir(dir)).filter((f) => f.includes("aic-transfer"));
    expect(leftovers).toEqual([]);
  });

  it("writes the temp file beside the destination, not in /tmp", async () => {
    // A rename is only atomic within one filesystem, and on a NAS or in a
    // container /tmp is routinely a different mount — writing there first would
    // silently downgrade the atomicity guarantee to a copy. So this observes the
    // destination directory WHILE the body is still streaming: a partial file must
    // be visible there, under a temp name, and must be gone by the end.
    const sub = join(dir, "data");
    await mkdir(sub);
    const dest = join(sub, "f.bin");

    let midStream: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        controller.enqueue(new Uint8Array([1]));
        // Let the writer flush the first chunk, then look at the directory.
        await new Promise((r) => setTimeout(r, 20));
        midStream = await readdir(sub);
        release();
        controller.enqueue(new Uint8Array([2]));
        controller.close();
      },
    });
    fetchMock.mockResolvedValue({ ok: true, status: 200, body });

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 2,
    });
    await gate;

    expect(result).toMatchObject({ ok: true, bytes: 2 });
    // Mid-transfer the partial bytes were in the DESTINATION's directory...
    expect(midStream.filter((f) => f.includes("aic-transfer"))).toHaveLength(1);
    // ...and the destination itself only appears, complete, after the rename.
    expect(midStream).not.toContain("f.bin");
    expect((await stat(dest)).size).toBe(2);
    expect((await readdir(sub)).filter((f) => f.includes("aic-transfer"))).toEqual([]);
  });

  it("refuses a destination whose parent does not exist", async () => {
    fetchMock.mockResolvedValue(bodyOf([1]));
    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: join(dir, "missing-dir", "f.bin"),
      token: TOKEN,
      expectedBytes: 1,
    });
    expect(result).toMatchObject({ ok: false, reason: "unwritable" });
  });

  it("refuses a relative destination without calling the relay", async () => {
    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: "relative.bin",
      token: TOKEN,
      expectedBytes: 1,
    });
    expect(result).toMatchObject({ ok: false, reason: "invalid_request" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends the token as a header and builds the URL from its own relay origin", async () => {
    fetchMock.mockResolvedValue(bodyOf([1]));
    await pushFileFromRelay({
      serverUrl: `${SERVER}/`,
      destPath: join(dir, "f.bin"),
      token: TOKEN,
      expectedBytes: 1,
    });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`${SERVER}/api/v1/blob`);
    expect(init.headers["X-AIC-Blob-Token"]).toBe(TOKEN);
  });

  it("refuses an oversized push before opening a socket", async () => {
    const dest = join(dir, "huge.bin");
    fetchMock.mockResolvedValue(bodyOf([1]));

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 5000,
      maxBytes: 1000,
    });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
    // Same bargain as the pull side: a refusal must cost nothing, and above all it
    // must cost no bytes on the user's disk.
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await readdir(dir)).toEqual([]);
  });

  it("defaults its ceiling to FILE_MAX_BYTES when the caller names none", async () => {
    fetchMock.mockResolvedValue(bodyOf([1]));
    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: join(dir, "huge.bin"),
      token: TOKEN,
      expectedBytes: FILE_MAX_BYTES + 1,
    });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("aborts mid-stream when the relay sends more than it declared", async () => {
    const dest = join(dir, "out.bin");
    // The relay declared 4 bytes and is handing back far more — a broken retention
    // sweep, or a relay trying to fill the disk. Either way the write must stop.
    fetchMock.mockResolvedValue(bodyOf(Array.from({ length: 4096 }, () => 7)));

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 4,
    });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
    // Nothing at the destination, and no half-written temp file left occupying the
    // space the abort was supposed to save.
    await expect(stat(dest)).rejects.toThrow();
    expect(await readdir(dir)).toEqual([]);
  });

  it("stops writing at the cap rather than after the whole body has landed", async () => {
    const dest = join(dir, "out.bin");
    let pulled = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(1024));
        if (pulled > 64) controller.close();
      },
    });
    fetchMock.mockResolvedValue({ ok: true, status: 200, body });

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 1024,
    });
    expect(result).toMatchObject({ ok: false, reason: "too_large" });
    // The point of capping inside the pipeline: the source is torn down a chunk or
    // two past the limit, not after all 64 KiB have been read and written.
    expect(pulled).toBeLessThan(10);
  });

  it("preserves the mode of the file it overwrites", async () => {
    const dest = join(dir, "dataset.csv");
    await writeFile(dest, "OLD");
    await chmod(dest, 0o644);
    fetchMock.mockResolvedValue(bodyOf([1, 2, 3]));

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 3,
    });
    expect(result).toMatchObject({ ok: true, bytes: 3 });
    // Inheriting 0644 is what keeps the non-root job that reads this dataset
    // working; the temp file's own 0600 would have locked it out.
    expect((await stat(dest)).mode & 0o777).toBe(0o644);
  });

  it("does not carry a setuid bit over from the file it overwrites", async () => {
    const dest = join(dir, "helper");
    await writeFile(dest, "OLD");
    await chmod(dest, 0o4755);
    fetchMock.mockResolvedValue(bodyOf([9, 9]));

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 2,
    });
    expect(result).toMatchObject({ ok: true, bytes: 2 });
    const { mode } = await stat(dest);
    // The rwx bits — including execute — still come over: a replacement of an
    // executable script that stopped being executable would be a broken push.
    expect(mode & 0o777).toBe(0o755);
    // The setuid bit does not. It was granted to the PREVIOUS contents; re-arming
    // it around bytes the pusher supplied is not the transfer path's call to make.
    expect(mode & 0o7000).toBe(0);
  });

  it("keeps 0600 for a file that did not exist before", async () => {
    const dest = join(dir, "fresh.bin");
    fetchMock.mockResolvedValue(bodyOf([1]));
    await pushFileFromRelay({ serverUrl: SERVER, destPath: dest, token: TOKEN, expectedBytes: 1 });
    // Nothing said who should be able to read this, so the private default stands.
    expect((await stat(dest)).mode & 0o777).toBe(0o600);
  });

  it("refuses a negative or fractional expected size", async () => {
    for (const expectedBytes of [-1, 1.5, Number.NaN]) {
      const result = await pushFileFromRelay({
        serverUrl: SERVER,
        destPath: join(dir, "f.bin"),
        token: TOKEN,
        expectedBytes,
      });
      expect(result).toMatchObject({ ok: false, reason: "invalid_request" });
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  /** The `.part` file a push is currently writing, found by its naming. */
  async function tempFileIn(where: string): Promise<string | undefined> {
    const name = (await readdir(where)).find((f) => f.startsWith(".aic-transfer-"));
    return name ? join(where, name) : undefined;
  }

  /** A body that lets the test act once, mid-stream, before the last chunk lands. */
  function gatedBody(act: () => Promise<void>): ReadableStream<Uint8Array> {
    let acted = false;
    return new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (!acted) {
          controller.enqueue(new Uint8Array([1]));
          await new Promise((r) => setTimeout(r, 20));
          await act();
          acted = true;
          return;
        }
        controller.enqueue(new Uint8Array([2]));
        controller.close();
      },
    });
  }

  it("cannot be redirected by swapping the temp file for a symlink", async () => {
    // The privesc this closes: the agent usually runs as root, the temp file sits in
    // a CALLER-CHOSEN directory, and a local user who can write there replaces the
    // name with a symlink while the bytes stream. Applied by name, the chmod/chown
    // that inherits the destination's identity then landed on the victim.
    const dest = join(dir, "dataset.csv");
    await writeFile(dest, "OLD");
    await chmod(dest, 0o644);

    const victim = join(dir, "victim");
    await writeFile(victim, "PRIVATE");
    await chmod(victim, 0o600);

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      body: gatedBody(async () => {
        const temp = await tempFileIn(dir);
        expect(temp).toBeTruthy();
        await unlink(temp!);
        await symlink(victim, temp!);
      }),
    });

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 2,
    });
    expect(result).toMatchObject({ ok: true, bytes: 2 });

    // The swap bought the attacker nothing: every write after the create went
    // through the descriptor, which still points at the file the agent made.
    const after = await stat(victim);
    expect(after.mode & 0o777).toBe(0o600);
    expect(await readFile(victim, "utf8")).toBe("PRIVATE");
    // The destination is deliberately not asserted on: the final rename is by name
    // and cannot be otherwise (Node exposes no renameat), so a swapped name does
    // move the planted link into place. That is not an escalation — it needs write
    // access to a directory in which the attacker could create the file anyway.
  });

  it("keeps the temp file private while it is only partly written", async () => {
    let midMode: number | undefined;
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      body: gatedBody(async () => {
        const temp = await tempFileIn(dir);
        midMode = (await lstat(temp!)).mode & 0o777;
      }),
    });

    await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: join(dir, "f.bin"),
      token: TOKEN,
      expectedBytes: 2,
    });
    // O_EXCL|0600: nobody reads a half-written blob, and the create refuses to
    // truncate or follow whatever might already sit at that name.
    expect(midMode).toBe(0o600);
  });

  it("does not inherit identity through a symlinked destination", async () => {
    const target = join(dir, "target");
    await writeFile(target, "T");
    await chmod(target, 0o666);
    const dest = join(dir, "link");
    await symlink(target, dest);

    fetchMock.mockResolvedValue(bodyOf([5]));
    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 1,
    });
    expect(result).toMatchObject({ ok: true, bytes: 1 });
    // `stat` would have resolved the link and donated the target's 0666 to bytes
    // the pusher supplied; `lstat` sees a symlink, which is not a file we inherit
    // from, so the private default stands.
    expect((await lstat(dest)).mode & 0o777).toBe(0o600);
    expect(await readFile(target, "utf8")).toBe("T");
  });

  it("stops before the rename when the connection is revoked mid-transfer", async () => {
    const dest = join(dir, "model.ckpt");
    await writeFile(dest, "ORIGINAL");
    const ac = new AbortController();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      body: gatedBody(async () => { ac.abort(); }),
    });

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: dest,
      token: TOKEN,
      expectedBytes: 2,
      signal: ac.signal,
    });
    expect(result).toMatchObject({ ok: false, reason: "transfer_failed" });
    // Revoking access has to mean the file is not replaced — the rename is the
    // moment a push becomes visible on the machine.
    expect(await readFile(dest, "utf8")).toBe("ORIGINAL");
    expect((await readdir(dir)).filter((f) => f.includes("aic-transfer"))).toEqual([]);
  });

  it("stops before the rename when the revocation lands during the identity step", async () => {
    // The window a single pre-rename check misses: chmod, chown and close are all
    // awaited, and a revocation arriving in the middle of them used to sail past a
    // check made before they started and land the file anyway. Aborting from inside
    // chmod puts the revocation exactly there.
    const dest = join(dir, "model.ckpt");
    await writeFile(dest, "ORIGINAL");
    await chmod(dest, 0o644);
    const ac = new AbortController();

    const proto = await fileHandlePrototype();
    const realChmod = proto.chmod;
    proto.chmod = async function (this: FileHandle, mode: number) {
      ac.abort();
      return realChmod.call(this, mode);
    };

    try {
      fetchMock.mockResolvedValue(bodyOf([1, 2]));
      const result = await pushFileFromRelay({
        serverUrl: SERVER,
        destPath: dest,
        token: TOKEN,
        expectedBytes: 2,
        signal: ac.signal,
      });
      expect(result).toMatchObject({ ok: false, reason: "transfer_failed" });
    } finally {
      proto.chmod = realChmod;
    }
    // Withdrawn access has to mean the destination is not replaced, however late the
    // withdrawal arrives — and nothing is left lying beside it either.
    expect(await readFile(dest, "utf8")).toBe("ORIGINAL");
    expect((await readdir(dir)).filter((f) => f.includes("aic-transfer"))).toEqual([]);
  });

  it("sweeps a stale .part left by an earlier crash, but not a fresh one", async () => {
    const orphan = join(dir, ".aic-transfer-0123456789abcdef.part");
    await writeFile(orphan, Buffer.alloc(64));
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
    await utimes(orphan, twoDaysAgo, twoDaysAgo);

    const fresh = join(dir, ".aic-transfer-fedcba9876543210.part");
    await writeFile(fresh, Buffer.alloc(64));

    fetchMock.mockResolvedValue(bodyOf([1]));
    await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: join(dir, "f.bin"),
      token: TOKEN,
      expectedBytes: 1,
    });

    // A crash, an update or a power loss leaves up to FILE_MAX_BYTES behind with
    // nothing to clean it up; repeated interruptions fill the user's disk.
    await expect(stat(orphan)).rejects.toThrow();
    // Age is what makes the sweep safe: a file young enough to be someone's
    // in-flight transfer is left alone even though the name matches.
    await expect(stat(fresh)).resolves.toBeTruthy();
  });

  it("never sweeps a temp file this process is still writing", async () => {
    let sweptWhileWriting = 0;
    let survivor: string | undefined;
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      body: gatedBody(async () => {
        survivor = await tempFileIn(dir);
        // Ten days into the future: age alone would condemn this file. The process's
        // own knowledge of what it has open is what saves it.
        sweptWhileWriting = await sweepStaleTransferTemps(dir, Date.now() + 10 * 86_400_000);
      }),
    });

    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: join(dir, "f.bin"),
      token: TOKEN,
      expectedBytes: 2,
    });
    expect(sweptWhileWriting).toBe(0);
    expect(survivor).toBeTruthy();
    expect(result).toMatchObject({ ok: true, bytes: 2 });
  });

  it("leaves files that are not ours alone", async () => {
    const notOurs = join(dir, ".aic-transfer-notourname.part");
    const alsoNot = join(dir, "important.part");
    await writeFile(notOurs, "x");
    await writeFile(alsoNot, "x");
    const old = new Date(Date.now() - 30 * 86_400_000);
    await utimes(notOurs, old, old);
    await utimes(alsoNot, old, old);

    expect(await sweepStaleTransferTemps(dir)).toBe(0);
    await expect(stat(notOurs)).resolves.toBeTruthy();
    await expect(stat(alsoNot)).resolves.toBeTruthy();
  });

  it("never puts the destination path in a refusal", async () => {
    fetchMock.mockResolvedValue(bodyOf([1]));
    const result = await pushFileFromRelay({
      serverUrl: SERVER,
      destPath: join(dir, "SECRET-DEST", "f.bin"),
      token: TOKEN,
      expectedBytes: 1,
    });
    expect(refusalText(result)).not.toContain("SECRET-DEST");
  });
});
