// File transfer on the machine side — the two operations behind `do:file_pull`
// and `do:file_push`.
//
// The relay hands this module a one-time TOKEN, never a URL. The endpoint is built
// from the agent's OWN trusted relay origin (the same one resolveTrustedServerUrl
// host-locked at startup), so nothing the relay says can send a root process to
// another host. That is the single most important line in this file.
//
// PAYLOAD SAFETY. A path and a filename are user data, exactly like command text:
// nothing here logs one, and no error returned to the relay contains one. The
// refusal REASON carries the meaning ("not_found", "unwritable"), and the caller
// already knows which path they asked for. An errno string is not returned either —
// it routinely embeds the path that produced it.
//
// A push writes ATOMICALLY: bytes land in a temp file beside the destination and
// are renamed into place only after the full expected length arrived. A reader on
// the machine therefore never sees a half-written file, and a transfer that dies
// mid-stream leaves the previous file untouched rather than truncated.
//
// A push is also SYMLINK-SAFE, which matters because this process is usually root
// while the destination directory is chosen by the caller and may be writable by an
// unprivileged local user. The temp file is created with O_EXCL and, from that moment
// on, is only ever touched through its FILE DESCRIPTOR — the bytes, the mode and the
// owner all go through the open handle, never through the pathname again. A local
// user who swaps the name for a symlink after creation therefore changes nothing: the
// descriptor still points at the file we made. The one operation that cannot work
// this way is the final rename, and the note above it explains why what remains there
// is not exploitable.
//
// A push is also BOUNDED IN BOTH DIRECTIONS. The declared size is checked against
// the agent's own ceiling and against the free space at the destination before a
// socket is opened, and the same declared size is a hard cap ON the stream — the
// write aborts the instant one byte more than promised arrives. Counting the bytes
// and comparing afterwards, which is what the length check at the end does, is an
// integrity check for a SHORT read; it is no defence at all against a relay (or a
// broken retention sweep) handing back an object big enough to fill the disk.

import { createReadStream } from "fs";
import { stat, lstat, statfs, rename, unlink, open, readdir, type FileHandle } from "fs/promises";
import { dirname, join } from "path";
import { Readable, Transform } from "stream";
import { randomBytes } from "crypto";
import { FILE_MAX_BYTES, type FileRpcResult } from "@aicommander/protocol";

/** Header the relay's blob endpoints read the one-time token from (never a query param). */
const TOKEN_HEADER = "X-AIC-Blob-Token";

/** Where both blob endpoints live, relative to the agent's trusted relay origin. */
const BLOB_PATH = "/api/v1/blob";

function refuse(
  reason: Extract<FileRpcResult, { ok: false }>["reason"],
  message?: string,
): FileRpcResult {
  return { ok: false, reason, ...(message ? { message } : {}) };
}

/**
 * Whether a path is absolute ON THIS MACHINE.
 *
 * Checked against the real platform rather than accepting both dialects: on Linux
 * `C:\\data\\x` is a legal RELATIVE filename, and treating it as absolute because it
 * looks Windows-ish would write a file called `C:\data\x` into whatever directory
 * the agent happens to be in. The relay applies a looser, platform-blind version of
 * this check to keep obvious nonsense off the wire; this is the one that decides.
 */
function isAbsolutePath(path: string): boolean {
  if (path.length === 0 || path.includes("\0")) return false;
  if (process.platform === "win32") {
    return /^[A-Za-z]:[\\/]/.test(path) || path.startsWith("\\\\");
  }
  return path.startsWith("/");
}

/** The blob endpoint on the agent's own trusted relay. */
function blobUrl(serverUrl: string): string {
  return `${serverUrl.replace(/\/+$/, "")}${BLOB_PATH}`;
}

export interface PullRequest {
  serverUrl: string;
  path: string;
  token: string;
  /** Ceiling asked for by the relay. Clamped to FILE_MAX_BYTES; see `sizeCeiling`. */
  maxBytes?: number;
  /** Aborts the transfer when the connection that ordered it goes away. */
  signal?: AbortSignal;
}

/**
 * The size ceiling this machine will actually honour.
 *
 * The relay sends one, but the frame is just JSON: a missing field made the old
 * `size > req.maxBytes` compare against undefined — always false — which deleted the
 * machine's own ceiling entirely, and an inflated one would have overridden it. Same
 * bargain as the push side: this process usually runs as root on someone's own
 * machine and does not get to take the relay's word for how many of that machine's
 * bytes may leave it. Anything absent, malformed or bigger falls back to our own cap.
 */
function sizeCeiling(maxBytes: unknown): number {
  return Number.isSafeInteger(maxBytes) && (maxBytes as number) > 0
    ? Math.min(maxBytes as number, FILE_MAX_BYTES)
    : FILE_MAX_BYTES;
}

/**
 * Read a local file and upload it to the relay.
 *
 * Order matters: stat first, refuse on shape or size, and only then open a socket.
 * A 4 GB checkpoint must cost a stat call and a clear refusal, not a transfer that
 * runs for minutes before the relay cuts it off at the cap.
 */
export async function pullFileToRelay(req: PullRequest): Promise<FileRpcResult> {
  if (!isAbsolutePath(req.path)) {
    return refuse("invalid_request", "Path must be absolute.");
  }

  const limit = sizeCeiling(req.maxBytes);

  let size: number;
  try {
    const info = await stat(req.path);
    if (!info.isFile()) {
      return refuse("not_a_file", "Not a regular file.");
    }
    size = info.size;
  } catch (err) {
    // ENOENT is genuinely different from EACCES for the caller: one is a wrong
    // path, the other is a permissions problem they can fix on the machine.
    return refuse(errnoIs(err, "ENOENT") ? "not_found" : "unreadable");
  }

  if (size > limit) {
    return refuse("too_large", `File is ${size} bytes; the limit is ${limit}.`);
  }

  // Counted on the way out so a body that ended short of the declared length can be
  // named as such. Without it every such transfer surfaces as the same opaque
  // "upload failed", because that is all undici says when a Content-Length is not met.
  let sent = 0;
  const counter = new Transform({
    transform(chunk: Buffer, _enc, done) {
      sent += chunk.length;
      done(null, chunk);
    },
  });

  // Whether the SOURCE reached its end. This is what separates the two ways a body
  // can come up short: the file was read to EOF and there was simply less of it than
  // `stat` promised (a shrink), or the read never finished because the request died
  // under it (a dropped connection, a relay 5xx). Both surface as the same rejection
  // from fetch, and telling the user their file shrank when the network gave out
  // sends them to inspect a file that is perfectly fine.
  let readComplete = false;

  let response: Response;
  try {
    // The read is bounded to exactly the size that was just declared. The advertised
    // use case is "a log too big to print", i.e. a file a running job is APPENDING
    // to: unbounded, the stream would read past the declared length, undici would
    // reject the body and the transfer would die for no reason the user can act on.
    // Reading [0, size-1] means growth is simply not observed — the caller gets the
    // snapshot the size check was made against.
    const file = size === 0 ? Readable.from([]) : createReadStream(req.path, { start: 0, end: size - 1 });
    file.on("error", (err: Error) => counter.destroy(err));
    file.on("end", () => { readComplete = true; });
    req.signal?.addEventListener("abort", () => file.destroy(), { once: true });
    // `duplex: "half"` is required by Node's fetch to send a streaming body and is
    // harmless everywhere else. Streaming rather than reading the file into memory
    // is deliberate: this agent runs on NAS boxes with very little RAM, where
    // buffering 100 MiB to send it is the difference between a transfer and an OOM.
    const body = Readable.toWeb(file.pipe(counter)) as unknown as ReadableStream;
    response = await fetch(blobUrl(req.serverUrl), {
      method: "PUT",
      headers: {
        [TOKEN_HEADER]: req.token,
        "Content-Type": "application/octet-stream",
        "Content-Length": String(size),
      },
      body,
      duplex: "half",
      ...(req.signal ? { signal: req.signal } : {}),
    } as RequestInit);
  } catch {
    if (req.signal?.aborted) {
      return refuse("transfer_failed", "The transfer was cancelled on the machine.");
    }
    // A file read to its END that yielded fewer bytes than `stat` declared SHRANK
    // between the two (a rotated log, a truncated checkpoint). It fails identically
    // to a network error inside fetch, so it is distinguished here rather than left
    // to read as a mysterious relay problem.
    if (readComplete && sent < size) {
      return refuse("transfer_failed", `The file shrank while it was being read: ${sent} of ${size} bytes.`);
    }
    // Short but the read never finished: the transfer died mid-flight. Saying how far
    // it got is still useful — it separates "never connected" from "died at 90%" —
    // but the file is not the thing to go looking at.
    if (sent < size) {
      return refuse("transfer_failed", `The upload was interrupted after ${sent} of ${size} bytes.`);
    }
    // Never surface the thrown error: a fetch/fs error message routinely embeds
    // the path (and sometimes the URL with its token).
    return refuse("transfer_failed", "Upload to the relay failed.");
  }

  if (!response.ok) {
    return refuse(
      response.status === 413 ? "too_large" : "transfer_failed",
      `Relay rejected the upload (HTTP ${response.status}).`,
    );
  }

  // The relay counts what it actually stored; the machine knows what it sent. A
  // disagreement means a truncated upload, and reporting success on one would leave
  // the caller with a corrupt file and no reason to suspect it.
  let storedBytes: number | null = null;
  try {
    const body = (await response.json()) as { bytes?: unknown };
    if (typeof body.bytes === "number") storedBytes = body.bytes;
  } catch {
    storedBytes = null;
  }
  if (storedBytes !== null && storedBytes !== size) {
    return refuse("transfer_failed", "The relay stored a different number of bytes than were sent.");
  }

  return { ok: true, kind: "pulled", bytes: size };
}

export interface PushRequest {
  serverUrl: string;
  destPath: string;
  token: string;
  expectedBytes: number;
  /** The agent's own ceiling. Defaults to FILE_MAX_BYTES; overridable for tests. */
  maxBytes?: number;
  /** Aborts the transfer when the connection that ordered it goes away. */
  signal?: AbortSignal;
}

/** Thrown by the cap in the write loop; distinguished from a real I/O failure. */
class TransferOverrunError extends Error {}

/** Thrown when the connection that ordered the transfer was torn down under it. */
class TransferAbortedError extends Error {}

/**
 * Thrown when `write()` accepts nothing at all without reporting an error.
 *
 * A partial write is retried, but a write that reports ZERO bytes written and no
 * error would spin the retry loop forever on a wedged device or a filesystem at its
 * limit. A hung push is worse than a failed one: the caller waits on a job that will
 * never end, and nothing on the machine says why.
 */
class WriteStalledError extends Error {}

/**
 * How much room the destination's filesystem has left, or null if we cannot tell.
 *
 * Best-effort by design: statfs does not exist on every runtime the agent is
 * compiled for, and some filesystems (network mounts especially) report figures
 * that mean nothing. An unknown answer must never block a transfer that would have
 * succeeded — the write itself still fails with ENOSPC, which is already handled.
 */
async function freeBytesAt(dir: string): Promise<number | null> {
  try {
    const fs = await statfs(dir);
    const free = Number(fs.bavail) * Number(fs.bsize);
    return Number.isFinite(free) && free >= 0 ? free : null;
  } catch {
    return null;
  }
}

/**
 * Give the temp file the destination's identity before it takes its place.
 *
 * The temp file is born 0600 so that no one can read a partially written blob, but
 * renaming it over an existing 0644 dataset would leave that file readable only by
 * the agent — and the job that consumes it fails much later, far from the cause. So
 * an OVERWRITE inherits the old file's permission bits and owner; a genuinely new
 * file keeps 0600, which is the safe default for a file the caller said nothing
 * about. Only a regular file is inherited from — a destination that is a directory,
 * a device or a symlink target of another shape is left alone entirely.
 *
 * Every step is best-effort. The bytes are already on disk and verified at this
 * point; aborting a completed transfer because a cosmetic chown was refused (the
 * agent is not always root, and root is not always privileged over NFS) would be a
 * far worse outcome than a file whose owner did not change.
 *
 * Both writes go through the temp file's DESCRIPTOR, never its name. Applied by name
 * this was a local privilege escalation: the temp file sits in a caller-chosen
 * directory, and an unprivileged user who can write there could replace the name with
 * a symlink between the create and the chmod/chown, at which point a root agent
 * happily changed the mode or owner of any file on the machine. An fd cannot be
 * redirected, so the window is not merely narrowed — it does not exist.
 *
 * The destination is read with LSTAT for the mirror-image reason: `stat` resolves a
 * symlink, so a destination planted as a link would have donated some other file's
 * identity to the bytes we are about to install. A link (or a directory, or a device)
 * is simply not a file we inherit from.
 */
async function inheritDestinationIdentity(handle: FileHandle, destPath: string): Promise<void> {
  let existing;
  try {
    existing = await lstat(destPath);
  } catch {
    return; // No previous file — 0600 stands.
  }
  if (!existing.isFile()) return;

  // 0o777, NOT 0o7777, and that is not an oversight to tidy up later: the wide mask
  // would carry setuid/setgid/sticky across too, and the chown below then restores
  // the original owner. Pushing new bytes over a 04755 root-owned binary would
  // re-arm it as setuid-root running CALLER-SUPPLIED content. A privilege bit was
  // granted to the PREVIOUS contents; a content replacement has no business
  // reinstating it. The ordinary rwx bits are the whole point of inheriting — they
  // keep the dataset readable to the non-root job, and a pushed replacement of an
  // executable script stays executable — so those, and only those, come over.
  await handle.chmod(existing.mode & 0o777).catch(() => {});
  await handle.chown(existing.uid, existing.gid).catch(() => {});
}

/**
 * Temp files this process is writing right now. The sweep below consults it so a
 * second concurrent push can never delete the first one's partially written bytes.
 */
const inFlightTempFiles = new Set<string>();

/** Only our own naming, and only lowercase hex, is ever a sweep candidate. */
const TEMP_FILE_PATTERN = /^\.aic-transfer-[0-9a-f]{16}\.part$/;

/**
 * How old an abandoned `.part` must be before the sweep will touch it. A transfer is
 * capped at FILE_MAX_BYTES and dies with the connection, so nothing legitimate is
 * still being written a day later — while a machine whose clock jumped, or a second
 * agent process mid-push, is exactly what an aggressive threshold would destroy.
 */
const STALE_TEMP_AGE_MS = 24 * 60 * 60 * 1000;

/**
 * Delete abandoned `.aic-transfer-*.part` files in one directory.
 *
 * The handled error paths already unlink their own temp file; this exists for the
 * ones that cannot — a crash, a self-update, a power loss mid-push — after which up
 * to FILE_MAX_BYTES stays on the user's disk with nothing left to clean it up. Run
 * from the push path against the directory a push is about to write to, because that
 * is both the only directory we ever leave these in and the one whose filling up the
 * user would notice. Entirely best-effort: a sweep that cannot read the directory
 * must never stop the transfer that triggered it.
 */
export async function sweepStaleTransferTemps(dir: string, now = Date.now()): Promise<number> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return 0;
  }

  let removed = 0;
  for (const name of entries) {
    if (!TEMP_FILE_PATTERN.test(name)) continue;
    const path = join(dir, name);
    if (inFlightTempFiles.has(path)) continue;
    try {
      // lstat, not stat: a `.part` name that is really a symlink is not ours and is
      // not something a root process should be resolving on the way to an unlink.
      const info = await lstat(path);
      if (!info.isFile() || now - info.mtimeMs < STALE_TEMP_AGE_MS) continue;
      await unlink(path);
      removed++;
    } catch {
      // Raced with another sweep, or not ours to remove. Either is fine.
    }
  }
  return removed;
}

/**
 * Download a stored blob from the relay and write it to a local path, atomically.
 *
 * The temp file lives in the DESTINATION'S directory, not in /tmp: a rename is only
 * atomic within one filesystem, and a NAS or a container routinely has /tmp on a
 * different mount than the data directory. Writing to /tmp first would silently
 * downgrade the guarantee to a copy — a reader could then observe a partial file.
 */
export async function pushFileFromRelay(req: PushRequest): Promise<FileRpcResult> {
  if (!isAbsolutePath(req.destPath)) {
    return refuse("invalid_request", "Destination path must be absolute.");
  }

  const limit = req.maxBytes ?? FILE_MAX_BYTES;
  if (!Number.isSafeInteger(req.expectedBytes) || req.expectedBytes < 0) {
    return refuse("invalid_request", "Expected size must be a non-negative integer.");
  }

  // Refuse BEFORE a socket is opened, per the do:file_push contract. The relay is
  // supposed to enforce the same ceiling, but this process usually runs as root on
  // someone's own machine: it does not get to take the relay's word for how many
  // bytes are about to be written to that machine's disk.
  if (req.expectedBytes > limit) {
    return refuse("too_large", `The file is ${req.expectedBytes} bytes; this machine's limit is ${limit}.`);
  }

  const destDir = dirname(req.destPath);
  const free = await freeBytesAt(destDir);
  if (free !== null && free < req.expectedBytes) {
    // The temp file sits beside the destination, so the whole transfer has to fit
    // there — and it fits ALONGSIDE the file it replaces, which is why this is not
    // discounted by the size of an existing destination.
    return refuse("unwritable", "Not enough free space at the destination.");
  }

  // Reclaim whatever earlier attempts died before they could clean up after
  // themselves. Cheap (one readdir), and this is the directory that would otherwise
  // accumulate them.
  await sweepStaleTransferTemps(destDir);

  const tempPath = join(destDir, `.aic-transfer-${randomBytes(8).toString("hex")}.part`);

  let response: Response;
  try {
    response = await fetch(blobUrl(req.serverUrl), {
      method: "GET",
      headers: { [TOKEN_HEADER]: req.token },
      ...(req.signal ? { signal: req.signal } : {}),
    } as RequestInit);
  } catch {
    return refuse("transfer_failed", req.signal?.aborted
      ? "The transfer was cancelled on the machine."
      : "Download from the relay failed.");
  }
  if (!response.ok || !response.body) {
    return refuse("transfer_failed", `Relay refused the download (HTTP ${response.status}).`);
  }

  // "wx" is O_CREAT|O_EXCL: the create fails outright rather than truncating an
  // existing file or following a symlink someone planted at that name. The name is
  // 64 unpredictable bits, so a collision means something is actively guessing — and
  // this is also the last time the temp file is addressed by name until the rename.
  let handle: FileHandle;
  try {
    handle = await open(tempPath, "wx", 0o600);
  } catch (err) {
    return errnoIs(err, "ENOENT") || errnoIs(err, "EACCES") || errnoIs(err, "EPERM")
      ? refuse("unwritable")
      : refuse("transfer_failed", "Writing the file failed.");
  }
  inFlightTempFiles.add(tempPath);

  // Two different counters, and the difference between them is the point. `received`
  // is what came off the socket, which is what the declared-size cap has to be
  // measured against; `written` is what `write()` REPORTED putting on disk, which is
  // what the integrity check at the end has to be measured against.
  let received = 0;
  let written = 0;
  try {
    const source = Readable.fromWeb(response.body as never);
    // Written chunk by chunk through the HANDLE rather than piped into a write
    // stream: a stream built from a FileHandle takes ownership of the descriptor and
    // closes it when it finishes, and the mode and owner still have to be set through
    // that descriptor afterwards. The loop keeps the fd ours for the whole transfer.
    //
    // The cap is checked BEFORE each write, not after the body has landed, so an
    // overrun costs one chunk of disk rather than however much the relay felt like
    // sending. Breaking out of the loop destroys the source, which cancels the
    // download too.
    for await (const chunk of source as AsyncIterable<Buffer>) {
      if (req.signal?.aborted) throw new TransferAbortedError();
      received += chunk.length;
      if (received > req.expectedBytes) throw new TransferOverrunError();
      // A write stream retried short writes for free; the handle does not. `write()`
      // may accept FEWER bytes than it was handed — at an ENOSPC boundary, on a
      // signal, on some network filesystems — and reports how many in `bytesWritten`.
      // Trusting the chunk length instead would leave a file on disk shorter than the
      // counter believes, which the length check below then waves through and the
      // rename installs as a truncated "successful" push.
      let offset = 0;
      while (offset < chunk.length) {
        const { bytesWritten } = await handle.write(chunk, offset, chunk.length - offset);
        if (bytesWritten <= 0) throw new WriteStalledError();
        offset += bytesWritten;
        written += bytesWritten;
      }
    }
  } catch (err) {
    await discardTemp(handle, tempPath);
    if (err instanceof TransferOverrunError) {
      // The relay sent more than it declared. That is either a bug or an attempt to
      // fill this machine's disk; either way the declared size is the contract.
      return refuse("too_large", `The download exceeded the declared ${req.expectedBytes} bytes and was aborted.`);
    }
    if (err instanceof TransferAbortedError || req.signal?.aborted) {
      return refuse("transfer_failed", "The transfer was cancelled on the machine.");
    }
    if (err instanceof WriteStalledError) {
      // No errno to map: the write simply stopped accepting bytes. From the user's
      // side it is the same class of problem as ENOSPC — something about the
      // destination, fixable on the machine.
      return refuse("unwritable");
    }
    // A write failure is almost always something the user can fix on the machine —
    // a missing parent directory, no permission, a full disk — so it gets its own
    // reason rather than being lumped in with a network failure.
    return errnoIs(err, "ENOENT") || errnoIs(err, "EACCES") || errnoIs(err, "EPERM") || errnoIs(err, "ENOSPC")
      ? refuse("unwritable")
      : refuse("transfer_failed", "Writing the file failed.");
  }

  // A short read is the failure mode that matters: HTTP will happily end a
  // truncated response body cleanly, and renaming that into place would replace a
  // good file with a broken one. `written` is the sum of what the writes actually
  // reported, so this compares bytes ON DISK with what was promised — comparing the
  // chunk lengths handed to `write()` would pass over a file that never fully landed.
  if (written !== req.expectedBytes) {
    await discardTemp(handle, tempPath);
    return refuse("transfer_failed", "The download ended early; the file was not replaced.");
  }

  // Access can be revoked while the bytes are in flight — the code reset, the agent
  // disabled. Checked here to skip the identity work for a transfer that is already
  // doomed; the check that actually enforces the revocation is the one below.
  if (req.signal?.aborted) {
    await discardTemp(handle, tempPath);
    return refuse("transfer_failed", "The transfer was cancelled on the machine.");
  }

  await inheritDestinationIdentity(handle, req.destPath);

  // `close()` is where deferred write errors surface, so its failure is not a
  // formality to swallow. On a buffered or network filesystem the error a write
  // provoked — ENOSPC, an I/O fault, a mount giving up — is frequently reported at
  // close rather than by the `write()` that caused it. Ignoring it would rename a
  // temp file whose contents are incomplete over the user's destination and report a
  // successful push: exactly the corruption the byte-count check above exists to
  // prevent, arriving by the one route that check cannot see. Classified like every
  // other destination-side I/O failure here — something about the machine, fixable
  // there — because that is what a failing close actually means.
  try {
    await handle.close();
  } catch {
    // Discarded by NAME only: the descriptor is spent whether the close succeeded or
    // not, and handing it to discardTemp would close it a second time — which either
    // throws again or masks the failure that brought us here.
    await discardTemp(null, tempPath);
    return refuse("unwritable");
  }

  // Re-checked immediately before the rename, because the chmod/chown/close above are
  // awaited and a revocation that lands during them would otherwise still reach this
  // line. The rename is the moment the push becomes visible on the machine, so it is
  // the operation this check exists to guard — the last point at which honouring a
  // withdrawal of access still means anything.
  if (req.signal?.aborted) {
    await discardTemp(null, tempPath);
    return refuse("transfer_failed", "The transfer was cancelled on the machine.");
  }

  try {
    // The one step that is unavoidably by NAME: Node exposes no renameat, so there is
    // no way to say "the file behind this descriptor". The residual race is a local
    // user swapping tempPath between the close above and this call, which would move
    // THEIR file to the destination instead of ours. It is not a privilege
    // escalation: it requires write access to the destination directory, and anyone
    // with that can already create the destination file directly with any content
    // they like. Nothing outside that directory can be reached, and the descriptor
    // work above means no file elsewhere can have its mode or owner changed.
    await rename(tempPath, req.destPath);
  } catch {
    await discardTemp(null, tempPath);
    return refuse("unwritable");
  }
  inFlightTempFiles.delete(tempPath);

  return { ok: true, kind: "pushed", bytes: written };
}

/** Close the descriptor (if still open) and remove the temp file. Never throws. */
async function discardTemp(handle: FileHandle | null, tempPath: string): Promise<void> {
  if (handle) await handle.close().catch(() => {});
  await unlink(tempPath).catch(() => {});
  inFlightTempFiles.delete(tempPath);
}

/** Whether a thrown value is a Node errno error with this code. */
function errnoIs(err: unknown, code: string): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === code;
}
