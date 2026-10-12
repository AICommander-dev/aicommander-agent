import fs from "node:fs";
import path from "node:path";

export const PRIVATE_DIR_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

/** Create (or reuse) a directory and reassert owner-only traversal mode. */
export function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
  try {
    fs.chmodSync(dir, PRIVATE_DIR_MODE);
  } catch {
    // mkdir mode is masked by umask; chmod is best-effort when we lack ownership.
  }
}

/** Best-effort chmod reassert when reading an existing credential file. */
export function reassertPrivateFileModes(dir: string, filePath: string): void {
  try {
    fs.chmodSync(dir, PRIVATE_DIR_MODE);
  } catch {
    // Non-fatal.
  }
  try {
    fs.chmodSync(filePath, PRIVATE_FILE_MODE);
  } catch {
    // Non-fatal.
  }
}

/**
 * Write via an exclusive temp file and atomic rename so readers never observe a
 * partial file or a transient wider mode. Cleans up the temp file on failure.
 */
export function atomicWriteFile(
  dir: string,
  fileName: string,
  writeTemp: (tmpPath: string) => void,
): void {
  ensurePrivateDir(dir);
  const finalPath = path.join(dir, fileName);
  const tmpPath = path.join(dir, `.${fileName}.${process.pid}.${Date.now()}.tmp`);
  try {
    writeTemp(tmpPath);
    fs.renameSync(tmpPath, finalPath);
    try {
      fs.chmodSync(finalPath, PRIVATE_FILE_MODE);
    } catch {
      // Non-fatal after a successful rename.
    }
  } catch (err) {
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch {
      // Ignore cleanup errors; propagate the original failure.
    }
    throw err;
  }
}

/**
 * A caller that has stopped waiting for an asynchronous write.
 *
 * A write nobody is waiting for any more cannot be cancelled — no fs API revokes
 * a request a filter driver is sitting on — so it goes on running, one step at a
 * time, minutes after the job it belonged to was erased. The latch is how it is
 * told that, so that whatever it does next it UNDOES rather than leaves behind.
 * See the abandonment handling in atomicWriteUtf8Async.
 */
export interface AsyncWriteAbandoned {
  /** Set by the caller the moment it gives up on the write. */
  abandoned: boolean;
}

/**
 * The same write, off the event loop.
 *
 * The synchronous twin above is right for everything that runs at startup or on
 * a CLI turn. It is wrong on the ONE path that runs inside the WebSocket frame
 * handler — a Windows job start — because the desktop app embeds this runtime on
 * Electron's main loop, where a filesystem an on-access scanner is holding turns
 * a small write into a stalled heartbeat and the "Reconnecting…" wedge this
 * whole effort exists to prevent (see tray.ts, diag-log.ts).
 *
 * Semantics are otherwise identical, including the temp-file cleanup on failure
 * and the errno the caller classifies (job-scripts.ts): the only difference is
 * which thread waits.
 *
 * ABANDONMENT is the one thing the synchronous twin never had to think about. A
 * caller that timed out (JOB_SCRIPT_IO_TIMEOUT_MS) has already failed its start
 * and deleted the job's directory — while THIS call is still parked inside the
 * scanner. It resumes into a world where its directory is gone, and its very
 * first step is `mkdir(recursive)`: it would recreate the id-shaped directory
 * the caller just removed and drop a wrapper.cmd or a `.tmp` into it, leaving a
 * directory with no meta.json that pruneUnreadable then keeps for the whole
 * retention window. So each step checks the latch and undoes what it has done:
 * the temp file, the renamed file, and the directory itself when this call is
 * what created it.
 */
export async function atomicWriteUtf8Async(
  dir: string,
  fileName: string,
  contents: string,
  giveUp?: AsyncWriteAbandoned,
): Promise<void> {
  // The path mkdir actually CREATED (undefined when the directory already
  // existed), which is exactly what an abandoned write may remove again.
  const created = await fs.promises.mkdir(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
  const finalPath = path.join(dir, fileName);
  const tmpPath = path.join(dir, `.${fileName}.${process.pid}.${Date.now()}.tmp`);
  const undo = async (): Promise<void> => {
    for (const target of [tmpPath, finalPath]) {
      try {
        await fs.promises.rm(target, { force: true });
      } catch {
        // Best-effort: the caller has already given up on this write.
      }
    }
    if (created === undefined) return;
    try {
      // rmdir, not a recursive rm: this removes the directory only while it is
      // still as empty as we found it, so a write abandoned late can never take
      // a directory something else has since put a job in.
      await fs.promises.rmdir(created);
    } catch {
      // Not empty, or gone already — either way, not ours to force.
    }
  };
  // A function, not a re-read of the field: the latch is flipped from OUTSIDE
  // this call while it is parked, which is exactly the narrowing TypeScript
  // would otherwise apply to a property it has already seen be false.
  const gaveUp = (): boolean => giveUp?.abandoned === true;
  if (gaveUp()) return undo();
  try {
    await fs.promises.chmod(dir, PRIVATE_DIR_MODE);
  } catch {
    // mkdir mode is masked by umask; chmod is best-effort when we lack ownership.
  }
  try {
    await fs.promises.writeFile(tmpPath, contents, {
      encoding: "utf8",
      flag: "wx",
      mode: PRIVATE_FILE_MODE,
    });
    if (gaveUp()) return undo();
    await fs.promises.rename(tmpPath, finalPath);
    if (gaveUp()) return undo();
    try {
      await fs.promises.chmod(finalPath, PRIVATE_FILE_MODE);
    } catch {
      // Non-fatal after a successful rename.
    }
  } catch (err) {
    try {
      await fs.promises.rm(tmpPath, { force: true });
    } catch {
      // Ignore cleanup errors; propagate the original failure.
    }
    // A write that FAILED after it was abandoned still owes the directory it
    // created: nobody is left to throw to, so clean up rather than propagate.
    if (gaveUp() && created !== undefined) {
      try {
        await fs.promises.rmdir(created);
      } catch {
        // Not empty, or gone already.
      }
      return;
    }
    throw err;
  }
}

export function atomicWriteUtf8(dir: string, fileName: string, contents: string): void {
  atomicWriteFile(dir, fileName, (tmpPath) => {
    const fd = fs.openSync(tmpPath, "wx", PRIVATE_FILE_MODE);
    try {
      fs.writeFileSync(fd, contents, { encoding: "utf8" });
    } finally {
      fs.closeSync(fd);
    }
  });
}

export function atomicWriteBuffer(dir: string, fileName: string, data: Buffer): void {
  atomicWriteFile(dir, fileName, (tmpPath) => {
    const fd = fs.openSync(tmpPath, "wx", PRIVATE_FILE_MODE);
    try {
      fs.writeFileSync(fd, data);
    } finally {
      fs.closeSync(fd);
    }
  });
}
