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
