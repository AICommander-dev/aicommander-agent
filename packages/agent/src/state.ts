import fs from "node:fs/promises";
import path from "node:path";
import { reassertPrivateFileModes } from "./atomic-file.js";
import {
  enforceCredentialStorageWrite,
  isStrictCredentialStorage,
} from "./credential-storage.js";

const STATE_DIR = "/var/run/aicommander-agent";
const STATE_FILE = path.join(STATE_DIR, "state.json");
// The state file carries the live sessionCode (a root-exec credential). Keep the
// dir owner-only and the file owner-read/write only so a local unprivileged user
// can neither traverse the dir nor read the secret.
const STATE_DIR_MODE = 0o700;
const STATE_FILE_MODE = 0o600;

export interface AgentState {
  sessionCode: string;
  pid: number;
  startedAt: string;
  serverUrl: string;
}

export async function writeState(state: AgentState): Promise<void> {
  // Declared outside the try so the catch can clean up the 0600 temp file if the
  // rename (or any later step) fails — otherwise an orphaned `.state.*.tmp`
  // (which carries the sessionCode credential) accumulates in the runtime dir.
  let tmpFile: string | null = null;
  try {
    await fs.mkdir(STATE_DIR, { recursive: true, mode: STATE_DIR_MODE });
    // mkdir's mode is masked by umask and a no-op if the dir already exists, so
    // chmod explicitly to guarantee 0700 regardless of how the dir was created.
    await fs.chmod(STATE_DIR, STATE_DIR_MODE);

    // Write to a temp file with 0600 (exclusive create), then atomically rename
    // so readers never observe a partial file or a wider mode.
    tmpFile = path.join(STATE_DIR, `.state.${process.pid}.${Date.now()}.tmp`);
    const handle = await fs.open(tmpFile, "wx", STATE_FILE_MODE);
    try {
      await handle.writeFile(JSON.stringify(state, null, 2), "utf8");
    } finally {
      await handle.close();
    }
    await fs.rename(tmpFile, STATE_FILE);
    // Rename consumed the temp path; nothing left to clean up on later failure.
    tmpFile = null;
    await fs.chmod(STATE_FILE, STATE_FILE_MODE);
  } catch (err) {
    if (isStrictCredentialStorage()) {
      enforceCredentialStorageWrite("runtime state", err);
    }
    // Non-fatal in dev / foreground runs that may lack /var/run write access.
  } finally {
    // Best-effort: remove a leftover temp file if anything after open() failed
    // (rename error, chmod error, …). Ignore unlink errors.
    if (tmpFile) {
      await fs.rm(tmpFile, { force: true }).catch(() => {});
    }
  }
}

export async function clearState(): Promise<void> {
  try {
    await fs.rm(STATE_FILE, { force: true });
  } catch {
    // Non-fatal
  }
}

export async function readState(): Promise<AgentState | null> {
  try {
    reassertPrivateFileModes(STATE_DIR, STATE_FILE);
    const raw = await fs.readFile(STATE_FILE, "utf8");
    return JSON.parse(raw) as AgentState;
  } catch {
    return null;
  }
}
