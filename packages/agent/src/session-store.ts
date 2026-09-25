import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  atomicWriteBuffer,
  atomicWriteUtf8,
  reassertPrivateFileModes,
} from "./atomic-file.js";
import {
  enforceCredentialStorageWrite,
  isStrictCredentialStorage,
} from "./credential-storage.js";
import { envConfigDir } from "./config-dir.js";

export interface StoredSession {
  sessionCode: string;
  agentToken: string;
}

/** OS-protected storage for the reusable agent token (desktop safeStorage). */
export interface TokenVault {
  isAvailable(): boolean;
  encrypt(plaintext: string): Buffer;
  decrypt(ciphertext: Buffer): string;
}

export type SessionStoreContext =
  | string
  | {
      configDir?: string;
      tokenVault?: TokenVault;
    };

/**
 * Durable session store: persists the agent's session code + token so the SAME
 * code is reused across reboots, service restarts, and reconnects. The code is
 * rotated ONLY by `change-code` (which clears this store and forces a new code).
 *
 * Modeled on device.ts: primary path under /etc (survives reboots), with a
 * user-config fallback for non-root / dev. We must NOT use /var/run (tmpfs).
 * Where /etc is a ramdisk (QNAP QTS), AICOMMANDER_CONFIG_DIR relocates the store
 * to durable storage and these two become read-and-purge only; see config-dir.ts.
 */
const PRIMARY_DIR = "/etc/aicommander-agent";
const FALLBACK_DIR = path.join(os.homedir(), ".config", "aicommander-agent");
const FILE_NAME = "session.json";
const TOKEN_FILE_NAME = "session.token";

/** One-shot marker written by `change-code` to force a new code on next start. */
const ROTATE_FILE_NAME = ".rotate";

interface SessionFilePayload {
  sessionCode: string;
  agentToken?: string;
  tokenProtected?: boolean;
}

function normalizeCtx(ctx?: SessionStoreContext): {
  configDir?: string;
  tokenVault?: TokenVault;
} {
  if (typeof ctx === "string") return { configDir: ctx };
  return ctx ?? {};
}

function isValidSession(value: unknown): value is StoredSession {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as StoredSession).sessionCode === "string" &&
    (value as StoredSession).sessionCode.length > 0 &&
    typeof (value as StoredSession).agentToken === "string" &&
    (value as StoredSession).agentToken.length > 0
  );
}

function isValidSessionFile(value: unknown): value is SessionFilePayload {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as SessionFilePayload).sessionCode === "string" &&
    (value as SessionFilePayload).sessionCode.length > 0
  );
}

function tryReadSession(
  dir: string,
  tokenVault?: TokenVault,
): StoredSession | null {
  const filePath = path.join(dir, FILE_NAME);
  try {
    if (!fs.existsSync(filePath)) return null;
    reassertPrivateFileModes(dir, filePath);
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (!isValidSessionFile(parsed)) return null;

    if (parsed.tokenProtected) {
      const tokenPath = path.join(dir, TOKEN_FILE_NAME);
      if (!fs.existsSync(tokenPath)) return null;
      reassertPrivateFileModes(dir, tokenPath);
      if (!tokenVault?.isAvailable()) return null;
      const ciphertext = fs.readFileSync(tokenPath);
      const agentToken = tokenVault.decrypt(ciphertext);
      if (!agentToken) return null;
      return { sessionCode: parsed.sessionCode, agentToken };
    }

    if (isValidSession(parsed)) {
      return { sessionCode: parsed.sessionCode, agentToken: parsed.agentToken };
    }
  } catch {
    // Missing / unreadable / malformed — caller treats as no stored session.
  }
  return null;
}

function writeSessionToDir(
  dir: string,
  session: StoredSession,
  tokenVault?: TokenVault,
): void {
  if (tokenVault?.isAvailable()) {
    const ciphertext = tokenVault.encrypt(session.agentToken);
    atomicWriteUtf8(
      dir,
      FILE_NAME,
      JSON.stringify({ sessionCode: session.sessionCode, tokenProtected: true }, null, 2),
    );
    atomicWriteBuffer(dir, TOKEN_FILE_NAME, ciphertext);
    return;
  }

  atomicWriteUtf8(
    dir,
    FILE_NAME,
    JSON.stringify(
      { sessionCode: session.sessionCode, agentToken: session.agentToken },
      null,
      2,
    ),
  );
  try {
    fs.rmSync(path.join(dir, TOKEN_FILE_NAME), { force: true });
  } catch {
    // Best-effort cleanup when migrating away from OS-protected storage.
  }
}

function writeWithFallback(
  label: string,
  configDir: string | undefined,
  write: (dir: string) => void,
): void {
  const dirs = writeDirs(configDir);
  let lastErr: unknown;
  for (const dir of dirs) {
    try {
      write(dir);
      return;
    } catch (err) {
      lastErr = err;
    }
  }
  if (isStrictCredentialStorage()) {
    enforceCredentialStorageWrite(label, lastErr ?? new Error("no writable session directory"));
  }
}

/**
 * Directories we may WRITE to, in order of preference. An explicit `configDir`
 * (the desktop app's per-user data dir) or AICOMMANDER_CONFIG_DIR is the ONLY
 * write target; with neither we use /etc, falling back to the user config dir.
 */
function writeDirs(configDir?: string): string[] {
  const dir = configDir ?? envConfigDir();
  return dir ? [dir] : [PRIMARY_DIR, FALLBACK_DIR];
}

/**
 * Locations a PRE-override install may still hold a session in — only under
 * AICOMMANDER_CONFIG_DIR, where the write target moved but the files did not.
 * They are read-and-purge only (never written to), so that turning the override
 * on keeps the SAME session code instead of orphaning every linked account, and
 * so a `change-code` run without the variable still reaches the live store.
 */
function inheritedDirs(configDir?: string): string[] {
  return !configDir && envConfigDir() ? [PRIMARY_DIR, FALLBACK_DIR] : [];
}

/** Every directory to READ from / PURGE, most specific first. */
function readDirs(configDir?: string): string[] {
  return [...writeDirs(configDir), ...inheritedDirs(configDir)];
}

/**
 * Load the persisted session — the write target first, then (under the env
 * override) the locations an earlier install used. Null if none has one.
 */
export function loadSession(ctx?: SessionStoreContext): StoredSession | null {
  const { configDir, tokenVault } = normalizeCtx(ctx);
  for (const dir of writeDirs(configDir)) {
    const session = tryReadSession(dir, tokenVault);
    if (session) return session;
  }
  for (const dir of inheritedDirs(configDir)) {
    const session = tryReadSession(dir, tokenVault);
    if (session) {
      // The next saveSession (run.ts always re-asserts the code right after
      // registering) copies it into the override dir, so this is a one-off.
      console.warn(`\n  ℹ  Reusing the session code found in ${dir}.\n`);
      return session;
    }
  }
  return null;
}

/** Persist the session to the write target, falling back to the user dir. */
export function saveSession(session: StoredSession, ctx?: SessionStoreContext): void {
  const { configDir, tokenVault } = normalizeCtx(ctx);
  writeWithFallback("session credentials", configDir, (dir) => {
    writeSessionToDir(dir, session, tokenVault);
  });
}

/**
 * Remove the persisted session from every location we read from (best-effort) —
 * a copy left in an inherited directory would be read back on the next start.
 */
export function clearSession(ctx?: SessionStoreContext): void {
  const { configDir } = normalizeCtx(ctx);
  for (const dir of readDirs(configDir)) {
    for (const name of [FILE_NAME, TOKEN_FILE_NAME]) {
      try {
        fs.rmSync(path.join(dir, name), { force: true });
      } catch {
        // Non-fatal.
      }
    }
  }
}

// --- change-code rotate marker ---------------------------------------------

/** Write the one-shot rotate marker (forces a new code on next startup). */
export function writeRotateMarker(ctx?: SessionStoreContext): void {
  const { configDir } = normalizeCtx(ctx);
  writeWithFallback("session rotate marker", configDir, (dir) => {
    atomicWriteUtf8(dir, ROTATE_FILE_NAME, "");
  });
}

/**
 * If the rotate marker exists in ANY location we read, delete it and return true.
 * Used at startup to decide whether to force a brand-new code (change-code path)
 * vs re-assert the existing one (reboot/restart path). Scanning the inherited
 * locations too is what makes a `change-code` invoked without the env override
 * still rotate the live code instead of silently marking a directory nobody reads.
 */
export function consumeRotateMarker(ctx?: SessionStoreContext): boolean {
  const { configDir } = normalizeCtx(ctx);
  let found = false;
  for (const dir of readDirs(configDir)) {
    const marker = path.join(dir, ROTATE_FILE_NAME);
    try {
      if (fs.existsSync(marker)) {
        found = true;
        reassertPrivateFileModes(dir, marker);
        fs.rmSync(marker, { force: true });
      }
    } catch {
      // Non-fatal.
    }
  }
  return found;
}
