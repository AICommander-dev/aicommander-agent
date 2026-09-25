import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { errorText, type DoctorContext } from "../types.js";
import { doctorConfigDirOverride } from "./paths.js";

/**
 * The stored session, read the way a DIAGNOSTIC is allowed to read it.
 *
 * `loadSession()` (session-store.ts) is the agent's reader and it is not
 * read-only: it resolves its directories through `envConfigDir()`, which CREATES
 * the configured directory, and it calls `reassertPrivateFileModes()`, which
 * chmods the store files it finds. Both are right for the agent — the store must
 * exist and must be 0600 before a credential is written into it — and both are
 * forbidden here: a doctor run that tightened a mode would have destroyed the
 * evidence of the very finding storage.ts's `config.store` check exists to
 * report, and one that created a directory would have changed the answer of the
 * check that runs after it.
 *
 * So this asks the same ladder the same questions with `stat`, `readFile` and
 * nothing else. The parsing rules are session-store.ts's, deliberately mirrored
 * rather than shared, because the shared thing would have to be the function
 * that mutates.
 *
 * The token that comes back is a credential: it is presented as a Bearer header
 * to the relay and NEVER put into a fact, a detail or a remedy.
 */

/** Mirrors session-store.ts. */
const PRIMARY_DIR = "/etc/aicommander-agent";
const FILE_NAME = "session.json";
const TOKEN_FILE_NAME = "session.token";

function fallbackDir(): string {
  return path.join(os.homedir(), ".config", "aicommander-agent");
}

export type SessionRead =
  | { kind: "found"; sessionCode: string; agentToken: string }
  /** No session file in any location we read. This machine never registered. */
  | { kind: "none" }
  /**
   * A session is there, but its token is in OS-protected storage that this
   * process cannot open — the desktop's safeStorage, from a headless run or from
   * a host that passed no vault. Not the same statement as "never registered".
   */
  | { kind: "protected" }
  | { kind: "unreadable"; error: string };

/**
 * Whether `session.json` says its token lives in the OS-protected sidecar.
 *
 * The one field of that file the store-completeness check needs, and the only
 * one that leaves this function: a protected session whose `session.token` is
 * gone is a store that has LOST a file, while an unprotected one has no sidecar
 * to lose — and a stat cannot tell those apart, because the flag is inside the
 * JSON. Nothing else is returned, and in particular `agentToken` is read past
 * and dropped: the parsed object is local and never reaches a fact, a detail or
 * a remedy.
 *
 * `unreadable` is its own answer for the reason everything in this directory now
 * has one: a session.json we could not parse must not be reported as an
 * unprotected session, which would then be reported as a healthy store.
 */
export type SessionShape =
  | { kind: "absent" }
  | { kind: "unreadable"; error: string }
  | { kind: "present"; tokenProtected: boolean };

export async function readSessionShape(dir: string): Promise<SessionShape> {
  try {
    const parsed = await readJson(path.join(dir, FILE_NAME));
    return { kind: "present", tokenProtected: parsed?.["tokenProtected"] === true };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return { kind: "absent" };
    return { kind: "unreadable", error: errorText(err) };
  }
}

/**
 * Every directory session-store.ts would READ from, most specific first, with
 * the env override resolved read-only (see paths.ts).
 */
export function sessionReadDirs(configDir?: string): string[] {
  const override = doctorConfigDirOverride();
  const write = configDir ?? override;
  if (write) {
    // Under the override the pre-override locations are still read (and purged)
    // by the agent, so a session found there is a session the agent would use.
    return configDir ? [configDir] : [write, PRIMARY_DIR, fallbackDir()];
  }
  return [PRIMARY_DIR, fallbackDir()];
}

async function readJson(file: string): Promise<Record<string, unknown> | null> {
  const raw = await fs.promises.readFile(file, "utf8");
  const parsed: unknown = JSON.parse(raw);
  return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
}

async function readOne(dir: string, ctx: DoctorContext): Promise<SessionRead | null> {
  const file = path.join(dir, FILE_NAME);
  let parsed: Record<string, unknown> | null;
  try {
    parsed = await readJson(file);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    return { kind: "unreadable", error: errorText(err) };
  }
  const sessionCode = parsed?.["sessionCode"];
  if (typeof sessionCode !== "string" || sessionCode === "") return null;

  if (parsed?.["tokenProtected"] === true) {
    if (!ctx.tokenVault) return { kind: "protected" };
    try {
      if (!ctx.tokenVault.isAvailable()) return { kind: "protected" };
      const ciphertext = await fs.promises.readFile(path.join(dir, TOKEN_FILE_NAME));
      const agentToken = ctx.tokenVault.decrypt(ciphertext);
      return agentToken ? { kind: "found", sessionCode, agentToken } : { kind: "protected" };
    } catch {
      // A vault that is not usable from here is "we could not read it", never
      // "there is nothing to read".
      return { kind: "protected" };
    }
  }

  const agentToken = parsed?.["agentToken"];
  if (typeof agentToken !== "string" || agentToken === "") return null;
  return { kind: "found", sessionCode, agentToken };
}

/** The first location that answers, in the agent's own order of preference. */
export async function readStoredSession(ctx: DoctorContext): Promise<SessionRead> {
  let deferred: SessionRead | null = null;
  for (const dir of sessionReadDirs(ctx.configDir)) {
    const read = await readOne(dir, ctx);
    if (!read) continue;
    if (read.kind === "found") return read;
    // Keep looking: a protected or unreadable copy in /etc must not hide a
    // usable one in the per-user directory, which is the order the agent walks.
    deferred ??= read;
  }
  return deferred ?? { kind: "none" };
}
