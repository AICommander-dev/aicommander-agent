import fs from "node:fs";
import path from "node:path";

/** Thrown when AICOMMANDER_CONFIG_DIR is set to a path we cannot store into. */
export class ConfigDirError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigDirError";
  }
}

/** Validated value, cached per raw env value so we syscall once per process. */
let validated: { raw: string; dir: string } | null = null;

/**
 * Optional override for the durable identity/session directory.
 *
 * `device.ts` and `session-store.ts` default to /etc with a ~/.config fallback,
 * which assumes /etc survives a reboot. That is not universally true: QNAP QTS
 * rebuilds its whole root filesystem — /etc, /var/run and /usr/local alike —
 * from a ramdisk on every boot, and some container images are equally volatile.
 * An agent persisting its identity there comes back from a restart with a NEW
 * session code and no linked accounts.
 *
 * Setting AICOMMANDER_CONFIG_DIR points both stores at durable storage instead
 * (on QNAP, a directory on the data volume). It is consulted only when no
 * explicit `configDir` was passed — the desktop app's per-user data dir still
 * wins — so leaving it unset preserves the existing behaviour exactly.
 *
 * An EMPTY or whitespace-only value is treated as unset (the defaults apply):
 * `AICOMMANDER_CONFIG_DIR=` and an absent variable are the same statement of
 * intent from a shell or a service wrapper, and wrappers that build the value can
 * legitimately end up with an empty string. A NON-blank but unusable value
 * THROWS instead of falling back to the defaults. Every other
 * store failure in this package has a safe fallback (/etc → ~/.config); this one
 * does not: silently reverting to a volatile /etc is precisely the "new device id
 * and new session code on every restart" failure the override exists to prevent,
 * and nothing downstream would report it (`loadOrCreateDevice` returns an
 * in-memory identity, `saveSession` no-ops outside strict mode). We deliberately
 * do NOT gate this on `isStrictCredentialStorage()`: the QNAP service that needs
 * the override most is not a systemd unit, so it would land in the quiet branch.
 */
export function envConfigDir(): string | undefined {
  const raw = process.env["AICOMMANDER_CONFIG_DIR"]?.trim();
  if (!raw) return undefined;
  if (validated?.raw === raw) return validated.dir;

  // Relative paths resolve against a cwd the operator does not control (the
  // service inherits QDK's extraction dir, systemd's WorkingDirectory, …).
  if (!path.isAbsolute(raw)) {
    throw new ConfigDirError(
      `AICOMMANDER_CONFIG_DIR must be an absolute path (got "${raw}").`,
    );
  }
  try {
    fs.mkdirSync(raw, { recursive: true, mode: 0o700 });
    fs.accessSync(raw, fs.constants.W_OK);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new ConfigDirError(
      `AICOMMANDER_CONFIG_DIR "${raw}" is not a usable directory: ${detail}. ` +
      `Point it at durable, writable storage — the device identity and session code live there.`,
    );
  }

  validated = { raw, dir: raw };
  return raw;
}
