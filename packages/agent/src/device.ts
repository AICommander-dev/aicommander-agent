import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { randomUUID, randomBytes } from "node:crypto";
import { ConfigDirError, envConfigDir } from "./config-dir.js";

export interface DeviceIdentity {
  deviceId: string;
  deviceSecret: string;
}

/**
 * Durable device identity directory.
 *
 * Primary path is /etc, which survives reboots on a normal distro. IMPORTANT: we
 * must NOT use /var/run (tmpfs — cleared on reboot), which is where the transient
 * state.json lives. For non-root / dev environments we fall back to the user's
 * config dir.
 *
 * Where /etc is NOT durable either — QNAP QTS rebuilds it from a ramdisk on every
 * boot — set AICOMMANDER_CONFIG_DIR to durable storage; see config-dir.ts.
 */
const PRIMARY_DIR = "/etc/aicommander-agent";
const FALLBACK_DIR = path.join(os.homedir(), ".config", "aicommander-agent");
const FILE_NAME = "device.json";

function generateDevice(): DeviceIdentity {
  return {
    deviceId: randomUUID(),
    deviceSecret: randomBytes(32).toString("base64url"),
  };
}

function isValidDevice(value: unknown): value is DeviceIdentity {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as DeviceIdentity).deviceId === "string" &&
    (value as DeviceIdentity).deviceId.length > 0 &&
    typeof (value as DeviceIdentity).deviceSecret === "string" &&
    (value as DeviceIdentity).deviceSecret.length > 0
  );
}

function tryRead(filePath: string): DeviceIdentity | null {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    if (isValidDevice(parsed)) {
      return { deviceId: parsed.deviceId, deviceSecret: parsed.deviceSecret };
    }
  } catch {
    // Missing / unreadable / malformed — caller regenerates.
  }
  return null;
}

/** Best-effort delete of an identity file; ignores ENOENT / permission errors. */
function tryRemove(dir: string): void {
  try {
    fs.rmSync(path.join(dir, FILE_NAME), { force: true });
  } catch {
    // Missing / unreadable / not permitted — nothing to clean up.
  }
}

function tryWrite(dir: string, device: DeviceIdentity): boolean {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(dir, FILE_NAME), JSON.stringify(device, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Persist into the AICOMMANDER_CONFIG_DIR override, or THROW.
 *
 * envConfigDir() validates writability once per process and caches the result,
 * so a volume that filled up or went read-only AFTER that check passes the guard
 * and fails only here. There is deliberately no fallback and no silent continue:
 * writing to /etc instead is exactly the volatile storage the override exists to
 * stop trusting (config-dir.ts), and an identity that is persisted nowhere means
 * a NEW device id and a NEW session code on the next boot — the one thing the
 * README guarantees does not happen without `change-code` or a full uninstall.
 * Callers already tolerate a throw here: envConfigDir() itself throws from these
 * same call sites when the very same condition is visible earlier.
 */
function writeOverrideOrThrow(dir: string, device: DeviceIdentity): void {
  if (tryWrite(dir, device)) return;
  throw new ConfigDirError(
    `Failed to persist the device identity in AICOMMANDER_CONFIG_DIR ("${dir}"): ` +
    `the directory was writable at startup, so the volume is now full, read-only, or gone. ` +
    `Nothing on disk was changed — fix the storage and start again.`,
  );
}

/** An identity left in the default locations (primary first), or null. */
function readDefaultDirs(): DeviceIdentity | null {
  return (
    tryRead(path.join(PRIMARY_DIR, FILE_NAME)) ?? tryRead(path.join(FALLBACK_DIR, FILE_NAME))
  );
}

/**
 * Minting a fresh identity with no override in play means one of two things: a
 * genuine first run, or a CLI invocation that is missing the
 * AICOMMANDER_CONFIG_DIR the service runs with — in which case list-admins /
 * block-admin register a SECOND device and address a machine the relay has never
 * seen. The two are indistinguishable from inside the process, so say it out loud.
 */
function warnNewIdentity(): void {
  console.warn(
    "\n  ℹ  No device identity found — this machine registers as NEW.\n" +
    "     If the agent here runs with AICOMMANDER_CONFIG_DIR set, export the same\n" +
    "     value for CLI commands; otherwise they address a different device.\n",
  );
}

/**
 * Load the persisted device identity, or create and persist a new one.
 *
 * The same deviceSecret must be sent on every registration so the relay can map
 * a re-registering agent (after reboot or 24h session-code rotation) back to the
 * same saved machine.
 *
 * When `configDir` is provided (e.g. the desktop app's per-user data dir), the
 * identity is stored directly under it (`<configDir>/device.json`) and nothing
 * else is consulted. With AICOMMANDER_CONFIG_DIR set we store it under that
 * directory, but still ADOPT an identity left in the default locations by an
 * earlier install (see below). With neither, we try the primary (/etc) location
 * first, then fall back to the user config dir if /etc is not writable
 * (non-root / dev).
 *
 * Only the AICOMMANDER_CONFIG_DIR branch THROWS when the write fails; the other
 * two keep the documented best-effort behaviour and return an in-memory identity.
 */
export function loadOrCreateDevice(configDir?: string): DeviceIdentity {
  if (configDir) {
    const existing = tryRead(path.join(configDir, FILE_NAME));
    if (existing) return existing;
    const device = generateDevice();
    tryWrite(configDir, device);
    return device;
  }

  const envDir = envConfigDir();
  if (envDir) {
    const existing = tryRead(path.join(envDir, FILE_NAME));
    if (existing) return existing;

    // Turning the override on for an already-registered machine must not orphan
    // it: without this, the agent registers as a brand-new device and every
    // linked account is lost. We COPY rather than read through, because /etc is
    // exactly the location the override exists to stop trusting — on QNAP it is
    // gone after the next boot, and a read-through would find nothing then.
    const inherited = readDefaultDirs();
    if (inherited) {
      console.warn(
        `\n  ℹ  Adopting the existing device identity into AICOMMANDER_CONFIG_DIR (${envDir}).\n`,
      );
      writeOverrideOrThrow(envDir, inherited);
      return inherited;
    }

    const device = generateDevice();
    writeOverrideOrThrow(envDir, device);
    return device;
  }

  // Prefer an existing identity from either location (primary first).
  const existing = readDefaultDirs();
  if (existing) return existing;

  // First run (or unrecoverable file) — generate and persist.
  warnNewIdentity();
  const device = generateDevice();
  if (tryWrite(PRIMARY_DIR, device)) return device;
  tryWrite(FALLBACK_DIR, device);
  // Even if both writes fail, return the in-memory identity so the agent can run.
  return device;
}

/**
 * Mint and persist a BRAND-NEW device identity, overwriting any existing one.
 *
 * Recovery path for when the relay rejects the current identity (a 403 device
 * secret mismatch — e.g. a stale relay record whose secret no longer matches).
 * Retrying the same identity would 403 forever, so the agent regenerates once
 * and re-registers as a fresh device. The machine then appears as new on the
 * relay (any prior account/alias binding must be re-established).
 *
 * Crucially, we also remove any stale identity file in the NON-target directory.
 * `loadOrCreateDevice` reads PRIMARY first, then FALLBACK — so a lingering old
 * file in the directory we didn't write to could be read back on the next start,
 * resurrecting the rejected identity and re-entering the 403 loop. Removal is
 * best-effort (ENOENT / permission errors are ignored).
 *
 * That purge is load-bearing under AICOMMANDER_CONFIG_DIR too: the variable can
 * be absent on a later manual `run` (or any CLI subcommand), which would read the
 * rejected identity straight back out of /etc. An explicit `configDir` needs no
 * purge — the desktop process always passes it, so nothing else is ever read.
 *
 * EVERY purge is gated on a DURABLE write of the fresh identity. Deleting the
 * fallbacks after a write we never confirmed would leave the identity persisted
 * nowhere, and the next start would mint a third one — losing the stable session
 * code instead of recovering it.
 */
export function regenerateDevice(configDir?: string): DeviceIdentity {
  const device = generateDevice();
  if (configDir) {
    // Best-effort, like loadOrCreateDevice's configDir branch: nothing is purged
    // here, so a failed write destroys nothing and the desktop app keeps running
    // on the in-memory identity.
    tryWrite(configDir, device);
    return device;
  }
  const envDir = envConfigDir();
  if (envDir) {
    // Throws before the purge below when the override storage went bad, so the
    // existing identity survives to be retried rather than being deleted.
    writeOverrideOrThrow(envDir, device);
    tryRemove(PRIMARY_DIR);
    tryRemove(FALLBACK_DIR);
    return device;
  }
  // Write to whichever directory is writable, and purge the OTHER one so the
  // rejected identity can't be read back from it.
  if (tryWrite(PRIMARY_DIR, device)) {
    tryRemove(FALLBACK_DIR);
    return device;
  }
  if (tryWrite(FALLBACK_DIR, device)) {
    tryRemove(PRIMARY_DIR);
    return device;
  }
  // Neither default location took the fresh identity. Keep both stale copies:
  // a rejected identity that is still readable re-enters the 403 path (which
  // regenerates again), whereas deleting the only records on disk makes this
  // machine a brand-new device on every single start. We do NOT throw on this
  // path — unlike the override, the defaults carry no operator promise of
  // durability, and a non-root dev run legitimately cannot write /etc.
  return device;
}
