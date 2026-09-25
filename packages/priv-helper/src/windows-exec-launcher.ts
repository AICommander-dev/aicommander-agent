import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

const REQUEST_MAGIC = Buffer.from("AICEXE01", "ascii");
const RESPONSE_MAGIC = Buffer.from("AICEXR01", "ascii");
const PROTOCOL_VERSION = 1;
const REQUEST_HEADER_BYTES = 16;
const RESPONSE_HEADER_BYTES = 20;
const MAX_ERROR_MESSAGE_BYTES = 4 * 1024;
const MAX_COMMAND_BYTES = 64 * 1024;
const PE_X64_MACHINE = 0x8664;

export const WINDOWS_LAUNCHER_HANDSHAKE_TIMEOUT_MS = 10_000;
export const WINDOWS_LAUNCHER_NAME_X64 = "aicommander-win-exec-x64.exe";
export const WINDOWS_LAUNCHER_HASH_SUFFIX = ".sha256";

export interface LauncherHandshakeReady {
  kind: "ready";
  trailingOutput: Buffer;
}

export interface LauncherHandshakeError {
  kind: "error";
  message: string;
}

export type LauncherHandshakeResult = LauncherHandshakeReady | LauncherHandshakeError;

/** Encode the exact bounded UTF-16LE stdin protocol consumed by the launcher. */
export function encodeWindowsLauncherRequest(command: string): Buffer {
  if (command.includes("\0")) {
    throw new Error("Windows command contains an unsupported NUL character");
  }
  // The launcher runs the command as `cmd.exe /d /s /c "<command>"`, and cmd.exe
  // stops parsing that line at the first newline: everything after it is
  // silently discarded and the caller gets exit code 0 for a program we never
  // ran. No escaping fixes it — the newline never reaches a statement separator
  // — and writing the command to a script file is not an option either, because
  // the launcher's trust model is that it travels only over this bounded stdin
  // protocol, never over disk or a command line. So it is refused as a property
  // of the REQUEST, the same way and with the same advice as a job command.
  // A newline only AFTER the command is harmless (cmd.exe has already parsed
  // the whole line) and keeps working, so only interior breaks are rejected.
  if (/[\r\n]/.test(command.replace(/[\r\n]+$/, ""))) {
    throw new Error(
      "A command cannot contain a line break on Windows: cmd.exe stops reading at the newline, so only the first line would run. Join the steps with `&&` instead. This is a property of the request, so sending it again unchanged will fail the same way.",
    );
  }
  const body = Buffer.from(command, "utf16le");
  if (body.length > MAX_COMMAND_BYTES) {
    throw new Error("Windows command is too large for the launcher protocol");
  }
  const frame = Buffer.allocUnsafe(REQUEST_HEADER_BYTES + body.length);
  REQUEST_MAGIC.copy(frame, 0);
  frame.writeUInt32LE(PROTOCOL_VERSION, 8);
  frame.writeUInt32LE(body.length, 12);
  body.copy(frame, REQUEST_HEADER_BYTES);
  return frame;
}

/** Incremental parser for the launcher's one private stdout handshake. */
export class WindowsLauncherHandshakeDecoder {
  #buffer = Buffer.alloc(0);
  #done = false;

  push(chunk: Buffer): LauncherHandshakeResult | null {
    if (this.#done) throw new Error("Windows launcher handshake was already consumed");
    this.#buffer = this.#buffer.length === 0
      ? Buffer.from(chunk)
      : Buffer.concat([this.#buffer, chunk]);
    if (this.#buffer.length < RESPONSE_HEADER_BYTES) return null;
    if (!this.#buffer.subarray(0, 8).equals(RESPONSE_MAGIC)) {
      throw new Error("Windows command launcher returned an invalid handshake");
    }
    const version = this.#buffer.readUInt32LE(8);
    const status = this.#buffer.readUInt32LE(12);
    const messageLength = this.#buffer.readUInt32LE(16);
    if (version !== PROTOCOL_VERSION || (status !== 0 && status !== 1)) {
      throw new Error("Windows command launcher returned an incompatible handshake");
    }
    if (messageLength > MAX_ERROR_MESSAGE_BYTES) {
      throw new Error("Windows command launcher returned an oversized handshake");
    }
    const frameLength = RESPONSE_HEADER_BYTES + messageLength;
    if (this.#buffer.length < frameLength) return null;
    if (status === 0 && messageLength !== 0) {
      throw new Error("Windows command launcher returned a malformed ready handshake");
    }
    this.#done = true;
    const message = this.#buffer.subarray(RESPONSE_HEADER_BYTES, frameLength).toString("utf8");
    if (status === 1) {
      return {
        kind: "error",
        message: message || "Windows command launcher could not start the command",
      };
    }
    return { kind: "ready", trailingOutput: this.#buffer.subarray(frameLength) };
  }
}

function assertTrustedX64Pe(path: string): void {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch {
    throw new Error("Windows command launcher is unavailable");
  }
  if (bytes.length < 0x40 || bytes.toString("ascii", 0, 2) !== "MZ") {
    throw new Error("Windows command launcher is not a valid PE executable");
  }
  const peOffset = bytes.readUInt32LE(0x3c);
  if (
    peOffset + 6 > bytes.length ||
    bytes.toString("ascii", peOffset, peOffset + 4) !== "PE\0\0" ||
    bytes.readUInt16LE(peOffset + 4) !== PE_X64_MACHINE
  ) {
    throw new Error("Windows command launcher is not a valid x64 PE executable");
  }

  let expectedHash: string;
  try {
    expectedHash = readFileSync(`${path}${WINDOWS_LAUNCHER_HASH_SUFFIX}`, "utf8").trim();
  } catch {
    throw new Error("Windows command launcher trust marker is unavailable");
  }
  if (!/^[a-fA-F0-9]{64}$/.test(expectedHash)) {
    throw new Error("Windows command launcher trust marker is invalid");
  }
  const actualHash = createHash("sha256").update(bytes).digest("hex");
  if (actualHash.toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error("Windows command launcher failed its installed trust check");
  }
}

/**
 * Resolve only the admin-installed sibling launcher and validate its native
 * architecture and installer-pinned SHA-256 before every execution.
 * Authenticode + ACL are enforced by the installer/registrar before the SYSTEM
 * task is registered; this runtime gate additionally fails closed for missing,
 * replaced, unpinned or wrong-architecture files.
 */
export function resolvePrivilegedWindowsLauncher(
  executable = process.execPath,
  pathExists: (path: string) => boolean = existsSync,
  explicitPath?: string,
  arch = process.arch,
): string {
  if (arch !== "x64") {
    throw new Error("Windows elevated command execution is unavailable on this architecture");
  }
  const path = explicitPath ?? join(dirname(executable), WINDOWS_LAUNCHER_NAME_X64);
  if (!pathExists(path)) throw new Error("Windows command launcher is unavailable");
  assertTrustedX64Pe(path);
  return path;
}

/** Test helper: form a valid response without duplicating the wire layout. */
export function encodeWindowsLauncherResponseForTest(
  status: "ready" | "error",
  message = "",
  trailingOutput = Buffer.alloc(0),
): Buffer {
  const body = Buffer.from(message, "utf8");
  const header = Buffer.alloc(RESPONSE_HEADER_BYTES);
  RESPONSE_MAGIC.copy(header, 0);
  header.writeUInt32LE(PROTOCOL_VERSION, 8);
  header.writeUInt32LE(status === "ready" ? 0 : 1, 12);
  header.writeUInt32LE(body.length, 16);
  return Buffer.concat([header, body, trailingOutput]);
}
