// Frozen local-IPC contract between the per-user tray agent (client) and the
// per-machine privileged helper (server). This is the ONLY wire format spoken
// over the unix socket / named pipe; both sides import these types so they can
// never drift.
//
// SECURITY POSITION (read this before touching anything here):
//   The authorization boundary for elevated execution is the RELAY-SIGNED
//   capability (compact JWS, verified against a pinned Ed25519 public key inside
//   the helper — see capability-verify.ts). This local channel is HYGIENE only:
//   its job is to move an already-authorized, short-lived, single-use capability
//   from the tray to the helper and stream the result back. A hostile same-user
//   process that reaches this socket/pipe still cannot MINT or FORGE a capability
//   — the worst it can do is replay a live one (defeated by anti-replay +
//   expiry) or squat the endpoint (a DoS; the boot-time service owns it first).
//   Native channel hardening (Windows pipe DACL + peer-cred, mac getpeereid,
//   Job Object KILL_ON_JOB_CLOSE) is additive defense-in-depth layered later; it
//   is NOT the thing that keeps same-user malware from running as root.

/** Bumped when this IPC wire shape changes; both sides pin a minimum. */
export const IPC_PROTOCOL_VERSION = 1;

/**
 * Hard cap on a single decoded frame (JSON message). Output chunks are streamed
 * as many small `output` frames, so no legitimate frame is large; a giant length
 * prefix is a hostile/corrupt peer and the decoder aborts the connection.
 */
export const MAX_FRAME_BYTES = 1 << 20; // 1 MiB

// --- Client → Helper --------------------------------------------------------

/** Handshake; MUST be the first frame the client sends. */
export interface HelloMsg {
  t: "hello";
  protocolVersion: number;
  /** Human-readable client (agent) version, for skew diagnostics + audit. */
  clientVersion: string;
}

/**
 * Run ONE relay-signed elevated command. `capability` is the compact JWS; the
 * command / cwd / env / timeout are read from the SIGNED claims inside it, never
 * from any unsigned field on the wire.
 */
export interface ExecMsg {
  t: "exec";
  /** Correlates output/done/error and matches the signed capability.requestId. */
  requestId: string;
  /** Compact-JWS ElevatedCapabilityClaims (EdDSA); the helper verifies it. */
  capability: string;
}

/** Kill a running command by its requestId (late kills for a settled/unknown id are no-ops). */
export interface KillMsg {
  t: "kill";
  requestId: string;
}

export type ClientToHelperMsg = HelloMsg | ExecMsg | KillMsg;

// --- Helper → Client --------------------------------------------------------

/** Handshake ack; carries the helper identity the client surfaces + audits. */
export interface HelloOkMsg {
  t: "hello-ok";
  protocolVersion: number;
  helperVersion: string;
  /**
   * Random per-boot nonce. The relay binds it into every capability
   * (claims.helperInstanceId) and the helper REQUIRES the match, so a capability
   * minted before this helper's last restart (or for a different helper) is rejected.
   */
  bootId: string;
  /** e.g. "root" (uid 0) or "nt authority\\system" — the identity commands will run as. */
  effectiveIdentity: string;
}

/** A chunk of command output. `chunk` is base64 (binary-safe, matches the exec path). */
export interface OutputMsg {
  t: "output";
  requestId: string;
  chunk: string;
  stream: "stdout" | "stderr";
}

/** Terminal success frame for a command. */
export interface DoneMsg {
  t: "done";
  requestId: string;
  exitCode: number;
  durationMs: number;
  /** The identity the command actually ran as (defense-in-depth: client can assert it). */
  effectiveIdentity: string;
}

/**
 * Terminal error frame. `requestId` is present for a per-command failure and
 * omitted for a connection-level failure (bad handshake, malformed frame).
 */
export interface ErrorMsg {
  t: "error";
  requestId?: string;
  message: string;
}

export type HelperToClientMsg = HelloOkMsg | OutputMsg | DoneMsg | ErrorMsg;

// --- Framing (length-prefixed JSON) -----------------------------------------
//
// Wire frame = 4-byte big-endian uint32 byte-length of the UTF-8 JSON body,
// followed by exactly that many bytes. Length-prefixed (not newline-delimited)
// because command output is arbitrary binary/multiline and must never be
// confused with a message boundary.

/** Encode one message as a length-prefixed frame ready to write to the socket. */
export function encodeFrame(msg: ClientToHelperMsg | HelperToClientMsg): Buffer {
  const body = Buffer.from(JSON.stringify(msg), "utf8");
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

/**
 * Streaming frame decoder. Feed it raw socket chunks; it yields each complete
 * JSON message. It NEVER buffers past MAX_FRAME_BYTES: a length prefix over the
 * cap throws (the caller must destroy the connection), so a hostile peer cannot
 * force unbounded memory growth with a giant declared length.
 */
export class FrameDecoder {
  private buf: Buffer = Buffer.alloc(0);

  /** Append raw bytes and return every complete message now available. Throws on an oversized frame. */
  push(chunk: Buffer): Array<Record<string, unknown>> {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const out: Array<Record<string, unknown>> = [];

    for (;;) {
      if (this.buf.length < 4) break; // need the length prefix
      const len = this.buf.readUInt32BE(0);
      if (len > MAX_FRAME_BYTES) {
        throw new Error(`IPC frame length ${len} exceeds limit ${MAX_FRAME_BYTES}`);
      }
      if (this.buf.length < 4 + len) break; // body not fully arrived
      const body = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      let parsed: unknown;
      try {
        parsed = JSON.parse(body.toString("utf8"));
      } catch {
        throw new Error("IPC frame body is not valid JSON");
      }
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("IPC frame body is not a JSON object");
      }
      out.push(parsed as Record<string, unknown>);
    }
    return out;
  }
}
