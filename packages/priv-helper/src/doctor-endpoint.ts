// `helper.endpoint` — the one check in the helper's doctor that talks to another
// process, split out of doctor.ts because that file had reached its size limit
// and this is the piece with its own subject: WHO is on the endpoint, and what
// this vantage point can and cannot establish about that.
//
// Everything here obeys the same two rules as the rest of the verb: it only
// READS (a `hello` carries no capability, and the socket is destroyed as soon as
// the answer arrives), and nothing a responder says reaches the report as text —
// booleans and numbers only, because the footer tells the reader the output is
// safe to forward.

import net from "node:net";
import { WIN_HELPER_TASK_NAME, type ElevatedEndpoint } from "./endpoint.js";
import { encodeFrame, FrameDecoder, IPC_PROTOCOL_VERSION } from "./protocol.js";
import { HELPER_VERSION } from "./version.js";
// Type-only, and deliberately: doctor.ts imports checkEndpoint from here, so a
// VALUE import back would be a module cycle. `import type` is erased.
import type { HelperCheck } from "./doctor.js";

function describeEndpoint(ep: ElevatedEndpoint): string {
  return ep.transport === "tcp" ? `tcp ${ep.host}:${ep.port}` : `unix ${ep.path}`;
}

/** What one endpoint said when asked to identify itself. */
export interface EndpointObservation {
  endpoint: string;
  /** The connection was accepted — SOMETHING is bound there, whoever it is. */
  connected: boolean;
  /** A complete `hello-ok` came back. */
  answered: boolean;
  /**
   * The helper's per-boot nonce, or null when the responder would not give a
   * usable one. It is what says WHICH process answered.
   */
  bootId: string | null;
  /**
   * The IPC protocol version the responder announced in its `hello-ok`, or null
   * when it announced none. Compared, not merely recorded: the agent refuses
   * elevated execution against a version it does not speak
   * (elevated-executor.ts's `protocol_mismatch`, and the agent's own doctor
   * requires the match before an endpoint counts as identified), so a responder
   * this check called healthy on a protocol we cannot speak would be a clean
   * verdict about a machine where every elevated command correctly fails.
   */
  protocolVersion: number | null;
  /** Why nothing answered, for the endpoints where nothing did. */
  error: string | null;
  /**
   * SOMETHING answered our `hello` with an `error` frame and hung up.
   *
   * NOT "the helper refused us", which is what this used to be read as. On a
   * fresh connection carrying exactly one `hello`, OUR helper sends `error` for
   * one reason only — a protocol version it will not speak (helper.ts; its other
   * two `error` cases need a second frame or a completed handshake, neither of
   * which happens here) — so a half-applied upgrade produces exactly this. But
   * so does any local process that bound the address first and wrote four bytes
   * of framing: an `error` frame carries no bootId and nothing else that could
   * say who sent it. The flag therefore records the SHAPE of the answer, and
   * `checkEndpoint` is careful not to turn a shape into an identity.
   *
   * A BOOLEAN, NOT THE MESSAGE, for the same reason it always was: the text is
   * an untrusted string from whatever is on the port, on its way into a report
   * we tell people to forward.
   */
  refused: boolean;
}

/**
 * Complete the `hello` handshake against one endpoint and hang up.
 *
 * NOT a bare TCP connect, which is what this used to be. "Something accepted a
 * connection on a loopback port" is not the question — any unprivileged process
 * can bind one of the candidate ports while the helper is down and be reported
 * as a healthy privileged helper. The agent's own discovery and its doctor both
 * require a `hello-ok` carrying a usable `bootId` and fail closed when two
 * endpoints disagree about it (agent/src/elevated-executor.ts,
 * doctor/checks/priv-helper.ts); a diagnostic must not be weaker than the thing
 * it is diagnosing, or it will report "fine" about the exact state in which
 * every elevated command correctly refuses to run.
 *
 * This is still only a READ: `hello` carries no capability, nothing is executed,
 * and the socket is destroyed as soon as the frame arrives.
 */
function handshake(ep: ElevatedEndpoint, timeoutMs: number): Promise<EndpointObservation> {
  const endpoint = describeEndpoint(ep);
  return new Promise((resolve) => {
    let base: EndpointObservation = {
      endpoint,
      connected: false,
      answered: false,
      bootId: null,
      protocolVersion: null,
      error: null,
      refused: false,
    };
    let socket: net.Socket;
    try {
      socket =
        ep.transport === "tcp"
          ? net.connect({ host: ep.host, port: ep.port })
          : net.connect({ path: ep.path });
    } catch (err) {
      resolve({ ...base, error: err instanceof Error ? err.message : String(err) });
      return;
    }
    const decoder = new FrameDecoder();
    let settled = false;
    const done = (result: EndpointObservation): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs, () => done({ ...base, error: "timed out" }));
    socket.once("connect", () => {
      base = { ...base, connected: true };
      socket.write(
        encodeFrame({ t: "hello", protocolVersion: IPC_PROTOCOL_VERSION, clientVersion: HELPER_VERSION }),
      );
    });
    socket.on("data", (chunk: Buffer) => {
      let frames: Array<Record<string, unknown>>;
      try {
        frames = decoder.push(chunk);
      } catch (err) {
        done({ ...base, error: `protocol error: ${err instanceof Error ? err.message : String(err)}` });
        return;
      }
      for (const frame of frames) {
        // A REFUSAL IS AN ANSWER, and this loop used to throw it away. The live
        // helper replies to a `hello` it cannot speak to with
        // `{t:"error", message:"unsupported IPC protocol version …"}` and closes;
        // discarding that frame left the subsequent close to be reported as
        // "something is listening … did not identify itself", with a remedy that
        // sends the reader hunting for a squatter — when the likelier cause is
        // much duller: the installed binary and this one are different builds,
        // and the fix is to finish the upgrade. Recorded, therefore, as a shape
        // and not as an identity: see `refused` above and the verdict below.
        if (frame["t"] === "error") {
          done({ ...base, refused: true });
          return;
        }
        if (frame["t"] !== "hello-ok") continue;
        const bootId = frame["bootId"];
        const proto = frame["protocolVersion"];
        done({
          ...base,
          answered: true,
          bootId: typeof bootId === "string" && bootId.length > 0 ? bootId : null,
          protocolVersion: typeof proto === "number" ? proto : null,
        });
        return;
      }
    });
    socket.once("error", (err: NodeJS.ErrnoException) => done({ ...base, error: err.code ?? err.message }));
    socket.once("close", () => done({ ...base, error: "closed the connection without answering" }));
  });
}

/** How to get the helper running again, on each platform. */
function startRemedy(): string {
  return process.platform === "win32"
    ? `Its SYSTEM task ("${WIN_HELPER_TASK_NAME}") starts it at boot. Re-run the installer, then reboot.`
    : "Its LaunchDaemon starts it at boot. Re-install from the .pkg, then reboot.";
}

/**
 * Does THE HELPER answer where the helper listens — not "does anything".
 *
 * Every candidate is probed, because the Windows helper binds the whole pool at
 * boot precisely so nobody else can sit on one of them (endpoint.ts). Two
 * distinct bootIds mean something that is not the helper is answering, which is
 * the state in which the agent refuses elevated execution; an answer with no
 * usable bootId is not an answer at all. Both are FAILURES with their own
 * sentence — never "listening", and never collapsed into "nothing is there".
 */
export async function checkEndpoint(
  timeoutMs: number,
  endpoints: readonly ElevatedEndpoint[],
): Promise<HelperCheck> {
  const id = "helper.endpoint";
  const title = "Privileged helper — endpoint";
  if (endpoints.length === 0) {
    return {
      id,
      title,
      verdict: "skipped",
      detail: "elevated execution is a macOS/Windows feature; there is no endpoint on this platform.",
    };
  }
  const observations: EndpointObservation[] = [];
  for (const ep of endpoints) observations.push(await handshake(ep, timeoutMs));

  // IDENTIFIED = answered, said WHICH process it is, AND speaks our protocol.
  // The last conjunct is not decoration: a responder on another version is one
  // the agent will not talk to (`protocol_mismatch`), so counting it here as the
  // privileged helper reports "fine" about the exact state in which every
  // elevated command fails closed — the rule stated in handshake()'s header,
  // applied to the version as well as to the bootId.
  const identified = observations.filter(
    (o) => o.answered && o.bootId !== null && o.protocolVersion === IPC_PROTOCOL_VERSION,
  );
  const bootIds = new Set(identified.map((o) => o.bootId));
  if (bootIds.size > 1) {
    return {
      id,
      title,
      verdict: "fail",
      detail:
        `${bootIds.size} different processes answered the helper endpoints ` +
        `(${identified.map((o) => o.endpoint).join(", ")}), so at least one of them is not the privileged helper.`,
      remedy:
        "Elevated commands fail closed in exactly this state, deliberately. Reboot so the helper reclaims every " +
        "port, and if it persists, find what else is listening before trusting elevated execution here.",
    };
  }
  const answered = identified[0];
  if (answered) {
    return {
      id,
      title,
      verdict: "ok",
      detail: `the privileged helper answered its handshake on ${answered.endpoint}.`,
    };
  }
  // PROTOCOL SKEW IS NOT A SQUATTER — AND IT IS NOT PROOF OF THE HELPER EITHER.
  // Checked before the anonymous case below because it is strictly more
  // specific: the responder spoke our framing, and either named a protocol
  // version or refused ours. Reporting that as "find what else is listening" is
  // a support case pointed at the wrong thing, because a half-applied upgrade is
  // the likelier cause and its remedy is different (`protocol_mismatch` is the
  // agent's name for the same state). But the opposite rounding is worse, and
  // this branch used to do it: NOTHING IN EITHER SHAPE SAYS WHICH PROCESS
  // ANSWERED. An `error` frame carries no bootId at all, a `hello-ok`'s bootId
  // is a value the responder chooses, and any local process that bound the
  // address ahead of the helper can produce both. Calling such a responder "the
  // helper, on the wrong protocol version" tells the reader the port is
  // legitimately ours and hands them a re-install — which is a worse answer
  // about a squatter than the anonymous-squatter sentence it replaced.
  //
  // So the verdict names BOTH possibilities and says it cannot tell them apart:
  // "could not establish" is its own answer, never rounded to the flattering
  // neighbour. The facts it prints are ours (a version number the responder
  // announced, or that it announced none) — never its text.
  //
  // TWO SHAPES, ONE VERDICT, because our own helper produces both depending on
  // which side is older. A helper that does not speak OUR version replies
  // `{t:"error"}` and closes (`refused`); a helper whose `hello-ok` announces a
  // version WE do not speak is the same skew seen from the other end, and is the
  // one the old `identified` filter let through as healthy.
  const skewed = observations.find(
    (o) => o.refused || (o.answered && o.protocolVersion !== null && o.protocolVersion !== IPC_PROTOCOL_VERSION),
  );
  if (skewed) {
    const spoken = skewed.refused
      ? "refused ours without naming its own"
      : `speaks IPC protocol ${skewed.protocolVersion}`;
    return {
      id,
      title,
      verdict: "fail",
      detail:
        `protocol mismatch on ${skewed.endpoint}: something there speaks this protocol's framing but ${spoken}, ` +
        `while this binary (${HELPER_VERSION}) speaks IPC protocol ${IPC_PROTOCOL_VERSION}. Nothing in that ` +
        "exchange says WHICH process it is — an error frame carries no boot id, and a boot id is a value the " +
        "responder chooses — so this is either the privileged helper from a half-applied upgrade, which is the " +
        "likelier of the two, or something else holding the endpoint; this check cannot tell which. Elevated " +
        "commands fail closed against a version skew either way, deliberately.",
      remedy:
        "Re-run the installer, then reboot so the SYSTEM helper restarts on the new binary. If the same answer " +
        "survives that reboot, the responder is not the helper — find what else is holding the endpoint before " +
        "trusting elevated execution here.",
    };
  }
  // ACCEPTED IS NOT IDENTIFIED. Either shape — a full `hello-ok` with no usable
  // bootId, or a listener that took the connection and never said who it is —
  // is something on the helper's endpoint that is not known to be the helper.
  const anonymous = observations.find((o) => o.answered) ?? observations.find((o) => o.connected);
  if (anonymous) {
    return {
      id,
      title,
      verdict: "fail",
      detail:
        `something is listening on ${anonymous.endpoint} but did not identify itself as the helper ` +
        `(${anonymous.answered ? "no boot id in its answer" : (anonymous.error ?? "no answer")}), ` +
        "so it is not treated as one — a connection that is accepted is not proof of who accepted it.",
      remedy:
        "Elevated commands fail closed against an unidentified responder. Reboot so the helper rebinds its " +
        "endpoints, and check what else is listening if it persists.",
    };
  }
  const errors = observations.map((o) => `${o.endpoint}: ${o.error ?? "no answer"}`);
  return {
    id,
    title,
    verdict: "fail",
    detail: `nothing answered the helper endpoint (${errors.join("; ")}) — elevated execution is unavailable on this machine.`,
    remedy: startRemedy(),
  };
}
