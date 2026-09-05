import dns from "node:dns";
import type { IncomingMessage } from "node:http";
import { randomBytes } from "node:crypto";
import WebSocket from "ws";
import { readStoredSession } from "./session-read.js";
import {
  errnoOf,
  errorText,
  fail,
  ok,
  skipped,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorFacts,
} from "../types.js";

/**
 * The four steps between "the computer is on" and "the machine shows online",
 * each reported with the status code it actually produced.
 *
 * On 2026-09-02 the ticket exchange that precedes `wss://…/ws/agent?ticket=…`
 * was failing and NOTHING anywhere said so — the product could describe neither
 * the step nor the status. That is what this group answers, in the order the
 * agent itself performs them:
 *
 *   1. DNS       — does the relay's name resolve at all?
 *   2. HTTPS     — does a TLS request reach the relay, and what does it answer?
 *   3. Ticket    — does POST /api/agent/ws-ticket succeed with THIS machine's
 *                  stored agent token, and if not, with what status?
 *   4. Upgrade   — does the WebSocket upgrade reach the relay?
 *
 * ── WHAT THIS IS ALLOWED TO DO TO LIVE STATE, AND WHAT IT REFUSES TO ─────────
 * A diagnostic that fixes nothing is still capable of breaking something. Three
 * deliberate refusals:
 *
 *   - `register()` IS NEVER CALLED. On a machine with no stored session,
 *     registration MINTS one — a new session code, a new device identity — so a
 *     "check" of the registration endpoint would hand the user a machine that
 *     had quietly changed its own identity. The registration leg is therefore
 *     checked through the token that registration already produced (step 3),
 *     and a machine that has never registered gets `skipped`, not a fresh
 *     identity.
 *
 *   - The ticket IS requested, and then DISCARDED. Minting one is safe: the
 *     relay stores it in a Durable Object keyed by the ticket itself (see
 *     worker/src/agent-websocket.ts), so it invalidates no other ticket,
 *     rotates no token and touches no session record. It expires unused within
 *     seconds. This is the one call the incident needed and could not make.
 *
 *   - The upgrade probe carries NO credential and a ticket that cannot exist —
 *     64 random hex digits we never obtained from the relay. A 401 from the
 *     relay is therefore the PASSING answer: it proves TLS, the proxy chain and
 *     the `Upgrade` handshake all reach the relay's own code. Opening a real
 *     agent socket would evict the machine's live relay session, which is
 *     exactly the outage a user runs `doctor` to escape.
 */

/** What the relay's `/ws/agent` route requires a ticket to look like. */
const TICKET_HEX_LENGTH = 64;

interface HttpsObservation {
  result: CheckResult;
  /**
   * The relay's `Date` header and the local clock AT THE MOMENT IT ARRIVED, for
   * the clock-skew check. Both, because the skew is the difference between the
   * two readings and nothing else — reading the local clock later, after two more
   * network legs have run, measures those legs.
   */
  serverDate: Date | null;
  receivedAt: number | null;
}

/** Resolution of a call that did not answer inside its leg's budget. */
const TIMED_OUT = Symbol("doctor-net-timed-out");

/**
 * Await `work`, giving up at `timeoutMs`.
 *
 * `AbortSignal.timeout` covers `fetch`; `dns.promises.lookup` takes no signal at
 * all, and a resolver that never answers would otherwise hold the whole command
 * past every bound the caller was promised. Giving up does not cancel the
 * lookup — nothing can — so a late rejection is swallowed rather than surfacing
 * as an unhandled rejection after the report has been printed.
 */
async function withinTimeout<T>(work: Promise<T>, timeoutMs: number): Promise<T | typeof TIMED_OUT> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<typeof TIMED_OUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMED_OUT), timeoutMs);
    timer.unref?.();
  });
  try {
    const settled = await Promise.race([work, guard]);
    if (settled === TIMED_OUT) void work.catch(() => undefined);
    return settled;
  } finally {
    clearTimeout(timer);
  }
}

function relayHost(serverUrl: string): string | null {
  try {
    return new URL(serverUrl).hostname;
  } catch {
    return null;
  }
}

async function checkDns(ctx: DoctorContext): Promise<CheckResult> {
  const id = "net.dns";
  const title = "DNS";
  const host = relayHost(ctx.serverUrl);
  if (!host) return fail(id, title, `the relay URL is unusable: ${ctx.serverUrl}`);
  try {
    const addresses = await withinTimeout(dns.promises.lookup(host, { all: true }), ctx.networkTimeoutMs);
    if (addresses === TIMED_OUT) {
      return fail(
        id,
        title,
        `${host} did not resolve within ${ctx.networkTimeoutMs}ms.`,
        "The resolver this machine is configured with is not answering. A filtering or VPN resolver that " +
          "black-holes a query looks exactly like this, and the agent hangs on it the same way.",
        { host, timeoutMs: ctx.networkTimeoutMs },
      );
    }
    return ok(id, title, `${host} resolves to ${addresses.length} address(es).`, {
      host,
      addresses: addresses.map((a) => a.address).join(", "),
    });
  } catch (err) {
    return fail(
      id,
      title,
      `${host} does not resolve: ${errorText(err)}`,
      "The machine cannot look up the relay's name. Check the DNS settings, a VPN or a filtering resolver.",
      { host, ...(errnoOf(err) ? { code: errnoOf(err)! } : {}) },
    );
  }
}

async function checkHttps(ctx: DoctorContext): Promise<HttpsObservation> {
  const id = "net.https";
  const title = "HTTPS to the relay";
  try {
    const response = await fetch(ctx.serverUrl, {
      method: "GET",
      signal: AbortSignal.timeout(ctx.networkTimeoutMs),
    });
    // We want the headers, not the page. Releasing the body keeps the socket
    // from being held open for a document nobody reads.
    // The local reading is taken HERE, against the header we just received, and
    // carried to the clock check rather than re-read there.
    const receivedAt = Date.now();
    await response.body?.cancel().catch(() => undefined);
    const dateHeader = response.headers.get("date");
    const serverDate = dateHeader ? new Date(dateHeader) : null;
    const facts: DoctorFacts = {
      url: ctx.serverUrl,
      status: response.status,
      ...(dateHeader ? { serverDate: dateHeader } : {}),
    };
    const detail = `${ctx.serverUrl} answered HTTP ${response.status}.`;
    const usableDate = serverDate && !Number.isNaN(serverDate.getTime()) ? serverDate : null;
    return {
      serverDate: usableDate,
      receivedAt: usableDate ? receivedAt : null,
      result:
        response.status < 400
          ? ok(id, title, detail, facts)
          : warn(
              id,
              title,
              detail,
              "The relay is reachable but answered an error. If this persists, something between this machine " +
                "and the relay (a proxy, a TLS-inspecting gateway) is rewriting the response.",
              facts,
            ),
    };
  } catch (err) {
    return {
      serverDate: null,
      receivedAt: null,
      result: fail(
        id,
        title,
        `${ctx.serverUrl} could not be reached: ${errorText(err)}`,
        "Nothing HTTPS gets through. Check a firewall, a TLS-inspecting proxy, or an outbound rule added by " +
          "security software. Note that Node does not honour HTTP_PROXY/HTTPS_PROXY — see the proxy check.",
        { url: ctx.serverUrl, ...(errnoOf(err) ? { code: errnoOf(err)! } : {}) },
      ),
    };
  }
}

/**
 * The step the incident could not see. Uses the stored agent token — the
 * credential the agent itself presents — so a 401 here is the real answer to
 * "why is this machine offline", not an artefact of the probe.
 *
 * The session is read READ-ONLY (session-read.ts): `loadSession()` creates the
 * configured directory and chmods the files it finds, and a diagnostic may do
 * neither. Where the token is in OS-protected storage this process cannot open,
 * the check says exactly that — "we could not read the credential" is a
 * different statement from "this machine has never registered", and telling a
 * registered desktop install the second one sends its owner to re-register a
 * machine that is already fine.
 */
async function checkTicket(ctx: DoctorContext): Promise<CheckResult> {
  const id = "net.ticket";
  const title = "Connection ticket exchange";

  const session = await readStoredSession(ctx);
  if (session.kind === "unreadable") {
    return skipped(id, title, `the stored session could not be read (${session.error}).`);
  }
  if (session.kind === "protected") {
    return skipped(
      id,
      title,
      "this machine's agent token is held in OS-protected storage (the desktop's safeStorage) that this " +
        "process cannot open, so the ticket exchange cannot be tested from here. Run the same diagnostics " +
        "from the app's tray menu, which can.",
    );
  }
  if (session.kind === "none") {
    return skipped(
      id,
      title,
      "this machine has no stored session token yet, and registering one to test with would mint a new " +
        "session code — a diagnostic must not do that. Start the agent once, then re-run.",
    );
  }

  const url = `${ctx.serverUrl}/api/agent/ws-ticket`;
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.agentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sessionCode: session.sessionCode }),
      signal: AbortSignal.timeout(ctx.networkTimeoutMs),
    });
    const facts: DoctorFacts = { status: response.status };
    if (response.ok) {
      // A 2xx is not the answer; a 2xx CARRYING A TICKET is. Any transparent
      // proxy or captive portal can produce a 200, and the agent — which parses
      // this body and needs a 64-hex ticket out of it — would reject what we
      // would otherwise be calling healthy. The body is read only to check its
      // SHAPE: the ticket itself is never stored, never used and never recorded
      // in a fact. It is a short-lived credential and the only safe thing to do
      // with one we do not need is to let it expire.
      const shape = await ticketBodyShape(response);
      if (shape.valid) {
        return ok(id, title, `the relay issued a connection ticket (HTTP ${response.status}).`, facts);
      }
      return fail(
        id,
        title,
        `HTTP ${response.status} came back, but the body is not a connection ticket (${shape.reason}).`,
        "Something answered on the relay's behalf. The agent parses this response and would refuse it too, so " +
          "the machine cannot connect. Look for a TLS-inspecting proxy or a captive portal.",
        { ...facts, ...(shape.contentType ? { contentType: shape.contentType } : {}) },
      );
    }
    await response.body?.cancel().catch(() => undefined);
    if (response.status === 401 || response.status === 403) {
      return fail(
        id,
        title,
        `the relay rejected this machine's agent token (HTTP ${response.status}).`,
        "The stored credential is no longer accepted, so the agent can never open its socket. Reset the " +
          "access code (`aicommander-agent change-code`) or re-install the agent to register again.",
        facts,
      );
    }
    return fail(
      id,
      title,
      `the ticket exchange failed with HTTP ${response.status}.`,
      "This is the step that precedes the WebSocket upgrade. A 5xx is the relay; anything else usually means " +
        "something between this machine and the relay is answering on its behalf.",
      facts,
    );
  } catch (err) {
    return fail(
      id,
      title,
      `the ticket exchange could not be performed: ${errorText(err)}`,
      "The agent cannot get a ticket, so it can never open its socket, and the machine will show offline.",
      { url, ...(errnoOf(err) ? { code: errnoOf(err)! } : {}) },
    );
  }
}

/**
 * Does this body hold what `/api/agent/ws-ticket` returns — a `ticket` of
 * TICKET_HEX_LENGTH hex digits? The value is examined and dropped; only the
 * verdict and the content type leave this function.
 */
async function ticketBodyShape(
  response: Response,
): Promise<{ valid: boolean; reason: string; contentType: string | null }> {
  const contentType = response.headers.get("content-type");
  let body: string;
  try {
    body = await response.text();
  } catch (err) {
    return { valid: false, reason: `the body could not be read: ${errorText(err)}`, contentType };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { valid: false, reason: "it is not JSON", contentType };
  }
  const ticket = (parsed as { ticket?: unknown } | null)?.ticket;
  if (typeof ticket !== "string") return { valid: false, reason: "it carries no ticket", contentType };
  return new RegExp(`^[0-9a-f]{${TICKET_HEX_LENGTH}}$`).test(ticket)
    ? { valid: true, reason: "", contentType }
    : { valid: false, reason: "the ticket is not the shape the relay issues", contentType };
}

interface UpgradeObservation {
  status: number | null;
  upgraded: boolean;
  error: string | null;
  /**
   * Whether the refusal LOOKS like the relay's own. A status alone does not say
   * who produced it, and neither does the shape — see `looksLikeRelayRefusal`.
   */
  relayShaped: boolean;
  contentType: string | null;
}

/**
 * Why the TLS anchor on this probe does not identify who answered, or `null`
 * when it does.
 *
 * ── THE SHAPE OF A REFUSAL PROVES NOTHING ON ITS OWN ─────────────────────────
 * The previous fix here demanded 401 + `application/json` + a string `error`,
 * and called that "the relay". Any intermediary can emit exactly those three
 * bytes-for-bytes; a shape is a thing anyone can copy, so requiring more of it
 * would not have helped either. The identification, if there is one, has to come
 * from something an intermediary cannot copy.
 *
 * There is exactly one such thing available to an unauthenticated probe, and we
 * already depend on it: the connection is `wss:`, and Node validated the
 * certificate chain against its OWN bundled Mozilla root store. A proxy, a
 * captive portal or a corporate gateway that wants to answer for the relay must
 * therefore hold a publicly trusted certificate for the relay's hostname — which
 * is a different and much larger claim than "it can return a JSON 401".
 *
 * That argument holds only while the bundled store really is the anchor, and a
 * handful of settings quietly move it — which is precisely how a TLS-inspecting
 * gateway gets installed in the first place: two environment variables here, and
 * every flag in `TRUST_STORE_FLAGS` below, which is the list that has to stay
 * complete for the `ok` to be earned. Each one is observable from here,
 * and when any of them is in force the probe cannot identify the responder at
 * all; it says so, in a `warn`, rather than reporting a captive portal as a
 * healthy WebSocket path.
 */
export function tlsAnchorCaveat(wsUrl: string): string | null {
  if (!/^wss:/i.test(wsUrl)) {
    return "the upgrade was not made over TLS, so nothing about the responder's identity was established";
  }
  if (process.env["NODE_TLS_REJECT_UNAUTHORIZED"] === "0") {
    return "NODE_TLS_REJECT_UNAUTHORIZED=0 turns certificate validation off, so any responder is accepted";
  }
  if (process.env["NODE_EXTRA_CA_CERTS"]) {
    return "NODE_EXTRA_CA_CERTS trusts roots outside Node's bundled store, which is how an inspecting proxy " +
      "is trusted";
  }
  for (const flag of TRUST_STORE_FLAGS) {
    if (nodeFlagInForce(flag.name)) return flag.caveat;
  }
  return null;
}

/**
 * The Node flags that move the TLS anchor off the bundled Mozilla store, and
 * therefore invalidate the identification argument above.
 *
 * The LIST is the point, not any one entry: this shipped naming only
 * `--use-openssl-ca` while the Node the agent runs on (v24) also has
 * `--use-system-ca`, which does the same thing by a shorter route — it loads the
 * OS trust store, which is exactly where an enterprise deployment installs its
 * inspection CA. A caveat that names some of the ways the anchor moves is a
 * caveat that reports an intercepting proxy as a healthy relay on the rest.
 *
 * `--use-bundled-ca` is deliberately absent: it PINS the bundled store, which is
 * the assumption, not a widening of it.
 *
 * `SSL_CERT_FILE` and `SSL_CERT_DIR` are absent for a different reason — Node
 * reads them only under `--use-openssl-ca`, which is already caught here, so
 * flagging them on their own would put a caveat on a healthy machine whose
 * anchor never moved. If a future Node makes them effective by themselves they
 * belong in this list.
 */
const TRUST_STORE_FLAGS: Array<{ name: string; caveat: string }> = [
  {
    name: "--use-openssl-ca",
    caveat:
      "--use-openssl-ca makes the system trust store the anchor, and a corporate inspection CA is " +
      "installed into exactly that",
  },
  {
    name: "--use-system-ca",
    caveat:
      "--use-system-ca makes the operating system's trust store an anchor, and a corporate inspection CA " +
      "is installed into exactly that",
  },
];

/**
 * Is this Node flag in force for THIS process — on the command line, or through
 * `NODE_OPTIONS` (which is where a service wrapper or an IT policy puts one, and
 * which Node's allow-list accepts all of the flags above in)?
 *
 * `execArgv` entries are exact, except that a flag may carry `=value`. In
 * `NODE_OPTIONS` the flag must be whitespace-delimited, which is also what keeps
 * `--no-use-system-ca` — the negation, which does not move the anchor — from
 * matching `--use-system-ca`.
 */
function nodeFlagInForce(flag: string): boolean {
  if (process.execArgv.some((arg) => arg === flag || arg.startsWith(`${flag}=`))) return true;
  return new RegExp(`(^|\\s)${flag}(=\\S*)?(\\s|$)`).test(process.env["NODE_OPTIONS"] ?? "");
}

/** Enough of a refusal body to recognise its shape; never enough to quote. */
const MAX_REFUSAL_BODY_BYTES = 2048;

/**
 * Read a bounded prefix of an `unexpected-response` body without holding the
 * socket open for a document nobody wants. Resolves to "" on any trouble.
 */
function readBoundedBody(res: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let text = "";
    const done = (): void => {
      res.destroy();
      resolve(text);
    };
    res.setEncoding("utf8");
    res.on("data", (chunk: string) => {
      text += chunk;
      if (text.length >= MAX_REFUSAL_BODY_BYTES) done();
    });
    res.on("end", () => resolve(text));
    res.on("error", () => resolve(text));
  });
}

/**
 * Does this refusal have the SHAPE the relay's own has? Note the word: shape.
 *
 * The status on its own cannot tell the relay from an intercepting proxy, a
 * captive portal or a corporate gateway — they all answer 401 or 403 to a
 * request they will not forward. The relay's route answers `{"error":"…"}` as
 * JSON before it looks at anything else (worker/src/agent-websocket.ts
 * `unauthorized`), so this is a necessary condition and a useful screen. It is
 * NOT sufficient and is not treated as sufficient: see `tlsAnchorCaveat` for the
 * one piece of evidence in this probe that an intermediary cannot forge, and
 * `checkUpgrade` for what the verdict says when that evidence is unavailable.
 *
 * The body is classified and DISCARDED — a proxy's error page is somebody else's
 * text and has no business in a report bound for a vendor.
 */
function looksLikeRelayRefusal(status: number, contentType: string | null, body: string): boolean {
  if (status !== 401) return false;
  if (!/application\/json/i.test(contentType ?? "")) return false;
  try {
    const parsed: unknown = JSON.parse(body);
    return typeof (parsed as { error?: unknown } | null)?.error === "string";
  } catch {
    return false;
  }
}

/**
 * Reach the `/ws/agent` upgrade WITHOUT being able to take the session.
 *
 * No Authorization header, and a ticket of 64 random hex digits that no Durable
 * Object holds. The relay's route answers `401` before it looks at anything
 * else, which is precisely the evidence we want: the upgrade handshake survived
 * the network path. An accepted upgrade is impossible; if one ever happened we
 * close it immediately rather than sit on a socket.
 */
function probeUpgrade(wsUrl: string, timeoutMs: number): Promise<UpgradeObservation> {
  return new Promise((resolve) => {
    const blank: UpgradeObservation = {
      status: null,
      upgraded: false,
      error: null,
      relayShaped: false,
      contentType: null,
    };
    let socket: WebSocket;
    try {
      socket = new WebSocket(wsUrl, { handshakeTimeout: timeoutMs });
    } catch (err) {
      resolve({ ...blank, error: errorText(err) });
      return;
    }
    let settled = false;
    /**
     * A refusal is in hand and its body is still being read. `ws` can emit
     * `error` on the same socket a moment later, and the STATUS is the better
     * evidence — letting the error win would turn "the relay refused us, as it
     * should" into "nothing answered". The outer timer still bounds the wait.
     */
    let refusalPending = false;
    const finish = (observation: UpgradeObservation): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Already gone.
      }
      try {
        socket.terminate();
      } catch {
        // Already gone.
      }
      resolve(observation);
    };
    const timer = setTimeout(() => finish({ ...blank, error: "timed out" }), timeoutMs);
    timer.unref?.();
    socket.on("unexpected-response", (_req, res) => {
      refusalPending = true;
      const status = res.statusCode ?? null;
      const contentType = res.headers?.["content-type"] ?? null;
      // The refusal's body decides WHO refused; the timer is still running, so a
      // response that never ends still settles on time.
      void readBoundedBody(res).then((body) => {
        finish({
          ...blank,
          status,
          contentType,
          relayShaped: status !== null && looksLikeRelayRefusal(status, contentType, body),
        });
      });
    });
    socket.on("open", () => finish({ ...blank, status: 101, upgraded: true }));
    socket.on("error", (err) => {
      if (refusalPending) return;
      finish({ ...blank, error: errorText(err) });
    });
  });
}

async function checkUpgrade(ctx: DoctorContext): Promise<CheckResult> {
  const id = "net.websocket";
  const title = "WebSocket upgrade";
  const endpoint = `${ctx.serverUrl.replace(/^http/, "ws")}/ws/agent`;
  const ticket = randomBytes(TICKET_HEX_LENGTH / 2).toString("hex");
  const wsUrl = `${endpoint}?ticket=${ticket}`;
  const observation = await probeUpgrade(wsUrl, ctx.networkTimeoutMs);
  const facts: DoctorFacts = {
    endpoint,
    status: observation.status,
    ...(observation.contentType ? { contentType: observation.contentType } : {}),
    ...(observation.error ? { error: observation.error } : {}),
  };

  if (observation.upgraded) {
    // Cannot happen against the real relay (no credential was sent), so if it
    // does, whatever answered is not the relay.
    return warn(
      id,
      title,
      "the upgrade was ACCEPTED without any credential — whatever answered is not the AI Commander relay.",
      "Something on the network is intercepting the connection. Check for a TLS-inspecting proxy.",
      facts,
    );
  }
  if (observation.status !== null) {
    // A 401 shaped like the relay's own is the expected answer to a deliberately
    // invalid ticket — but the shape is copyable, so the verdict turns on whether
    // the TLS anchor makes the responder's identity provable (tlsAnchorCaveat).
    if (observation.relayShaped) {
      const caveat = tlsAnchorCaveat(wsUrl);
      if (caveat === null) {
        return ok(
          id,
          title,
          `the upgrade was refused with HTTP ${observation.status} in the shape the relay's own route answers ` +
            "with, over TLS validated against Node's bundled public roots — so whatever answered holds a " +
            "publicly trusted certificate for this host, and the WebSocket path is open.",
          { ...facts, responderIdentified: true },
        );
      }
      return warn(
        id,
        title,
        `the upgrade was refused with HTTP ${observation.status} in the shape the relay answers with, but ` +
          `WHO answered could not be established: ${caveat}. A proxy or captive portal can return exactly ` +
          "this refusal, so this does not show the upgrade reached the relay.",
        "Nothing here is known to be broken; the check simply cannot identify the responder under this TLS " +
          "configuration. Re-run it without the setting named above to get an answer worth acting on.",
        { ...facts, responderIdentified: false },
      );
    }
    return warn(
      id,
      title,
      observation.status === 401 || observation.status === 403
        ? `the upgrade was refused with HTTP ${observation.status}, but the refusal did not come back in the ` +
          "shape the relay answers with, so something else on the path answered it."
        : `the upgrade was answered with HTTP ${observation.status}, not the expected 401.`,
      "Something between this machine and the relay is answering the upgrade itself. A proxy that does not " +
        "pass `Upgrade: websocket` through, a captive portal, or a TLS-inspecting gateway are the usual causes.",
      facts,
    );
  }
  return fail(
    id,
    title,
    `the WebSocket upgrade did not reach the relay: ${observation.error ?? "no response"}.`,
    "The agent can register but can never open its socket, so the machine shows offline. Check a firewall or " +
      "proxy that blocks WebSocket upgrades.",
    facts,
  );
}

/**
 * Clock skew, measured against the relay's own `Date` header rather than an
 * extra request to a time service — the header is already in hand from the
 * HTTPS leg, and the relay is the clock that actually matters here: a
 * sufficiently skewed machine fails TLS and token validation against it.
 *
 * Both readings are taken at the same instant (see HttpsObservation.receivedAt);
 * this function only subtracts them.
 */
function checkClock(https: HttpsObservation): CheckResult {
  const id = "env.clock";
  const title = "Clock skew";
  const { serverDate, receivedAt } = https;
  if (!serverDate || receivedAt === null) {
    return skipped(id, title, "the relay did not answer with a usable Date header, so there is nothing to compare against.");
  }
  // `receivedAt`, not `Date.now()`: this function runs after the ticket and
  // upgrade legs, each of which may take a full networkTimeoutMs, and reading
  // the local clock here would add both of them to the reported skew and warn a
  // healthy machine about a clock that is fine.
  const skewMs = receivedAt - serverDate.getTime();
  const skewSec = Math.round(skewMs / 1000);
  const facts: DoctorFacts = { skewSeconds: skewSec, serverDate: serverDate.toISOString() };
  const magnitude = Math.abs(skewSec);
  if (magnitude <= 60) return ok(id, title, `this machine's clock is within ${magnitude}s of the relay.`, facts);
  return warn(
    id,
    title,
    `this machine's clock is ${skewSec > 0 ? "ahead of" : "behind"} the relay by ${magnitude}s.`,
    "A large skew breaks TLS certificate validity and short-lived credentials. Enable automatic time " +
      "synchronisation on this machine.",
    facts,
  );
}

export const connectivityChecks: DoctorCheckGroup = {
  id: "net",
  title: "Connectivity",
  async run(ctx) {
    const titles: Array<[string, string]> = [
      ["net.dns", "DNS"],
      ["net.https", "HTTPS to the relay"],
      ["net.ticket", "Connection ticket exchange"],
      ["net.websocket", "WebSocket upgrade"],
      ["env.clock", "Clock skew"],
    ];
    if (ctx.offline) {
      return titles.map(([id, title]) => skipped(id, title, "skipped: --offline was requested."));
    }

    const dnsResult = await checkDns(ctx);
    // Each leg still runs after the one before it failed: a DNS answer served
    // from a cache while the resolver is down, and an HTTPS path that works
    // while WebSockets are blocked, are both real and both worth seeing.
    const https = await checkHttps(ctx);
    return [dnsResult, https.result, await checkTicket(ctx), await checkUpgrade(ctx), checkClock(https)];
  },
};
