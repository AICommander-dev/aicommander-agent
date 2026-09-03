import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import {
  elevatedEndpoints,
  encodeFrame,
  FrameDecoder,
  helperInstallDir,
  helperVersionMarkerPath,
  IPC_PROTOCOL_VERSION,
  MAC_DAEMON_LABEL,
  MAC_DAEMON_PLIST,
  WIN_HELPER_TASK_NAME,
  type ElevatedEndpoint,
} from "@aicommander/priv-helper";
import { capturedStdout, runCaptured, unavailableReason } from "../../capture.js";
import { AGENT_VERSION } from "../../version.js";
import {
  errorText,
  fail,
  ok,
  skipped,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorFacts,
} from "../types.js";
import { powerShellSingleQuote, queryScheduledTask, runPowerShell } from "./windows.js";

/**
 * The privileged helper: installed, registered, correctly signed, answering,
 * and speaking a protocol version this agent understands.
 *
 * On the machine that produced the 2026-09-02 incident the helper had NEVER
 * BEEN REGISTERED, and nothing anywhere said so — not the tray, not the relay,
 * not a log. Elevated exec was simply, permanently unavailable, and the Windows
 * watchdog that was supposed to notice a gutted install was not running to
 * notice anything. Every question below is one somebody had to answer by hand
 * that day.
 *
 * ── FIVE SEPARATE QUESTIONS, ON PURPOSE ──────────────────────────────────────
 * "The helper does not work" has five very different causes with five different
 * fixes, and collapsing them into one verdict is what made this expensive:
 * the files are not there (re-install), the task is not registered (re-run the
 * installer), the signature is not what we pin (a tampered or unsigned copy —
 * do not trust it), nothing answers the endpoint (the service is not running),
 * or something on the endpoint answers on a protocol number this agent will not
 * speak (a half-applied upgrade, or something else on the port — the handshake
 * cannot tell those apart; see `checkEndpoint`). Each gets its own check.
 *
 * ── THIS TALKS TO THE HELPER, AND ASKS IT FOR NOTHING ────────────────────────
 * The endpoint check completes the `hello` handshake and stops there. It never
 * sends `exec`, and it holds no capability to send one with — the authority to
 * run anything elevated is a relay-signed, machine-bound capability that a
 * diagnostic neither has nor should be able to obtain. The handshake is
 * side-effect-free on the helper's side.
 */

/*
 * WIN_HELPER_TASK_NAME (the SYSTEM task desktop/build/win-privhelper-task.ps1
 * registers) is imported from @aicommander/priv-helper rather than typed out
 * again: the agent's own discovery reads the same constant to tell "installed
 * but never registered" apart from "registered but not running", and a name
 * spelled differently in two places is a silent "helper not available".
 */

/** The SEA binary name that script installs and registers. */
const WIN_HELPER_EXE = "aicommander-priv-helper.exe";
/** The Mach-O the LaunchDaemon plist runs. */
const MAC_HELPER_BIN = "aicommander-priv-helper";

/**
 * The Authenticode subject `desktop/build/win-privhelper-task.ps1` pins before
 * it will register the SYSTEM task ($ExpectedSubject there).
 *
 * Mirrored, not imported: the installer is PowerShell in another package. A
 * mismatch here is reported as a WARNING and never as a failure, because the
 * two ways to reach it are not equally alarming — a genuinely unexpected signer,
 * or a certificate rotation that moved the pin over there and not here. The
 * doctor's job is to print what it saw; deciding is the installer's, and it
 * fails closed on exactly this comparison.
 */
const WIN_EXPECTED_SUBJECT = "CN=WEARFITS sp. z o.o., O=WEARFITS sp. z o.o., L=Krakow, C=PL";

/** How long the handshake gets before the helper counts as not answering. */
const HANDSHAKE_TIMEOUT_MS = 3_000;

interface HandshakeResult {
  answered: boolean;
  protocolVersion: number | null;
  /**
   * The version string the responder announced — BOUNDED AND SHAPE-CHECKED, or
   * null. See `sanitizeVersion`: this is the one free-form string on the wire
   * that reaches `DoctorFacts`, and the report is a file we invite people to
   * forward to support and to antivirus vendors.
   */
  helperVersion: string | null;
  /**
   * The helper's per-boot nonce. The agent's own discovery treats an answer with
   * no usable bootId as no answer at all (elevated-executor.ts
   * `probeHelperHello`), because the nonce is what identifies WHICH process
   * answered — and answers that disagree about it mean something that is not the
   * helper is on one of the ports.
   */
  bootId: string | null;
  error: string | null;
  endpoint: string;
  /**
   * SOMETHING answered our `hello` with an `error` frame and hung up.
   *
   * NOT "the helper refused us". On a fresh connection carrying exactly one
   * `hello`, OUR helper sends `error` for one reason only — a protocol version
   * it will not speak (priv-helper/src/helper.ts; its other two `error` cases
   * need a second frame or a completed handshake, neither of which happens
   * here) — so a half-applied upgrade produces exactly this. But so does any
   * local process that bound the address first and wrote four bytes of framing:
   * an `error` frame carries no bootId and nothing else that could say who sent
   * it. The flag records the SHAPE of the answer, and `checkEndpoint` is careful
   * not to turn a shape into an identity.
   *
   * A BOOLEAN, NOT THE MESSAGE, for the same reason it always was: the text is
   * an untrusted string from whatever is on the port, on its way into a report
   * the user is invited to forward to support.
   */
  refused: boolean;
}

function describeEndpoint(ep: ElevatedEndpoint): string {
  return ep.transport === "unix" ? ep.path : `${ep.host}:${ep.port}`;
}

/** The widest a version we will print may be, and the only bytes it may hold. */
const VERSION_SHAPE = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$/;

/**
 * A version string is the ONE free-form value a responder can push into this
 * report, so it is bounded and shape-checked before it becomes a fact — the same
 * rule `HandshakeResult.refused` exists to enforce for the `error` frame's text.
 *
 * Whatever is on the endpoint chose this string, and it lands in a file we tell
 * users to attach to a support case and mail to antivirus vendors. Anything that
 * is not a plausible version (ours look like `1.1.0`) is not a version, and we
 * report NOTHING rather than the responder's own prose: the fact only ever
 * mattered to tell two of our builds apart, and both of ours pass this shape.
 */
function sanitizeVersion(value: unknown): string | null {
  return typeof value === "string" && VERSION_SHAPE.test(value) ? value : null;
}

/**
 * Complete `hello` against one endpoint and hang up. Never throws: every failure
 * is an observation.
 */
function handshake(ep: ElevatedEndpoint): Promise<HandshakeResult> {
  const endpoint = describeEndpoint(ep);
  return new Promise((resolve) => {
    const base: HandshakeResult = {
      answered: false,
      protocolVersion: null,
      helperVersion: null,
      bootId: null,
      error: null,
      endpoint,
      refused: false,
    };
    let socket: net.Socket;
    try {
      socket = ep.transport === "unix" ? net.connect(ep.path) : net.connect(ep.port, ep.host);
    } catch (err) {
      resolve({ ...base, error: errorText(err) });
      return;
    }
    const decoder = new FrameDecoder();
    let settled = false;
    const finish = (result: HandshakeResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };
    const timer = setTimeout(() => finish({ ...base, error: "timed out" }), HANDSHAKE_TIMEOUT_MS);
    timer.unref?.();

    socket.on("connect", () => {
      socket.write(encodeFrame({ t: "hello", protocolVersion: IPC_PROTOCOL_VERSION, clientVersion: AGENT_VERSION }));
    });
    socket.on("data", (chunk: Buffer) => {
      let frames: Array<Record<string, unknown>>;
      try {
        frames = decoder.push(chunk);
      } catch (err) {
        finish({ ...base, error: `protocol error: ${errorText(err)}` });
        return;
      }
      for (const frame of frames) {
        // A REFUSAL IS AN ANSWER, and this loop used to throw it away. A helper
        // that cannot speak our `hello` replies
        // `{t:"error", message:"unsupported IPC protocol version …"}` and closes
        // BEFORE it would ever send `hello-ok` (helper.ts) — so against our own
        // helper the skew verdict below, built from `hello-ok.protocolVersion`,
        // was unreachable for the case it exists for. Dropping the frame left
        // the close to be reported as "something answered but did not identify
        // itself", with a remedy that sends the reader hunting for a squatter —
        // when the likelier cause is much duller: the installed helper and this
        // agent are different builds, and the fix is to finish the upgrade.
        // Recorded as a SHAPE and not as an identity: see `refused` above and
        // the verdict in checkEndpoint.
        if (frame["t"] === "error") {
          finish({ ...base, refused: true });
          return;
        }
        if (frame["t"] !== "hello-ok") continue;
        const bootId = frame["bootId"];
        finish({
          ...base,
          answered: true,
          protocolVersion: typeof frame["protocolVersion"] === "number" ? frame["protocolVersion"] : null,
          helperVersion: sanitizeVersion(frame["helperVersion"]),
          bootId: typeof bootId === "string" && bootId.length > 0 ? bootId : null,
        });
        return;
      }
    });
    socket.on("error", (err) => finish({ ...base, error: errorText(err) }));
    socket.on("close", () => finish({ ...base, error: "the helper closed the connection without answering" }));
  });
}

/**
 * Quote a value as a POSIX shell single-quoted word. Nothing is special inside
 * `'…'` except the quote itself, which is closed, escaped and reopened.
 */
function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Present on disk? Asynchronous like every other filesystem call in this
 * directory: the tray runs these checks on Electron's main loop, where a
 * synchronous stat on a path a filter driver is holding blocks the relay
 * heartbeat (see desktop/src/diagnostics.ts).
 */
async function fileExists(target: string): Promise<boolean> {
  try {
    await fs.promises.stat(target);
    return true;
  } catch {
    return false;
  }
}

async function checkInstalled(): Promise<{ result: CheckResult; helperExe: string | null }> {
  const id = "helper.installed";
  const title = "Privileged helper — files";
  const dir = helperInstallDir();
  const marker = helperVersionMarkerPath();
  if (!dir || !marker) {
    return { helperExe: null, result: skipped(id, title, "no privileged helper on this platform.") };
  }
  const helperExe = path.join(dir, process.platform === "win32" ? WIN_HELPER_EXE : MAC_HELPER_BIN);
  const facts: DoctorFacts = { dir, marker, binary: helperExe };
  if (!(await fileExists(dir))) {
    return {
      helperExe: null,
      result: fail(
        id,
        title,
        `the privileged helper is not installed — ${dir} does not exist.`,
        "Elevated commands cannot run on this machine. Re-run the installer; it installs and registers the " +
          "helper from its own elevated context.",
        facts,
      ),
    };
  }
  const hasMarker = await fileExists(marker);
  const hasBinary = await fileExists(helperExe);
  if (hasMarker && hasBinary) {
    let version: string | null = null;
    try {
      version = (await fs.promises.readFile(marker, "utf8")).trim() || null;
    } catch {
      // The marker's CONTENT is informational; its presence is the contract.
    }
    return {
      helperExe,
      result: ok(id, title, `the privileged helper is installed in ${dir}.`, { ...facts, marker: version }),
    };
  }
  return {
    helperExe: hasBinary ? helperExe : null,
    result: fail(
      id,
      title,
      `the helper directory exists but ${hasBinary ? "its VERSION marker" : "the helper binary"} is missing.`,
      "A half-present helper is treated as unavailable. Re-run the installer.",
      facts,
    ),
  };
}

async function checkRegistered(): Promise<CheckResult> {
  const id = "helper.registered";
  const title = "Privileged helper — registration";
  if (process.platform === "win32") {
    const task = await queryScheduledTask(WIN_HELPER_TASK_NAME);
    // "We could not ask" is not "the answer is no". `queried` is the discriminant
    // of ScheduledTaskInfo — there IS no `registered` to read until it is true —
    // because a machine that merely cannot run PowerShell would otherwise be told
    // its helper was never registered, inventing the 2026-09-02 incident's
    // signature on a box that may be perfectly healthy.
    if (!task.queried) {
      return skipped(
        id,
        title,
        `whether the SYSTEM task "${WIN_HELPER_TASK_NAME}" is registered could not be determined: ` +
          `${task.reason}. The endpoint check below still answers whether the helper is actually reachable.`,
        { task: WIN_HELPER_TASK_NAME },
      );
    }
    const facts: DoctorFacts = { task: WIN_HELPER_TASK_NAME, state: task.state, execute: task.execute };
    // Unlike the Relaunch task, this one is registered with the DEFAULT task ACL
    // (desktop/build/win-privhelper-task.ps1 calls Register-ScheduledTask with no
    // SDDL), which lets any authenticated user read it — so an unelevated run
    // being told there is no such task is real evidence, not a permissions
    // artefact. See persistence.ts's READABLE_BY_USERS for the task that differs.
    return task.registered
      ? ok(id, title, `the SYSTEM task "${WIN_HELPER_TASK_NAME}" is registered (state ${task.state ?? "unknown"}).`, facts)
      : fail(
          id,
          title,
          `the SYSTEM task "${WIN_HELPER_TASK_NAME}" is NOT registered — this is the state the 2026-09-02 machine ` +
            "was in, silently, and it means elevated commands can never run here.",
          "Re-run the installer. The task can only be registered from an elevated context, and the installer " +
            "verifies the helper's signature before doing so.",
          facts,
        );
  }
  if (process.platform === "darwin") {
    const facts: DoctorFacts = { plist: MAC_DAEMON_PLIST, label: MAC_DAEMON_LABEL };
    if (!(await fileExists(MAC_DAEMON_PLIST))) {
      return fail(
        id,
        title,
        `the LaunchDaemon plist ${MAC_DAEMON_PLIST} is not there, so nothing starts the helper.`,
        "Re-install with the .pkg — the plain .dmg does not install the privileged helper.",
        facts,
      );
    }
    // `launchctl print system/<label>` needs root, and it exits non-zero both
    // for "you may not ask" and for "launchd does not hold that service" — so
    // WHO IS ASKING is what turns its refusal into evidence. Reading the failure
    // without the uid reported a Mac whose helper is installed but NOT LOADED as
    // healthy, and blamed a lack of privilege the run did not lack — on the one
    // check whose job is to separate "registered" from "running".
    const root = typeof process.getuid === "function" ? process.getuid() === 0 : null;
    const captured = await runCaptured("/bin/launchctl", ["print", `system/${MAC_DAEMON_LABEL}`]);
    const loaded = captured.kind === "output" && captured.stdout.trim() !== "";
    // `false` only where launchd ACTUALLY ANSWERED and the asker had the rights
    // to be answered; `null` — not established — everywhere else.
    const answered = captured.kind !== "unavailable";
    const withState: DoctorFacts = {
      ...facts,
      root,
      loaded: loaded ? true : answered && root === true ? false : null,
    };
    if (loaded) return ok(id, title, `the LaunchDaemon ${MAC_DAEMON_LABEL} is loaded.`, withState);
    if (captured.kind === "unavailable") {
      // launchd was never asked at all. Neither "loaded" nor "not loaded" — and
      // the plist being installed is still a fact we established ourselves.
      return ok(
        id,
        title,
        `the LaunchDaemon plist is installed. launchd was not asked whether it is loaded (${captured.reason}), ` +
          "so that half is answered by the endpoint check below.",
        withState,
      );
    }
    if (root !== true) {
      return ok(
        id,
        title,
        `the LaunchDaemon plist is installed. launchd's own state was not readable from here (it needs root), ` +
          "so whether it is loaded is answered by the endpoint check below.",
        withState,
      );
    }
    return fail(
      id,
      title,
      `the LaunchDaemon plist ${MAC_DAEMON_PLIST} is installed, but launchd — asked AS ROOT, so this is not a ` +
        `permissions artefact — does not have ${MAC_DAEMON_LABEL} loaded (${unavailableReason(captured)}). ` +
        "Nothing starts the helper, so elevated commands can never run here.",
      `Load it with \`sudo launchctl bootstrap system ${MAC_DAEMON_PLIST}\`, or re-install with the .pkg, which ` +
        "registers it from its own elevated context.",
      withState,
    );
  }
  return skipped(id, title, "no privileged helper on this platform.");
}

/**
 * Is the installed helper signed by the identity the installer pins?
 *
 * Reported, not enforced — the enforcement already happened: the installer
 * refuses to register the SYSTEM task at all unless the Authenticode chain is
 * valid AND the subject matches exactly. What this adds is visibility after the
 * fact, for the case where somebody replaced the file afterwards, and the
 * observed subject in the report so a human can compare it themselves.
 */
async function checkSignature(helperExe: string | null): Promise<CheckResult> {
  const id = "helper.signature";
  const title = "Privileged helper — signature";
  if (!helperExe) return skipped(id, title, "there is no installed helper binary to verify.");

  if (process.platform === "win32") {
    const captured = await runPowerShell(
      "$ErrorActionPreference='Stop';" +
        `$s = Get-AuthenticodeSignature -FilePath ${powerShellSingleQuote(helperExe)};` +
        "Write-Output ('STATUS=' + $s.Status);" +
        "Write-Output ('SUBJECT=' + $s.SignerCertificate.Subject)",
    );
    const out = capturedStdout(captured);
    if (out.trim() === "") {
      return warn(id, title, "the Authenticode signature could not be read.", "Verify the file by hand with `Get-AuthenticodeSignature`.", { binary: helperExe });
    }
    const status = /^STATUS=(.*)$/m.exec(out)?.[1]?.trim() ?? "unknown";
    const subject = /^SUBJECT=(.*)$/m.exec(out)?.[1]?.trim() ?? "";
    const facts: DoctorFacts = { binary: helperExe, status, subject, expectedSubject: WIN_EXPECTED_SUBJECT };
    if (status !== "Valid") {
      return fail(
        id,
        title,
        `the installed helper's Authenticode signature is ${status}.`,
        "Do not trust this binary. Re-install from a release download; the installer refuses to register an " +
          "unsigned or tampered helper.",
        facts,
      );
    }
    return subject === WIN_EXPECTED_SUBJECT
      ? ok(id, title, "the installed helper carries a valid signature from the expected publisher.", facts)
      : warn(
          id,
          title,
          `the installed helper is validly signed, but by ${subject} rather than the pinned publisher.`,
          "Either the signing certificate was rotated (in which case a newer installer knows about it) or this " +
            "is not our binary. Re-install from a release download.",
          facts,
        );
  }

  if (process.platform === "darwin") {
    // `codesign` writes its verdict to STDERR and nothing to stdout, so both
    // calls go through a
    // shell that turns the parts we want into stdout. The path is single-quoted
    // for that shell: `JSON.stringify` is not a shell quoter and never was, and
    // inside its double quotes `$` and a backtick are still expanded by /bin/sh
    // (the same mistake installed-version.ts's `powerShellSingleQuote` header
    // warns about for PowerShell). Today the path is a constant of ours, so
    // nothing is exploitable — but a comment that asserts a safety property the
    // code does not have is how the next caller passes a path it read off disk.
    const quoted = shellSingleQuote(helperExe);
    // Sentinel shape: `echo VERIFIED` runs only on the verifying path, so the
    // token's presence is the measurement and the shell's exit status is not —
    // the one case capture.ts's `capturedStdout` is for.
    const verified = capturedStdout(
      await runCaptured("/bin/sh", [
        "-c",
        `/usr/bin/codesign --verify --strict ${quoted} >/dev/null 2>&1 && echo VERIFIED`,
      ]),
    );
    const described = capturedStdout(
      await runCaptured("/bin/sh", [
        "-c",
        `/usr/bin/codesign -dv ${quoted} 2>&1 | /usr/bin/grep '^Authority=' | /usr/bin/head -1`,
      ]),
    );
    const authority = described.trim().replace(/^Authority=/, "");
    const facts: DoctorFacts = { binary: helperExe, authority: authority || null };
    return verified.trim() === "VERIFIED"
      ? ok(id, title, `the installed helper's signature verifies${authority ? ` (${authority})` : ""}.`, facts)
      : warn(
          id,
          title,
          "the installed helper's code signature could not be verified.",
          "Run `codesign --verify --deep --strict` on it by hand. Re-install from a release download if it fails.",
          facts,
        );
  }
  return skipped(id, title, "no privileged helper on this platform.");
}

/**
 * Does a helper answer, and is it the same one on every port it should own?
 *
 * ── WHY EVERY CANDIDATE IS PROBED, NOT JUST THE FIRST ANSWER ─────────────────
 * The Windows helper binds EVERY loopback candidate it can at boot, before any
 * user logs in, precisely so nobody else can sit on one (endpoint.ts). The
 * agent's own discovery walks the whole list and fails closed when the answers
 * disagree about `bootId`, because a second distinct nonce means something the
 * helper does not own is answering — a local squatter that grabbed a port while
 * the helper was down (elevated-executor.ts `discoverHelperDetailed`). A doctor
 * that stopped at the first answer would report a healthy helper on a machine
 * where every elevated command correctly fails closed, which is the worst kind
 * of wrong answer this command can give: it contradicts the product.
 *
 * ── AND WHY "A CANDIDATE" MEANS EXACTLY WHAT DISCOVERY MEANS BY IT ───────────
 * `probeHelperHello` (elevated-executor.ts) classifies an answer whose IPC
 * protocol version is not ours as `protocol_mismatch` and does NOT put it in
 * `answers`; only compatible answers can produce a conflict, and the mismatch is
 * reported only when nothing compatible answered at all. A doctor that kept
 * incompatible responders among its candidates disagreed with that on the
 * machines where it matters most: one stale responder on a spare port could make
 * this check report a bootId conflict, or a protocol failure, on a machine where
 * `discoverHelperDetailed` finds a perfectly good endpoint and elevated exec
 * works. A diagnostic that contradicts the thing it diagnoses is worse than no
 * diagnostic, so the filter here is the same filter, in the same order:
 * compatible answers decide first, and the mismatch is a fallback verdict.
 *
 * An answer with NO usable bootId is treated the same way discovery treats it —
 * not an answer.
 */
async function checkEndpoint(): Promise<CheckResult> {
  const id = "helper.endpoint";
  const title = "Privileged helper — endpoint";
  const endpoints = elevatedEndpoints();
  if (endpoints.length === 0) {
    return skipped(
      id,
      title,
      "elevated execution is a macOS/Windows feature; a root agent on Linux runs privileged commands directly.",
    );
  }

  const observations: HandshakeResult[] = [];
  for (const ep of endpoints) observations.push(await handshake(ep));

  // The candidate set discovery uses: answered, identified itself, AND speaks
  // our protocol. An incompatible responder is remembered separately so it can
  // still be REPORTED — it is just never allowed to decide the verdict while a
  // usable helper is answering somewhere.
  const identified = observations.filter(
    (o) => o.answered && o.bootId !== null && o.protocolVersion === IPC_PROTOCOL_VERSION,
  );
  // TWO SHAPES, ONE STATE, because the helper produces both depending on which
  // side is older. A helper that does not speak OUR version replies `{t:"error"}`
  // and closes (`refused`); a helper whose `hello-ok` announces a version WE do
  // not speak is the same skew seen from the other end. Reading only the second
  // made this list dead against our own helper, which never gets as far as
  // `hello-ok` when it disagrees with us.
  const mismatched = observations.filter(
    (o) => o.refused || (o.answered && o.protocolVersion !== null && o.protocolVersion !== IPC_PROTOCOL_VERSION),
  );
  const facts: DoctorFacts = {
    endpoints: endpoints.map(describeEndpoint).join(", "),
    answered: observations.filter((o) => o.answered).length,
    agentProtocol: IPC_PROTOCOL_VERSION,
    ...(mismatched.length > 0 ? { incompatibleResponders: mismatched.length } : {}),
  };

  const bootIds = new Set(identified.map((o) => o.bootId!));
  if (bootIds.size > 1) {
    return fail(
      id,
      title,
      `${bootIds.size} different processes answered the helper endpoints (${identified
        .map((o) => o.endpoint)
        .join(", ")}), so at least one of them is not the privileged helper.`,
      "The agent refuses elevated commands in exactly this state, deliberately: a port the helper does not own " +
        "is answering its handshake. Reboot so the helper reclaims the whole pool, and if it persists, find " +
        "what else is listening before trusting elevated execution on this machine.",
      { ...facts, distinctIdentities: bootIds.size },
    );
  }

  const answered = identified[0];
  if (!answered) {
    // Only now, with no compatible answer anywhere, does a mismatch become the
    // verdict — the order `discoverHelperDetailed` reports its causes in.
    const stale = mismatched[0];
    if (stale) {
      // SKEW IS NOT A SQUATTER — AND IT IS NOT PROOF OF THE HELPER EITHER.
      // This branch used to call the responder "the helper … a half-applied
      // upgrade, not an impostor on the port", which is a worse answer about an
      // impostor than the squatter sentence it replaced: it tells the reader the
      // port is legitimately ours and hands them a re-install. NOTHING ON THIS
      // PATH IDENTIFIES THE RESPONDER. An `error` frame carries no bootId at
      // all, a `hello-ok`'s bootId is a value the responder CHOOSES, and any
      // local process that bound the address ahead of the helper produces both.
      //
      // So the verdict names BOTH possibilities and says it cannot tell them
      // apart — "could not establish" is its own answer, never rounded to the
      // flattering neighbour, which here is "it's ours". The half-applied
      // upgrade is still called the likelier of the two, because it is, and its
      // remedy goes first. Wording deliberately mirrors the helper's own copy
      // (priv-helper/src/doctor-endpoint.ts): a support engineer reads both
      // reports side by side.
      //
      // A REFUSAL NAMES NO NUMBER, and the number it would have named is the
      // responder's own text — never quoted here (see HandshakeResult.refused).
      const spoken = stale.refused
        ? "refused ours without naming its own"
        : `speaks IPC protocol ${stale.protocolVersion}`;
      return fail(
        id,
        title,
        `protocol mismatch on ${stale.endpoint}: something there speaks this protocol's framing but ${spoken}, ` +
          `while this agent speaks IPC protocol ${IPC_PROTOCOL_VERSION}, and nothing on the endpoint pool speaks ` +
          "ours. Nothing in that exchange says WHICH process it is — an error frame carries no boot id, and a " +
          "boot id is a value the responder chooses — so this is either the privileged helper from a half-applied " +
          "upgrade, which is the likelier of the two, or something else holding the endpoint; this check cannot " +
          "tell which. Elevated commands fail closed against a version skew either way, deliberately.",
        "Re-run the installer, then reboot so the SYSTEM helper restarts on the new binary. If the same answer " +
          "survives that reboot, the responder is not the helper — find what else is holding the endpoint before " +
          "trusting elevated execution here.",
        // Named for what they are: things a RESPONDER announced, not the
        // helper's own properties. The version is bounded and shape-checked at
        // the parse site (`sanitizeVersion`) precisely because this line puts it
        // in a forwardable file.
        {
          ...facts,
          endpoint: stale.endpoint,
          responderVersion: stale.helperVersion,
          responderProtocol: stale.protocolVersion,
        },
      );
    }
    const anonymous = observations.find((o) => o.answered);
    if (anonymous) {
      // Something completed the handshake but would not say which process it is.
      // The agent treats that as no helper, and so does this.
      return fail(
        id,
        title,
        `something answered on ${anonymous.endpoint} but did not identify itself, so it is not treated as the helper.`,
        "Elevated commands fail closed against an unidentified responder. Reboot so the helper rebinds its " +
          "endpoints, and check what else is listening if it persists.",
        facts,
      );
    }
    return fail(
      id,
      title,
      `nothing answered the helper endpoint (${observations.map((o) => `${o.endpoint}: ${o.error ?? "no answer"}`).join("; ")}).`,
      "The helper is not running. On Windows it is started by its SYSTEM scheduled task at boot; on macOS by its " +
        "LaunchDaemon. Re-run the installer if the registration check above also failed, otherwise reboot.",
      facts,
    );
  }

  const withVersions: DoctorFacts = {
    ...facts,
    endpoint: answered.endpoint,
    helperVersion: answered.helperVersion,
    helperProtocol: answered.protocolVersion,
  };
  // A compatible answer is what `discoverHelperDetailed` returns `ok` for, so
  // this says so — and mentions any incompatible responder rather than letting
  // it change the verdict, because the agent's discovery does not either.
  return mismatched.length > 0
    ? warn(
        id,
        title,
        `the helper answered on ${answered.endpoint} and speaks protocol ${answered.protocolVersion}, which ` +
          `is this agent's — but ${mismatched.length} other endpoint(s) answered on a protocol version that is ` +
          "not ours. Nothing in those answers says which process they are — a stale helper left by a " +
          "half-applied upgrade, or something else holding those endpoints. Elevated execution works over the " +
          "compatible endpoint either way.",
        "Discovery uses the compatible endpoint, so nothing is broken today. Reboot when convenient so the " +
          "helper reclaims the whole endpoint pool, and find what else is listening if it comes back.",
        withVersions,
      )
    : ok(
        id,
        title,
        `the helper answered on ${answered.endpoint} and speaks protocol ${answered.protocolVersion}.`,
        withVersions,
      );
}

export const privHelperChecks: DoctorCheckGroup = {
  id: "helper",
  title: "Privileged helper",
  async run() {
    const installed = await checkInstalled();
    return [
      installed.result,
      await checkRegistered(),
      await checkSignature(installed.helperExe),
      await checkEndpoint(),
    ];
  },
};
