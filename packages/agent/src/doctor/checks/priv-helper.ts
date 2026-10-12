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
import { pathPresence } from "./presence.js";
import {
  DENIAL_PROVES_TASK_EXISTS,
  powerShellSingleQuote,
  queryScheduledTask,
  runPowerShell,
} from "./windows.js";

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
 * Every path question below uses asynchronous, tri-state `pathPresence`.
 * EACCES, EPERM and EIO mean unknown rather than absent, so ACLs, quarantine,
 * filter drivers and I/O failures never become invented missing-file claims.
 */

/** The one sentence an undetermined path gets, so no branch invents its own. */
const UNREADABLE_REMEDY =
  "Nothing here says anything is missing — the path answered neither way, which is how a filter driver " +
  "holding a file, a quarantine, and a directory this account may not traverse all look. Inspect it by hand " +
  "(elevated, on Windows) before re-running the installer: a re-install does not address any of those.";

/**
 * The one sentence a signature question WINDOWS DID NOT SETTLE gets — the same
 * rule as `UNREADABLE_REMEDY` one line up, for the case where the file's own
 * stat was fine and it is `Get-AuthenticodeSignature` that came back without an
 * answer. Separate constant, because the action differs: there is a command to
 * run by hand here, and there is nothing to say about the path.
 */
const UNSETTLED_SIGNATURE_REMEDY =
  "Verify the file by hand with `Get-AuthenticodeSignature` from an elevated prompt. Nothing here says the " +
  "binary is untrustworthy: a file a filter driver is holding, a quarantined copy, and one this account may " +
  "not read all answer this way, and none of them is a bad signature.";

/** What we call a STATUS line we could not find or parse — never a status Windows names. */
const UNPARSED_STATUS = "unreadable";

/**
 * The `SignatureStatus` values that describe THE CHECK, not the file.
 *
 * Deliberately a short, closed list, because getting it wrong in the generous
 * direction costs tamper detection. `NotSigned`, `HashMismatch` and `NotTrusted`
 * are positive findings about the bytes on disk — a replaced or unsigned helper
 * is exactly what this check exists to shout about, and they stay a loud `fail`.
 * `NotSupportedFileFormat` on a path we install as a PE is also a finding about
 * the file (something that is not an executable is sitting where the helper
 * should be), so it stays a failure too.
 *
 * `Incompatible` means the signature could not be evaluated on this system.
 * `UNPARSED_STATUS` is our own name for output with no STATUS line at all.
 * `UnknownError` is different: Windows did not confirm a valid signature, so it
 * fails validation without claiming why validation failed.
 */
const UNSETTLED_STATUSES = new Set([UNPARSED_STATUS, "Incompatible"]);

/**
 * WHAT THE FILES CHECK ESTABLISHED ABOUT THE BINARY — all three answers, because
 * there are three.
 *
 * This used to be `string | null`, and a two-state value cannot carry a
 * tri-state measurement: `null` meant BOTH "no helper here" and "we never found
 * out", so the signature check had to guess which. It guessed the flattering
 * way in one direction (a `null` for an unreadable file became "there is no
 * installed helper binary to verify") and, once that was fixed by passing the
 * path anyway, the flattering way in the other — a file that could not be READ
 * reached `Get-AuthenticodeSignature` and could come back as "Do not trust this
 * binary". Both are the same invented certainty the `Presence` tri-state exists
 * to stop, one layer down. So the caller now says what it knows, and the
 * signature check never has to infer it.
 */
type HelperBinary =
  | { kind: "absent" }
  | { kind: "present"; path: string }
  | { kind: "unreadable"; path: string; error: string; code: string | null };

async function checkInstalled(): Promise<{ result: CheckResult; binary: HelperBinary }> {
  const id = "helper.installed";
  const title = "Privileged helper — files";
  const dir = helperInstallDir();
  const marker = helperVersionMarkerPath();
  if (!dir || !marker) {
    return { binary: { kind: "absent" }, result: skipped(id, title, "no privileged helper on this platform.") };
  }
  const helperExe = path.join(dir, process.platform === "win32" ? WIN_HELPER_EXE : MAC_HELPER_BIN);
  const facts: DoctorFacts = { dir, marker, binary: helperExe };
  const dirPresence = await pathPresence(dir);
  const markerPresence = await pathPresence(marker);
  const binaryPresence = await pathPresence(helperExe);

  // The required files decide installation state; the directory is supporting
  // evidence. Both children present settles the question even if the directory
  // stat raced with them or was denied.
  if (markerPresence.kind === "present" && binaryPresence.kind === "present") {
    let version: string | null = null;
    try {
      version = (await fs.promises.readFile(marker, "utf8")).trim() || null;
    } catch {
      // The marker's CONTENT is informational; its presence is the contract.
    }
    return {
      binary: { kind: "present", path: helperExe },
      result: ok(id, title, `the privileged helper is installed in ${dir}.`, { ...facts, marker: version }),
    };
  }

  const binary: HelperBinary =
    binaryPresence.kind === "present"
      ? { kind: "present", path: helperExe }
      : binaryPresence.kind === "absent"
        ? { kind: "absent" }
        : { kind: "unreadable", path: helperExe, error: binaryPresence.error, code: binaryPresence.code };
  const undetermined = (
    [
      [dir, dirPresence],
      [marker, markerPresence],
      [helperExe, binaryPresence],
    ] as const
  ).filter(([, presence]) => presence.kind === "unknown");
  const missing = [
    ...(markerPresence.kind === "absent" ? [{ label: "VERSION marker", target: marker }] : []),
    ...(binaryPresence.kind === "absent" ? [{ label: "helper binary", target: helperExe }] : []),
  ];
  const code = undetermined
    .map(([, presence]) => (presence.kind === "unknown" ? presence.code : null))
    .find((value): value is string => value !== null);
  const unknownDetail = undetermined
    .map(([target, presence]) => `${target} (${presence.kind === "unknown" ? presence.error : ""})`)
    .join("; ");

  // A confirmed absence remains a failure even when its sibling could not be
  // inspected. The two observations require two remedies: restore what is
  // missing, and investigate the access or I/O failure independently.
  if (missing.length > 0) {
    if (dirPresence.kind === "absent" && missing.length === 2) {
      return {
        binary,
        result: fail(
          id,
          title,
          `the privileged helper is not installed — ${dir}, its VERSION marker, and its helper binary do not exist.`,
          "Elevated commands cannot run on this machine. Re-run the installer; it installs and registers the " +
            "helper from its own elevated context.",
          facts,
        ),
      };
    }
    const conflict =
      dirPresence.kind === "absent"
        ? ` The directory stat also reported ${dir} absent while its child observations differed; those results ` +
          "may span a filesystem race."
        : "";
    const remedy =
      `Re-run the installer to restore the missing ${missing.map(({ label }) => label).join(" and ")}.` +
      (undetermined.length > 0
        ? ` Separately inspect ${undetermined.map(([target]) => target).join(" and ")} by hand (elevated, on ` +
          "Windows); restoring missing files does not resolve an access, quarantine, or I/O failure."
        : "");
    return {
      binary,
      result: fail(
        id,
        title,
        `the privileged helper installation is incomplete: ${missing
          .map(({ label, target }) => `${label} ${target}`)
          .join(" and ")} ${missing.length === 1 ? "is" : "are"} missing.` +
          (unknownDetail ? ` Separately, these paths could not be inspected: ${unknownDetail}.` : "") +
          conflict,
        remedy,
        { ...facts, ...(code ? { code } : {}) },
      ),
    };
  }

  if (undetermined.length > 0) {
    return {
      binary,
      result: warn(
        id,
        title,
        `whether the privileged helper is installed could not be determined: ${unknownDetail}.`,
        UNREADABLE_REMEDY,
        { ...facts, ...(code ? { code } : {}) },
      ),
    };
  }

  throw new Error("unreachable helper installation state");
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
      // A REFUSAL IS A POSITIVE FACT, AND SO IT LEAVES BEFORE THE "COULD NOT BE
      // DETERMINED" SENTENCE BELOW. For one release it did not: the denial was
      // reported with the shared opening "whether the SYSTEM task … is registered
      // could not be determined" and then asserted existence two clauses later
      // ("the task exists but this account may not read it", "which it only does
      // for a task that EXISTS") — one detail both withholding and settling
      // registration, and the opposite of what persistence.ts says about the very
      // same marker. `DENIAL_PROVES_TASK_EXISTS` is now the one sentence both
      // checks use, so they cannot drift apart again.
      //
      // A WARN, NOT AN `ok` AND NOT A `skipped`. Registration IS answered — this
      // is not a missing helper — but the refusal withheld the DEFINITION: the
      // state, and the program the task starts, which is the half this check
      // reports as facts when it can read it. Calling that `ok` would let an ACL
      // refusal alone stand in for a verified registration; calling it `skipped`
      // would deny a fact the same sentence goes on to state.
      if (task.cause === "denied") {
        return warn(
          id,
          title,
          `the SYSTEM task "${WIN_HELPER_TASK_NAME}" IS registered — ${DENIAL_PROVES_TASK_EXISTS} — but its ` +
            "state and the program it starts could not be read, so WHAT it starts was not verified. The " +
            "endpoint check below still answers whether the helper is actually reachable, whoever is asking.",
          // ABOUT WHAT THE INSTALLER SETS, never about this machine's current
          // ACL. desktop/build/win-privhelper-task.ps1 registers this task to run
          // as SYSTEM and passes no SDDL of its own, and the default ACL on such a
          // task grants a standard user no read — measured on aic-wfs-pc and
          // aic-wfs-pc2, where a non-admin COM lookup answers 0x80070005 for it.
          "Re-run the doctor from an elevated prompt to read the task's state and the program it starts. The " +
            "installer registers this task to run as SYSTEM without granting Users a read, so a refusal for a " +
            "standard user is expected rather than a fault.",
          { task: WIN_HELPER_TASK_NAME },
        );
      }
      // ONE REMEDY FOR THREE CAUSES WAS ITSELF A FALSE CLAIM. This branch used to
      // tell every unanswered query "a standard user cannot read this task's ACL,
      // re-run elevated" — including the timeout, the missing PowerShell, the
      // ConstrainedLanguage host and the blocked COM, where elevation changes
      // nothing and the sentence sends the reader after the wrong thing.
      // `task.cause` is the module's own discrimination; the words follow it.
      const because =
        // NOT the "nothing was learned" sentence, and that is the point of the
        // separate cause. Here the Task Scheduler service DID read the task, so
        // saying nothing was learned would contradict the reason printed one
        // clause earlier. What it does not do is settle registration: two lookups
        // disagreeing is not a positive answer, so this is neither a missing
        // helper nor a present one.
        task.cause === "contradiction"
          ? "Something WAS learned — the Task Scheduler service read the task — but the two lookups disagree, " +
            "which is not an answer either way, so registration here is UNKNOWN rather than missing. Re-run " +
            "the doctor from an elevated prompt; if they keep disagreeing, the task is not where or what the " +
            "installer registers."
          : // Only `lookup_failed` and `unavailable` reach this now — the refusal
            // that elevation actually answers returned above — so elevation is no
            // longer offered here: a query that never ran, never returned, or
            // broke before it reached the task needs whatever stopped it fixed
            // first, and running it elevated changes none of that.
            "Registration here is UNKNOWN, not missing: nothing was learned about the task either way. The " +
            "lookup never ran, never returned, or broke before it reached the task, so whatever stopped it " +
            "has to be fixed before this question can be answered.";
      return skipped(
        id,
        title,
        `whether the SYSTEM task "${WIN_HELPER_TASK_NAME}" is registered could not be determined: ` +
          `${task.reason}. ${because} The endpoint check below still answers whether the helper is ` +
          "actually reachable, whoever is asking.",
        { task: WIN_HELPER_TASK_NAME },
      );
    }
    const facts: DoctorFacts = { task: WIN_HELPER_TASK_NAME, state: task.state, execute: task.execute };
    // WHY `registered: false` IS TRUSTWORTHY HERE — and it is, but not for the
    // reason this comment gave for a release. It used to argue that the DEFAULT
    // task ACL (desktop/build/win-privhelper-task.ps1 registers with no SDDL) lets
    // any authenticated user read the task, so an unelevated "no such task" was
    // real evidence. MEASURED, not deduced, on aic-wfs-pc and aic-wfs-pc2: it is
    // false. As a non-admin the COM API answers 0x80070005 for
    // "AI Commander Privileged Helper" while the Relaunch and Update tasks on the
    // same box read fine — the default ACL on a SYSTEM task does NOT grant Users a
    // read, and an unelevated "no such task" is exactly the permissions artefact
    // the author had already anticipated for the OTHER tasks (persistence.ts used
    // to weaken its verdict for the Relaunch task by name) and then reasoned his
    // way out of for this one. Two of three Windows boxes reported a false
    // absence.
    // What makes the branch below safe now is queryScheduledTask, not the ACL: a
    // denied lookup comes back `queried: false` and was already reported as
    // undetermined above, so `registered: false` reaching this point means Windows
    // (or the COM API, HRESULT 0x80070002) positively said the task is not there.
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
    const plistPresence = await pathPresence(MAC_DAEMON_PLIST);
    const facts: DoctorFacts = {
      plist: MAC_DAEMON_PLIST,
      label: MAC_DAEMON_LABEL,
      ...(plistPresence.kind === "unknown" && plistPresence.code ? { code: plistPresence.code } : {}),
    };
    if (plistPresence.kind === "absent") {
      return fail(
        id,
        title,
        `the LaunchDaemon plist ${MAC_DAEMON_PLIST} is not there, so nothing starts the helper.`,
        "Re-install with the .pkg — the plain .dmg does not install the privileged helper.",
        facts,
      );
    }
    // An UNDETERMINED plist does not return here. launchd is the better witness
    // of the two, and it can still settle the question outright: a daemon it
    // reports as loaded is registered, while a root answer that it is not loaded
    // is a failure, whatever the file's stat did. The undetermined verdict only
    // applies when launchd could not settle registration either way.
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
    if (plistPresence.kind === "unknown" && !(answered && root === true)) {
      // Every remaining branch opens with "the LaunchDaemon plist is installed",
      // and not one of them may be said now: the file would not answer and
      // launchd did not report it loaded. A WARN rather than the `skipped` the
      // Windows branch above gives an unanswered query, because those are
      // different situations — there the TOOL never answered, which says nothing
      // about the machine, while here a path of OURS could not be read, which is
      // itself the finding (storage.ts warns for exactly this, in the same
      // words). `skipped` also carries no remedy field, and the one thing this
      // state needs is a remedy that does NOT say re-install.
      return warn(
        id,
        title,
        `whether the LaunchDaemon plist ${MAC_DAEMON_PLIST} is installed could not be determined: it could not ` +
          `be inspected (${plistPresence.error}), and launchd did not report ${MAC_DAEMON_LABEL} as loaded ` +
          "either, which on its own settles nothing. Registration here is UNKNOWN, not missing. The endpoint " +
          "check below still answers whether the helper is actually reachable.",
        UNREADABLE_REMEDY,
        withState,
      );
    }
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
      (plistPresence.kind === "unknown"
        ? `the LaunchDaemon plist ${MAC_DAEMON_PLIST} could not be inspected (${plistPresence.error}), but `
        : `the LaunchDaemon plist ${MAC_DAEMON_PLIST} is installed, but `) +
        `launchd — asked AS ROOT, so this is not a ` +
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
 *
 * ── IT TAKES THE MEASUREMENT, NOT A PATH ─────────────────────────────────────
 * The parameter is `HelperBinary` and not `string | null` because "we could not
 * read the file" is a third answer, and every verdict below is a claim about a
 * file that WAS read: `Valid`, `HashMismatch`, "could not be verified" and, at
 * the sharp end, "Do not trust this binary". A binary whose own stat would not
 * answer has to leave before any of them, which is what the `unreadable` branch
 * does — the same rule `checkInstalled` follows for the install as a whole, in
 * the same words.
 */
async function checkSignature(binary: HelperBinary): Promise<CheckResult> {
  const id = "helper.signature";
  const title = "Privileged helper — signature";
  if (binary.kind === "absent") return skipped(id, title, "there is no installed helper binary to verify.");
  if (binary.kind === "unreadable") {
    // NOT A VERDICT ON THE BINARY, on either platform. A file a filter driver is
    // holding is exactly the case this group was written for, and the two
    // platform branches below would each answer it with a claim they cannot
    // support: Windows can hand back a `Status` for a file it never read and
    // turn it into "Do not trust this binary", and `codesign` failing to open
    // the file is indistinguishable there from a signature that does not verify.
    return warn(
      id,
      title,
      `whether the installed helper is correctly signed could not be determined: the binary could not be ` +
        `inspected (${binary.error}), so nothing here is a statement about its signature either way.`,
      UNREADABLE_REMEDY,
      { binary: binary.path, ...(binary.code ? { code: binary.code } : {}) },
    );
  }
  const helperExe = binary.path;

  if (process.platform === "win32") {
    const captured = await runPowerShell(
      "$ErrorActionPreference='Stop';" +
        `$s = Get-AuthenticodeSignature -FilePath ${powerShellSingleQuote(helperExe)};` +
        "Write-Output ('STATUS=' + $s.Status);" +
        "Write-Output ('SUBJECT=' + $s.SignerCertificate.Subject)",
    );
    const out = capturedStdout(captured);
    if (out.trim() === "") {
      return warn(id, title, "the Authenticode signature could not be read.", UNSETTLED_SIGNATURE_REMEDY, {
        binary: helperExe,
      });
    }
    const status = /^STATUS=(.*)$/m.exec(out)?.[1]?.trim() ?? UNPARSED_STATUS;
    const subject = /^SUBJECT=(.*)$/m.exec(out)?.[1]?.trim() ?? "";
    const facts: DoctorFacts = { binary: helperExe, status, subject, expectedSubject: WIN_EXPECTED_SUBJECT };
    // A STATUS THAT MEANS "THE CHECK DID NOT COMPLETE" IS NOT A TAMPER VERDICT.
    // Everything that is not `Valid` used to end in "Do not trust this binary",
    // which is the right sentence for the three statuses that are findings about
    // the FILE and the wrong one for the two that are findings about the RUN.
    if (UNSETTLED_STATUSES.has(status)) {
      return warn(
        id,
        title,
        `whether the installed helper is correctly signed could not be determined: Windows answered ` +
          `${status}, which says the signature check did not complete — not that the signature is bad.`,
        UNSETTLED_SIGNATURE_REMEDY,
        facts,
      );
    }
    if (status === "UnknownError") {
      return fail(
        id,
        title,
        "Windows reported UnknownError, so the installed helper's Authenticode signature could not be confirmed.",
        "Treat the helper as unverified. Re-install from a release download, then confirm the signature with " +
          "`Get-AuthenticodeSignature` from an elevated prompt.",
        facts,
      );
    }
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
    // WHAT AN UNREADABLE BINARY DOES HERE, checked rather than assumed: the
    // sentinel `echo VERIFIED` runs only after `codesign --verify` exits 0, and
    // codesign that cannot OPEN the file exits non-zero exactly like codesign
    // that opened it and disliked what it found. So this branch cannot tell the
    // two apart at all — and it does not have to, because it never claims to:
    // the verdict below is a `warn` reading "could not be verified", which is
    // true of both, and it does not tell anyone the binary is untrustworthy.
    // The DISCRIMINATION is the caller's now (`binary.kind === "unreadable"`
    // returns before this), which is what keeps "could not be verified" here
    // meaning what it says: codesign read the file and would not vouch for it.
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
      await checkSignature(installed.binary),
      await checkEndpoint(),
    ];
  },
};
