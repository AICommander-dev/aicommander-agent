// `aicommander-priv-helper doctor` — a doctor that survives a gutted install
// (PLAN-av-hardening.md W2.3).
//
// WHY IT EXISTS AT ALL. On 2026-09-02 an antivirus emptied
// `C:\Program Files\AI Commander\` — 80 of 81 files — and the surviving exe died
// inside Electron's own startup with `Invalid file descriptor to ICU data
// received`. Nothing in $INSTDIR could run any more, which means every
// diagnostic that lives in the app (the tray's "Run Diagnostics…", the agent's
// `doctor` CLI shipped beside it) was unavailable at precisely the moment it was
// needed. This binary is not in $INSTDIR: it is installed in the SIBLING
// directory `%ProgramFiles%\AI Commander Privileged Helper`, which the sweep did
// not touch and which the app's uninstaller does not wipe. It is the last thing
// on the machine still able to describe what happened.
//
// ── THIS IS A NARROWER CHECK SET THAN `aicommander-agent doctor`, ON PURPOSE ──
// It is NOT the agent's check library. Two independent reasons, both structural:
//
//   1. It cannot be. The agent's doctor imports this package (its `helper.*`
//      checks need our endpoint, protocol frames and install locations), so
//      depending on `@aicommander/agent` from here makes a package cycle —
//      verified, not assumed: turbo refuses the workspace outright with
//      "Cyclic dependency detected: @aicommander/agent#build,
//      @aicommander/priv-helper#build". The helper is a standalone SEA whose
//      bundle would otherwise have swallowed the whole agent quite happily.
//   2. It should not be. This binary may be running as SYSTEM (its own scheduled
//      task) or as root. Half of the agent's checks are questions about ONE
//      USER'S session — their stored relay credentials, their jobs directory,
//      their autostart entry, their config store. Answered from SYSTEM they
//      would be answered about the wrong profile and would read as "nothing is
//      there", which is the most expensive wrong answer this whole workstream
//      exists to stop us giving.
//
// So the verb reports what THIS vantage point can honestly answer — machine-wide
// facts rooted in admin-owned state — names what it did not check, and says
// where the full set lives. `UNCHECKED_HERE` below is that list, and it is
// printed to the user rather than kept as a comment.
//
// ── EVERY LINE IS REDACTED, BECAUSE THIS FILE ONCE CLAIMED IT NEED NOT BE ────
// This header used to argue that nothing here needs redacting "by
// construction": fixed machine-wide locations, version strings, counts and
// booleans. The claim was wrong in three places, and the verb's own footer
// tells the reader the output is safe to send to support and to an antivirus
// vendor — so it had to be made true rather than asserted.
//   1. The VERSION marker's CONTENT is interpolated. A marker is a file, and
//      beside a COPIED helper it is a file whoever made the copy controls.
//   2. The unelevated install scan reports the root it counted in, derived from
//      THIS binary's own location — a user path the moment somebody runs the
//      helper out of their Downloads folder, which is the case checkBinary
//      exists to report.
//   3. A check that throws prints the exception's message, and an fs error's
//      message embeds the path it failed on.
// So `runHelperDoctor` passes every detail and remedy through
// `redactHelperText` (redact.ts — the agent's rules, mirrored because importing
// the agent from here is the package cycle described above), and the marker is
// narrowed to a version-shaped value or nothing at all. A CHECK ADDED HERE
// STILL MUST NOT GO LOOKING for user state; the redactor is what makes a
// mistake harmless, not a licence.
//
// ── IT DIAGNOSES; IT NEVER ACTS ──────────────────────────────────────────────
// Nothing below starts the daemon, opens the IPC listener, executes anything,
// registers or repairs anything. The one Windows query it makes is the
// watchdog's existing read-only probe — `probeWindows()`, never
// `triggerRelaunchTask()` — and when that probe is unavailable because the
// caller is not an administrator, the fallback (install-scan.ts) only lstats a
// list of relative paths under a directory beside this binary and returns
// integers. Both of them now read the install manifest from the copy the
// installer placed beside THIS binary when the one inside the install directory
// is gone, which is the only reason either can still answer the incident
// question at all (win-watchdog-install.ts). `looksUnelevated` adds one more
// read — an enumerate of a fixed administrators-only system directory, used
// solely to skip a probe that cannot succeed, and failing OPEN so being wrong
// costs seconds rather than an answer. Neither path turns anything it reads into a program, a path it
// executes, or a file it writes. The endpoint check opens a TCP/unix connection,
// sends the protocol's `hello` and hangs up on the answer: it asks WHO is
// listening, where a bare connect established only that something is, which any
// local squatter can arrange. What comes back is a CLAIM and is reported as one
// — a responder that will not speak our protocol version is not shown to the
// reader as our own helper, because nothing on this path can tell our helper
// from anything else that bound the address first. That check, and that
// distinction, live in doctor-endpoint.ts. `hello` carries no capability, so
// there is nothing it could ask the helper to do.

import fs from "node:fs";
import path from "node:path";
import {
  WIN_HELPER_TASK_NAME,
  MAC_DAEMON_PLIST,
  elevatedEndpoints,
  helperInstallDir,
  helperVersionMarkerPath,
  type ElevatedEndpoint,
} from "./endpoint.js";
import { HELPER_VERSION } from "./version.js";
import { checkEndpoint, type EndpointObservation } from "./doctor-endpoint.js";
import { redactHelperText } from "./redact.js";
import { probeWindows } from "./win-watchdog-probe.js";
import { scanInstall, type InstallScanResult } from "./install-scan.js";
import { WATCHDOG_LOG_NAME, watchdogLogDir } from "./win-watchdog-logfile.js";
import type { ProbeResult } from "./win-watchdog.js";

// Re-exported from the module it now lives in: `helper.endpoint` was split into
// doctor-endpoint.ts when this file reached its size limit, and this is still
// the module the doctor's result shapes are imported from.
export type { EndpointObservation };

/** Short URL of record; redirects to /troubleshooting/#antivirus. */
export const HELPER_DOCTOR_HELP_URL = "https://aicommander.dev/antivirus";

/** How long to wait for something to answer the helper endpoint. */
const ENDPOINT_TIMEOUT_MS = 2_000;

/**
 * The probe's budget WHEN THIS VERB RUNS IT — a quarter of the watchdog's, and
 * the difference is the audience. The watchdog probes on a 60-second timer with
 * nobody watching, so 30 seconds of patience costs nothing. This verb runs in a
 * console window the installer's Start Menu shortcut opened, in front of a person
 * whose app just stopped starting, and `renderHelperDoctor` prints nothing until
 * every check has finished. Thirty seconds of blank window is a hang as far as
 * that reader is concerned, and they close it.
 */
const DOCTOR_PROBE_TIMEOUT_MS = 8_000;

/**
 * Whether this process can read an administrators-only location — a cheap,
 * synchronous stand-in for "am I elevated", used ONLY to skip a probe that
 * cannot succeed.
 *
 * WHY IT EXISTS. `checkAppInstall` runs the watchdog's probe first and falls
 * back to the unelevated scan when it fails. For an administrator that is right.
 * For everybody else it is up to DOCTOR_PROBE_TIMEOUT_MS of powershell.exe cold
 * start, a Win32_Process enumeration and a pile of owner-SID lookups, all of it
 * discarded, before the answer that was always going to be used — on the exact
 * path (an unelevated Start Menu shortcut) this whole binary was built for.
 *
 * `%SystemRoot%\System32\config` is the canonical choice: its DACL grants
 * SYSTEM and Administrators and nobody else, and enumerating it needs
 * FILE_LIST_DIRECTORY. It is a READ of a fixed machine path and nothing else.
 *
 * IT FAILS OPEN, and that is the whole safety argument: anything other than a
 * clean access denial — success, a path we could not resolve, an unexpected
 * errno, a future Windows that changes the ACL — still runs the probe. Being
 * wrong therefore costs the 8 seconds it used to cost anyway, never an answer.
 */
function looksUnelevated(): boolean {
  if (process.platform !== "win32") return false;
  const root = process.env["SystemRoot"] ?? process.env["windir"];
  if (!root) return false;
  try {
    fs.readdirSync(path.join(root, "System32", "config"));
    return false;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === "EPERM" || code === "EACCES";
  }
}

/**
 * Same four words the agent's checks use, and for the same reasons:
 * `skipped` is "not checked, here is why" — never a verdict on the machine.
 */
export type HelperCheckVerdict = "ok" | "warn" | "fail" | "skipped";

export interface HelperCheck {
  /** Stable and dotted, like the agent's ids, so support tooling can key off it. */
  id: string;
  title: string;
  verdict: HelperCheckVerdict;
  detail: string;
  /** What to DO about it, on warn/fail, wherever we know. */
  remedy?: string;
}

/**
 * What `aicommander-agent doctor` (and the tray) check and this verb does not.
 * PRINTED, not merely documented: shipping a smaller check set under the same
 * word "diagnostics" without saying so would let a clean run here be read as a
 * clean bill of health for a machine whose relay credentials are the problem.
 */
export const UNCHECKED_HERE: readonly string[] = [
  "the connection to the relay (DNS, HTTPS, ticket exchange, WebSocket upgrade) — it needs the signed-in user's stored agent token, which this process cannot see and must not go looking for",
  "the live antivirus write probe in the user's jobs directory — a per-user path, and running it as SYSTEM would measure the wrong directory",
  "whether the install directory is writable from the user's own context",
  "the user's autostart entry (Run value / login item) and their config and session store",
  "disk space, clock skew and proxy environment as the agent sees them",
];

function fileExists(target: string): boolean {
  try {
    fs.statSync(target);
    return true;
  } catch {
    return false;
  }
}

/**
 * The only shape of VERSION marker content this verb will print back. Same
 * regex install-scan.ts applies to a manifest's `version`, for the same reason:
 * a value read off disk is only quoted when it looks like the thing it claims
 * to be.
 */
const MARKER_VERSION_RE = /^[0-9]{1,5}(\.[0-9]{1,5}){0,3}(-[A-Za-z0-9.]{1,16})?$/;

/** Windows: the SEA binary this verb is running from. macOS: the daemon binary. */
const WIN_HELPER_EXE = "aicommander-priv-helper.exe";
const MAC_HELPER_BIN = "aicommander-priv-helper";

/**
 * This binary: which build it is, and whether it is the installed copy.
 *
 * Note what is NOT printed: `process.execPath` when it is NOT the installed
 * location. Anybody may run this binary from their Downloads folder, so that
 * path is a USER path — the one class of string this output does not carry (see
 * the header). The installed location is fixed and machine-wide, so it prints;
 * "somewhere else" is all the reader needs about the other case.
 */
function checkBinary(): HelperCheck {
  const id = "helper.binary";
  const title = "Privileged helper — this binary";
  const dir = helperInstallDir();
  if (dir === null) {
    return { id, title, verdict: "ok", detail: `version ${HELPER_VERSION}.` };
  }
  const installed = path.join(dir, process.platform === "win32" ? WIN_HELPER_EXE : MAC_HELPER_BIN);
  if (path.resolve(process.execPath).toLowerCase() === path.resolve(installed).toLowerCase()) {
    return {
      id,
      title,
      verdict: "ok",
      detail: `version ${HELPER_VERSION}, running from its installed location (${installed}).`,
    };
  }
  return {
    id,
    title,
    verdict: "warn",
    detail: `version ${HELPER_VERSION}, but this copy is not the installed one (${installed}).`,
    remedy:
      "Everything below still describes this machine, but the installed helper — the one the system actually runs — may be a different build.",
  };
}

/**
 * The VERSION marker the installer writes beside the helper.
 *
 * `marker` is a seam: production passes `helperVersionMarkerPath()`, and the
 * tests pass a path they built, so this check's verdict depends on the fixture
 * rather than on whether the developer's own machine happens to have a helper
 * installed. (It used to depend on the latter, which is how the "asserts a
 * version it never read" branch went untested — the machine running the suite
 * always had a readable, version-shaped marker.)
 */
function checkMarker(marker: string | null): HelperCheck {
  const id = "helper.marker";
  const title = "Privileged helper — install marker";
  if (marker === null) {
    return { id, title, verdict: "skipped", detail: "no privileged helper on this platform." };
  }
  if (!fileExists(marker)) {
    return {
      id,
      title,
      verdict: "fail",
      detail: `the helper's VERSION marker is missing (${marker}) — as far as the rest of the product is concerned, no helper is installed.`,
      remedy: "Re-run the installer; it writes the marker from its own elevated context.",
    };
  }
  // THE MARKER'S CONTENT IS NOT OURS UNTIL IT LOOKS LIKE OURS. It is a file, and
  // beside a copied helper it is a file whoever made the copy wrote; this text
  // is interpolated into a report we tell people to forward. Anything that is
  // not version-shaped is dropped entirely rather than printed — the presence of
  // the marker is the contract, its content is only ever a skew hint.
  let recorded = "";
  // THE THIRD ANSWER, WHICH THIS CHECK USED TO ROUND AWAY. `recorded` stayed ""
  // both when the file could not be read and when what it held was not
  // version-shaped, and the success sentence then printed
  // `recorded || HELPER_VERSION` — i.e. it asserted the marker records THIS
  // build, having never read a version at all, in a report whose footer tells
  // the reader it is safe to forward. Read and unreadable are tracked apart.
  let unreadable = false;
  let unrecognised = false;
  try {
    const raw = fs.readFileSync(marker, "utf8").trim();
    if (MARKER_VERSION_RE.test(raw)) recorded = raw;
    else unrecognised = true;
  } catch {
    unreadable = true;
  }
  if (recorded && recorded !== HELPER_VERSION) {
    return {
      id,
      title,
      verdict: "warn",
      detail: `the marker records ${recorded} but this binary is ${HELPER_VERSION} — a half-applied upgrade.`,
      remedy: "Re-run the installer, then reboot so the SYSTEM helper restarts on the new binary.",
    };
  }
  if (unreadable || unrecognised) {
    // Not a failure: the marker's PRESENCE is the contract the rest of the
    // product reads (endpoint.ts), and it is present. But the recorded build is
    // unknown, so it is not claimed — and neither cause is health. An
    // unreadable file in an admin-owned directory is a denial worth seeing, and
    // content that is not version-shaped is somebody else's file where ours
    // should be.
    return {
      id,
      title,
      verdict: "warn",
      detail: unreadable
        ? `the helper's VERSION marker is present (${marker}) but could not be read, so the recorded build is unknown. That is access being denied, not a missing helper.`
        : `the helper's VERSION marker is present (${marker}) but does not contain a version, so the recorded build is unknown.`,
      remedy: "Re-run the installer; it rewrites the marker from its own elevated context.",
    };
  }
  return {
    id,
    title,
    verdict: "ok",
    detail: `installed and marked as ${recorded}.`,
  };
}

/** Is the helper registered with the OS at all — the incident's silent failure. */
function checkRegistration(): HelperCheck {
  const id = "helper.registration";
  const title = "Privileged helper — registration";
  if (process.platform === "darwin") {
    return fileExists(MAC_DAEMON_PLIST)
      ? { id, title, verdict: "ok", detail: `the LaunchDaemon plist is installed (${MAC_DAEMON_PLIST}).` }
      : {
          id,
          title,
          verdict: "fail",
          detail: `the LaunchDaemon plist is missing (${MAC_DAEMON_PLIST}) — elevated commands can never run here.`,
          remedy: "Re-install AI Commander from the .pkg, which installs and loads the daemon.",
        };
  }
  if (process.platform === "win32") {
    // Deliberately NOT a schtasks query: shelling out to enumerate a task would
    // be a second, weaker copy of a check the agent already owns, and the
    // endpoint answer below is the one that matters here — a registered task
    // that never starts is indistinguishable from an unregistered one from the
    // user's side. Named as skipped rather than quietly omitted.
    return {
      id,
      title,
      verdict: "skipped",
      detail: `whether the SYSTEM task "${WIN_HELPER_TASK_NAME}" is registered is not checked from here; the endpoint check below answers whether it is actually running.`,
    };
  }
  return { id, title, verdict: "skipped", detail: "no privileged helper on this platform." };
}

/**
 * THE incident question — "how many files are in your AI Commander folder?" —
 * answered from outside that folder.
 *
 * TWO WAYS OF ANSWERING IT, AND THE SECOND IS THE ONE THAT MATTERS. The first is
 * the watchdog's existing read-only probe: it derives the install directory from
 * the admin-owned Relaunch task (it refuses to GUESS, because it ACTS on what it
 * finds), reads the shipped manifest from inside it and counts what is missing.
 * That probe needs administrative rights — the Relaunch task's SDDL grants
 * access to SYSTEM and Administrators only — and the Start Menu entry the
 * installer creates for this verb launches UNELEVATED. So on the path this
 * binary was built for (a normal user clicking "AI Commander Diagnostics" after
 * the app stopped starting) the probe cannot answer at all, and this check used
 * to degrade to "Windows could not be queried" — the least useful sentence
 * available at that moment.
 *
 * The fallback is `scanInstall()`, which locates the app by convention from this
 * executable's own directory and counts the manifest itself. It may guess where
 * the probe may not, because it does nothing with the answer but print it; see
 * install-scan.ts. The output SAYS which of the two produced the numbers, so a
 * support engineer is never left wondering whether the directory was confirmed.
 *
 * Nothing about either observation is re-used to execute anything here.
 */
async function checkAppInstall(
  probe: () => Promise<ProbeResult>,
  scan: () => Promise<InstallScanResult>,
  /**
   * Whether the elevation shortcut below may run at all. False when the caller
   * INJECTED a probe — a test's probe is the machine, and consulting the real
   * `%SystemRoot%\System32\config` DACL would make the suite's behaviour depend
   * on whether the account running it happens to be an administrator.
   */
  mayShortCircuit: boolean,
): Promise<HelperCheck> {
  const id = "app.install";
  const title = "AI Commander install";
  if (process.platform !== "win32") {
    return {
      id,
      title,
      verdict: "skipped",
      detail:
        "checked only on Windows from here; on macOS the app bundle is signed and notarized, so `codesign --verify --deep` is the equivalent statement.",
    };
  }
  // Skip a probe that is going to be refused anyway — see looksUnelevated().
  // The reason handed to the unelevated answer names the skip rather than
  // borrowing a probe failure code that never happened.
  if (mayShortCircuit && looksUnelevated()) {
    return await checkAppInstallUnelevated(id, title, "not running as an administrator", scan);
  }
  const result = await probe();
  if (!result.ok) return await checkAppInstallUnelevated(id, title, result.reason, scan);
  const { trayExeInstalled, manifest } = result.snapshot.install;
  if (manifest === null) {
    // NEITHER COPY OF THE MANIFEST COULD BE READ — and that is the incident's
    // own shape, not a clean bill of health. This branch used to report `ok`
    // with the invented fact "this build shipped no file manifest", which the
    // probe cannot possibly know: it emits null identically for a build that
    // shipped none, a manifest quarantined along with everything else, and a
    // read that was denied. On the one verb an administrator runs after the app
    // stopped starting, that printed a pass.
    //
    // So: `warn`, and the sentence says what was tried. Both copies are now
    // tried (win-watchdog-install.ts), which is why "no manifest anywhere" is
    // a much stronger signal than it was — an install that has one usually has
    // two — without ever being evidence of damage on its own.
    return trayExeInstalled
      ? {
          id,
          title,
          verdict: "warn",
          detail:
            "the installed application is present, but NOTHING COULD BE COUNTED: no file manifest was readable — " +
            "not the one inside the install directory, and not the copy beside this helper. An install too old to " +
            "ship one reads exactly like an install whose manifest was quarantined, so this is not a statement " +
            "that files are missing — it is a statement that the question was not answered.",
          remedy:
            "Re-run the installer; it ships a fresh manifest and places the second copy beside this helper. If it " +
            `keeps happening, security software is denying reads of the install directory: ${HELPER_DOCTOR_HELP_URL}`,
        }
      : {
          id,
          title,
          verdict: "fail",
          detail: "the installed application executable is GONE from the install directory.",
          remedy: `This is what an antivirus sweep looks like. Restore it from quarantine and re-install: ${HELPER_DOCTOR_HELP_URL}`,
        };
  }
  const { totalFiles, missingFiles, missingCritical, unreadableFiles, version, source } = manifest;
  // A count from the sibling copy is a count from an inventory that MIGHT be a
  // build behind (it is only ever read when the in-tree one is gone), so the
  // report says so rather than letting the reader assume otherwise.
  const counted_from = source === "helper" ? fromHelperCopy : "";
  // Same rule as install-scan.ts's: an inventory that lists nothing is a damaged
  // inventory, and "all 0 shipped files are present" is the healthiest-looking
  // sentence this verb could print about a wrecked machine.
  if (totalFiles === 0) {
    return {
      id,
      title,
      verdict: "warn",
      detail:
        "the shipped file manifest lists no files at all, so nothing could be counted — the manifest itself " +
        "is empty or damaged. That is not a statement that files are missing.",
      remedy: `Re-install AI Commander; the installer ships a fresh manifest with it. ${HELPER_DOCTOR_HELP_URL}`,
    };
  }
  const counted = describeCounts({ totalFiles, missingFiles, missingCritical, unreadableFiles, version });
  if (missingCritical > 0) {
    return {
      id,
      title,
      verdict: "fail",
      detail: `the installation has been gutted: ${counted}${counted_from}`,
      remedy: `This is what an antivirus sweep looks like — the app cannot start without those files. Restore them from quarantine, add an exclusion, and re-install: ${HELPER_DOCTOR_HELP_URL}`,
    };
  }
  if (missingFiles > 0) {
    return {
      id,
      title,
      verdict: "warn",
      detail: `${counted} None of them is a file the app needs in order to start.${counted_from}`,
      remedy: `If you did not remove them yourself, security software did: ${HELPER_DOCTOR_HELP_URL}`,
    };
  }
  const unread =
    unreadableFiles > 0 ? ` ${unreadableFiles} could not be read — that is access being denied, not damage.` : "";
  return {
    id,
    title,
    verdict: trayExeInstalled ? "ok" : "warn",
    detail: trayExeInstalled
      ? `the installation is complete — all ${totalFiles} shipped files are present.${unread}${counted_from}`
      : `all ${totalFiles} manifested files are present, but the tray executable is not where the Relaunch task expects it.${unread}${counted_from}`,
    ...(trayExeInstalled ? {} : { remedy: "Re-run the installer; it re-pins the task at the current location." }),
  };
}

/**
 * Said whenever the numbers come from the copy beside this binary rather than
 * from inside the directory they describe — which only happens when the in-tree
 * manifest is gone, i.e. on exactly the machine this verb exists for.
 */
const fromHelperCopy =
  " The inventory used was the copy beside this helper: the one inside the install directory is gone too, " +
  "which is itself part of the picture.";

/** One sentence of counts, shared by the elevated and unelevated answers. */
function describeCounts(m: {
  totalFiles: number;
  missingFiles: number;
  missingCritical: number;
  unreadableFiles: number;
  version: string;
}): string {
  return (
    `${m.missingFiles} of ${m.totalFiles} shipped files are missing` +
    (m.missingCritical > 0 ? `, ${m.missingCritical} of them critical` : "") +
    // Reported, never counted as damage: an unreadable file is present as far as
    // anyone here knows, and a machine whose filter driver denies reads of
    // %ProgramFiles% is a support case that starts with exactly that fact.
    (m.unreadableFiles > 0 ? `, and ${m.unreadableFiles} could not be read` : "") +
    (m.version ? ` (build ${m.version})` : "") +
    "."
  );
}

/**
 * The answer for the user this verb exists for: no elevation, no scheduled-task
 * read, the install located by convention from this binary's own directory.
 * Every verdict says so, because a count from a directory we identified rather
 * than confirmed is worth exactly as much as the reader's knowledge of that.
 */
async function checkAppInstallUnelevated(
  id: string,
  title: string,
  probeReason: string,
  scan: () => Promise<InstallScanResult>,
): Promise<HelperCheck> {
  const result = await scan();
  if (!result.ok) {
    // A DAMAGED MANIFEST IS ITS OWN ANSWER. "We found the inventory and it lists
    // nothing" is not "we found no inventory", and neither is "the install is
    // fine" — see install-scan.ts.
    if (result.reason === "manifest-unusable") {
      return {
        id,
        title,
        verdict: "warn",
        detail:
          "an install manifest was found beside this program but it is not one we can count — it is empty, or it " +
          "names a path we will not follow, so the manifest itself is damaged and nothing was counted. That is " +
          "not a statement that files are missing.",
        remedy: `Re-install AI Commander; the installer ships a fresh manifest with it. ${HELPER_DOCTOR_HELP_URL}`,
      };
    }
    // ...and the limitation is NAMED rather than left as a bare "not confirmed":
    // only the default sibling locations are derivable from this binary's own
    // path, so an install placed elsewhere with NSIS `/D=` is out of reach from
    // an unelevated process — the probe, which CAN read the real directory off
    // the Relaunch task, is the one that needs elevation.
    const tried = result.triedRoots?.length ? ` Looked in: ${result.triedRoots.join(", ")}.` : "";
    return {
      id,
      title,
      verdict: "warn",
      detail:
        `the installation could not be located from here (${probeReason}, and no install manifest was found ` +
        `beside this program).${tried} Only the default install locations can be derived without ` +
        "administrative rights, so an app installed elsewhere is invisible from here — nothing was counted, " +
        "and this is not a statement that files are missing.",
      remedy:
        "If the app is installed somewhere other than the default folder, run `aicommander-agent doctor` from " +
        "the machine's own account instead; it reads the manifest from the app it ships beside. Running this " +
        "verb as an administrator also lets it read the install directory from the Relaunch task.",
    };
  }
  const { root, totalFiles, missingFiles, missingCritical, unreadableFiles, version, source } = result.scan;
  const located =
    ` Counted in ${root}, found beside this program; the exact folder was not confirmed against Windows (${probeReason}).` +
    (source === "helper" ? fromHelperCopy : "");
  const counted = describeCounts({ totalFiles, missingFiles, missingCritical, unreadableFiles, version });
  if (missingCritical > 0) {
    return {
      id,
      title,
      verdict: "fail",
      detail: `the installation has been gutted: ${counted}${located}`,
      remedy: `This is what an antivirus sweep looks like — the app cannot start without those files. Restore them from quarantine, add an exclusion, and re-install: ${HELPER_DOCTOR_HELP_URL}`,
    };
  }
  if (missingFiles > 0) {
    return {
      id,
      title,
      verdict: "warn",
      detail: `${counted} None of them is a file the app needs in order to start.${located}`,
      remedy: `If you did not remove them yourself, security software did: ${HELPER_DOCTOR_HELP_URL}`,
    };
  }
  // Nothing is missing. Where some entries could not be READ, the sentence says
  // so instead of claiming a completeness this process did not establish — but
  // it stays an `ok`: an unreadable file is present as far as anyone here knows,
  // and a warning on an intact machine is what gets the real one ignored.
  const complete =
    unreadableFiles > 0
      ? `no shipped file is missing, but ${unreadableFiles} of ${totalFiles} could not be read — that is access being denied, not damage.`
      : `the installation is complete — all ${totalFiles} shipped files are present.`;
  return { id, title, verdict: "ok", detail: `${complete}${located}` };
}

/** Has the watchdog ever had anything to say? Presence and age only, no content. */
function checkWatchdogLog(): HelperCheck {
  const id = "watchdog.log";
  const title = "Watchdog log";
  if (process.platform !== "win32") {
    return { id, title, verdict: "skipped", detail: "the crash watchdog is Windows-only." };
  }
  const file = path.join(watchdogLogDir(), WATCHDOG_LOG_NAME);
  let stats: fs.Stats;
  try {
    stats = fs.statSync(file);
  } catch {
    return {
      id,
      title,
      verdict: "warn",
      detail: `no watchdog log at ${file} — the privileged helper may never have run on this machine.`,
      remedy: "If the endpoint check above also failed, re-run the installer and reboot.",
    };
  }
  const hoursAgo = Math.round((Date.now() - stats.mtimeMs) / 3_600_000);
  return {
    id,
    title,
    verdict: "ok",
    // The path and the size only. The log's CONTENT is never quoted here: it is
    // written as SYSTEM and world-readable, and this output is meant to be
    // pasted into a support case as-is.
    detail: `${file} — ${stats.size} bytes, last written ${hoursAgo}h ago. Attach it to your support case.`,
  };
}

export interface HelperDoctorDeps {
  /** Test seam: the watchdog's read-only Windows probe. */
  probe?: () => Promise<ProbeResult>;
  /** Test seam: the unelevated manifest scan the probe falls back to. */
  scan?: () => Promise<InstallScanResult>;
  /** Test seam: endpoint connect budget. */
  endpointTimeoutMs?: number;
  /** Test seam: the endpoints to interrogate (production reads endpoint.ts). */
  endpoints?: readonly ElevatedEndpoint[];
  /**
   * Test seam: the VERSION marker to read (production reads endpoint.ts).
   * `null` means "no privileged helper on this platform", the same value
   * `helperVersionMarkerPath()` returns there.
   */
  markerPath?: string | null;
}

/**
 * Run every check. Never throws: one check that blew up must not silence the
 * others — a doctor that dies on its third question is worse than none, because
 * the user has already concluded the product cannot describe itself.
 */
export async function runHelperDoctor(deps: HelperDoctorDeps = {}): Promise<HelperCheck[]> {
  const probe = deps.probe ?? (() => probeWindows(DOCTOR_PROBE_TIMEOUT_MS));
  const scan = deps.scan ?? (() => scanInstall());
  const timeoutMs = deps.endpointTimeoutMs ?? ENDPOINT_TIMEOUT_MS;
  const checks: Array<() => HelperCheck | Promise<HelperCheck>> = [
    checkBinary,
    () => checkMarker(deps.markerPath !== undefined ? deps.markerPath : helperVersionMarkerPath()),
    checkRegistration,
    () => checkEndpoint(timeoutMs, deps.endpoints ?? elevatedEndpoints()),
    () => checkAppInstall(probe, scan, deps.probe === undefined),
    checkWatchdogLog,
  ];
  const results: HelperCheck[] = [];
  const push = (check: HelperCheck): void => {
    // ONE CHOKE POINT, so no future check can be the one that forgets. Titles
    // and ids are constants in this file; detail and remedy are where a marker's
    // content, a scanned root or an exception message can reach the page.
    results.push({
      ...check,
      detail: redactHelperText(check.detail),
      ...(check.remedy ? { remedy: redactHelperText(check.remedy) } : {}),
    });
  };
  for (const run of checks) {
    try {
      push(await run());
    } catch (err) {
      push({
        id: "doctor.error",
        title: "Diagnostic fault",
        verdict: "fail",
        detail: `a check could not be completed: ${err instanceof Error ? err.message : String(err)}`,
        remedy: "This is a fault in the diagnostic itself, not necessarily in the machine. The other checks still ran.",
      });
    }
  }
  return results;
}

const MARKS: Record<HelperCheckVerdict, string> = { ok: "✓", warn: "⚠", fail: "✗", skipped: "–" };

/**
 * Plain text, no colour, no dependencies — this is NOT a fork of the agent's
 * renderer (see the header for why that one cannot be reached from here); it
 * formats a different, smaller result shape, and it stays deliberately dull so
 * that whatever a user pastes into a ticket survives the paste.
 */
export function renderHelperDoctor(checks: readonly HelperCheck[]): string {
  const lines: string[] = [
    "",
    `  AI Commander — diagnostics from the privileged helper (${HELPER_VERSION}, ${process.platform}/${process.arch})`,
    "",
  ];
  for (const check of checks) {
    // Redacted AGAIN here, not only in runHelperDoctor. The footer below tells
    // the reader this text is safe to forward, and that promise belongs to
    // whatever is actually printed — `redactHelperText` is idempotent, so the
    // second pass costs nothing and covers a caller that built a check itself.
    lines.push(`  ${MARKS[check.verdict]}  ${check.title} — ${redactHelperText(check.detail)}`);
    if (check.remedy) lines.push(`       → ${redactHelperText(check.remedy)}`);
  }
  const failed = checks.filter((c) => c.verdict === "fail");
  lines.push("");
  lines.push(
    failed.length > 0
      ? `  ${failed.length} problem${failed.length === 1 ? "" : "s"} found. Start here: ${HELPER_DOCTOR_HELP_URL}`
      : "  Nothing broken in what this binary can see.",
  );
  lines.push("");
  lines.push("  This is the REDUCED check set the privileged helper can answer on its own.");
  lines.push("  It does not check:");
  for (const item of UNCHECKED_HERE) lines.push(`    · ${item}`);
  lines.push("");
  lines.push("  For all of those, run `aicommander-agent doctor` — or, once AI Commander starts");
  lines.push("  again, its menu-bar item \"Run Diagnostics…\".");
  lines.push("");
  lines.push("  Every line above has been through the same redaction the app's own report uses:");
  lines.push("  home directories are collapsed to ~, access codes masked, tokens and signed");
  lines.push("  capabilities blanked. It is safe to paste into a support case or an antivirus");
  lines.push("  vendor submission.");
  lines.push("");
  return lines.join("\n");
}

/** 1 when any check FAILED — warnings and skips are not failures. */
export function helperDoctorExitCode(checks: readonly HelperCheck[]): number {
  return checks.some((c) => c.verdict === "fail") ? 1 : 0;
}
