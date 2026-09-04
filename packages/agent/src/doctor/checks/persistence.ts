import fs from "node:fs";
import os from "node:os";
import { runCaptured } from "../../capture.js";
import {
  errorText,
  fail,
  ok,
  pathFact,
  skipped,
  warn,
  type CheckResult,
  type DoctorCheckGroup,
  type DoctorContext,
  type DoctorFacts,
} from "../types.js";
import {
  DENIAL_PROVES_TASK_EXISTS,
  extractExecutablePath,
  parsePinnedFilePath,
  queryScheduledTask,
  regQuery,
  type RegistryValue,
} from "./windows.js";

/**
 * Does the thing that is supposed to start us at boot point at something that
 * still exists?
 *
 * ── THE DEFECT THIS EXISTS FOR (PLAN-av-hardening §2 W7) ─────────────────────
 * The Windows "AI Commander Relaunch" task bakes the install directory into its
 * arguments as a string literal, once, at registration time, and nothing ever
 * re-verifies it. Only the NSIS installer re-registers it. A recovery that did
 * NOT run the installer — extracting `app-64.7z` by hand, which is exactly what
 * the 2026-09-02 recovery required — leaves the task, and the `HKCU\…\Run`
 * value, pointing at an executable that no longer exists. The app then silently
 * never starts at boot, and the watchdog, which derives its idea of where the
 * app lives from that same task action, measures the OLD directory forever: it
 * reports `tray-exe-missing` permanently and does not recognise a perfectly
 * healthy tray running from the new one. Three symptoms, one stale string.
 *
 * ── DETECT AND REPORT. NEVER REPAIR. ─────────────────────────────────────────
 * The obvious fix — have something resolve the executable at run time and
 * re-point the task — is a privilege-escalation footgun. The Relaunch task is
 * admin-owned and its SDDL grants non-admins no access; re-pointing it at a
 * location discovered from a running process or from the per-user `Run` key
 * converts a SYSTEM-triggered task into a user-chosen one. So this check names
 * the mismatch and the remedy is "run the installer again", which re-registers
 * both task and helper from its own elevated context.
 */

/** Registered by desktop/build/win-update-task.ps1; see win-watchdog.ts RELAUNCH_TASK_NAME. */
const RELAUNCH_TASK_NAME = "AI Commander Relaunch";
/** Registered by the same script; the silent-update task. */
const UPDATE_TASK_NAME = "AI Commander Update";

/**
 * WHERE THE ACL RULE WENT, because it used to live here and its absence is the
 * kind of thing a reader will otherwise re-derive wrongly.
 *
 * Task Scheduler enforces a per-task ACL, and the installer gives the two tasks
 * deliberately different ones (desktop/build/win-update-task.ps1):
 *
 *   Update   `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)` — Users may read;
 *   Relaunch `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)`               — Users may not.
 *
 * This check therefore used to weaken its verdict for the Relaunch task by name:
 * a standard-user tray is told the task does not exist whether or not it does, so
 * an absence could not be reported as a failure. That reasoning was a WORKAROUND
 * for a query that could not tell a refusal from an absence — mirroring an SDDL
 * from another package in the hope it stayed in step. It no longer has to:
 * queryScheduledTask asks the Task Scheduler COM API for the HRESULT and returns
 * a refusal as `queried: false, cause: "denied"`, which never reaches the
 * `registered` branch at all. What arrives there now is a positive absence
 * (0x80070002), for either task, from any account — so the two are handled the
 * same and no SDDL is mirrored here any more.
 */
const RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
/** The unit ctl/commands/install.ts writes. */
const SYSTEMD_UNIT = "/etc/systemd/system/aicommander-agent.service";
/** desktop/src/autolaunch.ts MAC_AGENT_LABEL — the LaunchAgent SMAppService registers. */
const MAC_AGENT_LABEL = "dev.aicommander.tray";

/**
 * Present on disk? Asynchronous, like every filesystem call in this directory:
 * the tray runs these checks on Electron's main loop and a synchronous stat on a
 * path a scanner is holding blocks the relay heartbeat.
 */
async function exists(target: string): Promise<boolean> {
  try {
    await fs.promises.stat(target);
    return true;
  } catch {
    return false;
  }
}

/**
 * Is this a PACKAGED desktop install, as opposed to the headless npm agent?
 *
 * It decides whether an absent scheduled task is normal or broken, and those are
 * opposite verdicts. The desktop tray passes Electron's `resourcesPath` (and
 * Electron sets it on `process` regardless); a plain Node process has neither,
 * which is exactly the npm agent that legitimately registers no tasks.
 */
function isPackagedInstall(ctx: DoctorContext): boolean {
  return Boolean(
    ctx.resourcesPath ?? (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath,
  );
}

const STALE_REMEDY =
  "The recorded path no longer exists, so nothing starts at boot. Re-run the installer — it re-registers the " +
  "autostart entry (and the privileged helper) from its own elevated context. Do not edit the entry by hand.";

/**
 * Windows: the per-user `Run` value and the two admin-owned scheduled tasks.
 *
 * The `Run` value is found by CONTENT rather than by name. Electron derives the
 * value name from the app user model id (`electron.app.<app name>`), which is
 * spelled from a different source than the install directory is — there is no
 * single constant that is right for both, and win-watchdog-probe.ts records two
 * silent failures caused by mirroring the wrong one. Matching on the data, which
 * is a path into an "AI Commander" directory, cannot make that mistake.
 */
/** The Run values that are OURS, matched on content — see the header above. */
function oursIn(values: RegistryValue[]): RegistryValue[] {
  return values.filter((v) => /AI ?Commander/i.test(v.data) || /AI ?Commander/i.test(v.name));
}

async function windowsPersistence(ctx: DoctorContext): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const packaged = isPackagedInstall(ctx);

  const query = await regQuery(RUN_KEY);
  if (!query.queried) {
    // `reg.exe` never answered. That is a statement about the diagnostic, not
    // about the registry — the same distinction the scheduled-task path draws
    // with its QUERIED sentinel, and the one this path used to lose.
    results.push(
      skipped(
        "persistence.run_key",
        "Autostart (Run key)",
        `whether an AI Commander value exists under HKCU\\…\\CurrentVersion\\Run could not be determined: ` +
          `${query.reason}.`,
      ),
    );
  } else if (oursIn(query.values).length === 0) {
    results.push(
      skipped(
        "persistence.run_key",
        "Autostart (Run key)",
        "no AI Commander value under HKCU\\…\\CurrentVersion\\Run. Normal for the headless agent, and for a " +
          'desktop install whose user turned "Start at login" off.',
      ),
    );
  } else {
    const ours = oursIn(query.values);
    for (const [index, value] of ours.entries()) {
      // One id per RESULT, not per check kind. The leftover this check exists to
      // find is a SECOND matching value pointing at an old directory, and two
      // results sharing `persistence.run_key` would be silently deduplicated by
      // any consumer keyed on the id — losing exactly the one that is stale.
      const id = ours.length === 1 ? "persistence.run_key" : `persistence.run_key_${index + 1}`;
      const target = extractExecutablePath(value.data);
      // The value's DATA is a command line, and command lines never enter a
      // fact (types.ts): the path we extracted from it is the diagnostic, and
      // the arguments beside it are not ours to forward to a vendor.
      const facts: DoctorFacts = { name: value.name, target: pathFact(target) };
      if (!target) {
        results.push(
          warn(id, "Autostart (Run key)", `the Run value ${value.name} holds no usable path.`, STALE_REMEDY, facts),
        );
      } else if (await exists(target)) {
        results.push(ok(id, "Autostart (Run key)", `the Run value points at ${target}, which exists.`, facts));
      } else {
        results.push(
          fail(
            id,
            "Autostart (Run key)",
            `the Run value points at ${target}, which does NOT exist — this machine will not start the app at login.`,
            STALE_REMEDY,
            facts,
          ),
        );
      }
    }
  }

  for (const [taskName, id, title] of [
    [RELAUNCH_TASK_NAME, "persistence.relaunch_task", "Relaunch task"],
    [UPDATE_TASK_NAME, "persistence.update_task", "Update task"],
  ] as const) {
    const task = await queryScheduledTask(taskName);
    const baseFacts: DoctorFacts = { task: taskName, packagedInstall: packaged };
    if (!task.queried) {
      // TWO VERDICTS, BECAUSE THERE ARE TWO SITUATIONS, and this is the check
      // that would otherwise have regressed. The Relaunch task's SDDL grants no
      // Users read, so on every unelevated packaged install this is now the
      // branch that fires — and reporting all of it `skipped` would quietly drop
      // what the doctor previously warned about.
      //
      //  - `denied` — Task Scheduler refused, which it only does for a task that
      //    EXISTS. That is a positive fact and a real shortfall of the report:
      //    the task is there but its action could not be read, so the path it
      //    starts was NOT verified. A warn, with the elevation that would answer
      //    it as the remedy — but only on a PACKAGED install, see below.
      //  - anything else, `contradiction` included — the query never ran, never
      //    returned, broke, or disagreed with itself. Whatever was learned, it is
      //    not a fact about this install's autostart; `task.reason` says which,
      //    and the verdict is a statement about the diagnostic, so `skipped`.
      if (task.cause === "denied") {
        // THE PACKAGED GATE COMES FIRST, ahead of any verdict that presumes we
        // own the task. A headless npm agent on a machine that ALSO has the
        // desktop install is refused the read for two tasks it never registers,
        // and warning there that "the path it starts at boot was not verified"
        // reports a shortfall in someone else's install as a fault in this one.
        // The absence branch below has always had this gate; the refusal branch
        // returned above it and lost it.
        results.push(
          packaged
            ? warn(
                id,
                title,
                // ONE SENTENCE, SHARED WITH THE HELPER CHECK. Both checks report
                // this same marker, and for one release they described it in
                // opposite words — this one "IS registered", priv-helper.ts
                // "could not be determined". The clause now comes from the module
                // that measures it (windows-scheduled-task.ts), so neither can
                // reword it alone.
                `the scheduled task "${taskName}" IS registered — ${DENIAL_PROVES_TASK_EXISTS} — but its ` +
                  "action could not be read, so " +
                  `the path it ${taskName === UPDATE_TASK_NAME ? "installs updates from" : "starts at boot"} was ` +
                  "not verified.",
                // THE TWO TASKS HAVE DIFFERENT ACLs, so they cannot share this
                // sentence (desktop/build/win-update-task.ps1):
                //   Update   …(A;;GRGX;;;BU) — Users may read and execute it, so a
                //            refusal is NOT expected and means the ACL is no longer
                //            what the installer set.
                //   Relaunch no Users grant at all — SYSTEM and Administrators
                //            only, so a refusal for a standard user is by design.
                // This describes what the INSTALLER sets, never what a given
                // machine's ACL must currently be: installs that predate the
                // Relaunch tightening are still out there reading fine.
                taskName === UPDATE_TASK_NAME
                  ? "Re-run this command from an elevated prompt to check the path the task actually starts. A " +
                    "refusal is unexpected here — the installer grants Users read and execute on the Update task, " +
                    "so its ACL no longer matches what was shipped."
                  : "Re-run this command from an elevated prompt to check the path the task actually starts. The " +
                    "installer grants the Relaunch task to SYSTEM and Administrators only, so a refusal for a " +
                    "standard user is by design.",
                baseFacts,
              )
            : skipped(
                id,
                title,
                `the scheduled task "${taskName}" exists on this machine but this account may not read it. ` +
                  "Normal for the headless agent, which registers no scheduled tasks — this one belongs to a " +
                  "desktop install, not to this one.",
                baseFacts,
              ),
        );
        continue;
      }
      results.push(
        skipped(
          id,
          title,
          `whether the scheduled task "${taskName}" is registered could not be determined: ${task.reason}.`,
          baseFacts,
        ),
      );
      continue;
    }
    if (!task.registered) {
      // On the headless agent these tasks are not supposed to exist. On a
      // PACKAGED install the installer registers both, and their absence is the
      // W7 state itself: nothing starts the app at boot and nothing updates it —
      // silently. Calling that "normal" is how the tray hid it.
      if (!packaged) {
        results.push(
          skipped(
            id,
            title,
            `the scheduled task "${taskName}" is not registered. Normal for the headless agent, which ` +
              "registers no scheduled tasks.",
            baseFacts,
          ),
        );
        continue;
      }
      const consequence = taskName === UPDATE_TASK_NAME ? "installs updates" : "starts the app at boot";
      // NO ACL ESCAPE HATCH LEFT HERE, and removing it is the point rather than a
      // tidy-up. It hedged this verdict for the Relaunch task because a refusal
      // used to arrive looking exactly like an absence; a refusal now returns on
      // the `queried: false` branch above and never reaches this line, so what is
      // left is Windows (or the COM API, HRESULT 0x80070002) positively saying the
      // task is not there. Hedging THAT is how the W7 state stayed hidden.
      results.push(
        fail(
          id,
          title,
          `the scheduled task "${taskName}" is not registered on a packaged install, so nothing ${consequence}.`,
          STALE_REMEDY,
          { ...baseFacts, elevated: task.elevated },
        ),
      );
      continue;
    }
    const pinned = task.args ? parsePinnedFilePath(task.args) : null;
    // `task.args` is the action's whole command line and stays out of the facts.
    const facts: DoctorFacts = { ...baseFacts, state: task.state, execute: pathFact(task.execute), pinnedPath: pathFact(pinned) };
    if (!pinned) {
      results.push(
        warn(
          id,
          title,
          `"${taskName}" is registered (state ${task.state ?? "unknown"}), but its action is not one of the ` +
            "shapes this check knows how to read, so the path it starts was NOT verified.",
          "Nothing here says the task is broken — only that it no longer looks like what the installer " +
            "registers. Re-run the installer if the app does not start at boot.",
          facts,
        ),
      );
      continue;
    }
    results.push(
      (await exists(pinned))
        ? ok(id, title, `"${taskName}" is registered and pinned to ${pinned}, which exists.`, facts)
        : fail(
            id,
            title,
            `"${taskName}" is pinned to ${pinned}, which does NOT exist. Nothing starts at boot, and the ` +
              "watchdog measures that same stale directory — so a healthy app running from elsewhere is not " +
              "recognised as ours.",
            STALE_REMEDY,
            facts,
          ),
    );
  }

  return results;
}

/**
 * Linux: the systemd unit ctl/commands/install.ts writes. `ExecStart` is
 * double-quoted by the installer, so the two paths (the Node binary and the
 * agent's own script) come out of the quotes directly.
 */
async function linuxPersistence(): Promise<CheckResult[]> {
  const id = "persistence.systemd";
  const title = "systemd unit";
  let unit: string;
  try {
    unit = await fs.promises.readFile(SYSTEMD_UNIT, "utf8");
  } catch (err) {
    return [
      skipped(
        id,
        title,
        `no systemd unit at ${SYSTEMD_UNIT} (${errorText(err)}). Normal when the agent was not installed as a service.`,
      ),
    ];
  }
  const execStart = /^ExecStart=(.*)$/m.exec(unit)?.[1]?.trim() ?? "";
  const quoted = [...execStart.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]!.replace(/\\(.)/g, "$1"));
  const targets = quoted.length > 0 ? quoted : execStart.split(/\s+/).filter((t) => t.startsWith("/"));
  const missing: string[] = [];
  for (const target of targets) {
    if (!(await exists(target))) missing.push(target);
  }
  // The PATHS, never the `ExecStart=` line they came from: that line is a
  // command line with its arguments, and the bundle this ends up in promises an
  // antivirus vendor it carries no command text (types.ts, report.ts).
  const facts: DoctorFacts = { unit: SYSTEMD_UNIT, targets: targets.join(" ") };

  if (targets.length === 0) {
    return [warn(id, title, `the unit at ${SYSTEMD_UNIT} has no usable ExecStart.`, "Re-run `aicommander-agent install`.", facts)];
  }
  return [
    missing.length === 0
      ? ok(id, title, `the unit's ExecStart points at ${targets.length} path(s), all of which exist.`, facts)
      : fail(
          id,
          title,
          `the unit's ExecStart points at ${missing.join(", ")}, which do(es) NOT exist — the service cannot start.`,
          "Re-run `aicommander-agent install` to rewrite the unit against the current paths.",
          { ...facts, missing: missing.join(", ") },
        ),
  ];
}

/**
 * macOS: the LaunchAgent SMAppService registers on the app's behalf. Its
 * registration lives in a per-user launchd database, not in a file we can stat,
 * so the only honest way to ask is launchd itself. A `launchctl print` that
 * answers nothing means "no such service for this user", which for the headless
 * agent is simply the truth and not a fault.
 */
async function macPersistence(): Promise<CheckResult[]> {
  const id = "persistence.launch_agent";
  const title = "Login item (LaunchAgent)";
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid === null) return [skipped(id, title, "the user id is not available, so launchd cannot be asked about this user's agents.")];

  const captured = await runCaptured("/bin/launchctl", ["print", `gui/${uid}/${MAC_AGENT_LABEL}`]);
  if (captured.kind === "unavailable") {
    // launchd was never asked. Reporting that as "no LaunchAgent is registered"
    // is the rounding capture.ts exists to stop.
    return [
      skipped(
        id,
        title,
        `whether a "${MAC_AGENT_LABEL}" LaunchAgent is registered for this user could not be determined: ` +
          `${captured.reason}.`,
        { label: MAC_AGENT_LABEL },
      ),
    ];
  }
  const out = captured.stdout;
  if (captured.kind === "failed" || out.trim() === "") {
    // launchd ANSWERED, and its answer is that it has no such service for this
    // user — `launchctl print` exits non-zero for a label it does not hold.
    return [
      skipped(
        id,
        title,
        `no "${MAC_AGENT_LABEL}" LaunchAgent is registered for this user. Normal for the headless agent, and ` +
          'for a desktop install whose user turned "Start at login" off.',
        { label: MAC_AGENT_LABEL },
      ),
    ];
  }
  // `path = /Applications/AI Commander.app/Contents/Library/LaunchAgents/…plist`
  //
  // …except when it is not a path at all. An agent registered through
  // SMAppService — which is how the tray registers, see desktop/src/autolaunch.ts
  // — prints `path = (submitted by smd.NNN)`, because its definition lives in
  // launchd's own database rather than in a file. Treating that as a filename
  // and reporting it missing is a check that fails on every healthy Mac, which
  // is worse than not having the check. Only absolute paths are compared.
  const asPath = (raw: string | undefined): string | null => {
    const value = raw?.trim();
    return value && value.startsWith("/") ? value : null;
  };
  const plist = asPath(/^\s*path\s*=\s*(.+)$/m.exec(out)?.[1]);
  const program = asPath(/^\s*program\s*=\s*(.+)$/m.exec(out)?.[1]);
  const facts: DoctorFacts = { label: MAC_AGENT_LABEL, plist: pathFact(plist), program: pathFact(program) };
  const missing: string[] = [];
  for (const target of [plist, program]) {
    if (typeof target === "string" && !(await exists(target))) missing.push(target);
  }
  return [
    missing.length === 0
      ? ok(
          id,
          title,
          `the "${MAC_AGENT_LABEL}" LaunchAgent is registered${plist || program ? " and the files it names exist" : " (launchd holds its definition; there is no file to check)"}.`,
          facts,
        )
      : fail(
          id,
          title,
          `the "${MAC_AGENT_LABEL}" LaunchAgent is registered but ${missing.join(", ")} does not exist.`,
          "Re-install the app (or drag it back to /Applications) — the registration points at a bundle that has moved or gone.",
          { ...facts, missing: missing.join(", ") },
        ),
  ];
}

export const persistenceChecks: DoctorCheckGroup = {
  id: "persistence",
  title: "Autostart",
  async run(ctx) {
    switch (process.platform) {
      case "win32":
        return windowsPersistence(ctx);
      case "darwin":
        return macPersistence();
      case "linux":
        return linuxPersistence();
      default:
        return [
          skipped(
            "persistence",
            "Autostart",
            `no autostart mechanism is known for ${process.platform} (${os.type()}).`,
          ),
        ];
    }
  },
};
