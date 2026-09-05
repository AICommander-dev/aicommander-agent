import fs from "node:fs";
import { execFileSync } from "node:child_process";
import chalk from "chalk";
import { maskSessionCode, DEFAULT_SERVER, SECURE_EXEC_USER } from "@aicommander/protocol";
import {
  daemonReload,
  systemctlEnable,
  systemctlRestart,
  systemctlStop,
  systemctlKill,
  systemctlStart,
  systemctlActiveState,
  systemdManagerAvailable,
} from "../systemctl.js";
import { ui, requireRoot } from "../ui.js";
import { readState } from "../../state.js";

const SERVICE_FILE = "/etc/systemd/system/aicommander-agent.service";
const DEVICE_DIR = "/etc/aicommander-agent";

/**
 * Validate the relay URL before baking it into the systemd unit. This value is
 * interpolated raw into `Environment=AICOMMANDER_SERVER=…`, so a newline or
 * control char could inject extra unit directives, and a non-http(s) scheme
 * would silently produce a broken service. Reject anything that isn't a clean
 * http:/https: URL. (web/install hardcodes a default and never takes arbitrary
 * input here, so the npm path is intentionally stricter.)
 */
function validateServerUrl(raw: string): string {
  // Reject any control character (newline, CR, tab, NUL, …) outright — these
  // can't legitimately appear in a URL and are the unit-injection vector.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(raw)) {
    ui.error(`Invalid --server URL: contains control characters: ${JSON.stringify(raw)}`);
    process.exit(1);
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    ui.error(`Invalid --server URL: not a valid URL: ${JSON.stringify(raw)}`);
    process.exit(1);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    ui.error(`Invalid --server URL: protocol must be http: or https: (got ${url.protocol})`);
    process.exit(1);
  }
  // systemd treats `%` as a specifier-escape introducer inside unit values
  // (e.g. Environment=). A literal `%` in the URL (e.g. a percent-encoded path)
  // would be mis-expanded; escape it as `%%` so the value is passed through
  // verbatim. See systemd.unit(5) "Specifiers".
  return raw.replace(/%/g, "%%");
}

/**
 * Quote a path for a systemd ExecStart argument. systemd supports double-quoted
 * arguments with C-style escaping; we escape backslash and double-quote so paths
 * containing spaces (or those chars) survive intact. We also double any `%`,
 * which systemd treats as a specifier-escape introducer (systemd.unit(5)
 * "Specifiers") — an unescaped `%` in a path would be mis-expanded.
 * See: systemd.service(5) "Command lines".
 */
function systemdQuote(p: string): string {
  return `"${p
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/%/g, "%%")}"`;
}

/**
 * Create the dedicated non-root account that `secure exec` (service-token) drops
 * to before running a command. Idempotent: a no-op if the user already exists.
 * A system user with no login shell and its own home (so an operator can
 * provision per-tool config like ~/.claude under it). Non-fatal — secure exec is
 * opt-in, so a failure here must not abort the base install; the secure path just
 * fails closed at call time until the user exists.
 */
function ensureSecureExecUser(): void {
  ui.step(`Ensuring sandbox user "${SECURE_EXEC_USER}"…`);
  try {
    execFileSync("getent", ["passwd", SECURE_EXEC_USER], { stdio: "ignore" });
    ui.ok(`Sandbox user "${SECURE_EXEC_USER}" already exists.`);
    ui.warn(
      `Existing "${SECURE_EXEC_USER}" permissions and groups were preserved; ` +
      "secure exec will refuse to run if its runtime group check is unsafe or inconclusive.",
    );
    return;
  } catch {
    /* not present — create below */
  }
  const nologin = ["/usr/sbin/nologin", "/sbin/nologin", "/bin/false"].find((p) =>
    fs.existsSync(p),
  ) ?? "/bin/false";
  try {
    execFileSync(
      "useradd",
      // No --groups/-G: a newly-created sandbox user gets no supplementary
      // memberships. Runtime independently enforces that invariant on every run.
      ["--system", "--create-home", "--shell", nologin, SECURE_EXEC_USER],
      { stdio: "ignore" },
    );
    // Lock the new home to 0700. useradd creates it 0755 by default, which would
    // let any local unprivileged user plant config (e.g. ~/.claude, a shell rc)
    // that a sandboxed secure-exec command — which runs AS this user — later
    // reads/executes. 0700 keeps the sandbox account's home owner-only.
    try {
      const home = execFileSync("getent", ["passwd", SECURE_EXEC_USER])
        .toString()
        .trim()
        .split(":")[5];
      if (home && fs.existsSync(home)) fs.chmodSync(home, 0o700);
    } catch {
      /* best-effort hardening — non-fatal if the home can't be resolved/chmod'd */
    }
    ui.ok(`Sandbox user "${SECURE_EXEC_USER}" created.`);
  } catch {
    ui.warn(
      `Could not create sandbox user "${SECURE_EXEC_USER}" — secure exec will be unavailable until it exists.`,
    );
  }
}

/**
 * Install the agent as a systemd service (Linux, root). Mirrors web/install — the
 * shell installer served from the relay — but installs the LOCALLY running CLI as
 * the service binary instead of downloading the signed standalone binary.
 */
export async function cmdInstall(opts: { server?: string }): Promise<void> {
  requireRoot();

  if (process.platform !== "linux") {
    ui.error(`The systemd service installer supports Linux only. Detected: ${process.platform}`);
    ui.blank();
    ui.step("For an ephemeral foreground run on this platform, use:");
    ui.step("  npx @aicommander/agent          (or: aicommander-agent run)");
    ui.step("For the signed Linux root-install flow (verify before sudo), see:");
    ui.step("  https://aicommander.dev/howto/#install-agent");
    process.exit(1);
  }

  // A systemctl binary can exist in a minimal container or on a distribution
  // whose PID 1 is not systemd. Verify the live manager bus before mkdir,
  // useradd, or writing the unit so a failed install leaves no partial state.
  if (!systemdManagerAvailable()) {
    ui.error("A running systemd manager is required, but none is reachable. No service was installed.");
    ui.blank();
    ui.step("Temporary foreground run: aicommander-agent run");
    ui.step("It runs only until that process or terminal closes.");
    ui.step(
      "For persistent startup and restarts, configure this command with your native init/process manager or platform autostart (for example OpenRC, supervisord, s6, runit, or a container restart policy).",
    );
    ui.step(
      "If this host provides no init/process manager or autostart facility, a persistent installation that returns after reboot is not possible.",
    );
    process.exit(1);
  }

  // Sanitize the relay URL before it is baked into the unit's Environment= line.
  const server = validateServerUrl(
    opts.server ?? process.env["AICOMMANDER_SERVER"] ?? DEFAULT_SERVER,
  );

  // Resolve the absolute path of the running CLI script so systemd doesn't depend
  // on PATH. We exec it via the same node binary that is running now. Both paths
  // are double-quoted (systemd ExecStart quoting) so a path containing spaces
  // survives intact.
  const script = fs.realpathSync(process.argv[1]!);
  const execStart = `${systemdQuote(process.execPath)} ${systemdQuote(script)} run`;

  ui.header("AI Commander Agent — systemd install");
  ui.info("Server", server);
  ui.info("ExecStart", execStart);
  ui.blank();

  // ── Device identity dir ────────────────────────────────────────────────────
  // The agent persists a stable device identity under /etc/aicommander-agent
  // (survives reboots, unlike /var/run). Pre-create it as root with tight perms.
  ui.step("Creating device identity dir…");
  fs.mkdirSync(DEVICE_DIR, { recursive: true });
  fs.chmodSync(DEVICE_DIR, 0o700);
  ui.ok(`Device identity dir ready (${DEVICE_DIR}).`);

  // ── Sandbox user for secure exec ───────────────────────────────────────────
  ensureSecureExecUser();

  // ── systemd unit ───────────────────────────────────────────────────────────
  // SOURCE OF TRUTH: web/install (the shell installer served from the relay). The
  // unit text below intentionally mirrors that file's [Service]/[Install] block;
  // the two MUST be kept in sync when either changes.
  ui.step(`Writing systemd service to ${SERVICE_FILE}…`);
  const unit = `[Unit]
Description=AI Commander Remote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
RuntimeDirectory=aicommander-agent
# 0700: the runtime dir holds state.json with the live session code (a root-exec
# credential); owner-only blocks local unprivileged users from reading it.
RuntimeDirectoryMode=0700
Environment=AICOMMANDER_SERVER=${server}
Environment=AICOMMANDER_SERVICE=1
Environment=NODE_ENV=production
ExecStart=${execStart}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aicommander-agent
TimeoutStopSec=30
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
`;
  fs.writeFileSync(SERVICE_FILE, unit, { mode: 0o644 });
  ui.ok("Service file written.");

  // ── Enable on boot, then restart to load the (possibly new) binary ─────────
  // Use restart, NOT start: on a fresh install it behaves like start; on an
  // UPDATE it forces systemd to stop the old process and exec the new one. Plain
  // start is a no-op while the unit is already active, leaving the OLD agent
  // running (and blocking the command channel).
  ui.step("Reloading systemd…");
  try {
    daemonReload();
  } catch {
    ui.error("daemon-reload failed. Inspect: journalctl -u aicommander-agent -n 50");
    process.exit(1);
  }

  ui.step("Enabling service on boot…");
  try {
    systemctlEnable();
  } catch {
    ui.warn("Could not enable the service on boot (non-critical).");
  }

  // Restart (NOT start) so an UPDATE replaces the old running process. On a
  // graceful-restart failure, mirror web/install step 7: stop → SIGKILL → start
  // to force a hung old process out of the way before bringing the new one up.
  ui.step("Restarting service…");
  try {
    systemctlRestart();
  } catch {
    ui.warn("Graceful restart failed — forcing stop then start…");
    try { systemctlStop(); } catch { /* already stopped */ }
    try { systemctlKill(); } catch { /* nothing to kill */ }
    try {
      systemctlStart();
    } catch {
      ui.error("Could not start aicommander-agent. Inspect: journalctl -u aicommander-agent -n 50");
      process.exit(1);
    }
  }

  // Never claim success on a dead/hung unit — verify it is actually active.
  if (systemctlActiveState() !== "active") {
    ui.error("Service is not active after restart. Inspect: journalctl -u aicommander-agent -n 50");
    process.exit(1);
  }
  ui.ok("Service started.");
  ui.blank();

  // ── Wait for the session code (max ~15s, polling every 500ms) ──────────────
  ui.step("Waiting for session code…");
  let sessionCode: string | null = null;
  for (let i = 0; i < 30; i++) {
    const state = await readState();
    if (state?.sessionCode) {
      sessionCode = state.sessionCode;
      break;
    }
    await new Promise((r) => setTimeout(r, 500));
  }

  ui.blank();
  if (sessionCode) {
    // Mask the code on screen — it is a root-exec credential and must not sit in
    // scrollback / screenshots. Reveal the full value on demand.
    ui.ok(chalk.bold("AI Commander ready!"));
    ui.blank();
    ui.info("Session code", chalk.bold.greenBright(maskSessionCode(sessionCode)));
    ui.blank();
    ui.step("Reveal full code:   sudo aicommander-agent status --reveal");
    ui.step("Then use in Claude: 'execute df -h on <code>'");
    ui.step("Service logs:       journalctl -u aicommander-agent -f");
    ui.step("Manage:             sudo aicommander-agent status");
    ui.step("Uninstall:          sudo aicommander-agent uninstall --force");
    ui.blank();
    ui.warn(
      "Keep this code secret. Anyone who has it can run commands as root on this machine.",
    );
  } else {
    ui.warn("The session code did not appear within 15 seconds.");
    ui.step("The service is running — the code should appear shortly.");
    ui.step("Status:  sudo aicommander-agent status");
    ui.step("Logs:    journalctl -u aicommander-agent -f");
  }
  ui.blank();
}
