#!/usr/bin/env node
// Entrypoint for the per-machine privileged helper. Runs as a long-lived root
// (macOS LaunchDaemon) / LocalSystem (Windows Service) process: it listens on the
// fixed local IPC endpoint and serves relay-signed elevated commands handed to it
// by the per-user tray. On the IPC surface it never initiates anything and never
// trusts the channel — authorization is the relay signature, verified per command.
// Its one self-initiated job is the Windows crash watchdog (src/win-watchdog.ts),
// which observes the machine and can only start one fixed, admin-owned task; it
// exchanges no messages with anybody.

import { createTransportServer } from "../src/transport.js";
import { createPrivilegedExecutor } from "../src/executor.js";
import { startHelper } from "../src/helper.js";
import {
  parsePrivHelperCliArgs,
  PRIV_HELPER_USAGE,
} from "../src/cli.js";
import { startWindowsWatchdog, type RunningWatchdog } from "../src/win-watchdog.js";
import { probeWindows, triggerRelaunchTask } from "../src/win-watchdog-probe.js";
import { createWatchdogLogFile } from "../src/win-watchdog-logfile.js";
import { HELPER_VERSION } from "../src/version.js";
import {
  helperDoctorExitCode,
  renderHelperDoctor,
  runHelperDoctor,
} from "../src/doctor.js";
import type { ElevatedEndpoint } from "../src/endpoint.js";

/**
 * Build an ElevatedEndpoint from the AIC_HELPER_ENDPOINT override string:
 *  - `tcp:HOST:PORT` → loopback/host TCP endpoint,
 *  - anything else → a unix socket path.
 */
function endpointFromOverride(raw: string): ElevatedEndpoint {
  const m = /^tcp:(.+):(\d+)$/.exec(raw);
  if (m) return { transport: "tcp", host: m[1]!, port: Number(m[2]) };
  return { transport: "unix", path: raw };
}

/** Wait for one Enter. Only ever called on an interactive console (see below). */
function waitForEnter(): Promise<void> {
  return new Promise((resolve) => {
    process.stdout.write("  Press Enter to close…\n");
    process.stdin.once("data", () => {
      process.stdin.pause();
      resolve();
    });
    process.stdin.resume();
  });
}

async function main(): Promise<void> {
  // Parse before reading the endpoint or constructing any privileged component.
  // In particular, `--version` must never behave like a second daemon: on macOS
  // an old duplicate startup could replace the pathname of the live unix socket.
  const cliMode = parsePrivHelperCliArgs(process.argv.slice(2));
  if (cliMode === "version") {
    process.stdout.write(`${HELPER_VERSION}\n`);
    return;
  }
  // `doctor` — the diagnostic that still runs when $INSTDIR has been emptied
  // (PLAN-av-hardening W2.3). Same rule as `--version`, and for the same reason:
  // it runs its checks, prints, and RETURNS. It never constructs a transport, an
  // executor or a watchdog, so a diagnostic invocation cannot become a second
  // daemon — on macOS an accidental second startup would replace the pathname of
  // the live unix socket. See src/doctor.ts for what it can and cannot check.
  if (cliMode === "doctor") {
    // AIC_HELPER_ENDPOINT is honoured here for the same reason the daemon below
    // honours it: it names the endpoint THIS helper uses, and a diagnostic that
    // ignored it would interrogate the machine's real helper while the operator
    // is asking about the one they just started on a temp socket. It is an
    // ops/smoke override only — the installed service never sets it.
    const doctorOverride = process.env["AIC_HELPER_ENDPOINT"];
    const checks = await runHelperDoctor(
      doctorOverride ? { endpoints: [endpointFromOverride(doctorOverride)] } : {},
    );
    process.stdout.write(renderHelperDoctor(checks));
    process.exitCode = helperDoctorExitCode(checks);
    // Launched from the Start Menu shortcut the installer creates, this is a
    // console window that closes the instant we return — taking the answer with
    // it. Hold it open only when somebody is actually looking (a TTY); a piped
    // or redirected run must never block.
    if (process.stdin.isTTY && process.stdout.isTTY) await waitForEnter();
    return;
  }
  if (cliMode === "invalid") {
    process.stderr.write(`priv-helper: invalid arguments\n${PRIV_HELPER_USAGE}\n`);
    process.exitCode = 2;
    return;
  }

  // AIC_HELPER_ENDPOINT overrides the fixed endpoint. Reserved for ops/smoke
  // tests (e.g. verifying a freshly built SEA binary against a temp unix socket,
  // or `tcp:127.0.0.1:PORT`); the installed daemon/service never sets it and uses
  // the fixed root-owned endpoint from elevatedEndpoint().
  const endpointOverride = process.env["AIC_HELPER_ENDPOINT"];
  const helper = await startHelper({
    transport: endpointOverride
      ? createTransportServer(endpointFromOverride(endpointOverride))
      : createTransportServer(),
    executor: createPrivilegedExecutor(),
  });

  process.stdout.write(
    `aicommander-priv-helper ${HELPER_VERSION} listening (boot ${helper.bootId})\n`,
  );

  // Windows crash watchdog (win-watchdog.ts). Windows-only on purpose: Linux has
  // systemd Restart=always, and macOS has its own answer in the desktop package
  // (a LaunchAgent with KeepAlive/SuccessfulExit=false), reviewed separately.
  // It rides along in THIS process because Task Scheduler already keeps the helper
  // alive (AtStartup, RestartCount 3, no time limit) — so the supervisor is itself
  // supervised. It observes and triggers a fixed task; it adds no IPC surface.
  let watchdog: RunningWatchdog | null = null;
  if (process.platform === "win32") {
    // The log goes to a FILE (%ProgramData%\AICommander\watchdog.log), not to
    // stdout: this process is hosted by a scheduled task with no redirection, so
    // everything written to stdout is discarded — which made every diagnostic
    // the watchdog's design depends on unobservable on a real machine. stdout is
    // still written for the benefit of anyone running the helper by hand.
    const toFile = createWatchdogLogFile();
    watchdog = startWindowsWatchdog({
      probe: probeWindows,
      trigger: triggerRelaunchTask,
      log: (line) => {
        toFile(line);
        process.stdout.write(`${line}\n`);
      },
    });
  }

  let stopping = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (stopping) return;
    stopping = true;
    process.stdout.write(`priv-helper: received ${signal}, shutting down\n`);
    watchdog?.stop();
    helper
      .stop()
      .then(() => process.exit(0))
      .catch(() => process.exit(1));
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((err) => {
  process.stderr.write(
    `priv-helper: fatal: ${err instanceof Error ? err.message : String(err)}\n`,
  );
  process.exit(1);
});
