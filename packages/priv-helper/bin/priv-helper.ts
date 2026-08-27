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

async function main(): Promise<void> {
  // Parse before reading the endpoint or constructing any privileged component.
  // In particular, `--version` must never behave like a second daemon: on macOS
  // an old duplicate startup could replace the pathname of the live unix socket.
  const cliMode = parsePrivHelperCliArgs(process.argv.slice(2));
  if (cliMode === "version") {
    process.stdout.write(`${HELPER_VERSION}\n`);
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
