import chalk from "chalk";
import { maskSessionCode } from "@aicommander/protocol";

/**
 * Render the session code on screen for the running agent.
 *
 * `reveal` controls whether the FULL code or only the masked form is shown.
 * Callers MUST gate it on a real interactive terminal (`process.stdout.isTTY`):
 *  - FOREGROUND interactive runs (`npx`, `aicommander-agent run` in a terminal)
 *    have a TTY and pass reveal=true. The user launched it in their own terminal
 *    to obtain the code there, so showing the masked form would make the
 *    foreground flow unusable.
 *  - The masked form (reveal=false) is used in every non-TTY context. Crucially
 *    this includes the systemd SERVICE path: `run` is supervised there and its
 *    stdout is inherited into journald (StandardOutput=journal), so revealing
 *    would persist the root-exec credential in the journal (readable by root and
 *    by systemd-journal/adm-group users) and leak it into exported logs /
 *    screen-shares — exactly what masking exists to prevent. `status --reveal`
 *    (root-gated) remains the way to query the full code on a service host.
 *
 * The "keep secret" warning is shown in BOTH modes.
 */
export function showCode(sessionCode: string, serverUrl: string, reveal = false): void {
  console.clear();
  console.log();
  console.log(chalk.bold.cyan("  AI Commander — Remote Agent"));
  console.log();
  console.log(chalk.gray("  Session code:"));
  console.log();
  // Foreground runs reveal the full code (the user ran this themselves to get
  // it); otherwise mask it — it is a root-exec credential that must not sit in
  // logs / on screen in a service context.
  console.log(chalk.bold.greenBright(`    ${reveal ? sessionCode : maskSessionCode(sessionCode)}`));
  console.log();
  if (!reveal) {
    console.log(chalk.gray("  Reveal the full code: sudo aicommander-agent status --reveal"));
  }
  console.log(chalk.gray("  Then give it to your admin to connect."));
  console.log(
    chalk.yellow("  ⚠ Keep this code secret — anyone who has it can run commands as root here."),
  );
  console.log(chalk.gray(`  Server: ${serverUrl}`));
  console.log(chalk.gray("  Press Ctrl+C to disconnect."));
  console.log();
  console.log(chalk.yellow("  Waiting for admin connection..."));
  console.log();
}

export function showReconnecting(attempt: number, delayMs: number): void {
  console.log(chalk.yellow(`  Reconnecting in ${Math.round(delayMs / 1000)}s (attempt ${attempt})...`));
}

export function showRelayConnected(): void {
  console.log(chalk.green("  Connected to relay — ready for commands."));
}

export type LocalOperation = "command" | "secure-exec" | "elevated-exec";

const LOCAL_OPERATION_LABELS: Record<LocalOperation, string> = {
  command: "Command",
  "secure-exec": "Secure exec",
  "elevated-exec": "Elevated exec",
};

/**
 * Render command lifecycle metadata without rendering relay-controlled payloads.
 *
 * Shell command text is never accepted by this API. Secure exec may include its
 * allowlisted executable basename, but only when it is a short, printable bare
 * name; argv, cwd, env, input, and output are never display inputs.
 */
export function showExecuting(
  operation: LocalOperation,
  executableBasename?: string,
): void {
  const safeBasename =
    operation === "secure-exec" &&
    executableBasename != null &&
    /^[A-Za-z0-9][A-Za-z0-9._+@-]{0,127}$/.test(executableBasename)
      ? executableBasename
      : null;
  const label = LOCAL_OPERATION_LABELS[operation];
  const detail = safeBasename ? ` (${safeBasename})` : "";
  console.log(chalk.cyan(`  ${label}${detail} started.`));
}

export function showDone(
  operation: LocalOperation,
  exitCode: number,
  durationMs: number,
): void {
  const color = exitCode === 0 ? chalk.green : chalk.red;
  const label = LOCAL_OPERATION_LABELS[operation];
  console.log(color(`  ${label} finished. Exit ${exitCode} in ${durationMs}ms.`));
}
