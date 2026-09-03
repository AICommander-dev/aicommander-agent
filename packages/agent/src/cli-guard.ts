/**
 * Guard for the one CLI shape that can hurt: an argument commander does not
 * recognise.
 *
 * `run` is registered as commander's DEFAULT command, because the systemd unit
 * execs the binary with no arguments at all (`ExecStart=/usr/local/bin/
 * aicommander-agent`). Commander applies that default to ANY unrecognised
 * argument — so a typo does not fail, it LAUNCHES A SECOND AGENT. That agent
 * registers with this machine's device identity, the relay hands it the live
 * session, and the real (service-managed) agent is left disconnected.
 *
 * This is not hypothetical: `aicommander-agent version` — a spelling of
 * `--version` that anyone, human or model, would try first — knocked a machine
 * off the relay in the field on 2026-08-10. The binary is documented as the
 * thing to run over `remote_exec`, so the audience for this footgun is exactly
 * the audience least able to recover from it: the remote caller loses the
 * connection it would have needed to undo the damage.
 *
 * The rule below keeps the systemd contract (no arguments ⇒ run) and turns
 * everything unknown into a usage error instead of a launch.
 */

/**
 * The offending token when `argv` opens with a bare word that is not a known
 * command, or null when the invocation is safe to hand to commander.
 *
 * Safe by this definition:
 *  - no arguments at all — the service's own launch, and the ONLY way to reach
 *    the default `run` command implicitly;
 *  - a known command name or alias (`run`, `status`, `reset-code`, …);
 *  - anything beginning with `-`, which commander parses as a flag and rejects
 *    on its own terms (`--version`, `--help`, an unknown `--flag`) without ever
 *    falling through to the default command.
 */
export function unknownCliCommand(argv: readonly string[], known: Iterable<string>): string | null {
  // argv is [execPath, entry, ...args] — but "the first real argument is index 2"
  // is only true for a DIRECT invocation. The supervisor re-execs the agent with
  // `spawn(process.execPath, process.argv.slice(1))` (supervisor.ts), which
  // forwards the runtime's own entry token as a positional argument; the compiled
  // build then injects a fresh one in front of it. A worker's argv really looks
  // like this, measured on a live box:
  //
  //   /usr/local/bin/aicommander-agent  /$bunfs/root/aicommander-agent-linux-x64
  //
  // so index 2 is a PATH, not a sub-command. Treating it as one would exit(1) on
  // every worker the supervisor spawns, the watchdog would burn its restart budget,
  // and the machine would go offline — the exact outcome this guard exists to
  // prevent, inflicted on every agent at once.
  //
  // A sub-command is a bare word: `status`, `change-code`, `self-update`. None
  // contains a path separator, so skipping leading tokens that do is both
  // sufficient and impossible to confuse with a real command. This mirrors
  // `isEntrypointToken` in live-agent.ts, which already documents the same
  // "/$bunfs/…" insertion for the same reason.
  for (const token of argv.slice(2)) {
    if (token.startsWith("-")) return null;
    if (token.includes("/") || token.includes("\\")) continue;
    return new Set(known).has(token) ? null : token;
  }
  return null;
}

/** What to print when the guard trips. Kept here so a test can assert on it. */
export function unknownCliCommandMessage(token: string): string {
  return (
    `aicommander-agent: unknown command '${token}'.\n` +
    `Run 'aicommander-agent --help' for the list of commands, or '--version' for the version.\n` +
    `Refusing to start the agent: an unrecognised argument used to fall through to 'run',\n` +
    `which starts a SECOND agent and takes the relay session away from the running one.\n` +
    `To start the agent deliberately, pass no arguments (as the service does) or 'run'.`
  );
}
