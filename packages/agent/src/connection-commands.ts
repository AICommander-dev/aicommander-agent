import type WebSocket from "ws";
import { executeCommand } from "./executor.js";
import { executeSecureCommand } from "./secure-executor.js";
import { executeElevatedCommand } from "./elevated-executor.js";
import { showExecuting, showDone } from "./display.js";
import type { AgentToDoMsg, DoToAgentMsg, RemoteOperator } from "@aicommander/protocol";
import { clampCommandTimeout, EXEC_IDLE_THRESHOLD_MS } from "@aicommander/protocol";
import type { ElevatedEndpoint } from "@aicommander/priv-helper";

/**
 * The connection-wide foreground command slot (do:exec, do:secure_exec,
 * do:elevated_exec, do:kill), split out of connection.ts. One instance per relay
 * socket: connection.ts routes the frames here and calls abortActiveCommand from
 * its teardown paths.
 */
type ActiveCommand = {
  commandId: string;
  terminalResponseSent: boolean;
  executionSettled: boolean;
  kill: (() => void) | null;
  idleCheck: ReturnType<typeof setInterval> | null;
  timeout: ReturnType<typeof setTimeout> | null;
};

export interface CommandSlotDeps {
  ws: WebSocket;
  silent: boolean | undefined;
  windowsExecLauncherPath: string | undefined;
  onActivity: (active: boolean) => void;
  onRemoteActivity: (operator: RemoteOperator | undefined) => void;
  /** The elevated helper endpoint discovery pinned, if any. */
  elevatedEndpoint: () => ElevatedEndpoint | null;
  /** The helper reported a bootId during an unsettled elevated exec. */
  onElevatedBootId: (bootId: string) => void;
}

export interface CommandSlot {
  /** True while a command occupies the slot (token rotation waits for it). */
  readonly busy: boolean;
  exec(msg: Extract<DoToAgentMsg, { type: "do:exec" }>): void;
  secureExec(msg: Extract<DoToAgentMsg, { type: "do:secure_exec" }>): void;
  elevatedExec(msg: Extract<DoToAgentMsg, { type: "do:elevated_exec" }>): void;
  kill(msg: Extract<DoToAgentMsg, { type: "do:kill" }>): void;
  abortActiveCommand(): void;
}

export function createCommandSlot(deps: CommandSlotDeps): CommandSlot {
  let activeCommand: ActiveCommand | null = null;

  const stopIdleCheck = (command = activeCommand) => {
    if (command?.idleCheck) {
      clearInterval(command.idleCheck);
      command.idleCheck = null;
    }
  };

  const stopCommandTimeout = (command = activeCommand) => {
    if (command?.timeout) {
      clearTimeout(command.timeout);
      command.timeout = null;
    }
  };

  // Claims the one connection-wide execution slot. All three foreground exec
  // modes share it: their kill handles, idle intervals and (for legacy exec)
  // deadlines must never be overwritten by a second relay frame.
  const beginCommand = (commandId: string): ActiveCommand | null => {
    if (activeCommand) {
      const busy: AgentToDoMsg = {
        type: "agent:error",
        commandId,
        error: "Another command is already running on this connection.",
      };
      try { deps.ws.send(JSON.stringify(busy)); } catch { /* socket gone */ }
      return null;
    }
    const command: ActiveCommand = {
      commandId,
      terminalResponseSent: false,
      executionSettled: false,
      kill: null,
      idleCheck: null,
      timeout: null,
    };
    activeCommand = command;
    return command;
  };

  // Releases the slot only when the executor confirms that its process is
  // actually gone. A timeout sends its response and starts termination, but
  // deliberately leaves executionSettled=false so TERM→KILL/taskkill cannot
  // overlap a new command. Queued callbacks retain this command token and can
  // therefore never release a later occupant of the slot.
  const settleCommandExecution = (command: ActiveCommand): boolean => {
    if (command.executionSettled) return false;
    command.executionSettled = true;
    stopIdleCheck(command);
    stopCommandTimeout(command);
    if (activeCommand === command) activeCommand = null;
    return true;
  };

  const abortActiveCommand = (): void => {
    const command = activeCommand;
    if (!command) return;
    const kill = command.kill;
    command.terminalResponseSent = true;
    if (!settleCommandExecution(command)) return;
    command.kill = null;
    try { kill?.(); } catch { /* connection cleanup remains terminal */ }
    deps.onActivity(false);
  };

  const exec = (msg: Extract<DoToAgentMsg, { type: "do:exec" }>): void => {
    const { commandId, command, cwd, env: cmdEnv, shell } = msg;
    const commandState = beginCommand(commandId);
    if (!commandState) return;
    // Treat the relay frame as untrusted even though the Worker normally
    // normalizes it first. This local deadline is the final enforcement
    // boundary: it kills the process and reports a deterministic terminal
    // error without depending on Worker/DO timers or another network hop.
    const timeoutMs = clampCommandTimeout(msg.timeoutMs);

    const onDone = (exitCode: number, durationMs: number) => {
      if (!settleCommandExecution(commandState)) return;
      commandState.kill = null;
      deps.onActivity(false);
      if (commandState.terminalResponseSent) return;
      commandState.terminalResponseSent = true;
      if (!deps.silent) showDone("command", exitCode, durationMs);
      const done: AgentToDoMsg = { type: "agent:done", commandId, exitCode, durationMs };
      deps.ws.send(JSON.stringify(done));
    };
    const onError = (error: string) => {
      if (!settleCommandExecution(commandState)) return;
      commandState.kill = null;
      deps.onActivity(false);
      if (commandState.terminalResponseSent) return;
      commandState.terminalResponseSent = true;
      const errMsg: AgentToDoMsg = { type: "agent:error", commandId, error };
      deps.ws.send(JSON.stringify(errMsg));
    };

    try {
      // Local output is intentionally metadata-only in every context. In
      // particular, systemd inherits stdout into journald, while library
      // consumers (including desktop) use silent mode.
      if (!deps.silent) showExecuting("command");
      deps.onActivity(true);
      deps.onRemoteActivity(msg.operator);

      // W4: surface a "possibly stuck" notice if the command goes quiet for a
      // long time. Informational ONLY — never kills (silence is normal for
      // builds, sleeps, and servers). Reset on every output chunk; report at
      // most once per idle stretch.
      let lastOutputAt = Date.now();
      let idleReported = false;
      commandState.idleCheck = setInterval(() => {
        if (commandState.terminalResponseSent || commandState.executionSettled) return;
        const idleMs = Date.now() - lastOutputAt;
        if (idleMs >= EXEC_IDLE_THRESHOLD_MS && !idleReported) {
          idleReported = true;
          const idle: AgentToDoMsg = { type: "agent:exec_idle", commandId, idleMs };
          deps.ws.send(JSON.stringify(idle));
        }
      }, EXEC_IDLE_THRESHOLD_MS);
      commandState.idleCheck.unref?.();

      // The one instant that defines this command's deadline. Derived
      // from the SAME timeoutMs, at the SAME moment the timer below is
      // armed, and handed to the executor so its post-exit drain can end
      // before we would declare a timeout. Recomputing it anywhere else
      // would let the two drift apart, which is precisely the bug.
      const deadlineMs = Date.now() + timeoutMs;
      commandState.timeout = setTimeout(() => {
        if (commandState.executionSettled || commandState.terminalResponseSent) return;
        const kill = commandState.kill;
        commandState.terminalResponseSent = true;
        stopCommandTimeout(commandState);
        stopIdleCheck(commandState);
        commandState.kill = null;
        deps.onActivity(false);
        const timedOut: AgentToDoMsg = {
          type: "agent:error",
          commandId,
          error: `Command timed out after ${timeoutMs}ms`,
        };
        try { deps.ws.send(JSON.stringify(timedOut)); } catch { /* socket gone */ }
        // Mark the response terminal before killing: kill() may
        // synchronously deliver the executor's close callback. That
        // callback releases the slot but cannot emit a second terminal
        // response. Async termination keeps the slot occupied meanwhile.
        try { kill?.(); } catch { /* keep the slot fail-closed */ }
      }, timeoutMs);
      commandState.timeout.unref?.();

      const running = executeCommand(command, cwd, cmdEnv, {
        onOutput: (chunk, stream) => {
          if (commandState.terminalResponseSent || commandState.executionSettled) return;
          lastOutputAt = Date.now();
          idleReported = false;
          const out: AgentToDoMsg = { type: "agent:output", commandId, chunk, stream };
          deps.ws.send(JSON.stringify(out));
        },
        onDone,
        onError,
      }, {
        windowsExecLauncherPath: deps.windowsExecLauncherPath,
        deadlineMs,
        // Forwarded verbatim, INCLUDING a value this machine cannot run:
        // the executor refuses it with a message naming what is available
        // here. Silently dropping it would run the command in the default
        // interpreter and report success for a language the caller never
        // asked for. Omitted ⇒ the machine default, as before.
        ...(shell !== undefined ? { shell } : {}),
      });
      // An executor may complete synchronously in tests or fail during
      // startup. Never resurrect its kill handle after a terminal callback.
      if (!commandState.executionSettled) commandState.kill = running.kill;
    } catch (err) {
      // A malformed relay frame or synchronous spawn rejection is returned
      // to the caller, but the Error object is never written locally.
      onError(err instanceof Error ? err.message : String(err));
    }
  };

  const secureExec = (msg: Extract<DoToAgentMsg, { type: "do:secure_exec" }>): void => {
    const { commandId, argv, allowedCommands, input, cwd, env: cmdEnv } = msg;
    const commandState = beginCommand(commandId);
    if (!commandState) return;

    const onDone = (exitCode: number, durationMs: number) => {
      if (!settleCommandExecution(commandState)) return;
      commandState.kill = null;
      deps.onActivity(false);
      if (commandState.terminalResponseSent) return;
      commandState.terminalResponseSent = true;
      if (!deps.silent) showDone("secure-exec", exitCode, durationMs);
      const done: AgentToDoMsg = { type: "agent:done", commandId, exitCode, durationMs };
      deps.ws.send(JSON.stringify(done));
    };
    const onError = (error: string) => {
      if (!settleCommandExecution(commandState)) return;
      commandState.kill = null;
      deps.onActivity(false);
      if (commandState.terminalResponseSent) return;
      commandState.terminalResponseSent = true;
      const errMsg: AgentToDoMsg = { type: "agent:error", commandId, error };
      deps.ws.send(JSON.stringify(errMsg));
    };

    try {
      // Everything below is inside the try so ANY malformed frame (e.g. a
      // non-array argv) fails closed via onError → agent:error rather than
      // throwing past the switch. Only a validated printable executable
      // basename may enter local display; the rest of argv never does.
      if (!deps.silent) {
        const executableBasename =
          Array.isArray(argv) && typeof argv[0] === "string" ? argv[0] : undefined;
        showExecuting("secure-exec", executableBasename);
      }
      deps.onActivity(true);

      // Idle observability, mirroring do:exec.
      let lastOutputAt = Date.now();
      let idleReported = false;
      commandState.idleCheck = setInterval(() => {
        if (commandState.terminalResponseSent || commandState.executionSettled) return;
        const idleMs = Date.now() - lastOutputAt;
        if (idleMs >= EXEC_IDLE_THRESHOLD_MS && !idleReported) {
          idleReported = true;
          const idle: AgentToDoMsg = { type: "agent:exec_idle", commandId, idleMs };
          deps.ws.send(JSON.stringify(idle));
        }
      }, EXEC_IDLE_THRESHOLD_MS);
      commandState.idleCheck.unref?.();

      const running = executeSecureCommand(
        { argv, allowedCommands, input, cwd, env: cmdEnv },
        {
          onOutput: (chunk, stream) => {
            if (commandState.terminalResponseSent || commandState.executionSettled) return;
            lastOutputAt = Date.now();
            idleReported = false;
            const out: AgentToDoMsg = { type: "agent:output", commandId, chunk, stream };
            deps.ws.send(JSON.stringify(out));
          },
          onDone,
          onError,
        },
      );
      if (!commandState.executionSettled) commandState.kill = running.kill;
    } catch (err) {
      // Pre-flight rejection (bad platform/privilege, unknown user,
      // disallowed argv, oversized input). Report as a terminal error.
      onError(err instanceof Error ? err.message : String(err));
    }
  };

  const elevatedExec = (msg: Extract<DoToAgentMsg, { type: "do:elevated_exec" }>): void => {
    const { commandId } = msg;
    const commandState = beginCommand(commandId);
    if (!commandState) return;

    const onDone = (exitCode: number, durationMs: number) => {
      if (!settleCommandExecution(commandState)) return;
      commandState.kill = null;
      deps.onActivity(false);
      if (commandState.terminalResponseSent) return;
      commandState.terminalResponseSent = true;
      if (!deps.silent) showDone("elevated-exec", exitCode, durationMs);
      const done: AgentToDoMsg = { type: "agent:done", commandId, exitCode, durationMs };
      deps.ws.send(JSON.stringify(done));
    };
    const onError = (error: string) => {
      if (!settleCommandExecution(commandState)) return;
      commandState.kill = null;
      deps.onActivity(false);
      if (commandState.terminalResponseSent) return;
      commandState.terminalResponseSent = true;
      const errMsg: AgentToDoMsg = { type: "agent:error", commandId, error };
      deps.ws.send(JSON.stringify(errMsg));
    };

    try {
      // Payload (the signed capability) never enters local display — it is
      // opaque to the agent, which only relays it to the privileged helper.
      if (!deps.silent) showExecuting("elevated-exec");
      deps.onActivity(true);
      deps.onRemoteActivity(msg.operator);

      // Idle observability, mirroring do:exec.
      let lastOutputAt = Date.now();
      let idleReported = false;
      commandState.idleCheck = setInterval(() => {
        if (commandState.terminalResponseSent || commandState.executionSettled) return;
        const idleMs = Date.now() - lastOutputAt;
        if (idleMs >= EXEC_IDLE_THRESHOLD_MS && !idleReported) {
          idleReported = true;
          const idle: AgentToDoMsg = { type: "agent:exec_idle", commandId, idleMs };
          deps.ws.send(JSON.stringify(idle));
        }
      }, EXEC_IDLE_THRESHOLD_MS);
      commandState.idleCheck.unref?.();

      const pinned = deps.elevatedEndpoint();
      const running = executeElevatedCommand(
        msg.capability,
        commandId,
        {
          onOutput: (chunk, stream) => {
            if (commandState.terminalResponseSent || commandState.executionSettled) return;
            lastOutputAt = Date.now();
            idleReported = false;
            const out: AgentToDoMsg = { type: "agent:output", commandId, chunk, stream };
            deps.ws.send(JSON.stringify(out));
          },
          onDone,
          onError,
        },
        {
          // Connect the endpoint discovery pinned (the first pool port that
          // answered the handshake — reuse it rather than re-scanning).
          // Omitted (→ default) only if we somehow have no pin;
          // executeElevatedCommand fails closed if that endpoint is dead.
          ...(pinned ? { endpoint: pinned } : {}),
          // Self-heal on helper restart: if the helper now reports a bootId
          // different from the one we advertised, the relay is minting
          // capabilities bound to a stale nonce (the helper rejects them, so
          // THIS request fails closed — correct). Re-register with the fresh
          // nonce so the NEXT elevated exec succeeds, instead of waiting up
          // to a full reauth cycle (~6h).
          onBootId: (bootId) => {
            if (!commandState.executionSettled) deps.onElevatedBootId(bootId);
          },
        },
      );
      if (!commandState.executionSettled) commandState.kill = running.kill;
    } catch (err) {
      // Fail-closed: any synchronous rejection is a terminal error, never a
      // fallback to unprivileged exec.
      onError(err instanceof Error ? err.message : String(err));
    }
  };

  const killCommand = (msg: Extract<DoToAgentMsg, { type: "do:kill" }>): void => {
    if (activeCommand?.commandId === msg.commandId && activeCommand.kill) {
      // Request termination; the terminal agent:done/error is emitted by
      // the executor's "close" handler once the process tree actually dies
      // (SIGTERM, escalating to SIGKILL). Do not clear activity here — wait
      // for the real terminal so the controller's state stays accurate.
      const commandState = activeCommand;
      const kill = commandState.kill;
      if (!kill) return;
      kill();
      // kill() may synchronously deliver the terminal callback. Only clear
      // the handle on the same token; never reach through to a later slot.
      commandState.kill = null;
    }
  };

  return {
    get busy() {
      return activeCommand !== null;
    },
    exec,
    secureExec,
    elevatedExec,
    kill: killCommand,
    abortActiveCommand,
  };
}
