/**
 * Which interpreter a remote command runs in — the shared vocabulary for the
 * `shell` argument of remote_exec.
 *
 * WHY THIS EXISTS. Until now the interpreter was implicit and per-platform:
 * POSIX machines ran every command through `/bin/sh -c`, Windows machines
 * through `cmd.exe /d /s /c`. That default hurts hardest on Windows, where
 * POSIX habits fail in ways that LOOK like success — `;` is not a separator, so
 * `echo a ; echo b` prints the rest of the line as literal text and exits 0 —
 * and where writing any script at all means hand-wrapping the whole thing in
 * `powershell -NoProfile -Command "…"` with the quoting done by eye.
 *
 * WHY IT LIVES IN THE PROTOCOL PACKAGE. Three parties must agree on the exact
 * same set of values and the exact same refusal wording: the relay (which
 * refuses a value the target platform cannot run, before sending anything), the
 * agent (which is the authority on what its own machine actually is), and the
 * tool schemas the model reads. A second copy of this table would drift, and the
 * drift would show up as the failure this whole surface is being hardened
 * against — a caller asking for one interpreter and silently getting another.
 *
 * THE RULE: an unsupported or unknown value is REFUSED, never ignored. There is
 * no "closest match" and no falling back to the default; a caller that asked for
 * PowerShell and received cmd.exe has been lied to.
 */

/** Every shell any platform can run. Not all of them on any one machine. */
export const EXEC_SHELLS = ["sh", "bash", "cmd", "powershell"] as const;

export type ExecShell = (typeof EXEC_SHELLS)[number];

/**
 * POSIX machines (darwin/linux).
 *
 * `sh` is the historical default and stays first. `bash` is a genuinely
 * different language — arrays, `[[ ]]`, process substitution, `pipefail` — and
 * on Debian-family Linux `/bin/sh` is dash, where a bash-ism is a syntax error
 * rather than a warning, so asking for it explicitly is worth a wire field.
 */
export const POSIX_EXEC_SHELLS: readonly ExecShell[] = ["sh", "bash"];

/**
 * Windows machines.
 *
 * `cmd` is the historical default. `powershell` is Windows PowerShell 5.1
 * (`%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`), which
 * ships with every supported Windows and is therefore the one interpreter the
 * relay can promise is present. PowerShell 7 (`pwsh`) is NOT offered: it is an
 * optional install, so advertising it would mean promising something most
 * machines do not have.
 */
export const WINDOWS_EXEC_SHELLS: readonly ExecShell[] = ["cmd", "powershell"];

/** What each value means on the machine, for messages the model has to act on. */
const EXEC_SHELL_DESCRIPTIONS: Record<ExecShell, string> = {
  sh: "sh (the default here — `/bin/sh -c`)",
  bash: "bash (`/bin/bash -c`)",
  cmd: "cmd (the default here — `cmd.exe /d /s /c`)",
  powershell: "powershell (Windows PowerShell 5.1, run with -NoProfile -NonInteractive)",
};

export function isExecShell(value: unknown): value is ExecShell {
  return typeof value === "string" && (EXEC_SHELLS as readonly string[]).includes(value);
}

/**
 * The shells a given `process.platform` string can run, or `null` when the
 * platform is unknown to us. `null` is NOT "none": the caller must treat it as
 * "cannot decide here", and leave the decision to the machine itself — the relay
 * only ever knows the LAST platform an agent reported, while the agent knows
 * what it is running on right now.
 */
export function execShellsForPlatform(platform: string | undefined): readonly ExecShell[] | null {
  if (platform === "win32") return WINDOWS_EXEC_SHELLS;
  if (platform === "darwin" || platform === "linux") return POSIX_EXEC_SHELLS;
  return null;
}

/** What omitting `shell` gets you on this platform. */
export function defaultExecShell(platform: string | undefined): ExecShell {
  return platform === "win32" ? "cmd" : "sh";
}

function describeShells(shells: readonly ExecShell[]): string {
  return shells.map((shell) => EXEC_SHELL_DESCRIPTIONS[shell]).join(", ");
}

function describePlatform(platform: string | undefined): string {
  if (platform === "win32") return "a Windows machine (platform 'win32')";
  if (platform === "darwin") return "a macOS machine (platform 'darwin')";
  if (platform === "linux") return "a Linux machine (platform 'linux')";
  return "this machine";
}

/**
 * Refusal for a `shell` value this machine cannot run — an unknown word, or a
 * value that belongs to the other family of platforms.
 *
 * Written for a model with no other window onto the box: it names what was
 * asked for, what the machine actually is, the complete list of values that DO
 * work there, that a retry is pointless, and the two ways forward. The
 * cross-platform hint at the end is what stops a caller from concluding the
 * feature is broken when it simply asked the wrong machine.
 */
export function unsupportedExecShellMessage(
  requested: string,
  platform: string | undefined,
): string {
  const supported = execShellsForPlatform(platform);
  const shells = supported ?? EXEC_SHELLS;
  const cross =
    platform === "win32"
      ? " `sh` and `bash` exist only on macOS/Linux machines."
      : supported
        ? " `cmd` and `powershell` exist only on Windows machines (platform 'win32')."
        : "";
  return (
    `\`shell\` was set to ${JSON.stringify(requested)}, which cannot be run on this machine — ` +
    `it is ${describePlatform(platform)}. The command was NOT run: a request for one interpreter is ` +
    "never quietly served by another. " +
    `Shells available here: ${describeShells(shells)}.${cross} ` +
    "Retrying this call unchanged will fail the same way — either omit `shell` to use this machine's " +
    "default, or pass one of the values listed above."
  );
}

/**
 * Refusal for `shell` sent to a machine whose agent predates the field.
 *
 * An older agent destructures only the fields it knows off `do:exec`, so the
 * request would run in the machine's DEFAULT shell while the caller believed
 * otherwise — a silent false success of exactly the kind `shell` was added to
 * prevent. The relay therefore requires the agent to have ADVERTISED shell
 * selection at register time (AgentRegisterMsg.shellSelect) and refuses here
 * when it did not, the same fail-closed shape as `elevatedExec` and `jobs`.
 */
export function execShellAgentTooOldMessage(platform: string | undefined): string {
  const fallback =
    platform === "win32"
      ? "on Windows you can still reach PowerShell from a cmd.exe command line with " +
        '`powershell -NoProfile -Command "…"`'
      : "on macOS/Linux you can still reach another shell from an sh command line with " +
        "`bash -c '…'`";
  return (
    "This machine's AI Commander agent is too old to choose a shell: it does not advertise the `shell` " +
    "field, so the field would be IGNORED and the command would run in the machine's default shell " +
    "while you believed it ran somewhere else. The command was NOT run. Retrying will not help until " +
    "that machine's agent is updated. Either update AI Commander on it, or re-send the call WITHOUT " +
    `\`shell\` and write the command for the default shell — ${fallback}.`
  );
}

/**
 * Refusal for `shell` combined with `elevated`.
 *
 * Same reasoning, and the same precedent, as `env` + `elevated`: the elevated
 * path does not send do:exec at all — it signs an ElevatedCapabilityClaims that
 * has no `shell` field — so the request would reach nothing and the privileged
 * command would run in the default interpreter. Refused rather than dropped.
 */
export const SHELL_WITH_ELEVATED_MESSAGE =
  "`shell` cannot be combined with `elevated`. The privileged path runs the command through a signed " +
  "capability that carries no shell field, so your choice would be dropped and the command would run in " +
  "the machine's default interpreter (cmd.exe on Windows, /bin/sh on macOS/Linux) instead of the one you " +
  "asked for. Either drop `elevated` and keep `shell`, or keep `elevated` and invoke the interpreter " +
  'inside the command itself (e.g. `powershell -NoProfile -Command "…"` or `bash -c \'…\'`). Retrying ' +
  "this call unchanged will fail the same way.";

/**
 * Refusal for `shell` on the detached-job path.
 *
 * Jobs are spawned by a different component (the agent's job manager) that has
 * no shell selection yet. Left unhandled the field would simply be dropped, so
 * it is refused here for the same reason `elevated` is: a job that runs in a
 * different language than the caller wrote for produces a syntax error hours
 * later, or worse, silently does the wrong half of the work.
 */
export const SHELL_NOT_SUPPORTED_FOR_JOBS_MESSAGE =
  "`shell` is not supported for jobs — a job always runs in the machine's default shell (cmd.exe on " +
  "Windows, /bin/sh on macOS/Linux). It is refused rather than ignored, because a job written for another " +
  "interpreter would fail (or half-succeed) long after this call returned. Either write the command for " +
  "the default shell, or invoke the interpreter inside it — e.g. " +
  '`powershell -NoProfile -File C:\\path\\to\\script.ps1` or `bash -c \'…\'`. For a SHORT command in a ' +
  "chosen shell, use remote_exec with `shell` instead. Note that LEAVING THE FIELD OUT is the only way " +
  "to ask for the default here: sending `shell: null` is a supplied value that names no interpreter, so " +
  "it is refused too rather than answered with a job you did not ask for.";
