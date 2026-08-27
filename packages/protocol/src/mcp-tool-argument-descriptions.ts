import {
  COMMAND_MAX_TIMEOUT_MS,
  FILE_BLOB_TTL_MS,
  JOB_LOGS_MAX_SLICE_BYTES,
  JOB_RETENTION_MS,
} from "./constants.js";
import { formatBytes, formatDuration, formatDurationShort } from "./limit-text.js";
import type { McpToolName } from "./mcp-tool-metadata.js";

/**
 * The single source of truth for the ARGUMENT descriptions the MCP tools serve.
 *
 * The companion of mcp-tool-descriptions.ts, one level down. The same two
 * servers publish the same arguments — the hosted Streamable-HTTP server in
 * `packages/worker/src/mcp-tools.ts` writes them as JSON-Schema `description`
 * fields, the stdio bridge in `packages/mcp/bin/mcp.ts` as zod `.describe()`
 * calls — and until now each carried its own copy of every string. They had
 * already drifted seven ways: four tools disagreed about how to name a machine,
 * two dropped a clause the other kept, and `remote_pull.path` lost its worked
 * example on one transport only.
 *
 * ONLY THE TEXT IS SHARED. The two SCHEMAS around it stay separate on purpose:
 * zod STRIPS an undeclared key while JSON Schema passes it through, so the
 * bridge must declare `remote_job_start`'s `shell`/`elevated` in order to refuse
 * them and the hosted server must not (see the comment at that call site). Types,
 * defaults, enums, required-ness and property order therefore remain the
 * business of each server.
 *
 * An argument only ONE transport has keeps its description at its own call site;
 * there is nothing to share, and inventing the other half would advertise a
 * field that server does not accept.
 */

// Every limit these texts quote, rendered from the constant that enforces it —
// see the same block in mcp-tool-descriptions.ts. A number typed out by hand
// here goes stale silently, and a wrong number is not wording drift: the caller
// acts on it.
const EXEC_DEADLINE_SHORT = formatDurationShort(COMMAND_MAX_TIMEOUT_MS);
const JOB_RETENTION = formatDuration(JOB_RETENTION_MS);
const LOG_SLICE_CAP = formatBytes(JOB_LOGS_MAX_SLICE_BYTES);
// Stated in hours on every surface, never as "1 day".
const BLOB_TTL = formatDuration(FILE_BLOB_TTL_MS, "hour");

/**
 * How the machine is named, spelled out in full.
 *
 * The tools a request STARTS at — the user names a machine and something happens
 * on it — carry the whole naming rule, because this is where a model decides
 * between an AIC- code, an alias, and (wrongly) a DNS lookup. The follow-up
 * tools below take the short form: by then the caller already has the name that
 * worked.
 */
const MACHINE_CODE_FULL =
  "How the user named the machine — pass it exactly as given. Either an AI Commander session code (AIC-…, e.g. AIC-XYZ-1234), or (when authenticated with an API key) a saved machine alias or hostname the user calls the computer by, e.g. 'wearfits-m3', 'aic-wearfits' or 'my-laptop'. A name that is not an AIC- code is treated as an alias and resolved to the user's saved machine.";

/** How the machine is named — the short form the follow-up tools use. */
const MACHINE_CODE =
  "How the user named the machine — pass it exactly as given (AIC- session code, or a saved alias/hostname when authenticated with an API key).";

const JOB_ID = "The jobId returned by remote_job_start (16 hex characters).";

const INCLUDE_COMMAND_JOB =
  "Also return the job's command line. Off by default.";

export const MCP_TOOL_ARGUMENT_DESCRIPTIONS = {
  remote_exec: {
    code: MACHINE_CODE_FULL,
    command:
      "Shell command to execute. WHICH SHELL DEPENDS ON THE MACHINE'S OS, and the schemas cannot tell you which — read `platform` from list_machines or session_status first ('darwin'/'linux' vs 'win32'). POSIX machines run the command via `/bin/sh -c`. Windows machines run it via cmd.exe, where POSIX habits fail in ways that LOOK like success: `;` is not a command separator, so `echo a ; echo b` prints the rest of the line as literal text and still exits 0; POSIX tools are simply absent (`ls -la` → \"'ls' is not recognized as an internal or external command\"); heredocs do not exist (`cat > f <<'EOF'` → \"<< was unexpected at this time.\"). On Windows: either chain steps with `&&` and keep the whole thing on ONE line (a multi-line command is REJECTED there — it used to silently run only the first line and return 0), or pass `shell: \"powershell\"` and write PowerShell instead, which accepts `;`, multi-line scripts and here-strings — but there judge the result by stderr, not by the exit code alone, because a PowerShell error does not fail the script (see `shell`). `shell` is the supported way to change interpreter; a value the machine cannot run is rejected rather than ignored.",
    cwd: "Working directory on the remote machine (optional)",
    env: "Extra environment variables for the command (string values only), e.g. HF_HOME or an API token the command needs, instead of inlining them into the command string. NOT accepted together with `elevated: true` — that combination is rejected with an error rather than silently dropped, because the elevated path runs through a signed capability that has no env field. If an elevated command needs a variable, set it inside the command itself.",
    // Concatenated, not a template literal: the sentence quotes `0` in backticks.
    timeout_ms:
      "Timeout in milliseconds: minimum 1000 (1 s), default 300000 (5 min), maximum " +
      COMMAND_MAX_TIMEOUT_MS +
      " (" +
      EXEC_DEADLINE_SHORT +
      "). Validated, not clamped — a value outside the range is rejected with an error. In particular `0` is NOT 'no timeout': it is below the minimum and used to be raised silently to 1000, killing the command after one second. Omit the field to get the default.",
    shell:
      "Which interpreter runs the command. Omit it for the machine's default — `/bin/sh -c` on 'darwin'/'linux', `cmd.exe` on 'win32' — which is what every call got before this argument existed. LEAVING THE FIELD OUT is the only way to ask for that default: `shell: null` is a supplied value that names no interpreter, so it is REJECTED rather than answered with whichever shell the machine happens to default to. Windows machines accept `cmd` and `powershell`; macOS/Linux machines accept `sh` and `bash`. A value the target cannot run (e.g. `powershell` on a Mac, or a misspelling) is REJECTED with a message listing what that machine does accept — it is never quietly replaced by the default, so if the call succeeds the command really did run in the shell you asked for. `powershell` is Windows PowerShell 5.1, run as `-NoProfile -NonInteractive`, and it is the answer to everything cmd.exe makes painful: `;` works as a separator, `Get-ChildItem`/`ls` exist, and a MULTI-LINE script IS allowed (unlike cmd, where a line break is rejected) because the agent hands PowerShell the script base64-encoded rather than on a command line. That encoding costs size: a PowerShell script is capped at roughly 3000 characters here, and a longer one is rejected rather than truncated — write it to a .ps1 file in pieces and run `powershell -NoProfile -File <path>` if you need more. STDERR IS POST-PROCESSED ON THIS PATH ONLY: that same encoding makes PowerShell serialize its error/warning/progress streams as CLIXML, so the agent strips the `#< CLIXML` framing and `<Objs>` envelope, drops the module-loading progress records, and reassembles the `<S>` fragments — undoing `_x000D_`-style escapes and XML entities — into the text a console would show. Anything it cannot positively identify as PowerShell's own framing (a block cut off mid-record, or CLIXML-shaped text your script printed itself) is passed through byte-for-byte, and `cmd`/`sh`/`bash` stderr is never touched at all. WHAT IT DOES NOT BUY YOU IS A TRUSTWORTHY EXIT CODE: a PowerShell NON-TERMINATING error — `Write-Error`, a failed cmdlet, most runtime errors — writes to the error stream and the script CARRIES ON, so THE EXIT CODE TRACKS THE LAST STATEMENT, not whether errors occurred. Measured on Windows: `Write-Output \"stdout-line\"; Write-Error \"this-is-a-real-error\"` returns exit code 0 with the error text on stderr — the exact shape of a success — and an error in the MIDDLE of a script that then does something successful leaves 0 just the same; a script whose final statement is the failing one exits 1, so a non-zero code does not mean the error you care about happened either. It is uninformative in BOTH directions. That is PowerShell's own semantics, not something AI Commander does to your command; cmd.exe and POSIX shells do not behave this way, so the surprise lands exactly when you switch to the interpreter recommended above. Under `powershell`, READ STDERR rather than trusting exit 0 on its own, and/or begin your script with `$ErrorActionPreference = 'Stop'` to make those errors terminating. The agent will not insert that for you: it would change YOUR script's control flow — a script that deliberately continues past an error would start aborting — so the choice stays yours. `bash` (POSIX) buys you arrays, `[[ ]]`, and `pipefail`, which `/bin/sh` on Debian-family Linux does not have. Cannot be combined with `elevated: true` — that combination is rejected, not ignored. Machines running an AI Commander too old to understand this argument REFUSE the call outright rather than running the default shell behind your back; update the agent there, or drop the argument.",
    elevated:
      "Run as root (macOS) / LocalSystem (Windows) via the privileged helper. Account-only; only works on mac/Windows machines with the helper installed. Most commands do NOT need this. NOT accepted together with `shell` — that combination is rejected with an error rather than silently dropped, because the elevated path runs through a signed capability that has no shell field.",
  },
  session_status: {
    code: MACHINE_CODE_FULL,
  },
  // Takes no arguments.
  list_machines: {},
  remote_screenshot: {
    code: MACHINE_CODE_FULL,
    display:
      "Which display to capture. Omit for the primary screen (index 0) — that is the safe default and what every machine did before this argument existed. Pass a 0-based index (0, 1, 2, …) to capture another monitor; the caption on any reply lists the machine's displays and their resolutions, so take the indexes from there. Pass the string \"all\" for the whole multi-monitor desktop in one image — WINDOWS ONLY, because macOS cannot capture more than one display at a time and will tell you so; an 'all' capture is also downscaled when it would otherwise exceed the 10 MB transfer limit, which can make small text unreadable. Machines running an AI Commander older than 1.0.50 ignore this argument and always return the primary screen — the reply says so explicitly rather than pretending otherwise.",
  },
  remote_job_start: {
    code: MACHINE_CODE_FULL,
    command:
      "Shell command to run as the job. WHICH SHELL DEPENDS ON THE MACHINE'S OS — read `platform` from list_machines or session_status first: POSIX machines ('darwin'/'linux') run it via `/bin/sh -c`, Windows machines ('win32') via cmd.exe. On Windows `;` is not a command separator (`echo a ; echo b` prints the rest as literal text and exits 0 — a silent false success), POSIX tools like `ls` do not exist, and heredocs are a syntax error; chain steps with `&&` on ONE line (a multi-line command is rejected), and wrap script-writing explicitly, e.g. `powershell -NoProfile -Command \"...\"`. A job ALWAYS runs in the machine's default shell: unlike remote_exec there is no `shell` argument here, and passing one is rejected rather than ignored. Use absolute paths or set `cwd`: the job does not inherit any state from earlier remote_exec calls.",
    cwd: "Working directory on the remote machine. Defaults to a per-job workspace directory the machine creates.",
    env: "Extra environment variables for the job (string values only), e.g. HF_HOME or TORCH_HOME so model weights land somewhere with space rather than in the service account's home directory.",
    name: "Short human-readable label for the job, so you and the user can recognize it later in remote_job_list. The machine generates one if omitted.",
    gpu_index:
      "Reserve this NVIDIA device (the `index` from the machine's GPU list, as reported by list_machines / session_status) exclusively for the job and set CUDA_VISIBLE_DEVICES accordingly. Refused with `gpu_busy` if another job already holds that card. When the machine's GPU list is known, an index that is not on it is REJECTED — an out-of-range index used to start a phantom job with CUDA_VISIBLE_DEVICES pointing at nothing, which then failed deep inside the training script. Read the GPU list before choosing.",
    // `shell` and `elevated` are NOT here: only the stdio bridge declares them,
    // and only so zod refuses them instead of stripping them. See that call site.
  },
  remote_job_list: {
    code: MACHINE_CODE,
    status: "Only return jobs in this state. Omit for all retained jobs.",
    include_command:
      "Also return each job's command line. Off by default so command strings are not echoed back unnecessarily.",
    limit:
      "Return only the newest N jobs (default 20; must be at least 1). The machine retains " +
      JOB_RETENTION +
      " of history, so a busy box can hold dozens of entries and listing them all burns your context for no benefit. Anything older than the newest N is omitted and the reply says how many were left out — raise the limit, or narrow with `status`, if you actually need them.",
  },
  remote_job_status: {
    code: MACHINE_CODE,
    job_id: JOB_ID,
    include_command: INCLUDE_COMMAND_JOB,
  },
  remote_job_logs: {
    code: MACHINE_CODE,
    job_id: JOB_ID,
    tail_lines:
      "Return the last N lines of the log (default 200). Must be an integer of at least 1 — validated, not silently corrected. Ignored when offset_bytes is given.",
    offset_bytes:
      "Read forward from this byte offset instead of tailing — pass the offset_bytes value the previous reply's header tells you to continue from, to follow a growing log. Must be an integer of 0 or more; a negative or fractional value is rejected.",
    max_bytes: `Requested slice size in bytes. Must be an integer from 1 to ${JOB_LOGS_MAX_SLICE_BYTES} (${LOG_SLICE_CAP}, also the default and the hard per-reply ceiling); a larger value is rejected rather than silently clamped, so page a long log with offset_bytes instead.`,
  },
  remote_job_cancel: {
    code: MACHINE_CODE,
    job_id: JOB_ID,
  },
  remote_pull: {
    code: MACHINE_CODE,
    path: "ABSOLUTE path of the file on the remote machine, e.g. `/home/u/aic-jobs/train/out.ckpt` or `C:\\Users\\u\\out.png`. A relative path is refused rather than resolved against some working directory. Must be a regular file: archive a directory first (`tar -czf /tmp/out.tgz <dir>`) and pull the archive.",
  },
  remote_push: {
    code: MACHINE_CODE,
    blob_id:
      "The blobId from a previous remote_pull, or from POST /api/v1/files (32 hex characters). Blobs belong to the account that created them and stop being readable after " +
      BLOB_TTL +
      ".",
    dest_path:
      "ABSOLUTE destination path on the remote machine, e.g. `/home/u/data/train.csv`. The parent directory must already exist. An existing file at this path is REPLACED.",
  },
} as const satisfies Readonly<Record<McpToolName, Readonly<Record<string, string>>>>;

/**
 * The description both servers serve for one argument.
 *
 * `argument` is typed against the named tool, so a renamed or misspelled
 * argument fails to compile at the call site rather than serving `undefined`.
 */
export function mcpToolArgumentDescription<T extends McpToolName>(
  tool: T,
  argument: keyof (typeof MCP_TOOL_ARGUMENT_DESCRIPTIONS)[T],
): string {
  return MCP_TOOL_ARGUMENT_DESCRIPTIONS[tool][argument] as string;
}
