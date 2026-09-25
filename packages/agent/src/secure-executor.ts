import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import {
  isSecureExecCommandDenied,
  KILL_ESCALATION_MS,
  SECURE_EXEC_PRIVILEGED_GROUPS,
  SECURE_EXEC_USER,
  SECURE_EXEC_MAX_INPUT_BYTES,
} from "@aicommander/protocol";
import { buildDropReexec } from "./secure-exec-drop.js";
import type { CommandHandlers, RunningCommand } from "./executor.js";

/**
 * Sandboxed execution path for service tokens. Four guarantees, all enforced
 * HERE in the agent (never trusted from the relay message):
 *
 *  1. No shell — argv is passed verbatim to the binary, so `&&`, `;`, `$(...)`
 *     are inert literal arguments. SHELL injection is impossible by construction.
 *  2. Drop privilege — the child runs as the dedicated non-root SECURE_EXEC_USER
 *     via an in-process Node drop (see secure-exec-drop.ts: initgroups → setgid →
 *     setuid, which also clears root's supplementary groups). NO external setpriv
 *     dependency, so it works after a plain install on any Linux. This is the REAL
 *     containment boundary, backed by a fail-closed local passwd/group check.
 *  3. Allowlist — argv[0] must be a bare command name (no `/`) on the token's
 *     allowedCommands, resolved against the LOCKED PATH in baseEnv. This is a
 *     basename match, NOT an integrity check: the allowlist itself arrives in
 *     the relay message, so it is a usability/blast-radius filter, not the
 *     security boundary. The shared protocol denylist rejects known shells,
 *     interpreters, argument runners and privilege clients even when a hostile
 *     relay includes one. It is intentionally not a complete sandbox policy.
 *  4. Group safety — before spawn, local primary + supplementary memberships are
 *     parsed without a shell and privileged groups/gid 0 are rejected. Missing,
 *     unreadable, malformed or duplicate identity data also fails closed.
 *
 * Linux-only and root-only: dropping to another uid requires both. On any other
 * platform, or when not running as root, secure exec FAILS CLOSED rather than
 * silently running with the agent's own (root) privileges.
 */

interface ResolvedUser {
  uid: number;
  gid: number;
  home: string;
  name: string;
}

interface GroupEntry {
  name: string;
  gid: number;
  members: string[];
}

const MAX_POSIX_ID = 0xffff_ffff;
const PRIVILEGED_GROUPS: ReadonlySet<string> =
  new Set(SECURE_EXEC_PRIVILEGED_GROUPS);

function parsePosixId(raw: string, source: string): number {
  // Strict decimal before Number(): reject signs, whitespace, hex and overflow.
  if (!/^\d+$/.test(raw)) throw new Error(`invalid numeric id in ${source}`);
  const id = Number(raw);
  if (!Number.isSafeInteger(id) || id < 0 || id > MAX_POSIX_ID) {
    throw new Error(`invalid numeric id in ${source}`);
  }
  return id;
}

/**
 * Parse /etc/group without invoking a shell or an external account tool. Any
 * malformed row, duplicate name/gid, or duplicate member makes the identity
 * database ambiguous, so secure exec fails closed instead of guessing.
 */
function readLocalGroups(): GroupEntry[] {
  let groupFile: string;
  try {
    groupFile = readFileSync("/etc/group", "utf8");
  } catch {
    throw new Error("cannot read /etc/group to verify secure-exec group membership");
  }

  const groups: GroupEntry[] = [];
  const names = new Set<string>();
  const gids = new Set<number>();
  for (const [index, line] of groupFile.split("\n").entries()) {
    if (line === "") continue;
    const fields = line.split(":");
    if (fields.length !== 4) {
      throw new Error(`malformed /etc/group entry at line ${index + 1}`);
    }
    const name = fields[0]!;
    const gid = parsePosixId(fields[2]!, `/etc/group line ${index + 1}`);
    const rawMembers = fields[3]!;
    if (!name || /[\s,\u0000-\u001f\u007f]/.test(name)) {
      throw new Error(`malformed /etc/group entry at line ${index + 1}`);
    }
    const members = rawMembers === "" ? [] : rawMembers.split(",");
    if (
      members.some((member) => !member || /[\s:\u0000-\u001f\u007f]/.test(member)) ||
      new Set(members).size !== members.length
    ) {
      throw new Error(`malformed /etc/group member list at line ${index + 1}`);
    }
    if (names.has(name) || gids.has(gid)) {
      throw new Error(`duplicate /etc/group name or gid at line ${index + 1}`);
    }
    names.add(name);
    gids.add(gid);
    groups.push({ name, gid, members });
  }
  return groups;
}

/**
 * Check primary and supplementary local group memberships before any spawn.
 * The installer creates a local account, so /etc/passwd + /etc/group are the
 * authoritative files this path supports. Missing/ambiguous data fails closed.
 */
function assertSafeGroupMembership(user: ResolvedUser): void {
  const groups = readLocalGroups();
  if (!groups.some((group) => group.gid === user.gid)) {
    throw new Error(`primary group ${user.gid} for ${SECURE_EXEC_USER} is not in /etc/group`);
  }

  const memberships = groups.filter(
    (group) => group.gid === user.gid || group.members.includes(user.name),
  );
  const unsafe = memberships.find(
    (group) => group.gid === 0 || PRIVILEGED_GROUPS.has(group.name),
  );
  if (unsafe) {
    throw new Error(
      `secure exec user "${SECURE_EXEC_USER}" belongs to privileged group "${unsafe.name}" (gid ${unsafe.gid})`,
    );
  }
}

/**
 * Resolve SECURE_EXEC_USER → {uid, gid, home} by reading /etc/passwd directly.
 * The sandbox user is a LOCAL account created by the installer (useradd), so it is
 * always in /etc/passwd — no `getent` (which may be absent on minimal hosts) and
 * no NSS round-trip. Read fresh on every exec to minimize stale identity data.
 * Throws (fail-closed) if the user is missing so a skipped install step can
 * never degrade into a root exec.
 */
function resolveExecUser(): ResolvedUser {
  // /etc/passwd line: name:passwd:uid:gid:gecos:home:shell
  let passwd: string;
  try {
    passwd = readFileSync("/etc/passwd", "utf8");
  } catch {
    throw new Error("cannot read /etc/passwd to resolve the secure-exec user");
  }
  // ALL lines matching our user. More than one is a poisoned/duplicate entry —
  // fail closed rather than silently taking the first.
  const matches = passwd
    .split("\n")
    .filter((l) => l.startsWith(`${SECURE_EXEC_USER}:`));
  if (matches.length === 0) {
    throw new Error(
      `secure exec user "${SECURE_EXEC_USER}" not found in /etc/passwd — reinstall the agent to create it`,
    );
  }
  if (matches.length > 1) {
    throw new Error(
      `multiple /etc/passwd entries for "${SECURE_EXEC_USER}" — refusing to guess which is the sandbox user`,
    );
  }
  // name:passwd:uid:gid:gecos:home:shell — EXACTLY 7 fields. The startsWith above
  // already pins field 0 to our user, so no separate field-0 check is needed.
  const f = matches[0]!.split(":");
  if (f.length !== 7) throw new Error(`malformed passwd entry for ${SECURE_EXEC_USER}`);
  let uid: number;
  let gid: number;
  try {
    uid = parsePosixId(f[2]!, "/etc/passwd uid");
    gid = parsePosixId(f[3]!, "/etc/passwd gid");
  } catch {
    throw new Error(`could not resolve uid/gid for ${SECURE_EXEC_USER}`);
  }
  const home = f[5] || "/tmp";
  // Refuse a root-mapped sandbox user at the PRIMARY resolution boundary — both
  // uid 0 and gid 0 — so the downstream dropper is never even asked to run as root.
  if (uid === 0) throw new Error(`refusing to run secure exec as uid 0`);
  if (gid === 0) throw new Error(`refusing to run secure exec as gid 0`);
  const user = { uid, gid, home, name: SECURE_EXEC_USER };
  assertSafeGroupMembership(user);
  return user;
}

// Locked PATH for the child (also where execvp resolves the bare argv[0]).
const LOCKED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/**
 * Caller-supplied env keys that can hijack a child via dynamic-linker /
 * interpreter hooks. Any LD_* var (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, …) is
 * stripped by pattern; the rest are exact-key matches. PATH/HOME/USER/LOGNAME are
 * also forced from baseEnv below, but listed here for clarity.
 */
const ENV_DANGER_KEYS = new Set([
  "NODE_OPTIONS", "BASH_ENV", "ENV", "IFS", "PYTHONSTARTUP", "PYTHONPATH",
  "PERL5OPT", "RUBYOPT", "GIT_EXTERNAL_DIFF",
  "PATH", "HOME", "USER", "LOGNAME",
]);
const isDangerEnvKey = (k: string): boolean =>
  /^LD_/.test(k) || ENV_DANGER_KEYS.has(k);

export interface SecureCommandRequest {
  argv: string[];
  allowedCommands: string[];
  input?: string; // base64
  cwd?: string;
  env?: Record<string, string>;
}

/**
 * Run a sandboxed command. Performs all pre-flight checks synchronously and
 * throws on any failure (bad platform/privilege, unknown user, empty or
 * disallowed argv, oversized input) — the caller maps the throw to agent:error.
 * On success returns a RunningCommand whose kill() tears down the process tree,
 * exactly like the legacy executor.
 */
export function executeSecureCommand(
  req: SecureCommandRequest,
  handlers: CommandHandlers,
): RunningCommand {
  if (process.platform !== "linux") {
    throw new Error("secure exec is only supported on Linux");
  }
  // Need root to setuid to the unprivileged user. Without it, fail closed.
  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    throw new Error("secure exec requires the agent to run as root (to drop privilege)");
  }

  const argv = req.argv;
  if (!Array.isArray(argv) || argv.length === 0 || typeof argv[0] !== "string") {
    throw new Error("secure exec requires a non-empty argv");
  }
  // argv[0] must be a BARE command name. A path (e.g. `/tmp/wrangler`) would let a
  // caller smuggle an arbitrary binary past the basename allowlist, so reject any
  // `/` and let execvp resolve the bare name against the LOCKED PATH below —
  // tying the allowed name to the real binary actually on the system PATH.
  const bin = argv[0];
  if (!bin || /[/\\\s]/.test(bin)) {
    throw new Error(`command "${bin}" must be a bare command name (no path separators or whitespace)`);
  }
  // A hostile/obsolete relay may hand us an allowlist minted before the Worker
  // denylist existed. Re-apply the shared protocol policy locally before spawn.
  if (isSecureExecCommandDenied(bin)) {
    throw new Error(`command "${bin}" is denied for secure exec`);
  }
  if (!req.allowedCommands.includes(bin)) {
    throw new Error(`command "${bin}" is not in this token's allowlist`);
  }

  // cwd, if supplied, must be absolute — fail closed rather than resolve a
  // relative path against an unpredictable working directory.
  if (req.cwd != null && !isAbsolute(req.cwd)) {
    throw new Error(`cwd "${req.cwd}" must be an absolute path`);
  }

  let stdin: Buffer | null = null;
  if (req.input != null) {
    stdin = Buffer.from(req.input, "base64");
    if (stdin.length > SECURE_EXEC_MAX_INPUT_BYTES) {
      throw new Error(
        `stdin payload ${stdin.length}B exceeds limit ${SECURE_EXEC_MAX_INPUT_BYTES}B`,
      );
    }
  }

  const user = resolveExecUser();

  // Minimal base env; the child runs AS the unprivileged user, so anchor HOME/USER
  // to that account (e.g. `claude -p` reads ~/.claude from it) and lock PATH.
  const baseEnv: Record<string, string> = {
    HOME: user.home,
    USER: user.name,
    LOGNAME: user.name,
    PATH: LOCKED_PATH,
  };

  // Build the child env: take caller env, STRIP anything that could override the
  // protected vars or hijack the dynamic linker / an interpreter, THEN overlay
  // baseEnv so PATH/HOME/USER/LOGNAME always win. Benign caller vars (e.g.
  // CLAUDE_CONFIG_DIR) pass through untouched.
  const filteredCallerEnv: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.env ?? {})) {
    if (!isDangerEnvKey(k)) filteredCallerEnv[k] = v;
  }
  const childEnv = { ...filteredCallerEnv, ...baseEnv };

  const startMs = Date.now();
  // Drop privilege in-process by re-exec'ing this Node runtime with the drop
  // sub-command (secure-exec-drop.ts): still root, it resets supplementary groups
  // and setgid/setuid to the unprivileged user, then execs `bin` against the
  // locked PATH. No external setpriv — works after a plain install. We do NOT pass
  // {uid,gid} to spawn() (that would not clear supplementary groups).
  const { cmd, args } = buildDropReexec([
    String(user.uid),
    String(user.gid),
    user.name,
    bin,
    ...argv.slice(1),
  ]);
  const proc = spawn(cmd, args, {
    cwd: req.cwd ?? user.home,
    env: childEnv,
    // Pipe stdin so we can feed `input`; pipe stdout/stderr like the legacy path.
    stdio: ["pipe", "pipe", "pipe"],
    // Own process group so kill() can signal the WHOLE tree (see executor.ts).
    detached: true,
    shell: false,
  });

  if (stdin && proc.stdin) {
    proc.stdin.on("error", () => {
      /* child may exit before draining stdin — ignore EPIPE */
    });
    proc.stdin.end(stdin);
  } else {
    proc.stdin?.end();
  }

  let closed = false;
  let escalationTimer: ReturnType<typeof setTimeout> | null = null;
  const clearEscalation = () => {
    if (escalationTimer) {
      clearTimeout(escalationTimer);
      escalationTimer = null;
    }
  };

  proc.stdout?.on("data", (chunk: Buffer) => {
    handlers.onOutput(chunk.toString("base64"), "stdout");
  });
  proc.stderr?.on("data", (chunk: Buffer) => {
    handlers.onOutput(chunk.toString("base64"), "stderr");
  });

  proc.on("close", (code) => {
    closed = true;
    clearEscalation();
    handlers.onDone(code ?? -1, Date.now() - startMs);
  });
  proc.on("error", (err) => {
    closed = true;
    clearEscalation();
    handlers.onError(err.message);
  });

  const signalTree = (signal: "SIGTERM" | "SIGKILL") => {
    if (closed || proc.pid == null) return;
    try {
      // POSIX only (this module is Linux-gated): negative pid = the detached
      // process group, so the WHOLE tree is signalled.
      process.kill(-proc.pid, signal);
    } catch {
      /* group already gone */
    }
  };

  return {
    kill: () => {
      if (closed) return;
      signalTree("SIGTERM");
      clearEscalation();
      escalationTimer = setTimeout(() => {
        escalationTimer = null;
        signalTree("SIGKILL");
      }, KILL_ESCALATION_MS);
      escalationTimer.unref?.();
    },
  };
}
