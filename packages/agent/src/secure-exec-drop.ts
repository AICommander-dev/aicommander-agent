import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { constants as osConstants } from "node:os";
import { SECURE_EXEC_USER } from "@aicommander/protocol";

// ESM has no `require`; build one bound to this module to load `node:sea`, which
// may be absent on older Node (so it must be loaded defensively, not statically).
const nodeRequire = createRequire(import.meta.url);

/**
 * Zero-dependency privilege drop for secure exec.
 *
 * Node's `spawn({uid,gid})` sets the primary uid/gid but does NOT clear root's
 * SUPPLEMENTARY groups, so the child would keep gid 0 et al. The classic fix is
 * the external `setpriv` (util-linux) binary — but that is NOT guaranteed to
 * exist on minimal hosts (alpine/musl, distroless, slim images), and secure exec
 * must work after a plain curl/npm install with NOTHING else to install.
 *
 * So we drop privilege IN-PROCESS using the agent's own bundled Node runtime:
 * the agent re-execs ITSELF (`process.execPath`) with the SENTINEL sub-command;
 * that child, still root, calls initgroups → setgid → setuid (exactly what
 * `setpriv --init-groups` does: supplementary groups reset to the target user's
 * own from /etc/group, root's groups dropped) and only THEN execs the target.
 * Works identically for the npm install (`node agent.js …`) and the single
 * self-contained binary (`agent …`) because execPath always points at a working
 * runtime — no external program, no PATH dependency.
 */
export const SECURE_EXEC_DROP_SENTINEL = "__secure-exec-drop";

/**
 * Locked PATH forced on the dropped child, identical to the value the executor
 * uses. The dropper sets this itself (rather than trusting the inherited env) so
 * a bare command name can NEVER be resolved against root's PATH — even if the
 * dropper is invoked directly rather than via the executor.
 */
const LOCKED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/**
 * Are we running as a single self-contained Node binary (SEA), as opposed to
 * `node <script> …`? Uses the official `node:sea` `isSea()` when available and
 * fails safe to `false` (the `node <script>` shape) on older Node where the
 * module is absent — extension-agnostic, so it survives extensionless global/npm
 * bin shims that a `.js/.mjs/.cjs` regex on argv[1] would misclassify.
 */
function isSingleExecutable(): boolean {
  let sea = false;
  try {
    sea = (nodeRequire("node:sea") as { isSea: () => boolean }).isSea();
  } catch {
    /* node:sea unavailable (older Node) → not a SEA */
  }
  return sea;
}

/**
 * Build the argv to re-exec THIS runtime with the drop sub-command. Handles both
 * launch shapes:
 *  - single self-contained binary (SEA): `binary __secure-exec-drop …` — argv[1]
 *    is a normal arg, no script to re-pass.
 *  - `node /path/agent.js …`: argv[1] is the script we MUST re-pass so the child
 *    Node loads it again. We re-pass argv[1] unconditionally regardless of its
 *    extension (extensionless global/npm bin shims have no `.js` suffix).
 */
export function buildDropReexec(extra: string[]): { cmd: string; args: string[] } {
  const script = process.argv[1];
  // When NOT a SEA we are `node <script> …` and must re-pass the script. If argv[1]
  // is somehow falsy, fall back to omitting it (belt — normally argv[1] is set).
  const args =
    !isSingleExecutable() && script
      ? [script, SECURE_EXEC_DROP_SENTINEL, ...extra]
      : [SECURE_EXEC_DROP_SENTINEL, ...extra];
  return { cmd: process.execPath, args };
}

/**
 * If `argv` carries the drop sentinel IN THE EXPECTED POSITION, perform the
 * privilege drop + exec the target and return true (the caller MUST then do
 * nothing else — this process is now the sandboxed command and will process.exit
 * with the child's code). Returns false for a normal agent launch.
 *
 * The sentinel is honoured ONLY as the FIRST real argument of our own re-exec —
 * never anywhere else in argv — so a stray token in a normal CLI invocation
 * (e.g. `status __secure-exec-drop …`) can NOT dispatch the drop parser:
 *   - single self-contained binary: `binary __secure-exec-drop …` → argv[1]
 *   - node+script:                  `node agent.js __secure-exec-drop …` → argv[2]
 *
 * Sentinel payload (immediately after the matched sentinel): uid gid username bin
 * [args…]. Runs as root on entry; fails closed (exit 127) on any privilege-drop
 * error so a misconfigured host can never silently run the command AS ROOT.
 */
export function maybeRunSecureExecDrop(argv: string[]): boolean {
  // Position-exact AND shape-gated: the sentinel is our re-exec's FIRST real
  // argument, whose index depends on the launch shape — argv[1] for a single
  // self-contained binary, argv[2] for `node <script>`. We check ONLY the index
  // valid for the CURRENT shape, so a stray token at the OTHER index (e.g.
  // `agent status __secure-exec-drop …` on a single binary) can never dispatch
  // the drop parser.
  const i = isSingleExecutable() ? 1 : 2;
  if (argv[i] !== SECURE_EXEC_DROP_SENTINEL) return false;

  const [uidStr, gidStr, uname, bin, ...args] = argv.slice(i + 1);
  const uid = Number(uidStr);
  const gid = Number(gidStr);

  // POSIX-only process methods (not on the base NodeJS.Process type).
  const posix = process as unknown as {
    initgroups?: (user: string | number, extraGroup: string | number) => void;
    setgid?: (id: string | number) => void;
    setuid?: (id: string | number) => void;
    getuid?: () => number;
    getgid?: () => number;
    getgroups?: () => number[];
  };

  try {
    if (
      !/^\d+$/.test(uidStr ?? "") ||
      !/^\d+$/.test(gidStr ?? "") ||
      !Number.isSafeInteger(uid) ||
      !Number.isSafeInteger(gid) ||
      uid <= 0 ||
      gid <= 0 ||
      uid > 0xffff_ffff ||
      gid > 0xffff_ffff ||
      uname !== SECURE_EXEC_USER ||
      !bin
    ) {
      throw new Error("invalid drop arguments");
    }
    if (
      typeof posix.initgroups !== "function" ||
      typeof posix.setgid !== "function" ||
      typeof posix.setuid !== "function" ||
      typeof posix.getuid !== "function" ||
      typeof posix.getgid !== "function" ||
      typeof posix.getgroups !== "function"
    ) {
      throw new Error("privilege-drop syscalls unavailable on this platform");
    }
    // initgroups (supplementary groups ← target user's own, from /etc/group, plus
    // the primary gid) BEFORE setgid/setuid; setuid LAST since it forfeits the
    // privilege needed for the other two. This clears root's supplementary groups.
    posix.initgroups(uname, gid);
    posix.setgid(gid);
    posix.setuid(uid);
    // Defence in depth: confirm we actually dropped the primary ids before exec.
    if (posix.getuid() !== uid || posix.getgid() !== gid) {
      throw new Error("privilege drop did not take effect");
    }
    // And confirm root's SUPPLEMENTARY groups are gone — the whole reason we do an
    // in-process initgroups instead of spawn({uid,gid}). If gid 0 (root) is still
    // present, the child would retain root-group access: fail closed.
    const groups = posix.getgroups();
    if (
      !Array.isArray(groups) ||
      groups.some((group) => !Number.isInteger(group) || group < 0) ||
      groups.includes(0)
    ) {
      throw new Error("privilege drop left unsafe supplementary groups in place");
    }
  } catch (err) {
    process.stderr.write(
      `secure-exec: privilege drop failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(127);
  }

  // Now NON-ROOT. Exec the target with inherited stdio (the parent agent piped our
  // stdio back to the relay). Force the LOCKED PATH onto the child env ourselves
  // (rather than trusting the inherited env) so the bare `bin` name can never be
  // resolved against root's PATH — even on a direct invocation. No shell.
  const childEnv = { ...process.env, PATH: LOCKED_PATH };
  const child = spawn(bin, args, { stdio: "inherit", env: childEnv, shell: false });
  let settled = false;
  child.on("error", (err) => {
    if (settled) return;
    settled = true;
    process.stderr.write(`secure-exec: spawn failed: ${err.message}\n`);
    process.exit(127);
  });
  child.on("exit", (code, signal) => {
    if (settled) return;
    settled = true;
    if (signal) {
      // Died from a signal: propagate as 128 + signum (SIGKILL→137, SIGTERM→143)
      // so the agent sees the real terminal cause, not a flat 128.
      const signum = osConstants.signals[signal as NodeJS.Signals];
      process.exit(128 + (typeof signum === "number" ? signum : 0));
    }
    process.exit(code ?? 0);
  });
  return true;
}
