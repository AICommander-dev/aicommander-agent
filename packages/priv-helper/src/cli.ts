// Privileged-helper CLI parsing must happen before the transport, executor, or
// watchdog is created. The bare invocation is reserved for the service manager;
// every diagnostic invocation must either exit here or fail closed here.

export const PRIV_HELPER_USAGE =
  "Usage: aicommander-priv-helper [--version | doctor]";

export type PrivHelperCliMode = "serve" | "version" | "doctor" | "invalid";

/**
 * Parse only user arguments (`process.argv.slice(2)`). Keep the surface
 * deliberately tiny: launchd / Task Scheduler use no arguments, and `--version`
 * and `doctor` are the two safe diagnostics. No other token may fall through to
 * daemon startup.
 *
 * `doctor` (PLAN-av-hardening W2.3) is the diagnostic a user can still reach
 * when antivirus has emptied the app's install directory and nothing in it runs
 * any more — this binary lives in a sibling directory the sweep did not touch.
 * It takes NO arguments of its own, and that is a security property rather than
 * a simplification: an option accepted here is an option somebody can be talked
 * into passing to a binary that runs as SYSTEM. Every shape but the bare verb is
 * `invalid`, so `doctor --anything` fails closed instead of degrading into
 * something else — and, like `--version`, it exits in bin/priv-helper.ts before
 * any transport, executor or watchdog exists, so no diagnostic can fall through
 * to daemon startup.
 */
export function parsePrivHelperCliArgs(
  args: readonly string[],
): PrivHelperCliMode {
  if (args.length === 0) return "serve";
  if (args.length === 1 && args[0] === "--version") return "version";
  if (args.length === 1 && args[0] === "doctor") return "doctor";
  return "invalid";
}
