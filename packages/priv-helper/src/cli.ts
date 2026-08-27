// Privileged-helper CLI parsing must happen before the transport, executor, or
// watchdog is created. The bare invocation is reserved for the service manager;
// every diagnostic invocation must either exit here or fail closed here.

export const PRIV_HELPER_USAGE =
  "Usage: aicommander-priv-helper [--version]";

export type PrivHelperCliMode = "serve" | "version" | "invalid";

/**
 * Parse only user arguments (`process.argv.slice(2)`). Keep the surface
 * deliberately tiny: launchd / Task Scheduler use no arguments, and `--version`
 * is the one safe diagnostic. No other token may fall through to daemon startup.
 */
export function parsePrivHelperCliArgs(
  args: readonly string[],
): PrivHelperCliMode {
  if (args.length === 0) return "serve";
  if (args.length === 1 && args[0] === "--version") return "version";
  return "invalid";
}
