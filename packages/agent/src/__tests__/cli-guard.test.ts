// The guard that stops an unrecognised argument from being treated as "start the
// agent". See cli-guard.ts: `run` is commander's default command (the systemd unit
// execs the binary bare), and commander routes ANY unknown argument to a default —
// so before this guard, `aicommander-agent version` launched a second agent, which
// re-registered this machine's device identity and took the relay session away from
// the service-managed one. That is how a live box went offline on 2026-08-10.

import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { unknownCliCommand, unknownCliCommandMessage } from "../cli-guard.js";

/**
 * The real command surface, mirroring what bin/agent.ts registers.
 *
 * The mirror is PINNED against the entry point below, because nothing else
 * catches it drifting: the binary builds its own list from `program.commands`,
 * so a command added there and forgotten here weakens every test in this file
 * silently — which is exactly what happened to `doctor`, whose whole point is
 * that it must not be mistaken for an unknown word and turned into a second
 * agent.
 */
const KNOWN = [
  "help",
  "run",
  "version",
  "self-update",
  "install",
  "status",
  "doctor",
  "enable",
  "disable",
  "change-code",
  "reset-code",
  "list-admins",
  "block-admin",
  "revoke-admin",
  "unblock-admin",
  "uninstall",
];

/** process.argv shape: [execPath, script, ...args]. */
const argv = (...args: string[]): string[] => ["/usr/bin/node", "/usr/local/bin/aicommander-agent", ...args];

// The shape that matters most, and the one this file originally failed to model.
// Measured on a live Ubuntu box (2026-08-10): the systemd MainPID runs
// `/usr/local/bin/aicommander-agent` with no arguments, and the worker it spawns
// runs `/usr/local/bin/aicommander-agent /$bunfs/root/aicommander-agent-linux-x64`
// — supervisor.ts re-execs with process.argv.slice(1), which on the compiled build
// forwards the runtime's embedded entry as a positional argument, and the child's
// runtime then injects a fresh one in front of it.
const BUNFS_ENTRY = "/$bunfs/root/aicommander-agent-linux-x64";
const workerArgv = (...args: string[]): string[] => [
  "/usr/local/bin/aicommander-agent",
  BUNFS_ENTRY,
  BUNFS_ENTRY,
  ...args,
];

/** Every name and alias bin/agent.ts registers, read out of its source. */
function registeredCommands(): string[] {
  const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "bin", "agent.ts");
  const source = fs.readFileSync(entry, "utf8");
  const names = [...source.matchAll(/\.command\(\s*"([^"\s<[]+)/g)].map((m) => m[1]!);
  const aliases = [...source.matchAll(/\.aliases\(\[([^\]]*)\]\)/g)].flatMap((m) =>
    [...m[1]!.matchAll(/"([^"]+)"/g)].map((a) => a[1]!),
  );
  // `help` is commander's own implicit command; the binary adds it by hand for
  // the same reason this list does.
  return ["help", ...names, ...aliases];
}

describe("the guard's command list against the binary's own", () => {
  it("covers every command bin/agent.ts registers", () => {
    // A command missing here is a command every test below silently stops
    // covering. `doctor` sat outside this list from the day it was added.
    const missing = registeredCommands().filter((name) => !KNOWN.includes(name));
    expect(missing).toEqual([]);
  });

  it("finds the commands it is reading, so a parse change cannot pass by default", () => {
    const registered = registeredCommands();
    expect(registered).toContain("run");
    expect(registered).toContain("doctor");
    expect(registered.length).toBeGreaterThan(10);
  });
});

describe("unknownCliCommand — the compiled binary's worker re-exec", () => {
  it("does NOT treat the runtime's entry token as a command", () => {
    // Getting this wrong exits 1 on every worker the supervisor spawns; the
    // watchdog burns its restart budget and the machine goes offline — the exact
    // failure this guard was written to prevent, on every agent at once.
    expect(unknownCliCommand(workerArgv(), KNOWN)).toBeNull();
  });

  it("still finds a real typo hiding behind that token", () => {
    expect(unknownCliCommand(workerArgv("staus"), KNOWN)).toBe("staus");
  });

  it("still passes a real command hiding behind that token", () => {
    expect(unknownCliCommand(workerArgv("self-update"), KNOWN)).toBeNull();
  });

  it("skips an npm-shape script path just the same", () => {
    const argv = ["/usr/bin/node", "/usr/lib/node_modules/@aicommander/agent/dist/bin/agent.js",
      "/usr/lib/node_modules/@aicommander/agent/dist/bin/agent.js", "status"];
    expect(unknownCliCommand(argv, KNOWN)).toBeNull();
  });
});

describe("unknownCliCommand", () => {
  it("lets the service's bare launch through", () => {
    // ExecStart=/usr/local/bin/aicommander-agent, no arguments. This is the ONE
    // invocation that may reach the implicit default command.
    expect(unknownCliCommand(argv(), KNOWN)).toBeNull();
  });

  it("lets every known command and alias through", () => {
    for (const name of KNOWN) {
      expect(unknownCliCommand(argv(name), KNOWN)).toBeNull();
    }
  });

  it("refuses the typo that actually knocked a machine off the relay", () => {
    expect(unknownCliCommand(argv("version"), KNOWN.filter((c) => c !== "version"))).toBe("version");
  });

  it("refuses a misspelled command instead of starting an agent", () => {
    expect(unknownCliCommand(argv("staus"), KNOWN)).toBe("staus");
    expect(unknownCliCommand(argv("start"), KNOWN)).toBe("start");
    expect(unknownCliCommand(argv("restart"), KNOWN)).toBe("restart");
  });

  it("leaves flags to commander, which rejects unknown ones on its own", () => {
    // A leading `-` never falls through to the default command, so the guard has
    // no business second-guessing it — `--version`/`--help` must keep working.
    expect(unknownCliCommand(argv("--version"), KNOWN)).toBeNull();
    expect(unknownCliCommand(argv("-V"), KNOWN)).toBeNull();
    expect(unknownCliCommand(argv("--help"), KNOWN)).toBeNull();
    expect(unknownCliCommand(argv("--nonsense"), KNOWN)).toBeNull();
  });

  it("judges only the first token, so a command's own arguments pass", () => {
    // `block-admin 2` — the `2` is that command's argument, not a command.
    expect(unknownCliCommand(argv("block-admin", "2"), KNOWN)).toBeNull();
    expect(unknownCliCommand(argv("uninstall", "--force"), KNOWN)).toBeNull();
  });

  it("explains itself in terms of what would otherwise happen", () => {
    const message = unknownCliCommandMessage("version");
    expect(message).toContain("unknown command 'version'");
    // The operator needs to know both that nothing started and why that matters.
    expect(message).toMatch(/SECOND agent/);
    expect(message).toMatch(/--help/);
  });
});
