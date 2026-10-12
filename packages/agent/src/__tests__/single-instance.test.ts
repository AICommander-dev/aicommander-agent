// The gate that stops a second agent from silently taking this machine's relay
// session. See single-instance.ts: two agents share one durable device identity,
// the relay keeps only the newest connection, and the loser vanishes without an
// error — which is how a live box became unreachable on 2026-08-10.

import { describe, it, expect } from "vitest";
import { singleInstanceVerdict, singleInstanceMessage } from "../single-instance.js";
import type { LiveAgentScan } from "../live-agent.js";

const scan = (over: Partial<LiveAgentScan> = {}): LiveAgentScan => ({
  running: [],
  unverified: [],
  scanFailed: false,
  ...over,
});

describe("singleInstanceVerdict", () => {
  it("clears a machine that was scanned properly and holds no agent", () => {
    expect(singleInstanceVerdict(scan())).toEqual({ kind: "clear" });
  });

  it("reports a proven agent with its pids", () => {
    expect(singleInstanceVerdict(scan({ running: [4242] }))).toEqual({
      kind: "running",
      pids: [4242],
    });
  });

  it("treats an unidentifiable live pid as doubt, never as absence", () => {
    // "We could not look" is not "there is nothing there" — and the cost of
    // guessing wrong is a machine falling off the network.
    expect(singleInstanceVerdict(scan({ unverified: [99] }))).toEqual({
      kind: "uncertain",
      pids: [99],
      scanFailed: false,
    });
  });

  it("treats a failed process-table walk as doubt on its own", () => {
    // The walk is the only source that finds an agent nobody recorded, so losing
    // it is exactly as disqualifying as an unreadable pid.
    expect(singleInstanceVerdict(scan({ scanFailed: true }))).toEqual({
      kind: "uncertain",
      pids: [],
      scanFailed: true,
    });
  });

  it("prefers the proven verdict when both signals are present", () => {
    // Knowing something beats not knowing something: the operator gets the
    // specific message with a pid they can actually go and look at.
    expect(singleInstanceVerdict(scan({ running: [7], unverified: [8], scanFailed: true }))).toEqual({
      kind: "running",
      pids: [7],
    });
  });
});

describe("singleInstanceMessage", () => {
  it("says nothing when there is nothing to say", () => {
    expect(singleInstanceMessage({ kind: "clear" })).toBe("");
  });

  it("names the pid, the consequence, and the override", () => {
    const text = singleInstanceMessage({ kind: "running", pids: [4242] }, "linux");
    expect(text).toContain("pid 4242");
    // The reader needs the consequence, not the rule that fired.
    expect(text).toMatch(/takes this machine's relay session away/);
    expect(text).toContain("--force");
    expect(text).toContain("systemctl status aicommander-agent");
  });

  it("offers remedies that exist on the platform it is printed on", () => {
    // This refusal is not systemd-only: the probe answers "could not tell" wherever
    // it cannot read a process's identity, and macOS reaches it through ps. Telling
    // a Mac operator to run systemctl reads as a broken tool and buries the one
    // line that applies to them.
    const mac = singleInstanceMessage({ kind: "running", pids: [7] }, "darwin");
    expect(mac).not.toContain("systemctl");
    expect(mac).toContain("ps -ef");
    expect(mac).toContain("--force");

    const win = singleInstanceMessage({ kind: "uncertain", pids: [7], scanFailed: false }, "win32");
    expect(win).not.toContain("systemctl");
    expect(win).toContain("--force");
  });

  it("distinguishes an unreadable pid from an unreadable process table", () => {
    const pidDoubt = singleInstanceMessage({ kind: "uncertain", pids: [99], scanFailed: false });
    expect(pidDoubt).toMatch(/pid 99 is alive but its identity could not be read/);

    const tableDoubt = singleInstanceMessage({ kind: "uncertain", pids: [], scanFailed: true });
    expect(tableDoubt).toMatch(/process table could not be read/);
    expect(tableDoubt).not.toMatch(/pid .* is alive/);
  });

  it("frames uncertainty as a refusal to guess, so --force stays a real option", () => {
    // If this read as a detection, an operator who knows the machine is idle
    // would think the tool is broken rather than cautious.
    const text = singleInstanceMessage({ kind: "uncertain", pids: [99], scanFailed: false });
    expect(text).toMatch(/refusal to GUESS/);
    expect(text).toMatch(/--force is correct/);
  });
});
