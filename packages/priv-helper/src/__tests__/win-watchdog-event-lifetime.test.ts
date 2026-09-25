// The one property of the refusal reporter that a mock cannot observe: that the
// child it starts CANNOT HOLD THE HELPER OPEN.
//
// WHY THIS FILE EXISTS SEPARATELY. win-watchdog-event.test.ts mocks
// node:child_process wholesale — deliberately, because what it pins is the
// invocation (which program, from where, with which arguments), and there is no
// Windows here to run it. But a mock has no event loop handle, so it is
// structurally incapable of noticing that `spawn(..., { timeout })` arms a REF'd
// timer which `child.unref()` does not cover. That is exactly what shipped: the
// suite was green while a stuck powershell.exe kept the helper alive for up to
// EVENT_REPORT_TIMEOUT_MS (15 s) at shutdown or restart, under a task with
// RestartCount 3.
//
// So this file runs the real function in a REAL child node process and times how
// long that process takes to exit while a long-lived grandchild is still
// running. No mocks, and a CONTROL that reproduces the old behaviour, so the
// measurement is shown to be capable of detecting a held event loop.
//
// Portable: the long-lived grandchild is `node -e setTimeout(...)`, not `sleep`.

import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

/** The module under test, imported by the child straight from source. */
const MODULE_URL = new URL("../win-watchdog-logfile.ts", import.meta.url).href;

/**
 * Node runs TypeScript by stripping types from 22.18 / 24 onwards, which is how
 * the child below imports the source with no build step. On an older runtime the
 * proof cannot run at all, and a skipped test says so in the runner's listing —
 * the alternative (a green test that silently proved nothing) is the failure
 * mode this whole file is a reaction to.
 */
const NODE_MAJOR = Number(process.versions.node.split(".")[0]);
const CAN_IMPORT_TS = Number.isFinite(NODE_MAJOR) && NODE_MAJOR >= 24;

/** A child that outlives the process that started it, on every platform. */
const LONG_LIVED = `setTimeout(() => {}, 5000)`;

/** Run `node -e <code>` and resolve how long it took to exit, in ms. */
function timeToExit(code: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    // stdio ignored on purpose: an inherited pipe would be held open by the
    // GRANDCHILD, so a piped run would measure the wrong thing.
    const child = spawn(process.execPath, ["-e", code], { stdio: "ignore" });
    child.on("error", reject);
    child.on("exit", () => resolve(Date.now() - started));
  });
}

describe("the refusal reporter cannot hold the helper open", () => {
  it.skipIf(!CAN_IMPORT_TS)(
    "exits immediately even with a stuck child still running",
    async () => {
      // MEASURED, not asserted from reading: this starts __spawnUnheldChild
      // against a grandchild that runs for 5 s and then does nothing else, so
      // the only thing that could keep the process alive is a handle the
      // reporter left behind. EVENT_REPORT_TIMEOUT_MS is 15 s; a process that
      // exits in well under a second is one that is waiting for none of it.
      const elapsed = await timeToExit(
        `import(${JSON.stringify(MODULE_URL)}).then((m) => {` +
          ` m.__spawnUnheldChild(process.execPath, ["-e", ${JSON.stringify(LONG_LIVED)}]); });`,
      );
      expect(elapsed).toBeLessThan(1500);
    },
    30_000,
  );

  it(
    "(control) the same measurement DOES catch spawn's own timeout option",
    async () => {
      // Anti-vacuity, and the bug reproduced in one line. If this control
      // exited as fast as the subject above, the assertion there would prove
      // nothing about handles — it would only prove that node starts quickly.
      // The option's timer is REF'd, so the process stays up for the whole
      // deadline (1.5 s here, 15 s in the code this replaced) even though the
      // child is unref'd and nobody is waiting for it.
      const elapsed = await timeToExit(
        `const { spawn } = require("node:child_process");` +
          ` const c = spawn(process.execPath, ["-e", ${JSON.stringify(LONG_LIVED)}],` +
          ` { stdio: "ignore", timeout: 1500 });` +
          ` c.on("error", () => {}); c.unref();`,
      );
      expect(elapsed).toBeGreaterThanOrEqual(1400);
    },
    30_000,
  );
});
