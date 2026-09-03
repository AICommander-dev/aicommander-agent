import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // scripts/ carries the release-provenance gate (verify-win-exec.mjs); it is
    // plain ESM with no build step, so it is tested where it lives.
    include: ["src/**/__tests__/**/*.test.ts", "scripts/**/*.test.mjs"],
    // Windows gets a bigger budget than everyone else, and only because it earns
    // it: these tests spawn REAL processes (job-manager drives cmd.exe there),
    // and on a loaded GitHub runner that is the slow path — `retention > reclaims
    // expired jobs when the next job starts` was killed at the 10 s mark on the
    // v1.0.41 release CI (run 31390091067), passed on a bare re-run with no code
    // change, and lives in a package that commit did not touch.
    //
    // The two failure modes are not symmetric. A budget that is too generous
    // costs a few extra seconds when something genuinely hangs; one that is too
    // tight turns green code red, and a suite that cries wolf stops being read.
    // So: 20 s where processes are slow, 10 s everywhere else, where a hang
    // should still surface fast during local work.
    testTimeout: process.platform === "win32" ? 20_000 : 10_000,
  },
});
