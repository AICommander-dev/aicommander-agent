import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Explicit because vitest 4 no longer excludes dist/ by default, and `tsc`
    // compiles the tests into dist/src/__tests__ — without this they would run
    // a second time after every build. scripts/ holds plain ESM release tooling
    // tested where it lives.
    include: ["src/**/__tests__/**/*.test.ts", "scripts/**/*.test.mjs"],
  },
});
