import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts", "apps/*/test/**/*.test.ts"],
    passWithNoTests: true,
    // File-backed PGlite opens take several seconds on shared CI runners.
    testTimeout: 60_000,
  },
});
