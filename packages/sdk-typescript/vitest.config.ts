import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
  },
  // Disable CSS processing so the repo-root postcss.config.js (used by the
  // Tauri app) isn't picked up when vitest walks upward looking for config.
  css: { postcss: { plugins: [] } },
});
