import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    // The browser tests in e2e/, e2e-actions/ and e2e-auth/ are run by Playwright, not by vitest.
    exclude: [...configDefaults.exclude, "e2e/**", "e2e-actions/**", "e2e-auth/**"],
    // Style files are empty in tests, except when a test reads one as text.
    css: { include: [/\.css\?raw$/] },
  },
});
